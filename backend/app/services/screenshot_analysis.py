import io
import re
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError

from app.services.risk_engine import RiskAnalysis, _extract_urls, analyze_message, analyze_url

SUPPORTED_IMAGE_FORMATS = {"PNG", "JPEG", "WEBP"}
MAX_IMAGE_PIXELS = 20_000_000


class ScreenshotTooLargeError(ValueError):
    pass


async def read_screenshot_upload(upload, max_bytes: int) -> bytes:
    """Read an upload in bounded chunks and always release its temporary file."""
    try:
        chunks: list[bytes] = []
        total_bytes = 0
        while True:
            chunk = await upload.read(min(64 * 1024, max_bytes - total_bytes + 1))
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise ScreenshotTooLargeError("The uploaded image exceeds the configured size limit.")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        await upload.close()


def validate_screenshot_upload(
    image_bytes: bytes,
    filename: str | None,
    content_type: str | None,
) -> None:
    if not image_bytes:
        raise ValueError("The uploaded image is empty.")

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image_format = image.format
            if image_format not in SUPPORTED_IMAGE_FORMATS:
                raise ValueError("Unsupported image format. Please upload a PNG, JPEG, or WebP image.")

            width, height = image.size
            if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                raise ValueError("The uploaded image dimensions are too large to process safely.")

            expected_extensions = {
                "PNG": {".png"},
                "JPEG": {".jpg", ".jpeg"},
                "WEBP": {".webp"},
            }
            if filename and Path(filename).suffix.lower() not in expected_extensions[image_format]:
                raise ValueError("The filename extension does not match the image content.")

            expected_content_types = {
                "PNG": "image/png",
                "JPEG": "image/jpeg",
                "WEBP": "image/webp",
            }
            if content_type and content_type.lower() != expected_content_types[image_format]:
                raise ValueError("The content type does not match the image content.")

            image.verify()
    except ValueError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise ValueError("The uploaded image dimensions are too large to process safely.") from exc
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise ValueError("The uploaded file is not a valid supported image.") from exc


def _safe_ocr_text(raw_text: str) -> str:
    text = raw_text.replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_text_from_image(image_bytes: bytes) -> str:
    try:
        from PIL import Image
        import pytesseract
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "OCR is not available in this environment. Install Tesseract and Pillow to enable screenshot analysis."
        ) from exc

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
        text = pytesseract.image_to_string(image)
    except Exception as exc:  # pragma: no cover - depends on external OCR binary
        if "TesseractNotFoundError" in type(exc).__name__ or "tesseract" in str(exc).lower():
            raise RuntimeError(
                "Tesseract is not installed or not available on PATH. Install Tesseract OCR to enable screenshot analysis."
            ) from exc
        raise RuntimeError("Failed to read the uploaded screenshot for OCR analysis.") from exc

    return _safe_ocr_text(text)


def analyze_screenshot_bytes(image_bytes: bytes, *, file_name: str | None = None) -> RiskAnalysis:
    cleaned_text = extract_text_from_image(image_bytes)
    if not cleaned_text:
        raise ValueError("The uploaded image did not contain readable text for analysis.")

    base_analysis = analyze_message(cleaned_text)
    extracted_urls = _extract_urls(cleaned_text)

    all_signals = list(base_analysis.signals)
    score = base_analysis.risk_score
    final_threat_type = base_analysis.threat_type
    final_prediction = base_analysis.prediction
    explanation = dict(base_analysis.explanation)
    explanation["source_text_preview"] = cleaned_text[:300]
    explanation["ocr_input_name"] = file_name or "uploaded_image"
    explanation["url_count"] = len(extracted_urls)
    explanation["combined_with_url_checks"] = bool(extracted_urls)

    for url in extracted_urls[:5]:
        try:
            url_analysis = analyze_url(url)
        except ValueError:
            continue

        all_signals.extend(url_analysis.signals)
        score = max(score, url_analysis.risk_score)
        if url_analysis.risk_score > base_analysis.risk_score:
            final_threat_type = url_analysis.threat_type
            final_prediction = url_analysis.prediction

    deduped_signals: list[Any] = []
    seen: set[tuple[str, str]] = set()
    for signal in all_signals:
        key = (signal.indicator_type, signal.description)
        if key in seen:
            continue
        seen.add(key)
        deduped_signals.append(signal)

    if score >= 80:
        final_threat_type = "Potential Phishing / Fraudulent Screenshot"
    elif score >= 60:
        final_threat_type = "Suspicious Screenshot Content"
    elif score >= 30:
        final_threat_type = "Screenshot Needs Verification"
    else:
        final_threat_type = "No Strong Screenshot Risk Indicators"

    confidence = min(98.0, max(base_analysis.confidence, 55.0 + (len(deduped_signals) * 5.0)))
    if extracted_urls:
        confidence = min(99.0, confidence + 4.0)

    return RiskAnalysis(
        risk_score=min(100, score),
        confidence=confidence,
        threat_type=final_threat_type,
        prediction=final_prediction,
        signals=deduped_signals,
        features={
            **base_analysis.features,
            "ocr_text_length": len(cleaned_text),
            "url_count": len(extracted_urls),
            "urls": extracted_urls[:5],
        },
        explanation={
            **explanation,
            "summary": "Risk was estimated from OCR text and any extracted URLs in the screenshot without opening external destinations.",
        },
        recommendations=base_analysis.recommendations or [
            "Do not act under time pressure. Verify through the official app or site.",
            "Never share OTPs, passwords, or PINs with a sender you only met through a screenshot.",
            "If the image contains a payment request, confirm the recipient through a trusted channel.",
        ],
        model_name="scamshield-screenshot-ocr",
        model_version="1.0.0",
        source="ocr_structural_analysis",
    )
