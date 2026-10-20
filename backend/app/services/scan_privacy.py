import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SENSITIVE_QUERY_KEY = re.compile(
    r"token|session|(?:^|[_-])sid(?:$|[_-])|auth|password|passwd|secret|"
    r"credential|api[_-]?key|access|refresh|reset|code|otp|signature|sig|state|ticket|jwt",
    re.IGNORECASE,
)
_OPAQUE_PATH_SEGMENT = re.compile(r"(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9_-]{24,}")
_PRIVATE_ANALYSIS_KEYS = {"source_text_preview", "ocr_input_name", "path"}


def redact_url_for_storage(value: str) -> str:
    """Keep useful URL structure while removing common URL-carried secrets."""
    candidate = value if "://" in value else f"https://{value}" if value.startswith("www.") else ""
    if not candidate:
        return "[redacted URL]"

    try:
        parsed = urlsplit(candidate)
        if not parsed.hostname:
            return "[redacted URL]"
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        segments = parsed.path.split("/")
        for index, segment in enumerate(segments):
            if index and re.search(r"reset|token|session|auth", segments[index - 1], re.IGNORECASE):
                segments[index] = "[redacted]"
            elif _OPAQUE_PATH_SEGMENT.fullmatch(segment):
                segments[index] = "[redacted]"
        query = [
            (key, "[redacted]" if _SENSITIVE_QUERY_KEY.search(key) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit((parsed.scheme, netloc, "/".join(segments), urlencode(query), ""))
    except ValueError:
        return "[redacted URL]"


def safe_scan_preview(input_type: str, raw_input: str | None = None) -> str:
    if input_type == "url" and raw_input:
        return redact_url_for_storage(raw_input)[:240]
    return {
        "message": "Message scan",
        "qr": "QR scan",
        "screenshot": "Screenshot scan",
    }.get(input_type, "Scan")


def sanitize_analysis_payload(value):
    """Remove user content from analysis JSON before storing or returning it."""
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in _PRIVATE_ANALYSIS_KEYS:
                continue
            if normalized_key == "normalized" and isinstance(item, str):
                sanitized[key] = redact_url_for_storage(item)
            elif normalized_key == "urls" and isinstance(item, list):
                sanitized[key] = [
                    redact_url_for_storage(url) if isinstance(url, str) else sanitize_analysis_payload(url)
                    for url in item
                ]
            elif normalized_key == "netloc" and isinstance(item, str):
                sanitized[key] = item.rsplit("@", 1)[-1]
            else:
                sanitized[key] = sanitize_analysis_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_analysis_payload(item) for item in value]
    return value
