import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


_URL_PATTERN = re.compile(
    r"[a-z][a-z0-9+.-]*://[^\s\"'<>]+|www\.[^\s\"'<>]+",
    re.IGNORECASE,
)
_PRIVATE_ANALYSIS_KEYS = {
    "source_text_preview", "ocr_input_name", "path", "query", "fragment",
    "text", "message", "raw_text", "ocr_text", "filename", "file_name",
    "input", "payload",
    "evidence_excerpt", "message_excerpt", "quote",
}
_INDICATOR_DESCRIPTIONS = {
    "dataset_known_malicious": "The exact normalized URL appears in an imported dataset with a malicious label.",
    "urgency_language": "The content uses pressure or time-sensitive language.",
    "account_targeting": "The content refers to account access or verification.",
    "credential_request": "The content references credentials such as passwords or one-time codes.",
    "financial_context": "The content refers to banking, payment, or money activity.",
    "possible_impersonation": "The content may impersonate an organization or authority.",
    "suspicious_link_presence": "The content includes a link that should be verified before opening.",
    "url_shortener": "The destination uses a URL shortener that can conceal its final destination.",
    "suspicious_hostname": "The destination hostname has suspicious characteristics.",
    "suspicious_keywords": "The destination includes language commonly used in scam or phishing attempts.",
    "payment_context": "The destination references payment or financial activity.",
    "ip_address_host": "The destination uses an IP address instead of a domain name.",
    "suspicious_path": "The destination path has suspicious structural characteristics.",
    "suspicious_query": "The destination query has suspicious structural characteristics.",
    "suspicious_tld": "The destination uses a potentially risky top-level domain.",
    "encoded_chars": "The destination contains encoded or unusual characters.",
    "sandbox_http_transport": "The sandbox observed navigation over unencrypted HTTP.",
    "sandbox_cross_origin_form": "The sandbox observed a form action directed to a different origin.",
    "sandbox_download_attempt": "The sandbox observed a download attempt; the file was not saved or opened.",
    "prize_bait": "The message uses a prize, giveaway, refund, lottery, or reward claim.",
    "call_to_action": "The message pressures the recipient to click or follow an instruction.",
    "cash_prize_click_combination": "A promised cash reward is paired with a request to take action.",
    "verification_threat": "The message threatens account access or eligibility unless verification is completed.",
    "payment_manipulation": "The message uses payment instructions or financial pressure that should be independently verified.",
    "impersonation_attempt": "The message may impersonate an organization or authority.",
    "credential_theft": "The message requests credentials, one-time codes, or other account secrets.",
    "benign_promotion_context": "The message includes context consistent with a legitimate promotion.",
}


def _normalize_hostname(hostname: str) -> str | None:
    try:
        address = ipaddress.ip_address(hostname)
        if address.version == 6 and "%" in hostname:
            return None
        normalized = address.compressed
        return f"[{normalized}]" if address.version == 6 else normalized
    except ValueError:
        try:
            normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
        if (
            not normalized
            or len(normalized) > 253
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in normalized.split("."))
        ):
            return None
        return normalized


def redact_url_for_storage(value: str) -> str:
    """Retain only a URL's scheme and normalized hostname."""
    candidate = value if "://" in value else f"https://{value}" if value.startswith("www.") else ""
    if not candidate:
        return "[redacted URL]"

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if not parsed.scheme or not hostname:
            return "[redacted URL]"
        # Accessing .port validates malformed and out-of-range port syntax; ports
        # are intentionally omitted from the persisted representation.
        _ = parsed.port
        normalized_hostname = _normalize_hostname(hostname)
        if normalized_hostname is None:
            return "[redacted URL]"
        return urlunsplit((parsed.scheme.lower(), normalized_hostname, "", "", ""))
    except ValueError:
        return "[redacted URL]"


def safe_scan_preview(input_type: str, raw_input: str | None = None) -> str:
    if input_type == "url" and raw_input:
        return redact_url_for_storage(raw_input)
    return {
        "message": "Message scan",
        "qr": "QR scan",
        "screenshot": "Screenshot scan",
    }.get(input_type, "Scan")


def sanitize_analysis_payload(value):
    """Remove raw content and minimize URL-bearing fields in analysis JSON."""
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in _PRIVATE_ANALYSIS_KEYS:
                continue
            if normalized_key in {"url", "uri", "link", "href", "destination", "normalized"}:
                sanitized[key] = redact_url_for_storage(item) if isinstance(item, str) else "[redacted URL]"
            elif normalized_key == "urls" and isinstance(item, list):
                sanitized[key] = [
                    redact_url_for_storage(url) if isinstance(url, str) else "[redacted URL]"
                    for url in item
                ]
            elif normalized_key == "netloc" and isinstance(item, str):
                sanitized[key] = redact_url_for_storage(f"https://{item}")
            elif normalized_key == "port":
                continue
            elif normalized_key == "hostname" and isinstance(item, str):
                sanitized[key] = _normalize_hostname(item) or "[redacted hostname]"
            else:
                sanitized[key] = sanitize_analysis_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_analysis_payload(item) for item in value]
    if isinstance(value, str):
        return _URL_PATTERN.sub(lambda match: redact_url_for_storage(match.group(0)), value)
    return value


def safe_indicator_description(indicator_type: str) -> str:
    """Return controlled copy instead of trusting persisted or analyzed text."""
    return _INDICATOR_DESCRIPTIONS.get(
        indicator_type,
        "A potential risk indicator was detected.",
    )
