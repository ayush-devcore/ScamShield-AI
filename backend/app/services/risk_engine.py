import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit


@dataclass(frozen=True)
class ThreatSignal:
    indicator_type: str
    description: str
    severity: str
    evidence: dict


@dataclass(frozen=True)
class RiskAnalysis:
    risk_score: int
    confidence: float
    threat_type: str
    prediction: str
    signals: list[ThreatSignal]
    features: dict
    explanation: dict
    recommendations: list[str] | None = None
    model_name: str = "scamshield-baseline-rules"
    model_version: str = "1.0.0"
    source: str = "baseline_rules"


URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bnow\b",
    r"\btoday\b",
    r"\basap\b",
    r"\bwithin\s+\d+\s*(?:minutes?|hours?)\b",
    r"\blast\s+warning\b",
]

ACCOUNT_PATTERNS = [
    r"\baccount\b",
    r"\blogin\b",
    r"\bsign\s*in\b",
    r"\bverification\b",
    r"\bverify\b",
    r"\bkyc\b",
    r"\bblocked\b",
    r"\bsuspend(?:ed)?\b",
]

CREDENTIAL_PATTERNS = [
    r"\botp\b",
    r"\bpassword\b",
    r"\bpin\b",
    r"\bpasscode\b",
    r"\bcredential(?:s)?\b",
    r"\bverification\s+code\b",
]

FINANCIAL_PATTERNS = [
    r"\bupi\b",
    r"\bpayment\b",
    r"\bpay\b",
    r"\btransfer\b",
    r"\bbank\b",
    r"\brefund\b",
    r"\bmoney\b",
    r"\btransaction\b",
    r"\bdebit\b",
    r"\bcredit\b",
]

IMPERSONATION_PATTERNS = [
    r"\bbank\b",
    r"\bpaytm\b",
    r"\bphonepe\b",
    r"\bgoogle\s*pay\b",
    r"\bamazon\b",
    r"\bflipkart\b",
    r"\bgovernment\b",
    r"\bincome\s*tax\b",
    r"\bcustoms\b",
    r"\bpolice\b",
    r"\bcourier\b",
    r"\bdelivery\b",
]

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s]+",
    re.IGNORECASE,
)


def _count_matches(
    text: str,
    patterns: list[str],
) -> int:
    return sum(
        1
        for pattern in patterns
        if re.search(pattern, text, re.IGNORECASE)
    )


def _extract_urls(text: str) -> list[str]:
    return URL_PATTERN.findall(text)


def _dedupe_strings(items: Iterable[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _url_recommendations(signals: list[ThreatSignal]) -> list[str]:
    mapping = {
        "url_shortener": "Do not trust shortened links. Open the official site directly instead of following a redirect.",
        "credential_request": "Never share OTPs, passwords, PINs, or account codes with a site you reached from a suspicious URL.",
        "account_targeting": "Verify the destination through an official app or trusted contact before entering credentials.",
        "suspicious_hostname": "Manually type the official domain or use a trusted bookmark instead of opening this link.",
        "payment_context": "Independently verify the recipient and payment request before sending money or credentials.",
        "suspicious_keywords": "Be careful with urgency, login, verification, or payment language in the URL itself.",
        "ip_address_host": "This URL uses an IP address instead of a normal hostname; confirm it is expected before visiting.",
    }

    recommendations: list[str] = []
    for signal in signals:
        if signal.indicator_type in mapping:
            recommendations.append(mapping[signal.indicator_type])

    return _dedupe_strings(recommendations)[:4]


def build_recommendations_from_indicators(signals: Iterable[ThreatSignal]) -> list[str]:
    """Create a concise set of recommendations from actual risks and indicators."""
    mapping = {
        "urgency_language": "Do not act under time pressure. Verify the request through an official channel before responding.",
        "account_targeting": "Verify the account or verification request through the official app or trusted support route before taking action.",
        "credential_request": "Never share OTPs, passwords, PINs, or account codes with anyone who contacted you unexpectedly.",
        "financial_context": "Independently verify the recipient and payment details before sending money or credentials.",
        "payment_context": "Independently verify the recipient and payment request before transferring funds.",
        "possible_impersonation": "Contact the person or company through a known trusted channel instead of the message or link itself.",
        "suspicious_link_presence": "Do not open the link. Type the official website into your browser or use a trusted bookmark.",
        "url_shortener": "Do not trust shortened links. Open the official site directly instead of following a redirect.",
        "suspicious_hostname": "Manually type the official domain or use a trusted bookmark instead of opening this link.",
        "suspicious_keywords": "Be careful with urgency, login, verification, or payment language in the destination or message.",
        "ip_address_host": "This destination uses an IP address instead of a normal hostname; confirm it is expected before visiting.",
    }

    recommendations: list[str] = []
    for signal in signals:
        recommendation = mapping.get(signal.indicator_type)
        if recommendation:
            recommendations.append(recommendation)

    return _dedupe_strings(recommendations)[:5]


def _safe_url_text(value: str) -> str:
    return value.strip().replace("\r", "").replace("\n", "")


def normalize_and_validate_url(candidate: str) -> str:
    """Validate a user-submitted URL without opening it."""
    url = _safe_url_text(candidate)
    if not url:
        raise ValueError("URL is required.")

    if len(url) > 2048:
        raise ValueError("URL is too long to analyze safely.")

    if any(ch.isspace() for ch in url):
        raise ValueError("URL contains whitespace and cannot be analyzed safely.")

    if not re.match(r"^(?:https?|ftp)://", url, flags=re.IGNORECASE):
        raise ValueError("Use a valid http:// or https:// URL.")

    parsed = urlsplit(url)
    if not parsed.netloc:
        raise ValueError("URL does not contain a valid hostname.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL hostname is missing or invalid.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        # Integer handling is intentionally not done here. Only the
        # structure is evaluated; the URL is never opened.
        pass

    return url


def analyze_url(raw_url: str) -> RiskAnalysis:
    """Analyze a URL using safe local structural heuristics only."""
    url = normalize_and_validate_url(raw_url)
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    port = parsed.port
    scheme = parsed.scheme.lower()

    signals: list[ThreatSignal] = []
    score = 0
    score_factors: dict[str, int] = {
        "url_shortener": 0,
        "credential_request": 0,
        "suspicious_keywords": 0,
        "suspicious_hostname": 0,
        "payment_context": 0,
        "ip_address_host": 0,
        "suspicious_path": 0,
        "suspicious_query": 0,
        "suspicious_tld": 0,
        "encoded_chars": 0,
    }

    if scheme not in {"http", "https"}:
        score += 35
        score_factors["suspicious_hostname"] += 35
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The URL uses a non-browser scheme and should not be trusted as a normal web destination.",
                severity="high",
                evidence={"scheme": scheme},
            )
        )

    if not hostname:
        raise ValueError("URL hostname is missing or invalid.")

    if hostname.startswith("xn--"):
        score += 14
        score_factors["suspicious_hostname"] += 14
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The hostname uses punycode, which can disguise a malicious destination.",
                severity="medium",
                evidence={"hostname": hostname},
            )
        )

    try:
        ipaddress.ip_address(hostname)
        score += 38
        score_factors["ip_address_host"] += 38
        signals.append(
            ThreatSignal(
                indicator_type="ip_address_host",
                description="The URL points to an IP address instead of a normal domain name.",
                severity="high",
                evidence={"hostname": hostname},
            )
        )
    except ValueError:
        pass

    suspicious_tlds = {"tk", "ml", "ga", "cf", "xyz", "club", "top", "icu", "bid", "loan"}
    hostname_parts = hostname.split(".")
    tld = hostname_parts[-1] if hostname_parts else ""
    if tld in suspicious_tlds:
        score += 20
        score_factors["suspicious_tld"] += 20
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The domain uses a high-risk top-level domain commonly associated with scam or phishing infrastructure.",
                severity="medium",
                evidence={"tld": tld},
            )
        )

    if hostname.count(".") > 3:
        score += 12
        score_factors["suspicious_hostname"] += 12
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The hostname has excessive subdomain depth, which is commonly used in phishing infrastructure.",
                severity="medium",
                evidence={"subdomain_depth": hostname.count(".")},
            )
        )

    if "@" in netloc:
        score += 18
        score_factors["suspicious_hostname"] += 18
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The URL contains embedded credentials in the authority section, which is unusual in legitimate destinations.",
                severity="high",
                evidence={"netloc": netloc},
            )
        )

    if port is not None and port not in {80, 443}:
        score += 16
        score_factors["suspicious_hostname"] += 16
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The URL uses an unusual port, which can hide or redirect intended traffic.",
                severity="medium",
                evidence={"port": port},
            )
        )

    shorteners = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "goo.gl", "tiny.cc", "shorturl.at", "buff.ly"}
    if any(hostname == item or hostname.endswith(f".{item}") for item in shorteners):
        score += 28
        score_factors["url_shortener"] += 28
        signals.append(
            ThreatSignal(
                indicator_type="url_shortener",
                description="The URL appears to use a URL shortener, which can mask the final destination.",
                severity="high",
                evidence={"hostname": hostname},
            )
        )

    suspicious_keyword_patterns = [
        "login", "verify", "verification", "secure", "account", "bank",
        "payment", "update", "confirm", "claim", "otp", "password", "signin",
        "invoice", "kyc", "security", "urgent", "suspend", "refund", "transfer",
    ]
    keyword_hits = [term for term in suspicious_keyword_patterns if re.search(rf"{re.escape(term)}", hostname + " " + path + " " + query, flags=re.IGNORECASE)]
    if keyword_hits:
        score += min(28, len(keyword_hits) * 8)
        score_factors["suspicious_keywords"] += min(28, len(keyword_hits) * 8)
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_keywords",
                description="The destination contains login, verification, or financial language commonly associated with scam or phishing flows.",
                severity="high",
                evidence={"keywords": keyword_hits[:5]},
            )
        )

    if len(path) > 220 or len(query) > 220:
        score += 14
        score_factors["suspicious_path"] += 14
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_path",
                description="The URL has an unusually long path or query string, which is often used to hide malicious destinations.",
                severity="medium",
                evidence={"path_length": len(path), "query_length": len(query)},
            )
        )

    if "//" in path or path.count("/") > 8:
        score += 10
        score_factors["suspicious_path"] += 10
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_path",
                description="The URL structure contains abnormal path complexity that may be used for deception or redirection.",
                severity="medium",
                evidence={"path": path[:200]},
            )
        )

    if re.search(r"[%@]+", url):
        score += 12
        score_factors["encoded_chars"] += 12
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The URL contains encoded or suspicious characters that may obfuscate the real destination.",
                severity="medium",
                evidence={"tokens": ["%", "@"]},
            )
        )

    encoded_matches = re.findall(r"%[0-9A-Fa-f]{2}", url)
    if encoded_matches:
        score += min(18, 6 * len(encoded_matches))
        score_factors["encoded_chars"] += min(18, 6 * len(encoded_matches))
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_hostname",
                description="The URL contains encoded URL characters and should be inspected carefully before use.",
                severity="medium",
                evidence={"encoded_count": len(encoded_matches)},
            )
        )

    if any(token in hostname for token in ["login", "verify", "secure", "account", "update", "confirm"]) or any(token in (path + query + fragment).lower() for token in ["login", "otp", "pay", "bank", "verify"]):
        score += 8
        score_factors["credential_request"] += 8
        signals.append(
            ThreatSignal(
                indicator_type="credential_request",
                description="The URL includes credential or login language that may indicate phishing or credential theft.",
                severity="high",
                evidence={"keywords": [token for token in ["login", "verify", "secure", "account", "update", "confirm", "otp", "pay", "bank"] if token in (hostname + path + query + fragment).lower()]},
            )
        )

    if any(token in (hostname + path + query + fragment).lower() for token in ["pay", "payment", "transfer", "bank", "refund", "invoice"]):
        score += 12
        score_factors["payment_context"] += 12
        signals.append(
            ThreatSignal(
                indicator_type="payment_context",
                description="The destination references payment or financial activity, which heightens scam risk if it arrives unsolicited.",
                severity="high",
                evidence={"keywords": [token for token in ["pay", "payment", "transfer", "bank", "refund", "invoice"] if token in (hostname + path + query + fragment).lower()]},
            )
        )

    score = min(100, max(0, score))

    if score >= 80:
        prediction = "high_risk"
        threat_type = "Potential Phishing / Fraudulent URL"
    elif score >= 60:
        prediction = "suspicious"
        threat_type = "Suspicious URL"
    elif score >= 30:
        prediction = "needs_verification"
        threat_type = "URL Needs Verification"
    else:
        prediction = "low_risk"
        threat_type = "No Strong URL Risk Indicators"

    confidence = min(98.0, 58.0 + (len(signals) * 5.0) + min(10.0, score / 10.0))

    explanation = {
        "engine": "local_url_structural_analysis",
        "engine_version": "1.0.0",
        "summary": "Risk was estimated from safe, local URL structure checks without opening the submitted destination.",
        "source": "local structural analysis",
        "external_threat_intelligence": {
            "available": False,
            "checked": False,
            "reason": "No API key was configured for Safe Browsing or PhishTank.",
        },
        "components": {
            "scheme": scheme,
            "hostname": hostname,
            "path_length": len(path),
            "query_length": len(query),
            "subdomain_depth": hostname.count("."),
            "is_ip_host": bool(hostname and hostname.replace(".", "").isdigit()),
            "has_encoded_chars": bool(encoded_matches),
            "has_shortener": any(hostname == item or hostname.endswith(f".{item}") for item in shorteners),
            "has_dynamic_query": bool(query),
            "normalized": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)),
        },
    }

    return RiskAnalysis(
        risk_score=score,
        confidence=confidence,
        threat_type=threat_type,
        prediction=prediction,
        signals=signals,
        features={
            "hostname": hostname,
            "scheme": scheme,
            "path_length": len(path),
            "query_length": len(query),
            "subdomain_depth": hostname.count("."),
            "has_shortener": any(hostname == item or hostname.endswith(f".{item}") for item in shorteners),
            "is_ip_host": bool(hostname and hostname.replace(".", "").isdigit()),
            "encoded_count": len(encoded_matches),
            "keyword_hits": sorted(set(keyword_hits)),
            "port": port,
            "external_threat_intelligence_available": False,
        },
        explanation=explanation,
        recommendations=_url_recommendations(signals),
        model_name="scamshield-url-rules",
        model_version="1.0.0",
        source="local_url_structural_analysis",
    )


def fuse_risk_signals(
    *,
    rule_signals: list[ThreatSignal] | None = None,
    ml_signal: ThreatSignal | None = None,
    url_signals: list[ThreatSignal] | None = None,
    qr_signals: list[ThreatSignal] | None = None,
    ocr_signals: list[ThreatSignal] | None = None,
    threat_intel_signals: list[ThreatSignal] | None = None,
    base_score: int | None = None,
    base_confidence: float | None = None,
    base_threat_type: str | None = None,
    base_prediction: str | None = None,
) -> RiskAnalysis:
    """Combine explainable signal sources into a transparent risk score without naive averaging."""
    signals: list[ThreatSignal] = []
    for group in (
        rule_signals or [],
        url_signals or [],
        qr_signals or [],
        ocr_signals or [],
        threat_intel_signals or [],
    ):
        signals.extend(group)

    if ml_signal is not None:
        signals.append(ml_signal)

    signal_weights = {
        "urgency_language": 10,
        "account_targeting": 12,
        "credential_request": 18,
        "financial_context": 14,
        "possible_impersonation": 10,
        "suspicious_link_presence": 12,
        "url_shortener": 16,
        "suspicious_hostname": 14,
        "suspicious_keywords": 12,
        "payment_context": 15,
        "ip_address_host": 18,
        "suspicious_path": 8,
        "suspicious_tld": 10,
        "encoded_chars": 6,
    }

    weighted_score = 0
    for signal in signals:
        weighted_score += signal_weights.get(signal.indicator_type, 5)

    if base_score is not None:
        weighted_score = max(weighted_score, int(base_score * 0.75))

    risk_score = min(100, max(5, weighted_score + (base_score or 0) // 6))
    if not signals:
        risk_score = base_score if base_score is not None else 0

    if risk_score >= 80:
        threat_type = base_threat_type or "Potential Phishing / Fraudulent Content"
        prediction = base_prediction or "high_risk"
    elif risk_score >= 60:
        threat_type = base_threat_type or "Suspicious Content"
        prediction = base_prediction or "suspicious"
    elif risk_score >= 30:
        threat_type = base_threat_type or "Needs Verification"
        prediction = base_prediction or "needs_verification"
    else:
        threat_type = base_threat_type or "No Strong Risk Indicators"
        prediction = base_prediction or "low_risk"

    confidence = base_confidence if base_confidence is not None else max(50.0, min(96.0, 50.0 + (len(signals) * 5.0)))
    recommendations = build_recommendations_from_indicators(signals)
    if not recommendations and base_threat_type:
        recommendations = [
            "Do not act under time pressure. Verify through the official app or site.",
            "Never share OTPs, passwords, or PINs with a sender you only met through an unknown channel.",
        ]

    return RiskAnalysis(
        risk_score=risk_score,
        confidence=confidence,
        threat_type=threat_type,
        prediction=prediction,
        signals=_dedupe_strings([f"{s.indicator_type}:{s.description}" for s in signals]) if False else signals,
        features={
            "signal_count": len(signals),
            "signal_types": sorted({signal.indicator_type for signal in signals}),
            "base_score": base_score,
            "ml_signal_present": ml_signal is not None,
        },
        explanation={
            "engine": "multi_signal_fusion",
            "engine_version": "1.0.0",
            "summary": "Risk was fused from multiple signal sources using weighted explainable indicators instead of a blind average.",
            "signal_sources": {
                "rule": bool(rule_signals),
                "ml": ml_signal is not None,
                "url": bool(url_signals),
                "qr": bool(qr_signals),
                "ocr": bool(ocr_signals),
                "threat_intel": bool(threat_intel_signals),
            },
            "weighted_score_breakdown": {
                signal.indicator_type: signal_weights.get(signal.indicator_type, 5) for signal in signals
            },
        },
        recommendations=recommendations,
        model_name="scamshield-risk-fusion",
        model_version="1.0.0",
        source="multimodal_fusion",
    )


def analyze_message(message: str) -> RiskAnalysis:
    """
    Analyze a message using an explainable baseline rule engine.

    This is intentionally a baseline engine, not a trained ML model.
    It is designed to provide deterministic risk signals until the
    production NLP model is integrated.
    """
    text = message.strip()

    urgency_count = _count_matches(text, URGENCY_PATTERNS)
    account_count = _count_matches(text, ACCOUNT_PATTERNS)
    credential_count = _count_matches(text, CREDENTIAL_PATTERNS)
    financial_count = _count_matches(text, FINANCIAL_PATTERNS)
    impersonation_count = _count_matches(
        text,
        IMPERSONATION_PATTERNS,
    )
    urls = _extract_urls(text)

    signals: list[ThreatSignal] = []

    if urgency_count:
        signals.append(
            ThreatSignal(
                indicator_type="urgency_language",
                description=(
                    "The message uses pressure or time-sensitive "
                    "language to encourage immediate action."
                ),
                severity="high",
                evidence={
                    "matches": urgency_count,
                },
            )
        )

    if account_count:
        signals.append(
            ThreatSignal(
                indicator_type="account_targeting",
                description=(
                    "The message references account access, "
                    "verification, KYC, or account suspension."
                ),
                severity="high",
                evidence={
                    "matches": account_count,
                },
            )
        )

    if credential_count:
        signals.append(
            ThreatSignal(
                indicator_type="credential_request",
                description=(
                    "The message references OTPs, passwords, "
                    "PINs, passcodes, or credentials."
                ),
                severity="critical",
                evidence={
                    "matches": credential_count,
                },
            )
        )

    if financial_count:
        signals.append(
            ThreatSignal(
                indicator_type="financial_context",
                description=(
                    "The message contains payment, banking, "
                    "transaction, or money-related language."
                ),
                severity="high",
                evidence={
                    "matches": financial_count,
                },
            )
        )

    if impersonation_count:
        signals.append(
            ThreatSignal(
                indicator_type="possible_impersonation",
                description=(
                    "The message mentions an organization or "
                    "authority that could be used for impersonation."
                ),
                severity="medium",
                evidence={
                    "matches": impersonation_count,
                },
            )
        )

    if urls:
        signals.append(
            ThreatSignal(
                indicator_type="suspicious_link_presence",
                description=(
                    "The message contains one or more URLs that "
                    "should be verified before opening."
                ),
                severity="high",
                evidence={
                    "url_count": len(urls),
                },
            )
        )

    # ---------------------------------------------------------
    # Baseline scoring
    # ---------------------------------------------------------
    score = 0

    score += min(20, urgency_count * 10)
    score += min(20, account_count * 5)
    score += min(25, credential_count * 15)
    score += min(15, financial_count * 5)
    score += min(15, impersonation_count * 5)
    score += min(15, len(urls) * 10)

    # Strong combinations increase risk.
    if urgency_count and account_count:
        score += 10

    if credential_count and (account_count or financial_count):
        score += 15

    if urls and (account_count or credential_count):
        score += 10

    score = min(score, 100)

    # ---------------------------------------------------------
    # Threat classification
    # ---------------------------------------------------------
    if score >= 80:
        prediction = "high_risk"
        threat_type = "Potential Phishing / Social Engineering"
    elif score >= 60:
        prediction = "suspicious"
        threat_type = "Potential Scam"
    elif score >= 30:
        prediction = "needs_verification"
        threat_type = "Suspicious Message"
    else:
        prediction = "low_risk"
        threat_type = "No Strong Scam Indicators"

    # This is baseline-engine confidence, not a calibrated ML
    # probability. A trained model will replace this later.
    confidence = min(
        98.0,
        55.0 + (len(signals) * 8.0),
    )

    features = {
        "urgency_matches": urgency_count,
        "account_matches": account_count,
        "credential_matches": credential_count,
        "financial_matches": financial_count,
        "impersonation_matches": impersonation_count,
        "url_count": len(urls),
        "signal_count": len(signals),
    }

    explanation = {
        "engine": "baseline_rules",
        "engine_version": "1.0.0",
        "summary": (
            "Risk was estimated from explainable message-level "
            "fraud indicators."
        ),
    }

    return RiskAnalysis(
        risk_score=score,
        confidence=confidence,
        threat_type=threat_type,
        prediction=prediction,
        signals=signals,
        features=features,
        explanation=explanation,
    )