"""Combine semantic provider output with deterministic message signals."""

from dataclasses import replace
import re

from app.core.config import settings
from app.schemas.scans import MessageFraudAssessment, MessageFraudIndicatorAssessment
from app.services.openrouter_messages import ProviderResult
from app.services.risk_engine import RiskAnalysis, ThreatSignal
from app.services.scan_privacy import safe_indicator_description


def _verdict(score: int, *, failed_closed: bool) -> str:
    if failed_closed and score < 30:
        return "unverified"
    if score >= 60:
        return "high_risk"
    if score >= 30:
        return "suspicious"
    return "safe"


_EVIDENCE_PATTERNS = {
    "urgency_language": r"\b(?:urgent|immediately|instantly|now|today|asap|last warning)\b",
    "account_targeting": r"\b(?:account|login|sign\s*in|verification|verify|kyc|blocked|suspended)\b",
    "credential_request": r"\b(?:otp|password|pin|passcode|credential|verification code)\b",
    "financial_context": r"\b(?:upi|payment|pay|transfer|bank|refund|money|transaction|debit|credit)\b",
    "possible_impersonation": r"\b(?:bank|paytm|phonepe|amazon|flipkart|government|police|courier|delivery)\b",
    "suspicious_link_presence": r"(?:https?://|www\.)[^\s]+",
    "prize_bait": r"\b(?:win|won|winner|prize|giveaway|lottery|reward|bonus|cashback|refund|claim)\b",
    "call_to_action": r"\b(?:click|tap|open|follow|visit|claim|collect|redeem)\b",
    "cash_prize_click_combination": r"\b(?:win|prize|giveaway|reward)\b.{0,120}\b(?:click|tap|link)\b|\b(?:click|tap|link)\b.{0,120}\b(?:win|prize|giveaway|reward)\b",
}


def _excerpt(message: str, indicator_type: str) -> str:
    pattern = _EVIDENCE_PATTERNS.get(indicator_type)
    match = re.search(pattern, message, re.IGNORECASE) if pattern else None
    if match:
        start = max(0, match.start() - 45)
        end = min(len(message), max(match.end() + 45, start + 1))
        return message[start:end].strip()[:160]
    return message[:160].strip()


def _rules_assessment(message: str, analysis: RiskAnalysis, provider_status: str) -> MessageFraudAssessment:
    score = analysis.risk_score
    verdict = _verdict(score, failed_closed=True)
    if score == 0:
        summary = "No strong indicator was found by deterministic rules. AI review was unavailable, so this message is unverified."
    else:
        summary = "Deterministic message rules identified one or more social-engineering indicators."
        if verdict == "unverified":
            summary += " AI review was unavailable; a low rule score does not establish safety."
    indicators = [
        MessageFraudIndicatorAssessment(
            indicator_type=signal.indicator_type,
            severity=signal.severity,
            evidence_excerpt=_excerpt(message, signal.indicator_type),
            explanation=safe_indicator_description(signal.indicator_type),
        )
        for signal in analysis.signals[:8]
    ]
    recommendations = [
        "Verify requests through an official app or contact channel before clicking, paying, or sharing account details."
    ]
    return MessageFraudAssessment(
        risk_score=score,
        verdict=verdict,
        summary=summary[:360],
        indicators=indicators,
        recommendations=recommendations,
        analysis_source="rules_only",
        provider_status=provider_status,
        model=None,
    )


def combine_message_assessment(
    message: str,
    rules: RiskAnalysis,
    provider: ProviderResult,
) -> tuple[RiskAnalysis, MessageFraudAssessment]:
    ai = provider.assessment
    if ai is None:
        fallback_assessment = _rules_assessment(message, rules, provider.status)
        rule_explanation = (
            "Rule-based review found no strong indicators; provider review was unavailable."
            if fallback_assessment.verdict == "unverified"
            else fallback_assessment.summary
        )
        features = {
            **rules.features,
            "analysis_source": "rules_only",
            "provider_status": provider.status,
        }
        analysis = replace(
            rules,
            confidence=None,
            prediction=fallback_assessment.verdict,
            threat_type=("Unverified message assessment" if fallback_assessment.verdict == "unverified" else rules.threat_type),
            features=features,
            explanation={
                "engine": "message_rules_only",
                "summary": rule_explanation,
                "analysis_source": "rules_only",
                "provider_status": provider.status,
                "score_mapping": "0-29 unverified without AI; 30-59 suspicious; 60-100 high risk",
                "recommendations": fallback_assessment.recommendations,
            },
            model_name="scamshield-message-rules",
            model_version=rules.model_version,
            source="message_rules_only",
        )
        return analysis, fallback_assessment

    score = max(rules.risk_score, ai.risk_score)
    verdict = _verdict(score, failed_closed=False)
    signals: dict[str, ThreatSignal] = {item.indicator_type: item for item in rules.signals}
    for item in ai.indicators:
        signals[item.indicator_type] = ThreatSignal(
            indicator_type=item.indicator_type,
            description=item.explanation,
            severity=item.severity,
            # Excerpts are returned in the immediate assessment only. The
            # privacy sanitizer removes this key before persistence.
            evidence={"evidence_excerpt": item.evidence_excerpt},
        )
    merged_signals = list(signals.values())[:8]
    assessment_summary = ai.summary
    if rules.risk_score > ai.risk_score:
        assessment_summary = f"{assessment_summary} Deterministic rules raised the final score."
    assessment = MessageFraudAssessment(
        risk_score=score,
        verdict=verdict,
        summary=assessment_summary[:360],
        indicators=[
            MessageFraudIndicatorAssessment(
                indicator_type=item.indicator_type,
                severity=item.severity,
                evidence_excerpt=item.evidence_excerpt,
                explanation=item.explanation,
            )
            for item in ai.indicators
        ] or [
            MessageFraudIndicatorAssessment(
                indicator_type=item.indicator_type,
                severity=item.severity,
                evidence_excerpt=_excerpt(message, item.indicator_type),
                explanation=safe_indicator_description(item.indicator_type),
            )
            for item in rules.signals[:8]
        ],
        recommendations=list(dict.fromkeys(ai.recommendations))[:5],
        analysis_source="ai_plus_rules",
        provider_status="ok",
        model=settings.openrouter_model,
        latency_ms=provider.latency_ms,
    )
    features = {
        **rules.features,
        "analysis_source": "ai_plus_rules",
        "provider_status": "ok",
        "ai_indicator_types": [item.indicator_type for item in ai.indicators],
    }
    analysis = replace(
        rules,
        risk_score=score,
        confidence=None,
        prediction=verdict,
        threat_type={"safe": "No Strong Scam Indicators", "suspicious": "Potential Scam", "high_risk": "Potential Phishing / Social Engineering"}[verdict],
        signals=merged_signals,
        features=features,
        explanation={
            "engine": "openrouter_ai_plus_rules",
            "summary": assessment.summary,
            "analysis_source": "ai_plus_rules",
            "provider_status": "ok",
            "model": settings.openrouter_model,
            "latency_ms": provider.latency_ms,
            "score_mapping": "0-29 safe; 30-59 suspicious; 60-100 high risk",
            "recommendations": assessment.recommendations,
        },
        model_name="openrouter-message+rules",
        model_version=settings.openrouter_model,
        source="message_ai_plus_rules",
    )
    return analysis, assessment
