from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.sandbox import SandboxJobResponse


class MessageScanRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=10000,
    )


class URLScanRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048,
    )


class QRScanRequest(BaseModel):
    payload: str | None = Field(
        default=None,
        max_length=4096,
    )


class ScreenshotScanRequest(BaseModel):
    filename: str | None = None
    content_type: str | None = None


class ThreatIndicatorResponse(BaseModel):
    id: UUID
    indicator_type: str
    description: str
    severity: str
    evidence: dict | None


class AnalysisResultResponse(BaseModel):
    id: UUID
    model_name: str
    model_version: str
    prediction: str
    probability: float | None
    features: dict | None
    explanation: dict | None
    created_at: datetime


class MessageFraudIndicatorAssessment(BaseModel):
    indicator_type: Literal[
        "urgency_language", "account_targeting", "credential_request", "financial_context",
        "possible_impersonation", "suspicious_link_presence", "prize_bait", "call_to_action",
        "cash_prize_click_combination", "verification_threat", "payment_manipulation",
        "impersonation_attempt", "credential_theft", "benign_promotion_context",
    ]
    severity: Literal["low", "medium", "high", "critical"]
    evidence_excerpt: str = Field(max_length=160)
    explanation: str = Field(max_length=280)


class MessageFraudAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    verdict: Literal["safe", "suspicious", "high_risk", "unverified"]
    summary: str = Field(max_length=360)
    indicators: list[MessageFraudIndicatorAssessment] = Field(max_length=8)
    recommendations: list[str] = Field(max_length=5)
    analysis_source: Literal["ai_plus_rules", "rules_only"]
    provider_status: Literal[
        "ok", "not_configured", "rate_limited", "usage_limit_reached", "limit_backend_unavailable",
        "concurrency_limited", "timeout", "provider_error", "provider_unavailable", "invalid_api_key",
        "invalid_json", "invalid_schema", "empty_response", "input_too_long",
    ]
    model: str | None = None
    latency_ms: int | None = Field(default=None, ge=0)


class ScanResponse(BaseModel):
    id: UUID
    input_type: str
    status: str
    risk_score: int | None
    confidence: float | None
    threat_type: str | None
    redacted_preview: str | None = None
    created_at: datetime
    analysis: AnalysisResultResponse | None = None
    indicators: list[ThreatIndicatorResponse] | None = None
    message_assessment: MessageFraudAssessment | None = None


class UrlDatasetLookupResponse(BaseModel):
    status: str
    match_type: str | None = None
    source_label: str | None = None
    dataset_name: str | None = None
    record_source: str | None = None
    dataset_fingerprint: str | None = None
    imported_at: datetime | None = None
    recorded_at: datetime | None = None


class UrlRiskAssessmentResponse(BaseModel):
    verdict: str
    risk_score: int | None = None
    method: str
    explanation: str
    indicators: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class UrlDecisionResponse(BaseModel):
    outcome: str
    dataset_lookup: UrlDatasetLookupResponse
    risk_assessment: UrlRiskAssessmentResponse | None = None
    reachability: str
    reason: str | None = None
    scan: ScanResponse | None = None
    sandbox_job: SandboxJobResponse | None = None


class ScanDetailResponse(BaseModel):
    id: UUID
    input_type: str
    status: str
    risk_score: int | None
    confidence: float | None
    threat_type: str | None
    created_at: datetime
    analysis: AnalysisResultResponse | None
    indicators: list[ThreatIndicatorResponse]
