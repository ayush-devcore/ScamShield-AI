from datetime import datetime
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
