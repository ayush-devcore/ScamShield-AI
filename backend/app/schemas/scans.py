from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


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


class ScanResponse(BaseModel):
    id: UUID
    input_type: str
    status: str
    risk_score: int | None
    confidence: float | None
    threat_type: str | None
    redacted_preview: str | None = None
    created_at: datetime


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