from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SandboxCapabilities(BaseModel):
    url_browser_runtime: bool
    restricted_egress: bool
    file_static_analysis: bool
    file_detonation: bool


class SandboxStatusResponse(BaseModel):
    status: str
    available: bool
    message: str
    capabilities: SandboxCapabilities
    reason: str | None = None


class SandboxUrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class SandboxJobResponse(BaseModel):
    id: UUID
    scan_id: UUID
    state: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    observations: dict | None = None
    report: dict | None = None

    model_config = ConfigDict(from_attributes=True)


class SandboxCancelResponse(BaseModel):
    id: UUID
    state: str
    cancel_requested: bool


class SandboxUnavailableResponse(BaseModel):
    status: str
    code: str
    message: str
