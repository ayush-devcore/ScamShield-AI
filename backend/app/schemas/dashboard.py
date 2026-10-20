from datetime import datetime
from typing import Literal

from pydantic import BaseModel


ScanStatus = Literal[
    "queued",
    "analyzing",
    "critical",
    "high",
    "medium",
    "safe",
]


class DashboardStats(BaseModel):
    total_scans: int
    high_risk: int
    medium_risk: int
    safe_scans: int


class ActivityPoint(BaseModel):
    day: str
    scans: int


class ThreatDistributionItem(BaseModel):
    name: str
    value: float


class RecentScanItem(BaseModel):
    id: str
    title: str
    type: str
    score: int | None
    confidence: float | None
    status: ScanStatus
    date: datetime


class DashboardResponse(BaseModel):
    stats: DashboardStats
    threat_activity: list[ActivityPoint]
    threat_distribution: list[ThreatDistributionItem]
    recent_scans: list[RecentScanItem]