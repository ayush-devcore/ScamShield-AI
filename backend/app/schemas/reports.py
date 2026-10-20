from datetime import datetime

from pydantic import BaseModel


class RiskDistributionItem(BaseModel):
    label: str
    count: int


class CountDistributionItem(BaseModel):
    name: str
    count: int


class TrendPoint(BaseModel):
    day: str
    scans: int


class RecentReportScan(BaseModel):
    id: str
    input_type: str
    threat_type: str | None = None
    risk_score: int | None = None
    created_at: datetime


class ReportSummaryResponse(BaseModel):
    total_scans: int
    risk_distribution: list[RiskDistributionItem]
    scan_type_distribution: list[CountDistributionItem]
    threat_type_distribution: list[CountDistributionItem]
    recent_trends: list[TrendPoint]
    recent_scans: list[RecentReportScan]
