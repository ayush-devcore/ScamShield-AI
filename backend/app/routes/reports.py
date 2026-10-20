from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import Scan, User
from app.db.session import get_db
from app.schemas.reports import (
    CountDistributionItem,
    RecentReportScan,
    ReportSummaryResponse,
    RiskDistributionItem,
    TrendPoint,
)

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


@router.get(
    "",
    response_model=ReportSummaryResponse,
)
async def get_reports(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportSummaryResponse:
    base_query = select(Scan).where(Scan.user_id == current_user.id)

    total_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )
    total_scans = total_result.scalar_one() or 0

    risk_result = await db.execute(
        select(
            Scan.status,
            func.count(Scan.id).label("count"),
        )
        .where(Scan.user_id == current_user.id)
        .group_by(Scan.status)
    )

    risk_counts = {status: int(count) for status, count in risk_result.all()}

    risk_distribution = [
        RiskDistributionItem(label="critical", count=risk_counts.get("critical", 0)),
        RiskDistributionItem(label="high", count=risk_counts.get("high", 0)),
        RiskDistributionItem(label="medium", count=risk_counts.get("medium", 0)),
        RiskDistributionItem(label="safe", count=risk_counts.get("safe", 0)),
    ]

    scan_type_result = await db.execute(
        select(
            Scan.input_type,
            func.count(Scan.id).label("count"),
        )
        .where(Scan.user_id == current_user.id)
        .group_by(Scan.input_type)
        .order_by(func.count(Scan.id).desc())
    )
    scan_type_distribution = [
        CountDistributionItem(name=name, count=int(count))
        for name, count in scan_type_result.all()
    ]

    threat_type_result = await db.execute(
        select(
            Scan.threat_type,
            func.count(Scan.id).label("count"),
        )
        .where(
            Scan.user_id == current_user.id,
            Scan.threat_type.is_not(None),
            Scan.threat_type != "",
        )
        .group_by(Scan.threat_type)
        .order_by(func.count(Scan.id).desc())
    )
    threat_type_distribution = [
        CountDistributionItem(name=name, count=int(count))
        for name, count in threat_type_result.all()
    ]

    now = datetime.now(timezone.utc)
    trend_result = await db.execute(
        select(
            func.date(Scan.created_at).label("day"),
            func.count(Scan.id).label("count"),
        )
        .where(
            Scan.user_id == current_user.id,
            Scan.created_at >= now - timedelta(days=6),
        )
        .group_by(func.date(Scan.created_at))
        .order_by(func.date(Scan.created_at))
    )

    trend_by_day = {day: int(count) for day, count in trend_result.all()}
    recent_trends: list[TrendPoint] = []
    for offset in range(7):
        day = (now - timedelta(days=6 - offset)).date()
        recent_trends.append(
            TrendPoint(
                day=day.strftime("%a"),
                scans=trend_by_day.get(str(day), 0),
            )
        )

    recent_scans_result = await db.execute(
        base_query.order_by(Scan.created_at.desc()).limit(10)
    )
    recent_scans = [
        RecentReportScan(
            id=str(scan.id),
            input_type=scan.input_type,
            threat_type=scan.threat_type,
            risk_score=scan.risk_score,
            created_at=scan.created_at,
        )
        for scan in recent_scans_result.scalars().all()
    ]

    return ReportSummaryResponse(
        total_scans=total_scans,
        risk_distribution=risk_distribution,
        scan_type_distribution=scan_type_distribution,
        threat_type_distribution=threat_type_distribution,
        recent_trends=recent_trends,
        recent_scans=recent_scans,
    )
