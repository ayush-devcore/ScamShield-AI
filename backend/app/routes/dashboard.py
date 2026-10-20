from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import Scan, User
from app.db.session import get_db
from app.schemas.dashboard import (
    ActivityPoint,
    DashboardResponse,
    DashboardStats,
    RecentScanItem,
    ThreatDistributionItem,
)


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


def display_status(scan: Scan) -> str:
    """Return the scan lifecycle/final status for the dashboard."""

    if scan.status in {"queued", "analyzing"}:
        return scan.status

    if scan.status in {"critical", "high", "medium", "safe"}:
        return scan.status

    # Fallback for unexpected legacy rows.
    if scan.risk_score is None:
        return "queued"

    if scan.risk_score >= 80:
        return "critical"

    if scan.risk_score >= 60:
        return "high"

    if scan.risk_score >= 30:
        return "medium"

    return "safe"

def scan_title(scan: Scan) -> str:
    """Create a safe display title without exposing raw input."""
    if scan.redacted_preview:
        preview = scan.redacted_preview.strip().replace("\n", " ")
        if preview:
            return preview[:80]

    return f"{scan.input_type.title()} scan"


@router.get(
    "",
    response_model=DashboardResponse,
)
async def get_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardResponse:
    # ---------------------------------------------------------
    # 1. Dashboard statistics
    # ---------------------------------------------------------
    stats_result = await db.execute(
    select(
        func.count(Scan.id).label("total"),
        func.count(
            case(
                (
                    Scan.status.in_(["critical", "high"]),
                    1,
                )
            )
        ).label("high_risk"),
        func.count(
            case(
                (
                    Scan.status == "medium",
                    1,
                )
            )
        ).label("medium_risk"),
        func.count(
            case(
                (
                    Scan.status == "safe",
                    1,
                )
            )
        ).label("safe_scans"),
    ).where(
        Scan.user_id == current_user.id,
    )
)

    stats = stats_result.one()

    dashboard_stats = DashboardStats(
        total_scans=stats.total or 0,
        high_risk=stats.high_risk or 0,
        medium_risk=stats.medium_risk or 0,
        safe_scans=stats.safe_scans or 0,
    )

    # ---------------------------------------------------------
    # 2. Last 7 days activity
    # ---------------------------------------------------------
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=6)

    activity_result = await db.execute(
        select(
            func.date(Scan.created_at).label("scan_date"),
            func.count(Scan.id).label("scan_count"),
        )
        .where(
            Scan.user_id == current_user.id,
            Scan.created_at >= start_date,
        )
        .group_by(
            func.date(Scan.created_at),
        )
        .order_by(
            func.date(Scan.created_at),
        )
    )

    activity_rows = activity_result.all()
    activity_by_date = {
        row.scan_date: row.scan_count
        for row in activity_rows
    }

    threat_activity: list[ActivityPoint] = []

    for offset in range(7):
        day = (now - timedelta(days=6 - offset)).date()

        threat_activity.append(
            ActivityPoint(
                day=day.strftime("%a"),
                scans=activity_by_date.get(day, 0),
            )
        )

    # ---------------------------------------------------------
    # 3. Threat distribution
    # ---------------------------------------------------------
    distribution_result = await db.execute(
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
        .order_by(desc(func.count(Scan.id)))
    )

    distribution_rows = distribution_result.all()

    total_classified = sum(
        row.count for row in distribution_rows
    )

    threat_distribution: list[ThreatDistributionItem] = []

    # Keep the UI manageable: top four categories + Other.
    for row in distribution_rows[:4]:
        percentage = (
            (row.count / total_classified) * 100
            if total_classified
            else 0
        )

        threat_distribution.append(
            ThreatDistributionItem(
                name=row.threat_type,
                value=round(percentage, 1),
            )
        )

    remaining_count = sum(
        row.count for row in distribution_rows[4:]
    )

    if remaining_count:
        remaining_percentage = (
            (remaining_count / total_classified) * 100
            if total_classified
            else 0
        )

        threat_distribution.append(
            ThreatDistributionItem(
                name="Other",
                value=round(remaining_percentage, 1),
            )
        )

    # ---------------------------------------------------------
    # 4. Recent scans
    # ---------------------------------------------------------
    recent_result = await db.execute(
        select(Scan)
        .where(
            Scan.user_id == current_user.id,
        )
        .order_by(
            Scan.created_at.desc(),
        )
        .limit(5)
    )

    recent_scans = [
        RecentScanItem(
            id=str(scan.id),
            title=scan_title(scan),
            type=scan.input_type.upper(),
            score=scan.risk_score,
confidence=scan.confidence,
            status=display_status(scan),
            date=scan.created_at,
        )
        for scan in recent_result.scalars().all()
    ]

    return DashboardResponse(
        stats=dashboard_stats,
        threat_activity=threat_activity,
        threat_distribution=threat_distribution,
        recent_scans=recent_scans,
    )