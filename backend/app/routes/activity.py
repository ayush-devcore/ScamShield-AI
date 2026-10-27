from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import AuditLog, User
from app.db.session import get_db


router = APIRouter(prefix="/activity", tags=["Security activity"])

_EVENTS = {
    "scan_completed": ("scan", "info", "Scan analysis completed."),
    "scan_high_risk": ("scan", "high", "High-risk scan result recorded."),
    "scan_critical_risk": ("scan", "critical", "Critical-risk scan result recorded."),
    "mfa_enabled": ("security", "info", "Authenticator-based password recovery was enabled."),
    "mfa_disabled": ("security", "warning", "Authenticator-based password recovery was disabled."),
    "recovery_codes_regenerated": ("security", "warning", "MFA recovery codes were regenerated."),
    "session_revoked": ("security", "warning", "An authenticated session was revoked."),
    "login_completed": ("security", "info", "A new authenticated session was created."),
    "password_reset_completed": ("security", "warning", "The account password was updated and existing sessions were revoked."),
}


@router.get("")
async def get_activity(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id, AuditLog.event_type.in_(_EVENTS))
        .order_by(AuditLog.created_at.desc())
        .limit(30)
    )).scalars().all()
    return [
        {
            "id": str(row.id),
            "event_type": row.event_type,
            "category": _EVENTS[row.event_type][0],
            "severity": _EVENTS[row.event_type][1],
            "message": _EVENTS[row.event_type][2],
            "created_at": row.created_at,
        }
        for row in rows
    ]
