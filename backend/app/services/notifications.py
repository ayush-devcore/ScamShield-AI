"""Create controlled, user-scoped notifications for real application events."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import UserNotification, UserPreference


_SECURITY_NOTIFICATIONS = {
    "login_completed": ("New sign-in", "A new authenticated session was created."),
    "password_reset_completed": ("Password updated", "The account password was updated and existing sessions were revoked."),
    "mfa_enabled": ("Recovery authenticator enabled", "Authenticator-based password recovery was enabled."),
    "mfa_disabled": ("Recovery authenticator disabled", "Authenticator-based password recovery was disabled."),
    "recovery_codes_regenerated": ("Recovery codes regenerated", "New MFA recovery codes were generated."),
    "session_revoked": ("Session revoked", "An authenticated session was revoked."),
}


async def get_user_preference(db: AsyncSession, user_id: UUID) -> UserPreference | None:
    return (await db.execute(
        select(UserPreference).where(UserPreference.user_id == user_id)
    )).scalar_one_or_none()


async def scan_history_enabled(db: AsyncSession, user_id: UUID) -> bool:
    preference = await get_user_preference(db, user_id)
    return preference.store_scan_history if preference is not None else True


async def create_scan_risk_notification(
    db: AsyncSession,
    user_id: UUID,
    classification: str,
    scan_id: UUID | None,
) -> bool:
    if classification not in {"high", "critical"}:
        return False
    preference = await get_user_preference(db, user_id)
    enabled = (preference.notify_critical_risk if classification == "critical" else preference.notify_high_risk) if preference is not None else True
    if not enabled:
        return False
    label = "Critical-risk" if classification == "critical" else "High-risk"
    db.add(UserNotification(
        user_id=user_id,
        scan_id=scan_id,
        event_type=f"scan_{classification}_risk",
        title=f"{label} scan result",
        message=f"A completed scan was classified as {classification} risk.",
        link_path=f"/threat/{scan_id}" if scan_id else None,
    ))
    return True


async def create_security_notification(
    db: AsyncSession,
    user_id: UUID,
    event_type: str,
) -> bool:
    content = _SECURITY_NOTIFICATIONS.get(event_type)
    if content is None:
        return False
    preference = await get_user_preference(db, user_id)
    if preference is not None and not preference.notify_security_events:
        return False
    db.add(UserNotification(
        user_id=user_id,
        scan_id=None,
        event_type=event_type,
        title=content[0],
        message=content[1],
    ))
    return True
