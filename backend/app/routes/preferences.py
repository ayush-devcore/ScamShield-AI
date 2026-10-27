from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import User, UserPreference
from app.db.session import get_db
from app.schemas.preferences import AppearancePreference, NotificationPreferences, PrivacyPreferences


router = APIRouter(prefix="/preferences", tags=["Preferences"])


@router.get("/appearance", response_model=AppearancePreference)
async def get_appearance(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AppearancePreference:
    preference = (
        await db.execute(
            select(UserPreference).where(UserPreference.user_id == current_user.id)
        )
    ).scalar_one_or_none()
    return AppearancePreference(appearance=preference.appearance if preference else "dark")


@router.put("/appearance", response_model=AppearancePreference)
async def update_appearance(
    preference: AppearancePreference,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AppearancePreference:
    statement = insert(UserPreference).values(
        user_id=current_user.id,
        appearance=preference.appearance,
    ).on_conflict_do_update(
        index_elements=[UserPreference.user_id],
        set_={"appearance": preference.appearance},
    )
    await db.execute(statement)
    await db.commit()
    return preference


@router.get("/notifications", response_model=NotificationPreferences)
async def get_notification_preferences(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> NotificationPreferences:
    row = (await db.execute(select(UserPreference).where(UserPreference.user_id == current_user.id))).scalar_one_or_none()
    return NotificationPreferences(
        high_risk=row.notify_high_risk if row else True,
        critical_risk=row.notify_critical_risk if row else True,
        security_events=row.notify_security_events if row else True,
    )


@router.put("/notifications", response_model=NotificationPreferences)
async def update_notification_preferences(
    preference: NotificationPreferences,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> NotificationPreferences:
    await db.execute(insert(UserPreference).values(
        user_id=current_user.id,
        notify_high_risk=preference.high_risk,
        notify_critical_risk=preference.critical_risk,
        notify_security_events=preference.security_events,
    ).on_conflict_do_update(
        index_elements=[UserPreference.user_id],
        set_={
            "notify_high_risk": preference.high_risk,
            "notify_critical_risk": preference.critical_risk,
            "notify_security_events": preference.security_events,
        },
    ))
    await db.commit()
    return preference


@router.get("/privacy", response_model=PrivacyPreferences)
async def get_privacy_preferences(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PrivacyPreferences:
    row = (await db.execute(select(UserPreference).where(UserPreference.user_id == current_user.id))).scalar_one_or_none()
    return PrivacyPreferences(store_scan_history=row.store_scan_history if row else True)


@router.put("/privacy", response_model=PrivacyPreferences)
async def update_privacy_preferences(
    preference: PrivacyPreferences,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PrivacyPreferences:
    await db.execute(insert(UserPreference).values(
        user_id=current_user.id,
        store_scan_history=preference.store_scan_history,
    ).on_conflict_do_update(
        index_elements=[UserPreference.user_id],
        set_={"store_scan_history": preference.store_scan_history},
    ))
    await db.commit()
    return preference
