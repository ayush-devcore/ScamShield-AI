from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import User, UserNotification
from app.db.session import get_db
from app.schemas.notifications import NotificationItem, NotificationList


router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=NotificationList)
async def list_notifications(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> NotificationList:
    rows = (await db.execute(
        select(UserNotification)
        .where(UserNotification.user_id == current_user.id)
        .order_by(UserNotification.created_at.desc())
        .limit(50)
    )).scalars().all()
    unread = (await db.execute(
        select(func.count(UserNotification.id)).where(
            UserNotification.user_id == current_user.id,
            UserNotification.read_at.is_(None),
        )
    )).scalar_one()
    return NotificationList(
        items=[NotificationItem.model_validate(row, from_attributes=True) for row in rows],
        unread_count=int(unread or 0),
    )


@router.post("/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_notification_read(
    notification_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(
        update(UserNotification)
        .where(UserNotification.id == notification_id, UserNotification.user_id == current_user.id)
        .values(read_at=func.coalesce(UserNotification.read_at, datetime.now(timezone.utc)))
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Notification not found.")
    await db.commit()


@router.post("/read-all", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    await db.execute(
        update(UserNotification)
        .where(UserNotification.user_id == current_user.id, UserNotification.read_at.is_(None))
        .values(read_at=datetime.now(timezone.utc))
    )
    await db.commit()
