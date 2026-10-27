import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db


router = APIRouter(tags=["Health"])

logger = logging.getLogger(__name__)


@router.get("/health")
async def health_check(
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(text("SELECT 1"))

        database_status = "connected"

        return {
            "service": "ScamShield AI",
            "status": "healthy",
            "database": database_status,
            "database_test": result.scalar_one(),
        }

    except Exception as exc:
        logger.exception(
            "Database health check failed: %s",
            type(exc).__name__,
        )

        return {
            "service": "ScamShield AI",
            "status": "degraded",
            "database": "disconnected",
        }