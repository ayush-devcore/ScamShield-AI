import logging

from fastapi import APIRouter, Depends, HTTPException
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
        result.scalar_one()
    except Exception as exc:
        logger.warning("Readiness check failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Service temporarily unavailable.") from None

    return {"service": "ScamShield AI", "status": "healthy"}
