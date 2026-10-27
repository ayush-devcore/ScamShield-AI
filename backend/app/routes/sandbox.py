import re
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import SandboxJob, Scan, User
from app.db.session import get_db
from app.schemas.sandbox import (
    SandboxCancelResponse,
    SandboxJobResponse,
    SandboxStatusResponse,
    SandboxUrlRequest,
)
from app.services.notifications import scan_history_enabled
from app.services.sandbox_runtime import encrypt_target, get_sandbox_status
from app.services.scan_privacy import redact_url_for_storage
from app.services.scan_privacy import sanitize_analysis_payload
from sandbox.proxy.network_policy import is_public_address, parse_ip_literal


router = APIRouter(prefix="/sandbox", tags=["Sandbox"])
_DENIED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def validate_sandbox_url(value: str) -> None:
    if not value or len(value) > 2048 or any(character.isspace() or ord(character) < 32 for character in value):
        raise HTTPException(status_code=400, detail="Enter a valid public HTTP or HTTPS URL.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Enter a valid public HTTP or HTTPS URL.") from None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not hostname or parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=400, detail="Enter a valid public HTTP or HTTPS URL without embedded credentials.")
    if port not in {None, 80 if scheme == "http" else 443}:
        raise HTTPException(status_code=400, detail="Only standard HTTP and HTTPS ports are supported.")
    address = parse_ip_literal(hostname)
    if address is None:
        try:
            normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            raise HTTPException(status_code=400, detail="Enter a valid public HTTP or HTTPS URL.") from None
        if (
            not normalized
            or "." not in normalized
            or normalized.endswith(_DENIED_SUFFIXES)
            or any(not _HOST_LABEL.fullmatch(label) for label in normalized.split("."))
        ):
            raise HTTPException(status_code=400, detail="Only public hostnames can be analyzed.")
    elif not is_public_address(address):
        raise HTTPException(status_code=400, detail="Only public destinations can be analyzed.")


def _job_response(job: SandboxJob, scan: Scan) -> SandboxJobResponse:
    return SandboxJobResponse(
        id=job.id,
        scan_id=scan.id,
        state=job.state,
        created_at=scan.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_code=job.error_code,
        observations=sanitize_analysis_payload(job.observations),
        report=sanitize_analysis_payload(job.report),
    )


@router.get("/status", response_model=SandboxStatusResponse)
async def sandbox_status(current_user: User = Depends(get_current_user)) -> SandboxStatusResponse:
    del current_user
    return get_sandbox_status()


@router.post("/url", response_model=SandboxJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_url_sandbox(
    payload: SandboxUrlRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxJobResponse:
    validate_sandbox_url(payload.url)
    capability = get_sandbox_status()
    if not capability.available:
        raise HTTPException(status_code=503, detail="Sandbox execution is unavailable.")
    if not await scan_history_enabled(db, current_user.id):
        raise HTTPException(status_code=409, detail="Enable scan history to create a durable sandbox job.")
    try:
        encrypted_target = encrypt_target(payload.url)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Sandbox execution is unavailable.") from None

    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid4(), user_id=current_user.id, input_type="url", status="queued",
        redacted_preview=redact_url_for_storage(payload.url), created_at=now,
    )
    job = SandboxJob(
        id=uuid4(), scan_id=scan.id, target_encrypted=encrypted_target, state="queued",
    )
    db.add_all([scan, job])
    await db.commit()
    await db.refresh(scan)
    await db.refresh(job)
    return _job_response(job, scan)


@router.get("/jobs", response_model=list[SandboxJobResponse])
async def list_sandbox_jobs(
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> list[SandboxJobResponse]:
    result = await db.execute(
        select(SandboxJob, Scan).join(Scan, Scan.id == SandboxJob.scan_id)
        .where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(100)
    )
    return [_job_response(job, scan) for job, scan in result.all()]


@router.get("/jobs/{job_id}", response_model=SandboxJobResponse)
async def get_sandbox_job(
    job_id: UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> SandboxJobResponse:
    result = await db.execute(
        select(SandboxJob, Scan).join(Scan, Scan.id == SandboxJob.scan_id)
        .where(SandboxJob.id == job_id, Scan.user_id == current_user.id)
    )
    pair = result.one_or_none()
    if pair is None:
        raise HTTPException(status_code=404, detail="Sandbox job not found.")
    return _job_response(*pair)


@router.post("/jobs/{job_id}/cancel", response_model=SandboxCancelResponse)
async def cancel_sandbox_job(
    job_id: UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> SandboxCancelResponse:
    result = await db.execute(
        select(SandboxJob).join(Scan, Scan.id == SandboxJob.scan_id)
        .where(SandboxJob.id == job_id, Scan.user_id == current_user.id).with_for_update()
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Sandbox job not found.")
    if job.state in {"completed", "failed", "timed_out", "blocked"}:
        return SandboxCancelResponse(id=job.id, state=job.state, cancel_requested=job.cancel_requested)
    job.cancel_requested = True
    if job.state == "queued":
        job.state = "blocked"
        job.error_code = "cancelled"
        job.target_encrypted = None
        job.completed_at = datetime.now(timezone.utc)
        scan = await db.get(Scan, job.scan_id)
        if scan is not None:
            scan.status = "blocked"
            scan.completed_at = job.completed_at
    await db.commit()
    return SandboxCancelResponse(id=job.id, state=job.state, cancel_requested=job.cancel_requested)
