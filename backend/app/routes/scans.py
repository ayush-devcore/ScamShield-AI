import hashlib
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.models import (
    AnalysisResult,
    Scan,
    ThreatIndicator,
    User,
)
from app.db.session import get_db
from app.schemas.scans import (
    AnalysisResultResponse,
    MessageScanRequest,
    QRScanRequest,
    ScanDetailResponse,
    ScanResponse,
    ScreenshotScanRequest,
    ThreatIndicatorResponse,
    URLScanRequest,
)
from app.services.risk_engine import analyze_message, analyze_url
from app.services.screenshot_analysis import (
    analyze_screenshot_bytes,
    hash_uploaded_bytes,
    validate_screenshot_upload,
)

router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)

def _persist_analysis_result(
    db: AsyncSession,
    scan: Scan,
    analysis,
) -> None:
    scan.risk_score = analysis.risk_score
    scan.confidence = analysis.confidence
    scan.threat_type = analysis.threat_type

    if analysis.risk_score >= 80:
        scan.status = "critical"
    elif analysis.risk_score >= 60:
        scan.status = "high"
    elif analysis.risk_score >= 30:
        scan.status = "medium"
    else:
        scan.status = "safe"

    db.add(
        AnalysisResult(
            scan_id=scan.id,
            model_name=analysis.model_name,
            model_version=analysis.model_version,
            prediction=analysis.prediction,
            probability=analysis.risk_score / 100,
            features=analysis.features,
            explanation=analysis.explanation,
        )
    )

    for signal in analysis.signals:
        db.add(
            ThreatIndicator(
                scan_id=scan.id,
                indicator_type=signal.indicator_type,
                description=signal.description,
                severity=signal.severity,
                evidence=signal.evidence,
            )
        )


@router.post(
    "/message",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_message_scan(
    payload: MessageScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    message = payload.message.strip()

    input_hash = hashlib.sha256(
        message.encode("utf-8")
    ).hexdigest()

    analysis = analyze_message(message)

    scan = Scan(
        user_id=current_user.id,
        input_type="message",
        status="analyzing",
        input_hash=input_hash,
        redacted_preview=None,
    )

    db.add(scan)
    await db.flush()
    _persist_analysis_result(db, scan, analysis)

    await db.commit()
    await db.refresh(scan)

    return scan


@router.post(
    "/url",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_url_scan(
    payload: URLScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    url = payload.url.strip()

    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required.",
        )

    input_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()

    try:
        analysis = analyze_url(url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    scan = Scan(
        user_id=current_user.id,
        input_type="url",
        status="analyzing",
        input_hash=input_hash,
        redacted_preview=url[:240],
    )

    db.add(scan)
    await db.flush()
    _persist_analysis_result(db, scan, analysis)

    await db.commit()
    await db.refresh(scan)

    return scan


@router.post(
    "/qr",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_qr_scan(
    payload: QRScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    text = (payload.payload or "").strip()

    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="QR payload is required.",
        )

    input_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    if text.startswith(("http://", "https://")):
        try:
            analysis = analyze_url(text)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
    else:
        analysis = analyze_message(text)

    scan = Scan(
        user_id=current_user.id,
        input_type="qr",
        status="analyzing",
        input_hash=input_hash,
        redacted_preview=text[:240],
    )

    db.add(scan)
    await db.flush()
    _persist_analysis_result(db, scan, analysis)

    await db.commit()
    await db.refresh(scan)

    return scan


@router.post(
    "/screenshot",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_screenshot_scan(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    content = await file.read()
    content_type = file.content_type or "application/octet-stream"

    try:
        validate_screenshot_upload(file.filename, content_type, len(content))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    try:
        analysis = analyze_screenshot_bytes(content, file_name=file.filename)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    input_hash = hash_uploaded_bytes(content)
    preview = (file.filename or "screenshot")[:240]

    scan = Scan(
        user_id=current_user.id,
        input_type="screenshot",
        status="analyzing",
        input_hash=input_hash,
        redacted_preview=preview,
    )

    db.add(scan)
    await db.flush()
    _persist_analysis_result(db, scan, analysis)

    await db.commit()
    await db.refresh(scan)

    return scan


@router.get(
    "",
    response_model=list[ScanResponse],
)
async def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Scan]:
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(100)
    )

    return list(result.scalars().all())


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
)
async def get_scan_detail(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )

    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    analysis_result_query = await db.execute(
        select(AnalysisResult)
        .where(AnalysisResult.scan_id == scan.id)
        .order_by(AnalysisResult.created_at.desc())
        .limit(1)
    )

    analysis_result = analysis_result_query.scalar_one_or_none()

    indicators_result = await db.execute(
        select(ThreatIndicator)
        .where(ThreatIndicator.scan_id == scan.id)
        .order_by(ThreatIndicator.created_at)
    )

    indicators = indicators_result.scalars().all()

    analysis_response = None

    if analysis_result is not None:
        analysis_response = AnalysisResultResponse(
            id=analysis_result.id,
            model_name=analysis_result.model_name,
            model_version=analysis_result.model_version,
            prediction=analysis_result.prediction,
            probability=analysis_result.probability,
            features=analysis_result.features,
            explanation=analysis_result.explanation,
            created_at=analysis_result.created_at,
        )

    indicator_responses = [
        ThreatIndicatorResponse(
            id=indicator.id,
            indicator_type=indicator.indicator_type,
            description=indicator.description,
            severity=indicator.severity,
            evidence=indicator.evidence,
        )
        for indicator in indicators
    ]

    return ScanDetailResponse(
        id=scan.id,
        input_type=scan.input_type,
        status=scan.status,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        threat_type=scan.threat_type,
        created_at=scan.created_at,
        analysis=analysis_response,
        indicators=indicator_responses,
    )
