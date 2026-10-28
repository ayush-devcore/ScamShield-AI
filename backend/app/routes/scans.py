from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.db.models import (
    AnalysisResult,
    Scan,
    ThreatIndicator,
    User,
)
from app.db.session import get_db
from app.services.audit import record_activity
from app.services.notifications import create_scan_risk_notification, scan_history_enabled
from app.schemas.scans import (
    AnalysisResultResponse,
    MessageFraudAssessment,
    MessageScanRequest,
    QRScanRequest,
    ScanDetailResponse,
    ScanResponse,
    ScreenshotScanRequest,
    ThreatIndicatorResponse,
    URLScanRequest,
    UrlDatasetLookupResponse,
    UrlDecisionResponse,
    UrlRiskAssessmentResponse,
)
from app.services.risk_engine import RiskAnalysis, ThreatSignal, analyze_message, analyze_url
from app.services.url_dataset import DatasetLookup, canonicalize_url, lookup_url
from app.services.scan_privacy import (
    safe_indicator_description,
    safe_scan_preview,
    sanitize_analysis_payload,
)
from app.services.screenshot_analysis import (
    ScreenshotTooLargeError,
    analyze_screenshot_bytes,
    read_screenshot_upload,
    validate_screenshot_upload,
)
from app.services.message_assessment import combine_message_assessment
from app.services.openrouter_messages import classify_message
from app.schemas.sandbox import SandboxUrlRequest
from app.services.sandbox_runtime import get_sandbox_status
from app.routes.sandbox import submit_url_sandbox

router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)

def _apply_analysis_result(scan: Scan, analysis) -> None:
    scan.risk_score = analysis.risk_score
    scan.confidence = analysis.confidence
    scan.threat_type = analysis.threat_type

    if analysis.risk_score >= 80:
        scan.status = "critical"
    elif analysis.risk_score >= 60:
        scan.status = "high"
    elif analysis.risk_score >= 30:
        scan.status = "medium"
    elif getattr(analysis, "source", None) == "message_rules_only":
        scan.status = "unverified"
    else:
        scan.status = "safe"


def _analysis_probability(analysis) -> float | None:
    # Risk scores are not calibrated probabilities. Message assessments do
    # not persist a probability or model-reported confidence value.
    if str(getattr(analysis, "source", "")).startswith("message_"):
        return None
    return analysis.risk_score / 100

def _persist_analysis_result(db: AsyncSession, scan: Scan, analysis) -> None:
    _apply_analysis_result(scan, analysis)
    features = sanitize_analysis_payload(analysis.features)
    explanation = sanitize_analysis_payload(analysis.explanation)
    if str(getattr(analysis, "source", "")).startswith("message_"):
        # Keep only non-content metadata in durable history. Message-specific
        # excerpts and the full provider explanation are returned once to the
        # user but are not saved, even when scan history is enabled.
        explanation = {
            "engine": analysis.source,
            "analysis_source": analysis.features.get("analysis_source"),
            "provider_status": analysis.features.get("provider_status"),
            "score_mapping": analysis.explanation.get("score_mapping"),
            "summary": "Message assessment metadata retained; message text and evidence excerpts are not stored.",
        }
    db.add(
        AnalysisResult(
            scan_id=scan.id,
            model_name=analysis.model_name,
            model_version=analysis.model_version,
            prediction=analysis.prediction,
            probability=_analysis_probability(analysis),
            features=features,
            explanation=explanation,
        )
    )

    for signal in analysis.signals:
        db.add(
            ThreatIndicator(
                scan_id=scan.id,
                indicator_type=signal.indicator_type,
                description=safe_indicator_description(signal.indicator_type),
                severity=signal.severity,
                evidence=sanitize_analysis_payload(signal.evidence),
            )
        )


def _record_scan_activity(db: AsyncSession, scan: Scan) -> None:
    record_activity(db, scan.user_id, "scan_completed")
    if scan.status == "critical":
        record_activity(db, scan.user_id, "scan_critical_risk")
    elif scan.status == "high":
        record_activity(db, scan.user_id, "scan_high_risk")


async def _finish_scan(db: AsyncSession, user: User, input_type: str, preview: str, analysis) -> Scan | ScanResponse:
    persist_history = await scan_history_enabled(db, user.id)
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid4(),
        user_id=user.id,
        input_type=input_type,
        status="analyzing",
        redacted_preview=preview,
    )
    if not persist_history:
        scan.created_at = now
        scan.completed_at = now
    if persist_history:
        db.add(scan)
        await db.flush()
        _persist_analysis_result(db, scan, analysis)
        _record_scan_activity(db, scan)
    else:
        # Return the genuine classification without creating history rows.
        _apply_analysis_result(scan, analysis)

    await create_scan_risk_notification(db, user.id, scan.status, scan.id if persist_history else None)
    await db.commit()
    if persist_history:
        await db.refresh(scan)
        return scan
    return ScanResponse(
        id=scan.id,
        input_type=scan.input_type,
        status=scan.status,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        threat_type=scan.threat_type,
        redacted_preview=scan.redacted_preview,
        created_at=scan.created_at,
        analysis=AnalysisResultResponse(
            id=uuid4(),
            model_name=analysis.model_name,
            model_version=analysis.model_version,
            prediction=analysis.prediction,
            probability=_analysis_probability(analysis),
            features=sanitize_analysis_payload(analysis.features),
            explanation=sanitize_analysis_payload(analysis.explanation),
            created_at=now,
        ),
        indicators=[
            ThreatIndicatorResponse(
                id=uuid4(),
                indicator_type=signal.indicator_type,
                description=safe_indicator_description(signal.indicator_type),
                severity=signal.severity,
                evidence=sanitize_analysis_payload(signal.evidence),
            )
            for signal in analysis.signals
        ],
    )


@router.post(
    "/message",
    response_model=ScanResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
)
async def create_message_scan(
    payload: MessageScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    message = payload.message.strip()
    rules = analyze_message(message)
    provider = await classify_message(message, str(current_user.id))
    analysis, assessment = combine_message_assessment(message, rules, provider)
    scan = await _finish_scan(db, current_user, "message", safe_scan_preview("message"), analysis)
    scan_id = scan.id
    created_at = scan.created_at or datetime.now(timezone.utc)
    return ScanResponse(
        id=scan_id,
        input_type="message",
        status=scan.status,
        risk_score=scan.risk_score,
        confidence=None,
        threat_type=scan.threat_type,
        redacted_preview=safe_scan_preview("message"),
        created_at=created_at,
        analysis=AnalysisResultResponse(
            id=uuid4(),
            model_name=analysis.model_name,
            model_version=analysis.model_version,
            prediction=analysis.prediction,
            probability=None,
            features=sanitize_analysis_payload(analysis.features),
            explanation=sanitize_analysis_payload(analysis.explanation),
            created_at=created_at,
        ),
        indicators=[
            ThreatIndicatorResponse(
                id=uuid4(),
                indicator_type=signal.indicator_type,
                description=safe_indicator_description(signal.indicator_type),
                severity=signal.severity,
                evidence=sanitize_analysis_payload(signal.evidence),
            )
            for signal in analysis.signals
        ],
        message_assessment=assessment,
    )


@router.post(
    "/url",
    response_model=ScanResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
)
async def create_url_scan(
    payload: URLScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan | ScanResponse:
    url = payload.url.strip()

    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required.",
        )

    try:
        analysis = analyze_url(url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return await _finish_scan(db, current_user, "url", safe_scan_preview("url", url), analysis)


def _dataset_lookup_response(lookup: DatasetLookup) -> UrlDatasetLookupResponse:
    if lookup.status not in {"known_malicious", "non_malicious_label"}:
        return UrlDatasetLookupResponse(status=lookup.status)
    return UrlDatasetLookupResponse(
        status=lookup.status,
        match_type=lookup.match_type,
        source_label=lookup.source_label,
        dataset_name=lookup.dataset_name,
        record_source=lookup.record_source,
        dataset_fingerprint=lookup.dataset_fingerprint,
        imported_at=lookup.imported_at,
        recorded_at=lookup.recorded_at,
    )


def _inline_scan(scan: Scan | ScanResponse, analysis, *, prediction: str | None = None) -> ScanResponse:
    now = datetime.now(timezone.utc)
    scan_id = scan.id
    return ScanResponse(
        id=scan_id,
        input_type="url",
        status=scan.status,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        threat_type=scan.threat_type,
        redacted_preview=safe_scan_preview("url"),
        created_at=scan.created_at or now,
        analysis=AnalysisResultResponse(
            id=uuid4(),
            model_name=analysis.model_name,
            model_version=analysis.model_version,
            prediction=prediction or analysis.prediction,
            probability=analysis.risk_score / 100,
            features=sanitize_analysis_payload(analysis.features),
            explanation=sanitize_analysis_payload(analysis.explanation),
            created_at=now,
        ),
        indicators=[
            ThreatIndicatorResponse(
                id=uuid4(),
                indicator_type=signal.indicator_type,
                description=safe_indicator_description(signal.indicator_type),
                severity=signal.severity,
                evidence=sanitize_analysis_payload(signal.evidence),
            )
            for signal in analysis.signals
        ],
    )


async def _finish_unverified_url(db: AsyncSession, user: User, url: str, analysis) -> ScanResponse:
    """Keep static-only results explicitly unverified, never convert low scores to safe."""
    now = datetime.now(timezone.utc)
    persist_history = await scan_history_enabled(db, user.id)
    scan = Scan(
        id=uuid4(),
        user_id=user.id,
        input_type="url",
        status="runtime_unavailable",
        risk_score=analysis.risk_score,
        confidence=analysis.confidence,
        threat_type="Unverified; isolated browser analysis unavailable",
        redacted_preview=safe_scan_preview("url", url),
        created_at=now,
        completed_at=now,
    )
    explanation = {
        **analysis.explanation,
        "detection_source": "local_static_heuristics",
        "verdict": "suspicious" if analysis.risk_score >= 30 else "unverified",
        "sandbox_status": "runtime_unavailable",
        "reachability": "unknown",
    }
    features = sanitize_analysis_payload(analysis.features)
    explanation = sanitize_analysis_payload(explanation)
    if persist_history:
        db.add(scan)
        await db.flush()
        db.add(AnalysisResult(
            scan_id=scan.id,
            model_name=analysis.model_name,
            model_version=analysis.model_version,
            prediction="suspicious" if analysis.risk_score >= 30 else "unverified",
            probability=analysis.risk_score / 100,
            features=features,
            explanation=explanation,
        ))
        for signal in analysis.signals:
            db.add(ThreatIndicator(
                scan_id=scan.id,
                indicator_type=signal.indicator_type,
                description=safe_indicator_description(signal.indicator_type),
                severity=signal.severity,
                evidence=sanitize_analysis_payload(signal.evidence),
            ))
        await db.commit()
        await db.refresh(scan)
    # Use this analysis for the immediate response even when history is disabled.
    response_scan = _inline_scan(scan, analysis, prediction="suspicious" if analysis.risk_score >= 30 else "unverified")
    response_scan.analysis.explanation = explanation
    return response_scan


def _static_risk(analysis, *, method: str, explanation: str, limitations: list[str]) -> UrlRiskAssessmentResponse:
    verdict = "suspicious" if analysis.risk_score >= 30 else "unverified"
    return UrlRiskAssessmentResponse(
        verdict=verdict,
        risk_score=analysis.risk_score,
        method=method,
        explanation=explanation,
        indicators=[signal.indicator_type for signal in analysis.signals],
        limitations=limitations,
    )


@router.post("/url/decision", response_model=UrlDecisionResponse)
async def decide_url_analysis(
    payload: URLScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UrlDecisionResponse:
    """Check the imported exact-URL index first, then use restricted browsing."""
    try:
        normalized_url = canonicalize_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    try:
        dataset_lookup = await lookup_url(db, normalized_url)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=503,
            detail="The URL dataset lookup is unavailable; no verdict was produced.",
        ) from None

    lookup_response = _dataset_lookup_response(dataset_lookup)
    if dataset_lookup.status == "known_malicious":
        provenance = {
            "dataset_name": dataset_lookup.dataset_name,
            "source": dataset_lookup.record_source,
            "source_label": dataset_lookup.source_label,
            "dataset_fingerprint": dataset_lookup.dataset_fingerprint,
            "imported_at": dataset_lookup.imported_at.isoformat() if dataset_lookup.imported_at else None,
            "recorded_at": dataset_lookup.recorded_at.isoformat() if dataset_lookup.recorded_at else None,
            "match_type": dataset_lookup.match_type,
        }
        analysis = RiskAnalysis(
            risk_score=100,
            confidence=100.0,
            threat_type="Known malicious URL in imported dataset",
            prediction="malicious",
            signals=[ThreatSignal(
                indicator_type="dataset_known_malicious",
                description="The exact normalized URL appears in an imported dataset with a malicious label.",
                severity="critical",
                evidence={"source_label": dataset_lookup.source_label, "match_type": dataset_lookup.match_type},
            )],
            features={"detection_source": "url_dataset", "dataset_match": provenance},
            explanation={
                "summary": (
                    "This exact URL matched a maliciously labeled dataset record. The destination was not opened."
                    if dataset_lookup.match_type == "exact_url"
                    else "The dataset record had no scheme; its hostname, path, and query matched exactly. The destination was not opened."
                ),
                "detection_source": "url_dataset",
                "dataset_match": provenance,
            },
            model_name="url-dataset-index",
            model_version=(dataset_lookup.dataset_fingerprint or "unknown")[:16],
            source="dataset_exact_match",
        )
        stored_scan = await _finish_scan(db, current_user, "url", safe_scan_preview("url", normalized_url), analysis)
        scan_response = _inline_scan(stored_scan, analysis)
        return UrlDecisionResponse(
            outcome="dataset_match",
            dataset_lookup=lookup_response,
            risk_assessment=UrlRiskAssessmentResponse(
                verdict="known_malicious", risk_score=100,
                method="exact URL dataset match" if dataset_lookup.match_type == "exact_url" else "scheme-agnostic exact host/path/query dataset match",
                explanation=("Detection came from the imported dataset; no browser execution was needed."
                             if dataset_lookup.match_type == "exact_url"
                             else "The dataset record omitted its URL scheme; host, path, and query matched exactly. No browser execution was needed."),
                indicators=["dataset_known_malicious"],
                limitations=["The dataset has no per-record timestamp; imported_at is the import time."],
            ),
            reachability="not_checked",
            scan=scan_response,
        )

    capability = get_sandbox_status()
    if capability.available:
        try:
            job = await submit_url_sandbox(SandboxUrlRequest(url=normalized_url), current_user, db)
            return UrlDecisionResponse(
                outcome="sandbox_queued",
                dataset_lookup=lookup_response,
                reachability="pending",
                sandbox_job=job,
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_409_CONFLICT:
                if exc.status_code != status.HTTP_503_SERVICE_UNAVAILABLE:
                    raise
                capability = get_sandbox_status()
            else:
                static_analysis = analyze_url(normalized_url)
                scan_response = await _finish_unverified_url(db, current_user, normalized_url, static_analysis)
                return UrlDecisionResponse(
                    outcome="sandbox_blocked",
                    dataset_lookup=lookup_response,
                    risk_assessment=_static_risk(
                        static_analysis,
                        method="local static URL heuristics",
                        explanation=("No malicious dataset entry matched. A benign dataset label does not verify that the destination is safe. Scan history is disabled, so a durable isolated-browser job cannot be queued."
                                     if dataset_lookup.status == "non_malicious_label"
                                     else "No malicious dataset entry matched. Scan history is disabled, so a durable isolated-browser job cannot be queued."),
                        limitations=["Static heuristics cannot establish that a destination is safe.", "No browser navigation occurred."],
                    ),
                    reachability="unknown",
                    reason="history_persistence_disabled",
                    scan=scan_response,
                )

    static_analysis = analyze_url(normalized_url)
    scan_response = await _finish_unverified_url(db, current_user, normalized_url, static_analysis)
    return UrlDecisionResponse(
        outcome="runtime_unavailable",
        dataset_lookup=lookup_response,
        risk_assessment=_static_risk(
            static_analysis,
            method="local static URL heuristics",
            explanation=("No malicious dataset entry matched. The dataset label is benign, but it does not verify that the destination is safe. The isolated browser runtime is unavailable, so this result is unverified."
                         if dataset_lookup.status == "non_malicious_label"
                         else "No confirmed malicious dataset entry matched. The isolated browser runtime is unavailable, so this result is unverified."),
            limitations=["No sandbox navigation or reachability check occurred.", "A low static heuristic score is not a safe verdict."],
        ),
        reachability="runtime_unavailable",
        reason=capability.reason or "sandbox_execution_unavailable",
        scan=scan_response,
    )


@router.post(
    "/qr",
    response_model=ScanResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
)
async def create_qr_scan(
    payload: QRScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan | ScanResponse:
    text = (payload.payload or "").strip()

    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="QR payload is required.",
        )

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

    return await _finish_scan(db, current_user, "qr", safe_scan_preview("qr"), analysis)


@router.post(
    "/screenshot",
    response_model=ScanResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
)
async def create_screenshot_scan(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan | ScanResponse:
    try:
        content = await read_screenshot_upload(
            file,
            settings.max_upload_size_mb * 1024 * 1024,
        )
    except ScreenshotTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        ) from exc

    try:
        validate_screenshot_upload(content, file.filename, file.content_type)
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

    return await _finish_scan(db, current_user, "screenshot", safe_scan_preview("screenshot"), analysis)


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

    scans = list(result.scalars().all())
    for scan in scans:
        scan.redacted_preview = safe_scan_preview(scan.input_type, scan.redacted_preview)
    return scans


@router.get("/export")
async def export_scan_data(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .options(selectinload(Scan.analysis_results), selectinload(Scan.threat_indicators))
        .order_by(Scan.created_at.desc())
    )).scalars().unique().all()
    exported = []
    for scan in rows:
        analyses = sorted(scan.analysis_results, key=lambda row: row.created_at, reverse=True)
        analysis = analyses[0] if analyses else None
        exported.append({
            "id": str(scan.id),
            "input_type": scan.input_type,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "confidence": scan.confidence,
            "threat_type": scan.threat_type,
            "preview": safe_scan_preview(scan.input_type, scan.redacted_preview),
            "created_at": scan.created_at.isoformat(),
            "analysis": ({
                "model_name": analysis.model_name,
                "model_version": analysis.model_version,
                "prediction": analysis.prediction,
                "probability": analysis.probability,
                "features": sanitize_analysis_payload(analysis.features),
                "explanation": sanitize_analysis_payload(analysis.explanation),
            } if analysis else None),
            "indicators": [{
                "indicator_type": item.indicator_type,
                "description": safe_indicator_description(item.indicator_type),
                "severity": item.severity,
                "evidence": sanitize_analysis_payload(item.evidence),
            } for item in scan.threat_indicators],
        })
    return JSONResponse(
        content={"exported_at": datetime.now(timezone.utc).isoformat(), "scans": exported},
        headers={"Content-Disposition": 'attachment; filename="scamshield-scan-export.json"'},
    )


@router.delete("/history")
async def delete_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(delete(Scan).where(Scan.user_id == current_user.id))
    await db.commit()
    return {"deleted_count": int(result.rowcount or 0)}


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
            features=sanitize_analysis_payload(analysis_result.features),
            explanation=sanitize_analysis_payload(analysis_result.explanation),
            created_at=analysis_result.created_at,
        )

    indicator_responses = [
        ThreatIndicatorResponse(
            id=indicator.id,
            indicator_type=indicator.indicator_type,
            description=safe_indicator_description(indicator.indicator_type),
            severity=indicator.severity,
            evidence=sanitize_analysis_payload(indicator.evidence),
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
