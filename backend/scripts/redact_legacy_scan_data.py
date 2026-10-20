"""Redact legacy scan fields in bounded batches.

Default invocation is an aggregate-only, read-only dry run. Apply mode is
deliberately explicit and requires --backup-confirmed.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select, text

from app.services.scan_privacy import (
    _URL_PATTERN,
    safe_indicator_description,
    safe_scan_preview,
    sanitize_analysis_payload,
)


_SENSITIVE_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|token|secret|session(?:_?id)?|sid|"
    r"api[_-]?key|access[_-]?key|reset[_-]?code|otp)\b\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_BEARER_OR_JWT = re.compile(
    r"\bBearer\s+\S+|\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_BATCH_MAX = 500
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_TABLES = ("scans", "analysis_results", "threat_indicators", "audit_logs")


def _description_exposes_sensitive_value(description: str) -> bool:
    if _SENSITIVE_ASSIGNMENT.search(description) or _BEARER_OR_JWT.search(description):
        return True
    if _PRIVATE_KEY.search(description):
        return True
    for match in _URL_PATTERN.finditer(description):
        candidate = match.group(0).rstrip(".,);]")
        sanitized = sanitize_analysis_payload(candidate)
        if sanitized != candidate:
            return True
        try:
            parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
            if parsed.username or parsed.password:
                return True
        except ValueError:
            return True
    return False


def transform_scan(scan):
    """Return safe replacements for the only scan fields this backfill changes."""
    preview = safe_scan_preview(scan.input_type, scan.redacted_preview)
    return preview, None


def transform_analysis(analysis):
    return (
        sanitize_analysis_payload(analysis.features),
        sanitize_analysis_payload(analysis.explanation),
    )


def transform_indicator(indicator):
    evidence = sanitize_analysis_payload(indicator.evidence)
    description = indicator.description
    if _description_exposes_sensitive_value(description):
        description = safe_indicator_description(indicator.indicator_type)
    return evidence, description


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="explicitly select the default read-only mode")
    mode.add_argument("--apply", action="store_true", help="apply redactions; requires --backup-confirmed")
    parser.add_argument(
        "--backup-confirmed",
        action="store_true",
        help="confirm a restorable database backup exists (required with --apply)",
    )
    parser.add_argument("--batch-size", type=int, default=100, help=f"rows per transaction (1-{_BATCH_MAX})")
    return parser


def _parse_args(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.batch_size < 1 or args.batch_size > _BATCH_MAX:
        parser.error(f"--batch-size must be between 1 and {_BATCH_MAX}")
    if args.apply and not args.backup_confirmed:
        parser.error("--apply requires --backup-confirmed")
    if args.backup_confirmed and not args.apply:
        parser.error("--backup-confirmed is only valid with --apply")
    return args


def _local_development_configuration():
    """Load configured URL without displaying it; reject non-local environments."""
    from app.core.config import settings

    if settings.environment.lower() != "development":
        raise RuntimeError("database environment is not development")
    try:
        parsed = urlsplit(settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1))
        host = parsed.hostname
    except ValueError as exc:
        raise RuntimeError("database configuration is invalid") from exc
    if host not in _LOOPBACK_HOSTS:
        raise RuntimeError("database host is not loopback")


async def _verify_schema(session):
    from app.db.base import Base
    from app.db import models as _models  # noqa: F401 - register model metadata

    expected_columns = {
        table: set(Base.metadata.tables[table].columns.keys()) for table in _TABLES
    }
    columns_result = await session.execute(text(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = ANY(CAST(:tables AS text[]))"
    ), {"tables": list(_TABLES)})
    actual_columns = {}
    for table, column in columns_result:
        actual_columns.setdefault(table, set()).add(column)
    if actual_columns != expected_columns:
        raise RuntimeError("database schema does not match expected application tables")

    fk_result = await session.execute(text(
        "SELECT tc.table_name, kcu.column_name, ccu.table_name, ccu.column_name, "
        "rc.delete_rule FROM information_schema.table_constraints tc "
        "JOIN information_schema.key_column_usage kcu "
        "ON tc.constraint_catalog = kcu.constraint_catalog "
        "AND tc.constraint_schema = kcu.constraint_schema "
        "AND tc.constraint_name = kcu.constraint_name "
        "JOIN information_schema.constraint_column_usage ccu "
        "ON ccu.constraint_catalog = tc.constraint_catalog "
        "AND ccu.constraint_schema = tc.constraint_schema "
        "AND ccu.constraint_name = tc.constraint_name "
        "JOIN information_schema.referential_constraints rc "
        "ON rc.constraint_catalog = tc.constraint_catalog "
        "AND rc.constraint_schema = tc.constraint_schema "
        "AND rc.constraint_name = tc.constraint_name "
        "WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public' "
        "AND tc.table_name = ANY(CAST(:tables AS text[]))"
    ), {"tables": list(_TABLES)})
    actual_fks = {(a, b, c, d, e.upper()) for a, b, c, d, e in fk_result}
    expected_fks = {
        ("scans", "user_id", "users", "id", "CASCADE"),
        ("analysis_results", "scan_id", "scans", "id", "CASCADE"),
        ("threat_indicators", "scan_id", "scans", "id", "CASCADE"),
        ("audit_logs", "user_id", "users", "id", "SET NULL"),
    }
    # Include all declared relationships for these tables, including any other FKs.
    declared = set()
    for table in _TABLES:
        for constraint in Base.metadata.tables[table].foreign_key_constraints:
            for element in constraint.elements:
                declared.add((
                    table,
                    element.parent.name,
                    element.column.table.name,
                    element.column.name,
                    (constraint.ondelete or "NO ACTION").upper(),
                ))
    if actual_fks != declared or not expected_fks.issubset(actual_fks):
        raise RuntimeError("database foreign-key rules do not match expected application relationships")


async def _process_batch(session, scans, apply):
    from app.db.models import AnalysisResult, ThreatIndicator

    scan_ids = [row.id for row in scans]
    analyses = (await session.execute(
        select(AnalysisResult).where(AnalysisResult.scan_id.in_(scan_ids))
    )).scalars().all() if scan_ids else []
    indicators = (await session.execute(
        select(ThreatIndicator).where(ThreatIndicator.scan_id.in_(scan_ids))
    )).scalars().all() if scan_ids else []
    changed = {"previews": 0, "hashes": 0, "analysis_json": 0, "indicator_evidence": 0, "descriptions": 0}

    for scan in scans:
        preview, input_hash = transform_scan(scan)
        if scan.redacted_preview != preview:
            changed["previews"] += 1
            if apply:
                scan.redacted_preview = preview
        if scan.input_hash is not None:
            changed["hashes"] += 1
            if apply:
                scan.input_hash = input_hash
    for analysis in analyses:
        features, explanation = transform_analysis(analysis)
        if analysis.features != features or analysis.explanation != explanation:
            changed["analysis_json"] += 1
            if apply:
                analysis.features = features
                analysis.explanation = explanation
    for indicator in indicators:
        evidence, description = transform_indicator(indicator)
        if indicator.evidence != evidence:
            changed["indicator_evidence"] += 1
            if apply:
                indicator.evidence = evidence
        if indicator.description != description:
            changed["descriptions"] += 1
            if apply:
                indicator.description = description
    return changed


async def _dry_run_counts(session, cutoff):
    """Return aggregate-only counts; never materialize ORM scan data."""
    result = await session.execute(text(
        "SELECT "
        "(SELECT COUNT(*) FROM scans WHERE created_at >= :cutoff) AS eligible_scans, "
        "(SELECT COUNT(*) FROM scans WHERE created_at >= :cutoff AND input_hash IS NOT NULL) AS scans_with_input_hash, "
        "(SELECT COUNT(*) FROM scans WHERE created_at >= :cutoff AND redacted_preview IS NOT NULL) AS scans_with_preview, "
        "(SELECT COUNT(*) FROM analysis_results ar JOIN scans s ON s.id = ar.scan_id "
        " WHERE s.created_at >= :cutoff) AS analysis_results, "
        "(SELECT COUNT(*) FROM analysis_results ar JOIN scans s ON s.id = ar.scan_id "
        " WHERE s.created_at >= :cutoff AND ar.features IS NOT NULL) AS analysis_with_features, "
        "(SELECT COUNT(*) FROM analysis_results ar JOIN scans s ON s.id = ar.scan_id "
        " WHERE s.created_at >= :cutoff AND ar.explanation IS NOT NULL) AS analysis_with_explanation, "
        "(SELECT COUNT(*) FROM threat_indicators ti JOIN scans s ON s.id = ti.scan_id "
        " WHERE s.created_at >= :cutoff) AS threat_indicators, "
        "(SELECT COUNT(*) FROM threat_indicators ti JOIN scans s ON s.id = ti.scan_id "
        " WHERE s.created_at >= :cutoff AND ti.evidence IS NOT NULL) AS indicators_with_evidence, "
        "(SELECT COUNT(*) FROM threat_indicators ti JOIN scans s ON s.id = ti.scan_id "
        " WHERE s.created_at >= :cutoff AND ti.description IS NOT NULL) AS indicators_with_description"
    ), {"cutoff": cutoff})
    row = result.one()
    return dict(row._mapping)


async def _run(args):
    from app.db.session import AsyncSessionLocal, engine

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    if not args.apply:
        try:
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    await session.execute(text("SET TRANSACTION READ ONLY"))
                    counts = await _dry_run_counts(session, cutoff)
        finally:
            await engine.dispose()
        print(f"mode=dry-run cutoff_utc={cutoff.isoformat()}")
        print("aggregate_counts=" + " ".join(f"{key}:{value}" for key, value in counts.items()))
        print("Exact redaction totals require value inspection and are intentionally not calculated in dry-run.")
        return

    from app.db.models import Scan

    totals = {"scans": 0, "previews": 0, "hashes": 0, "analysis_json": 0, "indicator_evidence": 0, "descriptions": 0}
    last_id = None
    try:
        while True:
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    if last_id is None:
                        await _verify_schema(session)
                    statement = select(Scan).where(Scan.created_at >= cutoff).order_by(Scan.id).limit(args.batch_size)
                    if last_id is not None:
                        statement = statement.where(Scan.id > last_id)
                    batch = (await session.execute(statement)).scalars().all()
                    if not batch:
                        break
                    last_id = batch[-1].id
                    changed = await _process_batch(session, batch, True)
                    totals["scans"] += len(batch)
                    for key, count in changed.items():
                        totals[key] += count
            # Dry-run must remain read-only; each batch starts its own read-only transaction.
    finally:
        await engine.dispose()
    print(f"mode=apply cutoff_utc={cutoff.isoformat()} eligible_scans={totals['scans']}")
    print("changed=", " ".join(f"{key}:{value}" for key, value in totals.items() if key != "scans"))


def main(argv=None):
    args = _parse_args(argv)
    try:
        _local_development_configuration()
        asyncio.run(_run(args))
    except Exception as exc:
        # Avoid exposing connection details or values that may appear in driver errors.
        print(f"Aborted safely: {type(exc).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
