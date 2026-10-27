"""Stream a reviewed URL CSV into the indexed, hash-only PostgreSQL lookup."""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete

from app.db.models import UrlDatasetRecord
from app.db.session import AsyncSessionLocal
from app.services.url_dataset import KNOWN_LABELS, canonical_dataset_hash


BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = BACKEND_DIR / "data" / "urls" / "malicious_phish.csv"
LABEL_COLUMNS = ("type", "label", "class", "category", "status")
URL_COLUMNS = ("url", "uri", "link", "address")
SOURCE_COLUMNS = ("source", "provider", "feed")
TIMESTAMP_COLUMNS = ("recorded_at", "timestamp", "date_added", "created_at")
BATCH_SIZE = 2000


def _column(fieldnames: list[str] | None, candidates: tuple[str, ...], explicit: str | None = None) -> str:
    names = {str(name).strip().lower(): name for name in (fieldnames or []) if name}
    if explicit:
        if explicit not in (fieldnames or []):
            raise ValueError(f"Configured column {explicit!r} is missing from the CSV header.")
        return explicit
    for candidate in candidates:
        if candidate in names:
            return names[candidate]
    raise ValueError(f"Could not identify a required CSV column from {fieldnames!r}.")


def _optional_column(fieldnames: list[str] | None, candidates: tuple[str, ...]) -> str | None:
    names = {str(name).strip().lower(): name for name in (fieldnames or []) if name}
    return next((names[name] for name in candidates if name in names), None)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_dataset(
    path: Path,
    url_column_arg: str | None = None,
    label_column_arg: str | None = None,
    source_column_arg: str | None = None,
    timestamp_column_arg: str | None = None,
) -> tuple[Path, dict]:
    temporary = tempfile.NamedTemporaryFile(prefix="scamshield-url-index-", suffix=".sqlite3", delete=False)
    temporary_path = Path(temporary.name)
    temporary.close()
    connection = sqlite3.connect(temporary_path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("""CREATE TABLE staged (
        canonical_hash TEXT PRIMARY KEY,
        source_label TEXT NOT NULL,
        record_source TEXT,
        recorded_at TEXT,
        ambiguous INTEGER NOT NULL DEFAULT 0,
        input_count INTEGER NOT NULL DEFAULT 1
    )""")
    connection.execute("""CREATE TABLE counters (kind TEXT PRIMARY KEY, value INTEGER NOT NULL)""")
    input_rows = malformed = invalid_timestamps = 0
    url_column = label_column = source_column = timestamp_column = None
    pending: list[tuple] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as source:
            reader = csv.DictReader(source)
            url_column = _column(reader.fieldnames, URL_COLUMNS, url_column_arg)
            label_column = _column(reader.fieldnames, LABEL_COLUMNS, label_column_arg)
            source_column = _column(reader.fieldnames, SOURCE_COLUMNS, source_column_arg) if source_column_arg else _optional_column(reader.fieldnames, SOURCE_COLUMNS)
            timestamp_column = _column(reader.fieldnames, TIMESTAMP_COLUMNS, timestamp_column_arg) if timestamp_column_arg else _optional_column(reader.fieldnames, TIMESTAMP_COLUMNS)
            for row in reader:
                input_rows += 1
                raw_url = (row.get(url_column) or "").strip()
                label = (row.get(label_column) or "").strip().casefold()
                if not raw_url or label not in KNOWN_LABELS:
                    malformed += 1
                    continue
                try:
                    digest = canonical_dataset_hash(raw_url)
                except ValueError:
                    malformed += 1
                    continue
                record_source = (row.get(source_column) or "").strip()[:255] if source_column else None
                recorded = _parse_timestamp(row.get(timestamp_column)) if timestamp_column else None
                if timestamp_column and row.get(timestamp_column) and recorded is None:
                    invalid_timestamps += 1
                pending.append((digest, label, record_source or None, recorded.isoformat() if recorded else None))
                if len(pending) >= BATCH_SIZE:
                    connection.executemany("""INSERT INTO staged(canonical_hash,source_label,record_source,recorded_at)
                        VALUES(?,?,?,?) ON CONFLICT(canonical_hash) DO UPDATE SET
                        input_count=input_count+1,
                        ambiguous=CASE WHEN staged.source_label != excluded.source_label THEN 1 ELSE staged.ambiguous END""", pending)
                    pending.clear()
            if pending:
                connection.executemany("""INSERT INTO staged(canonical_hash,source_label,record_source,recorded_at)
                    VALUES(?,?,?,?) ON CONFLICT(canonical_hash) DO UPDATE SET
                    input_count=input_count+1,
                    ambiguous=CASE WHEN staged.source_label != excluded.source_label THEN 1 ELSE staged.ambiguous END""", pending)
        connection.commit()
        duplicates = connection.execute("SELECT COALESCE(SUM(input_count-1),0) FROM staged").fetchone()[0]
        ambiguous_records = connection.execute("SELECT COUNT(*) FROM staged WHERE ambiguous=1").fetchone()[0]
        labels = dict(connection.execute("SELECT source_label,COUNT(*) FROM staged WHERE ambiguous=0 GROUP BY source_label ORDER BY source_label").fetchall())
        accepted = sum(labels.values())
        summary = {
            "input_rows": input_rows,
            "accepted_rows": accepted,
            "duplicate_rows": duplicates,
            "ambiguous_records": ambiguous_records,
            "malformed_records": malformed,
            "invalid_timestamps": invalid_timestamps,
            "records_by_label": labels,
            "columns": {
                "url": url_column,
                "label": label_column,
                "source": source_column,
                "timestamp": timestamp_column,
            },
        }
        return temporary_path, summary
    except Exception:
        connection.close()
        temporary_path.unlink(missing_ok=True)
        raise
    finally:
        connection.close()


async def _replace_records(stage_path: Path, dataset_name: str, fingerprint: str) -> None:
    imported_at = datetime.now(timezone.utc)
    connection = sqlite3.connect(stage_path)
    try:
        cursor = connection.execute("""SELECT canonical_hash,source_label,record_source,recorded_at
            FROM staged WHERE ambiguous=0 ORDER BY canonical_hash""")
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(delete(UrlDatasetRecord).where(UrlDatasetRecord.dataset_name == dataset_name))
                while True:
                    rows = cursor.fetchmany(BATCH_SIZE)
                    if not rows:
                        break
                    session.add_all([
                        UrlDatasetRecord(
                            canonical_hash=row[0],
                            source_label=row[1],
                            dataset_name=dataset_name,
                            record_source=row[2],
                            dataset_fingerprint=fingerprint,
                            imported_at=imported_at,
                            recorded_at=datetime.fromisoformat(row[3]) if row[3] else None,
                        )
                        for row in rows
                    ])
                    await session.flush()
    finally:
        connection.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--dataset-name", help="Stable source identity; rerunning replaces that source atomically.")
    parser.add_argument("--url-column")
    parser.add_argument("--label-column")
    parser.add_argument("--source-column")
    parser.add_argument("--timestamp-column")
    parser.add_argument("--dry-run", action="store_true", help="Validate and count input without changing PostgreSQL.")
    args = parser.parse_args()
    path = args.dataset.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")
    stage_path, summary = stage_dataset(path, args.url_column, args.label_column, args.source_column, args.timestamp_column)
    dataset_name = args.dataset_name or path.name
    fingerprint = _fingerprint(path)
    summary.update({"dataset_name": dataset_name, "dataset_sha256": fingerprint, "database_imported": False})
    try:
        if not args.dry_run:
            await _replace_records(stage_path, dataset_name, fingerprint)
            summary["database_imported"] = True
        print(json.dumps(summary, indent=2, sort_keys=True))
    finally:
        stage_path.unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
