"""Canonical exact-match lookups for imported URL datasets."""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import UrlDatasetRecord


MALICIOUS_LABELS = frozenset({"phishing", "malware", "defacement"})
KNOWN_LABELS = MALICIOUS_LABELS | {"benign"}
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


@dataclass(frozen=True)
class DatasetLookup:
    status: str
    match_type: str | None = None
    source_label: str | None = None
    dataset_name: str | None = None
    record_source: str | None = None
    dataset_fingerprint: str | None = None
    imported_at: datetime | None = None
    recorded_at: datetime | None = None


def _canonicalize(value: str, *, allow_scheme_less: bool) -> str:
    candidate = value.strip()
    if not candidate or len(candidate) > 2048 or any(ch.isspace() or ord(ch) < 32 for ch in candidate):
        raise ValueError("URL is malformed.")
    try:
        scheme_present = "://" in candidate
        if scheme_present:
            parsed = urlsplit(candidate)
        elif allow_scheme_less:
            parsed = urlsplit(candidate if candidate.startswith("//") else f"//{candidate}")
        else:
            parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("URL is malformed.") from None
    if (scheme_present and scheme not in {"http", "https"}) or (not scheme_present and not allow_scheme_less):
        raise ValueError("Use a valid HTTP or HTTPS URL.")
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Use a valid HTTP or HTTPS URL without embedded credentials.")
    if "%" in hostname or "\\" in hostname:
        raise ValueError("URL hostname is malformed.")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("URL port is invalid.")

    try:
        address = ipaddress.ip_address(hostname)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        try:
            host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            raise ValueError("URL hostname is malformed.") from None
        if (not host or len(host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in host.split("."))):
            raise ValueError("URL hostname is malformed.")

    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    netloc = host if port is None or (default_port is not None and port == default_port) else f"{host}:{port}"
    # Path/query remain byte-for-byte: normalizing their encoding could merge
    # distinct server resources. Fragments are not sent in HTTP requests.
    path = parsed.path or "/"
    if not scheme_present:
        return urlunsplit(("", netloc, path, parsed.query, ""))
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def canonicalize_url(value: str) -> str:
    """Normalize only URI-equivalent scheme/host/default-port/fragment details."""
    return _canonicalize(value, allow_scheme_less=False)


def canonicalize_dataset_url(value: str) -> str:
    """Keep scheme-less source URLs scheme-agnostic and exact by path/query."""
    return _canonicalize(value, allow_scheme_less=True)


def canonical_url_hash(value: str) -> str:
    return hashlib.sha256(canonicalize_url(value).encode("utf-8")).hexdigest()


def canonical_dataset_hash(value: str) -> str:
    return hashlib.sha256(canonicalize_dataset_url(value).encode("utf-8")).hexdigest()


def canonical_url_hashes(value: str) -> tuple[str, str]:
    exact = canonicalize_url(value)
    parsed = urlsplit(exact)
    scheme_less = urlunsplit(("", parsed.netloc, parsed.path, parsed.query, ""))
    return (
        hashlib.sha256(exact.encode("utf-8")).hexdigest(),
        hashlib.sha256(scheme_less.encode("utf-8")).hexdigest(),
    )


async def lookup_url(session: AsyncSession, value: str) -> DatasetLookup:
    hashes = canonical_url_hashes(value)
    result = await session.execute(select(UrlDatasetRecord).where(UrlDatasetRecord.canonical_hash.in_(hashes)))
    rows = result.scalars().all()
    if not rows:
        return DatasetLookup(status="not_listed")
    labels = {row.source_label for row in rows}
    if len(labels) != 1:
        return DatasetLookup(status="ambiguous")
    row = rows[0]
    matched_hashes = {item.canonical_hash for item in rows}
    match_type = "exact_url" if hashes[0] in matched_hashes else "scheme_agnostic_path"
    result = DatasetLookup(
        status="known_malicious" if row.source_label in MALICIOUS_LABELS else "non_malicious_label",
        match_type=match_type,
        source_label=row.source_label,
        dataset_name=row.dataset_name,
        record_source=row.record_source,
        dataset_fingerprint=row.dataset_fingerprint,
        imported_at=row.imported_at,
        recorded_at=row.recorded_at,
    )
    return result
