import asyncio
import json
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from app.db.models import AnalysisResult, ThreatIndicator
from app.routes.dashboard import scan_title
from app.routes import scans
from app.services.scan_privacy import (
    redact_url_for_storage,
    safe_indicator_description,
    safe_scan_preview,
)


class CaptureDB:
    def __init__(self, results=()):
        self.added = []
        self.results = iter(results)

    def add(self, row):
        self.added.append(row)

    async def execute(self, _statement):
        return next(self.results)


class ScanPrivacyTests(unittest.TestCase):
    def test_url_preview_keeps_only_scheme_and_normalized_host(self):
        url = (
            "HTTPS://user:password@Safe.Example.:8443/reset/RESET_TOKEN_123456789"
            "?unknown=ARBITRARY_SECRET&sid=SESSION_SECRET&campaign=summer"
            "#fragment-secret"
        )
        stored = redact_url_for_storage(url)

        for secret in (
            "user", "password", "RESET_TOKEN_123456789",
            "ARBITRARY_SECRET", "SESSION_SECRET", "fragment-secret", "8443",
            "reset", "campaign",
        ):
            self.assertNotIn(secret, stored)
        self.assertEqual(stored, "https://safe.example")

    def test_url_minimization_supports_ipv6_and_rejects_malformed_urls(self):
        self.assertEqual(
            redact_url_for_storage("https://user:secret@[2001:0db8::1]:9443/private?x=y#z"),
            "https://[2001:db8::1]",
        )
        self.assertEqual(
            redact_url_for_storage("https://[fe80::1%25eth0]/path"),
            "[redacted URL]",
        )
        self.assertEqual(redact_url_for_storage("https://[broken"), "[redacted URL]")
        self.assertEqual(redact_url_for_storage("https://safe.example:bad/path"), "[redacted URL]")

    def test_message_qr_and_screenshot_previews_are_generic(self):
        private_message = "PRIVATE bank message with OTP 481902"
        self.assertEqual(safe_scan_preview("message", private_message), "Message scan")
        self.assertEqual(safe_scan_preview("qr", private_message), "QR scan")
        self.assertEqual(safe_scan_preview("screenshot", "private-name.png"), "Screenshot scan")

    def test_analysis_persistence_removes_ocr_filename_and_sensitive_urls(self):
        secret_text = "PRIVATE MESSAGE reset-token-secret"
        secret_url = "https://safe.example/reset/reset-token-secret?unknown=session-secret#fragment-secret"
        analysis = SimpleNamespace(
            risk_score=72,
            confidence=88.0,
            threat_type="Suspicious Screenshot Content",
            prediction="suspicious",
            model_name="scamshield-screenshot-ocr",
            model_version="1.0.0",
            features={
                "hostname": "safe.example",
                "url_count": 1,
                "urls": [secret_url],
            },
            explanation={
                "summary": "Suspicious URL found",
                "source_text_preview": secret_text,
                "ocr_input_name": "private-filename.png",
                "normalized": secret_url,
            },
            signals=[SimpleNamespace(
                indicator_type="credential_request",
                description="Credential request found: reset-token-secret and private OCR text",
                severity="high",
                evidence={"path": "/reset/reset-token-secret", "hostname": "safe.example"},
            )],
        )
        scan = SimpleNamespace(id=uuid4(), risk_score=None, confidence=None, threat_type=None, status=None)
        db = CaptureDB()

        scans._persist_analysis_result(db, scan, analysis)

        result = next(row for row in db.added if isinstance(row, AnalysisResult))
        indicator = next(row for row in db.added if isinstance(row, ThreatIndicator))
        persisted = json.dumps({
            "features": result.features,
            "explanation": result.explanation,
            "evidence": indicator.evidence,
            "description": indicator.description,
        })
        for secret in (secret_text, "private-filename.png", "reset-token-secret", "session-secret", "fragment-secret"):
            self.assertNotIn(secret, persisted)
        self.assertEqual(result.features["url_count"], 1)
        self.assertEqual(result.features["hostname"], "safe.example")
        self.assertEqual(result.explanation["summary"], "Suspicious URL found")
        self.assertEqual(result.prediction, "suspicious")
        self.assertEqual(scan.status, "high")
        self.assertEqual(indicator.indicator_type, "credential_request")
        self.assertEqual(indicator.evidence["hostname"], "safe.example")
        self.assertEqual(
            indicator.description,
            "The content references credentials such as passwords or one-time codes.",
        )

    def test_history_response_replaces_legacy_private_previews(self):
        old_scans = [
            SimpleNamespace(input_type="message", redacted_preview="private message", created_at=datetime.now(timezone.utc)),
            SimpleNamespace(input_type="qr", redacted_preview="private QR payload", created_at=datetime.now(timezone.utc)),
            SimpleNamespace(input_type="screenshot", redacted_preview="private-file.png", created_at=datetime.now(timezone.utc)),
            SimpleNamespace(input_type="url", redacted_preview="https://safe.example/?token=secret#fragment", created_at=datetime.now(timezone.utc)),
        ]
        db = CaptureDB([SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: old_scans))])

        returned = asyncio.run(scans.get_scan_history(SimpleNamespace(id=uuid4()), db))
        serialized = json.dumps([scan.redacted_preview for scan in returned])

        self.assertNotIn("private message", serialized)
        self.assertNotIn("private QR payload", serialized)
        self.assertNotIn("private-file.png", serialized)
        self.assertNotIn("secret", serialized)
        self.assertIn("safe.example", serialized)

    def test_dashboard_title_minimizes_legacy_url_preview(self):
        scan = SimpleNamespace(
            input_type="url",
            redacted_preview="https://user:secret@safe.example/path?x=token#fragment",
        )
        title = scan_title(scan)
        self.assertEqual(title, "https://safe.example")

    def test_detail_response_redacts_legacy_analysis_and_indicator_fields(self):
        scan_id = uuid4()
        created_at = datetime.now(timezone.utc)
        scan = SimpleNamespace(
            id=scan_id, input_type="screenshot", status="high", risk_score=72,
            confidence=88.0, threat_type="Suspicious Screenshot Content", created_at=created_at,
        )
        legacy_url = "https://user:secret@safe.example/opaque/reset-secret?unknown=auth-secret#fragment-secret"
        analysis = SimpleNamespace(
            id=uuid4(), model_name="screenshot", model_version="1", prediction="suspicious",
            probability=0.72,
            features={"hostname": "safe.example", "urls": [legacy_url]},
            explanation={"source_text_preview": "private OCR text", "ocr_input_name": "local.png", "normalized": legacy_url},
            created_at=created_at,
        )
        indicator = SimpleNamespace(
            id=uuid4(), indicator_type="credential_request",
            severity="high",
            description="Private OCR secret auth-secret",
            evidence={"path": "/reset/reset-secret", "url": legacy_url, "hostname": "safe.example"},
        )
        db = CaptureDB([
            SimpleNamespace(scalar_one_or_none=lambda: scan),
            SimpleNamespace(scalar_one_or_none=lambda: analysis),
            SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [indicator])),
        ])

        response = asyncio.run(scans.get_scan_detail(scan_id, SimpleNamespace(id=uuid4()), db))
        serialized = response.model_dump_json()

        for secret in ("private OCR text", "local.png", "reset-secret", "auth-secret", "fragment-secret", "user:secret"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(response.analysis.features["hostname"], "safe.example")
        self.assertEqual(
            response.indicators[0].description,
            "The content references credentials such as passwords or one-time codes.",
        )
        self.assertEqual(response.analysis.explanation["normalized"], "https://safe.example")
        self.assertEqual(response.indicators[0].evidence["url"], "https://safe.example")

    def test_unknown_indicator_type_uses_generic_controlled_description(self):
        description = safe_indicator_description("unexpected")
        self.assertNotIn("submitted secret", description)
        self.assertEqual(description, "A potential risk indicator was detected.")


if __name__ == "__main__":
    unittest.main()
