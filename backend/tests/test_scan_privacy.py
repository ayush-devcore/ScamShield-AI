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
from app.routes import scans
from app.services.scan_privacy import (
    redact_url_for_storage,
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
    def test_url_preview_redacts_credentials_tokens_sessions_and_fragment(self):
        url = (
            "https://user:password@safe.example/reset/RESET_TOKEN_123456789"
            "?access_token=ACCESS_SECRET&sid=SESSION_SECRET&campaign=summer"
            "#fragment-secret"
        )
        stored = redact_url_for_storage(url)

        for secret in (
            "user", "password", "RESET_TOKEN_123456789", "ACCESS_SECRET",
            "SESSION_SECRET", "fragment-secret",
        ):
            self.assertNotIn(secret, stored)
        self.assertIn("safe.example", stored)
        self.assertIn("campaign=summer", stored)
        self.assertIn("access_token=%5Bredacted%5D", stored)

    def test_message_qr_and_screenshot_previews_are_generic(self):
        private_message = "PRIVATE bank message with OTP 481902"
        self.assertEqual(safe_scan_preview("message", private_message), "Message scan")
        self.assertEqual(safe_scan_preview("qr", private_message), "QR scan")
        self.assertEqual(safe_scan_preview("screenshot", "private-name.png"), "Screenshot scan")

    def test_analysis_persistence_removes_ocr_filename_and_sensitive_urls(self):
        secret_text = "PRIVATE MESSAGE reset-token-secret"
        secret_url = "https://safe.example/reset/reset-token-secret?session_id=session-secret#fragment-secret"
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
                description="Credential request found",
                severity="high",
                evidence={"path": "/reset/reset-token-secret", "hostname": "safe.example"},
            )],
        )
        scan = SimpleNamespace(id=uuid4(), risk_score=None, confidence=None, threat_type=None, status=None)
        db = CaptureDB()

        scans._persist_analysis_result(db, scan, analysis)

        result = next(row for row in db.added if isinstance(row, AnalysisResult))
        indicator = next(row for row in db.added if isinstance(row, ThreatIndicator))
        persisted = json.dumps({"features": result.features, "explanation": result.explanation, "evidence": indicator.evidence})
        for secret in (secret_text, "private-filename.png", "reset-token-secret", "session-secret", "fragment-secret"):
            self.assertNotIn(secret, persisted)
        self.assertEqual(result.features["url_count"], 1)
        self.assertEqual(result.features["hostname"], "safe.example")
        self.assertEqual(result.explanation["summary"], "Suspicious URL found")
        self.assertEqual(indicator.evidence["hostname"], "safe.example")

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

    def test_detail_response_redacts_legacy_analysis_and_indicator_fields(self):
        scan_id = uuid4()
        created_at = datetime.now(timezone.utc)
        scan = SimpleNamespace(
            id=scan_id, input_type="screenshot", status="high", risk_score=72,
            confidence=88.0, threat_type="Suspicious Screenshot Content", created_at=created_at,
        )
        legacy_url = "https://safe.example/reset/reset-secret?auth_token=auth-secret#fragment-secret"
        analysis = SimpleNamespace(
            id=uuid4(), model_name="screenshot", model_version="1", prediction="suspicious",
            probability=0.72,
            features={"hostname": "safe.example", "urls": [legacy_url]},
            explanation={"source_text_preview": "private OCR text", "ocr_input_name": "local.png", "normalized": legacy_url},
            created_at=created_at,
        )
        indicator = SimpleNamespace(
            id=uuid4(), indicator_type="credential_request", description="Credential request found",
            severity="high", evidence={"path": "/reset/reset-secret", "hostname": "safe.example"},
        )
        db = CaptureDB([
            SimpleNamespace(scalar_one_or_none=lambda: scan),
            SimpleNamespace(scalar_one_or_none=lambda: analysis),
            SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [indicator])),
        ])

        response = asyncio.run(scans.get_scan_detail(scan_id, SimpleNamespace(id=uuid4()), db))
        serialized = response.model_dump_json()

        for secret in ("private OCR text", "local.png", "reset-secret", "auth-secret", "fragment-secret"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(response.analysis.features["hostname"], "safe.example")
        self.assertEqual(response.indicators[0].description, "Credential request found")


if __name__ == "__main__":
    unittest.main()
