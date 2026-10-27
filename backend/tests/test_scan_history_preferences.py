import asyncio
import io
import os
import unittest
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import AsyncMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from starlette.datastructures import UploadFile

from app.db.models import AnalysisResult, AuditLog, Scan, ThreatIndicator, User, UserNotification
from app.routes import scans
from app.schemas.scans import MessageScanRequest, QRScanRequest, URLScanRequest


class ScanPreferenceFakeDB:
    def __init__(self, enabled: bool):
        self.preference = SimpleNamespace(
            store_scan_history=enabled,
            notify_high_risk=True,
            notify_critical_risk=True,
        )
        self.added = []
        self.commits = 0

    def add(self, value):
        self.added.append(value)

    async def execute(self, statement):
        return SimpleNamespace(scalar_one_or_none=lambda: self.preference)

    async def flush(self):
        pass

    async def refresh(self, value):
        pass

    async def commit(self):
        self.commits += 1


def make_analysis(risk_score=12):
    return SimpleNamespace(
        risk_score=risk_score,
        confidence=0.91,
        threat_type="safe",
        model_name="test-model",
        model_version="test",
        prediction="safe",
        features={},
        explanation={},
        signals=[],
    )


class ScanHistoryPreferenceTests(unittest.TestCase):
    def setUp(self):
        self.user = User(id=uuid4(), name="Test", email="test@example.com", password_hash="unused", is_active=True)

    def test_all_four_scanners_return_results_without_persisting_history(self):
        async def scenario():
            cases = [
                ("message", lambda db, analysis: scans.create_message_scan(MessageScanRequest(message="private message"), self.user, db), "analyze_message"),
                ("url", lambda db, analysis: scans.create_url_scan(URLScanRequest(url="https://example.test/private"), self.user, db), "analyze_url"),
                ("qr", lambda db, analysis: scans.create_qr_scan(QRScanRequest(payload="qr text"), self.user, db), "analyze_message"),
            ]
            for input_type, invoke, analyzer in cases:
                db = ScanPreferenceFakeDB(enabled=False)
                with patch.object(scans, analyzer, return_value=make_analysis()):
                    result = await invoke(db, make_analysis())
                self.assertEqual(result.input_type, input_type)
                self.assertEqual(result.status, "safe")
                self.assertEqual(result.risk_score, 12)
                self.assertIsNotNone(result.analysis)
                self.assertEqual(result.indicators, [])
                self.assertEqual(db.commits, 1)
                self.assertFalse(any(isinstance(row, (Scan, AnalysisResult, ThreatIndicator, AuditLog, UserNotification)) for row in db.added))

            db = ScanPreferenceFakeDB(enabled=False)
            uploaded = UploadFile(filename="synthetic.png", file=io.BytesIO(b"synthetic-image"))
            with (
                patch.object(scans, "read_screenshot_upload", new=AsyncMock(return_value=b"synthetic-image")),
                patch.object(scans, "validate_screenshot_upload"),
                patch.object(scans, "analyze_screenshot_bytes", return_value=make_analysis()),
            ):
                result = await scans.create_screenshot_scan(uploaded, self.user, db)
            self.assertEqual(result.input_type, "screenshot")
            self.assertEqual(result.status, "safe")
            self.assertIsNotNone(result.analysis)
            self.assertEqual(result.indicators, [])
            self.assertFalse(any(isinstance(row, (Scan, AnalysisResult, ThreatIndicator, AuditLog, UserNotification)) for row in db.added))

        asyncio.run(scenario())

    def test_history_enabled_still_persists_analysis_for_existing_behavior(self):
        async def scenario():
            db = ScanPreferenceFakeDB(enabled=True)
            with patch.object(scans, "analyze_message", return_value=make_analysis()):
                result = await scans.create_message_scan(MessageScanRequest(message="ordinary test"), self.user, db)
            self.assertEqual(result.status, "safe")
            self.assertTrue(any(isinstance(row, Scan) for row in db.added))
            self.assertTrue(any(isinstance(row, AnalysisResult) for row in db.added))
            self.assertEqual(db.commits, 1)
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
