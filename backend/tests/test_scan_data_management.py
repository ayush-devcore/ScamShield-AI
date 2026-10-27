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

from app.db.models import AnalysisResult, Scan, ThreatIndicator, User
from app.routes.scans import delete_scan_history, export_scan_data


class ScanDataFakeDB:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.statements = []
        self.commits = 0

    async def execute(self, statement):
        self.statements.append(statement)
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(unique=lambda: SimpleNamespace(all=lambda: self.rows)),
            rowcount=2,
        )

    async def commit(self):
        self.commits += 1


class ScanDataManagementTests(unittest.TestCase):
    def setUp(self):
        self.user = User(id=uuid4(), name="Test", email="test@example.com", password_hash="unused", is_active=True)

    def test_export_uses_only_user_rows_and_sanitizes_legacy_content(self):
        now = datetime.now(timezone.utc)
        scan = Scan(
            id=uuid4(), user_id=self.user.id, input_type="url", status="high",
            risk_score=70, confidence=.9, threat_type="credential_phishing",
            redacted_preview="https://person:password@example.test/reset/token?session=private#secret",
            created_at=now,
        )
        scan.analysis_results = [AnalysisResult(
            id=uuid4(), scan_id=scan.id, model_name="model", model_version="1",
            prediction="high", probability=.7,
            features={"url": "https://example.test/private/path?token=secret#fragment"},
            explanation={"text": "private submitted content"}, created_at=now,
        )]
        scan.threat_indicators = [ThreatIndicator(
            id=uuid4(), scan_id=scan.id, indicator_type="credential_request",
            description="raw sensitive legacy description", severity="high",
            evidence={"url": "https://example.test/private?token=secret"}, created_at=now,
        )]

        async def scenario():
            db = ScanDataFakeDB(rows=[scan])
            response = await export_scan_data(self.user, db)
            data = json.loads(response.body)
            serialized = json.dumps(data)
            self.assertIn(self.user.id, db.statements[0].compile().params.values())
            self.assertEqual(len(data["scans"]), 1)
            for private_value in ("person:password", "session=private", "#secret", "private submitted content", "raw sensitive legacy description"):
                self.assertNotIn(private_value, serialized)
            self.assertEqual(data["scans"][0]["preview"], "https://example.test")
        asyncio.run(scenario())

    def test_history_deletion_is_scoped_to_current_user_and_committed(self):
        async def scenario():
            db = ScanDataFakeDB()
            response = await delete_scan_history(self.user, db)
            self.assertEqual(response, {"deleted_count": 2})
            self.assertIn(self.user.id, db.statements[0].compile().params.values())
            self.assertIn("scans", str(db.statements[0]).lower())
            self.assertEqual(db.commits, 1)
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
