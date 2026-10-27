import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from fastapi import HTTPException

from app.routes.scans import decide_url_analysis
from app.schemas.sandbox import SandboxCapabilities, SandboxJobResponse, SandboxStatusResponse
from app.schemas.scans import ScanResponse, URLScanRequest
from app.services.url_dataset import DatasetLookup


def scan_response(status_value="critical"):
    now = datetime.now(timezone.utc)
    return ScanResponse(
        id=uuid4(), input_type="url", status=status_value, risk_score=0, confidence=None,
        threat_type="Unverified", redacted_preview="https://example.com", created_at=now,
        analysis=None, indicators=[],
    )


def runtime_status(available):
    return SandboxStatusResponse(
        status="available" if available else "runtime_unavailable",
        available=available,
        message="ready" if available else "disabled",
        reason=None if available else "sandbox_runtime_disabled",
        capabilities=SandboxCapabilities(
            url_browser_runtime=available,
            restricted_egress=available,
            file_static_analysis=False,
            file_detonation=False,
        ),
    )


class UrlDecisionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.user = SimpleNamespace(id=uuid4())
        self.db = SimpleNamespace(rollback=AsyncMock())
        self.request = URLScanRequest(url="HTTPS://Example.com:443/login#form")

    async def test_malicious_dataset_hit_skips_runtime_and_returns_provenance(self):
        lookup = DatasetLookup(
            status="known_malicious", source_label="phishing", dataset_name="malicious_phish.csv",
            dataset_fingerprint="a" * 64, imported_at=datetime.now(timezone.utc), recorded_at=None,
        )
        with patch("app.routes.scans.lookup_url", new=AsyncMock(return_value=lookup)), \
             patch("app.routes.scans._finish_scan", new=AsyncMock(return_value=SimpleNamespace(id=uuid4(), status="critical", risk_score=100, confidence=1, threat_type="Known malicious", created_at=datetime.now(timezone.utc)))), \
             patch("app.routes.scans._inline_scan", return_value=scan_response()), \
             patch("app.routes.scans.get_sandbox_status", side_effect=AssertionError("dataset hit must skip browser readiness")):
            result = await decide_url_analysis(self.request, self.user, self.db)
        self.assertEqual(result.outcome, "dataset_match")
        self.assertEqual(result.risk_assessment.verdict, "known_malicious")
        self.assertEqual(result.reachability, "not_checked")
        self.assertEqual(result.dataset_lookup.source_label, "phishing")

    async def test_unmatched_low_heuristic_score_never_becomes_safe_without_runtime(self):
        analysis = SimpleNamespace(
            risk_score=0, confidence=0.9, threat_type="Low structural risk", prediction="safe",
            signals=[], features={}, explanation={}, model_name="baseline", model_version="1",
        )
        with patch("app.routes.scans.lookup_url", new=AsyncMock(return_value=DatasetLookup(status="not_listed"))), \
             patch("app.routes.scans.get_sandbox_status", return_value=runtime_status(False)), \
             patch("app.routes.scans.analyze_url", return_value=analysis), \
             patch("app.routes.scans._finish_unverified_url", new=AsyncMock(return_value=scan_response("runtime_unavailable"))):
            result = await decide_url_analysis(self.request, self.user, self.db)
        self.assertEqual(result.outcome, "runtime_unavailable")
        self.assertEqual(result.risk_assessment.verdict, "unverified")
        self.assertEqual(result.reachability, "runtime_unavailable")
        self.assertNotEqual(result.risk_assessment.verdict, "safe")

    async def test_exact_benign_dataset_record_still_hands_off_to_sandbox(self):
        job = SandboxJobResponse(
            id=uuid4(), scan_id=uuid4(), state="queued", created_at=datetime.now(timezone.utc),
        )
        with patch("app.routes.scans.lookup_url", new=AsyncMock(return_value=DatasetLookup(status="non_malicious_label"))), \
             patch("app.routes.scans.get_sandbox_status", return_value=runtime_status(True)), \
             patch("app.routes.scans.submit_url_sandbox", new=AsyncMock(return_value=job)) as handoff:
            result = await decide_url_analysis(self.request, self.user, self.db)
        self.assertEqual(result.outcome, "sandbox_queued")
        self.assertEqual(result.reachability, "pending")
        handoff.assert_awaited_once()

    async def test_dataset_lookup_failure_returns_no_verdict_and_does_not_fall_through(self):
        with patch("app.routes.scans.lookup_url", new=AsyncMock(side_effect=RuntimeError("database unavailable"))), \
             patch("app.routes.scans.get_sandbox_status", side_effect=AssertionError("lookup failure is not a miss")):
            with self.assertRaises(HTTPException) as raised:
                await decide_url_analysis(self.request, self.user, self.db)
        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("no verdict", raised.exception.detail)
        self.db.rollback.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
