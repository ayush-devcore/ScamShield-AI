import asyncio
import contextlib
import io
import sys
import types
import unittest
from datetime import timezone
from types import SimpleNamespace
from unittest.mock import patch

from scripts.redact_legacy_scan_data import (
    _run,
    transform_analysis,
    transform_indicator,
    transform_scan,
)


class ScanPrivacyBackfillTests(unittest.TestCase):
    def test_dry_run_uses_only_readonly_aggregate_queries(self):
        calls = []
        counts = {
            "eligible_scans": 23,
            "scans_with_input_hash": 21,
            "scans_with_preview": 6,
            "analysis_results": 22,
            "analysis_with_features": 22,
            "analysis_with_explanation": 22,
            "threat_indicators": 36,
            "indicators_with_evidence": 36,
            "indicators_with_description": 36,
        }

        class Result:
            def one(self):
                return SimpleNamespace(_mapping=counts)

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            @contextlib.asynccontextmanager
            async def begin(self):
                yield

            async def execute(self, statement, params=None):
                calls.append((str(statement), params))
                return Result()

        async def dispose():
            return None

        session_module = types.ModuleType("app.db.session")
        session_module.AsyncSessionLocal = Session
        session_module.engine = SimpleNamespace(dispose=dispose)

        output = io.StringIO()
        with patch.dict(sys.modules, {"app.db.session": session_module}), contextlib.redirect_stdout(output):
            asyncio.run(_run(SimpleNamespace(apply=False, batch_size=100)))

        self.assertEqual(len(calls), 2)
        self.assertIn("SET TRANSACTION READ ONLY", calls[0][0])
        sql = calls[1][0].lower()
        self.assertIn("count(*)", sql)
        self.assertNotIn("select scans.", sql)
        self.assertNotIn("select ar.", sql)
        self.assertNotIn("select ti.", sql)
        self.assertEqual(calls[1][1]["cutoff"].tzinfo, timezone.utc)
        self.assertIn("eligible_scans:23", output.getvalue())
        self.assertIn("analysis_results:22", output.getvalue())
        self.assertIn("threat_indicators:36", output.getvalue())
        self.assertIn("intentionally not calculated", output.getvalue())

    def test_scan_preview_is_minimized_and_hash_is_cleared(self):
        scan = SimpleNamespace(
            input_type="url",
            redacted_preview="https://user:secret@safe.example/private?arbitrary=token#fragment",
            input_hash="old-input-hash",
        )
        preview, input_hash = transform_scan(scan)
        self.assertEqual(preview, "https://safe.example")
        self.assertIsNone(input_hash)

    def test_analysis_redacts_sensitive_fields_but_preserves_structure(self):
        secret_url = "https://safe.example/reset/private?unknown=session-secret#fragment"
        analysis = SimpleNamespace(
            features={"hostname": "safe.example", "url_count": 1, "urls": [secret_url]},
            explanation={"source_text_preview": "private message", "summary": "Suspicious link"},
        )
        features, explanation = transform_analysis(analysis)
        self.assertEqual(features["url_count"], 1)
        self.assertEqual(features["hostname"], "safe.example")
        self.assertEqual(features["urls"], ["https://safe.example"])
        self.assertNotIn("source_text_preview", explanation)
        self.assertEqual(explanation["summary"], "Suspicious link")

    def test_only_sensitive_description_is_replaced(self):
        safe = SimpleNamespace(
            indicator_type="suspicious_path",
            description="The link uses an unusual path structure.",
            evidence={"path": "/reset/private", "hostname": "safe.example"},
        )
        evidence, description = transform_indicator(safe)
        self.assertEqual(description, safe.description)
        self.assertNotIn("path", evidence)
        self.assertEqual(evidence["hostname"], "safe.example")

        sensitive = SimpleNamespace(
            indicator_type="credential_request",
            description="Reset URL https://safe.example/reset/private?x=secret",
            evidence=None,
        )
        _, safe_description = transform_indicator(sensitive)
        self.assertEqual(
            safe_description,
            "The content references credentials such as passwords or one-time codes.",
        )

    def test_reapplication_is_idempotent(self):
        scan = SimpleNamespace(input_type="message", redacted_preview="Message scan", input_hash=None)
        self.assertEqual(transform_scan(scan), ("Message scan", None))
        analysis = SimpleNamespace(features={"url_count": 1}, explanation={"summary": "Safe"})
        first = transform_analysis(analysis)
        self.assertEqual(first, transform_analysis(SimpleNamespace(features=first[0], explanation=first[1])))


if __name__ == "__main__":
    unittest.main()
