import csv
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from app.services.url_dataset import canonical_url_hashes, canonicalize_url, lookup_url
from scripts.import_url_dataset import stage_dataset


class UrlDatasetCanonicalizationTests(unittest.TestCase):
    def test_harmless_scheme_host_default_port_and_fragment_normalization(self):
        self.assertEqual(
            canonicalize_url("HTTP://ExAmPle.com:80/a?token=x#section"),
            "http://example.com/a?token=x",
        )
        self.assertEqual(
            canonicalize_url("https://example.com:443/a?token=x#other"),
            "https://example.com/a?token=x",
        )

    def test_scheme_agnostic_source_key_remains_exact_by_path_and_query(self):
        source_hash = canonical_url_hashes("https://shared.example/path/a?x=1")[1]
        unrelated_path_hash = canonical_url_hashes("https://shared.example/path/b?x=1")[1]
        unrelated_query_hash = canonical_url_hashes("https://shared.example/path/a?x=2")[1]
        self.assertNotEqual(source_hash, unrelated_path_hash)
        self.assertNotEqual(source_hash, unrelated_query_hash)


class UrlDatasetLookupTests(unittest.IsolatedAsyncioTestCase):
    async def test_scheme_less_dataset_entry_matches_exact_host_path_for_http_or_https(self):
        class Result:
            def scalars(self):
                return self
            def all(self):
                return [SimpleNamespace(
                    source_label="phishing", dataset_name="malicious_phish.csv", record_source=None,
                    canonical_hash=canonical_url_hashes("https://example.com/login")[1],
                    dataset_fingerprint="f" * 64, imported_at=datetime.now(timezone.utc), recorded_at=None,
                )]
        session = SimpleNamespace(execute=AsyncMock(return_value=Result()))
        result = await lookup_url(session, "https://example.com/login")
        self.assertEqual(result.status, "known_malicious")
        self.assertEqual(result.source_label, "phishing")
        session.execute.assert_awaited_once()

    async def test_benign_label_is_not_a_safe_verdict(self):
        class Result:
            def scalars(self):
                return self
            def all(self):
                return [SimpleNamespace(source_label="benign", dataset_name="feed.csv", record_source=None,
                    canonical_hash=canonical_url_hashes("https://example.com/")[0],
                    dataset_fingerprint="f" * 64, imported_at=datetime.now(timezone.utc), recorded_at=None)]
        result = await lookup_url(SimpleNamespace(execute=AsyncMock(return_value=Result())), "https://example.com/")
        self.assertEqual(result.status, "non_malicious_label")

    async def test_conflicting_dataset_labels_are_ambiguous(self):
        class Result:
            def scalars(self):
                return self
            def all(self):
                common = dict(dataset_name="feed.csv", record_source=None, dataset_fingerprint="f" * 64,
                              imported_at=datetime.now(timezone.utc), recorded_at=None)
                return [SimpleNamespace(source_label="benign", canonical_hash=canonical_url_hashes("https://example.com/")[0], **common),
                        SimpleNamespace(source_label="malware", canonical_hash=canonical_url_hashes("https://example.com/")[1], **common)]
        result = await lookup_url(SimpleNamespace(execute=AsyncMock(return_value=Result())), "https://example.com/")
        self.assertEqual(result.status, "ambiguous")

    async def test_lookup_failure_is_not_interpreted_as_a_miss(self):
        session = SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError("database unavailable")))
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            await lookup_url(session, "https://example.com/")


class UrlDatasetImportTests(unittest.TestCase):
    def test_streaming_import_counts_duplicates_conflicts_malformed_and_labels(self):
        rows = [
            ("https://a.example/login", "phishing"),
            ("HTTPS://A.EXAMPLE:443/login#form", "phishing"),
            ("SHARED.example/login", "benign"),
            ("shared.example/login", "malware"),
            ("bad url", "phishing"),
            ("https://unknown.example/", "unknown"),
            ("https://b.example/ok", "benign"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "fixture.csv"
            with dataset.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(("url", "type"))
                writer.writerows(rows)
            stage, summary = stage_dataset(dataset)
            try:
                self.assertEqual(summary["input_rows"], 7)
                self.assertEqual(summary["accepted_rows"], 2)
                self.assertEqual(summary["duplicate_rows"], 2)
                self.assertEqual(summary["ambiguous_records"], 1)
                self.assertEqual(summary["malformed_records"], 2)
                self.assertEqual(summary["records_by_label"], {"benign": 1, "phishing": 1})
            finally:
                stage.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
