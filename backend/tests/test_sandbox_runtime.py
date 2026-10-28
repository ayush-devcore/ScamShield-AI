import asyncio
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from fastapi import HTTPException

from app.db.models import User
from app.routes.sandbox import submit_url_sandbox, validate_sandbox_url
from app.schemas.sandbox import SandboxUrlRequest
from app.services.sandbox_runtime import get_sandbox_status


class SandboxUnavailableTests(unittest.TestCase):
    def setUp(self):
        self.user = User(
            id=uuid4(), name="Sandbox Tester", email="sandbox@example.test",
            password_hash="unused", is_active=True,
        )

    def test_capabilities_are_unavailable_when_runtime_flag_is_disabled(self):
        with patch("app.services.sandbox_runtime.settings.sandbox_runtime_enabled", False):
            status = get_sandbox_status()
        self.assertFalse(status.available)
        self.assertEqual(status.status, "runtime_unavailable")
        self.assertEqual(status.reason, "sandbox_runtime_disabled")
        self.assertFalse(status.capabilities.url_browser_runtime)
        self.assertFalse(status.capabilities.restricted_egress)
        self.assertFalse(status.capabilities.file_static_analysis)
        self.assertFalse(status.capabilities.file_detonation)

    def test_valid_target_is_rejected_when_runtime_flag_is_disabled(self):
        async def run():
            with patch("app.services.sandbox_runtime.settings.sandbox_runtime_enabled", False), \
                 self.assertRaises(HTTPException) as raised:
                await submit_url_sandbox(
                    SandboxUrlRequest(url="https://example.com/path?token=synthetic"),
                    self.user,
                    object(),
                )
            self.assertEqual(raised.exception.status_code, 503)
            self.assertNotIn("synthetic", str(raised.exception.detail))

        asyncio.run(run())

    def test_runtime_enabled_without_network_verification_remains_unavailable(self):
        with patch("app.services.sandbox_runtime.settings.sandbox_runtime_enabled", True), \
             patch("app.services.sandbox_runtime.settings.sandbox_network_verified", False):
            status = get_sandbox_status()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "network_isolation_not_verified")

    def test_valid_public_http_and_https_urls(self):
        for target in ("https://example.com/a?secret=synthetic", "http://example.org:80/", "https://[2606:4700:4700::1111]/"):
            with self.subTest(target="public URL"):
                validate_sandbox_url(target)

    def test_malformed_credentials_nonstandard_ports_and_private_destinations_rejected(self):
        for target in (
            "file:///etc/passwd", "ftp://example.com/file", "https://user:password@example.com/",
            "https://[::1", "https://example.com:invalid/", "https://example.com:8443/",
            "http://localhost/", "http://service.internal/", "http://127.0.0.1/",
            "http://2130706433/", "http://0177.0.0.1/", "http://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/latest/meta-data/", "http://192.168.1.1/",
        ):
            with self.subTest(target="blocked URL"):
                with self.assertRaises(HTTPException) as raised:
                    validate_sandbox_url(target)
                self.assertEqual(raised.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
