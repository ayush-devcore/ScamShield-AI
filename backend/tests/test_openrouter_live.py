"""Opt-in single-request smoke test; never calls OpenRouter in ordinary suites."""

import asyncio
import os
import unittest
import uuid

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from app.core.config import settings
from app.services.openrouter_messages import classify_message


@unittest.skipUnless(
    os.environ.get("RUN_OPENROUTER_INTEGRATION") == "1" and bool(settings.openrouter_api_key),
    "Set RUN_OPENROUTER_INTEGRATION=1 with a server-side OpenRouter key for one paid smoke request.",
)
class OpenRouterLiveSmokeTest(unittest.TestCase):
    def test_one_short_message_returns_valid_structured_output(self):
        result = asyncio.run(classify_message(
            "The neighborhood library will hold a free book event Saturday.",
            f"manual-integration-{uuid.uuid4()}",
        ))
        self.assertEqual(result.status, "ok")
        self.assertIsNotNone(result.assessment)
        self.assertGreaterEqual(result.latency_ms or 0, 0)


if __name__ == "__main__":
    unittest.main()
