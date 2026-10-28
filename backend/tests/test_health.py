import os
import unittest
from unittest.mock import AsyncMock, Mock

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from fastapi import HTTPException

from app.routes.health import health_check


class HealthCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_healthy_readiness_response_does_not_disclose_database_details(self):
        result = Mock()
        result.scalar_one.return_value = 1
        database = Mock()
        database.execute = AsyncMock(return_value=result)

        response = await health_check(database)

        self.assertEqual(response, {"service": "ScamShield AI", "status": "healthy"})
        database.execute.assert_awaited_once()

    async def test_database_failure_returns_generic_unavailable_response(self):
        database = Mock()
        database.execute = AsyncMock(side_effect=RuntimeError("synthetic connection failure with secret-like details"))

        with self.assertLogs("app.routes.health", level="WARNING") as captured:
            with self.assertRaises(HTTPException) as raised:
                await health_check(database)

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail, "Service temporarily unavailable.")
        self.assertEqual(len(captured.output), 1)
        self.assertNotIn("secret-like details", captured.output[0])


if __name__ == "__main__":
    unittest.main()
