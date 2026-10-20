import asyncio
import os
import unittest
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from fastapi import HTTPException
from redis.exceptions import ConnectionError as RedisConnectionError
from starlette.requests import Request

from app.core import rate_limit
from app.core.rate_limit import (
    LOGIN_ATTEMPT_LIMIT,
    LOGIN_ATTEMPT_WINDOW_SECONDS,
    RateLimitUnavailable,
)


class AtomicFakeRedis:
    def __init__(self):
        self.now = 0
        self.values: dict[str, int] = {}
        self.expires: dict[str, int] = {}
        self.lock = asyncio.Lock()
        self.eval_calls = 0

    def _live_value(self, key: str) -> int | None:
        if self.expires.get(key, self.now + 1) <= self.now:
            self.values.pop(key, None)
            self.expires.pop(key, None)
        return self.values.get(key)

    async def get(self, key: str) -> str | None:
        value = self._live_value(key)
        return None if value is None else str(value)

    async def eval(self, script: str, numkeys: int, key: str, window: int) -> int:
        self.eval_calls += 1
        self.assert_atomic_script(script, numkeys)
        async with self.lock:
            current = self._live_value(key) or 0
            attempts = current + 1
            self.values[key] = attempts
            if attempts == 1:
                self.expires[key] = self.now + window
            return attempts

    @staticmethod
    def assert_atomic_script(script: str, numkeys: int) -> None:
        if numkeys != 1 or "redis.call('INCR'" not in script or "redis.call('EXPIRE'" not in script:
            raise AssertionError("Increment and expiry must be performed by one Redis script")

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)
        self.expires.pop(key, None)


class FailingRedis:
    async def get(self, key: str):
        raise RedisConnectionError("redis host and credentials must not leak")

    async def eval(self, *args):
        raise RedisConnectionError("redis host and credentials must not leak")

    async def delete(self, key: str):
        raise RedisConnectionError("redis host and credentials must not leak")


def make_request() -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "path": "/auth/login",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("localhost", 8000),
    })


class FakeDB:
    def __init__(self, user=None):
        self.user = user

    async def execute(self, _statement):
        return SimpleNamespace(scalar_one_or_none=lambda: self.user)


async def no_attempts(_key):
    return 0


class LoginRateLimitTests(unittest.TestCase):
    def test_attempts_below_threshold_and_blocking_at_threshold(self):
        async def scenario():
            client = AtomicFakeRedis()
            with patch.object(rate_limit, "redis_client", client):
                for attempt in range(1, LOGIN_ATTEMPT_LIMIT):
                    self.assertEqual(
                        await rate_limit.record_failed_login("key"), attempt
                    )
                    self.assertFalse(rate_limit.login_is_blocked(attempt))
                attempts = await rate_limit.record_failed_login("key")
                self.assertEqual(attempts, LOGIN_ATTEMPT_LIMIT)
                self.assertTrue(rate_limit.login_is_blocked(attempts))

        asyncio.run(scenario())

    def test_attempt_window_expires_from_first_failure(self):
        async def scenario():
            client = AtomicFakeRedis()
            with patch.object(rate_limit, "redis_client", client):
                await rate_limit.record_failed_login("key")
                first_expiry = client.expires["key"]
                client.now += LOGIN_ATTEMPT_WINDOW_SECONDS - 1
                await rate_limit.record_failed_login("key")
                self.assertEqual(client.expires["key"], first_expiry)
                client.now += 2
                self.assertEqual(await rate_limit.get_login_attempts("key"), 0)
                self.assertEqual(await rate_limit.record_failed_login("key"), 1)
                self.assertEqual(
                    client.expires["key"], client.now + LOGIN_ATTEMPT_WINDOW_SECONDS
                )

        asyncio.run(scenario())

    def test_concurrent_attempts_are_atomic(self):
        async def scenario():
            client = AtomicFakeRedis()
            with patch.object(rate_limit, "redis_client", client):
                results = await asyncio.gather(*[
                    rate_limit.record_failed_login("key") for _ in range(32)
                ])
                self.assertEqual(sorted(results), list(range(1, 33)))
                self.assertEqual(await rate_limit.get_login_attempts("key"), 32)
                self.assertEqual(client.eval_calls, 32)
                self.assertEqual(
                    client.expires["key"], LOGIN_ATTEMPT_WINDOW_SECONDS
                )

        asyncio.run(scenario())

    def test_redis_connection_errors_become_unavailable_state(self):
        async def scenario():
            with patch.object(rate_limit, "redis_client", FailingRedis()):
                for operation in (
                    rate_limit.get_login_attempts("key"),
                    rate_limit.record_failed_login("key"),
                    rate_limit.clear_login_attempts("key"),
                ):
                    with self.assertRaises(RateLimitUnavailable):
                        await operation

        asyncio.run(scenario())

    def test_login_returns_generic_503_when_rate_limit_read_fails(self):
        from app.routes import auth
        from app.schemas.auth import LoginRequest

        async def fail_read(_key):
            raise RateLimitUnavailable

        async def scenario():
            with patch.object(auth, "get_login_attempts", fail_read):
                with self.assertRaises(HTTPException) as raised:
                    await auth.login_user(
                        LoginRequest(email="person@example.com", password="password123"),
                        make_request(),
                        FakeDB(),
                    )
                self.assertEqual(raised.exception.status_code, 503)
                self.assertEqual(
                    raised.exception.detail,
                    "Authentication is temporarily unavailable. Please try again later.",
                )

        asyncio.run(scenario())

    def test_login_returns_503_when_failure_recording_fails(self):
        from app.routes import auth
        from app.schemas.auth import LoginRequest

        async def fail_record(_key):
            raise RateLimitUnavailable

        async def scenario():
            with (
                patch.object(auth, "get_login_attempts", no_attempts),
                patch.object(auth, "record_failed_login", fail_record),
            ):
                with self.assertRaises(HTTPException) as raised:
                    await auth.login_user(
                        LoginRequest(email="person@example.com", password="password123"),
                        make_request(),
                        FakeDB(),
                    )
                self.assertEqual(raised.exception.status_code, 503)

        asyncio.run(scenario())

    def test_login_does_not_authenticate_when_clearing_limit_fails(self):
        from app.routes import auth
        from app.schemas.auth import LoginRequest

        user = SimpleNamespace(
            id=uuid4(),
            name="Person",
            email="person@example.com",
            password_hash="test-hash",
            is_active=True,
        )

        async def fail_clear(_key):
            raise RateLimitUnavailable

        async def scenario():
            with (
                patch.object(auth, "get_login_attempts", no_attempts),
                patch.object(auth, "verify_password", return_value=True),
                patch.object(auth, "clear_login_attempts", fail_clear),
                patch.object(auth, "create_access_token") as create_token,
            ):
                with self.assertRaises(HTTPException) as raised:
                    await auth.login_user(
                        LoginRequest(email="person@example.com", password="password123"),
                        make_request(),
                        FakeDB(user),
                    )
                self.assertEqual(raised.exception.status_code, 503)
                create_token.assert_not_called()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
