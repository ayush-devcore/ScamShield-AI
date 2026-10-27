import asyncio
import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.core.dependencies import get_current_user
from app.core.security import create_access_token
from app.db.models import User, UserSession
from app.routes.auth import list_sessions


class SessionAuthFakeDB:
    def __init__(self, user, session):
        self.user = user
        self.session = session
        self.commits = 0

    async def execute(self, statement):
        query = str(statement).lower()
        if "from user_sessions" in query:
            return SimpleNamespace(
                scalar_one_or_none=lambda: self.session,
                scalars=lambda: SimpleNamespace(all=lambda: [self.session]),
            )
        if "from users" in query:
            return SimpleNamespace(scalar_one_or_none=lambda: self.user)
        raise AssertionError("Unexpected query in focused auth test")

    async def commit(self):
        self.commits += 1


def request_with_state():
    request = Request({
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/api/v1/auth/sessions",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("localhost", 8000),
    })
    return request


class AuthSessionContextTests(unittest.TestCase):
    def setUp(self):
        self.user = User(
            id=uuid4(), name="Test User", email="test@example.com",
            password_hash="unused", is_active=True,
        )
        now = datetime.now(timezone.utc)
        self.session = UserSession(
            id=uuid4(), user_id=self.user.id,
            expires_at=now + timedelta(minutes=30),
            last_activity_at=now, revoked_at=None, user_agent="Test browser",
            created_at=now,
        )

    def test_session_routes_reuse_the_validated_session_context(self):
        async def scenario():
            db = SessionAuthFakeDB(self.user, self.session)
            request = request_with_state()
            token = create_access_token(str(self.user.id), str(self.session.id))
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

            authenticated_user = await get_current_user(request, credentials, db)
            sessions = await list_sessions(request, authenticated_user, db)

            self.assertEqual(authenticated_user.id, self.user.id)
            self.assertEqual(request.state.auth_session_id, self.session.id)
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].current)
            self.assertEqual(db.commits, 1)

        asyncio.run(scenario())

    def test_expired_and_revoked_sessions_remain_rejected(self):
        async def scenario():
            for changes in (
                {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)},
                {"revoked_at": datetime.now(timezone.utc)},
            ):
                session = UserSession(
                    id=uuid4(), user_id=self.user.id,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                    last_activity_at=datetime.now(timezone.utc), revoked_at=None,
                    created_at=datetime.now(timezone.utc),
                )
                for key, value in changes.items():
                    setattr(session, key, value)
                db = SessionAuthFakeDB(self.user, session)
                request = request_with_state()
                token = create_access_token(str(self.user.id), str(session.id))
                credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
                with self.assertRaises(HTTPException) as raised:
                    await get_current_user(request, credentials, db)
                self.assertEqual(raised.exception.status_code, 401)
                self.assertFalse(hasattr(request.state, "auth_session_id"))

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
