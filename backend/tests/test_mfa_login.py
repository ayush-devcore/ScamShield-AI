import asyncio
from datetime import datetime, timedelta, timezone
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from cryptography.fernet import Fernet
from fastapi import HTTPException
import jwt
import pyotp
from starlette.requests import Request

from app.core.config import settings
from app.core import rate_limit
from app.core.rate_limit import LOGIN_ATTEMPT_LIMIT, RateLimitUnavailable
from app.core.security import create_mfa_challenge, hash_password, verify_password
from app.db.models import RecoveryCode, User, UserMfa, UserSession
from app.routes import auth
from app.schemas.auth import AuthenticatorPasswordResetRequest, LoginRequest, MfaCodeRequest, MfaLoginRequest
from app.services.mfa import encrypt_secret, hash_recovery_code, new_secret


# Set up test keys if needed
if not settings.mfa_encryption_key:
    settings.mfa_encryption_key = Fernet.generate_key().decode()
if len(settings.jwt_secret_key.encode()) < 32:
    settings.jwt_secret_key = "test-only-secret-32-bytes-minimum-key!"


class AtomicFakeRedis:
    def __init__(self):
        self.now = 0
        self.values: dict[str, str | int] = {}
        self.expires: dict[str, int] = {}
        self.lock = asyncio.Lock()
        self.eval_calls = 0

    def _live_value(self, key: str) -> str | int | None:
        if self.expires.get(key, self.now + 1) <= self.now:
            self.values.pop(key, None)
            self.expires.pop(key, None)
        return self.values.get(key)

    async def get(self, key: str) -> str | None:
        value = self._live_value(key)
        return None if value is None else str(value)

    async def set(self, key: str, value: str, ex: int | None = None, nx: bool = False) -> bool | None:
        async with self.lock:
            if nx and self._live_value(key) is not None:
                return None
            self.values[key] = value
            if ex is not None:
                self.expires[key] = self.now + ex
            return True

    async def eval(self, script: str, numkeys: int, key: str, window: int) -> int:
        self.eval_calls += 1
        async with self.lock:
            current = int(self._live_value(key) or 0)
            attempts = current + 1
            self.values[key] = attempts
            if attempts == 1:
                self.expires[key] = self.now + window
            return attempts

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)
        self.expires.pop(key, None)


class FailingRedis:
    async def get(self, key: str):
        raise RateLimitUnavailable("redis unavailable")

    async def set(self, *args, **kwargs):
        raise RateLimitUnavailable("redis unavailable")

    async def eval(self, *args, **kwargs):
        raise RateLimitUnavailable("redis unavailable")

    async def delete(self, key: str):
        raise RateLimitUnavailable("redis unavailable")


def make_request(client_ip: str = "127.0.0.1") -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "path": "/auth/mfa/login",
        "query_string": b"",
        "headers": [],
        "client": (client_ip, 12345),
        "server": ("localhost", 8000),
    })


class FakeDB:
    def __init__(self, user=None, mfa=None, recovery_codes=None, recovery_lock=None, session_records=None):
        self.user = user
        self.mfa = mfa
        self.sessions: list[UserSession] = []
        self.session_records = session_records if session_records is not None else []
        self.added = []
        self.commits = 0
        self.recovery_codes = recovery_codes if recovery_codes is not None else []
        self.recovery_lock = recovery_lock or asyncio.Lock()
        self._recovery_lock_held = False

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, UserSession):
            self.sessions.append(obj)
            self.session_records.append(obj)
        elif isinstance(obj, UserMfa):
            self.mfa = obj

    async def commit(self):
        self.commits += 1
        self._release_recovery_lock()

    async def refresh(self, obj):
        pass

    async def rollback(self):
        self._release_recovery_lock()

    def _release_recovery_lock(self):
        if self._recovery_lock_held:
            self.recovery_lock.release()
            self._recovery_lock_held = False

    async def execute(self, statement):
        stmt_str = str(statement).lower()
        if "recovery_codes" in stmt_str:
            if self.recovery_codes and not self._recovery_lock_held:
                await self.recovery_lock.acquire()
                self._recovery_lock_held = True
            return SimpleNamespace(
                scalar_one_or_none=lambda: None,
                scalars=lambda: SimpleNamespace(
                    all=lambda: [row for row in self.recovery_codes if row.user_id == getattr(self.user, "id", None) and row.used_at is None]
                ),
            )
        if "user_sessions" in stmt_str and stmt_str.lstrip().startswith("select"):
            rows = [
                row for row in self.session_records
                if row.user_id == getattr(self.user, "id", None) and row.revoked_at is None
            ]
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
        if "from user_mfa" in stmt_str or "user_mfa" in stmt_str:
            return SimpleNamespace(scalar_one_or_none=lambda: self.mfa)
        if "from users" in stmt_str or "users" in stmt_str:
            return SimpleNamespace(scalar_one_or_none=lambda: self.user)
        return SimpleNamespace(scalar_one_or_none=lambda: None)


class MfaLoginRegressionTests(unittest.TestCase):
    def setUp(self):
        self.secret = new_secret()
        self.user_id = uuid4()
        self.user = User(
            id=self.user_id,
            name="Security Tester",
            email="security@example.com",
            password_hash=hash_password("correct-password-123"),
            is_active=True,
        )
        self.mfa = UserMfa(
            user_id=self.user_id,
            secret_encrypted=encrypt_secret(self.secret),
            pending_secret_encrypted=None,
            enabled_at=datetime.now(timezone.utc),
        )

    def test_valid_mfa_verification_succeeds(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            challenge = create_mfa_challenge(str(self.user_id))
            code = pyotp.TOTP(self.secret).now()

            with patch.object(rate_limit, "redis_client", redis_fake):
                response = await auth.complete_mfa_login(
                    MfaLoginRequest(challenge=challenge, code=code),
                    make_request(),
                    db=db,
                )

                self.assertIsNotNone(response.access_token)
                self.assertEqual(response.token_type, "bearer")
                self.assertEqual(len(db.sessions), 1)
                self.assertEqual(db.sessions[0].user_id, self.user_id)

        asyncio.run(scenario())

    def test_authenticator_can_authorize_password_recovery_and_replay_is_blocked(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            old_session = UserSession(
                user_id=self.user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                last_activity_at=datetime.now(timezone.utc),
            )
            other_user = User(id=uuid4(), name="Other", email="other@example.com", password_hash=hash_password("other-password"), is_active=True)
            other_session = UserSession(
                user_id=other_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                last_activity_at=datetime.now(timezone.utc),
            )
            all_sessions = [old_session, other_session]
            db = FakeDB(user=self.user, mfa=self.mfa, session_records=all_sessions)
            code = pyotp.TOTP(self.secret).now()
            payload = AuthenticatorPasswordResetRequest(
                email=self.user.email,
                code=code,
                new_password="new-strong-password",
                confirm_password="new-strong-password",
            )

            with patch.object(rate_limit, "redis_client", redis_fake):
                response = await auth.reset_password_with_authenticator(payload, make_request(), db)
                self.assertEqual(response["message"], "Password updated. Sign in with your new password.")
                self.assertTrue(verify_password("new-strong-password", self.user.password_hash))
                self.assertIsNotNone(old_session.revoked_at)
                self.assertIsNone(other_session.revoked_at)
                self.assertEqual(db.sessions, [])
                self.assertTrue(any(getattr(row, "event_type", None) == "password_reset_completed" for row in db.added))

                with self.assertRaises(HTTPException) as raised:
                    await auth.reset_password_with_authenticator(payload, make_request(), db)
                await db.rollback()

            self.assertEqual(raised.exception.status_code, 401)
            self.assertEqual(raised.exception.detail, auth._PASSWORD_RESET_FAILURE)
            self.assertTrue(verify_password("new-strong-password", self.user.password_hash))

        asyncio.run(scenario())

    def test_recovery_code_authorizes_reset_once_and_preserves_other_users_data(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            other_user = User(id=uuid4(), name="Other", email="other@example.com", password_hash=hash_password("other-password"), is_active=True)
            own_code = RecoveryCode(user_id=self.user_id, code_hash=hash_recovery_code("MY-RECOVERY-CODE"))
            other_code = RecoveryCode(user_id=other_user.id, code_hash=hash_recovery_code("OTHER-RECOVERY-CODE"))
            other_session = UserSession(
                user_id=other_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                last_activity_at=datetime.now(timezone.utc),
            )
            all_sessions = [other_session]
            db = FakeDB(user=self.user, mfa=self.mfa, recovery_codes=[own_code, other_code], session_records=all_sessions)
            payload = AuthenticatorPasswordResetRequest(
                email=self.user.email,
                code="MY-RECOVERY-CODE",
                new_password="recovered-password",
                confirm_password="recovered-password",
            )

            with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                await auth.reset_password_with_authenticator(payload, make_request(), db)
                self.assertIsNotNone(own_code.used_at)
                self.assertIsNone(other_code.used_at)
                self.assertIsNone(other_session.revoked_at)
                with self.assertRaises(HTTPException) as raised:
                    await auth.reset_password_with_authenticator(payload, make_request(), db)
                await db.rollback()

            self.assertEqual(raised.exception.status_code, 401)
            self.assertEqual(raised.exception.detail, auth._PASSWORD_RESET_FAILURE)
            self.assertEqual(len(db.sessions), 0)
            self.assertTrue(verify_password("recovered-password", self.user.password_hash))

        asyncio.run(scenario())

    def test_invalid_and_unconfigured_recovery_cannot_change_password_or_create_session(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            original_hash = self.user.password_hash
            valid_payload = AuthenticatorPasswordResetRequest(
                email=self.user.email,
                code="INVALID-RECOVERY-CODE",
                new_password="another-new-password",
                confirm_password="another-new-password",
            )
            db = FakeDB(user=self.user, mfa=self.mfa, recovery_codes=[])
            with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                with self.assertRaises(HTTPException) as raised:
                    await auth.reset_password_with_authenticator(valid_payload, make_request(), db)
                await db.rollback()
            self.assertEqual(raised.exception.status_code, 401)
            self.assertEqual(raised.exception.detail, auth._PASSWORD_RESET_FAILURE)
            self.assertEqual(self.user.password_hash, original_hash)
            self.assertEqual(db.sessions, [])

            disabled_mfa = UserMfa(
                user_id=self.user_id,
                secret_encrypted=encrypt_secret(self.secret),
                pending_secret_encrypted=None,
                enabled_at=None,
            )
            db_disabled = FakeDB(user=self.user, mfa=disabled_mfa)
            with patch.object(rate_limit, "redis_client", redis_fake):
                with self.assertRaises(HTTPException) as disabled:
                    await auth.reset_password_with_authenticator(valid_payload, make_request(), db_disabled)
            self.assertEqual(disabled.exception.status_code, 401)
            self.assertEqual(disabled.exception.detail, auth._PASSWORD_RESET_FAILURE)
            self.assertEqual(self.user.password_hash, original_hash)
            self.assertEqual(db_disabled.sessions, [])

            db_unconfigured = FakeDB(user=self.user, mfa=None)
            with patch.object(rate_limit, "redis_client", redis_fake):
                with self.assertRaises(HTTPException) as unconfigured:
                    await auth.reset_password_with_authenticator(valid_payload, make_request(), db_unconfigured)
            self.assertEqual(unconfigured.exception.status_code, 401)
            self.assertEqual(unconfigured.exception.detail, auth._PASSWORD_RESET_FAILURE)
            self.assertEqual(self.user.password_hash, original_hash)
            self.assertEqual(db_unconfigured.sessions, [])

        asyncio.run(scenario())

    def test_password_recovery_rate_limited_after_failed_codes(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            payload = AuthenticatorPasswordResetRequest(
                email=self.user.email,
                code="INVALID-RECOVERY-CODE",
                new_password="another-new-password",
                confirm_password="another-new-password",
            )

            with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                for _ in range(LOGIN_ATTEMPT_LIMIT - 1):
                    with self.assertRaises(HTTPException) as raised:
                        await auth.reset_password_with_authenticator(payload, make_request(), db)
                    await db.rollback()
                    self.assertEqual(raised.exception.status_code, 401)
                    self.assertEqual(raised.exception.detail, auth._PASSWORD_RESET_FAILURE)
                with self.assertRaises(HTTPException) as blocked:
                    await auth.reset_password_with_authenticator(payload, make_request(), db)

            self.assertEqual(blocked.exception.status_code, 429)
            self.assertEqual(db.sessions, [])

        asyncio.run(scenario())

    def test_password_recovery_fails_closed_when_redis_is_unavailable(self):
        async def scenario():
            db = FakeDB(user=self.user, mfa=self.mfa)
            original_hash = self.user.password_hash
            payload = AuthenticatorPasswordResetRequest(
                email=self.user.email,
                code=pyotp.TOTP(self.secret).now(),
                new_password="another-new-password",
                confirm_password="another-new-password",
            )

            with patch.object(rate_limit, "redis_client", FailingRedis()):
                with self.assertRaises(HTTPException) as raised:
                    await auth.reset_password_with_authenticator(payload, make_request(), db)

            self.assertEqual(raised.exception.status_code, 503)
            self.assertIn("temporarily unavailable", raised.exception.detail)
            self.assertEqual(self.user.password_hash, original_hash)
            self.assertEqual(db.sessions, [])

        asyncio.run(scenario())

    def test_valid_recovery_code_completes_login_and_is_consumed(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            recovery = RecoveryCode(
                user_id=self.user_id,
                code_hash=hash_recovery_code("TEST-RECOVERY-CODE"),
            )
            db = FakeDB(user=self.user, mfa=self.mfa, recovery_codes=[recovery])
            challenge = create_mfa_challenge(str(self.user_id))

            with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                response = await auth.complete_mfa_login(
                    MfaLoginRequest(challenge=challenge, code="TEST-RECOVERY-CODE"),
                    make_request(),
                    db=db,
                )

            self.assertTrue(response.access_token)
            self.assertEqual(len(db.sessions), 1)
            self.assertEqual(db.sessions[0].user_id, self.user_id)
            self.assertIsNotNone(recovery.used_at)
            self.assertEqual(db.commits, 1)

        asyncio.run(scenario())

    def test_recovery_code_cannot_be_reused_with_a_new_challenge(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            recovery = RecoveryCode(
                user_id=self.user_id,
                code_hash=hash_recovery_code("TEST-RECOVERY-CODE"),
            )
            db = FakeDB(user=self.user, mfa=self.mfa, recovery_codes=[recovery])

            with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                first = await auth.complete_mfa_login(
                    MfaLoginRequest(
                        challenge=create_mfa_challenge(str(self.user_id)),
                        code="TEST-RECOVERY-CODE",
                    ),
                    make_request(),
                    db=db,
                )
                self.assertTrue(first.access_token)
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(
                            challenge=create_mfa_challenge(str(self.user_id)),
                            code="TEST-RECOVERY-CODE",
                        ),
                        make_request(),
                        db=db,
                    )
                await db.rollback()

            self.assertEqual(raised.exception.status_code, 401)
            self.assertEqual(raised.exception.detail, "Invalid verification code.")
            self.assertEqual(len(db.sessions), 1)
            self.assertIsNotNone(recovery.used_at)

        asyncio.run(scenario())

    def test_invalid_recovery_code_is_rejected_generically(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            recovery = RecoveryCode(
                user_id=self.user_id,
                code_hash=hash_recovery_code("ANOTHER-TEST-CODE"),
            )
            db = FakeDB(user=self.user, mfa=self.mfa, recovery_codes=[recovery])

            with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(
                            challenge=create_mfa_challenge(str(self.user_id)),
                            code="INVALID-TEST-CODE",
                        ),
                        make_request(),
                        db=db,
                    )
                await db.rollback()

            self.assertEqual(raised.exception.status_code, 401)
            self.assertEqual(raised.exception.detail, "Invalid verification code.")
            self.assertEqual(db.sessions, [])
            self.assertIsNone(recovery.used_at)

        asyncio.run(scenario())

    def test_concurrent_recovery_attempts_consume_code_at_most_once(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            recovery = RecoveryCode(
                user_id=self.user_id,
                code_hash=hash_recovery_code("TEST-RECOVERY-CODE"),
            )
            shared_rows = [recovery]
            row_lock = asyncio.Lock()
            dbs = [
                FakeDB(user=self.user, mfa=self.mfa, recovery_codes=shared_rows, recovery_lock=row_lock)
                for _ in range(2)
            ]
            challenges = [create_mfa_challenge(str(self.user_id)) for _ in range(2)]

            async def submit(db, challenge):
                try:
                    with patch.object(rate_limit, "redis_client", redis_fake), patch.object(auth, "valid_code", return_value=False):
                        return await auth.complete_mfa_login(
                            MfaLoginRequest(challenge=challenge, code="TEST-RECOVERY-CODE"),
                            make_request(),
                            db=db,
                        )
                except HTTPException as error:
                    await db.rollback()
                    return error

            results = await asyncio.gather(*(submit(db, challenge) for db, challenge in zip(dbs, challenges)))
            successes = [result for result in results if not isinstance(result, HTTPException)]
            failures = [result for result in results if isinstance(result, HTTPException)]

            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0].status_code, 401)
            self.assertEqual(failures[0].detail, "Invalid verification code.")
            self.assertEqual(sum(len(db.sessions) for db in dbs), 1)
            self.assertIsNotNone(recovery.used_at)

        asyncio.run(scenario())

    def test_challenge_cannot_be_reused(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            challenge = create_mfa_challenge(str(self.user_id))
            code = pyotp.TOTP(self.secret).now()

            with patch.object(rate_limit, "redis_client", redis_fake):
                # First attempt succeeds
                first_response = await auth.complete_mfa_login(
                    MfaLoginRequest(challenge=challenge, code=code),
                    make_request(),
                    db=db,
                )
                self.assertIsNotNone(first_response.access_token)
                self.assertEqual(len(db.sessions), 1)

                # Replay with same challenge fails
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=code),
                        make_request(),
                        db=db,
                    )
                self.assertEqual(raised.exception.status_code, 401)
                self.assertEqual(raised.exception.detail, "Invalid or expired verification challenge.")
                # No additional session created
                self.assertEqual(len(db.sessions), 1)

        asyncio.run(scenario())

    def test_concurrent_requests_using_same_challenge_cannot_both_issue_sessions(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            challenge = create_mfa_challenge(str(self.user_id))
            code = pyotp.TOTP(self.secret).now()

            with patch.object(rate_limit, "redis_client", redis_fake):
                async def submit():
                    try:
                        return await auth.complete_mfa_login(
                            MfaLoginRequest(challenge=challenge, code=code),
                            make_request(),
                            db=db,
                        )
                    except HTTPException as e:
                        return e

                # Fire 10 concurrent requests with the identical challenge
                results = await asyncio.gather(*[submit() for _ in range(10)])

                successes = [r for r in results if not isinstance(r, HTTPException)]
                failures = [r for r in results if isinstance(r, HTTPException)]

                self.assertEqual(len(successes), 1)
                self.assertEqual(len(failures), 9)
                for f in failures:
                    self.assertEqual(f.status_code, 401)
                    self.assertEqual(f.detail, "Invalid or expired verification challenge.")

                # Only a single session was created in the database
                self.assertEqual(len(db.sessions), 1)

        asyncio.run(scenario())

    def test_invalid_codes_are_rate_limited(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            challenge = create_mfa_challenge(str(self.user_id))
            bad_code = "000000"

            with patch.object(rate_limit, "redis_client", redis_fake):
                # Submit failed attempts up to limit - 1
                for _ in range(LOGIN_ATTEMPT_LIMIT - 1):
                    with self.assertRaises(HTTPException) as raised:
                        await auth.complete_mfa_login(
                            MfaLoginRequest(challenge=challenge, code=bad_code),
                            make_request(),
                            db=db,
                        )
                    self.assertEqual(raised.exception.status_code, 401)
                    self.assertEqual(raised.exception.detail, "Invalid verification code.")

                # The attempt that hits the limit
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=bad_code),
                        make_request(),
                        db=db,
                    )
                self.assertEqual(raised.exception.status_code, 429)
                self.assertIn("Too many failed login attempts", raised.exception.detail)

                # Subsequent attempt is blocked by rate limiter before checking credentials
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=pyotp.TOTP(self.secret).now()),
                        make_request(),
                        db=db,
                    )
                self.assertEqual(raised.exception.status_code, 429)
                self.assertEqual(len(db.sessions), 0)

        asyncio.run(scenario())

    def test_invalid_password_and_inactive_account_stay_rejected(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            with patch.object(rate_limit, "redis_client", redis_fake):
                with self.assertRaises(HTTPException) as invalid:
                    await auth.login_user(
                        LoginRequest(email=self.user.email, password="incorrect-password"),
                        make_request(),
                        db,
                    )
                self.assertEqual(invalid.exception.status_code, 401)
                self.assertEqual(invalid.exception.detail, "Invalid email or password.")
                self.assertEqual(db.sessions, [])

                self.user.is_active = False
                with self.assertRaises(HTTPException) as inactive:
                    await auth.login_user(
                        LoginRequest(email=self.user.email, password="correct-password-123"),
                        make_request(),
                        db,
                    )
                self.assertEqual(inactive.exception.status_code, 403)
                self.assertEqual(db.sessions, [])

        asyncio.run(scenario())

    def test_expired_or_invalid_challenges_are_rejected(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            db = FakeDB(user=self.user, mfa=self.mfa)
            code = pyotp.TOTP(self.secret).now()

            # 1. Expired token
            now = datetime.now(timezone.utc)
            expired_payload = {
                "sub": str(self.user_id),
                "type": "mfa_challenge",
                "jti": "some-jti-12345",
                "iat": now - timedelta(minutes=10),
                "exp": now - timedelta(minutes=5),
            }
            expired_token = jwt.encode(expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

            # 2. Wrong token type
            wrong_type_payload = {
                "sub": str(self.user_id),
                "type": "access",
                "jti": "some-jti-12345",
                "iat": now,
                "exp": now + timedelta(minutes=5),
            }
            wrong_type_token = jwt.encode(wrong_type_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

            # 3. Missing jti
            missing_jti_payload = {
                "sub": str(self.user_id),
                "type": "mfa_challenge",
                "iat": now,
                "exp": now + timedelta(minutes=5),
            }
            missing_jti_token = jwt.encode(missing_jti_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

            with patch.object(rate_limit, "redis_client", redis_fake):
                for bad_token in (expired_token, wrong_type_token, missing_jti_token, "invalid.jwt.token123"):
                    with self.assertRaises(HTTPException) as raised:
                        await auth.complete_mfa_login(
                            MfaLoginRequest(challenge=bad_token, code=code),
                            make_request(),
                            db=db,
                        )
                    self.assertEqual(raised.exception.status_code, 401)
                    self.assertEqual(raised.exception.detail, "Invalid or expired verification challenge.")

                self.assertEqual(len(db.sessions), 0)

        asyncio.run(scenario())

    def test_inactive_account_or_missing_mfa_rejected_generically(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            code = pyotp.TOTP(self.secret).now()

            with patch.object(rate_limit, "redis_client", redis_fake):
                # 1. Inactive user
                inactive_user = User(
                    id=self.user_id,
                    name="Inactive User",
                    email="inactive@example.com",
                    password_hash=hash_password("pw"),
                    is_active=False,
                )
                db_inactive = FakeDB(user=inactive_user, mfa=self.mfa)
                challenge = create_mfa_challenge(str(self.user_id))
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=code),
                        make_request(),
                        db=db_inactive,
                    )
                self.assertEqual(raised.exception.status_code, 401)
                self.assertEqual(raised.exception.detail, "Invalid verification code.")

                # 2. Missing MFA configuration
                db_no_mfa = FakeDB(user=self.user, mfa=None)
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=code),
                        make_request(),
                        db=db_no_mfa,
                    )
                self.assertEqual(raised.exception.status_code, 401)
                self.assertEqual(raised.exception.detail, "Invalid verification code.")

        asyncio.run(scenario())

    def test_redis_failure_fails_closed(self):
        async def scenario():
            db = FakeDB(user=self.user, mfa=self.mfa)
            challenge = create_mfa_challenge(str(self.user_id))
            code = pyotp.TOTP(self.secret).now()

            # 1. Redis failure on initial rate limit check
            async def fail_redis(*args, **kwargs):
                raise RateLimitUnavailable("Redis is down")

            with patch.object(auth, "get_login_attempts", fail_redis):
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=code),
                        make_request(),
                        db=db,
                    )
                self.assertEqual(raised.exception.status_code, 503)
                self.assertIn("temporarily unavailable", raised.exception.detail)

            # 2. Redis failure on consume_once
            async def ok_attempts(_key):
                return 0

            with (
                patch.object(auth, "get_login_attempts", ok_attempts),
                patch.object(auth, "consume_once", fail_redis),
            ):
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=code),
                        make_request(),
                        db=db,
                    )
                self.assertEqual(raised.exception.status_code, 503)
                self.assertEqual(len(db.sessions), 0)

            # 3. Redis failure on clear_login_attempts
            with (
                patch.object(auth, "get_login_attempts", ok_attempts),
                patch.object(auth, "consume_once", return_value=True),
                patch.object(auth, "clear_login_attempts", fail_redis),
                patch.object(auth, "create_access_token") as mock_token,
            ):
                with self.assertRaises(HTTPException) as raised:
                    await auth.complete_mfa_login(
                        MfaLoginRequest(challenge=challenge, code=code),
                        make_request(),
                        db=db,
                    )
                self.assertEqual(raised.exception.status_code, 503)
                mock_token.assert_not_called()
                self.assertEqual(len(db.sessions), 0)

        asyncio.run(scenario())

    def test_existing_login_and_enrollment_compatibility(self):
        async def scenario():
            redis_fake = AtomicFakeRedis()
            with patch.object(rate_limit, "redis_client", redis_fake):
                # 1. Login user WITHOUT MFA receives access token directly
                user_without_mfa = User(
                    id=uuid4(),
                    name="No MFA User",
                    email="nomfa@example.com",
                    password_hash=hash_password("password123"),
                    is_active=True,
                )
                db_no_mfa = FakeDB(user=user_without_mfa, mfa=None)
                resp = await auth.login_user(
                    LoginRequest(email="nomfa@example.com", password="password123"),
                    make_request(),
                    db=db_no_mfa,
                )
                self.assertIsNotNone(resp.access_token)
                self.assertFalse(resp.mfa_required)
                self.assertIsNone(resp.mfa_challenge)

                # 2. Login user WITH authenticator recovery receives a normal session immediately.
                db_with_mfa = FakeDB(user=self.user, mfa=self.mfa)
                resp_mfa = await auth.login_user(
                    LoginRequest(email="security@example.com", password="correct-password-123"),
                    make_request(),
                    db=db_with_mfa,
                )
                self.assertFalse(resp_mfa.mfa_required)
                self.assertIsNone(resp_mfa.mfa_challenge)
                self.assertIsNotNone(resp_mfa.access_token)
                self.assertEqual(len(db_with_mfa.sessions), 1)
                self.assertEqual(db_with_mfa.sessions[0].user_id, self.user_id)

                # 3. Enrollment flow
                db_enroll = FakeDB(user=self.user, mfa=None)
                enroll_res = await auth.begin_mfa_enrollment(
                    current_user=self.user,
                    db=db_enroll,
                )
                self.assertIsNotNone(enroll_res.provisioning_uri)
                self.assertIsNotNone(enroll_res.manual_key)

                # 4. Enrollment confirmation
                totp_code = pyotp.TOTP(enroll_res.manual_key).now()
                verify_res = await auth.confirm_mfa_enrollment(
                    payload=MfaCodeRequest(code=totp_code),
                    current_user=self.user,
                    db=db_enroll,
                )
                self.assertTrue(verify_res.enabled)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
