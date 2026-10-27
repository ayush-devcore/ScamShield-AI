from datetime import datetime, timedelta, timezone
import secrets

import jwt
from pwdlib import PasswordHash

from app.core.config import settings


password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a password using the recommended secure algorithm."""
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plain password against its stored hash."""
    return password_hasher.verify(password, password_hash)


def create_access_token(subject: str, session_id: str | None = None) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    payload = {
        "sub": subject,
        "type": "access",
        "iat": now,
        "exp": expires_at,
    }
    if session_id:
        payload["sid"] = session_id

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict:
    """Decode and validate an access token."""
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )

    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Invalid token type.")

    if not payload.get("sub"):
        raise jwt.InvalidTokenError("Token subject is missing.")

    return payload


def create_mfa_challenge(subject: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": subject, "type": "mfa_challenge", "jti": secrets.token_urlsafe(16), "iat": now, "exp": now + timedelta(minutes=settings.mfa_challenge_expire_minutes)}, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_mfa_challenge(token: str) -> dict:
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )

    if (
        payload.get("type") != "mfa_challenge"
        or not payload.get("sub")
        or not payload.get("jti")
    ):
        raise jwt.InvalidTokenError("Invalid MFA challenge.")

    return payload