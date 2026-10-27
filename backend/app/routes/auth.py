import hashlib
import hmac
import math
import time
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.core.rate_limit import (
    LOGIN_ATTEMPT_LIMIT,
    RateLimitUnavailable,
    clear_login_attempts,
    consume_once,
    get_login_attempts,
    login_is_blocked,
    record_failed_login,
)
from app.core.security import (
    create_access_token,
    create_mfa_challenge,
    decode_mfa_challenge,
    hash_password,
    verify_password,
)
from app.db.models import RecoveryCode, User, UserMfa, UserSession
from app.db.session import get_db
from app.schemas.auth import (
    LoginRequest,
    MfaCodeRequest,
    MfaEnrollmentResponse,
    MfaLoginRequest,
    MfaStatusResponse,
    MfaDisableRequest,
    AuthenticatorPasswordResetRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    SessionResponse,
)
from app.services.mfa import decrypt_secret, encrypt_secret, hash_recovery_code, new_recovery_codes, new_secret, provisioning_uri, valid_code, valid_recovery_code
from app.services.audit import record_activity
from app.services.notifications import create_security_notification


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def _rate_limit_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Authentication is temporarily unavailable. Please try again later.",
        headers={"Retry-After": "30"},
    )


async def _consume_recovery_code(db: AsyncSession, user_id: UUID, code: str) -> bool:
    """Lock usable codes and consume one in the current transaction."""
    rows = (await db.execute(
        select(RecoveryCode)
        .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        .with_for_update()
    )).scalars().all()
    for row in rows:
        if valid_recovery_code(code.strip().upper(), row.code_hash):
            row.used_at = datetime.now(timezone.utc)
            return True
    return False


async def _recent_current_session(db: AsyncSession, user_id: UUID, session_id: UUID) -> UserSession:
    session = (await db.execute(
        select(UserSession).where(UserSession.id == session_id, UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    )).scalar_one_or_none()
    if session is None or session.created_at < datetime.now(timezone.utc) - timedelta(minutes=15):
        raise HTTPException(status_code=403, detail="Recent authentication is required.")
    return session


def _new_recovery_rows(user_id: UUID):
    codes = new_recovery_codes()
    return codes, [RecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code)) for code in codes]


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> User:
    email = payload.email.strip().lower()

    result = await db.execute(
        select(User).where(User.email == email)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        name=payload.name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        is_active=True,
    )

    db.add(user)

    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from None

    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
async def login_user(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    email = payload.email.strip().lower()

    # Use the direct client IP for now.
    # We will add trusted proxy handling before production deployment.
    client_ip = request.client.host if request.client else "unknown"

    # Combine email + IP so one client cannot trivially block
    # every other user with the same account email.
    rate_limit_key = f"scamshield:login:{email}:{client_ip}"

    try:
        attempts = await get_login_attempts(rate_limit_key)
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None

    if login_is_blocked(attempts):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many failed login attempts. "
                f"Please try again later."
            ),
            headers={"Retry-After": "900"},
        )

    result = await db.execute(
        select(User).where(User.email == email)
    )
    user = result.scalar_one_or_none()

    # Unknown user and wrong password intentionally produce
    # the same response.
    if user is None or not verify_password(
        payload.password,
        user.password_hash,
    ):
        try:
            failed_attempts = await record_failed_login(rate_limit_key)
        except RateLimitUnavailable:
            raise _rate_limit_unavailable() from None

        if failed_attempts >= LOGIN_ATTEMPT_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
                headers={"Retry-After": "900"},
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is inactive.",
        )

    # Successful authentication clears previous failures.
    try:
        await clear_login_attempts(rate_limit_key)
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None

    session = UserSession(
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes),
        last_activity_at=datetime.now(timezone.utc),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
    )
    db.add(session)
    record_activity(db, user.id, "login_completed")
    await create_security_notification(db, user.id, "login_completed")
    await db.commit()
    access_token = create_access_token(str(user.id), str(session.id))

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
    )


_PASSWORD_RESET_FAILURE = "Unable to verify recovery details or complete password reset. Authenticator-based recovery may be unavailable for this account; use another supported recovery method if it is not configured."


def _matching_totp_counter(secret: str, code: str, timestamp: float) -> tuple[int, int] | None:
    totp = pyotp.TOTP(secret)
    current_counter = int(timestamp // totp.interval)
    for counter in (current_counter - 1, current_counter, current_counter + 1):
        if counter < 0:
            continue
        if hmac.compare_digest(totp.generate_otp(counter), code.strip()):
            expiry = math.ceil((counter + 2) * totp.interval - timestamp)
            return counter, max(1, expiry)
    return None


@router.post("/password-reset/authenticator", status_code=status.HTTP_200_OK)
async def reset_password_with_authenticator(
    payload: AuthenticatorPasswordResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    email_key = hashlib.sha256(email.encode("utf-8")).hexdigest()
    rate_limit_key = f"scamshield:password-reset:{email_key}:{client_ip}"

    try:
        attempts = await get_login_attempts(rate_limit_key)
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None
    if login_is_blocked(attempts):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Unable to verify recovery details. Please try again later.",
            headers={"Retry-After": "900"},
        )

    user = (await db.execute(
        select(User).where(User.email == email).with_for_update()
    )).scalar_one_or_none()
    mfa = None
    valid = False
    valid_recovery = False
    totp_claim: tuple[str, int] | None = None
    if user is not None and user.is_active:
        mfa = (await db.execute(
            select(UserMfa).where(UserMfa.user_id == user.id).with_for_update()
        )).scalar_one_or_none()
    if user is not None and user.is_active and mfa and mfa.enabled_at and mfa.secret_encrypted:
        try:
            secret = decrypt_secret(mfa.secret_encrypted)
            matched = _matching_totp_counter(secret, payload.code, time.time())
            if matched is not None:
                counter, ttl = matched
                totp_claim = (f"scamshield:password-reset:totp:{user.id}:{counter}", ttl)
                valid = True
        except Exception:
            valid = False
        if not valid:
            valid_recovery = await _consume_recovery_code(db, user.id, payload.code)
            valid = valid_recovery

    if valid and totp_claim is not None:
        try:
            valid = await consume_once(*totp_claim)
        except RateLimitUnavailable:
            raise _rate_limit_unavailable() from None

    if not valid:
        try:
            failed_attempts = await record_failed_login(rate_limit_key)
        except RateLimitUnavailable:
            raise _rate_limit_unavailable() from None
        if failed_attempts >= LOGIN_ATTEMPT_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Unable to verify recovery details. Please try again later.",
                headers={"Retry-After": "900"},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_PASSWORD_RESET_FAILURE,
        )

    try:
        await clear_login_attempts(rate_limit_key)
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None

    now = datetime.now(timezone.utc)
    user.password_hash = hash_password(payload.new_password)
    sessions = (await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .with_for_update()
    )).scalars().all()
    for session in sessions:
        session.revoked_at = now
    record_activity(db, user.id, "password_reset_completed")
    await create_security_notification(db, user.id, "password_reset_completed")
    await db.commit()
    return {"message": "Password updated. Sign in with your new password."}


@router.post(
    "/mfa/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
async def complete_mfa_login(
    payload: MfaLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        challenge_data = decode_mfa_challenge(payload.challenge)
        user_id = UUID(str(challenge_data["sub"]))
        jti = str(challenge_data["jti"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired verification challenge.",
        ) from None

    client_ip = request.client.host if request.client else "unknown"
    rate_limit_key = f"scamshield:mfa:{user_id}:{client_ip}"

    try:
        attempts = await get_login_attempts(rate_limit_key)
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None

    if login_is_blocked(attempts):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": "900"},
        )

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()

    mfa = (
        await db.execute(select(UserMfa).where(UserMfa.user_id == user_id))
    ).scalar_one_or_none()

    is_valid_totp = False
    if user and user.is_active and mfa and mfa.enabled_at and mfa.secret_encrypted:
        try:
            secret = decrypt_secret(mfa.secret_encrypted)
            if valid_code(secret, payload.code):
                is_valid_totp = True
        except Exception:
            is_valid_totp = False

    used_recovery = False
    if not is_valid_totp and user and user.is_active and mfa and mfa.enabled_at:
        used_recovery = await _consume_recovery_code(db, user.id, payload.code)

    if not is_valid_totp and not used_recovery:
        try:
            failed_attempts = await record_failed_login(rate_limit_key)
        except RateLimitUnavailable:
            raise _rate_limit_unavailable() from None

        if failed_attempts >= LOGIN_ATTEMPT_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
                headers={"Retry-After": "900"},
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code.",
        )

    try:
        claimed = await consume_once(
            f"scamshield:mfa_challenge:{jti}",
            settings.mfa_challenge_expire_minutes * 60,
        )
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None

    if not claimed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired verification challenge.",
        )

    try:
        await clear_login_attempts(rate_limit_key)
    except RateLimitUnavailable:
        raise _rate_limit_unavailable() from None

    session = UserSession(
        user_id=user.id,
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=settings.access_token_expire_minutes),
        last_activity_at=datetime.now(timezone.utc),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
    )
    db.add(session)
    record_activity(db, user.id, "login_completed")
    await create_security_notification(db, user.id, "login_completed")
    await db.commit()

    access_token = create_access_token(str(user.id), str(session.id))

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
    )


@router.post("/mfa/enroll", response_model=MfaEnrollmentResponse)
async def begin_mfa_enrollment(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    secret = new_secret()
    record = (await db.execute(select(UserMfa).where(UserMfa.user_id == current_user.id))).scalar_one_or_none()
    if record is None:
        record = UserMfa(user_id=current_user.id)
        db.add(record)
    record.pending_secret_encrypted = encrypt_secret(secret)
    await db.commit()
    return MfaEnrollmentResponse(provisioning_uri=provisioning_uri(secret, current_user.email), manual_key=secret)


@router.post("/mfa/verify", response_model=MfaStatusResponse)
async def confirm_mfa_enrollment(payload: MfaCodeRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    record = (await db.execute(select(UserMfa).where(UserMfa.user_id == current_user.id).with_for_update())).scalar_one_or_none()
    if not record or not record.pending_secret_encrypted:
        raise HTTPException(status_code=400, detail="MFA enrollment has not been started.")
    secret = decrypt_secret(record.pending_secret_encrypted)
    if not valid_code(secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid verification code.")
    record.secret_encrypted, record.pending_secret_encrypted, record.enabled_at = record.pending_secret_encrypted, None, datetime.now(timezone.utc)
    await db.execute(RecoveryCode.__table__.delete().where(RecoveryCode.user_id == current_user.id))
    codes, rows = _new_recovery_rows(current_user.id)
    for row in rows:
        db.add(row)
    record_activity(db, current_user.id, "mfa_enabled")
    await create_security_notification(db, current_user.id, "mfa_enabled")
    await db.commit()
    return MfaStatusResponse(enabled=True, recovery_codes=codes)


@router.get("/mfa", response_model=MfaStatusResponse)
async def mfa_status(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    record = (await db.execute(select(UserMfa).where(UserMfa.user_id == current_user.id))).scalar_one_or_none()
    return MfaStatusResponse(enabled=bool(record and record.enabled_at and record.secret_encrypted))


@router.post("/mfa/recovery-codes", response_model=MfaStatusResponse)
async def regenerate_recovery_codes(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _recent_current_session(db, current_user.id, request.state.auth_session_id)
    mfa = (await db.execute(select(UserMfa).where(UserMfa.user_id == current_user.id).with_for_update())).scalar_one_or_none()
    if not mfa or not mfa.enabled_at or not mfa.secret_encrypted:
        raise HTTPException(status_code=400, detail="MFA is not enabled.")
    await db.execute(RecoveryCode.__table__.delete().where(RecoveryCode.user_id == current_user.id))
    codes, rows = _new_recovery_rows(current_user.id)
    for row in rows:
        db.add(row)
    record_activity(db, current_user.id, "recovery_codes_regenerated")
    await create_security_notification(db, current_user.id, "recovery_codes_regenerated")
    await db.commit()
    return MfaStatusResponse(enabled=True, recovery_codes=codes)


@router.post("/mfa/disable", response_model=MfaStatusResponse)
async def disable_mfa(
    request: Request,
    payload: MfaDisableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _recent_current_session(db, current_user.id, request.state.auth_session_id)
    mfa = (await db.execute(select(UserMfa).where(UserMfa.user_id == current_user.id).with_for_update())).scalar_one_or_none()
    if not mfa or not mfa.enabled_at or not mfa.secret_encrypted:
        raise HTTPException(status_code=400, detail="MFA is not enabled.")
    valid = False
    if payload.use_recovery_code:
        valid = await _consume_recovery_code(db, current_user.id, payload.code)
    else:
        valid = valid_code(decrypt_secret(mfa.secret_encrypted), payload.code)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid verification code.")
    mfa.secret_encrypted = None
    mfa.pending_secret_encrypted = None
    mfa.enabled_at = None
    await db.execute(RecoveryCode.__table__.delete().where(RecoveryCode.user_id == current_user.id))
    record_activity(db, current_user.id, "mfa_disabled")
    await create_security_notification(db, current_user.id, "mfa_disabled")
    await db.commit()
    return MfaStatusResponse(enabled=False)


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(request: Request, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    current_id = request.state.auth_session_id
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(UserSession).where(UserSession.user_id == current_user.id, UserSession.revoked_at.is_(None), UserSession.expires_at > now).order_by(UserSession.last_activity_at.desc()))).scalars().all()
    return [SessionResponse(id=row.id, created_at=row.created_at.isoformat(), last_activity_at=row.last_activity_at.isoformat(), expires_at=row.expires_at.isoformat(), user_agent=row.user_agent, current=row.id == current_id) for row in rows]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(session_id: UUID, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    session = (await db.execute(select(UserSession).where(UserSession.id == session_id, UserSession.user_id == current_user.id).with_for_update())).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found.")
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        record_activity(db, current_user.id, "session_revoked")
        await create_security_notification(db, current_user.id, "session_revoked")
        await db.commit()


@router.post("/sessions/revoke-others", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_other_sessions(request: Request, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    current_id = request.state.auth_session_id
    rows = (await db.execute(select(UserSession).where(UserSession.user_id == current_user.id, UserSession.id != current_id, UserSession.revoked_at.is_(None)).with_for_update())).scalars().all()
    for session in rows:
        session.revoked_at = datetime.now(timezone.utc)
    if rows:
        record_activity(db, current_user.id, "session_revoked")
        await create_security_notification(db, current_user.id, "session_revoked")
        await db.commit()


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_user(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke the bearer token's current server-side session."""
    session_id = request.state.auth_session_id
    session = (await db.execute(select(UserSession).where(UserSession.id == session_id, UserSession.user_id == current_user.id).with_for_update())).scalar_one_or_none()
    if session and session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        record_activity(db, current_user.id, "session_revoked")
        await create_security_notification(db, current_user.id, "session_revoked")
        await db.commit()


@router.get(
    "/me",
    response_model=UserResponse,
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user
