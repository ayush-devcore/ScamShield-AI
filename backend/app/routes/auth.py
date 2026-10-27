from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.core.rate_limit import (
    LOGIN_ATTEMPT_LIMIT,
    RateLimitUnavailable,
    clear_login_attempts,
    get_login_attempts,
    login_is_blocked,
    record_failed_login,
)
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.models import User
from app.db.session import get_db
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)


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

    access_token = create_access_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user
