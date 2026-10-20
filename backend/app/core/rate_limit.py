from redis.asyncio import Redis

from app.core.config import settings


LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60


redis_client = Redis.from_url(
    settings.redis_url,
    decode_responses=True,
)


async def get_login_attempts(key: str) -> int:
    """Return the current failed-attempt count for a key."""
    value = await redis_client.get(key)

    if value is None:
        return 0

    return int(value)


async def record_failed_login(key: str) -> int:
    """Increment failed attempts and set the expiry on the first attempt."""
    attempts = await redis_client.incr(key)

    if attempts == 1:
        await redis_client.expire(
            key,
            LOGIN_ATTEMPT_WINDOW_SECONDS,
        )

    return attempts


async def clear_login_attempts(key: str) -> None:
    """Clear failed-login attempts after a successful login."""
    await redis_client.delete(key)


def login_is_blocked(attempts: int) -> bool:
    """Return whether the account/IP should be temporarily blocked."""
    return attempts >= LOGIN_ATTEMPT_LIMIT