from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings


LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60


redis_client = Redis.from_url(
    settings.redis_url,
    decode_responses=True,
)

_INCREMENT_WITH_WINDOW = """
local attempts = redis.call('INCR', KEYS[1])
if attempts == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return attempts
"""


class RateLimitUnavailable(Exception):
    """Raised when Redis cannot provide a trustworthy rate-limit state."""


async def get_login_attempts(key: str) -> int:
    """Return the current failed-attempt count for a key."""
    try:
        value = await redis_client.get(key)
        return 0 if value is None else int(value)
    except (RedisError, TypeError, ValueError) as exc:
        raise RateLimitUnavailable from exc


async def record_failed_login(key: str) -> int:
    """Atomically increment failures and set the first-attempt window."""
    try:
        return int(
            await redis_client.eval(
                _INCREMENT_WITH_WINDOW,
                1,
                key,
                LOGIN_ATTEMPT_WINDOW_SECONDS,
            )
        )
    except (RedisError, TypeError, ValueError) as exc:
        raise RateLimitUnavailable from exc


async def clear_login_attempts(key: str) -> None:
    """Clear failed-login attempts after a successful login."""
    try:
        await redis_client.delete(key)
    except RedisError as exc:
        raise RateLimitUnavailable from exc

async def consume_once(key: str, ttl_seconds: int) -> bool:
    """Atomically claim a key once with a bounded lifetime."""
    if ttl_seconds < 1:
        raise ValueError("ttl_seconds must be positive")

    try:
        return bool(
            await redis_client.set(
                key,
                "1",
                ex=ttl_seconds,
                nx=True,
            )
        )
    except (RedisError, TypeError, ValueError) as exc:
        raise RateLimitUnavailable from exc

def login_is_blocked(attempts: int) -> bool:
    """Return whether the account/IP should be temporarily blocked."""
    return attempts >= LOGIN_ATTEMPT_LIMIT
