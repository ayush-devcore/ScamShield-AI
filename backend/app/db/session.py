from collections.abc import AsyncGenerator
from urllib.parse import parse_qsl, unquote, urlsplit

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings


def build_database_url() -> URL:
    """
    Build a SQLAlchemy URL from individual connection components.

    This avoids problems when a database password contains URL-special
    characters such as @, #, :, /, %, etc.
    """

    raw_url = settings.database_url

    normalized_url = raw_url.replace(
        "postgresql+asyncpg://",
        "postgresql://",
        1,
    )

    parsed = urlsplit(normalized_url)

    if not parsed.hostname:
        raise RuntimeError("DATABASE_URL is missing a valid host.")

    if not parsed.username:
        raise RuntimeError("DATABASE_URL is missing a valid username.")

    database = parsed.path.lstrip("/")

    if not database:
        raise RuntimeError("DATABASE_URL is missing a database name.")

    password = parsed.password or ""
    query = (
        dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.query
        else {}
    )

    return URL.create(
        drivername="postgresql+asyncpg",
        username=unquote(parsed.username),
        password=unquote(password),
        host=parsed.hostname,
        port=parsed.port or 5432,
        database=unquote(database),
        query=query,
    )


DATABASE_URL = build_database_url()

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_size=5,
    max_overflow=10,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
