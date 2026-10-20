import asyncio
from urllib.parse import unquote, urlsplit

import asyncpg
from dotenv import dotenv_values


async def main() -> None:
    config = dotenv_values(".env")

    raw_url = config.get("DATABASE_URL")

    if not raw_url:
        raise RuntimeError("DATABASE_URL is missing from .env")

    url = raw_url.replace(
        "postgresql+asyncpg://",
        "postgresql://",
        1,
    )

    parsed = urlsplit(url)

    print("Host:", parsed.hostname)
    print("Port:", parsed.port)
    print("User:", parsed.username)
    print("Database:", parsed.path.lstrip("/"))
    print("Password present:", bool(parsed.password))

    connection = None

    try:
        connection = await asyncpg.connect(
            host=parsed.hostname,
            port=parsed.port,
            user=parsed.username,
            password=parsed.password or "",
            database=parsed.path.lstrip("/"),
        )

        result = await connection.fetchval("SELECT 1")

        print()
        print("========================================")
        print("ASYNC PG DIRECT CONNECTION: SUCCESS")
        print("SELECT 1 RESULT:", result)
        print("========================================")

    except Exception as exc:
        print()
        print("========================================")
        print("ASYNC PG DIRECT CONNECTION: FAILED")
        print("ERROR TYPE:", type(exc).__name__)
        print("ERROR:", exc)
        print("========================================")

    finally:
        if connection:
            await connection.close()


if __name__ == "__main__":
    asyncio.run(main())
