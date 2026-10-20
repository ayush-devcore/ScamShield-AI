import asyncio

import asyncpg
from dotenv import dotenv_values


async def main() -> None:
    config = dotenv_values(".env")

    database_url = config.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is missing from .env")

    database_url = database_url.replace(
        "postgresql+asyncpg://",
        "postgresql://",
        1,
    )

    connection = None

    try:
        connection = await asyncpg.connect(database_url)

        result = await connection.fetchval("SELECT 1")

        print()
        print("========================================")
        print("DIRECT DATABASE CONNECTION: SUCCESS")
        print("SELECT 1 RESULT:", result)
        print("========================================")
        print()

    except Exception as exc:
        print()
        print("========================================")
        print("DIRECT DATABASE CONNECTION: FAILED")
        print("ERROR TYPE:", type(exc).__name__)
        print("ERROR:", exc)
        print("========================================")
        print()

    finally:
        if connection:
            await connection.close()


if __name__ == "__main__":
    asyncio.run(main())