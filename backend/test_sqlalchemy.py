import asyncio

from sqlalchemy import text

from app.db.session import AsyncSessionLocal


async def main() -> None:
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))

            print()
            print("========================================")
            print("SQLALCHEMY CONNECTION: SUCCESS")
            print("SELECT 1 RESULT:", result.scalar_one())
            print("========================================")
            print()

    except Exception as exc:
        print()
        print("========================================")
        print("SQLALCHEMY CONNECTION: FAILED")
        print("ERROR TYPE:", type(exc).__name__)
        print("ERROR:", exc)
        print("========================================")
        print()


if __name__ == "__main__":
    asyncio.run(main())