import asyncio
import asyncpg
import redis.asyncio as redis

async def main():
    try:
        print("Testing Postgres...")
        conn = await asyncpg.connect("postgresql://postgres:postgres@127.0.0.1:5432/phishing_detector")
        print("Postgres OK!")
        await conn.close()
        
        print("Testing Redis...")
        r = redis.from_url("redis://127.0.0.1:6379/0")
        pong = await r.ping()
        print(f"Redis OK: {pong}")
        await r.close()
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(main())
