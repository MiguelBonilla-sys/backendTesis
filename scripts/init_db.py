"""
Script de inicialización de base de datos.
Ejecutar una vez: python scripts/init_db.py
"""
import asyncio
import asyncpg
import os
from pathlib import Path


async def init_database() -> None:
    db_url = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/phishing_detector")
    schema_path = Path(__file__).parent / "schema.sql"

    if not schema_path.exists():
        print(f"ERROR: schema.sql not found at {schema_path}")
        return

    schema_sql = schema_path.read_text()

    conn = await asyncpg.connect(db_url)
    try:
        await conn.execute(schema_sql)
        print("Database schema initialized successfully")

        # Contar tablas creadas
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'"
        )
        print(f"{count} tables ready")
    except Exception as e:
        print(f"ERROR: {e}")
        raise
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(init_database())
