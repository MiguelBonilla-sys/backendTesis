#!/usr/bin/env python3
"""Seed an admin user into the database.

Run once after deploying Phase 7:
    ADMIN_EMAIL=admin@usbbog.edu.co ADMIN_PASSWORD=<strong> python scripts/seed_admin.py
"""

import asyncio
import os
import sys

# asyncpg is incompatible with the Windows ProactorEventLoop (Python 3.8+).
# Force SelectorEventLoop before any async code runs.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Allow running from backendTesis/ root without installing the package.
sys.path.insert(0, ".")

from models.database import close_db, get_session, init_db  # noqa: E402
from auth.auth_service import get_user_by_email, hash_password  # noqa: E402
from models.orm_models import User  # noqa: E402


async def main() -> None:
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")

    if not email or not password:
        print("ERROR: Set ADMIN_EMAIL and ADMIN_PASSWORD environment variables.")
        sys.exit(1)

    await init_db()

    # get_session is an async generator — consume it manually.
    gen = get_session()
    session = await gen.__anext__()
    try:
        existing = await get_user_by_email(session, email)
        if existing is not None:
            print(f"Admin already exists: {email}")
        else:
            user = User(
                email=email.lower(),
                password_hash=hash_password(password),
                role="admin",
            )
            session.add(user)
            await session.commit()
            print(f"Admin created: {email}")
    finally:
        # Exhaust generator to trigger session cleanup.
        try:
            await gen.__anext__()
        except StopAsyncIteration:
            pass

    await close_db()


if __name__ == "__main__":
    asyncio.run(main())
