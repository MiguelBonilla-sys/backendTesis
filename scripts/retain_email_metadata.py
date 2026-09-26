"""Clear old captured email fields; dry run unless --apply is explicitly set.

This is data minimization, not anonymization: incident URLs, scores, explanations
and audit records remain. Configure and schedule according to the retention
policy of the installation. No rows or knowledge collections are deleted.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime, timedelta

from core.config import settings

_FIELDS = """email_hash='', email_subject='', email_from='', email_to='',
             all_urls='[]'::jsonb, email_body_html='', email_images='[]'::jsonb,
             email_attachments='[]'::jsonb"""
_NONEMPTY = """(COALESCE(email_hash,'') <> '' OR email_subject <> '' OR email_from <> ''
               OR email_to <> '' OR all_urls <> '[]'::jsonb OR email_body_html <> ''
               OR email_images <> '[]'::jsonb OR email_attachments <> '[]'::jsonb)"""


async def retain_email_metadata(conn, *, days: int, apply: bool = False) -> int:
    if not 1 <= days <= 3650:
        raise ValueError("Retention must be between 1 and 3650 days")
    cutoff = datetime.now(UTC) - timedelta(days=days)
    if not apply:
        return await conn.fetchval(
            f"SELECT count(*) FROM incidents WHERE created_at < $1 AND {_NONEMPTY}",
            cutoff,
        )
    # Count and clear in the same statement; rerunning the job is idempotent.
    return await conn.fetchval(
        f"WITH cleared AS (UPDATE incidents SET {_FIELDS} "
        f"WHERE created_at < $1 AND {_NONEMPTY} RETURNING id) SELECT count(*) FROM cleared",
        cutoff,
    )


async def main():
    import asyncpg

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--days", type=int, default=settings.EMAIL_METADATA_RETENTION_DAYS)
    args = parser.parse_args()
    conn = await asyncpg.connect(
        settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
    )
    try:
        count = await retain_email_metadata(conn, days=args.days, apply=args.apply)
        print(f"{'cleared' if args.apply else 'would clear'} email fields in {count} incidents")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
