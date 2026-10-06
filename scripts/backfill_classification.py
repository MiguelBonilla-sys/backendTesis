"""Fill primary_category/categories/impact for incidents saved before migration 006.

Usage: python -m scripts.backfill_classification [--dry-run]
Only rows with an empty ``categories`` and a non-LEGITIMATE verdict are touched;
rows that cannot be classified stay as "sin clasificar" (NULL primary_category).
"""

from __future__ import annotations

import argparse
import asyncio
import json

from core.incident_taxonomy import categorize_stored, impact_for

SELECT = (
    "SELECT id, verdict, domain, s_risk, reasons FROM incidents "
    "WHERE categories = '[]'::jsonb AND verdict <> 'LEGITIMATE' ORDER BY created_at"
)


async def backfill(conn, *, dry: bool = False) -> dict[str, int]:
    updated = skipped = 0
    for row in await conn.fetch(SELECT):
        reasons = row["reasons"]
        reasons = json.loads(reasons) if isinstance(reasons, str) else (reasons or [])
        categories = categorize_stored(row["verdict"], row["domain"], reasons)
        if not categories:
            skipped += 1
            continue
        if not dry:
            await conn.execute(
                "UPDATE incidents SET primary_category = $2, categories = $3::jsonb, "
                "impact = $4::jsonb WHERE id = $1",
                row["id"], categories[0], json.dumps(categories),
                json.dumps(impact_for(categories, float(row["s_risk"]))),
            )
        updated += 1
    return {"updated": updated, "unclassified": skipped}


async def main() -> int:  # pragma: no cover - CLI wrapper
    import asyncpg

    from core.config import settings

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    conn = await asyncpg.connect(settings.DATABASE_URL.replace("postgresql+asyncpg://",
                                                               "postgresql://", 1))
    try:
        print(json.dumps(await backfill(conn, dry=args.dry_run)))
    finally:
        await conn.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(asyncio.run(main()))
