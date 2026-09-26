"""Authoritative PostgreSQL replica sync (historical filename retained).

Requires an explicitly selected authority and a fenced destination. Replicates
updates and deletions transactionally; never merges stale security state back.
Audit events are append-only in both directions using global event_id UUIDs.
Apply deploy/schema.sql on BOTH databases before running. See
 docs/synchronization-and-learning.md for failover/failback guarantees.
"""
from __future__ import annotations

import argparse
import asyncio
import os

from core.config import settings

_UUID_TABLES = [
    "users", "incidents", "analyzed_urls", "idn_scores", "ti_results", "feedback",
    "simulation_events", "theta_calibrations", "weight_calibrations",
]
_BATCH = 500


async def _cols(conn, table: str) -> list[str]:
    rows = await conn.fetch(
        "select column_name from information_schema.columns "
        "where table_schema = 'public' and table_name = $1 order by ordinal_position", table,
    )
    return [r["column_name"] for r in rows]


async def _merge_uuid_table(src, dst, table: str, *, dry: bool) -> int:
    """Copy every current value, including role, password, active and ingested."""
    if table not in _UUID_TABLES:
        raise ValueError("Unsupported replica table")
    cols = await _cols(src, table)
    if not cols or set(cols) != set(await _cols(dst, table)):
        raise RuntimeError(f"Schema mismatch for {table}; migrate both databases first")
    collist = ", ".join(f'"{c}"' for c in cols)
    placeholders = ", ".join(f"${i + 1}" for i in range(len(cols)))
    updates = ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in cols if c != "id")
    ins = f'INSERT INTO "{table}" ({collist}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET {updates}'
    moved = 0
    async for row in src.cursor(f'SELECT {collist} FROM "{table}" ORDER BY id', prefetch=_BATCH):
        if not dry:
            await dst.execute(ins, *tuple(row))
        moved += 1
    return moved


async def _prune_table(src, dst, table: str, *, dry: bool) -> int:
    if table not in _UUID_TABLES:
        raise ValueError("Unsupported replica table")
    src_ids = {r["id"] for r in await src.fetch(f'SELECT id FROM "{table}"')}
    dst_ids = {r["id"] for r in await dst.fetch(f'SELECT id FROM "{table}"')}
    stale = list(dst_ids - src_ids)
    if not dry:
        for i in range(0, len(stale), _BATCH):
            await dst.execute(f'DELETE FROM "{table}" WHERE id = ANY($1::uuid[])', stale[i:i + _BATCH])
    return len(stale)


async def _append_audit_log(src, dst, *, dry: bool) -> int:
    """No timestamp watermark: independent serial IDs and clocks cannot skip events."""
    dst_ids = {r["event_id"] for r in await dst.fetch("SELECT event_id FROM audit_log")}
    moved = 0
    async for row in src.cursor(
        "SELECT event_id, event_type, actor, resource, ip_address, status, detail, occurred_at "
        "FROM audit_log ORDER BY id", prefetch=_BATCH,
    ):
        if row["event_id"] in dst_ids:
            continue
        if not dry:
            await dst.execute(
                "INSERT INTO audit_log (event_id, event_type, actor, resource, ip_address, status, detail, occurred_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (event_id) DO NOTHING", *tuple(row),
            )
        moved += 1
    return moved


async def sync(src, dst, *, dry: bool = False) -> dict[str, int]:
    """One atomic replica snapshot; destination business rows mirror authority."""
    tables = ", ".join(f'"{t}"' for t in [*_UUID_TABLES, "audit_log"])
    async with src.transaction(isolation="repeatable_read"):
        async with dst.transaction(isolation="repeatable_read"):
            for conn in (src, dst):
                await conn.execute("SET LOCAL lock_timeout = '5s'")
                await conn.execute(f"LOCK TABLE {tables} IN EXCLUSIVE MODE")
            # Validate every table BEFORE deleting any rows (transaction rolls back on error).
            for table in _UUID_TABLES:
                if not await _cols(src, table) or set(await _cols(src, table)) != set(await _cols(dst, table)):
                    raise RuntimeError(f"Schema mismatch for {table}")
            pruned = sum([await _prune_table(src, dst, t, dry=dry) for t in reversed(_UUID_TABLES) if t != "users"])
            copied = sum([await _merge_uuid_table(src, dst, t, dry=dry) for t in _UUID_TABLES])
            pruned += await _prune_table(src, dst, "users", dry=dry)
            audit = await _append_audit_log(src, dst, dry=dry)
            audit += await _append_audit_log(dst, src, dry=dry)
    return {"copied": copied, "deleted": pruned, "audit_appended": audit}


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--authority", choices=("local", "standby"), required=True)
    ap.add_argument("--replica-fenced", action="store_true", help="operator asserts destination writers are stopped")
    ap.add_argument("--source-quiesced", action="store_true", help="operator asserts source writers/learning are paused through PG and Chroma sync")
    args = ap.parse_args()
    if not args.dry_run and not (args.replica_fenced and args.source_quiesced):
        ap.error("writes require --replica-fenced and --source-quiesced; see docs/synchronization-and-learning.md")
    import asyncpg

    local_dsn = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
    local = await asyncpg.connect(local_dsn, statement_cache_size=0)
    try:
        remote = await asyncpg.connect(os.environ["STANDBY_DATABASE_URL"], statement_cache_size=0)
        try:
            src, dst = (local, remote) if args.authority == "local" else (remote, local)
            counts = await sync(src, dst, dry=args.dry_run)
        finally:
            await remote.close()
    finally:
        await local.close()
    print(f"{'DRY RUN ' if args.dry_run else ''}authority={args.authority}: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
