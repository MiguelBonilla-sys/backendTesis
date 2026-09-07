"""Merge bidireccional de PostgreSQL entre Coolify (local, autoritativo) y Neon
(standby free-tier). Reemplaza el TRUNCATE+COPY una-vía por un upsert por PK en
LOS DOS SENTIDOS, para que si Coolify se cae y vuelve, lo que Render escribió en
Neon durante la caída se reintegre a Coolify — y viceversa.

Modelo (no es multi-master real, alcanza para este caso):
- Tablas con PK UUID (users, incidents, idn_scores, ti_results, feedback,
  analyzed_urls, simulation_events, theta_calibrations, weight_calibrations):
  merge en ambos sentidos. `INSERT ... ON CONFLICT (id) DO NOTHING`. Los UUID no
  colisionan entre instancias → append seguro.
- `audit_log` (PK BIGSERIAL → colisiona): una sola vía LOCAL→REMOTE, por watermark
  de `occurred_at`.
- Orden de inserción respeta las FK (users → incidents → hijas).

Limitación: los BORRADOS no se propagan (no hay TRUNCATE). Para borrar una fila:
hacerlo en los dos lados en la misma ventana, o parar el cron, borrar, reanudar.

Env: STANDBY_DATABASE_URL (Neon, libpq, endpoint DIRECTO).
Uso:  python -m scripts.sync_pg_bilateral [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import os

from core.config import settings
from core.logger import get_logger

logger = get_logger(__name__)

# Orden = FK-safe (padres primero).
_UUID_TABLES = [
    "users",
    "incidents",
    "analyzed_urls",
    "idn_scores",
    "ti_results",
    "feedback",
    "simulation_events",
    "theta_calibrations",
    "weight_calibrations",
]
_BATCH = 500


async def _cols(conn, table: str) -> list[str]:
    rows = await conn.fetch(
        "select column_name from information_schema.columns "
        "where table_schema = 'public' and table_name = $1 order by ordinal_position",
        table,
    )
    return [r["column_name"] for r in rows]


async def _merge_uuid_table(src, dst, table: str, *, dry: bool) -> int:
    src_ids = {r["id"] for r in await src.fetch(f'select id from "{table}"')}
    if not src_ids:
        return 0
    dst_ids = {r["id"] for r in await dst.fetch(f'select id from "{table}"')}
    missing = list(src_ids - dst_ids)
    if not missing:
        return 0
    if dry:
        return len(missing)

    cols = await _cols(src, table)
    collist = ", ".join(f'"{c}"' for c in cols)
    placeholders = ", ".join(f"${i + 1}" for i in range(len(cols)))
    ins = f'insert into "{table}" ({collist}) values ({placeholders}) on conflict (id) do nothing'
    moved = 0
    for i in range(0, len(missing), _BATCH):
        chunk = missing[i : i + _BATCH]
        rows = await src.fetch(f'select {collist} from "{table}" where id = any($1::uuid[])', chunk)
        await dst.executemany(ins, [tuple(r) for r in rows])
        moved += len(rows)
    return moved


async def _append_audit_log(src, dst, *, dry: bool) -> int:
    hwm = await dst.fetchval(
        "select coalesce(max(occurred_at), 'epoch'::timestamptz) from audit_log"
    )
    rows = await src.fetch(
        "select event_type, actor, resource, ip_address, status, detail, occurred_at "
        "from audit_log where occurred_at > $1 order by occurred_at",
        hwm,
    )
    if not rows or dry:
        return len(rows)
    await dst.executemany(
        "insert into audit_log "
        "(event_type, actor, resource, ip_address, status, detail, occurred_at) "
        "values ($1, $2, $3, $4, $5, $6, $7)",
        [tuple(r) for r in rows],
    )
    return len(rows)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    import asyncpg

    local_dsn = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
    remote_dsn = os.environ["STANDBY_DATABASE_URL"]
    local = await asyncpg.connect(local_dsn, statement_cache_size=0)
    remote = await asyncpg.connect(remote_dsn, statement_cache_size=0)

    tot_l2r = tot_r2l = 0
    try:
        for t in _UUID_TABLES:
            r = await _merge_uuid_table(local, remote, t, dry=args.dry_run)
            tot_l2r += r
            if r:
                logger.info("pg_merge", table=t, direction="local->neon", rows=r)
        for t in _UUID_TABLES:
            r = await _merge_uuid_table(remote, local, t, dry=args.dry_run)
            tot_r2l += r
            if r:
                logger.info("pg_merge", table=t, direction="neon->local", rows=r)
        al = await _append_audit_log(local, remote, dry=args.dry_run)
        if al:
            logger.info("pg_merge", table="audit_log", direction="local->neon", rows=al)
    finally:
        await local.close()
        await remote.close()

    tag = "DRY-RUN " if args.dry_run else ""
    print(f"{tag}pg bilateral — local->neon {tot_l2r} · neon->local {tot_r2l}")
    logger.info(
        "sync_pg_bilateral_done", local_to_neon=tot_l2r, neon_to_local=tot_r2l, dry=args.dry_run
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
