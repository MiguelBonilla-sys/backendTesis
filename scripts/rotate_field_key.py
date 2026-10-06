"""Validate and rotate encrypted incident fields in restartable transactions.

Default is a read-only dry run. Run from the repository root:
    python -m scripts.rotate_field_key [--apply] [--batch-size 100]
Reads DATABASE_URL and FIELD_ENC_* through settings. Never prints their values,
plaintext, ciphertext, or row identifiers. Does not remove old keys.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass
import json

import asyncpg

from core.config import settings
from core.crypto import FieldCryptoError, decrypt_field, is_configured, needs_rotation, reencrypt_field

COLUMNS = ("origin_ip_enc", "message_id_enc", "headers_enc")


@dataclass
class RotationStats:
    scanned_rows: int = 0
    candidates: int = 0
    rotated_fields: int = 0
    committed_batches: int = 0
    dry_run: bool = True


def rotate_values(row) -> dict[str, str]:
    """Authenticate every non-null value, including already-active ciphertext."""
    updates = {}
    for column in COLUMNS:
        token = row[column]
        if token is None:
            continue
        aad = f"{row['id']}|{column}"
        # needs_rotation alone tolerates malformed inputs. Always authenticate.
        decrypt_field(token, aad)
        if needs_rotation(token):
            updates[column] = reencrypt_field(token, aad)
    return updates


async def rotate(connection, *, apply: bool = False, batch_size: int = 100,
                 stats: RotationStats | None = None) -> RotationStats:
    if not 1 <= batch_size <= 1000:
        raise ValueError("batch_size must be between 1 and 1000")
    if not is_configured():
        raise FieldCryptoError("Configure both the active key and all previous keys first")
    stats = stats if stats is not None else RotationStats()
    stats.dry_run = not apply
    # A fixed upper bound makes this run finite while new incidents are inserted.
    # All writers must already use the active key before starting the rotation.
    ceiling = await connection.fetchval("SELECT id FROM incidents ORDER BY id DESC LIMIT 1")
    if ceiling is None:
        return stats
    last_id = None
    while True:
        async with connection.transaction(readonly=not apply):
            query = """SELECT id, origin_ip_enc, message_id_enc, headers_enc
                       FROM incidents
                       WHERE ($1::uuid IS NULL OR id > $1::uuid) AND id <= $2::uuid
                       ORDER BY id LIMIT $3"""
            if apply:
                # No SKIP LOCKED: skipped rows could otherwise be missed forever.
                query += " FOR UPDATE"
            rows = await connection.fetch(query, last_id, ceiling, batch_size)
            if not rows:
                break
            candidates = 0
            for row in rows:
                updates = rotate_values(row)
                candidates += len(updates)
                if apply and updates:
                    values = [updates.get(column, row[column]) for column in COLUMNS]
                    await connection.execute(
                        """UPDATE incidents SET origin_ip_enc=$2, message_id_enc=$3,
                           headers_enc=$4 WHERE id=$1""",
                        row["id"], *values,
                    )
            # Counters advance only after successful transaction exit below.
        stats.scanned_rows += len(rows)
        stats.candidates += candidates
        if apply:
            stats.rotated_fields += candidates
            stats.committed_batches += 1
        last_id = rows[-1]["id"]
    return stats


async def run(args) -> int:
    stats = RotationStats(dry_run=not args.apply)
    connection = None
    try:
        if not is_configured():
            raise FieldCryptoError("Keys are not configured")
        connection = await asyncpg.connect(
            settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1),
            command_timeout=60,
        )
        await rotate(connection, apply=args.apply, batch_size=args.batch_size, stats=stats)
        print(json.dumps({"status": "ok", **asdict(stats)}))
        return 0
    except (FieldCryptoError, UnicodeError):
        print(json.dumps({"status": "failed", "reason": "ciphertext_or_keys_invalid", **asdict(stats)}))
        return 2
    except Exception:
        # Database exceptions can contain connection credentials or row content.
        print(json.dumps({"status": "failed", "reason": "database_or_configuration_error", **asdict(stats)}))
        return 2
    finally:
        if connection is not None:
            await connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Commit changes; default only validates")
    parser.add_argument("--batch-size", type=int, choices=range(1, 1001), default=100, metavar="1..1000")
    args = parser.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
