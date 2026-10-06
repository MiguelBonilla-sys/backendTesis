"""Rotación de llaves de campos cifrados: idempotencia, rollback, reanudación y CLI.

Usa el mismo PostgreSQL local efímero aislado que test_storage_contracts.py.
No accede a producción ni requiere servicios externos.
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest

from core import crypto
from core.config import settings
from scripts.rotate_field_key import COLUMNS, RotationStats, rotate, rotate_values, run
from tests.integration.test_storage_contracts import databases, postgres_socket  # noqa: F401

SCHEMA = (Path(__file__).resolve().parents[2] / "deploy/schema.sql").read_text()

KEY_OLD = base64.b64encode(bytes(range(32))).decode()
KEY_ACTIVE = base64.b64encode(bytes(range(32, 64))).decode()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(
        settings, "FIELD_ENC_KEYS", json.dumps({"old": KEY_OLD, "active": KEY_ACTIVE})
    )
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "active")
    yield


def _encrypt_with_kid(plain: str, aad: str, kid: str, monkeypatch) -> str:
    previous = settings.FIELD_ENC_ACTIVE
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", kid)
    try:
        return crypto.encrypt_field(plain, aad)
    finally:
        monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", previous)


async def _seed(db, rows, monkeypatch) -> list[uuid.UUID]:
    """Inserta incidentes con columnas cifradas. `kid` por fila (default old)."""
    ids = []
    for row in rows:
        incident_id = row.get("id", uuid.uuid4())
        ids.append(incident_id)
        values = {column: None for column in COLUMNS}
        for column, plain in row.get("fields", {}).items():
            values[column] = _encrypt_with_kid(
                plain, f"{incident_id}|{column}", row.get("kid", "old"), monkeypatch
            )
        await db.execute(
            """INSERT INTO incidents(id, url, domain, verdict,
                                     origin_ip_enc, message_id_enc, headers_enc)
               VALUES ($1, $2, $3, 'PHISHING', $4, $5, $6)""",
            incident_id,
            f"https://{incident_id}.example",
            f"{incident_id}.example",
            *[values[c] for c in COLUMNS],
        )
    return ids


async def _tokens(db, incident_id) -> dict[str, str | None]:
    row = await db.fetchrow(
        "SELECT origin_ip_enc, message_id_enc, headers_enc FROM incidents WHERE id=$1",
        incident_id,
    )
    return dict(row)


def _kid(token: str) -> str:
    return token.split(":", 2)[1]


async def test_dry_run_validates_without_writing(databases, configured, monkeypatch):
    db, _ = databases
    await db.execute(SCHEMA)
    ids = await _seed(
        db,
        [
            {"fields": {"origin_ip_enc": "203.0.113.1", "headers_enc": "h1"}},
            {"fields": {"message_id_enc": "m2"}},
            {"fields": {}},
        ],
        monkeypatch,
    )
    before = {i: await _tokens(db, i) for i in ids}

    stats = await rotate(db, apply=False, batch_size=2)

    assert stats.dry_run is True
    assert stats.scanned_rows == 3
    assert stats.candidates == 3  # dos en fila 1, una en fila 2
    assert stats.committed_batches == 0
    assert stats.rotated_fields == 0
    assert {i: await _tokens(db, i) for i in ids} == before


async def test_apply_rotates_to_active_key_and_is_idempotent(databases, configured, monkeypatch):
    db, _ = databases
    await db.execute(SCHEMA)
    expected = {
        "origin_ip_enc": "203.0.113.1",
        "message_id_enc": "m1",
        "headers_enc": "h1",
    }
    ids = await _seed(
        db,
        [
            {"fields": dict(expected)},
            {"fields": {"origin_ip_enc": "203.0.113.2"}},
        ],
        monkeypatch,
    )

    stats = await rotate(db, apply=True, batch_size=1)
    assert stats.committed_batches == 2
    assert stats.rotated_fields == 4
    assert stats.dry_run is False

    first = await _tokens(db, ids[0])
    second = await _tokens(db, ids[1])
    for column, plain in expected.items():
        token = first[column]
        assert _kid(token) == "active"
        assert crypto.decrypt_field(token, f"{ids[0]}|{column}") == plain
    assert first["message_id_enc"] and first["headers_enc"]
    assert _kid(second["origin_ip_enc"]) == "active"
    assert (
        crypto.decrypt_field(second["origin_ip_enc"], f"{ids[1]}|origin_ip_enc")
        == "203.0.113.2"
    )
    assert second["message_id_enc"] is None and second["headers_enc"] is None

    before_second = {i: await _tokens(db, i) for i in ids}
    second = await rotate(db, apply=True)
    assert second.rotated_fields == 0
    assert second.candidates == 0
    assert {i: await _tokens(db, i) for i in ids} == before_second


async def test_batch_rolls_back_and_previous_batches_stay_committed(
    databases, configured, monkeypatch
):
    db, _ = databases
    await db.execute(SCHEMA)
    ids = await _seed(
        db,
        [
            {"fields": {"origin_ip_enc": "203.0.113.1"}},
            {"fields": {"origin_ip_enc": "203.0.113.2"}},
            {"fields": {"origin_ip_enc": "203.0.113.3"}},
        ],
        monkeypatch,
    )
    # rotate() pagina por UUID ascendente, no por orden de inserción.
    ordered = sorted(ids)
    middle = ordered[1]

    # Corrompe un byte del valor de la fila del medio.
    token = (await _tokens(db, middle))["origin_ip_enc"]
    prefix, kid, payload = token.split(":", 2)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 0x01
    corrupted = f"{prefix}:{kid}:{base64.b64encode(bytes(raw)).decode()}"
    await db.execute("UPDATE incidents SET origin_ip_enc=$1 WHERE id=$2", corrupted, middle)

    with pytest.raises(crypto.FieldCryptoError):
        await rotate(db, apply=True, batch_size=1)

    # El lote anterior al fallo quedó rotado y commiteado; el corrupto y el
    # posterior quedan intactos (el fallo aborta el lote en curso y el proceso).
    assert _kid((await _tokens(db, ordered[0]))["origin_ip_enc"]) == "active"
    assert (await _tokens(db, middle))["origin_ip_enc"] == corrupted
    assert _kid((await _tokens(db, ordered[2]))["origin_ip_enc"]) == "old"

    # Reanudación: se corrige la fila corrupta y se reejecuta. La ya rotada no
    # cuenta como candidata; solo la última pendiente se rota.
    await db.execute("DELETE FROM incidents WHERE id=$1", middle)
    stats = await rotate(db, apply=True, batch_size=1)
    assert stats.rotated_fields == 1
    assert stats.committed_batches == 2  # una fila ya activa + una rotada
    assert _kid((await _tokens(db, ordered[2]))["origin_ip_enc"]) == "active"


async def test_dry_run_detects_tampering(databases, configured, monkeypatch):
    db, _ = databases
    await db.execute(SCHEMA)
    ids = await _seed(db, [{"fields": {"origin_ip_enc": "203.0.113.1"}}], monkeypatch)
    await db.execute(
        "UPDATE incidents SET origin_ip_enc='texto-en-claro' WHERE id=$1", ids[0]
    )
    with pytest.raises(crypto.FieldCryptoError):
        await rotate(db, apply=False)


async def test_batch_size_bounds(databases, configured):
    db, _ = databases
    await db.execute(SCHEMA)
    for size in (0, 1001):
        with pytest.raises(ValueError):
            await rotate(db, batch_size=size)


async def test_unconfigured_keys_are_rejected(databases, monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", "")
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "")
    db, _ = databases
    await db.execute(SCHEMA)
    with pytest.raises(crypto.FieldCryptoError):
        await rotate(db)


def test_rotate_values_authenticates_already_active_ciphertext(configured):
    row = {"id": uuid.uuid4(), "origin_ip_enc": None, "message_id_enc": None,
           "headers_enc": None}
    assert rotate_values(row) == {}
    aad = f"{row['id']}|origin_ip_enc"
    row["origin_ip_enc"] = crypto.encrypt_field("203.0.113.9", aad)
    assert rotate_values(row) == {}
    assert row["origin_ip_enc"].startswith("v1:active:")


async def test_run_cli_dry_run_prints_json_and_does_not_write(
    databases, configured, monkeypatch, capsys, postgres_socket
):
    db, _ = databases
    await db.execute(SCHEMA)
    ids = await _seed(db, [{"fields": {"origin_ip_enc": "203.0.113.1"}}], monkeypatch)
    monkeypatch.setattr(settings, "DATABASE_URL", await _dsn(db, postgres_socket))
    before = await _tokens(db, ids[0])

    code = await run(_args(apply=False))

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "ok" and report["dry_run"] is True
    assert report["candidates"] == 1 and report["rotated_fields"] == 0
    assert await _tokens(db, ids[0]) == before


async def test_run_cli_apply_rotates(
    configured, monkeypatch, databases, capsys, postgres_socket
):
    db, _ = databases
    await db.execute(SCHEMA)
    ids = await _seed(db, [{"fields": {"origin_ip_enc": "203.0.113.1"}}], monkeypatch)
    monkeypatch.setattr(settings, "DATABASE_URL", await _dsn(db, postgres_socket))

    code = await run(_args(apply=True, batch_size=10))

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "ok" and report["rotated_fields"] == 1
    assert _kid((await _tokens(db, ids[0]))["origin_ip_enc"]) == "active"


async def test_run_cli_reports_unconfigured_without_touching_db(
    monkeypatch, capsys, configured
):
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", "")
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "")
    code = await run(_args(apply=False))
    assert code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "failed"
    assert report["reason"] == "ciphertext_or_keys_invalid"


async def test_run_cli_reports_tampering_without_leaking_values(
    databases, configured, monkeypatch, capsys, postgres_socket
):
    db, _ = databases
    await db.execute(SCHEMA)
    ids = await _seed(db, [{"fields": {"origin_ip_enc": "203.0.113.1"}}], monkeypatch)
    await db.execute(
        "UPDATE incidents SET origin_ip_enc='texto-en-claro' WHERE id=$1", ids[0]
    )
    monkeypatch.setattr(settings, "DATABASE_URL", await _dsn(db, postgres_socket))

    code = await run(_args(apply=False))

    assert code == 2
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["status"] == "failed"
    assert report["reason"] == "ciphertext_or_keys_invalid"
    for secret in (KEY_OLD, KEY_ACTIVE, "203.0.113", "texto-en-claro", "testuser"):
        assert secret not in out


async def _dsn(db, postgres_socket) -> str:
    name = await db.fetchval("SELECT current_database()")
    return f"postgresql://testuser@/{name}?host={postgres_socket}"


def _args(**kwargs):
    class Args:
        apply = kwargs.get("apply", False)
        batch_size = kwargs.get("batch_size", 100)

    return Args()
pytestmark = [pytest.mark.regression]
