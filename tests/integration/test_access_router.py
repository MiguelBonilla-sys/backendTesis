"""Access administration against a real isolated PostgreSQL (JSONB, FK, guards)."""

from __future__ import annotations

import importlib
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from auth.permissions import DEFAULT_ROLE_PERMISSIONS, effective_permissions
from schemas.access import RoleCreate, RoleUpdate, UserUpdate
from tests.integration.test_storage_contracts import (  # noqa: F401
    SCHEMA,
    databases,
    postgres_socket,
)

ar = importlib.import_module("routers.access_router")

ADMIN = {"sub": "boss@usb.edu.co", "role": "admin",
         "permissions": sorted(DEFAULT_ROLE_PERMISSIONS["admin"])}
USER_MANAGER = {"sub": "rrhh@usb.edu.co", "role": "viewer",
                "permissions": ["users:manage", "incidents:read"]}


class _Db:
    def __init__(self, conn, audit):
        self.fetchval, self.execute, self.audit = conn.fetchval, conn.execute, audit


@pytest.fixture
async def db(databases):  # noqa: F811
    conn, _ = databases
    await conn.execute(SCHEMA)
    with patch.object(ar, "fetch", conn.fetch), patch.object(ar, "fetchrow", conn.fetchrow), \
         patch.object(ar, "execute", conn.execute), \
         patch.object(ar, "log_audit_event", AsyncMock()) as audit:
        yield _Db(conn, audit)


async def _user(db, email, role="student", role_id=None, active=True):
    return await db.fetchval(
        "INSERT INTO users(email, password_hash, role, role_id, is_active) "
        "VALUES ($1, 'h', $2, $3, $4) RETURNING id", email, role, role_id, active)


async def test_create_assign_and_effective_permissions(db):
    admin_id = await _user(db, "boss@usb.edu.co", role="admin")
    role = await ar.create_role(
        RoleCreate(name="Analista SOC", permissions=["incidents:read", "alerts:receive"]), ADMIN)
    assert role.permissions == ["alerts:receive", "incidents:read"]
    student = await _user(db, "ana@usb.edu.co")
    updated = await ar.update_user(str(student), UserUpdate(role_id=role.id), ADMIN)
    assert updated.role_name == "Analista SOC"
    assert set(updated.permissions) == {"incidents:read", "alerts:receive"}
    assert db.audit.await_args.kwargs["event_type"] == "user_updated"
    roles = await ar.list_roles(ADMIN)
    assert [r.name for r in roles][:3] == ["admin", "student", "viewer"]
    assert next(r for r in roles if r.id == role.id).user_count == 1
    users = await ar.list_users(ADMIN)
    assert {u.email for u in users} == {"boss@usb.edu.co", "ana@usb.edu.co"}
    assert admin_id


async def test_duplicate_role_name_conflicts(db):
    await ar.create_role(RoleCreate(name="soc"), ADMIN)
    with pytest.raises(HTTPException) as exc:
        await ar.create_role(RoleCreate(name="SOC"), ADMIN)
    assert exc.value.status_code == 409


async def test_cannot_grant_permissions_you_do_not_hold(db):
    with pytest.raises(HTTPException) as exc:
        await ar.create_role(RoleCreate(name="xx", permissions=["roles:manage"]), USER_MANAGER)
    assert exc.value.status_code == 403
    await _user(db, "boss@usb.edu.co", role="admin")
    target = await _user(db, "ana@usb.edu.co")
    with pytest.raises(HTTPException) as exc:
        await ar.update_user(
            str(target), UserUpdate(role_id="00000000-0000-4000-8000-000000000001"), USER_MANAGER)
    assert exc.value.status_code == 403


async def test_system_roles_are_immutable_and_roles_with_users_kept(db):
    with pytest.raises(HTTPException) as exc:
        await ar.update_role("00000000-0000-4000-8000-000000000001",
                             RoleUpdate(permissions=[]), ADMIN)
    assert exc.value.status_code == 409
    role = await ar.create_role(RoleCreate(name="temporal"), ADMIN)
    await _user(db, "ana@usb.edu.co", role_id=uuid.UUID(role.id))
    with pytest.raises(HTTPException) as exc:
        await ar.delete_role(role.id, ADMIN)
    assert exc.value.status_code == 409


async def test_delete_and_update_custom_role(db):
    role = await ar.create_role(RoleCreate(name="borrar", description="a"), ADMIN)
    changed = await ar.update_role(role.id, RoleUpdate(description="b",
                                                       permissions=["metrics:read"]), ADMIN)
    assert (changed.description, changed.permissions) == ("b", ["metrics:read"])
    await ar.delete_role(role.id, ADMIN)
    assert await db.fetchval("SELECT count(*) FROM roles WHERE id = $1", uuid.UUID(role.id)) == 0


async def test_last_admin_cannot_be_removed(db):
    only_admin = await _user(db, "boss@usb.edu.co", role="admin")
    with pytest.raises(HTTPException) as exc:
        await ar.update_user(str(only_admin), UserUpdate(is_active=False), ADMIN)
    assert exc.value.status_code == 409
    with pytest.raises(HTTPException) as exc:
        await ar.update_user(
            str(only_admin), UserUpdate(role_id="00000000-0000-4000-8000-000000000003"), ADMIN)
    assert exc.value.status_code == 409
    await _user(db, "otro@usb.edu.co", role="admin")
    done = await ar.update_user(str(only_admin), UserUpdate(is_active=False), ADMIN)
    assert done.is_active is False


async def test_role_losing_roles_manage_keeps_a_manager(db):
    role = await ar.create_role(RoleCreate(name="jefes", permissions=["roles:manage"]), ADMIN)
    await _user(db, "jefe@usb.edu.co", role="student", role_id=uuid.UUID(role.id))
    with pytest.raises(HTTPException) as exc:
        await ar.update_role(role.id, RoleUpdate(permissions=[]), ADMIN)
    assert exc.value.status_code == 409
    await _user(db, "boss@usb.edu.co", role="admin")
    assert (await ar.update_role(role.id, RoleUpdate(permissions=[]), ADMIN)).permissions == []


async def test_clear_role_returns_to_base_defaults(db):
    await _user(db, "boss@usb.edu.co", role="admin")
    role = await ar.create_role(RoleCreate(name="rr", permissions=["metrics:read"]), ADMIN)
    uid = await _user(db, "ana@usb.edu.co", role_id=uuid.UUID(role.id))
    out = await ar.update_user(str(uid), UserUpdate(clear_role=True), ADMIN)
    assert out.role_id is None and out.permissions == ["analyze:run"]


async def test_not_found_and_bad_ids(db):
    for call in (ar.update_role(str(uuid.uuid4()), RoleUpdate(), ADMIN),
                 ar.update_user(str(uuid.uuid4()), UserUpdate(), ADMIN)):
        with pytest.raises(HTTPException) as exc:
            await call
        assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        await ar.delete_role("not-a-uuid", ADMIN)
    assert exc.value.status_code == 422
    uid = await _user(db, "ana@usb.edu.co")
    with pytest.raises(HTTPException) as exc:
        await ar.update_user(str(uid), UserUpdate(role_id=str(uuid.uuid4())), ADMIN)
    assert exc.value.status_code == 404


async def test_permission_catalog(db):
    codes = {p.code for p in await ar.list_permissions(ADMIN)}
    assert {"roles:manage", "alerts:receive", "incidents:forensics"} <= codes


def test_effective_permissions_fallbacks():
    assert effective_permissions("student") == {"analyze:run"}
    assert effective_permissions("admin", '["metrics:read","bogus"]') == {"metrics:read"}
    assert effective_permissions("nobody") == frozenset()


def test_unknown_permission_rejected_by_schema():
    with pytest.raises(ValueError):
        RoleCreate(name="xx", permissions=["root:all"])


def test_student_gets_403_over_http(auth_store):
    from main import app
    from tests.auth_helpers import create_access_token

    auth_store.add_account("alumno@usb.edu.co", "student")
    token = create_access_token({"sub": "alumno@usb.edu.co", "role": "student"})
    with patch("main.init_db", new_callable=AsyncMock), \
         patch("main.close_db", new_callable=AsyncMock), \
         patch("main.init_redis", new_callable=AsyncMock), \
         patch("main.close_redis", new_callable=AsyncMock), TestClient(app) as client:
        for path in ("/api/v1/roles", "/api/v1/users", "/api/v1/permissions"):
            resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403, path


async def test_f33_02_rename_to_existing_name_is_409(db):
    a = await ar.create_role(RoleCreate(name="alfa"), ADMIN)
    await ar.create_role(RoleCreate(name="beta"), ADMIN)
    with pytest.raises(HTTPException) as exc:
        await ar.update_role(a.id, RoleUpdate(name="BETA"), ADMIN)
    assert exc.value.status_code == 409
    assert (await ar.update_role(a.id, RoleUpdate(name="Alfa"), ADMIN)).name == "Alfa"


async def test_f33_02_unique_race_maps_to_409():
    import asyncpg

    from core.exceptions import DatabaseError

    async def racing(*args):
        try:
            raise asyncpg.UniqueViolationError("duplicate key")
        except asyncpg.UniqueViolationError as cause:
            raise DatabaseError("Database fetchrow failed") from cause

    with patch.object(ar, "fetchrow", side_effect=racing):
        with pytest.raises(HTTPException) as exc:
            await ar._write_role("INSERT ...")
    assert exc.value.status_code == 409
    with patch.object(ar, "fetchrow", side_effect=DatabaseError("down")):
        with pytest.raises(DatabaseError):
            await ar._write_role("INSERT ...")

pytestmark = [pytest.mark.acceptance]
