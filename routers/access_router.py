"""Access control administration: roles, permissions and user assignment.

Guards: system roles are immutable, a role with users cannot be deleted, an actor
can only grant permissions it already holds (no self-escalation) and no change may
leave the system without an active account holding ``roles:manage``.
"""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status

from auth.permissions import (
    PERMISSIONS,
    effective_permissions,
    parse_permissions,
    require_permission,
)
from core.logger import get_logger
from models.database import execute, fetch, fetchrow, log_audit_event
from schemas.access import PermissionInfo, RoleCreate, RoleOut, RoleUpdate, UserOut, UserUpdate

logger = get_logger(__name__)
router = APIRouter(tags=["access"])

_ROLE_SQL = (
    "SELECT r.id, r.name, r.description, r.permissions, r.is_system, "
    "(SELECT count(*) FROM users u WHERE u.role_id = r.id) AS user_count FROM roles r"
)
_USER_SQL = (
    "SELECT u.id, u.email, u.role, u.role_id, u.is_active, u.last_login, "
    "r.name AS role_name, r.permissions AS role_permissions "
    "FROM users u LEFT JOIN roles r ON r.id = u.role_id"
)
_MANAGERS_SQL = (
    "SELECT count(*) AS n FROM users u LEFT JOIN roles r ON r.id = u.role_id "
    "WHERE u.is_active AND u.id <> $1 AND ("
    "(u.role_id IS NULL AND u.role = 'admin') OR "
    "(u.role_id IS NOT NULL AND r.permissions ? 'roles:manage'))"
)


def _uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid id") from exc


def _role_out(row) -> RoleOut:
    return RoleOut(
        id=str(row["id"]), name=row["name"], description=row["description"] or "",
        permissions=parse_permissions(row["permissions"]), is_system=bool(row["is_system"]),
        user_count=int(row.get("user_count") or 0) if hasattr(row, "get") else 0,
    )


def _user_out(row) -> UserOut:
    perms = effective_permissions(row["role"], row["role_permissions"] if row["role_id"] else None)
    return UserOut(
        id=str(row["id"]), email=row["email"], base_role=row["role"],
        role_id=str(row["role_id"]) if row["role_id"] else None, role_name=row["role_name"],
        is_active=bool(row["is_active"]), permissions=sorted(perms), last_login=row["last_login"],
    )


def _ensure_grantable(actor: dict, permissions: list[str]) -> None:
    missing = sorted(set(permissions) - set(actor.get("permissions") or []))
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot grant permissions you do not hold: {', '.join(missing)}",
        )


async def _audit(actor: dict, event: str, resource: str, detail: dict) -> None:
    await log_audit_event(event_type=event, status="SUCCESS", actor=actor.get("sub"),
                          resource=resource, detail=detail)


@router.get("/permissions", response_model=list[PermissionInfo])
async def list_permissions(_: dict = Depends(require_permission("roles:manage"))):
    return [PermissionInfo(code=c, description=d) for c, d in PERMISSIONS.items()]


@router.get("/roles", response_model=list[RoleOut])
async def list_roles(_: dict = Depends(require_permission("roles:manage"))):
    rows = await fetch(f"{_ROLE_SQL} ORDER BY r.is_system DESC, r.name")  # nosec B608 # SQL literal
    return [_role_out(dict(row)) for row in rows]


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(body: RoleCreate, actor: dict = Depends(require_permission("roles:manage"))):
    _ensure_grantable(actor, body.permissions)
    if await fetchrow("SELECT id FROM roles WHERE lower(name) = lower($1)", body.name):
        raise HTTPException(status_code=409, detail="A role with that name already exists")
    row = await fetchrow(
        "INSERT INTO roles (name, description, permissions) VALUES ($1, $2, $3::jsonb) "
        "RETURNING id, name, description, permissions, is_system",
        body.name, body.description, json.dumps(body.permissions),
    )
    await _audit(actor, "role_created", f"role:{row['id']}",
                 {"name": body.name, "permissions": body.permissions})
    return _role_out(dict(row))


async def _load_role(role_id: str):
    row = await fetchrow(f"{_ROLE_SQL} WHERE r.id = $1", _uuid(role_id))  # nosec B608 # SQL literal
    if row is None:
        raise HTTPException(status_code=404, detail="Role not found")
    if row["is_system"]:
        raise HTTPException(status_code=409, detail="System roles cannot be changed")
    return dict(row)


@router.patch("/roles/{role_id}", response_model=RoleOut)
async def update_role(
    role_id: str, body: RoleUpdate, actor: dict = Depends(require_permission("roles:manage")),
):
    current = await _load_role(role_id)
    permissions = body.permissions if body.permissions is not None else parse_permissions(
        current["permissions"])
    _ensure_grantable(actor, permissions)
    if "roles:manage" in parse_permissions(current["permissions"]) and \
            "roles:manage" not in permissions and current["user_count"]:
        managers = await fetchrow(
            _MANAGERS_SQL.replace("u.id <> $1", "u.role_id IS DISTINCT FROM $1"), current["id"])
        if not managers["n"]:
            raise HTTPException(
                status_code=409, detail="This would leave no account able to manage roles")
    row = await fetchrow(
        "UPDATE roles SET name = $2, description = $3, permissions = $4::jsonb, updated_at = NOW() "
        "WHERE id = $1 RETURNING id, name, description, permissions, is_system",
        current["id"], body.name or current["name"],
        body.description if body.description is not None else current["description"],
        json.dumps(permissions),
    )
    await _audit(actor, "role_updated", f"role:{row['id']}", {"permissions": permissions})
    return _role_out({**dict(row), "user_count": current["user_count"]})


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: str, actor: dict = Depends(require_permission("roles:manage"))):
    current = await _load_role(role_id)
    if current["user_count"]:
        raise HTTPException(status_code=409, detail="Reassign the users of this role first")
    await execute("DELETE FROM roles WHERE id = $1", current["id"])
    await _audit(actor, "role_deleted", f"role:{current['id']}", {"name": current["name"]})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users", response_model=list[UserOut])
async def list_users(_: dict = Depends(require_permission("users:manage"))):
    rows = await fetch(f"{_USER_SQL} ORDER BY u.email LIMIT 500")  # nosec B608 # SQL literal
    return [_user_out(row) for row in rows]


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str, body: UserUpdate, actor: dict = Depends(require_permission("users:manage")),
):
    uid = _uuid(user_id)
    current = await fetchrow(f"{_USER_SQL} WHERE u.id = $1", uid)  # nosec B608 # SQL literal
    if current is None:
        raise HTTPException(status_code=404, detail="User not found")
    role_id = current["role_id"]
    role_permissions = current["role_permissions"]
    if body.clear_role:
        role_id, role_permissions = None, None
    elif body.role_id is not None:
        role = await fetchrow(
            "SELECT id, permissions FROM roles WHERE id = $1", _uuid(body.role_id))
        if role is None:
            raise HTTPException(status_code=404, detail="Role not found")
        role_id, role_permissions = role["id"], role["permissions"]
    new_perms = effective_permissions(current["role"], role_permissions if role_id else None)
    if role_id != current["role_id"]:
        _ensure_grantable(actor, sorted(new_perms))
    is_active = current["is_active"] if body.is_active is None else body.is_active
    if not is_active or "roles:manage" not in new_perms:
        others = await fetchrow(_MANAGERS_SQL, uid)
        if not others["n"]:
            raise HTTPException(status_code=409, detail="This would leave no active administrator")
    await execute("UPDATE users SET role_id = $2, is_active = $3 WHERE id = $1",
                  uid, role_id, is_active)
    await _audit(actor, "user_updated", f"user:{uid}",
                 {"role_id": str(role_id) if role_id else None, "is_active": is_active})
    updated = await fetchrow(f"{_USER_SQL} WHERE u.id = $1", uid)  # nosec B608 # SQL literal
    return _user_out(updated)
