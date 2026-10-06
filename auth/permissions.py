"""Permission catalog and the dependency that enforces it per request.

Permissions are resolved from the live account on every request (see
``auth.sessions.validate_session``), so a role change applies to the next call.
Accounts without an administrable role fall back to the defaults of their
base role (``users.role``), which keeps the JWT ``role`` claim unchanged.
"""

from __future__ import annotations

import json

from fastapi import Depends, HTTPException, status

from auth.dependencies import require_auth

PERMISSIONS: dict[str, str] = {
    "analyze:run": "Analizar enlaces y correos",
    "incidents:read": "Ver incidentes y su detalle",
    "incidents:feedback": "Confirmar o corregir veredictos",
    "incidents:forensics": "Ver IP de origen, Message-ID y encabezados",
    "metrics:read": "Ver métricas del dashboard",
    "settings:read": "Ver parámetros del modelo de fusión",
    "settings:write": "Cambiar parámetros del modelo",
    "users:manage": "Crear usuarios y asignar roles",
    "roles:manage": "Crear roles y editar permisos",
    "alerts:receive": "Recibir alertas tempranas por correo",
    "audit:read": "Consultar el registro de auditoría",
}

DEFAULT_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset(PERMISSIONS),
    "student": frozenset({"analyze:run"}),
    "viewer": frozenset({"analyze:run", "incidents:read", "metrics:read"}),
}


def parse_permissions(raw: object) -> list[str]:
    """Normalize a JSONB value (asyncpg returns text) to known permission codes."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    if not isinstance(raw, list):
        return []
    return sorted({code for code in raw if isinstance(code, str) and code in PERMISSIONS})


def effective_permissions(base_role: str | None, role_permissions: object = None) -> frozenset[str]:
    if role_permissions is not None:
        return frozenset(parse_permissions(role_permissions))
    return DEFAULT_ROLE_PERMISSIONS.get(base_role or "", frozenset())


def has_permission(current_user: dict, code: str) -> bool:
    granted = current_user.get("permissions")
    if granted is None:
        granted = effective_permissions(current_user.get("role"))
    return code in granted


def require_permission(*codes: str):
    """Dependency factory: every listed permission is required."""
    unknown = [code for code in codes if code not in PERMISSIONS]
    if unknown:
        raise ValueError(f"Unknown permissions: {unknown}")

    async def _check(current_user: dict = Depends(require_auth)) -> dict:
        missing = [code for code in codes if not has_permission(current_user, code)]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {', '.join(missing)}",
            )
        return current_user

    return _check
