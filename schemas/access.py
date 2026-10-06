"""Pydantic v2 schemas for administrable roles, users and permissions."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, StrictBool, field_validator

from auth.permissions import PERMISSIONS

_NAME = r"^[A-Za-z0-9ÁÉÍÓÚÑáéíóúñ _.-]{2,60}$"


def _known(codes: list[str]) -> list[str]:
    unknown = sorted(set(codes) - set(PERMISSIONS))
    if unknown:
        raise ValueError(f"Unknown permissions: {', '.join(unknown)}")
    return sorted(set(codes))


class PermissionInfo(BaseModel):
    code: str
    description: str


class RoleCreate(BaseModel):
    name: str = Field(..., pattern=_NAME)
    description: str = Field("", max_length=300)
    permissions: list[str] = Field(default_factory=list, max_length=len(PERMISSIONS))

    @field_validator("permissions")
    @classmethod
    def known(cls, value: list[str]) -> list[str]:
        return _known(value)


class RoleUpdate(BaseModel):
    name: str | None = Field(None, pattern=_NAME)
    description: str | None = Field(None, max_length=300)
    permissions: list[str] | None = Field(None, max_length=len(PERMISSIONS))

    @field_validator("permissions")
    @classmethod
    def known(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _known(value)


class RoleOut(BaseModel):
    id: str
    name: str
    description: str
    permissions: list[str]
    is_system: bool
    user_count: int = 0


class UserOut(BaseModel):
    id: str
    email: str
    base_role: str
    role_id: str | None
    role_name: str | None
    is_active: bool
    permissions: list[str]
    last_login: datetime | None = None


class UserUpdate(BaseModel):
    # role_id explícito en null = volver a los permisos del rol base.
    role_id: str | None = Field(None, min_length=36, max_length=36)
    clear_role: StrictBool = False
    is_active: StrictBool | None = None
