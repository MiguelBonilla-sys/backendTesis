"""Pydantic v2 schemas for authentication endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    """Alta self-service — el router valida además el dominio institucional USB."""

    # Forma básica de correo; el control real es la allowlist de dominios del router.
    email: str = Field(..., min_length=6, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    # Login must accept any non-empty credential — complexity rules belong on
    # registration only. Enforcing min_length here returns 422 and locks out
    # otherwise valid users instead of failing with a proper 401.
    username: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos (900 = 15 min)
    role: Literal["admin", "student", "viewer"]
    refresh_token: str | None = None
    refresh_expires_in: int | None = None  # segundos


class RefreshRequest(BaseModel):
    # Optativo: el dashboard no manda body, el refresh token viaja en la
    # cookie httpOnly. La extensión sigue mandándolo en el body.
    refresh_token: str | None = Field(None, min_length=1)


class UserInfo(BaseModel):
    username: str
    role: Literal["admin", "student", "viewer"]


class TokenPayload(BaseModel):
    sub: str  # username
    role: str  # "admin" | "student" | "viewer"
    exp: int  # unix timestamp
