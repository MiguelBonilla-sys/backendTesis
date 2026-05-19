"""Pydantic v2 schemas for authentication endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos (900 = 15 min)


class UserInfo(BaseModel):
    username: str
    role: Literal["admin", "student", "viewer"]


class TokenPayload(BaseModel):
    sub: str        # username
    role: str       # "admin" | "student" | "viewer"
    exp: int        # unix timestamp
