"""Pydantic v2 schemas for authentication endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


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


class UserInfo(BaseModel):
    username: str
    role: Literal["admin", "student", "viewer"]


class TokenPayload(BaseModel):
    sub: str        # username
    role: str       # "admin" | "student" | "viewer"
    exp: int        # unix timestamp
