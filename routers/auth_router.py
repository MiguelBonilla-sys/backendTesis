"""
Auth router — POST /api/v1/auth/login
Genera JWT HS256 con exp=15min para acceso a endpoints protegidos.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from auth.dependencies import require_auth
from auth.jwt import create_access_token
from core.config import settings
from core.logger import get_logger
from schemas.auth import LoginRequest, TokenResponse, UserInfo

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


# --------------------------------------------------------------------------- #
# POST /auth/login
# --------------------------------------------------------------------------- #


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest) -> TokenResponse:
    """
    Autentica usuario y retorna JWT.
    En v1: un solo usuario admin configurable via env vars.
    Protección: bcrypt verify de password.
    """
    user = await _authenticate_user(request.username, request.password)
    if not user:
        logger.warning("login_failed", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(data={"sub": user.username, "role": user.role})
    logger.info("login_success", username=user.username, role=user.role)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        role=user.role,
    )


# --------------------------------------------------------------------------- #
# GET /auth/me
# --------------------------------------------------------------------------- #


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(
    current_user: dict = Depends(require_auth),
) -> UserInfo:
    """Retorna info del usuario autenticado."""
    return UserInfo(
        username=current_user.get("sub", ""),
        role=current_user.get("role", "viewer"),
    )


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


async def _authenticate_user(username: str, password: str) -> UserInfo | None:
    """Valida credenciales contra la tabla users de PostgreSQL."""
    from core.security import verify_password
    from models.database import fetchrow

    row = await fetchrow(
        "SELECT email, password_hash, role, is_active FROM users WHERE email = $1",
        username,
    )
    if row is None or not row["is_active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return UserInfo(username=row["email"], role=row["role"])
