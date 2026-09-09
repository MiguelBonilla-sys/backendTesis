"""
Auth router — POST /api/v1/auth/login
Genera JWT HS256 con exp=15min para acceso a endpoints protegidos.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from auth.dependencies import require_auth
from auth.jwt import create_access_token, create_refresh_token, decode_token
from core.config import settings
from core.exceptions import AuthenticationError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from core.security import hash_password
from models.database import execute
from schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserInfo,
)

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
    refresh = create_refresh_token(data={"sub": user.username, "role": user.role})
    logger.info("login_success", username=user.username, role=user.role)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        role=user.role,
        refresh_token=refresh,
        refresh_expires_in=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
    )


# --------------------------------------------------------------------------- #
# POST /auth/register  — alta self-service (solo dominios USB)
# --------------------------------------------------------------------------- #


def _issue_tokens(sub: str, role: str) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(data={"sub": sub, "role": role}),
        token_type="bearer",
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        role=role,
        refresh_token=create_refresh_token(data={"sub": sub, "role": role}),
        refresh_expires_in=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, request: Request) -> TokenResponse:
    """Crea una cuenta de estudiante. Solo correos institucionales USB.

    Rol siempre ``student`` — el alta self-service nunca crea admins.
    Devuelve el token para iniciar sesión de una vez.
    """
    await check_rate_limit(
        f"rl:register:{get_client_ip(request)}", limit=5, window_seconds=3600
    )

    email = payload.email.strip().lower()
    domain = email.rsplit("@", 1)[-1]
    if domain not in settings.ALLOWED_SIGNUP_DOMAINS:
        allowed = " o ".join(f"@{d}" for d in settings.ALLOWED_SIGNUP_DOMAINS)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"El registro es solo para correos {allowed}",
        )

    result = await execute(
        "INSERT INTO users (email, password_hash, role, is_active) "
        "VALUES ($1, $2, 'student', true) ON CONFLICT (email) DO NOTHING",
        email,
        hash_password(payload.password),
    )
    if result.strip().endswith("0 0"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ese correo ya tiene una cuenta. Iniciá sesión.",
        )

    logger.info("user_registered", username=email, role="student")
    return _issue_tokens(email, "student")


# --------------------------------------------------------------------------- #
# GET /auth/me
# --------------------------------------------------------------------------- #


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest) -> TokenResponse:
    """Renueva el access token usando un refresh token válido."""
    try:
        payload = decode_token(request.refresh_token)
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido o vencido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token tipo incorrecto",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload.get("sub", "")
    role = payload.get("role", "student")

    token = create_access_token(data={"sub": sub, "role": role})
    new_refresh = create_refresh_token(data={"sub": sub, "role": role})
    logger.info("token_refreshed", username=sub)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        role=role,
        refresh_token=new_refresh,
        refresh_expires_in=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
    )


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
