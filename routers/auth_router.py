"""
Auth router — POST /api/v1/auth/login
Genera JWT HS256 con exp=15min para acceso a endpoints protegidos.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from auth.dependencies import require_auth
from auth.jwt import create_access_token, create_refresh_token, decode_token
from core.config import settings
from core.constants import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
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


def _cookie_kwargs() -> dict:
    """Flags de cookie — relajados en dev para que anden sin HTTPS.

    localhost:5173 (frontend) y localhost:8000 (backend) son same-site para el
    navegador (mismo host, distinto puerto no cuenta), así que Secure=False +
    SameSite=Lax alcanza en local. En producción Coolify y Render viven en
    subdominios de mangel.dpdns.org (`back-tesi.` / `render.`) — mismo
    registrable domain — así que AUTH_COOKIE_DOMAIN=mangel.dpdns.org comparte
    la cookie entre ambos y el failover deja de perder la sesión.
    """
    is_dev = settings.APP_ENV == "development"
    return {
        "httponly": True,
        "secure": False if is_dev else settings.AUTH_COOKIE_SECURE,
        "samesite": "lax" if is_dev else settings.AUTH_COOKIE_SAMESITE,
        "domain": settings.AUTH_COOKIE_DOMAIN or None,
        "path": "/",
    }


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """Setea las cookies httpOnly del dashboard. La extensión ignora esto y usa el body."""
    cookie_kwargs = _cookie_kwargs()
    response.set_cookie(
        ACCESS_TOKEN_COOKIE, access_token, max_age=settings.JWT_EXPIRE_MINUTES * 60, **cookie_kwargs
    )
    response.set_cookie(
        REFRESH_TOKEN_COOKIE,
        refresh_token,
        max_age=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
        **cookie_kwargs,
    )


def _clear_auth_cookies(response: Response) -> None:
    domain = settings.AUTH_COOKIE_DOMAIN or None
    response.delete_cookie(ACCESS_TOKEN_COOKIE, domain=domain, path="/")
    response.delete_cookie(REFRESH_TOKEN_COOKIE, domain=domain, path="/")


# --------------------------------------------------------------------------- #
# POST /auth/login
# --------------------------------------------------------------------------- #


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, response: Response) -> TokenResponse:
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
    _set_auth_cookies(response, token, refresh)

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
async def register(payload: RegisterRequest, request: Request, response: Response) -> TokenResponse:
    """Crea una cuenta de estudiante. Solo correos institucionales USB.

    Rol siempre ``student`` — el alta self-service nunca crea admins.
    Devuelve el token para iniciar sesión de una vez.
    """
    await check_rate_limit(f"rl:register:{get_client_ip(request)}", limit=5, window_seconds=3600)

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
    issued = _issue_tokens(email, "student")
    _set_auth_cookies(response, issued.access_token, issued.refresh_token or "")
    return issued


# --------------------------------------------------------------------------- #
# GET /auth/me
# --------------------------------------------------------------------------- #


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    response: Response, request: Request, body: RefreshRequest | None = None
) -> TokenResponse:
    """Renueva el access token. Dashboard: refresh token en cookie httpOnly.
    Extensión: sigue mandándolo en el body."""
    raw_token = (body.refresh_token if body else None) or request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(raw_token)
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
    _set_auth_cookies(response, token, new_refresh)

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


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    """Limpia las cookies httpOnly del dashboard. No requiere sesión válida."""
    _clear_auth_cookies(response)


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
