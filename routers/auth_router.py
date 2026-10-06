"""
Auth router — POST /api/v1/auth/login
Genera JWT HS256 con exp=15min para acceso a endpoints protegidos.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from auth.dependencies import require_auth
from auth.jwt import decode_token
from auth.mfa import (
    MfaError,
    new_recovery_codes,
    requires_mfa,
    resend_code,
    start_challenge,
    verify_challenge,
)
from auth.origins import has_auth_cookies, validate_origin
from auth.sessions import issue_session, revoke_session, rotate_session
from core.config import settings
from core.constants import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
from core.exceptions import AuthenticationError
from core.logger import get_logger
from core.rate_limiter import check_rate_limit, get_client_ip
from core.security import hash_email, hash_password_async
from models.database import execute, log_audit_event
from schemas.auth import (
    LoginRequest,
    MfaChallengeResponse,
    MfaResendRequest,
    MfaVerifyRequest,
    RecoveryCodesResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserInfo,
)
from schemas.errors import AUTH

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"], responses=AUTH)


def _cookie_kwargs() -> dict:
    """Flags de cookie — relajados en dev para que anden sin HTTPS.

    localhost:5173 (frontend) y localhost:8000 (backend) son same-site para el
    navegador (mismo host, distinto puerto no cuenta), así que Secure=False +
    SameSite=Lax alcanza en local. En producción Coolify y Render viven en
    subdominios de mangel.dpdns.org (`back-tesi.` / `render.`) — mismo
    registrable domain — así que AUTH_COOKIE_DOMAIN=mangel.dpdns.org comparte
    la cookie entre ambos. La sesión requiere además compartir Redis; un Redis
    independiente exige volver a iniciar sesión después del failover.
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


@router.post("/login", response_model=TokenResponse | MfaChallengeResponse)
async def login(
    payload: LoginRequest, request: Request, response: Response,
) -> TokenResponse | MfaChallengeResponse:
    """Authenticate against the current account under identity and IP budgets."""
    validate_origin(request, cookie_auth=has_auth_cookies(request))
    identity = payload.username.strip().lower()
    await check_rate_limit(
        f"rl:login:ip:{get_client_ip(request)}",
        limit=settings.RATE_LIMIT_LOGIN_IP,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        fail_closed=True,
    )
    await check_rate_limit(
        f"rl:login:identity:{hash_email(identity)}",
        limit=settings.RATE_LIMIT_LOGIN_IDENTITY,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        fail_closed=True,
    )
    user = await _authenticate_user(identity, payload.password)
    if not user:
        logger.warning("login_failed")
        raise HTTPException(
            status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"}
        )
    if requires_mfa(user.role):
        try:
            challenge_id, sent = await start_challenge(user.username)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Second factor unavailable") from exc
        await log_audit_event("mfa_challenge", "SUCCESS" if sent else "FAILURE",
                              actor=user.username, detail={"email_sent": sent})
        logger.info("login_mfa_challenge", username=user.username, email_sent=sent)
        return MfaChallengeResponse(challenge_id=challenge_id, email_sent=sent,
                                    expires_in=settings.MFA_OTP_TTL_SECONDS)
    issued = _token_response(await issue_session(user.username))
    logger.info("login_success", username=user.username, role=issued.role)
    _set_auth_cookies(response, issued.access_token, issued.refresh_token or "")
    return issued


# --------------------------------------------------------------------------- #
# POST /auth/mfa/*  — segundo factor del admin (RFS-01)
# --------------------------------------------------------------------------- #

_MFA_STATUS = {"cooldown": 429, "too_many_codes": 429, "too_many_attempts": 429}


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify(
    payload: MfaVerifyRequest, request: Request, response: Response,
) -> TokenResponse:
    validate_origin(request, cookie_auth=has_auth_cookies(request))
    await check_rate_limit(
        f"rl:mfa:ip:{get_client_ip(request)}",
        limit=settings.RATE_LIMIT_LOGIN_IP,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        fail_closed=True,
    )
    try:
        subject = await verify_challenge(payload.challenge_id, payload.code)
    except MfaError as exc:
        await log_audit_event("mfa_failed", "FAILURE", detail={"reason": exc.reason})
        raise HTTPException(status_code=_MFA_STATUS.get(exc.reason, 401),
                            detail=f"Second factor rejected: {exc.reason}") from exc
    issued = _token_response(await issue_session(subject))
    await log_audit_event("mfa_verified", "SUCCESS", actor=subject)
    _set_auth_cookies(response, issued.access_token, issued.refresh_token or "")
    return issued


@router.post("/mfa/resend", status_code=status.HTTP_202_ACCEPTED)
async def mfa_resend(payload: MfaResendRequest, request: Request) -> dict:
    validate_origin(request, cookie_auth=has_auth_cookies(request))
    try:
        sent = await resend_code(payload.challenge_id)
    except MfaError as exc:
        raise HTTPException(status_code=_MFA_STATUS.get(exc.reason, 401),
                            detail=f"Cannot resend: {exc.reason}") from exc
    return {"email_sent": sent}


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesResponse)
async def mfa_recovery_codes(current_user: dict = Depends(require_auth)) -> RecoveryCodesResponse:
    """Generate new one-time recovery codes for the current admin (shown once)."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Recovery codes are for admin accounts")
    codes = await new_recovery_codes(current_user["sub"])
    await log_audit_event("mfa_recovery_regenerated", "SUCCESS", actor=current_user["sub"])
    return RecoveryCodesResponse(codes=codes)


# --------------------------------------------------------------------------- #
# POST /auth/register  — alta self-service (solo dominios USB)
# --------------------------------------------------------------------------- #


def _token_response(tokens: tuple[str, str, str]) -> TokenResponse:
    access, refresh, role = tokens
    return TokenResponse(
        access_token=access,
        token_type="bearer",  # nosec B106 -- RFC 6750 literal
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        role=role,
        refresh_token=refresh,
        refresh_expires_in=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, request: Request, response: Response) -> TokenResponse:
    """Crea una cuenta de estudiante. Solo correos institucionales USB.

    Rol siempre ``student`` — el alta self-service nunca crea admins.
    Devuelve el token para iniciar sesión de una vez.
    """
    validate_origin(request, cookie_auth=has_auth_cookies(request))
    await check_rate_limit(
        f"rl:register:{get_client_ip(request)}", limit=5, window_seconds=3600, fail_closed=True
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
        await hash_password_async(payload.password),
    )
    if result.strip().endswith("0 0"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ese correo ya tiene una cuenta. Iniciá sesión.",
        )

    logger.info("user_registered", username=email, role="student")
    issued = _token_response(await issue_session(email))
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
    body_token = body.refresh_token if body else None
    raw_token = body_token or request.cookies.get(REFRESH_TOKEN_COOKIE)
    validate_origin(request, cookie_auth=bool(raw_token and not body_token))
    if not raw_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(raw_token, expected_type="refresh")
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail="Refresh token inválido o vencido",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    issued = _token_response(await rotate_session(payload))
    _set_auth_cookies(response, issued.access_token, issued.refresh_token or "")
    return issued


@router.get("/me", response_model=UserInfo)
async def get_current_user_info(
    current_user: dict = Depends(require_auth),
) -> UserInfo:
    """Retorna info del usuario autenticado."""
    return UserInfo(
        username=current_user.get("sub", ""),
        role=current_user.get("role", "viewer"),
        permissions=list(current_user.get("permissions") or []),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, body: RefreshRequest | None = None) -> None:
    """Revoke the server session and clear cookies, including extension logout."""
    authorization = request.headers.get("authorization", "")
    bearer = authorization[7:] if authorization.lower().startswith("bearer ") else None
    body_token = body.refresh_token if body else None
    explicit_token = bearer or body_token
    validate_origin(request, cookie_auth=has_auth_cookies(request) and not explicit_token)
    tokens = (
        [explicit_token]
        if explicit_token
        else [
            request.cookies.get(ACCESS_TOKEN_COOKIE),
            request.cookies.get(REFRESH_TOKEN_COOKIE),
        ]
    )
    for token in tokens:
        if not token:
            continue
        try:
            payload = decode_token(token)
        except AuthenticationError:
            continue
        await revoke_session(payload)
    _clear_auth_cookies(response)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


async def _authenticate_user(username: str, password: str) -> UserInfo | None:
    """Valida credenciales contra la tabla users de PostgreSQL."""
    from core.security import verify_password_async
    from models.database import fetchrow

    row = await fetchrow(
        "SELECT email, password_hash, role, is_active FROM users WHERE email = $1",
        username,
    )
    if row is None or not row["is_active"]:
        return None
    if not await verify_password_async(password, row["password_hash"]):
        return None
    return UserInfo(username=row["email"], role=row["role"])
