"""FastAPI dependency for JWT bearer-token authentication."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth.jwt import decode_token
from core.constants import ACCESS_TOKEN_COOKIE
from core.exceptions import AuthenticationError

# auto_error=False: la extensión manda Bearer, el dashboard manda cookie httpOnly.
# Sin header no debe cortar acá — se cae al cookie antes de rechazar.
security = HTTPBearer(auto_error=False)


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict:
    """FastAPI dependency that validates the JWT — vía Bearer header o cookie httpOnly.

    Usage::

        @router.get("/protected")
        async def protected_route(payload: dict = Depends(require_auth)):
            username = payload.get("sub")
            ...

    Returns:
        The decoded JWT payload dict on success.

    Raises:
        HTTPException(401): If the token is missing, expired, or invalid.
    """
    token = credentials.credentials if credentials else request.cookies.get(ACCESS_TOKEN_COOKIE)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return decode_token(token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def require_admin(current_user: dict = Depends(require_auth)) -> dict:
    """Dependency que exige rol 'admin'. Usado para endpoints de administración."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return current_user


def require_role(*roles: str):
    """Factory de dependency para roles específicos."""

    async def _check(current_user: dict = Depends(require_auth)) -> dict:
        if current_user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(roles)}",
            )
        return current_user

    return _check
