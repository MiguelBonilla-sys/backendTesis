"""FastAPI dependency for JWT bearer-token authentication."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth.jwt import decode_token
from core.exceptions import AuthenticationError

security = HTTPBearer()


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """FastAPI dependency that validates the Bearer JWT token.

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
    try:
        return decode_token(credentials.credentials)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
