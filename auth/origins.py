"""Origin protection for browser requests carrying ambient auth cookies."""

from fastapi import HTTPException, Request

from core.config import settings
from core.constants import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE


def validate_origin(request: Request, *, cookie_auth: bool = False) -> None:
    """Reject unlisted origins and cookie writes without a verifiable origin.

    Clients explicitly supplying Bearer/body tokens may omit Origin. Browsers
    using cookies must supply an exact configured Origin on unsafe requests.
    """
    origin = request.headers.get("origin")
    if origin is not None:
        if origin not in settings.CORS_ORIGINS:
            raise HTTPException(status_code=403, detail="Origin not allowed")
        return
    if cookie_auth or request.headers.get("sec-fetch-site"):
        raise HTTPException(status_code=403, detail="Origin required for cookie authentication")


def has_auth_cookies(request: Request) -> bool:
    return bool(
        request.cookies.get(ACCESS_TOKEN_COOKIE) or request.cookies.get(REFRESH_TOKEN_COOKIE)
    )
