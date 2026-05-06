"""POST /api/v1/auth/login and POST /api/v1/auth/register endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
except ModuleNotFoundError:
    class Limiter:  # type: ignore[override]
        """Fallback no-op limiter used when slowapi is unavailable."""

        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

        def limit(self, _rule: str):
            def decorator(func):
                return func

            return decorator

    def get_remote_address(_request: Request) -> str:
        return "0.0.0.0"

from auth.auth import create_access_token
from auth.auth_service import create_student_user, get_user_by_email, verify_password
from core.config import settings
from models.database import get_session
from schemas.auth_schemas import LoginRequest, RegisterRequest, TokenResponse

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate with email + password",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Authenticate any role (admin or student). Never reveals which field failed."""
    user = await get_user_by_email(session, body.email)
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )
    access_token = create_access_token(subject=str(user.id), role=user.role)
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user.role,
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new student account (USB institutional email required)",
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    body: RegisterRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Register extension student users only. Domain is validated by RegisterRequest."""
    existing = await get_user_by_email(session, body.email)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    user = await create_student_user(session, body.email, body.password)
    access_token = create_access_token(subject=str(user.id), role=user.role)
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user.role,
    )
