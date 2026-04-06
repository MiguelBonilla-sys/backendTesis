"""Global error handling middleware — never leaks internal details."""

import uuid

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from core.exceptions import (
    AuthError,
    BackendTesisError,
    ChromaDBError,
    IDNAnalysisError,
    InvalidURLError,
    LLMInferenceError,
    TIFetchError,
)
from core.logger import logger

_STATUS_MAP: dict[type, int] = {
    InvalidURLError: status.HTTP_422_UNPROCESSABLE_ENTITY,
    AuthError: status.HTTP_401_UNAUTHORIZED,
    IDNAnalysisError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    LLMInferenceError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    TIFetchError: status.HTTP_502_BAD_GATEWAY,
    ChromaDBError: status.HTTP_502_BAD_GATEWAY,
    BackendTesisError: status.HTTP_500_INTERNAL_SERVER_ERROR,
}


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except BackendTesisError as exc:
            trace_id = str(uuid.uuid4())
            http_status = _STATUS_MAP.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)
            logger.error(f"[{trace_id}] {type(exc).__name__}: {exc}", exc_info=True)
            return JSONResponse(
                status_code=http_status,
                content={
                    "error": type(exc).__name__,
                    "detail": str(exc),
                    "trace_id": trace_id,
                },
            )
        except Exception as exc:
            trace_id = str(uuid.uuid4())
            logger.error(f"[{trace_id}] Unhandled exception: {exc}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "internal_error",
                    "detail": "An unexpected error occurred.",
                    "trace_id": trace_id,
                },
            )
