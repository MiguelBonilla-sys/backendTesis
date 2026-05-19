"""Structured logging configuration using structlog with JSON output."""

import logging
import sys

import structlog
from structlog.stdlib import add_log_level
from structlog.processors import TimeStamper, JSONRenderer


def _configure_structlog(log_level: str = "INFO") -> None:
    """Configure structlog and the stdlib root logger once at startup."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            add_log_level,
            TimeStamper(fmt="iso"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


# Configure once on module import — respects LOG_LEVEL from config if already
# loaded; falls back to INFO when config is not yet available (e.g. during tests).
try:
    from core.config import settings as _settings  # noqa: PLC0415

    _configure_structlog(_settings.LOG_LEVEL)
except Exception:  # pragma: no cover — config unavailable during early import
    _configure_structlog("INFO")

# Module-level default logger
logger: structlog.stdlib.BoundLogger = structlog.get_logger()


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger bound with the calling module's name."""
    return structlog.get_logger().bind(module=name)
