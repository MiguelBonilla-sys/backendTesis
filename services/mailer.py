"""Outbound email through the Resend HTTP API (no SDK)."""

from __future__ import annotations

import httpx

from core.config import settings
from core.logger import get_logger

logger = get_logger(__name__)


def _header_safe(value: str) -> str:
    """Strip CR/LF so user-derived text can never inject extra mail headers."""
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())[:200]


async def send_email(to: list[str], subject: str, text: str, html: str, *, kind: str) -> bool:
    """Send one message. Returns True when Resend accepted it (or in dry-run)."""
    recipients = sorted({r.strip() for r in to if r and "@" in r and "\n" not in r})
    if not recipients:
        logger.warning("mail_no_recipients", kind=kind)
        return False
    subject = _header_safe(subject)
    if settings.MAIL_DRY_RUN:
        logger.info("mail_dry_run", kind=kind, recipients=len(recipients), subject=subject)
        return True
    if not settings.RESEND_API_KEY or not settings.MAIL_FROM:
        logger.warning("mail_not_configured", kind=kind)
        return False
    payload = {
        "from": settings.MAIL_FROM, "to": recipients, "subject": subject,
        "text": text, "html": html,
    }
    try:
        async with httpx.AsyncClient(timeout=settings.MAIL_TIMEOUT_S) as client:
            response = await client.post(
                settings.RESEND_API_URL, json=payload,
                headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
            )
    except httpx.HTTPError as exc:
        logger.warning("mail_send_failed", kind=kind, error_type=type(exc).__name__)
        return False
    if response.status_code >= 300:
        logger.warning("mail_rejected", kind=kind, status=response.status_code)
        return False
    logger.info("mail_sent", kind=kind, recipients=len(recipients))
    return True
