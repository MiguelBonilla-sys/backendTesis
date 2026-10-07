"""Early-warning email to security admins when an analysis ends in PHISHING.

Runs as background work after the incident is persisted; a failure here never
changes the analysis response. Redis bounds the volume: one alert per domain per
``ALERT_DEDUPE_SECONDS`` and at most ``ALERT_DAILY_CAP`` per UTC day (Resend free
plan: 100 emails/day shared with OTP codes). If Redis is unavailable no alert is
sent, so a storm cannot exhaust the quota unnoticed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape

from core.config import settings
from core.logger import get_logger
from services.mailer import send_email

logger = get_logger(__name__)

_RECIPIENTS_SQL = """
SELECT u.email FROM users u LEFT JOIN roles r ON r.id = u.role_id
WHERE u.is_active AND (
    (u.role_id IS NOT NULL AND r.permissions ? 'alerts:receive')
    OR (u.role_id IS NULL AND u.role = 'admin')
)
"""


@dataclass(frozen=True)
class AlertIncident:
    incident_id: str
    url: str
    domain: str
    verdict: str
    s_risk: float
    reasons: list[str] = field(default_factory=list)
    category: str | None = None
    origin_country: str | None = None
    origin_isp: str | None = None


async def _recipients() -> list[str]:
    from models.database import fetch

    rows = await fetch(_RECIPIENTS_SQL)
    emails = [row["email"] for row in rows]
    if not emails and settings.ALERT_FALLBACK_RECIPIENT:
        emails = [settings.ALERT_FALLBACK_RECIPIENT]
    return emails


_HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62}\b")


def defang(value: str) -> str:
    """Indicador inerte (práctica SOC): ``hxxps://dominio[.]tld``.

    Gmail convierte en enlace cualquier URL o dominio del texto, incluso en el
    HTML sin ``<a>``, y el filtro antispam trata la alerta como el phishing que
    describe. Neutralizado, el admin no puede abrir el sitio por error.
    """
    value = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", value)
    return _HOST_RE.sub(lambda m: m.group(0).replace(".", "[.]"), value)


def render_alert(incident: AlertIncident) -> tuple[str, str, str]:
    """Plain text and escaped HTML; never includes the message body.

    Domain, URL and reasons go defanged: the only clickable link is the dashboard.
    """
    link = f"{settings.DASHBOARD_URL.rstrip('/')}/incidents/{incident.incident_id}"
    lines = [
        f"Veredicto: {incident.verdict} (riesgo {incident.s_risk:.2f})",
        f"Dominio: {defang(incident.domain)}",
        f"Enlace analizado: {defang(incident.url)}",
    ]
    if incident.category:
        lines.append(f"Categoría: {incident.category}")
    if incident.origin_country or incident.origin_isp:
        lines.append(f"Origen: {incident.origin_country or '?'} · {incident.origin_isp or '?'}")
    reasons = [defang(r) for r in incident.reasons[:3]]
    text = "\n".join(
        ["Alerta temprana de phishing", "", *lines, "", "Señales principales:"]
        + [f"- {r}" for r in reasons] + ["", f"Ver el incidente: {link}"]
    )
    html = (
        "<h2>Alerta temprana de phishing</h2><ul>"
        + "".join(f"<li>{escape(line)}</li>" for line in lines)
        + "</ul><p>Señales principales:</p><ul>"
        + "".join(f"<li>{escape(r)}</li>" for r in reasons)
        + f'</ul><p><a href="{escape(link, quote=True)}">Ver el incidente</a></p>'
    )
    subject = f"Alerta temprana: {defang(incident.domain)} · riesgo {incident.s_risk:.2f}"
    return subject, text, html


async def _audit(status: str, incident: AlertIncident, detail: dict) -> None:
    from models.database import log_audit_event

    await log_audit_event(
        event_type="alert_" + status, status="SUCCESS" if status == "sent" else "FAILURE",
        actor="system", resource=f"incident:{incident.incident_id}", detail=detail,
    )


async def _admit(redis, domain: str) -> str:
    """Return 'send', 'duplicate', 'summary' (first over the cap) or 'capped'."""
    if not await redis.set(f"alert:dedupe:{domain}", "1", nx=True,
                           ex=settings.ALERT_DEDUPE_SECONDS):
        await redis.incr("alert:suppressed:duplicate")
        return "duplicate"
    day_key = f"alert:count:{datetime.now(UTC):%Y%m%d}"
    count = await redis.incr(day_key)
    await redis.expire(day_key, 172800)
    if count <= settings.ALERT_DAILY_CAP:
        return "send"
    return "summary" if count == settings.ALERT_DAILY_CAP + 1 else "capped"


async def notify_phishing(incident: AlertIncident) -> bool:
    if not settings.ALERTS_ENABLED or incident.verdict != "PHISHING":
        return False
    from models.redis_client import get_redis

    try:
        decision = await _admit(get_redis(), incident.domain)
    except Exception as exc:
        logger.warning("alert_skipped_no_redis", error_type=type(exc).__name__)
        return False
    if decision in {"duplicate", "capped"}:
        logger.info("alert_suppressed", reason=decision, domain=incident.domain)
        return False
    try:
        recipients = await _recipients()
    except Exception as exc:
        logger.warning("alert_recipients_failed", error_type=type(exc).__name__)
        fallback = settings.ALERT_FALLBACK_RECIPIENT
        recipients = [fallback] if fallback else []
    if decision == "summary":
        subject = "[Phishing] Tope diario de alertas alcanzado"
        text = (f"Se alcanzó el tope de {settings.ALERT_DAILY_CAP} alertas por hoy. "
                f"Las siguientes quedan en el dashboard: {settings.DASHBOARD_URL}")
        html = f"<p>{escape(text)}</p>"
    else:
        subject, text, html = render_alert(incident)
    sent = await send_email(recipients, subject, text, html, kind="alert")
    await _audit("sent" if sent else "failed", incident,
                 {"recipients": len(recipients), "decision": decision})
    return sent
