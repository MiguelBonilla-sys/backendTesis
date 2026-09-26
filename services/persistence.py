"""Awaited incident writes: an acknowledged analysis must have durable evidence."""
from __future__ import annotations

import json
from datetime import datetime

from core.config import settings
from core.exceptions import DatabaseError
from core.logger import get_logger
from schemas.analyze import (
    AnalyzeEmailRequest,
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
)
from utils.email_parser import ParsedEmail
from utils.url_parser import extract_domain

logger = get_logger(__name__)


async def _save_analysis(
    response: AnalyzeResponse, *, email_hash: str, subject: str, sender: str,
    recipient: str, urls: list[str], content: tuple[str, list[str], list[str]] | None = None,
) -> None:
    from models.database import execute

    columns = (
        "id, email_hash, url, domain, verdict, s_risk, s_idn, s_llm, s_ti, "
        "llm_reason, shap_contributions, email_subject, email_from, email_to, all_urls, reasons"
    )
    values: list[object] = [
        response.request_id, email_hash, response.url, response.domain, response.verdict,
        response.s_risk, response.agent_scores.s_idn, response.agent_scores.s_llm,
        response.agent_scores.s_ti, response.llm_reason,
        json.dumps(response.shap_explanation.feature_contributions), subject, sender, recipient,
        json.dumps(urls), json.dumps(response.reasons),
    ]
    if content is not None:
        columns += ", email_body_html, email_images, email_attachments"
        html, images, attachments = content
        values.extend([html, json.dumps(images), json.dumps(attachments)])
    columns += ", created_at, agent_status"
    values.extend([
        response.timestamp,
        json.dumps({name: signal.model_dump(mode="json")
                    for name, signal in response.agent_status.items()}),
    ])
    placeholders = ", ".join(f"${n}" for n in range(1, len(values) + 1))
    try:
        await execute(
            f"INSERT INTO incidents ({columns}) VALUES ({placeholders}) "
            "ON CONFLICT (id) DO NOTHING", *values,
        )
    except Exception as exc:
        logger.error("incident_persistence_failed", request_id=response.request_id,
                     error_type=type(exc).__name__)
        raise DatabaseError("Unable to save the analysis") from exc
    logger.info("incident_persisted", request_id=response.request_id)


async def _persist_incident(response: AnalyzeResponse, body: AnalyzeRequest) -> None:
    await _save_analysis(
        response, email_hash=body.email_hash or "", subject=body.email_subject or "",
        sender=body.email_from or "", recipient=body.email_to or "", urls=body.all_urls,
    )


async def _persist_email_incident(response: AnalyzeResponse, body: AnalyzeEmailRequest) -> None:
    # Full content retention is explicit. Operational metadata still contains
    # personal data; a message hash does not anonymize sender/subject fields.
    keep_content = settings.STORE_EMAIL_CONTENT
    await _save_analysis(
        response, email_hash=body.email_hash or "", subject=body.email_subject or "",
        sender=body.email_from or "", recipient=body.email_to or "", urls=body.all_urls,
        content=(body.email_body_html[:200_000] if keep_content else "",
                 body.images if keep_content else [], body.attachments if keep_content else []),
    )


async def _persist_eml_incident(
    response: AnalyzeResponse, parsed: ParsedEmail, all_urls: list[str],
) -> None:
    await _save_analysis(
        response, email_hash=parsed.email_hash, subject=parsed.subject, sender=parsed.sender,
        recipient="", urls=all_urls,
    )


async def _persist_batch_incident(response: AnalyzeResponse, body: BatchAnalyzeRequest) -> None:
    await _save_analysis(
        response, email_hash=body.email_hash or "", subject=body.email_subject or "",
        sender=body.email_from or "", recipient=body.email_to or "", urls=body.urls,
    )


async def _persist_manual_report(
    report_id: str, url: str, verdict: str, reporter: str, note: str, timestamp: datetime,
) -> None:
    from models.database import execute

    domain = extract_domain(url) if url.startswith("http") else url
    try:
        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict, s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions, analyzed_by, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (id) DO NOTHING
            """,
            report_id, "", url, domain, verdict, 1.0 if verdict == "PHISHING" else 0.5,
            0.0, 0.0, 0.0, f"Manual report: {note}" if note else "Manual report",
            json.dumps({}), reporter, timestamp,
        )
    except Exception as exc:
        logger.error("manual_report_persistence_failed", report_id=report_id,
                     error_type=type(exc).__name__)
        raise DatabaseError("Unable to save the report") from exc
    logger.info("manual_report_persisted", report_id=report_id)
