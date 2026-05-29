"""Persistence helpers — fire-and-forget async writes to PostgreSQL."""
from __future__ import annotations

import json
from datetime import datetime

from core.logger import get_logger
from schemas.analyze import AnalyzeEmailRequest, AnalyzeRequest, AnalyzeResponse, BatchAnalyzeRequest
from utils.url_parser import extract_domain

logger = get_logger(__name__)


async def _persist_incident(
    response: AnalyzeResponse,
    body: AnalyzeRequest,
) -> None:
    """Inserta el incidente en PostgreSQL de forma asíncrona."""
    try:
        from models.database import execute
        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict,
                s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions,
                email_subject, email_from, email_to, all_urls, reasons,
                created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11,
                $12, $13, $14, $15, $16,
                $17
            ) ON CONFLICT (id) DO NOTHING
            """,
            response.request_id,
            body.email_hash or "",
            response.url,
            response.domain,
            response.verdict,
            response.s_risk,
            response.agent_scores.s_idn,
            response.agent_scores.s_llm,
            response.agent_scores.s_ti,
            response.llm_reason,
            json.dumps(response.shap_explanation.feature_contributions),
            body.email_subject or "",
            body.email_from or "",
            body.email_to or "",
            json.dumps(body.all_urls),
            json.dumps(response.reasons),
            response.timestamp,
        )
        logger.info("incident_persisted", request_id=response.request_id)
    except Exception as exc:
        logger.error(
            "persist_incident_failed",
            request_id=response.request_id,
            error=str(exc),
        )


async def _persist_email_incident(
    response: AnalyzeResponse,
    body: AnalyzeEmailRequest,
) -> None:
    """Persiste un incidente de análisis de email completo en PostgreSQL (fire-and-forget)."""
    try:
        from models.database import execute
        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict,
                s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions,
                email_subject, email_from, email_to, all_urls, reasons,
                email_body_html, email_images, email_attachments,
                created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11,
                $12, $13, $14, $15, $16,
                $17, $18, $19,
                $20
            ) ON CONFLICT (id) DO NOTHING
            """,
            response.request_id,
            body.email_hash or "",
            response.url,
            response.domain,
            response.verdict,
            response.s_risk,
            response.agent_scores.s_idn,
            response.agent_scores.s_llm,
            response.agent_scores.s_ti,
            response.llm_reason,
            json.dumps(response.shap_explanation.feature_contributions),
            body.email_subject or "",
            body.email_from or "",
            body.email_to or "",
            json.dumps(body.all_urls),
            json.dumps(response.reasons),
            body.email_body_html[:200_000] if body.email_body_html else "",
            json.dumps(body.images),
            json.dumps(body.attachments),
            response.timestamp,
        )
        logger.info("email_incident_persisted", request_id=response.request_id)
    except Exception as exc:
        logger.error("persist_email_incident_failed", request_id=response.request_id, error=str(exc))


async def _persist_batch_incident(
    response: AnalyzeResponse,
    body: BatchAnalyzeRequest,
) -> None:
    """Persiste un incidente de batch en PostgreSQL (fire-and-forget)."""
    try:
        from models.database import execute
        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict,
                s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions,
                email_subject, email_from, email_to, all_urls, reasons,
                created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11,
                $12, $13, $14, $15, $16,
                $17
            ) ON CONFLICT (id) DO NOTHING
            """,
            response.request_id,
            body.email_hash or "",
            response.url,
            response.domain,
            response.verdict,
            response.s_risk,
            response.agent_scores.s_idn,
            response.agent_scores.s_llm,
            response.agent_scores.s_ti,
            response.llm_reason,
            json.dumps(response.shap_explanation.feature_contributions),
            body.email_subject or "",
            body.email_from or "",
            body.email_to or "",
            json.dumps(body.urls),
            json.dumps(response.reasons),
            response.timestamp,
        )
    except Exception as exc:
        logger.error("persist_batch_incident_failed", request_id=response.request_id, error=str(exc))


async def _persist_manual_report(
    report_id: str,
    url: str,
    verdict: str,
    reporter: str,
    note: str,
    timestamp: datetime,
) -> None:
    """Guarda reporte manual en incidents table."""
    try:
        domain = extract_domain(url) if url.startswith("http") else url
        from models.database import execute
        await execute(
            """
            INSERT INTO incidents (
                id, email_hash, url, domain, verdict,
                s_risk, s_idn, s_llm, s_ti,
                llm_reason, shap_contributions, analyzed_by, created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13
            ) ON CONFLICT (id) DO NOTHING
            """,
            report_id,
            "",
            url,
            domain,
            verdict,
            1.0 if verdict == "PHISHING" else 0.5,
            0.0,
            0.0,
            0.0,
            f"Manual report: {note}" if note else "Manual report",
            json.dumps({}),
            reporter,
            timestamp,
        )
        logger.info("manual_report_persisted", report_id=report_id)
    except Exception as exc:
        logger.error("persist_manual_report_failed", report_id=report_id, error=str(exc))
