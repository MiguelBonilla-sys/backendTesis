"""
LLM Agent — análisis semántico con LlamaStack + RAG dual desde ChromaDB.
Modelo: Llama-3.1-8B-Instruct-GGUF (local via LlamaStack)
RAG: email_embeddings (top-3) + idn_patterns (top-3) → prompt injection
"""
from __future__ import annotations

import asyncio
import re
import time

import httpx

from core.config import settings
from core.constants import (
    COLLECTION_EMAIL,
    COLLECTION_IDN,
    LLM_FALLBACK_SCORE,
    LLM_TIMEOUT_S,
    RAG_TOP_K,
)
from core.exceptions import LLMTimeoutError
from core.logger import get_logger

logger = get_logger(__name__)


class LLMAgent:
    """
    Stateless LLM Agent para análisis semántico de URLs/email content.

    Realiza dual RAG retrieval desde ChromaDB antes de inferencia LlamaStack.
    El agente es stateless por request — ``analyze()`` puede invocarse
    concurrentemente sin riesgo de condición de carrera.

    Lifecycle
    ---------
    Llamar a ``initialize()`` una sola vez durante el lifespan de FastAPI
    antes de servir requests.
    """

    def __init__(self) -> None:
        self._ready: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Inicializa la conexión a LlamaStack y verifica disponibilidad.
        Llamar durante el lifespan de FastAPI.
        """
        self._ready = True
        logger.info(
            "llm_agent_initialized",
            model=settings.LLAMASTACK_MODEL,
            llamastack_url=settings.LLAMASTACK_URL,
        )

    # ------------------------------------------------------------------
    # Main analysis entry point
    # ------------------------------------------------------------------

    async def analyze(
        self,
        url: str,
        domain: str,
        email_body_snippet: str | None = None,
        idn_result_summary: str | None = None,
    ) -> tuple[float, str]:
        """
        Analiza URL/contenido semántico y retorna ``(s_llm, reason)``.

        Proceso
        -------
        1. RAG retrieval concurrente: email_embeddings + idn_patterns (top-3 c/u)
        2. Construir prompt con contexto RAG inyectado
        3. Inferencia LlamaStack con timeout (``LLM_TIMEOUT_S``)
        4. Parsear SCORE del response via regex
        5. Fallback ``s_llm = LLM_FALLBACK_SCORE`` si timeout o error

        Parameters
        ----------
        url:
            URL completa a analizar.
        domain:
            Hostname extraído del URL.
        email_body_snippet:
            Fragmento del cuerpo del email (hasta 500 chars usados en el prompt).
        idn_result_summary:
            Resumen textual del resultado del IDN Agent para contexto adicional.

        Returns
        -------
        tuple[float, str]
            ``(score, reason)`` donde score ∈ [0.0, 1.0] y reason es la
            explicación textual extraída del response LLM.
        """
        t0 = time.perf_counter()

        try:
            # --- 1. RAG retrieval concurrente ----------------------------------
            query_text = (
                f"URL: {url}\nDomain: {domain}\n{email_body_snippet or ''}"
            )
            rag_context = await self._retrieve_rag_context(query_text)

            # --- 2. Construir prompt -------------------------------------------
            prompt = self._build_prompt(
                url=url,
                domain=domain,
                email_body=email_body_snippet,
                rag_context=rag_context,
                idn_summary=idn_result_summary,
            )

            # --- 3. Inferencia con timeout ------------------------------------
            try:
                response_text = await asyncio.wait_for(
                    self._call_llamastack(prompt),
                    timeout=LLM_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "llm_timeout",
                    url=url,
                    timeout_s=LLM_TIMEOUT_S,
                )
                raise LLMTimeoutError(
                    message=f"LLM timeout after {LLM_TIMEOUT_S}s",
                    detail=f"url={url}",
                )

            # --- 4. Parsear score y razón -------------------------------------
            score = self._parse_score(response_text)
            reason = self._parse_reason(response_text)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info(
                "llm_analysis_complete",
                url=url,
                score=score,
                rag_chunks=len(rag_context),
                elapsed_ms=round(elapsed_ms, 1),
            )

            return score, reason

        except LLMTimeoutError:
            return LLM_FALLBACK_SCORE, "LLM analysis timed out — fallback score applied"

        except Exception as exc:
            logger.error("llm_analysis_error", url=url, error=str(exc))
            return LLM_FALLBACK_SCORE, f"LLM error: {str(exc)[:100]}"

    # ------------------------------------------------------------------
    # RAG retrieval
    # ------------------------------------------------------------------

    async def _retrieve_rag_context(self, query: str) -> list[str]:
        """
        Dual RAG retrieval concurrente desde ChromaDB:

        - ``email_embeddings``: top-3 correos phishing similares históricos
        - ``idn_patterns``: top-3 patrones de ataque IDN conocidos

        Retorna lista de hasta 6 chunks de texto listos para inyectar en el
        prompt.  Si ChromaDB no está disponible devuelve lista vacía sin
        propagar el error (degraded gracefully).
        """
        try:
            from models.chromadb_client import query_collection

            email_task = query_collection(
                COLLECTION_EMAIL, [query], n_results=RAG_TOP_K
            )
            idn_task = query_collection(
                COLLECTION_IDN, [query], n_results=RAG_TOP_K
            )

            email_results, idn_results = await asyncio.gather(
                email_task,
                idn_task,
                return_exceptions=True,
            )

            chunks: list[str] = []

            if isinstance(email_results, list):
                for r in email_results:
                    if isinstance(r, dict) and r.get("document"):
                        chunks.append(f"[Past phishing pattern] {r['document']}")

            if isinstance(idn_results, list):
                for r in idn_results:
                    if isinstance(r, dict) and r.get("document"):
                        chunks.append(f"[IDN attack pattern] {r['document']}")

            return chunks[:6]  # máximo 6 chunks (3 + 3)

        except Exception as exc:
            logger.warning("rag_retrieval_failed", error=str(exc))
            return []

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        url: str,
        domain: str,
        email_body: str | None,
        rag_context: list[str],
        idn_summary: str | None,
    ) -> str:
        """
        Construye el prompt para LlamaStack con contexto RAG inyectado.

        Formato de respuesta esperado:
            ``SCORE: <float> | REASON: <text>``
        """
        context_block = (
            "\n".join(rag_context) if rag_context else "No similar patterns found."
        )

        idn_line = f"IDN Analysis: {idn_summary}" if idn_summary else ""
        email_line = (
            f"Email content snippet: {email_body[:500]}" if email_body else ""
        )

        extra_lines = "\n".join(
            line for line in [idn_line, email_line] if line
        )

        prompt = f"""You are a cybersecurity expert specializing in IDN homograph phishing detection.

## Relevant patterns from knowledge base:
{context_block}

## Analysis target:
URL: {url}
Domain: {domain}
{extra_lines}

## Task:
Analyze if this URL/domain is a phishing attempt. Consider:
1. Visual similarity to legitimate domains (homograph/IDN attacks using Cyrillic, Greek, or other confusable scripts)
2. Suspicious URL patterns, unusual TLDs, or deceptive subdomains
3. Context from email content if provided
4. Patterns matching known phishing campaigns from the knowledge base

Respond ONLY in this exact format (one line):
SCORE: <float between 0.0 and 1.0> | REASON: <concise explanation in 1-2 sentences>

Where SCORE=1.0 means definitely phishing, SCORE=0.0 means definitely legitimate."""

        return prompt

    # ------------------------------------------------------------------
    # LlamaStack HTTP call
    # ------------------------------------------------------------------

    async def _call_llamastack(self, prompt: str) -> str:
        """
        Invoca la API de LlamaStack para chat completion.

        Endpoint: ``POST {LLAMASTACK_URL}/v1/inference/chat_completion``

        El timeout del cliente HTTP es ligeramente mayor que ``LLM_TIMEOUT_S``
        para permitir que ``asyncio.wait_for`` cancele primero y se genere el
        log correcto antes del cierre de la conexión.

        Returns
        -------
        str
            Texto del completion extraído del campo
            ``completion_message.content``.
        """
        payload: dict = {
            "model_id": settings.LLAMASTACK_MODEL,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "sampling_params": {
                "strategy": {"type": "greedy"},
                "max_tokens": 150,
            },
        }

        async with httpx.AsyncClient(timeout=LLM_TIMEOUT_S + 2.0) as client:
            resp = await client.post(
                f"{settings.LLAMASTACK_URL}/v1/inference/chat_completion",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data: dict = resp.json()

        # LlamaStack response: {"completion_message": {"role": "...", "content": "..."}}
        content: str = (
            data.get("completion_message", {}).get("content", "")
            or str(data)
        )
        return content

    # ------------------------------------------------------------------
    # Response parsers
    # ------------------------------------------------------------------

    def _parse_score(self, text: str) -> float:
        """
        Extrae el SCORE del response LLM usando regex.

        Pattern: ``re.search(r"SCORE:\\s*([\\d.]+)", text)``

        Retorna ``LLM_FALLBACK_SCORE`` si el pattern no coincide o el valor
        no es un float válido.  El score se satura al rango [0.0, 1.0].
        """
        match = re.search(r"SCORE:\s*([\d.]+)", text)
        if match:
            try:
                score = float(match.group(1))
                return min(max(score, 0.0), 1.0)
            except ValueError:
                pass
        logger.warning("llm_score_parse_failed", raw_text=text[:200])
        return LLM_FALLBACK_SCORE

    def _parse_reason(self, text: str) -> str:
        """
        Extrae el REASON del response LLM.

        Busca ``REASON: <text>`` después del pipe separator.
        Si no encuentra el patrón devuelve el texto completo truncado a 500 chars.
        """
        match = re.search(
            r"REASON:\s*(.+?)(?:\n|$)", text, re.IGNORECASE | re.DOTALL
        )
        if match:
            return match.group(1).strip()[:500]
        return text.strip()[:200] if text else "No reason provided"


# ---------------------------------------------------------------------------
# Application singleton — importar y usar en FastAPI lifespan
# ---------------------------------------------------------------------------

llm_agent = LLMAgent()
