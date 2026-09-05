"""
LLM Gateway — punto único de inferencia generativa del backend.

Habla el protocolo OpenAI-compatible (``POST {base}/chat/completions``) contra
un proveedor remoto configurable (por defecto OpenCode Go / DeepSeek V4 Flash).
Reemplaza la llamada directa a Ollama/LlamaStack: el backend ya no depende de un
modelo instalado localmente.

El colapso a score neutral (``LLM_FALLBACK_SCORE``) lo maneja el caller
(``agents/llm_agent.py``) — acá solo se propagan los errores HTTP.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from core.config import settings
from core.logger import get_logger

logger = get_logger(__name__)

# Errores que justifican un reintento con el mismo modelo (transitorios).
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
# Errores que sugieren "modelo inválido/retirado" → reintento con el fallback.
_MODEL_STATUS = frozenset({400, 404})


@dataclass(frozen=True)
class LLMResult:
    """Resultado de una completion. ``model``/``provider`` se persisten en la
    traza para reproducibilidad cuando el modelo experimental cambie.
    ``reasoning`` trae el ``reasoning_content`` del modelo cuando está presente
    (DeepSeek V4 es un reasoning model) — material para la traza XAI."""

    text: str
    model: str
    provider: str
    latency_ms: float
    reasoning: str = ""


class LLMGateway:
    """Cliente OpenAI-compatible con un ``httpx.AsyncClient`` compartido.

    Stateless respecto al contenido: ``chat()`` es seguro para llamadas
    concurrentes. Llamar ``initialize()`` una vez en el lifespan de FastAPI
    y ``aclose()`` en shutdown.
    """

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if settings.LLM_API_KEY:
            headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"
        return headers

    async def initialize(self) -> None:
        """Crea el client compartido y verifica el endpoint (best-effort)."""
        if not settings.LLM_API_KEY:
            logger.warning(
                "llm_gateway_no_api_key",
                detail=(
                    "LLM_API_KEY vacío — el proveedor devolverá 401 y el pipeline "
                    "degradará s_llm a neutral (0.5). Configurá la key en .env."
                ),
                base_url=settings.LLM_BASE_URL,
            )
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=settings.LLM_BASE_URL)
        try:
            resp = await self._client.get(
                "/models", headers=self._headers(), timeout=10.0
            )
            resp.raise_for_status()
            logger.info(
                "llm_gateway_initialized",
                base_url=settings.LLM_BASE_URL,
                model=settings.LLM_MODEL,
                provider=settings.LLM_PROVIDER,
            )
        except Exception as exc:  # el backend arranca igual — se degradará a 0.5
            logger.warning("llm_gateway_healthcheck_failed", error=str(exc))

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[dict],
        *,
        model: str | None = None,
        max_tokens: int = 150,
        temperature: float = 0.0,
        timeout: float = 20.0,
        thinking: bool = False,
    ) -> LLMResult:
        """Envía una completion y devuelve ``LLMResult``.

        ``thinking=False`` (default) manda ``{"thinking": {"type": "disabled"}}``:
        DeepSeek V4 es un reasoning model y sin esto consume el presupuesto de
        tokens en ``reasoning_content`` y trunca la respuesta. Verificado contra
        OpenCode Go — el proxy pasa el campo.

        Reintenta una vez ante 429/5xx (transitorio) y una vez con
        ``LLM_MODEL_FALLBACK`` ante 400/404 (modelo inválido). Propaga el
        error si ambos fallan.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=settings.LLM_BASE_URL)

        primary = model or settings.LLM_MODEL
        t0 = time.perf_counter()

        for candidate in (primary, settings.LLM_MODEL_FALLBACK):
            try:
                text, reasoning = await self._post_once(
                    candidate, messages, max_tokens, temperature, timeout, thinking
                )
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in _MODEL_STATUS and candidate != settings.LLM_MODEL_FALLBACK:
                    logger.warning(
                        "llm_gateway_model_fallback", model=candidate, status=status
                    )
                    continue
                raise

            latency_ms = (time.perf_counter() - t0) * 1000
            logger.info(
                "llm_gateway_completion",
                model=candidate,
                latency_ms=round(latency_ms, 1),
            )
            return LLMResult(
                text=text,
                model=candidate,
                provider=settings.LLM_PROVIDER,
                latency_ms=latency_ms,
                reasoning=reasoning,
            )

        raise RuntimeError(  # pragma: no cover — el loop siempre retorna o relanza
            "llm_gateway: primary and fallback models both failed"
        )

    async def _post_once(
        self,
        model: str,
        messages: list[dict],
        max_tokens: int,
        temperature: float,
        timeout: float,
        thinking: bool,
    ) -> tuple[str, str]:
        """Un POST con un reintento ante error transitorio (429/5xx).
        Devuelve ``(content, reasoning_content)``."""
        assert self._client is not None
        payload: dict = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if not thinking:
            payload["thinking"] = {"type": "disabled"}

        last_exc: httpx.HTTPStatusError | None = None
        for attempt in (1, 2):
            try:
                resp = await self._client.post(
                    "/chat/completions",
                    json=payload,
                    headers=self._headers(),
                    timeout=timeout,
                )
                resp.raise_for_status()
                data: dict = resp.json()
                message = data.get("choices", [{}])[0].get("message", {})
                reasoning = message.get("reasoning_content", "") or ""
                # Si el budget se agotó en el reasoning (finish_reason=length),
                # content queda vacío → devolver el reasoning como texto útil,
                # nunca el dict crudo.
                content = message.get("content", "") or reasoning or ""
                return content, reasoning
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if exc.response.status_code not in _RETRY_STATUS or attempt == 2:
                    raise
                await asyncio.sleep(0.5 * attempt)

        raise last_exc  # pragma: no cover — el for siempre retorna o relanza antes


# ---------------------------------------------------------------------------
# Application singleton
# ---------------------------------------------------------------------------

llm_gateway = LLMGateway()
