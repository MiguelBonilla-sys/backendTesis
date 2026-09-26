"""
HuggingFace Agent — phishing classification via HF Inference API.

Specialized classifiers:
  URL:     pirocheto/phishing-url-detection          (PHISHING/LEGITIMATE)
  Content: cybersectony/phishing-email-detection-distilbert_v2.4.1

Graceful degradation: returns HF_FALLBACK_SCORE (0.5) when API key absent
or any call fails — never blocks the main analysis pipeline.
"""
from __future__ import annotations

import asyncio
import math
import time
from threading import Lock

import httpx

from core.agent_signal import SignalScore, telemetry_of
from core.config import settings
from core.constants import HF_FALLBACK_SCORE, HF_TIMEOUT_S
from core.logger import get_logger
from core.redaction import redact
from schemas.analyze import AgentTelemetry

logger = get_logger(__name__)

# HF migró la Inference API a "Inference Providers". El endpoint viejo
# (api-inference.huggingface.co) está muerto. `hf-inference` sirve el modelo de
# email (cybersectony/…, transformers). El de URL (pirocheto/…, sklearn/ONNX) NO
# lo sirve ningún provider → se corre LOCAL vía onnxruntime (ver _url_onnx_score).
_HF_BASE = "https://router.huggingface.co/hf-inference/models"

# Sesión ONNX del clasificador de URL — carga perezosa, una sola vez.
_url_onnx_session = None
_url_onnx_tried = False
_url_onnx_lock = Lock()


def _get_url_onnx():
    """InferenceSession del modelo de URL (pirocheto/…). None si no disponible.

    Path: ``settings.HF_URL_ONNX_PATH`` si está seteado (bundle offline), si no
    se descarga de HF (``model.onnx``, ~22 MB, público) y se cachea.
    """
    global _url_onnx_session, _url_onnx_tried
    # La carga ocurre en un worker; serializarla evita que otra solicitud vea
    # una sesión todavía vacía mientras se descarga el modelo compartido.
    with _url_onnx_lock:
        if _url_onnx_tried:
            return _url_onnx_session
        _url_onnx_tried = True
        try:
            import onnxruntime

            path = settings.HF_URL_ONNX_PATH
            if not path:
                from huggingface_hub import hf_hub_download

                path = hf_hub_download(
                    repo_id=settings.HF_URL_MODEL,
                    filename="model.onnx",
                    revision=settings.HF_URL_MODEL_REVISION or None,
                )
            _url_onnx_session = onnxruntime.InferenceSession(
                path, providers=["CPUExecutionProvider"]
            )
            logger.info("hf_url_onnx_loaded", path=path)
        except Exception as exc:  # noqa: BLE001 — degrada a la API / fallback
            logger.warning("hf_url_onnx_unavailable", error=str(exc))
        return _url_onnx_session


class HFAgent:
    """
    Stateless HuggingFace Inference Agent.

    Calls HF Inference API text-classification endpoints and returns a
    phishing probability s_hf ∈ [0.0, 1.0].

    Pipeline role
    -------------
    Runs concurrently with IDNAgent, ThreatIntelService and WebProbeAgent
    (Stage 1, ``asyncio.gather``).  The resulting ``s_hf`` is passed to
    FusionAgent where it is blended with the Ollama LLM score before fusion::

        s_llm_combined = (1 - HF_WEIGHT) * s_llm + HF_WEIGHT * s_hf
                       = 0.60 * s_llm + 0.40 * s_hf

    SHAP contributions (γ = 0.50)::

        llm_contribution = γ * (1 - HF_WEIGHT) * s_llm  →  0.30 * s_llm
        hf_contribution  = γ * HF_WEIGHT       * s_hf   →  0.20 * s_hf

    No initialization needed — ``analyze()`` is safe to call concurrently.
    """

    async def analyze(
        self,
        url: str,
        email_body_snippet: str | None = None,
    ) -> float:
        """
        Returns blended phishing score from HF classifiers.

        Runs URL and content classifiers concurrently when email body
        is provided; otherwise returns URL-only score.  Falls back to
        HF_FALLBACK_SCORE (0.5) on any error.

        El clasificador de URL corre local (ONNX) y no necesita API key; el de
        contenido usa la Inference API y degrada a 0.5 sin key.
        """
        started = time.perf_counter()
        tasks: list = [self._classify_url(url)]
        if email_body_snippet:
            tasks.append(self._classify_content(email_body_snippet))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        scores: list[float] = []
        components: dict[str, AgentTelemetry] = {}
        for name, r in zip(("hf_url", "hf_content"), results):
            if isinstance(r, float):
                scores.append(r)
                components[name] = telemetry_of(r)
            else:
                logger.warning("hf_classify_exception", error=str(r))
                components[name] = AgentTelemetry(status="error", error="classifier_error")

        if not scores:
            return SignalScore(HF_FALLBACK_SCORE, AgentTelemetry(
                status="error", error="all_classifiers_failed",
                latency_ms=(time.perf_counter() - started) * 1000,
            ), components)

        s_hf = sum(scores) / len(scores)
        logger.info(
            "hf_analysis_complete",
            url=url,
            s_hf=round(s_hf, 4),
            classifiers_used=len(scores),
        )
        statuses = [m.status for m in components.values()]
        status = ("ok" if all(s == "ok" for s in statuses)
                  else statuses[0] if len(set(statuses)) == 1 else "partial")
        meta = AgentTelemetry(
            status=status, model=str(settings.HF_URL_MODEL),
            revision=str(settings.HF_URL_MODEL_REVISION),
            latency_ms=(time.perf_counter() - started) * 1000,
        )
        return SignalScore(float(min(max(s_hf, 0.0), 1.0)), meta, components)

    async def analyze_content_with_status(self, text: str) -> tuple[float, AgentTelemetry]:
        """Content-only classification, with explicit unavailable/timeout state."""
        started = time.perf_counter()
        try:
            value = await self._classify_content(text)
            meta = telemetry_of(value)
        except Exception:
            value = HF_FALLBACK_SCORE
            meta = AgentTelemetry(status="error", error="classifier_error")
        meta = meta.model_copy(update={
            "model": settings.HF_EMAIL_MODEL,
            "latency_ms": (time.perf_counter() - started) * 1000,
        })
        return float(value), meta

    # ------------------------------------------------------------------
    # Internal classifiers
    # ------------------------------------------------------------------

    async def _classify_url(self, url: str) -> float:
        """Score de phishing de la URL. Prioriza el modelo ONNX local; si no
        está disponible cae a la API, dentro de un único presupuesto de tiempo."""
        started = time.perf_counter()
        try:
            async with asyncio.timeout(HF_TIMEOUT_S):
                score = await self._url_onnx_score(url)
                if score is not None:
                    return score
                return await self._call_hf_api(settings.HF_URL_MODEL, url)
        except TimeoutError:
            logger.warning("hf_url_timeout", timeout_s=HF_TIMEOUT_S)
            return SignalScore(HF_FALLBACK_SCORE, AgentTelemetry(
                status="timeout", model=str(settings.HF_URL_MODEL),
                revision=str(settings.HF_URL_MODEL_REVISION),
                latency_ms=(time.perf_counter() - started) * 1000,
            ))

    async def _url_onnx_score(self, url: str) -> float | None:
        """Inferencia ONNX local (LinearSVM). ``None`` si el modelo no cargó o
        la inferencia falla. Salida: ``run(...)[1]`` = ``[[p_legit, p_phish]]``."""
        started = time.perf_counter()
        sess = await asyncio.to_thread(_get_url_onnx)
        if sess is None:
            return None
        try:
            import numpy as np

            probs = await asyncio.to_thread(
                sess.run, None, {"inputs": np.array([url], dtype="str")}
            )
            p_phish = float(probs[1][0][1])
            if not math.isfinite(p_phish):
                raise ValueError("non-finite model output")
            return SignalScore(min(max(p_phish, 0.0), 1.0), AgentTelemetry(
                status="ok", model=str(settings.HF_URL_MODEL),
                revision=str(settings.HF_URL_MODEL_REVISION),
                latency_ms=(time.perf_counter() - started) * 1000,
            ))
        except Exception as exc:  # noqa: BLE001
            logger.warning("hf_url_onnx_infer_failed", error=str(exc))
            return None

    async def _classify_content(self, text: str) -> float:
        if not settings.HUGGINGFACE_API_KEY:
            return SignalScore(HF_FALLBACK_SCORE, AgentTelemetry(
                status="unavailable", model=str(settings.HF_EMAIL_MODEL), error="missing_api_key",
            ))
        return await self._call_hf_api(settings.HF_EMAIL_MODEL, text)

    async def _call_hf_api(self, model: str, text: str) -> float:
        """
        POST to HF Inference API text-classification endpoint.

        Endpoint: ``POST {_HF_BASE}/{model}``
        Auth: ``Authorization: Bearer {HUGGINGFACE_API_KEY}``
        """
        started = time.perf_counter()

        def result(value: float, status: str, error: str | None = None):
            return SignalScore(value, AgentTelemetry(
                status=status, model=str(model), error=error,
                # The hosted endpoint does not attest the pinned ONNX revision.
                revision=None,
                latency_ms=(time.perf_counter() - started) * 1000,
            ))

        headers = {
            "Authorization": f"Bearer {settings.HUGGINGFACE_API_KEY}",
            "Content-Type": "application/json",
        }
        # Redactar en la frontera HTTP cubre contenido y fallback de URL.
        # Se hace antes de truncar para no dejar fragmentos de un identificador.
        outbound = redact(text) if settings.LLM_REDACT_PROMPT else text
        if model == settings.HF_EMAIL_MODEL:
            outbound = outbound[:512]
        payload = {"inputs": outbound}

        try:
            async with httpx.AsyncClient(timeout=HF_TIMEOUT_S) as client:
                resp = await client.post(
                    f"{_HF_BASE}/{model}",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            logger.warning("hf_timeout", model=model)
            return result(HF_FALLBACK_SCORE, "timeout")
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "hf_http_error",
                model=model,
                status=exc.response.status_code,
            )
            return result(HF_FALLBACK_SCORE, "unavailable", f"http_{exc.response.status_code}")
        except Exception as exc:
            logger.warning("hf_call_failed", model=model, error=str(exc))
            return result(HF_FALLBACK_SCORE, "error", "provider_error")

        value = self._extract_phishing_score(data)
        meta = telemetry_of(value)
        return result(float(value), meta.status, meta.error)

    # ------------------------------------------------------------------
    # Score extraction
    # ------------------------------------------------------------------

    def _extract_phishing_score(self, data: object) -> float:
        """
        Extracts phishing probability from HF text-classification response.

        Handles both response shapes:
          - [[{"label": "PHISHING", "score": 0.9}, ...]]  (nested)
          - [{"label": "PHISHING", "score": 0.9}, ...]    (flat)

        Label matching (case-insensitive):
          - Contains "phish", "malicious", "1" → score = phishing probability
          - Contains "safe", "legitimate", "benign", "clean", "0" → score = 1 - value
          - Unrecognized → fallback 0.5
        """
        # Normalize: some models return [[{...}]] instead of [{...}]
        if isinstance(data, list) and data and isinstance(data[0], list):
            data = data[0]

        if not isinstance(data, list):
            return SignalScore(HF_FALLBACK_SCORE, AgentTelemetry(status="error", error="invalid_output"))

        for item in data:
            if not isinstance(item, dict):
                continue
            label: str = str(item.get("label", "")).lower()
            try:
                score: float = float(item["score"])
            except (KeyError, TypeError, ValueError):
                continue
            if not math.isfinite(score):
                continue

            if any(k in label for k in ("phish", "malicious", "label_1")):
                return SignalScore(min(max(score, 0.0), 1.0), AgentTelemetry(status="ok"))
            if any(k in label for k in ("safe", "legitimate", "benign", "clean", "label_0")):
                return SignalScore(min(max(1.0 - score, 0.0), 1.0), AgentTelemetry(status="ok"))

        return SignalScore(HF_FALLBACK_SCORE, AgentTelemetry(status="error", error="invalid_output"))


# ---------------------------------------------------------------------------
# Application singleton
# ---------------------------------------------------------------------------

hf_agent = HFAgent()
