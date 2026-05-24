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

import httpx

from core.config import settings
from core.constants import HF_FALLBACK_SCORE, HF_TIMEOUT_S
from core.logger import get_logger

logger = get_logger(__name__)

_HF_BASE = "https://api-inference.huggingface.co/models"


class HFAgent:
    """
    Stateless HuggingFace Inference Agent.

    Calls HF Inference API text-classification endpoints and returns a
    phishing probability s_hf ∈ [0.0, 1.0].

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
        HF_FALLBACK_SCORE (0.5) on any error or missing API key.
        """
        if not settings.HUGGINGFACE_API_KEY:
            logger.debug("hf_agent_skipped", reason="no api key configured")
            return HF_FALLBACK_SCORE

        tasks: list = [self._classify_url(url)]
        if email_body_snippet:
            tasks.append(self._classify_content(email_body_snippet))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        scores: list[float] = []
        for r in results:
            if isinstance(r, float):
                scores.append(r)
            else:
                logger.warning("hf_classify_exception", error=str(r))

        if not scores:
            return HF_FALLBACK_SCORE

        s_hf = sum(scores) / len(scores)
        logger.info(
            "hf_analysis_complete",
            url=url,
            s_hf=round(s_hf, 4),
            classifiers_used=len(scores),
        )
        return float(min(max(s_hf, 0.0), 1.0))

    # ------------------------------------------------------------------
    # Internal classifiers
    # ------------------------------------------------------------------

    async def _classify_url(self, url: str) -> float:
        return await self._call_hf_api(settings.HF_URL_MODEL, url)

    async def _classify_content(self, text: str) -> float:
        return await self._call_hf_api(settings.HF_EMAIL_MODEL, text[:512])

    async def _call_hf_api(self, model: str, text: str) -> float:
        """
        POST to HF Inference API text-classification endpoint.

        Endpoint: ``POST {_HF_BASE}/{model}``
        Auth: ``Authorization: Bearer {HUGGINGFACE_API_KEY}``
        """
        headers = {
            "Authorization": f"Bearer {settings.HUGGINGFACE_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {"inputs": text}

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
            return HF_FALLBACK_SCORE
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "hf_http_error",
                model=model,
                status=exc.response.status_code,
            )
            return HF_FALLBACK_SCORE
        except Exception as exc:
            logger.warning("hf_call_failed", model=model, error=str(exc))
            return HF_FALLBACK_SCORE

        return self._extract_phishing_score(data)

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
            return HF_FALLBACK_SCORE

        for item in data:
            if not isinstance(item, dict):
                continue
            label: str = str(item.get("label", "")).lower()
            score: float = float(item.get("score", 0.5))

            if any(k in label for k in ("phish", "malicious", "label_1")):
                return min(max(score, 0.0), 1.0)
            if any(k in label for k in ("safe", "legitimate", "benign", "clean", "label_0")):
                return min(max(1.0 - score, 0.0), 1.0)

        return HF_FALLBACK_SCORE


# ---------------------------------------------------------------------------
# Application singleton
# ---------------------------------------------------------------------------

hf_agent = HFAgent()
