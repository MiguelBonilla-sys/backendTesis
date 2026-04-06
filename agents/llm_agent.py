"""LLM Analysis Agent — LlamaStack (Llama 3.1 8B) + ChromaDB RAG."""

import asyncio
import re

import httpx

from agents.base_agent import BaseAgent
from core.config import settings
from core.constants import (
    COLLECTION_EMAIL_EMBEDDINGS,
    LLAMASTACK_MAX_TOKENS,
    LLAMASTACK_TIMEOUT_SECONDS,
    RAG_TOP_K,
)
from core.exceptions import LLMInferenceError


class LLMAgent(BaseAgent):
    """
    LLM analysis with 3-step flow:
      1. RAG retrieval from ChromaDB (email_embeddings, top-k=3)
      2. Prompt construction + LlamaStack inference
      3. Score parsing from response
    Falls back to 0.5 on timeout.
    """

    def __init__(self, chromadb_client=None) -> None:
        super().__init__("LLMAgent")
        self._chroma = chromadb_client

    async def analyze(
        self,
        domain: str,
        email_body: str | None = None,
        s_idn_local: float = 0.0,
    ) -> dict:
        self._log_start(domain)
        try:
            rag_context = await self._retrieve_rag(domain, email_body)
            prompt = self._build_prompt(domain, email_body, s_idn_local, rag_context)

            response = await asyncio.wait_for(
                self._call_llamastack(prompt),
                timeout=LLAMASTACK_TIMEOUT_SECONDS,
            )
            s_llm = self._parse_score(response)

            result = {
                "domain": domain,
                "s_llm": round(s_llm, 4),
                "reasoning": response.get("completion", ""),
                "rag_context": rag_context,
                "tokens_used": response.get("usage", {}).get("total_tokens", 0),
            }
            self._log_result(domain, s_llm)
            return result

        except asyncio.TimeoutError:
            self.logger.warning(f"LlamaStack timeout for {domain!r} — fallback 0.5")
            return {
                "domain": domain,
                "s_llm": 0.5,
                "reasoning": "timeout",
                "rag_context": [],
                "tokens_used": 0,
            }
        except Exception as exc:
            self.logger.error(f"LLM analysis failed: {exc}", exc_info=True)
            raise LLMInferenceError(f"LLM inference failed for {domain!r}") from exc

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _retrieve_rag(self, domain: str, email_body: str | None) -> list[str]:
        if self._chroma is None:
            return []
        try:
            query = f"{domain} {email_body or ''}".strip()
            results = self._chroma.query(
                collection_name=COLLECTION_EMAIL_EMBEDDINGS,
                query_texts=[query],
                n_results=RAG_TOP_K,
            )
            return results.get("documents", [[]])[0]
        except Exception as exc:
            self.logger.warning(f"ChromaDB RAG retrieval failed: {exc}")
            return []

    def _build_prompt(
        self,
        domain: str,
        email_body: str | None,
        s_idn: float,
        rag_context: list[str],
    ) -> str:
        ctx = "\n".join(f"- {c}" for c in rag_context) if rag_context else "None."
        body = (email_body or "")[:500] or "Not provided."
        return (
            "You are a phishing detection expert.\n"
            f"Similar past phishing emails:\n{ctx}\n\n"
            f"Domain: {domain}\n"
            f"IDN homograph score: {s_idn:.2f} (0=safe, 1=phishing)\n"
            f"Email body snippet: {body}\n\n"
            "Output a phishing risk score 0.0–1.0 and brief reasoning.\n"
            "Format: SCORE: <float> | REASON: <text>"
        )

    async def _call_llamastack(self, prompt: str) -> dict:
        async with httpx.AsyncClient(timeout=LLAMASTACK_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{settings.LLAMASTACK_URL}/v1/chat/completions",
                json={
                    "model": settings.LLAMASTACK_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": LLAMASTACK_MAX_TOKENS,
                    "temperature": 0.1,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return {"completion": content, "usage": data.get("usage", {})}

    def _parse_score(self, response: dict) -> float:
        text = response.get("completion", "")
        match = re.search(r"SCORE:\s*([\d.]+)", text)
        if match:
            return max(0.0, min(1.0, float(match.group(1))))
        self.logger.warning("Could not parse score from LLM — defaulting to 0.5")
        return 0.5
