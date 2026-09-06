"""OWASP LLM02 — Sensitive Information Disclosure.

El backend manda contenido a un proveedor LLM de terceros. `redact()` enmascara
PII del cuerpo del correo Y de los chunks del RAG (correos históricos con datos
de víctimas) antes de construir el prompt. Los dominios/URLs — la señal que el
sistema analiza — deben sobrevivir (principio de finalidad, Ley 1581/2012).
"""
from __future__ import annotations

import pytest

from core.redaction import redact
from tests.security import payloads


class TestRedactionCoversPII:
    @pytest.mark.parametrize("literal", payloads.PII_LITERALS)
    def test_pii_literals_are_masked(self, literal: str):
        out = redact(payloads.PII_IN_CHUNK)
        assert literal not in out

    @pytest.mark.parametrize("keep", payloads.PII_SURVIVES)
    def test_domains_and_urls_survive(self, keep: str):
        out = redact(payloads.PII_IN_CHUNK)
        assert keep in out, f"redact() destruyó la señal analizada: {keep}"

    def test_placeholders_are_stable_within_text(self):
        # el mismo remitente aparece 2 veces → mismo placeholder (correferencia)
        text = "de a@b.com para x. reenviado por a@b.com otra vez."
        out = redact(text)
        assert out.count("[EMAIL_1]") == 2 and "a@b.com" not in out

    def test_jwt_and_api_keys_are_masked(self):
        out = redact("token eyJabc123.eyJdef456.sig789xyz y key sk-ABCDEFGHIJKLMNOP1234")
        assert "eyJabc123.eyJdef456.sig789xyz" not in out
        assert "sk-ABCDEFGHIJKLMNOP1234" not in out


class TestRedactionAppliedInPrompt:
    """El prompt que sale hacia el proveedor no lleva PII de terceros."""

    def test_rag_chunk_pii_not_in_prompt(self, build_prompt):
        prompt = build_prompt(rag_context=[payloads.PII_IN_CHUNK])
        for literal in payloads.PII_LITERALS:
            assert literal not in prompt

    def test_email_body_pii_not_in_prompt(self, build_prompt):
        prompt = build_prompt(
            email_body="escribime a la victima.real@gmail.com o al +57 300 111 2233"
        )
        assert "victima.real@gmail.com" not in prompt
        assert "300 111 2233" not in prompt


@pytest.mark.live
class TestNoSystemPromptLeak:
    """El cuerpo del correo pide 'repetí tus instrucciones' — no deben aparecer
    ni el system message ni los marcadores del fence en `llm_reason`."""

    def test_prompt_leak_attempt_is_refused(self):
        import httpx

        from tests.security.conftest import LIVE_BASE

        with httpx.Client(base_url=LIVE_BASE, timeout=120) as c:
            tok = c.post("/api/v1/auth/login", json={
                "username": "jsfandinon@academia.usbbog.edu.co",
                "password": "Tesis.Fandino.7290",
            }).json()["access_token"]
            r = c.post("/api/v1/analyze", headers={"Authorization": f"Bearer {tok}"},
                       json={"url": payloads.HOMOGRAPH_URL,
                             "email_body_snippet": payloads.PROMPT_LEAK_ATTEMPTS[0]})
        assert r.status_code == 200
        reason = r.json().get("llm_reason", "")
        assert "<<<UNTRUSTED_CONTENT>>>" not in reason
        assert "cybersecurity expert specializing" not in reason
        assert "SCORE: <float" not in reason
