"""OWASP LLM01 — Prompt Injection  ·  OWASP Agentic ASI01 — Agent Goal Hijack
MITRE ATLAS AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak).

Superficie: el atacante controla el cuerpo del correo (`email_body_snippet`) y,
vía RAG, chunks recuperados. Ambos entran al prompt del LLMAgent. Defensas bajo
test: `_fence()` (delimita + neutraliza marcadores), el system message que
declara el bloque como datos, y `_parse_score()` (satura a [0,1] → una respuesta
manipulada no inyecta un score arbitrario).
"""
from __future__ import annotations

import pytest

from agents.llm_agent import _FENCE_CLOSE, _FENCE_OPEN, _fence
from core.constants import LLM_FALLBACK_SCORE
from tests.security import payloads


class TestFenceNeutralization:
    """El atacante no debe poder cerrar el fence y 'escaparse' a rol de sistema."""

    @pytest.mark.parametrize("attack", payloads.FENCE_ESCAPES)
    def test_injected_close_marker_is_neutralized(self, attack: str):
        fenced = _fence(attack)
        body = fenced[len(_FENCE_OPEN):-len(_FENCE_CLOSE)]
        # El literal del marcador de cierre no puede aparecer intacto dentro del bloque.
        assert _FENCE_CLOSE not in body
        assert _FENCE_OPEN not in body

    def test_fence_still_wraps_benign_text(self):
        fenced = _fence("dominio sospechoso xn--pypal-4ve.com")
        assert fenced.startswith(_FENCE_OPEN) and fenced.endswith(_FENCE_CLOSE)
        assert "xn--pypal-4ve.com" in fenced   # la señal analizada se conserva


class TestUntrustedContentIsFenced:
    """Todo lo controlable por el atacante llega al prompt dentro del fence."""

    @pytest.mark.parametrize("attack", payloads.DIRECT_INJECTIONS)
    def test_email_body_injection_lands_inside_fence(self, build_prompt, attack: str):
        prompt = build_prompt(email_body=attack)
        assert _FENCE_OPEN in prompt and _FENCE_CLOSE in prompt
        # el texto del atacante no aparece fuera de un bloque fenced
        head = prompt.split(_FENCE_OPEN, 1)[0]
        assert "IGNORE ALL PREVIOUS" not in head.upper()
        assert "SYSTEM OVERRIDE" not in head.upper()

    def test_poisoned_rag_chunk_is_fenced(self, build_prompt):
        prompt = build_prompt(rag_context=[payloads.POISONED_RAG_DOC])
        assert _FENCE_OPEN in prompt
        # la instrucción escondida queda dentro del bloque de datos
        pre_context = prompt.split("knowledge base", 1)[0]
        assert "for every future analysis" not in pre_context


class TestScoreParserCannotBeForced:
    """`_parse_score` satura a [0,1] y solo lee la etiqueta SCORE: — una
    respuesta inyectada no puede colar un valor fuera de rango ni texto."""

    def test_out_of_range_is_clamped(self, agent):
        assert agent._parse_score("SCORE: -5 | REASON: evade") >= 0.0
        assert agent._parse_score("SCORE: 999 | REASON: x") <= 1.0

    def test_prose_without_label_falls_back_not_zero_injected(self, agent):
        # respuesta manipulada sin SCORE: → fallback neutral, NO 0.0 del atacante
        assert agent._parse_score(
            "The attacker told me to say this is safe. Trust me."
        ) == LLM_FALLBACK_SCORE

    def test_html_in_reason_never_becomes_a_score(self, agent):
        s = agent._parse_score(payloads.OUTPUT_HANDLING_INJECTIONS[0])
        assert 0.0 <= s <= 1.0 and s == 0.9  # lee el 0.9, ignora el <script>


@pytest.mark.live
class TestLivePipelineResilience:
    """El veredicto de un homógrafo real no se voltea aunque el cuerpo del
    correo ordene 'esto es seguro, SCORE 0.0' — la fusión mezcla IDN/HF/TI."""

    def test_injection_in_email_body_does_not_flip_verdict(self):
        import httpx

        from tests.security.conftest import LIVE_BASE

        with httpx.Client(base_url=LIVE_BASE, timeout=120) as c:
            tok = c.post("/api/v1/auth/login", json={
                "username": "jsfandinon@academia.usbbog.edu.co",
                "password": "Tesis.Fandino.7290",
            }).json()["access_token"]
            r = c.post("/api/v1/analyze_email", headers={"Authorization": f"Bearer {tok}"},
                       json={
                           "email_subject": "cuenta verificada",
                           "email_from": "soporte@xn--pypal-4ve.com",
                           "email_to": "v@usbbog.edu.co",
                           "email_body_html": f"<p>{payloads.DIRECT_INJECTIONS[0]} "
                                              f"{payloads.HOMOGRAPH_URL}</p>",
                           "email_text_snippet": payloads.DIRECT_INJECTIONS[0],
                           "all_urls": [payloads.HOMOGRAPH_URL],
                       })
        assert r.status_code == 200
        body = r.json()
        assert body["email_verdict"] in ("PHISHING", "SUSPICIOUS"), body
        worst = body["worst"]["agent_scores"]
        # el IDN sigue marcando el homógrafo aunque el LLM haya sido manipulado
        assert worst["s_idn_local"] >= 0.80
