"""OWASP LLM05 — Improper Output Handling  ·  LLM10 — Unbounded Consumption.

`llm_reason` se persiste en `incidents` y se muestra en el dashboard. Un modelo
manipulado (vía inyección en el correo o en un chunk) podría intentar colar
markup en el REASON. `_parse_reason` debe devolver texto plano. Y los límites de
tamaño del schema deben cortar payloads de consumo no acotado.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from schemas.analyze import AnalyzeRequest, BatchAnalyzeRequest
from tests.security import payloads


class TestReasonIsPlainText:
    @pytest.mark.parametrize("resp", payloads.OUTPUT_HANDLING_INJECTIONS)
    def test_no_html_tags_in_parsed_reason(self, agent, resp: str):
        reason = agent._parse_reason(resp)
        assert "<script" not in reason.lower()
        assert "</script>" not in reason.lower()
        assert "javascript:" not in reason.lower()

    def test_reason_is_length_bounded(self, agent):
        huge = "SCORE: 0.9 | REASON: " + ("A" * 5000)
        assert len(agent._parse_reason(huge)) <= 500

    def test_benign_reason_survives(self, agent):
        r = agent._parse_reason("SCORE: 0.9 | REASON: Cyrillic 'а' spoofs paypal.com")
        assert "paypal.com" in r and "Cyrillic" in r


class TestSchemaLimitsCapConsumption:
    def test_oversized_email_body_rejected(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="https://x.com", email_body_snippet=payloads.OVERSIZED_BODY)

    def test_too_many_urls_rejected(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="https://x.com", all_urls=payloads.TOO_MANY_URLS)

    def test_batch_url_count_capped(self):
        with pytest.raises(ValidationError):
            BatchAnalyzeRequest(urls=[f"https://p{i}.example" for i in range(11)])

    def test_url_length_capped(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(url="https://x.com/" + "a" * 3000)


@pytest.mark.live
class TestLiveConsumptionGuards:
    def test_oversized_body_returns_422_not_5xx(self):
        import httpx

        from tests.security.conftest import LIVE_BASE

        with httpx.Client(base_url=LIVE_BASE, timeout=60) as c:
            tok = c.post("/api/v1/auth/login", json={
                "username": "jsfandinon@academia.usbbog.edu.co",
                "password": "Tesis.Fandino.7290",
            }).json()["access_token"]
            r = c.post("/api/v1/analyze", headers={"Authorization": f"Bearer {tok}"},
                       json={"url": "https://x.com", "email_body_snippet": payloads.OVERSIZED_BODY})
        assert r.status_code == 422
