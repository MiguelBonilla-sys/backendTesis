"""Los secretos de APIs no viajan en URLs ni quedan en logs (hallazgo de T35)."""

import logging

import httpx
import pytest

import core.logger  # noqa: F401  configura los niveles al importar
from core.config import settings
from data_pipeline.threat_intel import ThreatIntelService

pytestmark = [pytest.mark.regression]


def test_http_client_request_logs_are_silenced():
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING


async def test_safe_browsing_key_goes_in_header_not_url(monkeypatch):
    seen = {}

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, params=None, headers=None, json=None):
            seen.update(url=url, params=params, headers=headers)
            return httpx.Response(200, json={})

    monkeypatch.setattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "AIza-test-key")
    monkeypatch.setattr("data_pipeline.threat_intel.httpx.AsyncClient", Client)
    assert await ThreatIntelService()._query_gsb("https://example.org/") == 0.0
    assert "AIza-test-key" not in seen["url"] and not seen["params"]
    assert seen["headers"]["X-Goog-Api-Key"] == "AIza-test-key"
