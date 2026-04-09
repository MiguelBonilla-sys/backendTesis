"""Tests for data_pipeline/threat_intel.py — VT, URLScan, GSB mocked."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from data_pipeline.threat_intel import ThreatIntelService


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_httpx_mock(method: str = "get", status_code: int = 200, json_data: dict | None = None):
    """Create an async context-manager mock for httpx.AsyncClient."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data or {}

    mock_http = AsyncMock()
    getattr(mock_http, method).return_value = mock_response

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_cm, mock_http, mock_response


@pytest.fixture
def service() -> ThreatIntelService:
    return ThreatIntelService()


# ── VirusTotal ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_virustotal_no_api_key_returns_zero(service):
    with patch("data_pipeline.threat_intel.settings") as ms:
        ms.VIRUSTOTAL_API_KEY = ""
        result = await service._virustotal("example.com")
    assert result == 0.0


@pytest.mark.asyncio
async def test_virustotal_success(service):
    vt_json = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 45, "undetected": 0}
            }
        }
    }
    mock_cm, mock_http, _ = _make_httpx_mock("get", 200, vt_json)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.VIRUSTOTAL_API_KEY = "test-key"
        result = await service._virustotal("evil.com")

    assert result == pytest.approx(5 / 50)


@pytest.mark.asyncio
async def test_virustotal_non_200_returns_zero(service):
    mock_cm, _, _ = _make_httpx_mock("get", 404, {})

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.VIRUSTOTAL_API_KEY = "test-key"
        result = await service._virustotal("example.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_virustotal_exception_returns_zero(service):
    mock_http = AsyncMock()
    mock_http.get.side_effect = ConnectionError("network error")
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.VIRUSTOTAL_API_KEY = "test-key"
        result = await service._virustotal("example.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_virustotal_empty_stats_returns_zero(service):
    vt_json = {"data": {"attributes": {"last_analysis_stats": {}}}}
    mock_cm, _, _ = _make_httpx_mock("get", 200, vt_json)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.VIRUSTOTAL_API_KEY = "test-key"
        result = await service._virustotal("clean.com")

    assert result == 0.0


# ── URLScan ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_urlscan_no_api_key_returns_zero(service):
    with patch("data_pipeline.threat_intel.settings") as ms:
        ms.URLSCAN_API_KEY = ""
        result = await service._urlscan("example.com")
    assert result == 0.0


@pytest.mark.asyncio
async def test_urlscan_malicious_returns_one(service):
    urlscan_json = {
        "results": [{"verdicts": {"overall": {"malicious": True}}}]
    }
    mock_cm, _, _ = _make_httpx_mock("get", 200, urlscan_json)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.URLSCAN_API_KEY = "test-key"
        result = await service._urlscan("evil.com")

    assert result == 1.0


@pytest.mark.asyncio
async def test_urlscan_not_malicious_returns_zero(service):
    urlscan_json = {
        "results": [{"verdicts": {"overall": {"malicious": False}}}]
    }
    mock_cm, _, _ = _make_httpx_mock("get", 200, urlscan_json)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.URLSCAN_API_KEY = "test-key"
        result = await service._urlscan("safe.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_urlscan_empty_results_returns_zero(service):
    mock_cm, _, _ = _make_httpx_mock("get", 200, {"results": []})

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.URLSCAN_API_KEY = "test-key"
        result = await service._urlscan("unknown.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_urlscan_non_200_returns_zero(service):
    mock_cm, _, _ = _make_httpx_mock("get", 429, {})

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.URLSCAN_API_KEY = "test-key"
        result = await service._urlscan("example.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_urlscan_exception_returns_zero(service):
    mock_http = AsyncMock()
    mock_http.get.side_effect = TimeoutError("timeout")
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.URLSCAN_API_KEY = "test-key"
        result = await service._urlscan("example.com")

    assert result == 0.0


# ── Google Safe Browsing ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gsb_no_api_key_returns_zero(service):
    with patch("data_pipeline.threat_intel.settings") as ms:
        ms.GOOGLE_SAFE_BROWSING_API_KEY = ""
        result = await service._gsb("example.com")
    assert result == 0.0


@pytest.mark.asyncio
async def test_gsb_matches_returns_one(service):
    gsb_json = {"matches": [{"threatType": "MALWARE"}]}
    mock_cm, _, _ = _make_httpx_mock("post", 200, gsb_json)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
        result = await service._gsb("evil.com")

    assert result == 1.0


@pytest.mark.asyncio
async def test_gsb_no_matches_returns_zero(service):
    mock_cm, _, _ = _make_httpx_mock("post", 200, {})

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
        result = await service._gsb("safe.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_gsb_non_200_returns_zero(service):
    mock_cm, _, _ = _make_httpx_mock("post", 400, {})

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
        result = await service._gsb("example.com")

    assert result == 0.0


@pytest.mark.asyncio
async def test_gsb_exception_returns_zero(service):
    mock_http = AsyncMock()
    mock_http.post.side_effect = ConnectionError("gsb down")
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_http)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("data_pipeline.threat_intel.settings") as ms, \
         patch("data_pipeline.threat_intel.httpx.AsyncClient", return_value=mock_cm):
        ms.GOOGLE_SAFE_BROWSING_API_KEY = "test-key"
        result = await service._gsb("example.com")

    assert result == 0.0


# ── fetch_all ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_all_returns_all_three_scores(service):
    with patch("data_pipeline.threat_intel.settings") as ms:
        ms.VIRUSTOTAL_API_KEY = ""
        ms.URLSCAN_API_KEY = ""
        ms.GOOGLE_SAFE_BROWSING_API_KEY = ""
        result = await service.fetch_all("example.com")

    assert set(result.keys()) == {"virustotal", "urlscan", "google_safe_browsing"}
    assert all(v == 0.0 for v in result.values())


@pytest.mark.asyncio
async def test_fetch_all_aggregates_mixed_scores(service):
    async def mock_vt(domain): return 0.8
    async def mock_urlscan(domain): return 0.0
    async def mock_gsb(domain): return 1.0

    with patch.object(service, "_virustotal", mock_vt), \
         patch.object(service, "_urlscan", mock_urlscan), \
         patch.object(service, "_gsb", mock_gsb):
        result = await service.fetch_all("evil.com")

    assert result["virustotal"] == 0.8
    assert result["urlscan"] == 0.0
    assert result["google_safe_browsing"] == 1.0
