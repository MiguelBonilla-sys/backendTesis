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
    PROBE_MAX_REDIRECTS,
    PROBE_MAX_RESPONSE_BYTES,
    PROBE_REDIRECT_WEIGHT,
)


def _dns_addresses(*addresses: str):
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, 0),
        )
        for address in addresses
    ]


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
        with patch("agents.web_probe_agent.socket.getaddrinfo", return_value=_dns_addresses("10.0.0.1")):
            assert _is_ssrf_blocked("internal.corp") is True

    def test_dns_failure_fail_closed(self):
        with patch(
            "agents.web_probe_agent.socket.getaddrinfo",
            side_effect=socket.gaierror("NXDOMAIN"),
        ):
            assert _is_ssrf_blocked("nonexistent.host.invalid") is True

    def test_dns_resolves_to_public_allowed(self):
        with patch("agents.web_probe_agent.socket.getaddrinfo", return_value=_dns_addresses("93.184.216.34")):
            assert _is_ssrf_blocked("example.com") is False

    @pytest.mark.parametrize("address", [
        "::", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
        "224.0.0.1", "ff02::1", "100.64.0.1", "240.0.0.1", "192.0.2.1",
    ])
    def test_non_public_and_mapped_addresses_blocked(self, address):
        assert _is_ssrf_blocked(address) is True

    @pytest.mark.parametrize("address", ["2606:4700:4700::1111", "::ffff:8.8.8.8"])
    def test_public_ipv6_allowed(self, address):
        assert _is_ssrf_blocked(address) is False

    @pytest.mark.parametrize("addresses", [
        ("93.184.216.34", "10.0.0.1"),
        ("93.184.216.34", "::1"),
        ("2606:4700:4700::1111", "fc00::1"),
        (),
    ])
    def test_any_non_public_dns_answer_or_no_answers_blocks_host(self, addresses):
        with patch("agents.web_probe_agent.socket.getaddrinfo", return_value=_dns_addresses(*addresses)):
            assert _is_ssrf_blocked("mixed.example") is True

    def test_all_public_dns_answers_allowed(self):
        with patch(
            "agents.web_probe_agent.socket.getaddrinfo",
            return_value=_dns_addresses("93.184.216.34", "2606:4700:4700::1111"),
        ) as resolve:
            assert _is_ssrf_blocked("public.example") is False
        resolve.assert_called_once_with(
            "public.example", None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )


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

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", [
        "https://", "http://[broken", "https://example.com:bad/",
        "https://example.com:0/", "https://example.com:65536/",
        "https://user:secret@example.com/",
    ])
    async def test_invalid_url_returns_neutral_without_request(self, url):
        with patch("agents.web_probe_agent.httpx.AsyncClient.stream") as stream:
            result = await WebProbeAgent().analyze(url)
        assert result.s_probe == 0.0
        assert result.error
        stream.assert_not_called()


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
    @pytest.fixture(autouse=True)
    def public_dns(self):
        with patch(
            "agents.web_probe_agent.socket.getaddrinfo",
            return_value=_dns_addresses("93.184.216.34"),
        ):
            yield

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

    @pytest.mark.asyncio
    async def test_oversized_chunk_is_truncated_before_signal_extraction(self):
        html = b" " * PROBE_MAX_RESPONSE_BYTES + b'<form><input type="password"></form>'
        mock_client = _make_mock_client(html=html)
        with patch("agents.web_probe_agent.httpx.AsyncClient", return_value=mock_client):
            result = await WebProbeAgent().analyze("https://example.com/")
        assert result.error is None
        assert result.has_password_field is False
        assert result.s_probe == 0.0


class _TrackedStream(httpx.AsyncByteStream):
    """Response stream that records consumption and explicit closure."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.chunks_read = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.chunks_read += 1
            yield chunk

    async def aclose(self):
        self.closed = True


async def _run_transport_probe(handler, *, dns=None):
    """Exercise real HTTPX redirect/stream behavior without opening sockets."""
    requests = []

    def record(request):
        requests.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    with (
        patch("agents.web_probe_agent.httpx.AsyncClient", return_value=client),
        patch(
            "agents.web_probe_agent.socket.getaddrinfo",
            side_effect=dns,
            return_value=_dns_addresses("93.184.216.34"),
        ),
    ):
        result = await WebProbeAgent().analyze("https://public.example/start")
    return result, requests


class TestRedirectSafety:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("location", [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "//192.168.1.1/admin",
        "http://[::1]/admin",
        "http://[::ffff:169.254.169.254]/metadata",
        "file:///etc/passwd",
        "ftp://files.example/secret",
        "https://user:secret@other.example/",
        "https://other.example:65536/",
        "http://[broken",
    ])
    async def test_unsafe_redirect_never_reaches_transport(self, location):
        body = _TrackedStream([b"redirect body must not be read"])
        result, requests = await _run_transport_probe(
            lambda _: httpx.Response(302, headers={"location": location}, stream=body)
        )
        assert len(requests) == 1
        assert result.s_probe == 0.0
        assert result.error
        assert body.chunks_read == 0
        assert body.closed is True

    @pytest.mark.asyncio
    async def test_redirect_hostname_with_private_aaaa_is_blocked(self):
        def dns(host, *_args, **_kwargs):
            if host == "internal.example":
                return _dns_addresses("93.184.216.34", "fc00::1")
            return _dns_addresses("93.184.216.34")

        result, requests = await _run_transport_probe(
            lambda _: httpx.Response(302, headers={"location": "https://internal.example/"}),
            dns=dns,
        )
        assert len(requests) == 1
        assert result.error == "SSRF-blocked host: internal.example"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_public_relative_and_cross_domain_redirects_preserve_signals(self, status):
        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(status, headers={"location": "/intermediate"})
            if request.url.path == "/intermediate":
                return httpx.Response(status, headers={"location": "https://other.example/login"})
            return httpx.Response(
                200, headers={"content-type": "text/html"},
                content=b'<form><input type="password"></form>',
            )

        result, requests = await _run_transport_probe(handler)
        assert [str(request.url) for request in requests] == [
            "https://public.example/start", "https://public.example/intermediate",
            "https://other.example/login",
        ]
        assert result.error is None
        assert result.redirect_count == 2
        assert result.domain_changed_on_redirect is True
        assert result.final_domain == "other.example"
        assert result.has_login_form is True
        assert result.s_probe == min(PROBE_LOGIN_WEIGHT + PROBE_REDIRECT_WEIGHT, PROBE_BOOST_CAP)

    @pytest.mark.asyncio
    async def test_dns_revalidated_even_on_same_domain_redirect(self):
        answers = iter([
            _dns_addresses("93.184.216.34"), _dns_addresses("169.254.169.254")
        ])
        result, requests = await _run_transport_probe(
            lambda _: httpx.Response(302, headers={"location": "/next"}),
            dns=lambda *_args, **_kwargs: next(answers),
        )
        assert len(requests) == 1
        assert result.error == "SSRF-blocked host: public.example"

    @pytest.mark.asyncio
    async def test_redirect_loop_stops_at_limit(self):
        result, requests = await _run_transport_probe(
            lambda _: httpx.Response(302, headers={"location": "/start"})
        )
        assert len(requests) == PROBE_MAX_REDIRECTS + 1
        assert result.redirect_count == PROBE_MAX_REDIRECTS
        assert result.error == "Too many redirects"
        assert result.s_probe == 0.0

    @pytest.mark.asyncio
    async def test_exact_redirect_limit_can_reach_html(self):
        count = 0

        def handler(_request):
            nonlocal count
            count += 1
            if count <= PROBE_MAX_REDIRECTS:
                return httpx.Response(302, headers={"location": f"/page{count}"})
            return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html>ok</html>")

        result, requests = await _run_transport_probe(handler)
        assert len(requests) == PROBE_MAX_REDIRECTS + 1
        assert result.redirect_count == PROBE_MAX_REDIRECTS
        assert result.error is None
        assert result.domain_changed_on_redirect is False

    @pytest.mark.asyncio
    async def test_html_stream_stops_at_body_limit_and_closes(self):
        body = _TrackedStream([
            b" " * PROBE_MAX_RESPONSE_BYTES,
            b'<form><input type="password"></form>',
        ])
        result, _requests = await _run_transport_probe(
            lambda _: httpx.Response(200, headers={"content-type": "text/html"}, stream=body)
        )
        assert body.chunks_read == 1
        assert body.closed is True
        assert result.error is None
        assert result.has_password_field is False
        assert result.s_probe == 0.0

    @pytest.mark.asyncio
    async def test_non_html_body_is_never_consumed(self):
        body = _TrackedStream([b"large binary data"])
        result, _requests = await _run_transport_probe(
            lambda _: httpx.Response(200, headers={"content-type": "application/pdf"}, stream=body)
        )
        assert body.chunks_read == 0
        assert body.closed is True
        assert "Non-HTML" in result.error
