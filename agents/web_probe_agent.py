"""
WebProbeAgent — active URL probing for phishing signal extraction.

Fetches the target URL via a hardened HTTP client and extracts page-level
phishing signals: login forms, redirect chains, brand impersonation, and
external form actions.

s_probe ∈ [0.0, 1.0] — additive boost to s_risk in FusionAgent.

Safety controls:
  - Public HTTP(S) destinations only, revalidated before every redirect hop.
  - Buffered HTML: max PROBE_MAX_RESPONSE_BYTES (64 KB) of decoded body.
  - HTTP connect/read timeout: PROBE_TIMEOUT_S (8s) per operation.
  - Max redirects: PROBE_MAX_REDIRECTS (5) before abort.
  - Graceful degradation: always returns WebProbeResult — never raises.
    On any failure (timeout, DNS, SSRF block) returns s_probe=0.0 so the
    rest of the pipeline is unaffected.

DNS validation checks every returned IPv4/IPv6 address. The HTTP transport
resolves again when connecting, so this is not protection against DNS rebinding;
deployment egress rules must also deny access to internal/metadata networks.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

import httpx

from core.constants import (
    PROBE_BOOST_CAP,
    PROBE_BRAND_WEIGHT,
    PROBE_FORM_ACTION_WEIGHT,
    PROBE_LOGIN_WEIGHT,
    PROBE_MAX_REDIRECTS,
    PROBE_MAX_RESPONSE_BYTES,
    PROBE_REDIRECT_WEIGHT,
    PROBE_TIMEOUT_S,
)
from core.logger import get_logger
from schemas.analyze import WebProbeResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# SSRF policy — only globally routable unicast addresses
# ---------------------------------------------------------------------------


def _is_blocked_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast

# ---------------------------------------------------------------------------
# Brand keyword list for impersonation detection (lowercase, Colombian context)
# ---------------------------------------------------------------------------
_BRAND_KEYWORDS: frozenset[str] = frozenset({
    # Colombian banks & fintech
    "bancolombia", "davivienda", "bbva", "nequi", "daviplata",
    "banco de bogotá", "banco de bogota", "itaú", "itau", "scotiabank",
    "banco popular", "colpatria", "occidente",
    # Government & public entities
    "dian", "superfinanciera", "mintic", "registraduría", "registraduria",
    "dane", "mintransporte", "colpensiones",
    # International giants
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "whatsapp", "twitter", "tiktok",
    # Education
    "usbbog", "uniandes", "unal", "universidad san buenaventura",
})

# ---------------------------------------------------------------------------
# Compiled regexes for HTML signal extraction
# ---------------------------------------------------------------------------
_PASSWORD_INPUT_RE = re.compile(
    r'<input[^>]+type\s*=\s*["\']?password["\']?',
    re.IGNORECASE,
)
_FORM_RE = re.compile(r"<form\b", re.IGNORECASE)

# Captures the full href value of form action pointing to absolute URL
_FORM_ACTION_RE = re.compile(
    r'<form[^>]+action\s*=\s*["\']?(https?://[^"\'>\s]+)',
    re.IGNORECASE,
)
_TITLE_RE = re.compile(
    r"<title[^>]*>(.*?)</title>",
    re.IGNORECASE | re.DOTALL,
)

# Detects redirect meta tags (some phishing pages use them)
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+url\s*=\s*["\']?(https?://[^"\'>\s]+)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SSRF helpers
# ---------------------------------------------------------------------------


def _is_ssrf_blocked(host: str) -> bool:
    """
    Returns True unless every resolved address is globally routable unicast.

    Handles both direct IP literals and hostnames via DNS.
    Blocks on DNS failure (fail-closed).
    """
    # Handle IP literals (e.g., http://192.168.1.1/...)
    try:
        return _is_blocked_address(host)
    except ValueError:
        pass  # Not an IP literal — continue to DNS

    # DNS resolution (synchronous — fast for cached entries, acceptable in pipeline)
    try:
        addresses = socket.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        return not addresses or any(
            _is_blocked_address(address[4][0]) for address in addresses
        )
    except (OSError, ValueError):
        return True  # Block on DNS failure (fail-closed policy)


def _probe_url_error(url: httpx.URL) -> str | None:
    """Validate the same normalized URL that HTTPX will request."""
    if url.scheme not in ("http", "https"):
        return f"Unsupported scheme: {url.scheme!r}"
    if not url.host:
        return "No host in URL"
    if any(character in url.host for character in ("%", "\\", "[", "]")):
        return "Invalid host in probe URL"
    if url.username or url.password:
        return "Credentials in probe URL are not allowed"
    if url.port is not None and not 1 <= url.port <= 65535:
        return "Invalid port in probe URL"
    if _is_ssrf_blocked(url.host):
        logger.warning("probe_ssrf_blocked", host=url.host)
        return f"SSRF-blocked host: {url.host}"
    return None


def _extract_domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# WebProbeAgent
# ---------------------------------------------------------------------------


class WebProbeAgent:
    """
    Stateless active-probing agent.

    Fetches the URL, reads up to 64 KB of HTML, and extracts phishing signals:
    - Login form / password field presence
    - Domain change across redirect chain
    - Brand impersonation (brand keyword in title/body but not in domain)
    - External form action (data exfiltration to third-party domain)

    All signals contribute additively to s_probe, capped at PROBE_BOOST_CAP.
    """

    async def analyze(self, url: str) -> WebProbeResult:
        """
        Main entry point — always returns WebProbeResult, never raises.

        On any error (SSRF block, timeout, connection failure, non-HTML content)
        returns WebProbeResult with s_probe=0.0 and error set.
        """
        try:
            result = await self._fetch_and_analyze(
                url, original_domain=httpx.URL(url).host.lower()
            )
            if result.s_probe > 0:
                logger.info(
                    "probe_signals_detected",
                    url=url,
                    final_domain=result.final_domain,
                    s_probe=result.s_probe,
                    signals=result.probe_signals,
                )
            return result
        except Exception as exc:
            logger.warning("probe_unexpected_error", url=url, error=str(exc))
            return WebProbeResult(error=f"Unexpected probe error: {exc}")

    async def _fetch_and_analyze(
        self, url: str, original_domain: str
    ) -> WebProbeResult:
        """Perform the actual HTTP fetch and HTML signal extraction."""

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-CO,es;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
        }

        async with httpx.AsyncClient(
            timeout=PROBE_TIMEOUT_S,
            max_redirects=PROBE_MAX_REDIRECTS,
            follow_redirects=False,
            verify=False,  # nosec — intentional: probe even invalid-cert phishing pages
        ) as client:
            try:
                current_url = httpx.URL(url)
                redirect_count = 0
                while True:
                    error = _probe_url_error(current_url)
                    if error:
                        return WebProbeResult(error=error, redirect_count=redirect_count)

                    async with client.stream(
                        "GET", current_url, headers=headers, follow_redirects=False
                    ) as response:
                        status_code = response.status_code
                        if (
                            status_code in (301, 302, 303, 307, 308)
                            and "location" in response.headers
                        ):
                            if redirect_count >= PROBE_MAX_REDIRECTS:
                                return WebProbeResult(
                                    redirect_count=redirect_count,
                                    error="Too many redirects",
                                )
                            current_url = current_url.join(response.headers["location"])
                            redirect_count += 1
                            # Close this response without consuming its body, then
                            # validate the next target before making any request.
                            continue

                        final_url = str(response.url)
                        final_domain = _extract_domain(final_url)
                        domain_changed = bool(
                            final_domain and final_domain != original_domain
                        )
                        content_type = response.headers.get("content-type", "").lower()

                        # Only parse HTML responses — skip binaries/JSON/PDFs.
                        if "html" not in content_type and "xml" not in content_type:
                            return WebProbeResult(
                                final_url=final_url,
                                final_domain=final_domain,
                                status_code=status_code,
                                redirect_count=redirect_count,
                                domain_changed_on_redirect=domain_changed,
                                error=f"Non-HTML content-type: {content_type[:80]}",
                            )

                        raw_bytes = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=4096):
                            remaining = PROBE_MAX_RESPONSE_BYTES - len(raw_bytes)
                            raw_bytes.extend(chunk[:remaining])
                            if len(raw_bytes) >= PROBE_MAX_RESPONSE_BYTES:
                                break
                    break

            except httpx.TooManyRedirects:
                return WebProbeResult(
                    status_code=0,
                    redirect_count=PROBE_MAX_REDIRECTS,
                    error="Too many redirects",
                )
            except httpx.TimeoutException:
                return WebProbeResult(error="Probe timed out")
            except httpx.ConnectError as exc:
                return WebProbeResult(error=f"Connection error: {exc}")
            except httpx.RequestError as exc:
                return WebProbeResult(error=f"Request error: {exc}")

        html = raw_bytes.decode("utf-8", errors="replace")

        # --- Signal extraction ---
        has_password_field = bool(_PASSWORD_INPUT_RE.search(html))
        has_login_form = bool(_FORM_RE.search(html)) and has_password_field

        external_form_action = self._detect_external_form_action(html, final_domain)
        brand_impersonation = self._detect_brand_impersonation(html, final_domain)

        # --- Compute score ---
        s_probe, probe_signals = self._score(
            has_password_field=has_password_field,
            has_login_form=has_login_form,
            domain_changed=domain_changed,
            brand_impersonation=brand_impersonation,
            external_form_action=external_form_action,
        )

        return WebProbeResult(
            final_url=final_url,
            final_domain=final_domain,
            status_code=status_code,
            redirect_count=redirect_count,
            has_password_field=has_password_field,
            has_login_form=has_login_form,
            domain_changed_on_redirect=domain_changed,
            brand_impersonation=brand_impersonation,
            external_form_action=external_form_action,
            s_probe=s_probe,
            probe_signals=probe_signals,
        )

    def _detect_external_form_action(self, html: str, final_domain: str) -> bool:
        """Returns True if any <form action="https://other-domain..."> found."""
        for match in _FORM_ACTION_RE.finditer(html):
            action_domain = _extract_domain(match.group(1))
            if action_domain and action_domain != final_domain:
                return True
        return False

    def _detect_brand_impersonation(
        self, html: str, final_domain: str
    ) -> str | None:
        """
        Returns the brand name if a known brand keyword appears in the page
        title or early body content but NOT in the final domain name.
        """
        # Check <title> first (highest confidence)
        title_match = _TITLE_RE.search(html)
        if title_match:
            title_lower = title_match.group(1).lower()
            for brand in _BRAND_KEYWORDS:
                if brand in title_lower and brand not in final_domain:
                    return brand

        # Fallback: check first 15 KB of body text
        body_lower = html[:15_000].lower()
        for brand in _BRAND_KEYWORDS:
            if brand in body_lower and brand not in final_domain:
                return brand

        return None

    def _score(
        self,
        has_password_field: bool,
        has_login_form: bool,
        domain_changed: bool,
        brand_impersonation: str | None,
        external_form_action: bool,
    ) -> tuple[float, list[str]]:
        """
        Aggregate signal weights into s_probe ∈ [0.0, PROBE_BOOST_CAP].

        Weight semantics (from constants.py):
          PROBE_LOGIN_WEIGHT      — login form with password field (strongest direct signal)
          PROBE_REDIRECT_WEIGHT   — redirect to a different domain
          PROBE_BRAND_WEIGHT      — page claims to be a known brand but isn't
          PROBE_FORM_ACTION_WEIGHT — form submits to external domain (data exfiltration)
        """
        total = 0.0
        signals: list[str] = []

        if has_login_form:
            total += PROBE_LOGIN_WEIGHT
            signals.append(
                "Login form with password field detected on the target page"
            )
        elif has_password_field:
            # Password field without an enclosing <form> — weaker signal
            total += PROBE_LOGIN_WEIGHT * 0.6
            signals.append("Password input field detected on the target page")

        if domain_changed:
            total += PROBE_REDIRECT_WEIGHT
            signals.append("URL redirects to a different domain than originally requested")

        if brand_impersonation:
            total += PROBE_BRAND_WEIGHT
            signals.append(
                f"Page impersonates brand '{brand_impersonation}' "
                f"on an unrelated domain"
            )

        if external_form_action:
            total += PROBE_FORM_ACTION_WEIGHT
            signals.append(
                "Form submits credentials to an external domain (potential exfiltration)"
            )

        return round(min(total, PROBE_BOOST_CAP), 4), signals


# ---------------------------------------------------------------------------
# Module-level singleton imported by routers
# ---------------------------------------------------------------------------

web_probe_agent = WebProbeAgent()
