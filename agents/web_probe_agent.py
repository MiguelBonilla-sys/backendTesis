"""
WebProbeAgent — active URL probing for phishing signal extraction.

Fetches the target URL via a hardened HTTP client and extracts page-level
phishing signals: login forms, redirect chains, brand impersonation, and
external form actions.

s_probe ∈ [0.0, 1.0] — additive boost to s_risk in FusionAgent.

Safety guarantees:
  - SSRF protection: all private/loopback/link-local IP ranges blocked.
  - Streaming read: max PROBE_MAX_RESPONSE_BYTES (64 KB) downloaded.
  - Strict timeout: PROBE_TIMEOUT_S (8s) connect + read combined.
  - Max redirects: PROBE_MAX_REDIRECTS (5) before abort.
  - Graceful degradation: always returns WebProbeResult — never raises.
    On any failure (timeout, DNS, SSRF block) returns s_probe=0.0 so the
    rest of the pipeline is unaffected.
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
# SSRF block list — private/loopback/link-local/metadata CIDR ranges
# ---------------------------------------------------------------------------
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # AWS metadata / link-local
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),   # shared address space (RFC 6598)
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)

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
    Returns True if the host resolves to a private / blocked IP range.

    Handles both direct IP literals and hostnames via DNS.
    Blocks on DNS failure (fail-closed).
    """
    # Handle IP literals (e.g., http://192.168.1.1/...)
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        pass  # Not an IP literal — continue to DNS

    # DNS resolution (synchronous — fast for cached entries, acceptable in pipeline)
    try:
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _BLOCKED_NETWORKS)
    except (socket.gaierror, ValueError):
        return True  # Block on DNS failure (fail-closed policy)


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
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return WebProbeResult(error=f"Unsupported scheme: {parsed.scheme!r}")

        host = parsed.hostname or ""
        if not host:
            return WebProbeResult(error="No host in URL")

        if _is_ssrf_blocked(host):
            logger.warning("probe_ssrf_blocked", host=host)
            return WebProbeResult(error=f"SSRF-blocked host: {host}")

        try:
            result = await self._fetch_and_analyze(url, original_domain=host.lower())
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
            follow_redirects=True,
            verify=False,  # nosec — intentional: probe even invalid-cert phishing pages
        ) as client:
            try:
                async with client.stream("GET", url, headers=headers) as response:
                    status_code = response.status_code
                    redirect_count = len(response.history)
                    final_url = str(response.url)
                    final_domain = _extract_domain(final_url)
                    domain_changed = bool(
                        final_domain and final_domain != original_domain
                    )
                    content_type = response.headers.get("content-type", "").lower()

                    # Only parse HTML responses — skip binaries/JSON/PDFs
                    if "html" not in content_type and "xml" not in content_type:
                        return WebProbeResult(
                            final_url=final_url,
                            final_domain=final_domain,
                            status_code=status_code,
                            redirect_count=redirect_count,
                            domain_changed_on_redirect=domain_changed,
                            error=f"Non-HTML content-type: {content_type[:80]}",
                        )

                    # Stream body up to PROBE_MAX_RESPONSE_BYTES
                    raw_bytes = b""
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        raw_bytes += chunk
                        if len(raw_bytes) >= PROBE_MAX_RESPONSE_BYTES:
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
