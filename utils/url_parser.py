"""URL and domain parsing utilities with path-traversal protection."""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse, urlunparse

# Regex used to extract http/https URLs from free-form text
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# href/src attribute URL extractor for HTML bodies
_HREF_RE = re.compile(r'(?:href|src|action)=["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)

# Simple IPv4 pattern
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv6 pattern (bare, not including port brackets)
_IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")

# Free hosting platforms where the attacker controls the subdomain, not the 2LD.
# For IDN analysis on these platforms the relevant label is the leftmost subdomain.
# e.g. оutlоок-098.vercel.app → IDN label = "оutlоок-098", not "vercel"
_FREE_HOSTING_PLATFORMS: frozenset[str] = frozenset({
    "vercel.app",
    "github.io",
    "netlify.app",
    "pages.dev",          # Cloudflare Pages
    "glitch.me",
    "repl.co",
    "replit.dev",
    "web.app",            # Firebase Hosting
    "firebaseapp.com",
    "render.com",
    "onrender.com",
    "fly.dev",
    "herokuapp.com",
    "azurewebsites.net",
    "azurestaticapps.net",
    "surge.sh",
    "tiiny.site",
})

# CDN/storage hosts that may be abused to host phishing pages
_KNOWN_CDN_HOSTS: frozenset[str] = frozenset({
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "r2.cloudflarestorage.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "cdn.jsdelivr.net",
})

# Embedded-domain pattern: looks like "evil.com" or "sub.evil.co.uk" used as a filename
_EMBEDDED_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)


def extract_domain(url: str) -> str:
    """Extract the full hostname (without port) from *url*.

    Examples::

        extract_domain("https://login.paypal.com/auth") -> "login.paypal.com"
        extract_domain("http://192.168.1.1/page")       -> "192.168.1.1"
    """
    parsed = urlparse(url)
    # netloc may contain a port — strip it
    host = parsed.hostname or parsed.netloc
    return host.lower() if host else ""


def extract_2ld(domain: str) -> str:
    """Extract the second-level domain (registrable domain) from *domain*.

    The second-level domain is the part immediately before the public TLD,
    e.g. ``"login.paypal.com"`` → ``"paypal"``.

    For IP addresses or bare hostnames the input is returned unchanged.
    """
    domain = domain.lower().rstrip(".")
    if is_ip_address(domain):
        return domain
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


def is_ip_address(domain: str) -> bool:
    """Return True if *domain* is a bare IPv4 or IPv6 address."""
    domain = domain.strip("[]")
    return bool(_IPV4_RE.match(domain)) or bool(_IPV6_RE.match(domain))


def extract_urls_from_text(text: str) -> list[str]:
    """Return all http/https URLs found in *text*."""
    return _URL_RE.findall(text)


def extract_urls_from_html(html: str) -> list[str]:
    """
    Return all http/https URLs found in HTML *href*, *src*, and *action* attributes.

    More reliable than regex on raw HTML text because it targets attribute values
    directly, correctly stopping at the closing quote.
    """
    return _HREF_RE.findall(html)


def normalize_url(url: str) -> str:
    """Strip fragment identifier from *url* for deduplication purposes.

    Tracking tokens embedded in fragments (e.g. ``#id117285abc…``) make
    URLs look unique even when they point to the same resource.
    """
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def extract_idn_label(domain: str) -> str:
    """Return the label to use for IDN homograph analysis.

    For most domains this is the registrable 2LD (``paypal`` in ``login.paypal.com``).
    For free hosting platforms (Vercel, GitHub Pages, Netlify…) the attacker controls
    only the *subdomain* — so the relevant label is the leftmost part:

        оutlоок-098.vercel.app  →  "оutlоок-098"   (attacker-controlled)
        evilpaypal.netlify.app  →  "evilpaypal"

    Falls back to :func:`extract_2ld` for normal domains.
    """
    domain = domain.lower().rstrip(".")
    parts = domain.split(".")
    # Build the trailing host suffix and check against known platforms
    for n in (2, 3):  # check 2-part (vercel.app) and 3-part (pages.github.io) suffixes
        if len(parts) > n:
            suffix = ".".join(parts[-n:])
            if suffix in _FREE_HOSTING_PLATFORMS:
                return parts[0]  # leftmost = attacker subdomain
    return extract_2ld(domain)


def extract_effective_domain(url: str) -> str:
    """
    Return the effective target domain for threat-intelligence analysis.

    CDN/storage services (GCS, S3, Azure Blob…) are sometimes abused as
    phishing infrastructure — the actual attack domain is embedded in the
    path as a filename, e.g.:

        storage.googleapis.com/rnd-bucket/optimisticdigital.xyz.html
        → effective domain: optimisticdigital.xyz

    Falls back to :func:`extract_domain` for non-CDN URLs or when no
    embedded domain can be detected in the path.
    """
    host = extract_domain(url)
    if host not in _KNOWN_CDN_HOSTS:
        return host

    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]
    if not path_parts:
        return host

    filename = path_parts[-1]
    for ext in (".html", ".htm", ".php", ".asp", ".aspx"):
        if filename.lower().endswith(ext):
            candidate = filename[: -len(ext)]
            if _EMBEDDED_DOMAIN_RE.match(candidate):
                return candidate.lower()

    return host


def sanitize_path(path: str) -> str:
    """Resolve *path* and assert it stays within the process working directory.

    Raises:
        ValueError: If the resolved path escapes the allowed base directory,
                    indicating a directory-traversal attempt.
    """
    real = os.path.realpath(path)
    allowed_prefix = os.path.realpath(".")
    if not real.startswith(allowed_prefix + os.sep) and real != allowed_prefix:
        raise ValueError(f"Path traversal detected: {path!r} resolves to {real!r}")
    return real
