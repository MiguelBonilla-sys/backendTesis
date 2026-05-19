"""URL and domain parsing utilities with path-traversal protection."""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

# Regex used to extract http/https URLs from free-form text
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Simple IPv4 pattern
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv6 pattern (bare, not including port brackets)
_IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")


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
