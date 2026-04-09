import hashlib
from urllib.parse import urlparse

from core.exceptions import InvalidURLError


def hash_email_body(email_body: str) -> str:
    """SHA-256 hash of email body. Never store raw email content (Ley 1581/2012)."""
    return hashlib.sha256(email_body.encode("utf-8")).hexdigest()


def sanitize_url(url: str) -> str:
    """Strip and validate URL scheme. Raises InvalidURLError on bad input."""
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise InvalidURLError(f"Forbidden URL scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise InvalidURLError(f"URL has no host: {url!r}")
    return url


def extract_domain(url: str) -> str:
    """Extract full domain (no port) from a URL."""
    if not isinstance(url, str):
        raise InvalidURLError(f"Cannot extract domain from: {url!r}")

    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            raise InvalidURLError(f"Forbidden URL scheme: {parsed.scheme!r}")
        hostname = parsed.hostname
        if not hostname:
            raise InvalidURLError(f"URL has no host: {url!r}")
        return hostname.lower()
    except ValueError as exc:
        raise InvalidURLError(f"Cannot extract domain from: {url!r}") from exc


def extract_2ld(domain: str) -> str:
    """Return second-level domain label (e.g., 'example' from 'sub.example.com')."""
    parts = domain.lower().strip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def is_punycode(domain: str) -> bool:
    """Return True if any label in the domain uses Punycode encoding."""
    return any(label.startswith("xn--") for label in domain.split("."))
