from urllib.parse import urlparse

from core.exceptions import InvalidURLError


def extract_domain(url: str) -> str:
    """Extract full hostname from URL (no port, lowercase)."""
    try:
        parsed = urlparse(url.strip())
        netloc = parsed.netloc or parsed.path
        return netloc.split(":")[0].lower()
    except Exception as exc:
        raise InvalidURLError(f"Cannot extract domain from: {url!r}") from exc


def extract_2ld(domain: str) -> str:
    """Return second-level domain label (e.g., 'example' from 'sub.example.com')."""
    parts = domain.lower().strip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False
