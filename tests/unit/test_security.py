"""Tests for core/security.py — input validation and hashing."""

import pytest

from core.exceptions import InvalidURLError
from core.security import (
    extract_2ld,
    extract_domain,
    hash_email_body,
    is_punycode,
    sanitize_url,
)


def test_hash_email_body_returns_sha256():
    digest = hash_email_body("test email body")
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_hash_email_body_deterministic():
    assert hash_email_body("same") == hash_email_body("same")


def test_hash_email_body_different_inputs():
    assert hash_email_body("a") != hash_email_body("b")


def test_sanitize_url_valid():
    assert sanitize_url("https://apple.com") == "https://apple.com"
    assert sanitize_url("http://example.com/path") == "http://example.com/path"


def test_sanitize_url_strips_whitespace():
    assert sanitize_url("  https://apple.com  ") == "https://apple.com"


def test_sanitize_url_rejects_bad_scheme():
    with pytest.raises(InvalidURLError):
        sanitize_url("ftp://evil.com")

    with pytest.raises(InvalidURLError):
        sanitize_url("javascript:alert(1)")


def test_sanitize_url_rejects_no_host():
    with pytest.raises(InvalidURLError):
        sanitize_url("https://")


def test_extract_domain_basic():
    assert extract_domain("https://apple.com/path") == "apple.com"
    assert extract_domain("http://sub.example.co.uk") == "sub.example.co.uk"


def test_extract_domain_strips_port():
    assert extract_domain("http://localhost:8000/api") == "localhost"


def test_extract_domain_with_userinfo():
    assert extract_domain("http://user:pass@example.com:8080/path") == "example.com"


def test_extract_domain_ipv6_host():
    assert extract_domain("http://[2001:db8::1]:8080/path") == "2001:db8::1"


def test_extract_domain_invalid_type():
    with pytest.raises(InvalidURLError):
        extract_domain(None)  # type: ignore[arg-type]


def test_extract_domain_invalid_ipv6_url():
    with pytest.raises(InvalidURLError):
        extract_domain("http://[::1")


def test_extract_2ld_basic():
    assert extract_2ld("sub.example.com") == "example"
    assert extract_2ld("apple.com") == "apple"


def test_extract_2ld_single_label():
    assert extract_2ld("localhost") == "localhost"


def test_is_punycode_true():
    assert is_punycode("xn--pple-43d.com") is True
    assert is_punycode("sub.xn--nxasmq6b.com") is True


def test_is_punycode_false():
    assert is_punycode("apple.com") is False
    assert is_punycode("google.com") is False
