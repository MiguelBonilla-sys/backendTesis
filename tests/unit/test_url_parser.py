"""Tests for utils/url_parser.py."""

import pytest

from core.exceptions import InvalidURLError
from utils.url_parser import extract_2ld, extract_domain, is_valid_url


def test_extract_domain_https():
    assert extract_domain("https://apple.com/login") == "apple.com"


def test_extract_domain_subdomain():
    assert extract_domain("https://mail.google.com/inbox") == "mail.google.com"


def test_extract_domain_strips_port():
    assert extract_domain("http://localhost:8000") == "localhost"


def test_extract_domain_with_userinfo():
    assert extract_domain("http://user:pass@example.com:8080/path") == "example.com"


def test_extract_domain_ipv6_host():
    assert extract_domain("http://[2001:db8::1]:8080/path") == "2001:db8::1"


def test_extract_domain_invalid_url():
    with pytest.raises(InvalidURLError):
        extract_domain("not-a-url-!@#$%")


def test_extract_domain_invalid_type():
    with pytest.raises(InvalidURLError):
        extract_domain(None)  # type: ignore[arg-type]


def test_extract_domain_invalid_ipv6_url():
    with pytest.raises(InvalidURLError):
        extract_domain("http://[::1")


def test_extract_2ld_common():
    assert extract_2ld("apple.com") == "apple"
    assert extract_2ld("sub.apple.com") == "apple"
    assert extract_2ld("deep.sub.apple.com") == "apple"


def test_extract_2ld_single():
    assert extract_2ld("localhost") == "localhost"


def test_is_valid_url_true():
    assert is_valid_url("https://apple.com") is True
    assert is_valid_url("http://example.com/path?q=1") is True


def test_is_valid_url_false():
    assert is_valid_url("ftp://evil.com") is False
    assert is_valid_url("not-a-url") is False
    assert is_valid_url("") is False
