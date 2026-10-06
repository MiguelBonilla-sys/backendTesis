"""Run ONLY inside the isolated T33 container against its frozen application.

T33_ISOLATED=1 PYTHONPATH=/app:/tmp/t33-vendor-pure pytest /tmp/t33/test_properties.py --no-cov
These are characterization/security properties, not fixes or suppressed bugs.
"""
import hashlib
import ipaddress
import os
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

pytestmark = pytest.mark.skipif(os.getenv("T33_ISOLATED") != "1", reason="Opt-in isolated T33 container only")

settings.register_profile("t33", max_examples=250, derandomize=True, deadline=None)
settings.load_profile("t33")


@given(st.from_regex(r"[a-z]{1,20}", fullmatch=True), st.text(max_size=128))
def test_normalize_url_idempotent(host, fragment):
    from utils.url_parser import normalize_url
    normalized = normalize_url(f"https://{host}.example.test/a?x=1#{fragment}")
    assert normalize_url(normalized) == normalized
    assert "#" not in normalized


@given(st.text(max_size=2048))
def test_extracted_urls_have_http_scheme(text):
    from utils.url_parser import extract_urls_from_html, extract_urls_from_text
    for value in extract_urls_from_html(text) + extract_urls_from_text(text):
        assert value.lower().startswith(("https://", "http://"))


@given(st.text(alphabet=st.characters(blacklist_characters="\x00"), max_size=256))
def test_sanitized_paths_stay_in_working_directory(value):
    from utils.url_parser import sanitize_path
    try:
        result = sanitize_path(value)
    except (ValueError, OSError):
        return
    assert Path(result).is_relative_to(Path.cwd().resolve())


@given(st.text(alphabet="abcdef0123456789:", min_size=1, max_size=40))
def test_ip_recognition_matches_ipaddress(value):
    from utils.url_parser import is_ip_address
    try:
        ipaddress.ip_address(value)
        valid = True
    except ValueError:
        valid = False
    assert is_ip_address(value) == valid


@given(st.text(max_size=12000))
def test_raw_headers_do_not_raise_and_are_bounded(value):
    from utils.mail_forensics import from_raw, ALLOWED_HEADERS
    result = from_raw(value, "outlook-addin")
    assert len(result.headers) <= 90
    for name, content in result.headers:
        assert name in ALLOWED_HEADERS
        assert len(content) <= 1000
        assert "\r" not in content and "\n" not in content
    if result.origin_ip:
        assert ipaddress.ip_address(result.origin_ip).is_global


@given(st.text(alphabet=st.characters(blacklist_characters="\r\n"), max_size=1000))
def test_forensic_headers_exclude_recipients_and_dkim_signature(value):
    from utils.mail_forensics import from_raw
    result = from_raw(f"To: {value}\r\nCc: hidden@example.test\r\nBcc: hidden2@example.test\r\nDKIM-Signature: d=example.test; s=test; b=private_signature\r\n", "eml")
    assert all(name not in {"To", "Cc", "Bcc"} for name, _ in result.headers)
    assert "private_signature" not in (result.headers_json or "")


@given(st.integers(min_value=30, max_value=200))
def test_received_chain_bound_ignores_hops_after_thirty(count):
    from utils.mail_forensics import delivery_ip
    assert delivery_ip(["from internal ([10.0.0.1]) by receiver"] * count + ["from sender ([8.8.8.8]) by receiver"]) is None


@given(st.ip_addresses())
def test_delivery_ip_never_reports_private_address(ip):
    from utils.mail_forensics import delivery_ip
    result = delivery_ip([f"from sender ([{ip}]) by receiver"])
    assert result is None or ipaddress.ip_address(result).is_global


@given(st.binary(max_size=5000))
def test_eml_arbitrary_bytes_no_crash(content):
    from utils.email_parser import parse_eml
    result = parse_eml(content)
    assert result.email_hash == hashlib.sha256(content).hexdigest()
    assert result.authentication_verified is False


@given(st.text(alphabet=st.characters(blacklist_characters="\r\n", blacklist_categories=("Cs",)), max_size=500))
def test_eml_received_headers_share_bounded_parser(value):
    from utils.email_parser import parse_eml
    result = parse_eml(f"From: sender@example.test\r\nReceived: {value}\r\nTo: hidden@example.test\r\n\r\nSynthetic message".encode())
    assert all(name != "To" for name, _ in result.forensics.headers)
    assert result.authentication_verified is False
