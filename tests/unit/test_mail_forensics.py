import json
from pathlib import Path

import pytest

from utils import mail_forensics as mf
from utils.email_parser import parse_eml

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "forensics"


def _raw(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_gmail_delivery_ip_skips_internal_hops_and_lower_declarations():
    f = mf.from_raw(_raw("gmail_to_gmail.headers"), "outlook-addin")
    assert f.header_source == "outlook-addin"
    assert f.origin_ip == "209.85.220.41"
    assert f.message_id == "<CAF1234567890@mail.gmail.com>"
    assert f.mail_date.isoformat() == "2026-10-05T12:14:57-05:00"


def test_allowlist_drops_recipients_and_unknown_headers():
    f = mf.from_raw(_raw("gmail_to_gmail.headers"), "gmail-original")
    names = {name for name, _ in f.headers}
    assert {"Received", "From", "Message-ID", "DKIM-Signature"} <= names
    assert not names & {"To", "Cc", "Subject", "X-Custom-Tracking", "X-Received"}
    dkim = dict(f.headers)["DKIM-Signature"]
    assert dkim == "d=example.org; s=sel1"
    assert json.loads(f.headers_json) == f.headers


def test_spoofed_lower_hop_is_not_trusted_and_bad_date_is_none():
    f = mf.from_raw(_raw("spoofed_received.headers"), "outlook-addin")
    assert f.origin_ip == "185.220.101.5"
    assert f.mail_date is None


def test_minimal_and_empty_inputs_never_raise():
    f = mf.from_raw(_raw("minimal.headers"), "gmail-original")
    assert f.origin_ip is None and f.message_id is None and f.headers == []
    assert f.headers_json is None
    assert mf.from_raw(None, "outlook-addin").header_source == "none"
    assert mf.from_raw("Received: x", None).header_source == "none"


@pytest.mark.parametrize("hop,expected", [
    ("from a (a [IPv6:2001:4860:4864:20::2b]) by mx", "2001:4860:4864:20::2b"),
    ("from a (1.1.1.1) by mx", "1.1.1.1"),
    ("from a [192.168.0.10] by mx", None),
    ("from a [999.1.1.1] by mx", None),
    ("by mx.google.com with SMTP", None),
])
def test_delivery_ip_patterns(hop, expected):
    assert mf.delivery_ip([hop]) == expected


def test_parser_is_bounded_for_huge_input():
    hostile = "Received: from x " + "[" * 200_000 + "\n"
    f = mf.from_raw(hostile * 3, "gmail-original")
    assert f.origin_ip is None


def test_parse_eml_attaches_eml_forensics():
    raw = _raw("gmail_to_gmail.headers") + "\nHola, revisa https://example.org/login\n"
    parsed = parse_eml(raw.encode())
    assert parsed.forensics.header_source == "eml"
    assert parsed.forensics.origin_ip == "209.85.220.41"
