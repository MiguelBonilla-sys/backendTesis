"""Tests for utils/email_parser.py"""
from __future__ import annotations

import hashlib

import pytest

from utils.email_parser import (
    ParsedEmail,
    _detect_urgency,
    _extract_email_domain,
    _parse_auth_results,
    _strip_html,
    parse_eml,
)

# ---------------------------------------------------------------------------
# Minimal .eml fixtures
# ---------------------------------------------------------------------------

_EML_SIMPLE = b"""\
From: "Test Sender" <sender@evil.com>
To: victim@gmail.com
Subject: Test phishing email
Return-Path: <bounce@different.com>
Content-Type: text/html; charset="UTF-8"

<html><body>
<a href="https://phishing.evil.com/login">Click here</a>
<a href="https://storage.googleapis.com/bucket123/badsite.com.html">Prize</a>
</body></html>
"""

_EML_URGENT = b"""\
From: admin@bank.com
To: user@example.com
Subject: URGENTE: Su cuenta ha sido suspendida
Return-Path: <admin@bank.com>
Authentication-Results: mx.example.com; dkim=pass; spf=pass
Content-Type: text/plain; charset="UTF-8"

Actua ahora. Su cuenta sera bloqueada. https://verify-bank.example.com/now
"""

_EML_MULTIPART = b"""\
From: legit@company.com
To: employee@company.com
Subject: Quarterly Report
Return-Path: <legit@company.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="UTF-8"

Please find the report at https://reports.company.com/q4

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="report.exe"

<binary content>
--boundary123--
"""

_EML_NO_URLS = b"""\
From: friend@example.com
To: me@example.com
Subject: Hello
Return-Path: <friend@example.com>
Content-Type: text/plain

Just saying hi, no links here.
"""


# ---------------------------------------------------------------------------
# parse_eml — core extraction
# ---------------------------------------------------------------------------

class TestParseEml:
    def test_returns_parsed_email_instance(self):
        result = parse_eml(_EML_SIMPLE)
        assert isinstance(result, ParsedEmail)

    def test_extracts_urls_from_html_body(self):
        result = parse_eml(_EML_SIMPLE)
        assert any("phishing.evil.com" in u for u in result.urls)

    def test_extracts_gcs_url(self):
        result = parse_eml(_EML_SIMPLE)
        assert any("storage.googleapis.com" in u for u in result.urls)

    def test_deduplicates_urls_by_normalized_form(self):
        eml = b"""\
From: a@b.com
To: c@d.com
Subject: Test
Content-Type: text/html

<a href="https://evil.com/page#tracker1">1</a>
<a href="https://evil.com/page#tracker2">2</a>
<a href="https://evil.com/page#tracker3">3</a>
"""
        result = parse_eml(eml)
        # All three point to same normalized URL — should be deduplicated to 1
        assert len([u for u in result.urls if "evil.com/page" in u]) == 1

    def test_sha256_hash_computed(self):
        result = parse_eml(_EML_SIMPLE)
        expected = hashlib.sha256(_EML_SIMPLE).hexdigest()
        assert result.email_hash == expected

    def test_sender_domain_extracted(self):
        result = parse_eml(_EML_SIMPLE)
        assert result.sender_domain == "evil.com"

    def test_return_path_domain_extracted(self):
        result = parse_eml(_EML_SIMPLE)
        assert result.return_path_domain == "different.com"

    def test_sender_domain_mismatch_detected(self):
        result = parse_eml(_EML_SIMPLE)
        assert result.sender_domain_mismatch is True

    def test_no_mismatch_when_domains_match(self):
        result = parse_eml(_EML_URGENT)
        assert result.sender_domain_mismatch is False

    def test_subject_extracted(self):
        result = parse_eml(_EML_SIMPLE)
        assert "Test phishing email" in result.subject

    def test_no_urls_returns_empty_list(self):
        result = parse_eml(_EML_NO_URLS)
        assert result.urls == []

    def test_attachment_names_collected(self):
        result = parse_eml(_EML_MULTIPART)
        assert "report.exe" in result.attachment_names

    def test_suspicious_attachment_flagged(self):
        result = parse_eml(_EML_MULTIPART)
        assert result.has_suspicious_attachments is True

    def test_no_suspicious_attachments_for_clean_email(self):
        result = parse_eml(_EML_URGENT)
        assert result.has_suspicious_attachments is False


# ---------------------------------------------------------------------------
# Urgency detection
# ---------------------------------------------------------------------------

class TestDetectUrgency:
    def test_urgency_keyword_in_subject_detected(self):
        is_urgent, score = _detect_urgency("URGENTE: Actua ahora", "")
        assert is_urgent is True
        assert score > 0.0

    def test_urgency_keyword_in_body_detected(self):
        is_urgent, score = _detect_urgency("Hello", "Your account is suspended urgente")
        assert is_urgent is True

    def test_no_urgency_in_clean_email(self):
        is_urgent, score = _detect_urgency("Quarterly report", "Please find attached the report.")
        assert is_urgent is False
        assert score == 0.0

    def test_score_increases_with_more_keywords(self):
        _, score_one = _detect_urgency("urgent", "")
        _, score_many = _detect_urgency("urgent act now immediately", "account suspended verify now")
        assert score_many > score_one

    def test_score_capped_at_one(self):
        # Stuff with many keywords — score must not exceed 1.0
        text = " ".join(["urgente", "act now", "immediately", "suspended", "verify now", "urgent"])
        _, score = _detect_urgency(text, text)
        assert score <= 1.0

    def test_urgency_detected_in_eml_subject(self):
        result = parse_eml(_EML_URGENT)
        assert result.is_urgent is True


# ---------------------------------------------------------------------------
# Auth results parsing
# ---------------------------------------------------------------------------

class TestParseAuthResults:
    def test_spf_pass_detected(self):
        import email
        raw = b"Authentication-Results: mx.example.com; spf=pass\n\nBody"
        msg = email.message_from_bytes(raw)
        spf_pass, _ = _parse_auth_results(msg)
        assert spf_pass is True

    def test_dkim_pass_detected(self):
        import email
        raw = b"Authentication-Results: mx.example.com; dkim=pass\n\nBody"
        msg = email.message_from_bytes(raw)
        _, dkim_pass = _parse_auth_results(msg)
        assert dkim_pass is True

    def test_spf_fail_not_pass(self):
        import email
        raw = b"Authentication-Results: mx.example.com; spf=fail\n\nBody"
        msg = email.message_from_bytes(raw)
        spf_pass, _ = _parse_auth_results(msg)
        assert spf_pass is False

    def test_no_auth_headers_returns_false(self):
        import email
        raw = b"From: a@b.com\n\nBody"
        msg = email.message_from_bytes(raw)
        spf_pass, dkim_pass = _parse_auth_results(msg)
        assert spf_pass is False
        assert dkim_pass is False

    def test_received_spf_fallback(self):
        import email
        raw = b"Received-SPF: pass (google.com: domain of sender@example.com)\n\nBody"
        msg = email.message_from_bytes(raw)
        spf_pass, _ = _parse_auth_results(msg)
        assert spf_pass is True


# ---------------------------------------------------------------------------
# Strip HTML helper
# ---------------------------------------------------------------------------

class TestStripHtml:
    def test_removes_tags(self):
        result = _strip_html("<p>Hello <b>world</b></p>")
        assert "<" not in result
        assert "Hello" in result
        assert "world" in result

    def test_unescapes_entities(self):
        result = _strip_html("&lt;script&gt; &amp; &quot;")
        assert "&lt;" not in result
        assert "<" in result

    def test_empty_string(self):
        assert _strip_html("") == ""


# ---------------------------------------------------------------------------
# Domain extraction helper
# ---------------------------------------------------------------------------

class TestExtractEmailDomain:
    def test_extracts_from_angle_brackets(self):
        assert _extract_email_domain("<user@paypal.com>") == "paypal.com"

    def test_extracts_from_plain_address(self):
        assert _extract_email_domain("user@example.org") == "example.org"

    def test_extracts_from_display_name_format(self):
        assert _extract_email_domain('"John Doe" <john@company.co.uk>') == "company.co.uk"

    def test_returns_empty_for_no_domain(self):
        assert _extract_email_domain("no email here") == ""

    def test_lowercase_result(self):
        assert _extract_email_domain("User@PAYPAL.COM") == "paypal.com"
