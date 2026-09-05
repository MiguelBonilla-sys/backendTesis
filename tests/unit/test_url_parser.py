"""Tests for utils/url_parser.py"""
from __future__ import annotations

import pytest

from utils.url_parser import (
    extract_2ld,
    extract_domain,
    extract_effective_domain,
    extract_idn_label,
    extract_registrable_domain,
    extract_urls_from_html,
    extract_urls_from_text,
    is_ip_address,
    is_shared_hosting_subdomain,
    normalize_url,
    sanitize_path,
)


class TestExtractDomain:
    def test_https_url(self):
        assert extract_domain("https://paypal.com/login") == "paypal.com"

    def test_http_url(self):
        assert extract_domain("http://paypal.com") == "paypal.com"

    def test_subdomain_preserved(self):
        assert extract_domain("https://login.paypal.com/auth") == "login.paypal.com"

    def test_port_stripped(self):
        assert extract_domain("https://paypal.com:8080/page") == "paypal.com"

    def test_ip_address(self):
        assert extract_domain("http://192.168.1.1/page") == "192.168.1.1"

    def test_lowercase_result(self):
        assert extract_domain("HTTPS://PAYPAL.COM") == "paypal.com"

    def test_cyrillic_domain(self):
        cyrillic_p = chr(0x0440)
        url = f"https://{cyrillic_p}aypal.com/login"
        result = extract_domain(url)
        assert "com" in result or cyrillic_p in result

    def test_url_with_path_and_query(self):
        result = extract_domain("https://paypal.com/login?next=/dashboard")
        assert result == "paypal.com"


class TestExtract2ld:
    def test_extracts_second_level_domain(self):
        assert extract_2ld("login.paypal.com") == "paypal"

    def test_bare_domain(self):
        assert extract_2ld("paypal.com") == "paypal"

    def test_single_label(self):
        assert extract_2ld("localhost") == "localhost"

    def test_ip_address_returns_unchanged(self):
        assert extract_2ld("192.168.1.1") == "192.168.1.1"

    def test_lowercase_applied(self):
        assert extract_2ld("PayPal.COM") == "paypal"

    def test_trailing_dot_stripped(self):
        assert extract_2ld("paypal.com.") == "paypal"

    def test_deep_subdomain(self):
        assert extract_2ld("a.b.c.paypal.com") == "paypal"

    @pytest.mark.parametrize(
        ("domain", "label"),
        [
            ("portal.academia.usbbog.edu.co", "usbbog"),
            ("login.usbbоg.edu.co", "usbbоg"),  # Cyrillic о
            ("WWW.BBC.CO.UK.", "bbc"),
            ("login.evil.co.uk", "evil"),
            ("[::1]", "[::1]"),
            ("", ""),
        ],
    )
    def test_registrant_label_with_known_compound_suffixes(self, domain, label):
        assert extract_2ld(domain) == label


class TestHostingDomains:
    @pytest.mark.parametrize(
        ("domain", "shared", "label"),
        [
            ("оutlоок-098.vercel.app", True, "оutlоок-098"),
            ("LOGIN.ATTACKER.VERCEL.APP.", True, "login"),
            ("evilpaypal.github.io", True, "evilpaypal"),
            ("vercel.app", False, "vercel"),
            ("fakevercel.app", False, "fakevercel"),
            ("vercel.app.attacker.com", False, "attacker"),
            ("portal.usbbоg.edu.co", False, "usbbоg"),
        ],
    )
    def test_hosting_boundary_and_analysis_label(self, domain, shared, label):
        assert is_shared_hosting_subdomain(domain) is shared
        assert extract_idn_label(domain) == label


class TestExtractRegistrableDomain:
    def test_bare_domain_unchanged(self):
        assert extract_registrable_domain("paypal.com") == "paypal.com"

    def test_subdomain_stripped(self):
        assert extract_registrable_domain("login.paypal.com") == "paypal.com"

    def test_deep_subdomain(self):
        assert (
            extract_registrable_domain("email.mg.abdataclassactionmail.com")
            == "abdataclassactionmail.com"
        )

    def test_two_level_suffix_edu_co(self):
        assert (
            extract_registrable_domain("portal.academia.usbbog.edu.co")
            == "usbbog.edu.co"
        )

    def test_two_level_suffix_co_uk(self):
        assert extract_registrable_domain("www.bbc.co.uk") == "bbc.co.uk"

    def test_plain_co_is_single_tld(self):
        # `.co` solo (no `.com.co`) → eTLD+1 son los dos últimos labels
        assert extract_registrable_domain("shop.mercadolibre.co") == "mercadolibre.co"

    def test_lowercase_and_trailing_dot(self):
        assert extract_registrable_domain("Login.PayPal.COM.") == "paypal.com"

    def test_ip_unchanged(self):
        assert extract_registrable_domain("192.168.1.1") == "192.168.1.1"

    def test_single_label_unchanged(self):
        assert extract_registrable_domain("localhost") == "localhost"


class TestIsIpAddress:
    def test_valid_ipv4(self):
        assert is_ip_address("192.168.1.1") is True

    def test_valid_ipv4_loopback(self):
        assert is_ip_address("127.0.0.1") is True

    def test_regular_domain_not_ip(self):
        assert is_ip_address("paypal.com") is False

    def test_partial_ip_not_ip(self):
        assert is_ip_address("192.168.1") is False

    def test_ipv6_in_brackets(self):
        assert is_ip_address("[::1]") is True

    def test_empty_string_not_ip(self):
        assert is_ip_address("") is False


class TestExtractUrlsFromText:
    def test_extracts_single_https_url(self):
        text = "Visit https://paypal.com for info"
        urls = extract_urls_from_text(text)
        assert "https://paypal.com" in urls

    def test_extracts_multiple_urls(self):
        text = "See https://paypal.com and http://google.com"
        urls = extract_urls_from_text(text)
        assert len(urls) == 2

    def test_no_urls_returns_empty(self):
        assert extract_urls_from_text("no URLs here") == []

    def test_ftp_url_not_extracted(self):
        urls = extract_urls_from_text("ftp://paypal.com is not http")
        assert not any("ftp" in u for u in urls)

    def test_url_in_html_text(self):
        text = 'Click <a href="https://paypal.com">here</a>'
        urls = extract_urls_from_text(text)
        assert "https://paypal.com" in urls


class TestExtractEffectiveDomain:
    def test_gcs_bucket_abuse_extracts_embedded_domain(self):
        url = "https://storage.googleapis.com/bucket123/evil.com.html"
        assert extract_effective_domain(url) == "evil.com"

    def test_real_phishing_eml_url(self):
        url = (
            "https://storage.googleapis.com/xhr09fe05fe2026/"
            "optimisticdigital.xyz.html#tracker"
        )
        assert extract_effective_domain(url) == "optimisticdigital.xyz"

    def test_non_cdn_url_returns_host(self):
        assert extract_effective_domain("https://paypal.com/login") == "paypal.com"

    def test_subdomain_non_cdn_returns_full_host(self):
        assert extract_effective_domain("https://login.paypal.com/auth") == "login.paypal.com"

    def test_gcs_without_domain_filename_returns_host(self):
        # "report" is not a domain — no embedded domain detected
        url = "https://storage.googleapis.com/bucket/report.html"
        assert extract_effective_domain(url) == "storage.googleapis.com"

    def test_gcs_empty_path_returns_host(self):
        assert extract_effective_domain("https://storage.googleapis.com/") == "storage.googleapis.com"

    def test_s3_abuse_pattern(self):
        url = "https://s3.amazonaws.com/mybucket/phishing-target.com.html"
        assert extract_effective_domain(url) == "phishing-target.com"

    def test_result_is_lowercase(self):
        url = "https://storage.googleapis.com/bucket/EVIL.COM.html"
        assert extract_effective_domain(url) == "evil.com"

    def test_non_html_extension_returns_host(self):
        # .pdf extension not in the CDN strip list
        url = "https://storage.googleapis.com/bucket/evil.com.pdf"
        assert extract_effective_domain(url) == "storage.googleapis.com"


class TestNormalizeUrl:
    def test_strips_fragment(self):
        url = "https://evil.com/page#tracker123abc"
        assert normalize_url(url) == "https://evil.com/page"

    def test_no_fragment_unchanged(self):
        url = "https://paypal.com/login"
        assert normalize_url(url) == url

    def test_preserves_query_string(self):
        url = "https://evil.com/page?id=1#frag"
        assert normalize_url(url) == "https://evil.com/page?id=1"

    def test_empty_fragment_stripped(self):
        url = "https://evil.com/page#"
        assert normalize_url(url) == "https://evil.com/page"


class TestExtractUrlsFromHtml:
    def test_extracts_href(self):
        html = '<a href="https://phishing.com/login">Click</a>'
        urls = extract_urls_from_html(html)
        assert "https://phishing.com/login" in urls

    def test_extracts_src(self):
        html = '<img src="https://tracker.evil.com/pixel.gif">'
        urls = extract_urls_from_html(html)
        assert "https://tracker.evil.com/pixel.gif" in urls

    def test_extracts_multiple_hrefs(self):
        html = (
            '<a href="https://a.com">1</a>'
            '<a href="https://b.com">2</a>'
        )
        urls = extract_urls_from_html(html)
        assert len(urls) == 2

    def test_no_links_returns_empty(self):
        html = "<p>No links here</p>"
        assert extract_urls_from_html(html) == []

    def test_stops_at_closing_quote(self):
        html = '<a href="https://evil.com/path">text</a>'
        urls = extract_urls_from_html(html)
        assert urls == ["https://evil.com/path"]


class TestSanitizePath:
    def test_valid_relative_path_within_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        subdir = tmp_path / "sub"
        subdir.mkdir()
        result = sanitize_path(str(subdir))
        assert "sub" in result

    def test_path_traversal_raises(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="Path traversal"):
            sanitize_path("/etc/passwd")

    def test_current_dir_path_allowed(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # "." resolves to cwd itself — allowed
        result = sanitize_path(str(tmp_path))
        assert result == str(tmp_path)
