"""Tests for core/redaction.py"""
from core.redaction import redact


class TestRedact:
    def test_empty_and_none(self):
        assert redact("") == ""
        assert redact(None) == ""

    def test_masks_email(self):
        out = redact("Contacta a juan.perez@usb.edu.co ya")
        assert "juan.perez@usb.edu.co" not in out
        assert "[EMAIL_1]" in out

    def test_masks_phone_with_separators(self):
        out = redact("Llama al +57 300 123 4567")
        assert "300 123 4567" not in out
        assert "[PHONE_1]" in out

    def test_masks_bare_id_sequence(self):
        out = redact("CC 1032456789 vigente")
        assert "1032456789" not in out
        assert "[ID_1]" in out

    def test_masks_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4"
        out = redact(f"token={jwt}")
        assert jwt not in out
        assert "[TOKEN_1]" in out

    def test_masks_prefixed_key(self):
        out = redact("key sk-ABCDEFGHIJKLMNOP1234 leaked")
        assert "sk-ABCDEFGHIJKLMNOP1234" not in out
        assert "[TOKEN_1]" in out

    def test_coreference_is_stable(self):
        out = redact("a@b.com dice que a@b.com miente")
        assert out.count("[EMAIL_1]") == 2

    def test_distinct_values_get_distinct_placeholders(self):
        out = redact("a@b.com y c@d.com")
        assert "[EMAIL_1]" in out and "[EMAIL_2]" in out

    def test_urls_and_domains_survive(self):
        text = "Visita https://xn--pypal-4ve.com/login en paypal-secure.com"
        out = redact(text)
        assert "xn--pypal-4ve.com/login" in out
        assert "paypal-secure.com" in out

    def test_plain_text_untouched(self):
        text = "Your account has been suspended. Click to verify."
        assert redact(text) == text
