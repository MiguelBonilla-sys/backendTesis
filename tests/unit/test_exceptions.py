"""Tests for core/exceptions.py"""
from __future__ import annotations

import pytest

from core.exceptions import (
    AuthenticationError,
    DatabaseError,
    IDNAnalysisError,
    LLMTimeoutError,
    PhishingDetectorError,
    ThreatIntelError,
)


class TestPhishingDetectorError:
    def test_base_exception_message(self):
        exc = PhishingDetectorError("Base error")
        assert exc.message == "Base error"
        assert exc.detail == ""

    def test_base_exception_with_detail(self):
        exc = PhishingDetectorError("Base error", "some detail")
        assert exc.detail == "some detail"

    def test_repr_contains_class_name(self):
        exc = PhishingDetectorError("msg", "det")
        assert "PhishingDetectorError" in repr(exc)

    def test_is_exception_subclass(self):
        exc = PhishingDetectorError("test")
        assert isinstance(exc, Exception)


class TestIDNAnalysisError:
    def test_inherits_from_base(self):
        exc = IDNAnalysisError("IDN failed")
        assert isinstance(exc, PhishingDetectorError)

    def test_message_stored(self):
        exc = IDNAnalysisError("IDN analysis failed for domain.com", "parse error")
        assert exc.message == "IDN analysis failed for domain.com"
        assert exc.detail == "parse error"

    def test_can_be_raised_and_caught(self):
        with pytest.raises(IDNAnalysisError) as exc_info:
            raise IDNAnalysisError("test", "detail")
        assert exc_info.value.message == "test"


class TestLLMTimeoutError:
    def test_inherits_from_base(self):
        exc = LLMTimeoutError("LLM timeout")
        assert isinstance(exc, PhishingDetectorError)

    def test_message_stored(self):
        exc = LLMTimeoutError("Timeout after 10s")
        assert exc.message == "Timeout after 10s"

    def test_can_be_raised_and_caught(self):
        with pytest.raises(LLMTimeoutError):
            raise LLMTimeoutError("timeout", "url=test")


class TestThreatIntelError:
    def test_inherits_from_base(self):
        exc = ThreatIntelError("TI failed")
        assert isinstance(exc, PhishingDetectorError)

    def test_message_and_detail(self):
        exc = ThreatIntelError("VT API failed", "HTTP 429")
        assert exc.message == "VT API failed"
        assert exc.detail == "HTTP 429"


class TestAuthenticationError:
    def test_inherits_from_base(self):
        exc = AuthenticationError("Invalid token")
        assert isinstance(exc, PhishingDetectorError)

    def test_message_stored(self):
        exc = AuthenticationError("Invalid or expired token", "jwt error")
        assert "token" in exc.message


class TestDatabaseError:
    def test_inherits_from_base(self):
        exc = DatabaseError("DB failed")
        assert isinstance(exc, PhishingDetectorError)

    def test_can_chain_from_another_exception(self):
        original = ValueError("original")
        try:
            raise DatabaseError("DB error", "pool timeout") from original
        except DatabaseError as exc:
            assert exc.__cause__ is original
