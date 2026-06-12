"""Tests for scripts/ingest_usb_baseline.py — anonimización PII (T10/T9)."""
from __future__ import annotations

from scripts.ingest_usb_baseline import anonymize_subject, url_domains


class TestAnonymizeSubject:
    def test_strips_personal_email(self):
        out = anonymize_subject("Reenvío de juan.perez@gmail.com sobre el caso")
        assert "@gmail.com" not in out
        assert "<EMAIL>" in out

    def test_strips_proper_names(self):
        out = anonymize_subject("Mensaje para Juan Pérez del decano")
        assert "Juan" not in out
        assert "<NOMBRE>" in out

    def test_strips_document_numbers(self):
        out = anonymize_subject("Factura 1234567 pendiente")
        assert "1234567" not in out

    def test_strips_amounts(self):
        out = anonymize_subject("Pago de $1.500.000 aprobado")
        assert "1.500.000" not in out

    def test_keeps_structural_words(self):
        out = anonymize_subject("Comunicado oficial de la universidad")
        assert "Comunicado" in out or "comunicado" in out.lower()

    def test_truncates_long_subject(self):
        out = anonymize_subject("palabra " * 60)
        assert len(out) <= 200


class TestUrlDomains:
    def test_extracts_domains_drops_paths(self):
        urls = [
            "https://usbbog.edu.co/intranet?token=secret123",
            "https://aula.usbbog.edu.co/login",
        ]
        domains = url_domains(urls)
        assert "usbbog.edu.co" in domains
        assert "aula.usbbog.edu.co" in domains
        assert all("token" not in d and "/" not in d for d in domains)

    def test_dedup_preserves_order(self):
        urls = ["https://a.com/x", "https://a.com/y", "https://b.com/z"]
        assert url_domains(urls) == ["a.com", "b.com"]

    def test_empty_list(self):
        assert url_domains([]) == []
