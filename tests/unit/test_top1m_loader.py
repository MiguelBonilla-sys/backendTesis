"""Tests for data_pipeline/top1m_loader.py — Phase 4 coverage gap fix."""

from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from data_pipeline.top1m_loader import load_top1m


# ── Missing file ──────────────────────────────────────────────────────────────

def test_load_missing_file_returns_empty(tmp_path: Path) -> None:
    """Non-existent path → [] with a warning, no exception."""
    result = load_top1m(tmp_path / "nonexistent.txt")
    assert result == []


# ── Basic extraction ──────────────────────────────────────────────────────────

def test_load_extracts_2ld(tmp_path: Path) -> None:
    """FQDNs → 2LD labels extracted correctly (loader uses parts[-2], not eTLD)."""
    f = tmp_path / "top1m.txt"
    f.write_text("google.com\napple.com\namazon.com\n", encoding="utf-8")
    result = load_top1m(f)
    assert result == ["google", "apple", "amazon"]


def test_load_single_label_domain(tmp_path: Path) -> None:
    """Single-label hostname (no dot) → returns the label itself."""
    f = tmp_path / "top1m.txt"
    f.write_text("localhost\n", encoding="utf-8")
    result = load_top1m(f)
    assert result == ["localhost"]


def test_load_subdomain_uses_second_to_last_part(tmp_path: Path) -> None:
    """Deep FQDN like 'a.b.example.com' → 2LD is 'example'."""
    f = tmp_path / "top1m.txt"
    f.write_text("a.b.example.com\n", encoding="utf-8")
    result = load_top1m(f)
    assert result == ["example"]


# ── Deduplication ─────────────────────────────────────────────────────────────

def test_load_deduplicates_same_2ld(tmp_path: Path) -> None:
    """Two FQDNs with the same 2LD → only one entry, first rank wins."""
    f = tmp_path / "top1m.txt"
    f.write_text("mail.google.com\nwww.google.com\nyahoo.com\n", encoding="utf-8")
    result = load_top1m(f)
    assert result.count("google") == 1
    assert result == ["google", "yahoo"]


# ── limit parameter ───────────────────────────────────────────────────────────

def test_load_limit_stops_early(tmp_path: Path) -> None:
    """limit=2 returns at most 2 unique 2LDs."""
    f = tmp_path / "top1m.txt"
    f.write_text("a.com\nb.com\nc.com\nd.com\n", encoding="utf-8")
    result = load_top1m(f, limit=2)
    assert result == ["a", "b"]


def test_load_limit_none_returns_all(tmp_path: Path) -> None:
    """limit=None (default) returns all entries."""
    f = tmp_path / "top1m.txt"
    f.write_text("a.com\nb.com\nc.com\n", encoding="utf-8")
    result = load_top1m(f)
    assert len(result) == 3


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_load_skips_empty_lines(tmp_path: Path) -> None:
    """Empty lines in the file are silently ignored."""
    f = tmp_path / "top1m.txt"
    f.write_text("google.com\n\n\napple.com\n", encoding="utf-8")
    result = load_top1m(f)
    assert result == ["google", "apple"]


def test_load_lowercases_domains(tmp_path: Path) -> None:
    """FQDNs are lowercased before 2LD extraction."""
    f = tmp_path / "top1m.txt"
    f.write_text("GOOGLE.COM\n", encoding="utf-8")
    result = load_top1m(f)
    assert result == ["google"]


def test_load_preserves_rank_order(tmp_path: Path) -> None:
    """Output preserves the file's rank order (rank 1 first)."""
    f = tmp_path / "top1m.txt"
    f.write_text("z.com\na.com\nm.com\n", encoding="utf-8")
    result = load_top1m(f)
    assert result == ["z", "a", "m"]


# ── OSError handling ──────────────────────────────────────────────────────────

def test_load_oserror_returns_empty(tmp_path: Path) -> None:
    """OSError while reading file → [] returned, no exception propagated."""
    f = tmp_path / "top1m.txt"
    f.write_text("google.com\n", encoding="utf-8")

    with patch("builtins.open", side_effect=OSError("permission denied")):
        result = load_top1m(f)

    assert result == []
