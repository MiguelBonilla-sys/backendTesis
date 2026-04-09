"""Unit tests for agents/confusables_loader.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from agents.confusables_loader import (
    CONFUSABLE_SCRIPTS,
    ConfusablesCatalog,
    _hex_seq_to_str,
    char_script,
    detect_confusables,
    load_confusables,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
MINIMAL_CATALOG_PATH = FIXTURES_DIR / "confusables_minimal.txt"


# ── _hex_seq_to_str ────────────────────────────────────────────────────────────


def test_hex_seq_single_codepoint() -> None:
    assert _hex_seq_to_str("0061") == "a"


def test_hex_seq_cyrillic_a() -> None:
    assert _hex_seq_to_str("0430") == "\u0430"


def test_hex_seq_multi_codepoint() -> None:
    # Two codepoints: Latin A (0041) + combining accent (0301)
    result = _hex_seq_to_str("0041 0301")
    assert result == "\u0041\u0301"
    assert len(result) == 2


def test_hex_seq_invalid_raises() -> None:
    with pytest.raises(ValueError):
        _hex_seq_to_str("ZZZZ")


# ── load_confusables ───────────────────────────────────────────────────────────


def test_load_returns_empty_for_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent.txt"
    catalog = load_confusables(missing)
    assert catalog == {}


def test_load_minimal_catalog_nonempty() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert len(catalog) > 0


def test_load_cyrillic_a_in_catalog() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    cyrillic_a = "\u0430"  # CYRILLIC SMALL LETTER A
    assert cyrillic_a in catalog
    assert "a" in catalog[cyrillic_a]


def test_load_greek_omicron_in_catalog() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    greek_o = "\u03BF"  # GREEK SMALL LETTER OMICRON
    assert greek_o in catalog
    assert "o" in catalog[greek_o]


def test_load_skips_comment_lines() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    # Verify no key is a hash character (comment lines were parsed as data)
    assert "#" not in catalog


def test_load_accepts_path_string() -> None:
    catalog = load_confusables(str(MINIMAL_CATALOG_PATH))
    assert isinstance(catalog, dict)
    assert len(catalog) > 0


def test_load_custom_minimal_file(tmp_path: Path) -> None:
    f = tmp_path / "custom.txt"
    f.write_text("0430 ;\t0061 ;\tSA\t# Cyrillic a → Latin a\n", encoding="utf-8")
    catalog = load_confusables(f)
    assert "\u0430" in catalog
    assert "a" in catalog["\u0430"]


def test_load_ignores_malformed_lines(tmp_path: Path) -> None:
    f = tmp_path / "bad.txt"
    f.write_text("this is not a valid line\n0430 ;\t0061 ;\tSA\n", encoding="utf-8")
    catalog = load_confusables(f)
    # Only the valid line is parsed
    assert "\u0430" in catalog


# ── char_script ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("char,expected_script", [
    ("\u0430", "CYRILLIC"),   # Cyrillic а
    ("\u043E", "CYRILLIC"),   # Cyrillic о
    ("\u03B1", "GREEK"),      # Greek α
    ("\u03BF", "GREEK"),      # Greek ο
    ("a", "LATIN"),
    ("z", "LATIN"),
    ("0", "LATIN"),           # digit — not confusable script
])
def test_char_script(char: str, expected_script: str) -> None:
    assert char_script(char) == expected_script


def test_confusable_scripts_frozenset_immutable() -> None:
    assert isinstance(CONFUSABLE_SCRIPTS, frozenset)
    assert "CYRILLIC" in CONFUSABLE_SCRIPTS
    assert "GREEK" in CONFUSABLE_SCRIPTS
    assert "ARMENIAN" in CONFUSABLE_SCRIPTS


# ── detect_confusables ─────────────────────────────────────────────────────────


def test_detect_pure_latin_returns_empty() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert detect_confusables("paypal.com", catalog) == []


def test_detect_cyrillic_a_in_paypal() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    # "pаypal.com" — position 1 is Cyrillic а (U+0430)
    domain = "p\u0430ypal.com"
    result = detect_confusables(domain, catalog)
    assert len(result) == 1
    entry = result[0]
    assert entry["char"] == "\u0430"
    assert entry["position"] == 1
    assert entry["script"] == "Cyrillic"
    assert entry["lookalike"] == "a"


def test_detect_multiple_confusables() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    # "pаypаl" — Cyrillic а at positions 1 and 4
    domain = "p\u0430yp\u0430l.com"
    result = detect_confusables(domain, catalog)
    assert len(result) == 2
    positions = {e["position"] for e in result}
    assert positions == {1, 4}


def test_detect_greek_omicron_in_google() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    domain = "g\u03BF\u03BFgle.com"
    result = detect_confusables(domain, catalog)
    assert len(result) == 2
    for entry in result:
        assert entry["char"] == "\u03BF"
        assert entry["script"] == "Greek"
        assert entry["lookalike"] == "o"


def test_detect_with_empty_catalog_uses_heuristic() -> None:
    # With empty catalog the heuristic fires: lookalike=None
    domain = "p\u0430ypal.com"
    result = detect_confusables(domain, {})
    assert len(result) == 1
    assert result[0]["char"] == "\u0430"
    assert result[0]["lookalike"] is None  # heuristic — no catalog entry


def test_detect_skips_dots_and_hyphens() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    # Dots and hyphens must never be reported as confusables
    result = detect_confusables("sub.domain-name.com", catalog)
    assert result == []


def test_detect_returns_list_of_dicts() -> None:
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    result = detect_confusables("p\u0430ypal.com", catalog)
    assert isinstance(result, list)
    assert all(isinstance(e, dict) for e in result)
    required_keys = {"char", "position", "script", "lookalike"}
    for entry in result:
        assert required_keys.issubset(entry.keys())
