"""Tests for agents/confusables_loader.py"""
from __future__ import annotations

import pytest

from agents.confusables_loader import (
    CONFUSABLE_SCRIPTS,
    detect_confusables,
    is_mixed_script,
    load_confusables_catalog,
)


# ---------------------------------------------------------------------------
# load_confusables_catalog
# ---------------------------------------------------------------------------

class TestLoadConfusablesCatalog:
    def test_returns_empty_dict_when_file_not_found(self):
        result = load_confusables_catalog("/nonexistent/path/confusables.txt")
        assert result == {}

    def test_parses_valid_confusables_file(self, tmp_path):
        # 0061 = 'a' (Latin), 0430 = 'а' (Cyrillic)
        confusables_content = "0061 ; 0430 ; # LATIN a confused with CYRILLIC а\n"
        f = tmp_path / "confusables.txt"
        f.write_text(confusables_content, encoding="utf-8")
        result = load_confusables_catalog(str(f))
        assert "a" in result
        assert chr(0x0430) in result["a"]

    def test_ignores_comment_lines(self, tmp_path):
        content = "# This is a comment\n0061 ; 0430 ;\n"
        f = tmp_path / "confusables.txt"
        f.write_text(content, encoding="utf-8")
        result = load_confusables_catalog(str(f))
        # Only 1 valid entry — the comment line must not appear in catalog
        assert len(result) == 1

    def test_ignores_empty_lines(self, tmp_path):
        content = "\n\n0061 ; 0430 ;\n\n"
        f = tmp_path / "confusables.txt"
        f.write_text(content, encoding="utf-8")
        result = load_confusables_catalog(str(f))
        assert len(result) == 1

    def test_strips_inline_comments(self, tmp_path):
        # Inline comment after entry should be stripped
        content = "0061 ; 0430 ; # some comment here\n"
        f = tmp_path / "confusables.txt"
        f.write_text(content, encoding="utf-8")
        result = load_confusables_catalog(str(f))
        assert "a" in result

    def test_multiple_target_chars(self, tmp_path):
        # 0061 → multiple targets
        content = "0061 ; 0430 0435 ;\n"
        f = tmp_path / "confusables.txt"
        f.write_text(content, encoding="utf-8")
        result = load_confusables_catalog(str(f))
        assert len(result["a"]) == 2

    def test_ignores_malformed_lines(self, tmp_path):
        content = "notahex ; 0430 ;\n0061 ; 0430 ;\n"
        f = tmp_path / "confusables.txt"
        f.write_text(content, encoding="utf-8")
        result = load_confusables_catalog(str(f))
        # Only the valid line should be in catalog
        assert "a" in result

    def test_returns_dict_type(self, tmp_path):
        f = tmp_path / "confusables.txt"
        f.write_text("0061 ; 0430 ;\n", encoding="utf-8")
        result = load_confusables_catalog(str(f))
        assert isinstance(result, dict)

    def test_empty_file_returns_empty_dict(self, tmp_path):
        f = tmp_path / "confusables.txt"
        f.write_text("", encoding="utf-8")
        result = load_confusables_catalog(str(f))
        assert result == {}


# ---------------------------------------------------------------------------
# detect_confusables
# ---------------------------------------------------------------------------

class TestDetectConfusables:
    def test_detects_cyrillic_a_in_paypal(self):
        cyrillic_a = chr(0x0430)  # Cyrillic small letter а
        label = f"p{cyrillic_a}ypal"
        catalog: dict = {cyrillic_a: ["a"]}
        result = detect_confusables(label, catalog)
        assert len(result) == 1
        assert result[0]["char"] == cyrillic_a
        assert result[0]["position"] == 1

    def test_returns_empty_for_clean_ascii_domain(self):
        # Catalog with Cyrillic а but label is pure ASCII
        result = detect_confusables("paypal", {chr(0x0430): ["a"]})
        assert result == []

    def test_heuristic_fallback_when_catalog_empty(self):
        cyrillic_a = chr(0x0430)
        result = detect_confusables(f"p{cyrillic_a}ypal", {})
        # Heuristic: non-ASCII characters flagged
        assert len(result) >= 1
        assert any(r["char"] == cyrillic_a for r in result)

    def test_returns_position_correctly(self):
        cyrillic_p = chr(0x0440)  # Cyrillic р
        label = f"{cyrillic_p}aypal"
        catalog: dict = {cyrillic_p: ["p"]}
        result = detect_confusables(label, catalog)
        assert result[0]["position"] == 0

    def test_result_contains_required_keys(self):
        cyrillic_a = chr(0x0430)
        label = f"p{cyrillic_a}ypal"
        catalog: dict = {cyrillic_a: ["a"]}
        result = detect_confusables(label, catalog)
        assert len(result) == 1
        hit = result[0]
        assert "char" in hit
        assert "position" in hit
        assert "script" in hit
        assert "lookalike" in hit

    def test_multiple_confusable_chars_detected(self):
        cyrillic_a = chr(0x0430)
        cyrillic_p = chr(0x0440)
        label = f"{cyrillic_p}{cyrillic_a}ypal"
        catalog: dict = {cyrillic_a: ["a"], cyrillic_p: ["p"]}
        result = detect_confusables(label, catalog)
        assert len(result) == 2

    def test_heuristic_fallback_provides_script(self):
        cyrillic_a = chr(0x0430)
        result = detect_confusables(f"p{cyrillic_a}ypal", {})
        hit = result[0]
        assert hit["script"] != ""

    def test_only_non_ascii_chars_flagged_with_catalog(self):
        # 'a' is ASCII ord=97 — should NOT be flagged even if catalog maps it
        catalog: dict = {"a": [chr(0x0430)]}
        result = detect_confusables("paypal", catalog)
        # ord('a') == 97 < 128, so not flagged
        assert result == []

    def test_lookalike_is_latin_when_available(self):
        cyrillic_a = chr(0x0430)
        catalog: dict = {cyrillic_a: ["a", "x"]}
        result = detect_confusables(f"p{cyrillic_a}ypal", catalog)
        assert result[0]["lookalike"] == "a"

    def test_full_cyrillic_paypal_string(self):
        """Cyrillic р (0440) + aypal — classic phishing label."""
        cyrillic_p = chr(0x0440)
        label = f"{cyrillic_p}aypal"
        catalog: dict = {cyrillic_p: ["p"]}
        result = detect_confusables(label, catalog)
        assert len(result) == 1
        assert result[0]["char"] == cyrillic_p
        assert result[0]["position"] == 0


# ---------------------------------------------------------------------------
# is_mixed_script
# ---------------------------------------------------------------------------

class TestIsMixedScript:
    def test_pure_latin_is_not_mixed(self):
        assert not is_mixed_script("paypal")

    def test_cyrillic_mixed_with_latin_is_mixed(self):
        # р = Cyrillic, aypal = Latin
        cyrillic_p = chr(0x0440)
        assert is_mixed_script(f"{cyrillic_p}aypal")

    def test_pure_digits_and_hyphens_not_mixed(self):
        assert not is_mixed_script("pay-pal-123")

    def test_empty_string_not_mixed(self):
        assert not is_mixed_script("")

    def test_pure_cyrillic_not_mixed(self):
        # Construct a purely Cyrillic string: р а у (U+0440, U+0430, U+0443)
        pure_cyrillic = chr(0x0440) + chr(0x0430) + chr(0x0443)  # рау
        assert not is_mixed_script(pure_cyrillic)

    def test_digits_alone_not_mixed(self):
        assert not is_mixed_script("123456")

    def test_hyphen_does_not_count_as_script(self):
        # Hyphen is not alpha, should not affect script detection
        assert not is_mixed_script("pay-pal")

    def test_greek_mixed_with_latin_is_mixed(self):
        # α = Greek small letter alpha (U+03B1)
        greek_alpha = chr(0x03B1)
        assert is_mixed_script(f"p{greek_alpha}ypal")

    def test_single_char_latin(self):
        assert not is_mixed_script("a")

    def test_single_char_cyrillic(self):
        assert not is_mixed_script(chr(0x0430))


# ---------------------------------------------------------------------------
# CONFUSABLE_SCRIPTS constant
# ---------------------------------------------------------------------------

class TestConfusableScripts:
    def test_cyrillic_in_confusable_scripts(self):
        assert "Cyrillic" in CONFUSABLE_SCRIPTS

    def test_greek_in_confusable_scripts(self):
        assert "Greek" in CONFUSABLE_SCRIPTS

    def test_armenian_in_confusable_scripts(self):
        assert "Armenian" in CONFUSABLE_SCRIPTS

    def test_cherokee_in_confusable_scripts(self):
        assert "Cherokee" in CONFUSABLE_SCRIPTS

    def test_is_frozenset(self):
        assert isinstance(CONFUSABLE_SCRIPTS, frozenset)
