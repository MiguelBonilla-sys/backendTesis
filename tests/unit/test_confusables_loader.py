import pytest
from pathlib import Path
from agents.confusables_loader import (
    load_confusables,
    char_script,
    detect_confusables,
    CONFUSABLE_SCRIPTS,
    _hex_seq_to_str
)

# Use the same minimal fixture used in other tests
MINIMAL_CATALOG_PATH = Path("tests/fixtures/confusables_minimal.txt")

def test_hex_seq_single_codepoint():
    assert _hex_seq_to_str("0430") == "\u0430"

def test_hex_seq_cyrillic_a():
    assert _hex_seq_to_str("0430") == "а"

def test_hex_seq_multi_codepoint():
    # Example from TR#39: 0061 0301 is 'a' with acute accent
    assert _hex_seq_to_str("0061 0301") == "a\u0301"

def test_hex_seq_invalid_raises():
    with pytest.raises(ValueError):
        _hex_seq_to_str("XYZ")

def test_load_returns_empty_for_missing_file():
    assert load_confusables("non_existent_file.txt") == {}

def test_load_minimal_catalog_nonempty():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert isinstance(catalog, dict)
    assert len(catalog) > 0

def test_load_cyrillic_a_in_catalog():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert "\u0430" in catalog
    assert "a" in catalog["\u0430"]

def test_load_greek_omicron_in_catalog():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert "\u03bf" in catalog
    assert "o" in catalog["\u03bf"]

def test_load_skips_comment_lines(tmp_path):
    f = tmp_path / "comments.txt"
    f.write_text("# This is a comment\n\n0430 ; 0061 ; SA # Inline comment\n", encoding="utf-8")
    catalog = load_confusables(f)
    assert len(catalog) == 1
    assert "\u0430" in catalog

def test_load_accepts_path_string():
    catalog = load_confusables(str(MINIMAL_CATALOG_PATH))
    assert isinstance(catalog, dict)
    assert len(catalog) > 0

def test_load_custom_minimal_file(tmp_path):
    f = tmp_path / "custom.txt"
    f.write_text("0430 ;\t0061 ;\tSA\t# Cyrillic a → Latin a\n", encoding="utf-8")
    catalog = load_confusables(f)
    assert "\u0430" in catalog
    assert "a" in catalog["\u0430"]

def test_load_ignores_malformed_lines(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_text("this is not a valid line\n0430 ;\t0061 ;\tSA\n", encoding="utf-8")
    catalog = load_confusables(f)
    assert len(catalog) == 1
    assert "\u0430" in catalog

# ── char_script ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("char,expected_script", [
    ("\u0430", "CYRILLIC"),   
    ("\u043e", "CYRILLIC"),   
    ("\u03b1", "GREEK"),      
    ("\u03bf", "GREEK"),      
    ("a", "LATIN"),
    ("z", "LATIN"),
    ("0", "COMMON"),           
    (".", "COMMON"),
    ("-", "COMMON"),
])
def test_char_script(char, expected_script):
    assert char_script(char) == expected_script

def test_confusable_scripts_frozenset_immutable():
    assert isinstance(CONFUSABLE_SCRIPTS, frozenset)
    assert "CYRILLIC" in CONFUSABLE_SCRIPTS
    assert "GREEK" in CONFUSABLE_SCRIPTS

# ── detect_confusables ─────────────────────────────────────────────────────────

def test_detect_pure_latin_returns_empty():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert detect_confusables("paypal.com", catalog) == []

def test_detect_cyrillic_a_in_paypal():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    domain = "p\u0430ypal.com"
    result = detect_confusables(domain, catalog)
    assert len(result) == 1
    entry = result[0]
    assert entry["char"] == "\u0430"
    assert entry["position"] == 1
    assert entry["script"] == "CYRILLIC"
    assert entry["lookalike"] == ["a"]

def test_detect_multiple_confusables():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    domain = "p\u0430yp\u0430l.com"
    result = detect_confusables(domain, catalog)
    assert len(result) == 2
    positions = {e["position"] for e in result}
    assert positions == {1, 4}

def test_detect_greek_omicron_in_google():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    domain = "g\u03bf\u03bfgle.com"
    result = detect_confusables(domain, catalog)
    assert len(result) == 2
    assert result[0]["script"] == "GREEK"

def test_detect_skips_dots_and_hyphens():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    assert detect_confusables("a.b-c", catalog) == []

def test_detect_returns_list_of_dicts():
    catalog = load_confusables(MINIMAL_CATALOG_PATH)
    domain = "\u0430.com"
    result = detect_confusables(domain, catalog)
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], dict)
    assert "char" in result[0]
    assert "position" in result[0]
    assert "script" in result[0]
    assert "lookalike" in result[0]
