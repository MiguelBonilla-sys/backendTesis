"""Unit tests for agents/bktree.py."""
from __future__ import annotations

import pytest

from agents.bktree import BKTree, levenshtein_confusable
from agents.confusables_loader import ConfusablesCatalog

# Minimal catalog: Cyrillic а → a, Cyrillic о → o
CATALOG: ConfusablesCatalog = {
    "\u0430": ["a"],   # Cyrillic а → Latin a
    "\u043E": ["o"],   # Cyrillic о → Latin o
    "\u03BF": ["o"],   # Greek ο → Latin o
    "\u03B1": ["a"],   # Greek α → Latin a
}


# ── levenshtein_confusable ─────────────────────────────────────────────────────


def test_equal_strings_distance_zero() -> None:
    assert levenshtein_confusable("paypal", "paypal", CATALOG) == 0


def test_standard_substitution_costs_one() -> None:
    # 'x' vs 'y' — not confusable
    assert levenshtein_confusable("ax", "ay", {}) == 1


def test_confusable_substitution_costs_zero() -> None:
    # Cyrillic а vs Latin a — visually identical
    cyrillic_a = "\u0430"
    assert levenshtein_confusable(cyrillic_a, "a", CATALOG) == 0


def test_homograph_paypal_distance_zero() -> None:
    # "pаypal" (Cyrillic а at position 1) vs "paypal"
    homograph = "p\u0430ypal"
    assert levenshtein_confusable(homograph, "paypal", CATALOG) == 0


def test_homograph_google_two_confusables_distance_zero() -> None:
    # "gооgle" (2 Cyrillic о's) vs "google"
    homograph = "g\u043E\u043Egle"
    assert levenshtein_confusable(homograph, "google", CATALOG) == 0


def test_different_length_strings() -> None:
    # "ab" vs "abc" — edit distance 1 (insertion)
    assert levenshtein_confusable("ab", "abc", {}) == 1


def test_empty_strings_distance_zero() -> None:
    assert levenshtein_confusable("", "", {}) == 0


def test_empty_vs_nonempty() -> None:
    assert levenshtein_confusable("", "abc", {}) == 3
    assert levenshtein_confusable("abc", "", {}) == 3


def test_empty_catalog_falls_back_to_standard() -> None:
    # Without catalog, substitution always costs 1
    cyrillic_a = "\u0430"
    assert levenshtein_confusable(cyrillic_a, "a", {}) == 1


def test_greek_confusable_costs_zero() -> None:
    greek_o = "\u03BF"
    assert levenshtein_confusable(greek_o, "o", CATALOG) == 0


def test_bidirectional_confusable() -> None:
    # catalog["а"] = ["a"] — both directions should cost 0
    assert levenshtein_confusable("\u0430", "a", CATALOG) == 0
    assert levenshtein_confusable("a", "\u0430", CATALOG) == 0


def test_mixed_confusable_and_standard() -> None:
    # "р\u0430ge" vs "page" — р→p (cost=1, not in catalog), а→a (cost=0)
    # edit distance = 1 (only р vs p is non-zero)
    result = levenshtein_confusable("\u0440\u0430ge", "page", CATALOG)
    # \u0440 (Cyrillic р) not in CATALOG → cost 1; \u0430 (Cyrillic а) → cost 0
    assert result == 1


# ── BKTree ─────────────────────────────────────────────────────────────────────


def test_bktree_empty_query_returns_empty() -> None:
    tree = BKTree(CATALOG)
    assert tree.query("paypal", max_dist=1) == []


def test_bktree_len_empty() -> None:
    tree = BKTree(CATALOG)
    assert len(tree) == 0


def test_bktree_add_single_word() -> None:
    tree = BKTree(CATALOG)
    tree.add("paypal")
    assert len(tree) == 1


def test_bktree_add_and_query_exact() -> None:
    tree = BKTree(CATALOG)
    tree.add("paypal")
    results = tree.query("paypal", max_dist=0)
    assert len(results) == 1
    assert results[0] == ("paypal", 0)


def test_bktree_query_finds_homograph() -> None:
    tree = BKTree(CATALOG)
    tree.add("paypal")
    # "pаypal" (Cyrillic а) has confusable distance 0 to "paypal"
    results = tree.query("p\u0430ypal", max_dist=0)
    assert any(word == "paypal" for word, _ in results)


def test_bktree_query_max_dist_one() -> None:
    tree = BKTree(CATALOG)
    for word in ["paypal", "papal", "paypal2", "google"]:
        tree.add(word)
    results = tree.query("paypal", max_dist=1)
    matched = [w for w, _ in results]
    assert "paypal" in matched   # distance 0
    assert "papal" in matched    # distance 1 (delete 'y')
    assert "google" not in matched  # distance >> 1


def test_bktree_results_sorted_by_distance() -> None:
    tree = BKTree(CATALOG)
    for word in ["paypal", "paypa", "pay"]:
        tree.add(word)
    results = tree.query("paypal", max_dist=3)
    distances = [d for _, d in results]
    assert distances == sorted(distances)


def test_bktree_no_duplicates() -> None:
    tree = BKTree(CATALOG)
    tree.add("paypal")
    tree.add("paypal")  # duplicate
    assert len(tree) == 1


def test_bktree_confusable_equivalent_not_added_twice() -> None:
    # "pаypal" (confusable distance 0 from "paypal") should not be added
    # as a separate node when "paypal" is already in the tree
    tree = BKTree(CATALOG)
    tree.add("paypal")
    tree.add("p\u0430ypal")  # confusable-equivalent → treated as duplicate
    assert len(tree) == 1


def test_bktree_multiple_domains() -> None:
    domains = ["paypal", "google", "microsoft", "amazon", "apple"]
    tree = BKTree(CATALOG)
    for d in domains:
        tree.add(d)
    assert len(tree) == len(domains)


def test_bktree_query_returns_list_of_tuples() -> None:
    tree = BKTree(CATALOG)
    tree.add("paypal")
    results = tree.query("paypal", max_dist=0)
    assert isinstance(results, list)
    assert all(isinstance(r, tuple) and len(r) == 2 for r in results)
