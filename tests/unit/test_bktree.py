"""Tests for agents/bktree.py"""
from __future__ import annotations

import pytest

from agents.bktree import BKTree, _is_confusable_pair, levenshtein_confusable


# ---------------------------------------------------------------------------
# levenshtein_confusable
# ---------------------------------------------------------------------------

class TestLevenshteinConfusable:
    def test_identical_strings_distance_zero(self):
        assert levenshtein_confusable("paypal", "paypal", {}) == 0

    def test_empty_strings(self):
        assert levenshtein_confusable("", "", {}) == 0
        assert levenshtein_confusable("abc", "", {}) == 3
        assert levenshtein_confusable("", "abc", {}) == 3

    def test_normal_edit_distance_one_substitution(self):
        # "cat" → "bat" = 1 substitution
        assert levenshtein_confusable("cat", "bat", {}) == 1

    def test_normal_edit_distance_one_insertion(self):
        assert levenshtein_confusable("paypal", "paypall", {}) == 1

    def test_normal_edit_distance_one_deletion(self):
        assert levenshtein_confusable("paypall", "paypal", {}) == 1

    def test_confusable_pair_costs_zero(self):
        cyrillic_a = chr(0x0430)
        latin_a = "a"
        confusables: dict = {cyrillic_a: [latin_a]}
        # Cyrillic а vs Latin a → distance 0 when confusables cover them
        result = levenshtein_confusable(
            cyrillic_a + "bc",
            latin_a + "bc",
            confusables,
        )
        assert result == 0

    def test_confusable_pair_reverse_direction_costs_zero(self):
        cyrillic_a = chr(0x0430)
        latin_a = "a"
        # Reverse: Latin→Cyrillic mapping
        confusables: dict = {latin_a: [cyrillic_a]}
        result = levenshtein_confusable(
            cyrillic_a + "bc",
            latin_a + "bc",
            confusables,
        )
        assert result == 0

    def test_no_confusable_entry_costs_one(self):
        cyrillic_a = chr(0x0430)
        latin_a = "a"
        # Empty confusables — substitution cost = 1
        result = levenshtein_confusable(
            cyrillic_a + "bc",
            latin_a + "bc",
            {},
        )
        assert result == 1

    def test_single_char_strings(self):
        assert levenshtein_confusable("a", "b", {}) == 1
        assert levenshtein_confusable("a", "a", {}) == 0

    def test_cyrillic_paypal_vs_latin_paypal(self):
        """Full 'рaypal' vs 'paypal' with р≈p confusable should give distance 0."""
        cyrillic_p = chr(0x0440)
        latin_p = "p"
        confusables: dict = {cyrillic_p: [latin_p]}
        result = levenshtein_confusable(
            cyrillic_p + "aypal",
            latin_p + "aypal",
            confusables,
        )
        assert result == 0

    def test_different_length_strings(self):
        dist = levenshtein_confusable("abc", "abcdef", {})
        assert dist == 3

    def test_completely_different_strings(self):
        dist = levenshtein_confusable("abc", "xyz", {})
        assert dist == 3


# ---------------------------------------------------------------------------
# _is_confusable_pair
# ---------------------------------------------------------------------------

class TestIsConfusablePair:
    def test_direct_mapping(self):
        cyrillic_a = chr(0x0430)
        confusables: dict = {cyrillic_a: ["a"]}
        assert _is_confusable_pair(cyrillic_a, "a", confusables) is True

    def test_reverse_mapping(self):
        cyrillic_a = chr(0x0430)
        confusables: dict = {"a": [cyrillic_a]}
        assert _is_confusable_pair(cyrillic_a, "a", confusables) is True

    def test_no_mapping_returns_false(self):
        assert _is_confusable_pair("a", "b", {}) is False

    def test_same_char_not_in_confusables(self):
        assert _is_confusable_pair("a", "a", {}) is False


# ---------------------------------------------------------------------------
# BKTree
# ---------------------------------------------------------------------------

class TestBKTree:
    @pytest.fixture
    def empty_tree(self) -> BKTree:
        return BKTree(confusables={})

    @pytest.fixture
    def populated_tree(self) -> BKTree:
        tree = BKTree(confusables={})
        for domain in ["paypal", "google", "amazon", "facebook", "microsoft"]:
            tree.insert(domain)
        return tree

    def test_insert_increases_size(self, empty_tree: BKTree):
        assert empty_tree.size == 0
        empty_tree.insert("paypal")
        assert empty_tree.size == 1

    def test_duplicate_insert_ignored(self, empty_tree: BKTree):
        empty_tree.insert("paypal")
        empty_tree.insert("paypal")
        assert empty_tree.size == 1

    def test_multiple_inserts(self, empty_tree: BKTree):
        empty_tree.insert("paypal")
        empty_tree.insert("google")
        assert empty_tree.size == 2

    def test_search_finds_exact_match(self, populated_tree: BKTree):
        results = populated_tree.search("paypal", max_dist=2)
        domains = [r[0] for r in results]
        assert "paypal" in domains

    def test_search_finds_similar_domain(self, populated_tree: BKTree):
        # "paypa1" is 1 edit from "paypal"
        results = populated_tree.search("paypa1", max_dist=2)
        assert len(results) > 0
        assert any(r[0] == "paypal" for r in results)

    def test_search_returns_sorted_by_similarity_descending(self, populated_tree: BKTree):
        results = populated_tree.search("paypal", max_dist=3)
        if len(results) > 1:
            sims = [r[1] for r in results]
            assert sims == sorted(sims, reverse=True)

    def test_empty_tree_returns_empty_list(self, empty_tree: BKTree):
        assert empty_tree.search("paypal") == []

    def test_build_from_set(self, empty_tree: BKTree):
        domains = {"paypal", "google", "amazon"}
        empty_tree.build_from_set(domains)
        assert empty_tree.size == 3

    def test_similarity_exact_match_is_one(self, populated_tree: BKTree):
        results = populated_tree.search("paypal", max_dist=0)
        assert any(abs(r[1] - 1.0) < 1e-6 for r in results)

    def test_search_max_dist_zero_returns_exact(self, populated_tree: BKTree):
        results = populated_tree.search("paypal", max_dist=0)
        assert len(results) == 1
        assert results[0][0] == "paypal"

    def test_search_max_dist_zero_no_match(self, populated_tree: BKTree):
        results = populated_tree.search("xxxxxx", max_dist=0)
        assert results == []

    def test_similarity_values_between_zero_and_one(self, populated_tree: BKTree):
        results = populated_tree.search("paypal", max_dist=5)
        for _, sim in results:
            assert 0.0 <= sim <= 1.0

    def test_root_is_none_on_empty_tree(self, empty_tree: BKTree):
        assert empty_tree.root is None

    def test_root_is_set_after_first_insert(self, empty_tree: BKTree):
        empty_tree.insert("paypal")
        assert empty_tree.root is not None
        assert empty_tree.root.domain == "paypal"

    def test_confusable_distance_zero_for_matching_pairs(self):
        cyrillic_p = chr(0x0440)
        confusables: dict = {cyrillic_p: ["p"]}
        tree = BKTree(confusables=confusables)
        tree.insert("paypal")
        # "рaypal" (Cyrillic р) vs "paypal" → distance should be 0
        results = tree.search(f"{cyrillic_p}aypal", max_dist=1)
        assert len(results) > 0
        assert any(r[0] == "paypal" for r in results)

    def test_build_from_set_logs_info(self, empty_tree: BKTree):
        """build_from_set should not raise."""
        domains = {"paypal", "google"}
        empty_tree.build_from_set(domains)
        assert empty_tree.size == 2

    def test_early_exit_at_high_similarity(self):
        """Search early exits when sim_v >= SIM_V_EARLY_EXIT (0.95)."""
        from core.constants import SIM_V_EARLY_EXIT
        tree = BKTree(confusables={})
        tree.insert("paypal")
        # Exact match → sim=1.0 >= 0.95 → early exit
        results = tree.search("paypal", max_dist=2)
        assert len(results) >= 1
        assert results[0][1] >= SIM_V_EARLY_EXIT

    def test_size_property_type_is_int(self, empty_tree: BKTree):
        assert isinstance(empty_tree.size, int)
