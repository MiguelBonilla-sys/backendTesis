"""BK-tree with confusable-aware edit distance for visual similarity search.

The key insight: when comparing a potentially-homograph domain against a
reference domain (e.g., "pаypal" vs "paypal"), a Cyrillic 'а' substituting
a Latin 'a' should cost 0 rather than 1 because they are visually identical.
This makes ``levenshtein_confusable("pаypal", "paypal", catalog) == 0``,
yielding a visual similarity of 1.0 for the homograph attack.

The BK-tree enables sub-linear nearest-neighbour search against a large
domain index (e.g., top-1M list) using the metric property of edit distance.
"""
from __future__ import annotations

from agents.confusables_loader import ConfusablesCatalog


def levenshtein_confusable(
    a: str,
    b: str,
    catalog: ConfusablesCatalog,
) -> int:
    """Compute edit distance between *a* and *b* with confusable substitution cost 0.

    Standard Levenshtein costs:
    - Insertion / deletion: 1
    - Substitution of non-confusable pair: 1
    - Substitution of a TR#39-confusable pair (a[i] ↔ b[j]): **0**

    A pair (x, y) is confusable if ``y`` is in ``catalog[x]`` or ``x`` is in
    ``catalog[y]``.  When the catalog is empty, this reduces to standard edit
    distance (every substitution costs 1).

    Args:
        a: First string.
        b: Second string.
        catalog: TR#39 confusables catalog. Pass ``{}`` for standard edit distance.

    Returns:
        Integer edit distance (≥ 0).
    """
    m, n = len(a), len(b)
    # dp[j] = edit distance between a[:i] and b[:j]
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            char_a = a[i - 1]
            char_b = b[j - 1]
            if char_a == char_b:
                cost = 0
            elif catalog and (
                char_b in catalog.get(char_a, ())
                or char_a in catalog.get(char_b, ())
            ):
                # Confusable pair — visually identical, zero substitution cost
                cost = 0
            else:
                cost = 1
            dp[j] = min(
                dp[j] + 1,           # deletion
                dp[j - 1] + 1,       # insertion
                prev[j - 1] + cost,  # substitution
            )
    return dp[n]


# Internal BK-tree node type: (word, {distance: child_node})
_Node = tuple[str, dict]


class BKTree:
    """BK-tree for efficient nearest-neighbour search with confusable-aware edit distance.

    A BK-tree exploits the triangle inequality of metric spaces to prune the
    search space.  For a query word *w* with tolerance *k*, only nodes at
    tree-distance *d* where |d − dist(w, node)| ≤ k need to be explored.

    Usage::

        tree = BKTree(catalog)
        for domain in top1m:
            tree.add(domain)
        results = tree.query("pаypal", max_dist=1)
        # → [("paypal", 0)]  because confusable substitution costs 0

    Args:
        catalog: TR#39 confusables catalog used by :func:`levenshtein_confusable`.
    """

    def __init__(self, catalog: ConfusablesCatalog) -> None:
        self._catalog = catalog
        self._root: _Node | None = None

    def add(self, word: str) -> None:
        """Insert *word* into the tree."""
        if self._root is None:
            self._root = (word, {})
            return
        node_word, children = self._root
        while True:
            d = levenshtein_confusable(word, node_word, self._catalog)
            if d == 0:
                return  # Duplicate (or confusable-equivalent) — skip
            if d not in children:
                children[d] = (word, {})
                return
            node_word, children = children[d]

    def query(self, word: str, max_dist: int) -> list[tuple[str, int]]:
        """Return all words within *max_dist* of *word*.

        Args:
            word: Query string.
            max_dist: Maximum allowed edit distance (inclusive).

        Returns:
            List of ``(matched_word, distance)`` tuples, sorted by distance
            ascending.  Empty list if the tree is empty.
        """
        if self._root is None:
            return []
        results: list[tuple[str, int]] = []
        stack: list[_Node] = [self._root]
        while stack:
            node_word, children = stack.pop()
            d = levenshtein_confusable(word, node_word, self._catalog)
            if d <= max_dist:
                results.append((node_word, d))
            # BK-tree pruning: only recurse into children whose stored distance
            # is within [d - max_dist, d + max_dist]
            for child_dist, child_node in children.items():
                if abs(child_dist - d) <= max_dist:
                    stack.append(child_node)
        results.sort(key=lambda x: x[1])
        return results

    def __len__(self) -> int:
        """Return the number of words stored in the tree."""
        if self._root is None:
            return 0
        count = 0
        stack: list[_Node] = [self._root]
        while stack:
            _, children = stack.pop()
            count += 1
            stack.extend(children.values())
        return count
