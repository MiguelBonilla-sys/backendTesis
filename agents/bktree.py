"""
BK-Tree for sub-linear nearest-neighbour domain similarity search.
Uses confusable-aware Levenshtein: cost=0 for Unicode TR#39 confusable pairs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.constants import SIM_V_EARLY_EXIT
from core.logger import get_logger

logger = get_logger(__name__)


def levenshtein_confusable(
    a: str, b: str, confusables: dict[str, list[str]]
) -> int:
    """
    Edit distance with cost=0 for TR#39 confusable character pairs.

    Example: Cyrillic 'а' vs Latin 'a' → substitution cost 0, distance 0.
    Standard insertions and deletions still cost 1.
    """
    m, n = len(a), len(b)
    if m == 0:
        return n
    if n == 0:
        return m

    # Single-row DP (O(n) space)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                cost = 0
            elif _is_confusable_pair(a[i - 1], b[j - 1], confusables):
                cost = 0  # confusable pair → zero substitution cost
            else:
                cost = 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = temp

    return dp[n]


def _is_confusable_pair(
    a: str, b: str, confusables: dict[str, list[str]]
) -> bool:
    """Return True if a and b are a confusable pair according to TR#39."""
    if a in confusables and b in confusables.get(a, []):
        return True
    if b in confusables and a in confusables.get(b, []):
        return True
    return False


@dataclass
class BKNode:
    domain: str
    children: dict[int, "BKNode"] = field(default_factory=dict)


class BKTree:
    """
    BK-Tree for efficient nearest-neighbour search over domain names.

    Uses levenshtein_confusable as the metric so that visually identical
    characters (TR#39 confusable pairs) contribute zero to the distance.
    """

    def __init__(self, confusables: dict[str, list[str]]) -> None:
        self.confusables = confusables
        self.root: BKNode | None = None
        self._size: int = 0

    # ------------------------------------------------------------------
    # Insertion
    # ------------------------------------------------------------------

    def insert(self, domain: str) -> None:
        """Insert a domain string into the tree."""
        if self.root is None:
            self.root = BKNode(domain=domain)
            self._size += 1
            return

        node = self.root
        while True:
            dist = levenshtein_confusable(domain, node.domain, self.confusables)
            if dist == 0:
                return  # duplicate — skip
            if dist not in node.children:
                node.children[dist] = BKNode(domain=domain)
                self._size += 1
                return
            node = node.children[dist]

    def build_from_set(self, domains: set[str]) -> None:
        """Bulk-insert a set of reference domains and log completion."""
        for domain in domains:
            self.insert(domain)
        logger.info("bktree_built", size=self._size)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self, query: str, max_dist: int = 2, limit: int = 1000
    ) -> list[tuple[str, float]]:
        """
        Search for domains within *max_dist* edits of *query*.

        Returns a list of (domain, similarity) tuples sorted by similarity
        descending.  Applies early-exit when sim_v >= SIM_V_EARLY_EXIT (0.95).
        Checks at most *limit* nodes to bound worst-case latency.
        """
        if self.root is None:
            return []

        results: list[tuple[str, float]] = []
        checked: int = 0
        stack: list[BKNode] = [self.root]

        while stack and checked < limit:
            node = stack.pop()
            checked += 1

            dist = levenshtein_confusable(query, node.domain, self.confusables)
            max_len = max(len(query), len(node.domain))
            sim = 1.0 - dist / max_len if max_len > 0 else 1.0

            if dist <= max_dist:
                results.append((node.domain, sim))
                if sim >= SIM_V_EARLY_EXIT:
                    logger.debug(
                        "bktree_early_exit",
                        query=query,
                        match=node.domain,
                        sim=sim,
                    )
                    return sorted(results, key=lambda x: x[1], reverse=True)

            # BK-Tree pruning: only explore children whose edge distance
            # falls within [dist - max_dist, dist + max_dist].
            for child_dist, child in node.children.items():
                if abs(child_dist - dist) <= max_dist:
                    stack.append(child)

        return sorted(results, key=lambda x: x[1], reverse=True)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Number of domains stored in the tree."""
        return self._size
