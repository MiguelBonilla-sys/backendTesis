"""IDN Homograph Detection Agent — 5-stage algorithm (RFC 5890/5891, Unicode TR#39)."""
from __future__ import annotations

import unicodedata
from pathlib import Path

from agents.base_agent import BaseAgent
from agents.bktree import levenshtein_confusable
from agents.confusables_loader import (
    ConfusablesCatalog,
    detect_confusables,
    load_confusables,
)
from core.constants import BETA, IDN_HOMOGRAPH_RATIO_ALERT
from core.exceptions import IDNAnalysisError
from core.security import is_punycode

# Module-level singletons — populated once at app startup via init_catalog() /
# init_top1m().  Tests inject values directly via constructor arguments.
_CONFUSABLES_CATALOG: ConfusablesCatalog = {}
_TOP1M_INDEX: list[str] = []


def init_catalog(path: str | Path) -> None:
    """Load the TR#39 confusables catalog into the module-level singleton.

    Call once during application startup (lifespan context in main.py) before
    the first request is processed.  Tests should inject catalogs directly via
    the ``catalog`` constructor argument instead of calling this function.

    Args:
        path: Path to ``confusables.txt``.  Download from
              https://www.unicode.org/Public/security/latest/confusables.txt
    """
    global _CONFUSABLES_CATALOG
    _CONFUSABLES_CATALOG = load_confusables(path)


def init_top1m(index: list[str]) -> None:
    """Store the pre-loaded top-1M 2LD index in the module-level singleton.

    Call once during application startup after :func:`load_top1m` has been
    called.  Preserves Tranco rank order so ``_sim_v`` checks the most
    popular domains first.

    Args:
        index: Ordered list of 2LD strings from :func:`data_pipeline.top1m_loader.load_top1m`.
    """
    global _TOP1M_INDEX
    _TOP1M_INDEX = index


class IDNAgent(BaseAgent):
    """5-stage IDN homograph detection agent (stateless — one instance per request).

    Algorithm:
      1. Unicode NFC normalization + Punycode awareness
      2. UTR#39 confusable character detection (catalog-driven; heuristic fallback
         when catalog not loaded)
      3. Homograph ratio  r_h = |confusable_chars_in_2LD| / |chars(2LD)|
      4. Visual similarity  sim_v vs top-1M domain index using confusable-aware
         edit distance (``levenshtein_confusable``); checks up to 1000 entries,
         early-exit at sim_v ≥ 0.95
      5. Local score  S_IDN_local = β·r_h + (1−β)·sim_v  (β = BETA = 0.40)

    Args:
        top1m_index: Set of 2LD strings from the top-1M domain list.  Injected
                     at startup; pass a small set in tests.
        catalog: TR#39 confusables catalog from :func:`load_confusables`.
                 Defaults to the module-level singleton loaded via
                 :func:`init_catalog`.  Pass an explicit dict in tests.
    """

    def __init__(
        self,
        top1m_index: list[str] | set[str] | None = None,
        catalog: ConfusablesCatalog | None = None,
    ) -> None:
        super().__init__("IDNAgent")
        # Use injected index (tests) or fall back to module-level singleton.
        # list preserves Tranco rank order; set accepted for test compatibility.
        self._top1m: list[str] | set[str] = (
            top1m_index if top1m_index is not None else _TOP1M_INDEX
        )
        # Accept injected catalog (tests) or fall back to module-level singleton.
        self._catalog: ConfusablesCatalog = (
            catalog if catalog is not None else _CONFUSABLES_CATALOG
        )

    async def analyze(self, domain: str) -> dict:
        """Run the 5-stage IDN detection algorithm on *domain*.

        Args:
            domain: Domain string (not a full URL). The caller (router or test)
                    is responsible for URL → domain extraction.

        Returns:
            Result dict with keys:
                domain, normalized, is_punycode, confusables,
                confusable_details, ratio_h, sim_v, closest_domain,
                s_idn_local, ratio_h_alert
        """
        self._log_start(domain)
        try:
            # Stage 1: NFC normalization
            normalized = unicodedata.normalize("NFC", domain.lower().strip())

            # Stage 2: Confusable detection
            confusable_entries = detect_confusables(normalized, self._catalog)
            # Unique confusable chars as a sorted list (for ratio computation)
            confusables: list[str] = sorted({e["char"] for e in confusable_entries})

            # Stage 3: Homograph ratio on 2LD
            second_level = self._extract_2ld(normalized)
            ratio_h = self._ratio_h(second_level, confusables)

            # Stage 4: Visual similarity (confusable-aware when catalog loaded)
            sim_v, closest = self._sim_v(second_level)

            # Stage 5: S_IDN_local
            s_idn_local = BETA * ratio_h + (1.0 - BETA) * sim_v

            result = {
                "domain": domain,
                "normalized": normalized,
                "is_punycode": is_punycode(domain),
                "confusables": confusables,
                "confusable_details": confusable_entries,
                "ratio_h": round(ratio_h, 4),
                "sim_v": round(sim_v, 4),
                "closest_domain": closest,
                "s_idn_local": round(s_idn_local, 4),
                "ratio_h_alert": ratio_h >= IDN_HOMOGRAPH_RATIO_ALERT,
            }
            self._log_result(domain, s_idn_local)
            return result

        except Exception as exc:
            self.logger.error(
                "IDN analysis failed for %r: %s", domain, exc, exc_info=True
            )
            raise IDNAnalysisError(f"IDN analysis failed for {domain!r}") from exc

    # ── Private helpers ────────────────────────────────────────────────────────

    def _extract_2ld(self, domain: str) -> str:
        parts = domain.strip(".").split(".")
        return parts[-2] if len(parts) >= 2 else parts[0]

    def _ratio_h(self, second_level: str, confusables: list[str]) -> float:
        if not second_level:
            return 0.0
        confusable_set = set(confusables)
        count = sum(1 for c in second_level if c in confusable_set)
        return count / len(second_level)

    def _sim_v(self, second_level: str) -> tuple[float, str]:
        """Max visual similarity against the top-1M sample (first 1000 entries).

        Uses confusable-aware edit distance when a catalog is loaded, falling
        back to standard Levenshtein when the catalog is empty.

        Returns:
            (sim_v, closest_domain) — sim_v ∈ [0.0, 1.0].
        """
        if not self._top1m:
            return 0.0, ""
        max_sim = 0.0
        best_match = ""
        for ref in list(self._top1m)[:1000]:
            sim = self._visual_similarity(second_level, ref)
            if sim > max_sim:
                max_sim = sim
                best_match = ref
            if max_sim >= 0.95:  # early-exit — close enough
                break
        return max_sim, best_match

    def _visual_similarity(self, d: str, ref: str) -> float:
        if d == ref:
            return 1.0
        max_len = max(len(d), len(ref))
        if max_len == 0:
            return 1.0
        if self._catalog:
            ed = levenshtein_confusable(d, ref, self._catalog)
        else:
            ed = self._levenshtein(d, ref)
        return 1.0 - ed / max_len

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Standard Levenshtein distance (no confusable awareness)."""
        m, n = len(s1), len(s2)
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev, dp[0] = dp[:], i
            for j in range(1, n + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)
        return dp[n]
