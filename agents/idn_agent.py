"""IDN Homograph Detection Agent — 5-stage algorithm (RFC 5890/5891, Unicode TR#39)."""

import unicodedata

from agents.base_agent import BaseAgent
from core.constants import BETA, IDN_HOMOGRAPH_RATIO_ALERT
from core.exceptions import IDNAnalysisError
from core.security import is_punycode

# Scripts with known lookalike characters for Latin alphabet
_CONFUSABLE_SCRIPTS = frozenset({"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"})


def _char_script(char: str) -> str:
    """Return the Unicode script name of a character (uppercase)."""
    try:
        name = unicodedata.name(char, "").upper()
        for script in _CONFUSABLE_SCRIPTS:
            if script in name:
                return script
        return "LATIN"
    except Exception:
        return "UNKNOWN"


class IDNAgent(BaseAgent):
    """
    5-stage IDN homograph detection:
      1. Unicode NFC normalization + Punycode awareness
      2. UTR#39 confusable character detection
      3. Homograph ratio r_h = |confusable_chars| / |chars(2LD)|
      4. Visual similarity sim_v vs top-1M domain index
      5. Local score S_IDN_local = β*r_h + (1-β)*sim_v
    """

    def __init__(self, top1m_index: set[str] | None = None) -> None:
        super().__init__("IDNAgent")
        # Injected at startup via dependency injection
        self._top1m: set[str] = top1m_index or set()

    async def analyze(self, domain: str) -> dict:
        self._log_start(domain)
        try:
            # Stage 1: Normalize
            normalized = unicodedata.normalize("NFC", domain.lower().strip())

            # Stage 2: Detect confusables
            confusables = self._detect_confusables(normalized)

            # Stage 3: Homograph ratio on 2LD
            second_level = self._extract_2ld(normalized)
            ratio_h = self._ratio_h(second_level, confusables)

            # Stage 4: Visual similarity
            sim_v = self._sim_v(second_level)

            # Stage 5: S_IDN_local
            s_idn_local = BETA * ratio_h + (1.0 - BETA) * sim_v

            result = {
                "domain": domain,
                "normalized": normalized,
                "is_punycode": is_punycode(domain),
                "confusables": confusables,
                "ratio_h": round(ratio_h, 4),
                "sim_v": round(sim_v, 4),
                "s_idn_local": round(s_idn_local, 4),
                "ratio_h_alert": ratio_h >= IDN_HOMOGRAPH_RATIO_ALERT,
            }
            self._log_result(domain, s_idn_local)
            return result

        except Exception as exc:
            self.logger.error(f"IDN analysis failed for {domain!r}: {exc}", exc_info=True)
            raise IDNAnalysisError(f"IDN analysis failed for {domain!r}") from exc

    # ── Private helpers ───────────────────────────────────────────────────────

    def _extract_2ld(self, domain: str) -> str:
        parts = domain.strip(".").split(".")
        return parts[-2] if len(parts) >= 2 else parts[0]

    def _detect_confusables(self, domain: str) -> list[str]:
        found = {
            char
            for char in domain
            if char not in (".", "-", "_") and _char_script(char) in _CONFUSABLE_SCRIPTS
        }
        return sorted(found)

    def _ratio_h(self, second_level: str, confusables: list[str]) -> float:
        if not second_level:
            return 0.0
        confusable_set = set(confusables)
        count = sum(1 for c in second_level if c in confusable_set)
        return count / len(second_level)

    def _sim_v(self, second_level: str) -> float:
        """Max visual similarity against top-1M sample (first 1000 for performance)."""
        if not self._top1m:
            return 0.0
        max_sim = 0.0
        for ref in list(self._top1m)[:1000]:
            sim = self._visual_similarity(second_level, ref)
            if sim > max_sim:
                max_sim = sim
            if max_sim >= 0.95:
                break
        return max_sim

    def _visual_similarity(self, d: str, ref: str) -> float:
        if d == ref:
            return 1.0
        max_len = max(len(d), len(ref))
        if max_len == 0:
            return 1.0
        ed = self._levenshtein(d, ref)
        return 1.0 - ed / max_len

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        m, n = len(s1), len(s2)
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev, dp[0] = dp[:], i
            for j in range(1, n + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)
        return dp[n]
