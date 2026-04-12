"""Late Fusion Agent — weighted score fusion + SHAP-like XAI."""

from agents.base_agent import BaseAgent
from core.constants import (
    ALPHA,
    GAMMA,
    SUSPICIOUS_THRESHOLD,
    THETA,
    TI_GSB_WEIGHT,
    TI_URLSCAN_WEIGHT,
    TI_VIRUSTOTAL_WEIGHT,
    VERDICT_PHISHING,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
)
from core.exceptions import BackendTesisError


class FusionAgent(BaseAgent):
    """
    3-step late fusion:
      1. S_TI = 0.50*VT + 0.30*URLScan + 0.20*GSB
      2. S_IDN = α*S_IDN_local + (1-α)*S_TI
      3. S_risk = γ*S_IDN + (1-γ)*S_LLM
    Verdict: PHISHING if S_risk >= θ (0.70), SUSPICIOUS >= 0.50, else SAFE.
    Loss function penalizes false negatives 3× more than false positives (λ=0.30).
    """

    def __init__(self) -> None:
        super().__init__("FusionAgent")

    async def analyze(
        self,
        s_idn_local: float,
        s_llm: float,
        ti_scores: dict,
    ) -> dict:
        self._log_start("fusion")
        try:
            s_ti = self._aggregate_ti(ti_scores)
            s_idn = max(0.0, min(1.0, ALPHA * s_idn_local + (1.0 - ALPHA) * s_ti))
            s_risk = max(0.0, min(1.0, GAMMA * s_idn + (1.0 - GAMMA) * s_llm))
            verdict = self._verdict(s_risk)
            shap = self._shap(s_idn_local, s_ti, s_llm, s_idn, s_risk)

            result = {
                "s_ti": round(s_ti, 4),
                "s_idn": round(s_idn, 4),
                "s_llm": round(s_llm, 4),
                "s_risk": round(s_risk, 4),
                "verdict": verdict,
                "shap_explanation": shap,
                "top_features": self._top_features(shap),
            }
            self._log_result("fusion", s_risk)
            return result

        except Exception as exc:
            self.logger.error(f"Fusion failed: {exc}", exc_info=True)
            raise BackendTesisError("Fusion computation failed") from exc

    # ── Private helpers ───────────────────────────────────────────────────────

    def _aggregate_ti(self, ti_scores: dict) -> float:
        return (
            TI_VIRUSTOTAL_WEIGHT * ti_scores.get("virustotal", 0.0)
            + TI_URLSCAN_WEIGHT * ti_scores.get("urlscan", 0.0)
            + TI_GSB_WEIGHT * ti_scores.get("google_safe_browsing", 0.0)
        )

    def _verdict(self, s_risk: float) -> str:
        if s_risk >= THETA:
            return VERDICT_PHISHING
        if s_risk >= SUSPICIOUS_THRESHOLD:
            return VERDICT_SUSPICIOUS
        return VERDICT_SAFE

    def _shap(
        self,
        s_idn_local: float,
        s_ti: float,
        s_llm: float,
        s_idn: float,
        s_risk: float,
    ) -> dict[str, float]:
        """Marginal SHAP contributions relative to baseline=0.5."""
        baseline = 0.5
        return {
            "idn_contribution": round(GAMMA * (s_idn - baseline), 4),
            "llm_contribution": round((1.0 - GAMMA) * (s_llm - baseline), 4),
            "ti_contribution": round(GAMMA * (1.0 - ALPHA) * (s_ti - baseline), 4),
            "idn_local_score": round(s_idn_local, 4),
            "baseline": baseline,
        }

    @staticmethod
    def _top_features(shap: dict[str, float], n: int = 3) -> list[str]:
        """Return top-n feature keys sorted by |contribution| descending.

        Excludes 'baseline' and 'idn_local_score' (metadata, not contributions).
        """
        _exclude = {"baseline", "idn_local_score"}
        sortable = {k: v for k, v in shap.items() if k not in _exclude}
        return sorted(sortable, key=lambda k: abs(sortable[k]), reverse=True)[:n]
