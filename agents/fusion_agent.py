"""Late Fusion Agent — weighted score fusion + SHAP-like XAI."""

from agents.base_agent import BaseAgent
from core.constants import (
    ALPHA,
    GAMMA,
    GAMMA_DEFINITIVE_HOMOGRAPH,
    GAMMA_LLM_FALLBACK,
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
        is_definitive_homograph: bool = False,
        llm_is_fallback: bool = False,
    ) -> dict:
        """Run 3-step late fusion with adaptive GAMMA for resilience.

        Args:
            s_idn_local: IDN local score from IDNAgent (0–1).
            s_llm: LLM risk score from LLMAgent (0–1); 0.5 when timed out.
            ti_scores: Dict with virustotal, urlscan, google_safe_browsing keys.
            is_definitive_homograph: True when IDNAgent floor rule fired
                (is_mixed_script=True AND sim_v≥0.9 OR ratio_h>0.1).
                Triggers GAMMA_DEFINITIVE_HOMOGRAPH weight shift.
            llm_is_fallback: True when LLMAgent timed out (reasoning=="timeout").
                Triggers GAMMA_LLM_FALLBACK weight shift.

        Adaptive GAMMA logic (in priority order):
            1. is_definitive_homograph → γ=GAMMA_DEFINITIVE_HOMOGRAPH (0.85)
               Trust IDN+TI for confirmed mixed-script homographs.
            2. llm_is_fallback → γ=GAMMA_LLM_FALLBACK (0.75)
               LLM unavailable — shift weight to IDN+TI pipeline.
            3. Default → γ=GAMMA (0.50) normal operation.
        """
        self._log_start("fusion")
        try:
            s_ti = self._aggregate_ti(ti_scores)

            # Definitive homographs bypass TI blending: TI=0 means "not yet catalogued"
            # for zero-day phishing domains, NOT "legitimate". The TR#39 Unicode detection
            # is deterministic — a confirmed mixed-script homograph should not be exonerated
            # by a zero TI score. Use s_idn_local directly; TI still appears in SHAP.
            if is_definitive_homograph:
                s_idn = max(0.0, min(1.0, s_idn_local))
                effective_gamma = GAMMA_DEFINITIVE_HOMOGRAPH
            else:
                s_idn = max(0.0, min(1.0, ALPHA * s_idn_local + (1.0 - ALPHA) * s_ti))
                # Adaptive GAMMA: trust IDN more when LLM is unreliable
                if llm_is_fallback:
                    effective_gamma = GAMMA_LLM_FALLBACK
                else:
                    effective_gamma = GAMMA

            s_risk = max(0.0, min(1.0, effective_gamma * s_idn + (1.0 - effective_gamma) * s_llm))
            verdict = self._verdict(s_risk)
            shap = self._shap(s_idn_local, s_ti, s_llm, s_idn, s_risk, effective_gamma)

            result = {
                "s_ti": round(s_ti, 4),
                "s_idn": round(s_idn, 4),
                "s_llm": round(s_llm, 4),
                "s_risk": round(s_risk, 4),
                "verdict": verdict,
                "effective_gamma": round(effective_gamma, 4),
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
        effective_gamma: float = GAMMA,
    ) -> dict[str, float]:
        """Marginal SHAP contributions relative to baseline=0.5.

        Uses effective_gamma so SHAP values reflect the actual weights applied,
        including adaptive shifts for LLM fallback / definitive homograph modes.
        """
        baseline = 0.5
        return {
            "idn_contribution": round(effective_gamma * (s_idn - baseline), 4),
            "llm_contribution": round((1.0 - effective_gamma) * (s_llm - baseline), 4),
            "ti_contribution": round(effective_gamma * (1.0 - ALPHA) * (s_ti - baseline), 4),
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
