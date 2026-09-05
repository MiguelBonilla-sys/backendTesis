"""
AnalysisConductor — orquestador que arbitra los casos difíciles.

El pipeline determinista (`run_pipeline_core`: agentes en paralelo → LLM →
fusión tardía) sigue siendo el camino primario y el baseline del eval de tesis.
El conductor se ejecuta *después* de la fusión, opt-in (`CONDUCTOR_ENABLED`), y
solo interviene cuando el veredicto no es claro (banda "grey-zone", cf. PinSieve
/ PB-OEL):

  - verdict == "SUSPICIOUS", o
  - conflicto fuerte HF↔LLM, o
  - dominancia de una sola señal en SHAP (frágil — cf. Litvak 2026), o
  - s_idn_local ≥ 0.50 con veredicto ≠ PHISHING.

En esos casos hace UNA pasada deliberada del LLM con toda la evidencia (scores
de cada agente + SHAP + razones) y re-arbitra el veredicto. No toca ``s_risk``
ni las contribuciones SHAP — la explicabilidad lineal queda intacta.

Además:
  - lleva un contador rodante de overrides → señal de deriva (cf. drift
    detection, Sarkar et al. 2025);
  - cuando confirma un veredicto con acuerdo fuerte, emite una **pseudo-etiqueta**
    para el calibrador online (semi-supervisado, cf. SEED / PB-OEL).
"""
from __future__ import annotations

from collections import deque

from agents.llm_agent import llm_agent
from core.config import settings
from core.logger import get_logger
from schemas.analyze import AnalyzeResponse

logger = get_logger(__name__)

_CONFLICT_HI = 0.70
_CONFLICT_LO = 0.35
_SINGLE_SIGNAL_DOMINANCE = 0.60   # fracción de s_risk en una sola contribución SHAP
_DRIFT_WINDOW = 100
_DRIFT_ALARM_RATE = 0.35          # override_rate por encima → alarma de deriva

# Muestra para el calibrador online: (s_idn_local, s_ti, s_llm, s_hf, is_phishing, is_pseudo)
PseudoLabel = tuple[float, float, float, float, bool, bool]


class AnalysisConductor:
    """Stateless respecto al contenido. Mantiene solo métricas rodantes."""

    def __init__(self) -> None:
        self._recent_overrides: deque[bool] = deque(maxlen=_DRIFT_WINDOW)
        self.pseudo_labels: deque[PseudoLabel] = deque(maxlen=500)

    # ------------------------------------------------------------------
    # Métricas de deriva
    # ------------------------------------------------------------------

    @property
    def override_rate(self) -> float:
        n = len(self._recent_overrides)
        return sum(self._recent_overrides) / n if n else 0.0

    def _record(self, overridden: bool) -> None:
        self._recent_overrides.append(overridden)
        if len(self._recent_overrides) == _DRIFT_WINDOW and self.override_rate >= _DRIFT_ALARM_RATE:
            logger.warning(
                "conductor_drift_alarm",
                override_rate=round(self.override_rate, 3),
                window=_DRIFT_WINDOW,
                hint="revisar recalibración de pesos / posible concept drift",
            )

    # ------------------------------------------------------------------
    # Trigger
    # ------------------------------------------------------------------

    def should_review(self, resp: AnalyzeResponse) -> bool:
        if resp.verdict == "SUSPICIOUS":
            return True
        s = resp.agent_scores
        if (s.s_hf >= _CONFLICT_HI and s.s_llm <= _CONFLICT_LO) or (
            s.s_llm >= _CONFLICT_HI and s.s_hf <= _CONFLICT_LO
        ):
            return True
        if s.s_idn_local >= 0.50 and resp.verdict != "PHISHING":
            return True
        # Dominancia de una sola señal en un veredicto borderline: el resultado
        # cuelga de un único aporte y no está lejos del umbral SUSPICIOUS.
        if resp.s_risk >= 0.30 and resp.verdict != "PHISHING":
            contribs = resp.shap_explanation.feature_contributions
            primary = {"s_idn_local", "s_ti", "s_llm", "s_hf", "s_email", "s_probe"}
            vals = [abs(v) for k, v in contribs.items() if k in primary]
            total = sum(vals)
            if total > 0 and max(vals) / total >= _SINGLE_SIGNAL_DOMINANCE:
                return True
        return False

    # ------------------------------------------------------------------
    # Evidencia + pseudo-etiqueta
    # ------------------------------------------------------------------

    def _build_evidence(self, resp: AnalyzeResponse) -> str:
        s = resp.agent_scores
        idn = resp.idn_result
        ti = resp.ti_result
        shap = resp.shap_explanation.feature_contributions
        shap_lines = "\n".join(
            f"  {k}: {v:+.4f}" for k, v in sorted(
                shap.items(), key=lambda kv: abs(kv[1]), reverse=True
            )
        )
        probe = ""
        if resp.probe_result is not None and not resp.probe_result.error:
            probe = (
                f"\nWeb probe: s_probe={s.s_probe:.3f}, "
                f"final_domain={resp.probe_result.final_domain!r}, "
                f"signals={resp.probe_result.probe_signals}"
            )
        return (
            f"URL: {resp.url}\n"
            f"Domain (decoded): {idn.domain_unicode!r}  (raw: {resp.domain})\n"
            f"Deterministic fusion verdict: {resp.verdict}  (s_risk={resp.s_risk:.4f})\n\n"
            f"Agent scores:\n"
            f"  IDN local     s_idn_local={s.s_idn_local:.3f}  "
            f"(homograph_ratio={idn.homograph_ratio:.3f}, "
            f"visual_similarity={idn.visual_similarity:.3f}, "
            f"mixed_script={idn.is_mixed_script}, "
            f"confusables={idn.confusable_chars[:6]})\n"
            f"  Threat intel  s_ti={s.s_ti:.3f}  "
            f"(VT={ti.s_vt:.3f}, URLScan={ti.s_urlscan:.3f}, GSB={ti.s_gsb:.3f}, "
            f"newly_registered={ti.is_newly_registered})\n"
            f"  LLM semantic  s_llm={s.s_llm:.3f}  — {resp.llm_reason}\n"
            f"  ML classifier s_hf={s.s_hf:.3f}"
            f"{probe}\n\n"
            f"SHAP contributions to s_risk (desc by magnitude):\n{shap_lines}\n\n"
            f"Deterministic reasons:\n"
            + "\n".join(f"  - {r}" for r in resp.reasons)
        )

    def _maybe_pseudo_label(self, resp: AnalyzeResponse, llm_verdict: str) -> None:
        """Emite pseudo-etiqueta solo con acuerdo fuerte determinista↔LLM."""
        if llm_verdict not in ("PHISHING", "LEGITIMATE"):
            return
        if llm_verdict != resp.verdict:
            return  # sin acuerdo → no etiquetar
        s = resp.agent_scores
        is_phish = llm_verdict == "PHISHING"
        # exige convicción: al menos una señal fuerte en la dirección del label
        strong = max(s.s_idn_local, s.s_ti, s.s_hf) if is_phish else (
            1.0 - min(s.s_idn_local, s.s_ti, s.s_hf)
        )
        if strong < 0.70:
            return
        self.pseudo_labels.append(
            (s.s_idn_local, s.s_ti, s.s_llm, s.s_hf, is_phish, True)
        )
        logger.info(
            "conductor_pseudo_label",
            verdict=llm_verdict,
            signals=[round(s.s_idn_local, 3), round(s.s_ti, 3),
                     round(s.s_llm, 3), round(s.s_hf, 3)],
        )

    # ------------------------------------------------------------------
    # Review
    # ------------------------------------------------------------------

    async def review(self, resp: AnalyzeResponse) -> AnalyzeResponse:
        if not self.should_review(resp):
            return resp

        verdict, reason = await llm_agent.adjudicate(self._build_evidence(resp))

        if not verdict:
            logger.info("conductor_no_verdict", url=resp.url, verdict=resp.verdict)
            self._record(False)
            return resp

        self._maybe_pseudo_label(resp, verdict)

        if verdict == resp.verdict:
            if reason:
                resp.reasons.insert(0, f"[Conductor] Confirma {verdict}: {reason}")
            logger.info("conductor_confirm", url=resp.url, verdict=verdict)
            self._record(False)
            return resp

        logger.info(
            "conductor_override", url=resp.url,
            from_verdict=resp.verdict, to_verdict=verdict, s_risk=resp.s_risk,
        )
        resp.reasons.insert(
            0, f"[Conductor] Re-arbitrado {resp.verdict} → {verdict}: {reason}"
        )
        resp.verdict = verdict  # type: ignore[assignment]  # Literal validado en adjudicate()
        self._record(True)
        return resp


conductor = AnalysisConductor()


async def apply_conductor(resp: AnalyzeResponse) -> AnalyzeResponse:
    """Punto de entrada del pipeline. No-op si ``CONDUCTOR_ENABLED`` es False."""
    if not settings.CONDUCTOR_ENABLED:
        return resp
    return await conductor.review(resp)
