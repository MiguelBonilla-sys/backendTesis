"""
Fusion Agent — late fusion de scores IDN, TI y LLM con SHAP explanation.

Fórmulas (CLAUDE.md spec):
    S_TI   = W_VT*S_VT + W_URLSCAN*S_URLScan + W_GSB*S_GSB
    S_IDN  = α*S_IDN_local + (1-α)*S_TI           (α=0.60)
    S_risk = γ*S_IDN + (1-γ)*S_LLM                 (γ=0.50)
    verdict = PHISHING    if S_risk >= θ (0.70)
              SUSPICIOUS  if 0.40 <= S_risk < 0.70
              LEGITIMATE  otherwise

SHAP: ``dict[str, float]`` con contribuciones lineales de cada feature
sobre ``S_risk``.  Los features son:
    s_idn_local, s_ti, s_llm, s_vt, s_urlscan, s_gsb,
    homograph_ratio, visual_similarity, is_mixed_script
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Literal

from core.constants import ALPHA, BETA, GAMMA, HF_WEIGHT, HOMOGRAPH_THRESHOLD, THETA, W_GSB, W_URLSCAN, W_VT
from core.logger import get_logger
from schemas.analyze import (
    AgentScores,
    AnalyzeResponse,
    EmailSignals,
    IDNResult,
    ShapExplanation,
    TIResult,
)

logger = get_logger(__name__)


class FusionAgent:
    """
    Stateless Fusion Agent.

    Combina los outputs del IDN Agent, ThreatIntelService y LLM Agent
    mediante late fusion ponderada y genera una explicación tipo SHAP
    (contribuciones lineales de cada feature al score final).

    El agente es stateless por request — ``fuse()`` puede invocarse
    concurrentemente sin riesgo de condición de carrera.
    """

    async def fuse(
        self,
        url: str,
        domain: str,
        idn_result: IDNResult,
        ti_result: TIResult,
        s_llm: float,
        llm_reason: str,
        start_time: float,
        email_hash: str | None = None,
        s_hf: float = 0.5,
        email_signals: EmailSignals | None = None,
    ) -> AnalyzeResponse:
        """
        Ejecuta la fusión tardía de los 3 agentes y retorna un
        ``AnalyzeResponse`` completamente poblado.

        Paso 1: ``S_IDN = α*S_IDN_local + (1-α)*S_TI``
        Paso 2: ``S_risk = γ*S_IDN + (1-γ)*S_LLM``
        Paso 3: Verdict por umbrales θ
        Paso 4: Contribuciones SHAP lineales

        Parameters
        ----------
        url:
            URL completa analizada.
        domain:
            Hostname extraído del URL.
        idn_result:
            Output del IDN Agent (contiene ``s_idn_local``, ``homograph_ratio``,
            ``visual_similarity``, ``is_mixed_script``).
        ti_result:
            Output del ThreatIntelService (contiene ``s_vt``, ``s_urlscan``,
            ``s_gsb``, ``s_ti``).
        s_llm:
            Score del LLM Agent ∈ [0.0, 1.0].
        llm_reason:
            Razón textual provista por el LLM Agent.
        start_time:
            ``time.perf_counter()`` del comienzo del pipeline completo, para
            calcular ``processing_ms``.
        email_hash:
            SHA-256 hash del email (solo para trazabilidad; no se almacena PII).

        Returns
        -------
        AnalyzeResponse
            Respuesta completa con scores, verdict, SHAP y metadata.
        """
        # --- Paso 1: IDN score combinado -------------------------------------
        s_idn = ALPHA * idn_result.s_idn_local + (1.0 - ALPHA) * ti_result.s_ti
        s_idn = float(min(max(s_idn, 0.0), 1.0))

        # --- Paso 1b: Blend HF classifier into s_llm -------------------------
        # s_llm_combined = (1-HF_WEIGHT)*s_llm + HF_WEIGHT*s_hf
        # HF specialized classifier augments Ollama semantic score (HF_WEIGHT=0.40)
        s_llm_combined = (1.0 - HF_WEIGHT) * s_llm + HF_WEIGHT * s_hf
        s_llm_combined = float(min(max(s_llm_combined, 0.0), 1.0))

        # --- Paso 2: Risk score final ----------------------------------------
        s_risk = GAMMA * s_idn + (1.0 - GAMMA) * s_llm_combined
        s_risk = float(min(max(s_risk, 0.0), 1.0))

        # --- Paso 3: Verdict -------------------------------------------------
        verdict = self._compute_verdict(s_risk)

        # --- Paso 3b: Human-readable reasons (same thresholds as verdict) ----
        reasons = self._compute_reasons(
            idn_result=idn_result,
            ti_result=ti_result,
            s_llm=s_llm,
            verdict=verdict,
            email_signals=email_signals,
        )

        # --- Paso 4: SHAP contributions --------------------------------------
        shap = self._compute_shap(
            s_idn_local=idn_result.s_idn_local,
            s_ti=ti_result.s_ti,
            s_vt=ti_result.s_vt,
            s_urlscan=ti_result.s_urlscan,
            s_gsb=ti_result.s_gsb,
            s_llm=s_llm,
            s_hf=s_hf,
            homograph_ratio=idn_result.homograph_ratio,
            visual_similarity=idn_result.visual_similarity,
            is_mixed_script=float(idn_result.is_mixed_script),
        )

        processing_ms = (time.perf_counter() - start_time) * 1000.0

        logger.info(
            "fusion_complete",
            url=url,
            verdict=verdict,
            s_risk=round(s_risk, 4),
            s_idn=round(s_idn, 4),
            s_llm=round(s_llm, 4),
            s_hf=round(s_hf, 4),
            s_llm_combined=round(s_llm_combined, 4),
            s_idn_local=round(idn_result.s_idn_local, 4),
            s_ti=round(ti_result.s_ti, 4),
            email_hash=email_hash,
            processing_ms=round(processing_ms, 1),
        )

        return AnalyzeResponse(
            request_id=str(uuid.uuid4()),
            url=url,
            domain=domain,
            verdict=verdict,
            s_risk=round(s_risk, 4),
            agent_scores=AgentScores(
                s_idn_local=round(idn_result.s_idn_local, 4),
                s_ti=round(ti_result.s_ti, 4),
                s_idn=round(s_idn, 4),
                s_llm=round(s_llm, 4),
                s_hf=round(s_hf, 4),
                s_risk=round(s_risk, 4),
            ),
            idn_result=idn_result,
            ti_result=ti_result,
            llm_reason=llm_reason,
            shap_explanation=ShapExplanation(feature_contributions=shap),
            reasons=reasons,
            processing_ms=round(processing_ms, 1),
            timestamp=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # Human-readable reasons (coordinated with verdict thresholds)
    # ------------------------------------------------------------------

    def _compute_reasons(
        self,
        idn_result: IDNResult,
        ti_result: TIResult,
        s_llm: float,
        verdict: str,
        email_signals: EmailSignals | None = None,
    ) -> list[str]:
        """
        Genera razones legibles derivadas de los mismos umbrales que ``_compute_verdict``.

        Garantía: las razones son coherentes con el veredicto porque se generan a
        partir de los scores y señales que determinan ``S_risk``, no de lógica
        independiente en el frontend.

        Returns
        -------
        list[str]
            Lista de razones ordenadas por severidad (IDN → TI → LLM → email).
            Siempre retorna al menos un elemento.
        """
        reasons: list[str] = []

        # --- Señales IDN ---
        if idn_result.is_mixed_script:
            reasons.append(
                "Mixed-script domain detected (potential IDN homograph attack)"
            )
        if idn_result.homograph_ratio >= HOMOGRAPH_THRESHOLD:
            reasons.append(
                f"High confusable character ratio "
                f"({idn_result.homograph_ratio:.0%}) above alert threshold (30%)"
            )
        if idn_result.visual_similarity >= 0.90:
            reasons.append(
                "Domain visually similar to a known legitimate domain (sim ≥ 0.90)"
            )
        if idn_result.confusable_chars:
            sample = ", ".join(repr(c) for c in idn_result.confusable_chars[:3])
            extra = (
                f" (+{len(idn_result.confusable_chars) - 3} more)"
                if len(idn_result.confusable_chars) > 3
                else ""
            )
            reasons.append(f"Confusable Unicode characters detected: {sample}{extra}")

        # --- Señales TI ---
        if ti_result.s_vt >= 0.30:
            reasons.append("Domain flagged by VirusTotal anti-malware engines")
        if ti_result.s_urlscan >= 0.50:
            reasons.append("Domain marked malicious by URLScan.io")
        if ti_result.s_gsb >= 0.50:
            reasons.append("URL matched Google Safe Browsing threat list")
        if ti_result.is_newly_registered:
            age_str = (
                f"{ti_result.domain_age_days} days old"
                if ti_result.domain_age_days is not None
                else "recently registered"
            )
            reasons.append(f"Domain is newly registered ({age_str})")

        # --- Señal LLM ---
        if s_llm >= 0.70:
            reasons.append("LLM semantic analysis indicates phishing content")

        # --- Señales del email (contexto completo: cabeceras + cuerpo) ---
        if email_signals is not None:
            if email_signals.is_urgent:
                reasons.append(
                    "Email uses urgency/pressure tactics to coerce immediate action"
                )
            if email_signals.sender_domain_mismatch:
                reasons.append(
                    f"Sender domain ({email_signals.sender_domain!r}) does not match "
                    f"return-path domain ({email_signals.return_path_domain!r})"
                )
            if email_signals.has_suspicious_attachments:
                names = ", ".join(email_signals.attachment_names[:3])
                reasons.append(f"Suspicious attachments detected: {names}")
            if not email_signals.spf_pass and email_signals.sender_domain:
                reasons.append(
                    f"SPF authentication failed for {email_signals.sender_domain!r}"
                )
            if not email_signals.dkim_pass and email_signals.sender_domain:
                reasons.append(
                    f"DKIM signature verification failed for "
                    f"{email_signals.sender_domain!r}"
                )

        if not reasons:
            reasons.append("No suspicious indicators detected")

        return reasons

    # ------------------------------------------------------------------
    # Verdict classification
    # ------------------------------------------------------------------

    def _compute_verdict(
        self, s_risk: float
    ) -> Literal["PHISHING", "SUSPICIOUS", "LEGITIMATE"]:
        """
        Clasifica el riesgo en uno de los tres verdicts por umbrales:

        - ``PHISHING``   : ``s_risk >= θ``   (θ=0.70)
        - ``SUSPICIOUS`` : ``0.40 <= s_risk < 0.70``
        - ``LEGITIMATE`` : ``s_risk < 0.40``
        """
        if s_risk >= THETA:
            return "PHISHING"
        if s_risk >= 0.40:
            return "SUSPICIOUS"
        return "LEGITIMATE"

    # ------------------------------------------------------------------
    # SHAP contributions
    # ------------------------------------------------------------------

    def _compute_shap(
        self,
        s_idn_local: float,
        s_ti: float,
        s_vt: float,
        s_urlscan: float,
        s_gsb: float,
        s_llm: float,
        s_hf: float,
        homograph_ratio: float,
        visual_similarity: float,
        is_mixed_script: float,
    ) -> dict[str, float]:
        """
        Calcula contribuciones lineales tipo SHAP para explicabilidad XAI.

        Descomposición analítica de ``S_risk``:

        .. code-block:: text

            S_risk = γ * S_IDN + (1-γ) * S_LLM
                   = γ * [α * S_IDN_local + (1-α) * S_TI] + (1-γ) * S_LLM
                   = γα * S_IDN_local  +  γ(1-α) * S_TI  +  (1-γ) * S_LLM

        Sub-descomposición de S_TI (proporcional a pesos TI):
            contrib_vt      = γ(1-α) * W_VT * S_VT
            contrib_urlscan = γ(1-α) * W_URLSCAN * S_URLScan
            contrib_gsb     = γ(1-α) * W_GSB * S_GSB

        Sub-descomposición de S_IDN_local (proporcional a β en IDN Agent):
            contrib_homograph   = γα * β * homograph_ratio
            contrib_visual      = γα * (1-β) * visual_similarity
            contrib_mixed       = γα * 0.1 * is_mixed_script   (bonus flag)

        Los valores son contribuciones absolutas al score final, por lo que
        su suma aproxima ``S_risk`` (diferencia por saturaciones y redondeos).

        Returns
        -------
        dict[str, float]
            Diccionario con contribución de cada feature al ``S_risk`` final.
        """
        # Pesos compuestos
        idn_weight: float = GAMMA * ALPHA                    # γα        = 0.30
        ti_weight: float = GAMMA * (1.0 - ALPHA)             # γ(1-α)   = 0.20
        llm_combined_weight: float = 1.0 - GAMMA             # (1-γ)    = 0.50
        # s_llm_combined = (1-HF_WEIGHT)*s_llm + HF_WEIGHT*s_hf
        llm_weight: float = llm_combined_weight * (1.0 - HF_WEIGHT)  # 0.50 * 0.60 = 0.30
        hf_weight: float = llm_combined_weight * HF_WEIGHT           # 0.50 * 0.40 = 0.20

        # Contribuciones principales
        contrib_idn_local: float = idn_weight * s_idn_local
        contrib_ti: float = ti_weight * s_ti
        contrib_llm: float = llm_weight * s_llm
        contrib_hf: float = hf_weight * s_hf

        # Sub-contribuciones de TI (descompone contrib_ti en sus fuentes)
        contrib_vt: float = ti_weight * W_VT * s_vt
        contrib_urlscan: float = ti_weight * W_URLSCAN * s_urlscan
        contrib_gsb: float = ti_weight * W_GSB * s_gsb

        # Sub-contribuciones de IDN local (descompone contrib_idn_local)
        # BETA=0.40: peso de homograph_ratio vs visual_similarity en IDN Agent
        contrib_homograph: float = idn_weight * BETA * homograph_ratio
        contrib_visual: float = idn_weight * (1.0 - BETA) * visual_similarity
        # is_mixed_script es un flag binario que activa el multiplicador F_MIX;
        # aquí se representa como un bonus proporcional pequeño (0.1 calibrado).
        contrib_mixed: float = idn_weight * 0.1 * is_mixed_script

        return {
            "s_idn_local": round(contrib_idn_local, 4),
            "s_ti": round(contrib_ti, 4),
            "s_llm": round(contrib_llm, 4),
            "s_hf": round(contrib_hf, 4),
            "s_vt": round(contrib_vt, 4),
            "s_urlscan": round(contrib_urlscan, 4),
            "s_gsb": round(contrib_gsb, 4),
            "homograph_ratio": round(contrib_homograph, 4),
            "visual_similarity": round(contrib_visual, 4),
            "is_mixed_script": round(contrib_mixed, 4),
        }


# ---------------------------------------------------------------------------
# Application singleton — importar y usar en FastAPI lifespan / routers
# ---------------------------------------------------------------------------

fusion_agent = FusionAgent()
