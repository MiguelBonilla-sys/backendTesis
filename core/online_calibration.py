"""
Calibración adaptativa del vector de pesos de fusión {α, γ, w_hf}.

Extiende `core/calibration.py` (que sólo mueve θ) al resto de los pesos que
determinan el veredicto. β vive dentro del IDN Agent y se calibra aparte.

**Por qué NO "con cada análisis":** calibrar un peso requiere ground truth.
Un análisis suelto no lo trae. La señal de etiqueta llega en dos formas
(feedback mixto, cf. PB-OEL, Peng et al. 2025):
  - **real**: feedback FP/FN confirmado por un admin;
  - **pseudo**: consenso fuerte de señales deterministas + conductor
    (semi-supervisado, cf. SEED, Chen et al. 2026) — con peso menor.
El *aprendizaje* es continuo (se acumulan muestras en cada análisis); el
*update* del peso es por lotes y acotado — mover un peso por una muestra
ruidosa es inestable y, en un contexto adversario, se auto-refuerza
(deriva performativa, cf. Harris et al. 2024).

Guardrails (misma filosofía que `core/calibration.py`):
  - cada peso sólo se mueve dentro de ``±WEIGHT_DRIFT_MAX`` de su valor de
    tesis (ROC Sprint 6);
  - mínimo ``RECAL_MIN_LABELS`` etiquetas nuevas para ajustar;
  - misma loss asimétrica de la tesis (FN pesa más que FP, λ=0.30);
  - cada ajuste queda auditado en ``weight_calibrations`` y visible en
    ``GET /api/v1/settings``.
  - kill-switch: ``settings.ONLINE_CALIBRATION_ENABLED`` (default False) —
    los pesos de la tesis siguen congelados como baseline del eval.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.constants import ALPHA, GAMMA, HF_WEIGHT
from core.logger import get_logger

logger = get_logger(__name__)

# Guardrails
WEIGHT_DRIFT_MAX: float = 0.15   # |w_nuevo − w_tesis| ≤ 0.15 por peso
RECAL_MIN_LABELS: int = 40       # mínimo de etiquetas (real+pseudo) para ajustar
RECAL_LAMBDA: float = 0.30       # loss asimétrica: L = λ·FP + (1−λ)·FN
WEIGHT_SWEEP_STEP: float = 0.05  # grilla de búsqueda por peso
PSEUDO_LABEL_WEIGHT: float = 0.5  # una pseudo-etiqueta cuenta como media muestra

# Baseline de tesis — centro del rango permitido para cada peso
_BASE = {"alpha": ALPHA, "gamma": GAMMA, "w_hf": HF_WEIGHT}

# Pesos efectivos en runtime — módulo-level, cargados en lifespan
_effective: dict[str, float] = dict(_BASE)


def get_effective_weights() -> dict[str, float]:
    """{'alpha','gamma','w_hf'} vigentes. Default: constantes de tesis."""
    return dict(_effective)


def set_effective_weights(values: dict[str, float]) -> None:
    """Fija los pesos efectivos, clampeando cada uno a ``±WEIGHT_DRIFT_MAX``."""
    for k, base in _BASE.items():
        if k in values:
            lo, hi = base - WEIGHT_DRIFT_MAX, base + WEIGHT_DRIFT_MAX
            _effective[k] = min(max(float(values[k]), lo), hi)


def reset_effective_weights() -> None:
    """Vuelve a los pesos base de tesis (tests / rollback)."""
    _effective.update(_BASE)


async def load_effective_weights_from_db() -> None:
    """Carga la última calibración desde ``weight_calibrations`` (si existe).
    Falla en silencio: sin DB/tabla, siguen los pesos de tesis."""
    try:
        from models.database import fetchrow

        row = await fetchrow(
            "SELECT alpha, gamma, w_hf FROM weight_calibrations "
            "ORDER BY created_at DESC LIMIT 1"
        )
        if row is not None:
            set_effective_weights(
                {"alpha": float(row["alpha"]), "gamma": float(row["gamma"]),
                 "w_hf": float(row["w_hf"])}
            )
            logger.info("effective_weights_loaded", **get_effective_weights())
    except Exception as exc:
        logger.warning("effective_weights_load_skipped", error=str(exc))


# ---------------------------------------------------------------------------
# Selección de pesos — función pura (unit-testeable, sin DB)
# ---------------------------------------------------------------------------

# Una muestra: (s_idn_local, s_ti, s_llm, s_hf, is_phishing, is_pseudo)
Sample = tuple[float, float, float, float, bool, bool]


@dataclass(frozen=True)
class WeightRecalResult:
    adjusted: bool
    old: dict[str, float]
    new: dict[str, float]
    n_labels: float          # efectivo (pseudo cuenta 0.5)
    loss: float
    reason: str


def _s_risk(s: Sample, alpha: float, gamma: float, w_hf: float) -> float:
    s_idn_local, s_ti, s_llm, s_hf, _, _ = s
    s_llm_comb = (1.0 - w_hf) * s_llm + w_hf * s_hf
    s_idn = alpha * s_idn_local + (1.0 - alpha) * s_ti
    return gamma * s_idn + (1.0 - gamma) * s_llm_comb


def _loss(
    samples: list[Sample], alpha: float, gamma: float, w_hf: float,
    theta: float, lam: float,
) -> float:
    """L = λ·Σw·FP + (1−λ)·Σw·FN ; pseudo-etiquetas pesan PSEUDO_LABEL_WEIGHT."""
    fp = fn = 0.0
    for s in samples:
        *_, is_phish, is_pseudo = s
        w = PSEUDO_LABEL_WEIGHT if is_pseudo else 1.0
        risk = _s_risk(s, alpha, gamma, w_hf)
        if risk >= theta and not is_phish:
            fp += w
        elif risk < theta and is_phish:
            fn += w
    return lam * fp + (1.0 - lam) * fn


def _effective_n(samples: list[Sample]) -> float:
    return sum(PSEUDO_LABEL_WEIGHT if s[5] else 1.0 for s in samples)


def choose_weights(
    samples: list[Sample],
    theta: float,
    current: dict[str, float] | None = None,
    min_labels: int = RECAL_MIN_LABELS,
    lam: float = RECAL_LAMBDA,
    drift_max: float = WEIGHT_DRIFT_MAX,
    step: float = WEIGHT_SWEEP_STEP,
) -> WeightRecalResult:
    """
    Coordinate-descent acotado sobre {α, γ, w_hf} minimizando la loss
    asimétrica de la tesis sobre muestras etiquetadas. θ se pasa fijo
    (lo calibra ``core.calibration.choose_theta`` por separado).

    Cada peso se busca en ``[base ± drift_max]`` en pasos de ``step``.
    3 pasadas de coordinate-descent bastan para converger en esta grilla.
    """
    cur = dict(current) if current else dict(_BASE)
    n_eff = _effective_n(samples)
    base_loss = _loss(samples, cur["alpha"], cur["gamma"], cur["w_hf"], theta, lam)

    if n_eff < min_labels:
        return WeightRecalResult(
            False, cur, cur, n_eff, base_loss,
            f"insufficient_labels ({n_eff:.1f} < {min_labels})",
        )

    def grid(name: str) -> list[float]:
        b = _BASE[name]
        vals, v = [], b - drift_max
        while v <= b + drift_max + 1e-9:
            vals.append(round(v, 4))
            v += step
        return vals

    best = dict(cur)
    best_loss = base_loss
    for _ in range(3):
        for name in ("alpha", "gamma", "w_hf"):
            for cand in grid(name):
                trial = dict(best)
                trial[name] = cand
                loss = _loss(samples, trial["alpha"], trial["gamma"],
                             trial["w_hf"], theta, lam)
                if loss < best_loss - 1e-9:
                    best_loss, best = loss, trial

    changed = any(abs(best[k] - cur[k]) >= step / 2 for k in _BASE)
    return WeightRecalResult(
        adjusted=changed,
        old=cur,
        new=best if changed else cur,
        n_labels=n_eff,
        loss=best_loss,
        reason="loss_minimized" if changed else "optimum_equals_current",
    )
