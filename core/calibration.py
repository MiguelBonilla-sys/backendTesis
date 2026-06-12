"""
Calibración adaptativa de θ (T12 — docs/tasks.md).

θ efectivo en runtime: arranca en ``THETA`` (valor ROC del Sprint 6) y puede
ser ajustado por el job ``scripts/recalibrate_theta.py`` usando el feedback
FP/FN confirmado por admins en PostgreSQL.

Guardrails:
- θ solo se mueve dentro de ``[THETA - THETA_DRIFT_MAX, THETA + THETA_DRIFT_MAX]``
- el job no ajusta con menos de ``RECAL_MIN_FEEDBACK`` feedbacks nuevos
- cada ajuste queda auditado en la tabla ``theta_calibrations`` y es visible
  en ``GET /api/v1/settings``

La función pura ``choose_theta()`` vive acá para ser unit-testeable sin DB.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.constants import THETA
from core.logger import get_logger

logger = get_logger(__name__)

# Guardrails del job de recalibración
THETA_DRIFT_MAX: float = 0.10     # |θ_nuevo − THETA| ≤ 0.10
RECAL_MIN_FEEDBACK: int = 30      # mínimo de feedbacks confirmados para ajustar
RECAL_LAMBDA: float = 0.30        # loss asimétrica: L = λ·FP + (1−λ)·FN
THETA_SWEEP_STEP: float = 0.01

# θ efectivo en runtime — módulo-level, cargado en lifespan
_effective_theta: float = THETA


def get_effective_theta() -> float:
    """θ vigente para el veredicto PHISHING. Default: ``THETA`` (constante ROC)."""
    return _effective_theta


def set_effective_theta(value: float) -> None:
    """Fija el θ efectivo (clampeado a los guardrails). Uso: lifespan + tests."""
    global _effective_theta
    lo, hi = THETA - THETA_DRIFT_MAX, THETA + THETA_DRIFT_MAX
    _effective_theta = min(max(value, lo), hi)


def reset_effective_theta() -> None:
    """Vuelve al θ base (tests / rollback)."""
    global _effective_theta
    _effective_theta = THETA


async def load_effective_theta_from_db() -> None:
    """
    Carga el último θ calibrado desde ``theta_calibrations`` (si existe).
    Falla en silencio: sin DB o sin tabla, el θ base sigue vigente.
    """
    try:
        from models.database import fetchrow

        row = await fetchrow(
            "SELECT new_theta FROM theta_calibrations "
            "ORDER BY created_at DESC LIMIT 1"
        )
        if row is not None:
            set_effective_theta(float(row["new_theta"]))
            logger.info("effective_theta_loaded", theta=_effective_theta)
    except Exception as exc:
        logger.warning("effective_theta_load_skipped", error=str(exc))


# ---------------------------------------------------------------------------
# Selección de θ — función pura (unit-testeable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecalResult:
    """Resultado de una pasada de recalibración."""

    adjusted: bool
    old_theta: float
    new_theta: float
    n_samples: int
    loss: float
    reason: str


def choose_theta(
    samples: list[tuple[float, bool]],
    base_theta: float = THETA,
    current_theta: float | None = None,
    min_samples: int = RECAL_MIN_FEEDBACK,
    lam: float = RECAL_LAMBDA,
    drift_max: float = THETA_DRIFT_MAX,
    step: float = THETA_SWEEP_STEP,
) -> RecalResult:
    """
    Elige θ minimizando la loss asimétrica sobre feedback confirmado.

    Parameters
    ----------
    samples:
        Lista de ``(s_risk, is_phishing)`` donde ``is_phishing`` es el
        veredicto CONFIRMADO por el admin (ground truth).
    base_theta:
        θ del ROC del Sprint 6 — centro del rango permitido.
    current_theta:
        θ vigente (para reportar el delta). Default: ``base_theta``.

    Loss (coherente con la tesis: FN penalizado más que FP, λ=0.30):
        ``L(θ) = λ·#FP(θ) + (1−λ)·#FN(θ)``

    Returns
    -------
    RecalResult
        ``adjusted=False`` (θ sin cambio) cuando ``len(samples) < min_samples``
        o cuando el θ óptimo coincide con el vigente.
    """
    current = current_theta if current_theta is not None else base_theta

    if len(samples) < min_samples:
        return RecalResult(
            adjusted=False,
            old_theta=current,
            new_theta=current,
            n_samples=len(samples),
            loss=_loss(samples, current, lam),
            reason=f"insufficient_feedback ({len(samples)} < {min_samples})",
        )

    lo, hi = base_theta - drift_max, base_theta + drift_max
    best_theta, best_loss = current, _loss(samples, current, lam)

    theta = lo
    while theta <= hi + 1e-9:
        candidate = round(theta, 4)
        loss = _loss(samples, candidate, lam)
        if loss < best_loss:
            best_theta, best_loss = candidate, loss
        theta += step

    if abs(best_theta - current) < step / 2:
        return RecalResult(
            adjusted=False,
            old_theta=current,
            new_theta=current,
            n_samples=len(samples),
            loss=best_loss,
            reason="optimum_equals_current",
        )

    return RecalResult(
        adjusted=True,
        old_theta=current,
        new_theta=best_theta,
        n_samples=len(samples),
        loss=best_loss,
        reason="loss_minimized",
    )


def _loss(samples: list[tuple[float, bool]], theta: float, lam: float) -> float:
    """Loss asimétrica: FP pesa λ, FN pesa (1−λ) — FN cuesta más (seguridad)."""
    fp = sum(1 for s_risk, is_phish in samples if s_risk >= theta and not is_phish)
    fn = sum(1 for s_risk, is_phish in samples if s_risk < theta and is_phish)
    return lam * fp + (1.0 - lam) * fn
