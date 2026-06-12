"""
Job de recalibración adaptativa de θ (T12 — docs/tasks.md).

Reajusta el umbral de veredicto PHISHING usando el feedback FP/FN confirmado
por admins, con la misma loss asimétrica de la tesis (FN > FP, λ=0.30).

Diseñado para correr como k8s CronJob (reutiliza la plantilla de eval-job)
o manualmente:

    python -m scripts.recalibrate_theta            # dry-run (no escribe)
    python -m scripts.recalibrate_theta --apply    # persiste si hay ajuste

Guardrails (core/calibration.py):
- mínimo RECAL_MIN_FEEDBACK feedbacks no usados en calibraciones previas
- θ acotado a ±THETA_DRIFT_MAX del valor ROC base
- cada ajuste queda auditado en ``theta_calibrations`` (visible en
  GET /api/v1/settings) — el valor anterior, el nuevo y el N de evidencia
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from core.calibration import (
    RECAL_MIN_FEEDBACK,
    RecalResult,
    choose_theta,
    get_effective_theta,
)
from core.constants import THETA
from core.logger import get_logger

logger = get_logger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS theta_calibrations (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    old_theta   DOUBLE PRECISION NOT NULL,
    new_theta   DOUBLE PRECISION NOT NULL,
    n_feedback  INTEGER      NOT NULL,
    loss        DOUBLE PRECISION NOT NULL,
    reason      TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
"""

_SAMPLES_SQL = """
SELECT i.s_risk, f.confirmed_verdict
  FROM feedback f
  JOIN incidents i ON i.id = f.incident_id
 WHERE f.created_at > COALESCE(
           (SELECT MAX(created_at) FROM theta_calibrations), 'epoch'::timestamptz
       )
"""


async def fetch_samples() -> list[tuple[float, bool]]:
    """Feedback confirmado posterior a la última calibración → (s_risk, truth)."""
    from models.database import fetch

    rows = await fetch(_SAMPLES_SQL)
    return [
        (float(r["s_risk"]), r["confirmed_verdict"] == "PHISHING")
        for r in rows
    ]


async def persist_calibration(result: RecalResult) -> None:
    from models.database import execute

    await execute(_CREATE_TABLE_SQL)
    await execute(
        "INSERT INTO theta_calibrations (old_theta, new_theta, n_feedback, loss, reason) "
        "VALUES ($1, $2, $3, $4, $5)",
        result.old_theta,
        result.new_theta,
        result.n_samples,
        result.loss,
        result.reason,
    )


async def run(apply: bool) -> RecalResult:
    from models.database import execute, init_db

    await init_db()
    await execute(_CREATE_TABLE_SQL)

    samples = await fetch_samples()
    result = choose_theta(
        samples,
        base_theta=THETA,
        current_theta=get_effective_theta(),
    )

    logger.info(
        "recalibration_pass",
        adjusted=result.adjusted,
        old_theta=result.old_theta,
        new_theta=result.new_theta,
        n_samples=result.n_samples,
        loss=round(result.loss, 4),
        reason=result.reason,
        applied=apply and result.adjusted,
    )

    if apply and result.adjusted:
        await persist_calibration(result)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Recalibración adaptativa de θ")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persistir el ajuste en theta_calibrations (default: dry-run)",
    )
    args = parser.parse_args()

    result = asyncio.run(run(apply=args.apply))

    print(
        f"θ {result.old_theta:.2f} → {result.new_theta:.2f} | "
        f"n={result.n_samples} (mín {RECAL_MIN_FEEDBACK}) | "
        f"loss={result.loss:.4f} | {result.reason} | "
        f"{'APLICADO' if args.apply and result.adjusted else 'dry-run / sin cambio'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
