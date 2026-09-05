"""
Recalibración adaptativa del vector de pesos de fusión {α, γ, w_hf}.

Extiende ``scripts/recalibrate_theta.py`` al resto de los pesos. Misma
filosofía: lote + guardrails + auditoría, nunca por-análisis (ver
``core/online_calibration.py`` para el porqué).

Fuentes de etiquetas:
  --from-db      feedback FP/FN confirmado por admins (real). `incidents` hoy NO
                 guarda s_hf ni s_idn_local separados → se usan
                 s_idn_local≈s_idn y s_hf≈s_llm: esto calibra bien {α, γ} pero
                 NO w_hf. Para calibrar w_hf de verdad hay que agregar
                 incidents.s_hf + incidents.s_idn_local y persistirlos en
                 services/persistence.py.
  --from-pseudo  JSONL de pseudo-etiquetas del conductor (semi-supervisado),
                 líneas: {"signals":[s_idn_local,s_ti,s_llm,s_hf],"phishing":bool}
                 — esta vía SÍ trae las 4 señales reales.

Uso:
    python -m scripts.recalibrate_weights --from-pseudo data/pseudo_labels.jsonl
    python -m scripts.recalibrate_weights --from-db --apply
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from core.calibration import get_effective_theta
from core.constants import ALPHA, GAMMA, HF_WEIGHT
from core.logger import get_logger
from core.online_calibration import (
    RECAL_MIN_LABELS,
    Sample,
    WeightRecalResult,
    choose_weights,
    get_effective_weights,
)

logger = get_logger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS weight_calibrations (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    alpha      DOUBLE PRECISION NOT NULL,
    gamma      DOUBLE PRECISION NOT NULL,
    w_hf       DOUBLE PRECISION NOT NULL,
    old_alpha  DOUBLE PRECISION NOT NULL,
    old_gamma  DOUBLE PRECISION NOT NULL,
    old_w_hf   DOUBLE PRECISION NOT NULL,
    n_labels   DOUBLE PRECISION NOT NULL,
    loss       DOUBLE PRECISION NOT NULL,
    reason     TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
"""

# `incidents` no tiene s_hf ni s_idn_local separados → s_idn_local≈s_idn,
# s_hf≈s_llm (calibra {α, γ}, no w_hf). Ver docstring.
_SAMPLES_SQL = """
SELECT
    i.s_idn                            AS s_idn_local,
    i.s_ti                             AS s_ti,
    i.s_llm                            AS s_llm,
    i.s_llm                            AS s_hf,
    (f.confirmed_verdict = 'PHISHING') AS is_phishing
  FROM feedback f
  JOIN incidents i ON i.id = f.incident_id
 WHERE f.created_at > COALESCE(
           (SELECT MAX(created_at) FROM weight_calibrations), 'epoch'::timestamptz
       )
"""


def _from_pseudo(path: Path) -> list[Sample]:
    out: list[Sample] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        s = rec["signals"]
        out.append((float(s[0]), float(s[1]), float(s[2]), float(s[3]),
                    bool(rec["phishing"]), True))
    return out


async def _from_db() -> list[Sample]:
    from models.database import fetch

    rows = await fetch(_SAMPLES_SQL)
    return [
        (float(r["s_idn_local"]), float(r["s_ti"]), float(r["s_llm"]),
         float(r["s_hf"]), bool(r["is_phishing"]), False)
        for r in rows
    ]


async def persist(result: WeightRecalResult) -> None:
    from models.database import execute

    await execute(_CREATE_TABLE_SQL)
    await execute(
        "INSERT INTO weight_calibrations "
        "(alpha, gamma, w_hf, old_alpha, old_gamma, old_w_hf, n_labels, loss, reason) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        result.new["alpha"], result.new["gamma"], result.new["w_hf"],
        result.old["alpha"], result.old["gamma"], result.old["w_hf"],
        result.n_labels, result.loss, result.reason,
    )


async def run(from_db: bool, pseudo_path: str | None, apply: bool) -> WeightRecalResult:
    samples: list[Sample] = []
    if pseudo_path:
        samples += _from_pseudo(Path(pseudo_path))
    if from_db:
        from models.database import execute, init_db

        await init_db()
        await execute(_CREATE_TABLE_SQL)
        samples += await _from_db()

    result = choose_weights(
        samples, theta=get_effective_theta(), current=get_effective_weights()
    )
    logger.info(
        "weight_recalibration_pass",
        adjusted=result.adjusted, old=result.old, new=result.new,
        n_labels=result.n_labels, loss=round(result.loss, 4), reason=result.reason,
        applied=apply and result.adjusted,
    )
    if apply and result.adjusted and from_db:
        await persist(result)
    return result


def main() -> int:
    p = argparse.ArgumentParser(description="Recalibración adaptativa de {α, γ, w_hf}")
    p.add_argument("--from-db", action="store_true", help="usar feedback confirmado")
    p.add_argument("--from-pseudo", type=str, default=None, help="JSONL de pseudo-etiquetas")
    p.add_argument("--apply", action="store_true", help="persistir en weight_calibrations")
    args = p.parse_args()
    if not args.from_db and not args.from_pseudo:
        p.error("indicá --from-db y/o --from-pseudo")

    r = asyncio.run(run(args.from_db, args.from_pseudo, args.apply))
    print(
        f"tesis: α={ALPHA} γ={GAMMA} w_hf={HF_WEIGHT}\n"
        f"actual→nuevo: "
        f"α {r.old['alpha']:.2f}→{r.new['alpha']:.2f}  "
        f"γ {r.old['gamma']:.2f}→{r.new['gamma']:.2f}  "
        f"w_hf {r.old['w_hf']:.2f}→{r.new['w_hf']:.2f}\n"
        f"n={r.n_labels:.1f} (mín {RECAL_MIN_LABELS}) | loss={r.loss:.4f} | {r.reason} | "
        f"{'APLICADO' if args.apply and r.adjusted and args.from_db else 'dry-run / sin cambio'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
