"""
Generador de homógrafos IDN sintéticos (T5 — docs/tasks.md).

Toma dominios legítimos del índice top-1M y los convierte en homógrafos IDN
sustituyendo caracteres latinos por confusables TR#39 de otros scripts
(Cyrillic, Greek, Armenian, ...). Metodología defendible en la tesis:
ShamFinder (Suzuki et al., 2019) y PhishHunter usan la misma idea para
compensar la escasez de homógrafos IDN reales en los feeds.

El corpus resultante complementa los casos reales de OpenPhish/PhishTank,
documentando explícitamente la proporción sintético/real (ver spec F1).

Uso:
    python -m scripts.generate_idn_corpus --n 500 --out data/idn_synth.jsonl
    python -m scripts.generate_idn_corpus --n 500 --subs-per-domain 2 --seed 42

Salida JSONL, un caso por línea:
    {"domain": "xn--...", "unicode": "gооgle.com", "base": "google.com",
     "substitutions": [{"latin": "o", "confusable": "о", "script": "Cyrillic"}],
     "label": "phishing", "synthetic": true}
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import unicodedata
from pathlib import Path

from agents.confusables_loader import _get_script_name, load_confusables_catalog
from core.config import settings
from core.logger import get_logger

logger = get_logger(__name__)

# Scripts de ataque homógrafo clásico (mismo criterio que el IDN Agent, pero
# en MAYÚSCULA porque _get_script_name devuelve la primera palabra del nombre
# Unicode). Restringir a estos evita ruido como dígitos matemáticos (o→𝟢) o
# variantes latinas que no son cross-script reales — corpus más defendible.
ATTACK_SCRIPTS: frozenset[str] = frozenset(
    {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"}
)


def build_reverse_catalog(
    catalog: dict[str, list[str]],
    attack_scripts: frozenset[str] = ATTACK_SCRIPTS,
) -> dict[str, list[tuple[str, str]]]:
    """
    Invierte el catálogo TR#39 (confusable→[latin]) a (latin→[(confusable, script)]).

    Conserva solo sustituciones donde la fuente es ASCII latino y el confusable
    pertenece a un script de ataque cross-script real (``attack_scripts``).
    """
    reverse: dict[str, list[tuple[str, str]]] = {}
    for confusable, latins in catalog.items():
        if ord(confusable) <= 127:
            continue  # la fuente debe ser no-ASCII para ser un homógrafo útil
        script = _get_script_name(confusable)
        if script not in attack_scripts:
            continue
        for latin in latins:
            if len(latin) == 1 and ord(latin) <= 127 and latin.isalpha():
                reverse.setdefault(latin.lower(), []).append((confusable, script))
    return reverse


def make_homograph(
    domain: str,
    reverse: dict[str, list[tuple[str, str]]],
    subs_per_domain: int,
    rng: random.Random,
) -> dict | None:
    """
    Genera un homógrafo de ``domain`` sustituyendo hasta ``subs_per_domain``
    caracteres del 2LD por confusables. Devuelve None si no hay sustituciones
    posibles (dominio sin letras confundibles).
    """
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    sld = labels[-2]

    candidate_positions = [i for i, ch in enumerate(sld) if ch.lower() in reverse]
    if not candidate_positions:
        return None

    k = min(subs_per_domain, len(candidate_positions))
    chosen = rng.sample(candidate_positions, k)

    chars = list(sld)
    substitutions: list[dict] = []
    for pos in chosen:
        latin = chars[pos].lower()
        confusable, script = rng.choice(reverse[latin])
        chars[pos] = confusable
        substitutions.append(
            {"latin": latin, "confusable": confusable, "script": script}
        )

    homo_sld = "".join(chars)
    homo_domain = ".".join(labels[:-2] + [homo_sld, labels[-1]])

    # Punycode (xn--) del dominio completo — como lo registraría el atacante
    try:
        puny = homo_domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        puny = homo_domain  # algunos confusables no son IDNA-válidos; se omite abajo

    return {
        "domain": puny,
        "unicode": unicodedata.normalize("NFC", homo_domain),
        "base": domain,
        "substitutions": substitutions,
        "label": "phishing",
        "synthetic": True,
    }


def generate(
    n: int,
    subs_per_domain: int,
    seed: int,
    top1m_path: Path,
    confusables_path: Path,
) -> list[dict]:
    rng = random.Random(seed)
    catalog = load_confusables_catalog(confusables_path)
    reverse = build_reverse_catalog(catalog)
    if not reverse:
        raise RuntimeError(
            f"catálogo de confusables vacío en {confusables_path} — "
            "no se pueden generar homógrafos"
        )

    # Carga perezosa de dominios base
    base_domains: list[str] = []
    if top1m_path.exists():
        with open(top1m_path, encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                parts = raw.split(",")
                d = (parts[-1] if len(parts) > 1 else parts[0]).strip().lower()
                if "." in d:
                    base_domains.append(d)
                if len(base_domains) >= n * 4:  # margen para descartes
                    break
    if not base_domains:
        raise RuntimeError(f"no se cargaron dominios base desde {top1m_path}")

    rng.shuffle(base_domains)
    cases: list[dict] = []
    for domain in base_domains:
        case = make_homograph(domain, reverse, subs_per_domain, rng)
        if case and case["domain"] != case["base"]:
            cases.append(case)
        if len(cases) >= n:
            break

    logger.info("idn_corpus_generated", requested=n, produced=len(cases))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Generador de homógrafos IDN sintéticos")
    parser.add_argument("--n", type=int, default=500, help="número de homógrafos a generar")
    parser.add_argument("--subs-per-domain", type=int, default=1, help="sustituciones por dominio")
    parser.add_argument("--seed", type=int, default=42, help="semilla para reproducibilidad")
    parser.add_argument("--out", type=str, default="data/idn_synth.jsonl")
    parser.add_argument("--top1m", type=str, default=settings.TOP1M_PATH)
    parser.add_argument("--confusables", type=str, default=settings.CONFUSABLES_PATH)
    args = parser.parse_args()

    cases = generate(
        n=args.n,
        subs_per_domain=args.subs_per_domain,
        seed=args.seed,
        top1m_path=Path(args.top1m),
        confusables_path=Path(args.confusables),
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")

    print(
        f"Generados {len(cases)} homógrafos IDN sintéticos → {out_path}\n"
        f"  seed={args.seed}, subs/domain={args.subs_per_domain}\n"
        f"  ejemplo: {cases[0]['unicode']} (base: {cases[0]['base']})"
        if cases
        else "Sin casos generados."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
