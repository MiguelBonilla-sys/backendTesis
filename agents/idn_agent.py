"""
IDN Agent — 5-stage homograph phishing detection pipeline.
Spec: CLAUDE.md § "5-stage IDN detection algorithm"
"""
from __future__ import annotations

import time
import unicodedata
from pathlib import Path

from core.config import settings
from core.constants import (
    BETA,
    F_MIX,
    HOMOGRAPH_THRESHOLD,
    IDN_CACHE_PREFIX,
    RAG_TOP_K,
    SIM_V_EARLY_EXIT,
)
from core.exceptions import IDNAnalysisError
from core.logger import get_logger
from agents.confusables_loader import (
    detect_confusables,
    is_mixed_script,
    load_confusables_catalog,
)
from agents.bktree import BKTree
from utils.url_parser import extract_domain, extract_2ld, extract_idn_label
from schemas.analyze import IDNResult

logger = get_logger(__name__)


class IDNAgent:
    """
    Stateless IDN homograph detection agent.

    Instantiated once at application startup; ``analyze()`` is thread-safe
    and async-compatible.  Call ``initialize()`` during the FastAPI lifespan
    before serving requests.

    Pipeline stages
    ---------------
    1. NFC normalisation + Punycode decoding (RFC 5890/5891)
    2. UTR#39 confusable character detection
    3. Homograph ratio  r_h = |confusable_chars| / |chars(2LD)|
    4. Visual similarity sim_v via BKTree (levenshtein_confusable)
    5. Local IDN score S_IDN_local with mixed-script floor rule
    """

    def __init__(self) -> None:
        self._confusables: dict[str, list[str]] = {}
        self._bktree: BKTree | None = None
        self._ready: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(
        self,
        confusables_path: str | None = None,
        reference_domains: set[str] | None = None,
    ) -> None:
        """
        Load the confusables catalog and build the BKTree reference index.

        Parameters
        ----------
        confusables_path:
            Path to Unicode TR#39 ``confusables.txt``.  Falls back to
            ``settings.CONFUSABLES_PATH`` when *None*.
        reference_domains:
            Pre-loaded set of reference domains.  When *None*, the agent
            attempts to load from ``settings.TOP1M_PATH``.
        """
        path = confusables_path or settings.CONFUSABLES_PATH
        self._confusables = load_confusables_catalog(path)

        self._bktree = BKTree(self._confusables)

        if reference_domains is not None:
            self._bktree.build_from_set(reference_domains)
            logger.info("idn_agent_initialized", bktree_size=self._bktree.size)
        else:
            top1m_path = Path(settings.TOP1M_PATH)
            if top1m_path.exists():
                domains = await _load_top1m(top1m_path)
                self._bktree.build_from_set(domains)
                logger.info("idn_agent_initialized", bktree_size=self._bktree.size)
            else:
                logger.warning(
                    "idn_agent_no_reference_index", top1m_path=str(top1m_path)
                )

        self._ready = True

    # ------------------------------------------------------------------
    # Main analysis entry point
    # ------------------------------------------------------------------

    async def analyze(self, url: str) -> IDNResult:
        """
        Analyse *url* and return an :class:`IDNResult` with ``s_idn_local``.

        Raises
        ------
        IDNAnalysisError
            If any stage of the pipeline fails unexpectedly.
        """
        t0 = time.perf_counter()

        try:
            # Stage 1 — extract domain and normalise
            # For free hosting platforms (vercel.app, github.io, …) the attacker
            # controls the subdomain — use it as the IDN label instead of the 2LD.
            domain = extract_domain(url)
            label_2ld = extract_idn_label(domain)
            unicode_form = _normalize_and_decode(label_2ld)

            # Stage 2 — UTR#39 confusable detection
            confusable_hits = detect_confusables(unicode_form, self._confusables)
            confusable_chars = [h["char"] for h in confusable_hits]
            mixed = is_mixed_script(unicode_form)

            # Stage 3 — homograph ratio
            r_h = len(confusable_chars) / len(unicode_form) if unicode_form else 0.0

            # Stage 4 — visual similarity via BKTree
            sim_v = 0.0
            if self._bktree is not None and self._bktree.size > 0:
                matches = self._bktree.search(unicode_form, max_dist=3, limit=1000)
                sim_v = matches[0][1] if matches else 0.0

            # Stage 5 — compute S_IDN_local
            f_mix_val = F_MIX if mixed else 1.0
            s_idn_local = (BETA * r_h + (1.0 - BETA) * sim_v) * f_mix_val

            # Floor rule: apply 0.85 floor for high-confidence mixed-script hits
            if mixed and (sim_v >= 0.90 or r_h > 0.10):
                s_idn_local = max(s_idn_local, 0.85)

            # Saturate to [0.0, 1.0]
            s_idn_local = min(s_idn_local, 1.0)

            is_suspicious = r_h >= HOMOGRAPH_THRESHOLD or sim_v >= SIM_V_EARLY_EXIT

            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.debug(
                "idn_agent_result",
                url=url,
                domain=unicode_form,
                r_h=round(r_h, 4),
                sim_v=round(sim_v, 4),
                s_idn_local=round(s_idn_local, 4),
                mixed=mixed,
                is_suspicious=is_suspicious,
                elapsed_ms=round(elapsed_ms, 2),
            )

            return IDNResult(
                domain_unicode=unicode_form,
                confusable_chars=confusable_chars,
                homograph_ratio=round(r_h, 4),
                visual_similarity=round(sim_v, 4),
                s_idn_local=round(s_idn_local, 4),
                is_mixed_script=mixed,
                is_suspicious=is_suspicious,
            )

        except IDNAnalysisError:
            raise
        except Exception as exc:
            raise IDNAnalysisError(
                message=f"IDN analysis failed for {url}",
                detail=str(exc),
            ) from exc


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _normalize_and_decode(label: str) -> str:
    """Apply NFC normalisation and decode a Punycode (``xn--``) label."""
    label = unicodedata.normalize("NFC", label.lower())
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            pass  # Keep the Punycode form if IDNA decoding fails
    return label


async def _load_top1m(path: Path, limit: int = 1_000_000) -> set[str]:
    """
    Load a Majestic Million / Tranco top-1M CSV into a set of 2LD strings.

    Supports both plain-text (one domain per line) and CSV formats where the
    domain is the last comma-separated field.
    """
    domains: set[str] = set()
    try:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                raw = line.strip()
                if not raw:
                    continue
                # CSV: rank,domain  or  rank,domain,category,...
                parts = raw.split(",")
                domain = parts[-1].strip().lower() if len(parts) > 1 else parts[0].strip().lower()
                labels = domain.split(".")
                if len(labels) >= 2:
                    domains.add(f"{labels[-2]}.{labels[-1]}")
    except OSError as exc:
        logger.warning("top1m_load_failed", path=str(path), error=str(exc))

    logger.info("top1m_loaded", count=len(domains))
    return domains


# ---------------------------------------------------------------------------
# Application singleton — import and use in FastAPI lifespan
# ---------------------------------------------------------------------------

idn_agent = IDNAgent()
