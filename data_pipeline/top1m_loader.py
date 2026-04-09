"""Top-1M domain index loader for IDN Agent visual similarity search.

Reads the Tranco top-1M list (``data/top1m.txt``) and returns an ordered
list of second-level domain (2LD) labels, preserving Tranco rank order so
that ``IDNAgent._sim_v()`` checks the most popular domains first.

Source: https://tranco-list.eu  (updated weekly)
Format: one FQDN per line, rank-ordered (rank 1 = most popular)
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_top1m(path: str | Path, limit: int | None = None) -> list[str]:
    """Load and extract 2LDs from the top-1M domain list file.

    Reads FQDNs line-by-line, extracts the second-level domain label
    (e.g. ``google`` from ``google.com``), deduplicates while preserving
    rank order, and returns the result as an ordered list.

    Args:
        path: Path to the top-1M text file (one FQDN per line).
        limit: If set, stop after loading this many unique 2LDs.
               Defaults to ``None`` (load all 1M entries).
               For the IDN Agent's ``_sim_v()`` only the first 1000
               entries are ever checked, so ``limit=1000`` is sufficient
               for production runtime (startup is faster and memory is lower).

    Returns:
        Ordered list of 2LD strings (no duplicates), preserving rank order.
        Returns empty list (with a warning) if the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        logger.warning(
            "Top-1M domain index not found at '%s'. "
            "IDN visual similarity will return 0.0 for all domains. "
            "Download from https://tranco-list.eu/top-1m.csv.zip",
            p,
        )
        return []

    seen: set[str] = set()
    result: list[str] = []
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                fqdn = line.strip().lower()
                if not fqdn:
                    continue
                # Extract 2LD: last label before the TLD
                parts = fqdn.rstrip(".").split(".")
                label = parts[-2] if len(parts) >= 2 else parts[0]
                if label and label not in seen:
                    seen.add(label)
                    result.append(label)
                    if limit is not None and len(result) >= limit:
                        break
    except OSError as exc:
        logger.error("Failed to read top-1M index at '%s': %s", p, exc)
        return []

    logger.info(
        "Loaded top-1M index: %d unique 2LDs from '%s'%s",
        len(result),
        p,
        f" (limit={limit})" if limit else "",
    )
    return result
