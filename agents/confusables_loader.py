"""Unicode TR#39 confusables catalog loader.

Parses the confusables.txt file published by the Unicode Consortium:
  https://www.unicode.org/Public/security/latest/confusables.txt

The catalog maps each confusable source character to the list of characters
it can be confused with (the "prototype" characters). This is used by the
IDN Agent to detect cross-script lookalike characters.
"""
from __future__ import annotations

import logging
import unicodedata
from pathlib import Path

logger = logging.getLogger(__name__)

# Type alias: char → list of chars it can be confused with
ConfusablesCatalog = dict[str, list[str]]

# Scripts with known lookalike characters for the Latin alphabet.
# Kept here as the single authoritative definition — imported by idn_agent.py.
CONFUSABLE_SCRIPTS = frozenset({"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"})


def _hex_seq_to_str(hex_seq: str) -> str:
    """Convert a space-separated hex codepoint sequence to a Python string.

    Example: "0430" → "а"  (Cyrillic small letter A)
    Example: "0041 0301" → "Á"  (multi-codepoint)
    """
    return "".join(chr(int(cp, 16)) for cp in hex_seq.strip().split())


def load_confusables(path: str | Path) -> ConfusablesCatalog:
    """Parse a Unicode TR#39 confusables.txt file into a catalog dict.

    Returns:
        dict mapping each confusable source character to the list of
        prototype characters it can be confused with.

    Returns an empty dict (with a warning) if the file does not exist,
    allowing the IDN Agent to fall back to its heuristic detection.
    """
    p = Path(path)
    if not p.exists():
        logger.warning(
            "Confusables catalog not found at '%s'. "
            "IDN detection will use heuristic fallback. "
            "Download from https://www.unicode.org/Public/security/latest/confusables.txt",
            p,
        )
        return {}

    catalog: ConfusablesCatalog = {}
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip inline comment before splitting on ";"
                if "#" in line:
                    line = line[: line.index("#")].strip()
                parts = line.split(";")
                if len(parts) < 2:
                    continue
                source_hex = parts[0].strip()
                target_hex = parts[1].strip()
                if not source_hex or not target_hex:
                    continue
                try:
                    source_char = _hex_seq_to_str(source_hex)
                    target_char = _hex_seq_to_str(target_hex)
                except ValueError:
                    continue
                if source_char not in catalog:
                    catalog[source_char] = []
                if target_char not in catalog[source_char]:
                    catalog[source_char].append(target_char)
    except OSError as exc:
        logger.error("Failed to read confusables catalog at '%s': %s", p, exc)
        return {}

    logger.info("Loaded confusables catalog: %d entries from '%s'", len(catalog), p)
    return catalog


def char_script(char: str) -> str:
    """Return the Unicode script name of a single character (uppercase).

    Uses unicodedata.name() as a heuristic — checks if the character name
    contains a known script keyword (e.g., "CYRILLIC", "GREEK").
    Returns "LATIN" for Latin characters and "UNKNOWN" for unrecognised ones.
    """
    try:
        name = unicodedata.name(char, "").upper()
        for script in CONFUSABLE_SCRIPTS:
            if script in name:
                return script
        return "LATIN"
    except Exception:
        return "UNKNOWN"


def detect_confusables(
    domain_unicode: str,
    catalog: ConfusablesCatalog,
) -> list[dict]:
    """Detect confusable characters in a domain string.

    For each character in *domain_unicode* that belongs to a confusable
    script, this function attempts to find a Latin lookalike:

    1. Catalog lookup (precise, TR#39-based): if the character is in the
       catalog and has a Latin lookalike, report it with that lookalike.
    2. Heuristic fallback (when catalog is empty or char is absent): if the
       character's Unicode name contains a confusable script keyword, report
       it with ``lookalike=None``.

    Args:
        domain_unicode: Normalised (NFC) domain string.
        catalog: TR#39 confusables catalog from :func:`load_confusables`.
                 Pass an empty dict to use heuristic-only detection.

    Returns:
        List of dicts, one per confusable character found::

            {"char": "а", "position": 1, "script": "Cyrillic", "lookalike": "a"}

        ``lookalike`` is ``None`` when only the heuristic fired.
    """
    result: list[dict] = []
    for pos, char in enumerate(domain_unicode):
        if char in (".", "-", "_", " "):
            continue

        script = char_script(char)
        if script not in CONFUSABLE_SCRIPTS:
            continue  # Latin or unknown — not a cross-script confusable

        lookalikes = catalog.get(char, [])
        if lookalikes:
            # Find the first lookalike that is NOT itself a confusable-script char
            latin_lookalike: str | None = None
            for lk in lookalikes:
                if char_script(lk) not in CONFUSABLE_SCRIPTS:
                    latin_lookalike = lk
                    break
            if latin_lookalike is not None:
                result.append(
                    {
                        "char": char,
                        "position": pos,
                        "script": script.capitalize(),
                        "lookalike": latin_lookalike,
                    }
                )
        else:
            # Char not in catalog — heuristic-only detection (lookalike unknown)
            result.append(
                {
                    "char": char,
                    "position": pos,
                    "script": script.capitalize(),
                    "lookalike": None,
                }
            )

    return result
