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

# NEW: Import for better script detection if available
try:
    import unicodedata2 as ud2
except ImportError:
    ud2 = None

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
        # Priority 1: Check known Scripts from CONFUSABLE_SCRIPTS
        name = unicodedata.name(char, "").upper()
        for script in CONFUSABLE_SCRIPTS:
            if script in name:
                return script
        
        # Priority 2: Explicitly identify LATIN
        if "LATIN" in name:
            return "LATIN"
        
        # Priority 3: Common symbols/digits are treated as COMMON
        if not name or any(k in name for k in ["DIGIT", "SPACE", "FULL STOP", "HYPHEN"]):
            return "COMMON"
            
        return "OTHER"
    except (ValueError, Exception):
        return "UNKNOWN"


def detect_script_mixing(text: str) -> dict[str, set[str]]:
    """Analyze a string to detect if it contains characters from multiple scripts.

    Phishing attacks often mix scripts (e.g., Latin + Cyrillic) to create
    homographs. Legitimate domains usually stick to a single script.

    Returns:
        A dict mapping script names to the set of characters found for that script.
        Common characters (digits, hyphens) are typically ignored or counted as 'COMMON'.
    """
    scripts_found: dict[str, set[str]] = {}
    for char in text:
        script = char_script(char)
        if script not in scripts_found:
            scripts_found[script] = set()
        scripts_found[script].add(char)
    
    return scripts_found


def detect_confusables(text: str, catalog: ConfusablesCatalog) -> list[dict]:
    """Identify characters in *text* that are present in the confusables *catalog*.

    Returns:
        List of dicts: {"char", "position", "script", "lookalike"}
        - char: The character found in text.
        - position: 0-indexed position in text.
        - script: Unicode script of the character.
        - lookalike: List of prototype characters it can be confused with.
    """
    results = []
    for i, char in enumerate(text):
        if char in catalog:
            results.append(
                {
                    "char": char,
                    "position": i,
                    "script": char_script(char),
                    "lookalike": catalog[char],
                }
            )
    return results
