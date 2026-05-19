"""
Unicode TR#39 confusables catalog loader.
Reference: https://www.unicode.org/reports/tr39/
"""
import unicodedata
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)

# Scripts considered high-risk for homograph attacks
CONFUSABLE_SCRIPTS: frozenset[str] = frozenset({
    "Cyrillic", "Greek", "Armenian", "Cherokee", "Coptic",
    "Hangul", "Hiragana", "Katakana", "Hebrew", "Arabic"
})


def load_confusables_catalog(path: str | Path) -> dict[str, list[str]]:
    """
    Load the Unicode TR#39 confusables.txt file.

    Format per line: C1 ; C2 C3... ; # IDENTIFIER_TYPE SCRIPT
    Returns dict {source_char: [confusable_chars]}.
    If the file does not exist, returns an empty dict (heuristic fallback).
    """
    catalog: dict[str, list[str]] = {}
    path = Path(path)

    if not path.exists():
        logger.warning("confusables_catalog_not_found", path=str(path))
        return catalog

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip inline comment
            if "#" in line:
                line = line[: line.index("#")].strip()
            parts = line.split(";")
            if len(parts) < 2:
                continue
            try:
                source_hex = parts[0].strip()
                target_hexes = parts[1].strip().split()
                source_char = chr(int(source_hex, 16))
                target_chars = [chr(int(h, 16)) for h in target_hexes if h]
                if target_chars:
                    catalog[source_char] = target_chars
            except (ValueError, OverflowError):
                continue

    logger.info("confusables_catalog_loaded", entries=len(catalog))
    return catalog


def detect_confusables(label: str, catalog: dict[str, list[str]]) -> list[dict]:
    """
    Detect confusable characters in a domain label.

    Returns a list of dicts: {"char", "position", "script", "lookalike"}.
    Heuristic fallback when catalog is empty: flags every non-ASCII char (ord > 127).
    """
    results: list[dict] = []

    if not catalog:
        # Heuristic fallback: any non-ASCII character is suspicious
        for i, ch in enumerate(label):
            if ord(ch) > 127:
                script = _get_script_name(ch)
                results.append({
                    "char": ch,
                    "position": i,
                    "script": script,
                    "lookalike": "?",
                })
        return results

    for i, ch in enumerate(label):
        if ch in catalog and ord(ch) > 127:
            lookalike = _find_latin_lookalike(ch, catalog[ch])
            script = _get_script_name(ch)
            results.append({
                "char": ch,
                "position": i,
                "script": script,
                "lookalike": lookalike or "?",
            })

    return results


def is_mixed_script(label: str) -> bool:
    """
    Return True if the label mixes Unicode scripts (e.g. Latin + Cyrillic).

    A purely ASCII or single-script label returns False.
    """
    scripts: set[str] = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if name:
                script = name.split()[0]
                scripts.add(script)
    return len(scripts) > 1


def _find_latin_lookalike(ch: str, confusables: list[str]) -> str | None:
    """Return the ASCII/Latin lookalike from the confusables list, or the first entry."""
    for c in confusables:
        if ord(c) < 128:  # ASCII range → Latin
            return c
    return confusables[0] if confusables else None


def _get_script_name(ch: str) -> str:
    """Return the Unicode script name for a character (first word of its Unicode name)."""
    try:
        name = unicodedata.name(ch, "")
        if name:
            return name.split()[0]
    except Exception:
        pass
    return "UNKNOWN"
