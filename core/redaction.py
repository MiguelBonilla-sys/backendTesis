"""
Redacción de PII antes de enviar contenido de correo a un proveedor LLM externo.

Principio de finalidad (Ley 1581/2012): al proveedor solo debe salir lo que el
sistema necesita analizar — URLs, dominios y la *estructura* del mensaje. Los
identificadores personales se enmascaran con placeholders estables dentro del
mismo texto (``[EMAIL_1]``, ``[PHONE_1]``...) para conservar la correferencia
(que "el mismo remitente aparece tres veces" siga siendo señal).

URLs y dominios NO se redactan: son exactamente lo que el pipeline evalúa.
"""
from __future__ import annotations

import re

# Orden importa: lo más específico primero. Un email debe consumirse antes de
# que su parte local/numérica caiga en otro patrón.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # JWT: tres segmentos base64url separados por puntos, empezando en eyJ
    ("TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    # Claves con prefijo conocido: sk-, pk-, ghp_, gho_, hf_, xoxb-, AKIA...
    ("TOKEN", re.compile(r"\b(?:sk|pk|ghp|gho|hf|xox[bap])[-_][A-Za-z0-9]{16,}\b")),
    ("TOKEN", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # Teléfono: exige al menos un separador o un prefijo internacional para no
    # tragarse cédulas (secuencias de dígitos sin formato → van a ID).
    ("PHONE", re.compile(
        r"(?<![\w.])(?:\+\d{1,3}[ .\-]?)?"
        r"(?:\(\d{2,4}\)[ .\-]?|\d{2,4}[ .\-])"
        r"\d{3}[ .\-]?\d{2,4}(?![\w])"
    )),
    # Cédula / documento / secuencia larga de dígitos sin formato (6-19).
    ("ID", re.compile(r"(?<!\d)\d{6,19}(?!\d)")),
]


def redact(text: str | None) -> str:
    """Enmascara PII en ``text``. Devuelve ``""`` si la entrada es vacía/None."""
    if not text:
        return ""

    counters: dict[str, int] = {}
    seen: dict[str, str] = {}

    def _sub(tag: str, match: re.Match[str]) -> str:
        raw = match.group(0)
        if raw in seen:
            return seen[raw]
        counters[tag] = counters.get(tag, 0) + 1
        placeholder = f"[{tag}_{counters[tag]}]"
        seen[raw] = placeholder
        return placeholder

    out = text
    for tag, pattern in _PATTERNS:
        out = pattern.sub(lambda m, t=tag: _sub(t, m), out)
    return out
