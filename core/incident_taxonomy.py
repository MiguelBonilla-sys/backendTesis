"""Deterministic incident classification over signals the pipeline already computes.

Rules run in a fixed order and only read the analysis result (IDN, probe, TI and
the fusion reasons, which are fixed strings emitted by ``agents/fusion_agent.py``).
Up to three categories are kept; the first is the primary one. The remediation
catalog is guidance for the security admin: the platform never acts on mailboxes.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from schemas.analyze import AnalyzeResponse
from utils.url_parser import _FREE_HOSTING_PLATFORMS

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "remediation_catalog.json"
CATEGORIES = (
    "idn_homograph", "credential_harvesting", "sender_spoofing",
    "malicious_attachment", "free_hosting_abuse", "generic_phishing",
)
IMPACT = {
    "idn_homograph": ["confidencialidad", "integridad"],
    "credential_harvesting": ["confidencialidad"],
    "sender_spoofing": ["integridad", "autenticidad"],
    "malicious_attachment": ["integridad", "disponibilidad"],
    "free_hosting_abuse": ["confidencialidad"],
    "generic_phishing": ["confidencialidad"],
}
HIGH_RISK = 0.70


def _has_reason(response: AnalyzeResponse, *prefixes: str) -> bool:
    return any(reason.startswith(prefixes) for reason in response.reasons or [])


def _on_free_hosting(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == p or domain.endswith("." + p) for p in _FREE_HOSTING_PLATFORMS)


def categorize(response: AnalyzeResponse) -> list[str]:
    if response.verdict == "LEGITIMATE":
        return []
    idn, probe = response.idn_result, response.probe_result
    found: list[str] = []
    # The verdict is already non-legitimate: confusables in a mixed-script name are
    # the homograph pattern even when the IDN agent alone stayed below its threshold.
    if idn.confusable_chars and (idn.is_suspicious or idn.is_mixed_script):
        found.append("idn_homograph")
    login_page = probe is not None and not probe.error and (
        probe.has_login_form or probe.has_password_field)
    if login_page and (probe.brand_impersonation or probe.external_form_action):
        found.append("credential_harvesting")
    if _has_reason(response, "Sender domain (", "SPF failure declared", "DKIM failure declared"):
        found.append("sender_spoofing")
    if _has_reason(response, "Suspicious attachments detected"):
        found.append("malicious_attachment")
    brand = probe.brand_impersonation if probe is not None else None
    if _on_free_hosting(response.domain) and (brand or idn.is_suspicious):
        found.append("free_hosting_abuse")
    if not found and response.verdict == "PHISHING":
        found.append("generic_phishing")
    return found[:3]


_LOGIN = ("Login form with password field", "Password input field detected")
_STEAL = ("Page impersonates brand", "Form submits credentials to an external domain")


def categorize_stored(verdict: str, domain: str, reasons: list[str]) -> list[str]:
    """Best-effort classification for incidents saved before 006 (only reasons survive)."""
    if verdict == "LEGITIMATE":
        return []

    def has(*prefixes: str) -> bool:
        return any(r.startswith(prefixes) for r in reasons)

    found: list[str] = []
    if has("Confusable Unicode characters detected", "Mixed-script domain detected"):
        found.append("idn_homograph")
    if has(*_LOGIN) and has(*_STEAL):
        found.append("credential_harvesting")
    if has("Sender domain (", "SPF failure declared", "DKIM failure declared"):
        found.append("sender_spoofing")
    if has("Suspicious attachments detected"):
        found.append("malicious_attachment")
    if _on_free_hosting(domain) and (has("Page impersonates brand") or "idn_homograph" in found):
        found.append("free_hosting_abuse")
    if not found and verdict == "PHISHING":
        found.append("generic_phishing")
    return found[:3]


def impact_for(categories: list[str], s_risk: float) -> dict:
    if not categories:
        return {}
    properties: list[str] = []
    for category in categories:
        for prop in IMPACT[category]:
            if prop not in properties:
                properties.append(prop)
    return {"properties": properties, "level": "alto" if s_risk >= HIGH_RISK else "medio"}


@lru_cache(maxsize=1)
def catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def guidance(primary_category: str | None) -> dict:
    entry = catalog().get(primary_category or "", {})
    return {
        "label": entry.get("label", ""),
        "containment": list(entry.get("containment", [])),
        "remediation": list(entry.get("remediation", [])),
        "references": list(entry.get("references", [])),
    }
