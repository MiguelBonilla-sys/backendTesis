"""TI aggregation — VirusTotal v3, URLScan.io, Google Safe Browsing v4."""

import asyncio

import httpx

from core.config import settings
from core.logger import logger


class ThreatIntelService:
    """Fetches TI scores concurrently. Returns 0.0 if API key is missing or call fails."""

    async def fetch_all(self, domain: str) -> dict:
        vt, urlscan, gsb = await asyncio.gather(
            self._virustotal(domain),
            self._urlscan(domain),
            self._gsb(domain),
            return_exceptions=False,
        )
        return {"virustotal": vt, "urlscan": urlscan, "google_safe_browsing": gsb}

    # ── VirusTotal v3 ─────────────────────────────────────────────────────────

    async def _virustotal(self, domain: str) -> float:
        if not settings.VIRUSTOTAL_API_KEY:
            return 0.0
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
                if resp.status_code != 200:
                    return 0.0
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                return malicious / total
        except Exception as exc:
            logger.warning(f"VirusTotal failed for {domain!r}: {exc}")
            return 0.0

    # ── URLScan.io ────────────────────────────────────────────────────────────

    async def _urlscan(self, domain: str) -> float:
        if not settings.URLSCAN_API_KEY:
            return 0.0
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
                    headers={"API-Key": settings.URLSCAN_API_KEY},
                )
                if resp.status_code != 200:
                    return 0.0
                results = resp.json().get("results", [])
                if results and results[0].get("verdicts", {}).get("overall", {}).get("malicious"):
                    return 1.0
                return 0.0
        except Exception as exc:
            logger.warning(f"URLScan failed for {domain!r}: {exc}")
            return 0.0

    # ── Google Safe Browsing v4 ───────────────────────────────────────────────

    async def _gsb(self, domain: str) -> float:
        if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
            return 0.0
        try:
            payload = {
                "client": {"clientId": "backendtesis", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"https://{domain}"}],
                },
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                    json=payload,
                )
                if resp.status_code != 200:
                    return 0.0
                return 1.0 if resp.json().get("matches") else 0.0
        except Exception as exc:
            logger.warning(f"GSB failed for {domain!r}: {exc}")
            return 0.0
