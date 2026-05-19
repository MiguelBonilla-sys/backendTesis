"""
ThreatIntelService — consulta concurrente a VirusTotal v3, URLScan.io,
Google Safe Browsing v4 y WhoisXML (antigüedad de dominio).

Fórmula de agregación:
    S_TI_base = W_VT * S_VT + W_URLSCAN * S_URLScan + W_GSB * S_GSB
    S_TI = min(S_TI_base + WHOIS_WEIGHT * S_Whois, 1.0)

Pesos base definidos en core/constants.py (W_VT=0.50, W_URLSCAN=0.30, W_GSB=0.20).
WhoisXML actúa como modificador adicional con WHOIS_WEIGHT=0.10 (no altera pesos del paper).
Cache Redis: key = ti:{domain_2ld}, TTL = settings.TI_CACHE_TTL (3600s).
"""
from __future__ import annotations

import asyncio

import httpx

from core.config import settings
from core.constants import W_GSB, W_URLSCAN, W_VT
from core.logger import get_logger
from data_pipeline.cache_manager import get_ti_cache, set_ti_cache
from schemas.analyze import TIResult
from utils.url_parser import extract_2ld

logger = get_logger(__name__)

# Timeout compartido para todas las llamadas HTTP a APIs de TI
_API_TIMEOUT = 5.0


class ThreatIntelService:
    """
    Servicio stateless de Threat Intelligence.

    Consulta VirusTotal v3, URLScan.io y Google Safe Browsing en paralelo
    con ``asyncio.gather``.  Si una API individual falla (timeout, error HTTP,
    key ausente) su score es 0.0 — el análisis continúa con las demás.

    Dev/test mode: si todas las API keys están vacías retorna S_TI = 0.0
    inmediatamente sin realizar ninguna llamada de red.
    """

    async def analyze(self, url: str, domain: str) -> TIResult:
        """
        Analiza una URL contra las 3 TI APIs y devuelve puntuaciones agregadas.

        Flujo:
            1. Comprueba cache Redis — retorna resultado cacheado si existe.
            2. Si miss: consulta las 3 APIs en paralelo con asyncio.gather.
            3. Calcula S_TI ponderado y satura al rango [0.0, 1.0].
            4. Persiste resultado en cache.

        Args:
            url:    URL completa a analizar (ej. "https://login.paypaI.com/auth").
            domain: Hostname ya extraído del URL (ej. "login.paypaI.com").

        Returns:
            TIResult con s_vt, s_urlscan, s_gsb y s_ti.
        """
        domain_2ld = extract_2ld(domain)

        # --- 1. Cache check ---------------------------------------------------
        cached = await get_ti_cache(domain_2ld)
        if cached is not None:
            logger.debug("ti_cache_return", domain=domain_2ld)
            return TIResult(**cached)

        # --- 2. Dev/test mode: todas las keys vacías --------------------------
        no_keys = (
            not settings.VIRUSTOTAL_API_KEY
            and not settings.URLSCAN_API_KEY
            and not settings.GOOGLE_SAFE_BROWSING_API_KEY
            and not settings.WHOISXML_API_KEY
        )
        if no_keys:
            logger.info(
                "ti_no_keys_dev_mode",
                domain=domain_2ld,
                message="All TI API keys empty — returning S_TI=0.0 (dev/test mode)",
            )
            result = TIResult(s_vt=0.0, s_urlscan=0.0, s_gsb=0.0, s_ti=0.0)
            await set_ti_cache(domain_2ld, result.model_dump(), ttl=settings.TI_CACHE_TTL)
            return result

        # --- 3. Consulta concurrente a las 4 APIs ----------------------------
        vt_score, urlscan_score, gsb_score, (whois_score, age_days) = await asyncio.gather(
            self._query_virustotal(url, domain),
            self._query_urlscan(url, domain),
            self._query_gsb(url),
            self._query_whoisxml(domain_2ld),
        )

        # --- 4. Agregación ponderada -----------------------------------------
        # S_TI base con pesos oficiales del paper (no se alteran)
        s_ti_base = W_VT * vt_score + W_URLSCAN * urlscan_score + W_GSB * gsb_score

        # WhoisXML como modificador adicional (no altera los pesos del paper)
        WHOIS_WEIGHT = 0.10
        s_ti = min(s_ti_base + WHOIS_WEIGHT * whois_score, 1.0)
        s_ti = min(max(s_ti, 0.0), 1.0)

        suspicious_days = settings.DOMAIN_AGE_SUSPICIOUS_DAYS
        result = TIResult(
            s_vt=round(vt_score, 4),
            s_urlscan=round(urlscan_score, 4),
            s_gsb=round(gsb_score, 4),
            s_ti=round(s_ti, 4),
            domain_age_days=age_days,
            is_newly_registered=(age_days is not None and age_days < suspicious_days),
            whois_registrar=None,
        )

        # --- 5. Guardar en cache ----------------------------------------------
        await set_ti_cache(domain_2ld, result.model_dump(), ttl=settings.TI_CACHE_TTL)
        logger.info(
            "ti_analysis_complete",
            domain=domain_2ld,
            s_vt=result.s_vt,
            s_urlscan=result.s_urlscan,
            s_gsb=result.s_gsb,
            s_ti=result.s_ti,
            domain_age_days=age_days,
            is_newly_registered=result.is_newly_registered,
        )

        return result

    # -------------------------------------------------------------------------
    # Private helpers — one per TI API
    # -------------------------------------------------------------------------

    async def _query_virustotal(self, url: str, domain: str) -> float:
        """
        Consulta VirusTotal v3 API para el dominio dado.

        Endpoint: GET https://www.virustotal.com/api/v3/domains/{domain}

        Score:  malicious / (sum of all engine verdicts)
                0.0 si el dominio no tiene registros o la key está ausente.

        HTTP 404 → dominio desconocido → 0.0 (no es error).
        Cualquier otro error HTTP o de red → 0.0 (degraded gracefully).

        Args:
            url:    URL completa (no utilizado directamente, reservado).
            domain: Hostname completo (ej. "login.paypaI.com").

        Returns:
            Score en [0.0, 1.0].
        """
        if not settings.VIRUSTOTAL_API_KEY:
            return 0.0

        try:
            async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )

            if resp.status_code == 200:
                data = resp.json()
                stats: dict[str, int] = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious: int = stats.get("malicious", 0)
                total: int = sum(stats.values()) if stats else 0
                if total > 0:
                    return min(malicious / total, 1.0)
                return 0.0

            if resp.status_code == 404:
                # Domain not in VT database — treat as clean
                return 0.0

            logger.warning(
                "vt_unexpected_status",
                status=resp.status_code,
                domain=domain,
            )

        except httpx.TimeoutException:
            logger.warning("vt_timeout", domain=domain)
        except httpx.RequestError as exc:
            logger.warning("vt_request_error", domain=domain, error=str(exc))

        return 0.0

    async def _query_urlscan(self, url: str, domain: str) -> float:
        """
        Consulta URLScan.io buscando el historial de escaneos para el dominio.

        Endpoint: GET https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1

        Lógica de scoring:
            - verdict.malicious == True  → 1.0
            - verdict.score > 50         → 0.5  (sospechoso)
            - sin datos / clean          → 0.0

        HTTP 429 (rate-limit) → 0.0 con aviso de log.

        Args:
            url:    URL completa (reservado).
            domain: Hostname completo.

        Returns:
            Score en {0.0, 0.5, 1.0}.
        """
        if not settings.URLSCAN_API_KEY:
            return 0.0

        try:
            async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
                resp = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"domain:{domain}", "size": 1},
                    headers={"API-Key": settings.URLSCAN_API_KEY},
                )

            if resp.status_code == 200:
                data = resp.json()
                results: list[dict] = data.get("results", [])
                if results:
                    verdict: dict = (
                        results[0].get("verdicts", {}).get("overall", {})
                    )
                    if verdict.get("malicious"):
                        return 1.0
                    if verdict.get("score", 0) > 50:
                        return 0.5
                return 0.0

            if resp.status_code == 429:
                logger.warning("urlscan_rate_limited", domain=domain)
                return 0.0

            logger.warning(
                "urlscan_unexpected_status",
                status=resp.status_code,
                domain=domain,
            )

        except httpx.TimeoutException:
            logger.warning("urlscan_timeout", domain=domain)
        except httpx.RequestError as exc:
            logger.warning("urlscan_request_error", domain=domain, error=str(exc))

        return 0.0

    async def _query_gsb(self, url: str) -> float:
        """
        Consulta Google Safe Browsing API v4 para la URL dada.

        Endpoint: POST https://safebrowsing.googleapis.com/v4/threatMatches:find

        Amenazas consultadas: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE.

        Score:  1.0 si hay al menos un match, 0.0 si clean o sin datos.

        Args:
            url: URL completa a verificar.

        Returns:
            Score en {0.0, 1.0}.
        """
        if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
            return 0.0

        payload: dict = {
            "client": {
                "clientId": "phishing-detector-usb",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
                resp = await client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                    json=payload,
                )

            if resp.status_code == 200:
                data = resp.json()
                # GSB returns {} when clean, {"matches": [...]} when threat found
                if data.get("matches"):
                    return 1.0
                return 0.0

            logger.warning(
                "gsb_unexpected_status",
                status=resp.status_code,
                url=url,
            )

        except httpx.TimeoutException:
            logger.warning("gsb_timeout", url=url)
        except httpx.RequestError as exc:
            logger.warning("gsb_request_error", url=url, error=str(exc))

        return 0.0

    async def _query_whoisxml(self, domain: str) -> tuple[float, int | None]:
        """
        Consulta WhoisXML API para obtener antigüedad del dominio.

        Endpoint: GET https://www.whoisxmlapi.com/whoisserver/WhoisService

        Score:
            - dominio < 30 días  → 0.8 (altamente sospechoso)
            - dominio 30–90 días → 0.4 (moderadamente sospechoso)
            - dominio > 90 días  → 0.0 (no agrega riesgo por edad)
            - sin datos / key ausente → 0.0

        Args:
            domain: Dominio de segundo nivel (ej. "paypal.com").

        Returns:
            Tupla (score_whois: float, age_days: int | None).
        """
        if not settings.WHOISXML_API_KEY:
            return 0.0, None

        try:
            async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
                resp = await client.get(
                    "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                    params={
                        "apiKey": settings.WHOISXML_API_KEY,
                        "domainName": domain,
                        "outputFormat": "JSON",
                        "da": 2,  # domain availability check
                    },
                )

            if resp.status_code == 200:
                data = resp.json()
                whois_record: dict = data.get("WhoisRecord", {})
                created_date: str | None = (
                    whois_record.get("createdDateNormalized")
                    or whois_record.get("createdDate")
                )

                if created_date:
                    from datetime import datetime, timezone

                    try:
                        created = datetime.fromisoformat(
                            created_date.replace("Z", "+00:00")
                        )
                        age_days = (datetime.now(timezone.utc) - created).days

                        suspicious_days = settings.DOMAIN_AGE_SUSPICIOUS_DAYS
                        if age_days < suspicious_days:
                            return 0.8, age_days   # muy nuevo = altamente sospechoso
                        elif age_days < 90:
                            return 0.4, age_days   # moderadamente nuevo
                        else:
                            return 0.0, age_days   # dominio maduro = no agrega riesgo
                    except (ValueError, TypeError):
                        pass

            logger.warning(
                "whoisxml_unexpected_status",
                status=resp.status_code,
                domain=domain,
            )

        except httpx.TimeoutException:
            logger.warning("whoisxml_timeout", domain=domain)
        except httpx.RequestError as exc:
            logger.warning("whoisxml_request_error", domain=domain, error=str(exc))

        return 0.0, None


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly in agents/routers
# ---------------------------------------------------------------------------
threat_intel_service = ThreatIntelService()
