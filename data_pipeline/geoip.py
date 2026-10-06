"""Local IP geolocation with DB-IP Lite MMDB files (CC BY 4.0, "IP Geolocation by DB-IP").

The IP never leaves the process. Missing files, a bad path or a lookup error
return empty values: geolocation is best effort and never blocks an analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from core.config import settings
from core.logger import get_logger

logger = get_logger(__name__)
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com)"


@dataclass(frozen=True)
class GeoInfo:
    country: str | None = None
    city: str | None = None
    isp: str | None = None
    asn: int | None = None


@lru_cache(maxsize=4)
def _reader(path: str):
    if not path:
        return None
    try:
        import maxminddb

        return maxminddb.open_database(path)
    except Exception as exc:
        logger.warning("geoip_db_unavailable", path=path, error_type=type(exc).__name__)
        return None


def _get(path: str, ip: str) -> dict:
    reader = _reader(path)
    if reader is None:
        return {}
    try:
        return reader.get(ip) or {}
    except Exception as exc:
        logger.warning("geoip_lookup_failed", error_type=type(exc).__name__)
        return {}


def lookup(ip: str | None) -> GeoInfo:
    if not ip:
        return GeoInfo()
    city_rec = _get(settings.GEOIP_CITY_DB, ip)
    asn_rec = _get(settings.GEOIP_ASN_DB, ip)
    country = (city_rec.get("country") or {}).get("iso_code")
    city = ((city_rec.get("city") or {}).get("names") or {}).get("en")
    asn = asn_rec.get("autonomous_system_number")
    return GeoInfo(
        country=country[:2] if isinstance(country, str) else None,
        city=city if isinstance(city, str) else None,
        isp=asn_rec.get("autonomous_system_organization") or None,
        asn=int(asn) if isinstance(asn, int) else None,
    )
