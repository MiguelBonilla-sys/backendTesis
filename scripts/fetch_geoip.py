"""Descarga DB-IP Lite City y ASN (CC BY 4.0, «IP Geolocation by DB-IP»).

DB-IP publica un archivo por mes; si el del mes en curso todavía no está, se usa
el del mes anterior. Solo stdlib: corre igual en la imagen slim y en local.

Uso: python scripts/fetch_geoip.py [destino]   (por defecto data/geoip)
Después: GEOIP_CITY_DB=<destino>/dbip-city-lite.mmdb GEOIP_ASN_DB=<destino>/dbip-asn-lite.mmdb
"""

from __future__ import annotations

import gzip
import sys
import urllib.request
from datetime import date, timedelta
from pathlib import Path

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
KINDS = ("city", "asn")


def candidate_months(today: date) -> list[str]:
    first = today.replace(day=1)
    return [first.strftime("%Y-%m"), (first - timedelta(days=1)).strftime("%Y-%m")]


def fetch(dest: Path, today: date | None = None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for kind in KINDS:
        for month in candidate_months(today or date.today()):
            url = URL.format(kind=kind, month=month)
            try:
                # DB-IP responde 403 al User-Agent por defecto de urllib.
                req = urllib.request.Request(url, headers={"User-Agent": "tesis-idn-geoip/1.0"})
                with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310  # nosec B310 — URL fija https
                    data = gzip.decompress(resp.read())
            except OSError as exc:
                print(f"{kind} {month}: {exc}", file=sys.stderr)
                continue
            (dest / f"dbip-{kind}-lite.mmdb").write_bytes(data)
            print(f"{kind} {month}: {len(data)} bytes")
            break
        else:
            raise SystemExit(f"no se pudo descargar DB-IP {kind}")


if __name__ == "__main__":
    if candidate_months(date(2026, 1, 15)) != ["2026-01", "2025-12"]:
        raise SystemExit("candidate_months roto")
    fetch(Path(sys.argv[1] if len(sys.argv) > 1 else "data/geoip"))
