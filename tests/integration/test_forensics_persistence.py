"""Forensic columns written to a real PostgreSQL: encrypted, bound to the row."""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest

from core import crypto
from core.config import settings
from data_pipeline import geoip
from schemas.analyze import AnalyzeEmailRequest
from services.persistence import _persist_email_incident, _persist_eml_incident
from tests.integration.test_storage_contracts import (  # noqa: F401
    SCHEMA,
    databases,
    postgres_socket,
)
from tests.unit.test_persist_helpers import _make_response
from utils.email_parser import parse_eml

HEADERS = (Path(__file__).resolve().parents[1] / "fixtures/forensics/gmail_to_gmail.headers"
           ).read_text()


@pytest.fixture
async def db(databases, monkeypatch):  # noqa: F811
    conn, _ = databases
    await conn.execute(SCHEMA)
    monkeypatch.setattr("models.database.get_pool", lambda: conn)
    monkeypatch.setattr(geoip, "lookup", lambda ip: geoip.GeoInfo(
        country="US", city="Mountain View", isp="Google LLC", asn=15169) if ip else geoip.GeoInfo())
    return conn


@pytest.fixture
def keys(monkeypatch):
    key = base64.b64encode(bytes(range(32))).decode()
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", json.dumps({"k1": key}))
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "k1")


def _body(**extra) -> AnalyzeEmailRequest:
    return AnalyzeEmailRequest(
        all_urls=["https://example.org/login"], email_body_html="<p>x</p>", email_subject="s",
        email_from="soporte@example.org", email_to="e@usb.edu.co", email_text_snippet="x",
        **extra,
    )


async def test_outlook_headers_are_encrypted_and_origin_in_clear(db, keys):
    response = _make_response()
    await _persist_email_incident(response, _body(raw_headers=HEADERS,
                                                  header_source="outlook-addin"))
    row = await db.fetchrow("SELECT * FROM incidents WHERE id=$1", uuid.UUID(response.request_id))
    assert row["header_source"] == "outlook-addin"
    assert (row["origin_country"], row["origin_isp"], row["origin_asn"]) == ("US", "Google LLC",
                                                                             15169)
    assert row["mail_date"] is not None
    for column in ("origin_ip_enc", "message_id_enc", "headers_enc"):
        assert row[column].startswith("v1:k1:")
        assert "209.85.220.41" not in row[column]
    aad = f"{response.request_id}|origin_ip_enc"
    assert crypto.decrypt_field(row["origin_ip_enc"], aad) == "209.85.220.41"
    with pytest.raises(crypto.FieldCryptoError):
        crypto.decrypt_field(row["origin_ip_enc"], f"{uuid.uuid4()}|origin_ip_enc")


async def test_without_key_sensitive_values_are_not_stored(db, monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", "")
    response = _make_response()
    await _persist_email_incident(response, _body(raw_headers=HEADERS,
                                                  header_source="gmail-original"))
    row = await db.fetchrow("SELECT * FROM incidents WHERE id=$1", uuid.UUID(response.request_id))
    assert row["header_source"] == "gmail-original" and row["origin_country"] == "US"
    assert row["origin_ip_enc"] is None and row["headers_enc"] is None


async def test_no_headers_keeps_defaults(db, keys):
    response = _make_response()
    await _persist_email_incident(response, _body())
    row = await db.fetchrow("SELECT * FROM incidents WHERE id=$1", uuid.UUID(response.request_id))
    assert row["header_source"] == "none" and row["origin_ip_enc"] is None


async def test_eml_source_is_server_assigned(db, keys):
    parsed = parse_eml((HEADERS + "\nhttps://example.org/login\n").encode())
    response = _make_response()
    await _persist_eml_incident(response, parsed, ["https://example.org/login"])
    row = await db.fetchrow("SELECT * FROM incidents WHERE id=$1", uuid.UUID(response.request_id))
    assert row["header_source"] == "eml"


def test_client_cannot_claim_eml_source():
    with pytest.raises(ValueError):
        _body(raw_headers=HEADERS, header_source="eml")


def test_geoip_reads_mmdb_records(monkeypatch):
    class Reader:
        def get(self, ip):
            return {"country": {"iso_code": "CO"}, "city": {"names": {"en": "Bogotá"}},
                    "autonomous_system_number": 3816,
                    "autonomous_system_organization": "COLOMBIA TELECOMUNICACIONES"}

    monkeypatch.setattr(geoip, "_reader", lambda path: Reader() if path else None)
    monkeypatch.setattr(settings, "GEOIP_CITY_DB", "city.mmdb")
    monkeypatch.setattr(settings, "GEOIP_ASN_DB", "asn.mmdb")
    info = geoip.lookup("181.49.0.1")
    assert info == geoip.GeoInfo("CO", "Bogotá", "COLOMBIA TELECOMUNICACIONES", 3816)
    assert geoip.lookup(None) == geoip.GeoInfo()
    monkeypatch.setattr(settings, "GEOIP_CITY_DB", "")
    monkeypatch.setattr(settings, "GEOIP_ASN_DB", "")
    assert geoip.lookup("1.1.1.1") == geoip.GeoInfo()


def test_geoip_missing_file_is_empty():
    geoip._reader.cache_clear()
    assert geoip._reader("/no/such.mmdb") is None
    assert geoip._reader("") is None


async def test_router_filters_and_forensics_permission(db, keys, monkeypatch):
    import importlib
    from unittest.mock import AsyncMock

    router = importlib.import_module("routers.incidents_router")
    monkeypatch.setattr(router, "check_rate_limit", AsyncMock())
    monkeypatch.setattr(router, "get_client_ip", lambda request: "127.0.0.1")
    response = _make_response()
    await _persist_email_incident(response, _body(raw_headers=HEADERS,
                                                  header_source="outlook-addin"))
    other = _make_response(verdict="LEGITIMATE", s_risk=0.1)
    await _persist_email_incident(other, _body())

    listed = await router.list_incidents(None, page=1, page_size=20, verdict=None,
                                         category="idn_homograph", country="US",
                                         current_user={})
    assert [i.id for i in listed.items] == [response.request_id] and listed.total == 1
    assert listed.items[0].origin.ip is None and listed.items[0].guidance is None
    none = await router.list_incidents(None, page=1, page_size=20, verdict="PHISHING",
                                       category=None, country="CO", current_user={})
    assert none.total == 0

    analyst = {"role": "viewer", "permissions": ["incidents:read"]}
    plain = await router.get_incident(response.request_id, current_user=analyst)
    assert plain.origin.country == "US" and plain.origin.ip is None
    assert plain.primary_category == "idn_homograph"
    assert plain.guidance.label == "Homografía IDN" and plain.guidance.containment

    admin = {"role": "admin", "permissions": ["incidents:read", "incidents:forensics"]}
    full = await router.get_incident(response.request_id, current_user=admin)
    assert full.origin.ip == "209.85.220.41"
    assert full.origin.message_id == "<CAF1234567890@mail.gmail.com>"
    assert ["DKIM-Signature", "d=example.org; s=sel1"] in full.origin.headers

    await db.execute("UPDATE incidents SET origin_ip_enc = $2 WHERE id = $1",
                     uuid.UUID(response.request_id), "v1:k1:AAAA")
    broken = await router.get_incident(response.request_id, current_user=admin)
    assert broken.origin.ip is None


async def test_backfill_classifies_legacy_rows(db):
    from scripts.backfill_classification import backfill

    legacy = [
        ("PHISHING", "paypa1.com", ["Confusable Unicode characters detected: а"]),
        ("SUSPICIOUS", "x.vercel.app", [
            "Page impersonates brand 'Microsoft' on an unrelated domain",
            "Login form with password field detected on the target page",
        ]),
        ("SUSPICIOUS", "y.com", ["LLM semantic analysis indicates phishing content"]),
        ("LEGITIMATE", "google.com", ["No suspicious indicators detected"]),
    ]
    ids = []
    for verdict, domain, reasons in legacy:
        ids.append(await db.fetchval(
            "INSERT INTO incidents (url, domain, verdict, s_risk, reasons) "
            "VALUES ($1, $2, $3, 0.8, $4::jsonb) RETURNING id",
            f"https://{domain}", domain, verdict, json.dumps(reasons)))
    assert await backfill(db, dry=True) == {"updated": 2, "unclassified": 1}
    assert await backfill(db) == {"updated": 2, "unclassified": 1}
    got = [await db.fetchval("SELECT primary_category FROM incidents WHERE id=$1", i) for i in ids]
    assert got == ["idn_homograph", "credential_harvesting", None, None]
    assert await backfill(db) == {"updated": 0, "unclassified": 1}
