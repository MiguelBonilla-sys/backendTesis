"""Regresiones de los hallazgos del pentest T33 (Reports/tests-back/pentest/2026-10-08)."""

import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from schemas.access import UserUpdate
from schemas.analyze import ReportRequest
from utils.email_parser import _strip_html, parse_eml
from utils.url_parser import is_ip_address


def _html_eml(body: str) -> bytes:
    return ("Content-Type: text/html; charset=utf-8\n\n" + body).encode()


def test_f33_01_unclosed_tags_parse_in_linear_time():
    started = time.perf_counter()
    parse_eml(_html_eml("<" * 131_072))
    assert time.perf_counter() - started < 0.5  # antes: corte a 2 s (cuadrático)


def test_f33_01_tag_stripping_unchanged_for_wellformed_html():
    assert _strip_html('<p>Hola <a href="x">aquí</a></p>&amp;').split() == ["Hola", "aquí", "&"]
    assert "texto" in _strip_html("<<b>texto")


@pytest.mark.parametrize("value,expected", [
    ("0", False), ("1.2.3", False), ("deadbeef", False), ("999.1.1.1", False),
    ("1.1.1.1", True), ("[2001:db8::1]", True), ("::1", True),
])
def test_f33_03_ip_detection_is_strict(value, expected):
    assert is_ip_address(value) is expected


@pytest.mark.parametrize("url", ["0" * 254, "javascript:alert(1)", "https://", "ftp://x.com",
                                 "https://" + "a" * 254 + ".com"])
def test_f33_06_report_rejects_invalid_urls(url):
    with pytest.raises(ValidationError):
        ReportRequest(url=url)


def test_f33_06_report_accepts_http_urls():
    assert ReportRequest(url=" https://synthetic.example.test/x ").url == \
        "https://synthetic.example.test/x"


def test_f33_04_is_active_is_strictly_boolean():
    with pytest.raises(ValidationError):
        UserUpdate(is_active=0)
    assert UserUpdate(is_active=False).is_active is False


def test_f33_05_invalid_incident_id_is_422_without_touching_storage(auth_store):
    from main import app
    from tests.auth_helpers import create_access_token

    auth_store.add_account("boss@usb.edu.co", "admin")
    token = create_access_token({"sub": "boss@usb.edu.co", "role": "admin"})
    fetch = AsyncMock()
    with patch("main.init_db", new_callable=AsyncMock), \
         patch("main.close_db", new_callable=AsyncMock), \
         patch("main.init_redis", new_callable=AsyncMock), \
         patch("main.close_redis", new_callable=AsyncMock), \
         patch("routers.incidents_router.fetchrow", fetch), TestClient(app) as client:
        resp = client.get("/api/v1/incidents/not-a-uuid",
                          headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 422
    fetch.assert_not_awaited()

pytestmark = [pytest.mark.regression]
