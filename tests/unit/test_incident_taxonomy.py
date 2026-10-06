import pytest

from core import incident_taxonomy as tx
from schemas.analyze import WebProbeResult
from tests.unit.test_persist_helpers import _make_response


def test_idn_homograph_primary_and_impact():
    r = _make_response()
    cats = tx.categorize(r)
    assert cats[0] == "idn_homograph"
    assert tx.impact_for(cats, 0.85) == {"properties": ["confidencialidad", "integridad"],
                                          "level": "alto"}


def test_credential_harvesting_and_spoofing_from_signals():
    r = _make_response()
    r.idn_result.is_suspicious, r.idn_result.confusable_chars = False, []
    r.probe_result = WebProbeResult(has_login_form=True, brand_impersonation="Microsoft")
    r.reasons = ["Sender domain ('a.com') does not match return-path domain ('b.com')",
                 "Suspicious attachments detected: x.exe"]
    assert tx.categorize(r) == ["credential_harvesting", "sender_spoofing",
                                "malicious_attachment"]


def test_free_hosting_and_generic_and_legitimate():
    r = _make_response(s_risk=0.5)
    r.domain = "outlook-098.vercel.app"
    r.idn_result.confusable_chars = []
    assert tx.categorize(r) == ["free_hosting_abuse"]
    r.domain = "example.com"
    r.idn_result.is_suspicious = False
    assert tx.categorize(r) == ["generic_phishing"]
    assert tx.impact_for(["generic_phishing"], 0.5)["level"] == "medio"
    assert tx.categorize(_make_response(verdict="LEGITIMATE", s_risk=0.1)) == []
    assert tx.impact_for([], 0.1) == {}


def test_probe_error_is_ignored():
    r = _make_response()
    r.idn_result.is_suspicious, r.idn_result.confusable_chars = False, []
    r.probe_result = WebProbeResult(has_login_form=True, brand_impersonation="X", error="timeout")
    assert tx.categorize(r) == ["generic_phishing"]


def test_catalog_covers_every_category_in_spanish():
    for category in tx.CATEGORIES:
        g = tx.guidance(category)
        assert g["label"] and g["containment"] and g["remediation"]
    assert tx.guidance(None) == {"label": "", "containment": [], "remediation": [],
                                 "references": []}


def test_mixed_script_confusables_count_even_below_idn_threshold():
    r = _make_response(s_risk=0.53)
    r.idn_result.is_suspicious = False
    assert tx.categorize(r)[0] == "idn_homograph"
    r.idn_result.is_mixed_script = False
    assert tx.categorize(r)[0] == "generic_phishing"

pytestmark = [pytest.mark.acceptance]
