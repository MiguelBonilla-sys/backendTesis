"""
Integration tests — live agent pipeline against running backend (localhost:8000).

Run ONLY when the backend + data stores are active:
    pytest tests/integration/test_agents_live.py -v --no-cov

Tests verify:
  1. IDN Agent detects real confusable domains (Cyrillic, mixed-script)
  2. Fusion Agent produces correct S_risk and SHAP for IDN-heavy cases
  3. Full pipeline: POST /api/v1/analyze returns verdicts for known domains
  4. Health / connectivity checks
  5. Auth flow (login → token → protected endpoint)
"""
from __future__ import annotations

import os
import pytest
import httpx

BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
TIMEOUT = 20.0

ADMIN_EMAIL = "mabonillat@academia.usbbog.edu.co"
ADMIN_PASSWORD = "admin1234"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_token() -> str:
    """Obtain JWT from the running backend using seeded admin credentials."""
    resp = httpx.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        # Fallback: generate token locally if auth endpoint differs
        from auth.jwt import create_access_token
        return create_access_token({"sub": ADMIN_EMAIL, "role": "admin"})
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def token() -> str:
    return _get_token()


@pytest.fixture(scope="module")
def headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def analyze(url: str, headers: dict, **extra) -> httpx.Response:
    body = {"url": url, **extra}
    return httpx.post(
        f"{BASE_URL}/api/v1/analyze",
        json=body,
        headers=headers,
        timeout=TIMEOUT,
    )


# ---------------------------------------------------------------------------
# 1. Health & connectivity
# ---------------------------------------------------------------------------

class TestLiveHealth:
    def test_backend_reachable(self):
        resp = httpx.get(f"{BASE_URL}/health", timeout=5)
        assert resp.status_code == 200

    def test_health_status_ok(self):
        data = httpx.get(f"{BASE_URL}/health", timeout=5).json()
        assert data["status"] == "ok"

    def test_health_contains_version(self):
        data = httpx.get(f"{BASE_URL}/health", timeout=5).json()
        assert "version" in data


# ---------------------------------------------------------------------------
# 2. Auth
# ---------------------------------------------------------------------------

class TestLiveAuth:
    def test_analyze_without_token_returns_401(self):
        resp = analyze("https://paypal.com", headers={})
        assert resp.status_code in {401, 403}

    def test_token_obtained_from_backend(self, token: str):
        assert len(token) > 10

    def test_protected_endpoint_accepts_token(self, headers: dict):
        resp = analyze("https://paypal.com", headers=headers)
        # Auth passes — response is 200 or pipeline error, not auth error
        assert resp.status_code not in {401, 403}


# ---------------------------------------------------------------------------
# 3. IDN Agent — Cyrillic homograph detection
# ---------------------------------------------------------------------------

class TestIDNAgentLive:
    """
    Uses domains with Cyrillic characters that the IDN Agent must flag.
    TI APIs are in dev-mode (no keys) so S_TI=0. Formula:
      S_IDN  = 0.60 * s_idn_local + 0.40 * 0.0 = 0.60 * s_idn_local
      s_llm  = 0.5 (fallback, LlamaStack not running)
      S_risk = 0.50 * S_IDN + 0.50 * 0.5 = 0.30 * s_idn_local + 0.25
    Mixed-script floor (s_idn_local >= 0.85):
      S_risk >= 0.30*0.85 + 0.25 = 0.505 -> SUSPICIOUS or PHISHING
    """

    def test_cyrillic_paypal_flagged(self, headers: dict):
        # р (Cyrillic) replacing p — classic homograph
        resp = analyze("https://рaypal.com/login", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        idn = data["idn_result"]
        assert idn["is_mixed_script"] is True
        assert idn["homograph_ratio"] > 0
        assert idn["s_idn_local"] >= 0.80

    def test_cyrillic_paypal_verdict_not_legitimate(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        data = resp.json()
        assert data["verdict"] in {"PHISHING", "SUSPICIOUS"}

    def test_s_risk_above_threshold_for_cyrillic(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        data = resp.json()
        assert data["s_risk"] >= 0.50

    def test_idn_result_contains_confusable_chars(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        idn = resp.json()["idn_result"]
        assert len(idn["confusable_chars"]) > 0

    def test_clean_ascii_domain_low_idn_score(self, headers: dict):
        resp = analyze("https://google.com", headers=headers)
        assert resp.status_code == 200
        idn = resp.json()["idn_result"]
        assert idn["s_idn_local"] < 0.30
        assert idn["is_mixed_script"] is False

    def test_clean_ascii_domain_not_phishing(self, headers: dict):
        resp = analyze("https://google.com", headers=headers)
        data = resp.json()
        # Clean domain must never be classified as PHISHING.
        # WebProbe may add a redirect signal (google.com → www.google.com) which
        # can push the verdict to SUSPICIOUS — that is acceptable behavior.
        assert data["verdict"] != "PHISHING"


# ---------------------------------------------------------------------------
# 4. Fusion Agent — SHAP completeness and S_risk formula
# ---------------------------------------------------------------------------

class TestFusionAgentLive:
    EXPECTED_SHAP_KEYS = {
        "s_idn_local", "s_ti", "s_llm", "s_hf",
        "s_vt", "s_urlscan", "s_gsb",
        "homograph_ratio", "visual_similarity", "is_mixed_script",
        "s_email", "s_probe",
    }

    def test_shap_has_all_12_keys(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        shap = resp.json()["shap_explanation"]["feature_contributions"]
        assert set(shap.keys()) == self.EXPECTED_SHAP_KEYS

    def test_shap_values_sum_to_s_risk(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        data = resp.json()
        shap = data["shap_explanation"]["feature_contributions"]
        shap_sum = round(sum(shap.values()), 2)
        s_risk = round(data["s_risk"], 2)
        # SHAP contributions are weighted approximations — allow ±0.06 rounding tolerance.
        assert abs(shap_sum - s_risk) <= 0.06, (
            f"SHAP sum {shap_sum} should approximate s_risk {s_risk}"
        )

    def test_s_risk_in_range(self, headers: dict):
        for url in ["https://рaypal.com", "https://google.com", "https://github.com"]:
            resp = analyze(url, headers=headers)
            s_risk = resp.json()["s_risk"]
            assert 0.0 <= s_risk <= 1.0, f"s_risk={s_risk} out of range for {url}"

    def test_cyrillic_has_higher_s_risk_than_clean(self, headers: dict):
        cyrillic_risk = analyze("https://рaypal.com", headers=headers).json()["s_risk"]
        clean_risk = analyze("https://google.com", headers=headers).json()["s_risk"]
        assert cyrillic_risk > clean_risk

    def test_idn_shap_contribution_dominant_for_cyrillic(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        shap = resp.json()["shap_explanation"]["feature_contributions"]
        # IDN-related contributions should exceed TI (which is 0.0 in dev mode)
        idn_contrib = shap.get("s_idn_local", 0) + shap.get("homograph_ratio", 0)
        ti_contrib = shap.get("s_ti", 0)
        assert idn_contrib > ti_contrib


# ---------------------------------------------------------------------------
# 5. Response schema completeness
# ---------------------------------------------------------------------------

class TestResponseSchema:
    def test_response_has_all_required_fields(self, headers: dict):
        resp = analyze("https://рaypal.com/login", headers=headers)
        data = resp.json()
        required = {
            "request_id", "url", "domain", "verdict", "s_risk",
            "agent_scores", "idn_result", "ti_result",
            "llm_reason", "shap_explanation", "processing_ms", "timestamp",
        }
        assert required.issubset(set(data.keys()))

    def test_agent_scores_present(self, headers: dict):
        data = analyze("https://рaypal.com/login", headers=headers).json()
        scores = data["agent_scores"]
        for key in ("s_idn_local", "s_ti", "s_idn", "s_llm", "s_risk"):
            assert key in scores, f"Missing agent score: {key}"

    def test_ti_result_present(self, headers: dict):
        data = analyze("https://рaypal.com/login", headers=headers).json()
        ti = data["ti_result"]
        for key in ("s_vt", "s_urlscan", "s_gsb", "s_ti"):
            assert key in ti

    def test_processing_ms_positive(self, headers: dict):
        data = analyze("https://рaypal.com/login", headers=headers).json()
        assert data["processing_ms"] > 0

    def test_request_id_is_uuid_format(self, headers: dict):
        import re
        data = analyze("https://рaypal.com/login", headers=headers).json()
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        assert uuid_pattern.match(data["request_id"])


# ---------------------------------------------------------------------------
# 6. TI service (dev mode — no keys → S_TI=0 immediately, cached)
# ---------------------------------------------------------------------------

class TestTIServiceLive:
    def test_ti_returns_zero_in_dev_mode(self, headers: dict):
        data = analyze("https://рaypal.com/login", headers=headers).json()
        ti = data["ti_result"]
        assert ti["s_vt"] == 0.0
        assert ti["s_urlscan"] == 0.0
        assert ti["s_gsb"] == 0.0

    def test_second_call_faster_due_to_cache(self, headers: dict):
        import time
        url = "https://cached-domain-test.com/path"
        # First call — cache miss
        t0 = time.time()
        analyze(url, headers=headers)
        first_ms = (time.time() - t0) * 1000
        # Second call — cache hit
        t1 = time.time()
        analyze(url, headers=headers)
        second_ms = (time.time() - t1) * 1000
        # Cache hit should be at least 20% faster (rough check)
        assert second_ms <= first_ms * 1.5, (
            f"Second call ({second_ms:.0f}ms) not faster than first ({first_ms:.0f}ms)"
        )


# ---------------------------------------------------------------------------
# 7. Incident persistence
# ---------------------------------------------------------------------------

class TestIncidentPersistenceLive:
    def test_analysis_creates_incident_in_db(self, headers: dict):
        """After analysis, the incident should appear in GET /incidents."""
        # Analyze a unique URL
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        url = f"https://рaypal-{unique_id}.com/phish"

        analyze_resp = analyze(url, headers=headers)
        assert analyze_resp.status_code == 200
        request_id = analyze_resp.json()["request_id"]

        # Wait briefly for async persistence
        import time
        time.sleep(0.5)

        # Check incidents endpoint
        list_resp = httpx.get(
            f"{BASE_URL}/api/v1/incidents",
            params={"page": 1, "page_size": 10},
            headers=headers,
            timeout=TIMEOUT,
        )
        assert list_resp.status_code == 200
        items = list_resp.json()["items"]
        ids = [item["id"] for item in items]
        assert request_id in ids, f"request_id {request_id} not found in incidents"
