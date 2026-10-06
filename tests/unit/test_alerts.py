from unittest.mock import AsyncMock, patch

import httpx
import pytest

from core.config import settings
from services import alerts, mailer
from services.alerts import AlertIncident


class FakeRedis:
    def __init__(self):
        self.values: dict[str, int | str] = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True

    async def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    async def expire(self, key, ttl):
        return True


class BrokenRedis:
    async def set(self, *args, **kwargs):
        raise ConnectionError("down")


def _incident(domain="paypa1.com", verdict="PHISHING", reasons=None):
    return AlertIncident(
        incident_id="inc-1", url=f"https://{domain}/login", domain=domain, verdict=verdict,
        s_risk=0.91, reasons=reasons or ["dominio homógrafo", "formulario externo"],
        category="idn_homograph", origin_country="RU", origin_isp="AS0 Example",
    )


@pytest.fixture
def mail_env(monkeypatch):
    monkeypatch.setattr(settings, "ALERTS_ENABLED", True)
    monkeypatch.setattr(settings, "MAIL_DRY_RUN", False)
    monkeypatch.setattr(settings, "RESEND_API_KEY", "re_test")
    monkeypatch.setattr(settings, "MAIL_FROM", "alertas@example.org")
    monkeypatch.setattr(settings, "ALERT_DAILY_CAP", 2)
    monkeypatch.setattr(settings, "ALERT_FALLBACK_RECIPIENT", "")


class FakeClient:
    calls: list[dict] = []
    status = 200
    error: Exception | None = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        if FakeClient.error:
            raise FakeClient.error
        FakeClient.calls.append({"url": url, "json": json, "headers": headers})
        return httpx.Response(FakeClient.status)


@pytest.fixture
def fake_http(monkeypatch):
    FakeClient.calls, FakeClient.status, FakeClient.error = [], 200, None
    monkeypatch.setattr(mailer.httpx, "AsyncClient", FakeClient)
    return FakeClient


class TestMailer:
    async def test_sends_through_resend(self, mail_env, fake_http):
        assert await mailer.send_email(["a@x.org"], "Hola", "t", "<p>t</p>", kind="test")
        call = fake_http.calls[0]
        assert call["url"] == settings.RESEND_API_URL
        assert call["headers"]["Authorization"] == "Bearer re_test"
        assert call["json"]["to"] == ["a@x.org"]

    async def test_subject_cannot_inject_headers(self, mail_env, fake_http):
        await mailer.send_email(["a@x.org"], "Hola\r\nBcc: evil@x.org", "t", "h", kind="test")
        assert "\n" not in fake_http.calls[0]["json"]["subject"]

    async def test_no_recipients(self, mail_env, fake_http):
        assert not await mailer.send_email(["not-an-email", "x@y\n.org"], "s", "t", "h", kind="t")
        assert fake_http.calls == []

    async def test_dry_run_skips_http(self, mail_env, fake_http, monkeypatch):
        monkeypatch.setattr(settings, "MAIL_DRY_RUN", True)
        assert await mailer.send_email(["a@x.org"], "s", "t", "h", kind="t")
        assert fake_http.calls == []

    async def test_not_configured(self, mail_env, fake_http, monkeypatch):
        monkeypatch.setattr(settings, "RESEND_API_KEY", "")
        assert not await mailer.send_email(["a@x.org"], "s", "t", "h", kind="t")

    async def test_rejected_and_network_error(self, mail_env, fake_http):
        fake_http.status = 422
        assert not await mailer.send_email(["a@x.org"], "s", "t", "h", kind="t")
        fake_http.error = httpx.ConnectError("boom")
        assert not await mailer.send_email(["a@x.org"], "s", "t", "h", kind="t")


class TestRender:
    def test_escapes_html_and_links_incident(self):
        subject, text, html = alerts.render_alert(_incident(reasons=["<script>x</script>"]))
        assert "paypa1.com" in subject
        assert "<script>" not in html and "&lt;script&gt;" in html
        assert "/incidents/inc-1" in text


class TestNotify:
    @pytest.fixture
    def wired(self, mail_env, fake_http):
        redis = FakeRedis()
        audit = AsyncMock()
        with patch("models.redis_client.get_redis", return_value=redis), \
             patch("models.database.fetch",
                   AsyncMock(return_value=[{"email": "admin@usb.edu.co"}])), \
             patch("models.database.log_audit_event", audit):
            yield redis, audit, fake_http

    async def test_sends_alert_and_audits(self, wired):
        redis, audit, http = wired
        assert await alerts.notify_phishing(_incident())
        assert http.calls[0]["json"]["to"] == ["admin@usb.edu.co"]
        assert audit.await_args.kwargs["event_type"] == "alert_sent"

    async def test_same_domain_within_window_is_suppressed(self, wired):
        _, _, http = wired
        assert await alerts.notify_phishing(_incident())
        assert not await alerts.notify_phishing(_incident())
        assert len(http.calls) == 1

    async def test_daily_cap_sends_one_summary_then_stops(self, wired):
        _, _, http = wired
        for i in range(5):
            await alerts.notify_phishing(_incident(domain=f"d{i}.com"))
        subjects = [c["json"]["subject"] for c in http.calls]
        assert len(subjects) == 3
        assert "Tope diario" in subjects[-1]

    async def test_non_phishing_and_disabled(self, wired, monkeypatch):
        _, _, http = wired
        assert not await alerts.notify_phishing(_incident(verdict="SUSPICIOUS"))
        monkeypatch.setattr(settings, "ALERTS_ENABLED", False)
        assert not await alerts.notify_phishing(_incident())
        assert http.calls == []

    async def test_resend_failure_is_audited(self, wired):
        _, audit, http = wired
        http.status = 500
        assert not await alerts.notify_phishing(_incident())
        assert audit.await_args.kwargs["event_type"] == "alert_failed"

    async def test_redis_down_sends_nothing(self, mail_env, fake_http):
        with patch("models.redis_client.get_redis", return_value=BrokenRedis()):
            assert not await alerts.notify_phishing(_incident())
        assert fake_http.calls == []

    async def test_fallback_recipient_when_query_fails(self, mail_env, fake_http, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_FALLBACK_RECIPIENT", "soc@usb.edu.co")
        with patch("models.redis_client.get_redis", return_value=FakeRedis()), \
             patch("models.database.fetch", AsyncMock(side_effect=RuntimeError("db"))), \
             patch("models.database.log_audit_event", AsyncMock()):
            assert await alerts.notify_phishing(_incident())
        assert fake_http.calls[0]["json"]["to"] == ["soc@usb.edu.co"]


async def test_persistence_schedules_alert_only_for_phishing(monkeypatch):
    from services import persistence

    scheduled = []
    monkeypatch.setattr(settings, "ALERTS_ENABLED", True)
    monkeypatch.setattr("core.background.schedule",
                        lambda coro, name: (scheduled.append(name), coro.close()))

    class R:
        request_id, url, domain, s_risk, reasons = "r1", "https://x.com", "x.com", 0.9, ["a"]
        verdict = "PHISHING"

    persistence._schedule_alert(R())
    R.verdict = "LEGITIMATE"
    persistence._schedule_alert(R())
    assert scheduled == ["alert:r1"]
