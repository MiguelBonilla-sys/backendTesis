"""Tests for models/orm_models.py — ORM model definitions and instantiation.

Importing the module covers all SQLAlchemy class-body statements (column defs,
table args, relationships) which are executed at class-definition time.
"""

import uuid

import pytest

import models.orm_models as orm  # noqa: F401  — import covers all 88 stmts


def test_user_tablename():
    assert orm.User.__tablename__ == "users"


def test_analysis_tablename():
    assert orm.Analysis.__tablename__ == "analyses"


def test_url_analysis_tablename():
    assert orm.URLAnalysis.__tablename__ == "url_analyses"


def test_agent_result_tablename():
    assert orm.AgentResult.__tablename__ == "agent_results"


def test_ti_cache_tablename():
    assert orm.TICache.__tablename__ == "ti_cache"


def test_xai_report_tablename():
    assert orm.XAIReport.__tablename__ == "xai_reports"


def test_incident_tablename():
    assert orm.Incident.__tablename__ == "incidents"


def test_user_instantiation():
    # Phase 7: User model uses email + password_hash instead of username + api_key_hash.
    user = orm.User(
        email="student@usbbog.edu.co",
        password_hash="$2b$12$" + "a" * 53,
        role="student",
        is_active=True,
    )
    assert user.email == "student@usbbog.edu.co"
    assert user.role == "student"
    assert user.is_active is True


def test_analysis_instantiation():
    analysis = orm.Analysis(
        url="https://evil.com",
        domain="evil.com",
        verdict="PHISHING",
        s_risk=0.95,
        s_idn=0.9,
        s_llm=0.8,
        s_ti=0.7,
    )
    assert analysis.url == "https://evil.com"
    assert analysis.verdict == "PHISHING"


def test_url_analysis_instantiation():
    ua = orm.URLAnalysis(
        analysis_id=uuid.uuid4(),
        url="https://evil.com",
        domain_normalized="evil.com",
        is_punycode=False,
        confusables=[],
        ratio_h=0.0,
        sim_v=0.0,
        s_idn_local=0.0,
    )
    assert ua.domain_normalized == "evil.com"
    assert ua.is_punycode is False


def test_agent_result_instantiation():
    ar = orm.AgentResult(
        analysis_id=uuid.uuid4(),
        agent_name="IDNAgent",
        score=0.85,
        raw_output={"ratio_h": 0.5},
        duration_ms=12,
    )
    assert ar.agent_name == "IDNAgent"
    assert ar.score == 0.85


def test_ti_cache_instantiation():
    tic = orm.TICache(
        domain="evil.com",
        s_virustotal=0.9,
        s_urlscan=0.8,
        s_gsb=1.0,
        s_ti_aggregate=0.88,
    )
    assert tic.domain == "evil.com"
    assert tic.s_virustotal == 0.9


def test_xai_report_instantiation():
    xai = orm.XAIReport(
        analysis_id=uuid.uuid4(),
        shap_values={"idn_contribution": 0.5},
        lime_values={},
        top_features=["idn_contribution"],
    )
    assert "idn_contribution" in xai.shap_values


def test_incident_instantiation():
    inc = orm.Incident(
        analysis_id=uuid.uuid4(),
        verdict="PHISHING",
        s_risk=0.95,
        domain="evil.com",
        reviewed=False,
    )
    assert inc.verdict == "PHISHING"
    assert inc.reviewed is False
