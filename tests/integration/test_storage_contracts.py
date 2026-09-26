"""Real isolated PostgreSQL: migrations, writes, replica state and retention."""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest

from schemas.analyze import AgentTelemetry, AnalyzeEmailRequest
from scripts.retain_email_metadata import retain_email_metadata
from scripts.sync_pg_bilateral import sync
from services.persistence import _persist_email_incident, _persist_incident, _persist_manual_report
from tests.support.local_process import run
from tests.unit.test_persist_helpers import _make_body, _make_response

SCHEMA = (Path(__file__).resolve().parents[2] / "deploy/schema.sql").read_text()


@pytest.fixture(scope="module")
def postgres_socket():
    executable = shutil.which("initdb")
    if executable is None:
        candidates = list(Path("/opt/homebrew/opt").glob("postgresql*/bin/initdb"))
        candidates += list(Path("/usr/lib/postgresql").glob("*/bin/initdb"))
        executable = str(candidates[0]) if candidates else None
    if executable is None:
        pytest.skip("PostgreSQL binaries required for isolated storage integration")
    binaries = Path(executable).parent
    with tempfile.TemporaryDirectory(prefix="tesis-pg-", dir="/tmp") as directory:
        data = str(Path(directory) / "data")
        run(
            [executable, "-D", data, "-A", "trust", "-U", "testuser", "--no-locale", "-E", "UTF8"],
            check=True,
            capture_output=True,
            timeout=20,
        )
        run(
            [
                str(binaries / "pg_ctl"),
                "-D",
                data,
                "-w",
                "-t",
                "10",
                "-l",
                str(Path(directory) / "postgres.log"),
                "-o",
                f"-k {directory} -c listen_addresses='' -c fsync=off",
                "start",
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        try:
            yield directory
        finally:
            run(
                [str(binaries / "pg_ctl"), "-D", data, "-m", "immediate", "stop"],
                check=True,
                capture_output=True,
                timeout=15,
            )


@pytest.fixture
async def databases(postgres_socket):
    admin = await asyncpg.connect(host=postgres_socket, user="testuser", database="postgres")
    names = ["test_" + uuid.uuid4().hex for _ in range(2)]
    connections = []
    try:
        for name in names:
            await admin.execute(f'CREATE DATABASE "{name}"')
            connections.append(
                await asyncpg.connect(host=postgres_socket, user="testuser", database=name)
            )
        yield connections
    finally:
        for connection in connections:
            await connection.close()
        for name in names:
            await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
        await admin.close()


async def test_legacy_upgrade_preserves_identity_and_is_repeatable(databases):
    db, replica = databases
    await db.execute("""
        CREATE TABLE users (
          id UUID PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL, role VARCHAR(20) NOT NULL DEFAULT 'viewer',
          is_active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ DEFAULT now(),
          last_login TIMESTAMPTZ);
        CREATE TABLE incidents (
          id UUID PRIMARY KEY, email_hash VARCHAR(64) NOT NULL DEFAULT '',
          url TEXT NOT NULL, domain VARCHAR(255) NOT NULL, verdict VARCHAR(20) NOT NULL,
          s_risk NUMERIC(6,4), s_idn NUMERIC(6,4), s_llm NUMERIC(6,4), s_ti NUMERIC(6,4),
          llm_reason TEXT, shap_contributions JSONB, analyzed_by VARCHAR(50),
          created_at TIMESTAMPTZ DEFAULT now());
    """)
    user_id = uuid.uuid4()
    await db.execute(
        "INSERT INTO users(id, username, password_hash) VALUES ($1,'legacy','hash')", user_id
    )
    await db.execute(SCHEMA)
    await db.execute(SCHEMA)
    user = await db.fetchrow("SELECT * FROM users WHERE id=$1", user_id)
    assert (user["email"], user["password_hash"], user["role"]) == ("legacy", "hash", "viewer")
    assert await db.fetchval("SELECT count(*) FROM schema_migrations") == 3
    await replica.execute(SCHEMA)
    await sync(db, replica)
    copied = await replica.fetchrow("SELECT * FROM users WHERE id=$1", user_id)
    assert (copied["email"], copied["role"]) == ("legacy", "viewer")
    assert (
        await db.fetchval(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_name='incidents' AND column_name='agent_status'"
        )
        == 1
    )


async def test_real_writes_serialize_uuid_json_and_default_minimization(databases, monkeypatch):
    db, _ = databases
    await db.execute(SCHEMA)
    monkeypatch.setattr("models.database.get_pool", lambda: db)
    response = _make_response()
    response.agent_status = {"hf_url": AgentTelemetry(status="ok", model="test", revision="frozen")}
    await _persist_incident(response, _make_body(email_hash="hash"))
    saved = await db.fetchrow("SELECT * FROM incidents WHERE id=$1", uuid.UUID(response.request_id))
    assert json.loads(saved["agent_status"])["hf_url"]["status"] == "ok"
    assert saved["verdict"] == response.verdict

    response = _make_response()
    body = AnalyzeEmailRequest(
        all_urls=["https://example.com"],
        email_body_html="<p>private content</p>",
        email_subject="private subject",
        images=["https://example.com/image"],
        email_from="from@example.com",
        email_to="to@example.com",
        email_text_snippet="private content",
    )
    await _persist_email_incident(response, body)
    saved = await db.fetchrow("SELECT * FROM incidents WHERE id=$1", uuid.UUID(response.request_id))
    assert saved["email_body_html"] == ""
    assert json.loads(saved["email_images"]) == []
    assert saved["email_subject"] == "private subject"

    report_id = str(uuid.uuid4())
    await _persist_manual_report(
        report_id,
        "https://example.com",
        "PHISHING",
        "operator@example.com",
        "reported",
        datetime.now(UTC),
    )
    assert (
        await db.fetchval("SELECT analyzed_by FROM incidents WHERE id=$1", uuid.UUID(report_id))
        == "operator@example.com"
    )


async def test_authority_propagates_security_updates_purges_and_late_audit(databases):
    source, replica = databases
    for db in databases:
        await db.execute(SCHEMA)
    user_id, incident_id, feedback_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    for db in databases:
        await db.execute(
            "INSERT INTO users(id,email,password_hash,role) "
            "VALUES ($1,'same@example.com','old','admin')",
            user_id,
        )
        await db.execute(
            "INSERT INTO incidents(id,url,domain,verdict) "
            "VALUES ($1,'https://x.example','x.example','PHISHING')",
            incident_id,
        )
        await db.execute(
            "INSERT INTO feedback(id,incident_id,confirmed_verdict,confirmed_by) "
            "VALUES($1,$2,'PHISHING',$3)",
            feedback_id,
            incident_id,
            user_id,
        )
    await source.execute(
        "UPDATE users SET role='student',is_active=false,password_hash='new' WHERE id=$1", user_id
    )
    await source.execute(
        "UPDATE feedback SET confirmed_verdict='LEGITIMATE', ingested=true WHERE id=$1", feedback_id
    )
    stale = uuid.uuid4()
    await replica.execute(
        "INSERT INTO incidents(id,url,domain,verdict) "
        "VALUES ($1,'https://stale.example','stale.example','PHISHING')",
        stale,
    )
    await source.execute(
        "INSERT INTO audit_log(event_type,status,occurred_at) "
        "VALUES('SOURCE','SUCCESS','2020-01-01')"
    )
    await replica.execute(
        "INSERT INTO audit_log(event_type,status,occurred_at) "
        "VALUES('REPLICA','SUCCESS','2030-01-01')"
    )

    await sync(source, replica, dry=True)
    assert await replica.fetchval("SELECT is_active FROM users WHERE id=$1", user_id)
    await sync(source, replica)
    user = await replica.fetchrow("SELECT * FROM users WHERE id=$1", user_id)
    assert (user["role"], user["is_active"], user["password_hash"]) == ("student", False, "new")
    feedback = await replica.fetchrow("SELECT * FROM feedback WHERE id=$1", feedback_id)
    assert (feedback["confirmed_verdict"], feedback["ingested"]) == ("LEGITIMATE", True)
    assert not await replica.fetchval("SELECT EXISTS(SELECT 1 FROM incidents WHERE id=$1)", stale)
    await source.execute(
        "INSERT INTO audit_log(event_type,status,occurred_at) VALUES('LATE','SUCCESS','2019-01-01')"
    )
    await sync(source, replica)
    await sync(source, replica)
    for db in databases:
        assert await db.fetchval("SELECT count(*) FROM audit_log") == 3
    await source.execute("DELETE FROM incidents WHERE id=$1", incident_id)
    await sync(source, replica)
    assert await replica.fetchval("SELECT count(*) FROM incidents") == 0
    assert await replica.fetchval("SELECT count(*) FROM feedback") == 0


async def test_retention_is_dry_by_default_and_preserves_recent_rows(databases):
    db, _ = databases
    await db.execute(SCHEMA)
    await db.execute("""
      INSERT INTO incidents(url,domain,verdict,email_subject,email_body_html,created_at) VALUES
      ('https://old.example','old.example','PHISHING','old subject','body',
       now()-interval '31 days'),
      ('https://new.example','new.example','PHISHING','new subject','body', now());
    """)
    assert await retain_email_metadata(db, days=30) == 1
    assert (
        await db.fetchval("SELECT email_subject FROM incidents WHERE domain='old.example'")
        == "old subject"
    )
    assert await retain_email_metadata(db, days=30, apply=True) == 1
    assert await retain_email_metadata(db, days=30, apply=True) == 0
    assert (
        await db.fetchval("SELECT email_subject FROM incidents WHERE domain='new.example'")
        == "new subject"
    )
