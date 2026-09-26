"""Tests for scripts/schema.sql integrity"""
from pathlib import Path

import pytest


class TestSchemaSql:
    @pytest.fixture
    def schema_content(self):
        path = Path(__file__).parent.parent.parent / "scripts" / "schema.sql"
        assert path.exists(), f"schema.sql debe existir en scripts/ (buscado en {path})"
        return path.read_text()

    def test_both_paths_use_one_canonical_schema(self):
        root = Path(__file__).resolve().parents[2]
        assert (root / "scripts/schema.sql").resolve() == root / "deploy/schema.sql"

    def test_schema_has_theta_calibrations_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS theta_calibrations" in schema_content

    def test_schema_has_users_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS users" in schema_content

    def test_schema_has_incidents_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS incidents" in schema_content

    def test_schema_has_audit_log_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS audit_log" in schema_content

    def test_schema_has_simulation_events_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS simulation_events" in schema_content

    def test_schema_supports_current_persistence_and_versioned_upgrade(self, schema_content):
        for column in ("email", "email_subject", "email_body_html", "agent_status", "event_id"):
            assert column in schema_content
        assert "RENAME COLUMN username TO email" in schema_content
        assert "schema_migrations" in schema_content
        assert "DROP TABLE" not in schema_content

    def test_schema_has_indexes(self, schema_content):
        indexes = [l for l in schema_content.split("\n") if "CREATE INDEX" in l]
        assert len(indexes) >= 7, f"Se esperan al menos 7 índices, hay {len(indexes)}"

    def test_users_has_bcrypt_password(self, schema_content):
        assert "password_hash" in schema_content.lower()

    def test_incidents_has_verdict_check(self, schema_content):
        assert "PHISHING" in schema_content
        assert "LEGITIMATE" in schema_content
        assert "SUSPICIOUS" in schema_content


class TestInitDbScript:
    def test_init_db_script_exists(self):
        path = Path(__file__).parent.parent.parent / "scripts" / "init_db.py"
        assert path.exists(), f"init_db.py debe existir en scripts/ (buscado en {path})"

    def test_init_db_imports_asyncpg(self):
        path = Path(__file__).parent.parent.parent / "scripts" / "init_db.py"
        assert "asyncpg" in path.read_text()
