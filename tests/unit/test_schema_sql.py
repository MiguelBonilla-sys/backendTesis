"""Tests for scripts/schema.sql integrity"""
import pytest
from pathlib import Path


class TestSchemaSql:
    @pytest.fixture
    def schema_content(self):
        path = Path(__file__).parent.parent.parent / "scripts" / "schema.sql"
        assert path.exists(), f"schema.sql debe existir en scripts/ (buscado en {path})"
        return path.read_text()

    def test_schema_has_8_tables(self, schema_content):
        tables = [l.strip() for l in schema_content.split("\n")
                  if l.strip().startswith("CREATE TABLE")]
        assert len(tables) == 8, f"Se esperan 8 tablas, hay {len(tables)}: {tables}"

    def test_schema_has_users_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS users" in schema_content

    def test_schema_has_incidents_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS incidents" in schema_content

    def test_schema_has_audit_log_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS audit_log" in schema_content

    def test_schema_has_simulation_events_table(self, schema_content):
        assert "CREATE TABLE IF NOT EXISTS simulation_events" in schema_content

    def test_no_pii_email_columns(self, schema_content):
        """Ninguna tabla debe tener columna 'email' directa — solo hashes."""
        lines = schema_content.lower().split("\n")
        email_columns = [l for l in lines if "email" in l and "hash" not in l and "CREATE" not in l and "--" not in l and l.strip()]
        # Solo deben existir columnas email_hash o student_hash, no 'email' raw
        raw_email = [l for l in email_columns if "varchar" in l or "text" in l]
        assert len(raw_email) == 0, f"Columnas de email raw encontradas: {raw_email}"

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
