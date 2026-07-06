"""v0.49.3 code-review fixes: migration hardening.

1. The observables ADD COLUMN loop crashed the losing worker on a concurrent
   multi-worker boot (both inspect, both see the column missing, both ALTER,
   the loser raises) — unlike the session_token_hash migration which was
   explicitly hardened for this exact race in v0.31.23.
2. ix_ai_feedback_alert_template (v0.47 detection-health dedup GROUP BY) was
   declared on the model only; create_all skips pre-existing tables and the
   idempotent index migration list was never extended, so upgraded
   deployments full-scan the dashboard query forever.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect, text

import ion.storage.database as db_mod


@pytest.fixture
def sqlite_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    yield engine
    engine.dispose()


def _make_observables_table(engine, with_col: bool):
    cols = "id INTEGER PRIMARY KEY, type VARCHAR(32), value VARCHAR(2048)"
    if with_col:
        cols += ", is_ignored BOOLEAN NOT NULL DEFAULT 0"
    with engine.begin() as conn:
        conn.execute(text(f"CREATE TABLE observables ({cols})"))


class TestAddColumnTolerant:
    def test_adds_missing_column(self, sqlite_engine):
        _make_observables_table(sqlite_engine, with_col=False)
        db_mod._add_column_tolerant(
            sqlite_engine, "observables", "is_ignored", "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        cols = {c["name"] for c in inspect(sqlite_engine).get_columns("observables")}
        assert "is_ignored" in cols

    def test_survives_concurrent_worker_race(self, sqlite_engine):
        """The losing worker's ALTER hits 'duplicate column' — it must log and
        continue, not crash the boot."""
        _make_observables_table(sqlite_engine, with_col=True)
        # Simulates the race: our inspector snapshot said the column was
        # missing, but another worker added it before our ALTER ran.
        db_mod._add_column_tolerant(
            sqlite_engine, "observables", "is_ignored", "BOOLEAN NOT NULL DEFAULT FALSE"
        )  # must not raise

    def test_boolean_default_translated_for_sqlite(self, sqlite_engine):
        """Older SQLite has no FALSE keyword; the default must be emitted as 0
        on SQLite (Postgres keeps FALSE — 0 is invalid for boolean there)."""
        _make_observables_table(sqlite_engine, with_col=False)
        with sqlite_engine.begin() as conn:
            conn.execute(text("INSERT INTO observables (type, value) VALUES ('ip', '1.2.3.4')"))
        db_mod._add_column_tolerant(
            sqlite_engine, "observables", "is_ignored", "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        col = next(
            c for c in inspect(sqlite_engine).get_columns("observables")
            if c["name"] == "is_ignored"
        )
        assert str(col["default"]).strip().upper() != "FALSE", (
            "FALSE keyword reached SQLite — emit 0 instead"
        )
        with sqlite_engine.connect() as conn:
            val = conn.execute(text("SELECT is_ignored FROM observables")).scalar()
        assert val in (0, False)


class TestAiFeedbackIndexMigration:
    def test_upgraded_db_gets_detection_health_index(self, sqlite_engine):
        """A pre-v0.47 DB (ai_feedback exists, index doesn't) must receive
        ix_ai_feedback_alert_template from the idempotent migration."""
        from ion.models.document import Base

        Base.metadata.create_all(sqlite_engine)
        with sqlite_engine.begin() as conn:
            conn.execute(text("DROP INDEX IF EXISTS ix_ai_feedback_alert_template"))
        idx = {i["name"] for i in inspect(sqlite_engine).get_indexes("ai_feedback")}
        assert "ix_ai_feedback_alert_template" not in idx  # sanity: upgrade state

        db_mod._run_migrations(sqlite_engine)

        idx = {i["name"] for i in inspect(sqlite_engine).get_indexes("ai_feedback")}
        assert "ix_ai_feedback_alert_template" in idx


class TestPostgresBranchSql:
    """Production is PostgreSQL — pin the SQL the Postgres branch emits (it
    cannot be executed here without a live server, so assert the string)."""

    def test_postgres_add_column_uses_if_not_exists_and_keeps_false(self):
        sql = db_mod._add_column_sql(
            True, "observables", "is_ignored", "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        assert sql == (
            "ALTER TABLE observables ADD COLUMN IF NOT EXISTS is_ignored "
            "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        # Postgres rejects DEFAULT 0 for a BOOLEAN column — must NOT be rewritten.
        assert "DEFAULT 0" not in sql

    def test_sqlite_add_column_rewrites_false_and_omits_if_not_exists(self):
        sql = db_mod._add_column_sql(
            False, "observables", "is_ignored", "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        assert "IF NOT EXISTS" not in sql
        assert "DEFAULT 0" in sql and "DEFAULT FALSE" not in sql

    def test_postgres_non_boolean_default_untouched(self):
        sql = db_mod._add_column_sql(
            True, "cyab_systems", "business_unit", "VARCHAR(255)"
        )
        assert sql == "ALTER TABLE cyab_systems ADD COLUMN IF NOT EXISTS business_unit VARCHAR(255)"


def test_upgraded_db_gets_single_running_job_index(sqlite_engine):
    """AUDIT-1: upgraded deployments must receive the partial unique index
    that enforces at most one running doc-analysis job."""
    from ion.models.document import Base

    Base.metadata.create_all(sqlite_engine)
    with sqlite_engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS uq_doc_analysis_jobs_one_running"))

    db_mod._run_migrations(sqlite_engine)

    idx = {i["name"] for i in inspect(sqlite_engine).get_indexes("doc_analysis_jobs")}
    assert "uq_doc_analysis_jobs_one_running" in idx


def test_upgraded_db_gets_is_ignored_index(sqlite_engine):
    """AUDIT-7: _ignored_normalized_values runs on every case-detail GET —
    without an index Postgres seq-scans the observables table per view."""
    from ion.models.document import Base

    Base.metadata.create_all(sqlite_engine)
    with sqlite_engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_observables_is_ignored"))

    db_mod._run_migrations(sqlite_engine)

    idx = {i["name"] for i in inspect(sqlite_engine).get_indexes("observables")}
    assert "ix_observables_is_ignored" in idx
