"""The scheduled_reports drop — removing the last trace of report_scheduler_service.

`report_scheduler_service` was `ScheduledReport`'s only reader and has been
archived, so the model is gone and the table goes with it. ION has no Alembic;
schema changes live in the idempotent `_run_migrations` sweep in
`storage/database.py`, alongside the `notifications`, `threat_hunts` and
`kb_document_embeddings` drops that set the pattern.

**Why this is tested rather than taken on trust.** The test suite runs on SQLite
and production runs on PostgreSQL, so a migration can pass here and fail on
upgrade. This one is portable by construction rather than by dialect branch —
`has_table` is asked through SQLAlchemy's inspector, which is implemented per
dialect, and `DROP TABLE <name>` is identical SQL on both. What the tests below
pin is the behaviour that portability depends on: the guard, so the sweep does
not raise on a fresh database that never had the table; the drop itself, so an
upgraded deployment actually loses it; idempotency, so a second boot is a no-op;
and that `create_all` cannot bring it back now the model is gone.

The table's only foreign key points OUT (`created_by_id` -> `users.id`) and
nothing references it, so there is no dependent object to drop first and no
CASCADE needed — which is the other reason one plain statement serves both
backends.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect, text

from ion.models.base import Base
from ion.storage.database import _run_migrations

# The pre-migration shape, as an upgraded deployment carries it. Written out
# rather than taken from the model, because the model no longer exists — which
# is the point.
LEGACY_DDL = """
CREATE TABLE scheduled_reports (
    id INTEGER PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    schedule VARCHAR(50) NOT NULL,
    day_of_week INTEGER,
    day_of_month INTEGER,
    time_utc VARCHAR(5),
    is_active BOOLEAN,
    created_by_id INTEGER NOT NULL REFERENCES users(id),
    last_run_at DATETIME,
    last_result TEXT,
    recipients TEXT,
    config TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)
"""


@pytest.fixture
def engine(tmp_path):
    """A database at the CURRENT schema — what `_run_migrations` expects to find.

    The sweep touches many tables beyond this one, so it needs the full schema
    present; a bare database makes it fail for unrelated reasons.
    """
    import ion.models  # noqa: F401  — registers every model on Base.metadata

    eng = create_engine(f"sqlite:///{tmp_path / 'ion.db'}")
    Base.metadata.create_all(eng)
    return eng


def _add_legacy_table(eng, *, rows: int = 1) -> None:
    with eng.begin() as conn:
        conn.execute(text(LEGACY_DDL))
        for i in range(rows):
            conn.execute(text(
                "INSERT INTO scheduled_reports "
                "(id, name, report_type, schedule, created_by_id, created_at, updated_at) "
                "VALUES (:i, :n, 'executive', 'weekly', 1, '2026-01-01', '2026-01-01')"
            ), {"i": i + 1, "n": f"weekly exec {i}"})


class TestTheModelIsGone:
    def test_scheduled_reports_is_no_longer_declared(self):
        """If the model came back, create_all would recreate the table on every
        boot and the drop below would fight it forever."""
        import ion.models  # noqa: F401

        assert "scheduled_reports" not in Base.metadata.tables

    def test_the_model_is_no_longer_importable(self):
        with pytest.raises(ImportError):
            from ion.models.sla import ScheduledReport  # noqa: F401

    def test_it_is_no_longer_exported_from_the_models_package(self):
        import ion.models as models

        assert not hasattr(models, "ScheduledReport")

    def test_the_sibling_models_in_that_file_survive(self):
        """The file holds PlaybookAction and PlaybookActionLog, both live —
        `playbook_action_service` is imported by `web/response_api.py`."""
        from ion.models.sla import PlaybookAction, PlaybookActionLog  # noqa: F401

        assert "playbook_actions" in Base.metadata.tables

    def test_the_oncall_models_are_untouched(self):
        """Explicitly out of scope: on-call roster is still a README feature, so
        these stay declared even though nothing reads them yet."""
        from ion.models.oncall import (  # noqa: F401
            EscalationLog,
            EscalationPolicy,
            OnCallRoster,
        )

        for table in ("oncall_roster", "escalation_policies", "escalation_log"):
            assert table in Base.metadata.tables, table


class TestTheDrop:
    def test_a_fresh_database_never_gets_the_table(self, engine):
        assert not inspect(engine).has_table("scheduled_reports")

    def test_the_sweep_does_not_raise_on_a_database_without_it(self, engine):
        """The guard. A new install has no such table, and an unguarded DROP
        would abort the whole startup sweep on its first boot."""
        _run_migrations(engine)

        assert not inspect(engine).has_table("scheduled_reports")

    def test_an_upgraded_database_loses_the_table(self, engine):
        _add_legacy_table(engine)
        assert inspect(engine).has_table("scheduled_reports")

        _run_migrations(engine)

        assert not inspect(engine).has_table("scheduled_reports")

    def test_rows_go_with_it(self, engine):
        """Deliberate: the config has no reader left, so there is nothing to
        migrate it to. Recorded here so the data loss is a decision on the
        record rather than a surprise."""
        _add_legacy_table(engine, rows=3)

        _run_migrations(engine)

        with pytest.raises(Exception):
            engine.connect().execute(
                text("SELECT count(*) FROM scheduled_reports")).scalar()

    def test_running_the_sweep_twice_is_a_no_op(self, engine):
        """Every boot runs it, so the second pass must not raise."""
        _add_legacy_table(engine)

        _run_migrations(engine)
        _run_migrations(engine)

        assert not inspect(engine).has_table("scheduled_reports")

    def test_create_all_does_not_bring_it_back(self, engine):
        """The sequence a real boot runs: migrate, then create_all. If the model
        were still declared these would deadlock against each other."""
        _add_legacy_table(engine)

        _run_migrations(engine)
        Base.metadata.create_all(engine)

        assert not inspect(engine).has_table("scheduled_reports")

    def test_the_tables_around_it_are_left_alone(self, engine):
        """A DROP naming the wrong table, or a CASCADE, would take neighbours
        with it — `users` is the one the dropped foreign key pointed at."""
        _add_legacy_table(engine)

        _run_migrations(engine)

        insp = inspect(engine)
        for table in ("users", "playbook_actions", "comm_templates",
                      "oncall_roster", "escalation_policies"):
            assert insp.has_table(table), table
