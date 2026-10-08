"""Every foreign key a migration declares must point at a table something creates.

Found by trying to bring ION up against an empty PostgreSQL database
(8 Oct 2026). Startup died in ``_run_migrations``::

    (psycopg2.errors.UndefinedTable) relation "lessons" does not exist
    [SQL: CREATE TABLE lab_fixtures (
            ... lesson_id INTEGER NOT NULL REFERENCES lessons(id) ...)]

The ``Lesson`` model arrived with the course framework in v0.11.2 and was
removed in ``0d07781`` ("scope reduction... dark-module sweep"). The five
``lab_*`` migrations that referenced it were left behind, so nothing in
the codebase creates a ``lessons`` table any more.

Two things hid it for months:

* **Existing databases already had the table**, created while the model
  still existed, so every running deployment migrated fine.
* **The test suite runs on SQLite**, which does not resolve a foreign
  key's target table at ``CREATE TABLE`` time — it only complains when
  the FK is actually enforced. PostgreSQL rejects it immediately.

So the failure only appeared on a *fresh PostgreSQL* database, which is
the documented production deployment.

The first test below is the general guard: it parses every ``REFERENCES
<table>`` in the migration module and requires a creator for each, so the
next dropped model cannot leave a dangling reference behind. It is
static, which is the point — it holds regardless of which backend the
suite happens to run against.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.storage.database import _run_migrations

_DATABASE_PY = _SRC / "ion" / "storage" / "database.py"

#: Tables the ORM creates from model metadata.
_MODEL_TABLES = set(Base.metadata.tables)


def _migration_source() -> str:
    return _DATABASE_PY.read_text(encoding="utf-8")


def _referenced_tables() -> set[str]:
    """Every table named as a foreign-key target in the migrations."""
    return set(re.findall(r"REFERENCES\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
                          _migration_source()))


def _migration_created_tables() -> set[str]:
    """Every table the migrations create themselves."""
    return set(re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
                          r"([a-zA-Z_][a-zA-Z0-9_]*)",
                          _migration_source()))


# ── The general invariant ─────────────────────────────────────────────────


def test_every_migration_fk_target_has_a_creator():
    """No migration may reference a table nothing creates.

    PostgreSQL resolves the target at CREATE TABLE time, so a dangling
    reference is a hard startup failure on a fresh database — not a
    latent wart.
    """
    creatable = _MODEL_TABLES | _migration_created_tables()
    dangling = sorted(_referenced_tables() - creatable)

    assert not dangling, (
        "These migration foreign keys point at tables that neither a model "
        f"nor another migration creates: {dangling}. On a fresh PostgreSQL "
        "database the CREATE TABLE fails and ION will not start. Either "
        "create the table or remove the migration that references it."
    )


def test_the_dropped_lessons_table_is_no_longer_referenced():
    """The specific regression: `lessons` went away with its model."""
    assert "lessons" not in _referenced_tables()
    assert "lessons" not in _MODEL_TABLES


# ── The dead course/lab tables are gone, not half-present ─────────────────


_LAB_TABLES = [
    "lab_fixtures",
    "lab_session_fixtures",
    "lab_sessions",
    "lab_rubrics",
    "lab_criterion_results",
]


@pytest.mark.parametrize("table", _LAB_TABLES)
def test_lab_tables_are_not_created_on_a_fresh_database(tmp_path, table):
    """The replayable-labs feature was removed; its tables should not return.

    Migrations never drop, so an existing deployment keeps whatever it
    already has. This only pins what a *new* database gets.
    """
    engine = create_engine(f"sqlite:///{tmp_path / f'fresh_{table}.db'}")
    Base.metadata.create_all(engine)
    _run_migrations(engine)
    try:
        assert not inspect(engine).has_table(table)
    finally:
        engine.dispose()


def test_migrations_still_run_clean_on_a_fresh_database(tmp_path):
    """Whatever else changed, a fresh database must still migrate."""
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh_full.db'}")
    Base.metadata.create_all(engine)
    _run_migrations(engine)
    try:
        names = set(inspect(engine).get_table_names())
        # A representative core table, to prove migrations really ran
        # rather than erroring out early and being swallowed.
        assert "alert_cases" in names
        assert len(names) > 50
    finally:
        engine.dispose()


def test_migrations_are_idempotent(tmp_path):
    """Running twice must not fail — every block is existence-guarded."""
    engine = create_engine(f"sqlite:///{tmp_path / 'twice.db'}")
    Base.metadata.create_all(engine)
    _run_migrations(engine)
    _run_migrations(engine)
    engine.dispose()
