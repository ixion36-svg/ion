"""`ion upgrade` wrote enum VALUES into columns that store enum NAMES.

`test_v032_sqlenum_name_storage.py` is the canonical statement of the rule:
`SQLEnum(native_enum=False)` stores the NAME, ORM filters coerce, and raw
`text()` SQL does NOT. `test_v081_3_proposal_enum_repair.py` covers the same
failure in `detection_proposals`.

Eight raw-SQL migrations in `cli/main.py` had it too, writing `'alert'`,
`'case'`, `'webhook'`, `'activity'` and `'health_check'` into `notes`,
`observable_links` and `integration_events`. There is no CHECK constraint
behind a non-native enum, so the row inserts cleanly and fails later:

    LookupError: 'webhook' is not among the defined enum values.
    Enum name: integrationeventtype. Possible values: WEBHOOK, ACTIVITY, ...

The failure is at row hydration, so it takes the whole query, not the row.
Readers affected: integration_api, webhook_api, integration_log_service,
webhook_service, case_lifecycle_api, and every reader of notes/observables.

**SQLite, not Postgres**, unlike the detection_proposals test. That one asserts
a storage-layer round-trip against the deployment's real database. The claim
here is about SQLAlchemy's result processor, which raises identically on any
backend, so gating this on a Postgres server would only stop it running in CI
-- which is where a migration nobody runs locally most needs a guard.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models import Base  # noqa: E402
from ion.models.alert_triage import Note, NoteEntityType  # noqa: E402
from ion.models.integration import (  # noqa: E402
    IntegrationEvent,
    IntegrationEventType,
    IntegrationStatus,
    IntegrationType,
    LogLevel,
    WebhookStatus,
)
from ion.models.observable import ObservableLink, ObservableLinkType  # noqa: E402
from ion.storage.database import repair_enum_name_storage  # noqa: E402

CLI_SOURCE = Path(__file__).resolve().parent.parent / "src" / "ion" / "cli" / "main.py"

TABLES = [Note.__table__, ObservableLink.__table__, IntegrationEvent.__table__]


@pytest.fixture
def engine():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng, tables=TABLES)
    return eng


def _insert_raw(engine, sql: str) -> None:
    with engine.begin() as conn:
        conn.execute(text(sql))


def _scalar(engine, sql: str):
    with engine.begin() as conn:
        return conn.execute(text(sql)).scalar()


# --------------------------------------------------------------- the contract

def test_the_orm_stores_the_member_name(engine):
    with Session(engine) as s:
        s.add(Note(entity_type=NoteEntityType.ALERT, entity_id="a-1",
                   user_id=1, content="x"))
        s.commit()
    assert _scalar(engine, "SELECT entity_type FROM notes") == "ALERT"


def test_a_non_native_enum_has_no_check_constraint(engine):
    """Which is why a wrong-case write is accepted instead of rejected."""
    ddl = _scalar(engine, "SELECT sql FROM sqlite_master WHERE name='notes'")
    assert "CHECK" not in (ddl or "")


def test_a_value_written_by_raw_sql_breaks_every_read_of_the_table(engine):
    _insert_raw(engine, "INSERT INTO notes (entity_type, entity_id, user_id, "
                        "content, created_at) VALUES ('alert', 'a-1', 1, 'x', "
                        "CURRENT_TIMESTAMP)")
    with pytest.raises(LookupError) as exc, Session(engine) as s:
        s.execute(select(Note)).scalars().all()
    assert "not among the defined enum values" in str(exc.value)


# ------------------------------------------------------------------ the repair

def test_repair_rewrites_values_to_names_in_every_affected_table(engine):
    _insert_raw(engine, "INSERT INTO notes (entity_type, entity_id, user_id, "
                        "content, created_at) VALUES ('alert', 'a-1', 1, 'x', "
                        "CURRENT_TIMESTAMP)")
    _insert_raw(engine, "INSERT INTO observable_links (observable_id, link_type, "
                        "entity_id, context, extracted_from, created_at) "
                        "VALUES (1, 'case', 7, 'c', 'manual', CURRENT_TIMESTAMP)")
    _insert_raw(engine, "INSERT INTO integration_events (event_type, "
                        "integration_type, level, created_at) "
                        "VALUES ('webhook', 'custom', 'error', CURRENT_TIMESTAMP)")

    with engine.begin() as conn:
        repaired = repair_enum_name_storage(conn)

    assert repaired == 3, "one row per table"
    assert _scalar(engine, "SELECT entity_type FROM notes") == "ALERT"
    assert _scalar(engine, "SELECT link_type FROM observable_links") == "CASE"
    assert _scalar(engine, "SELECT event_type FROM integration_events") == "WEBHOOK"
    assert _scalar(engine, "SELECT integration_type FROM integration_events") == "CUSTOM"
    assert _scalar(engine, "SELECT level FROM integration_events") == "ERROR"

    # and the rows are readable again, which is the point
    with Session(engine) as s:
        assert len(s.execute(select(Note)).scalars().all()) == 1
        assert len(s.execute(select(IntegrationEvent)).scalars().all()) == 1


def test_a_row_with_several_bad_columns_counts_once(engine):
    _insert_raw(engine, "INSERT INTO integration_events (event_type, "
                        "integration_type, level, status, health_status, created_at) "
                        "VALUES ('activity', 'gitlab', 'warning', 'failed', "
                        "'degraded', CURRENT_TIMESTAMP)")
    with engine.begin() as conn:
        assert repair_enum_name_storage(conn) == 1
    assert _scalar(engine, "SELECT status FROM integration_events") == "FAILED"
    assert _scalar(engine, "SELECT health_status FROM integration_events") == "DEGRADED"


def test_repair_is_idempotent(engine):
    _insert_raw(engine, "INSERT INTO notes (entity_type, entity_id, user_id, "
                        "content, created_at) VALUES ('case', 'c-1', 1, 'x', "
                        "CURRENT_TIMESTAMP)")
    with engine.begin() as conn:
        assert repair_enum_name_storage(conn) == 1
    with engine.begin() as conn:
        assert repair_enum_name_storage(conn) == 0


def test_repair_leaves_a_value_matching_no_member_alone(engine):
    """Guessing at an unknown value would invent a verdict nobody recorded."""
    _insert_raw(engine, "INSERT INTO notes (entity_type, entity_id, user_id, "
                        "content, created_at) VALUES ('sasquatch', 'a-1', 1, "
                        "'x', CURRENT_TIMESTAMP)")
    with engine.begin() as conn:
        assert repair_enum_name_storage(conn) == 0
    assert _scalar(engine, "SELECT entity_type FROM notes") == "sasquatch"


def test_repair_skips_tables_this_deployment_does_not_have():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng, tables=[Note.__table__])
    with eng.begin() as conn:
        assert repair_enum_name_storage(conn) == 0


# ------------------------------------------------- the migrations that caused it

def _cli_source_without_comments() -> str:
    """Comments name the lowercase values when explaining the bug, so a naive
    search matches the explanation rather than the SQL."""
    out = []
    for line in CLI_SOURCE.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


@pytest.mark.parametrize("literal", ["'ALERT'", "'CASE'", "'WEBHOOK'",
                                     "'ACTIVITY'", "'HEALTH_CHECK'"])
def test_upgrade_inserts_enum_names_not_values(literal):
    assert literal in _cli_source_without_comments(), (
        f"{literal} is not written by any migration in cli/main.py. A member "
        "VALUE there inserts cleanly and then raises LookupError on read."
    )


@pytest.mark.parametrize("expr", ["UPPER(integration_type)", "UPPER(level)",
                                  "UPPER(status)"])
def test_upgrade_uppercases_enum_columns_carried_from_old_tables(expr):
    """A column copied from a legacy table arrives in whatever case it was
    stored in, so the literal fix is not enough on its own."""
    assert expr in _cli_source_without_comments(), (
        f"{expr} missing: a carried-over enum column is not being normalised."
    )


def test_upper_is_a_safe_transform_for_every_affected_enum():
    """UPPER() is only correct while each member's name is its value upper-cased.
    A member added as FOO = "bar" would silently break the migrations above."""
    offenders = [
        f"{e.__name__}.{m.name} = {m.value!r}"
        for e in (NoteEntityType, ObservableLinkType, IntegrationEventType,
                  IntegrationType, LogLevel, WebhookStatus, IntegrationStatus)
        for m in e
        if m.name != str(m.value).upper()
    ]
    assert not offenders, offenders


def test_no_migration_still_inserts_a_lowercase_event_type():
    """The specific regression: the three event_type literals, lowercase."""
    source = _cli_source_without_comments()
    for bad in ("SELECT 'webhook'", "SELECT 'activity'", "SELECT 'health_check'"):
        assert bad not in source, f"{bad} writes a member value, not its name"


def test_the_repair_covers_every_table_the_migrations_write():
    """A migration added later against a new enum column needs a repair row too."""
    from ion.storage.database import _enum_name_storage_targets

    covered = {table for table, _ in _enum_name_storage_targets()}
    source = _cli_source_without_comments()
    written = {t for t in ("notes", "observable_links", "integration_events")
               if re.search(rf"INSERT INTO {t}\b", source)}
    assert written <= covered, f"not repaired: {written - covered}"
