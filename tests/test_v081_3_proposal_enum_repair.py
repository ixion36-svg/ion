"""Raw-SQL enum writes broke every ORM read of `detection_proposals`.

`test_v032_sqlenum_name_storage.py` is the canonical statement of the rule:
`SQLEnum(native_enum=False)` stores the enum NAME, ORM filters coerce, and raw
`text()` SQL does NOT. The legacy-tuning-proposal carry-over in `database.py`
wrote its INSERT by hand with `'draft'`, `'bob'` and `'other'` — the enum
VALUES — so the rows it created cannot be read back:

    LookupError: 'human' is not among the defined enum values.
    Enum name: detectionproposalsource. Possible values: HUMAN, BOB

One such row 500s `GET /api/de/proposals` for everyone, because the failure is
at row hydration and takes the whole query with it. That endpoint is also the
health probe METIS's ION connector uses, so a single bad row reads as "ION is
down" from the other product.

Found running METIS against a real ION container, not by a test — both suites
mock the other side, so neither could see it.

**Postgres, not SQLite.** This is a storage-layer contract about how an enum
column round-trips, and the deployment that has the bad rows runs Postgres.
Asserting it against SQLite would test a different database than the one the
claim is about. Set `ION_TEST_DATABASE_URL` to a Postgres server; the tests
create and drop their own scratch database and never touch an existing one.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.detection_proposal import (  # noqa: E402
    DetectionProposal,
    DetectionProposalChangeType,
    DetectionProposalSource,
    DetectionProposalStatus,
)
from ion.storage.database import Base, repair_detection_proposal_enums  # noqa: E402

ADMIN_URL = os.environ.get("ION_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not ADMIN_URL,
    reason="needs a Postgres server: set ION_TEST_DATABASE_URL "
           "(e.g. postgresql+psycopg2://ion:pw@127.0.0.1:5433/ion)",
)


@pytest.fixture
def session():
    """A scratch database of its own, dropped afterwards.

    CREATE DATABASE cannot run inside a transaction, hence AUTOCOMMIT.
    """
    scratch = f"ion_enum_repair_{uuid.uuid4().hex[:12]}"
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{scratch}"'))

    engine = create_engine(ADMIN_URL.rsplit("/", 1)[0] + f"/{scratch}")
    with engine.begin() as conn:
        # Case-embedding tables use pgvector; a fresh database has no
        # extensions, and create_all needs the type to exist first.
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    # Whole schema, not just this table: detection_proposals carries FKs to
    # users, alerts and investigations.
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    try:
        with factory() as s:
            yield s
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :d"), {"d": scratch})
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}"'))
        admin.dispose()


def _insert_raw(session, *, status: str, source: str, change_type: str) -> None:
    """Exactly what the carry-over migration did: literals, no bind processor."""
    session.execute(
        text(
            "INSERT INTO detection_proposals "
            "(rule_name, change_type, title, suggested_change, status, source, "
            " created_at, updated_at) "
            "VALUES ('r', :ct, 't', 'c', :st, :src, "
            " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ),
        {"ct": change_type, "st": status, "src": source},
    )
    session.commit()


def test_a_value_written_by_raw_sql_cannot_be_read_back(session):
    """The bug, pinned. Untreated this is a 500 on a list endpoint."""
    _insert_raw(session, status="draft", source="bob", change_type="other")

    with pytest.raises(LookupError):
        session.query(DetectionProposal).all()


def test_repair_rewrites_values_to_names(session):
    _insert_raw(session, status="draft", source="bob", change_type="other")

    repaired = repair_detection_proposal_enums(session.connection())
    session.commit()

    assert repaired == 1
    row = session.query(DetectionProposal).one()
    assert row.status is DetectionProposalStatus.DRAFT
    assert row.source is DetectionProposalSource.BOB
    assert row.change_type is DetectionProposalChangeType.OTHER


def test_repair_leaves_correctly_stored_rows_alone(session):
    """Idempotent: it runs on every startup, so a second pass must be a no-op
    rather than mangling a name it already wrote."""
    session.add(DetectionProposal(
        rule_name="r", title="t", suggested_change="c",
        change_type=DetectionProposalChangeType.NEW_RULE,
        status=DetectionProposalStatus.APPLIED,
        source=DetectionProposalSource.HUMAN))
    session.commit()

    assert repair_detection_proposal_enums(session.connection()) == 0

    row = session.query(DetectionProposal).one()
    assert row.change_type is DetectionProposalChangeType.NEW_RULE
    assert row.status is DetectionProposalStatus.APPLIED


def test_repair_handles_the_underscored_member(session):
    """`new_rule` -> `NEW_RULE` is the one member where name and value differ
    by more than case folding is guaranteed to cover. Pinned so a rename that
    breaks that assumption is caught here rather than in production."""
    _insert_raw(session, status="applied", source="human", change_type="new_rule")

    assert repair_detection_proposal_enums(session.connection()) == 1
    session.commit()

    assert session.query(DetectionProposal).one().change_type is \
        DetectionProposalChangeType.NEW_RULE


def test_a_mixed_row_is_repaired_on_the_wrong_column_only(session):
    """The row that actually surfaced this had status='APPLIED' (the name)
    and source='human' (the value) in the same row."""
    _insert_raw(session, status="APPLIED", source="human", change_type="NEW_RULE")

    assert repair_detection_proposal_enums(session.connection()) == 1
    session.commit()

    row = session.query(DetectionProposal).one()
    assert row.status is DetectionProposalStatus.APPLIED
    assert row.source is DetectionProposalSource.HUMAN


def test_an_unrecognised_value_is_left_for_a_human(session):
    """Repair maps known values to their member names. Anything it cannot
    place is left alone and not counted — silently coercing an unknown to a
    valid-looking member would invent provenance that was never recorded.

    The junk value has to fit VARCHAR(5): the column is sized to the longest
    member NAME ('HUMAN'), which is itself why storing values rather than
    names was never going to be caught by a length constraint.
    """
    _insert_raw(session, status="draft", source="zzz", change_type="other")

    repair_detection_proposal_enums(session.connection())
    session.commit()

    left = session.execute(
        text("SELECT source FROM detection_proposals")).scalar_one()
    assert left == "zzz"
