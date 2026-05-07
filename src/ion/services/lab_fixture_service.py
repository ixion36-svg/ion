"""Replayable lab fixture lifecycle service (v0.21.0).

Seed / teardown mock data for LAB-type lessons so each learner gets an
isolated, repeatable environment without affecting real SOC data.

Concurrency model
-----------------
``seed_lab`` holds ``pg_advisory_xact_lock(LAB_FIXTURES_NS, enrollment_id)``
for the duration of the insert transaction. This prevents double-materialisation
when two browser tabs race on the same (enrollment, lesson) pair. On SQLite the
lock call is a no-op (SQLite serialises writers anyway).

Lock namespace constant LAB_FIXTURES_NS is derived from the ASCII bytes of
'LABF' so it won't clash with the case-ledger namespace ('CEVL').
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Namespace for pg_advisory_xact_lock — 'LABF' as 4 bytes interpreted as int32.
LAB_FIXTURES_NS = 0x4C414246  # 'LABF'

# Allowed target tables — guards against arbitrary-table injection via fixture payload.
_ALLOWED_TABLES: frozenset[str] = frozenset(
    {"alerts", "alert_triage", "alert_cases", "observables"}
)


def _advisory_lock(session: Session, enrollment_id: int) -> None:
    """Acquire a per-enrolment advisory lock for the current transaction.

    No-op on non-postgres backends. Released automatically at COMMIT/ROLLBACK.
    """
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :eid)"),
        {"ns": LAB_FIXTURES_NS, "eid": int(enrollment_id)},
    )


def _validate_target_table(table: str) -> None:
    if table not in _ALLOWED_TABLES:
        raise ValueError(
            f"target_table '{table}' is not in the allowed set: {sorted(_ALLOWED_TABLES)}"
        )


def seed_lab(
    session: Session, *, enrollment_id: int, lesson_id: int
) -> list[int]:
    """Materialise fixture rows for a lab session.

    Idempotent: if active (not torn-down) lab_session_fixtures rows already
    exist for (enrollment_id, lesson_id), returns their materialised_row_ids
    without inserting duplicates.

    Returns a list of materialised row PKs in the target tables (in insertion
    order). Returns an empty list if no fixtures are defined for the lesson.
    """
    _advisory_lock(session, enrollment_id)

    # Idempotency check — return existing materialisations if still live.
    existing = session.execute(
        text(
            "SELECT materialised_row_id FROM lab_session_fixtures "
            "WHERE enrollment_id = :eid AND lesson_id = :lid AND torn_down_at IS NULL "
            "ORDER BY id"
        ),
        {"eid": enrollment_id, "lid": lesson_id},
    ).fetchall()
    if existing:
        logger.debug(
            "seed_lab idempotent hit: enrollment=%d lesson=%d rows=%d",
            enrollment_id, lesson_id, len(existing),
        )
        return [row[0] for row in existing]

    # Load fixture templates for this lesson.
    fixtures = session.execute(
        text(
            "SELECT id, fixture_kind, payload, target_table "
            "FROM lab_fixtures WHERE lesson_id = :lid ORDER BY id"
        ),
        {"lid": lesson_id},
    ).fetchall()

    materialised_ids: list[int] = []

    for fix_id, fix_kind, payload_raw, target_table in fixtures:
        _validate_target_table(target_table)

        payload: dict[str, Any] = (
            payload_raw if isinstance(payload_raw, dict) else json.loads(payload_raw)
        )

        row_id = _insert_row(session, target_table=target_table, payload=payload)
        materialised_ids.append(row_id)

        session.execute(
            text(
                "INSERT INTO lab_session_fixtures "
                "(enrollment_id, lesson_id, fixture_id, materialised_row_id, "
                "materialised_table, created_at) "
                "VALUES (:eid, :lid, :fid, :rid, :tbl, :ts)"
            ),
            {
                "eid": enrollment_id,
                "lid": lesson_id,
                "fid": fix_id,
                "rid": row_id,
                "tbl": target_table,
                "ts": datetime.now(timezone.utc).replace(tzinfo=None),
            },
        )
        logger.debug(
            "seed_lab: inserted %s row id=%d (fixture_kind=%s)",
            target_table, row_id, fix_kind,
        )

    logger.info(
        "seed_lab: enrollment=%d lesson=%d materialised=%d rows",
        enrollment_id, lesson_id, len(materialised_ids),
    )
    return materialised_ids


def teardown_lab(
    session: Session, *, enrollment_id: int, lesson_id: int
) -> int:
    """Delete materialised rows and mark session fixtures as torn down.

    Best-effort per row: if a target row was already deleted by hand, logs
    a warning and continues. Returns the count of session-fixture rows
    marked as torn down.
    """
    rows = session.execute(
        text(
            "SELECT id, materialised_row_id, materialised_table "
            "FROM lab_session_fixtures "
            "WHERE enrollment_id = :eid AND lesson_id = :lid AND torn_down_at IS NULL "
            "ORDER BY id"
        ),
        {"eid": enrollment_id, "lid": lesson_id},
    ).fetchall()

    if not rows:
        logger.debug(
            "teardown_lab: no live rows for enrollment=%d lesson=%d",
            enrollment_id, lesson_id,
        )
        return 0

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    torn_down = 0

    for sess_fix_id, mat_row_id, mat_table in rows:
        _validate_target_table(mat_table)
        try:
            result = session.execute(
                text(f"DELETE FROM {mat_table} WHERE id = :rid"),  # noqa: S608
                {"rid": mat_row_id},
            )
            if result.rowcount == 0:
                logger.warning(
                    "teardown_lab: %s row id=%d not found (already deleted?)",
                    mat_table, mat_row_id,
                )
        except Exception as exc:
            logger.warning(
                "teardown_lab: failed to delete %s row id=%d: %s",
                mat_table, mat_row_id, exc,
            )

        session.execute(
            text(
                "UPDATE lab_session_fixtures SET torn_down_at = :ts WHERE id = :id"
            ),
            {"ts": now, "id": sess_fix_id},
        )
        torn_down += 1

    logger.info(
        "teardown_lab: enrollment=%d lesson=%d torn_down=%d rows",
        enrollment_id, lesson_id, torn_down,
    )
    return torn_down


import re as _re
_SAFE_COLUMN_RE = _re.compile(r"^[a-z_][a-z0-9_]*$")


def _insert_row(
    session: Session, *, target_table: str, payload: dict[str, Any]
) -> int:
    """Insert a single row into target_table from payload and return its new PK.

    Uses raw SQL to stay generic across table schemas. Column names from the
    payload dict are used as-is; the caller is responsible for ensuring the
    payload keys match the target table's columns.
    """
    if not payload:
        raise ValueError("payload must not be empty")

    columns = list(payload.keys())
    for col in columns:
        if not _SAFE_COLUMN_RE.match(col):
            raise ValueError(f"Unsafe column name rejected: {col!r}")
    placeholders = [f":{col}" for col in columns]
    col_list = ", ".join(columns)
    ph_list = ", ".join(placeholders)

    dialect = session.bind.dialect.name if session.bind else "sqlite"
    if dialect == "postgresql":
        sql = (
            f"INSERT INTO {target_table} ({col_list}) "  # noqa: S608
            f"VALUES ({ph_list}) RETURNING id"
        )
        row = session.execute(text(sql), payload).fetchone()
        return int(row[0])
    else:
        # SQLite — no RETURNING; use lastrowid.
        sql = (
            f"INSERT INTO {target_table} ({col_list}) "  # noqa: S608
            f"VALUES ({ph_list})"
        )
        result = session.execute(text(sql), payload)
        return int(result.lastrowid)


def get_live_session_fixtures(
    session: Session, *, enrollment_id: int, lesson_id: int
) -> list[dict]:
    """Return metadata for active (not torn-down) materialisations.

    Used by the API to build deep-links back to seeded alerts/cases.
    """
    rows = session.execute(
        text(
            "SELECT sf.materialised_row_id, sf.materialised_table, lf.fixture_kind "
            "FROM lab_session_fixtures sf "
            "JOIN lab_fixtures lf ON lf.id = sf.fixture_id "
            "WHERE sf.enrollment_id = :eid AND sf.lesson_id = :lid "
            "AND sf.torn_down_at IS NULL "
            "ORDER BY sf.id"
        ),
        {"eid": enrollment_id, "lid": lesson_id},
    ).fetchall()
    return [
        {
            "materialised_row_id": r[0],
            "materialised_table": r[1],
            "fixture_kind": r[2],
        }
        for r in rows
    ]


def _observable_link(row_id: int, table: str) -> Optional[str]:
    """Build an ION deep-link for a materialised row, if applicable."""
    _table_to_path: dict[str, str] = {
        "alert_triage": "/alerts",
        "alert_cases": "/cases",
        "observables": "/observables",
    }
    path = _table_to_path.get(table)
    if path is None:
        return None
    return f"{path}/{row_id}"
