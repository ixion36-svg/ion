"""Lab session lifecycle service (v0.23.0).

Promotes the implicit-via-torn_down_at lab state machine into a first-class
``lab_sessions`` parent row. One row per (enrollment, lesson, attempt) with
``started_at`` / ``completed_at`` / ``score`` columns; child
``lab_session_fixtures`` rows now carry a nullable ``session_id`` FK so
materialised data can be back-correlated to a session for grading.

Concurrency model
-----------------
``start_or_resume`` holds ``pg_advisory_xact_lock(LAB_SESSIONS_NS,
enrollment_id)`` for the duration of the call. This serialises double-click
launches on the same (enrollment, lesson) and prevents creating two
in-progress sessions concurrently. On SQLite the lock is a no-op.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# 'LABS' as a 4-byte int32 — disjoint from LAB_FIXTURES_NS ('LABF').
LAB_SESSIONS_NS = 0x4C414253


def _advisory_lock(session: Session, enrollment_id: int) -> None:
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :eid)"),
        {"ns": LAB_SESSIONS_NS, "eid": int(enrollment_id)},
    )


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def start_or_resume(
    session: Session,
    *,
    enrollment_id: int,
    lesson_id: int,
) -> int:
    """Return the id of the active (not completed) lab session.

    Idempotent: if a session for (enrollment, lesson) exists with
    ``completed_at IS NULL``, returns its id. Otherwise inserts a new row
    with ``attempt_number = max + 1`` and returns the new id.
    """
    _advisory_lock(session, enrollment_id)

    row = session.execute(
        text(
            "SELECT id FROM lab_sessions "
            "WHERE enrollment_id = :eid AND lesson_id = :lid "
            "AND completed_at IS NULL "
            "ORDER BY attempt_number DESC LIMIT 1"
        ),
        {"eid": enrollment_id, "lid": lesson_id},
    ).fetchone()
    if row is not None:
        return int(row[0])

    last_attempt = session.execute(
        text(
            "SELECT MAX(attempt_number) FROM lab_sessions "
            "WHERE enrollment_id = :eid AND lesson_id = :lid"
        ),
        {"eid": enrollment_id, "lid": lesson_id},
    ).scalar()
    next_attempt = (last_attempt or 0) + 1

    dialect = session.bind.dialect.name if session.bind else "sqlite"
    if dialect == "postgresql":
        new_id = session.execute(
            text(
                "INSERT INTO lab_sessions (enrollment_id, lesson_id, attempt_number) "
                "VALUES (:eid, :lid, :n) RETURNING id"
            ),
            {"eid": enrollment_id, "lid": lesson_id, "n": next_attempt},
        ).scalar()
        return int(new_id)
    else:
        result = session.execute(
            text(
                "INSERT INTO lab_sessions (enrollment_id, lesson_id, attempt_number) "
                "VALUES (:eid, :lid, :n)"
            ),
            {"eid": enrollment_id, "lid": lesson_id, "n": next_attempt},
        )
        return int(result.lastrowid)


def link_fixtures(session: Session, *, session_id: int, materialised_ids: list[int]) -> None:
    """Attach the most recent lab_session_fixtures rows to a session.

    ``seed_lab`` returns the materialised row ids in insertion order; this
    helper looks them up by (enrollment, lesson) without session_id and
    populates the FK. Idempotent — rows with session_id already set are
    left alone.
    """
    if not materialised_ids:
        return
    placeholders = ", ".join(f":id_{i}" for i in range(len(materialised_ids)))
    params = {"sid": session_id}
    for i, mid in enumerate(materialised_ids):
        params[f"id_{i}"] = mid
    session.execute(
        text(
            f"UPDATE lab_session_fixtures SET session_id = :sid "
            f"WHERE materialised_row_id IN ({placeholders}) "
            f"AND session_id IS NULL AND torn_down_at IS NULL"
        ),
        params,
    )


def complete(
    session: Session,
    *,
    session_id: int,
    score: Optional[int] = None,
    points_earned: int = 0,
    points_max: int = 0,
) -> None:
    """Finalize a session — set completed_at + score columns.

    Caller is responsible for ensuring the session belongs to the requesting
    user's enrollment (the labs_api layer enforces that before calling).
    """
    session.execute(
        text(
            "UPDATE lab_sessions "
            "SET completed_at = :ts, score = :score, "
            "    points_earned = :pe, points_max = :pm "
            "WHERE id = :sid AND completed_at IS NULL"
        ),
        {
            "ts": _utcnow_naive(),
            "score": score,
            "pe": points_earned,
            "pm": points_max,
            "sid": session_id,
        },
    )


def current_for(
    session: Session,
    *,
    enrollment_id: int,
    lesson_id: int,
) -> Optional[int]:
    """Return the id of the active (not completed) session, or None."""
    row = session.execute(
        text(
            "SELECT id FROM lab_sessions "
            "WHERE enrollment_id = :eid AND lesson_id = :lid "
            "AND completed_at IS NULL "
            "ORDER BY attempt_number DESC LIMIT 1"
        ),
        {"eid": enrollment_id, "lid": lesson_id},
    ).fetchone()
    return int(row[0]) if row else None
