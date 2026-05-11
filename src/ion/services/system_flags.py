"""Runtime flag storage (v0.23.1).

A small key/value bag for runtime toggles that must be visible across
all workers — most importantly, the leader worker that owns the
investigation sweep loop AND the request-handling worker that toggles a
pause flag from the UI. In-process state on a singleton would not
satisfy the multi-worker uvicorn deployment because the request-handler
worker may not be the loop-owning worker.

Keys used in v0.23.1:

* ``investigation_loop_paused`` — when ``"true"``, the sweep loop's
  iteration body returns immediately without fetching alerts. Default
  (missing row) = not paused.

The table is keyed by string; values are stringly-typed. Read paths
are tolerant of NULL/missing rows. Write paths upsert.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ── Known keys ───────────────────────────────────────────────────────────


INVESTIGATION_LOOP_PAUSED = "investigation_loop_paused"


# ── Read ─────────────────────────────────────────────────────────────────


def get_flag(session: Session, key: str) -> Optional[str]:
    """Return the current string value of a flag, or None if unset."""
    row = session.execute(
        text("SELECT value FROM system_runtime_flags WHERE key = :k"),
        {"k": key},
    ).fetchone()
    return row[0] if row else None


def is_truthy(value: Optional[str]) -> bool:
    """Treat ``"true"`` / ``"1"`` / ``"yes"`` / ``"on"`` as truthy."""
    if value is None:
        return False
    return value.strip().lower() in ("true", "1", "yes", "on")


def is_flag_true(session: Session, key: str) -> bool:
    """Convenience: read + truthy-test in one call."""
    return is_truthy(get_flag(session, key))


def get_flag_metadata(session: Session, key: str) -> dict:
    """Return ``{value, updated_at, updated_by_id}`` for a key, or empty dict.

    ``updated_at`` comes back as a string (SQLite) or datetime (Postgres);
    we normalise to an ISO-format string either way so the API response
    shape is dialect-independent.
    """
    row = session.execute(
        text(
            "SELECT value, updated_at, updated_by_id "
            "FROM system_runtime_flags WHERE key = :k"
        ),
        {"k": key},
    ).fetchone()
    if row is None:
        return {}
    updated_at = row[1]
    if updated_at is not None and hasattr(updated_at, "isoformat"):
        updated_at = updated_at.isoformat()
    return {
        "value": row[0],
        "updated_at": updated_at,
        "updated_by_id": row[2],
    }


# ── Write ────────────────────────────────────────────────────────────────


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def set_flag(
    session: Session,
    key: str,
    value: str,
    *,
    user_id: Optional[int] = None,
) -> None:
    """Upsert a flag value. Caller is responsible for commit."""
    existing = session.execute(
        text("SELECT 1 FROM system_runtime_flags WHERE key = :k"),
        {"k": key},
    ).fetchone()
    if existing is None:
        session.execute(
            text(
                "INSERT INTO system_runtime_flags "
                "(key, value, updated_at, updated_by_id) "
                "VALUES (:k, :v, :ts, :uid)"
            ),
            {"k": key, "v": value, "ts": _utcnow_naive(), "uid": user_id},
        )
    else:
        session.execute(
            text(
                "UPDATE system_runtime_flags SET "
                "value = :v, updated_at = :ts, updated_by_id = :uid "
                "WHERE key = :k"
            ),
            {"k": key, "v": value, "ts": _utcnow_naive(), "uid": user_id},
        )


def clear_flag(session: Session, key: str) -> None:
    """Delete a flag row. Caller is responsible for commit."""
    session.execute(
        text("DELETE FROM system_runtime_flags WHERE key = :k"),
        {"k": key},
    )
