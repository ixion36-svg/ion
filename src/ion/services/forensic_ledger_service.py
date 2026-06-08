"""Tamper-evident ledger for ForensicCase Workbench actions (v0.20.1).

Mirrors ``case_ledger_service`` exactly, but operates on
``forensic_case_ledger`` / ``ForensicCaseLedger`` instead of
``case_evidence_ledger`` / ``CaseEvidenceLedger``.

The advisory-lock namespace constant is ``FCWL`` (Forensic Case Workbench
Ledger) — distinct from the AlertCase ``CEVL`` namespace so two parallel
appends on the same forensic_case_id don't accidentally serialise against
AlertCase appends.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

from sqlalchemy import desc, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ion.models.forensic_workbench import ForensicCaseLedger

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64

# How many times append() re-reads-and-retries on a UNIQUE(seq) collision.
# Only reachable on SQLite (no per-case advisory lock); Postgres serialises.
_MAX_APPEND_ATTEMPTS = 3


def _assert_roundtrip_stable(payload: dict[str, Any]) -> None:
    """Reject payload values whose JSON round-trip is not byte-stable.

    ``verify_chain`` recomputes the hash from the payload after it round-trips
    through the DB JSON column. ``float`` values are the hazard (jsonb may
    normalise ``1.0`` -> ``1``), which would make verify_chain report a *false*
    content_hash mismatch. Ledger payloads must be composed only of
    str / int / bool / None / list / dict.
    """
    def _check(value: Any) -> None:
        if isinstance(value, float):
            raise ValueError(
                "ledger payload must not contain float values "
                "(not JSON-round-trip-stable)"
            )
        if isinstance(value, dict):
            for v in value.values():
                _check(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _check(v)

    _check(payload)


def canonical_payload(payload: dict[str, Any]) -> str:
    """Deterministic JSON encoding — identical algorithm to case_ledger_service."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_content_hash(prev_hash: str, action: str, payload: dict[str, Any]) -> str:
    """Reproducible hash — used by both append and verify.

    The pre-image is ``prev_hash | action | canonical_json(payload)``. It is
    unambiguous only because ``prev_hash`` is fixed-width 64-hex (no ``|``) and
    ``append`` rejects any ``action`` containing ``|`` — pinning both
    delimiters. Do not relax either invariant without length-prefixing.
    """
    canonical = canonical_payload(payload)
    blob = f"{prev_hash}|{action}|{canonical}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _per_case_lock(session: Session, forensic_case_id: int) -> None:
    """Acquire per-ForensicCase advisory lock for the current transaction.

    Namespace ``FCWL`` (0x4643574C) is unique to this subsystem.
    No-op on non-postgres backends.
    """
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    NAMESPACE = 0x4643574C  # 'FCWL'
    session.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :cid)"),
        {"ns": NAMESPACE, "cid": int(forensic_case_id)},
    )


def append(
    session: Session,
    *,
    forensic_case_id: int,
    action: str,
    payload: dict[str, Any],
    actor_id: Optional[int],
) -> ForensicCaseLedger:
    """Append a single ledger row for the given forensic case.

    Caller is responsible for the surrounding transaction.
    Raises ValueError if action is empty or payload is not a dict.
    """
    if not action or not isinstance(action, str):
        raise ValueError("action must be a non-empty string")
    if "|" in action:
        # '|' is the hash pre-image delimiter; an action containing it would
        # make the action/payload boundary ambiguous (collision vector).
        raise ValueError("action must not contain the '|' delimiter")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    _assert_roundtrip_stable(payload)

    _per_case_lock(session, forensic_case_id)

    # Insert under a SAVEPOINT so a UNIQUE(forensic_case_id, seq) collision —
    # only reachable on SQLite, where the per-case lock is a no-op — rolls back
    # just this row (not the caller's outer transaction) and we re-read + retry.
    # On Postgres the advisory lock makes the race impossible (loop runs once).
    for attempt in range(_MAX_APPEND_ATTEMPTS):
        last = session.execute(
            select(ForensicCaseLedger)
            .where(ForensicCaseLedger.forensic_case_id == forensic_case_id)
            .order_by(desc(ForensicCaseLedger.seq))
            .limit(1)
        ).scalar_one_or_none()

        if last is None:
            seq = 1
            prev_hash = GENESIS_PREV_HASH
        else:
            seq = last.seq + 1
            prev_hash = last.content_hash

        content_hash = compute_content_hash(prev_hash, action, payload)
        row = ForensicCaseLedger(
            forensic_case_id=forensic_case_id,
            seq=seq,
            action=action,
            actor_id=actor_id,
            payload=payload,
            prev_hash=prev_hash,
            content_hash=content_hash,
        )
        try:
            with session.begin_nested():
                session.add(row)
                session.flush()  # surface UNIQUE(forensic_case_id, seq) now
            return row
        except IntegrityError:
            if attempt + 1 >= _MAX_APPEND_ATTEMPTS:
                raise
            continue

    raise RuntimeError("ledger append exhausted retries")  # pragma: no cover


def verify_chain(session: Session, forensic_case_id: int) -> dict[str, Any]:
    """Walk the forensic case ledger from seq=1 forward, recomputing each hash.

    Returns:
        {
          "is_valid": bool,
          "seq_count": int,
          "first_break_seq": int | None,
          "error": str | None,
        }
    """
    rows = session.execute(
        select(ForensicCaseLedger)
        .where(ForensicCaseLedger.forensic_case_id == forensic_case_id)
        .order_by(ForensicCaseLedger.seq)
    ).scalars().all()

    if not rows:
        return {
            "is_valid": True,
            "seq_count": 0,
            "first_break_seq": None,
            "error": None,
        }

    expected_prev = GENESIS_PREV_HASH
    expected_seq = 1
    for row in rows:
        if row.seq != expected_seq:
            return {
                "is_valid": False,
                "seq_count": len(rows),
                "first_break_seq": row.seq,
                "error": f"seq gap: expected {expected_seq}, got {row.seq}",
            }
        if row.prev_hash != expected_prev:
            return {
                "is_valid": False,
                "seq_count": len(rows),
                "first_break_seq": row.seq,
                "error": f"prev_hash mismatch at seq {row.seq}",
            }
        recomputed = compute_content_hash(row.prev_hash, row.action, row.payload)
        if recomputed != row.content_hash:
            return {
                "is_valid": False,
                "seq_count": len(rows),
                "first_break_seq": row.seq,
                "error": f"content_hash mismatch at seq {row.seq}",
            }
        expected_prev = row.content_hash
        expected_seq += 1

    return {
        "is_valid": True,
        "seq_count": len(rows),
        "first_break_seq": None,
        "error": None,
    }


def list_entries(
    session: Session, forensic_case_id: int, *, limit: int = 500
) -> list[dict[str, Any]]:
    """Return ledger rows for a forensic case, oldest-first, as dicts."""
    rows = session.execute(
        select(ForensicCaseLedger)
        .where(ForensicCaseLedger.forensic_case_id == forensic_case_id)
        .order_by(ForensicCaseLedger.seq)
        .limit(limit)
    ).scalars().all()
    return [r.to_dict() for r in rows]
