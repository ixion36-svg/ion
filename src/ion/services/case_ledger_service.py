"""Tamper-evident ledger for case Workbench actions (v0.20.0).

Every workbench mutation (pin, status_change, summary_edit, dismiss, ...)
emits a row via :func:`append`. The row's ``content_hash`` is computed as
``sha256(prev_hash || "|" || action || "|" || canonical_json(payload))``,
where canonical_json sorts keys and uses compact separators so the hash is
reproducible by any verifier without ambiguity.

The chain genesis uses ``prev_hash = "0" * 64`` for ``seq = 1`` of each case.
Validation walks rows in seq order, recomputes each hash, and reports the
first seq where the chain breaks (or that ``is_valid: True`` if intact).

Concurrency: per-case ``pg_advisory_xact_lock`` so two parallel appends
can't compute prev_hash off the same row. SQLite serialises writers via its
global write lock, so the lock call is a no-op there.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

from sqlalchemy import desc, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ion.models.case_evidence import CaseEvidenceLedger

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64

# How many times append() re-reads-and-retries on a UNIQUE(seq) collision.
# Only reachable on SQLite (no per-case advisory lock); Postgres serialises.
_MAX_APPEND_ATTEMPTS = 3


def _assert_roundtrip_stable(payload: dict[str, Any]) -> None:
    """Reject payload values whose JSON round-trip is not byte-stable.

    ``verify_chain`` recomputes the hash from the payload after it round-trips
    through the DB JSON column. ``float`` values are the hazard: a jsonb column
    may normalise ``1.0`` -> ``1``, so the recomputed canonical bytes would
    differ and verify_chain would report a *false* content_hash mismatch.
    Ledger payloads must therefore be composed only of str / int / bool / None /
    list / dict. (bool is an int subclass and is fine.)
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
    """Deterministic JSON encoding for hashing.

    sort_keys=True so dict ordering is irrelevant, separators stripped to
    eliminate whitespace ambiguity, ensure_ascii=False so unicode strings
    hash identically regardless of platform default. allow_nan=False rejects
    NaN/Infinity (which JSON technically forbids) so we don't store rows
    that can never round-trip.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_content_hash(prev_hash: str, action: str, payload: dict[str, Any]) -> str:
    """Reproducible hash function — used by both append and verify.

    The pre-image is ``prev_hash | action | canonical_json(payload)`` with a raw
    ``|`` delimiter. This is unambiguous ONLY because (a) ``prev_hash`` is a
    fixed-width 64-char hex digest containing no ``|`` (so the first delimiter is
    pinned), and (b) ``append`` rejects any ``action`` containing ``|`` (so the
    second delimiter is pinned). With both boundaries fixed, two distinct
    (action, payload) pairs cannot collide regardless of payload content.
    Do not relax either invariant without length-prefixing the pre-image.
    """
    canonical = canonical_payload(payload)
    blob = f"{prev_hash}|{action}|{canonical}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _per_case_lock(session: Session, alert_case_id: int) -> None:
    """Acquire a per-case advisory lock for the duration of the current
    transaction. No-op on non-postgres backends (SQLite serialises writers
    anyway). Released automatically at COMMIT/ROLLBACK.

    The lock key is derived from a stable namespace + the case_id so two
    appends on the SAME case serialise, but appends across DIFFERENT cases
    proceed in parallel.
    """
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    # Two-int variant of pg_advisory_xact_lock: (namespace, case_id). The
    # namespace constant ('CEVL' = case_evidence_ledger as 4 ASCII bytes
    # interpreted as int32) is unique to this subsystem.
    NAMESPACE = 0x4345564C  # 'CEVL'
    session.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :cid)"),
        {"ns": NAMESPACE, "cid": int(alert_case_id)},
    )


def append(
    session: Session,
    *,
    alert_case_id: int,
    action: str,
    payload: dict[str, Any],
    actor_id: Optional[int],
) -> CaseEvidenceLedger:
    """Append a single ledger row for the given case.

    Caller is responsible for the surrounding transaction. The session must
    already be in a transaction (typically the FastAPI request scope). On
    return the row is staged; the FastAPI commit hook flushes it.

    Raises ValueError if action is empty or payload is not a dict.
    """
    if not action or not isinstance(action, str):
        raise ValueError("action must be a non-empty string")
    if "|" in action:
        # The hash pre-image uses '|' as a delimiter; an action containing it
        # would make the action/payload boundary ambiguous (collision vector).
        raise ValueError("action must not contain the '|' delimiter")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    _assert_roundtrip_stable(payload)

    _per_case_lock(session, alert_case_id)

    # Read latest seq, compute the hash, and insert under a SAVEPOINT. On
    # SQLite the per-case lock is a no-op, so two writers can read the same
    # `last` row and collide on UNIQUE(alert_case_id, seq); the savepoint rolls
    # back just the failed row (not the caller's outer transaction) and we
    # re-read + retry. On Postgres the advisory lock makes the race impossible,
    # so this loop runs exactly once.
    for attempt in range(_MAX_APPEND_ATTEMPTS):
        last = session.execute(
            select(CaseEvidenceLedger)
            .where(CaseEvidenceLedger.alert_case_id == alert_case_id)
            .order_by(desc(CaseEvidenceLedger.seq))
            .limit(1)
        ).scalar_one_or_none()

        if last is None:
            seq = 1
            prev_hash = GENESIS_PREV_HASH
        else:
            seq = last.seq + 1
            prev_hash = last.content_hash

        content_hash = compute_content_hash(prev_hash, action, payload)
        row = CaseEvidenceLedger(
            alert_case_id=alert_case_id,
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
                session.flush()  # surface UNIQUE(alert_case_id, seq) now
            return row
        except IntegrityError:
            if attempt + 1 >= _MAX_APPEND_ATTEMPTS:
                raise
            # Savepoint rolled the failed row back; loop re-reads the new seq.
            continue

    # Unreachable: the loop either returns or re-raises on the final attempt.
    raise RuntimeError("ledger append exhausted retries")  # pragma: no cover


def verify_chain(session: Session, alert_case_id: int) -> dict[str, Any]:
    """Walk the case's ledger from seq=1 forward, recomputing each hash.

    Returns:
        {
          "is_valid": bool,
          "seq_count": int,
          "first_break_seq": int | None,
          "error": str | None,
        }

    A "break" can be: a missing seq (gap or duplicate), a prev_hash that
    doesn't match the previous row's content_hash, or a content_hash that
    doesn't match a freshly recomputed value. ``first_break_seq`` is the
    seq number of the row at which the chain first failed validation.
    """
    rows = session.execute(
        select(CaseEvidenceLedger)
        .where(CaseEvidenceLedger.alert_case_id == alert_case_id)
        .order_by(CaseEvidenceLedger.seq)
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
    session: Session, alert_case_id: int, *, limit: int = 500
) -> list[dict[str, Any]]:
    """Return ledger rows for a case, oldest-first, hydrated as dicts."""
    rows = session.execute(
        select(CaseEvidenceLedger)
        .where(CaseEvidenceLedger.alert_case_id == alert_case_id)
        .order_by(CaseEvidenceLedger.seq)
        .limit(limit)
    ).scalars().all()
    return [r.to_dict() for r in rows]
