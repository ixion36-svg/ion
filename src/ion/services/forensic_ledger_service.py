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
from sqlalchemy.orm import Session

from ion.models.forensic_workbench import ForensicCaseLedger

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64


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
    """Reproducible hash — used by both append and verify."""
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
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")

    _per_case_lock(session, forensic_case_id)

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
    session.add(row)
    session.flush()  # surface UNIQUE(forensic_case_id, seq) violations now
    return row


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
