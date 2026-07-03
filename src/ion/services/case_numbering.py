"""Shared, collision-free case-number allocation.

The old ``case_number = max(AlertCase.id) + 1`` read-then-write (copy-pasted
across the auto-case loop, the RTMON monitor, the case grouper and the manual
create path) races under concurrent workers and diverges after row deletion,
tripping the UNIQUE constraint on ``case_number``. Deriving the number from the
DB-assigned ``id`` after flush is collision-free — ids are unique and never
reused — and keeps ``CASE-NNNN`` aligned with the row id.
"""

from __future__ import annotations

import uuid


def assign_case_number(session, case) -> str:
    """Flush ``case`` to obtain its DB-assigned id, then set a unique
    ``CASE-NNNN`` derived from it. Returns the assigned number.

    A short unique placeholder satisfies the NOT NULL + UNIQUE constraints on
    the intermediate flush; it is overwritten with the id-derived value before
    the caller commits.
    """
    case.case_number = f"PENDING-{uuid.uuid4().hex[:16]}"
    session.add(case)
    session.flush()  # DB assigns case.id
    case.case_number = f"CASE-{case.id:04d}"
    return case.case_number
