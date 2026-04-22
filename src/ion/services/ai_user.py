"""Helpers to locate the Bob (AI analyst) service-user id.

Every AI-authored artefact (notes, observables, ticker entries, tuning
proposals) is attributed to Bob so audit logs, "created by" filters, and
analyst-efficiency dashboards cleanly separate human vs AI authorship.

The id is cached in-process after first lookup — Bob is seeded once at
startup and doesn't change.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ion.models.user import User

logger = logging.getLogger(__name__)

_BOB_ID_CACHE: Optional[int] = None
BOB_USERNAME = "bob"


def get_bob_user_id(session: Session) -> Optional[int]:
    """Return Bob's user id, cached.

    Returns None if Bob hasn't been seeded yet (e.g. first boot before the
    auth seed hook ran). Callers should treat None as "attribute anonymously"
    and keep going — do not raise.
    """
    global _BOB_ID_CACHE
    if _BOB_ID_CACHE is not None:
        return _BOB_ID_CACHE
    user = session.query(User).filter(User.username == BOB_USERNAME).first()
    if user is None:
        return None
    _BOB_ID_CACHE = user.id
    return user.id


def reset_bob_cache() -> None:
    """Clear the in-process cache — test helper."""
    global _BOB_ID_CACHE
    _BOB_ID_CACHE = None
