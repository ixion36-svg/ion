"""Observable allowlist: values that never become observables.

ION's three per-observable switches (``is_whitelisted``, ``is_ignored``,
``ignore_similarity``) are all reactive -- the observable has to exist and
be wrong before anyone can mark it. On an estate where a rule fires
hundreds of times a day that means marking the same value over and over,
and the record of *why* lives nowhere.

Every column here exists because of a way allowlists go wrong. An allowlist
stops you seeing something, so the thing to design against is it doing that
quietly:

``reason``        Mandatory. An entry nobody can review is permanent.
``hit_count``     An entry matching nothing is stale and safe to delete; one
                  matching thousands is too broad and is hiding sightings.
                  Without a count both look identical -- silent.
``expires_at``    Optional, and honoured. "Temporary while we investigate"
                  is the most common reason given and the least likely to
                  be revisited.
``created_by``    Someone to ask.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class ObservableAllowlist(Base, TimestampMixin):
    """One pattern that suppresses automatic observable extraction."""

    __tablename__ = "observable_allowlist"
    __table_args__ = (
        # The same pattern twice for the same scope is a duplicate, and two
        # rows with different reasons is worse than one: whoever reviews it
        # cannot tell which reason is the live one.
        UniqueConstraint(
            "match_type", "pattern", "observable_type",
            name="uq_observable_allowlist_entry",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    #: exact | cidr | domain_suffix | wildcard. See services/observable_allowlist.
    match_type: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Stored canonicalised: 10.0.0.5/8 is kept as 10.0.0.0/8, because the
    #: typed form reads as one host when it covers sixteen million.
    pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    #: The observable family this applies to (ip, domain, user, ...), or
    #: NULL for any. Scoping matters: allowlisting the hostname "backup"
    #: should not allowlist a user called "backup".
    observable_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    #: Why. Required at the API, and the column is NOT NULL so a row cannot
    #: reach the table without one.
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default="1"
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    #: How much this entry is actually doing. Zero after a long time means
    #: it can go; a very large number means it is probably too broad.
    hit_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    #: The last value it suppressed, so a reviewer can see what it is
    #: catching without having to reconstruct it from logs.
    last_hit_value: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "match_type": self.match_type,
            "pattern": self.pattern,
            "observable_type": self.observable_type,
            "reason": self.reason,
            "created_by": self.created_by,
            "created_by_id": self.created_by_id,
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "hit_count": self.hit_count,
            "last_hit_at": self.last_hit_at.isoformat() if self.last_hit_at else None,
            "last_hit_value": self.last_hit_value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
