"""Daily-work tracking models.

Two tables back the daily-work feature (My Day / Team Day):

- ``WorkTaskType`` — the admin-configurable taxonomy of predefined task types
  an analyst can quick-log (Meeting, Training, IR engagement, …). NOT a
  hardcoded enum so each SOC can add its own. Seeded with sensible defaults
  (see ``DEFAULT_TASK_TYPES``) the first time the table is empty.
- ``WorkLogEntry`` — a single manually-logged activity: who, when, which task
  type, and a free-text note. The "auto" half of the timeline (triage, case
  transitions, playbook runs, …) is DERIVED from existing ION tables at read
  time and is NOT stored here — this table holds only the manual entries.

Schema decision (locked): type + text + timestamp only. No duration / start-stop
time-tracking — "active time" stays a derived estimate, keeping the log fast to
write and un-timesheet-like for analysts.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class WorkTaskType(Base, TimestampMixin):
    """An admin-configurable predefined task type for manual work logging.

    ``key`` is a stable slug used by entries + the quick-add chips; ``category``
    groups types for colour-coding (collab / learning / proactive / response /
    admin); ``color`` + ``glyph`` drive the chip/timeline rendering.
    """

    __tablename__ = "work_task_types"
    __table_args__ = (
        UniqueConstraint("key", name="uq_work_task_type_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(50), nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False, default="admin")
    color: Mapped[str] = mapped_column(String(20), nullable=False, default="muted")
    glyph: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "label": self.label,
            "category": self.category,
            "color": self.color,
            "glyph": self.glyph,
            "sort_order": self.sort_order,
            "is_active": self.is_active,
        }


class WorkLogEntry(Base, TimestampMixin):
    """A single manually-logged daily-work activity (the manual half of the
    hybrid timeline). Auto activity is derived at read time, not stored here."""

    __tablename__ = "work_log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    # logged-at instant; indexed for per-user per-day reads.
    logged_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    # task-type slug (FK-by-key to work_task_types.key; kept as a string so a
    # retired/renamed type doesn't orphan historical entries).
    task_type: Mapped[str] = mapped_column(String(50), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "logged_at": self.logged_at.isoformat() if self.logged_at else None,
            "task_type": self.task_type,
            "text": self.text,
            "source": "logged",
        }


# Default taxonomy seeded when work_task_types is empty. Mirrors the locked
# prototype (concepts/daily-work.html). categories: collab / learning /
# proactive / response / admin. color = an ion-* colour-helper key.
DEFAULT_TASK_TYPES = [
    {"key": "meeting",  "label": "Meeting",       "category": "collab",    "color": "blue",   "glyph": "◷", "sort_order": 10},
    {"key": "training", "label": "Training",      "category": "learning",  "color": "purple", "glyph": "✦", "sort_order": 20},
    {"key": "ir",       "label": "IR engagement", "category": "response",  "color": "red",    "glyph": "⚑", "sort_order": 30},
    {"key": "hunt",     "label": "Threat hunt",   "category": "proactive", "color": "cyan",   "glyph": "⌖", "sort_order": 40},
    {"key": "docs",     "label": "Documentation", "category": "proactive", "color": "blue",   "glyph": "✎", "sort_order": 50},
    {"key": "pairing",  "label": "Pairing",       "category": "collab",    "color": "blue",   "glyph": "⇄", "sort_order": 60},
    {"key": "reading",  "label": "Reading",       "category": "learning",  "color": "purple", "glyph": "▤", "sort_order": 70},
    {"key": "admin",    "label": "Admin / 1:1",   "category": "admin",     "color": "muted",  "glyph": "▤", "sort_order": 80},
    {"key": "note",     "label": "Note",          "category": "admin",     "color": "purple", "glyph": "✎", "sort_order": 90},
    {"key": "break",    "label": "Break",         "category": "admin",     "color": "muted",  "glyph": "☕", "sort_order": 100},
]


def seed_default_task_types(session) -> int:
    """Insert DEFAULT_TASK_TYPES if the table is empty. Idempotent — does
    nothing once any task type exists (so admin edits/deletions stick).
    Returns the number of rows inserted."""
    existing = session.query(WorkTaskType).count()
    if existing:
        return 0
    for spec in DEFAULT_TASK_TYPES:
        session.add(WorkTaskType(**spec))
    session.commit()
    return len(DEFAULT_TASK_TYPES)
