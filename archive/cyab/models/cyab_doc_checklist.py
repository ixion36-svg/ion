"""CyAB Documentation Checklist (v0.18.0).

One row per ``(system_id, kind)`` tracking the status of a documentation
artifact for a CyAB system — HLD, LLD, network topology, runbook, etc.
The default catalogue lives in
``ion.services.cyab_doc_checklist_service._DEFAULT_CHECKLIST`` and is
lazy-seeded the first time a system's checklist is fetched (so existing
systems get a checklist without a backfill migration). Operators can add
``is_custom=True`` rows beyond the default catalogue per system, and
delete those custom rows; default rows can have status / URL / notes
edited but the row itself stays.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base

# Status string constants used both in the model and the service. Stored
# as plain strings (not an enum) so operators can extend without a
# schema migration if a future workflow needs e.g. "deprecated".
STATUS_DONE        = "done"
STATUS_IN_PROGRESS = "in_progress"
STATUS_MISSING     = "missing"
STATUS_NA          = "na"
STATUS_UNKNOWN     = "unknown"
ALL_STATUSES = (STATUS_DONE, STATUS_IN_PROGRESS, STATUS_MISSING, STATUS_NA, STATUS_UNKNOWN)

# Category bucket for grouping in the UI. Same string-not-enum reasoning.
CATEGORY_DESIGN      = "design"
CATEGORY_OPERATIONAL = "operational"
CATEGORY_SECURITY    = "security"
CATEGORY_COMPLIANCE  = "compliance"
ALL_CATEGORIES = (CATEGORY_DESIGN, CATEGORY_OPERATIONAL, CATEGORY_SECURITY, CATEGORY_COMPLIANCE)


class CyabDocChecklistItem(Base):
    """One documentation artifact tracked for one CyAB system."""

    __tablename__ = "cyab_doc_checklist"
    __table_args__ = (
        Index("ix_cyab_doc_checklist_system", "system_id"),
        Index("ix_cyab_doc_checklist_kind", "kind"),
        UniqueConstraint("system_id", "kind", name="uq_cyab_doc_system_kind"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    system_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("cyab_systems.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Canonical key (e.g. "HLD", "NETWORK_TOPOLOGY") + human label.
    # Kind is stable across rows of the same default; label can be
    # edited or different for custom rows.
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default=CATEGORY_DESIGN)

    # Critical = surfaced as a soft gate on the Onboarding Pack export.
    # Custom = operator-added, free to delete (default rows stay).
    is_critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_custom: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Status string — see ALL_STATUSES.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=STATUS_UNKNOWN)
    url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    updated_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now(),
    )

    updated_by = relationship("User", foreign_keys=[updated_by_id])

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "system_id":     self.system_id,
            "kind":          self.kind,
            "label":         self.label,
            "category":      self.category,
            "is_critical":   self.is_critical,
            "is_custom":     self.is_custom,
            "status":        self.status,
            "url":           self.url,
            "notes":         self.notes,
            "updated_at":    self.updated_at.isoformat() if self.updated_at else None,
            "updated_by":    (
                (self.updated_by.display_name or self.updated_by.username)
                if self.updated_by else None
            ),
        }

    def __repr__(self) -> str:
        return f"<CyabDocChecklistItem(system={self.system_id}, kind='{self.kind}', status='{self.status}')>"
