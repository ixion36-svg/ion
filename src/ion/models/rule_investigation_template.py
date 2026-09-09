"""Bob-generated custom investigation template, per detection rule.

The rule's own investigation guide (the Kibana rule `note`) is authored once and
shown verbatim on every alert it fires — so it often doesn't fit the actual
alert. When Bob is asked, it generates a custom, evidence-grounded checklist for
the rule and stores it here alongside the predefined one. Human-reviewed:
pending_review -> approved / rejected before it becomes the default guide.

One row per rule (rule_id unique); regeneration updates the row.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin

STATUS_PENDING = "pending_review"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_SUPERSEDED = "superseded"


class RuleInvestigationTemplate(Base, TimestampMixin):
    """A Bob-generated investigation checklist for one detection rule."""

    __tablename__ = "rule_investigation_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    rule_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    checklist_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=STATUS_PENDING)
    # hash(rule description + evidence signature) — lets a caller decide whether a
    # regeneration is warranted rather than blindly re-running the model.
    source_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    generated_from: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: evidence ids
    model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    reviewed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "checklist_text": self.checklist_text,
            "status": self.status,
            "source_hash": self.source_hash,
            "model": self.model,
            "reviewed_by_id": self.reviewed_by_id,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
