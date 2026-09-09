"""Analyst-pinned alert fields.

Per-user field pins that surface in the alert-detail Case-context panel, so an
analyst decides which ECS fields matter for a rule instead of the set being
hardcoded. Scoped per rule with a global fallback.

rule_id is NOT NULL with '' meaning "global" (applies to every rule) — an empty
string, not NULL, so the (user_id, rule_id, field_name) unique constraint
actually rejects duplicate global pins. Postgres treats NULLs as distinct, so a
NULL rule_id would let identical global pins through.
"""

from sqlalchemy import ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class AnalystPinnedField(Base, TimestampMixin):
    """One field an analyst pinned, for a rule (or globally when rule_id='')."""

    __tablename__ = "analyst_pinned_fields"
    __table_args__ = (
        UniqueConstraint("user_id", "rule_id", "field_name", name="uq_analyst_pin"),
        Index("ix_analyst_pin_user_rule", "user_id", "rule_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    field_name: Mapped[str] = mapped_column(String(256), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id or None,
            "field_name": self.field_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
