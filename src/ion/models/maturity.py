"""SOC Maturity Assessment model.

Stores completed assessments with per-domain scores and individual
question responses. Each assessment is a point-in-time snapshot so
the SOC can track maturity progression over time.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from ion.models.base import Base


class MaturityAssessment(Base):
    """A completed SOC maturity assessment."""

    __tablename__ = "maturity_assessments"
    __table_args__ = (
        Index("ix_maturity_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    # Per-domain scores (1-5)
    scores: Mapped[dict] = mapped_column(JSON, nullable=False)
    # Individual question responses {domain: {question_id: {score, notes}}}
    responses: Mapped[dict] = mapped_column(JSON, nullable=False)
    overall_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_level: Mapped[str] = mapped_column(String(30), nullable=False, default="Initial")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    created_by = relationship("User", foreign_keys=[created_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "scores": self.scores,
            "responses": self.responses,
            "overall_score": self.overall_score,
            "overall_level": self.overall_level,
            "notes": self.notes,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
