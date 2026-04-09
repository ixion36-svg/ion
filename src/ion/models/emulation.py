"""Adversary Emulation Plan models.

A plan is a sequence of TTPs that the team will execute against the network
in a controlled exercise (purple team / red team drill). Each step is mapped
to one or more MITRE ATT&CK techniques and the TIDE rule(s) we *expect* to
detect that activity. After the operator runs the step, ION can check the
configured Elasticsearch backend for matching alerts and mark the step as
``passed`` (rule fired) or ``failed`` (silent — detection gap).
"""

from datetime import datetime
from enum import Enum
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User


class EmulationPlanStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class StepResult(str, Enum):
    PENDING = "pending"
    PASSED = "passed"   # detection fired
    FAILED = "failed"   # detection silent
    SKIPPED = "skipped"
    PARTIAL = "partial"  # some expected rules fired, others didn't


class EmulationPlan(Base, TimestampMixin):
    """A planned adversary emulation exercise."""

    __tablename__ = "emulation_plans"
    __table_args__ = (
        Index("ix_emul_plan_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actor_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=EmulationPlanStatus.DRAFT.value
    )
    target_systems: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    created_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by_id])
    steps: Mapped[list["EmulationStep"]] = relationship(
        "EmulationStep",
        back_populates="plan",
        cascade="all, delete-orphan",
        order_by="EmulationStep.order_index.asc()",
    )

    def to_dict(self, include_steps: bool = True) -> dict:
        steps = self.steps or []
        passed = sum(1 for s in steps if s.result == StepResult.PASSED.value)
        failed = sum(1 for s in steps if s.result == StepResult.FAILED.value)
        partial = sum(1 for s in steps if s.result == StepResult.PARTIAL.value)
        total = len(steps)
        coverage_pct = (
            round(((passed + partial * 0.5) / total) * 100) if total else 0
        )
        out = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "actor_name": self.actor_name,
            "actor_id": self.actor_id,
            "status": self.status,
            "target_systems": self.target_systems or [],
            "tags": self.tags or [],
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "step_count": total,
            "passed_count": passed,
            "failed_count": failed,
            "partial_count": partial,
            "coverage_pct": coverage_pct,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_steps:
            out["steps"] = [s.to_dict() for s in steps]
        return out


class EmulationStep(Base, TimestampMixin):
    """A single TTP in an emulation plan."""

    __tablename__ = "emulation_steps"
    __table_args__ = (
        Index("ix_emul_step_plan_id", "plan_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emulation_plans.id", ondelete="CASCADE"), nullable=False
    )
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # ATT&CK technique IDs this step exercises
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # Free-form how-to / command line for the operator
    procedure: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Expected TIDE rule_ids (or names) — informational
    expected_rules: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Execution / verification fields
    result: Mapped[str] = mapped_column(
        String(20), nullable=False, default=StepResult.PENDING.value
    )
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    matched_alert_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    matched_rule_names: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    plan: Mapped["EmulationPlan"] = relationship("EmulationPlan", back_populates="steps")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "plan_id": self.plan_id,
            "order_index": self.order_index,
            "title": self.title,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques or [],
            "procedure": self.procedure,
            "expected_rules": self.expected_rules or [],
            "result": self.result,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "matched_alert_count": self.matched_alert_count,
            "matched_rule_names": self.matched_rule_names or [],
            "notes": self.notes,
        }
