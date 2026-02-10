"""Playbook models for investigation workflows."""

from datetime import datetime
from enum import Enum
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    Index,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from ixion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ixion.models.user import User


class StepType(str, Enum):
    """Types of playbook steps."""

    MANUAL_CHECKLIST = "manual_checklist"
    AUTO_ENRICH_OBSERVABLES = "auto_enrich_observables"
    AUTO_UPDATE_STATUS = "auto_update_status"
    AUTO_CREATE_CASE = "auto_create_case"


class ExecutionStatus(str, Enum):
    """Status of playbook execution."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Playbook(Base, TimestampMixin):
    """Playbook model for investigation workflows."""

    __tablename__ = "playbooks"
    __table_args__ = (
        Index("ix_playbooks_active", "is_active"),
        Index("ix_playbooks_priority", "priority"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    trigger_conditions: Mapped[dict] = mapped_column(JSON, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )

    # Relationships
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])
    steps: Mapped[List["PlaybookStep"]] = relationship(
        "PlaybookStep",
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="PlaybookStep.step_order",
    )
    executions: Mapped[List["PlaybookExecution"]] = relationship(
        "PlaybookExecution",
        back_populates="playbook",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Playbook(id={self.id}, name='{self.name}')>"

    def to_dict(self, include_steps: bool = True) -> dict:
        """Convert to dictionary for API responses."""
        result = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "trigger_conditions": self.trigger_conditions,
            "priority": self.priority,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "step_count": len(self.steps) if self.steps else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_steps:
            result["steps"] = [step.to_dict() for step in self.steps]
        return result

    def matches_alert(
        self,
        rule_name: Optional[str] = None,
        severity: Optional[str] = None,
        mitre_techniques: Optional[List[str]] = None,
        mitre_tactics: Optional[List[str]] = None,
    ) -> bool:
        """Check if this playbook matches the given alert characteristics."""
        if not self.is_active:
            return False

        conditions = self.trigger_conditions or {}

        # Check rule patterns (any pattern must match)
        rule_patterns = conditions.get("rule_patterns", [])
        if rule_patterns and rule_name:
            import re

            pattern_matched = False
            for pattern in rule_patterns:
                try:
                    if re.search(pattern, rule_name, re.IGNORECASE):
                        pattern_matched = True
                        break
                except re.error:
                    # Invalid regex, treat as literal match
                    if pattern.lower() in rule_name.lower():
                        pattern_matched = True
                        break
            if rule_patterns and not pattern_matched:
                return False

        # Check severities (any must match)
        severities = conditions.get("severities", [])
        if severities and severity:
            if severity.lower() not in [s.lower() for s in severities]:
                return False

        # Check MITRE techniques (any must match)
        techniques = conditions.get("mitre_techniques", [])
        if techniques and mitre_techniques:
            if not any(t in techniques for t in mitre_techniques):
                return False

        # Check MITRE tactics (any must match)
        tactics = conditions.get("mitre_tactics", [])
        if tactics and mitre_tactics:
            if not any(t in tactics for t in mitre_tactics):
                return False

        return True


class PlaybookStep(Base):
    """PlaybookStep model for individual steps in a playbook."""

    __tablename__ = "playbook_steps"
    __table_args__ = (Index("ix_playbook_steps_playbook", "playbook_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("playbooks.id"), nullable=False
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    step_type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    step_params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    playbook: Mapped["Playbook"] = relationship("Playbook", back_populates="steps")

    def __repr__(self) -> str:
        return f"<PlaybookStep(id={self.id}, playbook_id={self.playbook_id}, order={self.step_order})>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "step_order": self.step_order,
            "step_type": self.step_type,
            "title": self.title,
            "description": self.description,
            "step_params": self.step_params,
            "is_required": self.is_required,
        }


class PlaybookExecution(Base, TimestampMixin):
    """PlaybookExecution model for tracking playbook runs against alerts."""

    __tablename__ = "playbook_executions"
    __table_args__ = (
        Index("ix_playbook_executions_alert", "es_alert_id"),
        Index("ix_playbook_executions_playbook", "playbook_id"),
        Index("ix_playbook_executions_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("playbooks.id"), nullable=False
    )
    es_alert_id: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=ExecutionStatus.PENDING.value
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    step_statuses: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    executed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Relationships
    playbook: Mapped["Playbook"] = relationship("Playbook", back_populates="executions")
    executed_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[executed_by_id]
    )

    def __repr__(self) -> str:
        return f"<PlaybookExecution(id={self.id}, playbook_id={self.playbook_id}, alert='{self.es_alert_id}')>"

    def to_dict(self, include_playbook: bool = False) -> dict:
        """Convert to dictionary for API responses."""
        result = {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "es_alert_id": self.es_alert_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "step_statuses": self.step_statuses or {},
            "executed_by_id": self.executed_by_id,
            "executed_by_username": (
                self.executed_by.username if self.executed_by else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_playbook and self.playbook:
            result["playbook"] = self.playbook.to_dict(include_steps=True)
        return result

    def get_step_status(self, step_id: int) -> Optional[dict]:
        """Get the status of a specific step."""
        if not self.step_statuses:
            return None
        return self.step_statuses.get(str(step_id))

    def update_step_status(
        self,
        step_id: int,
        status: str,
        completed_by_id: Optional[int] = None,
        completed_by_username: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Update the status of a specific step."""
        if self.step_statuses is None:
            self.step_statuses = {}

        self.step_statuses[str(step_id)] = {
            "status": status,
            "completed_at": datetime.utcnow().isoformat() if status in ("completed", "skipped") else None,
            "completed_by_id": completed_by_id,
            "completed_by_username": completed_by_username,
            "notes": notes,
        }

    def check_completion(self) -> bool:
        """Check if all required steps are completed and update status."""
        if not self.playbook or not self.playbook.steps:
            return False

        required_steps = [s for s in self.playbook.steps if s.is_required]
        all_required_done = True

        for step in required_steps:
            step_status = self.get_step_status(step.id)
            if not step_status or step_status.get("status") not in ("completed", "skipped"):
                all_required_done = False
                break

        if all_required_done:
            self.status = ExecutionStatus.COMPLETED.value
            self.completed_at = datetime.utcnow()
            return True

        return False
