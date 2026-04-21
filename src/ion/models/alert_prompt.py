"""Alert prompt template model — per-rule LLM investigation prompts.

Lets SOC analysts define custom investigation prompts per Elastic Security
rule/rule-group that the AI analyst auto-selects during triage.
"""

from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User


class AlertPromptTemplate(Base, TimestampMixin):
    """Per-rule LLM investigation prompt template.

    Matches an alert via exact rule-ID list, regex on rule id, or any of the
    alert's ``rule.groups`` being present in the template's ``rule_groups_json``.
    Priority (lower = higher) resolves ties; updated_at desc as secondary.
    """

    __tablename__ = "alert_prompt_templates"
    __table_args__ = (
        Index("ix_alert_prompt_templates_enabled", "enabled"),
        Index("ix_alert_prompt_templates_priority", "priority"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Matching fields (all JSON-encoded text lists for cross-backend portability)
    rule_ids_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_groups_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_id_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Ordering: lower = higher priority (matches Playbook semantics inverted — see repo)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    # Prompt content
    prompt_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    investigation_checklist_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity_hint: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    expected_outputs_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Audit trail
    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    created_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[created_by_id]
    )

    def __repr__(self) -> str:
        return (
            f"<AlertPromptTemplate(id={self.id}, name='{self.name}', "
            f"priority={self.priority}, enabled={self.enabled})>"
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        import json as _json

        def _load(raw: Optional[str]) -> list:
            if not raw:
                return []
            try:
                val = _json.loads(raw)
                return val if isinstance(val, list) else []
            except Exception:
                return []

        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "rule_ids": _load(self.rule_ids_json),
            "rule_groups": _load(self.rule_groups_json),
            "rule_id_pattern": self.rule_id_pattern,
            "priority": self.priority,
            "prompt_text": self.prompt_text,
            "investigation_checklist_text": self.investigation_checklist_text,
            "severity_hint": self.severity_hint,
            "expected_outputs": _load(self.expected_outputs_json),
            "created_by_id": self.created_by_id,
            "created_by_username": (
                self.created_by.username if self.created_by else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
