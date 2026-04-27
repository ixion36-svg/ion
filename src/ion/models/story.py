"""Story model — JSON-DAG playbook (Tines-inspired, v0.11.0).

A `Story` is a directed graph of automation steps stored as JSON. Each
step has a typed input schema and emits a JSON output that downstream
steps can reference via `{{nodes.<id>.<field>}}`. v0.11.0 ships a
**linear-only** executor — each node has exactly one `next` — branching
+ canvas editor land in v0.11.1+.

Why a new model rather than extending the existing `Playbook` table?
- Existing playbooks are TIDE-driven, read-only catalogue items
- Stories are user-authored automation; different lifecycle (versioned,
  importable, executable against arbitrary entities)
- Keeping them separate avoids breaking v0.10.x playbook UI

JSON shape:

    {
      "name": "Triage alert",
      "description": "...",
      "schema_version": 1,
      "nodes": [
        {
          "id": "investigate",
          "type": "bob_investigate_alert",
          "config": {"alert_id": "{{ trigger.alert_id }}"},
          "next": "summarise"
        },
        {
          "id": "summarise",
          "type": "case_note",
          "config": {
            "case_id": "{{ trigger.case_id }}",
            "content": "Bob verdict: {{ nodes.investigate.verdict }}"
          },
          "next": null
        }
      ],
      "start": "investigate"
    }
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base


class Story(Base):
    """A user-authored JSON-DAG automation playbook."""

    __tablename__ = "stories"
    __table_args__ = (
        Index("ix_stories_enabled", "enabled"),
        Index("ix_stories_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # The full DAG as a JSON string. Validated at write time by the API
    # layer; stored verbatim so import/export is byte-stable.
    dag_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Authorship
    created_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    runs: Mapped[List["StoryRun"]] = relationship(
        "StoryRun", back_populates="story", cascade="all, delete-orphan",
        order_by="StoryRun.id.desc()",
    )

    def __repr__(self) -> str:
        return f"<Story(id={self.id}, name='{self.name}')>"


class StoryRun(Base):
    """One execution of a Story."""

    __tablename__ = "story_runs"
    __table_args__ = (
        Index("ix_story_runs_story_id", "story_id"),
        Index("ix_story_runs_status", "status"),
        Index("ix_story_runs_started_at", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    story_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("stories.id", ondelete="CASCADE"), nullable=False
    )

    # Trigger context — the entity the story was run against. Nullable
    # because some stories are pure transforms with no entity bind.
    case_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    triggered_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )  # pending | running | completed | failed | cancelled
    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Per-step output captured during execution. Shape:
    #   {"<node_id>": {"status": "ok|error|skipped", "output": <any>,
    #                  "error": "...", "duration_ms": N}}
    # Stored as text so SQLite/PG both work without JSONB-specific quirks.
    step_outputs_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    story: Mapped["Story"] = relationship("Story", back_populates="runs")

    def __repr__(self) -> str:
        return f"<StoryRun(id={self.id}, story_id={self.story_id}, status='{self.status}')>"
