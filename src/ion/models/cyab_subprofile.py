"""CyAB Onboarding Studio — pillar + sub-profile catalogue tables (v0.12.0).

Two new tables. Both are *catalogue* tables seeded from code on first
boot and editable by operators thereafter. The seeder respects the
``is_custom`` flag on sub-profile rows: anything an operator has edited
is left alone on subsequent boots.

Schema (matches §11 of `_research_cyab_onboarding_studio.md`):

- ``cyab_pillars`` — six rows, the top-level taxonomy:
  Identity / Endpoint / Network / Cloud / Data / OT.

- ``cyab_subprofiles`` — second-level rows under a pillar (Active
  Directory, Windows endpoint, Linux endpoint, etc.). The
  ``catalogue_json`` column stores intake questions, recommended
  tasks, detection use cases, and audit use cases as a JSON blob —
  same JSON-as-text pattern used by ``cyab_assessments``.

Two additional ALTER TABLE columns are added by ``database._run_migrations``
on the existing CyAB tables (kept there to follow the established
pattern):

- ``cyab_data_sources.subprofile_id`` — FK so each data source is
  tagged with its sub-profile.
- ``cyab_systems.containment_authority`` — TEXT, captured on the
  Onboarding Pack approval flow.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base


class CyabPillar(Base):
    """Top-level taxonomy node for the Onboarding Studio.

    Six rows, code-seeded. ``priority`` mirrors the Gemini gold-standard
    log-source hierarchy: Identity=1, Endpoint=2, Network=2, Cloud=3,
    Data=3, OT=4. Lower number = ranked first in the UI.
    """

    __tablename__ = "cyab_pillars"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    icon: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=99)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    subprofiles: Mapped[List["CyabSubProfile"]] = relationship(
        "CyabSubProfile", back_populates="pillar",
        order_by="CyabSubProfile.label",
    )

    def __repr__(self) -> str:
        return f"<CyabPillar(id='{self.id}', label='{self.label}')>"


class CyabSubProfile(Base):
    """Second-level taxonomy + catalogue row.

    Stored under one pillar. The catalogue content (intake questions,
    recommended tasks, detection use cases, audit use cases,
    references) lives in ``catalogue_json`` as a JSON-as-text blob so
    the catalogue shape can evolve without per-field migrations.
    """

    __tablename__ = "cyab_subprofiles"
    __table_args__ = (
        Index("ix_cyab_subprofiles_pillar", "pillar_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    pillar_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("cyab_pillars.id"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    icon: Mapped[str] = mapped_column(String(32), nullable=False, default="cpu")

    # JSON-as-text. Lists of strings.
    ecs_anchors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_feeds: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # The big one — see services/cyab_subprofile_catalogue.py for the
    # shape: { intake_questions, recommended_tasks, detection_use_cases,
    # audit_use_cases, references }.
    catalogue_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    catalogue_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )

    # is_custom=True means this row has been operator-edited and the
    # idempotent seeder will skip it on subsequent boots. Code-seeded
    # rows stay False until someone PATCHes them.
    is_custom: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    pillar: Mapped["CyabPillar"] = relationship(
        "CyabPillar", back_populates="subprofiles"
    )

    def __repr__(self) -> str:
        return (
            f"<CyabSubProfile(id='{self.id}', pillar_id='{self.pillar_id}', "
            f"is_custom={self.is_custom})>"
        )
