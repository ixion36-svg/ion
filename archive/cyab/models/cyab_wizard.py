"""CyAB onboarding wizard session — server-side state for the 4-step flow.

A row exists for the lifetime of an in-progress onboarding. When the user
hits "Finish" on step 4 the row stays (audit trail) but is_complete=True.
The actual CyabSystem and CyabDataSource rows are created mid-wizard
(end of Step 1 and Step 3 respectively) so on-page autosaves can write
real intake answers via the existing /api/cyab endpoints.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base


class CyabWizardSession(Base):
    """One row per in-progress (or completed) wizard run."""

    __tablename__ = "cyab_wizard_sessions"

    # UUID4 hex; primary key so URLs can carry it directly.
    id: Mapped[str] = mapped_column(String(36), primary_key=True)

    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Current step (1..4). Advances on save_*.
    step: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # JSON blob — see cyab_wizard_service for shape.
    state_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # Pointers to real rows — populated mid-wizard.
    system_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cyab_systems.id", ondelete="SET NULL"), nullable=True
    )
    source_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cyab_data_sources.id", ondelete="SET NULL"), nullable=True
    )

    is_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<CyabWizardSession(id={self.id!r}, step={self.step}, sys_id={self.system_id})>"
