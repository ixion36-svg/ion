"""CyAB sign-offs and checklist exceptions.

Sign-off used to be two name/date pairs on the system row, typed by whoever
was at the keyboard and overwritten on each re-sign, so neither who signed nor
when the previous sign-off happened survived. A CyabSignoff is one signature
by a signed-in user, kept for good.

A CyabChecklistException accepts a documentation gap for a stated reason, on
someone's authority, until a date. Expired or revoked, it stops counting and
the gap is open again. This is the "accepted risk" record CyAB_SAL.md 12.2
describes, kept per checklist item.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base

ROLE_DEPARTMENT = "department"
ROLE_SOC = "soc"
SIGNOFF_ROLES = (ROLE_DEPARTMENT, ROLE_SOC)


class CyabSignoff(Base):
    __tablename__ = "cyab_signoffs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cyab_systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    signer_name: Mapped[str] = mapped_column(String(255), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    sal_tier: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    readiness_pct: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class CyabChecklistException(Base):
    __tablename__ = "cyab_checklist_exceptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    item_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cyab_doc_checklist.id", ondelete="CASCADE"), nullable=False, index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cyab_systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approver: Mapped[str] = mapped_column(String(255), nullable=False)
    accepted_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    until: Mapped[date] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def active_on(self, day: date) -> bool:
        return self.revoked_at is None and self.until >= day
