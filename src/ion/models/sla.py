"""Playbook action definitions and their execution log.

Named for the SLA/reporting models it used to hold. SLAPolicy,
SLABreachLog, DashboardLayout, ThreatHunt and ScheduledReport have all
been removed with the services that were their only callers; the removal
notes below record which went when and why.
"""

from typing import Optional

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

# ThreatHunt model removed alongside the half-built
# /threat-hunting page + threat_hunt_api. The threat_hunts table is
# dropped via the migration in storage/database.py. Hunt workflow
# now lives in /discover (queries) + /cases (findings); the parallel
# CRUD surface never integrated with either.


# ScheduledReport model removed alongside report_scheduler_service, which
# was its only reader. The service was orphaned by the v0.26.0 route audit
# (its router went, and the CHANGELOG's claim that the service "remains"
# was never true of this one) and `scheduler_service` supersedes it with
# generic crontab expressions, a handler registry and a wired API. The
# scheduled_reports table is dropped via the migration in
# storage/database.py.


class PlaybookAction(Base, TimestampMixin):
    """Automated action that can be executed from a playbook step."""

    __tablename__ = "playbook_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)  # block_ip, disable_account, quarantine_host, block_domain, isolate_host
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_integration: Mapped[str] = mapped_column(String(50), nullable=False)  # firewall, active_directory, edr, email_gateway, dns
    config_template: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: action parameters template
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="high")


class PlaybookActionLog(Base, TimestampMixin):
    """Log of executed playbook actions."""

    __tablename__ = "playbook_action_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[int] = mapped_column(Integer, ForeignKey("playbook_actions.id"), nullable=False)
    case_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("alert_cases.id"), nullable=True)
    executed_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    target: Mapped[str] = mapped_column(String(500), nullable=False)  # the IP, account, host being acted on
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending_approval, approved, executing, completed, failed, rejected
    result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON result
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    action = relationship("PlaybookAction", foreign_keys=[action_id])
    executed_by = relationship("User", foreign_keys=[executed_by_id])
    approved_by = relationship("User", foreign_keys=[approved_by_id])
