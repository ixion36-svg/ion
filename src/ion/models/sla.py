"""SLA targets, threat hunting, dashboard widgets, reporting schedule, playbook actions."""

from datetime import datetime, date
from typing import Optional

from sqlalchemy import (
    Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class SLAPolicy(Base, TimestampMixin):
    """SLA response time targets per severity level."""

    __tablename__ = "sla_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)  # critical, high, medium, low
    acknowledge_minutes: Mapped[int] = mapped_column(Integer, nullable=False)  # target time to acknowledge
    resolve_minutes: Mapped[int] = mapped_column(Integer, nullable=False)  # target time to resolve
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SLABreachLog(Base, TimestampMixin):
    """Log of SLA breaches — when response targets were missed."""

    __tablename__ = "sla_breach_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("alert_cases.id"), nullable=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    breach_type: Mapped[str] = mapped_column(String(20), nullable=False)  # acknowledge, resolve
    target_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    actual_minutes: Mapped[float] = mapped_column(Float, nullable=False)
    exceeded_by_minutes: Mapped[float] = mapped_column(Float, nullable=False)


class ThreatHunt(Base, TimestampMixin):
    """Threat hunting hypothesis and investigation."""

    __tablename__ = "threat_hunts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")  # active, confirmed, refuted, inconclusive
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")  # critical, high, medium, low
    created_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_to_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    data_sources: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list: which ES indices / log sources
    queries: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of {query, description, result_count}
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # markdown
    conclusion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    iocs_found: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_id])
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])


class DashboardLayout(Base, TimestampMixin):
    """Per-user dashboard widget layout."""

    __tablename__ = "dashboard_layouts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    widgets: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON array of {widget_id, position, size, visible}
    theme_overrides: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON


class ScheduledReport(Base, TimestampMixin):
    """Scheduled report generation config."""

    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # executive, shift_handover, soc_health, compliance
    schedule: Mapped[str] = mapped_column(String(50), nullable=False)  # daily, weekly, monthly
    day_of_week: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 0=Mon for weekly
    day_of_month: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 1-28 for monthly
    time_utc: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)  # HH:MM
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: {status, file_path, error}
    recipients: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of user_ids
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: report-specific params (days, etc.)

    created_by = relationship("User", foreign_keys=[created_by_id])


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
