"""On-Call roster, escalation paths, and Duty IM models."""

from datetime import date, datetime, time
from typing import Optional

from sqlalchemy import (
    Boolean, Date, DateTime, ForeignKey, Integer, String, Text, Time,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class OnCallRoster(Base, TimestampMixin):
    """On-call rotation entry — who is on duty for a given date/shift."""

    __tablename__ = "oncall_roster"
    __table_args__ = (
        UniqueConstraint("user_id", "date", "role_type", name="uq_oncall_user_date_role"),
        Index("ix_oncall_date", "date"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    date: Mapped[date] = mapped_column(Date, nullable=False)
    role_type: Mapped[str] = mapped_column(String(50), nullable=False)  # duty_im, primary_analyst, secondary_analyst, engineer_oncall
    shift: Mapped[str] = mapped_column(String(20), nullable=False, default="day")  # day, night, 24h
    start_time: Mapped[Optional[time]] = mapped_column(Time, nullable=True)  # e.g. 08:00
    end_time: Mapped[Optional[time]] = mapped_column(Time, nullable=True)  # e.g. 20:00
    contact_phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    contact_alt: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)  # Teams/Slack/radio
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    user = relationship("User", foreign_keys=[user_id])


class EscalationPolicy(Base, TimestampMixin):
    """Escalation policy — defines when and how to escalate alerts/cases."""

    __tablename__ = "escalation_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    severity_threshold: Mapped[str] = mapped_column(String(20), nullable=False, default="high")  # critical, high, medium, low
    auto_escalate_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # auto-escalate if unacknowledged after N minutes
    escalate_to_role: Mapped[str] = mapped_column(String(50), nullable=False, default="duty_im")  # who gets escalated to
    notify_method: Mapped[str] = mapped_column(String(50), nullable=False, default="notification")  # notification, email, both
    conditions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: additional conditions (rule patterns, host patterns)


class EscalationLog(Base, TimestampMixin):
    """Log of escalation events — tracks when alerts/cases were escalated to Duty IM."""

    __tablename__ = "escalation_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("alert_cases.id"), nullable=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    escalated_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    escalated_to_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending, acknowledged, resolved
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    escalated_by = relationship("User", foreign_keys=[escalated_by_id])
    escalated_to = relationship("User", foreign_keys=[escalated_to_id])


class ServiceAccount(Base, TimestampMixin):
    """Service account lifecycle tracker."""

    __tablename__ = "service_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    account_type: Mapped[str] = mapped_column(String(50), nullable=False, default="service")  # service, gMSA, scheduled_task, application
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")  # active, disabled, pending_review, decommissioned
    password_last_set: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    password_expires: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    password_never_expires: Mapped[bool] = mapped_column(Boolean, default=False)
    rotation_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # target rotation period in days
    last_logon: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    systems: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of systems this account is used on
    permissions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: key permissions/group memberships
    spn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Service Principal Names
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")  # critical, high, medium, low
    review_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    owner = relationship("User", foreign_keys=[owner_id])


class UserBookmark(Base, TimestampMixin):
    """User's bookmarked searches and workspace shortcuts."""

    __tablename__ = "user_bookmarks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    search_type: Mapped[str] = mapped_column(String(50), nullable=False)  # alert, case, observable, discover, entity_timeline
    query: Mapped[str] = mapped_column(Text, nullable=False)  # the search query or filter JSON
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class CommTemplate(Base, TimestampMixin):
    """Communication templates for incident notifications."""

    __tablename__ = "comm_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # breach_notification, ransomware, phishing, executive_brief, status_update
    subject_template: Mapped[str] = mapped_column(String(500), nullable=False)
    body_template: Mapped[str] = mapped_column(Text, nullable=False)
    audience: Mapped[str] = mapped_column(String(100), nullable=False, default="internal")  # internal, executive, legal, external, all_staff
    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    created_by = relationship("User", foreign_keys=[created_by_id])


class ChangeLogEntry(Base, TimestampMixin):
    """Change management log — tracks config/rule/system changes with approval."""

    __tablename__ = "change_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    change_type: Mapped[str] = mapped_column(String(50), nullable=False)  # detection_rule, integration, config, user, policy
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    changed_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="applied")  # proposed, approved, applied, rolled_back
    rollback_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_systems: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="low")  # critical, high, medium, low

    changed_by = relationship("User", foreign_keys=[changed_by_id])
    approved_by = relationship("User", foreign_keys=[approved_by_id])
