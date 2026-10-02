"""Model classes for the unwired services archived alongside them.

Kept for reference only — nothing imports this file, and it is excluded from
ruff, packaging, pytest and the Docker context like the rest of archive/.

  SLAPolicy, SLABreachLog   from models/sla.py, for sla_service
  DashboardLayout           from models/sla.py, for dashboard_layout_service
  ChangeLogEntry            from models/oncall.py, for change_log_service
  UserBookmark              from models/oncall.py, for saved_search_service

Their tables are not dropped. Nothing read them, but a deployed database may
still hold rows, and that is an operator's call rather than a code removal's.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

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


class DashboardLayout(Base, TimestampMixin):
    """Per-user dashboard widget layout."""

    __tablename__ = "dashboard_layouts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    widgets: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON array of {widget_id, position, size, visible}
    theme_overrides: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON


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
