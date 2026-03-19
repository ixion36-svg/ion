"""Analytics Engine models for ION.

Tracks scheduled analysis jobs and their historical results.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class AnalyticsJobType(str, Enum):
    """Types of analytics jobs available."""

    ENTITY_RISK_SCORE = "entity_risk_score"
    REPEAT_OFFENDERS = "repeat_offenders"
    RULE_NOISE = "rule_noise"
    OBSERVABLE_VELOCITY = "observable_velocity"
    CASE_METRICS = "case_metrics"
    STALE_INVESTIGATIONS = "stale_investigations"


class AnalyticsJob(Base, TimestampMixin):
    """Configuration and state for a scheduled analytics job."""

    __tablename__ = "analytics_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_type: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    schedule_minutes: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<AnalyticsJob(job_type='{self.job_type}', enabled={self.enabled})>"


class AnalyticsSnapshot(Base):
    """Historical snapshot of analytics job results for trend tracking."""

    __tablename__ = "analytics_snapshots"
    __table_args__ = (
        Index("ix_analytics_snapshots_job_type_created", "job_type", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    snapshot_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<AnalyticsSnapshot(job_type='{self.job_type}', created_at={self.created_at})>"
