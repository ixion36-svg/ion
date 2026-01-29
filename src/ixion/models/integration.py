"""Integration management models for IXION.

Provides models for webhooks, webhook logs, integration logs, and health checks.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
import secrets

from sqlalchemy import (
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Float,
    func,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ixion.models.base import Base, TimestampMixin


class IntegrationType(str, Enum):
    """Types of integrations supported by IXION."""
    GITLAB = "gitlab"
    OPENCTI = "opencti"
    ELASTICSEARCH = "elasticsearch"
    SLACK = "slack"      # Future
    JIRA = "jira"        # Future
    CUSTOM = "custom"


class IntegrationStatus(str, Enum):
    """Health status of an integration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    DISABLED = "disabled"


class LogLevel(str, Enum):
    """Log level for integration logs."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class WebhookStatus(str, Enum):
    """Status of a webhook request processing."""
    SUCCESS = "success"
    FAILED = "failed"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_PAYLOAD = "invalid_payload"
    HANDLER_ERROR = "handler_error"


def generate_webhook_token() -> str:
    """Generate a secure random webhook token."""
    return secrets.token_urlsafe(32)


class Webhook(Base, TimestampMixin):
    """Webhook configuration for receiving events from external services."""

    __tablename__ = "webhooks"
    __table_args__ = (
        Index("ix_webhooks_token", "token"),
        Index("ix_webhooks_source_type", "source_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, default=generate_webhook_token
    )
    secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_type: Mapped[str] = mapped_column(
        SQLEnum(IntegrationType), default=IntegrationType.CUSTOM, nullable=False
    )
    event_types: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    created_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by_id])
    logs: Mapped[List["WebhookLog"]] = relationship(
        "WebhookLog", back_populates="webhook", cascade="all, delete-orphan"
    )

    def to_dict(self, include_token: bool = False) -> dict:
        """Convert to dictionary for API response."""
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "source_type": self.source_type.value if isinstance(self.source_type, Enum) else self.source_type,
            "event_types": self.event_types,
            "is_active": self.is_active,
            "created_by_id": self.created_by_id,
            "last_triggered_at": self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            "trigger_count": self.trigger_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "has_secret": bool(self.secret),
        }
        if include_token:
            data["token"] = self.token
        return data


class WebhookLog(Base):
    """Log entry for webhook events received."""

    __tablename__ = "webhook_logs"
    __table_args__ = (
        Index("ix_webhook_logs_webhook_id", "webhook_id"),
        Index("ix_webhook_logs_created_at", "created_at"),
        Index("ix_webhook_logs_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    webhook_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    status: Mapped[str] = mapped_column(
        SQLEnum(WebhookStatus), default=WebhookStatus.SUCCESS, nullable=False
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    processing_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    webhook: Mapped["Webhook"] = relationship("Webhook", back_populates="logs")

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "webhook_id": self.webhook_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "headers": self.headers,
            "source_ip": self.source_ip,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "error_message": self.error_message,
            "processing_time_ms": self.processing_time_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IntegrationLog(Base):
    """Log entry for integration activities."""

    __tablename__ = "integration_logs"
    __table_args__ = (
        Index("ix_integration_logs_integration_type", "integration_type"),
        Index("ix_integration_logs_level", "level"),
        Index("ix_integration_logs_timestamp", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    integration_type: Mapped[str] = mapped_column(
        SQLEnum(IntegrationType), nullable=False
    )
    level: Mapped[str] = mapped_column(
        SQLEnum(LogLevel), default=LogLevel.INFO, nullable=False
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[user_id])

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "integration_type": self.integration_type.value if isinstance(self.integration_type, Enum) else self.integration_type,
            "level": self.level.value if isinstance(self.level, Enum) else self.level,
            "action": self.action,
            "message": self.message,
            "details": self.details,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class IntegrationHealthCheck(Base, TimestampMixin):
    """Health check record for an integration."""

    __tablename__ = "integration_health_checks"
    __table_args__ = (
        Index("ix_integration_health_checks_type", "integration_type"),
        Index("ix_integration_health_checks_checked_at", "checked_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    integration_type: Mapped[str] = mapped_column(
        SQLEnum(IntegrationType), nullable=False
    )
    status: Mapped[str] = mapped_column(
        SQLEnum(IntegrationStatus), default=IntegrationStatus.HEALTHY, nullable=False
    )
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    check_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "integration_type": self.integration_type.value if isinstance(self.integration_type, Enum) else self.integration_type,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "response_time_ms": self.response_time_ms,
            "error_message": self.error_message,
            "metadata": self.check_metadata,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# Type hint for User relationship (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ixion.models.user import User
