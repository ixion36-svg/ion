"""Integration management models for ION.

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

from ion.models.base import Base, TimestampMixin


class IntegrationType(str, Enum):
    """Types of integrations supported by ION."""
    GITLAB = "gitlab"
    OPENCTI = "opencti"
    ELASTICSEARCH = "elasticsearch"
    DFIR_IRIS = "dfir_iris"
    KIBANA_CASES = "kibana_cases"
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


class IntegrationEventType(str, Enum):
    """Types of integration events."""
    WEBHOOK = "webhook"           # Incoming webhook event
    ACTIVITY = "activity"         # General integration activity log
    HEALTH_CHECK = "health_check" # Health check result


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
    logs: Mapped[List["IntegrationEvent"]] = relationship(
        "IntegrationEvent",
        back_populates="webhook",
        foreign_keys="IntegrationEvent.webhook_id",
        cascade="all, delete-orphan",
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


class IntegrationEvent(Base):
    """Unified event log for all integration activities.

    Consolidates webhook logs, integration activity logs, and health checks
    into a single table with an event_type discriminator.
    """

    __tablename__ = "integration_events"
    __table_args__ = (
        Index("ix_integration_events_type", "event_type"),
        Index("ix_integration_events_integration_type", "integration_type"),
        Index("ix_integration_events_created_at", "created_at"),
        Index("ix_integration_events_webhook_id", "webhook_id"),
        Index("ix_integration_events_level", "level"),
        Index("ix_integration_events_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Event classification
    event_type: Mapped[str] = mapped_column(
        SQLEnum(IntegrationEventType), nullable=False
    )
    integration_type: Mapped[str] = mapped_column(
        SQLEnum(IntegrationType), nullable=False
    )

    # Common fields
    action: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Activity log specific
    level: Mapped[Optional[str]] = mapped_column(
        SQLEnum(LogLevel), nullable=True
    )

    # Webhook specific
    webhook_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("webhooks.id", ondelete="SET NULL"), nullable=True
    )
    webhook_event_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(
        SQLEnum(WebhookStatus), nullable=True
    )

    # Health check specific - reuses status but with IntegrationStatus
    health_status: Mapped[Optional[str]] = mapped_column(
        SQLEnum(IntegrationStatus), nullable=True
    )

    # User tracking
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    webhook: Mapped[Optional["Webhook"]] = relationship("Webhook", back_populates="logs")
    user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[user_id])

    # Backward compatibility properties
    @property
    def timestamp(self) -> datetime:
        """Alias for created_at (backward compatibility with IntegrationLog)."""
        return self.created_at

    @property
    def checked_at(self) -> datetime:
        """Alias for created_at (backward compatibility with IntegrationHealthCheck)."""
        return self.created_at

    @property
    def check_metadata(self) -> Optional[dict]:
        """Alias for details (backward compatibility with IntegrationHealthCheck)."""
        return self.details

    @property
    def processing_time_ms(self) -> Optional[float]:
        """Alias for response_time_ms (backward compatibility with WebhookLog)."""
        return self.response_time_ms

    @property
    def event_type_str(self) -> str:
        """Get webhook_event_type for backward compatibility."""
        return self.webhook_event_type or ""

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        base = {
            "id": self.id,
            "event_type": self.event_type.value if isinstance(self.event_type, Enum) else self.event_type,
            "integration_type": self.integration_type.value if isinstance(self.integration_type, Enum) else self.integration_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

        if self.event_type == IntegrationEventType.WEBHOOK:
            base.update({
                "webhook_id": self.webhook_id,
                "webhook_event_type": self.webhook_event_type,
                "payload": self.payload,
                "headers": self.headers,
                "source_ip": self.source_ip,
                "status": self.status.value if isinstance(self.status, Enum) else self.status,
                "error_message": self.error_message,
                "response_time_ms": self.response_time_ms,
            })
        elif self.event_type == IntegrationEventType.ACTIVITY:
            base.update({
                "level": self.level.value if isinstance(self.level, Enum) else self.level,
                "action": self.action,
                "message": self.message,
                "details": self.details,
                "user_id": self.user_id,
            })
        elif self.event_type == IntegrationEventType.HEALTH_CHECK:
            base.update({
                "status": self.health_status.value if isinstance(self.health_status, Enum) else self.health_status,
                "response_time_ms": self.response_time_ms,
                "error_message": self.error_message,
                "metadata": self.details,
            })

        return base


# Backward compatibility aliases
WebhookLog = IntegrationEvent
IntegrationLog = IntegrationEvent
IntegrationHealthCheck = IntegrationEvent


# Type hint for User relationship (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ion.models.user import User
