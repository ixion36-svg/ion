"""Security event models for DocForge."""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from docforge.models.base import Base, TimestampMixin


class SecurityEventType(str, Enum):
    """Types of security events."""

    # Authentication events
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_LOCKOUT = "account_lockout"
    SUSPICIOUS_LOGIN = "suspicious_login"
    PASSWORD_SPRAY = "password_spray"

    # Injection attacks
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"

    # Access control
    PATH_TRAVERSAL = "path_traversal"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_HIJACKING = "session_hijacking"

    # Rate limiting
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DDOS_SUSPECTED = "ddos_suspected"

    # Reconnaissance
    DIRECTORY_ENUMERATION = "directory_enumeration"
    USER_ENUMERATION = "user_enumeration"
    API_ABUSE = "api_abuse"

    # Data exfiltration
    BULK_DATA_ACCESS = "bulk_data_access"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"

    # Other
    MALFORMED_REQUEST = "malformed_request"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    SCANNER_DETECTED = "scanner_detected"
    OTHER = "other"


class SecurityEventSeverity(str, Enum):
    """Severity levels for security events."""

    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # Serious threat
    MEDIUM = "medium"  # Moderate concern
    LOW = "low"  # Minor issue
    INFO = "info"  # Informational


class SecurityEventStatus(str, Enum):
    """Status of security events."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"


class SecurityEvent(Base, TimestampMixin):
    """Security event model for tracking potential attacks."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Event classification
    event_type: Mapped[SecurityEventType] = mapped_column(
        SQLEnum(SecurityEventType), nullable=False, index=True
    )
    severity: Mapped[SecurityEventSeverity] = mapped_column(
        SQLEnum(SecurityEventSeverity), nullable=False, index=True
    )
    status: Mapped[SecurityEventStatus] = mapped_column(
        SQLEnum(SecurityEventStatus), default=SecurityEventStatus.NEW, nullable=False
    )

    # Event details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Source information
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    request_method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    # User association (if known)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Detection details
    detection_rule: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence_score: Mapped[int] = mapped_column(
        Integer, default=50, nullable=False
    )  # 0-100

    # Event data
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    matched_patterns: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Tracking
    event_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Response
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exported_to_siem: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Relationships
    user = relationship("User", backref="security_events")

    # Indexes
    __table_args__ = (
        Index("ix_security_events_created", "created_at"),
        Index("ix_security_events_type_severity", "event_type", "severity"),
        Index("ix_security_events_source_ip_type", "source_ip", "event_type"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_path": self.request_path,
            "request_method": self.request_method,
            "user_id": self.user_id,
            "username": self.username,
            "detection_rule": self.detection_rule,
            "confidence_score": self.confidence_score,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "blocked": self.blocked,
            "exported_to_siem": self.exported_to_siem,
            "matched_patterns": self.matched_patterns,
            "raw_data": self.raw_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_siem_format(self) -> dict:
        """Convert to CEF/SIEM-compatible format."""
        return {
            "timestamp": self.created_at.isoformat() if self.created_at else None,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "severity_number": self._severity_to_number(),
            "source_ip": self.source_ip,
            "user": self.username,
            "user_id": self.user_id,
            "action": self.detection_rule,
            "outcome": "blocked" if self.blocked else "detected",
            "description": self.description,
            "request": {
                "method": self.request_method,
                "path": self.request_path,
                "user_agent": self.user_agent,
            },
            "detection": {
                "rule": self.detection_rule,
                "confidence": self.confidence_score,
                "patterns": self.matched_patterns,
            },
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "raw_data": self.raw_data,
        }

    def _severity_to_number(self) -> int:
        """Convert severity to numeric value for SIEM."""
        mapping = {
            SecurityEventSeverity.CRITICAL: 10,
            SecurityEventSeverity.HIGH: 8,
            SecurityEventSeverity.MEDIUM: 5,
            SecurityEventSeverity.LOW: 3,
            SecurityEventSeverity.INFO: 1,
        }
        return mapping.get(self.severity, 5)


class SecurityAlertRule(Base, TimestampMixin):
    """Custom alert rules for security monitoring."""

    __tablename__ = "security_alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Rule configuration
    event_type: Mapped[SecurityEventType] = mapped_column(
        SQLEnum(SecurityEventType), nullable=False
    )
    threshold: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    time_window_minutes: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    severity: Mapped[SecurityEventSeverity] = mapped_column(
        SQLEnum(SecurityEventSeverity), default=SecurityEventSeverity.MEDIUM
    )

    # Matching criteria
    patterns: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    ip_whitelist: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    ip_blacklist: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Actions
    block_source: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    send_to_siem: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "event_type": self.event_type.value,
            "threshold": self.threshold,
            "time_window_minutes": self.time_window_minutes,
            "severity": self.severity.value,
            "patterns": self.patterns,
            "ip_whitelist": self.ip_whitelist,
            "ip_blacklist": self.ip_blacklist,
            "block_source": self.block_source,
            "send_to_siem": self.send_to_siem,
        }


class BlockedIP(Base, TimestampMixin):
    """Temporarily or permanently blocked IP addresses."""

    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    blocked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    permanent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Reference to triggering event
    security_event_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("security_events.id"), nullable=True
    )

    security_event = relationship("SecurityEvent")

    def is_active(self) -> bool:
        """Check if the block is still active."""
        if self.permanent:
            return True
        if self.blocked_until is None:
            return True
        return datetime.utcnow() < self.blocked_until
