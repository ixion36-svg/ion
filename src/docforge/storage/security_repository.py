"""Repository for security event operations."""

from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from docforge.models.security import (
    BlockedIP,
    SecurityAlertRule,
    SecurityEvent,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityEventType,
)


class SecurityEventRepository:
    """Repository for security event CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        title: str,
        description: str,
        source_ip: str,
        detection_rule: str,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None,
        request_method: Optional[str] = None,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        confidence_score: int = 50,
        raw_data: Optional[dict] = None,
        matched_patterns: Optional[list] = None,
        blocked: bool = False,
    ) -> SecurityEvent:
        """Create a new security event."""
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            user_agent=user_agent,
            request_path=request_path,
            request_method=request_method,
            user_id=user_id,
            username=username,
            detection_rule=detection_rule,
            confidence_score=confidence_score,
            raw_data=raw_data,
            matched_patterns=matched_patterns,
            blocked=blocked,
        )
        self.session.add(event)
        return event

    def get_by_id(self, event_id: int) -> Optional[SecurityEvent]:
        """Get security event by ID."""
        return self.session.query(SecurityEvent).filter_by(id=event_id).first()

    def get_recent(
        self,
        hours: int = 24,
        event_type: Optional[SecurityEventType] = None,
        severity: Optional[SecurityEventSeverity] = None,
        status: Optional[SecurityEventStatus] = None,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """Get recent security events."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = self.session.query(SecurityEvent).filter(
            SecurityEvent.created_at >= since
        )

        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if status:
            query = query.filter(SecurityEvent.status == status)

        return query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()

    def get_by_source_ip(
        self,
        source_ip: str,
        hours: int = 24,
        event_type: Optional[SecurityEventType] = None,
    ) -> List[SecurityEvent]:
        """Get events from a specific IP address."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = self.session.query(SecurityEvent).filter(
            and_(
                SecurityEvent.source_ip == source_ip,
                SecurityEvent.created_at >= since,
            )
        )

        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)

        return query.order_by(SecurityEvent.created_at.desc()).all()

    def count_by_ip_and_type(
        self,
        source_ip: str,
        event_type: SecurityEventType,
        minutes: int = 5,
    ) -> int:
        """Count events from IP of specific type within time window."""
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return (
            self.session.query(SecurityEvent)
            .filter(
                and_(
                    SecurityEvent.source_ip == source_ip,
                    SecurityEvent.event_type == event_type,
                    SecurityEvent.created_at >= since,
                )
            )
            .count()
        )

    def get_or_create_aggregated(
        self,
        event_type: SecurityEventType,
        source_ip: str,
        detection_rule: str,
        window_minutes: int = 5,
    ) -> Tuple[SecurityEvent, bool]:
        """Get existing event or create new one (for aggregation)."""
        since = datetime.utcnow() - timedelta(minutes=window_minutes)
        existing = (
            self.session.query(SecurityEvent)
            .filter(
                and_(
                    SecurityEvent.source_ip == source_ip,
                    SecurityEvent.event_type == event_type,
                    SecurityEvent.detection_rule == detection_rule,
                    SecurityEvent.created_at >= since,
                )
            )
            .first()
        )

        if existing:
            existing.event_count += 1
            existing.last_seen = datetime.utcnow()
            return existing, False

        return None, True

    def update_status(
        self, event_id: int, status: SecurityEventStatus
    ) -> Optional[SecurityEvent]:
        """Update event status."""
        event = self.get_by_id(event_id)
        if event:
            event.status = status
        return event

    def mark_exported(self, event_ids: List[int]) -> int:
        """Mark events as exported to SIEM."""
        count = (
            self.session.query(SecurityEvent)
            .filter(SecurityEvent.id.in_(event_ids))
            .update({SecurityEvent.exported_to_siem: True}, synchronize_session=False)
        )
        return count

    def get_unexported(self, limit: int = 1000) -> List[SecurityEvent]:
        """Get events not yet exported to SIEM."""
        return (
            self.session.query(SecurityEvent)
            .filter(SecurityEvent.exported_to_siem == False)
            .order_by(SecurityEvent.created_at.asc())
            .limit(limit)
            .all()
        )

    def get_statistics(self, hours: int = 24) -> dict:
        """Get security event statistics."""
        since = datetime.utcnow() - timedelta(hours=hours)

        # Total events
        total = (
            self.session.query(SecurityEvent)
            .filter(SecurityEvent.created_at >= since)
            .count()
        )

        # By severity
        severity_counts = (
            self.session.query(
                SecurityEvent.severity, func.count(SecurityEvent.id)
            )
            .filter(SecurityEvent.created_at >= since)
            .group_by(SecurityEvent.severity)
            .all()
        )

        # By type
        type_counts = (
            self.session.query(
                SecurityEvent.event_type, func.count(SecurityEvent.id)
            )
            .filter(SecurityEvent.created_at >= since)
            .group_by(SecurityEvent.event_type)
            .all()
        )

        # Top source IPs
        top_ips = (
            self.session.query(
                SecurityEvent.source_ip, func.count(SecurityEvent.id).label("count")
            )
            .filter(SecurityEvent.created_at >= since)
            .group_by(SecurityEvent.source_ip)
            .order_by(func.count(SecurityEvent.id).desc())
            .limit(10)
            .all()
        )

        # Blocked count
        blocked_count = (
            self.session.query(SecurityEvent)
            .filter(
                and_(
                    SecurityEvent.created_at >= since,
                    SecurityEvent.blocked == True,
                )
            )
            .count()
        )

        return {
            "total_events": total,
            "by_severity": {s.value: c for s, c in severity_counts},
            "by_type": {t.value: c for t, c in type_counts},
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "blocked_count": blocked_count,
            "time_period_hours": hours,
        }

    def get_timeline(self, hours: int = 24, bucket_minutes: int = 60) -> List[dict]:
        """Get event timeline for charts."""
        since = datetime.utcnow() - timedelta(hours=hours)

        # This is a simplified version - in production you'd use
        # database-specific date truncation functions
        events = (
            self.session.query(SecurityEvent)
            .filter(SecurityEvent.created_at >= since)
            .order_by(SecurityEvent.created_at)
            .all()
        )

        # Bucket events
        buckets = {}
        bucket_size = timedelta(minutes=bucket_minutes)

        for event in events:
            bucket_time = event.created_at.replace(
                minute=(event.created_at.minute // bucket_minutes) * bucket_minutes,
                second=0,
                microsecond=0,
            )
            key = bucket_time.isoformat()
            if key not in buckets:
                buckets[key] = {"timestamp": key, "total": 0, "critical": 0, "high": 0}
            buckets[key]["total"] += 1
            if event.severity == SecurityEventSeverity.CRITICAL:
                buckets[key]["critical"] += 1
            elif event.severity == SecurityEventSeverity.HIGH:
                buckets[key]["high"] += 1

        return sorted(buckets.values(), key=lambda x: x["timestamp"])


class SecurityAlertRuleRepository:
    """Repository for security alert rules."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, **kwargs) -> SecurityAlertRule:
        """Create a new alert rule."""
        rule = SecurityAlertRule(**kwargs)
        self.session.add(rule)
        return rule

    def get_by_id(self, rule_id: int) -> Optional[SecurityAlertRule]:
        """Get rule by ID."""
        return self.session.query(SecurityAlertRule).filter_by(id=rule_id).first()

    def get_by_name(self, name: str) -> Optional[SecurityAlertRule]:
        """Get rule by name."""
        return self.session.query(SecurityAlertRule).filter_by(name=name).first()

    def get_enabled(self) -> List[SecurityAlertRule]:
        """Get all enabled rules."""
        return (
            self.session.query(SecurityAlertRule)
            .filter(SecurityAlertRule.enabled == True)
            .all()
        )

    def get_all(self) -> List[SecurityAlertRule]:
        """Get all rules."""
        return self.session.query(SecurityAlertRule).all()

    def update(self, rule_id: int, **kwargs) -> Optional[SecurityAlertRule]:
        """Update a rule."""
        rule = self.get_by_id(rule_id)
        if rule:
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
        return rule

    def delete(self, rule_id: int) -> bool:
        """Delete a rule."""
        rule = self.get_by_id(rule_id)
        if rule:
            self.session.delete(rule)
            return True
        return False


class BlockedIPRepository:
    """Repository for blocked IP addresses."""

    def __init__(self, session: Session):
        self.session = session

    def block(
        self,
        ip_address: str,
        reason: str,
        duration_minutes: Optional[int] = None,
        permanent: bool = False,
        security_event_id: Optional[int] = None,
    ) -> BlockedIP:
        """Block an IP address."""
        blocked_until = None
        if duration_minutes and not permanent:
            blocked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)

        # Check if already blocked
        existing = self.get_by_ip(ip_address)
        if existing:
            existing.reason = reason
            existing.blocked_until = blocked_until
            existing.permanent = permanent
            existing.security_event_id = security_event_id
            return existing

        blocked = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            blocked_until=blocked_until,
            permanent=permanent,
            security_event_id=security_event_id,
        )
        self.session.add(blocked)
        return blocked

    def unblock(self, ip_address: str) -> bool:
        """Unblock an IP address."""
        blocked = self.get_by_ip(ip_address)
        if blocked:
            self.session.delete(blocked)
            return True
        return False

    def get_by_ip(self, ip_address: str) -> Optional[BlockedIP]:
        """Get blocked IP entry."""
        return self.session.query(BlockedIP).filter_by(ip_address=ip_address).first()

    def is_blocked(self, ip_address: str) -> bool:
        """Check if IP is currently blocked."""
        blocked = self.get_by_ip(ip_address)
        if blocked:
            return blocked.is_active()
        return False

    def get_all_active(self) -> List[BlockedIP]:
        """Get all actively blocked IPs."""
        now = datetime.utcnow()
        return (
            self.session.query(BlockedIP)
            .filter(
                or_(
                    BlockedIP.permanent == True,
                    BlockedIP.blocked_until > now,
                    BlockedIP.blocked_until == None,
                )
            )
            .all()
        )

    def cleanup_expired(self) -> int:
        """Remove expired blocks."""
        now = datetime.utcnow()
        count = (
            self.session.query(BlockedIP)
            .filter(
                and_(
                    BlockedIP.permanent == False,
                    BlockedIP.blocked_until != None,
                    BlockedIP.blocked_until <= now,
                )
            )
            .delete(synchronize_session=False)
        )
        return count
