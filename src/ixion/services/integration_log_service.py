"""Integration log service for tracking integration activity.

Provides logging and health check recording for all integrations.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from sqlalchemy import func
from sqlalchemy.orm import Session

from ixion.models.integration import (
    IntegrationLog,
    IntegrationHealthCheck,
    IntegrationType,
    IntegrationStatus,
    LogLevel,
)
from ixion.storage.database import get_session

logger = logging.getLogger(__name__)


class IntegrationLogService:
    """Service for logging integration activity and recording health checks."""

    # ==========================================================================
    # Logging Operations
    # ==========================================================================

    def log(
        self,
        integration_type: IntegrationType,
        action: str,
        message: str,
        level: LogLevel = LogLevel.INFO,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        session: Optional[Session] = None,
    ) -> IntegrationLog:
        """Create an integration log entry.

        Args:
            integration_type: The type of integration.
            action: The action being performed (e.g., 'sync', 'connect', 'healthcheck').
            message: Human-readable log message.
            level: Log level (debug, info, warning, error).
            details: Optional structured details.
            user_id: Optional user ID who triggered the action.
            session: Optional database session.

        Returns:
            The created IntegrationLog instance.
        """
        def _log(sess: Session) -> IntegrationLog:
            log_entry = IntegrationLog(
                integration_type=integration_type,
                level=level,
                action=action,
                message=message,
                details=details,
                user_id=user_id,
            )
            sess.add(log_entry)
            sess.flush()
            sess.refresh(log_entry)
            return log_entry

        if session:
            return _log(session)

        for sess in get_session():
            return _log(sess)

    def log_debug(
        self,
        integration_type: IntegrationType,
        action: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> IntegrationLog:
        """Log a debug message."""
        return self.log(integration_type, action, message, LogLevel.DEBUG, details, user_id)

    def log_info(
        self,
        integration_type: IntegrationType,
        action: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> IntegrationLog:
        """Log an info message."""
        return self.log(integration_type, action, message, LogLevel.INFO, details, user_id)

    def log_warning(
        self,
        integration_type: IntegrationType,
        action: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> IntegrationLog:
        """Log a warning message."""
        return self.log(integration_type, action, message, LogLevel.WARNING, details, user_id)

    def log_error(
        self,
        integration_type: IntegrationType,
        action: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> IntegrationLog:
        """Log an error message."""
        return self.log(integration_type, action, message, LogLevel.ERROR, details, user_id)

    def get_logs(
        self,
        integration_type: Optional[IntegrationType] = None,
        level: Optional[LogLevel] = None,
        action: Optional[str] = None,
        hours: int = 24,
        limit: int = 100,
        offset: int = 0,
        session: Optional[Session] = None,
    ) -> List[IntegrationLog]:
        """Get integration logs with optional filters.

        Args:
            integration_type: Filter by integration type.
            level: Filter by log level.
            action: Filter by action.
            hours: Limit to logs within this many hours.
            limit: Maximum number of logs to return.
            offset: Number of logs to skip.
            session: Optional database session.

        Returns:
            List of matching IntegrationLog instances.
        """
        def _get_logs(sess: Session) -> List[IntegrationLog]:
            query = sess.query(IntegrationLog)

            # Time filter
            if hours:
                since = datetime.utcnow() - timedelta(hours=hours)
                query = query.filter(IntegrationLog.timestamp >= since)

            if integration_type is not None:
                query = query.filter(IntegrationLog.integration_type == integration_type)
            if level is not None:
                query = query.filter(IntegrationLog.level == level)
            if action is not None:
                query = query.filter(IntegrationLog.action == action)

            return query.order_by(IntegrationLog.timestamp.desc()).offset(offset).limit(limit).all()

        if session:
            return _get_logs(session)

        for sess in get_session():
            return _get_logs(sess)

    def get_log_stats(
        self,
        hours: int = 24,
        session: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """Get log statistics.

        Args:
            hours: Time window in hours.
            session: Optional database session.

        Returns:
            Dictionary with log statistics.
        """
        def _get_stats(sess: Session) -> Dict[str, Any]:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Total count
            total = sess.query(func.count(IntegrationLog.id)).filter(
                IntegrationLog.timestamp >= since
            ).scalar() or 0

            # Count by integration type
            by_type = {}
            type_counts = sess.query(
                IntegrationLog.integration_type,
                func.count(IntegrationLog.id),
            ).filter(
                IntegrationLog.timestamp >= since
            ).group_by(IntegrationLog.integration_type).all()

            for integration_type, count in type_counts:
                key = integration_type.value if hasattr(integration_type, 'value') else str(integration_type)
                by_type[key] = count

            # Count by level
            by_level = {}
            level_counts = sess.query(
                IntegrationLog.level,
                func.count(IntegrationLog.id),
            ).filter(
                IntegrationLog.timestamp >= since
            ).group_by(IntegrationLog.level).all()

            for level, count in level_counts:
                key = level.value if hasattr(level, 'value') else str(level)
                by_level[key] = count

            return {
                "total": total,
                "by_type": by_type,
                "by_level": by_level,
                "hours": hours,
            }

        if session:
            return _get_stats(session)

        for sess in get_session():
            return _get_stats(sess)

    # ==========================================================================
    # Health Check Operations
    # ==========================================================================

    def record_health_check(
        self,
        integration_type: IntegrationType,
        status: IntegrationStatus,
        response_time_ms: float,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        session: Optional[Session] = None,
    ) -> IntegrationHealthCheck:
        """Record a health check result.

        Args:
            integration_type: The type of integration.
            status: The health status.
            response_time_ms: Response time in milliseconds.
            error_message: Optional error message.
            metadata: Optional metadata from the check.
            session: Optional database session.

        Returns:
            The created IntegrationHealthCheck instance.
        """
        def _record(sess: Session) -> IntegrationHealthCheck:
            health_check = IntegrationHealthCheck(
                integration_type=integration_type,
                status=status,
                response_time_ms=response_time_ms,
                error_message=error_message,
                check_metadata=metadata,
            )
            sess.add(health_check)
            sess.flush()
            sess.refresh(health_check)
            return health_check

        if session:
            return _record(session)

        for sess in get_session():
            return _record(sess)

    def get_latest_health_checks(
        self,
        session: Optional[Session] = None,
    ) -> Dict[str, IntegrationHealthCheck]:
        """Get the latest health check for each integration type.

        Args:
            session: Optional database session.

        Returns:
            Dictionary mapping integration type to latest health check.
        """
        def _get_latest(sess: Session) -> Dict[str, IntegrationHealthCheck]:
            # Get all integration types
            from ixion.models.integration import IntegrationType
            result = {}

            for int_type in IntegrationType:
                latest = sess.query(IntegrationHealthCheck).filter(
                    IntegrationHealthCheck.integration_type == int_type
                ).order_by(IntegrationHealthCheck.checked_at.desc()).first()

                if latest:
                    key = int_type.value if hasattr(int_type, 'value') else str(int_type)
                    result[key] = latest

            return result

        if session:
            return _get_latest(session)

        for sess in get_session():
            return _get_latest(sess)

    def get_health_history(
        self,
        integration_type: Optional[IntegrationType] = None,
        hours: int = 24,
        limit: int = 100,
        session: Optional[Session] = None,
    ) -> List[IntegrationHealthCheck]:
        """Get health check history.

        Args:
            integration_type: Optional filter by integration type.
            hours: Time window in hours.
            limit: Maximum number of records to return.
            session: Optional database session.

        Returns:
            List of IntegrationHealthCheck instances.
        """
        def _get_history(sess: Session) -> List[IntegrationHealthCheck]:
            since = datetime.utcnow() - timedelta(hours=hours)
            query = sess.query(IntegrationHealthCheck).filter(
                IntegrationHealthCheck.checked_at >= since
            )

            if integration_type is not None:
                query = query.filter(IntegrationHealthCheck.integration_type == integration_type)

            return query.order_by(IntegrationHealthCheck.checked_at.desc()).limit(limit).all()

        if session:
            return _get_history(session)

        for sess in get_session():
            return _get_history(sess)


# Singleton instance
_integration_log_service: Optional[IntegrationLogService] = None


def get_integration_log_service() -> IntegrationLogService:
    """Get the global IntegrationLogService instance."""
    global _integration_log_service
    if _integration_log_service is None:
        _integration_log_service = IntegrationLogService()
    return _integration_log_service


def reset_integration_log_service() -> None:
    """Reset the global IntegrationLogService instance."""
    global _integration_log_service
    _integration_log_service = None
