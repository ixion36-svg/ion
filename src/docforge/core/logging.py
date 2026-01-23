"""ECS-compliant structured logging for DocForge.

This module provides:
- ECS (Elastic Common Schema) compliant JSON logging
- Structured log fields for easy Elasticsearch indexing
- Request context tracking (trace IDs, user info)
- Performance metrics logging

Logs are output to stdout in JSON format for easy collection by Filebeat.
"""

import logging
import sys
import os
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from functools import wraps

# Try to import ecs_logging, fall back to basic JSON if not available
try:
    import ecs_logging
    ECS_AVAILABLE = True
except ImportError:
    ECS_AVAILABLE = False

try:
    from pythonjsonlogger import jsonlogger
    JSON_LOGGER_AVAILABLE = True
except ImportError:
    JSON_LOGGER_AVAILABLE = False


# Context variables for request tracking
_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_user_id: ContextVar[Optional[int]] = ContextVar("user_id", default=None)
_username: ContextVar[Optional[str]] = ContextVar("username", default=None)
_client_ip: ContextVar[Optional[str]] = ContextVar("client_ip", default=None)
_trace_id: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)


# =============================================================================
# ECS Field Mappings
# =============================================================================

ECS_SERVICE_NAME = os.environ.get("DOCFORGE_SERVICE_NAME", "docforge")
ECS_SERVICE_VERSION = os.environ.get("DOCFORGE_VERSION", "1.0.0")
ECS_ENVIRONMENT = os.environ.get("DOCFORGE_ENVIRONMENT", "production")


class ECSFormatter(logging.Formatter):
    """Custom formatter that outputs ECS-compliant JSON logs.

    ECS (Elastic Common Schema) fields:
    - @timestamp: ISO 8601 timestamp
    - log.level: Log level (info, warning, error, etc.)
    - log.logger: Logger name
    - message: Log message
    - service.name: Application name
    - service.version: Application version
    - service.environment: Deployment environment
    - trace.id: Distributed trace ID
    - transaction.id: Request/transaction ID
    - user.id: User ID (if authenticated)
    - user.name: Username (if authenticated)
    - client.ip: Client IP address
    - error.*: Error details (if exception)
    - event.*: Event categorization
    """

    def __init__(self):
        super().__init__()
        self.hostname = os.environ.get("HOSTNAME", "unknown")

    def format(self, record: logging.LogRecord) -> str:
        # Base ECS structure
        ecs_record = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
                "origin": {
                    "file": {
                        "name": record.filename,
                        "line": record.lineno,
                    },
                    "function": record.funcName,
                },
            },
            "message": record.getMessage(),
            "service": {
                "name": ECS_SERVICE_NAME,
                "version": ECS_SERVICE_VERSION,
                "environment": ECS_ENVIRONMENT,
            },
            "host": {
                "hostname": self.hostname,
            },
            "ecs": {
                "version": "8.11.0",
            },
        }

        # Add trace context
        trace_id = _trace_id.get()
        if trace_id:
            ecs_record["trace"] = {"id": trace_id}

        request_id = _request_id.get()
        if request_id:
            ecs_record["transaction"] = {"id": request_id}

        # Add user context
        user_id = _user_id.get()
        username = _username.get()
        if user_id or username:
            ecs_record["user"] = {}
            if user_id:
                ecs_record["user"]["id"] = str(user_id)
            if username:
                ecs_record["user"]["name"] = username

        # Add client IP
        client_ip = _client_ip.get()
        if client_ip:
            ecs_record["client"] = {"ip": client_ip}

        # Add exception info if present
        if record.exc_info:
            import traceback
            exc_type, exc_value, exc_tb = record.exc_info
            ecs_record["error"] = {
                "type": exc_type.__name__ if exc_type else "Unknown",
                "message": str(exc_value) if exc_value else "",
                "stack_trace": "".join(traceback.format_exception(*record.exc_info)),
            }

        # Add custom fields from record
        if hasattr(record, "event_category"):
            ecs_record.setdefault("event", {})["category"] = record.event_category
        if hasattr(record, "event_action"):
            ecs_record.setdefault("event", {})["action"] = record.event_action
        if hasattr(record, "event_outcome"):
            ecs_record.setdefault("event", {})["outcome"] = record.event_outcome
        if hasattr(record, "event_duration"):
            ecs_record.setdefault("event", {})["duration"] = record.event_duration

        # Add HTTP context if present
        if hasattr(record, "http_method"):
            ecs_record.setdefault("http", {}).setdefault("request", {})["method"] = record.http_method
        if hasattr(record, "http_path"):
            ecs_record.setdefault("url", {})["path"] = record.http_path
        if hasattr(record, "http_status"):
            ecs_record.setdefault("http", {}).setdefault("response", {})["status_code"] = record.http_status

        # Add any extra fields
        if hasattr(record, "extra_fields"):
            ecs_record["labels"] = record.extra_fields

        import json
        return json.dumps(ecs_record, default=str)


class SimpleJSONFormatter(logging.Formatter):
    """Fallback JSON formatter when ecs-logging is not available."""

    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": ECS_SERVICE_NAME,
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
        }

        # Add context
        if _request_id.get():
            log_record["request_id"] = _request_id.get()
        if _user_id.get():
            log_record["user_id"] = _user_id.get()
        if _username.get():
            log_record["username"] = _username.get()
        if _client_ip.get():
            log_record["client_ip"] = _client_ip.get()
        if _trace_id.get():
            log_record["trace_id"] = _trace_id.get()

        # Add exception
        if record.exc_info:
            import traceback
            log_record["exception"] = "".join(traceback.format_exception(*record.exc_info))

        import json
        return json.dumps(log_record, default=str)


# =============================================================================
# Logger Setup
# =============================================================================

def setup_logging(
    level: str = "INFO",
    json_output: bool = True,
    ecs_format: bool = True,
    log_file: Optional[str] = None,
) -> None:
    """Configure application logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: Output logs as JSON (required for Elasticsearch)
        ecs_format: Use full ECS format (vs simple JSON)
        log_file: Optional file path to write logs to (for Filebeat collection)
    """
    from logging.handlers import RotatingFileHandler
    from pathlib import Path

    # Get settings from environment or parameters
    level = os.environ.get("DOCFORGE_LOG_LEVEL", level).upper()
    json_output = os.environ.get("DOCFORGE_LOG_JSON", str(json_output)).lower() == "true"
    ecs_format = os.environ.get("DOCFORGE_LOG_ECS", str(ecs_format)).lower() == "true"
    log_file = os.environ.get("DOCFORGE_LOG_FILE", log_file)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level, logging.INFO))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatter based on settings
    if json_output:
        if ecs_format and ECS_AVAILABLE:
            formatter = ecs_logging.StdlibFormatter()
        elif ecs_format:
            formatter = ECSFormatter()
        else:
            formatter = SimpleJSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    # Create stdout handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(getattr(logging, level, logging.INFO))
    stdout_handler.setFormatter(formatter)
    root_logger.addHandler(stdout_handler)

    # Create file handler if log_file is specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(getattr(logging, level, logging.INFO))
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Configure specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


# =============================================================================
# Context Management
# =============================================================================

def set_request_context(
    request_id: Optional[str] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    client_ip: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> None:
    """Set logging context for the current request.

    Call this at the start of each request to include context in all logs.
    """
    if request_id:
        _request_id.set(request_id)
    if user_id:
        _user_id.set(user_id)
    if username:
        _username.set(username)
    if client_ip:
        _client_ip.set(client_ip)
    if trace_id:
        _trace_id.set(trace_id)


def clear_request_context() -> None:
    """Clear the logging context (call at end of request)."""
    _request_id.set(None)
    _user_id.set(None)
    _username.set(None)
    _client_ip.set(None)
    _trace_id.set(None)


def generate_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())


# =============================================================================
# Structured Logging Helpers
# =============================================================================

class StructuredLogger:
    """Helper class for creating structured log entries."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def _log(
        self,
        level: int,
        message: str,
        event_category: Optional[str] = None,
        event_action: Optional[str] = None,
        event_outcome: Optional[str] = None,
        event_duration: Optional[int] = None,
        http_method: Optional[str] = None,
        http_path: Optional[str] = None,
        http_status: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
        exc_info: bool = False,
    ) -> None:
        """Log with structured fields."""
        record_extra = {}
        if event_category:
            record_extra["event_category"] = event_category
        if event_action:
            record_extra["event_action"] = event_action
        if event_outcome:
            record_extra["event_outcome"] = event_outcome
        if event_duration:
            record_extra["event_duration"] = event_duration
        if http_method:
            record_extra["http_method"] = http_method
        if http_path:
            record_extra["http_path"] = http_path
        if http_status:
            record_extra["http_status"] = http_status
        if extra:
            record_extra["extra_fields"] = extra

        self.logger.log(level, message, extra=record_extra, exc_info=exc_info)

    def auth_event(
        self,
        action: str,
        outcome: str,
        username: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Log an authentication event.

        Args:
            action: login, logout, password_change, etc.
            outcome: success, failure
            username: Username involved
            reason: Failure reason if applicable
        """
        extra = {}
        if username:
            extra["target_username"] = username
        if reason:
            extra["failure_reason"] = reason

        level = logging.INFO if outcome == "success" else logging.WARNING
        self._log(
            level,
            f"Authentication {action}: {outcome}",
            event_category="authentication",
            event_action=action,
            event_outcome=outcome,
            extra=extra,
        )

    def access_event(
        self,
        resource_type: str,
        resource_id: Any,
        action: str,
        outcome: str = "success",
    ) -> None:
        """Log a resource access event.

        Args:
            resource_type: template, document, collection, etc.
            resource_id: ID of the resource
            action: read, create, update, delete
            outcome: success, failure, denied
        """
        level = logging.INFO if outcome == "success" else logging.WARNING
        self._log(
            level,
            f"{action.title()} {resource_type} {resource_id}: {outcome}",
            event_category="database",
            event_action=action,
            event_outcome=outcome,
            extra={"resource_type": resource_type, "resource_id": str(resource_id)},
        )

    def http_request(
        self,
        method: str,
        path: str,
        status: int,
        duration_ms: int,
        user_agent: Optional[str] = None,
    ) -> None:
        """Log an HTTP request.

        Args:
            method: GET, POST, etc.
            path: Request path
            status: Response status code
            duration_ms: Request duration in milliseconds
            user_agent: Client user agent
        """
        outcome = "success" if status < 400 else "failure"
        extra = {}
        if user_agent:
            extra["user_agent"] = user_agent

        self._log(
            logging.INFO,
            f"{method} {path} {status} {duration_ms}ms",
            event_category="web",
            event_action="http_request",
            event_outcome=outcome,
            event_duration=duration_ms * 1000000,  # Convert to nanoseconds for ECS
            http_method=method,
            http_path=path,
            http_status=status,
            extra=extra,
        )

    def error(
        self,
        message: str,
        error_type: Optional[str] = None,
        exc_info: bool = True,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an error event."""
        log_extra = extra or {}
        if error_type:
            log_extra["error_type"] = error_type

        self._log(
            logging.ERROR,
            message,
            event_category="process",
            event_action="error",
            event_outcome="failure",
            extra=log_extra,
            exc_info=exc_info,
        )

    def security_event(
        self,
        action: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a security-related event.

        Args:
            action: rate_limit_exceeded, invalid_token, permission_denied, etc.
            outcome: success (blocked), failure (allowed through)
            details: Additional context
        """
        level = logging.WARNING
        self._log(
            level,
            f"Security event: {action}",
            event_category="intrusion_detection",
            event_action=action,
            event_outcome=outcome,
            extra=details,
        )


def get_structured_logger(name: str) -> StructuredLogger:
    """Get a structured logger for the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        StructuredLogger instance
    """
    return StructuredLogger(logging.getLogger(name))


# =============================================================================
# Performance Logging Decorator
# =============================================================================

def log_performance(logger_name: Optional[str] = None):
    """Decorator to log function execution time.

    Args:
        logger_name: Logger name to use (defaults to function's module)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            name = logger_name or func.__module__
            logger = get_structured_logger(name)

            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = int((time.time() - start_time) * 1000)
                logger._log(
                    logging.DEBUG,
                    f"{func.__name__} completed in {duration_ms}ms",
                    event_category="process",
                    event_action="function_call",
                    event_outcome="success",
                    event_duration=duration_ms * 1000000,
                    extra={"function": func.__name__},
                )
                return result
            except Exception as e:
                duration_ms = int((time.time() - start_time) * 1000)
                logger._log(
                    logging.ERROR,
                    f"{func.__name__} failed after {duration_ms}ms: {e}",
                    event_category="process",
                    event_action="function_call",
                    event_outcome="failure",
                    event_duration=duration_ms * 1000000,
                    extra={"function": func.__name__},
                    exc_info=True,
                )
                raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            name = logger_name or func.__module__
            logger = get_structured_logger(name)

            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration_ms = int((time.time() - start_time) * 1000)
                logger._log(
                    logging.DEBUG,
                    f"{func.__name__} completed in {duration_ms}ms",
                    event_category="process",
                    event_action="function_call",
                    event_outcome="success",
                    event_duration=duration_ms * 1000000,
                    extra={"function": func.__name__},
                )
                return result
            except Exception as e:
                duration_ms = int((time.time() - start_time) * 1000)
                logger._log(
                    logging.ERROR,
                    f"{func.__name__} failed after {duration_ms}ms: {e}",
                    event_category="process",
                    event_action="function_call",
                    event_outcome="failure",
                    event_duration=duration_ms * 1000000,
                    extra={"function": func.__name__},
                    exc_info=True,
                )
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
