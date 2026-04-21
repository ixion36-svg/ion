"""Active-response executor adapters for ION playbook actions.

Each adapter implements an async ``execute(action_type, params, config)``
coroutine that performs the real side-effecting call (firewall webhook,
DNS sinkhole, EDR isolate, LDAP modify, etc.) and returns an
:class:`ExecutorResult` describing the outcome.

The :mod:`ion.services.playbook_executors.registry` module dispatches
``action_type`` values to the right adapter.  The
:mod:`ion.services.playbook_executor_service` module glues the registry
into the existing ``playbook_action_service`` approval/logging flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ExecutorResult:
    """Result of a single active-response execution.

    All fields must be populated by the adapter before returning.  The
    orchestrator (:mod:`playbook_executor_service`) uses the fields to
    write a ``PlaybookActionLog`` row (status, result JSON, error,
    duration).  ``request_payload``/``response_payload`` MUST be passed
    through :func:`ion.services.playbook_executors.audit.redact` before
    being set on the result, so secrets never reach the database.
    """

    success: bool
    adapter: str            # which adapter ran (e.g. "firewall_rest")
    action_type: str        # the action type invoked (e.g. "block_ip")
    target: str             # the target resource (IP, username, host, etc.)
    message: str            # human-readable outcome
    started_at: datetime    # tz-aware
    completed_at: datetime  # tz-aware
    request_payload: dict = field(default_factory=dict)   # redacted of secrets
    response_payload: dict = field(default_factory=dict)  # redacted of secrets
    error: Optional[str] = None
    dry_run: bool = False

    @property
    def duration_ms(self) -> int:
        """Total wall-clock duration of the execution in milliseconds."""
        delta = self.completed_at - self.started_at
        return int(delta.total_seconds() * 1000)

    def to_log_result(self) -> dict:
        """Serialise to the JSON structure stored in ``PlaybookActionLog.result``."""
        return {
            "success": self.success,
            "adapter": self.adapter,
            "action_type": self.action_type,
            "target": self.target,
            "message": self.message,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": self.duration_ms,
            "request": self.request_payload,
            "response": self.response_payload,
            "error": self.error,
            "dry_run": self.dry_run,
        }


__all__ = ["ExecutorResult"]
