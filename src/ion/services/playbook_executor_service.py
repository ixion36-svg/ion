"""Orchestrator that bridges ``playbook_action_service`` to the real
adapter layer in :mod:`ion.services.playbook_executors`.

The existing ``playbook_action_service.execute_action`` simulates the
result.  This service exposes ``execute_action(...)`` returning an
:class:`ExecutorResult`; the caller (after approval gating + permission
checks + state-machine transitions already happen there) writes the
result into the ``PlaybookActionLog`` row the same way it wrote the
simulated one.

Design notes
------------
* Singleton pattern matches other ION services.
* Uses async ``httpx.AsyncClient`` (inside the adapters).
* Reads ``get_config()`` lazily so tests can swap the global.
* Writes to the supplied SQLAlchemy Session exactly like the existing
  simulation path — same status values, same ``result``/``error``
  columns — so downstream UI / log query code continues to work.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from sqlalchemy.orm import Session

from ion.core.config import get_config
from ion.models.sla import PlaybookAction, PlaybookActionLog
from ion.services.playbook_executors import ExecutorResult
from ion.services.playbook_executors.registry import (
    is_adapter_configured,
    run_executor,
)

logger = logging.getLogger(__name__)


class PlaybookExecutorService:
    """Thin orchestrator around the adapter registry."""

    def __init__(self) -> None:
        # Config is resolved per-call via ``get_config()`` so env-var
        # changes / test swaps take effect without a reset.
        pass

    # -- Adapter status ----------------------------------------------------

    def is_configured(self, action_type: str) -> bool:
        """Whether the adapter for ``action_type`` has the env vars it needs."""
        return is_adapter_configured(action_type, get_config())

    # -- Main entry point --------------------------------------------------

    async def execute_action(
        self,
        action_row: PlaybookAction,
        target_value: str,
        params: Optional[dict[str, Any]] = None,
        db: Optional[Session] = None,
    ) -> ExecutorResult:
        """Run the real adapter for ``action_row`` and (optionally) persist
        the result into ``PlaybookActionLog``.

        The caller in ``playbook_action_service`` is expected to have
        already performed approval gating, permission checks, and moved
        the log row into status ``executing``.  This method returns the
        :class:`ExecutorResult` so the caller can also mutate its own
        in-memory log entry; when ``db`` is passed, a NEW standalone
        ``PlaybookActionLog`` row is written too (useful when this
        service is invoked outside the approval flow, e.g. by
        automation).

        Args:
            action_row: The ``PlaybookAction`` being executed.
            target_value: The target string (IP, hostname, sAMAccountName, …).
            params: Adapter-specific extras merged on top of the action's
                ``config_template``.  Always includes ``{"target": target_value}``.
            db: Optional SQLAlchemy session.  When provided a standalone
                log row is inserted.

        Returns:
            :class:`ExecutorResult`.
        """
        config = get_config()

        # Merge action's config_template (if any) with supplied params.
        merged_params: dict[str, Any] = {}
        if action_row.config_template:
            try:
                tpl = json.loads(action_row.config_template)
                if isinstance(tpl, dict):
                    merged_params.update(tpl)
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "Action %s has invalid config_template JSON; ignoring",
                    action_row.id,
                )
        if params:
            merged_params.update(params)
        merged_params["target"] = target_value

        result = await run_executor(
            action_type=action_row.action_type,
            target_integration=action_row.target_integration or "",
            params=merged_params,
            config=config,
        )

        logger.info(
            "Executor ran: adapter=%s action_type=%s target=%s success=%s dry_run=%s",
            result.adapter,
            result.action_type,
            result.target,
            result.success,
            result.dry_run,
        )

        if db is not None:
            self._write_standalone_log(db, action_row, result)

        return result

    # -- Persistence -------------------------------------------------------

    def _write_standalone_log(
        self,
        db: Session,
        action_row: PlaybookAction,
        result: ExecutorResult,
    ) -> PlaybookActionLog:
        """Insert a fresh ``PlaybookActionLog`` row for this execution.

        Used when the caller didn't pre-create a log row via the
        approval flow (e.g. automation path).  Mirrors the field set
        the simulated path wrote so UI / queries stay consistent.
        """
        log_entry = PlaybookActionLog(
            action_id=action_row.id,
            executed_by_id=0,  # system / automation; caller can overwrite
            target=result.target,
            status="success" if result.success else "failed",
            result=json.dumps(result.to_log_result()),
            error=result.error,
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry

    def apply_result_to_log(
        self,
        db: Session,
        log_entry: PlaybookActionLog,
        result: ExecutorResult,
    ) -> PlaybookActionLog:
        """Mutate an existing ``PlaybookActionLog`` row with the result of
        an execution.  Preserves the simulated path's column layout:

        * ``status``     — ``"completed"`` on success, ``"failed"`` on error
                           (matches the existing simulated code path).
        * ``result``     — JSON string with the full ExecutorResult dict.
        * ``error``      — ``result.error`` (or ``None`` on success).

        The caller is responsible for ``session.commit()`` / ``refresh``
        because the existing service manages its own commit points.
        """
        log_entry.status = "completed" if result.success else "failed"
        log_entry.result = json.dumps(result.to_log_result())
        log_entry.error = result.error
        return log_entry


# Singleton
_playbook_executor_service: Optional[PlaybookExecutorService] = None


def get_playbook_executor_service() -> PlaybookExecutorService:
    """Get the global PlaybookExecutorService instance."""
    global _playbook_executor_service
    if _playbook_executor_service is None:
        _playbook_executor_service = PlaybookExecutorService()
    return _playbook_executor_service


def reset_playbook_executor_service() -> None:
    """Reset the singleton (for tests / config changes)."""
    global _playbook_executor_service
    _playbook_executor_service = None


__all__ = [
    "PlaybookExecutorService",
    "get_playbook_executor_service",
    "reset_playbook_executor_service",
]
