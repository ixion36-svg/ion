"""Action-type → adapter dispatch registry.

Provides a central mapping from ``PlaybookAction.action_type`` to the
adapter module's async ``execute`` function, plus helpers to run an
adapter and to check whether its env-var config is populated.

The orchestrator (:mod:`ion.services.playbook_executor_service`) uses
this registry instead of hard-coding adapter imports, so new adapters
can be added by registering them here without touching the service.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

from ion.services.playbook_executors import (
    ExecutorResult,
    active_directory_ldap,
    dns_sinkhole,
    edr_webhook,
    email_gateway,
    firewall_rest,
    generic_webhook,
)

# Type alias: each adapter exposes ``async def execute(action_type, params, config)``.
AdapterExecute = Callable[[str, dict, object], Awaitable[ExecutorResult]]


# Primary routing table — action_type → adapter.
EXECUTORS: dict[str, AdapterExecute] = {
    "block_ip": firewall_rest.execute,
    "block_domain": dns_sinkhole.execute,
    "disable_account": active_directory_ldap.execute,
    "reset_password": active_directory_ldap.execute,
    "quarantine_host": edr_webhook.execute,
    "block_sender": email_gateway.execute,
    # Explicit catch-all — also used when target_integration == "webhook".
    "webhook": generic_webhook.execute,
}


# Map each action_type to the adapter module exposing ``is_configured(config)``.
_ADAPTER_BY_ACTION = {
    "block_ip": firewall_rest,
    "block_domain": dns_sinkhole,
    "disable_account": active_directory_ldap,
    "reset_password": active_directory_ldap,
    "quarantine_host": edr_webhook,
    "block_sender": email_gateway,
}


def is_adapter_configured(action_type: str, config) -> bool:
    """Return True if the adapter handling ``action_type`` has all required
    env vars set.  Returns False for unknown action types.  The generic
    webhook is considered "configured" because its endpoint is per-action.
    """
    if action_type == "webhook":
        return True
    adapter = _ADAPTER_BY_ACTION.get(action_type)
    if adapter is None:
        return False
    return bool(adapter.is_configured(config))


async def run_executor(
    action_type: str,
    target_integration: str,
    params: dict,
    config,
) -> ExecutorResult:
    """Dispatch to the right adapter and run it.

    If ``action_type`` has no direct mapping but ``target_integration``
    is ``webhook``, the generic webhook adapter is used as a catch-all.
    Unknown combinations return a failed :class:`ExecutorResult` with
    error ``unknown_action_type``.

    Args:
        action_type: ``PlaybookAction.action_type`` value.
        target_integration: ``PlaybookAction.target_integration`` value
            (used to select the generic webhook catch-all).
        params: Adapter-specific parameters — MUST contain ``target``.
        config: ION Config instance.
    """
    executor = EXECUTORS.get(action_type)
    if executor is None and (target_integration or "").lower() == "webhook":
        executor = generic_webhook.execute

    target = str(params.get("target", "") or "")

    if executor is None:
        now = datetime.now(timezone.utc)
        return ExecutorResult(
            success=False,
            adapter="unknown",
            action_type=action_type,
            target=target,
            message=(
                f"No executor registered for action_type='{action_type}' "
                f"(target_integration='{target_integration}')"
            ),
            started_at=now,
            completed_at=now,
            request_payload={},
            response_payload={},
            error="unknown_action_type",
        )

    return await executor(action_type, params, config)


__all__ = ["EXECUTORS", "is_adapter_configured", "run_executor"]
