"""Firewall REST adapter — ``block_ip`` active response.

Generic webhook-style integration: POST ``{exec_firewall_url}/blocklist``
with a bearer-token ``Authorization`` header.  Fits most modern next-gen
firewalls / orchestrators that expose a ``/blocklist`` endpoint
(PAN-OS+Panorama webhook, pfSense custom, FortiGate via script, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ion.services.playbook_executors import ExecutorResult
from ion.services.playbook_executors._http import post_with_retry, resolve_verify
from ion.services.playbook_executors.audit import redact

ADAPTER_NAME = "firewall_rest"
SUPPORTED_ACTIONS = ("block_ip",)


def is_configured(config) -> bool:
    return bool(
        getattr(config, "exec_firewall_url", "")
        and getattr(config, "exec_firewall_api_key", "")
    )


async def execute(action_type: str, params: dict[str, Any], config) -> ExecutorResult:
    """Execute a firewall block action.

    Args:
        action_type: Must be ``block_ip``.
        params: ``{"target": "<ip>", "reason": "<why>", "expires_at": "<iso8601>"}``.
                ``target`` is required; ``reason`` and ``expires_at`` are
                optional.
        config: ION Config instance.

    Returns:
        ExecutorResult describing the outcome.
    """
    started = datetime.now(timezone.utc)
    target = str(params.get("target", "") or "")
    reason = params.get("reason") or "ION active response"
    expires_at = params.get("expires_at")

    request_body = {"ip": target, "reason": reason}
    if expires_at:
        request_body["expires_at"] = expires_at

    if action_type not in SUPPORTED_ACTIONS:
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"Unsupported action_type for firewall adapter: {action_type}",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_body),
            response_payload={},
            error="unsupported_action_type",
        )

    if getattr(config, "exec_dry_run", True):
        return ExecutorResult(
            success=True,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"DRY_RUN — would POST /blocklist to firewall for IP {target}",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_body),
            response_payload={},
            dry_run=True,
        )

    if not is_configured(config):
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message="Firewall adapter not configured (missing exec_firewall_url / exec_firewall_api_key)",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_body),
            response_payload={},
            error="not_configured",
        )

    base_url = str(getattr(config, "exec_firewall_url", "")).rstrip("/")
    url = f"{base_url}/blocklist"
    headers = {
        "Authorization": f"Bearer {config.exec_firewall_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    timeout_s = float(getattr(config, "exec_default_timeout_s", 20))
    verify = resolve_verify(config, bool(getattr(config, "exec_firewall_verify_ssl", True)))

    result = await post_with_retry(
        url,
        json_body=request_body,
        headers=headers,
        timeout_s=timeout_s,
        verify_ssl=verify,
    )

    completed = datetime.now(timezone.utc)
    if result.success:
        return ExecutorResult(
            success=True,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"Blocked IP {target} at firewall",
            started_at=started,
            completed_at=completed,
            request_payload=redact(request_body),
            response_payload=redact(result.response_json),
        )

    return ExecutorResult(
        success=False,
        adapter=ADAPTER_NAME,
        action_type=action_type,
        target=target,
        message=f"Failed to block IP {target} at firewall",
        started_at=started,
        completed_at=completed,
        request_payload=redact(request_body),
        response_payload=redact(result.response_json),
        error=result.error,
    )
