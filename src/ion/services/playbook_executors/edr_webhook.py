"""EDR adapter — ``quarantine_host`` active response.

Generic webhook: POST ``{exec_edr_url}/hosts/isolate`` with a bearer
token.  Maps cleanly to CrowdStrike Falcon (contain host), SentinelOne
(network quarantine), Defender for Endpoint (machine action "isolate"),
etc., when routed through a normalising proxy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ion.services.playbook_executors import ExecutorResult
from ion.services.playbook_executors._http import post_with_retry, resolve_verify
from ion.services.playbook_executors.audit import redact

ADAPTER_NAME = "edr_webhook"
SUPPORTED_ACTIONS = ("quarantine_host",)


def is_configured(config) -> bool:
    return bool(
        getattr(config, "exec_edr_url", "")
        and getattr(config, "exec_edr_api_key", "")
    )


async def execute(action_type: str, params: dict[str, Any], config) -> ExecutorResult:
    started = datetime.now(timezone.utc)
    target = str(params.get("target", "") or "")
    reason = params.get("reason") or "ION active response"

    request_body = {"hostname": target, "reason": reason}

    if action_type not in SUPPORTED_ACTIONS:
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"Unsupported action_type for EDR adapter: {action_type}",
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
            message=f"DRY_RUN — would POST /hosts/isolate for host {target}",
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
            message="EDR adapter not configured",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_body),
            response_payload={},
            error="not_configured",
        )

    base_url = str(getattr(config, "exec_edr_url", "")).rstrip("/")
    url = f"{base_url}/hosts/isolate"
    headers = {
        "Authorization": f"Bearer {config.exec_edr_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    timeout_s = float(getattr(config, "exec_default_timeout_s", 20))
    verify = resolve_verify(config, bool(getattr(config, "exec_edr_verify_ssl", True)))

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
            message=f"Quarantined host {target} via EDR",
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
        message=f"Failed to quarantine host {target}",
        started_at=started,
        completed_at=completed,
        request_payload=redact(request_body),
        response_payload=redact(result.response_json),
        error=result.error,
    )
