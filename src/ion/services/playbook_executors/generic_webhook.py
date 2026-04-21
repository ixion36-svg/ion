"""Generic webhook adapter — catch-all for unknown ``action_type`` values
whose ``PlaybookAction.target_integration`` is ``webhook``.

The per-action endpoint comes from ``params['target_endpoint']`` (or
``params['endpoint']``) — typically stored in the
``PlaybookAction.config_template`` JSON and merged into params by the
orchestrator.  A bearer token (optional) is read from
``params['api_key']`` or falls back to ``config.exec_generic_webhook_api_key``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ion.services.playbook_executors import ExecutorResult
from ion.services.playbook_executors._http import post_with_retry, resolve_verify
from ion.services.playbook_executors.audit import redact

ADAPTER_NAME = "generic_webhook"


async def execute(action_type: str, params: dict[str, Any], config) -> ExecutorResult:
    started = datetime.now(timezone.utc)
    target = str(params.get("target", "") or "")

    # Pull the per-action endpoint out of params (action's config template
    # should provide ``target_endpoint``; fall back to ``endpoint``).
    endpoint = (
        params.get("target_endpoint")
        or params.get("endpoint")
        or ""
    )

    # Build request body from params minus adapter-wiring keys.
    omit_keys = {"target_endpoint", "endpoint", "api_key", "verify_ssl"}
    request_body = {k: v for k, v in params.items() if k not in omit_keys}
    request_body.setdefault("action_type", action_type)
    request_body.setdefault("target", target)

    if not endpoint:
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message="Generic webhook requires params['target_endpoint']",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_body),
            response_payload={},
            error="missing_target_endpoint",
        )

    if getattr(config, "exec_dry_run", True):
        return ExecutorResult(
            success=True,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"DRY_RUN — would POST {endpoint} for {action_type}({target})",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_body),
            response_payload={},
            dry_run=True,
        )

    # Resolve auth — per-action api_key wins, else fall back to a global.
    api_key = params.get("api_key") or getattr(config, "exec_generic_webhook_api_key", "")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    timeout_s = float(getattr(config, "exec_default_timeout_s", 20))
    per_action_verify = params.get("verify_ssl")
    if per_action_verify is None:
        per_action_verify = True
    verify = resolve_verify(config, bool(per_action_verify))

    result = await post_with_retry(
        str(endpoint),
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
            message=f"Webhook {action_type} dispatched to {endpoint}",
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
        message=f"Webhook {action_type} to {endpoint} failed",
        started_at=started,
        completed_at=completed,
        request_payload=redact(request_body),
        response_payload=redact(result.response_json),
        error=result.error,
    )
