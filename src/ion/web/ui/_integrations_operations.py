"""Integration operations reads, gated by the page's alert:read permission.

Only display fields cross the view boundary. Webhook credentials, delivery
payloads and headers never enter either HTML or the negotiated JSON view.
"""

from __future__ import annotations

import math
from typing import Optional, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.integration import IntegrationType, LogLevel
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web import integration_api as api
from ion.web.ui._integration_safety import safe_diagnostic
from ion.web.ui._shared import plain, render_view

router = APIRouter(default_response_class=HTMLResponse)


class StatusItem(TypedDict):
    type: str
    name: str
    status: str
    configured: Optional[bool]
    enabled: Optional[bool]
    response_time_ms: Optional[float]
    version: Optional[str]
    compatible: Optional[bool]


class StatusView(TypedDict):
    state: str
    items: list[StatusItem]
    can_manage: bool


class WebhookItem(TypedDict):
    id: Optional[int]
    name: str
    source_type: str
    active: Optional[bool]
    trigger_count: Optional[float]


class WebhooksView(TypedDict):
    state: str
    items: list[WebhookItem]
    can_manage: bool


class WebhookLogItem(TypedDict):
    timestamp: str
    event_type: str
    status: str
    source_ip: str
    processing_time_ms: Optional[float]


class WebhookLogsView(TypedDict):
    state: str
    items: list[WebhookLogItem]


class IntegrationLogItem(TypedDict):
    timestamp: str
    integration_type: str
    level: str
    action: str
    message: str


class IntegrationLogsView(TypedDict):
    state: str
    items: list[IntegrationLogItem]


def _mapping(value):
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise ValueError("Unexpected row shape")


def _list(value):
    if not isinstance(value, list):
        raise ValueError("Unexpected collection shape")
    return [_mapping(item) for item in value]


def _text(value, default="Unknown"):
    value = plain(value)
    return value if isinstance(value, str) and value else default


def _number(value):
    if isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value):
        return value
    return None


def _bool(value):
    return value if isinstance(value, bool) else None


@router.get("/integrations/status")
async def status_fragment(
    request: Request,
    user: User = Depends(require_permission("alert:read")),
):
    items = []
    state = "failed"
    try:
        source = _list(await api.get_integration_status(current_user=user))
        for item in source:
            metadata = item.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            compatibility = metadata.get("version_compatibility")
            compatibility = compatibility if isinstance(compatibility, dict) else {}
            configured = _bool(item.get("is_configured"))
            status = _text(item.get("status"), "")
            if not status:
                if configured is True:
                    status = "Configured"
                elif configured is False:
                    status = "Not configured"
                else:
                    status = "Unknown"
            items.append(
                StatusItem(
                    type=_text(item.get("type"), ""),
                    name=_text(item.get("display_name")),
                    status=status,
                    configured=configured,
                    enabled=_bool(item.get("is_enabled")),
                    response_time_ms=_number(item.get("response_time_ms")),
                    version=_text(metadata.get("version"), "") or None,
                    compatible=_bool(compatibility.get("in_range")),
                )
            )
        state = "data" if items else "empty"
    except Exception:
        items = []
    view = StatusView(state=state, items=items, can_manage=user.has_permission("integration:manage"))
    return render_view(request, "_fragments/integrations_ops_status.html", view)


@router.get("/integrations/webhooks")
def webhooks_fragment(
    request: Request,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    items = []
    state = "failed"
    try:
        source = _list(api.list_webhooks(source_type=None, is_active=None, session=session, current_user=user))
        for item in source:
            identifier = item.get("id")
            items.append(
                WebhookItem(
                    id=identifier if isinstance(identifier, int) and not isinstance(identifier, bool) else None,
                    name=_text(item.get("name")),
                    source_type=_text(item.get("source_type")),
                    active=_bool(item.get("is_active")),
                    trigger_count=_number(item.get("trigger_count")),
                )
            )
        state = "data" if items else "empty"
    except Exception:
        items = []
    view = WebhooksView(state=state, items=items, can_manage=user.has_permission("integration:manage"))
    return render_view(request, "_fragments/integrations_ops_webhooks.html", view)


@router.get("/integrations/webhooks/{webhook_id}/logs")
def webhook_logs_fragment(
    request: Request,
    webhook_id: int,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    items = []
    state = "failed"
    try:
        source = _list(api.get_webhook_logs(webhook_id=webhook_id, status=None, limit=50, offset=0, session=session, current_user=user))
        for item in source:
            items.append(
                WebhookLogItem(
                    timestamp=_text(item.get("created_at")),
                    event_type=_text(item.get("event_type")),
                    status=_text(item.get("status")),
                    source_ip=_text(item.get("source_ip")),
                    processing_time_ms=_number(item.get("processing_time_ms")),
                )
            )
        state = "data" if items else "empty"
    except Exception:
        items = []
    view = WebhookLogsView(state=state, items=items)
    return render_view(request, "_fragments/integrations_ops_webhook_logs.html", view)


@router.get("/integrations/logs")
def logs_fragment(
    request: Request,
    integration_type: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    items = []
    state = "failed"
    try:
        # The JSON adapter catches a failed service read into an empty list.
        # Use its service directly so an outage remains visibly unavailable.
        source = _list(
            api.get_integration_log_service().get_logs(
                integration_type=IntegrationType(integration_type) if integration_type else None,
                level=LogLevel(level) if level else None,
                action=None,
                hours=24,
                limit=100,
                offset=0,
                session=session,
            )
        )
        for item in source:
            items.append(
                IntegrationLogItem(
                    timestamp=_text(item.get("created_at", item.get("timestamp"))),
                    integration_type=_text(item.get("integration_type")),
                    level=_text(item.get("level")),
                    action=_text(item.get("action")),
                    message=safe_diagnostic(_text(item.get("message"))),
                )
            )
        state = "data" if items else "empty"
    except Exception:
        items = []
    view = IntegrationLogsView(state=state, items=items)
    return render_view(request, "_fragments/integrations_ops_logs.html", view)
