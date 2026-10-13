"""Allowlisted integration metric views; the page's alert:read gate is retained."""

from __future__ import annotations

import math
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import integration_api
from ion.web.ui._shared import render_view

router = APIRouter()
State = Literal["failed", "empty", "data"]


class Metric(TypedDict):
    key: str
    label: str
    value: int | float | None
    unit: str
    level: Literal["normal", "elevated", "high"]
    bar: bool


class ServerMetricsView(TypedDict):
    state: State
    metrics: list[Metric]


class ElasticsearchPanel(TypedDict):
    state: State
    metrics: list[Metric]
    status: str | None
    name: str | None


class ElasticsearchMetricsView(TypedDict):
    state: State
    configured: bool | None
    cluster: ElasticsearchPanel
    indices: ElasticsearchPanel


class DataFlowMetricsView(TypedDict):
    state: State
    metrics: list[Metric]


class ServerLogsMetricsView(TypedDict):
    state: State
    configured: bool | None
    metrics: list[Metric]


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _valid(value: Any) -> bool:
    return isinstance(value, dict) and not value.get("error")


def _measurements(value: Any) -> dict:
    return value if _valid(value) else {}


def _metric(key: str, label: str, value: Any, unit: str = "", *, bar: bool = False, alarm: bool = False) -> Metric:
    number = _number(value)
    if bar and number is not None and number > 100:
        number = None
    level = "normal"
    if number is not None:
        if bar:
            level = "high" if number > 80 else "elevated" if number > 60 else "normal"
        elif alarm and number > 0:
            level = "high"
        elif key == "success_rate" and number < 95:
            level = "elevated"
    return {"key": key, "label": label, "value": number, "unit": unit, "level": level, "bar": bar}


@router.get("/integrations/metrics/server", response_class=HTMLResponse)
async def server_metrics(request: Request, user=Depends(require_permission("alert:read"))):
    try:
        payload = await integration_api.get_server_metrics(current_user=user)
    except Exception:
        payload = None
    valid = _valid(payload) and any(_valid(payload.get(key)) for key in ("cpu", "memory", "disk", "process"))
    data = _mapping(payload) if valid else {}
    view: ServerMetricsView = {
        "state": "data" if valid else "failed",
        "metrics": [
            _metric("cpu", "CPU", _measurements(data.get("cpu")).get("percent"), "%", bar=True),
            _metric("memory", "Memory", _measurements(data.get("memory")).get("used_percent"), "%", bar=True),
            _metric("disk", "Disk", _measurements(data.get("disk")).get("used_percent"), "%", bar=True),
            _metric("process_memory", "Process memory", _measurements(data.get("process")).get("memory_mb"), " MB"),
            _metric("threads", "Process threads", _measurements(data.get("process")).get("threads")),
        ],
    }
    return render_view(request, "_fragments/integrations_metrics_server.html", view)


def _es_panel(payload: Any, configured: bool | None, fields: tuple[tuple[str, str, str], ...]) -> ElasticsearchPanel:
    state: State = "failed"
    if configured is False:
        state = "empty"
    elif configured is True and _valid(payload):
        state = "data"
    data = _mapping(payload) if state == "data" else {}
    status = data.get("status")
    name = data.get("cluster_name")
    return {
        "state": state,
        "metrics": [_metric(key, label, data.get(key), unit) for key, label, unit in fields],
        "status": status if status in ("green", "yellow", "red") else None,
        "name": name if isinstance(name, str) else None,
    }


@router.get("/integrations/metrics/elasticsearch", response_class=HTMLResponse)
async def elasticsearch_metrics(request: Request, user=Depends(require_permission("alert:read"))):
    try:
        payload = await integration_api.get_elasticsearch_metrics(current_user=user)
    except Exception:
        payload = None
    data = _mapping(payload)
    configured = data.get("configured") if isinstance(data.get("configured"), bool) else None
    if data.get("error") and configured is not False:
        configured = None
    cluster = _es_panel(
        data.get("cluster"),
        configured,
        (("number_of_nodes", "Nodes", ""), ("active_shards", "Shards", " active")),
    )
    indices = _es_panel(
        data.get("indices"),
        configured,
        (("total_docs", "Documents", ""), ("total_size_mb", "Size", " MB"), ("index_total", "Indexed", ""), ("search_total", "Searches", "")),
    )
    state: State = "failed"
    if configured is False:
        state = "empty"
    elif cluster["state"] == "data" or indices["state"] == "data":
        state = "data"
    view: ElasticsearchMetricsView = {
        "state": state,
        "configured": configured,
        "cluster": cluster,
        "indices": indices,
    }
    return render_view(request, "_fragments/integrations_metrics_elasticsearch.html", view)


@router.get("/integrations/metrics/data-flows", response_class=HTMLResponse)
async def data_flow_metrics(request: Request, session: Session = Depends(get_db_session), user=Depends(require_permission("alert:read"))):
    try:
        payload = await integration_api.get_data_flow_metrics(hours=24, session=session, current_user=user)
    except Exception:
        payload = None
    valid = _valid(payload) and any(_valid(payload.get(key)) for key in ("integration_activity", "webhooks"))
    data = _mapping(payload) if valid else {}
    activity = data["integration_activity"] if _valid(data.get("integration_activity")) else {}
    webhooks = data["webhooks"] if _valid(data.get("webhooks")) else {}
    levels = activity.get("by_level")
    errors = levels.get("error", 0) if isinstance(levels, dict) else None
    view: DataFlowMetricsView = {
        "state": "data" if valid else "failed",
        "metrics": [
            _metric("total", "Integration Logs", activity.get("total")),
            _metric("error", "Errors", errors, alarm=True),
            _metric("active_webhooks", "Active Webhooks", webhooks.get("active_webhooks")),
            _metric("total_webhooks", "Total Webhooks", webhooks.get("total_webhooks")),
            _metric("total_triggers", "Triggers", webhooks.get("total_triggers")),
        ],
    }
    return render_view(request, "_fragments/integrations_metrics_data_flows.html", view)


def _status_counts(value: Any) -> tuple[int | float | None, int | float | None, int | float | None]:
    if not isinstance(value, dict):
        return None, None, None
    counts = []
    for code, count in value.items():
        try:
            status = int(code)
        except (TypeError, ValueError):
            return None, None, None
        number = _number(count)
        if number is None or not 100 <= status <= 599:
            return None, None, None
        counts.append((status, number))
    return (
        sum(number for code, number in counts if 200 <= code < 400),
        sum(number for code, number in counts if 400 <= code < 500),
        sum(number for code, number in counts if 500 <= code < 600),
    )


@router.get("/integrations/metrics/server-logs", response_class=HTMLResponse)
async def server_logs_metrics(request: Request, user=Depends(require_permission("alert:read"))):
    try:
        payload = await integration_api.get_server_log_metrics(hours=24, current_user=user)
    except Exception:
        payload = None
    data = _mapping(payload)
    configured = data.get("configured") if isinstance(data.get("configured"), bool) else None
    valid = configured is True and _valid(payload)
    total = _number(data.get("total")) if valid else None
    success, client_errors, server_errors = _status_counts(data.get("by_status")) if valid else (None, None, None)
    requests = success + client_errors + server_errors if success is not None else None
    rate = success / requests * 100 if requests is not None and requests > 0 else None
    levels = data.get("by_level") if valid else None
    errors = levels.get("error", 0) if isinstance(levels, dict) else None
    state: State = "failed"
    if configured is False or (valid and total == 0):
        state = "empty"
    elif valid:
        state = "data"
    view: ServerLogsMetricsView = {
        "state": state,
        "configured": configured,
        "metrics": [
            _metric("total", "Total Logs", total),
            _metric("success_rate", "Success Rate", rate, "%"),
            _metric("error", "Errors", errors, alarm=True),
            _metric("success_count", "HTTP 2xx/3xx", success),
            _metric("client_errors", "HTTP 4xx", client_errors, alarm=True),
            _metric("server_errors", "HTTP 5xx", server_errors, alarm=True),
        ],
    }
    return render_view(request, "_fragments/integrations_metrics_server_logs.html", view)
