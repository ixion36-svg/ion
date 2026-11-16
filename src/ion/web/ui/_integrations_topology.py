"""Topology reads retain each source's permission and expose no credentials."""

from __future__ import annotations

import asyncio
import logging
from typing import Literal, TypedDict
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.web import ai_api, api, elasticsearch_api, gitlab_api, integration_api, kibana_api
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)
router = APIRouter()
PERMISSION = require_permission("alert:read")
SERVICES = [
    ("elasticsearch", "Elasticsearch", 9200, "HTTPS", "Search & analytics engine"),
    ("kibana", "Kibana", 5601, "HTTPS", "Data visualization & dashboards"),
    ("gitlab", "GitLab", 8929, "HTTPS", "Source control & CI/CD"),
    ("opencti", "OpenCTI", 8080, "HTTP", "Threat intelligence platform"),
    ("tide", "TIDE", 443, "HTTPS", "Threat Informed Detection Engineering"),
    ("ollama", "Ollama", 11434, "HTTP", "Local AI model inference"),
    ("dfir_iris", "DFIR-IRIS", 8100, "HTTP", "Incident response platform"),
]


class ServicePanel(TypedDict):
    id: str
    name: str
    port: int
    protocol: str
    description: str
    state: Literal["failed", "data", "withheld"]
    status: Literal["healthy", "error", "disabled", "unknown"]
    response_ms: float | None
    version: str | None
    endpoint: str | None
    cluster_name: str | None
    cluster_status: str | None
    nodes: int | None
    indices: int | None
    model: str | None


class TopologyPanel(TypedDict):
    state: Literal["failed", "data"]
    services: list[ServicePanel]
    healthy: int
    errors: int
    disabled: int
    unknown: int
    percentage: int | None


def safe_endpoint(value: object) -> str | None:
    """Keep the useful address while dropping userinfo, query and fragment."""
    if not isinstance(value, str) or not value or value.endswith("..."):
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        host = "[" + parts.hostname + "]" if ":" in parts.hostname else parts.hostname
        port = ":" + str(parts.port) if parts.port is not None else ""
        return urlunsplit((parts.scheme, host + port, parts.path, "", ""))
    except ValueError:
        return None


def _number(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


async def read_service(service: str, user):
    """Call existing reads explicitly; never invoke a dependency default."""
    readers = {
        "elasticsearch": (elasticsearch_api.get_es_config_status, elasticsearch_api.test_es_connection),
        "kibana": (kibana_api.get_kibana_config_endpoint, kibana_api.get_kibana_status),
        "gitlab": (gitlab_api.get_gitlab_config_endpoint, gitlab_api.test_gitlab_connection),
        "opencti": (api.get_opencti_config_endpoint, api.test_opencti_connection),
        "dfir_iris": (api.get_iris_config_endpoint, api.test_iris_connection),
    }
    if service == "ollama":
        value = await ai_api.get_ai_status(current_user=user)
        value = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        return value, value
    if service == "tide":
        # The old client GET to /healthcheck was a 405. Read the recorded status;
        # explicit health checks remain the existing POST action.
        values = await integration_api.get_integration_status(current_user=user)
        for value in values if isinstance(values, list) else []:
            value = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
            if isinstance(value, dict) and value.get("type") == "tide":
                return {"enabled": value.get("is_enabled"), "configured": value.get("is_configured")}, value
        return None, None
    config_reader, test_reader = readers[service]
    config = await config_reader(current_user=user)
    if not isinstance(config, dict) or config.get("enabled") is False:
        return config, None
    return config, await test_reader(current_user=user)


async def _service(definition, user) -> ServicePanel:
    identifier, name, port, protocol, description = definition
    panel: ServicePanel = {
        "id": identifier,
        "name": name,
        "port": port,
        "protocol": protocol,
        "description": description,
        "state": "failed",
        "status": "unknown",
        "response_ms": None,
        "version": None,
        "endpoint": None,
        "cluster_name": None,
        "cluster_status": None,
        "nodes": None,
        "indices": None,
        "model": None,
    }
    if identifier == "gitlab" and not user.has_permission("template:read"):
        panel["state"] = "withheld"
        return panel
    try:
        config, result = await read_service(identifier, user)
    except Exception:
        logger.exception("Could not read topology service %s", identifier)
        return panel
    if not isinstance(config, dict) or not config:
        return panel
    panel["endpoint"] = safe_endpoint(config.get("url"))
    if config.get("enabled") is False or config.get("configured") is False:
        panel.update(state="data", status="disabled")
        return panel
    if hasattr(result, "model_dump"):
        result = result.model_dump(mode="json")
    if not isinstance(result, dict) or not result:
        return panel
    verdicts = [result.get(key) for key in ("connected", "available", "success")]
    status = result.get("status")
    if status is not None and not isinstance(status, str):
        return panel
    if status in {"error", "degraded"}:
        panel["status"] = "error"
    elif status == "disabled":
        panel["status"] = "disabled"
    elif any(value is True for value in verdicts) or status in {"ok", "healthy"} or _text(result.get("cluster_name")):
        panel["status"] = "healthy"
    elif any(value is False for value in verdicts):
        panel["status"] = "error"
    panel["state"] = "data" if panel["status"] != "unknown" else "failed"
    panel.update(
        version=_text(result.get("version")) or _text(result.get("server_version")),
        cluster_name=_text(result.get("cluster_name")),
        cluster_status=_text(result.get("cluster_status")),
        nodes=_number(result.get("node_count")),
        indices=_number(result.get("index_count")),
        model=_text(result.get("model")) or _text(result.get("default_model")),
    )
    response = result.get("response_time_ms")
    if isinstance(response, (int, float)) and not isinstance(response, bool) and response >= 0:
        panel["response_ms"] = response
    return panel


@router.get("/integrations/topology", response_class=HTMLResponse)
async def topology(request: Request, user=Depends(PERMISSION)):
    services = await asyncio.gather(*(_service(definition, user) for definition in SERVICES))
    counts = {status: sum(service["status"] == status for service in services) for status in ("healthy", "error", "disabled", "unknown")}
    configured = counts["healthy"] + counts["error"]
    percentage = round(counts["healthy"] / configured * 100) if configured and not counts["unknown"] else None
    view: TopologyPanel = {
        "state": "data" if any(service["state"] == "data" for service in services) else "failed",
        "services": services,
        "healthy": counts["healthy"],
        "errors": counts["error"],
        "disabled": counts["disabled"],
        "unknown": counts["unknown"],
        "percentage": percentage,
    }
    return render_view(request, "_fragments/integrations_topology.html", view)
