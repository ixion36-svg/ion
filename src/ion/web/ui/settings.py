"""Settings read surfaces preserve the stronger admin and wizard gates."""

from __future__ import annotations

from typing import Any, TypedDict
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_admin, require_permission
from ion.core.config import ENV_FIELD_MAP
from ion.models.user import User
from ion.web import admin_api
from ion.web.ui._integration_safety import safe_diagnostic
from ion.web.ui._shared import render_view, rows

router = APIRouter(
    prefix="/settings",
    default_response_class=HTMLResponse,
    dependencies=[Depends(require_permission("system:settings"))],
)


class SessionsView(TypedDict):
    state: str
    items: list[dict[str, Any]]


class BackupsView(TypedDict):
    state: str
    items: list[dict[str, Any]]


class WizardView(TypedDict):
    state: str
    items: list[dict[str, Any]]


class DatabaseView(TypedDict):
    state: str
    size: int | float | None
    total_tables: int | float | None
    total_rows: int | float | None
    items: list[dict[str, Any]]


class RecoveryView(TypedDict):
    state: str
    supported: bool | None
    backend: str
    target: str
    guidance: list[str] | None
    not_covered: list[str] | None


class SystemView(TypedDict):
    state: str
    technologies: list[dict[str, str]]
    details: list[dict[str, str]]
    packages: list[dict[str, str]] | None


class EnvironmentView(TypedDict):
    state: str
    items: list[dict[str, str]]


class LogsView(TypedDict):
    state: str
    items: list[dict[str, str]]


class InventoryView(TypedDict):
    state: str
    items: list[dict[str, Any]]
    total: int | None


def _text(value: object, fallback: str = "Unknown") -> str:
    return str(value) if isinstance(value, (str, int, float, bool)) else fallback


def _number(value: object) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _safe_url(value: object) -> str:
    """Diagnostic locations keep their host and path, never credentials."""
    text = _text(value)
    if "://" in text and text.endswith("..."):
        return "Address unavailable"
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.netloc:
            host = parts.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            if parts.port is not None:
                host += f":{parts.port}"
            return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except ValueError:
        return "Unknown"
    return text


async def _read(handler, **kwargs) -> dict | None:
    try:
        payload = await handler(**kwargs)
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("error"):
        return None
    return payload


def _state(items: list | None) -> str:
    return "failed" if items is None else "data" if items else "empty"


def _records(payload: dict | None, key: str) -> list[dict] | None:
    result = rows(payload, key)
    return result if result is not None and all(isinstance(item, dict) for item in result) else None


@router.get("/sessions")
async def sessions(request: Request, user: User = Depends(require_admin)):
    payload = await _read(admin_api.get_active_sessions, current_user=user)
    source = _records(payload, "sessions")
    items = []
    for item in source or []:
        items.append(
            {
                "user_id": item.get("user_id") if isinstance(item.get("user_id"), int) else None,
                "username": _text(item.get("username")),
                "email": _text(item.get("email"), "No email"),
                "last_login": _text(item.get("last_login"), "Never"),
                "roles": [_text(role) for role in item["roles"]] if isinstance(item.get("roles"), list) else None,
                "current": item.get("user_id") == user.id,
            }
        )
    view: SessionsView = {"state": _state(source), "items": items}
    return render_view(request, "_fragments/settings_sessions.html", view)


@router.get("/backups")
async def backups(request: Request, user: User = Depends(require_admin)):
    payload = await _read(admin_api.list_database_backups, current_user=user)
    source = _records(payload, "backups")
    items = [
        {
            "filename": _text(item.get("filename")),
            "actionable": isinstance(item.get("filename"), str) and bool(item["filename"]),
            "size": _number(item.get("size_mb")),
            "created_at": _text(item.get("created_at")),
        }
        for item in source or []
    ]
    view: BackupsView = {"state": _state(source), "items": items}
    return render_view(request, "_fragments/settings_backups.html", view)


@router.get("/wizard")
async def wizard(request: Request, user: User = Depends(require_permission("integration:manage"))):
    payload = await _read(admin_api.get_wizard_integrations, current_user=user)
    integrations = payload.get("integrations") if payload else None
    source = list(integrations.values()) if isinstance(integrations, dict) and all(isinstance(item, dict) for item in integrations.values()) else None
    items = [
        {
            "name": _text(item.get("name")),
            "configured": item.get("configured") if isinstance(item.get("configured"), bool) else None,
            "enabled": item.get("enabled") if isinstance(item.get("enabled"), bool) else None,
        }
        for item in source or []
    ]
    view: WizardView = {"state": _state(source), "items": items}
    return render_view(request, "_fragments/settings_wizard.html", view)


@router.get("/database")
async def database(request: Request, user: User = Depends(require_admin)):
    payload = await _read(admin_api.get_database_stats, current_user=user)
    source = _records(payload, "tables")
    payload = payload or {}
    view: DatabaseView = {
        "state": _state(source),
        "size": _number(payload.get("database_size_mb")),
        "total_tables": _number(payload.get("total_tables")),
        "total_rows": _number(payload.get("total_rows")),
        "items": [{"name": _text(item.get("name")), "count": _number(item.get("row_count"))} for item in source or []],
    }
    return render_view(request, "_fragments/settings_database.html", view)


@router.get("/recovery")
async def recovery(request: Request, user: User = Depends(require_admin)):
    payload = await _read(admin_api.get_recovery_capability, current_user=user)
    payload = payload or {}
    supported = payload.get("file_copy_supported")
    supported = supported if isinstance(supported, bool) else None
    view: RecoveryView = {
        "state": "failed" if supported is None else "data",
        "supported": supported,
        "backend": _text(payload.get("backend")),
        "target": _safe_url(payload.get("target")),
        "guidance": [_text(item) for item in payload["guidance"]] if isinstance(payload.get("guidance"), list) else None,
        "not_covered": [_text(item) for item in payload["not_covered"]] if isinstance(payload.get("not_covered"), list) else None,
    }
    return render_view(request, "_fragments/settings_recovery.html", view)


@router.get("/system")
async def system(request: Request, user: User = Depends(require_admin)):
    payload = await _read(admin_api.get_system_info, current_user=user)
    payload = payload or {}
    ai = payload.get("ai") if isinstance(payload.get("ai"), dict) else {}
    packages = payload.get("packages") if isinstance(payload.get("packages"), dict) else None
    technologies = [
        {"label": label, "value": _text(payload.get(key))}
        for label, key in (
            ("Application", "ion_version"),
            ("Runtime", "python_version"),
            ("Database", "database_type"),
        )
    ]
    technologies.extend(
        [
            {
                "label": "AI Model",
                "value": _text(ai.get("model")) if ai.get("enabled") is True else "Disabled" if ai.get("enabled") is False else "Unknown",
            },
            {"label": "Web Framework", "value": "FastAPI + Uvicorn"},
            {"label": "Auth", "value": "JWT + bcrypt + OIDC"},
            {
                "label": "AI Engine",
                "value": "Ollama" if ai.get("enabled") is True else "Disabled" if ai.get("enabled") is False else "Unknown",
            },
            {"label": "PCAP Analysis", "value": "dpkt"},
        ]
    )
    details = [
        {"label": label, "value": _text(payload.get(key))}
        for label, key in (
            ("Platform", "platform"),
            ("Architecture", "architecture"),
            ("Data Directory", "data_directory"),
            ("Database Size (MB)", "database_size_mb"),
            ("Config Path", "config_path"),
        )
    ]
    disk = payload.get("disk") if isinstance(payload.get("disk"), dict) else {}
    details.append(
        {
            "label": "Disk Usage",
            "value": f"{_text(disk.get('used_gb'))} / {_text(disk.get('total_gb'))} GB ({_text(disk.get('percent'))}%)",
        }
    )
    view: SystemView = {
        "state": "data" if payload else "failed",
        "technologies": technologies,
        "details": details,
        "packages": [{"name": _text(name), "version": _text(version)} for name, version in packages.items()] if packages is not None else None,
    }
    return render_view(request, "_fragments/settings_system.html", view)


@router.get("/environment")
async def environment(request: Request, user: User = Depends(require_admin)):
    payload = await _read(admin_api.get_environment_variables, current_user=user)
    variables = payload.get("variables") if payload else None
    source = variables if isinstance(variables, dict) else None
    items = []
    for name, value in (source or {}).items():
        if not isinstance(name, str) or not name.startswith("ION_"):
            continue
        masked = admin_api.mask_env_value(name, _text(value, ""))
        secret = any(hint in name.lower() for hint in ("password", "secret", "token", "key", "license", "credential", "dsn"))
        shown = "Configuration status unknown"
        if isinstance(value, str):
            shown = "Not configured" if value in ("", "(not set)") else "Currently set"
        items.append({"name": name, "value": shown if secret else _safe_url(masked)})
    view: EnvironmentView = {"state": _state(None if source is None else items), "items": items}
    return render_view(request, "_fragments/settings_environment.html", view)


@router.get("/logs")
async def logs(
    request: Request,
    limit: int = 200,
    level: str | None = None,
    search: str | None = None,
    user: User = Depends(require_admin),
):
    payload = await _read(admin_api.get_system_logs, limit=limit, level=level, logger_name=None, search=search)
    source = _records(payload, "logs")
    items = []
    for item in source or []:
        severity = item.get("level")
        severity = severity if severity in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "UNKNOWN"
        model = {
            key: _text(item.get(key), "")
            for key in (
                "timestamp",
                "logger",
                "function",
                "file",
                "line",
                "username",
                "client_ip",
                "request_id",
            )
        }
        model.update(
            {
                "message": safe_diagnostic(item.get("message")),
                "exception": safe_diagnostic(item.get("exception")),
                "level": severity,
            }
        )
        items.append(model)
    view: LogsView = {"state": _state(source), "items": items}
    return render_view(request, "_fragments/settings_logs.html", view)


@router.get("/inventory")
async def inventory(
    request: Request,
    search: str = "",
    non_default: bool = False,
    user: User = Depends(require_permission("system:settings")),
):
    payload = await _read(admin_api.get_configuration, current_user=user)
    source = _records(payload, "inventory")
    items = []
    for item in source or []:
        field = item.get("field")
        if not isinstance(field, str) or field not in admin_api.config_field_names():
            continue
        secret = admin_api._is_secret_field(field) or item.get("is_secret") is True or item.get("kind") == "secret"
        kind = "secret" if secret else item.get("kind")
        if kind not in ("secret", "bool", "int", "float", "text"):
            kind = admin_api._field_kind(field)
        value = item.get("value")
        available = item.get("available") if isinstance(item.get("available"), bool) else None
        safe_value = None if secret else value if value is None or isinstance(value, (bool, int, float)) else _safe_url(value)
        redacted = not secret and isinstance(value, str) and safe_value != value
        source_name = item.get("source") if item.get("source") in ("environment", "file", "default") else "unknown"
        model = {
            "field": field,
            "env_var": ENV_FIELD_MAP.get(field),
            "kind": kind,
            "value": safe_value,
            "secret_set": bool(value) if available is True and value is not None else None,
            "available": available,
            "source": source_name,
            "writable": item.get("writable") is True and source_name != "environment" and not redacted,
            "write_blocked_by": "environment" if source_name == "environment" else "credentials" if redacted else "policy",
            "restart": field in admin_api._RESTART_REQUIRED,
        }
        items.append(model)
    total = len(items) if source is not None else None
    term = search.strip().lower()
    items = [item for item in items if (not non_default or item["source"] != "default") and (not term or any(term in _text(item[key], "").lower() for key in ("field", "env_var", "value")))]
    view: InventoryView = {
        "state": _state(None if source is None else items),
        "items": items,
        "total": total,
    }
    return render_view(request, "_fragments/settings_inventory.html", view)


# Only fields consumed by populateForms may cross this boundary.
_FORM_FIELDS = {
    "general": (
        "default_format",
        "max_versions_to_keep",
        "auto_save",
        "cookie_secure",
    ),
    "elasticsearch": (
        "elasticsearch_enabled",
        "elasticsearch_url",
        "elasticsearch_username",
        "elasticsearch_alert_index",
        "elasticsearch_case_index",
        "elasticsearch_verify_ssl",
        "elasticsearch_user_index",
        "elasticsearch_user_field",
        "elasticsearch_assignment_field",
        "elasticsearch_password_set",
        "elasticsearch_api_key_set",
    ),
    "gitlab": (
        "gitlab_enabled",
        "gitlab_url",
        "gitlab_project_id",
        "gitlab_verify_ssl",
        "gitlab_sudo_enabled",
        "gitlab_token_set",
    ),
    "opencti": (
        "opencti_enabled",
        "opencti_url",
        "opencti_verify_ssl",
        "opencti_token_set",
    ),
    "kibana": (
        "kibana_cases_enabled",
        "kibana_url",
        "kibana_username",
        "kibana_space_id",
        "kibana_case_owner",
        "kibana_verify_ssl",
        "kibana_password_set",
    ),
    "dfir_iris": (
        "dfir_iris_enabled",
        "dfir_iris_url",
        "dfir_iris_default_customer",
        "dfir_iris_verify_ssl",
        "dfir_iris_api_key_set",
    ),
    "tide": (
        "tide_enabled",
        "tide_url",
        "tide_space",
        "tide_client_id",
        "tide_verify_ssl",
        "tide_api_key_set",
    ),
    "arkime": (
        "arkime_enabled",
        "arkime_url",
        "arkime_verify_ssl",
        "arkime_username",
    ),
    "ollama": (
        "ollama_enabled",
        "ollama_url",
        "ollama_model",
        "ollama_timeout",
        "ollama_verify_ssl",
    ),
    "abuseipdb": (
        "abuseipdb_enabled",
        "abuseipdb_api_key_set",
    ),
    "virustotal": (
        "virustotal_enabled",
        "virustotal_api_key_set",
    ),
    "oidc": (
        "base_url",
        "oidc_enabled",
        "oidc_keycloak_url",
        "oidc_realm",
        "oidc_client_id",
        "oidc_role_claim",
        "oidc_auto_create_users",
        "oidc_verify_ssl",
        "oidc_client_secret_set",
    ),
}


class ConfigurationView(TypedDict):
    state: str
    configuration: dict[str, dict[str, Any]]
    sources: dict[str, str]
    source_env_names: dict[str, str]
    locked_fields: list[str]
    unavailable_fields: list[str]


@router.get("/configuration")
async def configuration(request: Request, user: User = Depends(require_permission("system:settings"))):
    payload = await _read(admin_api.get_configuration, current_user=user)
    payload = payload or {}
    result = {}
    locked = []
    unavailable = []
    for section, fields in _FORM_FIELDS.items():
        source = payload.get(section)
        source = source if isinstance(source, dict) else {}
        result[section] = {}
        for field in fields:
            value = source.get(field)
            if field not in source and not field.endswith("_set"):
                unavailable.append(field)
            if field.endswith("_set"):
                result[section][field] = value if isinstance(value, bool) else None
            elif admin_api._is_secret_field(field):
                continue
            elif isinstance(value, str):
                safe = _safe_url(value)
                result[section][field] = safe
                if safe != value:
                    locked.append(field)
            else:
                result[section][field] = value if value is None or isinstance(value, (bool, int, float)) else None
    source_fields = payload.get("sources")
    sources = {}
    if isinstance(source_fields, dict):
        for field, source in source_fields.items():
            if field in admin_api.config_field_names() and source in (
                "environment",
                "file",
                "default",
            ):
                sources[field] = source
    view: ConfigurationView = {
        "state": "data" if payload else "failed",
        "configuration": result,
        "sources": sources,
        "source_env_names": dict(ENV_FIELD_MAP),
        "locked_fields": locked,
        "unavailable_fields": unavailable,
    }
    return render_view(request, "_fragments/settings_configuration.html", view)
