"""ION MCP (Model Context Protocol) server — Streamable HTTP transport.

Exposes ION's core SOC data as MCP tools at ``POST /api/mcp``.
Follows the 2025-03-26 protocol spec (JSON-RPC 2.0 over HTTP, no SSE).

Supported JSON-RPC methods
--------------------------
  initialize              → server capabilities handshake
  ping                    → keepalive
  notifications/*         → silently acknowledged (HTTP 202)
  tools/list              → list of tools the caller has permission to use
  tools/call              → dispatch to a named tool

Tools (all read-only unless noted)
-----------------------------------
  list_alerts             alert:read      recent AlertTriage rows from the ION DB
  get_alert               alert:read      single AlertTriage by ID
  list_cases              case:read       AlertCase list with summary fields
  get_case                case:read       AlertCase detail with notes
  search_observables      observable:read full-text + type + threat-level search
  get_observable          observable:read Observable detail with enrichment records
  list_playbooks          playbook:read   Playbook catalogue
  add_case_note           case:update     append a Note to an AlertCase  [write]

Feature flag — OFF by default
------------------------------
The whole endpoint is gated behind ``ION_MCP_ENABLED`` and is **disabled
unless explicitly toggled on** (``ION_MCP_ENABLED=true|1|yes``).  This is a
new network-facing surface, so it follows ION's opt-in hardening convention
(cf. the v0.39.3–v0.39.4 controls): when the flag is off, ``/api/mcp`` returns
``404 Not Found`` — the route is indistinguishable from a non-existent one, so
the surface isn't even advertised to an unauthenticated caller.

Auth
----
Accepts the ION session cookie (``ion_session``) OR an
``Authorization: Bearer <token>`` header.  Authentication is validated on a
**short-lived** DB session that is closed before any tool DB work — matching
the pattern established in ``events_api.py`` for SSE streams.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import selectinload

from ion.auth.dependencies import SESSION_COOKIE_NAME
from ion.auth.service import AuthService
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    Note,
    NoteEntityType,
)
from ion.models.observable import Observable
from ion.models.user import User
from ion.services.kibana_sync_helpers import sync_note_to_kibana
from ion.services.observable_service import ObservableService
from ion.storage.database import get_session_factory
from ion.storage.playbook_repository import PlaybookRepository

try:
    import ion as _ion_pkg

    _ION_VERSION = _ion_pkg.__version__
except (ImportError, AttributeError):
    _ION_VERSION = "unknown"

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mcp"])

_MCP_VERSION = "2025-03-26"
_SERVER_INFO = {"name": "ION MCP Server", "version": _ION_VERSION}

# Truthy env values that enable the (default-off) feature flag.
_TRUTHY = {"true", "1", "yes", "on"}


def mcp_enabled() -> bool:
    """Feature flag — **OFF by default**.

    The MCP endpoint is a new external-facing surface, so it stays closed
    unless an operator explicitly sets ``ION_MCP_ENABLED`` to a truthy value.
    When off, ``/api/mcp`` returns 404 (route hidden entirely).
    """
    return os.getenv("ION_MCP_ENABLED", "").strip().lower() in _TRUTHY

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
# Each entry has a private ``_permission`` key (stripped before sending to
# clients) so the permission check lives next to the schema definition.

_TOOLS: list[dict] = [
    {
        "name": "list_alerts",
        "description": (
            "List recent security alerts tracked in ION's triage database. "
            "Returns status, priority, rule name, and MITRE technique annotations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["open", "acknowledged", "closed"],
                    "description": "Filter by triage status.",
                },
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 200,
                    "description": "Maximum number of alerts to return.",
                },
            },
        },
        "_permission": "alert:read",
    },
    {
        "name": "get_alert",
        "description": (
            "Get full detail for a single ION alert triage entry by its ION database ID "
            "(AlertTriage.id — not the Elasticsearch alert ID)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "integer", "description": "ION AlertTriage.id"},
            },
            "required": ["alert_id"],
        },
        "_permission": "alert:read",
    },
    {
        "name": "list_cases",
        "description": (
            "List investigation cases in ION. Each case groups one or more alerts "
            "into a named incident with severity, ownership, and closure metadata."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["open", "acknowledged", "closed"],
                    "description": "Filter by case status.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Filter by severity.",
                },
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 200,
                },
            },
        },
        "_permission": "case:read",
    },
    {
        "name": "get_case",
        "description": (
            "Get full detail for a security case including linked alert count, "
            "affected hosts/users, evidence summary, and analyst notes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "integer", "description": "AlertCase.id"},
            },
            "required": ["case_id"],
        },
        "_permission": "case:read",
    },
    {
        "name": "search_observables",
        "description": (
            "Search observables (IP addresses, domains, file hashes, URLs, CVEs, etc.) "
            "tracked in ION. Supports free-text, type, and threat-level filters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Free-text search against observable value.",
                },
                "type": {
                    "type": "string",
                    "enum": [
                        "ipv4", "ipv6", "domain", "url", "email",
                        "md5", "sha1", "sha256", "filename", "user_account",
                        "mac", "cve",
                    ],
                    "description": "Filter by observable type.",
                },
                "threat_level": {
                    "type": "string",
                    "enum": ["unknown", "benign", "low", "medium", "high", "critical"],
                    "description": "Filter by threat level.",
                },
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 200,
                },
            },
        },
        "_permission": "observable:read",
    },
    {
        "name": "get_observable",
        "description": (
            "Get full detail for a tracked observable including enrichment records "
            "from OpenCTI / VirusTotal and watchlist / IOC flags."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "observable_id": {"type": "integer", "description": "Observable.id"},
            },
            "required": ["observable_id"],
        },
        "_permission": "observable:read",
    },
    {
        "name": "list_playbooks",
        "description": "List response playbooks configured in ION.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "When true, return only active playbooks.",
                },
            },
        },
        "_permission": "playbook:read",
    },
    {
        "name": "add_case_note",
        "description": "Append an analyst note (markdown supported) to an investigation case.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "integer", "description": "AlertCase.id"},
                "content": {"type": "string", "description": "Note body (markdown supported)."},
            },
            "required": ["case_id", "content"],
        },
        "_permission": "case:update",
    },
]

_TOOL_BY_NAME: dict[str, dict] = {t["name"]: t for t in _TOOLS}


def _public_tool(t: dict) -> dict:
    return {k: v for k, v in t.items() if not k.startswith("_")}


# ---------------------------------------------------------------------------
# Auth — short-lived session (same pattern as events_api.py)
# ---------------------------------------------------------------------------

def _authenticate(request: Request) -> Optional[User]:
    """Return the User for a valid session token, or None."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        return None
    session = get_session_factory()()
    try:
        return AuthService(session).validate_session(token)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _ok(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_err(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tool_result(data: Any) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps(data, default=str)}],
        "isError": False,
    }


def _tool_error(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

_CASE_STATUS_MAP = {s.value: s for s in AlertCaseStatus}
_ALERT_STATUS_MAP = {s.value: s for s in AlertTriageStatus}


def _tool_list_alerts(args: dict) -> dict:
    raw_status = args.get("status")
    limit = max(1, min(int(args.get("limit", 50)), 200))

    status_val = None
    if raw_status:
        status_val = _ALERT_STATUS_MAP.get(raw_status)
        if status_val is None:
            return _tool_error(f"Invalid status '{raw_status}'.")

    session = get_session_factory()()
    try:
        q = session.query(AlertTriage)
        if status_val is not None:
            q = q.filter(AlertTriage.status == status_val)
        rows = q.order_by(AlertTriage.updated_at.desc()).limit(limit).all()
        return _tool_result({
            "alerts": [
                {
                    "id": r.id,
                    "es_alert_id": r.es_alert_id,
                    "rule_name": r.rule_name,
                    "status": r.status.value if hasattr(r.status, "value") else r.status,
                    "priority": r.priority,
                    "case_id": r.case_id,
                    "mitre_techniques": r.mitre_techniques,
                    "source_system": r.source_system,
                    "suggested_verdict": r.suggested_verdict,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                }
                for r in rows
            ],
            "total": len(rows),
        })
    finally:
        session.close()


def _tool_get_alert(args: dict) -> dict:
    alert_id = args.get("alert_id")
    if not isinstance(alert_id, int):
        return _tool_error("alert_id must be an integer.")
    session = get_session_factory()()
    try:
        row = session.query(AlertTriage).filter_by(id=alert_id).first()
        if not row:
            return _tool_error(f"Alert {alert_id} not found.")
        return _tool_result({
            "id": row.id,
            "es_alert_id": row.es_alert_id,
            "rule_name": row.rule_name,
            "status": row.status.value if hasattr(row.status, "value") else row.status,
            "priority": row.priority,
            "case_id": row.case_id,
            "analyst_notes": row.analyst_notes,
            "observables": row.observables,
            "mitre_techniques": row.mitre_techniques,
            "source_system": row.source_system,
            "suggested_verdict": row.suggested_verdict,
            "suggested_verdict_confidence_int": row.suggested_verdict_confidence_int,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        })
    finally:
        session.close()


def _tool_list_cases(args: dict) -> dict:
    raw_status = args.get("status")
    raw_severity = args.get("severity")
    limit = max(1, min(int(args.get("limit", 50)), 200))

    status_val = None
    if raw_status:
        status_val = _CASE_STATUS_MAP.get(raw_status)
        if status_val is None:
            return _tool_error(f"Invalid status '{raw_status}'.")

    session = get_session_factory()()
    try:
        q = session.query(AlertCase).options(
            selectinload(AlertCase.created_by),
            selectinload(AlertCase.assigned_to),
        )
        if status_val is not None:
            q = q.filter(AlertCase.status == status_val)
        if raw_severity:
            q = q.filter(AlertCase.severity == raw_severity)
        cases = q.order_by(AlertCase.created_at.desc()).limit(limit).all()
        return _tool_result({
            "cases": [
                {
                    "id": c.id,
                    "case_number": c.case_number,
                    "title": c.title,
                    "status": c.status.value if hasattr(c.status, "value") else c.status,
                    "severity": c.severity,
                    "created_by": c.created_by.username if c.created_by else None,
                    "assigned_to": c.assigned_to.username if c.assigned_to else None,
                    "closure_reason": c.closure_reason,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                }
                for c in cases
            ],
            "total": len(cases),
        })
    finally:
        session.close()


def _tool_get_case(args: dict) -> dict:
    case_id = args.get("case_id")
    if not isinstance(case_id, int):
        return _tool_error("case_id must be an integer.")
    session = get_session_factory()()
    try:
        case = (
            session.query(AlertCase)
            .options(
                selectinload(AlertCase.created_by),
                selectinload(AlertCase.assigned_to),
                selectinload(AlertCase.triage_entries),
                selectinload(AlertCase.notes),
            )
            .filter_by(id=case_id)
            .first()
        )
        if not case:
            return _tool_error(f"Case {case_id} not found.")
        return _tool_result({
            "id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "description": case.description,
            "status": case.status.value if hasattr(case.status, "value") else case.status,
            "severity": case.severity,
            "created_by": case.created_by.username if case.created_by else None,
            "assigned_to": case.assigned_to.username if case.assigned_to else None,
            "closure_reason": case.closure_reason,
            "closure_notes": case.closure_notes,
            "affected_hosts": case.affected_hosts,
            "affected_users": case.affected_users,
            "triggered_rules": case.triggered_rules,
            "evidence_summary": case.evidence_summary,
            "alert_count": len(case.triage_entries),
            "notes": [
                {
                    "id": n.id,
                    "content": n.content,
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                }
                for n in (case.notes or [])
            ],
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        })
    finally:
        session.close()


def _tool_search_observables(args: dict) -> dict:
    query = args.get("query") or None
    obs_type = args.get("type") or None
    threat_level = args.get("threat_level") or None
    limit = max(1, min(int(args.get("limit", 50)), 200))

    session = get_session_factory()()
    try:
        svc = ObservableService(session)
        results, total = svc.search(
            query=query,
            types=[obs_type] if obs_type else None,
            threat_level=threat_level,
            limit=limit,
        )
        return _tool_result({
            "observables": [
                {
                    "id": o.id,
                    "type": o.type.value if hasattr(o.type, "value") else o.type,
                    "value": o.value,
                    "threat_level": (
                        o.threat_level.value if hasattr(o.threat_level, "value") else o.threat_level
                    ),
                    "sighting_count": o.sighting_count,
                    "is_ioc": o.is_ioc,
                    "is_watched": o.is_watched,
                    "is_ignored": o.is_ignored,
                    "first_seen": o.first_seen.isoformat() if o.first_seen else None,
                    "last_seen": o.last_seen.isoformat() if o.last_seen else None,
                }
                for o in results
            ],
            "total": total,
        })
    finally:
        session.close()


def _tool_get_observable(args: dict) -> dict:
    obs_id = args.get("observable_id")
    if not isinstance(obs_id, int):
        return _tool_error("observable_id must be an integer.")
    session = get_session_factory()()
    try:
        obs = (
            session.query(Observable)
            .options(selectinload(Observable.enrichments))
            .filter_by(id=obs_id)
            .first()
        )
        if not obs:
            return _tool_error(f"Observable {obs_id} not found.")
        return _tool_result({
            "id": obs.id,
            "type": obs.type.value if hasattr(obs.type, "value") else obs.type,
            "value": obs.value,
            "normalized_value": obs.normalized_value,
            "threat_level": (
                obs.threat_level.value if hasattr(obs.threat_level, "value") else obs.threat_level
            ),
            "sighting_count": obs.sighting_count,
            "is_ioc": obs.is_ioc,
            "is_watched": obs.is_watched,
            "is_ignored": obs.is_ignored,
            "watch_reason": obs.watch_reason,
            "tags": obs.tags,
            "notes": obs.notes,
            "tlp": obs.tlp,
            "pap": obs.pap,
            "enrichments": [
                {
                    "source": e.source,
                    "is_malicious": e.is_malicious,
                    "score": e.score,
                    "labels": e.labels,
                    "enriched_at": e.enriched_at.isoformat() if e.enriched_at else None,
                }
                for e in (obs.enrichments or [])
            ],
            "first_seen": obs.first_seen.isoformat() if obs.first_seen else None,
            "last_seen": obs.last_seen.isoformat() if obs.last_seen else None,
        })
    finally:
        session.close()


def _tool_list_playbooks(args: dict) -> dict:
    active_only = bool(args.get("active_only", True))
    session = get_session_factory()()
    try:
        repo = PlaybookRepository(session)
        playbooks = repo.list_playbooks(active_only=active_only)
        return _tool_result({
            "playbooks": [p.to_dict(include_steps=True) for p in playbooks],
            "total": len(playbooks),
        })
    finally:
        session.close()


# Keep strong references to fire-and-forget sync tasks so they aren't GC'd
# mid-flight (asyncio only holds weak refs to tasks).
_BG_SYNC_TASKS: set = set()


def _schedule_case_es_sync(case_id: int) -> None:
    """Re-index the case into ES after a note lands — same side effect the
    REST route (case_lifecycle_api.add_case_note) performs. Scheduled as a
    task so the sync's HTTP round-trip doesn't block MCP dispatch; runs
    inline when no loop is available (CLI/tests). Never raises."""
    from ion.web.case_lifecycle_api import _background_case_sync

    coro = _background_case_sync(case_id)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(coro)
        return
    task = loop.create_task(coro)
    _BG_SYNC_TASKS.add(task)
    task.add_done_callback(_BG_SYNC_TASKS.discard)


def _fire_and_forget_kibana_note(kibana_case_id, username: str, content: str) -> None:
    """Run sync_note_to_kibana without blocking the event loop.

    The tool dispatch is sync code executing ON the loop; sync_note_to_kibana
    is a blocking httpx POST (5s timeout) that already swallows its own
    errors — hand it to the default executor when a loop is running, call it
    inline otherwise (CLI/tests)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        sync_note_to_kibana(kibana_case_id, username, content)
        return
    loop.run_in_executor(None, sync_note_to_kibana, kibana_case_id, username, content)


def _tool_add_case_note(args: dict, user: User) -> dict:
    case_id = args.get("case_id")
    content = (args.get("content") or "").strip()
    if not isinstance(case_id, int):
        return _tool_error("case_id must be an integer.")
    if not content:
        return _tool_error("content must not be empty.")
    session = get_session_factory()()
    try:
        case = session.query(AlertCase).filter_by(id=case_id).first()
        if not case:
            return _tool_error(f"Case {case_id} not found.")
        note = Note(
            entity_type=NoteEntityType.CASE,
            entity_id=str(case_id),
            user_id=user.id,
            content=content,
        )
        session.add(note)
        session.commit()
        session.refresh(note)
        # Mirror the REST route's side effects (case_lifecycle_api.add_case_note):
        # notes added via MCP must reach ES-driven case views and Kibana
        # comments too, or external state silently diverges from the ION DB.
        kibana_case_id = case.kibana_case_id
        result = _tool_result({
            "id": note.id,
            "case_id": note.case_id,
            "content": note.content,
            "created_at": note.created_at.isoformat() if note.created_at else None,
        })
        _schedule_case_es_sync(case_id)
        _fire_and_forget_kibana_note(kibana_case_id, user.username, content)
        return result
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Dispatch table — read-only tools ignore user; write tools receive it.
_DISPATCH: dict[str, Any] = {
    "list_alerts": lambda args, user: _tool_list_alerts(args),
    "get_alert": lambda args, user: _tool_get_alert(args),
    "list_cases": lambda args, user: _tool_list_cases(args),
    "get_case": lambda args, user: _tool_get_case(args),
    "search_observables": lambda args, user: _tool_search_observables(args),
    "get_observable": lambda args, user: _tool_get_observable(args),
    "list_playbooks": lambda args, user: _tool_list_playbooks(args),
    "add_case_note": _tool_add_case_note,
}


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------

def _handle_message(msg: dict, user: User) -> Optional[dict]:
    """Process one JSON-RPC 2.0 message.  Returns None for notifications."""
    method = msg.get("method", "")
    req_id = msg.get("id")  # absent on notifications
    params = msg.get("params") or {}

    if method == "initialize":
        return _ok(req_id, {
            "protocolVersion": _MCP_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": _SERVER_INFO,
        })

    if method == "ping":
        if req_id is None:
            return None  # ping as notification — ignore
        return _ok(req_id, {})

    if method.startswith("notifications/"):
        return None  # all notifications are fire-and-forget

    if method == "tools/list":
        tools = [
            _public_tool(t)
            for t in _TOOLS
            if user.has_permission(t["_permission"])
        ]
        return _ok(req_id, {"tools": tools})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        tool_def = _TOOL_BY_NAME.get(name)
        if not tool_def:
            return _ok(req_id, _tool_error(f"Unknown tool: '{name}'."))
        if not user.has_permission(tool_def["_permission"]):
            return _ok(req_id, _tool_error(
                f"Permission denied: '{name}' requires {tool_def['_permission']}."
            ))
        try:
            result = _DISPATCH[name](arguments, user)
        except Exception as exc:
            logger.warning("MCP tool '%s' raised: %s", name, exc, exc_info=True)
            # Return a generic message — the detail (paths, internals) is in the
            # server log above, never in the client-facing tool result.
            result = _tool_error(f"Tool error: {type(exc).__name__}")
        return _ok(req_id, result)

    if req_id is None:
        return None  # unrecognised notification — ignore

    return _rpc_err(req_id, -32601, f"Method not found: '{method}'.")


# ---------------------------------------------------------------------------
# FastAPI endpoint
# ---------------------------------------------------------------------------

@router.post("/api/mcp")
async def mcp_endpoint(request: Request) -> JSONResponse:
    """MCP Streamable HTTP endpoint (spec 2025-03-26).

    Accepts a JSON-RPC 2.0 object or batch array.
    Returns JSON-RPC 2.0 responses as ``application/json``.

    Auth: ``ion_session`` cookie or ``Authorization: Bearer <token>``.
    Fine-grained permission checks happen per-tool so a caller only sees
    the tools their ION role permits.

    The endpoint is OFF unless ``ION_MCP_ENABLED`` is truthy; when disabled it
    returns 404 so the surface isn't advertised. The flag is checked *before*
    authentication so a disabled endpoint does zero DB work.
    """
    if not mcp_enabled():
        return JSONResponse(
            _rpc_err(None, -32601, "Not found."),
            status_code=404,
        )

    user = _authenticate(request)
    if user is None:
        return JSONResponse(
            _rpc_err(None, -32001, "Unauthorized — supply a valid ION session."),
            status_code=401,
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _rpc_err(None, -32700, "Parse error — body must be JSON."),
            status_code=400,
        )

    if isinstance(body, list):
        # JSON-RPC 2.0: a batch entry that is not an object gets a per-item
        # -32600 (id null) — it must not AttributeError into a 500.
        responses = []
        for msg in body:
            if not isinstance(msg, dict):
                responses.append(_rpc_err(None, -32600, "Invalid Request."))
                continue
            r = _handle_message(msg, user)
            if r is not None:
                responses.append(r)
        if not responses:
            return JSONResponse(None, status_code=204)
        return JSONResponse(responses)

    if isinstance(body, dict):
        response = _handle_message(body, user)
        if response is None:
            return JSONResponse(None, status_code=202)
        return JSONResponse(response)

    return JSONResponse(
        _rpc_err(None, -32600, "Invalid Request."),
        status_code=400,
    )
