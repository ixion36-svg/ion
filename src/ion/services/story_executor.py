"""Story executor — walks a JSON-DAG playbook against a trigger entity.

v0.11.0 ships a **linear-only** executor. Each step has at most one
`next` target, and we walk from `start` until `next is None` or we hit
a step that errors. Branching/conditional edges are deferred to v0.11.1.

Implemented step types:
- ``case_note``              — append a note to a case (templated content)
- ``bob_investigate_alert``  — run Bob's investigation on an alert
- ``http_request``           — outbound HTTP call (response stored in context)

Each step receives a ``context`` dict: ``{trigger: {...}, nodes: {<id>: <output>}}``.
Templated config values use ``{{ trigger.alert_id }}`` / ``{{ nodes.foo.bar }}``
syntax — a deliberately tiny placeholder substitution, not full Jinja —
to keep the security surface narrow on a freshly-imported story.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class StoryExecutionError(Exception):
    """Wraps any failure during story execution. Carries node id."""
    def __init__(self, message: str, node_id: Optional[str] = None):
        super().__init__(message)
        self.node_id = node_id


# ── Tiny templating: {{ path.to.value }} → context value ─────────────────
_TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}")


def _resolve_path(context: Dict[str, Any], path: str) -> Any:
    """Walk a dotted path through the context dict. Missing → empty string."""
    cur: Any = context
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return ""
        else:
            return ""
    return cur if cur is not None else ""


def _render(value: Any, context: Dict[str, Any]) -> Any:
    """Recursively substitute {{path}} placeholders in strings/dicts/lists."""
    if isinstance(value, str):
        def _sub(m: re.Match) -> str:
            resolved = _resolve_path(context, m.group(1))
            if isinstance(resolved, (dict, list)):
                return json.dumps(resolved, default=str)
            return str(resolved)
        return _TEMPLATE_RE.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _render(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, context) for v in value]
    return value


# ── Step implementations ─────────────────────────────────────────────────


def _step_case_note(config: Dict[str, Any], context: Dict[str, Any], session) -> Dict[str, Any]:
    """Append an analyst note to a case.

    Config: ``{case_id: int, content: str, author_name: str (optional)}``.
    The note is authored under the executing user; story attribution
    appears in the rendered content (a "[story:<name>]" prefix).
    """
    from ion.models.alert_triage import Note, NoteEntityType
    from ion.services.ai_user import get_bob_user_id

    case_id = config.get("case_id")
    if case_id in (None, ""):
        raise StoryExecutionError("case_note: 'case_id' is required")
    try:
        case_id = int(case_id)
    except (TypeError, ValueError):
        raise StoryExecutionError(f"case_note: case_id not an integer: {case_id!r}")

    content = (config.get("content") or "").strip()
    if not content:
        raise StoryExecutionError("case_note: 'content' is required")

    # Stories run as Bob by default — they're automation, not human input.
    # If a user is on the run record we use that instead so the audit
    # trail attributes to the triggering analyst.
    user_id = context.get("trigger", {}).get("user_id") or get_bob_user_id(session)
    if user_id is None:
        raise StoryExecutionError("case_note: no user available to author the note")

    story_name = context.get("trigger", {}).get("story_name") or "story"
    full_content = f"_[from story: **{story_name}**]_\n\n{content}"

    note = Note(
        entity_type=NoteEntityType.CASE,
        entity_id=str(case_id),
        user_id=user_id,
        content=full_content,
    )
    session.add(note)
    session.flush()
    return {"note_id": note.id, "case_id": case_id, "chars": len(full_content)}


def _step_bob_investigate_alert(config: Dict[str, Any], context: Dict[str, Any], session) -> Dict[str, Any]:
    """Run Bob's investigation pipeline against an alert.

    Config: ``{alert_id: str, force: bool (optional)}``.
    Returns the verdict + summary so downstream steps can branch on them
    once branching exists.
    """
    import asyncio
    from ion.services.investigation_service import InvestigationService

    alert_id = config.get("alert_id") or ""
    if not alert_id:
        raise StoryExecutionError("bob_investigate_alert: 'alert_id' is required")
    force = bool(config.get("force", False))

    svc = InvestigationService()
    # The investigation service is async. We're called from a sync FastAPI
    # endpoint; spin a fresh event loop so we don't conflict with the host
    # request loop.
    try:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Called from inside an async context — run in a thread
                # with its own loop. Investigations are slow (seconds);
                # the caller is expected to await the run endpoint.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(asyncio.run, svc.investigate_alert(
                        alert_id=alert_id, force=force, triggered_by="story",
                    ))
                    inv = fut.result(timeout=600)
            else:
                inv = loop.run_until_complete(svc.investigate_alert(
                    alert_id=alert_id, force=force, triggered_by="story",
                ))
        except RuntimeError:
            inv = asyncio.run(svc.investigate_alert(
                alert_id=alert_id, force=force, triggered_by="story",
            ))
    except Exception as exc:
        raise StoryExecutionError(f"bob_investigate_alert: {exc}")
    return {
        "investigation_id": inv.id if inv else None,
        "verdict": getattr(inv, "verdict", None),
        "severity": getattr(inv, "severity_assessment", None),
        "summary": (getattr(inv, "summary_text", None) or "")[:1000],
    }


def _step_http_request(config: Dict[str, Any], context: Dict[str, Any], session) -> Dict[str, Any]:
    """Outbound HTTP call. Response captured into the context.

    Config: ``{method: str, url: str, headers: dict, json: dict|str,
    timeout_s: int}``.

    Stories that trigger external state changes (block IP, page on-call,
    etc.) flow through this step. We deliberately don't expose secrets
    interpolation in the body — secrets should live in env vars and be
    referenced by the application code, not embedded in story JSON.
    """
    import httpx

    method = (config.get("method") or "GET").upper()
    url = (config.get("url") or "").strip()
    if not url:
        raise StoryExecutionError("http_request: 'url' is required")
    headers = config.get("headers") or {}
    body = config.get("json")
    timeout_s = float(config.get("timeout_s") or 30.0)

    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=True) as client:
            resp = client.request(method, url, headers=headers, json=body)
        # Best-effort JSON parse; fall back to text.
        try:
            payload = resp.json()
        except Exception:
            payload = resp.text[:8000]
        return {
            "status_code": resp.status_code,
            "ok": resp.is_success,
            "headers": dict(resp.headers),
            "body": payload,
        }
    except httpx.HTTPError as exc:
        raise StoryExecutionError(
            f"http_request: {type(exc).__name__}: {exc}"
        )


_STEP_REGISTRY = {
    "case_note": _step_case_note,
    "bob_investigate_alert": _step_bob_investigate_alert,
    "http_request": _step_http_request,
}


def list_step_types() -> List[Dict[str, str]]:
    """Return the public catalogue of step types for the admin UI.

    Each entry: ``{type, label, description, config_schema_hint}``.
    """
    return [
        {
            "type": "case_note",
            "label": "Append case note",
            "description": "Add an analyst note to a case. Templated content.",
            "config_schema_hint": '{"case_id": "{{ trigger.case_id }}", "content": "..."}',
        },
        {
            "type": "bob_investigate_alert",
            "label": "Bob: investigate alert",
            "description": "Run the autonomous investigation pipeline on an alert. Returns verdict + summary.",
            "config_schema_hint": '{"alert_id": "{{ trigger.alert_id }}", "force": false}',
        },
        {
            "type": "http_request",
            "label": "HTTP request",
            "description": "Make an outbound HTTP call. Response captured into the context for downstream steps.",
            "config_schema_hint": '{"method": "POST", "url": "https://...", "headers": {}, "json": {}, "timeout_s": 30}',
        },
    ]


# ── Validator + executor ─────────────────────────────────────────────────


def validate_dag(dag: Dict[str, Any]) -> List[str]:
    """Static validation of a DAG. Returns a list of error strings (empty = valid).

    Checks:
    - has ``start`` pointing at an existing node id
    - every node has ``id`` and ``type``
    - every ``type`` is in the registry
    - every ``next`` (when set) points at an existing node id
    - no duplicate node ids
    - **acyclic** — walking from ``start`` doesn't revisit a node (linear v0.11.0)
    """
    errors: List[str] = []
    if not isinstance(dag, dict):
        return ["DAG must be a JSON object"]
    nodes = dag.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return ["DAG must contain a non-empty 'nodes' array"]
    start = dag.get("start")

    seen_ids: set = set()
    by_id: Dict[str, Dict[str, Any]] = {}
    for n in nodes:
        if not isinstance(n, dict):
            errors.append(f"Node is not an object: {n!r}")
            continue
        nid = n.get("id")
        if not nid or not isinstance(nid, str):
            errors.append(f"Node missing 'id' (string): {n!r}")
            continue
        if nid in seen_ids:
            errors.append(f"Duplicate node id: {nid}")
            continue
        seen_ids.add(nid)
        by_id[nid] = n
        ntype = n.get("type")
        if ntype not in _STEP_REGISTRY:
            errors.append(f"Node {nid}: unknown type {ntype!r} (valid: {sorted(_STEP_REGISTRY)})")
    if start and start not in by_id:
        errors.append(f"'start' references unknown node id: {start}")
    # next pointers
    for nid, n in by_id.items():
        nxt = n.get("next")
        if nxt is not None and nxt not in by_id:
            errors.append(f"Node {nid}: 'next' references unknown node id: {nxt}")

    # Walk from start and check linear + acyclic
    if start and start in by_id:
        visited: set = set()
        cur = start
        while cur is not None:
            if cur in visited:
                errors.append(f"Cycle detected at node {cur} — v0.11.0 requires linear DAG")
                break
            visited.add(cur)
            cur = by_id.get(cur, {}).get("next")
    return errors


def execute_story(
    dag: Dict[str, Any],
    trigger: Dict[str, Any],
    session,
    *,
    timeout_total_s: float = 600.0,
) -> Dict[str, Any]:
    """Run the DAG. Returns ``{status, step_outputs, error?}``.

    Walks linearly from ``dag['start']`` following each node's ``next``.
    A step error stops the run with status ``failed``. ``timeout_total_s``
    is enforced across the whole story (not per-step) — most steps
    complete in milliseconds, but ``bob_investigate_alert`` can take 30 s.
    """
    errors = validate_dag(dag)
    if errors:
        return {
            "status": "failed",
            "step_outputs": {},
            "error": "DAG validation failed: " + "; ".join(errors),
        }

    nodes_by_id: Dict[str, Dict[str, Any]] = {n["id"]: n for n in dag.get("nodes", [])}
    cur_id = dag.get("start")
    context: Dict[str, Any] = {"trigger": dict(trigger), "nodes": {}}
    step_outputs: Dict[str, Any] = {}
    started = time.monotonic()

    while cur_id is not None:
        if (time.monotonic() - started) > timeout_total_s:
            return {
                "status": "failed",
                "step_outputs": step_outputs,
                "error": f"Story exceeded total timeout {timeout_total_s}s at node {cur_id}",
            }
        node = nodes_by_id.get(cur_id)
        if not node:
            return {
                "status": "failed",
                "step_outputs": step_outputs,
                "error": f"Unknown node id at runtime: {cur_id}",
            }
        impl = _STEP_REGISTRY.get(node.get("type"))
        if not impl:
            return {
                "status": "failed",
                "step_outputs": step_outputs,
                "error": f"Unknown step type at runtime: {node.get('type')}",
            }
        rendered_config = _render(node.get("config") or {}, context)
        node_started = time.monotonic()
        try:
            output = impl(rendered_config, context, session)
            duration_ms = int((time.monotonic() - node_started) * 1000)
            step_outputs[cur_id] = {
                "status": "ok",
                "output": output,
                "duration_ms": duration_ms,
            }
            context["nodes"][cur_id] = output
        except StoryExecutionError as exc:
            duration_ms = int((time.monotonic() - node_started) * 1000)
            step_outputs[cur_id] = {
                "status": "error",
                "error": str(exc),
                "duration_ms": duration_ms,
            }
            return {
                "status": "failed",
                "step_outputs": step_outputs,
                "error": f"Step {cur_id}: {exc}",
            }
        cur_id = node.get("next")

    return {"status": "completed", "step_outputs": step_outputs}
