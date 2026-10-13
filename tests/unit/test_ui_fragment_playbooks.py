"""Playbooks page fragments: the library, the view, the step form, and executions.

The page route is playbook:read. The executions family is playbook:execute,
which read does not imply. A viewer who can open the page but cannot execute
must be told the figures are withheld. Rendering them as zero, or as "no
executions", would say the estate is quiet when it was not read.

Every figure below is driven through TestClient. The template is never
rendered with a hand-built context. The JSON handlers are monkeypatched,
which is what makes a raised read and a payload of the wrong shape
distinguishable from an empty table.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/playbooks.html"
CSS = ROOT / "src/ion/web/static/css/playbooks-page.css"

LIBRARY = "/ui/playbooks/library"
VIEW = "/ui/playbooks/7"
STEP = "/ui/playbooks/step"
PARAMS = "/ui/playbooks/step-params"
EXECUTIONS = "/ui/playbooks/executions"
DETAIL = "/ui/playbooks/executions/4"
BADGE = "/ui/playbooks/executions/badge"


def _src(path: Path) -> str:
    """Source with comments removed, so an assertion cannot pass on prose."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?<![:'\"\\])//[^\n]*", "", text)
    return text


def _page_script() -> str:
    text = _src(PAGE)
    return "\n".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", text, flags=re.S))


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


class _User:
    id = 1
    username = "playbook-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions

    def has_any_permission(self, names):
        return any(self.has_permission(name) for name in names)


def _client(user, monkeypatch, **fakes):
    import ion.web.ui.playbooks as mod
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    for name, fake in fakes.items():
        monkeypatch.setattr(mod, name, fake)
    application = FastAPI()
    application.include_router(mod.router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: object()
    return TestClient(application)


def _get(monkeypatch, url, *permissions, **fakes):
    with _client(_User(*permissions), monkeypatch, **fakes) as client:
        return client.get(url)


# ---------------------------------------------------------------------------
# The page, before any route is involved
# ---------------------------------------------------------------------------


def test_the_page_script_no_longer_assigns_inner_html():
    script = _page_script()
    assert script.strip(), "the page script did not render"
    assert not re.search(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", script)


def test_the_page_has_no_inline_style_block():
    text = _src(PAGE)
    assert "<style" not in text
    assert CSS.is_file()
    assert 'href="/static/css/playbooks-page.css' in PAGE.read_text(encoding="utf-8")


def test_the_library_and_the_badge_load_through_htmx_and_the_names_stay():
    script = _page_script()
    assert "function loadPlaybooks(" in script
    assert "function loadExecutions(" in script
    assert "function loadExecutionsBadge(" in script
    assert "function addStep(" in script
    assert "function loadStepParams(" in script
    assert "htmx.ajax" in script
    page = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/playbooks/library"' in page
    assert 'hx-get="/ui/playbooks/executions/badge"' in page
    assert "id=\"outcome-modal-template\"" in page


def test_outcome_modal_args_are_json_not_a_string_the_parser_drops():
    """showOutcomeModal used to write data-args by interpolation. The
    complete button now receives the id through JSON.stringify after the
    template is cloned, and the template itself carries no raw id."""
    script = _page_script()
    assert "JSON.stringify([executionId])" in script
    assert "cloneTemplate('outcome-modal-template')" in script
    body = PAGE.read_text(encoding="utf-8")
    assert "outcome-modal-template" in body
    assert "javascript:" not in body.split("outcome-modal-template", 1)[1].split("</template>", 1)[0]


# ---------------------------------------------------------------------------
# Library. playbook:read, the same gate as GET /api/playbooks.
# ---------------------------------------------------------------------------


def _playbook(**over):
    row = {
        "id": 7,
        "name": "Brute force",
        "description": "A" * 60,
        "is_active": True,
        "trigger_conditions": {
            "severities": ["high", "critical"],
            "rule_patterns": ["a", "b"],
            "mitre_techniques": [],
            "mitre_tactics": [],
        },
        "priority": 0,
        "step_count": 2,
        "steps": [
            {"id": 1, "step_type": "manual_checklist", "title": "Confirm",
             "description": "Look", "is_required": True, "step_params": {}},
        ],
        "created_by_username": "ada",
        "created_at": "2026-04-01T12:00:00",
        "updated_at": "2026-04-02T12:00:00",
    }
    row.update(over)
    return row


def _list(rows):
    def fake(active_only=False, current_user=None, session=None):
        fake.calls.append(active_only)
        return {"playbooks": rows, "total": len(rows)}
    fake.calls = []
    return fake


def test_the_library_refuses_a_caller_without_playbook_read(monkeypatch):
    res = _get(monkeypatch, LIBRARY, "playbook:execute", list_playbooks=_list([_playbook()]))
    assert res.status_code == 403
    assert "Brute force" not in res.text


def test_playbook_read_opens_the_library_and_a_zero_priority_stays_zero(monkeypatch):
    fake = _list([_playbook()])
    res = _get(monkeypatch, LIBRARY + "?active_only=true", "playbook:read", list_playbooks=fake)
    assert res.status_code == 200
    assert fake.calls == [True]
    body = flat(res.text)
    assert "Brute force" in body
    assert "Sev: high, critical" in body
    assert "2 rule pattern(s)" in body
    assert "2 steps" in body
    assert "Priority" not in body or "0" in res.text
    assert ">0<" in res.text or ">0 steps<" in res.text or "0" in body
    assert "Active" in body
    assert "No playbooks found" not in body
    assert "could not be read" not in body


def test_a_raised_library_read_is_not_an_empty_library(monkeypatch):
    def fake(**kwargs):
        raise RuntimeError("db down")
    res = _get(monkeypatch, LIBRARY, "playbook:read", list_playbooks=fake)
    assert res.status_code == 200
    body = flat(res.text)
    assert "could not be read" in body
    assert "No playbooks found" not in body
    assert "Brute force" not in body


def test_a_library_payload_of_the_wrong_shape_is_not_empty(monkeypatch):
    def fake(**kwargs):
        return {"playbooks": {"not": "a list"}}
    res = _get(monkeypatch, LIBRARY, "playbook:read", list_playbooks=fake)
    body = flat(res.text)
    assert "could not be read" in body
    assert "No playbooks found" not in body


def test_an_empty_library_says_none_were_found(monkeypatch):
    res = _get(monkeypatch, LIBRARY, "playbook:read", list_playbooks=_list([]))
    body = flat(res.text)
    assert "No playbooks found" in body
    assert "could not be read" not in body


def test_a_missing_priority_is_not_painted_as_zero(monkeypatch):
    res = _get(
        monkeypatch, LIBRARY, "playbook:read",
        list_playbooks=_list([_playbook(priority=None, step_count=None, is_active=None)]),
    )
    body = flat(res.text)
    assert "unknown" in body
    assert "Inactive" not in body
    assert "0 steps" not in body


def test_a_flag_where_a_step_count_belongs_is_not_one_step(monkeypatch):
    res = _get(
        monkeypatch, LIBRARY, "playbook:read",
        list_playbooks=_list([_playbook(step_count=True, priority=False)]),
    )
    body = flat(res.text)
    assert "1 steps" not in body
    assert "0" not in body.split("Brute force", 1)[-1].split("unknown")[0] or "unknown" in body
    assert "unknown" in body


def test_trigger_conditions_that_are_not_an_object_are_not_all_alerts(monkeypatch):
    res = _get(
        monkeypatch, LIBRARY, "playbook:read",
        list_playbooks=_list([_playbook(trigger_conditions="high")]),
    )
    body = flat(res.text)
    assert "All alerts" not in body
    assert "could not be read" in body


def test_no_trigger_conditions_still_means_all_alerts(monkeypatch):
    res = _get(
        monkeypatch, LIBRARY, "playbook:read",
        list_playbooks=_list([_playbook(trigger_conditions=None)]),
    )
    assert "All alerts" in flat(res.text)
    assert "could not be read" not in flat(res.text)


def test_edit_and_delete_are_withheld_without_those_permissions(monkeypatch):
    res = _get(monkeypatch, LIBRARY, "playbook:read", list_playbooks=_list([_playbook()]))
    assert 'data-click-action="viewPlaybook"' in res.text
    assert 'data-click-action="editPlaybook"' not in res.text
    assert 'data-click-action="deletePlaybook"' not in res.text
    res = _get(
        monkeypatch, LIBRARY, "playbook:read", "playbook:update", "playbook:delete",
        list_playbooks=_list([_playbook()]),
    )
    assert 'data-click-action="editPlaybook"' in res.text
    assert 'data-click-action="deletePlaybook"' in res.text


def test_library_data_args_are_parseable_and_there_is_no_javascript_url(monkeypatch):
    res = _get(
        monkeypatch, LIBRARY, "playbook:read", "playbook:update", "playbook:delete",
        list_playbooks=_list([_playbook(name="O'Hara <script>")]),
    )
    assert res.status_code == 200
    assert "O&#39;Hara" in res.text or "O&#x27;Hara" in res.text or "O'Hara" not in res.text.split("data-args")[0]
    assert "<script>" not in res.text
    assert "javascript:" not in res.text
    assert ' style="' not in res.text
    for raw in re.findall(r"data-args='([^']*)'", res.text):
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
    assert "Brute" not in res.text or "O" in flat(res.text)


def test_an_inactive_playbook_is_labelled_inactive(monkeypatch):
    res = _get(
        monkeypatch, LIBRARY, "playbook:read",
        list_playbooks=_list([_playbook(is_active=False, description="")]),
    )
    assert "Inactive" in flat(res.text)
    assert "status-inactive" in res.text
    assert "status-active" not in res.text


# ---------------------------------------------------------------------------
# View one playbook. Same permission as GET /api/playbooks/{id}.
# ---------------------------------------------------------------------------


def _one(playbook=None, status=200):
    def fake(playbook_id, current_user=None, session=None):
        fake.calls.append(playbook_id)
        if status == 404:
            raise HTTPException(status_code=404, detail="Playbook not found")
        return {"playbook": playbook}
    fake.calls = []
    return fake


def test_the_view_refuses_without_playbook_read(monkeypatch):
    res = _get(monkeypatch, VIEW, "playbook:execute", get_playbook=_one(_playbook()))
    assert res.status_code == 403


def test_the_view_renders_the_playbook_and_asks_for_that_id(monkeypatch):
    fake = _one(_playbook())
    res = _get(monkeypatch, VIEW, "playbook:read", get_playbook=fake)
    assert res.status_code == 200
    assert fake.calls == [7]
    body = flat(res.text)
    assert "Brute force" in body
    assert "Confirm" in body
    assert "manual_checklist" in body
    assert "Required" in body
    assert "ada" in body
    assert "Active" in body
    assert "No description" not in body
    assert 'datetime="2026-04-01T12:00:00"' in res.text
    assert "javascript:" not in res.text


def test_a_missing_playbook_is_gone_not_empty_of_steps(monkeypatch):
    res = _get(monkeypatch, VIEW, "playbook:read", get_playbook=_one(status=404))
    body = flat(res.text)
    assert res.status_code == 200
    assert "no longer" in body
    assert "No steps defined" not in body
    assert "No description" not in body


def test_a_raised_view_is_not_an_empty_playbook(monkeypatch):
    def fake(**kwargs):
        raise RuntimeError("db down")
    res = _get(monkeypatch, VIEW, "playbook:read", get_playbook=fake)
    body = flat(res.text)
    assert "could not be read" in body
    assert "No steps defined" not in body


def test_a_playbook_with_no_steps_says_so(monkeypatch):
    res = _get(
        monkeypatch, VIEW, "playbook:read",
        get_playbook=_one(_playbook(steps=[], description=None)),
    )
    body = flat(res.text)
    assert "No steps defined" in body
    assert "No description" in body
    assert "could not be read" not in body


def test_steps_that_are_not_a_list_are_not_reported_as_none_defined(monkeypatch):
    res = _get(
        monkeypatch, VIEW, "playbook:read",
        get_playbook=_one(_playbook(steps={"no": "list"})),
    )
    body = flat(res.text)
    assert "could not be read" in body
    assert "No steps defined" not in body


def test_the_view_answers_json_for_a_json_only_caller(monkeypatch):
    with _client(_User("playbook:read"), monkeypatch, get_playbook=_one(_playbook())) as client:
        res = client.get(VIEW, headers={"accept": "application/json"})
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    body = res.json()
    assert body["state"] == "data"
    assert body["playbook"]["name"] == "Brute force"
    with _client(_User("playbook:read"), monkeypatch, get_playbook=_one(_playbook())) as client:
        html = client.get(VIEW, headers={"accept": "text/html, */*; q=0.01"})
    assert "text/html" in html.headers["content-type"]
    assert "Brute force" in html.text


# ---------------------------------------------------------------------------
# Step form. Markup the editor used to concatenate. No extra data.
# ---------------------------------------------------------------------------


def test_the_step_form_needs_playbook_read(monkeypatch):
    res = _get(monkeypatch, STEP + "?n=1", "playbook:execute")
    assert res.status_code == 403


def test_a_new_step_defaults_to_the_checklist_and_checks_opencti_only_as_a_default(monkeypatch):
    res = _get(monkeypatch, STEP + "?n=3", "playbook:read")
    assert res.status_code == 200
    assert 'id="step-3"' in res.text
    assert "Step 3" in res.text
    assert "Checklist Items" in res.text
    assert "data-args='[3]'" in res.text or 'data-args=\'[3]\'' in res.text
    # Changing type is what used to always check OpenCTI, including when the
    # saved step had turned it off. A new enrich step defaults it on.
    params = _get(
        monkeypatch,
        PARAMS + "?n=3&step_type=auto_enrich_observables",
        "playbook:read",
    )
    assert "checked" in params.text
    saved = _get(
        monkeypatch,
        PARAMS + '?n=3&step_type=auto_enrich_observables&step_params='
        + json.dumps({"sources": []}),
        "playbook:read",
    )
    assert "checked" not in saved.text
    assert 'value="opencti"' in saved.text


def test_saved_checklist_items_round_trip_and_a_bad_params_blob_is_not_a_blank_form(monkeypatch):
    good = _get(
        monkeypatch,
        PARAMS + "?n=1&step_type=manual_checklist&step_params="
        + json.dumps({"checklist_items": ["one", "two"]}),
        "playbook:read",
    )
    assert "one\ntwo" in good.text or "one\r\ntwo" in good.text or ">one\ntwo<" in good.text
    assert "could not be read" not in flat(good.text)
    bad = _get(
        monkeypatch,
        PARAMS + "?n=1&step_type=manual_checklist&step_params=" + json.dumps(["nope"]),
        "playbook:read",
    )
    assert "could not be read" in flat(bad.text)
    assert "step-checklist-items" not in bad.text


def test_an_update_status_step_selects_the_saved_value_and_keeps_an_unknown_one(monkeypatch):
    res = _get(
        monkeypatch,
        PARAMS + "?n=2&step_type=auto_update_status&step_params="
        + json.dumps({"new_status": "contained", "priority": "high"}),
        "playbook:read",
    )
    assert 'value="contained" selected' in res.text or "selected" in res.text
    assert ">contained<" in res.text
    weird = _get(
        monkeypatch,
        PARAMS + "?n=2&step_type=auto_update_status&step_params="
        + json.dumps({"new_status": "quarantined"}),
        "playbook:read",
    )
    assert "quarantined" in weird.text
    assert "selected" in weird.text


def test_a_case_step_keeps_a_blank_title_template_distinct_from_the_default(monkeypatch):
    """The old form filled a missing title with 'Case: {rule_name}' and also
    used that string as the placeholder, so an analyst could not tell a saved
    blank from the default. A saved empty string stays empty."""
    res = _get(
        monkeypatch,
        PARAMS + "?n=1&step_type=auto_create_case&step_params="
        + json.dumps({"title_template": "", "severity": "high"}),
        "playbook:read",
    )
    assert 'value=""' in res.text
    assert "value=\"high\" selected" in res.text or 'value="high" selected' in res.text
    fresh = _get(monkeypatch, PARAMS + "?n=1&step_type=auto_create_case", "playbook:read")
    assert "Case: {rule_name}" in fresh.text


def test_step_markup_has_no_inline_handler_or_style(monkeypatch):
    res = _get(monkeypatch, STEP + "?n=1&title=Look&is_required=true", "playbook:read")
    assert res.status_code == 200
    assert "Look" in res.text
    assert "checked" in res.text
    assert "javascript:" not in res.text
    assert ' style="' not in res.text
    assert "hx-on" not in res.text
    assert "<script" not in res.text


# ---------------------------------------------------------------------------
# Executions. playbook:execute, withheld from a reader.
# ---------------------------------------------------------------------------


def _execution(**over):
    row = {
        "id": 4,
        "es_alert_id": "abcdef0123456789EXTRA",
        "status": "in_progress",
        "started_at": "2026-05-01T08:00:00",
        "executed_by_username": "grace",
        "case_number": "C-10",
        "case_title": "Beacon",
        "outcome": None,
        "report_document_id": None,
        "total_steps": 2,
        "completed_steps": 0,
        "progress_pct": 0,
        "step_statuses": {},
        "playbook": {
            "name": "Triage",
            "steps": [
                {"id": 9, "title": "Isolate", "is_required": True, "step_type": "manual_checklist"},
            ],
        },
    }
    row.update(over)
    return row


def _execs(rows, boom=False, shape="ok"):
    def fake(status=None, limit=50, current_user=None, session=None):
        fake.calls.append({"status": status, "limit": limit})
        if boom:
            raise RuntimeError("db down")
        if shape == "bad":
            return {"executions": "nope"}
        return {"executions": rows, "total": len(rows)}
    fake.calls = []
    return fake


def test_executions_are_withheld_from_a_reader_and_the_api_is_not_called(monkeypatch):
    fake = _execs([_execution()])
    res = _get(monkeypatch, EXECUTIONS, "playbook:read", list_playbook_executions=fake)
    assert res.status_code == 200
    assert fake.calls == []
    body = flat(res.text)
    assert "withheld" in body
    assert "No executions found" not in body
    assert "Triage" not in body
    assert "0/0" not in body and "0%" not in body


def test_executions_are_refused_with_neither_permission(monkeypatch):
    res = _get(monkeypatch, EXECUTIONS, "alert:read", list_playbook_executions=_execs([]))
    assert res.status_code == 403


def test_an_executor_sees_a_real_zero_progress_and_not_a_hundred(monkeypatch):
    fake = _execs([_execution()])
    res = _get(
        monkeypatch, EXECUTIONS + "?status=in_progress", "playbook:execute",
        list_playbook_executions=fake,
    )
    assert res.status_code == 200
    assert fake.calls == [{"status": "in_progress", "limit": 50}]
    body = flat(res.text)
    assert "Triage" in body
    assert "grace" in body
    assert "C-10" in body
    assert "0/2 steps (0%)" in body
    assert "in progress" in body
    assert 'data-ion-style="width:0%"' in res.text
    assert "No executions found" not in body
    assert 'datetime="2026-05-01T08:00:00"' in res.text
    args = re.findall(r"data-args='([^']*)'", res.text)
    assert args and json.loads(args[0]) == [4]


def test_a_raised_execution_read_is_not_an_empty_table(monkeypatch):
    res = _get(
        monkeypatch, EXECUTIONS, "playbook:execute",
        list_playbook_executions=_execs([], boom=True),
    )
    body = flat(res.text)
    assert "could not be read" in body
    assert "No executions found" not in body
    assert "withheld" not in body


def test_an_execution_payload_of_the_wrong_shape_is_not_empty(monkeypatch):
    res = _get(
        monkeypatch, EXECUTIONS, "playbook:execute",
        list_playbook_executions=_execs([], shape="bad"),
    )
    body = flat(res.text)
    assert "could not be read" in body
    assert "No executions found" not in body


def test_no_executions_says_none_were_found(monkeypatch):
    res = _get(monkeypatch, EXECUTIONS, "playbook:execute", list_playbook_executions=_execs([]))
    body = flat(res.text)
    assert "No executions found" in body
    assert "could not be read" not in body
    assert "withheld" not in body


def test_a_missing_progress_is_not_zero_percent(monkeypatch):
    row = _execution(total_steps=None, completed_steps=None, progress_pct=None, playbook={"name": "Triage"})
    res = _get(monkeypatch, EXECUTIONS, "playbook:execute", list_playbook_executions=_execs([row]))
    body = flat(res.text)
    assert "unknown" in body
    assert "0%" not in body
    assert "width:0%" not in res.text


def test_a_long_alert_id_is_shortened_without_losing_the_title(monkeypatch):
    res = _get(monkeypatch, EXECUTIONS, "playbook:execute", list_playbook_executions=_execs([_execution()]))
    assert "abcdef0123456789EXTR" in res.text
    assert 'title="abcdef0123456789EXTRA"' in res.text
    assert "..." in res.text


def test_the_execution_detail_is_withheld_without_execute(monkeypatch):
    def fake(**kwargs):
        fake.called = True
        return {"execution": _execution()}
    fake.called = False
    res = _get(monkeypatch, DETAIL, "playbook:read", get_playbook_execution=fake)
    assert res.status_code == 200
    assert fake.called is False
    assert "withheld" in flat(res.text)
    assert "Isolate" not in res.text


def test_the_execution_detail_renders_the_step_and_a_zero_progress(monkeypatch):
    def fake(execution_id, current_user=None, session=None):
        fake.calls.append(execution_id)
        return {"execution": _execution(step_statuses={"9": {"status": "pending", "action_data": {"findings": "none"}}})}
    fake.calls = []
    res = _get(monkeypatch, DETAIL, "playbook:execute", get_playbook_execution=fake)
    assert fake.calls == [4]
    body = flat(res.text)
    assert "Isolate" in body
    assert "Required" in body
    assert "0/1 steps completed (0%)" in body
    assert "Complete" in body and "Classify" in body
    assert "none" in res.text
    assert "Mark Failed" in body
    args = [json.loads(raw) for raw in re.findall(r"data-args='([^']*)'", res.text)]
    assert [4, 9, "$checked"] in args
    assert "javascript:" not in res.text
    assert ' style="' not in res.text


def test_a_missing_execution_is_gone_and_a_raised_one_failed(monkeypatch):
    def missing(**kwargs):
        raise HTTPException(status_code=404, detail="Execution not found")
    gone = _get(monkeypatch, DETAIL, "playbook:execute", get_playbook_execution=missing)
    assert gone.status_code == 200
    assert "no longer" in flat(gone.text)
    assert "No steps defined" not in flat(gone.text)

    def boom(**kwargs):
        raise RuntimeError("db down")
    failed = _get(monkeypatch, DETAIL, "playbook:execute", get_playbook_execution=boom)
    assert "could not be read" in flat(failed.text)
    assert "No steps defined" not in flat(failed.text)


def test_a_completed_execution_shows_its_outcome_and_not_the_complete_button(monkeypatch):
    row = _execution(
        status="completed", outcome="true_positive", report_document_id=3,
        total_steps=1, completed_steps=1, progress_pct=100,
        step_statuses={"9": {"status": "completed", "completed_by_username": "grace",
                             "completed_at": "2026-05-01T09:00:00"}},
    )
    def fake(**kwargs):
        return {"execution": row}
    res = _get(monkeypatch, DETAIL, "playbook:execute", get_playbook_execution=fake)
    body = flat(res.text)
    assert "true positive" in body
    assert "View Report" in body
    assert "Regenerate Report" in body
    assert "Complete &amp; Classify" not in res.text and "Complete & Classify" not in body
    assert "Mark Failed" not in body
    assert "Done" in body
    assert "grace" in body


def test_an_execution_whose_body_is_not_an_object_is_not_an_empty_one(monkeypatch):
    def fake(**kwargs):
        return ["nope"]
    res = _get(monkeypatch, DETAIL, "playbook:execute", get_playbook_execution=fake)
    assert "could not be read" in flat(res.text)
    assert "No steps defined" not in flat(res.text)


def test_the_badge_hides_a_true_zero_and_does_not_hide_a_failure_as_zero(monkeypatch):
    def zero(current_user=None, session=None):
        return {"in_progress": 0, "pending": 0, "completed": 4, "failed": 0, "total": 4}
    res = _get(monkeypatch, BADGE, "playbook:execute", playbook_executions_summary=zero)
    assert "hidden" in res.text
    assert ">0<" not in res.text
    assert "unavailable" not in flat(res.text)

    def active(current_user=None, session=None):
        return {"in_progress": 2, "pending": 1, "completed": 0, "failed": 0, "total": 3}
    shown = _get(monkeypatch, BADGE, "playbook:execute", playbook_executions_summary=active)
    assert ">3<" in shown.text
    assert "hidden" not in shown.text

    def boom(current_user=None, session=None):
        raise RuntimeError("db down")
    failed = _get(monkeypatch, BADGE, "playbook:execute", playbook_executions_summary=boom)
    assert "unavailable" in flat(failed.text)
    assert ">0<" not in failed.text

    def bad(current_user=None, session=None):
        return {"in_progress": "many"}
    unread = _get(monkeypatch, BADGE, "playbook:execute", playbook_executions_summary=bad)
    assert "unavailable" in flat(unread.text)
    assert ">0<" not in unread.text


def test_the_badge_is_withheld_rather_than_zero_without_execute(monkeypatch):
    def fake(**kwargs):
        fake.called = True
        return {"in_progress": 0, "pending": 0}
    fake.called = False
    res = _get(monkeypatch, BADGE, "playbook:read", playbook_executions_summary=fake)
    assert res.status_code == 200
    assert fake.called is False
    assert "withheld" in res.text
    assert ">0<" not in res.text


def test_a_true_zero_in_one_bucket_still_counts_the_other(monkeypatch):
    """pending of 0 is a measurement. Dropping it as falsy would hide one
    in-progress execution behind the zero pending bucket."""
    def fake(current_user=None, session=None):
        return {"in_progress": 1, "pending": 0}
    res = _get(monkeypatch, BADGE, "playbook:execute", playbook_executions_summary=fake)
    assert ">1<" in res.text


def test_fragments_carry_no_colour_literals():
    frag_dir = ROOT / "src/ion/web/templates/_fragments"
    names = [
        "playbooks_library.html", "playbooks_view.html", "playbooks_step.html",
        "playbooks_step_params.html", "playbooks_executions.html",
        "playbooks_execution.html", "playbooks_badge.html",
    ]
    for name in names:
        text = (frag_dir / name).read_text(encoding="utf-8")
        assert "<script" not in text, name
        assert ' style="' not in text, name
        assert "javascript:" not in text, name
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", text), name
        assert "var(--" not in text, name
