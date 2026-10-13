"""The alerts page's playbook region as fragments: the executions list in
the case management modal, the Start Playbook picker, the Investigation
Playbooks section of the detail modal and its library panel.

Each case below is something the JavaScript either got right and must keep,
or got wrong and must stop doing. Measured against the tree before stage 3:

  * loadPlaybooksForAlert wrote `recommendedRes.ok ? json : { playbooks: [] }`
    and the same for executions, so a 403, a 400 from an instance without
    Elasticsearch and an alert with no matching playbook were all "No
    matching playbooks for this alert", and a failed executions read hid an
    execution in progress.
  * loadCasePlaybookExecutions wrote `data.executions || []`, so a refusal
    was "No playbook executions".
  * showCasePlaybookPicker showed a toast and no dialog for an empty list,
    and offered Start to every reader of a POST that carries
    playbook:execute.
  * The step checkbox's data-args carried `this.checked ? ... : ...` inside
    the JSON, which event-delegation.js rejects, so ticking a step never
    reached the server.
  * togglePlaybookLibrary tested style.display on a panel hidden by a class;
    the first click did nothing.

The render tests use fixtures: this deployment has one case, six playbooks,
no executions and no alerts, and an empty render proves nothing about rows.
"""
from __future__ import annotations

import inspect
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
from ion.storage.playbook_repository import PlaybookRepository
from ion.web.templating import make_templates
from ion.web.ui import alerts as mod
from ion.web.ui.alerts import (
    EXEC_COMPLETED,
    EXEC_IN_PROGRESS,
    LIBRARY_DESCRIPTION_CHARS,
    PLAYBOOK_EXECUTE_PERMISSION,
    PLAYBOOK_READ_PERMISSION,
    RECOMMENDED_SHOWN,
    _count,
    active_execution,
    case_execution_rows,
    completed_count,
    execution_progress,
    execution_view,
    library_groups,
    pending_step_ids,
    recommended_rows,
    router,
    short_description,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"
SERVER = ROOT / "src/ion/web/server.py"
FRAGMENTS = ROOT / "src/ion/web/templates/_fragments"

CASE_EXECS = mod.CASE_EXECUTIONS_FRAGMENT
PICKER = mod.CASE_PLAYBOOK_PICKER_FRAGMENT
SECTION = mod.ALERT_PLAYBOOKS_FRAGMENT
LIBRARY = mod.PLAYBOOK_LIBRARY_FRAGMENT
MANAGE = mod.MANAGE_FRAGMENT

WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


def render(name: str, **ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(name).render(**ctx)


def flat(body: str) -> str:
    """The render with its whitespace collapsed, for sentences the template
    wraps across lines."""
    return " ".join(body.split())


# ---------------------------------------------------------------------------
# Shapes, as the JSON endpoints emit them
# ---------------------------------------------------------------------------


def _step(step_id: int, title: str = "Isolate host", required: bool = False) -> dict:
    return {"id": step_id, "playbook_id": 5, "step_order": step_id, "step_type": "manual",
            "title": title, "description": None, "step_params": None,
            "is_required": required}


def _playbook(**over: Any) -> dict:
    """What Playbook.to_dict(include_steps=True) returns."""
    base = {
        "id": 5, "name": "Ransomware triage", "description": "Contain, then collect.",
        "is_active": True, "trigger_conditions": {"severity": ["critical"]},
        "priority": 10, "created_by_id": 1, "created_by_username": "admin",
        "step_count": 2, "created_at": "2026-10-01T00:00:00",
        "updated_at": "2026-10-01T00:00:00",
        "steps": [_step(11, "Isolate host", True), _step(12, "Collect memory")],
    }
    base.update(over)
    return base


def _execution(**over: Any) -> dict:
    """What PlaybookExecution.to_dict(include_playbook=True) returns."""
    base = {
        "id": 42, "playbook_id": 5, "es_alert_id": "alert-1", "status": EXEC_IN_PROGRESS,
        "started_at": "2026-10-12T10:00:00", "completed_at": None,
        "step_statuses": {"11": {"status": "completed", "completed_by": "admin"}},
        "executed_by_id": 1, "executed_by_username": "admin", "case_id": None,
        "case_number": None, "case_title": None, "outcome": None, "outcome_notes": None,
        "report_document_id": None, "created_at": "2026-10-12T10:00:00",
        "updated_at": "2026-10-12T10:00:00", "playbook": _playbook(),
    }
    base.update(over)
    return base


def _case_execution(**over: Any) -> dict:
    """The case executions endpoint's row: the execution plus three counts."""
    base = _execution(total_steps=2, completed_steps=1, progress_pct=50)
    base.update(over)
    return base


def _suggested(**over: Any) -> dict:
    base = _playbook(suggestion_type="recommended", has_active_execution=False)
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The helpers that make the outcomes distinct
# ---------------------------------------------------------------------------


def test_count_is_none_for_a_flag_or_a_missing_value_not_zero():
    assert _count(None) is None
    assert _count(True) is None
    assert _count("3") is None
    assert _count(0) == 0
    assert _count(7) == 7


def test_progress_of_a_playbook_with_no_steps_is_not_zero_percent():
    ex = _execution(playbook=_playbook(steps=[]), step_statuses={})
    assert execution_progress(ex) == {"completed": 0, "total": 0, "pct": None}


def test_progress_counts_skipped_steps_as_done_like_the_endpoint():
    ex = _execution(step_statuses={"11": {"status": "completed"}, "12": {"status": "skipped"}})
    assert execution_progress(ex) == {"completed": 2, "total": 2, "pct": 100}
    assert execution_progress(_execution())["pct"] == 50


def test_pending_step_ids_leaves_out_done_steps_and_keeps_order():
    assert pending_step_ids(_execution()) == [12]
    assert pending_step_ids(_execution(step_statuses={})) == [11, 12]
    assert pending_step_ids(_execution(playbook=None)) == []


def test_execution_view_marks_each_step_and_carries_the_pending_ids():
    view = execution_view(_execution(step_statuses={"12": {"status": "skipped"}}))
    assert [s["done"] for s in view["steps"]] == [False, True]
    assert view["steps"][1]["skipped"] is True
    assert view["pending_step_ids"] == [11]
    assert view["status"] == EXEC_IN_PROGRESS


def test_active_execution_is_the_first_in_progress_one_or_none():
    done = _execution(id=1, status=EXEC_COMPLETED)
    running = _execution(id=2)
    assert active_execution([done, running, _execution(id=3)])["id"] == 2
    assert active_execution([done]) is None
    assert active_execution([]) is None


def test_completed_count_counts_only_completed():
    rows = [_execution(status=EXEC_COMPLETED), _execution(), _execution(status="failed")]
    assert completed_count(rows) == 1


def test_recommended_rows_drop_the_active_playbook_and_cap_at_three():
    books = [_playbook(id=i) for i in range(1, 7)]
    rows = recommended_rows(books, _execution(playbook_id=2))
    assert [p["id"] for p in rows] == [1, 3, 4]
    assert len(rows) == RECOMMENDED_SHOWN
    assert [p["id"] for p in recommended_rows(books[:2], None)] == [1, 2]


def test_short_description_cuts_at_the_javascript_length():
    long = "x" * (LIBRARY_DESCRIPTION_CHARS + 5)
    assert short_description(long) == "x" * LIBRARY_DESCRIPTION_CHARS + "..."
    assert short_description("short") == "short"
    assert short_description(None) is None
    assert short_description("") is None


def test_library_groups_follow_the_page_split_and_hide_the_running_recommendation():
    rows = [
        _suggested(id=1),
        _suggested(id=2, has_active_execution=True),
        _suggested(id=3, suggestion_type="library", is_active=False, has_active_execution=True),
        _suggested(id=4, suggestion_type="library", is_active=False),
    ]
    groups = library_groups(rows)
    assert [p["id"] for p in groups["recommended"]] == [1]
    assert [p["id"] for p in groups["library"]] == [3, 4]
    assert groups["library"][0]["has_active_execution"] is True


def test_case_execution_rows_guard_the_three_counts():
    row = case_execution_rows([_case_execution(progress_pct=None, completed_steps="1")])[0]
    assert row["progress_pct"] is None
    assert row["completed_steps"] is None
    assert row["total_steps"] == 2
    assert row["playbook_name"] == "Ransomware triage"


# ---------------------------------------------------------------------------
# Case executions fragment
# ---------------------------------------------------------------------------


def test_a_failed_case_executions_read_does_not_say_there_are_none():
    body = render(CASE_EXECS, case_id=1, failed=True, missing=False, executions=None)
    assert 'role="alert"' in body and "could not be read" in body
    assert "No playbook executions" not in body


def test_an_empty_case_executions_list_says_so_and_not_that_it_failed():
    body = render(CASE_EXECS, case_id=1, failed=False, missing=False, executions=[])
    assert "No playbook executions" in body
    assert "could not be read" not in body and 'role="alert"' not in body


def test_a_missing_case_is_worded_as_gone_not_as_a_failure():
    body = render(CASE_EXECS, case_id=9, failed=False, missing=True, executions=None)
    assert "no longer exists" in body
    assert "could not be read" not in body and "No playbook executions" not in body


def test_a_case_execution_row_carries_its_progress_status_and_work_link():
    rows = case_execution_rows([_case_execution()])
    body = render(CASE_EXECS, case_id=1, failed=False, missing=False, executions=rows)
    assert "Ransomware triage" in body
    assert 'data-ion-style="width: 50%"' in body
    assert "playbook-progress-fill in_progress" in body
    assert ">1/2<" in body
    assert "/playbooks?execution=42" in body
    assert ' style="' not in body, "style-src-attr is 'none'; only data-ion-style may carry a style"


def test_a_completed_case_execution_has_no_work_link_and_shows_its_outcome():
    rows = case_execution_rows([_case_execution(
        status=EXEC_COMPLETED, outcome="false_positive", progress_pct=100,
        completed_steps=2, report_document_id=3)])
    body = render(CASE_EXECS, case_id=1, failed=False, missing=False, executions=rows)
    assert "/playbooks?execution=" not in body
    assert "status-active" in body
    assert "outcome-false_positive" in body and "false positive" in body
    assert "View Report" in body


def test_a_case_execution_row_without_counts_does_not_print_none_over_none():
    rows = case_execution_rows([_case_execution(progress_pct=None, completed_steps=None,
                                                 total_steps=None)])
    body = render(CASE_EXECS, case_id=1, failed=False, missing=False, executions=rows)
    assert "steps not counted" in body
    assert "None" not in body
    assert "data-ion-style" not in body, "no width is claimed for a progress that was not reported"


# ---------------------------------------------------------------------------
# Picker fragment
# ---------------------------------------------------------------------------


def test_a_failed_picker_read_is_a_dialog_that_says_so_and_offers_no_start():
    body = render(PICKER, case_id=1, can_start=True, failed=True, playbooks=None)
    assert 'id="case-playbook-picker"' in body and 'role="alert"' in body
    assert "No active playbooks" not in body and "startCasePlaybook" not in body


def test_an_empty_picker_is_a_dialog_that_says_so_and_offers_no_start():
    body = render(PICKER, case_id=1, can_start=True, failed=False, playbooks=[])
    assert "No active playbooks" in body
    assert 'role="alert"' not in body and "startCasePlaybook" not in body


def test_the_picker_lists_the_playbooks_with_start_bound_to_the_case():
    rows = [{**_playbook(id=5), "step_count": 2}, {**_playbook(id=6, name="Phishing"), "step_count": 0}]
    body = render(PICKER, case_id=3, can_start=True, failed=False, playbooks=rows)
    assert "Ransomware triage" in body and "Phishing" in body
    assert "data-args='[3, 5]'" in body and "data-args='[3, 6]'" in body
    assert "2 steps" in body and "0 steps" in body and "Priority: 10" in body


def test_the_picker_withholds_start_without_playbook_execute():
    rows = [{**_playbook(id=5), "step_count": 2}]
    body = render(PICKER, case_id=3, can_start=False, failed=False, playbooks=rows)
    assert "Ransomware triage" in body
    assert "startCasePlaybook" not in body
    assert "playbook:execute" in body


# ---------------------------------------------------------------------------
# Alert section fragment
# ---------------------------------------------------------------------------


def section_ctx(**over: Any) -> dict:
    ctx = {
        "alert_id": "alert-1", "can_execute": True, "alert_missing": False,
        "recommended_failed": False, "recommended_error": None,
        "recommended": [{**_playbook(id=7, name="Lateral movement"), "step_count": 3}],
        "executions_withheld": False, "executions_failed": False,
        "active": None, "completed_count": 0,
    }
    ctx.update(over)
    return ctx


def test_the_section_renders_the_active_execution_with_live_step_boxes():
    body = render(SECTION, **section_ctx(active=execution_view(_execution())))
    assert 'id="playbook-execution-42"' in body
    assert "data-pending-step-ids='[12]'" in body
    assert body.count('data-change-action="updateStepStatus"') == 2
    assert """data-args='["alert-1", 42, 11, "$checked"]'""" in body
    assert "this.checked" not in body, "the page's data-args carried JavaScript inside the JSON"
    assert "Progress: 50% (1/2 steps)" in body
    assert 'data-args=\'["alert-1", 42]\'' in body  # Complete and Skip Remaining
    assert "Required" in body


def test_an_active_execution_without_steps_does_not_claim_zero_percent():
    ex = _execution(playbook=_playbook(steps=[]), step_statuses={})
    body = render(SECTION, **section_ctx(active=execution_view(ex)))
    assert "0%" not in body
    assert "no steps" in body


def test_a_failed_recommendations_read_names_the_reason_and_is_not_no_match():
    body = render(SECTION, **section_ctx(recommended=None, recommended_failed=True,
                                         recommended_error="Elasticsearch is not configured"))
    assert 'role="alert"' in body
    assert "could not be read: Elasticsearch is not configured" in body
    assert "No matching playbooks" not in body
    assert "startPlaybook" not in body


def test_a_missing_alert_is_worded_as_not_found_not_as_a_failure():
    body = render(SECTION, **section_ctx(recommended=None, alert_missing=True))
    assert "was not found in Elasticsearch" in body
    assert "could not be read" not in body and "No matching playbooks" not in body


def test_no_recommendations_and_no_active_execution_says_no_match():
    body = render(SECTION, **section_ctx(recommended=[]))
    assert "No matching playbooks for this alert" in body
    assert 'role="alert"' not in body


def test_no_recommendations_with_an_active_execution_does_not_say_no_match():
    body = render(SECTION, **section_ctx(recommended=[], active=execution_view(_execution())))
    assert "No matching playbooks" not in body
    assert 'id="playbook-execution-42"' in body


def test_recommendations_render_with_start_and_the_library_toggle_over_a_hidden_panel():
    body = render(SECTION, **section_ctx())
    assert "Lateral movement" in body and "3 steps" in body
    assert """data-click-action="startPlaybook" data-args='["alert-1", 7]'""" in body
    assert """data-click-action="togglePlaybookLibrary" data-args='["alert-1"]'""" in body
    assert '<div id="playbook-library-panel" hidden></div>' in body


def test_the_section_withholds_start_without_playbook_execute():
    body = render(SECTION, **section_ctx(can_execute=False, executions_withheld=True,
                                         completed_count=None))
    assert "Lateral movement" in body
    assert "startPlaybook" not in body
    assert "requires the playbook:execute permission" in body


def test_withheld_failed_and_counted_executions_are_three_different_sentences():
    withheld = render(SECTION, **section_ctx(executions_withheld=True, completed_count=None))
    failed = render(SECTION, **section_ctx(executions_failed=True, completed_count=None))
    counted = render(SECTION, **section_ctx(completed_count=2))
    none = render(SECTION, **section_ctx(completed_count=0))
    assert "not shown" in withheld and 'role="alert"' not in withheld
    assert "could not be read" in failed and "One may be in progress" in flat(failed)
    assert "2 playbook(s) completed previously" in counted
    for word in ("not shown", "could not be read", "completed previously"):
        assert word not in none


def test_an_alert_id_with_a_quote_cannot_break_out_of_the_args_attribute():
    body = render(SECTION, **section_ctx(alert_id="a'b\"c"))
    for args in re.findall(r"data-args='(\[.*?\])'", body):
        parsed = json.loads(args)
        assert parsed[0] == "a'b\"c"


# ---------------------------------------------------------------------------
# Library fragment
# ---------------------------------------------------------------------------


def library_ctx(**over: Any) -> dict:
    ctx = {"alert_id": "alert-1", "can_start": True, "missing": False, "failed": False,
           "error": None, "recommended": None, "library": None}
    ctx.update(over)
    return ctx


def test_a_failed_library_read_names_the_reason_and_is_not_no_match():
    body = render(LIBRARY, **library_ctx(failed=True, error="Elasticsearch is not configured"))
    assert 'role="alert"' in body and "Elasticsearch is not configured" in body
    assert "No matching playbooks in library" not in body


def test_an_empty_library_says_so_and_not_that_it_failed():
    body = render(LIBRARY, **library_ctx(recommended=[], library=[]))
    assert "No matching playbooks in library" in body
    assert 'role="alert"' not in body


def test_a_missing_alert_in_the_library_is_not_a_failure():
    body = render(LIBRARY, **library_ctx(missing=True))
    assert "was not found in Elasticsearch" in body and "could not be read" not in body


def test_the_library_groups_render_with_running_disabled_and_descriptions_cut():
    groups = library_groups([
        _suggested(id=1, description="y" * 100),
        _suggested(id=3, name="Old runbook", suggestion_type="library", has_active_execution=True),
    ])
    body = render(LIBRARY, **library_ctx(**groups))
    assert "Recommended (Active)" in body and "From Library" in body
    assert "y" * LIBRARY_DESCRIPTION_CHARS + "..." in body
    assert "y" * (LIBRARY_DESCRIPTION_CHARS + 1) not in body
    assert """data-click-action="startPlaybook" data-args='["alert-1", 1]'""" in body
    assert 'disabled title="Already running">Running' in body
    assert "data-args='[\"alert-1\", 3]'" not in body


def test_the_library_withholds_start_without_playbook_execute():
    groups = library_groups([_suggested(id=1)])
    body = render(LIBRARY, **library_ctx(can_start=False, **groups))
    assert "Ransomware triage" in body
    assert "startPlaybook" not in body and "Running" not in body
    assert "playbook:execute" in body


# ---------------------------------------------------------------------------
# The routes over HTTP
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "alerts-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: session
    return application


def _make_case(session, number="CASE-0301", alerts=1) -> AlertCase:
    case = AlertCase(case_number=number, title=f"probe {number}", status=AlertCaseStatus.OPEN,
                     severity="high", created_by_id=1)
    session.add(case)
    session.commit()
    for i in range(alerts):
        session.add(AlertTriage(es_alert_id=f"{number}-alert-{i}", case_id=case.id,
                                rule_name="Encoded PowerShell"))
    session.commit()
    return case


def _make_playbook(session, name="Ransomware triage", active=True, steps=2):
    repo = PlaybookRepository(session)
    playbook = repo.create_playbook(name=name, trigger_conditions={"severity": ["critical"]},
                                    created_by_id=1, is_active=active, priority=10)
    for i in range(steps):
        repo.add_step(playbook=playbook, step_type="manual", title=f"Step {i + 1}",
                      is_required=(i == 0))
    session.commit()
    return repo.get_playbook_by_id(playbook.id)


def _start(session, playbook, alert_id="alert-1", case_id=None):
    repo = PlaybookRepository(session)
    execution = repo.start_execution(playbook=playbook, es_alert_id=alert_id,
                                     executed_by_id=1, case_id=case_id)
    session.commit()
    return repo.get_execution(execution.id)


READ_PATHS = [
    "/ui/alerts/case-playbook-picker/1",
    "/ui/alerts/playbooks/alert-1",
    "/ui/alerts/playbook-library/alert-1",
]


@pytest.mark.parametrize("path", READ_PATHS)
def test_a_read_fragment_refuses_a_caller_without_playbook_read(session, path):
    with TestClient(_app(session, _User("alert:read", PLAYBOOK_EXECUTE_PERMISSION))) as client:
        assert client.get(path).status_code == 403


def test_the_executions_fragment_refuses_a_caller_with_only_playbook_read(session):
    """The read-shaped endpoint it mirrors carries playbook:execute."""
    with TestClient(_app(session, _User("alert:read", PLAYBOOK_READ_PERMISSION))) as client:
        assert client.get("/ui/alerts/case-playbook-executions/1").status_code == 403


def test_the_executions_route_lists_a_real_execution_with_its_counts(session):
    case = _make_case(session)
    playbook = _make_playbook(session)
    execution = _start(session, playbook, alert_id=f"{case.case_number}-alert-0", case_id=case.id)
    with TestClient(_app(session, _User(PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-playbook-executions/{case.id}").text
    assert "Ransomware triage" in body
    assert ">0/2<" in body and 'data-ion-style="width: 0%"' in body
    assert f"/playbooks?execution={execution.id}" in body
    assert "No playbook executions" not in body


def test_the_executions_route_discovers_an_execution_through_the_case_alerts(session):
    """The handler's back-fill: an execution on a linked alert with no
    case_id is the case's. Reusing the handler keeps that behaviour."""
    case = _make_case(session)
    playbook = _make_playbook(session)
    _start(session, playbook, alert_id=f"{case.case_number}-alert-0", case_id=None)
    with TestClient(_app(session, _User(PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-playbook-executions/{case.id}").text
    assert "Ransomware triage" in body


def test_the_executions_route_says_none_for_a_case_with_none(session):
    case = _make_case(session)
    with TestClient(_app(session, _User(PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-playbook-executions/{case.id}").text
    assert "No playbook executions" in body and 'role="alert"' not in body


def test_the_executions_route_answers_a_missing_case_as_gone_not_as_a_404(session):
    with TestClient(_app(session, _User(PLAYBOOK_EXECUTE_PERMISSION))) as client:
        response = client.get("/ui/alerts/case-playbook-executions/987654321")
    assert response.status_code == 200
    assert "no longer exists" in response.text


def test_the_executions_route_says_so_when_the_handler_raises(session, monkeypatch):
    from ion.web import case_lifecycle_api

    def boom(*a, **k):
        raise RuntimeError("database went away")

    monkeypatch.setattr(case_lifecycle_api, "get_case_playbook_executions", boom)
    with TestClient(_app(session, _User(PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-playbook-executions/1").text
    assert "could not be read" in body
    assert "No playbook executions" not in body


def test_a_payload_without_an_executions_list_is_a_failed_read(session, monkeypatch):
    from ion.web import case_lifecycle_api

    monkeypatch.setattr(case_lifecycle_api, "get_case_playbook_executions",
                        lambda *a, **k: {"detail": "nope"})
    with TestClient(_app(session, _User(PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-playbook-executions/1").text
    assert "could not be read" in body and "No playbook executions" not in body


def test_the_picker_route_lists_active_playbooks_only_and_binds_start_to_the_case(session):
    active = _make_playbook(session, name="Active one")
    _make_playbook(session, name="Retired one", active=False)
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-playbook-picker/3").text
    assert "Active one" in body and "Retired one" not in body
    assert f"data-args='[3, {active.id}]'" in body
    assert "2 steps" in body


def test_the_picker_route_withholds_start_for_a_reader(session):
    _make_playbook(session)
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-playbook-picker/3").text
    assert "Ransomware triage" in body and "startCasePlaybook" not in body


def test_the_picker_route_says_so_when_the_list_raises(session, monkeypatch):
    from ion.web import api

    def boom(*a, **k):
        raise RuntimeError("no")

    monkeypatch.setattr(api, "list_playbooks", boom)
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-playbook-picker/3").text
    assert 'role="alert"' in body and "No active playbooks" not in body


def _stub_recommended(monkeypatch, result=None, raises: Optional[Exception] = None):
    from ion.web import api

    async def stub(alert_id, current_user=None, session=None):
        if raises is not None:
            raise raises
        return result

    monkeypatch.setattr(api, "get_recommended_playbooks", stub)


def _stub_suggested(monkeypatch, result=None, raises: Optional[Exception] = None):
    from ion.web import api

    async def stub(alert_id, current_user=None, session=None):
        if raises is not None:
            raise raises
        return result

    monkeypatch.setattr(api, "get_suggested_playbooks", stub)


def test_the_section_route_reads_both_halves_and_renders_the_real_execution(session, monkeypatch):
    playbook = _make_playbook(session)
    execution = _start(session, playbook, alert_id="alert-1")
    _stub_recommended(monkeypatch, {"playbooks": [_playbook(id=99, name="Other book")], "total": 1})
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbooks/alert-1").text
    assert f'id="playbook-execution-{execution.id}"' in body
    assert "Progress: 0% (0/2 steps)" in body
    assert "Other book" in body and "startPlaybook" in body
    assert '"$checked"' in body


def test_the_section_route_withholds_executions_and_start_without_execute(session, monkeypatch):
    playbook = _make_playbook(session)
    _start(session, playbook, alert_id="alert-1")
    _stub_recommended(monkeypatch, {"playbooks": [_playbook(id=99, name="Other book")], "total": 1})
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbooks/alert-1").text
    assert "playbook-execution-" not in body, "an execution read the viewer may not make"
    assert "Other book" in body and "startPlaybook" not in body
    assert "not shown" in body and "playbook:execute" in body


def test_the_section_route_renders_a_400_from_the_handler_as_a_failed_read_with_its_reason(session, monkeypatch):
    _stub_recommended(monkeypatch, raises=HTTPException(400, "Elasticsearch is not configured"))
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbooks/alert-1").text
    assert "could not be read: Elasticsearch is not configured" in body
    assert "No matching playbooks" not in body


def test_the_section_route_tells_a_missing_alert_from_a_failed_read(session, monkeypatch):
    _stub_recommended(monkeypatch, raises=HTTPException(404, "Alert not found"))
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbooks/alert-1").text
    assert "was not found in Elasticsearch" in body and "could not be read" not in body


def test_the_section_route_says_so_when_only_the_executions_read_fails(session, monkeypatch):
    from ion.web import api

    def boom(*a, **k):
        raise RuntimeError("no")

    monkeypatch.setattr(api, "get_alert_playbook_executions", boom)
    _stub_recommended(monkeypatch, {"playbooks": [], "total": 0})
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbooks/alert-1").text
    assert "One may be in progress" in flat(body)
    assert "No matching playbooks for this alert" in body, "the recommendations half still rendered"


def test_the_library_route_groups_the_suggestions_and_gates_start(session, monkeypatch):
    _stub_suggested(monkeypatch, {"playbooks": [
        _suggested(id=1), _suggested(id=2, name="Old", suggestion_type="library")], "total": 2})
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbook-library/alert-1").text
    assert "Recommended (Active)" in body and "From Library" in body and "Old" in body
    assert "startPlaybook" in body
    with TestClient(_app(session, _User(PLAYBOOK_READ_PERMISSION))) as client:
        body = client.get("/ui/alerts/playbook-library/alert-1").text
    assert "startPlaybook" not in body


def test_the_library_route_has_four_outcomes(session, monkeypatch):
    user = _User(PLAYBOOK_READ_PERMISSION)
    _stub_suggested(monkeypatch, {"playbooks": [], "total": 0})
    with TestClient(_app(session, user)) as client:
        empty = client.get("/ui/alerts/playbook-library/alert-1").text
    _stub_suggested(monkeypatch, raises=HTTPException(400, "Elasticsearch is not configured"))
    with TestClient(_app(session, user)) as client:
        failed = client.get("/ui/alerts/playbook-library/alert-1").text
    _stub_suggested(monkeypatch, raises=HTTPException(404, "Alert not found"))
    with TestClient(_app(session, user)) as client:
        missing = client.get("/ui/alerts/playbook-library/alert-1").text
    assert "No matching playbooks in library" in empty and 'role="alert"' not in empty
    assert "Elasticsearch is not configured" in failed and "No matching" not in failed
    assert "was not found" in missing and "could not be read" not in missing


# ---------------------------------------------------------------------------
# The permissions are the JSON routes' own
# ---------------------------------------------------------------------------


def _route_permission(api_router, path: str, method: str) -> Optional[str]:
    for route in api_router.routes:
        if route.path != path or method not in (route.methods or ()):
            continue
        for dep in route.dependant.dependencies:
            call = getattr(dep, "call", None)
            if call is None:
                continue
            try:
                found = inspect.getclosurevars(call).nonlocals.get("permission_name")
            except TypeError:
                found = None
            if isinstance(found, str):
                return found
        return None
    raise AssertionError(f"no route {method} {path}")


def test_the_permission_constants_are_the_ones_the_json_routes_carry():
    from ion.web import api
    from ion.web import case_lifecycle_api as cases

    alerts = "/elasticsearch/alerts/{alert_id}"
    assert _route_permission(api.router, alerts + "/recommended-playbooks", "GET") == PLAYBOOK_READ_PERMISSION
    assert _route_permission(api.router, alerts + "/suggested-playbooks", "GET") == PLAYBOOK_READ_PERMISSION
    assert _route_permission(api.router, "/playbooks", "GET") == PLAYBOOK_READ_PERMISSION
    assert _route_permission(api.router, alerts + "/playbook-executions", "GET") == PLAYBOOK_EXECUTE_PERMISSION
    assert _route_permission(api.router, alerts + "/playbook/{playbook_id}/start", "POST") == PLAYBOOK_EXECUTE_PERMISSION
    assert _route_permission(api.router, "/playbook-executions/{execution_id}/steps/{step_id}", "PUT") == PLAYBOOK_EXECUTE_PERMISSION
    assert _route_permission(api.router, "/playbook-executions/{execution_id}/complete", "POST") == PLAYBOOK_EXECUTE_PERMISSION
    base = "/elasticsearch/alerts/cases/{case_id}"
    assert _route_permission(cases.router, base + "/playbook-executions", "GET") == PLAYBOOK_EXECUTE_PERMISSION
    assert _route_permission(cases.router, base + "/playbook/{playbook_id}/start", "POST") == PLAYBOOK_EXECUTE_PERMISSION


def test_the_fragment_routes_carry_those_same_permissions():
    assert _route_permission(router, "/alerts/case-playbook-executions/{case_id}", "GET") == PLAYBOOK_EXECUTE_PERMISSION
    assert _route_permission(router, "/alerts/case-playbook-picker/{case_id}", "GET") == PLAYBOOK_READ_PERMISSION
    assert _route_permission(router, "/alerts/playbooks/{alert_id}", "GET") == PLAYBOOK_READ_PERMISSION
    assert _route_permission(router, "/alerts/playbook-library/{alert_id}", "GET") == PLAYBOOK_READ_PERMISSION


# ---------------------------------------------------------------------------
# The page shell and the modal fragment that hosts the executions list
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _script() -> str:
    page = _page()
    start = page.rindex('<script nonce="{{ csp_nonce }}">')
    body = page[page.index(">", start) + 1:]
    body = body[:body.index("</script>")]
    return body.replace("{% raw %}", "").replace("{% endraw %}", "")


def test_the_playbook_renderers_and_their_cache_are_gone_from_the_script():
    script = _script()
    for name in ("renderPlaybooksSection", "renderPlaybookLibraryPanel", "renderActiveExecution",
                 "renderLibraryItem", "playbookCache", "loadCasePlaybookExecutions"):
        assert name not in script, name


def test_the_script_has_no_jinja_and_parses():
    script = _script()
    assert "{%" not in script and "{{" not in script
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; the Jinja check above still ran")
    probe = ROOT / "tests" / "unit" / ".alerts_script_probe.js"
    probe.write_text(script, encoding="utf-8")
    try:
        result = subprocess.run([node, "--check", str(probe)], capture_output=True, text=True)
    finally:
        probe.unlink()
    assert result.returncode == 0, result.stderr


def test_the_section_is_requested_from_the_fragment_and_the_read_fact_is_on_the_root():
    page, script = _page(), _script()
    assert 'data-can-read-playbooks="{{' in page
    assert "'/ui/alerts/playbooks/' + encodeURIComponent(alertId)" in script
    assert "if (!canReadPlaybooks())" in script
    assert "root.dataset.canReadPlaybooks === 'true'" in script
    server = SERVER.read_text(encoding="utf-8")
    assert '"can_read_playbooks": user.has_permission("playbook:read")' in server


def test_the_section_reload_control_sits_outside_the_content_it_refreshes():
    """The same invariant, now asserted where the markup lives. Stage 5 moved
    the playbooks section out of renderTriageBar's template literal and into
    the triage bar fragment, so the control is checked against the fragment
    rather than against the page's script. The point is unchanged: a failed
    render of #playbooks-content must not be able to remove the button that
    re-requests it."""
    text = (FRAGMENTS / "alerts_triage_bar.html").read_text(encoding="utf-8")
    section = text[text.index('<div class="playbooks-section" id="playbooks-section">'):]
    section = section[:section.index('id="playbooks-content"')]
    assert 'data-click-action="loadPlaybooksForAlert"' in section


def test_the_library_toggle_uses_the_hidden_attribute_and_requests_the_panel():
    script = _script()
    toggle = script[script.index("function togglePlaybookLibrary"):]
    toggle = toggle[:toggle.index("\n}\n")]
    assert "panel.hidden" in toggle and "style.display" not in toggle
    assert "'/ui/alerts/playbook-library/' + encodeURIComponent(alertId)" in toggle


def test_the_step_box_state_is_mapped_to_a_status_and_skip_reads_the_block():
    script = _script()
    assert "if (status === true) status = 'completed';" in script
    assert "else if (status === false) status = 'pending';" in script
    skip = script[script.index("async function skipRemainingSteps"):]
    skip = skip[:skip.index("\n}\n")]
    assert "block.dataset.pendingStepIds" in skip
    assert "playbookCache" not in skip


def test_the_picker_lands_in_its_host_and_start_refreshes_the_list_by_event():
    page, script = _page(), _script()
    assert '<div id="case-playbook-picker-host"></div>' in page
    assert "'/ui/alerts/case-playbook-picker/' + encodeURIComponent(caseId)" in script
    assert "new CustomEvent('case-playbooks-refresh')" in script
    start = script[script.index("async function startCasePlaybook"):]
    start = start[:start.index("\n}\n")]
    assert "refreshCasePlaybookExecutions()" in start
    assert "fetch(`/api/cases/${caseId}/playbook-executions`)" not in script


def test_the_modal_fragment_loads_the_list_on_load_and_on_the_refresh_event():
    text = (FRAGMENTS / "alerts_case_manage.html").read_text(encoding="utf-8")
    tag = text[text.index('<div id="case-playbook-executions-{{ case.id }}"'):]
    tag = tag[:tag.index(">")]
    assert 'hx-get="/ui/alerts/case-playbook-executions/{{ case.id }}"' in tag
    assert 'hx-trigger="load, case-playbooks-refresh from:body"' in tag
    assert "hx-on" not in text and "js:" not in text


def test_the_modal_reload_control_sits_outside_the_list_it_refreshes():
    text = (FRAGMENTS / "alerts_case_manage.html").read_text(encoding="utf-8")
    heading = text.index(">Playbook Executions</span>")
    target = text.index('<div id="case-playbook-executions-{{ case.id }}"')
    button_start = text.index("<button", heading)
    button = text[button_start:text.index(">", button_start)]
    assert button_start < target, "the control is in the heading, not in the swap target"
    assert 'hx-get="/ui/alerts/case-playbook-executions/{{ case.id }}"' in button
    assert 'hx-target="#case-playbook-executions-{{ case.id }}"' in button


def test_the_fragments_have_no_style_attributes_and_no_evaluated_htmx():
    for name in ("alerts_playbook_case_executions.html", "alerts_playbook_case_picker.html",
                 "alerts_playbooks.html", "alerts_playbook_library.html"):
        text = (FRAGMENTS / name).read_text(encoding="utf-8")
        assert ' style="' not in text, name
        assert "hx-on" not in text and "js:" not in text and "<script" not in text, name


def test_the_region_removed_eleven_write_sites():
    """80 before stage 3, measured by the status tool's expression; the six
    writers held 11 between them. Stage 4, the alert queue, took 15 more,
    so the page reads 54; this equality is lowered by every later stage."""
    assert len(WRITES.findall(_page())) == 18
