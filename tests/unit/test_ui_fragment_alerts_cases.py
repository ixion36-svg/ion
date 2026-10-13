"""The alerts page's case side as fragments: Cases card, slide-out panel,
Add-to-Case picker, management modal and AI summary.

Each case below is something the JavaScript either got right and must keep,
or got wrong and must stop doing. The ones worth reading are the failure
renders, because the defect this conversion exists to remove is that a
failed read and an empty result were the same sentence, or no sentence.

Measured against the tree before the change:

  * loadCases returned early on `!response.ok`, so a failed case list left
    "Loading..." in the Cases card for the life of the page, and
    `data.cases || []` rendered "No cases" for a refusal.
  * The Cases card's closure badge keyed on `c.closure_reason`, which the
    compact list row in case_query_service._summary did not carry. It had
    never rendered.
  * openCasePanel offered status, severity and Add note to every reader;
    all three endpoints require case:update and the page is alert:read.
  * _renderAcpContent wrote `c.severity || 'medium'` and an age of "0m old"
    for a case with no created_at.
  * addToExistingCase fell back to GET /api/cases/ with a trailing slash,
    which matches no route, and assigned the object it got to an array.
  * showCaseDetail rendered nothing at all on a failed read.

The render tests use fixtures: this deployment has one case and no
alerts, and an empty render proves nothing about the rows.
"""
from __future__ import annotations

import html
import inspect
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    Note,
    NoteEntityType,
)
from ion.web.templating import make_templates
from ion.web.ui import alerts as mod
from ion.web.ui.alerts import (
    CREATE_PERMISSION,
    PANEL_ALERTS_SHOWN,
    PERMISSION,
    PLAYBOOK_EXECUTE_PERMISSION,
    PLAYBOOK_READ_PERMISSION,
    SUMMARY_LIMIT,
    TRIAGE_PERMISSION,
    UPDATE_PERMISSION,
    _rows,
    active_total,
    age_label,
    closure_label,
    format_ai_content,
    observable_text,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"
PAGE_CSS = ROOT / "src/ion/web/static/css/alerts-page.css"
SERVER = ROOT / "src/ion/web/server.py"
FRAGMENTS = ROOT / "src/ion/web/templates/_fragments"

SUMMARY = "_fragments/alerts_cases_summary.html"
PANEL = "_fragments/alerts_case_panel.html"
PICKER = "_fragments/alerts_case_picker.html"
MANAGE = "_fragments/alerts_case_manage.html"
AI = "_fragments/alerts_case_ai_summary.html"

# The expression tools/ui_redesign_status.py measures with.
WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


def render(name: str, **ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(name).render(**ctx)


def _case(**over: Any) -> dict:
    """What GET /api/cases/{id} returns, as get_case_detail builds it."""
    base = {
        "id": 7,
        "case_number": "CASE-0007",
        "title": "Suspicious PowerShell on ws-01",
        "description": "Encoded command line seen twice.",
        "status": "open",
        "severity": "high",
        "created_by": "analyst",
        "assigned_to": None,
        "assigned_to_id": None,
        "kibana_assignees": [],
        "kibana_sync_pending": False,
        "affected_hosts": ["ws-01"],
        "affected_users": ["jdoe"],
        "triggered_rules": ["Encoded PowerShell"],
        "evidence_summary": "Two alerts, one host.",
        "source_alert_ids": ["a1"],
        "observables": [{"type": "source_ip", "value": "10.0.0.5"}],
        "kibana_case_id": None,
        "kibana_url": None,
        "dfir_iris_case_id": None,
        "dfir_iris_url": None,
        "closure_reason": None,
        "closure_notes": None,
        "closed_by": None,
        "closed_at": None,
        "created_at": "2026-10-10T08:00:00",
        "updated_at": "2026-10-12T08:00:00",
        "alerts": [{"es_alert_id": "a1", "rule_name": "Encoded PowerShell",
                    "status": "open", "priority": "high", "observables": [],
                    "mitre_techniques": [], "analyst_notes": None}],
        "notes": [{"id": 1, "user": "analyst", "content": "Looking.",
                   "created_at": "2026-10-11T08:00:00"}],
    }
    base.update(over)
    return base


def _summary_row(**over: Any) -> dict:
    base = {
        "id": 3, "case_number": "CASE-0003", "title": "Beaconing from db-02",
        "status": "open", "severity": "medium", "alert_count": 4,
        "closure_reason": None, "status_value": "open", "closure_short": None,
    }
    base.update(over)
    return base


def panel_ctx(**over: Any) -> dict:
    """A data render of the panel with a stand-in for the module's view."""
    case = over.pop("case", _case())
    ctx = {
        "case_id": case["id"] if case else 7, "failed": False, "missing": False,
        "case": case, "view": mod._case_view(case) if case else None,
        "can_update": True,
        "status_options": mod.STATUS_OPTIONS,
        "severity_options": mod.SEVERITY_OPTIONS,
    }
    ctx.update(over)
    return ctx


def manage_ctx(**over: Any) -> dict:
    case = over.pop("case", _case())
    ctx = {
        "case_id": case["id"] if case else 7, "failed": False, "missing": False,
        "case": case, "view": mod._case_view(case) if case else None,
        "can_update": True, "can_triage": True, "can_close": True,
        "can_execute_playbooks": True, "can_start_playbook": True,
        "ai_available": True, "kfp": mod.kfp_context(case) if case else None,
        "status_options": mod.STATUS_OPTIONS,
        "severity_options": mod.SEVERITY_OPTIONS,
    }
    ctx.update(over)
    return ctx


# ---------------------------------------------------------------------------
# The helpers that make the third outcome reachable
# ---------------------------------------------------------------------------


def test_rows_returns_none_for_a_refusal_body_rather_than_an_empty_list():
    assert _rows({"detail": "Not authenticated"}, "cases") is None
    assert _rows({"cases": []}, "cases") == []
    assert _rows(None, "cases") is None


def test_active_total_tells_a_true_zero_from_an_unreadable_count():
    """A status missing from a GROUP BY result is a zero. A payload with no
    by_status at all, or a refusal body, is not a count of anything."""
    assert active_total({"by_status": {}}) == 0
    assert active_total({"by_status": {"open": 2, "closed": 9}}) == 2
    assert active_total({"by_status": {"open": 2, "acknowledged": 3}}) == 5
    assert active_total({}) is None
    assert active_total({"detail": "forbidden"}) is None
    # Not a dict at all. A mutation that returned 0 for this branch survived
    # the first pass because every case above is a dict.
    assert active_total(None) is None
    assert active_total([]) is None
    assert active_total({"by_status": {"open": "2"}}) is None
    assert active_total({"by_status": {"open": True}}) is None


def test_age_label_is_none_for_a_case_with_no_creation_time():
    """The JavaScript initialised the age to 0 ms and said "0m old"."""
    assert age_label(None) is None
    assert age_label("not a date") is None
    assert age_label("") is None


def test_age_label_bands_match_the_javascript_thresholds():
    now = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
    assert age_label(now - timedelta(days=3, hours=2), now) == "3d"
    assert age_label(now - timedelta(hours=5, minutes=30), now) == "5h"
    assert age_label(now - timedelta(minutes=12), now) == "12m"
    # A clock ahead of the server is not a negative age.
    assert age_label(now + timedelta(minutes=5), now) == "0m"


def test_age_label_reads_a_naive_timestamp_as_utc():
    """get_case_detail emits isoformat() of a naive column. new Date() in
    the browser parsed it as local time, so the age was off by the viewer's
    offset. Here naive is UTC, which is what SQLite stores."""
    now = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
    assert age_label("2026-10-13T10:00:00", now) == "2h"
    assert age_label("2026-10-13T10:00:00Z", now) == "2h"
    assert age_label("2026-10-13T11:00:00+01:00", now) == "2h"


def test_closure_label_knows_the_six_reasons_and_passes_an_unknown_one_through():
    assert closure_label("benign_true_positive") == "Benign True Positive"
    assert closure_label("something_new") == "something_new"
    assert closure_label(None) is None
    assert closure_label("") is None


def test_observable_text_follows_the_javascript_fallback_chain():
    assert observable_text({"value": "10.0.0.5", "normalized_value": "x"}) == "10.0.0.5"
    assert observable_text({"normalized_value": "evil.example"}) == "evil.example"
    assert json.loads(observable_text({"type": "hash"})) == {"type": "hash"}
    assert observable_text("plain") == "plain"


def test_format_ai_content_escapes_the_model_text_before_adding_its_own_tags():
    out = str(format_ai_content("**bold** and <script>x</script> `code`\n## Head\n- item\n1. first"))
    assert "<strong>bold</strong>" in out
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "<code" in out and ">code</code>" in out
    assert 'text-[0.9375rem] mt-3">Head</div>' in out
    assert "&bull; item" in out
    assert '<div class="pl-4">1. first</div>' in out


def test_format_ai_content_of_nothing_is_empty_not_the_word_none():
    assert str(format_ai_content(None)) == ""


# ---------------------------------------------------------------------------
# Cases card
# ---------------------------------------------------------------------------


def test_a_failed_case_list_does_not_claim_there_are_no_cases():
    html_ = render(SUMMARY, failed=True, cases=None, active_total=None,
                   facets_failed=True, limit=SUMMARY_LIMIT)
    assert "could not be read" in html_
    assert "No cases" not in html_
    assert 'role="alert"' in html_
    # The badge, out of band, says unknown rather than 0.
    badge = re.search(r'<span id="cases-count"[^>]*hx-swap-oob="true"[^>]*>\s*(\S+)\s*</span>', html_)
    assert badge and badge.group(1) == "?"
    assert "could not be read" in badge.group(0)


def test_an_empty_case_list_says_so_and_does_not_say_the_read_failed():
    html_ = render(SUMMARY, failed=False, cases=[], active_total=0,
                   facets_failed=False, limit=SUMMARY_LIMIT)
    assert "No cases" in html_
    assert "could not be read" not in html_
    assert re.search(r'id="cases-count"[^>]*>\s*0\s*</span>', html_), "zero active is a count"


def test_a_case_row_opens_the_panel_and_carries_its_status_as_a_class():
    html_ = render(SUMMARY, failed=False, cases=[_summary_row()], active_total=1,
                   facets_failed=False, limit=SUMMARY_LIMIT)
    assert "CASE-0003" in html_
    assert "Beaconing from db-02" in html_
    assert 'data-click-action="openCasePanel"' in html_
    assert "data-args='[3]'" in html_
    assert "list-item-count case-status-open" in html_
    assert "style=" not in html_


def test_a_closed_case_in_the_card_shows_its_closure_badge():
    """The badge the JavaScript could never render, because the list row
    did not carry closure_reason."""
    html_ = render(SUMMARY, failed=False, active_total=0, facets_failed=False,
                   limit=SUMMARY_LIMIT,
                   cases=[_summary_row(status="closed", status_value="closed",
                                       closure_reason="false_positive",
                                       closure_short="FP")])
    assert "closure-reason-badge reason-false_positive" in html_
    assert ">FP</span>" in html_
    assert "case-status-closed" in html_


def test_an_open_case_in_the_card_has_no_closure_badge():
    html_ = render(SUMMARY, failed=False, cases=[_summary_row()], active_total=1,
                   facets_failed=False, limit=SUMMARY_LIMIT)
    assert "closure-reason-badge" not in html_


def test_rows_with_an_unreadable_facets_count_still_render_but_the_badge_says_unknown():
    html_ = render(SUMMARY, failed=False, cases=[_summary_row()], active_total=None,
                   facets_failed=True, limit=SUMMARY_LIMIT)
    assert "CASE-0003" in html_
    assert re.search(r'id="cases-count"[^>]*>\s*\?\s*</span>', html_)


def test_an_alert_count_that_did_not_arrive_is_not_zero_alerts():
    html_ = render(SUMMARY, failed=False, active_total=1, facets_failed=False,
                   limit=SUMMARY_LIMIT, cases=[_summary_row(alert_count=None)])
    assert re.search(r'data-case-count="3">\s*\?\s*</span>', html_)
    assert "None" not in html_


# ---------------------------------------------------------------------------
# Slide-out panel
# ---------------------------------------------------------------------------


def test_a_missing_case_in_the_panel_is_worded_as_gone_and_takes_the_header_with_it():
    html_ = render(PANEL, **panel_ctx(missing=True, case=None, view=None))
    assert "no longer exists" in html_
    assert re.search(r'id="acp-title"[^>]*hx-swap-oob="true"[^>]*>not found<', html_)
    assert "No alerts linked" not in html_
    assert "severity" not in html_


def test_a_failed_panel_read_does_not_render_the_empty_states_of_a_case():
    """"No alerts linked." and "No notes yet." are findings about a case.
    A failed read has no case to make findings about."""
    html_ = render(PANEL, **panel_ctx(failed=True, case=None, view=None))
    assert "could not be read" in html_
    assert 'role="alert"' in html_
    assert "No alerts linked" not in html_
    assert "No notes yet" not in html_
    assert "No observables" not in html_
    assert re.search(r'id="acp-number"[^>]*hx-swap-oob="true"[^>]*>Case 7<', html_)


def test_a_panel_render_carries_the_case_and_its_sections():
    html_ = render(PANEL, **panel_ctx())
    assert re.search(r'id="acp-number"[^>]*>CASE-0007<', html_)
    assert re.search(r'id="acp-title"[^>]*>Suspicious PowerShell on ws-01<', html_)
    assert "acp-sev-strip sev-high" in html_
    assert "1 alert" in html_ and "1 observable" in html_
    assert "Encoded PowerShell" in html_
    assert "10.0.0.5" in html_
    assert "Looking." in html_
    assert "/cases?selected=CASE-0007" in html_


def test_an_unrated_case_is_not_rated_medium_and_an_undated_one_has_no_age():
    html_ = render(PANEL, **panel_ctx(case=_case(severity=None, created_at=None)))
    assert "severity not set" in html_
    assert "sev-medium" not in html_
    assert "age unknown" in html_
    assert "0m old" not in html_


def test_the_panel_withholds_the_update_controls_without_case_update():
    with_it = render(PANEL, **panel_ctx(can_update=True))
    without = render(PANEL, **panel_ctx(can_update=False))
    assert "acpUpdateField" in with_it
    assert "acpAddNote" in with_it
    assert "acpUpdateField" not in without
    assert "acpAddNote" not in without
    assert "Read only" in without
    # The values are still shown; only the controls go.
    assert ">open<" in without and ">high<" in without


def test_the_panel_caps_the_alert_list_and_says_how_many_it_left_out():
    alerts = [{"es_alert_id": f"a{i}", "rule_name": f"rule {i}", "status": "open"}
              for i in range(PANEL_ALERTS_SHOWN + 5)]
    html_ = render(PANEL, **panel_ctx(case=_case(alerts=alerts)))
    assert html_.count('class="acp-item-title"') == PANEL_ALERTS_SHOWN + 1  # + the observable
    assert f"Showing {PANEL_ALERTS_SHOWN} of {PANEL_ALERTS_SHOWN + 5}" in html_


def test_a_closed_case_in_the_panel_shows_its_closure_block():
    html_ = render(PANEL, **panel_ctx(case=_case(
        status="closed", closure_reason="duplicate", closure_notes="Same as CASE-0001",
        closed_by="lead", closed_at="2026-10-12T09:00:00")))
    assert "acp-closure-info" in html_
    assert "Duplicate" in html_
    assert "Same as CASE-0001" in html_
    assert "Closed by lead" in html_
    assert 'datetime="2026-10-12T09:00:00"' in html_


# ---------------------------------------------------------------------------
# Add-to-Case picker
# ---------------------------------------------------------------------------


def test_a_failed_picker_read_is_not_no_open_cases_and_offers_no_confirm():
    html_ = render(PICKER, failed=True, cases=None, total=None, truncated=False,
                   selected=2, can_add=True)
    assert "could not be listed" in html_
    assert "No open cases" not in html_
    assert "confirmAddToCase" not in html_
    assert "closeAddToCaseModal" in html_, "the way out stays"


def test_a_picker_with_no_open_cases_says_so_and_offers_no_confirm():
    html_ = render(PICKER, failed=False, cases=[], total=0, truncated=False,
                   selected=2, can_add=True)
    assert "No open cases available" in html_
    assert "confirmAddToCase" not in html_
    assert "could not be listed" not in html_


def test_a_picker_lists_the_cases_and_states_the_selection_count():
    html_ = render(PICKER, failed=False, total=2, truncated=False, selected=3,
                   can_add=True,
                   cases=[_summary_row(), _summary_row(id=4, case_number="CASE-0004",
                                                       title="Other")])
    assert "Adding 3 alert(s)" in html_
    assert '<option value="3">CASE-0003 - Beaconing from db-02</option>' in html_
    assert '<option value="4">CASE-0004 - Other</option>' in html_
    assert "confirmAddToCase" in html_
    assert "Showing the newest" not in html_


def test_the_picker_withholds_add_to_case_without_alert_triage():
    html_ = render(PICKER, failed=False, cases=[_summary_row()], total=1,
                   truncated=False, selected=1, can_add=False)
    assert "confirmAddToCase" not in html_
    assert "alert:triage" in html_
    assert 'id="target-case-id"' in html_, "the list is still shown"


def test_a_truncated_picker_says_it_is_truncated():
    html_ = render(PICKER, failed=False, cases=[_summary_row()], total=140,
                   truncated=True, selected=1, can_add=True)
    assert "Showing the newest 1 of 140" in html_


# ---------------------------------------------------------------------------
# Management modal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("outcome", ["failed", "missing"])
def test_a_management_modal_that_could_not_load_still_opens_with_a_way_out(outcome):
    """showCaseDetail logged a failed read and rendered nothing, so the
    click did nothing visible."""
    ctx = manage_ctx(case=None, view=None, kfp=None)
    ctx["case_id"] = 7
    ctx[outcome] = True
    html_ = render(MANAGE, **ctx)
    assert 'id="case-mgmt-overlay"' in html_
    assert 'role="alert"' in html_
    assert ("no longer exists" if outcome == "missing" else "could not be read") in html_
    assert 'data-remove-target="case-mgmt-overlay"' in html_
    assert "<select" not in html_
    assert "closeCaseWithAlerts" not in html_
    assert "No linked alerts" not in html_


def test_the_management_modal_renders_the_case():
    html_ = render(MANAGE, **manage_ctx())
    assert "CASE-0007: Suspicious PowerShell on ws-01" in html_
    assert 'id="ai-case-summary-7"' in html_
    assert 'id="case-fp-banner-7"' in html_
    assert "Two alerts, one host." in html_
    assert "Encoded command line seen twice." in html_
    assert 'class="context-tag tag-host">ws-01<' in html_
    assert "Linked Alerts (1)" in html_
    assert 'data-click-action="showAlertDetail"' in html_
    assert "Looking." in html_
    assert 'data-case-status="open"' in html_


def test_the_management_modal_description_is_text_not_markup():
    """The page rendered it through marked plus DOMPurify. ION has no
    server-side sanitiser, so it is escaped text with line breaks kept."""
    html_ = render(MANAGE, **manage_ctx(case=_case(description="line one\n<img src=x onerror=alert(1)>")))
    assert "<img" not in html_
    assert "&lt;img" in html_
    assert "whitespace-pre-wrap" in html_


def test_the_management_modal_withholds_the_update_controls_without_case_update():
    without = render(MANAGE, **manage_ctx(can_update=False))
    with_it = render(MANAGE, **manage_ctx(can_update=True))
    for action in ("handleCaseStatusChange", "updateCaseField",
                   "addCaseNoteFromModal", "escalateToDFIRIRIS"):
        assert action in with_it
        assert action not in without, action
    assert "Read only" in without


def test_close_case_as_follows_can_close_not_can_update():
    """With linked alerts the close goes through POST .../alerts/{id}/close
    (alert:triage); with none, through PATCH /api/cases/{id} (case:update).
    The module computes can_close; the template must honour it alone."""
    offered = render(MANAGE, **manage_ctx(can_close=True))
    withheld = render(MANAGE, **manage_ctx(can_close=False, can_update=True))
    assert offered.count("closeCaseWithAlerts") == 6
    assert "closeCaseWithAlerts" not in withheld
    assert "Closing this case requires the alert:triage permission" in withheld
    no_alerts = render(MANAGE, **manage_ctx(case=_case(alerts=[]), can_close=False))
    assert "requires the case:update permission" in no_alerts


def test_a_closed_case_offers_no_close_case_as_and_shows_its_closure():
    html_ = render(MANAGE, **manage_ctx(case=_case(
        status="closed", closure_reason="true_positive", closed_by="lead",
        closed_at="2026-10-12T09:00:00")))
    assert "closeCaseWithAlerts" not in html_
    assert "Closing this case requires" not in html_
    assert "closure-reason-badge reason-true_positive" in html_
    assert "True Positive" in html_


def test_per_alert_closure_buttons_need_alert_triage():
    with_it = render(MANAGE, **manage_ctx(can_triage=True))
    without = render(MANAGE, **manage_ctx(can_triage=False))
    assert with_it.count("showAlertClosureModal") == 3
    assert "showAlertClosureModal" not in without
    assert 'data-click-action="showAlertDetail"' in without, "opening the alert is alert:read"


def test_the_playbook_section_needs_execute_and_start_needs_read_as_well():
    full = render(MANAGE, **manage_ctx())
    no_execute = render(MANAGE, **manage_ctx(can_execute_playbooks=False, can_start_playbook=False))
    no_read = render(MANAGE, **manage_ctx(can_execute_playbooks=True, can_start_playbook=False))
    assert 'id="case-playbook-executions-7"' in full and "showCasePlaybookPicker" in full
    assert "case-playbook-executions" not in no_execute
    assert "showCasePlaybookPicker" not in no_execute
    assert 'id="case-playbook-executions-7"' in no_read
    assert "showCasePlaybookPicker" not in no_read


def test_ai_summary_is_offered_only_when_the_service_answered():
    assert "aiSummarizeCase" in render(MANAGE, **manage_ctx(ai_available=True))
    assert "aiSummarizeCase" not in render(MANAGE, **manage_ctx(ai_available=False))


def test_the_kfp_context_on_the_overlay_is_json_the_page_can_parse():
    html_ = render(MANAGE, **manage_ctx(case=_case(title='Quote " in title',
                                                   affected_hosts=['ws-"01'])))
    raw = re.search(r"data-kfp-context='([^']*)'", html_).group(1)
    ctx = json.loads(html.unescape(raw))
    assert ctx["id"] == 7
    assert ctx["affected_hosts"] == ['ws-"01']
    assert ctx["observables"] == [{"type": "source_ip", "value": "10.0.0.5"}]


def test_dfir_iris_shows_the_link_when_escalated_and_the_button_only_when_allowed():
    linked = render(MANAGE, **manage_ctx(case=_case(dfir_iris_case_id=42,
                                                    dfir_iris_url="https://iris/case/42")))
    assert "View in DFIR-IRIS #42" in linked
    assert "escalateToDFIRIRIS" not in linked
    unlinked_reader = render(MANAGE, **manage_ctx(can_update=False))
    assert "escalateToDFIRIRIS" not in unlinked_reader
    assert "DFIR-IRIS" not in unlinked_reader


# ---------------------------------------------------------------------------
# AI summary
# ---------------------------------------------------------------------------


def test_the_four_ai_summary_failures_are_worded_differently():
    base = dict(case_id=7, missing=False, unavailable=None, failed=False,
                analysis=None, model=None)
    missing = render(AI, **{**base, "missing": True})
    unavailable = render(AI, **{**base, "unavailable": "AI service not available"})
    failed = render(AI, **{**base, "failed": True})
    empty = render(AI, **base)
    assert "no longer exists" in missing
    assert "AI summary unavailable: AI service not available" in unavailable
    assert "could not be produced" in failed
    assert "answered with no text" in empty
    for h in (missing, unavailable, failed, empty):
        assert 'role="alert"' in h
        assert "AI Case Summary" not in h


def test_an_ai_summary_renders_the_formatted_analysis_and_the_model():
    html_ = render(AI, case_id=7, missing=False, unavailable=None, failed=False,
                   analysis=format_ai_content("**Summary**: fine"), model="llama3")
    assert "AI Case Summary" in html_
    assert "<strong>Summary</strong>" in html_
    assert 'class="ai-model-tag">llama3<' in html_


def test_a_summary_whose_model_was_not_reported_says_so():
    html_ = render(AI, case_id=7, missing=False, unavailable=None, failed=False,
                   analysis=format_ai_content("x"), model=None)
    assert "model not reported" in html_
    assert "None" not in html_


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


def _make_case(session, number="CASE-0101", status=AlertCaseStatus.OPEN,
               alerts=1, note=True, **over) -> AlertCase:
    case = AlertCase(case_number=number, title=f"probe {number}", status=status,
                     severity="high", created_by_id=1, affected_hosts=["ws-01"],
                     observables=[{"type": "source_ip", "value": "10.0.0.5"}], **over)
    session.add(case)
    session.commit()
    for i in range(alerts):
        session.add(AlertTriage(es_alert_id=f"{number}-alert-{i}", case_id=case.id,
                                rule_name="Encoded PowerShell"))
    if note:
        session.add(Note(entity_type=NoteEntityType.CASE, entity_id=str(case.id),
                         user_id=1, content="probe note"))
    session.commit()
    return case


GET_PATHS = [
    "/ui/alerts/cases-summary",
    "/ui/alerts/case-panel/1",
    "/ui/alerts/case-picker",
    "/ui/alerts/case-manage/1",
]


@pytest.mark.parametrize("path", GET_PATHS)
def test_a_read_fragment_refuses_a_caller_without_case_read(session, path):
    with TestClient(_app(session, _User("alert:read", UPDATE_PERMISSION))) as client:
        assert client.get(path).status_code == 403


def test_the_ai_summary_fragment_refuses_a_caller_without_case_read(session):
    with TestClient(_app(session, _User("alert:read"))) as client:
        assert client.post("/ui/alerts/case-summary/1").status_code == 403


@pytest.mark.parametrize("path", GET_PATHS)
def test_case_read_alone_opens_every_read_fragment(session, path):
    _make_case(session)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        assert client.get(path).status_code == 200


def test_the_summary_route_renders_a_real_case_and_counts_it(session):
    _make_case(session, "CASE-0101")
    _make_case(session, "CASE-0102", status=AlertCaseStatus.ACKNOWLEDGED, alerts=0)
    _make_case(session, "CASE-0103", status=AlertCaseStatus.CLOSED, alerts=0,
               closure_reason="false_positive")
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/cases-summary").text
    assert "CASE-0101" in body and "CASE-0103" in body
    assert re.search(r'id="cases-count"[^>]*>\s*2\s*</span>', body), "open + acknowledged"
    assert ">FP</span>" in body, "closure_reason reaches the row through _summary"
    assert 'data-case-count="' in body
    assert "case-status-closed" in body


def test_the_summary_route_says_so_when_the_list_cannot_be_read(session, monkeypatch):
    from ion.services import case_query_service as cq

    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(cq, "list_cases_page", boom)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/cases-summary").text
    assert "could not be read" in body
    assert "No cases" not in body
    # The facets read is independent and succeeded, so the badge is a real
    # count (zero active cases in this database) beside a list that could
    # not be read. Two reads, two answers, as in the JavaScript.
    assert re.search(r'id="cases-count"[^>]*>\s*0\s*</span>', body)


def test_a_list_payload_with_no_case_list_is_a_failed_read_not_an_empty_one(session, monkeypatch):
    """The third outcome at the route: the service answered, with a shape
    this fragment cannot read. `data.cases || []` rendered "No cases" for
    it. A mutation that stopped flagging it survived the first pass because
    the only failure exercised was the service raising."""
    from ion.services import case_query_service as cq

    monkeypatch.setattr(cq, "list_cases_page", lambda *a, **k: {"detail": "wrong shape"})
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/cases-summary").text
    assert "could not be read" in body
    assert "No cases" not in body


def test_the_summary_route_marks_the_badge_unknown_when_both_reads_fail(session, monkeypatch):
    from ion.services import case_query_service as cq

    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(cq, "list_cases_page", boom)
    monkeypatch.setattr(cq, "case_facets", boom)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/cases-summary").text
    assert "could not be read" in body
    assert re.search(r'id="cases-count"[^>]*>\s*\?\s*</span>', body)


def test_the_summary_route_keeps_the_rows_when_only_the_facets_fail(session, monkeypatch):
    from ion.services import case_query_service as cq

    _make_case(session)

    def boom(*a, **k):
        raise RuntimeError("count failed")

    monkeypatch.setattr(cq, "case_facets", boom)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/cases-summary").text
    assert "CASE-0101" in body
    assert 'role="alert"' not in body, "the rows read fine; only the count is unknown"
    assert re.search(r'id="cases-count"[^>]*title="The active case count could not be read"[^>]*>\s*\?\s*</span>', body)


def test_the_summary_route_asks_for_the_rows_it_shows(session, monkeypatch):
    from ion.services import case_query_service as cq

    seen = {}
    real = cq.list_cases_page

    def spy(sess, **kw):
        seen.update(kw)
        return real(sess, **kw)

    monkeypatch.setattr(cq, "list_cases_page", spy)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        client.get("/ui/alerts/cases-summary")
    assert seen["limit"] == SUMMARY_LIMIT
    assert seen["sort"] == "created_at" and seen["order"] == "desc"


def test_the_panel_route_renders_a_real_case_and_withholds_updates_for_a_reader(session):
    case = _make_case(session)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-panel/{case.id}").text
    assert "CASE-0101" in body, "the case must render or this proves nothing"
    assert "Encoded PowerShell" in body
    assert "probe note" in body
    assert "acpUpdateField" not in body
    assert "acpAddNote" not in body
    assert "Read only" in body

    with TestClient(_app(session, _User(PERMISSION, UPDATE_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-panel/{case.id}").text
    assert "acpUpdateField" in body and "acpAddNote" in body


def test_the_panel_route_answers_a_missing_case_as_gone_not_as_a_404(session):
    """htmx does not swap a 404, so the previous case's body would stay on
    screen under this id. The fragment swaps a sentence in instead."""
    with TestClient(_app(session, _User(PERMISSION))) as client:
        resp = client.get("/ui/alerts/case-panel/999")
    assert resp.status_code == 200
    assert "no longer exists" in resp.text
    assert "could not be read" not in resp.text


def test_the_panel_route_says_so_when_the_read_raises(session, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("es down")

    monkeypatch.setattr(mod, "_read_case", boom)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/case-panel/1").text
    assert "could not be read" in body
    assert "no longer exists" not in body
    assert "No alerts linked" not in body


def test_the_picker_route_lists_open_and_acknowledged_cases_only(session):
    _make_case(session, "CASE-0101", status=AlertCaseStatus.OPEN, alerts=0)
    _make_case(session, "CASE-0102", status=AlertCaseStatus.ACKNOWLEDGED, alerts=0)
    _make_case(session, "CASE-0103", status=AlertCaseStatus.CLOSED, alerts=0)
    with TestClient(_app(session, _User(PERMISSION, TRIAGE_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-picker?selected=3").text
    assert "CASE-0101" in body and "CASE-0102" in body
    assert "CASE-0103" not in body
    assert "Adding 3 alert(s)" in body
    assert "confirmAddToCase" in body


def test_the_picker_route_withholds_add_without_alert_triage(session):
    _make_case(session, alerts=0)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get("/ui/alerts/case-picker?selected=1").text
    assert "CASE-0101" in body, "the list must render or this proves nothing"
    assert "confirmAddToCase" not in body


def test_the_picker_route_refuses_a_negative_selection_count(session):
    with TestClient(_app(session, _User(PERMISSION))) as client:
        assert client.get("/ui/alerts/case-picker?selected=-1").status_code == 422


def test_the_picker_route_says_so_when_the_list_raises(session, monkeypatch):
    from ion.services import case_query_service as cq

    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(cq, "list_cases_page", boom)
    with TestClient(_app(session, _User(PERMISSION, TRIAGE_PERMISSION))) as client:
        body = client.get("/ui/alerts/case-picker").text
    assert "could not be listed" in body
    assert "No open cases" not in body
    assert "confirmAddToCase" not in body


def test_the_manage_route_derives_can_close_from_the_case_and_the_viewer(session, monkeypatch):
    async def off():
        return False

    monkeypatch.setattr(mod, "_ai_available", off)
    with_alerts = _make_case(session, "CASE-0101", alerts=2)
    no_alerts = _make_case(session, "CASE-0102", alerts=0)

    updater = _User(PERMISSION, UPDATE_PERMISSION)
    with TestClient(_app(session, updater)) as client:
        linked = client.get(f"/ui/alerts/case-manage/{with_alerts.id}").text
        bare = client.get(f"/ui/alerts/case-manage/{no_alerts.id}").text
    assert "CASE-0101" in linked and "CASE-0102" in bare
    assert "closeCaseWithAlerts" not in linked, "linked alerts close through alert:triage"
    assert "closeCaseWithAlerts" in bare, "no alerts: the PATCH needs case:update, which this viewer has"

    triager = _User(PERMISSION, TRIAGE_PERMISSION)
    with TestClient(_app(session, triager)) as client:
        linked = client.get(f"/ui/alerts/case-manage/{with_alerts.id}").text
        bare = client.get(f"/ui/alerts/case-manage/{no_alerts.id}").text
    assert "closeCaseWithAlerts" in linked
    assert "closeCaseWithAlerts" not in bare
    assert "aiSummarizeCase" not in linked, "AI probe said no"


def test_the_manage_route_offers_ai_summary_when_the_probe_answers(session, monkeypatch):
    async def on():
        return True

    monkeypatch.setattr(mod, "_ai_available", on)
    case = _make_case(session)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-manage/{case.id}").text
    assert "CASE-0101" in body
    assert "aiSummarizeCase" in body


def test_the_manage_route_gates_playbooks_on_execute_and_start_on_read_too(session, monkeypatch):
    async def off():
        return False

    monkeypatch.setattr(mod, "_ai_available", off)
    case = _make_case(session)
    with TestClient(_app(session, _User(PERMISSION, PLAYBOOK_EXECUTE_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-manage/{case.id}").text
    assert f'id="case-playbook-executions-{case.id}"' in body
    assert "showCasePlaybookPicker" not in body
    with TestClient(_app(session, _User(PERMISSION, PLAYBOOK_EXECUTE_PERMISSION,
                                        PLAYBOOK_READ_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-manage/{case.id}").text
    assert "showCasePlaybookPicker" in body
    with TestClient(_app(session, _User(PERMISSION, PLAYBOOK_READ_PERMISSION))) as client:
        body = client.get(f"/ui/alerts/case-manage/{case.id}").text
    assert "case-playbook-executions" not in body


def test_the_manage_route_answers_a_missing_case_with_a_dialog_that_says_so(session, monkeypatch):
    async def off():
        return False

    monkeypatch.setattr(mod, "_ai_available", off)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        resp = client.get("/ui/alerts/case-manage/999")
    assert resp.status_code == 200
    assert "no longer exists" in resp.text
    assert 'id="case-mgmt-overlay"' in resp.text


def test_the_ai_summary_route_runs_the_json_handler_with_the_case_payload(session, monkeypatch):
    import ion.web.ai_api as ai_api

    seen = {}

    async def fake_analyze(alert_data, current_user=None, session=None):
        seen.update(alert_data)
        return {"analysis": "**Summary**: two alerts", "model": "llama3"}

    monkeypatch.setattr(ai_api, "analyze_alert", fake_analyze)
    case = _make_case(session, alerts=2)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        body = client.post(f"/ui/alerts/case-summary/{case.id}").text
    assert seen["type"] == "case_summary"
    assert seen["case_number"] == "CASE-0101"
    assert seen["alerts_count"] == 2
    assert seen["affected_hosts"] == ["ws-01"]
    assert "<strong>Summary</strong>" in body
    assert 'class="ai-model-tag">llama3<' in body


def test_the_ai_summary_route_renders_a_503_as_unavailable_with_its_reason(session, monkeypatch):
    import ion.web.ai_api as ai_api

    async def refused(alert_data, current_user=None, session=None):
        raise HTTPException(status_code=503, detail="AI service not available")

    monkeypatch.setattr(ai_api, "analyze_alert", refused)
    case = _make_case(session)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        resp = client.post(f"/ui/alerts/case-summary/{case.id}")
    assert resp.status_code == 200
    assert "AI summary unavailable: AI service not available" in resp.text
    assert "AI Case Summary" not in resp.text


def test_the_ai_summary_route_tells_a_missing_case_from_a_failed_model(session, monkeypatch):
    import ion.web.ai_api as ai_api

    async def boom(alert_data, current_user=None, session=None):
        raise RuntimeError("socket closed")

    monkeypatch.setattr(ai_api, "analyze_alert", boom)
    case = _make_case(session)
    with TestClient(_app(session, _User(PERMISSION))) as client:
        missing = client.post("/ui/alerts/case-summary/999").text
        failed = client.post(f"/ui/alerts/case-summary/{case.id}").text
    assert "no longer exists" in missing
    assert "could not be produced" in failed
    assert "no longer exists" not in failed


# ---------------------------------------------------------------------------
# The permissions, derived from the route table rather than restated
# ---------------------------------------------------------------------------


def _route_permission(api_router, path: str, method: str) -> Optional[str]:
    """The permission a route's require_permission guard closes over."""
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

    base = "/elasticsearch/alerts/cases"
    assert _route_permission(cases.router, base, "GET") == PERMISSION
    assert _route_permission(cases.router, base + "/facets", "GET") == PERMISSION
    assert _route_permission(cases.router, base + "/{case_id}", "GET") == PERMISSION
    assert _route_permission(cases.router, base + "/{case_id}", "PATCH") == UPDATE_PERMISSION
    assert _route_permission(cases.router, base + "/{case_id}/notes", "POST") == UPDATE_PERMISSION
    assert _route_permission(cases.router, base, "POST") == CREATE_PERMISSION
    assert _route_permission(cases.router, base + "/{case_id}/playbook-executions", "GET") == PLAYBOOK_EXECUTE_PERMISSION
    assert _route_permission(api.router, "/elasticsearch/alerts-triage/bulk-update", "POST") == TRIAGE_PERMISSION
    assert _route_permission(api.router, "/elasticsearch/alerts/{alert_id}/close", "POST") == TRIAGE_PERMISSION
    assert _route_permission(api.router, "/playbooks", "GET") == PLAYBOOK_READ_PERMISSION


def test_the_ai_handler_the_summary_reuses_is_auth_only():
    """So case:read, the read half of the flow, is the right gate and not a
    softer one than either endpoint."""
    from ion.web import ai_api

    assert _route_permission(ai_api.router, "/api/ai/analyze/alert", "POST") is None


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _script() -> str:
    page = _page()
    start = page.rindex('<script nonce="{{ csp_nonce }}">')
    body = page[page.index(">", start) + 1:]
    body = body[:body.index("</script>")]
    return body.replace("{% raw %}", "").replace("{% endraw %}", "")


def test_the_cases_card_pulls_its_rows_from_the_fragment_on_load_and_on_refresh_events():
    page = _page()
    tag = page[page.index('id="cases-summary"'):]
    tag = tag[:tag.index(">")]
    assert 'hx-get="/ui/alerts/cases-summary"' in tag
    assert "hx-trigger=" in tag and "load" in tag and "cases-refresh from:body" in tag
    assert "cases-refresh" in _script(), "loadCases must dispatch the event the card listens for"


def test_the_cases_refresh_control_sits_outside_the_card_it_refreshes():
    page = _page()
    heading = page.index(">Cases</h3>")
    target = page.index('id="cases-summary"')
    button_start = page.index("<button", heading)
    button = page[button_start:page.index(">", button_start)]
    assert button_start < target, "the control is in the header, not in the swap target"
    assert 'hx-get="/ui/alerts/cases-summary"' in button
    assert 'hx-target="#cases-summary"' in button


def test_the_panel_names_its_loading_indicator_outside_the_body():
    page = _page()
    panel = page[page.index('id="acp-panel"'):page.index('id="acp-body"')]
    assert 'hx-indicator="#acp-loading"' in panel
    assert 'id="acp-loading"' in panel, "the indicator is before the body, not inside it"


def test_the_dialog_hosts_and_templates_are_on_the_page():
    page = _page()
    for needle in ('id="add-to-case-host"', 'id="case-mgmt-host"',
                   '<template id="case-create-template">',
                   '<template id="bulk-case-create-template">',
                   '<template id="case-closure-quick-template">'):
        assert needle in page, needle


def test_the_create_case_submit_is_offered_only_with_case_create():
    page = _page()
    macro = page[page.index("{% macro create_case_form"):page.index("{% endmacro %}")]
    gate = macro.index("{% if can_create_case %}")
    assert 'data-click-action="{{ submit_action }}"' in macro[gate:]
    assert "{{ submit_action }}" not in macro[:gate]
    assert 'data-can-create-case="{{' in page
    assert _script().count("!canCreateCase()") == 2, (
        "both showCreateCaseForm and showCreateCaseFromSelected check it"
    )


@pytest.mark.parametrize("opener,submitter,template_id", [
    ("showCreateCaseForm", "submitCreateCase", "case-create-template"),
    ("showCreateCaseFromSelected", "submitBulkCreateCase", "bulk-case-create-template"),
])
def test_the_create_form_templates_carry_every_field_the_handlers_read(opener, submitter, template_id):
    """Found live: the first version of the template named the evidence
    field `case-evidence` while submitCreateCase reads
    `case-evidence-summary`, and the opener threw on a null element. The
    ids the opener fills and the ids the submitter reads must both be in
    the rendered template, which the page shell renders with Jinja."""
    page = _page()
    script = _script()

    def ids_read(fn_name):
        start = script.index(f"function {fn_name}(")
        nxt = [i for i in (script.find("\nfunction ", start + 10),
                           script.find("\nasync function ", start + 10)) if i != -1]
        body = script[start:min(nxt)] if nxt else script[start:]
        return set(re.findall(r"getElementById\('((?:bulk-)?case-[a-z-]+)'\)", body)) | set(
            re.findall(r"querySelector\('#((?:bulk-)?case-[a-z-]+)'\)", body))

    wanted = ids_read(opener) | ids_read(submitter)
    wanted -= {"case-create-overlay", "bulk-case-create-overlay"}
    assert wanted, "the handlers read fields by id, or this test checks nothing"

    env = make_templates().env
    tpl = page[page.index(f'<template id="{template_id}">'):]
    tpl = tpl[:tpl.index("</template>")]
    macro = page[page.index("{% macro create_case_form"):page.index("{% endmacro %}") + len("{% endmacro %}")]
    rendered = env.from_string(macro + tpl).render(can_create_case=True)
    for field_id in sorted(wanted):
        assert f'id="{field_id}"' in rendered, field_id


def test_the_page_route_passes_the_create_permission_as_a_fact_about_the_viewer():
    server = SERVER.read_text(encoding="utf-8")
    handler = server[server.index("async def alerts_page"):]
    handler = handler[:handler.index("@app.get", 10)]
    assert '"can_create_case"' in handler
    assert 'has_permission("case:create")' in handler


def test_the_script_block_holds_no_jinja_so_it_stays_checkable():
    assert not re.search(r"\{\{|\{%", _script())


def test_the_page_no_longer_builds_the_case_side_in_javascript():
    script = _script()
    for gone in ("function renderCasesSummary", "function _renderAcpContent",
                 "function renderCaseManagementModal", "_ACP_CLOSURE_LABELS",
                 "casesActiveTotal", "fetch('/api/cases/')"):
        assert gone not in script, gone
    for kept in ("function openCasePanel", "function showCaseDetail",
                 "function addToExistingCase", "function aiSummarizeCase",
                 "function closeCaseWithAlerts", "function showCreateCaseForm",
                 "function showCreateCaseFromSelected", "function cloneTemplate"):
        assert kept in script, kept
    for route in ("/ui/alerts/case-panel/", "/ui/alerts/case-manage/",
                  "/ui/alerts/case-picker", "/ui/alerts/case-summary/"):
        assert route in script, route


def test_the_five_modal_refreshes_go_through_the_fragment():
    """Five callers re-fetched /api/cases/{id} and handed the JSON to
    renderCaseManagementModal. They call showCaseDetail now, which is one
    request where there were two."""
    script = _script()
    assert "renderCaseManagementModal(" not in script
    assert script.count("await showCaseDetail(caseId)") == 5


#: DOM write sites left in alerts.html after this stage. The plan measured
#: 93 before it; this stage removed 13 (openCasePanel 3, renderCasesSummary
#: 2, aiSummarizeCase 3, and one each in closeCaseWithAlerts,
#: addToExistingCase, showCreateCaseForm, showCreateCaseFromSelected and
#: renderCaseManagementModal). This number may only go down. Stage 3, the
#: playbook region, removed 11 more (loadCasePlaybookExecutions 3,
#: renderPlaybooksSection 2, togglePlaybookLibrary 2,
#: renderPlaybookLibraryPanel 2, showCasePlaybookPicker 1,
#: loadPlaybooksForAlert 1): 80 to 69. Stage 4, the alert queue, removed
#: 15 more (loadAlerts 9, _renderAlertsFallback 2, renderSideList 2,
#: renderFilterChips 1, populateSystemFilterFromAlerts 1): 69 to 54.
WRITES_REMAINING = 54


def test_the_dom_writes_in_the_page_do_not_increase():
    assert len(WRITES.findall(_page())) == WRITES_REMAINING


def test_the_converted_functions_hold_no_dom_writes():
    script = _script()
    for name in ("openCasePanel", "showCaseDetail", "addToExistingCase",
                 "aiSummarizeCase", "closeCaseWithAlerts", "showCreateCaseForm",
                 "showCreateCaseFromSelected"):
        start = script.index(f"function {name}(")
        end = script.index("\nfunction ", start + 10) if "\nfunction " in script[start + 10:] else len(script)
        end2 = script.index("\nasync function ", start + 10) if "\nasync function " in script[start + 10:] else len(script)
        body = script[start:min(end, end2)]
        assert not WRITES.search(body), name


# ---------------------------------------------------------------------------
# CSP
# ---------------------------------------------------------------------------


FRAGMENT_FILES = ["alerts_cases_summary.html", "alerts_case_panel.html",
                  "alerts_case_picker.html", "alerts_case_manage.html",
                  "alerts_case_ai_summary.html"]


@pytest.mark.parametrize("name", FRAGMENT_FILES)
def test_a_fragment_carries_nothing_the_csp_would_block(name):
    text = (FRAGMENTS / name).read_text(encoding="utf-8")
    assert not re.search(r"\sstyle=", text), "style-src-attr 'none'"
    assert "hx-on" not in text, "Function()-evaluated, blocked without unsafe-eval"
    assert "js:" not in text
    assert "<script" not in text
    assert "onclick=" not in text


def test_the_page_additions_carry_nothing_the_csp_would_block():
    page = _page()
    shell = page[:page.rindex('<script nonce="{{ csp_nonce }}">')]
    assert "hx-on" not in shell
    assert 'hx-vals="js:' not in shell and 'hx-headers="js:' not in shell
    for trigger in re.findall(r'hx-trigger="([^"]*)"', shell):
        assert "[" not in trigger, f"event filter in {trigger!r} is evaluated"


def test_the_status_colour_classes_the_card_emits_have_rules_in_the_stylesheet():
    css = PAGE_CSS.read_text(encoding="utf-8")
    for status in ("open", "acknowledged", "closed"):
        assert f".side-panel .list-item-count.case-status-{status} {{" in css
    assert ".ai-case-summary.visible.ion-busy:empty::before" in css


def test_the_permission_constants_match_what_the_endpoints_declare():
    assert PERMISSION == "case:read"
    assert UPDATE_PERMISSION == "case:update"
    assert CREATE_PERMISSION == "case:create"
    assert TRIAGE_PERMISSION == "alert:triage"
    assert PLAYBOOK_EXECUTE_PERMISSION == "playbook:execute"
    assert PLAYBOOK_READ_PERMISSION == "playbook:read"


def test_the_list_row_now_carries_the_closure_reason_the_badge_keys_on():
    """Additive to GET /api/cases: the compact row gains one 50-char enum."""
    from ion.services.case_query_service import _summary

    class Row:
        id = 1
        case_number = "CASE-1"
        title = "t"
        status = AlertCaseStatus.CLOSED
        severity = "low"
        created_at = updated_at = closed_at = None
        assigned_to_id = None
        kibana_case_id = None
        dfir_iris_case_id = None
        closure_reason = "duplicate"

    assert _summary((Row(), None, 0))["closure_reason"] == "duplicate"
