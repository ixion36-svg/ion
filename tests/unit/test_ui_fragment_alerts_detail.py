"""The alert detail modal's triage bar, comments, case tab, KFP banner and
OpenCTI enrichment as fragments.

Every test goes through a route and TestClient. Nothing in this file renders
a template with a hand-built context, because across many mutation rounds on
this project every first-pass survivor was a template tested that way while
the module computing its context went undriven.

Measured on the page before this stage, by reading alerts.html:

  * loadTriage returned on `!response.ok`, so a failed read left the bar on
    the shell's "Loading triage..." for the life of the modal, and wrote
    `data.comments || []`, so a payload with no comment list read as an
    alert nobody had commented on.
  * renderMitreSection mapped over the MERGED technique list,
    `[auto, ...saved]`, and passed that position to removeMitreTechnique,
    which splices the SAVED list. With an auto technique present every index
    was one too high: removing the first deleted the second, and removing
    the last fell outside the array and silently did nothing.
  * The Bob badge's early return tested `=== null && === undefined`, which
    no value can satisfy.
  * checkKFPMatches returned early in three situations and rendered nothing
    in all of them, so a failed check looked like a clean case.
  * enrichObservables wrote `data.results || []` and renderEnrichResults
    answered "No results returned." for it, and that sentence shared the
    `enrich-no-match` class with a 503, a malformed answer and the catch.
  * renderCaseTab filled in `c.notes || []`, `c.severity || '-'`,
    `c.assigned_to || 'Unassigned'` and `c.closed_by || 'unknown'`, and read
    `c.alerts.length` without a guard.
  * Every data-args on these renderers was built by interpolating
    escapeHtml output into a JSON array. escapeHtml turns a double quote
    into &quot;, which the browser decodes to a bare quote inside the JSON
    string; event-delegation.js parses data-args with JSON.parse and on a
    throw it logs and returns, so the control looked functional and did
    nothing.
"""
from __future__ import annotations

import html
import inspect
import json
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import ion.web.api as api
from ion.web.ui import alerts as mod
from ion.web.ui.alerts import (
    BOB_HIGH,
    BOB_LOW_CONFIDENCE,
    BOB_MEDIUM,
    DETAIL_PERMISSION,
    PERMISSION,
    TRIAGE_PERMISSION,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"
FRAGMENTS = ROOT / "src/ion/web/templates/_fragments"


def flat(markup: str) -> str:
    """Rendered markup with its whitespace collapsed. Prose in a template
    wraps, so a sentence asserted as one string would otherwise fail on
    where the paragraph breaks rather than on what it says."""
    return " ".join(markup.split())


def text_of(markup: str) -> str:
    """The visible text: tags stripped, entities decoded, space collapsed."""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


class _User:
    id = 1
    username = "detail-tester"

    def __init__(self, *permissions: str):
        self.permissions = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self.permissions


READER = ("alert:read",)
WITH_CASE = ("alert:read", "case:read")
FULL = ("alert:read", "case:read", "alert:triage", "case:create",
        "case:update", "playbook:read")


class _Query:
    def __init__(self, row, boom):
        self._row, self._boom = row, boom

    def filter_by(self, **_kw):
        return self

    def first(self):
        if self._boom:
            raise RuntimeError("triage table unavailable")
        return self._row


class _Session:
    """Only the one query the enrich route makes."""

    def __init__(self, row=None, boom=False):
        self._row, self._boom = row, boom

    def query(self, _model):
        return _Query(self._row, self._boom)


class _Triage:
    def __init__(self, observables):
        self.observables = observables


def _app(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: session
    return application


def get(url: str, *permissions: str, session=None):
    with TestClient(_app(session, _User(*(permissions or FULL)))) as client:
        return client.get(url)


# ---------------------------------------------------------------------------
# Fixtures for the two reads these routes make
# ---------------------------------------------------------------------------


@pytest.fixture
def triage(monkeypatch):
    """Stub GET .../triage's handler, which is what _read_triage calls."""
    box: dict[str, Any] = {"payload": {"triage": None, "comments": []}}

    async def handler(alert_id, current_user=None, session=None):
        payload = box["payload"]
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(api, "get_alert_triage", handler)
    return box


@pytest.fixture
def case(monkeypatch):
    """Stub the case read and the KFP match."""
    box: dict[str, Any] = {"case": None, "matches": []}

    async def read_case(case_id, current_user, session):
        value = box["case"]
        if isinstance(value, Exception):
            raise value
        return value

    def match(_session, **_criteria):
        value = box["matches"]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(mod, "_read_case", read_case)
    monkeypatch.setattr(api, "_match_known_false_positives", match)
    return box


@pytest.fixture(autouse=True)
def ai_off(monkeypatch):
    async def off():
        return False

    monkeypatch.setattr(mod, "_ai_available", off)


def _triage_dict(**over):
    base = {
        "status": "open", "priority": "high", "case_id": 7,
        "case_number": "CASE-0007", "analyst_notes": "backup agent, probably",
        "observables": [{"type": "source_ip", "value": "10.0.0.9"}],
        "mitre_techniques": [],
    }
    base.update(over)
    return base


def _case_dict(**over):
    base = {
        "id": 7, "case_number": "CASE-0007", "title": "Odd logins",
        "status": "open", "severity": "high", "created_by": "ana",
        "assigned_to": None, "description": "two hosts",
        "closure_reason": None, "affected_hosts": ["ws-01"],
        "affected_users": [], "triggered_rules": [],
        "observables": [], "alerts": [], "notes": [], "created_at": None,
    }
    base.update(over)
    return base


TRIAGE_URL = "/ui/alerts/triage/a-1"


# ---------------------------------------------------------------------------
# Gates, derived from the live route table rather than from endpoint names
# ---------------------------------------------------------------------------


def _permission_names(route) -> set:
    found = set()
    dependant = getattr(route, "dependant", None)
    for dep in (dependant.dependencies if dependant else []):
        for cell in (getattr(dep.call, "__closure__", None) or ()):
            value = cell.cell_contents
            if isinstance(value, str) and ":" in value:
                found.add(value)
    return found


def _route(path: str):
    for r in router.routes:
        if r.path == path:
            return r
    raise AssertionError(f"no route at {path}")


@pytest.mark.parametrize("path, expected", [
    ("/alerts/triage/{alert_id}", {"alert:read"}),
    ("/alerts/comments/{alert_id}", {"alert:read"}),
    ("/alerts/enrich/{alert_id}", {"alert:read"}),
    ("/alerts/case-tab/{case_id}", {"case:read", "alert:read"}),
    ("/alerts/kfp-banner/{case_id}", {"case:read", "alert:read"}),
])
def test_each_fragment_carries_the_gate_its_reads_require(path, expected):
    assert _permission_names(_route(path)) == expected


def test_the_permission_constants_are_spelled_once():
    assert DETAIL_PERMISSION == "alert:read"
    assert PERMISSION == "case:read"
    assert TRIAGE_PERMISSION == "alert:triage"


def test_a_caller_without_alert_read_is_refused_every_fragment():
    for url in (TRIAGE_URL, "/ui/alerts/comments/a-1", "/ui/alerts/enrich/a-1"):
        assert get(url, "case:read", session=_Session()).status_code == 403


def test_the_case_fragments_need_case_read_as_well():
    assert get("/ui/alerts/case-tab/7", *READER).status_code == 403
    assert get("/ui/alerts/kfp-banner/7", *READER).status_code == 403


# ---------------------------------------------------------------------------
# The triage read: failed, no record, record
# ---------------------------------------------------------------------------


def test_a_failed_triage_read_says_nothing_is_known(triage):
    triage["payload"] = RuntimeError("elasticsearch down")
    body = get(TRIAGE_URL).text
    assert "could not be read" in text_of(body)
    assert "Nothing in this bar is known" in text_of(body)
    assert "Loading triage" not in body, "the shell's loading row must be replaced"


@pytest.mark.parametrize("payload", [["not", "a", "dict"], "a string", 7])
def test_a_payload_that_is_not_a_mapping_is_a_failed_read(triage, payload):
    triage["payload"] = payload
    assert "Nothing in this bar is known" in text_of(get(TRIAGE_URL).text)


def test_a_triage_that_is_not_a_mapping_is_a_failed_read(triage):
    """The handler promises a dict or None under `triage`. Anything else is
    the handler not producing what it promises, which is a failure and not a
    record."""
    triage["payload"] = {"triage": "nope", "comments": []}
    assert "Nothing in this bar is known" in text_of(get(TRIAGE_URL).text)


def test_no_triage_record_is_an_untouched_alert_not_a_failure(triage):
    triage["payload"] = {"triage": None, "comments": []}
    body = get(TRIAGE_URL).text
    assert "Nothing in this bar is known" not in text_of(body)
    assert "No observables yet" in body
    assert "not linked to a case" in text_of(body).lower()


def test_a_record_renders_its_status_priority_and_notes(triage, case):
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL).text
    assert "backup agent, probably" in body
    assert 'value="high" selected' in body or "selected" in body
    assert "10.0.0.9" in body


# ---------------------------------------------------------------------------
# The comments half, read separately from the bar
# ---------------------------------------------------------------------------


def test_a_payload_with_no_comment_list_does_not_say_there_are_none(triage, case):
    """`data.comments || []` and "No comments yet" were the page's whole
    handling. A payload that carried a triage and no comment list is a
    partial read, not an alert nobody has commented on."""
    triage["payload"] = {"triage": _triage_dict()}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL).text
    assert "comments could not be read" in text_of(body)
    assert "No comments yet" not in body


def test_an_empty_comment_list_is_an_alert_with_no_comments(triage, case):
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL).text
    assert "No comments yet" in body
    assert "could not be read" not in text_of(body)


def test_comment_prose_is_escaped_text_and_not_rendered_markdown(triage):
    triage["payload"] = {"triage": None, "comments": [
        {"id": 1, "user": "ana", "content": "line one\nline two **not bold**",
         "created_at": None}]}
    body = get("/ui/alerts/comments/a-1").text
    assert "<strong>" not in body, "markdown must not become markup"
    assert "**not bold**" in body
    assert "whitespace-pre-wrap" in body, "the line break has to survive"


def test_a_comment_with_no_author_is_not_an_author_called_null(triage):
    triage["payload"] = {"triage": None, "comments": [
        {"id": 1, "content": "x", "created_at": None}]}
    assert "unknown analyst" in get("/ui/alerts/comments/a-1").text


def test_a_non_mapping_comment_row_is_dropped_not_rendered(triage):
    triage["payload"] = {"triage": None, "comments": [
        "not a dict", {"id": 2, "user": "b", "content": "kept", "created_at": None}]}
    body = get("/ui/alerts/comments/a-1").text
    assert "kept" in body
    assert "not a dict" not in body


def test_the_comment_box_is_offered_only_with_alert_triage(triage):
    triage["payload"] = {"triage": None, "comments": []}
    assert "<textarea" in get("/ui/alerts/comments/a-1").text
    withheld = get("/ui/alerts/comments/a-1", *WITH_CASE).text
    assert "<textarea" not in withheld
    assert "alert:triage" in withheld


# ---------------------------------------------------------------------------
# The Bob badge
# ---------------------------------------------------------------------------


def test_a_bob_confidence_of_zero_is_a_measured_low(triage, case):
    """`|| 0` and truthiness both erase a measured zero. 0 is a Low, and the
    absence of a score is not a Low."""
    triage["payload"] = {"triage": _triage_dict(
        suggested_verdict_confidence_int=0, suggested_verdict="likely_benign"),
        "comments": []}
    case["case"] = _case_dict()
    body = text_of(get(TRIAGE_URL).text)
    assert "Bob Low 0%" in body
    assert "likely benign" in body


def test_no_bob_score_renders_no_pill_at_all(triage, case):
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    case["case"] = _case_dict()
    assert "Bob" not in text_of(get(TRIAGE_URL).text)


@pytest.mark.parametrize("score, level", [
    (BOB_HIGH, "High"), (BOB_HIGH + 19, "High"),
    (BOB_MEDIUM, "Medium"), (BOB_HIGH - 1, "Medium"),
    (BOB_MEDIUM - 1, "Low"), (0, "Low"),
])
def test_the_confidence_bands_are_the_ones_the_page_used(triage, case, score, level):
    triage["payload"] = {"triage": _triage_dict(
        suggested_verdict_confidence_int=score), "comments": []}
    case["case"] = _case_dict()
    assert f"Bob {level} {score}%" in text_of(get(TRIAGE_URL).text)


def test_a_non_integer_confidence_is_absent_not_zero(triage, case):
    triage["payload"] = {"triage": _triage_dict(
        suggested_verdict_confidence_int="high"), "comments": []}
    case["case"] = _case_dict()
    assert "Bob" not in text_of(get(TRIAGE_URL).text)


def test_the_auto_escalated_pill_stands_alone(triage, case):
    triage["payload"] = {"triage": _triage_dict(
        bob_escalation_badge=BOB_LOW_CONFIDENCE), "comments": []}
    case["case"] = _case_dict()
    body = text_of(get(TRIAGE_URL).text)
    assert "Auto-escalated" in body
    assert "Bob Low" not in body, "no score was recorded"


# ---------------------------------------------------------------------------
# MITRE: the off-by-one that deleted the wrong technique
# ---------------------------------------------------------------------------


def _remove_args(body: str) -> list:
    out = []
    for m in re.finditer(r"data-click-action=\"removeMitreTechnique\"[^>]*data-args='([^']*)'", body):
        out.append(json.loads(html.unescape(m.group(1))))
    return out


def test_remove_passes_the_saved_position_not_the_merged_one(triage, case):
    """The defect this stage fixes. The page merged the alert's own
    auto-detected technique in at position 0 and then handed
    removeMitreTechnique the merged index, while that function splices the
    saved list. Removing the first saved technique deleted the second."""
    triage["payload"] = {"triage": _triage_dict(mitre_techniques=[
        {"technique_id": "T1003", "technique_name": "Dump", "source": "manual"},
        {"technique_id": "T1021", "technique_name": "Remote", "source": "manual"},
    ]), "comments": []}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL + "?mitre_technique_id=T1059&mitre_technique_name=Cmd").text

    assert "T1059" in body, "the alert's own technique is shown"
    assert _remove_args(body) == [["a-1", 0], ["a-1", 1]], (
        "the saved techniques keep their own positions, 0 and 1, even though "
        "the auto row is rendered before them")


def test_the_auto_row_gets_no_remove_control(triage, case):
    triage["payload"] = {"triage": _triage_dict(mitre_techniques=[]), "comments": []}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL + "?mitre_technique_id=T1059").text
    assert "T1059" in body
    assert _remove_args(body) == [], "the auto technique is not in the saved list"


def test_an_auto_technique_already_saved_is_not_duplicated(triage, case):
    triage["payload"] = {"triage": _triage_dict(mitre_techniques=[
        {"technique_id": "T1059", "technique_name": "Cmd", "source": "manual"}]),
        "comments": []}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL + "?mitre_technique_id=T1059").text
    assert body.count("T1059") == 1 or _remove_args(body) == [["a-1", 0]]


def test_no_techniques_says_so_rather_than_rendering_an_empty_list(triage, case):
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    case["case"] = _case_dict()
    assert "No techniques recorded" in get(TRIAGE_URL).text


# ---------------------------------------------------------------------------
# The case link: five states where the page had two
# ---------------------------------------------------------------------------


def test_a_failed_read_does_not_claim_the_alert_is_unlinked(triage):
    triage["payload"] = RuntimeError("down")
    body = text_of(get(TRIAGE_URL).text)
    assert "whether this alert belongs to a case is not known" in body
    assert "not linked to a case" not in body


def test_an_unlinked_alert_offers_create_and_link_with_case_create(triage):
    triage["payload"] = {"triage": _triage_dict(case_id=None, case_number=None),
                         "comments": []}
    body = get(TRIAGE_URL).text
    assert "showCreateCaseForm" in body
    assert "linkAlertToCase" in body


def test_an_unlinked_alert_withholds_those_without_case_create(triage):
    triage["payload"] = {"triage": _triage_dict(case_id=None, case_number=None),
                         "comments": []}
    body = get(TRIAGE_URL, *WITH_CASE).text
    assert "showCreateCaseForm" not in body
    assert "case:create permission" in text_of(body)


def test_a_linked_case_the_viewer_cannot_read_says_so(triage):
    """Neither a dead link nor a claim that the alert is unlinked."""
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    body = text_of(get(TRIAGE_URL, *READER).text)
    assert "linked to a case" in body
    assert "case:read permission" in body


def test_a_missing_linked_case_is_not_an_unlinked_alert(triage, case):
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    case["case"] = HTTPException(status_code=404)
    body = text_of(get(TRIAGE_URL).text)
    assert "no longer exists" in body


def test_a_failed_case_read_names_nothing_about_the_case(triage, case):
    """The bar still shows the case number, because the TRIAGE record
    reported it and that read succeeded. It is the case tab that must name
    nothing, since its own read is the one that failed."""
    triage["payload"] = {"triage": _triage_dict(), "comments": []}
    case["case"] = RuntimeError("db gone")
    body = get(TRIAGE_URL).text
    tab = body[body.index('id="detail-tab-case"'):]
    assert "could not be read" in text_of(tab)
    assert "Odd logins" not in tab, "nothing was read, so nothing is named"
    assert "Manage Case" not in tab


# ---------------------------------------------------------------------------
# The case tab's filled-in defaults
# ---------------------------------------------------------------------------


def test_a_case_with_no_severity_does_not_render_a_dash(case):
    case["case"] = _case_dict(severity=None)
    body = text_of(get("/ui/alerts/case-tab/7").text)
    assert "not recorded" in body


def test_a_case_with_no_assignee_is_unassigned_only_when_reported(case):
    case["case"] = _case_dict(assigned_to=None)
    assert "Unassigned" in text_of(get("/ui/alerts/case-tab/7").text)
    payload = _case_dict()
    del payload["assigned_to"]
    case["case"] = payload
    assert "not reported" in text_of(get("/ui/alerts/case-tab/7").text)


def test_a_payload_with_no_alert_list_does_not_raise(case):
    """`c.alerts.length` was read unguarded, so a payload without the key
    raised a TypeError into the catch and the whole tab became the loading
    row."""
    payload = _case_dict()
    del payload["alerts"]
    case["case"] = payload
    r = get("/ui/alerts/case-tab/7")
    assert r.status_code == 200
    assert "Linked Alerts (0)" in r.text


def test_a_payload_with_no_note_list_is_not_a_case_with_no_notes(case):
    payload = _case_dict()
    del payload["notes"]
    case["case"] = payload
    assert "No notes yet" in get("/ui/alerts/case-tab/7").text


def test_a_closure_with_no_recorded_author_does_not_say_unknown(case):
    case["case"] = _case_dict(status="closed", closure_reason="false_positive",
                              closed_by=None, closed_at=None)
    body = text_of(get("/ui/alerts/case-tab/7").text)
    assert "does not name" in body
    assert "Closed by unknown" not in body


def test_a_closed_case_with_no_reason_says_the_record_does_not_say(case):
    case["case"] = _case_dict(status="closed", closure_reason=None)
    assert "does not say why" in text_of(get("/ui/alerts/case-tab/7").text)


def test_the_closure_buttons_are_offered_on_the_right_permission(case):
    case["case"] = _case_dict(alerts=[{"es_alert_id": "a-1", "status": "open"}])
    assert "closeCaseWithAlerts" in get("/ui/alerts/case-tab/7").text
    withheld = get("/ui/alerts/case-tab/7", *WITH_CASE).text
    assert "closeCaseWithAlerts" not in withheld
    assert "alert:triage permission" in text_of(withheld)


def test_a_case_with_no_alerts_needs_case_update_to_close(case):
    case["case"] = _case_dict(alerts=[])
    withheld = get("/ui/alerts/case-tab/7", "alert:read", "case:read").text
    assert "case:update permission" in text_of(withheld)


def test_an_observable_scored_zero_shows_its_badge(case):
    case["case"] = _case_dict(observables=[
        {"type": "source_ip", "value": "10.0.0.9",
         "enrichment": {"score": 0, "is_malicious": False}}])
    assert "observable-enriched" in get("/ui/alerts/case-tab/7").text


# ---------------------------------------------------------------------------
# The known-false-positive banner: four outcomes where the page had silence
# ---------------------------------------------------------------------------


BANNER = "/ui/alerts/kfp-banner/7"


def test_a_failed_match_is_not_a_clean_case(case):
    case["case"] = _case_dict()
    case["matches"] = RuntimeError("kfp service down")
    body = text_of(get(BANNER).text)
    assert "could not run" in body
    assert "has not been ruled out" in body


def test_a_non_list_answer_is_also_a_failed_match(case):
    case["case"] = _case_dict()
    case["matches"] = {"matches": []}
    assert "could not run" in text_of(get(BANNER).text)


def test_a_clean_case_renders_nothing_at_all(case):
    case["case"] = _case_dict()
    case["matches"] = []
    assert get(BANNER).text.strip() == ""


def test_a_closed_case_renders_nothing(case):
    case["case"] = _case_dict(status="closed")
    assert get(BANNER).text.strip() == ""


def test_a_case_with_nothing_to_match_on_says_so(case):
    """The skip the page could not distinguish from a clean result. An
    analyst reading no banner would otherwise assume the check ran."""
    case["case"] = _case_dict(affected_hosts=[], affected_users=[],
                              triggered_rules=[], observables=[])
    body = text_of(get(BANNER).text)
    assert "nothing to match" in body


def test_a_missing_case_was_not_checked(case):
    case["case"] = HTTPException(status_code=404)
    body = text_of(get(BANNER).text)
    assert "not a clean result" in body


def test_a_match_names_the_entry_and_its_fields(case):
    case["case"] = _case_dict()
    case["matches"] = [{"id": 3, "title": "Backup agent scan",
                        "matched_fields": ["hosts", "ips"]}]
    body = text_of(get(BANNER).text)
    assert "Backup agent scan" in body
    assert "matched: hosts, ips" in body


def test_a_match_with_no_matched_fields_is_still_a_match(case):
    """`match.matched_fields.join(', ')` was unguarded, so a payload without
    that key raised inside the try and the catch rendered nothing: a real
    match reported as a clean case."""
    case["case"] = _case_dict()
    case["matches"] = [{"id": 3, "title": "Backup agent scan"}]
    body = text_of(get(BANNER).text)
    assert "Backup agent scan" in body
    assert "did not report which fields" in body


def test_further_matches_are_counted(case):
    case["case"] = _case_dict()
    case["matches"] = [{"id": 1, "title": "A"}, {"id": 2, "title": "B"},
                       {"id": 3, "title": "C"}]
    assert "and 2 others" in text_of(get(BANNER).text)


def test_close_as_known_fp_needs_alert_triage(case):
    case["case"] = _case_dict()
    case["matches"] = [{"id": 3, "title": "A"}]
    assert "closeAsKnownFP" in get(BANNER).text
    withheld = get(BANNER, *WITH_CASE).text
    assert "closeAsKnownFP" not in withheld
    assert "alert:triage permission" in text_of(withheld)


def test_the_ip_observables_are_the_only_ones_matched_on(case):
    """kfp_criteria took source_ip and destination_ip values, as
    checkKFPMatches did. A url observable is not an IP."""
    seen = {}

    def match(_session, **criteria):
        seen.update(criteria)
        return []

    import ion.web.api as _api
    _api._match_known_false_positives = match
    case["case"] = _case_dict(observables=[
        {"type": "source_ip", "value": "10.0.0.1"},
        {"type": "destination_ip", "value": "10.0.0.2"},
        {"type": "url", "value": "http://x"}])
    get(BANNER)
    assert seen["ips"] == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# Enrichment: six outcomes where the page had one sentence and a catch
# ---------------------------------------------------------------------------


ENRICH = "/ui/alerts/enrich/a-1"
OBS = [{"type": "source_ip", "value": "10.0.0.9"},
       {"type": "hostname", "value": "ws-01"}]


def _enrich(monkeypatch, result):
    async def handler(request, current_user=None):
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(api, "enrich_batch", handler)


def test_a_failed_triage_read_is_not_an_alert_without_observables(monkeypatch):
    _enrich(monkeypatch, {"results": []})
    body = text_of(get(ENRICH, session=_Session(boom=True)).text)
    assert "could not be read" in body
    assert "no observables recorded" not in body


def test_no_observables_is_a_real_absence(monkeypatch):
    _enrich(monkeypatch, {"results": []})
    body = text_of(get(ENRICH, session=_Session(_Triage([]))).text)
    assert "no observables recorded" in body


def test_none_enrichable_keeps_the_pages_wording(monkeypatch):
    _enrich(monkeypatch, {"results": []})
    session = _Session(_Triage([{"type": "user_account", "value": "ana"}]))
    assert "No enrichable observables" in get(ENRICH, session=session).text


def test_an_unavailable_opencti_names_its_reason(monkeypatch):
    """The handler says 503 by returning a JSONResponse with an `error`. The
    page put that in the same class and colour as a clean result."""
    _enrich(monkeypatch, JSONResponse(status_code=503,
                                      content={"error": "OpenCTI is not configured"}))
    body = text_of(get(ENRICH, session=_Session(_Triage(OBS))).text)
    assert "could not be queried" in body
    assert "OpenCTI is not configured" in body
    assert "not established" in body


def test_a_raising_enrichment_is_not_a_clean_lookup(monkeypatch):
    _enrich(monkeypatch, RuntimeError("boom"))
    body = text_of(get(ENRICH, session=_Session(_Triage(OBS))).text)
    assert "request failed" in body
    assert "not a clean result" in body


def test_an_answer_with_no_results_list_is_a_failure(monkeypatch):
    _enrich(monkeypatch, {"error": None})
    body = text_of(get(ENRICH, session=_Session(_Triage(OBS))).text)
    assert "not a clean result" in body or "cannot read" in body


def test_an_empty_results_list_is_a_finding_about_the_observables(monkeypatch):
    """The only one of these that says something about the indicators rather
    than about the service."""
    _enrich(monkeypatch, {"results": []})
    body = text_of(get(ENRICH, session=_Session(_Triage(OBS))).text)
    assert "returned nothing for 2 observables" in body


def test_results_render_their_matches_and_counts(monkeypatch):
    _enrich(monkeypatch, {"results": [
        {"found": True, "value": "10.0.0.9", "type": "ipv4-addr",
         "labels": [{"value": "malware", "color": "#ff0000"}],
         "threat_actors": [{"name": "APT29", "description": "d"}],
         "indicators": [{"name": "ind", "description": "x", "score": 0}],
         "observable": {"score": 0}},
        {"found": False, "value": "ws-01", "type": "domain-name"},
    ]})
    body = get(ENRICH, session=_Session(_Triage(OBS))).text
    assert "1 of 2 matched" in text_of(body)
    assert "MATCH" in body and "NO MATCH" in body
    assert "malware" in body and "APT29" in body
    assert "Score: 0" in body, "an indicator scored zero is an assessment"
    assert "Observable score: 0" in body


def test_a_row_without_found_is_not_reported_as_a_match(monkeypatch):
    _enrich(monkeypatch, {"results": [{"value": "10.0.0.9", "type": "ipv4-addr"}]})
    body = get(ENRICH, session=_Session(_Triage(OBS))).text
    assert "NO MATCH" in body
    assert "0 of 1 matched" in text_of(body)


def test_the_observables_list_is_swapped_out_of_band_with_its_dots(monkeypatch):
    _enrich(monkeypatch, {"results": [
        {"found": True, "value": "10.0.0.9", "type": "ipv4-addr"},
        {"found": False, "value": "ws-01", "type": "domain-name"},
    ]})
    body = get(ENRICH, session=_Session(_Triage(OBS))).text
    assert 'id="observables-list" hx-swap-oob="innerHTML"' in flat(body)
    assert "enrich-dot hit" in body
    assert "enrich-dot miss" in body


def test_an_observable_absent_from_the_results_gets_no_dot(monkeypatch):
    """`resultByValue[value] ? 'hit' : 'miss'` painted a value the results
    did not mention as a miss. Not looked up is not looked up and clean."""
    _enrich(monkeypatch, {"results": [
        {"found": True, "value": "10.0.0.9", "type": "ipv4-addr"}]})
    body = get(ENRICH, session=_Session(_Triage(OBS))).text
    assert body.count("enrich-dot") == 1


# ---------------------------------------------------------------------------
# data-args: every argument is JSON the dispatcher can parse
# ---------------------------------------------------------------------------


def _all_args(body: str) -> list:
    return re.findall(r"data-args='([^']*)'", body)


def test_every_data_args_parses_as_json_even_with_a_quote_in_the_data(triage, case):
    """The defect found three times on this page. escapeHtml turns a double
    quote into &quot;, the browser decodes it to a bare quote inside the JSON
    string, JSON.parse throws, and event-delegation.js logs and returns, so
    the control looks like it works and does nothing."""
    triage["payload"] = {"triage": _triage_dict(observables=[
        {"type": "url", "value": 'http://x/?q="a"'}],
        mitre_techniques=[{"technique_id": 'T"1', "technique_name": "Odd",
                           "source": "manual"}]),
        "comments": [{"id": 1, "user": 'o"brien', "content": 'he said "no"',
                      "created_at": None}]}
    case["case"] = _case_dict(alerts=[{"es_alert_id": 'a"1', "status": "open"}],
                              observables=[{"type": "url", "value": 'http://y/?q="b"'}])
    body = get(TRIAGE_URL).text

    args = _all_args(body)
    assert args, "there are controls on this render"
    for raw in args:
        json.loads(html.unescape(raw))


def test_the_observable_controls_carry_the_value_and_its_position(triage, case):
    triage["payload"] = {"triage": _triage_dict(observables=[
        {"type": "source_ip", "value": "10.0.0.1"},
        {"type": "url", "value": 'http://x/?q="a"'}]), "comments": []}
    case["case"] = _case_dict()
    body = get(TRIAGE_URL).text
    removes = [json.loads(html.unescape(m)) for m in re.findall(
        r"data-click-action=\"removeObservable\"[^>]*data-args='([^']*)'", body)]
    assert removes == [["a-1", 0], ["a-1", 1]]
    opens = [json.loads(html.unescape(m)) for m in re.findall(
        r"data-click-action=\"openObservableDetail\"[^>]*data-args='([^']*)'", body)]
    assert ["url", 'http://x/?q="a"'] in opens


# ---------------------------------------------------------------------------
# What the page no longer does
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


def test_the_retired_writers_are_gone_from_the_page():
    page = _page()
    for name in ("renderTriageBar", "renderMitreSection", "renderCaseObservables",
                 "checkKFPMatches", "checkKFPMatchesForTab", "enrichObservables",
                 "renderEnrichResults", "updateObservableEnrichDots"):
        assert not re.search(r"(?<![\w.])" + name + r"\s*\(", page), name


def test_the_three_kept_functions_request_fragments_instead_of_writing():
    """loadTriage, renderCommentsTab and renderCaseTab keep their names
    because static/js/alert-detail.js probes for renderCommentsTab and falls
    back to writing its own markup into #detail-tab-comments when it is
    absent, and because the other two have callers across the page."""
    page = _page()
    for name, url in (("loadTriage", "/ui/alerts/triage/"),
                      ("renderCommentsTab", "/ui/alerts/comments/"),
                      ("renderCaseTab", "/ui/alerts/case-tab/")):
        body = page[page.index("function " + name + "("):].replace("\r\n", "\n")
        body = body[:body.index("\n}")]
        # WRITES, not the bare substring. `swap: 'innerHTML'` names the
        # slot the server's markup lands in, which is the opposite of a
        # string the browser assembles, and the measure says so too.
        assert not WRITES.search(body), name
        assert url in body, name
        assert "htmx.ajax" in body, name


def test_the_dead_kfp_attributes_are_gone_with_their_reader():
    """Asserted against the markup with the Jinja comments stripped. The
    comment explaining the removal names both attributes, and an assertion
    over the raw file text matches its own explanation. That mistake has
    produced a false pass repeatedly on this project, so the parsed thing
    is what gets checked."""
    manage = (FRAGMENTS / "alerts_case_manage.html").read_text(encoding="utf-8")
    markup = re.sub(r"\{#.*?#\}", "", manage, flags=re.S)
    assert "data-kfp-context" not in markup
    assert "data-case-status" not in markup
    assert 'hx-get="/ui/alerts/kfp-banner/' in markup


def test_the_script_has_no_jinja_and_the_page_builds_no_markup_for_this_region():
    page = _page()
    start = page.rindex('<script nonce="{{ csp_nonce }}">')
    script = page[page.index(">", start) + 1:]
    script = script[:script.index("</script>")]
    script = script.replace("{% raw %}", "").replace("{% endraw %}", "")
    assert "{%" not in script and "{{" not in script


def test_no_fragment_in_this_stage_uses_an_inline_style_attribute():
    """style-src-attr is 'none' in this app's CSP, so an inline style
    attribute is dropped. Data-driven styling goes through data-ion-style."""
    for name in ("alerts_triage_bar.html", "alerts_comments.html",
                 "alerts_case_tab.html", "alerts_kfp_banner.html",
                 "alerts_enrich.html", "alerts_observables.html"):
        text = (FRAGMENTS / name).read_text(encoding="utf-8")
        assert not re.search(r"\sstyle=\"", text), name


def test_no_fragment_in_this_stage_compiles_an_htmx_expression():
    """No hx-on, no js: forms, no hx-trigger event filter. The CSP has no
    unsafe-eval, so anything htmx hands to Function() throws silently."""
    for name in ("alerts_triage_bar.html", "alerts_comments.html",
                 "alerts_case_tab.html", "alerts_kfp_banner.html",
                 "alerts_enrich.html", "alerts_observables.html"):
        text = (FRAGMENTS / name).read_text(encoding="utf-8")
        assert "hx-on" not in text, name
        assert "js:" not in text, name
        for value in re.findall(r'hx-trigger="([^"]*)"', text):
            assert "[" not in value, (name, value)


def test_the_enrich_button_requests_the_fragment_and_is_gated_on_enrichability():
    text = (FRAGMENTS / "alerts_triage_bar.html").read_text(encoding="utf-8")
    button = text[text.index('id="enrich-btn"'):]
    button = button[:button.index(">") + 1]
    assert 'hx-get="/ui/alerts/enrich/' in button
    assert 'hx-target="#enrich-results"' in button
    assert "view.enrichable" in button, "disabled unless something maps"


def test_the_fragment_names_are_the_ones_the_module_renders():
    """A fragment renamed on one side only would 500 every call, and the
    module's five names are the five files."""
    for name in ("alerts_triage_bar.html", "alerts_comments.html",
                 "alerts_case_tab.html", "alerts_kfp_banner.html",
                 "alerts_enrich.html"):
        assert (FRAGMENTS / name).exists(), name
    source = inspect.getsource(mod)
    for name in ("alerts_triage_bar.html", "alerts_comments.html",
                 "alerts_case_tab.html", "alerts_kfp_banner.html",
                 "alerts_enrich.html"):
        assert f'"_fragments/{name}"' in source, name


# ---------------------------------------------------------------------------
# The four survivors of this stage's mutation pass. All four were real gaps
# rather than equivalent mutants, and each was the sibling of a case already
# covered: the tests above exercised the branch but not the one input where
# the guard changes the answer.
# ---------------------------------------------------------------------------


def test_a_closed_case_stays_silent_even_when_it_would_match(case):
    """Closes a survivor. test_a_closed_case_renders_nothing used a case with
    no match to find, so skipping the check and running it both produced
    silence and removing the skip changed nothing. The skip only matters for
    a closed case that WOULD match, which is also the case an analyst would
    be most annoyed to be nagged about: it is already closed."""
    case["case"] = _case_dict(status="closed")
    case["matches"] = [{"id": 3, "title": "Backup agent scan",
                        "matched_fields": ["hosts"]}]
    assert get(BANNER).text.strip() == ""
    assert "Backup agent scan" not in get(BANNER).text


def test_a_non_list_matched_fields_is_not_joined_character_by_character(case):
    """Closes a survivor. The coercion in kfp_check only changes the answer
    when matched_fields is present and is not a list. A bare string survives
    `or []` in the template and then `|join(', ')` iterates its characters,
    so "hosts" renders as "h, o, s, t, s"."""
    case["case"] = _case_dict()
    case["matches"] = [{"id": 3, "title": "Backup agent scan",
                        "matched_fields": "hosts"}]
    body = text_of(get(BANNER).text)
    assert "Backup agent scan" in body
    assert "h, o, s, t, s" not in body
    assert "did not report which fields" in body, (
        "a matched_fields the service did not send as a list tells us nothing "
        "about which fields matched")


def test_a_truthy_non_true_found_is_not_reported_as_a_match(monkeypatch):
    """Closes a survivor. `r.get("found") is True` and truthiness agree on
    True, False and absent, which is all the tests above supply. They differ
    for a value like 1 or "yes", and a service that starts answering 1 would
    otherwise have every row reported as a confirmed match."""
    _enrich(monkeypatch, {"results": [
        {"found": 1, "value": "10.0.0.9", "type": "ipv4-addr"},
        {"found": "yes", "value": "ws-01", "type": "domain-name"},
    ]})
    body = get(ENRICH, session=_Session(_Triage(OBS))).text
    assert "0 of 2 matched" in text_of(body)
    assert "MATCH" not in re.sub(r"NO MATCH", "", body), (
        "only a real boolean true is a match")


@pytest.mark.parametrize("alerts, permissions, offered", [
    # With linked alerts the close path goes through the first alert, which
    # carries alert:triage. case:update alone must not offer it.
    ([{"es_alert_id": "a-1", "status": "open"}],
     ("alert:read", "case:read", "case:update"), False),
    ([{"es_alert_id": "a-1", "status": "open"}],
     ("alert:read", "case:read", "alert:triage"), True),
    # With no linked alerts it PATCHes the case, which carries case:update.
    ([], ("alert:read", "case:read", "alert:triage"), False),
    ([], ("alert:read", "case:read", "case:update"), True),
])
def test_the_close_permission_follows_whether_the_case_has_alerts(
        case, alerts, permissions, offered):
    """Closes a survivor. Every test above gave the viewer both permissions
    or neither, so swapping the two arms of the rule changed nothing. Each
    row here holds exactly one of them, which is the only shape that can
    tell the correct rule from its inverse."""
    case["case"] = _case_dict(alerts=alerts)
    body = get("/ui/alerts/case-tab/7", *permissions).text
    assert ("closeCaseWithAlerts" in body) is offered, (alerts, permissions)
