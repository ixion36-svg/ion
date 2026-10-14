"""The case detail panel's own markup: tabs, metadata, context, notes, rail.

`renderPanelContent` was 408 lines returning one string, assigned straight
to `body.innerHTML`, and `openCaseDetail` wrapped the whole sequence in a
single try. Its own comment admits what that cost:

    // Name the failure. Everything above runs inside one try, so a throw
    // in any of renderPanelContent / applyConfidenceMeters /
    // switchPanelTab / selectCaseAlert lands here indistinguishably --
    // and the request itself returns 200, so the server log is clean and
    // the only evidence was the words "Failed to load case details".

Server-side, a render failure is a 500 with a traceback instead.

TWO COUPLINGS THAT HAD TO SURVIVE

`renderPanelContent` sorted `c.alerts` **in place**, deliberately, because
`openCaseDetail` then reads `c.alerts[0]` and passes index 0 to
`selectCaseAlert`. Sorting a copy would have left the rail showing one
alert selected while the detail column rendered another. The sort is
server-side now, so the fragment states which alert is first and the page
reads that rather than re-deriving it.

`_railAlerts[alertId] = a` stashed each full alert so selecting a row
could hand it to the shared alert-detail component without a refetch.
That still happens: `openCaseDetail` keeps its `/api/cases/{id}` read for
the async loaders anyway, so the page fills `_railAlerts` from the same
payload it already had.

AND ONE THING THAT CANNOT MOVE

The notes render markdown. `ui/template_render.py` records why that stays
client-side: ION has no HTML sanitiser in its dependencies. So the
fragment emits each note's raw text and the page renders it, but through
`DOMPurify`'s `RETURN_DOM_FRAGMENT` and `replaceChildren` rather than
`innerHTML`, so it is not a runtime write.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.cases import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"

URL = "/ui/cases/7/panel"


class _User:
    id = 1
    username = "cases-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(user):
    with TestClient(_app(user)) as client:
        return client.get(URL)


def _reader():
    return _User(PERMISSION, "alert:read")


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def case(monkeypatch):
    def set(payload=None, raises=None, users=None):
        def handler(case_id, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        async def user_handler(session=None):
            return {"users": users if users is not None else []}

        monkeypatch.setattr("ion.web.ui.cases.read_case_detail", handler,
                            raising=False)
        monkeypatch.setattr("ion.web.api.list_assignable_users",
                            user_handler)

    return set


def _alert(**over):
    a = {"es_alert_id": "a1", "rule_name": "Suspicious logon",
         "priority": "high", "status": "open", "timestamp":
         "2026-10-13T09:00:00", "observables": [], "mitre_techniques": []}
    a.update(over)
    return a


def _case(**over):
    c = {
        "id": 7, "case_number": "CASE-7", "title": "A case",
        "severity": "high", "status": "open", "assigned_to_id": None,
        "created_at": "2026-10-13T09:00:00",
        "description": "a description", "evidence_summary": None,
        "affected_hosts": ["WS-01"], "affected_users": ["jdoe"],
        "triggered_rules": ["R-1"],
        "observables": [{"type": "ip", "value": "10.0.0.1"}],
        "alerts": [_alert()], "notes": [], "kibana_assignees": [],
        "kibana_case_id": None, "kibana_url": None,
        "dfir_iris_case_id": None,
    }
    c.update(over)
    return c


# ---------------------------------------------------------------------------
# Gate and failure
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_permission(case):
    case(payload=_case())
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


def test_a_failed_read_names_the_failure(case):
    case(raises=RuntimeError("the case store went away"))
    body = flat(_get(_reader()).text)
    assert "could not" in body.lower()
    assert "No linked alerts" not in body


def test_a_body_that_is_not_a_mapping_is_a_failure(case):
    case(payload="broken")
    assert "could not" in flat(_get(_reader()).text).lower()


# ---------------------------------------------------------------------------
# The severity strip and the tabs
# ---------------------------------------------------------------------------


def test_the_severity_strip_counts_alerts_and_observables(case):
    case(payload=_case())
    body = flat(_get(_reader()).text)
    assert "high severity" in body
    assert "1 alert" in body
    assert "1 observable" in body


def test_the_counts_are_pluralised(case):
    case(payload=_case(alerts=[_alert(es_alert_id="a1"),
                               _alert(es_alert_id="a2")]))
    assert "2 alerts" in flat(_get(_reader()).text)


def test_observables_are_deduplicated_across_case_and_alerts(case):
    """The page did this so a multi-alert case never shows the same IP
    twice, and so the count matches the list."""
    case(payload=_case(
        observables=[{"type": "ip", "value": "10.0.0.1"}],
        alerts=[_alert(observables=[
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "domain", "value": "bad.test"}])]))
    body = flat(_get(_reader()).text)
    assert "2 observables" in body
    assert body.count("10.0.0.1") == 1


def test_all_seven_tabs_are_present(case):
    case(payload=_case())
    html = _get(_reader()).text
    for tab in ("alerts", "overview", "observables", "timeline",
                "attackpath", "notes", "actions"):
        assert 'data-tab="%s"' % tab in html, tab


def test_a_missing_severity_falls_back_to_medium(case):
    """The page's own default."""
    case(payload=_case(severity=None))
    assert "medium severity" in flat(_get(_reader()).text)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_the_status_and_severity_selects_mark_the_current_value(case):
    case(payload=_case(status="acknowledged", severity="low"))
    html = _get(_reader()).text
    assert re.search(r'value="acknowledged"\s+selected', html)
    assert re.search(r'value="low"\s+selected', html)


def test_the_assignee_options_come_from_the_user_list(case):
    case(payload=_case(assigned_to_id=4),
         users=[{"id": 4, "display_name": "Lyndon", "username": "l",
                 "has_elastic_profile": True},
                {"id": 5, "display_name": None, "username": "other",
                 "has_elastic_profile": False}])
    html = _get(_reader()).text
    assert re.search(r'value="4"\s+selected', html)
    assert "Lyndon" in flat(html)
    assert "no Kibana profile" in flat(html)


def test_a_kibana_assignee_mismatch_is_flagged(case):
    """ION and Kibana disagreeing means someone edited the case in Kibana
    since ION last wrote."""
    case(payload=_case(assigned_to_id=4, kibana_assignees=[
        {"ion_user_id": 9, "ion_display_name": "Someone Else"}]))
    body = flat(_get(_reader()).text)
    assert "mismatch" in body
    assert "Someone Else" in body


def test_a_matching_kibana_assignee_is_not_flagged(case):
    case(payload=_case(assigned_to_id=4, kibana_assignees=[
        {"ion_user_id": 4, "ion_display_name": "Lyndon"}]))
    assert "mismatch" not in flat(_get(_reader()).text)


def test_an_unassigned_case_with_a_kibana_assignee_is_a_mismatch(case):
    case(payload=_case(assigned_to_id=None, kibana_assignees=[
        {"ion_user_id": 4, "ion_display_name": "Lyndon"}]))
    assert "mismatch" in flat(_get(_reader()).text)


def test_the_created_date_is_absolute_and_zone_named(case):
    """fmtDate was `new Date(s).toLocaleDateString()` on a naive UTC
    column, so it read as the viewer's local time."""
    case(payload=_case(created_at="2026-10-13T09:00:00"))
    assert "2026-10-13 09:00 UTC" in _get(_reader()).text


def test_a_missing_created_date_says_so(case):
    case(payload=_case(created_at=None))
    html = _get(_reader()).text
    assert "Invalid Date" not in html
    assert "an-absent" in html


# ---------------------------------------------------------------------------
# Context, description, observables
# ---------------------------------------------------------------------------


def test_context_tags_are_typed(case):
    case(payload=_case())
    html = _get(_reader()).text
    assert "cpanel-tag-host" in html
    assert "cpanel-tag-user" in html
    assert "cpanel-tag-rule" in html


def test_the_context_section_is_omitted_when_there_is_nothing(case):
    case(payload=_case(affected_hosts=[], affected_users=[],
                       triggered_rules=[]))
    assert "Context" not in flat(_get(_reader()).text)


def test_unreadable_context_lists_are_not_silence(case):
    case(payload=_case(affected_hosts="WS-01", affected_users=[],
                       triggered_rules=[]))
    assert "not in a shape" in flat(_get(_reader()).text)


def test_the_description_falls_back_to_the_evidence_summary(case):
    """It rides in an attribute, not as text: it is markdown and the page
    renders it for the same reason the notes are rendered there."""
    case(payload=_case(description=None,
                       evidence_summary="what we know"))
    html = _get(_reader()).text
    assert 'data-note-raw="what we know"' in html


def test_no_observables_says_so(case):
    case(payload=_case(observables=[], alerts=[_alert(observables=[])]))
    assert "No observables extracted yet" in flat(_get(_reader()).text)


def test_an_unreadable_observable_list_is_not_none_extracted(case):
    case(payload=_case(observables="10.0.0.1",
                       alerts=[_alert(observables=[])]))
    body = flat(_get(_reader()).text)
    assert "No observables extracted yet" not in body
    assert "not in a shape" in body


def test_mitre_techniques_are_deduplicated_across_alerts(case):
    case(payload=_case(alerts=[
        _alert(es_alert_id="a1", mitre_techniques=[
            {"id": "T1059", "name": "Scripting"}]),
        _alert(es_alert_id="a2", mitre_techniques=[
            {"id": "T1059", "name": "Scripting"},
            "T1071"])]))
    body = flat(_get(_reader()).text)
    assert body.count("T1059") == 1
    assert "T1071" in body
    assert "MITRE ATT&CK (2)" in body


# ---------------------------------------------------------------------------
# The alert rail, and the sort the page depends on
# ---------------------------------------------------------------------------


def test_the_rail_is_ordered_by_severity_then_newest(case):
    case(payload=_case(severity="low", alerts=[
        _alert(es_alert_id="low1", priority="low", rule_name="Low one"),
        _alert(es_alert_id="crit", priority="critical",
               rule_name="Critical one"),
        _alert(es_alert_id="high", priority="high",
               rule_name="High one")]))
    html = _get(_reader()).text
    assert (html.index("Critical one") < html.index("High one")
            < html.index("Low one"))


def test_an_alert_with_no_priority_takes_the_case_severity(case):
    """The rail row's own resolution, kept."""
    case(payload=_case(severity="critical", alerts=[
        _alert(es_alert_id="noprio", priority=None, rule_name="Inherits"),
        _alert(es_alert_id="low1", priority="low", rule_name="Low one")]))
    html = _get(_reader()).text
    assert html.index("Inherits") < html.index("Low one")


def test_the_fragment_states_which_alert_is_first(case):
    """The page read `c.alerts[0]` after this function sorted in place.
    Server-side the sort happens here, so the page has to be told rather
    than re-deriving it and disagreeing with the rail."""
    case(payload=_case(alerts=[
        _alert(es_alert_id="low1", priority="low"),
        _alert(es_alert_id="crit", priority="critical")]))
    html = _get(_reader()).text
    match = re.search(r'data-first-alert-id="([^"]*)"', html)
    assert match, html[:500]
    assert match.group(1) == "crit"
    assert 'data-first-alert-index="0"' in html


def test_the_first_rail_row_is_the_selected_one(case):
    case(payload=_case(alerts=[
        _alert(es_alert_id="low1", priority="low"),
        _alert(es_alert_id="crit", priority="critical")]))
    html = _get(_reader()).text
    # The class attribute precedes the id on that element, so the row
    # has to be matched from its opening tag rather than forward from
    # the id.
    row = re.search(r'<div class="[^"]*"\s+id="rail-alert-0"', html)
    assert row, html[:600]
    assert "selected" in row.group(0)


def test_a_rail_row_carries_its_alert_id_and_index(case):
    case(payload=_case(alerts=[_alert(es_alert_id="a1")]))
    html = _get(_reader()).text
    found = [json.loads(unescape(m.group(1)))
             for m in re.finditer(r"data-args='([^']*)'", html)]
    assert ["a1", 0, 7] in found, found


def test_an_alert_with_no_id_is_still_addressable(case):
    case(payload=_case(alerts=[_alert(es_alert_id=None,
                                      rule_name="Nameless")]))
    body = flat(_get(_reader()).text)
    assert "Nameless" in body
    assert "undefined" not in _get(_reader()).text


def test_the_alert_status_badge_is_a_class_not_a_composed_colour(case):
    """statusColors held an rgba and a var per status in JavaScript, and
    the badge read them through data-ion-style."""
    case(payload=_case(alerts=[_alert(status="acknowledged")]))
    html = _get(_reader()).text
    assert "cpanel-alert-badge" in html
    assert "rgba(" not in html
    assert "status-acknowledged" in html


def test_no_alerts_says_so(case):
    case(payload=_case(alerts=[]))
    assert "No linked alerts" in flat(_get(_reader()).text)


def test_an_unreadable_alert_list_is_not_no_linked_alerts(case):
    case(payload=_case(alerts="one"))
    body = flat(_get(_reader()).text)
    assert "No linked alerts" not in body
    assert "not in a shape" in body


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_a_note_hands_its_raw_text_to_the_page_for_rendering(case):
    """Markdown rendering stays client-side: ION has no HTML sanitiser,
    which ui/template_render.py records. So the server sends text."""
    case(payload=_case(notes=[
        {"id": 1, "user": "lyndon", "content": "**bold** finding",
         "created_at": "2026-10-13T09:00:00"}]))
    html = _get(_reader()).text
    assert "data-note-raw" in html
    assert "**bold** finding" in unescape(html)


def test_a_note_is_escaped_in_the_attribute_it_rides_in(case):
    case(payload=_case(notes=[
        {"id": 1, "content": "<img src=x onerror=alert(1)>"}]))
    html = _get(_reader()).text
    assert "<img src=x" not in html


def test_a_note_with_no_author_or_date_says_so(case):
    case(payload=_case(notes=[{"id": 1, "content": "x"}]))
    html = _get(_reader()).text
    assert "Unknown" in flat(html) or "an-absent" in html
    assert "Invalid Date" not in html


def test_the_note_count_is_reported(case):
    case(payload=_case(notes=[{"id": 1, "content": "a"},
                              {"id": 2, "content": "b"}]))
    assert "Investigation Notes (2)" in flat(_get(_reader()).text)


def test_an_unreadable_note_list_is_not_zero_notes(case):
    case(payload=_case(notes="one note"))
    body = flat(_get(_reader()).text)
    assert "Investigation Notes (0)" not in body
    assert "not in a shape" in body


# ---------------------------------------------------------------------------
# The async containers and the action buttons
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ident", [
    "case-sync-status", "response-actions-container",
    "case-timeline-container", "attack-path-container",
    "similar-cases-container", "similar-observables-container",
    "cpanel-alert-workspace", "cpanel-alert-guide",
])
def test_every_container_a_loader_fills_still_exists(case, ident):
    """Ten loaders run after the panel paints. A container that moved or
    lost its id is a panel section that silently never fills."""
    case(payload=_case())
    assert 'id="%s"' % ident in _get(_reader()).text, ident


def test_the_workbench_and_annotation_containers_carry_the_case_id(case):
    case(payload=_case())
    html = _get(_reader()).text
    for ident in ("workbench-kanban-7", "workbench-pin-count-7",
                  "workbench-verify-banner-7", "annotations-body-7",
                  "case-playbook-browser-7"):
        assert 'id="%s"' % ident in html, ident


def test_an_escalated_case_cannot_be_escalated_again(case):
    case(payload=_case(dfir_iris_case_id="IRIS-1"))
    html = _get(_reader()).text
    assert "Already escalated" in html
    assert "escalateCase" not in html


def test_a_case_not_yet_escalated_offers_the_button(case):
    case(payload=_case())
    assert "escalateCase" in _get(_reader()).text


def test_the_kibana_link_appears_only_with_a_url(case):
    case(payload=_case(kibana_url="https://kibana.test/app/cases/1"))
    assert "View in Kibana" in flat(_get(_reader()).text)
    case(payload=_case(kibana_url=None))
    assert "View in Kibana" not in flat(_get(_reader()).text)


def test_the_kibana_comments_section_appears_only_when_synced(case):
    case(payload=_case(kibana_case_id="kb-1"))
    assert "Kibana Comments" in flat(_get(_reader()).text)
    case(payload=_case(kibana_case_id=None))
    assert "Kibana Comments" not in flat(_get(_reader()).text)


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_the_panel():
    body = _scripts()
    assert "function renderPanelContent" not in body
    assert "cpanel-tab-nav" not in body
    assert "statusColors" not in body


def test_the_page_still_fills_the_rail_alert_cache():
    """selectCaseAlert hands the whole alert to the shared component, so
    the cache has to survive. openCaseDetail already has the payload."""
    body = _scripts()
    assert "_railAlerts" in body
    assert "function selectCaseAlert" in body


def test_the_page_reads_the_first_alert_from_the_fragment():
    body = _scripts()
    assert "firstAlertId" in body or "data-first-alert-id" in body
    assert "c.alerts || [])[0]" not in body


def test_the_note_render_uses_a_fragment_not_inner_html():
    """DOMPurify can return a DocumentFragment, so the one thing that
    cannot move server-side need not be a runtime write."""
    body = _scripts()
    assert "RETURN_DOM_FRAGMENT" in body
    assert "replaceChildren" in body


def test_ageLabel_is_gone_and_fmtDate_has_one_caller_left():
    """The panel was ageLabel's only caller, so it goes with it.

    fmtDate still has one, in loadKibanaComments, which belongs to a
    tranche that has not landed. Leaving it is deliberate: deleting a
    function with a live caller is how I removed sixteen of them by
    accident earlier. This asserts the position rather than the wish, and
    it will fail when that last caller goes, which is the right moment to
    delete the formatter.
    """
    import re as _re

    body = _scripts()
    assert "function ageLabel" not in body
    assert "function fmtDate" in body
    callers = _re.findall(r"fmtDate\(", body)
    # One definition line plus exactly one call.
    assert len(callers) == 2, callers
    assert "loadKibanaComments" in body


def test_a_rail_subtitle_cannot_inject_markup(case):
    """I shipped this as `a.bits | join('<br>') | safe`, which turns
    autoescaping off for the whole joined string. A process name is
    whatever ran on the host, and an alert's source IP is whatever the
    document said, so both are injectable. Four security reviews flagged
    it on the commit.

    The page this replaced escaped each bit before joining, which is the
    part I dropped. Each bit is emitted separately now so autoescaping
    applies, and the <br> between them is still real markup.
    """
    case(payload=_case(alerts=[_alert(
        process_name="<img src=x onerror=alert(1)>",
        source_ip="<script>alert(2)</script>",
        destination_ip="10.0.0.9")]))
    html = _get(_reader()).text
    assert "<img src=x" not in html
    assert "<script>alert(2)" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    # And the separator survives, so two bits still render on two lines.
    sub = re.search(r'<div class="cpanel-rail-alert-sub">(.*?)</div>',
                    html, re.S)
    assert sub, html[:400]
    assert "<br>" in sub.group(1)
