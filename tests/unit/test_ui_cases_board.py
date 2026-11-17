"""The /cases inbox: the list fragment, its chips and sort, each row's latest
activity, the preview pane's derived next action, and the empty states."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.services import case_query_service as cq
from ion.storage.database import get_db_session
from ion.web import api, case_lifecycle_api
from ion.web.ui import _cases_board as ui

NOW = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)


def iso(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).replace(tzinfo=None).isoformat()


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    user = SimpleNamespace(id=7, has_permission=lambda permission: permission == "case:read")
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            app.dependency_overrides[dependency.call] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    monkeypatch.setattr(ui, "utc_now", lambda: NOW)
    return TestClient(app), user


@pytest.fixture
def reads(monkeypatch):
    """The three service reads, recorded; each test sets what they return."""
    calls = {"page": [], "activity": [], "counts": []}
    out = {"page": {"cases": [], "total": 0, "has_more": False}, "activity": {}, "counts": {"changed": 1, "mine": 2, "unassigned": 3, "critical": 4, "closed": 5}}

    def answer(key, kwargs):
        calls[key].append(kwargs)
        value = out[key]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(cq, "list_cases_page", lambda session, **kw: answer("page", kw))
    monkeypatch.setattr(cq, "case_activity", lambda session, ids: answer("activity", {"ids": ids}))
    monkeypatch.setattr(cq, "inbox_counts", lambda session, **kw: answer("counts", kw))
    return calls, out


def view(c, **params):
    response = c.get("/ui/cases/board", params=params, headers={"Accept": "application/json"})
    assert response.status_code == 200
    return response.json()


def soup(c, url="/ui/cases/board", **params):
    response = c.get(url, params=params)
    assert response.status_code == 200
    return BeautifulSoup(response.text, "html.parser")


# ── Read outcomes and empty states ──────────────────────────────────────


def test_a_failed_read_is_not_an_empty_queue(client, reads):
    c, _ = client
    _, out = reads
    out["page"] = RuntimeError("database down")
    assert view(c)["state"] == "failed"
    page = soup(c)
    assert "could not be read" in page.text
    assert "No cases" not in page.text


def test_an_empty_queue_with_no_filters_says_so(client, reads):
    c, _ = client
    page = soup(c)
    assert "No cases yet" in page.text
    assert page.select_one("[data-click-action=inboxClearFilters]") is None


@pytest.mark.parametrize("params", [{"q": "nothing"}, {"severity": "critical"}, {"changed": "true"}, {"mine": "true"}, {"unassigned": "true"}])
def test_an_empty_filtered_queue_offers_to_clear_the_filters(client, reads, params):
    c, _ = client
    page = soup(c, **params)
    assert "No cases match these filters" in page.text
    assert page.select_one("[data-click-action=inboxClearFilters]") is not None


def test_titles_are_escaped(client, reads):
    c, _ = client
    _, out = reads
    out["page"] = {"cases": [{"id": 1, "title": "<script>x</script>"}], "total": 1, "has_more": False}
    assert "<script>x</script>" not in c.get("/ui/cases/board").text


# ── Sort and filters reach the query ───────────────────────────────────


@pytest.mark.parametrize("mode,sort,order", [("activity", "last_activity", "desc"), ("newest", "created_at", "desc"), ("oldest", "created_at", "asc"), ("severity", "severity", "desc"), ("alerts", "created_at", "desc")])
def test_each_sort_reaches_the_query(client, reads, mode, sort, order):
    c, _ = client
    calls, _ = reads
    view(c, mode=mode)
    assert (calls["page"][0]["sort"], calls["page"][0]["order"]) == (sort, order)


def test_the_default_sort_is_last_activity_newest_first(client, reads):
    c, _ = client
    calls, _ = reads
    view(c)
    assert (calls["page"][0]["sort"], calls["page"][0]["order"]) == ("last_activity", "desc")


def test_most_alerts_admits_it_is_newest_first(client, reads):
    c, _ = client
    assert "Newest first is shown" in c.get("/ui/cases/board", params={"mode": "alerts"}).text


def test_filters_and_the_window_reach_the_query(client, reads):
    c, _ = client
    calls, _ = reads
    view(c, status="open", severity="high", assigned_to_id=9, q='quoted " title', limit=12, offset=24)
    kw = calls["page"][0]
    assert {k: kw[k] for k in ("status", "severity", "assigned_to_id", "unassigned", "q", "active_since", "limit", "offset")} == {
        "status": "open", "severity": "high", "assigned_to_id": 9, "unassigned": False, "q": 'quoted " title', "active_since": None, "limit": 12, "offset": 24,
    }


def test_the_window_is_bounded(client, reads):
    c, _ = client
    assert c.get("/ui/cases/board", params={"limit": 501}).status_code == 422
    assert c.get("/ui/cases/board", params={"offset": -1}).status_code == 422


def test_changed_means_activity_in_the_last_day(client, reads):
    c, _ = client
    calls, _ = reads
    view(c, changed="true")
    assert calls["page"][0]["active_since"] == (NOW - timedelta(hours=24)).replace(tzinfo=None)
    assert calls["counts"][0]["active_since"] == (NOW - timedelta(hours=24)).replace(tzinfo=None)


def test_mine_is_the_signed_in_user_resolved_on_the_server(client, reads):
    c, _ = client
    calls, _ = reads
    data = view(c, mine="true", assigned_to_id=3)
    assert calls["page"][0]["assigned_to_id"] == 7
    assert [chip["key"] for chip in data["chips"] if chip["on"]] == ["mine"]


def test_unassigned_wins_over_an_assignee(client, reads):
    c, _ = client
    calls, _ = reads
    view(c, unassigned="true", assigned_to_id=3)
    assert calls["page"][0]["unassigned"] is True
    assert calls["page"][0]["assigned_to_id"] is None


def test_an_unknown_status_is_refused(client, reads):
    c, _ = client
    assert c.get("/ui/cases/board", params={"status": "bogus"}).status_code == 422


# ── Chips ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("params,on", [
    ({}, []),
    ({"changed": "true"}, ["changed"]),
    ({"mine": "true"}, ["mine"]),
    ({"assigned_to_id": 7}, ["mine"]),
    ({"unassigned": "true"}, ["unassigned"]),
    ({"severity": "critical"}, ["critical"]),
    ({"severity": "high"}, []),
    ({"status": "closed"}, ["closed"]),
    ({"status": "closed", "severity": "critical"}, ["critical", "closed"]),
])
def test_each_chip_is_on_exactly_when_its_filter_is(client, reads, params, on):
    c, _ = client
    data = view(c, **params)
    assert [chip["key"] for chip in data["chips"] if chip["on"]] == on
    rendered = [b["data-ci-chip"] for b in soup(c, **params).select("#ci-chips, [hx-swap-oob='innerHTML:#ci-chips']")[0].select(".ci-chip.on")]
    assert rendered == on


def test_chips_carry_whole_table_counts(client, reads):
    c, _ = client
    data = view(c)
    assert [(chip["key"], chip["count"]) for chip in data["chips"]] == [("changed", 1), ("mine", 2), ("unassigned", 3), ("critical", 4), ("closed", 5)]


def test_a_failed_count_is_blank_not_zero_and_the_list_still_renders(client, reads):
    c, _ = client
    _, out = reads
    out["counts"] = RuntimeError("count failed")
    out["page"] = {"cases": [{"id": 1, "title": "A"}], "total": 1, "has_more": False}
    data = view(c)
    assert data["state"] == "data"
    assert all(chip["count"] is None for chip in data["chips"])
    chip = soup(c).select_one("[data-ci-chip=critical]")
    assert chip.select_one(".ci-chip-n").text == ""
    assert "could not be read" in chip["title"]


def test_later_pages_do_not_recount_or_redraw_the_chips(client, reads):
    c, _ = client
    calls, _ = reads
    c.get("/ui/cases/board", params={"offset": 50})
    assert calls["counts"] == []
    assert "#ci-chips" not in c.get("/ui/cases/board", params={"offset": 50}).text


# ── Rows ───────────────────────────────────────────────────────────────


def row_view(c, reads, case, extra=None):
    _, out = reads
    out["page"] = {"cases": [case], "total": 1, "has_more": False}
    out["activity"] = {case["id"]: extra} if extra is not None else {}
    return view(c)["rows"][0]


def test_a_row_carries_what_the_inbox_shows(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 4, "case_number": "CASE-0004", "title": "Ransomware", "severity": "CRITICAL", "status": "open",
                              "assigned_to": "s.reyes", "alert_count": 7, "created_at": iso(30), "updated_at": iso(30), "last_activity_at": iso(2)},
                   {"host": "SRV-FILE01", "note": None, "alert": None})
    assert {k: row[k] for k in ("number", "title", "host", "severity", "status", "assignee", "initials", "alert_count", "age")} == {
        "number": "CASE-0004", "title": "Ransomware", "host": "SRV-FILE01", "severity": "critical", "status": "open",
        "assignee": "s.reyes", "initials": "SR", "alert_count": 7, "age": "2h",
    }


def test_the_age_is_last_activity_not_creation(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1, "created_at": iso(300), "updated_at": iso(300), "last_activity_at": iso(1.5)})
    assert row["age"] == "1h"


def test_a_host_the_title_already_names_is_not_repeated(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1, "title": "[Auto] Beacon — srv-db01"}, {"host": "SRV-DB01", "note": None, "alert": None})
    assert row["host"] is None


def test_an_unowned_case_shows_a_question_mark(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1})
    assert (row["assignee"], row["initials"], row["hue"]) == (None, "?", None)
    assert soup(c).select_one(".ci-av.none").text == "?"


@pytest.mark.parametrize("value", [None, -1, "3", True])
def test_an_unreadable_alert_count_is_a_dash_not_zero(client, reads, value):
    c, _ = client
    row = row_view(c, reads, {"id": 1, "alert_count": value})
    assert row["alert_count"] is None
    assert soup(c).select_one(".ci-n").text == "—"


def test_a_measured_zero_alerts_prints_zero(client, reads):
    c, _ = client
    row_view(c, reads, {"id": 1, "alert_count": 0})
    assert soup(c).select_one(".ci-n").text == "0"


def test_latest_activity_is_the_newest_note(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1, "created_at": iso(10), "updated_at": iso(10)},
                   {"host": None, "note": {"at": iso(1), "user": "a.patel", "content": "## Heading\n\n**Reset** the krbtgt"}, "alert": {"at": iso(3), "linked": True, "rule": "Golden Ticket", "status": "open"}})
    assert (row["activity_kind"], row["activity"]) == ("note", "a.patel: Heading")


def test_latest_activity_is_the_newest_alert_change(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1, "created_at": iso(10), "updated_at": iso(10)},
                   {"host": None, "note": {"at": iso(5), "user": "a", "content": "x"}, "alert": {"at": iso(1), "linked": True, "rule": "Golden Ticket", "status": "open"}})
    assert (row["activity_kind"], row["activity"]) == ("alert", "Alert linked: Golden Ticket")


def test_an_alert_status_change_reads_as_one(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1, "created_at": iso(10), "updated_at": iso(10)},
                   {"host": None, "note": None, "alert": {"at": iso(1), "linked": False, "rule": "Beacon", "status": "closed"}})
    assert row["activity"] == "Alert closed: Beacon"


@pytest.mark.parametrize("case,words", [
    ({"created_at": iso(5), "updated_at": iso(5)}, "Case opened"),
    ({"created_at": iso(5), "updated_at": iso(1)}, "Case updated"),
    ({"created_at": iso(5), "updated_at": iso(1), "status": "closed", "closure_reason": "false_positive"}, "Closed as false positive"),
    ({"created_at": iso(5), "updated_at": iso(1), "status": "closed"}, "Closed"),
])
def test_the_case_lifecycle_is_activity_too(client, reads, case, words):
    c, _ = client
    row = row_view(c, reads, {"id": 1, **case})
    assert row["activity"] == words


def test_no_timestamps_is_unknown_activity_not_a_guess(client, reads):
    c, _ = client
    row = row_view(c, reads, {"id": 1})
    assert (row["activity_kind"], row["activity"], row["age"]) == ("unknown", None, None)
    assert "No activity recorded" in soup(c).text


def test_a_failed_activity_read_keeps_the_rows(client, reads):
    c, _ = client
    _, out = reads
    out["page"] = {"cases": [{"id": 1, "title": "Still here", "created_at": iso(5), "updated_at": iso(5)}], "total": 1, "has_more": False}
    out["activity"] = RuntimeError("activity failed")
    data = view(c)
    assert data["state"] == "data"
    assert data["rows"][0]["activity"] == "Case opened"


def test_rows_select_and_carry_their_id(client, reads):
    c, _ = client
    row_view(c, reads, {"id": 42, "status": "closed"})
    row = soup(c).select_one("[data-ci-row]")
    assert row["data-ci-row"] == "42"
    assert row["data-click-action"] == "inboxSelect"
    assert row["data-args"] == "[42]"
    assert "is-closed" in row["class"]


def test_load_more_shows_only_on_an_explicit_more(client, reads):
    c, _ = client
    _, out = reads
    for more, hidden in ((True, False), (False, True), (None, True)):
        out["page"] = {"cases": [{"id": 1}], "total": 9, "has_more": more}
        assert soup(c).select_one("#cases-loadmore").has_attr("hidden") is hidden


def test_attention_items_select_the_case_in_the_list(client, reads):
    c, _ = client
    row_view(c, reads, {"id": 5, "status": "open", "severity": "critical", "created_at": iso(1), "updated_at": iso(1)})
    item = soup(c).select_one(".attn-item")
    assert item["data-click-action"] == "inboxSelect"
    assert item["data-args"] == "[5]"


# ── The preview ─────────────────────────────────────────────────────────


DETAIL = {
    "id": 3, "case_number": "CASE-0003", "title": "Lateral movement", "severity": "high", "status": "open",
    "assigned_to": None, "assigned_to_id": None, "affected_hosts": ["SRV-DB01"], "observables": [{}, {}], "notes": [{}],
    "dfir_iris_case_id": 12, "dfir_iris_url": "https://iris.example/case/12", "kibana_case_id": "k-1", "kibana_sync_pending": False,
    "created_at": iso(8),
    "alerts": [
        {"es_alert_id": "closed-1", "status": "closed"},
        {"es_alert_id": "open-1", "status": "open"},
        {"es_alert_id": "retention:3", "status": "open"},
        {"es_alert_id": "open-2", "status": "acknowledged"},
    ],
}
TIMELINE = {"events": [
    {"ts": iso(9), "kind": "system", "title": "Case opened"},
    {"ts": iso(1), "kind": "analyst", "title": "Note", "detail": "**checked** the backups"},
    {"ts": iso(3), "kind": "bob", "title": "Bob verdict"},
    {"ts": None, "kind": "system", "title": "undated"},
    {"ts": iso(2), "kind": "system", "title": "Alert linked"},
    {"ts": iso(4), "kind": "system", "title": "Oldest kept"},
]}


@pytest.fixture
def preview_reads(monkeypatch):
    out = {"detail": dict(DETAIL), "timeline": TIMELINE}

    async def detail(**kw):
        if isinstance(out["detail"], Exception):
            raise out["detail"]
        return out["detail"]

    def timeline(**kw):
        if isinstance(out["timeline"], Exception):
            raise out["timeline"]
        return out["timeline"]

    monkeypatch.setattr(case_lifecycle_api, "get_case_detail", detail)
    monkeypatch.setattr(case_lifecycle_api, "get_case_timeline", timeline)
    return out


def preview(c):
    response = c.get("/ui/cases/3/preview", headers={"Accept": "application/json"})
    assert response.status_code == 200
    return response.json()


def test_the_next_action_is_the_case_windows_closure_blockers(client, preview_reads):
    c, _ = client
    data = preview(c)
    # The retention marker is not an alert, as in the case window.
    assert [b["key"] for b in data["blockers"]] == ["alerts", "assignee", "iris"]
    assert data["blockers"][0]["title"] == "2 linked alerts not triaged"
    page = soup(c, "/ui/cases/3/preview")
    assert page.select_one(".ci-next > b").text == "2 linked alerts not triaged"
    assert [li.text for li in page.select(".ci-blk li")] == ["No one is assigned", "Escalated to DFIR-IRIS #12"]


def test_a_recorded_verdict_clears_the_alert_as_the_case_window_does(client, preview_reads):
    c, _ = client
    note = {"content": "**Alert closed as Escalated**\nAlert: `open-2`", "created_at": "2026-11-17T10:00:00"}
    preview_reads["detail"] = {**DETAIL, "notes": [note]}
    assert preview(c)["blockers"][0]["title"] == "1 linked alert not triaged"


def test_nothing_blocking_says_so(client, preview_reads):
    c, _ = client
    preview_reads["detail"] = {**DETAIL, "assigned_to_id": 7, "assigned_to": "me", "dfir_iris_case_id": None, "alerts": [{"es_alert_id": "a", "status": "closed"}]}
    assert preview(c)["blockers"] == []
    assert soup(c, "/ui/cases/3/preview").select_one(".ci-next > b").text == "Nothing blocks closing it"


def test_unreadable_alerts_are_a_blocker_of_their_own(client, preview_reads):
    c, _ = client
    preview_reads["detail"] = {**DETAIL, "alerts": None}
    data = preview(c)
    assert data["blockers"][0]["key"] == "alerts-unknown"
    assert data["counts"]["alerts"] is None


def test_a_closed_case_has_no_next_action(client, preview_reads):
    c, _ = client
    preview_reads["detail"] = {**DETAIL, "status": "closed", "closure_reason": "true_positive"}
    assert preview(c)["blockers"] == []
    assert "Nothing pending" in soup(c, "/ui/cases/3/preview").select_one(".ci-next").text


def test_key_fields_are_read_from_open_alerts_first(client, preview_reads):
    c, _ = client
    assert preview(c)["alert_ids"] == ["open-1", "open-2", "closed-1"]


def test_latest_activity_is_the_newest_dated_timeline_entries(client, preview_reads):
    c, _ = client
    events = preview(c)["activity"]
    assert [e["title"] for e in events] == ["Note", "Alert linked", "Bob verdict", "Oldest kept"]
    assert events[0]["detail"] == "checked the backups"


def test_a_failed_timeline_is_not_an_empty_one(client, preview_reads):
    c, _ = client
    preview_reads["timeline"] = RuntimeError("timeline failed")
    assert preview(c)["activity"] is None
    assert "could not be read" in soup(c, "/ui/cases/3/preview").select_one(".ci-sec").text
    preview_reads["timeline"] = {"events": []}
    assert "Nothing on the timeline yet" in soup(c, "/ui/cases/3/preview").select_one(".ci-sec").text


def test_key_facts(client, preview_reads):
    c, _ = client
    data = preview(c)
    assert (data["owner"], data["opened_age"], data["kibana"], data["iris_id"]) == (None, "8h", "linked", 12)
    assert data["counts"] == {"alerts": 3, "observables": 2, "notes": 1}
    preview_reads["detail"] = {**DETAIL, "kibana_sync_pending": True}
    assert preview(c)["kibana"] == "pending"
    preview_reads["detail"] = {**DETAIL, "kibana_case_id": None}
    assert preview(c)["kibana"] == "none"


def test_a_failed_case_read_still_offers_open(client, preview_reads):
    c, _ = client
    preview_reads["detail"] = HTTPException(404, "Case not found")
    data = preview(c)
    assert data["state"] == "failed"
    page = soup(c, "/ui/cases/3/preview")
    assert "could not be read" in page.text
    assert page.select_one("[data-click-action=openCaseDetail]")["data-args"] == "[3]"


def test_write_actions_need_case_update(client, preview_reads):
    c, user = client
    page = soup(c, "/ui/cases/3/preview")
    assert page.select_one("[data-click-action=inboxAssignMe]") is None
    assert page.select_one("[data-ci-notebox]") is None
    user.has_permission = lambda permission: True
    page = soup(c, "/ui/cases/3/preview")
    assert page.select_one("[data-click-action=inboxAssignMe]")["data-args"] == "[3]"
    close = page.select_one(".ci-acts [data-click-action=panelUpdateField]")
    assert close["data-args"] == '[3, "status", "closed"]'
    assert page.select_one("[data-click-action=addPanelNote]")["data-args"] == "[3]"
    assert page.select_one("[data-ci-preview]")["data-ci-me"] == "7"


def test_an_owned_case_offers_reassign_not_assign(client, preview_reads):
    c, user = client
    user.has_permission = lambda permission: True
    preview_reads["detail"] = {**DETAIL, "assigned_to_id": 2, "assigned_to": "k.osei"}
    page = soup(c, "/ui/cases/3/preview")
    assert page.select_one("[data-click-action=inboxAssignMe]") is None
    assert page.select_one("[data-click-action=inboxReassign]") is not None


# ── Permissions ─────────────────────────────────────────────────────────


def test_the_routes_refuse_without_case_read(client, reads, preview_reads):
    c, _ = client

    def denied():
        raise HTTPException(403, "Forbidden")

    c.app.dependency_overrides[ui.READ] = denied
    assert c.get("/ui/cases/board").status_code == 403
    assert c.get("/ui/cases/3/preview").status_code == 403


def test_case_reader_cannot_read_assignees_without_alert_read(client, monkeypatch):
    c, _ = client

    async def forbidden(**kwargs):
        pytest.fail("picker source called without alert:read")

    monkeypatch.setattr(api, "list_assignable_users", forbidden)
    response = c.get("/ui/cases/assignees", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "withheld"
    page = soup(c, "/ui/cases/assignees")
    assert page.select_one("#filter-assignee").has_attr("disabled")
    assert page.select_one("#filter-assignee option")["value"] == ""


def test_assignee_option_values_are_ids(client, monkeypatch):
    c, user = client
    user.has_permission = lambda permission: True

    async def read(**kwargs):
        return {"users": [{"id": 9, "username": 'name"quoted', "display_name": "Person <safe>", "has_elastic_profile": False}]}

    monkeypatch.setattr(api, "list_assignable_users", read)
    page = soup(c, "/ui/cases/assignees")
    assert page.select_one('#filter-assignee option[value="9"]').text == "Person <safe>"
    assert page.select_one('#new-case-assignee option[value="9"]') is not None


def test_the_retention_marker_is_not_latest_activity(client, preview_reads):
    c, _ = client
    preview_reads["timeline"] = {"events": [
        {"ts": iso(1), "kind": "system", "title": "Alert linked: retention:3", "source_type": "alert", "source_id": "retention:3"},
        {"ts": iso(2), "kind": "system", "title": "Alert linked: real", "source_type": "alert", "source_id": "real-1"},
    ]}
    assert [e["title"] for e in preview(c)["activity"]] == ["Alert linked: real"]


def test_the_note_box_carries_no_id_until_it_is_opened(client, preview_reads):
    c, user = client
    user.has_permission = lambda permission: True
    page = soup(c, "/ui/cases/3/preview")
    assert page.select_one("[data-ci-notebox]")["data-ci-placeholder"] == "Add a note to CASE-0003"
    assert page.select_one("#panel-note-input") is None
