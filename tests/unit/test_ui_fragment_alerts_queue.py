"""The alerts page's queue as a fragment: the read behind the table, the
fallback rows, the system select, the notice line and the failed state of
the three side lists.

Each case below is something the JavaScript either got right and must keep,
or got wrong and must stop doing. Measured against the tree before stage 4:

  * loadAlerts wrote `data.alerts || []`, and on the handler's own message
    branch AND in its catch wrote the identical `<div class="empty-state">-
    </div>` into top-hosts-list, top-rules-list and top-users-list. A failed
    Elasticsearch read and a quiet estate were the same picture in all three
    side panels.
  * When the handler reported a message but lab fixtures came with it, the
    fixtures were rendered and the message dropped. An unreachable
    Elasticsearch looked like a healthy one with a few alerts.
  * The table was wiped to "Loading alerts..." on every five-minute refresh.
  * The system select accumulated options in a client Map for the life of
    the page, so filtering by one system emptied it of the others on a
    fresh load.
  * The 500-row cap was never shown.
  * The fallback rows offered Assign, Acknowledge and Create case to every
    reader; the first two PUT a route carrying alert:triage and the third
    needs case:create.

The side lists' rows and the filter chips stay on the client, cloned from
<template> elements in the page shell, because they follow the client's own
narrowing (search text, severity, entity, saved view) and a second,
server-side definition of that filter would be the two-paths-disagree
failure the page's own comments warn of. Only their failed state is the
server's.

The render tests use fixtures: this deployment has no Elasticsearch and no
alerts, and an empty render proves nothing about the rows.
"""
from __future__ import annotations

import inspect
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from page_css import page_css

from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
from ion.web.templating import make_templates
from ion.web.ui import alerts as mod
from ion.web.ui.alerts import (
    CREATE_PERMISSION,
    CUSTOM_RANGE,
    QUEUE_DEFAULT_HOURS,
    QUEUE_FALLBACK_COLUMNS,
    QUEUE_LIMIT,
    QUEUE_PERMISSION,
    TRIAGE_PERMISSION,
    include_closed,
    queue_outcome,
    queue_rows,
    queue_window,
    router,
    system_options,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"
#: Retired into the one build; this is the
#: body[data-page="alerts"] block and only that block.
PAGE_CSS_TEXT = page_css("alerts")
FRAGMENTS = ROOT / "src/ion/web/templates/_fragments"
QUEUE = mod.QUEUE_FRAGMENT

WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")
DATA_BLOCK = re.compile(
    r'<script type="application/json" id="alerts-queue-data"[^>]*data-outcome="(\w+)">(.*?)</script>',
    re.S,
)


def render(name: str, **ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(name).render(**ctx)


def flat(body: str) -> str:
    return " ".join(body.split())


# ---------------------------------------------------------------------------
# Shapes, as GET /api/elasticsearch/alerts emits them
# ---------------------------------------------------------------------------


def _alert(**over: Any) -> dict:
    """An alert as get_es_alerts emits it: ElasticsearchAlert.to_dict without
    raw_data, plus the system resolution and the annotations."""
    base = {
        "id": "a1", "title": "Encoded PowerShell on ws-01", "severity": "high",
        "status": "open", "source": "siem", "message": "powershell -enc ...",
        "timestamp": "2026-10-13T08:00:00+00:00", "rule_name": "Encoded PowerShell",
        "host": "ws-01", "user": "jdoe", "tags": [], "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "mitre_tactic_name": "Execution", "geo_data": {}, "source_system": "corp",
        "process_name": None, "command_line": None, "parent_process_name": None,
        "file_name": None, "file_hash": None, "file_path": None,
        "network_community_id": None, "arkime_node": None, "source_ip": "10.0.0.5",
        "destination_ip": None, "cyab_system_id": 3, "cyab_system_name": "Corp SIEM",
        "cyab_data_source_name": None, "tide_system_id": None, "tide_system_name": None,
        "observables": [],
    }
    base.update(over)
    return base


def _triage_row(**over: Any) -> dict:
    """One value of the batch triage endpoint's map."""
    base = {"status": "acknowledged", "priority": "high", "case_id": 7,
            "case_number": "CASE-0007", "case_title": "Suspicious PowerShell",
            "assigned_to": None, "suggested_verdict": None,
            "suggested_verdict_confidence": None, "observable_count": 0,
            "observable_threat": "unknown"}
    base.update(over)
    return base


def _ctx(**over: Any) -> dict:
    """The route's context for the data outcome with one row."""
    alerts = [_alert()]
    ctx = {
        "failed": False, "degraded": False, "reason": None, "connection_error": False,
        "alerts": alerts, "arkime_enabled": True,
        "rows": queue_rows(alerts, {"a1": _triage_row()}, True),
        "triage_failed": False, "total": 1, "limit": QUEUE_LIMIT, "truncated": False,
        "window": {"hours": 24, "time_from": None, "time_to": None, "defaulted": False},
        "include_closed": False,
        "systems": system_options(alerts, [{"namespace": "other", "display_name": "Other"}], ""),
        "system": "", "colspan": QUEUE_FALLBACK_COLUMNS,
        "can_triage": True, "can_create_case": True,
        "data": {"alerts": alerts, "arkime_enabled": True},
    }
    ctx.update(over)
    return ctx


def failed_ctx(**over: Any) -> dict:
    ctx = _ctx(failed=True, reason="Elasticsearch is not configured", alerts=None,
               rows=None, total=None, data=None, systems=system_options(None, None, ""),
               arkime_enabled=False)
    ctx.update(over)
    return ctx


def empty_ctx(**over: Any) -> dict:
    ctx = _ctx(alerts=[], rows=[], total=0, data={"alerts": [], "arkime_enabled": False},
               arkime_enabled=False, systems=system_options([], None, ""))
    ctx.update(over)
    return ctx


def rows_section(body: str) -> str:
    return body[body.index('<tbody id="alerts-queue-rows">'):body.index("</tbody>")]


def data_block(body: str) -> tuple[str, Optional[dict]]:
    found = DATA_BLOCK.findall(body)
    assert len(found) == 1, "exactly one data block"
    outcome, payload = found[0]
    return outcome, json.loads(payload) if payload.strip() else None


# ---------------------------------------------------------------------------
# The window and the outcome, as loadAlerts derived them
# ---------------------------------------------------------------------------


def test_the_window_sends_hours_from_the_select_value():
    assert queue_window("168") == {"hours": 168, "time_from": None, "time_to": None,
                                   "defaulted": False}
    assert queue_window("1")["hours"] == 1


@pytest.mark.parametrize("value", ["abc", "", "0", "-5", "24.5"])
def test_a_select_value_that_is_not_a_positive_integer_falls_back_and_says_so(value):
    window = queue_window(value)
    assert window["hours"] == QUEUE_DEFAULT_HOURS
    assert window["defaulted"] is True
    assert window["time_from"] is None


def test_a_custom_range_is_read_on_the_viewers_clock():
    """getTimezoneOffset() is minutes west of UTC: -60 is UTC+1, so a local
    10:00 is 09:00Z, which is what `new Date(from).toISOString()` gave."""
    window = queue_window(CUSTOM_RANGE, "2026-10-13T10:00", "2026-10-13T12:30", "-60")
    assert window == {"hours": QUEUE_DEFAULT_HOURS, "time_from": "2026-10-13T09:00:00Z",
                      "time_to": "2026-10-13T11:30:00Z", "defaulted": False}


def test_a_custom_range_with_no_offset_is_read_as_utc_not_shifted():
    assert queue_window(CUSTOM_RANGE, "2026-10-13T10:00", "", "")["time_from"] == "2026-10-13T10:00:00Z"
    assert queue_window(CUSTOM_RANGE, "2026-10-13T10:00", "", "junk")["time_from"] == "2026-10-13T10:00:00Z"


def test_a_custom_range_without_a_start_falls_back_like_the_page_did():
    window = queue_window(CUSTOM_RANGE, "", "2026-10-13T12:30", "0")
    assert window["hours"] == QUEUE_DEFAULT_HOURS and window["defaulted"] is True
    assert window["time_from"] is None and window["time_to"] is None
    assert queue_window(CUSTOM_RANGE, "not a date", "", "0")["defaulted"] is True


def test_a_custom_end_that_does_not_parse_is_dropped_not_guessed():
    window = queue_window(CUSTOM_RANGE, "2026-10-13T10:00", "yesterday", "0")
    assert window["time_from"] == "2026-10-13T10:00:00Z" and window["time_to"] is None


@pytest.mark.parametrize("status,expected", [
    ("closed", True), ("all", True), ("open", False), ("", False),
    ("acknowledged", False), (None, False),
])
def test_only_closed_and_all_ask_for_closed_alerts(status, expected):
    assert include_closed(status) is expected


def test_a_payload_without_a_list_is_failed_with_no_reason():
    for payload in (None, "nope", {"detail": "Forbidden"}, {"alerts": None}, {"alerts": "x"}):
        out = queue_outcome(payload)
        assert out["failed"] is True and out["alerts"] is None and out["reason"] is None, payload
        assert out["degraded"] is False


def test_a_message_with_no_alerts_is_failed_and_keeps_the_reason_and_the_kind():
    out = queue_outcome({"alerts": [], "total": 0, "enabled": True, "configured": True,
                         "connection_error": True, "message": "Connection refused"})
    assert out == {"failed": True, "degraded": False, "reason": "Connection refused",
                   "connection_error": True, "alerts": None, "arkime_enabled": False}
    cfg = queue_outcome({"alerts": [], "enabled": False,
                         "message": "Elasticsearch integration is not enabled"})
    assert cfg["failed"] is True and cfg["connection_error"] is False
    assert cfg["reason"] == "Elasticsearch integration is not enabled"


def test_a_message_with_alerts_is_degraded_not_failed_and_keeps_both():
    """The page rendered the fixtures and dropped the message."""
    out = queue_outcome({"alerts": [_alert(is_lab_fixture=True)], "connection_error": True,
                         "message": "Connection refused"})
    assert out["failed"] is False and out["degraded"] is True
    assert out["reason"] == "Connection refused" and out["connection_error"] is True
    assert len(out["alerts"]) == 1


def test_no_message_and_no_alerts_is_empty_which_is_a_measured_zero():
    out = queue_outcome({"alerts": [], "total": 0, "hours": 24, "enabled": True,
                         "configured": True, "arkime_enabled": False})
    assert out["failed"] is False and out["degraded"] is False
    assert out["alerts"] == [] and out["reason"] is None


def test_data_keeps_only_dict_rows_and_reads_arkime_only_when_literally_true():
    out = queue_outcome({"alerts": [_alert(), "junk", None], "arkime_enabled": "yes"})
    assert len(out["alerts"]) == 1 and out["arkime_enabled"] is False
    assert queue_outcome({"alerts": [_alert()], "arkime_enabled": True})["arkime_enabled"] is True


# ---------------------------------------------------------------------------
# The select's options and the row derivations
# ---------------------------------------------------------------------------


def test_system_options_union_the_registry_and_the_rows_sorted_by_label():
    known = [{"namespace": "zeta", "display_name": "Zeta SIEM"},
             {"namespace": "corp", "display_name": "Corp SIEM"}]
    alerts = [_alert(source_system="corp"), _alert(source_system="edge", cyab_system_name=None,
                                                    tide_system_name="Edge (TIDE)"),
              _alert(source_system="raw", cyab_system_name=None), _alert(source_system=None)]
    out = system_options(alerts, known, "")
    assert [(o["value"], o["label"]) for o in out] == [
        ("corp", "Corp SIEM"), ("edge", "Edge (TIDE)"), ("raw", "raw"), ("zeta", "Zeta SIEM")]
    assert not any(o["selected"] for o in out)


def test_the_selected_system_is_kept_even_when_nothing_else_names_it():
    out = system_options([], None, "ghost")
    assert out == [{"value": "ghost", "label": "ghost", "selected": True}]
    out = system_options([_alert(source_system="corp")], None, "corp")
    assert [o["selected"] for o in out] == [True]


def test_system_options_tolerate_a_failed_registry_read_and_junk_rows():
    out = system_options([_alert(source_system="corp")], None, "")
    assert [o["value"] for o in out] == ["corp"]
    out = system_options(None, ["junk", {"display_name": "no namespace"}], "")
    assert out == []


def test_rows_tell_a_triage_that_was_not_read_from_one_that_does_not_exist():
    not_read = queue_rows([_alert()], None, True)[0]
    assert not_read["triage_read"] is False and not_read["triage_status"] is None
    assert not_read["effective_status"] == "open" and not_read["case_number"] is None

    none = queue_rows([_alert()], {}, True)[0]
    assert none["triage_read"] is True and none["triage_status"] is None
    assert none["effective_status"] == "open"

    read = queue_rows([_alert()], {"a1": _triage_row()}, True)[0]
    assert read["triage_status"] == "acknowledged" and read["effective_status"] == "acknowledged"
    assert read["case_number"] == "CASE-0007" and read["case_title"] == "Suspicious PowerShell"


def test_the_batch_handler_emits_the_triage_status_as_a_string(session):
    """queue_rows takes the triage status as the handler emits it, with no
    normalisation of its own, because get_batch_triage writes
    `t.status.value`. That is the invariant this pins, on the handler's
    output rather than on a render: AlertTriageStatus is a str enum, so a
    `== "closed"` on the member could never fail, and a template guard
    with no reachable case behind it is not coverage. If the handler ever
    emits the member, this fails here, and str(member) would otherwise
    print "AlertTriageStatus.CLOSED" into the row's class."""
    import asyncio
    from enum import Enum

    from ion.web.api import BatchTriageRequestWithStatus, get_batch_triage

    session.add(AlertTriage(es_alert_id="inv-1", status=AlertTriageStatus.CLOSED))
    session.commit()
    payload = asyncio.run(get_batch_triage(BatchTriageRequestWithStatus(alert_ids=["inv-1"]),
                                           current_user=_User(QUEUE_PERMISSION), session=session))
    status = payload["triage"]["inv-1"]["status"]
    assert status == "closed"
    assert type(status) is str and not isinstance(status, Enum)


def test_the_alerts_own_status_is_normalised_because_the_fixture_path_carries_the_member():
    """_fixture_alert_dicts passes `t.status` through, the enum member, and
    the one path that renders the alert's own status is a fixture whose
    triage read failed. That path is reachable, so this is a guard with a
    case behind it, unlike the triage side."""
    row = queue_rows([_alert(status=AlertTriageStatus.OPEN)], None, False)[0]
    assert row["effective_status"] == "open" and type(row["effective_status"]) is str
    body = rows_section(render(QUEUE, **_ctx(rows=[row])))
    assert 'alert-status-open">open<' in body
    assert "AlertTriageStatus" not in body


def test_the_arkime_link_needs_arkime_and_a_network_field():
    assert queue_rows([_alert()], {}, True)[0]["arkime"] is True
    assert queue_rows([_alert()], {}, False)[0]["arkime"] is False
    assert queue_rows([_alert(source_ip=None)], {}, True)[0]["arkime"] is False
    assert queue_rows([_alert(source_ip=None, arkime_node="n1")], {}, True)[0]["arkime"] is True
    by_ip = queue_rows([_alert()], {}, True)[0]
    assert by_ip["arkime_by_ip"] is True
    full = queue_rows([_alert(network_community_id="1:abc")], {}, True)[0]
    assert full["arkime"] is True and full["arkime_by_ip"] is False


def test_the_system_badge_follows_the_page_precedence_and_is_none_for_no_system():
    badge = queue_rows([_alert()], {}, False)[0]["system_badge"]
    assert badge == {"display": "Corp SIEM", "tooltip": "namespace: corp • CyAB: Corp SIEM",
                     "cyab_system_id": 3}
    tide = queue_rows([_alert(cyab_system_name=None, cyab_system_id=None,
                              tide_system_name="Corp (TIDE)")], {}, False)[0]["system_badge"]
    assert tide["display"] == "Corp (TIDE)" and "TIDE: Corp (TIDE)" in tide["tooltip"]
    assert tide["cyab_system_id"] is None
    # A TIDE name equal to the CyAB name is not repeated, as the page did not.
    same = queue_rows([_alert(tide_system_name="Corp SIEM")], {}, False)[0]["system_badge"]
    assert same["tooltip"] == "namespace: corp • CyAB: Corp SIEM"
    differs = queue_rows([_alert(tide_system_name="Corp (TIDE)")], {}, False)[0]["system_badge"]
    assert differs["tooltip"] == "namespace: corp • CyAB: Corp SIEM • TIDE: Corp (TIDE)"
    raw = queue_rows([_alert(cyab_system_name=None, cyab_system_id=None)], {}, False)[0]["system_badge"]
    assert raw["display"] == "corp" and raw["tooltip"] == "namespace: corp"
    assert queue_rows([_alert(source_system=None, cyab_system_name=None, cyab_system_id=None)],
                      {}, False)[0]["system_badge"] is None


# ---------------------------------------------------------------------------
# The fragment: four outcomes
# ---------------------------------------------------------------------------


def test_the_response_starts_with_a_table_so_htmx_parses_the_rows():
    """htmx wraps a fragment whose first tag is <tr> in a table and reads it
    at depth two; the out-of-band select and divs would then be
    foster-parented out of that wrapper and the rows lost."""
    body = render(QUEUE, **_ctx())
    first = re.search(r"<([a-z][^\s/>]*)", body)
    assert first and first.group(1) == "table"
    assert '<tbody id="alerts-queue-rows">' in body


def test_a_connection_failure_names_itself_and_is_not_an_empty_queue():
    body = render(QUEUE, **failed_ctx(connection_error=True, reason="Connection refused"))
    rows = rows_section(body)
    assert 'role="alert"' in rows
    assert "Alerts could not be read: Elasticsearch could not be reached." in rows
    assert "Connection refused" in rows
    assert "This is not an empty queue; nothing was counted." in rows
    assert "No alerts in this window" not in body
    assert f'colspan="{QUEUE_FALLBACK_COLUMNS}"' in rows


def test_a_configuration_failure_carries_the_handlers_message():
    body = render(QUEUE, **failed_ctx(reason="Elasticsearch is not configured"))
    rows = rows_section(body)
    assert "Alerts could not be read:" in rows and "Elasticsearch is not configured" in rows
    assert "could not be reached" not in rows
    assert 'class="aq-reason whitespace-pre-wrap"' in rows


def test_a_failure_with_no_reason_says_the_server_produced_no_list():
    body = render(QUEUE, **failed_ctx(reason=None))
    assert "the server did not produce a list" in rows_section(body)


def test_a_failed_read_swaps_all_three_side_lists_and_badges_to_unknown():
    body = render(QUEUE, **failed_ctx())
    for list_id, badge_id in (("top-hosts-list", "hosts-count"), ("top-rules-list", "rules-count"),
                              ("top-users-list", "users-count")):
        assert f'<div hx-swap-oob="innerHTML:#{list_id}">' in body, list_id
        assert f'<div hx-swap-oob="innerHTML:#{badge_id}">?</div>' in body, badge_id
    assert body.count('role="alert">Could not be read</div>') == 3
    assert "None</div>" not in body, "the side lists must not say None for a read that failed"


def test_a_failed_read_says_so_in_the_data_block_and_carries_no_array():
    """The page decides on data-outcome before it parses anything, and the
    route builds `data` as None exactly when the read failed (pinned on
    the route below), so the block's body is `null` and nothing else needs
    guarding in the template."""
    body = render(QUEUE, **failed_ctx())
    outcome, payload = data_block(body)
    assert outcome == "failed" and payload is None
    assert DATA_BLOCK.search(body).group(2) == "null"


def test_an_empty_window_says_so_and_is_not_a_failure():
    body = render(QUEUE, **empty_ctx())
    rows = rows_section(body)
    assert "No alerts in this window" in rows
    assert 'role="alert"' not in rows and "could not be read" not in rows.lower()
    assert "(closed alerts not requested)" in rows
    assert "hx-swap-oob=\"innerHTML:#top-hosts-list\"" not in body, "the page counts its own zero"
    outcome, payload = data_block(body)
    assert outcome == "read" and payload == {"alerts": [], "arkime_enabled": False}


def test_an_empty_window_names_the_system_and_drops_the_closed_note_when_closed_were_asked_for():
    body = render(QUEUE, **empty_ctx(system="corp", include_closed=True))
    rows = rows_section(body)
    assert "for system corp" in rows
    assert "(closed alerts not requested)" not in rows


def test_a_data_row_carries_the_hooks_and_the_row_facts():
    body = render(QUEUE, **_ctx())
    rows = rows_section(body)
    # On the element: the row and its checkbox both carry data-alert-id, so
    # a search of the whole section could not notice the row losing it (a
    # mutation pass found exactly that).
    row_tag = _tag(rows, 'class="alert-row aq-fallback-row"')
    assert 'data-alert-id="a1"' in row_tag
    assert "data-click-action=\"showAlertDetail\" data-args='[\"a1\"]'" in row_tag
    assert "data-contextmenu-args='[\"$event\", \"a1\"]'" in row_tag
    box_tag = _tag(rows, 'class="alert-checkbox"')
    assert 'data-alert-id="a1"' in box_tag
    assert "data-args='[\"a1\", \"$checked\"]'" in rows
    assert '<span class="triage-dot triage-acknowledged" title="Triage: acknowledged"></span>' in rows
    assert 'class="severity-badge severity-high"' in rows
    assert '<span class="mitre-inline-badge" title="Command and Scripting Interpreter (Execution)">T1059</span>' in rows
    assert '<span class="case-link-badge" title="Suspicious PowerShell">CASE-0007</span>' in rows
    assert 'class="status-badge alert-status-acknowledged">acknowledged<' in rows
    assert '<a href="/cyab#3" class="system-badge linked"' in rows
    assert "<time datetime=" in rows and 'data-ts-local="yes"' in rows
    assert 'href="/alerts/a1/arkime"' in rows and "(IP search, no community ID)" in rows
    assert "Lab fixture" not in rows
    assert ' style="' not in body


def test_a_data_row_escapes_what_it_was_handed():
    body = render(QUEUE, **_ctx(rows=queue_rows([_alert(id="a<1'", title="<b>x</b></script>")],
                                                {}, False)))
    rows = rows_section(body)
    assert "<b>x</b>" not in rows and "&lt;b&gt;x&lt;/b&gt;" in rows
    assert "data-args='[\"a\\u003c1\\u0027\"]'" in rows
    outcome, payload = data_block(body)
    assert payload["alerts"][0]["id"] == "a1"
    assert "</script>" not in body[body.index('id="alerts-queue-data"'):body.rindex("</script>")]


def test_the_checkbox_args_are_json_even_for_an_id_holding_a_double_quote():
    """A hand-built `'["{{ a.id }}", "$checked"]'` survives autoescaping for
    < and ' (the browser decodes the entities back to the same JSON) but
    not for a double quote: &#34; decodes to a bare quote inside the JSON
    string and JSON.parse throws, so the tick never reaches the server.
    tojson writes \\" and the attribute stays parseable."""
    import html

    body = render(QUEUE, **_ctx(rows=queue_rows([_alert(id='a"b')], {}, False)))
    box_tag = _tag(rows_section(body), 'class="alert-checkbox"')
    value = re.search(r"data-args='([^']*)'", box_tag).group(1)
    # What the browser hands JSON.parse is the attribute after entity
    # decoding. The hand-built form gives `["a"b", "$checked"]` here, which
    # throws, and event-delegation.js then logs and returns: a tick that
    # looks like it worked and reaches nothing.
    assert json.loads(html.unescape(value)) == ['a"b', "$checked"]
    # The attribute itself is also escaped correctly (an entity in an
    # attribute is the right spelling; this is not the JSON).
    assert 'data-alert-id="a&#34;b"' in box_tag


def test_a_lab_fixture_row_is_badged():
    body = render(QUEUE, **_ctx(rows=queue_rows([_alert(is_lab_fixture=True)], {}, False)))
    assert 'class="lab-fixture-badge"' in rows_section(body)


def test_a_row_whose_triage_was_not_read_says_so_rather_than_none():
    body = render(QUEUE, **_ctx(rows=queue_rows([_alert()], None, False)))
    rows = rows_section(body)
    assert 'class="triage-dot triage-unknown" title="Triage not read"' in rows
    assert 'title="Triage not read">?</span>' in rows
    assert "triage-none" not in rows and "case-link-badge" not in rows
    assert 'alert-status-open">open<' in rows, "the ES status stands in"


def test_a_row_with_no_triage_record_is_none_not_unknown():
    body = render(QUEUE, **_ctx(rows=queue_rows([_alert()], {}, False)))
    rows = rows_section(body)
    assert 'class="triage-dot triage-none" title="No triage record"' in rows
    assert "triage-unknown" not in rows and "?</span>" not in rows
    assert '<span class="text-[var(--text-muted)]">-</span>' in rows


def test_the_quick_actions_are_offered_only_with_the_permissions_their_routes_carry():
    both = rows_section(render(QUEUE, **_ctx()))
    assert 'data-click-action="quickAssignToMe"' in both
    assert 'data-click-action="quickStatusChange"' in both
    assert 'data-click-action="showCreateCaseForm"' in both

    no_triage = rows_section(render(QUEUE, **_ctx(can_triage=False)))
    assert "quickAssignToMe" not in no_triage and "quickStatusChange" not in no_triage
    assert 'data-click-action="showCreateCaseForm"' in no_triage

    no_case = rows_section(render(QUEUE, **_ctx(can_create_case=False)))
    assert "showCreateCaseForm" not in no_case
    assert 'data-click-action="quickAssignToMe"' in no_case


def test_the_arkime_link_follows_the_row_flag_and_its_title_the_community_id():
    rows = rows_section(render(QUEUE, **_ctx(rows=queue_rows([_alert()], {}, False))))
    assert "/arkime" not in rows
    rows = rows_section(render(QUEUE, **_ctx(
        rows=queue_rows([_alert(network_community_id="1:abc")], {}, True))))
    assert 'href="/alerts/a1/arkime"' in rows
    assert "IP search" not in rows


def test_a_row_without_a_system_shows_a_dash_and_a_cyab_less_one_is_not_a_link():
    rows = rows_section(render(QUEUE, **_ctx(rows=queue_rows(
        [_alert(source_system=None, cyab_system_name=None, cyab_system_id=None)], {}, False))))
    assert "system-badge" not in rows
    rows = rows_section(render(QUEUE, **_ctx(rows=queue_rows(
        [_alert(cyab_system_id=None)], {}, False))))
    assert '<span class="system-badge" title="namespace: corp • CyAB: Corp SIEM">Corp SIEM</span>' in rows
    assert "/cyab#" not in rows


def test_the_data_block_carries_the_array_and_the_arkime_flag():
    outcome, payload = data_block(render(QUEUE, **_ctx()))
    assert outcome == "read"
    assert [a["id"] for a in payload["alerts"]] == ["a1"]
    assert payload["arkime_enabled"] is True


# ---------------------------------------------------------------------------
# The notice line, one key at a time
# ---------------------------------------------------------------------------


def notice(body: str) -> str:
    start = body.index('<div hx-swap-oob="innerHTML:#alerts-queue-notice">')
    return flat(body[start:body.index("</div>", start)])


def test_the_notice_is_empty_when_there_is_nothing_to_say():
    assert notice(render(QUEUE, **_ctx())) == '<div hx-swap-oob="innerHTML:#alerts-queue-notice">'


def test_a_degraded_read_says_only_fixtures_are_shown_and_why():
    conn = notice(render(QUEUE, **_ctx(degraded=True, connection_error=True, reason="refused")))
    assert "Elasticsearch could not be reached; only lab fixture alerts are shown." in conn
    assert "refused" not in conn
    cfg = notice(render(QUEUE, **_ctx(degraded=True, reason="Elasticsearch is not configured")))
    assert "Elasticsearch is not configured; only lab fixture alerts are shown." in cfg
    assert "could not be reached" not in cfg
    assert "aq-notice-degraded" not in notice(render(QUEUE, **_ctx(degraded=False, reason="x")))


def test_a_capped_window_is_said_out_loud():
    full = notice(render(QUEUE, **_ctx(truncated=True)))
    assert f"Showing the newest {QUEUE_LIMIT} alerts; the window holds more." in full
    assert "aq-notice-truncated" not in notice(render(QUEUE, **_ctx(truncated=False)))


def test_a_defaulted_window_is_said_with_the_hours_actually_read():
    body = notice(render(QUEUE, **_ctx(window={"hours": 24, "time_from": None, "time_to": None,
                                                "defaulted": True})))
    assert "The time range could not be read from the controls; the last 24 hours are shown." in body
    assert "aq-notice-window" not in notice(render(QUEUE, **_ctx()))


def test_a_failed_triage_batch_is_said_in_the_notice():
    assert "Triage status could not be read for these rows." in notice(render(QUEUE, **_ctx(triage_failed=True)))
    assert "aq-notice-triage" not in notice(render(QUEUE, **_ctx(triage_failed=False)))


# ---------------------------------------------------------------------------
# The system select
# ---------------------------------------------------------------------------


def select(body: str) -> str:
    start = body.index('<select id="alert-system-filter"')
    return body[start:body.index("</select>", start)]


def test_the_select_is_swapped_whole_and_keeps_the_page_controls_attributes():
    tag = select(render(QUEUE, **_ctx()))
    head = tag[:tag.index(">")]
    assert 'name="system"' in head and 'hx-swap-oob="true"' in head
    assert 'data-change-action="loadAlerts"' in head
    assert 'class="ion-select w-auto!"' in head


def test_the_select_marks_the_requested_system_and_all_systems_otherwise():
    alerts = [_alert()]
    body = select(render(QUEUE, **_ctx(systems=system_options(alerts, None, "corp"), system="corp")))
    assert '<option value="corp" selected>Corp SIEM</option>' in body
    assert '<option value="" selected>' not in body
    body = select(render(QUEUE, **_ctx(systems=system_options(alerts, None, ""), system="")))
    assert '<option value="" selected>All Systems</option>' in body
    assert '<option value="corp">Corp SIEM</option>' in body


def test_the_select_is_rendered_on_a_failed_read_too():
    body = select(render(QUEUE, **failed_ctx(systems=system_options(None, [{"namespace": "z", "display_name": "Zeta"}], "z"), system="z")))
    assert '<option value="z" selected>Zeta</option>' in body


# ---------------------------------------------------------------------------
# The route, through every outcome
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "queue-tester"

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


@pytest.fixture
def es(monkeypatch):
    """Stubs get_es_alerts where the fragment imports it, recording the
    arguments it was called with. `es.payload` is what it returns; set
    `es.raise_` to make it raise."""
    import ion.web.elasticsearch_api as es_api

    class Stub:
        payload: Any = {"alerts": [], "total": 0, "hours": 24, "enabled": True,
                        "configured": True, "arkime_enabled": False}
        raise_: Optional[Exception] = None
        calls: list = []

    async def fake(**kwargs):
        Stub.calls.append(kwargs)
        if Stub.raise_:
            raise Stub.raise_
        return Stub.payload

    monkeypatch.setattr(es_api, "get_es_alerts", fake)
    return Stub


@pytest.fixture
def triage(monkeypatch):
    import ion.web.api as api

    class Stub:
        payload: Any = {"triage": {}}
        raise_: Optional[Exception] = None
        calls: list = []

    async def fake(data, current_user=None, session=None):
        Stub.calls.append(data)
        if Stub.raise_:
            raise Stub.raise_
        return Stub.payload

    monkeypatch.setattr(api, "get_batch_triage", fake)
    return Stub


@pytest.fixture
def registry(monkeypatch):
    import ion.services.system_resolver_service as svc

    class Stub:
        rows: Any = []
        raise_: Optional[Exception] = None

    def fake(session):
        if Stub.raise_:
            raise Stub.raise_
        return Stub.rows

    monkeypatch.setattr(svc, "list_known_systems", fake)
    return Stub


def test_the_route_refuses_a_caller_without_alert_read(session, es):
    with TestClient(_app(session, _User("case:read"))) as client:
        assert client.get("/ui/alerts/queue").status_code == 403
    assert es.calls == []


def test_the_route_passes_the_derived_window_and_the_limit_to_the_handler(session, es, triage, registry):
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        client.get("/ui/alerts/queue?time_range=168&status=open&system=")
        client.get("/ui/alerts/queue?time_range=custom&custom_from=2026-10-13T10:00&custom_to=&tz_offset=-60&status=closed&system=corp")
        client.get("/ui/alerts/queue?status=all")
    first, second, third = es.calls
    assert first["hours"] == 168 and first["include_closed"] is False
    assert first["system"] is None and first["limit"] == QUEUE_LIMIT
    assert first["time_from"] is None and first["time_to"] is None
    assert second["time_from"] == "2026-10-13T09:00:00Z" and second["time_to"] is None
    assert second["include_closed"] is True and second["system"] == "corp"
    assert third["include_closed"] is True and third["hours"] == QUEUE_DEFAULT_HOURS
    assert all(c["current_user"].username == "queue-tester" for c in es.calls)


def test_the_route_renders_a_failed_read_from_the_handlers_message(session, es, triage, registry):
    es.payload = {"alerts": [], "total": 0, "enabled": True, "configured": True,
                  "connection_error": True, "message": "Connection refused"}
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "Elasticsearch could not be reached" in body and "Connection refused" in body
    assert 'hx-swap-oob="innerHTML:#top-hosts-list"' in body
    assert data_block(body) == ("failed", None)
    assert triage.calls == [], "no triage read for rows that were not read"


def test_the_route_renders_a_raising_handler_as_failed_not_empty(session, es, triage, registry):
    es.raise_ = RuntimeError("socket closed")
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "the server did not produce a list" in body
    assert "No alerts in this window" not in body
    assert data_block(body) == ("failed", None)


def test_the_route_renders_a_degraded_read_with_the_rows_and_the_notice(session, es, triage, registry):
    es.payload = {"alerts": [_alert(id="lab-fixture-1", is_lab_fixture=True)], "total": 1,
                  "enabled": True, "configured": False, "message": "Elasticsearch is not configured"}
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert 'data-alert-id="lab-fixture-1"' in body and "Lab fixture" in body
    assert "Elasticsearch is not configured; only lab fixture alerts are shown." in body
    assert 'role="alert">Could not be read' not in body
    outcome, payload = data_block(body)
    assert outcome == "read" and [a["id"] for a in payload["alerts"]] == ["lab-fixture-1"]


def test_the_route_renders_an_empty_window_as_a_measured_zero(session, es, triage, registry):
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "No alerts in this window" in body
    assert data_block(body) == ("read", {"alerts": [], "arkime_enabled": False})
    assert triage.calls == []


def test_the_route_reads_triage_for_the_rows_and_shows_it(session, es, triage, registry):
    es.payload = {"alerts": [_alert(), _alert(id="a2")], "arkime_enabled": True}
    triage.payload = {"triage": {"a1": _triage_row()}}
    with TestClient(_app(session, _User(QUEUE_PERMISSION, TRIAGE_PERMISSION, CREATE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert [c.alert_ids for c in triage.calls] == [["a1", "a2"]]
    assert triage.calls[0].es_statuses is None, "a read: the Kibana sync must not run from here"
    rows = rows_section(body)
    assert "CASE-0007" in rows
    assert rows.count('class="triage-dot triage-none"') == 1
    assert rows.count('data-click-action="quickAssignToMe"') == 2
    assert rows.count('data-click-action="showCreateCaseForm"') == 2
    assert rows.count('href="/alerts/a') == 2, "arkime_enabled from the payload reaches the rows"
    assert "Triage status could not be read" not in body


def test_the_route_tells_a_failed_triage_read_from_no_triage(session, es, triage, registry):
    es.payload = {"alerts": [_alert()]}
    triage.raise_ = RuntimeError("db gone")
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert 'class="triage-dot triage-unknown"' in body
    assert "Triage status could not be read for these rows." in body
    assert "triage-none" not in body


def test_the_route_treats_a_triage_payload_without_a_map_as_not_read(session, es, triage, registry):
    es.payload = {"alerts": [_alert()]}
    triage.payload = {"detail": "nope"}
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "triage-unknown" in body and "Triage status could not be read" in body


def test_the_route_withholds_the_quick_actions_from_a_reader(session, es, triage, registry):
    es.payload = {"alerts": [_alert()]}
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        rows = rows_section(client.get("/ui/alerts/queue").text)
    assert "quickAssignToMe" not in rows and "quickStatusChange" not in rows
    assert "showCreateCaseForm" not in rows
    assert 'data-click-action="showAlertDetail"' in rows


def test_the_route_builds_the_select_from_the_registry_and_the_rows(session, es, triage, registry):
    es.payload = {"alerts": [_alert(source_system="edge", cyab_system_name="Edge")]}
    registry.rows = [{"namespace": "corp", "display_name": "Corp SIEM"}]
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = select(client.get("/ui/alerts/queue?system=corp").text)
    assert '<option value="corp" selected>Corp SIEM</option>' in body
    assert '<option value="edge">Edge</option>' in body


def test_the_route_survives_a_failed_registry_read_with_the_rows_systems(session, es, triage, registry):
    es.payload = {"alerts": [_alert()]}
    registry.raise_ = RuntimeError("cache build failed")
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        resp = client.get("/ui/alerts/queue")
    assert resp.status_code == 200
    assert '<option value="corp">Corp SIEM</option>' in select(resp.text)


def test_the_route_says_when_the_window_was_capped(session, es, triage, registry):
    es.payload = {"alerts": [_alert(id=f"a{i}") for i in range(QUEUE_LIMIT)]}
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert f"Showing the newest {QUEUE_LIMIT} alerts" in body
    es.payload = {"alerts": [_alert(id=f"a{i}") for i in range(QUEUE_LIMIT - 1)]}
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "Showing the newest" not in body


def test_the_route_says_when_the_time_range_was_defaulted(session, es, triage, registry):
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue?time_range=custom&custom_from=").text
    assert "The time range could not be read from the controls" in body
    assert es.calls[-1]["hours"] == QUEUE_DEFAULT_HOURS


# ---------------------------------------------------------------------------
# The route through the real handler, with Elasticsearch stubbed at its edge
# ---------------------------------------------------------------------------


def test_the_real_handler_not_enabled_is_a_failed_read_and_a_fixture_makes_it_degraded(session, monkeypatch):
    import ion.web.elasticsearch_api as es_api

    monkeypatch.setattr(es_api, "get_elasticsearch_config", lambda: {"enabled": False})
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "Elasticsearch integration is not enabled" in rows_section(body)
    assert data_block(body) == ("failed", None)

    session.add(AlertTriage(es_alert_id="lab-fixture-7", rule_name="Lab: brute force",
                            priority="medium", status=AlertTriageStatus.OPEN))
    session.commit()
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    rows = rows_section(body)
    assert 'data-alert-id="lab-fixture-7"' in rows and "Lab fixture" in rows
    assert 'class="triage-dot triage-open"' in rows, "the fixture's own triage row was read"
    assert "Elasticsearch integration is not enabled; only lab fixture alerts are shown." in body
    outcome, payload = data_block(body)
    assert outcome == "read" and payload["alerts"][0]["is_lab_fixture"] is True

    # The fixture's own status is the enum member; with the triage read
    # failed it is what the row renders, as a value.
    import ion.web.api as api

    async def boom(data, current_user=None, session=None):
        raise RuntimeError("db gone")

    monkeypatch.setattr(api, "get_batch_triage", boom)
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    rows = rows_section(body)
    assert 'class="triage-dot triage-unknown"' in rows
    assert 'alert-status-open">open<' in rows
    assert "AlertTriageStatus" not in body


def test_the_real_handler_connection_error_and_data_paths(session, monkeypatch):
    import ion.web.elasticsearch_api as es_api
    from ion.services.elasticsearch_service import ElasticsearchAlert, ElasticsearchError

    class Service:
        is_configured = True
        fail = True

        async def get_alerts(self, **kwargs):
            if self.fail:
                raise ElasticsearchError("connection refused")
            return [ElasticsearchAlert(
                id="es-1", title="Beaconing", severity="critical", status="open",
                source="siem", message="periodic DNS", rule_name="Beaconing",
                host="db-02", user=None, source_system="corp",
                timestamp=datetime(2026, 10, 13, 8, 0, tzinfo=timezone.utc))]

    service = Service()
    monkeypatch.setattr(es_api, "get_elasticsearch_config", lambda: {"enabled": True})
    monkeypatch.setattr(es_api, "get_elasticsearch_service", lambda: service)

    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue").text
    assert "Elasticsearch could not be reached" in rows_section(body)
    assert data_block(body) == ("failed", None)

    service.fail = False
    case = AlertCase(case_number="CASE-0401", title="Beaconing", status=AlertCaseStatus.OPEN,
                     severity="critical", created_by_id=1)
    session.add(case)
    session.commit()
    session.add(AlertTriage(es_alert_id="es-1", case_id=case.id, status=AlertTriageStatus.ACKNOWLEDGED))
    session.commit()
    with TestClient(_app(session, _User(QUEUE_PERMISSION))) as client:
        body = client.get("/ui/alerts/queue?time_range=72").text
    rows = rows_section(body)
    assert 'data-alert-id="es-1"' in rows and "CASE-0401" in rows
    assert 'class="triage-dot triage-acknowledged"' in rows
    assert 'alert-status-acknowledged">acknowledged<' in rows
    outcome, payload = data_block(body)
    assert outcome == "read" and payload["alerts"][0]["host"] == "db-02"
    assert "raw_data" not in payload["alerts"][0], "the list shape, as the JSON endpoint sends it"


# ---------------------------------------------------------------------------
# The permissions, derived from the route tables rather than restated
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


def test_the_queue_permission_is_what_both_json_routes_carry():
    from ion.web import api, elasticsearch_api

    assert _route_permission(elasticsearch_api.router, "/elasticsearch/alerts", "GET") == QUEUE_PERMISSION
    assert _route_permission(api.router, "/elasticsearch/alerts-triage/batch", "POST") == QUEUE_PERMISSION
    # The select's options come from list_known_systems, which GET
    # /api/elasticsearch/alerts/systems serves under the same permission.
    assert _route_permission(elasticsearch_api.router, "/elasticsearch/alerts/systems", "GET") == QUEUE_PERMISSION
    assert _route_permission(router, "/alerts/queue", "GET") == QUEUE_PERMISSION


def test_the_control_permissions_are_what_their_routes_carry():
    from ion.web import api, case_lifecycle_api

    assert _route_permission(api.router, "/elasticsearch/alerts/{alert_id}/triage", "PUT") == TRIAGE_PERMISSION
    assert _route_permission(case_lifecycle_api.router, "/elasticsearch/alerts/cases", "POST") == CREATE_PERMISSION


# ---------------------------------------------------------------------------
# The page shell, attribute by attribute on the element that carries it
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _script() -> str:
    page = _page()
    start = page.rindex('<script nonce="{{ csp_nonce }}">')
    body = page[page.index(">", start) + 1:]
    body = body[:body.index("</script>")]
    return body.replace("{% raw %}", "").replace("{% endraw %}", "")


def _shell() -> str:
    page = _page()
    return page[:page.rindex('<script nonce="{{ csp_nonce }}">')]


def _tag(text: str, needle: str) -> str:
    """The opening tag that contains `needle`, from its < to the > that
    closes it. A > inside a quoted attribute value (hx-select's child
    combinator) does not count."""
    at = text.index(needle)
    start = text.rindex("<", 0, at)
    quote = None
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return text[start:i]
    raise AssertionError(f"unterminated tag at {needle!r}")


def _function(name: str) -> str:
    script = _script()
    start = script.index(f"function {name}(")
    nxt = [i for i in (script.find("\nfunction ", start + 10), script.find("\nasync function ", start + 10),
                       script.find("\ndocument.", start + 10), script.find("\n// ", start + 10))
           if i != -1]
    return script[start:min(nxt)] if nxt else script[start:]


def test_the_tbody_carries_the_read_and_every_control_in_its_include_list():
    tbody = _tag(_shell(), 'id="alerts-tbody"')
    assert 'hx-get="/ui/alerts/queue"' in tbody
    assert 'hx-trigger="load, alerts-refresh from:body"' in tbody
    assert 'hx-select="#alerts-queue-rows > tr"' in tbody
    assert 'hx-swap="innerHTML"' in tbody
    assert 'hx-indicator="#alerts-queue-loading"' in tbody
    assert 'hx-disinherit="*"' in tbody
    include = re.search(r'hx-include="([^"]*)"', tbody).group(1)
    for control in ("#alert-time-range", "#custom-time-from", "#custom-time-to", "#aq-tz-offset",
                    "#alert-status-filter", "#alert-system-filter"):
        assert control in include.split(", "), control


@pytest.mark.parametrize("element_id,name", [
    ("alert-time-range", "time_range"), ("custom-time-from", "custom_from"),
    ("custom-time-to", "custom_to"), ("aq-tz-offset", "tz_offset"),
    ("alert-status-filter", "status"), ("alert-system-filter", "system"),
])
def test_each_included_control_carries_the_name_the_route_reads(element_id, name):
    tag = _tag(_shell(), f'id="{element_id}"')
    assert f'name="{name}"' in tag, tag


def test_the_included_names_are_the_routes_parameters():
    params = inspect.signature(mod.alerts_queue_fragment).parameters
    for name in ("time_range", "custom_from", "custom_to", "tz_offset", "status", "system"):
        assert name in params, name


def test_the_indicator_the_notice_and_the_data_block_sit_outside_the_tbody():
    shell = _shell()
    tbody_open = shell.index('<tbody id="alerts-tbody"')
    tbody_close = shell.index("</tbody>", tbody_open)
    indicator = shell.index('id="alerts-queue-loading"')
    assert indicator < tbody_open
    assert 'class="aq-count htmx-indicator"' in _tag(shell, 'id="alerts-queue-loading"')
    notice = shell.index('id="alerts-queue-notice"')
    assert notice < tbody_open and 'class="aq-notice"' in _tag(shell, 'id="alerts-queue-notice"')
    block = _tag(shell, 'id="alerts-queue-data"')
    assert shell.index('id="alerts-queue-data"') > tbody_close
    assert 'type="application/json"' in block and 'data-outcome="none"' in block
    assert "nonce" not in block, "a data block is never executed and needs no nonce"


def test_the_refresh_control_sits_outside_the_target_it_refreshes():
    shell = _shell()
    assert shell.index('data-click-action="loadAlerts"') < shell.index('<tbody id="alerts-tbody"')


def test_the_side_list_badges_start_uncounted_not_at_zero():
    shell = _shell()
    for badge in ("hosts-count", "rules-count", "users-count"):
        tag = _tag(shell, f'id="{badge}"')
        assert 'title="Not counted yet"' in tag, badge
        after = shell[shell.index(f'id="{badge}"'):]
        assert after[after.index(">") + 1:after.index("</span>")] == "&hellip;", badge


def test_the_templates_the_client_clones_are_in_the_shell_with_the_slots_it_fills():
    shell = _shell()
    facet = shell[shell.index('<template id="aq-facet-template">'):]
    facet = facet[:facet.index("</template>")]
    assert 'class="list-item aq-facet"' in facet
    assert 'class="overflow-hidden text-ellipsis whitespace-nowrap aq-facet-name"' in facet
    assert 'class="list-item-count"' in facet
    assert facet.count("<i class=\"sev-") == 4
    for sev in ("critical", "high", "medium", "low"):
        assert f'<i class="sev-{sev}" data-sev="{sev}"></i>' in facet, sev
    for tpl in ("aq-facet-empty-template", "aq-chip-template", "aq-chip-all-template",
                "aq-module-missing-template"):
        assert f'<template id="{tpl}">' in shell, tpl
    chip = shell[shell.index('<template id="aq-chip-template">'):]
    chip = chip[:chip.index("</template>")]
    assert 'class="aq-chip-label"' in chip and "<b></b>" in chip
    assert 'class="x" data-aq-chip=""' in chip
    assert 'class="aq-chip-all" data-aq-chip="__all"' in shell


def test_load_alerts_dispatches_the_event_the_tbody_listens_for():
    body = _function("loadAlerts")
    assert "dispatchEvent(new CustomEvent('alerts-refresh'))" in body
    assert "fetch(" not in body
    assert "`/api/elasticsearch/alerts?${params}`" not in _script(), "the list read is the fragment's"


def test_the_swap_handler_reads_the_data_block_only_when_a_read_happened():
    body = _function("onQueueSwapped")
    assert "getElementById('alerts-queue-data')" in body
    assert "block.dataset.outcome !== 'read'" in body
    assert "JSON.parse(block.textContent)" in body
    assert "Array.isArray(data.alerts)" in body
    assert "allAlerts = data.alerts;" in body
    assert "arkimeEnabled = data.arkime_enabled === true;" in body
    for call in ("applyFilters();", "renderThreatBanner();", "renderAnalytics();",
                 "loadTriageBatch();", "loadPatternDetections();"):
        assert call in body, call
    assert "|| []" not in body
    script = _script()
    listener = script[script.index("addEventListener('htmx:afterSwap'"):]
    listener = listener[:listener.index("});")]
    assert "target.id === 'alerts-tbody'" in listener and "onQueueSwapped()" in listener


def test_the_page_no_longer_requests_the_queue_itself_at_load():
    script = _script()
    ready = script[script.index("addEventListener('DOMContentLoaded'"):]
    ready = ready[:ready.index("\n});")]
    assert "loadAlerts()" not in ready, "the tbody's hx-trigger=\"load\" makes the request"
    assert "loadCasesIndex();" in ready


def test_the_zone_offset_is_set_before_htmx_can_request():
    script = _script()
    iife = script[script.index("getElementById('aq-tz-offset')") - 120:script.index("getTimezoneOffset()") + 40]
    assert "(function () {" in iife and "tz.value = String(new Date().getTimezoneOffset());" in iife
    assert script.index("getTimezoneOffset()") < script.index("addEventListener('DOMContentLoaded'")


def test_the_side_lists_and_chips_are_cloned_from_the_templates():
    side = _function("renderSideList")
    assert "cloneTemplate('aq-facet-template')" in side
    assert "cloneTemplate('aq-facet-empty-template')" in side
    assert "badge.removeAttribute('title')" in side
    assert "replaceChildren" in side
    assert "_fillSevMix(" in side and "function _fillSevMix(" in _script()
    chips = _function("renderFilterChips")
    assert "cloneTemplate('aq-chip-template')" in chips
    assert "cloneTemplate('aq-chip-all-template')" in chips
    alerts = _function("renderAlerts")
    assert "cloneTemplate('aq-module-missing-template')" in alerts
    assert "_renderAlertsFallback" not in _script()


def test_the_search_box_dispatches_to_a_window_visible_function():
    """event-delegation.js resolves `data-input-action="debouncedSearch"` as
    window.debouncedSearch. A top-level `const` is not a window property, so
    the search box dispatched to nothing: measured live before this stage,
    typing "ws-01" left the queue at two rows where one matched."""
    shell = _shell()
    assert 'data-input-action="debouncedSearch"' in _tag(shell, 'id="alert-search"')
    assert re.search(r"^var debouncedSearch = debounce\(", _script(), re.M)
    assert not re.search(r"^const debouncedSearch", _script(), re.M)


def test_the_page_no_longer_builds_the_queue_region_in_javascript():
    script = _script()
    for gone in ("function populateSystemFilterFromAlerts", "_knownSystems",
                 "function _renderAlertsFallback", "function _sevMixBar"):
        assert gone not in script, gone
    for kept in ("function renderSideList", "function renderFilterChips", "function renderAlerts",
                 "function _worstSev", "function applyFilters", "function loadTriageBatch"):
        assert kept in script, kept


@pytest.mark.parametrize("name", ["loadAlerts", "onQueueSwapped", "renderSideList",
                                  "renderFilterChips", "renderAlerts", "_fillSevMix"])
def test_the_converted_functions_hold_no_dom_writes(name):
    assert not WRITES.search(_function(name)), name


def test_the_fragment_carries_nothing_the_csp_would_block():
    text = (FRAGMENTS / "alerts_queue.html").read_text(encoding="utf-8")
    assert not re.search(r"\sstyle=", text), "style-src-attr 'none'"
    assert "hx-on" not in text and "js:" not in text and "onclick=" not in text
    scripts = re.findall(r"<script[^>]*>", text)
    assert scripts == ['<script type="application/json" id="alerts-queue-data" hx-swap-oob="true"\n        data-outcome="{{ \'failed\' if failed else \'read\' }}">'], (
        "the one script element is the data block, which no browser executes"
    )


def test_the_page_additions_carry_nothing_the_csp_would_block():
    shell = _shell()
    assert "hx-on" not in shell
    assert 'hx-vals="js:' not in shell and 'hx-headers="js:' not in shell
    for trigger in re.findall(r'hx-trigger="([^"]*)"', shell):
        assert "[" not in trigger, trigger


def test_the_classes_the_fragment_and_shell_emit_have_rules_in_the_stylesheet():
    css = PAGE_CSS_TEXT
    for rule in (".aq-notice {", ".aq-notice:empty {", ".aq-failed {", ".aq-reason {",
                 ".triage-dot.triage-unknown {", ".side-panel .empty-state.aq-side-failed {",
                 ".aq-notice-degraded, .aq-notice-triage, .aq-notice-module {"):
        assert rule in css, rule
