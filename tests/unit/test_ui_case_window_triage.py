"""Triage and closure in the case window's Triage layout.

The analyst marks the selected alert, or the ticked alerts, true positive,
benign or false positive, and reaches what stops closure and the close
dialog without switching to Read. Pinned here:

  * the verdict vocabulary is the alert window's (closure types sent to
    POST /elasticsearch/alerts/{id}/close), named by case closure reason;
  * a verdict is read back from the case note that endpoint writes, so it
    survives a reload, and an alert with one no longer blocks closure;
  * the fragment carries the controls, and only for a reader allowed to
    use them;
  * the logic case-window.js runs after a write, run for real under node:
    the request it sends, the recount, the suggested reason and the key
    guard.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from html import unescape
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ion.web.ui._cases_window import (
    VERDICTS,
    alert_verdicts,
    blockers,
    untriaged,
    untriaged_title,
)
from ion.web.ui.cases import PERMISSION
from tests.unit.test_ui_cases_panel import (  # noqa: F401  (case is a fixture)
    URL,
    _alert,
    _app,
    _case,
    _get,
    _User,
    case,
    flat,
)

ROOT = Path(__file__).resolve().parents[2]
CASE_WINDOW = ROOT / "src/ion/web/static/js/case-window.js"


def _closed_as(alert_id, closure_type, when="2026-11-01T10:00:00"):
    """The note close_alert writes, as tests/test_alert_close_keeps_case_open.py pins it."""
    label = closure_type.replace("_", " ").title()
    return {"id": alert_id + when, "user": "analyst", "created_at": when,
            "content": "**Alert closed as %s**\nAlert: `%s`\nReason: N/A" % (label, alert_id)}


def _triager(*more):
    return _User(PERMISSION, "alert:read", "alert:triage", *more)


# ---------------------------------------------------------------------------
# The vocabulary and the read-back
# ---------------------------------------------------------------------------

def test_the_three_verdicts_are_the_alert_windows_closure_types():
    assert [(v["reason"], v["closure_type"], v["key"]) for v in VERDICTS] == [
        ("true_positive", "escalated", "t"),
        ("benign_true_positive", "benign", "b"),
        ("false_positive", "false_positive", "f"),
    ]


def test_a_verdict_is_read_back_from_the_close_note_latest_first():
    notes = [
        _closed_as("a1", "benign", "2026-11-01T10:00:00"),
        _closed_as("a1", "false_positive", "2026-11-01T11:00:00"),
        _closed_as("a2", "escalated"),
        {"content": "**Alert closed as Something Else**\nAlert: `a3`"},
        {"content": "a note that mentions **Alert closed as Benign** later"},
        "not a mapping",
    ]
    assert alert_verdicts(notes) == {"a1": "false_positive", "a2": "true_positive"}
    assert alert_verdicts(None) is None


def test_an_alert_with_a_verdict_does_not_block_closure():
    alerts = [{"es_alert_id": "a1", "status": "acknowledged"},
              {"es_alert_id": "a2", "status": "open"},
              {"es_alert_id": "a3", "status": "closed"}]
    verdicts = {"a1": "true_positive"}
    assert untriaged(alerts, verdicts) == ["a2"]
    titles = [b["title"] for b in blockers(alerts, 3, None, None, verdicts)]
    assert titles == ["1 linked alert not triaged"]
    assert blockers(alerts, 3, None, None, {"a1": "true_positive", "a2": "benign_true_positive"}) == []
    assert untriaged("unreadable", {}) is None


# ---------------------------------------------------------------------------
# The fragment
# ---------------------------------------------------------------------------

def test_rows_and_exhibits_carry_the_verdict_and_bobs(case):
    case(payload=_case(assigned_to_id=3, alerts=[_alert(es_alert_id="a1", status="acknowledged"),
                               _alert(es_alert_id="a2")],
                       notes=[_closed_as("a1", "escalated")]),
         extras={"investigations": {"a2": {"status": "completed", "verdict": "false_positive",
                                           "confidence_int": 60, "summary_text": "s",
                                           "recommended_actions_json": None}},
                 "triage": {}, "enrichments": {}})
    html = _get(_triager()).text
    row = re.search(r'<tr[^>]*data-alert-id="a1"[^>]*>', html).group(0)
    assert 'data-verdict="true_positive"' in row and 'data-bob-verdict=""' in row
    row2 = re.search(r'<tr[^>]*data-alert-id="a2"[^>]*>', html).group(0)
    assert 'data-verdict=""' in row2 and 'data-bob-verdict="false_positive"' in row2
    assert re.search(r'<article class="cwin-ex" data-ex="a1"[^>]*data-verdict="true_positive"', html)
    chips = re.findall(r'<span class="cwin-verdict[^"]*" data-cwin-verdict="a1"[^>]*>([^<]*)</span>', html)
    assert chips == ["True positive", "True positive"]  # the row and the exhibit
    body = flat(html)
    assert "1 block closure" in body and "1 linked alert not triaged" in body  # a2: open, no verdict


def test_the_verdict_table_rides_on_the_window_for_the_script(case):
    case(payload=_case())
    html = _get(_triager()).text
    carried = re.search(r'data-verdicts="([^"]*)"', html).group(1)
    assert json.loads(unescape(carried)) == list(VERDICTS)


def test_the_triage_controls_need_the_triage_permission(case):
    case(payload=_case())
    reader = _get(_User(PERMISSION, "alert:read")).text
    for action in ("cwTriage", "cwBulkTriage", "cwTriageThem"):
        assert 'data-click-action="%s"' % action not in reader
    assert "Marking alerts needs the alert:triage permission." in flat(reader)

    html = _get(_triager()).text
    detail = re.findall(r'data-click-action="cwTriage" data-args=\'([^\']*)\'', html)
    assert [json.loads(a) for a in detail] == [["true_positive"], ["benign_true_positive"], ["false_positive"]]
    bulk = re.findall(r'data-click-action="cwBulkTriage" data-args=\'([^\']*)\'>([^<]*)<', html)
    assert [(json.loads(a), label) for a, label in bulk] == [
        (["true_positive"], "Mark true positive"),
        (["benign_true_positive"], "Mark benign"),
        (["false_positive"], "Mark false positive")]
    assert 'data-click-action="cwTriageThem"' in html


def test_assign_to_me_is_offered_with_the_case_update_permission(case):
    case(payload=_case(assigned_to_id=None))
    assert 'data-click-action="cwAssignMe"' not in _get(_triager()).text
    html = _get(_triager("case:update")).text
    assert re.search(r'data-click-action="cwAssignMe"\s+data-args=\'\[7, 1\]\'', html)


def test_the_alerts_blocker_is_there_to_recount_even_when_none_block(case):
    case(payload=_case(assigned_to_id=3, alerts=[_alert(es_alert_id="a1")],
                       notes=[_closed_as("a1", "benign")]))
    html = _get(_triager()).text
    hidden = re.findall(r'<li class="cwin-bl cwin-bl-alerts" data-cwin-bl="alerts" hidden>', html)
    assert len(hidden) == 2  # the popover's and Read section 3's
    assert "Nothing blocks closure" in flat(html)


def test_the_close_dialog_extra_is_informational(case):
    case(payload=_case())
    html = _get(_triager()).text
    extra = re.search(r"<template data-cwin-close-extra>(.*?)</template>", html, re.S).group(1)
    assert "You can close anyway." in flat(extra)
    assert "<button" not in extra and "disabled" not in extra


# ---------------------------------------------------------------------------
# case-window.js, under node
# ---------------------------------------------------------------------------

def _logic(expression: str):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH")
    program = (
        "global.window = {}; global.document = { addEventListener: function () {} };"
        f"require({json.dumps(str(CASE_WINDOW))});"
        "const L = window.ionCaseWindow.logic;"
        f"const V = {json.dumps(list(VERDICTS))};"
        f"process.stdout.write(JSON.stringify({expression}));"
    )
    result = subprocess.run([node, "-e", program], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_one_alert_is_marked_through_the_alert_close_leaving_the_case_open():
    req = _logic("L.closeRequest('a/1 b', V[0])")
    assert req == {"url": "/api/elasticsearch/alerts/a%2F1%20b/close", "method": "POST",
                   "body": {"closure_type": "escalated", "notes": None, "close_case": False}}


def test_ticked_alerts_are_one_request_each_with_the_same_verdict():
    reqs = _logic("L.bulkRequests(['a1', 'a2', 'a3'], V[2])")
    assert [r["url"] for r in reqs] == ["/api/elasticsearch/alerts/%s/close" % a for a in ("a1", "a2", "a3")]
    assert {json.dumps(r["body"], sort_keys=True) for r in reqs} == {
        json.dumps({"closure_type": "false_positive", "notes": None, "close_case": False}, sort_keys=True)}


def test_the_blockers_recount_after_a_triage_result():
    alerts = [{"id": "a1", "status": "open", "verdict": "", "bob": ""},
              {"id": "a2", "status": "open", "verdict": "", "bob": ""},
              {"id": "a3", "status": "closed", "verdict": "", "bob": ""}]
    # The owner is missing too, so one blocker does not depend on the alerts.
    before = _logic(f"L.derive({json.dumps(alerts)}, 1, V)")
    assert (before["untriaged"], before["blockers"], before["pill"], before["notClosed"]) == (
        2, 2, "2 block closure", 2)
    # a1 marked true positive: the server answers acknowledged.
    alerts[0].update(status="acknowledged", verdict="true_positive")
    mid = _logic(f"L.derive({json.dumps(alerts)}, 1, V)")
    assert (mid["untriaged"], mid["untriagedTitle"], mid["blockers"], mid["notClosed"]) == (
        1, "1 linked alert not triaged", 2, 2)
    assert mid["byStatus"] == {"open": 1, "acknowledged": 1, "closed": 1}
    alerts[1].update(status="closed", verdict="benign_true_positive")
    after = _logic(f"L.derive({json.dumps(alerts)}, 1, V)")
    assert (after["untriaged"], after["blockers"], after["pill"], after["notClosed"]) == (
        0, 1, "1 block closure", 1)
    assert _logic(f"L.derive({json.dumps(alerts)}, 0, V).pill") == "Nothing blocks closure"


def test_the_script_and_the_server_agree_on_what_is_untriaged():
    rows = [("a1", "open", ""), ("a2", "acknowledged", ""), ("a3", "acknowledged", "true_positive"),
            ("a4", "closed", ""), ("a5", "open", "false_positive")]
    model = [{"id": i, "status": s, "verdict": v, "bob": ""} for i, s, v in rows]
    server = untriaged([{"es_alert_id": i, "status": s} for i, s, _ in rows],
                       {i: v for i, _, v in rows if v})
    assert _logic(f"L.untriaged({json.dumps(model)})") == server == ["a1", "a2"]
    for n in (1, 2):
        assert _logic(f"L.untriagedTitle({n})") == untriaged_title(n)


def _alerts(*pairs):
    return json.dumps([{"id": "a%d" % i, "status": "open", "verdict": v, "bob": b}
                       for i, (v, b) in enumerate(pairs)])


def test_the_suggested_reason_is_the_most_common_verdict():
    got = _logic("L.suggest(%s, V)" % _alerts(("false_positive", ""), ("false_positive", ""),
                                             ("true_positive", "true_positive"), ("", "true_positive")))
    assert got == {"reason": "false_positive", "label": "False positive", "count": 2, "of": 4,
                   "source": "analyst"}


def test_the_analysts_verdicts_outrank_bobs_and_bob_fills_in_when_there_are_none():
    mine = _logic("L.suggest(%s, V)" % _alerts(("benign_true_positive", ""), ("", "true_positive"),
                                              ("", "true_positive")))
    assert (mine["reason"], mine["source"]) == ("benign_true_positive", "analyst")
    bobs = _logic("L.suggest(%s, V)" % _alerts(("", "true_positive"), ("", ""), ("", "false_positive"),
                                              ("", "true_positive")))
    assert (bobs["reason"], bobs["count"], bobs["source"]) == ("true_positive", 2, "bob")


def test_a_tie_goes_to_the_earlier_verdict_and_nothing_suggests_nothing():
    tie = _logic("L.suggest(%s, V).reason" % _alerts(("false_positive", ""), ("true_positive", "")))
    assert tie == "true_positive"
    assert _logic("L.suggest(%s, V)" % _alerts(("", ""), ("", ""))) is None


@pytest.mark.parametrize("ctx, expected", [
    ({"key": "t"}, "triage:true_positive"),
    ({"key": "b"}, "triage:benign_true_positive"),
    ({"key": "f"}, "triage:false_positive"),
    ({"key": "j"}, "next"),
    ({"key": "x"}, "tick"),
    ({"key": "t", "dialog": True}, None),
    ({"key": "j", "dialog": True}, None),
    ({"key": "Escape", "dialog": True}, None),
    ({"key": "f", "popover": True}, None),
    ({"key": "Escape", "popover": True}, "popover"),
    ({"key": "t", "asking": True}, None),
    ({"key": "Escape", "asking": True}, "escape"),
    ({"key": "b", "typing": True}, None),
    ({"key": "t", "mod": True}, None),
    ({"key": "t", "canTriage": False}, None),
    ({"key": "t", "focus": None}, None),
    ({"key": "q"}, None),
])
def test_the_key_guard(ctx, expected):
    full = {"mod": False, "typing": False, "dialog": False, "popover": False, "asking": False,
            "focus": "a1", "canTriage": True}
    full.update(ctx)
    assert _logic("L.keyAction(Object.assign(%s, {verdicts: V}))" % json.dumps(full)) == expected
