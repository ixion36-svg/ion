"""The alerts page's Systems filter, from the option to the Elasticsearch
query and back through Clear and the saved views.

A CyAB system is a set of data sources and each names its own
data_stream.namespace, so "one system" is a set of namespaces. The filter
used to be one namespace wide at every step.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ion.services.elasticsearch_service import ElasticsearchService
from ion.web.ui.alerts import QUEUE_FRAGMENT, system_options
from ion.web.templating import make_templates

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"

CORP = [
    {"namespace": "corp-win", "display_name": "Corp Servers", "cyab_system_id": 2},
    {"namespace": "corp-linux", "display_name": "Corp Servers", "cyab_system_id": 2},
    {"namespace": "default", "display_name": "FUBS Workstations", "cyab_system_id": 1},
]


# ---------------------------------------------------------------------------
# The options
# ---------------------------------------------------------------------------


def test_a_system_with_two_namespaces_is_one_option_covering_both():
    out = system_options([], CORP, "")
    assert [(o["value"], o["label"]) for o in out] == [
        ("corp-linux,corp-win", "Corp Servers"), ("default", "FUBS Workstations")]


def test_the_option_stays_selected_whatever_order_the_request_names_its_namespaces():
    out = system_options([], CORP, "corp-win,corp-linux")
    assert [(o["label"], o["selected"]) for o in out] == [
        ("Corp Servers", True), ("FUBS Workstations", False)]


def test_an_alert_in_a_registered_namespace_adds_no_second_option():
    alert = {"source_system": "corp-win", "cyab_system_name": "Corp Servers"}
    out = system_options([alert], CORP, "")
    assert [o["label"] for o in out] == ["Corp Servers", "FUBS Workstations"]


def test_two_systems_sharing_a_name_stay_two_options():
    known = [{"namespace": "a", "display_name": "Lab", "cyab_system_id": 1},
             {"namespace": "b", "display_name": "Lab", "cyab_system_id": 2}]
    assert [o["value"] for o in system_options([], known, "")] == ["a", "b"]


# ---------------------------------------------------------------------------
# The Elasticsearch query
# ---------------------------------------------------------------------------


def _namespace_clauses(system: str) -> list:
    svc = ElasticsearchService(url="http://es.invalid:9200")
    sent: dict[str, Any] = {}

    async def fake(method, path, json=None, **_):
        sent["query"] = json
        return {"hits": {"hits": []}}

    svc._request = fake  # type: ignore[method-assign]
    asyncio.run(svc.get_alerts(hours=24, system=system))
    return [c for c in sent["query"]["query"]["bool"]["must"]
            if "data_stream.namespace" in json.dumps(c)]


def test_the_query_matches_every_namespace_the_option_names():
    assert _namespace_clauses("corp-win, Corp-Linux") == [
        {"terms": {"data_stream.namespace": ["corp-linux", "corp-win"]}}]


def test_one_namespace_is_still_one_namespace():
    assert _namespace_clauses("default") == [
        {"terms": {"data_stream.namespace": ["default"]}}]


# ---------------------------------------------------------------------------
# The fragment
# ---------------------------------------------------------------------------


def _render(**over: Any) -> str:
    ctx = {
        "failed": False, "degraded": False, "reason": None, "connection_error": False,
        "alerts": [], "arkime_enabled": False, "rows": [], "triage_failed": False,
        "total": 0, "limit": 500, "truncated": False,
        "window": {"hours": 24, "time_from": None, "time_to": None, "defaulted": False},
        "include_closed": False, "systems": [], "system": "", "system_label": "",
        "systems_unread": False, "colspan": 12, "can_triage": True,
        "can_create_case": True, "data": {"alerts": [], "arkime_enabled": False},
    }
    ctx.update(over)
    return " ".join(make_templates().env.get_template(QUEUE_FRAGMENT).render(**ctx).split())


def _select(body: str) -> str:
    start = body.index('<select id="alert-system-filter"')
    return body[start:body.index("</select>", start)]


def test_a_select_with_no_system_to_offer_says_why():
    body = _select(_render())
    assert "<option disabled>No system is registered or seen in this window</option>" in body
    assert "could not be read" not in body


def test_an_unread_registry_is_not_reported_as_no_systems():
    body = _select(_render(systems_unread=True))
    assert "<option disabled>The system registry could not be read</option>" in body
    assert "No system is registered" not in body


def test_a_select_with_systems_carries_no_notice():
    body = _select(_render(systems=system_options([], CORP, "")))
    assert "<option disabled>" not in body
    assert '<option value="corp-linux,corp-win">Corp Servers</option>' in body


def test_the_empty_row_names_the_system_by_its_label():
    body = _render(systems=system_options([], CORP, "corp-linux,corp-win"),
                   system="corp-linux,corp-win", system_label="Corp Servers")
    assert "No alerts in this window for system Corp Servers" in body


# ---------------------------------------------------------------------------
# The page's own handling of the control, run in Node
# ---------------------------------------------------------------------------

DOM = """
class Select {
    constructor(values) { this.options = values.map(v => ({value: v, textContent: v || 'All Systems'})); this._v = values[0]; }
    // A browser select ignores a value no option carries and falls back.
    set value(v) { this._v = this.options.some(o => o.value === v) ? v : ''; }
    get value() { return this._v; }
    add(o) { this.options.push(o); }
    get selectedOptions() { return this.options.filter(o => o.value === this._v); }
}
function Option(text, value) { return {textContent: text, value}; }
const plain = (v) => ({value: v, style: {}});
const els = {
    'alert-system-filter': new Select(['']),
    'alert-severity-filter': plain(''), 'alert-status-filter': plain('open'),
    'alert-search': plain(''), 'alert-time-range': plain('24'),
    'custom-time-range': plain(''), 'custom-time-from': plain(''), 'custom-time-to': plain(''),
    'active-filter-banner': plain(''), 'active-filter-text': plain(''),
};
const document = {getElementById: (id) => els[id] || null};
const calls = {loadAlerts: 0, applyFilters: 0};
function loadAlerts() { calls.loadAlerts++; }
function applyFilters() { calls.applyFilters++; }
function applySorting() {} function renderAlerts() {} function renderSidePanels() {}
function updateStatsBar() {}
let entityFilter = null, allAlerts = [], filteredAlerts = [], triageCache = {};
const pick = (...values) => { els['alert-system-filter'] = new Select(['', ...values]); return els['alert-system-filter']; };
"""


def _function(name: str) -> str:
    text = PAGE.read_text(encoding="utf-8")
    found = re.search(r"\nfunction " + name + r"\([^)]*\) \{.*?\n\}\n", text, re.S)
    assert found, f"{name} is not in the page"
    return found.group(0)


def _run(functions: list[str], body: str) -> Any:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to run the page's filter handlers")
    script = DOM + "".join(_function(f) for f in functions) + body
    out = subprocess.run([node, "-e", script], capture_output=True, text=True,
                         check=True, encoding="utf-8")
    return json.loads(out.stdout)


def test_a_saved_view_keeps_its_system_and_reads_the_queue_again():
    got = _run(["setSystemFilter", "clearEntityFilter", "getCurrentFilterState", "applyFilterState"], """
        pick('corp-linux,corp-win').value = 'corp-linux,corp-win';
        const saved = getCurrentFilterState();
        // A fresh page: the select has not been handed that system yet.
        const fresh = pick();
        applyFilterState(JSON.parse(JSON.stringify(saved)));
        console.log(JSON.stringify({saved: saved.system, restored: fresh.value, reads: calls.loadAlerts}));
    """)
    assert got == {"saved": "corp-linux,corp-win", "restored": "corp-linux,corp-win", "reads": 1}


def test_a_view_saved_before_systems_were_kept_restores_all_systems():
    got = _run(["setSystemFilter", "clearEntityFilter", "getCurrentFilterState", "applyFilterState"], """
        const sel = pick('default'); sel.value = 'default';
        applyFilterState({timeRange: '24', status: 'open'});
        console.log(JSON.stringify(sel.value));
    """)
    assert got == ""


@pytest.mark.parametrize("system,time_range,reads", [
    ("default", "24", 1),   # the rows on the page are that system's only
    ("", "168", 1),         # and a wider window's rows are not the default window's
    ("", "24", 0),          # nothing the server applied has changed
])
def test_clear_reads_the_queue_again_when_the_server_applied_a_filter(system, time_range, reads):
    got = _run(["clearEntityFilter", "clearAllFilters"], f"""
        const sel = pick('default'); sel.value = {json.dumps(system)};
        els['alert-time-range'].value = {json.dumps(time_range)};
        clearAllFilters();
        console.log(JSON.stringify({{system: sel.value, reads: calls.loadAlerts}}));
    """)
    assert got == {"system": "", "reads": reads}


@pytest.mark.parametrize("handler,call", [
    ("filterToAttention", "filterToAttention('critical', 4)"),
    ("filterToAttentionUnassigned", "filterToAttentionUnassigned()"),
])
def test_an_attention_chip_leaves_the_system_the_rows_were_read_for(handler, call):
    # The chip's count is over the loaded rows, which are one system's. A
    # select reset to All Systems above those rows would be saying otherwise.
    got = _run([handler], f"""
        const sel = pick('default'); sel.value = 'default';
        {call};
        console.log(JSON.stringify(sel.value));
    """)
    assert got == "default"
