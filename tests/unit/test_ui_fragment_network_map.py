"""The Network Mapper page as server-rendered fragments.

network_map.html built the four summary tiles, the source-system filter,
the asset table, its pager, the detail drawer and the subnet topology by
concatenating strings into innerHTML. Each test below names the defect that
version had, and the arrangement is one the defect would still produce: a
read that threw, a payload that is not the expected shape, a measured zero
that truthiness swallows, a total nobody returned.

Every route is driven through TestClient with the JSON endpoint's own
function stubbed, rather than rendering the template directly. A template
rendered directly passes while its module goes undriven, which is where
every first-pass mutation survivor in this project came from.

The page is not licence-gated: /network-map is not under /api/de and the
four reads behind it are plain `alert:read`, so require_de_module is the
wrong gate and these tests fail if it appears.

WHAT WAS SHOWN TO FAIL, AND WHAT IS A PIN

Run against the page as it stood, the whole file errors at collection:
ion.web.ui.network_map does not exist. Run with the module present and the
old shell restored, the five shell assertions fail there: the write count,
templates inside the script, an interpolated data-args, the four hx-get
regions and the filter names.

Ten of the behavioural assertions were then driven against the module
carrying exactly their defect, one at a time, and every one of them
failed: a bool read as a count, `|| {}` on the OS breakdown, `|| []` on
the asset list, a sort treating an unread host count as zero, a NULL
environment coerced to "unknown", a page count computed from a missing
total, a missing timestamp given an age of "0m", truthiness on a measured
zero event count, a dropped filter choice, and a 404 propagated to htmx.

Three here pass against the old page and are kept as pins rather than
offered as evidence: no duplicate template id, no template nothing clones,
and no inline style attribute. The old page had no templates at all and no
style attributes, so each was true by absence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.network_map import (
    ALERT_READ,
    PAGE_SIZE,
    _asset_row,
    _subnet,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src" / "ion" / "web" / "templates" / "network_map.html"

SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
TEMPLATE_ID = re.compile(r"<template\s+id=\"([^\"]+)\"")
#: Template ids the script names. `graphMessage` is the page's one
#: indirection over cloneTemplate, and leaving it out of this pattern made
#: the "dead markup" assertion below fail on two templates that are used.
CLONE = re.compile(r"(?:cloneTemplate|graphMessage)\(\s*'([^']+)'\s*\)")
WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


class _User:
    id = 1
    username = "alice"

    def has_permission(self, _name):
        return True


@pytest.fixture
def app():
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    # The service functions are stubbed per test, so the session is only
    # ever passed through. A real one would cost a temp database per test
    # and prove nothing extra.
    application.dependency_overrides[get_db_session] = lambda: object()
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Stubs. Each replaces exactly the function the JSON endpoint is.
# ---------------------------------------------------------------------------


def _stub(monkeypatch, name, result):
    """Replace one network_map_api function. `result` may be an exception."""
    def fake(**kwargs):
        fake.kwargs = kwargs
        if isinstance(result, BaseException):
            raise result
        return result

    fake.kwargs = {}
    monkeypatch.setattr(f"ion.web.network_map_api.{name}", fake)
    return fake


def _page() -> str:
    """The page with its comments blanked.

    A whole-file substring match is otherwise true of a comment that
    describes the thing the test thinks it is looking at, and four separate
    checks in this project have passed against their own prose.
    """
    text = PAGE.read_text(encoding="utf-8").replace("\r\n", "\n")
    text = JINJA_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return HTML_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _markup() -> str:
    return SCRIPT.sub(
        lambda m: "<script>" + "\n" * m.group(1).count("\n") + "</script>",
        _page(),
    )


def _scripts() -> str:
    return "\n".join(SCRIPT.findall(_page()))


def _route(path):
    for route in router.routes:
        if getattr(route, "path", None) == path:
            return route
    raise AssertionError(path)


def _permissions_of(route) -> set[str]:
    found: set[str] = set()
    stack = list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        fn = dep.call
        stack.extend(dep.dependencies)
        if fn is None:
            continue
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(
            fn.__code__.co_freevars,
            (c.cell_contents for c in (fn.__closure__ or ())),
        ))
        name = cells.get("permission_name")
        if isinstance(name, str):
            found.add(name)
    return found


PATHS = [
    "/network-map/stats",
    "/network-map/systems",
    "/network-map/assets",
    "/network-map/assets/{asset_id}",
    "/network-map/topology",
]


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", PATHS)
def test_every_fragment_requires_the_permission_its_endpoint_requires(path):
    """All five /api/network-map reads are alert:read. The page is weaker
    than that — /network-map takes require_page_auth and names no
    permission — so copying the page would make these fragments a softer
    way to read the host inventory than the API is."""
    assert _permissions_of(_route(path)) == {ALERT_READ}


@pytest.mark.parametrize("path", PATHS)
def test_no_fragment_uses_a_redirecting_page_dependency(path):
    """require_page_permission redirects to /login on an expired session and
    htmx would swap a password box into the middle of the asset table."""
    names = []
    stack = list(_route(path).dependant.dependencies)
    while stack:
        dep = stack.pop()
        stack.extend(dep.dependencies)
        if dep.call is not None:
            names.append(getattr(dep.call, "__qualname__", ""))
    assert names, path
    for name in names:
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name
        assert "require_de_module" not in name


# ---------------------------------------------------------------------------
# The four tiles
# ---------------------------------------------------------------------------


def test_a_failed_stats_read_says_unknown_rather_than_showing_four_dashes(
        client, monkeypatch):
    _stub(monkeypatch, "get_stats", RuntimeError("boom"))
    body = client.get("/ui/network-map/stats").text
    assert "could not be read" in body
    assert "unknown, not zero" in body
    assert "Total Assets" not in body


def test_a_measured_zero_renders_as_zero_and_not_as_a_dash(client, monkeypatch):
    """Four tiles, and an estate ION has read and found empty is a real
    reading. `?? '—'` was right here; the test pins it so a later `|| '—'`
    cannot creep back."""
    _stub(monkeypatch, "get_stats", {
        "total_assets": 0, "seen_24h": 0, "total_ips": 0, "os_breakdown": {},
    })
    data = client.get("/ui/network-map/stats",
                      headers={"accept": "application/json"}).json()
    assert data == {
        "view": "stats", "failed": False, "total": 0, "seen_24h": 0,
        "total_ips": 0, "os_families": 0,
    }
    body = client.get("/ui/network-map/stats").text
    assert "Not measured" not in body


def test_a_missing_os_breakdown_is_not_zero_os_families(client, monkeypatch):
    """`Object.keys(d.os_breakdown || {}).length` turned a breakdown that
    did not come back into a measured zero, on the one tile of the four
    whose figure was computed rather than read."""
    _stub(monkeypatch, "get_stats", {
        "total_assets": 7, "seen_24h": 2, "total_ips": 9,
    })
    data = client.get("/ui/network-map/stats",
                      headers={"accept": "application/json"}).json()
    assert data["os_families"] is None
    body = client.get("/ui/network-map/stats").text
    assert "Not measured" in body
    assert ">7<" in re.sub(r"\s+", "", body)


def test_a_boolean_count_is_not_read_as_one(client, monkeypatch):
    """bool is a subclass of int, so a check that only rejects non-numbers
    reports True as a total of 1 asset."""
    _stub(monkeypatch, "get_stats", {"total_assets": True})
    data = client.get("/ui/network-map/stats",
                      headers={"accept": "application/json"}).json()
    assert data["total"] is None


def test_a_stats_payload_that_is_not_an_object_is_a_failed_read(
        client, monkeypatch):
    _stub(monkeypatch, "get_stats", ["not", "a", "payload"])
    assert "could not be read" in client.get("/ui/network-map/stats").text


# ---------------------------------------------------------------------------
# The source-system filter
# ---------------------------------------------------------------------------


def test_an_unreadable_system_list_still_offers_all_systems(client, monkeypatch):
    """The table behind the filter is readable even when this list is not,
    so the select stays usable and says which part is missing. It must not
    read as an estate nothing reports into."""
    _stub(monkeypatch, "get_stats", RuntimeError("boom"))
    body = client.get("/ui/network-map/systems").text
    assert "All Systems" in body
    assert "Source systems unreadable" in body
    assert "No source system recorded" not in body


def test_an_empty_system_list_says_so_rather_than_nothing(client, monkeypatch):
    _stub(monkeypatch, "get_stats", {"source_systems": []})
    body = client.get("/ui/network-map/systems").text
    assert "No source system recorded" in body
    assert "Source systems unreadable" not in body


def test_a_payload_without_a_system_list_is_a_failed_read(client, monkeypatch):
    _stub(monkeypatch, "get_stats", {"source_systems": "elasticsearch"})
    assert "Source systems unreadable" in client.get("/ui/network-map/systems").text


def test_the_readers_current_choice_survives_a_refresh(client, monkeypatch):
    """This region is re-requested after a sync. The JavaScript saved
    `sysSel.value` and put it back; losing it would move the reader to All
    Systems while the table stayed filtered on their choice."""
    _stub(monkeypatch, "get_stats", {"source_systems": ["arkime", "elastic"]})
    body = client.get("/ui/network-map/systems?source_system=elastic").text
    assert '<option value="elastic" selected>elastic</option>' in body
    assert '<option value="" selected>All Systems</option>' not in body


def test_a_choice_the_read_no_longer_lists_is_kept_as_an_option(
        client, monkeypatch):
    """Dropping it would silently widen the reader's filter the next time
    the form submits, and the table would grow without them touching it."""
    _stub(monkeypatch, "get_stats", {"source_systems": ["arkime"]})
    body = client.get("/ui/network-map/systems?source_system=gone").text
    assert '<option value="gone" selected>gone</option>' in body


# ---------------------------------------------------------------------------
# The asset table
# ---------------------------------------------------------------------------


def _asset(asset_id=1, **extra):
    row = {
        "id": asset_id,
        "display_hostname": f"host{asset_id}",
        "primary_ip": "10.0.0.1",
        "os_name": "Ubuntu",
        "os_version": "22.04",
        "environment": "prod",
        "criticality": "high",
        "source_systems": ["elastic"],
        "last_seen": "2026-10-13T00:00:00+00:00",
        "event_count": 12,
    }
    row.update(extra)
    return row


def test_a_failed_asset_read_does_not_tell_the_reader_to_run_a_sync(
        client, monkeypatch):
    """Three sentences for one outcome was the page's worst habit here:
    "Error loading assets", "Failed to load" and "No assets found. Run a
    sync or adjust filters." The third one is advice about an estate, given
    when ION had not managed to read the estate."""
    _stub(monkeypatch, "list_assets", RuntimeError("boom"))
    body = client.get("/ui/network-map/assets").text
    assert "could not be read" in body
    assert "Run a sync" not in body
    assert "count unknown" in body


def test_an_empty_result_is_told_apart_from_a_failed_one(client, monkeypatch):
    _stub(monkeypatch, "list_assets", {"assets": [], "total": 0})
    body = client.get("/ui/network-map/assets").text
    assert "No assets matched" in body
    assert "could not be read" not in body
    assert "0 assets" in body


def test_a_payload_that_is_not_a_list_of_assets_is_a_failed_read(
        client, monkeypatch):
    """`d.assets || []` made this an empty estate. The payload shape is the
    one signal that an endpoint answered something other than a page of
    assets, so it cannot be collapsed into the empty case."""
    _stub(monkeypatch, "list_assets", {"assets": None, "total": 4})
    assert "could not be read" in client.get("/ui/network-map/assets").text


def test_the_count_is_unmeasured_rather_than_undefined(client, monkeypatch):
    """`d.total + ' asset'` printed "undefined assets", and the pager
    divided by it to get NaN pages which `pages <= 1` then swallowed."""
    _stub(monkeypatch, "list_assets", {"assets": [_asset()]})
    data = client.get("/ui/network-map/assets",
                      headers={"accept": "application/json"}).json()
    assert data["total"] is None
    # Not 1. A page count computed from a total nobody returned is the NaN
    # the JavaScript printed, with a confident number in its place.
    assert data["pages"] is None
    body = client.get("/ui/network-map/assets").text
    assert "count unmeasured" in body
    assert "undefined" not in body
    assert "NaN" not in body
    assert "Paging unavailable" in body


def test_a_measured_zero_event_count_is_shown_rather_than_dashed_out(
        client, monkeypatch):
    """`a.event_count?.toLocaleString() || '—'` hid the asset reporting
    nothing, which is the asset worth noticing on a page about telemetry."""
    _stub(monkeypatch, "list_assets",
          {"assets": [_asset(event_count=0)], "total": 1})
    data = client.get("/ui/network-map/assets",
                      headers={"accept": "application/json"}).json()
    assert data["rows"][0]["event_count"] == 0
    assert ">0<" in re.sub(r"\s+", "", client.get("/ui/network-map/assets").text)


def test_an_asset_with_no_timestamp_is_not_given_an_age(client, monkeypatch):
    """`relTime(null)` returned an em dash, which is honest, but
    `relTime(undefined)` on a zoneless value was wrong by the viewer's
    offset. The age is computed here, where an elapsed interval needs no
    timezone, and a missing timestamp has no age at all."""
    _stub(monkeypatch, "list_assets",
          {"assets": [_asset(last_seen=None)], "total": 1})
    data = client.get("/ui/network-map/assets",
                      headers={"accept": "application/json"}).json()
    assert data["rows"][0]["age"] is None
    assert "no timestamp" in client.get("/ui/network-map/assets").text


def test_the_pager_counts_pages_from_the_querys_own_total(client, monkeypatch):
    _stub(monkeypatch, "list_assets",
          {"assets": [_asset()], "total": PAGE_SIZE * 2 + 1})
    data = client.get("/ui/network-map/assets?page=1",
                      headers={"accept": "application/json"}).json()
    assert data["pages"] == 3
    assert data["page"] == 1
    body = client.get("/ui/network-map/assets?page=1").text
    assert "Page 2 of 3" in body
    assert "Prev" in body and "Next" in body


def test_the_page_number_reaches_the_endpoint_as_an_offset(client, monkeypatch):
    """The fragment pages by page number and the endpoint pages by offset.
    A page of 2 is an offset of 400, not of 2."""
    fake = _stub(monkeypatch, "list_assets", {"assets": [], "total": 0})
    client.get("/ui/network-map/assets?page=2")
    assert fake.kwargs["offset"] == PAGE_SIZE * 2
    assert fake.kwargs["limit"] == PAGE_SIZE


def test_the_filters_reach_the_endpoint_under_its_own_parameter_names(
        client, monkeypatch):
    fake = _stub(monkeypatch, "list_assets", {"assets": [], "total": 0})
    client.get("/ui/network-map/assets?search=web&environment=prod"
               "&criticality=high&source_system=elastic&last_seen_within=24h")
    assert fake.kwargs["search"] == "web"
    assert fake.kwargs["environment"] == "prod"
    assert fake.kwargs["criticality"] == "high"
    assert fake.kwargs["source_system"] == "elastic"
    assert fake.kwargs["last_seen_within"] == "24h"
    assert fake.kwargs["archived"] is False


def test_a_negative_page_is_clamped_rather_than_sent_as_a_negative_offset(
        client, monkeypatch):
    fake = _stub(monkeypatch, "list_assets", {"assets": [], "total": 0})
    client.get("/ui/network-map/assets?page=-3")
    assert fake.kwargs["offset"] == 0


def test_an_entry_that_is_not_an_asset_is_dropped_rather_than_rendered():
    """A row with no usable id cannot carry a drawer link, and
    `data-args='[undefined]'` is invalid JSON that event-delegation.js logs
    and returns from, leaving a row that looks clickable and is not."""
    assert _asset_row({"display_hostname": "x"}) is None
    assert _asset_row(_asset(asset_id=True)) is None
    assert _asset_row("not a dict") is None


def test_a_criticality_the_sheet_does_not_know_falls_back_to_unknown():
    """The model returns the word and the stylesheet paints it. A value
    nobody has a rule for must not reach the class attribute, because
    `CRIT_CLS[a.criticality]` resolved to undefined and rendered the word
    "undefined" as a class name."""
    row = _asset_row(_asset(criticality="catastrophic", environment="qa"))
    assert row["criticality"] == "unknown"
    assert row["environment"] == "unknown"


# ---------------------------------------------------------------------------
# The detail drawer
# ---------------------------------------------------------------------------


def _full_asset(**extra):
    row = _asset()
    row.update({
        "architecture": "x86_64",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_index": "winlogbeat-2026.10.13",
        "owner": "platform",
        "notes": "patched",
        "ips": [{"ip": "10.0.0.1", "last_seen": "2026-10-13T00:00:00+00:00",
                 "event_count": 12}],
        "macs": [{"mac": "aa:bb:cc:dd:ee:ff"}],
    })
    row.update(extra)
    return row


def test_an_asset_that_is_gone_answers_markup_rather_than_a_404(
        client, monkeypatch):
    """htmx does not swap a non-2xx response, so a 404 would leave the
    previous asset's detail in the drawer under the new hostname."""
    _stub(monkeypatch, "get_asset", HTTPException(404, "Asset not found"))
    response = client.get("/ui/network-map/assets/9")
    assert response.status_code == 200
    assert "could not be read" in response.text
    assert "Asset unavailable" in response.text


def test_the_hostname_is_swapped_out_of_band_because_it_sits_outside(
        client, monkeypatch):
    _stub(monkeypatch, "get_asset", _full_asset())
    body = client.get("/ui/network-map/assets/1").text
    assert 'id="drawer-hostname"' in body
    assert 'hx-swap-oob="true"' in body
    assert "host1" in body


def test_an_unset_environment_selects_not_set_rather_than_unknown(
        client, monkeypatch):
    """`${a.environment==='unknown'?'selected':''}` left nothing selected
    for a NULL column, so the browser showed the first option, "Unknown",
    and Save wrote the string "unknown" over a value nobody had set."""
    _stub(monkeypatch, "get_asset",
          _full_asset(environment=None, criticality=None))
    data = client.get("/ui/network-map/assets/1",
                      headers={"accept": "application/json"}).json()
    assert data["environment"] == ""
    assert data["criticality"] == ""
    body = client.get("/ui/network-map/assets/1").text
    assert '<option value="" selected>Not set</option>' in body
    assert '<option value="unknown" selected>' not in body


def test_a_null_last_index_does_not_become_the_word_null_in_a_tooltip(
        client, monkeypatch):
    """`title="${esc(a.last_index)}"` stringified null, so the tooltip of a
    cell showing a dash said "null"."""
    _stub(monkeypatch, "get_asset", _full_asset(last_index=None))
    body = client.get("/ui/network-map/assets/1").text
    assert "null" not in body
    assert 'title=' not in body.split('Last Index')[1].split('</div>')[0]


def test_the_save_button_carries_its_id_as_json(client, monkeypatch):
    """event-delegation.js parses data-args with JSON.parse and on a throw
    it logs and returns, so an interpolated id makes Save a dead control."""
    _stub(monkeypatch, "get_asset", _full_asset())
    body = client.get("/ui/network-map/assets/1").text
    match = re.search(r"data-click-action=\"saveEnrichment\"\s+data-args='([^']*)'",
                      body)
    assert match, body
    assert json.loads(match.group(1)) == [1]


def test_an_ip_history_row_with_no_count_says_so_rather_than_showing_zero(
        client, monkeypatch):
    _stub(monkeypatch, "get_asset", _full_asset(
        ips=[{"ip": "10.0.0.2", "last_seen": None, "event_count": None}]))
    body = client.get("/ui/network-map/assets/1").text
    assert "events not read" in body
    assert "no timestamp" in body


# ---------------------------------------------------------------------------
# The subnet topology
# ---------------------------------------------------------------------------


def _subnet_payload(**extra):
    row = {
        "subnet": "10.0.0.0/24",
        "host_count": 2,
        "worst_criticality": "critical",
        "environments": ["prod"],
        "total_events": 40,
        "hosts": [
            {"id": 1, "hostname": "host1", "ip": "10.0.0.1", "os": "Ubuntu",
             "criticality": "critical",
             "last_seen": "2026-10-13T00:00:00+00:00"},
        ],
    }
    row.update(extra)
    return row


def test_a_failed_subnet_read_is_not_an_estate_with_no_subnets(
        client, monkeypatch):
    """The JavaScript fell back to fetching /assets and grouping in the
    browser on any non-ok response, so a 403 rendered a topology built from
    a different query with its own idea of the worst criticality, and
    nothing said which one the reader was looking at. There is one read
    now."""
    _stub(monkeypatch, "list_subnets", RuntimeError("boom"))
    body = client.get("/ui/network-map/topology").text
    assert "could not be read" in body
    assert "No subnets to display" not in body


def test_an_empty_topology_says_it_is_empty(client, monkeypatch):
    _stub(monkeypatch, "list_subnets", {"subnets": []})
    body = client.get("/ui/network-map/topology").text
    assert "No subnets to display" in body
    assert "could not be read" not in body


def test_a_payload_without_a_subnet_list_is_a_failed_read(client, monkeypatch):
    """`subnets = d.subnets || d` handed the whole payload object to
    `subnets.sort`, which throws, leaving the loading placeholder on screen
    for ever."""
    _stub(monkeypatch, "list_subnets", {"total_subnets": 3})
    assert "could not be read" in client.get("/ui/network-map/topology").text


def test_subnets_are_ordered_by_host_count_largest_first(client, monkeypatch):
    _stub(monkeypatch, "list_subnets", {"subnets": [
        _subnet_payload(subnet="10.0.1.0/24", host_count=1, hosts=[]),
        _subnet_payload(subnet="10.0.2.0/24", host_count=9, hosts=[]),
    ]})
    data = client.get("/ui/network-map/topology",
                      headers={"accept": "application/json"}).json()
    assert [s["subnet"] for s in data["subnets"]] == [
        "10.0.2.0/24", "10.0.1.0/24"]
    assert [s["index"] for s in data["subnets"]] == [0, 1]


def test_a_subnet_whose_host_count_did_not_read_sorts_last_not_as_zero(
        client, monkeypatch):
    """Sorting by `(b.host_count || 0) - (a.host_count || 0)` put an
    unmeasured subnet among the empty ones, where it reads as a subnet with
    no hosts in it."""
    _stub(monkeypatch, "list_subnets", {"subnets": [
        _subnet_payload(subnet="a/24", host_count=None, hosts=[]),
        _subnet_payload(subnet="b/24", host_count=0, hosts=[]),
    ]})
    data = client.get("/ui/network-map/topology",
                      headers={"accept": "application/json"}).json()
    assert [s["subnet"] for s in data["subnets"]] == ["b/24", "a/24"]
    assert "host count unread" in client.get("/ui/network-map/topology").text


def test_a_topology_host_reads_the_subnet_endpoints_own_column_names():
    """/subnets names its columns `hostname`, `ip` and a pre-joined `os`;
    /assets names them `display_hostname`, `primary_ip`, `os_name` and
    `os_version`. One renderer read both spellings off one object because
    it could not tell which endpoint had answered."""
    row = _subnet(_subnet_payload(), 0)
    assert row["hosts"][0]["hostname"] == "host1"
    assert row["hosts"][0]["ip"] == "10.0.0.1"
    assert row["hosts"][0]["os"] == "Ubuntu"
    assert row["hosts"][0]["age"] is not None


def test_a_subnet_with_no_host_rows_is_not_the_same_as_a_count_of_zero(
        client, monkeypatch):
    _stub(monkeypatch, "list_subnets",
          {"subnets": [_subnet_payload(host_count=4, hosts=[])]})
    body = client.get("/ui/network-map/topology").text
    assert "4 hosts" in body
    assert "host list came back empty" in body


def test_a_toggle_carries_its_index_as_json(client, monkeypatch):
    _stub(monkeypatch, "list_subnets", {"subnets": [_subnet_payload()]})
    body = client.get("/ui/network-map/topology").text
    match = re.search(r"data-click-action=\"toggleSubnet\"\s+data-args='([^']*)'",
                      body)
    assert match, body
    assert json.loads(match.group(1)) == [0]


# ---------------------------------------------------------------------------
# The shell
# ---------------------------------------------------------------------------


def test_the_page_makes_no_runtime_dom_write_anywhere():
    """The point of the conversion, counted over the whole file so a new
    writer anywhere trips it. tools/ui_redesign_status.py measures the same
    thing and is the only thing that decides whether the page is done."""
    assert WRITES.findall(_page()) == []


def test_every_template_lives_outside_the_script_block():
    """A <template> inside a <script> is text, not an element.
    document.getElementById finds nothing, cloneTemplate returns null, and
    every control built from it quietly does not appear."""
    for body in SCRIPT.findall(_page()):
        assert TEMPLATE_ID.findall(body) == []
    assert len(TEMPLATE_ID.findall(_markup())) == 3


def test_every_cloned_id_is_a_template_the_page_defines():
    defined = set(TEMPLATE_ID.findall(_markup()))
    used = set(CLONE.findall(_scripts()))
    assert used - defined == set()
    assert defined - used == set(), "a template nothing clones is dead markup"


def test_no_template_id_is_defined_twice():
    ids = TEMPLATE_ID.findall(_markup())
    assert {i for i in ids if ids.count(i) > 1} == set()


def test_every_literal_data_args_in_the_shell_is_valid_json():
    found = re.findall(r"data-args='([^']*)'", _markup())
    assert found, "no literal data-args found; the anchor has moved"
    for raw in found:
        assert isinstance(json.loads(raw), list), raw


def test_no_data_args_is_built_by_string_interpolation():
    for body in SCRIPT.findall(_page()):
        assert not re.search(r"data-args=[\"'][^\"']*\$\{", body)


def test_the_four_regions_pull_their_own_markup_from_the_ui_routes():
    shell = _markup()
    for path in ("/ui/network-map/stats", "/ui/network-map/systems",
                 "/ui/network-map/assets", "/ui/network-map/topology"):
        assert f'hx-get="{path}"' in shell, path
    assert "/ui/network-map/assets/" in _scripts()


def test_the_filter_names_are_the_parameter_names_the_route_takes():
    """The form serialises itself, so a renamed field silently drops a
    filter: the request still succeeds and returns a wider table."""
    shell = _markup()
    for name in ("search", "environment", "criticality", "source_system",
                 "last_seen_within"):
        assert f'name="{name}"' in shell, name


def test_the_shell_carries_no_inline_style_attribute():
    """style-src-attr is 'none', so an inline style= paints nothing at all
    and the element silently keeps the stylesheet's value."""
    assert not re.search(r"<[^>]*\sstyle=", _markup())
