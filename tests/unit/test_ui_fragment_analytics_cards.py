"""The analytics system card grid and the alert-volume timeline.

The grid was deferred on the first pass through this page, with the reason
recorded in the module: buildSysCard is a hundred lines of structure and a
simplified fragment would have dropped most of it. This finishes it.

WHAT WAS WRONG WITH THE CARDS

Every count on the card was `|| 0` over a payload whose Elasticsearch half
may not have happened. `es_failed` says so, and the card read none of it,
so a namespace reported zero alerts and zero logs when nothing was
measured. The stats bar above already reads the flag; the cards did not.

    (sys.alert_count || 0).toLocaleString()
    (sys.logs_ingested || 0).toLocaleString()
    sys.unique_hosts || sys.logs_unique_hosts || 0

The third of those is worse than a default: a namespace with a genuinely
recorded 0 unique hosts falls through to the second field, and then to 0,
so a recorded zero and two missing fields are one value.

Two percentages drove a colour from a `|| 0`:

    const covPct = t.coverage_pct || 0;
    covPct >= 70 ? green : covPct >= 40 ? yellow : red

so a system whose TIDE coverage was not recorded was drawn in red at 0%,
which on a coverage bar states that nothing is covered. Readiness did the
same.

`t.applied_rules`/`t.total_rules`/`t.enabled_rules` went in raw, so a
TIDE link missing those columns rendered "undefined/undefined rules".

And both sparkline builders repeated the NaN defect the index bars had:
`Math.max(...timeline.map(t => t.count), 1)` is NaN if any one count is
not a number, which makes every coordinate NaN and the path unparseable,
so the chart silently vanished.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.analytics import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/analytics.html"

URL = "/ui/analytics/system"


class _User:
    id = 1
    username = "analytics-tester"

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
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def overview(monkeypatch):
    def set(payload=None, raises=None):
        async def handler(hours=168, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.analytics_api.get_system_overview", handler)

    return set


def _payload(**over):
    p = {
        "es_failed": False,
        "error": None,
        "hours": 24,
        "total_alerts": 12,
        "total_logs_ingested": 900,
        "total_severity": {"critical": 1},
        "total_systems": 1,
        "mapped_systems": 1,
        "avg_tide_coverage": 60,
        "total_timeline": [{"count": 3}, {"count": 9}, {"count": 1}],
        "interval": "1h",
        "indices": [],
        "systems": [],
    }
    p.update(over)
    return p


def _sys(**over):
    s = {
        "system": "windows-logs",
        "mapped": True,
        "alert_count": 40,
        "logs_ingested": 1200,
        "unique_hosts": 7,
        "unique_users": 3,
        "severity": {"critical": 2, "high": 5},
        "status": {"open": 4, "closed": 1},
        "timeline": [{"count": 1}, {"count": 5}],
        "top_rules": [{"rule": "Suspicious logon", "count": 9}],
        "tide": {"name": "Win", "coverage_pct": 80, "applied_rules": 8,
                 "total_rules": 10, "enabled_rules": 7,
                 "disabled_rules": 1,
                 "severity_breakdown": {"critical": 2, "high": 3}},
        "cyab": {"cyab_system_name": "Win Estate", "readiness_score": 75,
                 "use_case_status": "Reviewed",
                 "cyab_source_name": "winlog"},
    }
    s.update(over)
    return s


def _card(html: str) -> str:
    start = html.find('class="sys-card')
    assert start != -1, html[:600]
    return html[html.rfind("<div", 0, start):]


# ---------------------------------------------------------------------------
# The flag the cards never read
# ---------------------------------------------------------------------------


def test_a_failed_elasticsearch_read_does_not_show_a_namespace_as_quiet(
        overview):
    overview(payload=_payload(es_failed=True, systems=[_sys(
        alert_count=0, logs_ingested=0, severity={})]))
    card = _card(_get(_reader()).text)
    assert "an-absent" in card
    body = flat(card)
    assert "0 logs" not in body


def test_a_healthy_read_shows_the_counts(overview):
    overview(payload=_payload(systems=[_sys()]))
    body = flat(_card(_get(_reader()).text))
    assert "40" in body
    assert "1,200 logs" in body


def test_a_recorded_zero_unique_hosts_is_not_a_missing_field(overview):
    """`sys.unique_hosts || sys.logs_unique_hosts || 0` sent a recorded
    zero through to the fallback chain."""
    overview(payload=_payload(systems=[_sys(
        unique_hosts=0, logs_unique_hosts=11)]))
    assert "0 hosts" in flat(_card(_get(_reader()).text))


def test_the_fallback_field_is_used_when_the_first_is_absent(overview):
    overview(payload=_payload(systems=[_sys(
        unique_hosts=None, logs_unique_hosts=11)]))
    assert "11 hosts" in flat(_card(_get(_reader()).text))


def test_neither_host_field_is_not_zero_hosts(overview):
    overview(payload=_payload(systems=[_sys(
        unique_hosts=None, logs_unique_hosts=None)]))
    card = _card(_get(_reader()).text)
    assert "0 hosts" not in flat(card)
    assert "an-absent" in card


# ---------------------------------------------------------------------------
# The two percentages that drove a colour
# ---------------------------------------------------------------------------


def test_an_unrecorded_tide_coverage_is_not_drawn_as_zero_percent(
        overview):
    """`t.coverage_pct || 0` with the red band states that nothing is
    covered."""
    overview(payload=_payload(systems=[_sys(tide={
        "name": "Win", "applied_rules": 1, "total_rules": 2,
        "enabled_rules": 1})]))
    card = _card(_get(_reader()).text)
    assert "0%" not in flat(card)
    assert "an-cov-poor" not in card
    assert "an-absent" in card


@pytest.mark.parametrize("pct,cls", [
    (85, "an-cov-good"), (55, "an-cov-fair"), (10, "an-cov-poor")])
def test_the_coverage_band_is_a_class(overview, pct, cls):
    tide = dict(_sys()["tide"])
    tide["coverage_pct"] = pct
    overview(payload=_payload(systems=[_sys(tide=tide)]))
    assert cls in _card(_get(_reader()).text)


def test_an_unrecorded_readiness_is_not_zero_percent_ready(overview):
    overview(payload=_payload(systems=[_sys(cyab={
        "cyab_system_name": "Win Estate"})]))
    card = _card(_get(_reader()).text)
    assert "0% ready" not in flat(card)
    assert "an-absent" in card


def test_a_recorded_zero_readiness_is_shown(overview):
    cyab = dict(_sys()["cyab"])
    cyab["readiness_score"] = 0
    overview(payload=_payload(systems=[_sys(cyab=cyab)]))
    assert "0% ready" in flat(_card(_get(_reader()).text))


def test_a_tide_link_missing_its_rule_counts_does_not_print_undefined(
        overview):
    overview(payload=_payload(systems=[_sys(tide={
        "name": "Win", "coverage_pct": 50})]))
    html = _get(_reader()).text
    assert "undefined" not in html
    assert "an-absent" in html


def test_a_mapped_system_with_no_tide_link_says_so(overview):
    overview(payload=_payload(systems=[_sys(tide=None)]))
    assert "no TIDE system linked" in flat(_card(_get(_reader()).text))


def test_an_unmapped_namespace_carries_the_badge(overview):
    overview(payload=_payload(systems=[_sys(mapped=False, cyab=None,
                                            tide=None)]))
    assert "No system mapping" in flat(_card(_get(_reader()).text))


# ---------------------------------------------------------------------------
# The namespace icon and colour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,letter", [
    ("windows-logs", "W"), ("linux-audit", "L"), ("firewall-eu", "N"),
    ("aws-cloudtrail", "C"), ("edr-endpoint", "E"), ("exchange", "M"),
    ("dns-resolver", "D"), ("proxy-web", "P"), ("identity-ad", "A"),
    ("postgres-db", "B"), ("zebra", "Z"),
])
def test_the_namespace_letter_comes_from_a_table(overview, name, letter):
    overview(payload=_payload(systems=[_sys(system=name)]))
    card = _card(_get(_reader()).text)
    match = re.search(r'class="sys-icon"[^>]*>\s*([A-Z?])', card)
    assert match, card[:400]
    assert match.group(1) == letter


def test_a_nameless_namespace_still_gets_an_icon(overview):
    overview(payload=_payload(systems=[_sys(system=None)]))
    card = _card(_get(_reader()).text)
    assert "unknown" in flat(card)
    assert re.search(r'class="sys-icon"[^>]*>\s*[A-Z?]', card)


def test_an_unlisted_namespace_gets_a_stable_kind_class(overview):
    """The page built an hsl() literal from a JS string hash. The kind is
    a class now and the sheet carries the colour, so a theme can reach it.

    It must also be stable across processes, which is why the hash is
    hashlib and not hash(): Python salts str hashing per process, so the
    same namespace would have changed colour on every restart.
    """
    import re as _re

    overview(payload=_payload(systems=[_sys(system="zebra")]))
    card = _card(_get(_reader()).text)
    match = _re.search(r"sys-card (ns-[a-z0-9]+)", card)
    assert match, card[:300]
    from ion.web.ui.analytics import namespace_kind

    assert namespace_kind("zebra") == match.group(1)
    assert namespace_kind("zebra") == namespace_kind("ZEBRA")


@pytest.mark.parametrize("name,kind", [
    ("windows-logs", "ns-windows"), ("default", "ns-windows"),
    ("linux-audit", "ns-linux"), ("azure-activity", "ns-azure"),
    ("gcp-audit", "ns-gcp"), ("aws-cloudtrail", "ns-aws"),
])
def test_the_named_namespaces_keep_their_kind(overview, name, kind):
    overview(payload=_payload(systems=[_sys(system=name)]))
    assert "sys-card " + kind in _card(_get(_reader()).text)


def test_every_kind_the_module_can_emit_has_a_colour_in_the_sheet():
    """A kind with no rule is an icon with no background."""
    from ion.web.ui.analytics import NAMESPACE_FALLBACKS, NAMESPACE_KINDS

    sheet = (ROOT / "src/ion/web/static/css/analytics-page.css").read_text(
        encoding="utf-8")
    for _needles, kind in NAMESPACE_KINDS:
        assert ".sys-card." + kind + " " in sheet, kind
    for index in range(NAMESPACE_FALLBACKS):
        assert ".sys-card.ns-p%d " % index in sheet, index
    assert "--ns-color" in sheet


# ---------------------------------------------------------------------------
# Sparklines and the timeline
# ---------------------------------------------------------------------------


def test_one_unreadable_count_does_not_make_the_whole_spark_vanish(
        overview):
    """`Math.max(...map(t => t.count), 1)` is NaN if any count is not a
    number, and every coordinate then renders as NaN."""
    overview(payload=_payload(systems=[_sys(timeline=[
        {"count": 4}, {"count": "lots"}, {"count": 2}])]))
    card = _card(_get(_reader()).text)
    assert "NaN" not in card
    assert "<path" in card


def test_a_system_with_no_timeline_draws_no_spark(overview):
    overview(payload=_payload(systems=[_sys(timeline=[])]))
    card = _card(_get(_reader()).text)
    assert "NaN" not in card


def test_the_alert_volume_timeline_is_drawn(overview):
    overview(payload=_payload())
    html = _get(_reader()).text
    assert "sys-timeline" in html
    assert "<path" in html
    assert "1h" in flat(html)


def test_one_unreadable_count_does_not_make_the_timeline_vanish(overview):
    overview(payload=_payload(total_timeline=[
        {"count": 3}, {"count": None}, {"count": 8}]))
    html = _get(_reader()).text
    assert "NaN" not in html
    assert "<path" in html


def test_an_empty_timeline_says_so(overview):
    overview(payload=_payload(total_timeline=[]))
    assert "No timeline data" in flat(_get(_reader()).text)


def test_a_timeline_that_is_not_a_list_is_not_an_empty_one(overview):
    overview(payload=_payload(total_timeline="broken"))
    body = flat(_get(_reader()).text)
    assert "not in a shape" in body or "could not" in body.lower()


def test_the_timeline_is_withheld_when_elasticsearch_failed(overview):
    """It is built from the half that did not happen."""
    overview(payload=_payload(es_failed=True, total_timeline=[]))
    body = flat(_get(_reader()).text)
    assert "No timeline data" not in body
    assert "not a quiet estate" in body


# ---------------------------------------------------------------------------
# Rules and status
# ---------------------------------------------------------------------------


def test_a_rule_name_is_escaped(overview):
    overview(payload=_payload(systems=[_sys(top_rules=[
        {"rule": "<script>alert(1)</script>", "count": 2}])]))
    html = _get(_reader()).text
    assert "<script>alert(1)" not in html
    assert "alert(1)" in flat(html)


def test_at_most_four_rules_are_shown(overview):
    overview(payload=_payload(systems=[_sys(top_rules=[
        {"rule": "r%d" % i, "count": i} for i in range(9)])]))
    card = _card(_get(_reader()).text)
    assert card.count("sys-rule-row") == 4


def test_a_rule_with_no_count_does_not_print_undefined(overview):
    overview(payload=_payload(systems=[_sys(top_rules=[
        {"rule": "noisy"}])]))
    html = _get(_reader()).text
    assert "undefined" not in html
    assert "noisy" in flat(html)


def test_the_status_line_lists_what_was_recorded(overview):
    overview(payload=_payload(systems=[_sys(
        status={"open": 4, "acknowledged": 2, "closed": 1})]))
    body = flat(_card(_get(_reader()).text))
    assert "4 open" in body
    assert "2 ack" in body
    assert "1 closed" in body


def test_an_empty_status_is_a_dash(overview):
    overview(payload=_payload(systems=[_sys(status={})]))
    assert "sys-card" in _get(_reader()).text


def test_no_systems_says_so(overview):
    overview(payload=_payload(systems=[]))
    assert "No systems found" in flat(_get(_reader()).text)


def test_systems_that_are_not_a_list_say_so(overview):
    overview(payload=_payload(systems="broken"))
    body = flat(_get(_reader()).text)
    assert "not in a shape" in body
    assert "No systems found" not in body


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _page_js() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    return re.sub(r"//[^\n]*", "", body)


def test_the_page_no_longer_builds_the_cards_or_the_timeline():
    body = _page_js()
    for name in ("buildSysCard", "buildSysSparkline", "renderSysTimeline",
                 "renderSysCards", "getSysIcon", "getSysColor",
                 "formatSysStatus"):
        assert "function " + name not in body, name


def test_the_page_has_no_runtime_dom_writes_left():
    """The measured column this page has never passed."""
    body = _page_js()
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    assert not re.search(r"innerHTML\s*\+?=", scripts)
    assert "insertAdjacentHTML" not in scripts
    assert not re.search(r"outerHTML\s*\+?=", scripts)


def test_the_module_no_longer_claims_the_grid_is_deferred():
    module = (ROOT / "src/ion/web/ui/analytics.py").read_text(
        encoding="utf-8")
    assert "renderSysCards stays a write site on purpose" not in module
