"""The analytics drawer's systems tab as a fragment.

Measured on the page before this stage:

  * loadAdSystems fetched with
    `Authorization: Bearer ${localStorage.getItem('token')}`. Nothing in
    this codebase ever calls localStorage.setItem('token', ...), and that
    line was its only reader, so the header was always the literal string
    "Bearer null". It worked because get_session_token tries the
    ion_session cookie before the header; with the precedence the other way
    the tab would have answered 401 for every user since it was written.
  * `data.total_alerts || 0` and its three siblings turned a figure the
    payload did not carry into a measured zero, in cards the size of a
    headline.
  * `t.coverage_pct || 0` did the same to TIDE coverage and then banded the
    result red, so a system nobody had measured was painted as an urgent
    gap.
  * `data.systems || []` rendered "No systems found. Connect Elasticsearch
    to see system data.", so a refusal advised the reader to go and
    configure something.
  * The sparkline drew only when `tl.length > 1`, and `Math.max(1, ...)`
    drew an all-zero timeline as a flat line along the bottom.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ion.web.analytics_api as analytics_api
from ion.web.ui.alerts import (
    SYS_SPARK_H,
    TIDE_FAIR,
    TIDE_GOOD,
    router,
    sys_card,
    sys_overview,
    sys_spark,
    tide_band,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"
FRAGMENTS = ROOT / "src/ion/web/templates/_fragments"
URL = "/ui/alerts/systems?hours=168"


def text_of(markup: str) -> str:
    import html as _html
    return " ".join(_html.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


class _User:
    id = 1
    username = "systems-tester"

    def __init__(self, *permissions: str):
        self.permissions = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self.permissions


@pytest.fixture
def overview(monkeypatch):
    box: dict[str, Any] = {"payload": {"systems": []}}

    async def handler(hours=168, current_user=None, session=None):
        value = box["payload"]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(analytics_api, "get_system_overview", handler)
    return box


def get(*permissions: str, url: str = URL):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User(
        *(permissions or ("alert:read",)))
    app.dependency_overrides[get_db_session] = lambda: None
    with TestClient(app) as client:
        return client.get(url)


def _sys(**over):
    base = {
        "system": "corp-ad", "mapped": True, "alert_count": 12,
        "severity": {"critical": 2, "high": 3, "medium": 0, "low": 0},
        "timeline": [{"count": 1}, {"count": 4}, {"count": 2}],
        "tide": {"coverage_pct": 55, "applied_rules": 11, "total_rules": 20,
                 "enabled_rules": 9, "disabled_rules": 2},
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The gate and the dead header
# ---------------------------------------------------------------------------


def test_the_fragment_carries_the_gate_its_read_requires(overview):
    assert get("case:read").status_code == 403
    assert get("alert:read").status_code == 200


def test_the_page_builds_no_authorization_header_any_more():
    """The fetch sent a Bearer token from a localStorage key nothing sets.
    Asserted on the script with its line comments stripped, because the
    comment recording the removal names the old expression and an assertion
    over the raw text would match its own explanation."""
    page = PAGE.read_text(encoding="utf-8")
    start = page.rindex('<script nonce="{{ csp_nonce }}">')
    script = page[page.index(">", start) + 1:]
    script = script[:script.index("</script>")]
    live = re.sub(r"^\s*//.*$", "", script, flags=re.M)
    assert "getItem('token')" not in live
    assert "Authorization" not in live


def test_nothing_in_the_codebase_sets_the_token_key_it_used_to_read():
    """The reason that header was always "Bearer null". Pinned so a future
    reader does not restore the fetch believing the token exists."""
    web = ROOT / "src/ion/web"
    setters = []
    for path in list(web.rglob("*.html")) + list(web.rglob("*.js")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"localStorage\.setItem\(\s*['\"]token['\"]", text):
            setters.append(path.name)
    assert setters == [], setters


# ---------------------------------------------------------------------------
# Three outcomes where the page had one sentence of advice
# ---------------------------------------------------------------------------


def test_a_failed_read_does_not_advise_connecting_elasticsearch(overview):
    overview["payload"] = RuntimeError("overview down")
    body = text_of(get().text)
    assert "could not be read" in body
    assert "Connect Elasticsearch" not in body
    assert "not known" in body


def test_a_payload_with_no_systems_list_is_not_a_deployment_with_none(overview):
    overview["payload"] = {"total_alerts": 5}
    body = text_of(get().text)
    assert "cannot say which systems exist" in body
    assert "Connect Elasticsearch" not in body


def test_a_genuinely_empty_list_keeps_the_pages_advice(overview):
    """The one case where "connect Elasticsearch" was the right thing to
    say, and it is kept word for word."""
    overview["payload"] = {"systems": []}
    assert "No systems found. Connect Elasticsearch to see system data." in \
        text_of(get().text)


def test_a_payload_that_is_not_a_mapping_is_a_failed_read(overview):
    overview["payload"] = ["nope"]
    assert "could not be read" in text_of(get().text)


# ---------------------------------------------------------------------------
# TIDE coverage: nought and unmeasured are opposite findings
# ---------------------------------------------------------------------------


def test_a_coverage_of_zero_is_a_measurement_with_a_band(overview):
    overview["payload"] = {"systems": [_sys(tide={"coverage_pct": 0})]}
    body = get().text
    assert "0%" in body
    assert "var(--danger)" in body, "nought percent coverage is the urgent band"
    assert "not measured" not in body


def test_an_unreported_coverage_is_not_banded_at_all(overview):
    """The page banded a missing figure as nought and painted it red, which
    asserts an urgent gap about a system nobody measured."""
    overview["payload"] = {"systems": [_sys(tide={"applied_rules": 1})]}
    body = get().text
    assert "not measured" in text_of(body)
    assert "ad-sys-tide-bar-fill" not in body, "no figure, no bar"
    assert "var(--danger)" not in body


@pytest.mark.parametrize("pct, band", [
    (TIDE_GOOD, "var(--success)"), (100, "var(--success)"),
    (TIDE_FAIR, "var(--warning)"), (TIDE_GOOD - 1, "var(--warning)"),
    (TIDE_FAIR - 1, "var(--danger)"), (0, "var(--danger)"),
])
def test_the_coverage_bands_are_the_ones_the_page_used(pct, band):
    assert tide_band(pct) == band


def test_no_figure_means_no_band():
    assert tide_band(None) is None


def test_a_mapped_system_with_no_tide_block_says_so(overview):
    overview["payload"] = {"systems": [_sys(tide=None)]}
    body = text_of(get().text)
    assert "no TIDE data" in body
    assert "not measured" not in body, "a different claim from an absent figure"


# ---------------------------------------------------------------------------
# The sparkline
# ---------------------------------------------------------------------------


def test_a_timeline_of_one_bucket_still_draws(overview):
    """`tl.length > 1` drew nothing for this, so a system with one hour of
    history looked like a system with none."""
    overview["payload"] = {"systems": [_sys(timeline=[{"count": 3}])]}
    assert "polyline" in get().text


def test_an_all_zero_timeline_says_so_rather_than_drawing_a_flat_line(overview):
    """`Math.max(1, ...)` drew a line along the bottom, which reads as a real
    series that happens to be low."""
    overview["payload"] = {"systems": [
        _sys(timeline=[{"count": 0}, {"count": 0}])]}
    body = get().text
    assert "No alerts in this window" in text_of(body)
    assert "polyline" not in body


def test_no_timeline_draws_nothing_at_all(overview):
    overview["payload"] = {"systems": [_sys(timeline=None)]}
    body = get().text
    assert "ad-sys-sparkline" not in body


def test_the_spark_points_scale_to_the_peak():
    out = sys_spark([{"count": 0}, {"count": 10}])
    assert out["flat"] is False
    ys = [float(p.split(",")[1]) for p in out["points"].split(" ")]
    assert ys[0] > ys[1], "the bigger count sits higher up the box"


def test_a_non_mapping_timeline_bucket_counts_as_zero():
    out = sys_spark(["nope", {"count": 4}])
    assert out["flat"] is False


# ---------------------------------------------------------------------------
# The four figures above the grid
# ---------------------------------------------------------------------------


def test_the_four_figures_swap_out_of_band(overview):
    overview["payload"] = {"systems": [_sys()], "total_alerts": 12,
                           "total_systems": 1, "mapped_systems": 1,
                           "avg_tide_coverage": 55}
    body = " ".join(get().text.split())
    for key in ("total", "count", "mapped", "coverage"):
        assert f'id="ad-sys-{key}" hx-swap-oob="innerHTML"' in body, key
    assert ">12<" in body
    assert "55%" in body


def test_an_unreported_figure_is_not_a_measured_zero(overview):
    overview["payload"] = {"systems": [_sys()]}
    body = get().text
    assert "not reported by this read" in body
    total = body[body.index('id="ad-sys-total"'):]
    total = total[:total.index("</span>") + 7]
    assert ">0<" not in total


def test_a_figure_of_zero_is_rendered_as_zero(overview):
    overview["payload"] = {"systems": [], "total_alerts": 0,
                           "total_systems": 0, "mapped_systems": 0,
                           "avg_tide_coverage": 0}
    body = " ".join(get().text.split())
    assert "not reported by this read" not in body
    assert ">0<" in body


def test_a_flag_where_a_figure_belongs_is_not_rendered_as_one(overview):
    """`_count` and `_number` exclude bool, because True is an int in Python
    and a payload carrying a flag where a count was expected must not read
    as one."""
    overview["payload"] = {"systems": [], "total_alerts": True}
    body = get().text
    assert "not reported by this read" in body
    assert ">1<" not in body


# ---------------------------------------------------------------------------
# The cards
# ---------------------------------------------------------------------------


def test_the_cards_are_mapped_first_then_by_alert_count(overview):
    overview["payload"] = {"systems": [
        _sys(system="unmapped-busy", mapped=False, alert_count=99),
        _sys(system="mapped-quiet", mapped=True, alert_count=1),
        _sys(system="mapped-busy", mapped=True, alert_count=50),
    ]}
    body = get().text
    order = [m for m in re.findall(r'class="ad-sys-name">([^<]+)<', body)]
    assert order == ["mapped-busy", "mapped-quiet", "unmapped-busy"]


def test_a_card_with_no_alert_count_sorts_last_among_its_group():
    rows = sys_overview({"systems": [
        {"system": "nocount", "mapped": True},
        {"system": "counted", "mapped": True, "alert_count": 1},
    ]})["rows"]
    assert [r["name"] for r in rows] == ["counted", "nocount"]


def test_a_severity_measured_at_zero_is_not_a_pill(overview):
    """`if (sev.critical)` in the page, which is right: a wedge saying
    "0 crit" is not a finding."""
    overview["payload"] = {"systems": [
        _sys(severity={"critical": 0, "high": 0, "medium": 0, "low": 0})]}
    body = get().text
    assert "0 crit" not in body
    assert "No alerts" in text_of(body)


def test_a_missing_severity_block_is_not_an_estate_with_no_alerts(overview):
    overview["payload"] = {"systems": [_sys(severity=None, alert_count=None)]}
    assert "Severities not reported" in text_of(get().text)


def test_a_non_mapping_row_is_dropped_rather_than_rendered(overview):
    overview["payload"] = {"systems": ["nope", _sys()]}
    body = get().text
    assert "corp-ad" in body
    assert body.count("ad-sys-card") == 1


def test_a_row_with_no_name_is_still_a_system():
    card = sys_card({"system": None, "mapped": False})
    assert card["name"] == "unknown"
    assert card["initials"] == "UN"


# ---------------------------------------------------------------------------
# What the page no longer does
# ---------------------------------------------------------------------------


WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


def test_the_retired_writers_are_gone():
    page = PAGE.read_text(encoding="utf-8")
    for name in ("renderAdSystems", "buildAdSysCard"):
        assert not re.search(r"(?<![\w.])" + name + r"\s*\(", page), name


def test_load_ad_systems_dispatches_rather_than_fetching():
    page = PAGE.read_text(encoding="utf-8")
    body = page[page.index("function loadAdSystems("):].replace("\r\n", "\n")
    body = body[:body.index("\n}")]
    assert not WRITES.search(body)
    assert "alerts-systems" in body
    assert "fetch(" not in body


def test_the_grid_requests_the_fragment_with_its_range_control():
    page = PAGE.read_text(encoding="utf-8")
    div = page[page.index('id="ad-sys-grid"'):]
    div = div[:div.index(">") + 1]
    assert 'hx-get="/ui/alerts/systems"' in div
    assert 'hx-trigger="alerts-systems from:body"' in div
    assert 'hx-include="#ad-sys-range"' in div


def test_the_fragment_uses_no_inline_style_and_no_htmx_expression():
    text = (FRAGMENTS / "alerts_systems.html").read_text(encoding="utf-8")
    assert not re.search(r"\sstyle=\"", text)
    assert "data-ion-style" in text
    assert "hx-on" not in text
    assert "js:" not in text


# ---------------------------------------------------------------------------
# The survivors of this stage's mutation pass.
#
# One is equivalent in output. Removing the `isinstance(payload, dict)` guard
# in sys_overview does not change what the reader sees: the next line calls
# payload.get, a list raises AttributeError, and the route's except turns
# that into the same failed render. The guard is redundant with the except
# rather than load-bearing, which is worth knowing and is not worth a test
# that cannot fail. test_a_payload_that_is_not_a_mapping_is_a_failed_read
# already pins the outcome by whichever path it arrives.
#
# The other seven were real gaps, each the sibling of a case already
# covered: the branch was exercised, but not with the one input where the
# guard changes the answer.
# ---------------------------------------------------------------------------


def test_a_single_bucket_sparkline_draws_two_points_not_one():
    """Closes a survivor. The existing test asserted the word "polyline" was
    present, and a polyline with one point is still a polyline element: it
    just draws nothing. The second point is what makes one bucket visible."""
    out = sys_spark([{"count": 3}])
    assert out["flat"] is False
    pairs = out["points"].split(" ")
    assert len(pairs) == 2, out["points"]
    assert pairs[0].split(",")[1] == pairs[1].split(",")[1], (
        "a single bucket is a flat segment at its own height, not a slope")


def test_an_empty_timeline_list_is_no_timeline_at_all():
    """Closes a survivor. The absent case was covered with None, and a list
    that is present but empty is the sibling. Without the emptiness check
    `max(counts)` is called on an empty list and raises."""
    assert sys_spark([]) is None
    assert sys_spark(None) is None
    assert sys_spark("not a list") is None


def test_a_non_mapping_bucket_holds_its_place_as_a_zero():
    """Closes a survivor. The existing test only asserted the series was not
    flat, which skipping the bad bucket also satisfies. Dropping it instead
    of zeroing it shortens the series, so every later bucket slides left and
    the line no longer lines up with the window it describes."""
    out = sys_spark(["nope", {"count": 4}, {"count": 2}])
    assert len(out["points"].split(" ")) == 3, out["points"]
    first_y = float(out["points"].split(" ")[0].split(",")[1])
    assert first_y == pytest.approx(SYS_SPARK_H - 2), (
        "the unreadable bucket sits on the floor as a zero")


def test_a_truthy_non_true_mapped_flag_is_not_a_mapped_system():
    """Closes a survivor. `is True` and truthiness agree on True, False and
    absent, which is all the tests above supply. A service that starts
    answering 1 would otherwise have every system reported as TIDE-mapped,
    and the mapped badge is what tells an analyst coverage is being
    measured at all."""
    assert sys_card({"system": "s", "mapped": 1})["mapped"] is False
    assert sys_card({"system": "s", "mapped": "yes"})["mapped"] is False
    assert sys_card({"system": "s", "mapped": True})["mapped"] is True


def test_an_unreported_average_coverage_is_not_a_measured_zero(overview):
    """Closes a survivor. The unreported-figure test looked only at the
    alerts total, and the average coverage is the one that goes through
    `_number` rather than `_count`."""
    overview["payload"] = {"systems": [], "total_alerts": 0,
                           "total_systems": 0, "mapped_systems": 0}
    body = get().text
    coverage = body[body.index('id="ad-sys-coverage"'):]
    coverage = coverage[:coverage.index("</span>") + 7]
    assert "not reported by this read" in coverage
    assert "0%" not in coverage


def test_a_flag_where_the_average_coverage_belongs_is_not_one_percent(overview):
    """Closes a survivor. `_number` excludes bool for the same reason
    `_count` does, and only the average coverage reaches `_number` from this
    payload."""
    overview["payload"] = {"systems": [], "avg_tide_coverage": True}
    body = get().text
    coverage = body[body.index('id="ad-sys-coverage"'):]
    coverage = coverage[:coverage.index("</span>") + 7]
    assert "not reported by this read" in coverage
    assert "1%" not in coverage


def test_a_system_counted_at_zero_sorts_ahead_of_one_not_counted(overview):
    """Closes a survivor. The existing ordering test paired a count of 1
    against None, and both the correct rule and its replacement put the
    counted one first. A count of zero against None is the only pair that
    tells them apart: zero was measured and belongs above an unknown."""
    rows = sys_overview({"systems": [
        {"system": "not-counted", "mapped": True},
        {"system": "counted-zero", "mapped": True, "alert_count": 0},
    ]})["rows"]
    assert [r["name"] for r in rows] == ["counted-zero", "not-counted"]


# ---------------------------------------------------------------------------
# Stage 8: the writes a CSS class or static markup already covered
# ---------------------------------------------------------------------------


def test_the_timer_button_writes_no_icon_markup():
    """alerts-page.css has `.timer-btn.playing::before { content: "▶" }` and
    the Lucide sheet gives `.icon-play` a glyph too, so while the timer was
    paused the button rendered both: the CSS triangle and the injected icon
    element, side by side. The class was already the state."""
    page = PAGE.read_text(encoding="utf-8")
    assert "btn.innerHTML" not in page
    assert 'class="timer-icon-pause"' in page

    css = (ROOT / "src/ion/web/static/css/alerts-page.css").read_text(encoding="utf-8")
    assert ".timer-btn.playing .timer-icon-pause" in css, (
        "the bars have to be hidden when the ::before triangle shows, or the "
        "paused button draws two icons again")
    assert '.timer-btn.playing::before' in css


def test_the_timer_still_toggles_the_class_that_is_the_state():
    page = PAGE.read_text(encoding="utf-8")
    body = page[page.index("function toggleInvestigationTimer("):].replace("\r\n", "\n")
    body = body[:body.index("\n}")]
    assert "classList.add('playing')" in body
    assert "classList.remove('playing')" in body


def test_the_keyboard_help_markup_lives_in_the_shell():
    """Thirty-four lines with no interpolation and no escapeHtml call in
    them, assembled and inserted on the body each time it was opened."""
    page = PAGE.read_text(encoding="utf-8")
    assert '<template id="keyboard-help-template">' in page
    body = page[page.index("function showKeyboardShortcutsHelp("):].replace("\r\n", "\n")
    body = body[:body.index("\n}")]
    assert "insertAdjacentHTML" not in body
    assert "innerHTML" not in body
    assert "cloneTemplate('keyboard-help-template')" in body


def test_the_help_template_is_outside_the_script_block():
    """A <template> inside <script> is text, not markup, and cloneTemplate
    would find no content to clone."""
    page = PAGE.read_text(encoding="utf-8")
    script = page.rindex('<script nonce="{{ csp_nonce }}">')
    assert page.index('<template id="keyboard-help-template">') < script


def test_the_help_modal_keeps_its_close_controls():
    page = PAGE.read_text(encoding="utf-8")
    tpl = page[page.index('<template id="keyboard-help-template">'):]
    tpl = tpl[:tpl.index("</template>")]
    assert tpl.count('data-remove-target="keyboard-help-modal"') == 2
    assert "data-remove-self-on-self-click" in tpl


# ---------------------------------------------------------------------------
# An Elasticsearch that could not be read, told apart from an estate with
# no systems in it.
#
# get_system_overview initialised es_data to {"systems": [], ...} and used
# that default for all three unreadable cases: no url configured, a service
# reporting itself not configured, and a read that threw. Only the third
# recorded anything, an `error` key no consumer read. So this tab said "No
# systems found. Connect Elasticsearch to see system data." while the
# analytics tab beside it, reading the same absent Elasticsearch, correctly
# said the alerts could not be read. Measured live on 2026-10-13.
#
# The system list is not purely an Elasticsearch read: get_system_overview
# merges the ES systems with the CyAB namespace mappings out of ION's own
# database, so an unreadable ES can still leave a real list of systems
# whose alert figures are unknown. The two cases are separated below.
# ---------------------------------------------------------------------------


def test_an_unreadable_elasticsearch_with_no_mapped_systems_is_a_failed_read():
    """Nothing is known: no ES, and no CyAB mapping to fall back on. The
    reader must not be told to go and connect the thing that is the reason
    the panel is empty."""
    view = sys_overview({"systems": [], "es_failed": True,
                         "error": "Elasticsearch is not configured"})
    assert view["failed"] is True
    assert view["reason"] == "Elasticsearch is not configured"


def test_an_unreadable_elasticsearch_still_lists_the_mapped_systems():
    """The CyAB mappings come from ION's own database and are a real answer
    to "which systems exist". Losing them because ES is down would be the
    opposite mistake."""
    view = sys_overview({"systems": [_sys(alert_count=0)], "es_failed": True,
                         "error": "Elasticsearch is not configured",
                         "total_alerts": 0})
    assert view["failed"] is False
    assert view["degraded"] is True
    assert view["reason"] == "Elasticsearch is not configured"
    assert [c["name"] for c in view["rows"]] == ["corp-ad"]


def test_an_unreadable_read_reports_no_alert_total_rather_than_zero():
    """total_alerts comes from the ES side. Zero would say the estate was
    quiet, when the truth is that nobody counted."""
    view = sys_overview({"systems": [_sys()], "es_failed": True,
                         "total_alerts": 0, "error": "boom"})
    assert view["total_alerts"] is None


def test_a_degraded_read_keeps_the_figures_ion_itself_knows():
    """total_systems and mapped_systems are counted from the merged list,
    which ION produced, so they stay measurements."""
    view = sys_overview({"systems": [_sys(), _sys(system="corp-dns")],
                         "es_failed": True, "total_systems": 2,
                         "mapped_systems": 2, "error": "boom"})
    assert view["total_systems"] == 2
    assert view["mapped_systems"] == 2


def test_a_successful_read_with_no_systems_is_still_a_real_absence():
    """The branch the old wording was written for, and the only one where
    "Connect Elasticsearch" is the right advice."""
    view = sys_overview({"systems": [], "es_failed": False})
    assert view["failed"] is False
    assert view["degraded"] is False
    assert view["rows"] == []


def test_a_payload_that_does_not_say_is_not_treated_as_degraded():
    """get_system_overview always sets es_failed, so an absent key is an
    unexpected shape rather than a signal. It is not read as a failure,
    which would turn every healthy render into a warning."""
    view = sys_overview({"systems": [_sys()], "total_alerts": 5})
    assert view["degraded"] is False
    assert view["total_alerts"] == 5


def test_the_fragment_says_the_counts_are_unknown_on_a_degraded_read(overview):
    overview["payload"] = {"systems": [_sys(alert_count=0)], "es_failed": True,
                           "error": "Elasticsearch is not configured",
                           "total_alerts": 0, "total_systems": 1,
                           "mapped_systems": 1}
    body = get().text
    assert "corp-ad" in body, "the mapped system is still listed"
    assert "Elasticsearch is not configured" in body
    assert "No systems found" not in body


def test_the_fragment_does_not_advise_connecting_es_when_es_is_the_problem(overview):
    overview["payload"] = {"systems": [], "es_failed": True,
                           "error": "Elasticsearch is not configured"}
    body = get().text
    assert "No systems found. Connect Elasticsearch" not in body
    assert "could not be read" in body


def test_the_real_overview_reports_an_unconfigured_elasticsearch(session):
    """Drives the handler itself rather than the stub. This deployment has
    no Elasticsearch, which is the case that returned an empty list and
    said nothing."""
    import asyncio

    from ion.web.analytics_api import get_system_overview

    payload = asyncio.run(
        get_system_overview(hours=24, current_user=None, session=session))
    assert payload["es_failed"] is True
    assert payload["error"]
    assert isinstance(payload["systems"], list)
