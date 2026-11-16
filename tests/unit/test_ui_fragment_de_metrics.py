"""DE Metrics as a server-rendered fragment.

de_metrics.html built six stat tiles, a noise-campaign table and a
per-campaign evidence panel out of string concatenation and wrote the
result into `#de-content` with innerHTML at four sites, with a hand-rolled
`deEsc()` and a `deSlug()` keying the drill rows. Those are the cases
below: each one is something the JavaScript either got right and must keep,
or got wrong and must stop doing.

This panel exists to rank rules by the analyst hours their false positives
are costing, so every figure on it is a number somebody acts on, and the
difference between a measured zero and an unmeasured figure is the whole
point. `s.addressable_hours || 0` erased it for four of the six tiles, and
the Bob-agreement tile painted "not measured" in the same red as "wrong on
every alert".

The render tests use fixtures rather than live data: the dev database has
no closed false-positive cases, and an empty render proves nothing about
the table, which is all that moved. The route tests build real
AlertTriage/AlertCase rows and drive the real service, because that is the
only way to know the fragment and GET /api/de/metrics answer the same way.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.licensing import gating
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
from ion.web.templating import make_templates
from ion.web.ui.de_metrics import (
    MITRE_SHOWN,
    PERMISSION,
    PROPOSE_PERMISSION,
    SEVERITY_BADGES,
    TREND_STYLES,
    _band,
    _trim,
    campaign_row,
    campaign_rows,
    closure_split,
    number_tile,
    router,
    scored_sub,
    severity_badge,
    stat_tiles,
    trend_tile,
)

FRAGMENT = "_fragments/de_metrics.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/de_metrics.html"
SERVER = ROOT / "src/ion/web/server.py"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _summary(**over: Any) -> dict:
    base = {
        "campaign_count": 3,
        "total_fp_alerts": 48,
        "addressable_hours": 8.0,
        "top_reclaimable_hours": 4.5,
        "noisiest_rule": "Suspicious PowerShell Execution",
        "noise_trend": {"recent_fp_closures": 30, "older_fp_closures": 18,
                        "delta_pct": 66.7, "direction": "rising"},
        "bob_agreement": {"scored": 40, "agreed": 34, "agreement_rate": 85.0},
    }
    base.update(over)
    return base


def _campaign(**over: Any) -> dict:
    base = {
        "rule_name": "Suspicious PowerShell Execution",
        "fp_alerts": 27,
        "case_count": 9,
        "false_positive": 24,
        "benign_true_positive": 3,
        "first_seen": "2026-08-01T02:00:00",
        "last_seen": "2026-10-01T02:00:00",
        "cost_hours": 4.5,
        "severity_mix": {"high": 20, "low": 7},
        "mitre_techniques": ["T1059.001", "T1086"],
        "top_signatures": [{"value": "powershell.exe", "count": 20}],
        "top_hosts": [{"value": "web01", "count": 18}],
        "sample_alert_ids": ["alert-1", "alert-2"],
    }
    base.update(over)
    return base


def panel(summary: dict | None = None, campaigns: list | None = None,
          minutes: Any = 10, can_propose: bool = True,
          period_days: int = 90) -> str:
    """The whole fragment for one payload, the way the route renders it."""
    return render(
        failed=False,
        period_days=period_days,
        tiles=stat_tiles(_summary() if summary is None else summary),
        campaigns=campaign_rows(
            {"campaigns": [_campaign()] if campaigns is None else campaigns}
        ),
        minutes_per_alert=minutes,
        can_propose=can_propose,
    )


def one(**over: Any) -> str:
    """The fragment with one campaign row overridden field by field."""
    return panel(campaigns=[_campaign(**over)])


def prose(html: str) -> str:
    """The render with every run of whitespace collapsed to one space.

    Every sentence in the fragment is wrapped to fit the file, so a phrase
    long enough to be worth asserting on arrives with a newline and an indent
    somewhere inside it. The assertions below that quote a sentence read this
    rather than the raw render, so reflowing the template cannot turn a
    passing guard red and cannot be what makes a reworded one pass.
    """
    return re.sub(r"\s+", " ", html)


def tile(label: str, html: str) -> str:
    """The rendered tile whose title is `label`, so a test about one tile
    cannot pass on another tile's value."""
    match = re.search(
        r'<div class="stat-title">' + re.escape(label)
        + r'</div>\s*<div class="stat-value[^"]*"[^>]*>(.*?)</div>\s*'
        r'(?:<div class="stat-desc">(.*?)</div>)?',
        html, re.S,
    )
    assert match, f"no tile titled {label!r} in the render"
    return match.group(0)


# ---------------------------------------------------------------------------
# The tiles, where a measured zero and an unmeasured figure are opposites
# ---------------------------------------------------------------------------


def test_all_six_tiles_render_in_the_order_the_page_had_them():
    html = panel()
    labels = re.findall(r'<div class="stat-title">([^<]+)</div>', html)
    assert labels == ["Addressable hours", "FP alerts", "Noise campaigns",
                      "Top campaign", "Noise trend", "Bob agreement"]


@pytest.mark.parametrize("key,label", [
    ("addressable_hours", "Addressable hours"),
    ("total_fp_alerts", "FP alerts"),
    ("campaign_count", "Noise campaigns"),
    ("top_reclaimable_hours", "Top campaign"),
])
def test_a_figure_measured_at_zero_is_printed_rather_than_hidden(key, label):
    """`is not none`, not truthiness.

    `s.addressable_hours || 0` happened to print the right digit for a
    measured zero and the same digit for a key that never arrived, so the
    page could not say which it was. Zero addressable hours is the finding
    that this estate's closed false positives are costing nothing worth
    reclaiming, which is a result, and it has to be distinguishable from
    nobody having measured it.
    """
    cell = tile(label, panel(_summary(**{key: 0})))
    assert ">0<" in cell
    assert "unknown" not in cell


@pytest.mark.parametrize("key,label", [
    ("addressable_hours", "Addressable hours"),
    ("total_fp_alerts", "FP alerts"),
    ("campaign_count", "Noise campaigns"),
    ("top_reclaimable_hours", "Top campaign"),
])
def test_a_figure_the_summary_never_carried_says_unknown(key, label):
    summary = _summary()
    del summary[key]
    cell = tile(label, panel(summary))
    assert "unknown" in cell
    assert ">0<" not in cell
    assert "None" not in cell


def test_a_whole_number_of_hours_loses_its_trailing_zero():
    """The service rounds to one decimal, so 12 arrives as 12.0. JSON made
    that a JavaScript 12 and the tile read "12"; the port is meant to be
    invisible, so it still does."""
    assert ">12<" in tile("Addressable hours",
                          panel(_summary(addressable_hours=12.0)))


def test_a_fractional_figure_keeps_its_decimal():
    assert ">12.5<" in tile("Addressable hours",
                            panel(_summary(addressable_hours=12.5)))


@pytest.mark.parametrize("hours,colour", [
    (8.0, "text-warning"),
    (12.0, "text-warning"),
    (7.9, "text-primary"),
    (0, "text-primary"),
])
def test_addressable_hours_is_emphasised_from_a_full_working_day(hours, colour):
    assert colour in tile("Addressable hours",
                          panel(_summary(addressable_hours=hours)))


@pytest.mark.parametrize("count,colour", [
    (1, "text-warning"),
    (9, "text-warning"),
    (0, "text-primary"),
])
def test_a_campaign_count_is_emphasised_only_when_there_is_one(count, colour):
    """Zero noise campaigns is good news, not an alarm, and the JavaScript's
    `s.campaign_count ? 'warn' : ''` agreed."""
    assert colour in tile("Noise campaigns", panel(_summary(campaign_count=count)))


def test_an_unmeasured_campaign_count_is_not_emphasised():
    summary = _summary()
    del summary["campaign_count"]
    assert "text-warning" not in tile("Noise campaigns", panel(summary))


def test_the_top_campaign_tile_names_the_noisiest_rule():
    assert "Suspicious PowerShell Execution" in tile("Top campaign", panel())


def test_an_estate_with_no_campaigns_shows_a_dash_for_the_noisiest_rule():
    cell = tile("Top campaign", panel(_summary(noisiest_rule=None)))
    assert "—" in cell
    assert "None" not in cell


# ---------------------------------------------------------------------------
# Bob agreement, where the JavaScript painted "unmeasured" as "always wrong"
# ---------------------------------------------------------------------------


def test_an_agreement_rate_of_zero_is_printed_and_painted_critical():
    """Bob wrong on every alert an analyst scored is the strongest finding
    this tile can carry, and it is the one a `|| 0` cannot distinguish from
    silence."""
    cell = tile("Bob agreement", panel(_summary(
        bob_agreement={"scored": 12, "agreed": 0, "agreement_rate": 0})))
    assert ">0%<" in cell
    assert "text-error" in cell


def test_an_unmeasured_agreement_rate_is_not_painted_as_a_failing_one():
    """The defect this guard exists for.

    `agreeCls` tested `agree.agreement_rate === null`, which is false for
    `undefined`, so a payload without the key fell through to
    `>= 80 ? 'good' : >= 60 ? 'warn' : 'crit'` and an unscored deployment
    was shown a red tile that reads as "Bob is always wrong".
    """
    cell = tile("Bob agreement", panel(_summary(
        bob_agreement={"scored": 0, "agreed": 0, "agreement_rate": None})))
    assert "unknown" in cell
    assert "text-error" not in cell


@pytest.mark.parametrize("rate,colour", [
    (100.0, "text-success"),
    (80.0, "text-success"),
    (79.9, "text-warning"),
    (60.0, "text-warning"),
    (59.9, "text-error"),
])
def test_each_agreement_band_keeps_its_colour(rate, colour):
    assert colour in tile("Bob agreement", panel(_summary(
        bob_agreement={"scored": 10, "agreement_rate": rate})))


def test_the_agreement_rate_carries_its_percent_sign():
    assert ">85%<" in tile("Bob agreement", panel())


def test_a_scored_count_of_zero_is_printed():
    """The number that says whether the rate above it means anything."""
    assert "0 scored" in tile("Bob agreement", panel(_summary(
        bob_agreement={"scored": 0, "agreement_rate": None})))


def test_an_absent_scored_count_is_not_reported_as_zero():
    assert scored_sub(None) == "scored count unknown"
    assert scored_sub(0) == "0 scored"


def test_a_missing_agreement_block_does_not_crash_the_tile():
    summary = _summary()
    del summary["bob_agreement"]
    cell = tile("Bob agreement", panel(summary))
    assert "unknown" in cell
    assert "scored count unknown" in cell


# ---------------------------------------------------------------------------
# The noise trend, which had four states and rendered three
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("direction,arrow,colour", [
    ("rising", "▲", "text-error"),
    ("falling", "▼", "text-success"),
    ("flat", "▬", "opacity-50"),
])
def test_each_trend_direction_keeps_its_arrow_and_colour(direction, arrow, colour):
    cell = tile("Noise trend", panel(_summary(
        noise_trend={"direction": direction, "delta_pct": 12.0})))
    assert arrow in cell
    assert direction in cell
    assert colour in cell


@pytest.mark.parametrize("trend", [
    None,
    {},
    {"delta_pct": 12.0},
    {"direction": None, "delta_pct": 12.0},
    {"direction": "spiking", "delta_pct": 12.0},
    {"direction": 1, "delta_pct": 12.0},
])
def test_a_direction_this_page_cannot_draw_says_not_measured(trend):
    """Four states, not three, and the guard is a membership lookup rather
    than truthiness.

    `s.noise_trend || {}` turned a missing trend into an empty object, which
    is truthy, so `if(!t)` never fired and the tile rendered "▬ " with
    nothing after it: indistinguishable from a trend measured as flat. A
    direction string the service starts emitting later is the same case, and
    it is the one a truthiness guard gets wrong, because "spiking" is truthy
    and has no arrow to draw.
    """
    cell = tile("Noise trend", panel(_summary(noise_trend=trend)))
    assert "not measured" in cell
    for arrow in ("▲", "▼", "▬"):
        assert arrow not in cell


def test_the_trend_tile_keeps_its_subtitle_when_the_trend_is_unknown():
    """The tile is still a tile. An unknown trend must not leave the reader
    wondering which halves of the window were compared."""
    assert "recent vs older half" in tile(
        "Noise trend", panel(_summary(noise_trend=None)))


def test_a_delta_of_zero_is_printed_rather_than_dropped():
    """Equal halves is a measurement: the noise is neither growing nor
    shrinking. It is not the same as an older half with no closures at all,
    which is what a missing delta means."""
    assert trend_tile({"direction": "flat", "delta_pct": 0})["delta"] == "0%"


def test_a_delta_nobody_could_compute_prints_no_percentage():
    """`delta_pct` is None when the older half of the window had no closures
    to compare against. There was nothing to change from, so there is no
    percentage to show, and 0% would claim there was."""
    cell = tile("Noise trend", panel(_summary(
        noise_trend={"direction": "flat", "delta_pct": None})))
    assert "flat" in cell
    assert "%" not in cell
    assert "None" not in cell


@pytest.mark.parametrize("delta,shown", [
    (66.7, "+66.7%"),
    (12.0, "+12%"),
    (0, "0%"),
    (-12.5, "-12.5%"),
    (None, None),
    ("rising", None),
    (True, None),
])
def test_the_delta_is_signed_the_way_the_javascript_signed_it(delta, shown):
    assert trend_tile({"direction": "flat", "delta_pct": delta})["delta"] == shown


def test_every_direction_the_service_emits_has_a_style():
    """A direction added to _noise_trend must fail here rather than render a
    tile that silently says the trend was not measured."""
    assert set(TREND_STYLES) == {"rising", "falling", "flat"}


# ---------------------------------------------------------------------------
# The campaign row
# ---------------------------------------------------------------------------


def test_a_campaign_renders_its_row():
    html = one()
    assert "Suspicious PowerShell Execution" in html
    assert ">27<" in html or ">27" in html
    assert "T1059.001" in html


@pytest.mark.parametrize("key", ["fp_alerts", "case_count", "cost_hours"])
def test_a_row_figure_measured_at_zero_is_printed(key):
    """A rule with a cost of 0 hours was measured and found cheap. A rule
    whose cost is missing was not measured. The table is sorted by that
    number, so the two cannot share a cell."""
    html = one(**{key: 0})
    assert ">0<" in html


@pytest.mark.parametrize("key", ["fp_alerts", "case_count", "cost_hours"])
def test_a_row_figure_that_is_missing_shows_a_dash(key):
    html = one(**{key: None})
    assert "&mdash;" in html
    assert "None" not in html


def test_a_cost_of_zero_hours_is_not_confused_with_a_missing_one():
    """The pair that pins `is not none` on the column the table ranks by:
    both renders have to exist and they have to differ."""
    assert ">0<" in one(cost_hours=0)
    assert ">0<" not in one(cost_hours=None)


# ---------------------------------------------------------------------------
# The FP / benign split
# ---------------------------------------------------------------------------


def test_the_split_breaks_out_the_benign_share():
    assert "24 FP + 3 benign" in one()


def test_no_benign_closures_means_no_split_to_show():
    """It would restate the number above it, and the JavaScript suppressed
    it for the same reason."""
    assert "FP + 0 benign" not in one(false_positive=27, benign_true_positive=0)
    assert closure_split(27, 0) is None


def test_a_missing_benign_count_shows_no_split():
    assert closure_split(24, None) is None


def test_a_split_is_not_rendered_half_known():
    """The JavaScript tested only the benign half, so a campaign missing its
    false-positive count would have rendered "undefined FP + 3 benign"."""
    assert closure_split(None, 3) is None


def test_the_split_trims_whole_numbers_like_every_other_figure():
    assert closure_split(24.0, 3.0) == "24 FP + 3 benign"


# ---------------------------------------------------------------------------
# The window, which is never formatted on the server
# ---------------------------------------------------------------------------


def test_the_window_is_emitted_for_the_viewers_clock():
    """The JavaScript sliced the ISO string, which is the server's clock, so
    an analyst in another timezone read the wrong day on every row. The
    macro emits the machine-readable instant and
    static/js/local-time.js decides."""
    html = one()
    assert '<time datetime="2026-08-01T02:00:00"' in html
    assert '<time datetime="2026-10-01T02:00:00"' in html
    assert 'data-ts-format="date"' in html


def test_one_missing_end_of_the_window_is_a_question_mark():
    """deWindow()'s shape: a campaign whose last closure is unknown still
    has a known first one, and the row should say which half is missing."""
    html = one(last_seen=None)
    assert "?" in html
    assert '<time datetime="2026-08-01T02:00:00"' in html


def test_a_campaign_with_no_window_at_all_shows_one_dash():
    """One dash, not "? → ?".

    Two question marks claim two separately unknown ends of a window that
    exists. A campaign with neither end has no window at all, which is what
    the JavaScript's `if(!a && !b)` said, and dropping this branch is
    invisible in a diff because the `ts` macro renders its fallback for
    both halves and the row still looks plausible.
    """
    html = one(first_seen=None, last_seen=None)
    assert "<time" not in html
    assert "?" not in html
    assert "&mdash;" in html
    assert "1970" not in html


def test_an_unparseable_window_end_keeps_the_value_it_was_given():
    """A timestamp nobody can parse is still evidence of something.

    The first version of this module parsed the two ends itself and returned
    None for anything `fromisoformat` refused, so an unreadable value rendered
    as "?", which claims the service sent nothing. `_ts_parts` keeps the text
    and labels the clock instead, and this is the only test that would notice
    a parse being reintroduced here.
    """
    html = one(last_seen="not a date")
    assert "not a date" in html


@pytest.mark.parametrize("raw", [
    "2026-08-01T02:00:00Z",
    "2026-08-01T02:00:00+00:00",
])
def test_a_window_end_that_carries_a_zone_keeps_it(raw):
    """A zone-labelled instant is localisable and must be marked as one.

    This is the defect that cost the parked draft its own helper. It parsed
    each end with `datetime.fromisoformat(str(raw).replace("Z", ""))`, which
    deletes the offset instead of reading it, so a UTC instant reached the
    macro naive. `_ts_parts` then marked it `data-ts-local="no"` with a
    "stores no timezone" note and static/js/local-time.js left it on the
    server's clock, which is exactly the thing the macro exists to prevent.
    The service emits naive strings today, so nothing on screen was wrong
    yet, and the next repository to hand back an aware value would have been.
    """
    html = one(first_seen=raw, last_seen=raw)
    assert 'data-ts-local="yes"' in html
    assert 'data-ts-local="no"' not in html
    assert "stores no timezone" not in html


def test_a_naive_window_end_is_not_localised_and_says_whose_clock_it_is():
    """The other half of the same decision, and the live case.

    `get_noise_campaigns` isoformats a naive datetime, so this is what the
    column actually renders. Localising it would read the digits as the
    viewer's clock and convert out of a zone the value was never in.
    """
    html = one()
    assert 'data-ts-local="no"' in html
    assert "stores no timezone" in html


# ---------------------------------------------------------------------------
# Severity, MITRE and the enum trap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,badge", [
    ("critical", "badge-error"),
    ("crit", "badge-error"),
    ("high", "badge-warning"),
    ("medium", "badge-warning"),
    ("low", "badge-info"),
    ("informational", "badge-info"),
    ("CRITICAL", "badge-error"),
    ("quarantined", "badge-ghost"),
    (None, "badge-ghost"),
])
def test_each_severity_keeps_the_badge_the_old_helper_gave_it(name, badge):
    assert severity_badge(name) == badge


def test_a_severity_pill_reads_the_value_not_the_enum_repr():
    """The failure two earlier conversions hit independently.

    AlertCase.severity is free text today, but ION keeps severity as a
    SQLEnum elsewhere and a payload keyed by enum members would render
    "Severity.HIGH 20" in the cell. Value equality still holds, so the
    colour lookup keeps matching and only the visible text is wrong, which
    is why it survives a glance.
    """
    from enum import Enum

    class Severity(str, Enum):
        HIGH = "high"

    html = one(severity_mix={Severity.HIGH: 20})
    assert "Severity.HIGH" not in html
    assert ">high 20<" in html
    assert "badge-warning" in html


def test_a_severity_count_of_zero_is_printed():
    assert ">high 0<" in one(severity_mix={"high": 0})


def test_a_severity_count_that_is_missing_prints_the_label_alone():
    html = one(severity_mix={"high": None})
    assert ">high<" in html
    assert "None" not in html


def test_a_campaign_with_no_severity_mix_shows_a_dash():
    assert "&mdash;" in one(severity_mix={})


def test_the_mitre_cell_stops_at_six_techniques():
    """`.slice(0,6)`. A campaign can union up to 20 and the cell has to stay
    a cell."""
    html = one(mitre_techniques=[f"T{i}" for i in range(10)])
    assert "T5" in html
    assert "T6" not in html
    assert MITRE_SHOWN == 6


def test_a_campaign_with_no_mitre_mapping_shows_a_dash():
    assert "&mdash;" in one(mitre_techniques=[])


def test_jinja_escapes_what_the_hand_rolled_deesc_used_to():
    """deEsc() is gone. This is what replaces it."""
    html = one(
        rule_name="<script>alert(1)</script>",
        severity_mix={"<img src=x onerror=1>": 2},
        mitre_techniques=["<svg onload=1>"],
        top_signatures=[{"value": "<b>sig</b>", "count": 1}],
        top_hosts=[{"value": "<i>host</i>", "count": 1}],
        sample_alert_ids=["<u>id</u>"],
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "<svg onload=1>" not in html
    assert "<b>sig</b>" not in html
    assert "<i>host</i>" not in html
    assert "<u>id</u>" not in html


# ---------------------------------------------------------------------------
# The evidence drill-down, which used to be built on click from a cache
# ---------------------------------------------------------------------------


def test_the_evidence_panel_is_rendered_with_its_row():
    html = one()
    assert "Top triggering signatures" in html
    assert "powershell.exe" in html
    assert "Top hosts" in html
    assert "web01" in html
    assert "alert-1, alert-2" in html


def test_the_evidence_panel_starts_hidden():
    assert re.search(r'<tr id="de-drill-0" hidden>', one())


def test_the_evidence_button_addresses_the_row_the_fragment_rendered():
    """deSlug() mapped "Suspicious PowerShell" and "Suspicious-PowerShell"
    onto the same id, so the second row's Evidence button opened the first
    row's panel. The index cannot collide."""
    html = panel(campaigns=[_campaign(rule_name="Suspicious PowerShell"),
                            _campaign(rule_name="Suspicious-PowerShell")])
    drills = re.findall(r'data-drill="(de-drill-\d+)"', html)
    rows = re.findall(r'<tr id="(de-drill-\d+)" hidden>', html)
    assert drills == ["de-drill-0", "de-drill-1"]
    assert rows == drills


def test_a_signature_count_of_zero_is_printed():
    assert "&times;0" in one(top_signatures=[{"value": "pwsh.exe", "count": 0}])


def test_a_signature_with_no_count_shows_its_value_alone():
    html = one(top_signatures=[{"value": "pwsh.exe", "count": None}])
    assert "pwsh.exe" in html
    assert "None" not in html


def test_a_campaign_with_nothing_captured_says_so_in_both_lists():
    html = one(top_signatures=[], top_hosts=[])
    assert html.count("none captured") == 2


def test_no_sample_alert_ids_leaves_the_line_out():
    assert "Sample alert ids" not in one(sample_alert_ids=[])


# ---------------------------------------------------------------------------
# The draft button, which POSTs under a different permission
# ---------------------------------------------------------------------------


def test_the_draft_button_is_offered_to_a_reader_who_may_propose():
    html = panel(can_propose=True)
    assert 'data-click-action="deDraft"' in html
    assert 'data-rule="Suspicious PowerShell Execution"' in html


def test_the_draft_button_is_withheld_from_a_reader_who_may_not():
    """A button whose POST answers 403 is a worse answer than no button.
    The JavaScript offered it to every reader of the page."""
    html = panel(can_propose=False)
    assert "deDraft" not in html
    assert 'data-click-action="deDrill"' in html


# ---------------------------------------------------------------------------
# The costing rate the headline number comes from
# ---------------------------------------------------------------------------


def test_the_footnote_names_the_rate_the_hours_were_costed_at():
    assert "at 10 min/alert" in prose(panel(minutes=10))


def test_a_costing_rate_of_zero_is_stated_rather_than_hidden():
    """0 min/alert is why every campaign costs 0 hours, and it is the only
    thing that explains the headline figure."""
    assert "at 0 min/alert" in prose(panel(minutes=0))


def test_an_unknown_costing_rate_is_not_reported_as_the_default_ten():
    """`(d.settings ? d.settings.minutes_per_alert : 10)` told a deployment
    that had set ION_DE_MINUTES_PER_ALERT to 20 that its hours came from a
    rate that was not the one they were computed with."""
    html = prose(panel(minutes=None))
    assert "at a per-alert rate this read could not confirm" in html
    assert "10 min/alert" not in html


# ---------------------------------------------------------------------------
# Empty is not failed, and neither of them is a zero
# ---------------------------------------------------------------------------


def test_no_campaigns_says_so_and_names_what_would_create_one():
    html = prose(panel(campaigns=[]))
    assert "No false-positive closures in this window" in html
    assert "Campaigns appear as cases are closed as false-positive / benign" in html
    assert "<table" not in html


@pytest.mark.parametrize("summary", [None, {}, "not a dict"],
                         ids=["absent", "empty", "wrong-type"])
def test_a_summary_block_that_never_arrived_prints_no_figure_at_all(summary):
    """The defect this page was most exposed to, named on its own.

    `const s = d.summary || {}` followed by six `|| 0` defaults meant a
    payload that carried no summary rendered six confident zeros: no
    addressable hours, no FP alerts, no campaigns, and Bob agreeing on
    nothing. Read off this panel that is "this estate has no detection
    noise", which is an estate nobody needs to tune. The per-key tests above
    cover one figure going missing; this covers the whole block, which is the
    shape that produced five zeros on a board report and three kinds of
    silence printing one word on a log-source page.
    """
    # Built through render rather than panel(), whose `summary=None` means
    # "use the fixture" and would quietly test the fixture instead.
    html = render(failed=False, period_days=90, tiles=stat_tiles(summary),
                  campaigns=[], minutes_per_alert=10, can_propose=True)
    for label in ("Addressable hours", "FP alerts", "Noise campaigns",
                  "Top campaign", "Bob agreement"):
        assert ">unknown<" in tile(label, html), f"{label} is printing a figure"
    assert "not measured" in tile("Noise trend", html)
    assert "scored count unknown" in tile("Bob agreement", html)
    for figure in (">0<", ">0%<", "0 scored"):
        assert figure not in html, f"{figure} is a measurement nobody took"


def test_the_tiles_still_render_when_there_are_no_campaigns():
    """An estate with no noise still has a measured zero to show, and the
    tiles are where it shows."""
    html = panel(campaigns=[])
    assert "Addressable hours" in html
    assert "Bob agreement" in html


def test_a_failed_read_says_so_rather_than_showing_zeros():
    """"Nothing to reclaim" and "we could not look" lead to opposite
    decisions, and one of them is to leave a rule firing. The JavaScript
    distinguished them ("Failed to load: 500") and so must this."""
    html = prose(render(failed=True, period_days=30, tiles=[], campaigns=None,
                        minutes_per_alert=None, can_propose=True))
    assert "DE metrics could not be read" in html
    assert "which is not the same as an estate with no noise to reclaim" in html
    assert "<table" not in html
    assert "No false-positive closures" not in html
    assert ">0<" not in html


def test_the_failed_read_names_the_window_it_failed_for():
    """The window comes from the request in the failure branch, so the
    message cannot lose the only context it has."""
    html = prose(render(failed=True, period_days=30, tiles=[], campaigns=None,
                        minutes_per_alert=None, can_propose=True))
    assert "for the last 30 days" in html


def test_the_failed_read_renders_no_tiles_at_all():
    """A tile reading "unknown" six times would be a second way of saying
    the same thing, and the JavaScript replaced the whole body with the
    error."""
    html = render(failed=True, period_days=90, tiles=[], campaigns=None,
                  minutes_per_alert=None, can_propose=True)
    assert "stat-title" not in html


# ---------------------------------------------------------------------------
# The helpers, tested where the three-state decision is actually made
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    (12.0, 12),
    (12.5, 12.5),
    (0.0, 0),
    (0, 0),
    (None, None),
    ("12.0", "12.0"),
    (True, True),
])
def test_trim_only_touches_real_numbers(value, expected):
    assert _trim(value) == expected
    assert type(_trim(value)) is type(expected)


@pytest.mark.parametrize("value", [None, "85", True])
def test_a_figure_that_is_not_a_number_earns_no_emphasis(value):
    """The agreement defect, at the helper. `undefined >= 80` is false in
    JavaScript, so an unmeasured rate reached the last band and was painted
    critical. A non-numeric value is the same case and is the one a bare
    `is not None` check would still get wrong."""
    from ion.web.ui.de_metrics import AGREEMENT_BANDS

    assert _band(value, AGREEMENT_BANDS) == ""


def test_a_zero_earns_the_bottom_band_rather_than_no_band():
    from ion.web.ui.de_metrics import AGREEMENT_BANDS

    assert _band(0, AGREEMENT_BANDS) == "crit"


def test_number_tile_keeps_a_missing_value_as_none():
    assert number_tile("x", None, ((0.0, ""),), None)["value"] is None


def test_the_badge_table_covers_what_the_javascript_covered():
    assert set(SEVERITY_BADGES) == {
        "critical", "crit", "high", "medium", "med",
        "low", "info", "informational",
    }


def test_campaign_row_tolerates_a_payload_that_is_not_a_dict():
    row = campaign_row(0, None)
    assert row["rule_name"] is None
    assert row["severity"] == []


# ---------------------------------------------------------------------------
# The gates, which are the point of a licence-gated page
# ---------------------------------------------------------------------------


def _dependency_names(route) -> list[str]:
    return [getattr(d.call, "__qualname__", "") for d in route.dependant.dependencies]


def _permission_of(route) -> str | None:
    for dep in route.dependant.dependencies:
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            return cells.get("permission_name")
    return None


def _fragment_route():
    (route,) = router.routes
    return route


def _json_route():
    from ion.web.de_api import router as de_router

    for route in de_router.routes:
        if route.path == "/de/metrics" and "GET" in route.methods:
            return route
    raise AssertionError("GET /de/metrics not found in de_api")


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """A fragment must never be a softer way in than the API it mirrors. The
    permission is read out of the JSON route's own dependency rather than
    restated, so the two cannot drift."""
    assert PERMISSION == "de:read"
    assert _permission_of(_json_route()) == PERMISSION
    assert _permission_of(_fragment_route()) == PERMISSION


def test_the_propose_permission_is_not_what_the_fragment_gates_on():
    """The panel is a read. Only the Draft button answers to de:propose."""
    assert PROPOSE_PERMISSION == "de:propose"
    assert _permission_of(_fragment_route()) != PROPOSE_PERMISSION


def test_the_fragment_carries_the_licence_module_gate():
    """/api/de/metrics gets require_de_module from its router mount, so a
    fragment without it would be a way to read an estate's detection noise
    out of a deployment whose licence does not include the module."""
    assert "require_de_module" in _dependency_names(_fragment_route())


def test_the_module_gate_runs_before_the_permission_gate():
    """Same order as the JSON endpoint, where the gate is a router
    dependency and therefore runs first. It decides what an unauthenticated
    request to a licence-disabled deployment is told: 404 (this does not
    exist) rather than 401 (log in and ask again)."""
    names = _dependency_names(_fragment_route())
    gate = names.index("require_de_module")
    perm = next(i for i, n in enumerate(names)
                if n.startswith("require_permission."))
    assert gate < perm


def test_the_json_router_is_mounted_behind_the_same_gate():
    """The claim the two tests above are matching against. If server.py ever
    stops gating the DE router, the fragment's gate becomes the stricter of
    the two and this says so instead of letting them drift silently."""
    src = SERVER.read_text(encoding="utf-8")
    assert re.search(
        r"include_router\(\s*de_router,[^)]*require_de_module", src
    ), "de_router is no longer mounted with require_de_module"


def test_require_de_module_is_a_404_when_the_module_is_off(monkeypatch):
    """Positive control for the gate itself, so the two tests above are not
    asserting about a dependency that does nothing."""
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with pytest.raises(HTTPException) as excinfo:
        gating.require_de_module()
    assert excinfo.value.status_code == 404


def test_the_window_is_bounded_the_way_the_json_endpoint_bounds_it():
    """A window the API would refuse must not be reachable through the
    fragment, or the fragment is a way around the endpoint's limits."""
    fragment = next(p for p in _fragment_route().dependant.query_params
                    if p.name == "days")
    json_param = next(p for p in _json_route().dependant.query_params
                      if p.name == "days")
    assert fragment.field_info.metadata == json_param.field_info.metadata


# ---------------------------------------------------------------------------
# The route over HTTP, driving the real service
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "de-tester"
    permissions = {PERMISSION, PROPOSE_PERMISSION}

    def has_permission(self, name):
        return name in self.permissions


@pytest.fixture
def app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: session
    yield application
    application.dependency_overrides.clear()


def _noise(session, rule: str = "Probe Rule", alerts: int = 2,
           days_ago: int = 1) -> None:
    """A real noise campaign: one closed false-positive case with `alerts`
    triage rows hanging off it.

    Two alerts rather than one because ION_DE_MIN_CAMPAIGN defaults to 2 and
    a single FP closure is below the cluster size the service lists.
    """
    # Naive UTC, the way the service computes its cutoff, so the window
    # arithmetic in the test and in the service agree.
    closed = (datetime.now(timezone.utc).replace(tzinfo=None)
              - timedelta(days=days_ago))
    case = AlertCase(
        case_number=f"PROBE-{rule}-{days_ago}",
        title="probe case",
        status=AlertCaseStatus.CLOSED,
        severity="high",
        created_by_id=1,
        closure_reason="false_positive",
        closed_at=closed,
        affected_hosts=["web01"],
    )
    session.add(case)
    session.commit()
    for i in range(alerts):
        session.add(AlertTriage(
            es_alert_id=f"probe-{rule}-{days_ago}-{i}",
            case_id=case.id,
            rule_name=rule,
            observables=[{"type": "process", "value": "powershell.exe"}],
            mitre_techniques=["T1059.001"],
        ))
    session.commit()


def test_the_route_renders_a_real_campaign_from_the_service(
    app, session, monkeypatch
):
    """The fragment and GET /api/de/metrics share one query, so this drives
    de_metrics_service.get_de_metrics rather than a stand-in for it."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _noise(session)
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics")
    assert resp.status_code == 200
    assert "Probe Rule" in resp.text
    assert "T1059.001" in resp.text
    assert "powershell.exe" in resp.text
    assert "web01" in resp.text


def test_the_route_honours_the_window(app, session, monkeypatch):
    """A campaign outside the window is not in the table, which is what the
    select is for."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _noise(session, days_ago=40)
    with TestClient(app) as client:
        wide = client.get("/ui/de-metrics", params={"days": 90})
        narrow = client.get("/ui/de-metrics", params={"days": 7})
    assert "Probe Rule" in wide.text
    assert "Probe Rule" not in narrow.text
    assert "No false-positive closures in this window" in narrow.text


def test_the_route_refuses_a_window_the_json_endpoint_would_refuse(
    app, monkeypatch
):
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    with TestClient(app) as client:
        assert client.get("/ui/de-metrics", params={"days": 0}).status_code == 422
        assert client.get("/ui/de-metrics", params={"days": 999}).status_code == 422


def test_the_route_404s_when_the_module_is_licence_disabled(
    app, session, monkeypatch
):
    """The state that is neither empty nor failed. Nothing about the
    estate's detection noise leaks, and htmx-errors.js words the 404."""
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    _noise(session)
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics")
    assert resp.status_code == 404
    assert "Probe Rule" not in resp.text


def test_a_read_failure_renders_the_failure_fragment_not_zeros(
    app, monkeypatch
):
    """200 with a fragment that says so, because htmx does not swap a 500
    and the user would be left reading the spinner."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)

    def boom(*_a, **_k):
        raise RuntimeError("alert store unreachable")

    monkeypatch.setattr("ion.services.de_metrics_service.get_de_metrics", boom)
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics")
    assert resp.status_code == 200
    assert "DE metrics could not be read" in prose(resp.text)
    assert "stat-title" not in resp.text
    assert "No false-positive closures" not in resp.text
    assert "alert store unreachable" not in resp.text


def test_a_payload_with_no_settings_block_does_not_claim_a_rate(
    app, monkeypatch
):
    """Through the route, because the template cannot be the whole guard.

    The template-level version of this passes `minutes_per_alert=None` by
    hand, which proves the wording and nothing about whether the route ever
    chooses it. A mutation pass caught that: putting `or 10` back on
    `settings.get("minutes_per_alert")` left every test green, so the page
    would again have told a deployment costed at 20 min/alert that its hours
    came from 10.
    """
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    monkeypatch.setattr(
        "ion.services.de_metrics_service.get_de_metrics",
        lambda *_a, **_k: {"period_days": 90, "summary": {}, "campaigns": []},
    )
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics")
    assert resp.status_code == 200
    body = prose(resp.text)
    assert "at a per-alert rate this read could not confirm" in body
    assert "min/alert" not in body.replace(
        "at a per-alert rate this read could not confirm", ""
    )


def test_a_costing_rate_of_zero_survives_the_route(app, monkeypatch):
    """The positive control, and the reason `or 10` is wrong rather than
    merely redundant. Zero minutes an alert is why every campaign on the page
    costs nothing, so it is the one figure that explains the headline."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    monkeypatch.setattr(
        "ion.services.de_metrics_service.get_de_metrics",
        lambda *_a, **_k: {"period_days": 90, "summary": {},
                           "settings": {"minutes_per_alert": 0}, "campaigns": []},
    )
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics")
    assert "at 0 min/alert" in prose(resp.text)


def test_a_reported_window_of_zero_is_not_relabelled_with_the_one_asked_for(
    app, monkeypatch
):
    """The `period_days` fix had no guard, so the fix would not have stayed.

    The route reads `payload.get("period_days")` with `is None` rather than
    `or`, and the comment above it explains that truthiness here is the
    `|| 0` bug with the sign flipped. Nothing asserted it: changing that
    line back to `if not reported_days` left all 145 tests green, found by
    mutation rather than by reading. A heading claiming 90 days over
    figures the service measured across 0 is a wrong label on every number
    beneath it.

    Zero is not reachable from the route today, since `days` is bounded at
    one and the service echoes it. That is an argument for the guard and not
    against it: the next caller of this payload has no such bound, and the
    code already declines to substitute, so the only thing missing was the
    test that keeps it declining.
    """
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    monkeypatch.setattr(
        "ion.services.de_metrics_service.get_de_metrics",
        lambda *_a, **_k: {"period_days": 0, "summary": {}, "campaigns": []},
    )
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics?days=90")
    assert resp.status_code == 200
    body = prose(resp.text)
    # The campaign heading, which is where the window is stated on the
    # success path. The failure fragment words it as "the last N days"
    # instead, so quoting the heading keeps this test on the branch it is
    # about. My first attempt asserted "0 days" and failed against correct
    # output for exactly that reason.
    assert "costliest first &middot; 0d" in body, "the window the service reported"
    assert "costliest first &middot; 90d" not in body, "the window asked for"


def test_a_window_the_payload_omits_falls_back_to_the_one_asked_for(
    app, monkeypatch
):
    """The other half, so the test above cannot be satisfied by printing
    nothing. An absent `period_days` is the only case where substituting the
    requested window is right, because that is the window the read used."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    monkeypatch.setattr(
        "ion.services.de_metrics_service.get_de_metrics",
        lambda *_a, **_k: {"summary": {}, "campaigns": []},
    )
    with TestClient(app) as client:
        resp = client.get("/ui/de-metrics?days=7")
    assert "costliest first &middot; 7d" in prose(resp.text)


def test_the_draft_button_follows_the_readers_propose_permission(
    app, session, monkeypatch
):
    """Decided on the live dependency rather than on a context flag, so the
    button cannot be offered to a reader whose POST would be refused."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _noise(session)

    class _ReadOnly(_User):
        permissions = {PERMISSION}

    with TestClient(app) as client:
        allowed = client.get("/ui/de-metrics")
        app.dependency_overrides[
            __import__("ion.auth.dependencies", fromlist=["x"]).get_current_user
        ] = lambda: _ReadOnly()
        refused = client.get("/ui/de-metrics")
    assert "deDraft" in allowed.text
    assert "deDraft" not in refused.text
    assert 'data-click-action="deDrill"' in refused.text


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _page_js(strip_comments: bool = False) -> str:
    """The page's inline script bodies, optionally without their comments.

    The comments name what the conversion removed, which is worth keeping
    in the page and is not code. A test asserting a helper is gone has to
    read the code only, or the comment saying it is gone fails the test.
    """
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>",
                            src, re.S))
    if strip_comments:
        js = re.sub(r"^\s*//.*$", "", js, flags=re.M)
    return js


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does. Scoped to the inline script bodies on purpose: `hx-swap="innerHTML"`
    is an attribute telling htmx where to put server-rendered markup, which
    is the opposite of the thing being removed."""
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/de-metrics"' in src
    assert 'hx-trigger="load"' in src


def test_the_string_building_helpers_are_gone_from_the_page():
    js = _page_js(strip_comments=True)
    assert js.strip(), "no inline script found, so this proves nothing"
    assert "deEsc" not in js, "Jinja autoescapes"
    assert "deRender" not in js, "a row has one definition"
    assert "deStat" not in js
    assert "deTrendText" not in js
    assert "deSevBadge" not in js
    assert "deWindow" not in js
    assert "deSlug" not in js
    assert "_deData" not in js, "nothing caches the payload any more"


def test_refresh_has_one_definition_and_it_is_the_fragment_url():
    """deLoad() is gone: the select and Refresh are both hx-get at the
    fragment, so there is no second definition of what a refresh does."""
    assert "deLoad" not in _page_js(strip_comments=True)
    assert 'hx-get="/ui/de-metrics"' in PAGE.read_text(encoding="utf-8")


def test_the_window_select_and_refresh_sit_outside_the_swap_target():
    """A control inside the fragment is removed by any render that omits it,
    so a failed read could take away the button that retries."""
    src = PAGE.read_text(encoding="utf-8")
    content = src.index('id="de-content"')
    assert src.index('id="de-days"') < content
    assert src.index('id="de-refresh"') < content


def test_the_select_value_rides_along_on_the_first_paint():
    """Firefox restores a select's value across a reload, so without
    hx-include the first paint would report 90 days while the select read
    7."""
    src = PAGE.read_text(encoding="utf-8")
    assert src.count('hx-include="#de-days"') >= 2


def test_the_window_is_not_sent_twice_on_the_selects_own_request():
    """htmx sends a triggering input's own value, and hx-include is an
    inherited attribute, so a select that also names itself in hx-include
    puts `days` on the query string twice.

    One already-converted page does exactly this. FastAPI takes the first
    value for a scalar parameter, so the page keeps working and the defect
    only shows in the request log, which is why it is still open. The
    assertion is on the select's own tag: a page-wide substring check would
    pass on the hx-include the slot and Refresh legitimately carry.
    """
    src = PAGE.read_text(encoding="utf-8")
    select = re.search(r"<select\b[^>]*id=\"de-days\"[^>]*>", src)
    assert select, "the window select is gone"
    assert "hx-include" not in select.group(0)
    assert 'name="days"' in select.group(0), (
        "without a name htmx sends the select's value under no key at all"
    )


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what a 401 does."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src
