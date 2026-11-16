"""The executive report fragments, and the honesty contract they carry.

executive_report.html built its whole body with five `innerHTML` writes fed
by 188 lines of inline JavaScript: seven stat cards, a daily trend chart, a
closure-reason breakdown, a notable-incidents table, a Team Performance
table, and on a second tab an hourly activity chart and a nine-column
per-analyst breakdown, with a hand-rolled `esc()`.

This page is a stakeholder brief, so the figures on it are read by people
who cannot check them and who act on them in a board pack. A metric
measured at zero and a metric nobody computed lead to opposite conclusions,
and the JavaScript collapsed the two in six places:

  * `c.opened||0`, `c.closed||0`, `c.open_backlog||0`, `a.total_triaged||0`
    and `a.analysts_active||0`, each of which prints a figure it never read
    as a measured zero, and `d.cases||{}` / `d.alerts||{}`, which turn a
    missing section into seven confident zeros;
  * a per-analyst FP rate of `0.0`, which analyst_efficiency_service emits
    when the analyst made no threat/not-threat call at all, printed as
    "0%" and so indistinguishable from ten calls all of which were right;
  * the FP Rate card on the Summary tab, which is measured against ALL
    closures, shown under the same two words as the Team tab's rate, which
    is measured against dispositions only, with the explanatory note on the
    Team tab alone;
  * a reporting period taken from the request rather than from the payload,
    so a window the service shortened would still be labelled with the one
    the reader asked for;
  * a bar chart with a 2px floor under every bar, so a day with no activity
    drew the same stub as a day with one case, and a 24-hour row of zeros
    read as a trickle of work rather than none;
  * `AlertCase.status`, an SQLEnum column, which reaches a template as the
    member and not its value.

Every case below was watched failing against the defective behaviour it
guards before it was made to pass. The mutation table is in the report.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.executive_report import (
    SUMMARY_FRAGMENT,
    TEAM_FRAGMENT,
    TEAM_MAX_HOURS,
    UNMEASURED_TONE,
    analyst_views,
    closure_views,
    fp_basis_note,
    hourly_views,
    incident_views,
    period_view,
    stat_views,
    summary_team_views,
    team_hours,
    team_window_view,
    trend_view,
)

PAGE = Path(ion.web.__file__).parent / "templates" / "executive_report.html"


def _flat(html: str) -> str:
    """Whitespace-collapsed, so a prose assertion does not encode the wrap.

    The templates wrap their sentences, so a contiguous substring check for
    a sentence fails against correct output. Collapse first.
    """
    return " ".join(html.split())


# ---------------------------------------------------------------------------
# Payloads shaped like the two services' real returns
# ---------------------------------------------------------------------------


def _report(**over: Any) -> dict:
    """A payload shaped like generate_executive_report's return."""
    base: dict[str, Any] = {
        "generated_at": "2026-10-12T14:00:00+00:00",
        "period_start": "2026-10-05T14:00:00+00:00",
        "period_end": "2026-10-12T14:00:00+00:00",
        "period_days": 7,
        "cases": {
            "opened": 12,
            "closed": 9,
            "closure_reasons": {"true_positive": 5, "false_positive": 4},
            "fp_rate": 44.4,
            "avg_mttr": 6.25,
            "by_severity": {"high": 3},
            "open_backlog": 11,
        },
        "alerts": {"total_triaged": 40, "analysts_active": 3},
        "team": {"analysts": [
            {"username": "ana", "cases_closed": 5, "total_actions": 80},
        ]},
        "notable_incidents": [],
        "trends": {"daily": [
            {"date": "2026-10-05", "opened": 2, "closed": 1},
            {"date": "2026-10-06", "opened": 4, "closed": 3},
        ]},
    }
    base.update(over)
    return base


def _metrics(**over: Any) -> dict:
    """A payload shaped like get_analyst_efficiency's return."""
    base: dict[str, Any] = {
        "period_hours": 168,
        "analysts": [{
            "user_id": 1, "username": "ana", "cases_closed": 5,
            "cases_opened": 2, "alerts_triaged": 14, "true_positives": 3,
            "false_positives": 2, "fp_rate": 40.0, "avg_mttr_hours": 6.25,
            "total_actions": 80, "top_actions": {},
        }],
        "team_summary": {
            "total_cases_closed": 5, "total_cases_opened": 2,
            "total_alerts_triaged": 14, "overall_fp_rate": 40.0,
            "fp_rate_basis": "of_dispositions", "avg_mttr_hours": 6.25,
            "busiest_analyst": "ana", "most_efficient": "ana",
        },
        "hourly_activity": [
            {"hour": "2026-10-11T15:00:00", "cases_closed": 1, "alerts_triaged": 2},
            {"hour": "2026-10-11T16:00:00", "cases_closed": 0, "alerts_triaged": 0},
        ],
    }
    base.update(over)
    return base


def render_summary(report: dict, requested_days: int = 7) -> str:
    """Render through the real view builders, so a break in either fails."""
    env = make_templates().env
    return env.get_template(SUMMARY_FRAGMENT).render(
        failed=False,
        requested_days=requested_days,
        period=period_view(report, requested_days),
        stats=stat_views(report),
        trend=trend_view(report),
        closures=closure_views(report),
        incidents=incident_views(report),
        team=summary_team_views(report),
    )


def render_summary_failed(requested_days: int = 7) -> str:
    env = make_templates().env
    return env.get_template(SUMMARY_FRAGMENT).render(
        failed=True, requested_days=requested_days, period=None, stats=[],
        trend=None, closures=[], incidents=[], team=[],
    )


def render_team(metrics: dict, requested_hours: int = 168) -> str:
    env = make_templates().env
    return env.get_template(TEAM_FRAGMENT).render(
        failed=False,
        window=team_window_view(metrics, requested_hours),
        hourly=hourly_views(metrics),
        analysts=analyst_views(metrics),
        fp_basis=fp_basis_note(metrics),
    )


def render_team_failed(requested_hours: int = 168) -> str:
    env = make_templates().env
    return env.get_template(TEAM_FRAGMENT).render(
        failed=True, window=None, hourly=None, analysts=[], fp_basis=None,
    )


def _request(path: str) -> Request:
    return Request({"type": "http", "method": "GET", "path": path,
                    "headers": [], "query_string": b"", "app": None})


# ---------------------------------------------------------------------------
# A stat card: zero is a measurement, absent is not
# ---------------------------------------------------------------------------


def test_a_zero_stat_is_a_measurement_not_an_absence():
    """The case a truthiness port gets wrong in the dangerous direction.

    A SOC that genuinely opened no cases in the window must read 0, not
    "not computed". `{% if stat.value %}` and `value is not None` differ on
    exactly this payload, and only on this payload, which is why the test
    exists for 0 and not only for None.
    """
    report = _report(cases={**_report()["cases"], "opened": 0, "closed": 0})
    views = {v["label"]: v for v in stat_views(report)}
    assert views["Cases Opened"]["measured"] is True
    assert views["Cases Opened"]["value"] == "0"
    assert views["Cases Closed"]["value"] == "0"

    html = _flat(render_summary(report))
    assert ">0</div>" in html
    assert "not computed" not in html


def test_an_unmeasured_stat_prints_no_figure_at_all():
    """fp_rate and avg_mttr are None whenever nothing was closed.

    case_metrics returns None for both rather than 0, deliberately. The
    card must say so and print no number, because a board pack reader
    cannot tell a 0% false-positive rate from a quarter with no closures.
    """
    report = _report(cases={**_report()["cases"], "fp_rate": None,
                            "avg_mttr": None, "closed": 0})
    views = {v["label"]: v for v in stat_views(report)}
    assert views["FP Rate"]["measured"] is False
    assert views["FP Rate"]["value"] is None
    assert views["Avg MTTR"]["measured"] is False

    html = _flat(render_summary(report))
    assert "not computed" in html
    # Bracketed, because a bar whose height really is 50% of the peak emits
    # `height:50.0%` in its style attribute and that is not a figure.
    assert ">0%<" not in html
    assert ">0h<" not in html


def test_a_missing_cases_section_is_not_seven_zeros():
    """`d.cases||{}` is how a failed section becomes a confident report.

    Every figure in a section the payload does not carry is unmeasured.
    The JavaScript printed five zeros here and a dash for the other two,
    which reads as a quiet week rather than as a read that did not happen.
    """
    report = _report()
    del report["cases"]
    del report["alerts"]
    views = stat_views(report)
    assert views, "no stats built, so this proves nothing"
    assert all(v["measured"] is False for v in views)
    assert all(v["value"] is None for v in views)

    html = _flat(render_summary(report))
    assert ">0</div>" not in html


def test_an_unmeasured_stat_takes_no_healthy_tone():
    """A colour is a claim too.

    The JavaScript's `c.fp_rate>50?'crit':c.fp_rate>30?'warn':''` falls
    through to the default tone for None, so an unmeasured false-positive
    rate was painted in the same colour as a good one. stat_tone is total
    over None and no value can select UNMEASURED_TONE.
    """
    report = _report(cases={**_report()["cases"], "fp_rate": None})
    views = {v["label"]: v for v in stat_views(report)}
    assert views["FP Rate"]["tone"] == UNMEASURED_TONE

    healthy = {v["tone"] for v in stat_views(_report())}
    assert UNMEASURED_TONE not in healthy, (
        "a measured figure can select the unmeasured tone, so the tone "
        "no longer distinguishes the two"
    )


def test_the_tone_bands_still_fire_on_the_boundaries_the_javascript_used():
    """A port that drops the bands is a regression even if it is honest.

    The JavaScript used strict `>`, so exactly 50 is not critical and
    exactly 30 is not a warning. Asserted so a later tidy cannot quietly
    turn these into `>=` and move every threshold by one.
    """
    def tone(fp_rate: float) -> str:
        report = _report(cases={**_report()["cases"], "fp_rate": fp_rate})
        return {v["label"]: v for v in stat_views(report)}["FP Rate"]["tone"]

    assert tone(50.1) == "text-error"
    assert tone(50.0) == "text-warning"
    assert tone(30.0) == "text-primary"
    assert tone(0.0) == "text-primary"


def test_the_fp_rate_card_states_the_denominator_it_was_measured_against():
    """The one figure on this page that exists twice with two meanings.

    `cases.fp_rate` is case_metrics' `fp_rate_of_closed`. The Team tab's
    per-analyst rate is `fp / (tp + fp)`. The JavaScript showed both under
    the words "FP Rate" and explained the difference on the Team tab only,
    so a reader of the Summary tab had no way to know which one they had.
    """
    views = {v["label"]: v for v in stat_views(_report())}
    assert "all closures" in views["FP Rate"]["basis"]
    assert _flat(render_summary(_report())).count("all closures") >= 1


# ---------------------------------------------------------------------------
# The reporting period: the one the service measured, not the one asked for
# ---------------------------------------------------------------------------


def test_a_period_the_service_measured_as_asked_is_not_flagged():
    """Positive control. Without it the test below passes on any output."""
    html = _flat(render_summary(_report(period_days=7), requested_days=7))
    assert "You asked for" not in html
    assert "did not state" not in html
    assert "7 days" in html


def test_a_period_the_service_shortened_is_stated_not_relabelled():
    """The reader must learn the figures cover a different window.

    The JavaScript printed `d.period_days`, which happens to be the
    requested value today, so nothing on the page compared the two. A
    service that clamps or rounds the window would be invisible.
    """
    view = period_view(_report(period_days=3), 30)
    assert view["days"] == 3
    assert view["requested_days"] == 30
    assert view["matches"] is False

    html = _flat(render_summary(_report(period_days=3), requested_days=30))
    assert "You asked for 30 days" in html
    assert "cover 3 days" in html


def test_a_period_the_service_did_not_state_is_not_the_requested_one():
    """The third state, which is not the false branch of the second.

    A payload with no `period_days` must not be labelled with the number
    the UI asked for. It says the period was not stated.
    """
    report = _report()
    del report["period_days"]
    view = period_view(report, 7)
    assert view["stated"] is False
    assert view["matches"] is False

    html = _flat(render_summary(report))
    assert "did not state the period" in html
    assert "You asked for" not in html


def test_the_period_bounds_are_time_elements_not_server_formatted_text():
    """The JavaScript called toLocaleDateString, which is the viewer's clock.

    A server knows only its own, so the macro emits `<time datetime>` and
    static/js/local-time.js rewrites the text after load and after every
    htmx swap.
    """
    html = render_summary(_report())
    assert 'data-ts-format="date"' in html
    assert '<time datetime="2026-10-05T14:00:00+00:00"' in html


# ---------------------------------------------------------------------------
# The trend chart: a zero day is not a small day
# ---------------------------------------------------------------------------


def test_a_day_with_no_activity_draws_no_bar():
    """The JavaScript floored every bar at 2px.

    `Math.max(day.opened/maxVal*80,2)` means a day with nothing drew the
    same stub as a day with one case, and at a glance a flat row of stubs
    reads as a trickle of work. A zero is rendered at zero height and the
    count is still printed beside it.
    """
    report = _report(trends={"daily": [
        {"date": "2026-10-05", "opened": 0, "closed": 0},
        {"date": "2026-10-06", "opened": 4, "closed": 3},
    ]})
    rows = trend_view(report)["rows"]
    assert rows[0]["opened_pct"] == 0
    assert rows[0]["closed_pct"] == 0
    assert rows[1]["opened_pct"] == 100


def test_a_window_with_no_activity_at_all_says_so_instead_of_drawing_zeros():
    """`_compute_trends` always returns a bucket per day, so the
    JavaScript's `if(daily.length)` was always true and a dead-quiet week
    drew a full chart of 2px stubs with nothing saying it was empty."""
    report = _report(trends={"daily": [
        {"date": "2026-10-05", "opened": 0, "closed": 0},
        {"date": "2026-10-06", "opened": 0, "closed": 0},
    ]})
    view = trend_view(report)
    assert view["measured"] is True
    assert view["any_activity"] is False

    html = _flat(render_summary(report))
    assert "No case was opened or closed on any day in this window" in html


def test_a_day_with_a_missing_count_is_not_a_day_with_none():
    """A bucket missing `opened` is not a bucket that measured zero."""
    report = _report(trends={"daily": [
        {"date": "2026-10-05", "closed": 1},
        {"date": "2026-10-06", "opened": 4, "closed": 3},
    ]})
    rows = trend_view(report)["rows"]
    assert rows[0]["measured"] is False
    assert rows[0]["opened_pct"] is None
    assert rows[1]["measured"] is True


def test_no_daily_buckets_at_all_is_distinguished_from_a_quiet_window():
    view = trend_view(_report(trends={"daily": []}))
    assert view["measured"] is False
    assert view["any_activity"] is False
    html = _flat(render_summary(_report(trends={"daily": []})))
    assert "no daily buckets" in html


def test_the_daily_bucket_labels_say_what_they_actually_cover():
    """`_compute_trends` buckets by `cutoff + i days`, not by calendar day.

    So the bar labelled 10-05 covers 10-05 14:00 to 10-06 14:00. The
    JavaScript printed `day.date.substring(5)` with nothing to say that.
    """
    html = _flat(render_summary(_report()))
    assert "24-hour window starting at the time the report was generated" in html


# ---------------------------------------------------------------------------
# Closure reasons
# ---------------------------------------------------------------------------


def test_closure_reasons_are_ordered_and_their_shares_sum_against_the_total():
    rows = closure_views(_report(cases={
        **_report()["cases"],
        "closure_reasons": {"true_positive": 1, "false_positive": 3},
    }))
    assert [r["reason"] for r in rows] == ["false positive", "true positive"]
    assert [r["pct"] for r in rows] == [75, 25]


def test_a_case_closed_with_no_reason_is_not_presented_as_a_category():
    """case_metrics maps a NULL closure_reason to the key "unspecified".

    The JavaScript rendered that as "Unspecified", which sits in the list
    looking like a disposition somebody chose.
    """
    rows = closure_views(_report(cases={
        **_report()["cases"], "closure_reasons": {"unspecified": 2},
    }))
    assert rows[0]["reason"] == "closed with no reason recorded"


def test_no_closure_reasons_is_not_an_empty_breakdown_shown_as_zero():
    assert closure_views(_report(cases={
        **_report()["cases"], "closure_reasons": {},
    })) == []
    html = _flat(render_summary(_report(cases={
        **_report()["cases"], "closure_reasons": {},
    })))
    assert "Closure Reasons" not in html


# ---------------------------------------------------------------------------
# Notable incidents: the SQLEnum column and the escaping
# ---------------------------------------------------------------------------


def test_a_case_status_renders_its_value_not_the_enum_member_repr():
    """AlertCase.status is SQLEnum(AlertCaseStatus), so a row read through
    the ORM carries the member. FastAPI serialised it by value for free;
    a template renders `str()`, which is "AlertCaseStatus.CLOSED"."""
    from ion.models.alert_triage import AlertCaseStatus

    report = _report(notable_incidents=[{
        "case_number": "CASE-1", "title": "Beacon", "severity": "critical",
        "status": AlertCaseStatus.CLOSED,
        "created_at": "2026-10-06T09:00:00+00:00",
    }])
    assert incident_views(report)[0]["status"] == AlertCaseStatus.CLOSED.value

    html = render_summary(report)
    assert "AlertCaseStatus." not in html
    assert AlertCaseStatus.CLOSED.value in html


def test_an_incident_with_no_severity_recorded_takes_no_severity_colour():
    """AlertCase.severity is nullable. The JavaScript printed `sev || '-'`
    and gave it badge-ghost, which was right; this keeps it right while
    saying which of the two it is."""
    report = _report(notable_incidents=[{
        "case_number": "CASE-2", "title": "t", "severity": None,
        "status": "open", "created_at": None,
    }])
    view = incident_views(report)[0]
    assert view["severity"] is None
    assert view["badge"] == "badge-ghost"

    html = _flat(render_summary(report))
    assert "not recorded" in html


def test_the_template_escapes_markup_instead_of_a_hand_rolled_esc():
    """Jinja autoescapes, so the 188 lines' `esc()` is retired. Asserted
    rather than assumed, because the whole point of deleting a sanitiser is
    that something else is doing the job."""
    report = _report(notable_incidents=[{
        "case_number": "CASE-3",
        "title": "<script>alert(1)</script>",
        "severity": "high", "status": "open", "created_at": None,
    }])
    html = render_summary(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_an_incident_timestamp_is_a_time_element_with_a_stated_fallback():
    report = _report(notable_incidents=[
        {"case_number": "A", "title": "a", "severity": "high",
         "status": "open", "created_at": "2026-10-06T09:00:00+00:00"},
        {"case_number": "B", "title": "b", "severity": "high",
         "status": "open", "created_at": None},
    ])
    html = render_summary(report)
    assert '<time datetime="2026-10-06T09:00:00+00:00"' in html
    assert "No date recorded" in html


# ---------------------------------------------------------------------------
# The Summary tab's Team Performance table
# ---------------------------------------------------------------------------


def test_the_summary_team_table_states_who_it_leaves_out():
    """`_team_metrics` keeps only analysts with `total_actions > 0`.

    So an analyst who closed cases but wrote nothing to the audit log is
    absent from a table headed "Team Performance", and their closures are
    absent with them. The JavaScript said nothing about it.
    """
    html = _flat(render_summary(_report()))
    assert "at least one audit-log action" in html


def test_a_summary_team_row_with_a_missing_count_is_not_zero():
    rows = summary_team_views(_report(team={"analysts": [
        {"username": "ana", "total_actions": 3},
    ]}))
    assert rows[0]["cases_closed"] is None
    assert rows[0]["total_actions"] == 3


# ---------------------------------------------------------------------------
# The Team tab
# ---------------------------------------------------------------------------


def test_an_analyst_with_no_dispositions_is_not_a_zero_percent_fp_rate():
    """The worst collapse on this page.

    analyst_efficiency_service emits `fp_rate: 0.0` when `tp + fp == 0`,
    which is not a measurement: the analyst made no threat/not-threat call.
    The JavaScript printed `a.fp_rate + '%'` unconditionally, so "0%" meant
    either a perfect record or no record, and in a board pack those read
    the same and mean opposite things. The payload still carries tp and fp,
    so the distinction is recoverable, and this recovers it.
    """
    metrics = _metrics(analysts=[{
        **_metrics()["analysts"][0],
        "true_positives": 0, "false_positives": 0, "fp_rate": 0.0,
    }])
    row = analyst_views(metrics)[0]
    assert row["dispositions"] == 0
    assert row["fp_measured"] is False

    html = _flat(render_team(metrics))
    # `>0.0%<` rather than `0.0%`, because a bar whose height really is zero
    # emits `height:0.0%` in its style attribute and that is not a figure.
    assert ">0.0%<" not in html
    # Bracketed, because the legend under the table quotes the same words.
    assert ">no disposition recorded<" in html


def test_an_analyst_with_a_real_zero_percent_fp_rate_still_reads_zero():
    """The other half of the pair, without which the test above passes on
    a template that never prints a rate at all."""
    metrics = _metrics(analysts=[{
        **_metrics()["analysts"][0],
        "true_positives": 4, "false_positives": 0, "fp_rate": 0.0,
    }])
    row = analyst_views(metrics)[0]
    assert row["dispositions"] == 4
    assert row["fp_measured"] is True
    html = _flat(render_team(metrics))
    assert ">0.0%<" in html
    assert ">no disposition recorded<" not in html


def test_an_analyst_with_no_closures_has_no_mttr_rather_than_zero_hours():
    metrics = _metrics(analysts=[{
        **_metrics()["analysts"][0], "avg_mttr_hours": None,
    }])
    assert analyst_views(metrics)[0]["avg_mttr"] is None
    assert "0h" not in _flat(render_team(metrics))


def test_an_unstated_fp_rate_basis_is_said_out_loud():
    """The JavaScript rendered the note only when the basis was exactly
    'of_dispositions', so a payload that stopped emitting the key dropped
    the explanation and left two different rates under one heading."""
    assert fp_basis_note(_metrics()) is not None
    assert "dispositions" in fp_basis_note(_metrics())

    metrics = _metrics(team_summary={})
    assert fp_basis_note(metrics) is None
    html = _flat(render_team(metrics))
    assert "did not state which denominator" in html


def test_an_hour_with_a_missing_count_is_not_an_hour_of_no_activity():
    """`(h.cases_closed||0) + (h.alerts_triaged||0)` is how a missing
    count becomes a measured quiet hour."""
    metrics = _metrics(hourly_activity=[
        {"hour": "2026-10-11T15:00:00", "cases_closed": 1},
        {"hour": "2026-10-11T16:00:00", "cases_closed": 2, "alerts_triaged": 2},
    ])
    rows = hourly_views(metrics)["rows"]
    assert rows[0]["measured"] is False
    assert rows[0]["total"] is None
    assert rows[0]["pct"] is None
    assert rows[1]["total"] == 4


def test_a_flat_24_hours_says_nothing_happened_rather_than_drawing_stubs():
    """`_hourly_activity` always returns 24 buckets, so the JavaScript's
    `if(hourly.length)` was always true and its `Math.max(...,2)` floor
    drew a full row of visible bars for a day with no work at all."""
    metrics = _metrics(hourly_activity=[
        {"hour": "2026-10-11T15:00:00", "cases_closed": 0, "alerts_triaged": 0},
        {"hour": "2026-10-11T16:00:00", "cases_closed": 0, "alerts_triaged": 0},
    ])
    view = hourly_views(metrics)
    assert view["measured"] is True
    assert view["any_activity"] is False
    assert [r["pct"] for r in view["rows"]] == [0, 0]

    html = _flat(render_team(metrics))
    assert "No case closure or alert triage was recorded in any of" in html


def test_the_hourly_chart_window_is_the_fixed_24_hours_the_service_measures():
    """`_hourly_activity` ignores `hours` entirely and always reads the last
    24 hours, while the table beside it covers the whole lookback. Two
    windows in one panel, and only one of them was labelled."""
    html = _flat(render_team(_metrics(), requested_hours=720))
    assert "last 24 hours" in html
    assert "168 hours" in html


def test_the_team_window_comes_from_the_payload_not_from_the_request():
    """The fragment clamps days*24 into the range the JSON endpoint
    accepts, so the window the reader gets can be shorter than the one the
    select asked for. The figure shown is the service's own."""
    view = team_window_view(_metrics(period_hours=720), 2160)
    assert view["hours"] == 720
    assert view["requested_hours"] == 2160
    assert view["matches"] is False

    html = _flat(render_team(_metrics(period_hours=720), requested_hours=2160))
    assert "You asked for 2160 hours" in html


def test_a_team_window_the_service_did_not_state_is_not_the_requested_one():
    metrics = _metrics()
    del metrics["period_hours"]
    view = team_window_view(metrics, 168)
    assert view["stated"] is False
    assert "did not state the window" in _flat(render_team(metrics))


def test_the_team_lookback_is_clamped_to_what_the_json_endpoint_accepts():
    """/api/analyst-efficiency/metrics declares hours ge=24 le=720, and the
    days select reaches 90 days = 2160 hours. Without the clamp the service
    is asked for a window its own API would reject with a 422."""
    assert team_hours(7) == 168
    assert team_hours(30) == TEAM_MAX_HOURS
    assert team_hours(90) == TEAM_MAX_HOURS
    assert team_hours(1) == 24


def test_the_team_tab_escapes_an_analyst_name():
    metrics = _metrics(analysts=[{
        **_metrics()["analysts"][0], "username": "<img src=x onerror=1>",
    }])
    html = render_team(metrics)
    assert "<img src=x" not in html
    assert "&lt;img" in html


# ---------------------------------------------------------------------------
# A failed read is not empty data
# ---------------------------------------------------------------------------


def test_the_failed_summary_fragment_prints_no_figure_at_all():
    html = _flat(render_summary_failed())
    assert "could not be computed" in html
    assert "not the same as a report of zeros" in html
    assert "stat-value" not in html
    assert ">0<" not in html


def test_the_failed_team_fragment_prints_no_figure_at_all():
    html = _flat(render_team_failed())
    assert "could not be computed" in html
    assert "ae-activity-bar" not in html
    assert "<table" not in html


def test_the_summary_route_renders_the_failed_fragment_when_the_service_raises(
    monkeypatch,
):
    """Rendering the template with failed=True proves the template. Only
    calling the route proves the route selects that state."""
    import ion.services.executive_report_service as svc
    from ion.web.ui.executive_report import executive_report_summary_fragment

    def _boom(session, days):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(svc, "generate_executive_report", _boom)
    response = executive_report_summary_fragment(
        request=_request("/ui/executive-report/summary"), days=7, session=None,
    )
    assert response.status_code == 200
    body = response.body.decode()
    assert "could not be computed" in body
    assert "stat-value" not in body


def test_the_team_route_renders_the_failed_fragment_when_the_service_raises(
    monkeypatch,
):
    import ion.services.analyst_efficiency_service as svc
    from ion.web.ui.executive_report import executive_report_team_fragment

    def _boom(session, hours):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(svc, "get_analyst_efficiency", _boom)
    response = executive_report_team_fragment(
        request=_request("/ui/executive-report/team"), days=7, session=None,
    )
    assert response.status_code == 200
    body = response.body.decode()
    assert "could not be computed" in body
    assert "<table" not in body


def test_the_summary_route_renders_the_real_payload_when_the_service_works(
    monkeypatch,
):
    """Positive control for both route tests above. Without it they pass
    against a route that always renders the failure branch."""
    import ion.services.executive_report_service as svc
    from ion.web.ui.executive_report import executive_report_summary_fragment

    monkeypatch.setattr(
        svc, "generate_executive_report", lambda session, days: _report()
    )
    response = executive_report_summary_fragment(
        request=_request("/ui/executive-report/summary"), days=7, session=None,
    )
    body = response.body.decode()
    assert "could not be computed" not in body
    assert "Cases Opened" in body


def test_the_team_route_asks_the_service_for_the_clamped_window(monkeypatch):
    """The route must not hand the service a window its own API rejects."""
    import ion.services.analyst_efficiency_service as svc
    from ion.web.ui.executive_report import executive_report_team_fragment

    seen: list[int] = []

    def _record(session, hours):
        seen.append(hours)
        return _metrics(period_hours=hours)

    monkeypatch.setattr(svc, "get_analyst_efficiency", _record)
    executive_report_team_fragment(
        request=_request("/ui/executive-report/team"), days=90, session=None,
    )
    assert seen == [TEAM_MAX_HOURS]


# ---------------------------------------------------------------------------
# Wiring: the fragments are not a softer way in than the APIs they mirror
# ---------------------------------------------------------------------------


def _dependency_calls(route) -> list:
    out, stack = [], list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _permissions(route) -> set[str]:
    found = set()
    for fn in _dependency_calls(route):
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        name = cells.get("permission_name")
        if name:
            found.add(name)
    return found


def _only(routes: list, suffix: str):
    matched = [r for r in routes if r.path.endswith(suffix)]
    assert len(matched) == 1, f"{suffix}: {[r.path for r in routes]}"
    return matched[0]


def test_the_summary_fragment_permission_matches_the_json_endpoint_exactly():
    """Read off both routers rather than asserting a literal, so the test
    fails if either side is changed and the other is not."""
    from ion.web.executive_report_api import router as api_router
    from ion.web.ui.executive_report import router as ui_router

    api = _only(list(api_router.routes), "/json")
    ui = _only(list(ui_router.routes), "/summary")
    assert _permissions(ui), "the fragment requires no permission at all"
    assert _permissions(ui) == _permissions(api)


def test_the_team_fragment_permission_matches_the_json_endpoint_exactly():
    from ion.web.analyst_efficiency_api import router as api_router
    from ion.web.ui.executive_report import router as ui_router

    api = _only(list(api_router.routes), "/metrics")
    ui = _only(list(ui_router.routes), "/team")
    assert _permissions(ui), "the fragment requires no permission at all"
    assert _permissions(ui) == _permissions(api)


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _inline_js() -> str:
    page = PAGE.read_text(encoding="utf-8")
    return "".join(
        m.group(1) for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page, re.S)
    )


def test_the_page_template_builds_no_markup_in_javascript():
    """The redesign's `server` column, asserted where the work was done.

    Counted inside inline `<script>` blocks only, the same way
    tools/ui_redesign_status.py measures it. A bare search of the file
    would hit `hx-swap="innerHTML"`, which is htmx being told where to put
    server-rendered HTML and is the opposite of the thing being removed.
    """
    writes = re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", _inline_js())
    assert writes == []


def test_the_page_keeps_no_hand_rolled_escaper_and_no_fetch():
    js = _inline_js()
    assert "function esc(" not in js
    assert "fetch(" not in js


def test_the_page_requests_both_fragments_over_htmx():
    page = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/executive-report/summary"' in page
    assert 'hx-get="/ui/executive-report/team"' in page
    assert "load" in _trigger_for(page, 'id="er-content"')


def _trigger_for(page: str, anchor: str) -> str:
    start = page.index(anchor)
    return re.search(r'hx-trigger="([^"]*)"', page[start:]).group(1)


def test_picking_a_window_regenerates_without_a_second_click():
    """The select carried `data-change-action="erLoad"`, so changing the
    window reloaded the report. Dropping that in the port would have been a
    silent regression: the figures would stay on the old window until
    somebody noticed the Generate button."""
    page = PAGE.read_text(encoding="utf-8")
    assert "change from:#er-days" in _trigger_for(page, 'id="er-content"')


def test_the_team_tab_is_still_lazy_and_still_refreshable():
    """Lazy, which is what `_erTeamLoaded` achieved, but not stale forever,
    which is what `_erTeamLoaded` also achieved: it never re-read the panel
    after a window change."""
    page = PAGE.read_text(encoding="utf-8")
    trigger = _trigger_for(page, 'id="er-team"')
    assert "load" not in trigger, trigger
    assert "click from:#er-tab-team" in trigger
    assert "click from:#er-generate" in trigger


def test_the_controls_sit_outside_the_swap_targets():
    """A control inside the fragment is removed by any render that omits
    it, so a failed read can take away the button that would retry. The
    swap targets are the last two divs and neither contains a control.
    """
    page = PAGE.read_text(encoding="utf-8")
    for anchor in ('id="er-content"', 'id="er-team"'):
        start = page.index(anchor)
        target = page[start:page.index("</div>", start)]
        assert "<button" not in target, anchor
        assert "<select" not in target, anchor
    assert 'id="er-days"' in page.split('id="er-content"')[0]
    assert 'id="er-generate"' in page.split('id="er-content"')[0]


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing. One converted
    page shipped a dead Enter key this way."""
    page = PAGE.read_text(encoding="utf-8")
    assert "hx-on" not in page
    assert "js:" not in page
    for attr in re.findall(r'hx-trigger="([^"]*)"', page):
        assert "[" not in attr, attr
        assert "]" not in attr, attr


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a 401 and a
    500 mean. A per-page listener is one copy per page of that decision."""
    js = _inline_js()
    assert "htmx:responseError" not in js
    assert "htmx:afterRequest" not in js
    assert "htmx:beforeSwap" not in js


@pytest.mark.parametrize("fragment", [SUMMARY_FRAGMENT, TEAM_FRAGMENT])
def test_each_fragment_template_exists(fragment):
    assert (Path(ion.web.__file__).parent / "templates" / fragment).exists()
