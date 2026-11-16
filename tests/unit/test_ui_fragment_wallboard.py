"""The wallboard as a server-rendered fragment.

wallboard.html built the topology, the status lines, the bars and the
threat-landscape paragraph out of string concatenation and wrote them with
innerHTML and insertAdjacentHTML. Those are the cases below. Each one is a
number the JavaScript coerced with `|| 0`, a failed collector the service
returns as zeros plus an error, or a label the JSON encoder used to
stringify and a template will not.

The rows are fixtures rather than a live gather. get_snapshot also calls
Ollama, and an empty render proves nothing about the panels, which is all
that moved.
"""
from __future__ import annotations

import enum
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.templating import make_templates
from ion.web.ui.wallboard import (
    PERMISSION,
    fmt_age,
    fmt_n,
    present_snapshot,
    router,
    sparkline_paths,
)

FRAGMENT = "_fragments/wallboard.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/wallboard.html"


def render(**ctx: Any) -> str:
    return make_templates().env.get_template(FRAGMENT).render(**ctx)


def quiet() -> dict:
    """A measured estate where every zero was actually counted.

    Overrides replace one panel. A test that starts from a snapshot whose
    zeros were filled in by ``or {}`` cannot tell a measured zero from a
    hole, so this one has the keys the collectors write.
    """
    return {
        "cache_age_seconds": 0,
        "attention": {
            "level": "ok",
            "headline": "All clear — no critical or high-severity cases open",
            "open_critical": 0,
            "open_high": 0,
            "open_alert_backlog": 0,
        },
        "alerts": {
            "by_status": {"open": 0, "acknowledged": 0, "closed": 0},
            "last_24h_total": 0,
            "prev_24h_total": 0,
            "verdict_distribution_7d": {},
            "histogram_24h": [],
        },
        "cases": {
            "by_status": {"open": 0, "acknowledged": 0, "closed": 0},
            "open_by_severity": {},
            "closures_24h_total": 0,
            "closures_prev_24h_total": 0,
            "closures_history_7d": [],
        },
        "bob": {
            "investigations_24h": 0,
            "investigations_prev_24h": 0,
            "investigations_total": 0,
            "feedback_7d_total": 0,
            "agreement_pct": None,
            "agreement_count": 0,
            "agreement_total": 0,
            "history_7d": [],
        },
        "rules": {
            "total_rules": 0,
            "enabled_rules": 0,
            "severity": {},
            "quality": {"avg_quality": None},
            "covered_techniques": 0,
            "total_techniques": None,
            "tide_unavailable": False,
        },
        "topology": {"nodes": [], "counts": {"up": 0, "down": 0, "off": 0}},
        "threat_landscape": {
            "summary": None,
            "summary_kind": "stats",
            "stats": {
                "alerts_24h_total": 0,
                "severity_24h": {},
                "verdict_7d": {},
                "top_closures_7d": [],
                "open_backlog_sev": {},
            },
        },
        "org": {
            "headline": (
                "No establishment defined, so there is nothing to measure "
                "staffing against."
            ),
            "worst": [],
            "leads_gapped": 0,
            "pillars_total": 0,
            "pillars_uncovered": 0,
            "pillars_self_rated": 0,
            "pillars_measured": False,
            "duty": {"assigned": False, "user": None, "acknowledged": False},
            "duty_unfilled_weeks": 0,
            "duty_next_unfilled": None,
        },
    }


def draw(snapshot: dict) -> str:
    return render(**present_snapshot(snapshot))


def text_of(html: str, element_id: str) -> str:
    """The text of an element that contains no nested tags.

    A whole-document search is how a comment, a bar width of ``0%`` and a
    neighbouring panel all impersonate the assertion. The id is the panel.
    """
    match = re.search(rf'id="{element_id}"[^>]*>([^<]*)', html)
    assert match, f"{element_id} not in the render"
    return match.group(1).strip()


class _Status(enum.Enum):
    """A plain enum, not a str mixin.

    ``str(member)`` on 3.12 is ``_Status.OPEN``. FastAPI's JSON encoder
    would have written ``open``. ``plain`` is what puts that back, and a
    test whose member is a ``str`` enum passes even when plain is deleted,
    because ``str()`` already returned the value.
    """

    OPEN = "open"


class _Severity(enum.Enum):
    CRITICAL = "critical"


class _Node(enum.Enum):
    UP = "up"


# ---------------------------------------------------------------------------
# Numbers: zero is a measurement, None is not
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    (0, "0"),
    (0.0, "0"),
    (None, "—"),
    (True, "—"),
    (False, "—"),
    (1500, "1.5k"),
    (2000, "2k"),
    (999, "999"),
])
def test_fmt_n_keeps_zero_and_refuses_what_is_not_a_count(value, expected):
    """``fmtN`` returned an em dash for null and ``0`` for zero.

    ``True`` is the one a type check gets wrong: ``bool`` is an ``int``,
    so a helper that forgets the bool guard publishes a flag as the count 1.
    """
    assert fmt_n(value) == expected


def test_a_quiet_day_prints_zero_alerts_not_a_dash():
    """``{% if total %}`` renders a measured zero as the em dash."""
    assert text_of(draw(quiet()), "wb-alerts-24h") == "0"


def test_an_unmeasured_alert_total_is_a_dash_not_zero():
    """A missing key is not the zero the collector writes when it counted."""
    snap = quiet()
    del snap["alerts"]["last_24h_total"]
    assert text_of(draw(snap), "wb-alerts-24h") == "—"


def test_a_flat_delta_says_zero_and_a_missing_side_does_not():
    """``(curr || 0) - (prev || 0)`` turns "nobody counted yesterday" into
    "today is up by the whole of today's number". Both arrangements are in
    this test because a flat zero and an unknown delta look the same under
    that expression the moment today is also zero, so the unknown case has
    to be a non-zero today.

    The assertion is the alerts delta, not the document. Cases and Bob are
    still a measured flat zero in the unknown arrangement, and a search for
    ``±0`` across the board would fail a correct render for their sake."""
    assert text_of(draw(quiet()), "wb-alerts-delta") == "±0 vs prev 24h"
    snap = quiet()
    snap["alerts"]["last_24h_total"] = 5
    del snap["alerts"]["prev_24h_total"]
    html = draw(snap)
    assert text_of(html, "wb-alerts-delta") == "vs prev 24h not measured"
    assert "▲" not in text_of(html, "wb-alerts-delta")
    assert text_of(html, "wb-cases-delta") == "±0 vs prev 24h"
    assert text_of(html, "wb-bob-delta") == "±0 vs prev 24h"


def test_alert_growth_is_bad_and_closure_growth_is_good():
    """The same arrow is a different colour. Fewer alerts is the good
    direction and more closures is the good direction, and one flag copied
    onto both panels paints the wrong one green."""
    snap = quiet()
    snap["alerts"]["last_24h_total"] = 8
    snap["alerts"]["prev_24h_total"] = 6
    snap["cases"]["closures_24h_total"] = 8
    snap["cases"]["closures_prev_24h_total"] = 6
    html = draw(snap)
    assert 'text-ion-coral font-semibold tabular-nums">▲ 2' in html
    assert 'text-ion-lime font-semibold tabular-nums">▲ 2' in html


def test_an_agreement_of_zero_percent_is_printed():
    """``agreement_pct != null`` in the JavaScript. Zero resolved rows that
    all disagreed is a measured 0%, and ``{% if pct %}`` renders it as the
    em dash reserved for "no resolved feedback"."""
    snap = quiet()
    snap["bob"].update({
        "agreement_pct": 0, "agreement_count": 0, "agreement_total": 4,
    })
    assert text_of(draw(snap), "wb-bob-agreement-num") == "0 / 4 (0%)"


def test_an_unmeasured_agreement_is_not_zero_percent():
    """No resolved feedback is not a 0% agreement. The bar width is still
    empty, which is why this asserts the label and not the width: both
    states draw an empty bar, and only the label says which one it is."""
    assert text_of(draw(quiet()), "wb-bob-agreement-num") == "— / —"


def test_zero_enabled_rules_are_printed_when_tide_answered():
    snap = quiet()
    assert text_of(draw(snap), "wb-rules-enabled") == "0"


def test_a_quality_of_zero_is_printed():
    snap = quiet()
    snap["rules"]["quality"] = {"avg_quality": 0}
    assert text_of(draw(snap), "wb-rules-quality") == "0"


def test_a_missing_quality_is_a_dash():
    assert text_of(draw(quiet()), "wb-rules-quality") == "—"


def test_no_attack_catalogue_does_not_become_zero_over_zero():
    """TIDE 6 does not serve the catalogue. ``total_techniques`` stays
    None, and ``covered || 0`` next to it used to render ``0 / 0 (0%)``.
    A total of 0 is the same refusal: there is no denominator."""
    html = draw(quiet())
    assert "not reported" in html
    assert "0 / 0" not in html
    assert "(0%)" not in html

    snap = quiet()
    snap["rules"]["total_techniques"] = 0
    snap["rules"]["covered_techniques"] = 0
    html = draw(snap)
    assert "0 / 0" not in html
    assert "(0%)" not in html


def test_a_measured_coverage_of_zero_percent_is_printed():
    """The other side of the catalogue guard. Zero covered techniques out
    of a real catalogue is a measurement, and the guard that hides ``0 / 0``
    must not also hide it."""
    snap = quiet()
    snap["rules"]["covered_techniques"] = 0
    snap["rules"]["total_techniques"] = 100
    assert "0 / 100 (0%)" in draw(snap)


def test_an_unmeasured_covered_count_is_not_zero_over_the_catalogue():
    snap = quiet()
    snap["rules"]["covered_techniques"] = None
    snap["rules"]["total_techniques"] = 100
    html = draw(snap)
    assert "0 / 100" not in html
    assert "not reported" in html


def test_a_true_positive_rate_with_no_verdicts_is_not_zero_percent():
    assert text_of(draw(quiet()), "wb-tl-tp-rate") == "—"


def test_a_measured_true_positive_rate_of_zero_is_printed():
    snap = quiet()
    snap["threat_landscape"]["stats"]["verdict_7d"] = {"false_positive": 4}
    assert text_of(draw(snap), "wb-tl-tp-rate") == "0%"


def test_zero_critical_is_printed_on_a_warning_banner():
    """``open_critical || 0`` is how a missing count becomes zero, and
    ``{% if open_critical %}`` is how a counted zero becomes a dash. The
    value passed to the template is the number, because the string ``"0"``
    is truthy and would let the second bug pass."""
    snap = quiet()
    snap["attention"] = {
        "level": "warning",
        "headline": "3 high-severity cases open",
        "open_critical": 0,
        "open_high": 3,
        "open_alert_backlog": 1,
    }
    html = draw(snap)
    assert "0 critical" in html
    assert "3 high" in html
    assert "wb-panel-warning" in html
    assert "wb-panel-critical" not in html


def test_cache_age_zero_is_zero_seconds_and_a_missing_age_is_not_just_now():
    """The JavaScript treated null as "just now", which reads as a fresh
    gather. The service writes 0 when it just computed one."""
    assert fmt_age(0) == "0s ago"
    assert fmt_age(None) is None
    assert fmt_age(90) == "2m ago"
    assert "refreshed 0s ago" in draw(quiet())
    snap = quiet()
    del snap["cache_age_seconds"]
    assert "not measured" in draw(snap)
    assert "just now" not in draw(snap)


# ---------------------------------------------------------------------------
# A failed read is not an empty result
# ---------------------------------------------------------------------------


def test_a_failed_alert_read_does_not_render_the_zeroed_default():
    """The collector's failure shape is ``{last_24h_total: 0, error}``.
    Printing the 0 says the estate was quiet. The empty-verdict sentence
    is the same lie one level down."""
    snap = quiet()
    snap["alerts"] = {
        "error": "nope", "by_status": {}, "last_24h_total": 0,
        "verdict_distribution_7d": {},
    }
    html = draw(snap)
    assert "Alerts could not be read" in html
    assert "not zero alerts" in html
    assert "No verdicts captured" not in html
    assert "wb-alerts-24h" not in html


def test_a_failed_case_read_does_not_say_nothing_is_open():
    snap = quiet()
    snap["cases"] = {
        "error": "nope", "by_status": {}, "open_by_severity": {},
        "closures_24h_total": 0,
    }
    html = draw(snap)
    assert "Cases could not be read" in html
    assert "No open cases right now" not in html
    assert "wb-cases-open" not in html


def test_an_all_clear_computed_from_a_failed_case_read_is_not_shown():
    """``_compute_attention`` runs on the zeroed default, so a thrown case
    collector comes back as level ok and the headline "All clear". That is
    the banner telling the room there is no critical case when the cases
    were not counted."""
    snap = quiet()
    snap["cases"] = {"error": "nope", "by_status": {}, "open_by_severity": {}}
    html = draw(snap)
    assert "Attention state is unknown" in html
    assert "not an all-clear" in html
    assert "All clear" not in html
    assert "wb-att-ok" not in html
    assert "wb-panel-critical" not in html


def test_a_failed_rule_read_is_not_reported_as_tide_being_unconfigured():
    """The exception default sets ``tide_unavailable`` as well as ``error``,
    because the zeroed default already had the flag. Checking the flag
    first tells the wall TIDE is absent when the truth is that the read
    threw. The enabled count on that default is 0, which is the other lie."""
    snap = quiet()
    snap["rules"] = {
        "error": "boom", "tide_unavailable": True,
        "enabled_rules": 0, "total_rules": 0, "severity": {},
    }
    html = draw(snap)
    assert "Rule posture could not be read" in html
    assert "TIDE not configured" not in html
    assert text_of(html, "wb-rules-enabled") == "—"


def test_tide_unconfigured_is_its_own_state_and_not_a_zero():
    snap = quiet()
    snap["rules"] = {
        "tide_unavailable": True, "enabled_rules": 0, "total_rules": 0,
        "severity": {},
    }
    html = draw(snap)
    assert "TIDE not configured" in html
    assert "Rule posture could not be read" not in html
    assert text_of(html, "wb-rules-enabled") == "—"


@pytest.mark.parametrize("flag", [None, "no"])
def test_an_unreported_tide_flag_is_neither_configured_nor_zero(flag):
    """Three states. ``None`` does not distinguish ``is True`` from
    truthiness, so the non-boolean is the one that does: truthiness reads
    the string ``"no"`` as unconfigured, and ``is not False`` reads it as
    unconfigured too. Neither has been told that TIDE is down, and the
    enabled count sitting beside the flag is the zeroed default."""
    snap = quiet()
    snap["rules"]["tide_unavailable"] = flag
    snap["rules"]["enabled_rules"] = 0
    html = draw(snap)
    assert "TIDE not configured" not in html
    assert "was not reported" in html
    assert text_of(html, "wb-rules-enabled") == "—"


def test_a_failed_topology_does_not_say_nothing_is_up():
    snap = quiet()
    snap["topology"] = {"error": "nope", "nodes": [], "counts": {"up": 0, "down": 0, "off": 0}}
    html = draw(snap)
    assert "Platform topology could not be read" in html
    assert "0 up" not in html
    assert "could not be read" in text_of(html, "wb-topology-summary") or "could not be read" in html


def test_a_counted_zero_up_is_printed():
    assert text_of(draw(quiet()), "wb-top-up") == "0 up"


def test_an_omitted_topology_count_is_a_dash_not_zero():
    snap = quiet()
    snap["topology"]["counts"] = {}
    assert text_of(draw(snap), "wb-top-up") == "— up"


def test_a_verdict_distribution_that_was_not_read_is_not_an_empty_week():
    snap = quiet()
    snap["alerts"]["verdict_distribution_7d"] = None
    html = draw(snap)
    assert "No verdicts captured" not in html
    assert "not an empty list" in html

    snap = quiet()
    html = draw(snap)
    assert "No verdicts captured" in html
    assert "not an empty list" not in html


def test_a_severity_map_that_was_not_read_is_not_an_empty_map():
    snap = quiet()
    snap["rules"]["severity"] = None
    html = draw(snap)
    assert "No severity data captured" not in html
    assert "Severity could not be read" in html


def test_a_failed_org_read_does_not_say_nobody_is_on_duty():
    """The org default says assigned False, leads 0 and pillars unmeasured,
    which is exactly the "fully staffed, nobody on duty, capability
    unmeasured" picture a failed read must not draw."""
    snap = quiet()
    snap["org"] = {
        "error": "nope",
        "leads_gapped": 0,
        "pillars_measured": False,
        "duty_unfilled_weeks": 0,
        "headline": "Staffing unavailable.",
        "duty": {"assigned": False, "user": None, "acknowledged": False},
    }
    html = draw(snap)
    assert "Staffing could not be read" in html
    assert "Nobody on duty" not in html
    assert "capability unmeasured" not in html
    assert "with no lead" not in html
    assert "Staffing unavailable" not in html


def test_a_gather_failure_renders_no_zeros_and_does_not_call_the_age_fresh():
    """The no-cache failure is ``{error, cache_age_seconds: 0}``. Formatting
    that 0 says the board refreshed just now, which is the opposite of a
    gather that threw."""
    html = draw({"error": "gather failed", "cache_age_seconds": 0})
    assert "wallboard snapshot could not be read" in html
    assert "not measured" in html
    assert "0s ago" not in html
    assert "All clear" not in html
    assert "0 up" not in html
    assert "Nobody on duty" not in html
    assert "wb-alerts-24h" not in html


def test_a_stale_snapshot_keeps_the_old_numbers_and_says_they_are_old():
    """Showing the previous snapshot is honest. Replacing it with the
    failure card throws away the last thing that was actually counted, and
    showing it without the banner pretends the gather succeeded."""
    snap = quiet()
    snap["stale_due_to_error"] = "gather failed"
    snap["alerts"]["last_24h_total"] = 7
    snap["cache_age_seconds"] = 720
    html = draw(snap)
    assert "previous snapshot" in html
    assert text_of(html, "wb-alerts-24h") == "7"
    assert "were not counted" not in html
    assert "refreshed 12m ago" in html


# ---------------------------------------------------------------------------
# SQLEnum labels, escaping, and the topology geometry
# ---------------------------------------------------------------------------


def test_a_status_enum_counts_as_its_value_not_its_repr():
    """By-status keys are SQLEnum members until something unwraps them.
    ``str(_Status.OPEN)`` is ``_Status.OPEN``, which matches no status, so
    the open count falls through to the "other statuses were counted, this
    one is zero" branch and a status with 19 rows renders as 0."""
    snap = quiet()
    snap["alerts"]["by_status"] = {_Status.OPEN: 19, "acknowledged": 0, "closed": 1}
    html = draw(snap)
    assert text_of(html, "wb-alerts-open") == "19"
    assert "_Status" not in html


def test_a_severity_enum_fills_its_bar_instead_of_a_zero():
    snap = quiet()
    snap["cases"]["open_by_severity"] = {_Severity.CRITICAL: 17}
    html = draw(snap)
    assert "17" in html
    assert "_Severity" not in html
    assert "No open cases right now" not in html


def test_a_node_status_enum_picks_the_up_colour():
    """The colour map is keyed by the string. A member that was not
    unwrapped misses it and the node is painted "off", so a healthy
    service reads as not configured. The repr must not land in the SVG
    either, because the title tooltip is the status when details are empty."""
    snap = quiet()
    snap["topology"]["nodes"] = [{
        "key": "elasticsearch", "label": "Elasticsearch",
        "status": _Node.UP, "details": "",
    }]
    snap["topology"]["counts"] = {"up": 1, "down": 0, "off": 0}
    html = draw(snap)
    assert "rgb(134,240,160)" in html
    assert "_Node" not in html


def test_a_down_node_is_dashed_and_a_single_node_sits_at_the_top():
    """The angle is ``-pi/2`` plus a share of the circle, so one node is
    the top of the ellipse: x 230, y 35. Movement between refreshes reads
    as instability, which is why the position is fixed rather than laid out
    by the template."""
    snap = quiet()
    snap["topology"]["nodes"] = [{
        "key": "tide", "label": "TIDE", "status": "down", "details": "refused",
    }]
    html = draw(snap)
    assert 'cx="230.0"' in html or 'x2="230.0"' in html
    assert 'y2="35.0"' in html
    assert 'stroke-dasharray="4 3"' in html
    assert "wb-pulse-down" in html


def test_a_zero_count_is_a_point_on_the_sparkline():
    """Dropping falsy buckets deletes a quiet hour and, once only one
    bucket is left, hides the line. Two zero buckets are a flat line, not
    an absent one."""
    assert sparkline_paths([{"count": 0}, {"count": None}]) is None
    assert sparkline_paths([{"count": 0}]) is None
    flat = sparkline_paths([{"count": 0}, {"count": 0}])
    assert flat is not None and flat["line"] == "M2.0,48.0 L158.0,48.0"
    rising = sparkline_paths([{"count": 0}, {"count": 10}])
    assert rising is not None and rising["line"] == "M2.0,48.0 L158.0,6.0"

    snap = quiet()
    snap["alerts"]["histogram_24h"] = [{"count": 0}, {"count": 10}]
    assert 'd="M2.0,48.0 L158.0,6.0"' in draw(snap)


def test_jinja_escapes_what_eschtml_used_to():
    """The summary, the bullets, the node label and the duty name are all
    text an operator or a model supplied. The JavaScript ran them through
    escHtml. The template has to escape them, and a ``|safe`` would not."""
    snap = quiet()
    snap["threat_landscape"]["summary"] = (
        "Lead <script>alert(1)</script>\n- <img src=x onerror=1>"
    )
    snap["threat_landscape"]["summary_kind"] = "ai"
    snap["topology"]["nodes"] = [{
        "key": "ollama", "label": "<svg onload=1>", "status": "up",
        "details": "javascript:alert(1)",
    }]
    snap["org"]["duty"] = {
        "assigned": True,
        "user": {"name": "<script>alert(2)</script>"},
        "acknowledged": True,
    }
    html = draw(snap)
    assert "<script>alert(1)</script>" not in html
    assert "<script>alert(2)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "<svg onload=1>" not in html
    # A stored string that happens to be a URL is tooltip text. It is not
    # a link, so a javascript: scheme in it must not become one.
    assert 'href="javascript:' not in html


def test_a_closure_reason_is_escaped_in_the_stats_fallback():
    snap = quiet()
    snap["threat_landscape"]["stats"]["top_closures_7d"] = [
        {"reason": "<script>alert(3)</script>", "count": 2},
    ]
    html = draw(snap)
    assert "<script>alert(3)</script>" not in html
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in html


# ---------------------------------------------------------------------------
# People: three-state flags, and a zero that means "don't show the badge"
# ---------------------------------------------------------------------------


def test_nobody_on_duty_is_said_when_the_rota_says_so():
    assert "Nobody on duty this week" in draw(quiet())


def test_an_assigned_duty_with_no_name_is_not_nobody():
    snap = quiet()
    snap["org"]["duty"] = {"assigned": True, "user": None, "acknowledged": True}
    html = draw(snap)
    assert "Duty could not be read" in html
    assert "Nobody on duty" not in html


@pytest.mark.parametrize("ack,expected,forbidden", [
    (True, "Ada on duty", "not acknowledged"),
    (False, "not acknowledged", "not recorded"),
    (None, "acknowledgement not recorded", "not acknowledged"),
    ("no", "acknowledgement not recorded", "not acknowledged"),
])
def test_acknowledgement_stays_three_states(ack, expected, forbidden):
    """``{% if not ack %}`` warns on None as well as False, and stays quiet
    for the string ``"no"`` because that string is truthy. ``is not true``
    warns on all three. Only ``is false`` warns on False alone, and the
    other two have to say the acknowledgement was not a yes or a no.

    ``"not acknowledged"`` is not a substring of ``"not recorded"``, which
    is the only reason the forbidden check can be a substring at all.
    """
    snap = quiet()
    snap["org"]["duty"] = {
        "assigned": True, "user": {"name": "Ada"}, "acknowledged": ack,
    }
    html = draw(snap)
    assert expected in text_of(html, "wb-org-duty")
    assert forbidden not in text_of(html, "wb-org-duty")


def test_zero_lead_gaps_draw_no_badge_and_an_unknown_count_does():
    """Hiding the badge is the right rendering of a measured zero and the
    wrong rendering of a count that was never read. The two fixtures differ
    only by whether the key was set."""
    assert "with no lead" not in draw(quiet())
    assert "leads unknown" not in draw(quiet())
    snap = quiet()
    del snap["org"]["leads_gapped"]
    assert "leads unknown" in draw(snap)


@pytest.mark.parametrize("measured,present,absent", [
    (False, "capability unmeasured", "capability unknown"),
    (None, "capability unknown", "unmeasured"),
    ("no", "capability unknown", "unmeasured"),
])
def test_pillar_measurement_stays_three_states(measured, present, absent):
    """``{% if not measured %}`` says unmeasured for None, and for the
    string ``"no"`` falls into the measured branch, which then hides the
    badge because uncovered and self-rated are both zero. The badge has to
    be there, and it has to say the measurement was not a boolean."""
    snap = quiet()
    snap["org"]["pillars_measured"] = measured
    snap["org"]["pillars_uncovered"] = 0
    snap["org"]["pillars_self_rated"] = 0
    html = draw(snap)
    assert present in html
    assert absent not in html


def test_zero_uncovered_pillars_and_zero_self_rated_draw_no_badge():
    """A measured, fully covered, not-merely-self-rated estate is the
    state the JavaScript hid. Painting "0 uncovered" would be a badge that
    reads as a problem."""
    snap = quiet()
    snap["org"]["pillars_measured"] = True
    snap["org"]["pillars_uncovered"] = 0
    snap["org"]["pillars_self_rated"] = 0
    snap["org"]["pillars_total"] = 4
    html = draw(snap)
    assert "pillars uncovered" not in html
    assert "self-rated" not in html
    assert "unmeasured" not in html
    assert "capability unknown" not in html


def test_uncovered_pillars_name_the_count():
    snap = quiet()
    snap["org"]["pillars_measured"] = True
    snap["org"]["pillars_uncovered"] = 2
    snap["org"]["pillars_total"] = 5
    assert "2 of 5 pillars uncovered" in draw(snap)


def test_the_next_unfilled_week_is_a_date_and_not_a_midnight():
    """``duty_next_unfilled`` is a date. Parsing it as a datetime would
    invent 00:00, and a missing one must not become the epoch."""
    snap = quiet()
    snap["org"]["duty_unfilled_weeks"] = 2
    snap["org"]["duty_next_unfilled"] = "2026-10-19"
    html = draw(snap)
    assert 'datetime="2026-10-19"' in html
    assert "2026-10-19 00:00" not in html
    assert "1970" not in html


def test_an_unmeasured_rota_does_not_say_zero_weeks():
    snap = quiet()
    del snap["org"]["duty_unfilled_weeks"]
    html = draw(snap)
    assert "rota ahead not measured" in html
    assert "0 week" not in html


# ---------------------------------------------------------------------------
# The gates
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
    from ion.web.wallboard_api import router as wallboard_router

    for route in wallboard_router.routes:
        if route.path == "/api/wallboard/snapshot" and "GET" in route.methods:
            return route
    raise AssertionError("GET /api/wallboard/snapshot not found")


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """Read out of the JSON route's dependency, not restated. fragment_plan
    reports the same cell: require_permission('alert:read')."""
    assert PERMISSION == "alert:read"
    assert _permission_of(_json_route()) == PERMISSION
    assert _permission_of(_fragment_route()) == PERMISSION


def test_the_fragment_does_not_add_a_licence_gate_the_api_does_not_have():
    """Wallboard is not a detection-engineering page. Its router is mounted
    with no require_de_module, and the live app gates the snapshot on
    alert:read alone. Adding the module gate would 404 the board on a
    deployment that is not licensed for that module, which is a board the
    API still serves. If the API ever grows the gate, this fails on the
    JSON side first, which is the point of comparing the two."""
    assert "require_de_module" not in _dependency_names(_json_route())
    assert "require_de_module" not in _dependency_names(_fragment_route())
    assert "require_page_permission" not in _dependency_names(_fragment_route())


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "wall-tester"

    def has_permission(self, _name):
        return True


class _NoPerm:
    id = 2
    username = "no-perm"

    def has_permission(self, _name):
        return False


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


def test_the_route_renders_the_snapshot_it_was_given(app, session, monkeypatch):
    """The fragment and GET /api/wallboard/snapshot share get_snapshot, and
    the fragment does not force a recompute. Forcing would make every wall
    skip the cache the JSON GET is careful to use."""
    seen = {}

    def fake(db, force=False):
        seen["session"] = db
        seen["force"] = force
        snap = quiet()
        snap["alerts"]["last_24h_total"] = 42
        return snap

    monkeypatch.setattr("ion.services.wallboard_service.get_snapshot", fake)
    with TestClient(app) as client:
        resp = client.get("/ui/wallboard")
    assert resp.status_code == 200
    assert text_of(resp.text, "wb-alerts-24h") == "42"
    assert seen["session"] is session
    assert seen["force"] is False


def test_a_raised_gather_is_a_failure_fragment_and_not_the_exception(app, monkeypatch):
    """200, because htmx does not swap a 500 and the wall would keep the
    spinner. The exception text stays in the log: a wall is a bad place to
    print a traceback."""
    def boom(_session, force=False):
        raise RuntimeError("queue-marker-secret")

    monkeypatch.setattr("ion.services.wallboard_service.get_snapshot", boom)
    with TestClient(app) as client:
        resp = client.get("/ui/wallboard")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "queue-marker-secret" not in resp.text
    assert "0 up" not in resp.text


def test_unauthenticated_is_401_not_a_rendered_board(session):
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_db_session] = lambda: session
    with TestClient(application) as client:
        resp = client.get("/ui/wallboard")
    assert resp.status_code == 401


def test_a_user_without_alert_read_gets_403_and_no_snapshot(session, monkeypatch):
    """The route body must not run. A fragment that forgot the permission
    and kept only get_current_user would render the board for anyone logged
    in, which is softer than the API."""
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    called = {"yes": False}

    def fake(*_a, **_k):
        called["yes"] = True
        return quiet()

    monkeypatch.setattr("ion.services.wallboard_service.get_snapshot", fake)
    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _NoPerm()
    application.dependency_overrides[get_db_session] = lambda: session
    with TestClient(application) as client:
        resp = client.get("/ui/wallboard")
    assert resp.status_code == 403
    assert called["yes"] is False


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _script(src: str) -> str:
    return "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))


def test_the_page_builds_no_markup_in_javascript():
    """The server column, measured the way tools/ui_redesign_status.py does.
    Scoped to inline scripts: hx-swap="innerHTML" is htmx's instruction for
    where to put the fragment, which is the opposite of the thing removed."""
    src = PAGE.read_text(encoding="utf-8")
    js = _script(src)
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js)


def test_the_poll_lives_on_the_shell_element_and_not_in_a_comment():
    """A substring over the whole file stays green when the attribute moves
    into the comment that names it. The trigger has to be on #wb-content,
    because that element's contents are what a failed render replaces and
    its attributes are not."""
    src = PAGE.read_text(encoding="utf-8")
    tag = re.search(r'<div id="wb-content"[^>]*>', src).group(0)
    assert 'hx-get="/ui/wallboard"' in tag
    assert 'hx-trigger="load, every 300s"' in tag
    assert 'hx-swap="innerHTML"' in tag
    fragment = (ROOT / "src/ion/web/templates" / FRAGMENT).read_text(encoding="utf-8")
    assert "hx-trigger" not in fragment
    assert "<script" not in fragment


def test_the_clock_sits_outside_the_swap_target():
    """The clock ticks every second. Inside the swap it would be replaced
    on every poll, and a failed render would remove it."""
    src = PAGE.read_text(encoding="utf-8")
    assert src.index('id="wb-clock-time"') < src.index('id="wb-content"')


def test_the_string_building_and_the_refresh_loop_are_gone():
    src = PAGE.read_text(encoding="utf-8")
    assert "function escHtml(" not in src
    assert "function refresh(" not in src
    assert "function renderAlerts(" not in src
    assert "function renderTopology(" not in src
    assert "insertAdjacentHTML" not in src


def test_the_page_writes_no_failure_handler_of_its_own():
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src
    assert "hx-on:" not in src
    assert "key==" not in src


def test_the_page_is_still_standalone():
    """wallboard does not extend base.html. A sweep that assumes it does
    would drop the attention CSS this page carries itself."""
    first = PAGE.read_text(encoding="utf-8").splitlines()[0]
    assert "{% extends" not in first
