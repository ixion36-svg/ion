"""The detection-health fragments, and the honesty contract they carry.

detection_health.html built the whole body with four `innerHTML` writes fed
by 133 lines of inline JavaScript. What moved to Jinja is not only markup.
This table is what a detection engineer reads to decide whether to tune a
rule, switch it off, or leave it alone, and the three answers a rate cell
can give have to stay three:

  * a false-positive rate of 0 is a measurement and draws a bar at zero
    width,
  * a rate that could not be computed draws a dash and no bar,
  * a rate computed from fewer closures than the service needs before it
    will flag anything says so.

The JavaScript held the first two and had no notion of the third, so a 100%
false-positive rate from one closed alert was indistinguishable from one
measured over five hundred.

Every case below was watched failing against a mutated template or module
before it was made to pass. The mutations are in the scratchpad script
falsify_detection_health.py, which puts each guard back to its defective
form one at a time and checks the named test goes red.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.detection_health import (
    DISAGREEMENTS_FRAGMENT,
    FRAGMENT,
    PROPOSE_PERMISSION,
    READ_PERMISSION,
    SUMMARY_TILES,
    drill_url,
    fp_bands,
    is_sparse,
    rate_cell,
    rule_rows,
    stat_tiles,
    unmapped_note,
)

PAGE = Path(ion.web.__file__).parent / "templates" / "detection_health.html"

# The shape get_rule_disagreements really returns: AIFeedback.created_at is
# a naive DateTime column on both backends and the service hands back
# `c.isoformat()` of it, so what reaches this page is a zoneless string.
# This was a timezone-aware datetime, which the service cannot produce, and
# the assertions underneath it certified a localised render this page never
# performs. A fixture richer than production is a test that passes while the
# real path is broken.
CREATED = "2026-10-01T14:05:00"

# Kept only to assert that this page does not reach the localising branch.
CREATED_AWARE = datetime(2026, 10, 1, 14, 5, tzinfo=timezone.utc)


def _rule(**over: Any) -> dict[str, Any]:
    """One rule as get_detection_health emits it, with every field present.

    Non-zero and non-None throughout, so a test that wants one figure zeroed
    or absent changes exactly that one.
    """
    base: dict[str, Any] = {
        "rule_name": "Suspicious PowerShell",
        "volume": 120,
        "closed": 40,
        "tp_count": 8,
        "fp_count": 32,
        "fp_rate": 80.0,
        "tp_yield": 20.0,
        "bob_disagreement_rate": 12.5,
        "bob_scored": 16,
        "flags": {"silent": False, "noisy": True, "decaying": False},
        "flagged": True,
    }
    base.update(over)
    return base


def _payload(**over: Any) -> dict[str, Any]:
    """A payload shaped like get_detection_health's return."""
    base: dict[str, Any] = {
        "period_days": 90,
        "generated_at": "2026-10-12T10:00:00",
        "thresholds": {
            "lookback_days": 90,
            "min_sample": 5,
            "noisy_fp_pct": 70.0,
            "decay_delta_pct": 20.0,
            "benign_tp_as_fp": True,
        },
        "summary": {
            "rules_tracked": 1,
            "total_alerts": 120,
            "total_closed": 40,
            "silent_rules": 0,
            "noisy_rules": 1,
            "decaying_rules": 0,
            "unmapped_alerts": 0,
        },
        "rules": [_rule()],
    }
    base.update(over)
    return base


def _flat(html: str) -> str:
    """Whitespace-normalised, so an assertion does not encode the indenting."""
    return " ".join(html.split())


def render(payload: dict[str, Any], can_propose: bool = True) -> str:
    """Render through the real view builders, so a break in either fails."""
    env = make_templates().env
    summary = payload.get("summary") or {}
    return env.get_template(FRAGMENT).render(
        failed=False,
        tiles=stat_tiles(summary),
        rows=rule_rows(payload),
        period_days=payload.get("period_days"),
        min_sample=(payload.get("thresholds") or {}).get("min_sample"),
        unmapped=unmapped_note(summary),
        can_propose=can_propose,
    )


def render_failed(period_days: int = 90) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        failed=True, tiles=[], rows=None, period_days=period_days,
        min_sample=None, unmapped=None, can_propose=True,
    )


def render_drill(disagreements: list[dict[str, Any]],
                 rule: str = "Suspicious PowerShell",
                 failed: bool = False) -> str:
    env = make_templates().env
    return env.get_template(DISAGREEMENTS_FRAGMENT).render(
        failed=failed, rule=rule, disagreements=disagreements,
    )


_ROW = re.compile(r"<tr(?: [^>]*)?>(.*?)</tr>", re.S)

#: Header order of the rule table, so a cell is addressed by its column
#: rather than by "the string appears somewhere in the fragment".
COLUMNS = ("Rule", "Volume", "Closed", "FP rate", "TP yield",
           "Bob disagree", "Flags", "Propose")


def _cells(html: str, rule_name: str) -> list[str]:
    """The cells of the data row for this rule, whitespace-normalised.

    Addressed per row and per column because "a dash appears in the
    fragment" is true of a table with one dash in the right cell and of a
    table with eight in the wrong ones.
    """
    for match in _ROW.finditer(html):
        row = match.group(1)
        # The drill-down row that follows each data row has one cell; the
        # header row has none. Counting beats searching for "dh-drill",
        # which the data row also carries, on the button that opens it.
        if row.count("<td") < 2 or rule_name not in row:
            continue
        return [_flat(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
    raise AssertionError(f"no data row for {rule_name!r}")


def _cell(html: str, column: str, rule_name: str = "Suspicious PowerShell") -> str:
    return _cells(html, rule_name)[COLUMNS.index(column)]


def _tile(html: str, label: str) -> str:
    """The stat-value of the tile carrying this label."""
    pattern = (r'<div class="stat-title">\s*' + re.escape(label)
               + r'\s*</div>\s*<div class="stat-value ([^"]*)">(.*?)</div>')
    match = re.search(pattern, html, re.S)
    assert match, f"no tile for {label!r}"
    return _flat(match.group(1) + "|" + match.group(2))


def _inline_js(page: str) -> str:
    return "".join(
        m.group(1) for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page, re.S)
    )


def _js_code(page: str) -> str:
    """The inline JavaScript with its `//` comments removed.

    A comment naming what the conversion deleted is not the deleted thing,
    and this page's surviving script opens with a comment that names
    dhRender.
    """
    return re.sub(r"(?m)^\s*//.*$", "", _inline_js(page))


def _request(path: str = "/ui/detection-health/metrics") -> Request:
    return Request({"type": "http", "method": "GET", "path": path,
                    "headers": [], "query_string": b"", "app": None})


class _User:
    """Just enough User for the propose gate."""

    def __init__(self, *permissions: str) -> None:
        self._held = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self._held


# ---------------------------------------------------------------------------
# The rate cells: 0% and "could not be computed" point opposite ways
# ---------------------------------------------------------------------------


def test_a_zero_false_positive_rate_draws_a_bar_at_zero_width():
    """The case a truthiness port gets wrong in the dangerous direction.

    `{% if cell.value %}` is false for 0.0, so a rule measured over 40
    closures as never producing a false positive would render as a rule
    nobody could measure. Those are the opposite recommendation: leave it
    alone, versus go and find out why there is no feedback.
    """
    html = render(_payload(rules=[_rule(fp_rate=0.0, tp_yield=0.0)]))
    assert "width:0%" in _cell(html, "FP rate")
    assert ">0%<" in _cell(html, "FP rate")
    assert "&mdash;" not in _cell(html, "FP rate")
    assert "width:0%" in _cell(html, "TP yield")


def test_a_rate_that_could_not_be_computed_draws_a_dash_and_no_bar():
    """What the service returns for a rule with no closed alerts."""
    html = render(_payload(rules=[_rule(fp_rate=None, tp_yield=None,
                                        closed=0)]))
    assert _cell(html, "FP rate") == '<span class="opacity-50">&mdash;</span>'
    assert _cell(html, "TP yield") == '<span class="opacity-50">&mdash;</span>'
    assert "dh-bar" not in html


def test_rate_cell_keeps_zero_and_unmeasured_apart():
    bands = fp_bands(70.0)
    assert rate_cell(0.0, bands)["width"] == 0
    assert rate_cell(0.0, bands)["value"] == 0.0
    assert rate_cell(None, bands)["width"] is None
    assert rate_cell(None, bands)["value"] is None


def test_an_unmeasured_rate_cannot_be_painted_a_healthy_colour():
    """The colour function is total over None, so a template that lost its
    guard would paint an uncomputed rate in the resting colour rather than
    green."""
    assert rate_cell(None, fp_bands(70.0))["colour"] \
        == rate_cell(None, ((0.0, "var(--color-success)"),))["colour"] \
        == "var(--color-base-content)"


def test_a_rate_over_one_hundred_is_clamped_to_the_bar_but_printed_whole():
    cell = rate_cell(140.0, fp_bands(70.0))
    assert cell["width"] == 100
    assert cell["shown"] == 140


def test_a_whole_percentage_prints_without_a_decimal_point():
    """The service rounds to one decimal, so 70% arrives as 70.0. JSON made
    that a JavaScript 70; Python would print "70.0%" and a reader comparing
    the two pages should not have to decide whether the digits changed
    meaning."""
    assert rate_cell(70.0, fp_bands(70.0))["shown"] == 70
    assert rate_cell(33.3, fp_bands(70.0))["shown"] == 33.3


# ---------------------------------------------------------------------------
# The summary tiles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key,label,_e", SUMMARY_TILES)
def test_a_zero_count_tile_prints_zero_rather_than_unknown(key, label, _e):
    """Zero noisy rules is the state an engineer is working towards, so it
    is the one figure on this panel that must never read as missing."""
    html = render(_payload(summary={k: 0 for k, _l, _x in SUMMARY_TILES}))
    assert _tile(html, label).endswith("|0")
    assert "unknown" not in html


@pytest.mark.parametrize("key,label,_e", SUMMARY_TILES)
def test_a_count_the_summary_never_carried_says_unknown(key, label, _e):
    summary = {k: 3 for k, _l, _x in SUMMARY_TILES}
    del summary[key]
    html = render(_payload(summary=summary))
    assert "unknown" in _tile(html, label)
    assert "|0" not in _tile(html, label)


def test_a_zero_noisy_count_is_not_painted_as_an_alarm():
    html = render(_payload(summary={"noisy_rules": 0, "decaying_rules": 0,
                                    "silent_rules": 0}))
    assert _tile(html, "Noisy Rules") == "text-primary|0"
    assert "text-error" not in html


def test_a_non_zero_noisy_count_is_painted_as_an_alarm():
    html = render(_payload(summary={"noisy_rules": 2, "silent_rules": 1,
                                    "decaying_rules": 1}))
    assert _tile(html, "Noisy Rules") == "text-error|2"
    assert _tile(html, "Silent Rules") == "text-warning|1"


def test_an_unknown_count_is_not_painted_as_an_alarm_either():
    """`value is not none and value > 0`, in that order: a bare `> 0`
    against None raises, and a count nobody read is not an alarm."""
    tiles = stat_tiles({"noisy_rules": None})
    assert [t["colour"] for t in tiles if t["label"] == "Noisy Rules"] \
        == ["text-primary"]


# ---------------------------------------------------------------------------
# Counts on the row
# ---------------------------------------------------------------------------


def test_a_rule_that_fired_with_nothing_closed_prints_zero_closed():
    html = render(_payload(rules=[_rule(closed=0, fp_rate=None,
                                        tp_yield=None)]))
    assert _cell(html, "Closed") == "0"


def test_a_bob_disagreement_rate_of_zero_still_opens_the_drill_down():
    """0% disagreement is Bob agreeing every time, which is a result worth
    reading. The JavaScript tested `=== null` here and got this right."""
    html = render(_payload(rules=[_rule(bob_disagreement_rate=0.0)]))
    cell = _cell(html, "Bob disagree")
    assert ">0%</button>" in cell
    assert "&mdash;" not in cell


def test_a_rule_bob_never_scored_shows_a_dash_not_a_zero():
    html = render(_payload(rules=[_rule(bob_disagreement_rate=None,
                                        bob_scored=0)]))
    assert _cell(html, "Bob disagree") == '<span class="opacity-50">&mdash;</span>'
    assert "dh-drill-0" not in _cell(html, "Bob disagree")


# ---------------------------------------------------------------------------
# Too few closures to judge: the distinction the JavaScript did not make
# ---------------------------------------------------------------------------


def test_a_rule_under_the_minimum_sample_is_marked_low_sample():
    """The service evaluates noisy, silent and decaying only once a rule has
    min_sample closures, so under that line every flag is False by
    construction. An empty flags cell would read as "judged and clean"."""
    html = render(_payload(rules=[_rule(
        closed=2, fp_rate=100.0, tp_yield=0.0,
        flags={"silent": False, "noisy": False, "decaying": False},
        flagged=False,
    )]))
    cell = _cell(html, "Flags")
    assert "low sample" in cell
    assert "&mdash;" not in cell
    assert "Only 2 closed alert(s), under the 5" in _flat(html)


def test_a_rule_with_enough_closures_and_no_flags_keeps_the_dash():
    """Judged and clean is a different answer from not yet judged."""
    html = render(_payload(rules=[_rule(
        closed=40, fp_rate=10.0,
        flags={"silent": False, "noisy": False, "decaying": False},
        flagged=False,
    )]))
    assert _cell(html, "Flags") == '<span class="opacity-50">&mdash;</span>'
    assert "low sample" not in _cell(html, "Flags")


def test_a_flagged_rule_shows_its_badges_rather_than_the_sample_marker():
    html = render(_payload(rules=[_rule(closed=2, flags={
        "silent": True, "noisy": True, "decaying": False})]))
    cell = _cell(html, "Flags")
    assert "badge-error" in cell and "noisy" in cell
    assert "badge-warning" in cell and "silent" in cell
    assert "decaying" not in cell
    assert "low sample" not in cell


def test_is_sparse_needs_both_numbers():
    """An unknown denominator is not a claim that the sample was adequate,
    and it is not a claim that it was too small either."""
    assert is_sparse(2, 5) is True
    assert is_sparse(5, 5) is False
    assert is_sparse(0, 5) is True
    assert is_sparse(None, 5) is False
    assert is_sparse(2, None) is False


def test_the_sample_threshold_is_explained_under_the_table():
    html = _flat(render(_payload()))
    assert "only assessed once a rule has 5 closed alerts" in html


# ---------------------------------------------------------------------------
# Flags stay three-state
# ---------------------------------------------------------------------------


def test_only_a_flag_the_service_set_true_is_badged():
    """`flags.get(key) is true`, not truthiness: a flag the service left out
    is not a flag it cleared, and neither is a badge."""
    html = render(_payload(rules=[_rule(flags={"noisy": None,
                                               "silent": False})]))
    cell = _cell(html, "Flags")
    assert "badge-error" not in cell
    assert "badge-warning" not in cell


# ---------------------------------------------------------------------------
# The unmapped-alerts notice
# ---------------------------------------------------------------------------


def test_the_unmapped_notice_is_shown_when_there_are_unmapped_alerts():
    html = _flat(render(_payload(summary=dict(
        _payload()["summary"], unmapped_alerts=4))))
    assert "4 alert(s) lack a rule_name snapshot" in html


def test_the_unmapped_notice_is_suppressed_at_zero_and_when_absent():
    """A notice, not a measurement: "0 alerts lack a rule_name" is not
    something to tell anyone, and neither is a count that never arrived."""
    assert unmapped_note({"unmapped_alerts": 0}) is None
    assert unmapped_note({}) is None
    assert unmapped_note(None) is None
    assert "lack a rule_name" not in render(_payload())


# ---------------------------------------------------------------------------
# The false-positive band follows the service's own threshold
# ---------------------------------------------------------------------------


def test_the_red_band_moves_with_the_services_noisy_threshold():
    """The JavaScript hard-coded 70 while the service read
    ION_DH_NOISY_FP_PCT, so raising the threshold left rules painted red
    with no badge and lowering it left flagged rules painted in the resting
    colour. The bar and the badge now answer to one number."""
    strict = rule_rows(_payload(
        thresholds={"min_sample": 5, "noisy_fp_pct": 50.0},
        rules=[_rule(fp_rate=55.0)]))
    lax = rule_rows(_payload(
        thresholds={"min_sample": 5, "noisy_fp_pct": 90.0},
        rules=[_rule(fp_rate=55.0)]))
    assert strict[0]["fp"]["colour"] == "var(--color-error)"
    assert lax[0]["fp"]["colour"] == "var(--color-warning)"


def test_a_payload_without_thresholds_still_bands_and_does_not_raise():
    rows = rule_rows({"rules": [_rule(fp_rate=80.0)], "period_days": 30})
    assert rows[0]["fp"]["colour"] == "var(--color-error)"
    assert rows[0]["sparse"] is False


# ---------------------------------------------------------------------------
# A failed read is not empty data
# ---------------------------------------------------------------------------


def test_a_failed_read_says_so_and_prints_no_rate_at_all():
    html = _flat(render_failed())
    assert "could not be read" in html
    assert "not the same as an estate where every rule is behaving" in html
    assert "stat-value" not in html
    assert "dh-bar" not in html
    assert ">0<" not in html
    assert "Per-rule detection health" not in html


def test_the_failed_fragment_still_names_the_window_it_failed_on():
    """Chrome wraps both states. The heading's value has to exist when
    there is no payload, so the route passes the requested window."""
    assert "the last 7 days" in _flat(render_failed(period_days=7))


def test_the_route_renders_the_failed_fragment_when_the_read_raises(monkeypatch):
    """A read that fails must not reach the browser as a 500, which htmx
    does not swap, leaving the page's spinner turning as if it were still
    loading."""
    import ion.services.detection_health_service as service
    from ion.web.ui.detection_health import detection_health_metrics_fragment

    def _boom(session, days=None):
        raise RuntimeError("database gone")

    monkeypatch.setattr(service, "get_detection_health", _boom)
    response = detection_health_metrics_fragment(
        request=_request(), days=30, current_user=_User(READ_PERMISSION),
        session=None,
    )

    assert response.status_code == 200
    body = response.body.decode()
    assert "could not be read" in body
    assert "stat-value" not in body
    assert "the last 30 days" in body


@pytest.mark.parametrize("echoed,heading", [
    (7, "7d"),      # the service's own window wins
    (None, "30d"),  # no window echoed, so the request's is the fallback
    (0, "0d"),      # the case that separates `is None` from `or`
])
def test_the_heading_names_the_window_the_service_reported(
        monkeypatch, echoed, heading):
    """The service echoes the window it actually used, and that is what the
    heading has to name. The request's value is the fallback, reached with
    `is None` rather than a truthiness default.

    A window of 0 is not reachable today: `days` is bounded `ge=1` and the
    service echoes it back. So the third case is a guard rather than a fix,
    and it is here because it is the only input that tells `is None` apart
    from `or`, which means without it the guard could be weakened back to a
    truthiness default and nothing would notice.
    """
    import ion.services.detection_health_service as service
    from ion.web.ui.detection_health import detection_health_metrics_fragment

    monkeypatch.setattr(
        service, "get_detection_health",
        lambda session, days=None: _payload(period_days=echoed))
    body = detection_health_metrics_fragment(
        request=_request(), days=30, current_user=_User(READ_PERMISSION),
        session=None).body.decode()
    assert f"&middot; {heading})" in body


def test_a_failed_drill_down_is_not_a_record_of_agreement():
    html = _flat(render_drill([], failed=True))
    assert "could not be read" in html
    assert "No Bob-vs-analyst disagreements recorded" not in html


def test_the_drill_route_renders_the_failed_panel_when_the_read_raises(monkeypatch):
    import ion.services.detection_health_service as service
    from ion.web.ui.detection_health import (
        detection_health_disagreements_fragment,
    )

    def _boom(session, rule_name, days=None):
        raise RuntimeError("database gone")

    monkeypatch.setattr(service, "get_rule_disagreements", _boom)
    response = detection_health_disagreements_fragment(
        request=_request("/ui/detection-health/disagreements"),
        rule="Suspicious PowerShell", days=90, session=None,
    )

    assert response.status_code == 200
    body = response.body.decode()
    assert "could not be read" in body
    assert "disagreement(s)" not in body


# ---------------------------------------------------------------------------
# The drill-down panel, and the escape hatch it has to carry in every state
# ---------------------------------------------------------------------------


def test_the_drill_down_lists_the_disagreements():
    html = _flat(render_drill([
        {"alert_id": "alert-1", "bob_suggested_verdict": "false_positive",
         "human_verdict": "true_positive", "created_at": CREATED},
    ]))
    assert "<strong>1 disagreement(s)</strong>" in html
    assert "alert-1" in html
    assert "Bob said <em>false_positive</em>" in html
    assert "analyst closed <em>true_positive</em>" in html


@pytest.mark.parametrize("state", ["populated", "empty", "failed"])
def test_every_drill_down_state_carries_a_hide_control(state):
    """A panel that rendered empty or failed without a Hide would leave the
    row open with no way to close it but a page reload. Invisible in the
    template; it showed up when the panel was driven in a browser."""
    rows = [{"alert_id": "a", "bob_suggested_verdict": "b",
             "human_verdict": "c", "created_at": CREATED}]
    html = render_drill(
        rows if state == "populated" else [], failed=state == "failed")
    assert 'data-click-action="dhHide"' in html
    assert ">Hide</button>" in html


def test_an_empty_drill_down_says_nothing_was_recorded():
    html = _flat(render_drill([]))
    assert "No Bob-vs-analyst disagreements recorded for this rule." in html


def test_a_verdict_the_row_does_not_carry_is_not_printed_as_none():
    html = _flat(render_drill([
        {"alert_id": "alert-2", "bob_suggested_verdict": None,
         "human_verdict": None, "created_at": None},
    ]))
    assert ">None<" not in html
    assert "<em>nothing recorded</em>" in html


# ---------------------------------------------------------------------------
# The timestamp, which on this page is the server's clock and says so
# ---------------------------------------------------------------------------


def test_a_disagreement_timestamp_is_marked_as_server_time():
    """What this page can actually render.

    The feedback row's `created_at` is a naive column, so nothing records
    which zone its digits are in. Localising it would read those digits as
    the viewer's clock and convert out of a zone the value was never in,
    which is wrong by the viewer's offset while looking authoritative, so
    the macro declines and labels it instead.
    """
    html = render_drill([
        {"alert_id": "a", "bob_suggested_verdict": "b", "human_verdict": "c",
         "created_at": CREATED},
    ])
    assert '<time datetime="2026-10-01T14:05:00"' in html
    assert 'data-ts-local="no"' in html
    assert "stores no timezone" in _flat(html)


def test_this_page_never_reaches_the_localising_branch():
    """The guard on the fixture above.

    If the service ever starts returning an aware value, this goes red and
    whoever changed it has to decide what the page should say, rather than
    the page quietly switching clocks. The aware shape is asserted here to
    show the branch exists and that this page is not taking it.
    """
    aware = render_drill([
        {"alert_id": "a", "bob_suggested_verdict": "b", "human_verdict": "c",
         "created_at": CREATED_AWARE},
    ])
    assert 'data-ts-local="yes"' in aware, "the macro can localise"

    from ion.services import detection_health_service as svc
    source = Path(svc.__file__).read_text(encoding="utf-8")
    assert '"created_at": c.isoformat() if c else None' in source, (
        "get_rule_disagreements no longer returns the naive column's "
        "isoformat; re-check what data-ts-local the page now emits")


def test_a_disagreement_with_no_timestamp_does_not_render_the_epoch():
    html = _flat(render_drill([
        {"alert_id": "a", "bob_suggested_verdict": "b", "human_verdict": "c",
         "created_at": None},
    ]))
    assert "no timestamp" in html
    assert "1970" not in html
    assert "<time" not in html


# ---------------------------------------------------------------------------
# Escaping, which retires the hand-rolled dhEsc()
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    html = render(_payload(rules=[_rule(
        rule_name='<img src=x onerror=alert(1)>')]))
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html


def test_the_drill_down_escapes_the_three_fields_it_prints():
    html = render_drill([
        {"alert_id": "<script>alert(1)</script>",
         "bob_suggested_verdict": "<b>fp</b>",
         "human_verdict": "<i>tp</i>", "created_at": None},
    ], rule="<svg onload=alert(1)>")
    assert "<script>" not in html
    assert "<b>fp</b>" not in html
    assert "<svg onload" not in html
    assert "&lt;script&gt;" in html


def test_a_rule_name_with_a_quote_keeps_the_propose_button_intact():
    """The JavaScript interpolated the rule name into a JSON array inside a
    single-quoted `data-args` attribute, so a rule name containing a double
    quote produced invalid JSON and the button silently did nothing. The
    name now goes in its own data attribute, which Jinja escapes.
    """
    html = render(_payload(rules=[_rule(rule_name='say "hi"')]))
    assert 'data-rule="say &#34;hi&#34;"' in html
    assert "data-args" not in html


# ---------------------------------------------------------------------------
# The drill-down URL is built as one value
# ---------------------------------------------------------------------------


def test_the_drill_url_is_percent_encoded_and_carries_the_window():
    assert drill_url("Rule & Co", 30) == \
        "/ui/detection-health/disagreements?rule=Rule+%26+Co&days=30"
    assert drill_url("(unmapped)", None) == \
        "/ui/detection-health/disagreements?rule=%28unmapped%29"


def test_the_panel_disinherits_its_hx_include():
    """So the window in that URL is the one the request carries.

    htmx inherits hx-include, and every drill-down button is rendered
    inside #dh-content, which carries hx-include="#dh-days" for its own
    load. The button therefore sent the select's live value appended after
    its own baked one, measured in a browser as

        ?rule=probe&days=90&days=90

    and FastAPI reads the last of a duplicate, so the select was deciding
    the window rather than the row. The two agree today because every path
    that changes the select also re-renders the panel, which is why nothing
    looked wrong. hx-disinherit governs only what children inherit, so the
    panel's own request still sends the select, which the test below holds.
    """
    page = PAGE.read_text(encoding="utf-8")
    container = re.search(r"<div id=\"dh-content\"[^>]*>", page)
    assert container, "the panel container moved or was renamed"
    assert 'hx-disinherit="hx-include"' in container.group(0)


def test_the_panel_still_sends_the_window_on_its_own_request():
    """The other half. Dropping hx-include to stop the duplicate would mean
    a select the browser restored across a reload reporting one window
    while the panel was rendered for another."""
    page = PAGE.read_text(encoding="utf-8")
    container = re.search(r"<div id=\"dh-content\"[^>]*>", page)
    assert 'hx-include="#dh-days"' in container.group(0)


def test_the_rendered_drill_url_escapes_its_separator_once():
    """`{{ base }}&days={{ n }}` in template text emits the variable's
    ampersand escaped and the literal one bare. Built whole, there is one
    ampersand and it is escaped."""
    html = render(_payload(period_days=7, rules=[_rule(rule_name="a&b")]))
    assert "rule=a%26b&amp;days=7" in html
    assert "rule=a%26b&days=7" not in html


def test_the_drill_url_carries_the_window_the_panel_was_rendered_for():
    html = render(_payload(period_days=180))
    assert "days=180" in _cell(html, "Bob disagree")


# ---------------------------------------------------------------------------
# The propose button: the page's one mutation has its own permission
# ---------------------------------------------------------------------------


def test_the_propose_button_is_offered_only_to_a_reader_who_may_propose():
    """The POST is gated de:propose while the panel is gated security:read,
    so a reader can hold the read and not the write. A button whose POST is
    going to answer 403 is a worse answer than no button."""
    assert "Propose tuning" in render(_payload(), can_propose=True)
    assert "Propose tuning" not in render(_payload(), can_propose=False)


def test_the_table_keeps_its_shape_for_a_reader_who_cannot_propose():
    """The column stays so the table's shape does not depend on who is
    looking, which is also what keeps the drill row's colspan correct."""
    html = render(_payload(), can_propose=False)
    assert len(_cells(html, "Suspicious PowerShell")) == len(COLUMNS)
    assert 'colspan="8"' in html


def test_the_route_reads_the_propose_permission_off_the_user(monkeypatch):
    import ion.services.detection_health_service as service
    from ion.web.ui.detection_health import detection_health_metrics_fragment

    monkeypatch.setattr(service, "get_detection_health",
                        lambda session, days=None: _payload())
    without = detection_health_metrics_fragment(
        request=_request(), days=90, current_user=_User(READ_PERMISSION),
        session=None).body.decode()
    with_it = detection_health_metrics_fragment(
        request=_request(), days=90,
        current_user=_User(READ_PERMISSION, PROPOSE_PERMISSION),
        session=None).body.decode()

    assert "Propose tuning" not in without
    assert "Propose tuning" in with_it


# ---------------------------------------------------------------------------
# One definition: the fragments and the JSON endpoints read the same service
# ---------------------------------------------------------------------------


def test_the_fragment_renders_the_service_payload(monkeypatch):
    """Reuse asserted by observation, not by reading the import.

    The flag thresholds and the dedup contract live inside
    get_detection_health. A second copy in the fragment would keep flagging
    rules by the old threshold after ION_DH_NOISY_FP_PCT moved, and nothing
    on the page would look different.
    """
    import ion.services.detection_health_service as service
    from ion.web.ui.detection_health import detection_health_metrics_fragment

    seen: list[tuple[object, object]] = []

    def _fake(session, days=None):
        seen.append((session, days))
        return _payload(rules=[_rule(rule_name="SENTINEL-RULE")])

    monkeypatch.setattr(service, "get_detection_health", _fake)
    response = detection_health_metrics_fragment(
        request=_request(), days=180, current_user=_User(READ_PERMISSION),
        session="SENTINEL-SESSION")

    assert seen == [("SENTINEL-SESSION", 180)]
    assert "SENTINEL-RULE" in response.body.decode()


def test_the_drill_fragment_renders_the_service_payload(monkeypatch):
    import ion.services.detection_health_service as service
    from ion.web.ui.detection_health import (
        detection_health_disagreements_fragment,
    )

    seen: list[tuple[object, object, object]] = []

    def _fake(session, rule_name, days=None):
        seen.append((session, rule_name, days))
        return {"rule_name": rule_name, "disagreements": [
            {"alert_id": "SENTINEL-ALERT", "bob_suggested_verdict": "fp",
             "human_verdict": "tp", "created_at": None}]}

    monkeypatch.setattr(service, "get_rule_disagreements", _fake)
    response = detection_health_disagreements_fragment(
        request=_request("/ui/detection-health/disagreements"),
        rule="(unmapped)", days=7, session="SENTINEL-SESSION")

    assert seen == [("SENTINEL-SESSION", "(unmapped)", 7)]
    assert "SENTINEL-ALERT" in response.body.decode()


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
    """Every permission name a route's dependencies require.

    Both factories, not just one. This read only `require_permission`,
    which made the guard below blind to exactly the gate it exists to
    police: the tuning POST is declared
    `require_any_permission(["de:propose"])`, so a fragment gated the same
    way returned an empty set here and the assertion that no fragment is
    locked behind the write permission passed without looking at anything.
    A guard that cannot see the thing it forbids is worse than no guard,
    because it reports success.
    """
    found = set()
    for fn in _dependency_calls(route):
        base = getattr(fn, "__qualname__", "").split(".")[0]
        if base not in ("require_permission", "require_any_permission"):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        one = cells.get("permission_name")
        many = cells.get("permission_names")
        if isinstance(one, str):
            found.add(one)
        if isinstance(many, (list, tuple, set)):
            found.update(str(p) for p in many)
    return found


def test_the_permission_reader_sees_both_dependency_factories():
    """The guard on the helper above.

    Without this, the blindness that made
    test_no_fragment_is_gated_on_the_proposal_permission vacuous is
    reintroduced by a one-word edit and nothing goes red. Read off the real
    API router, which uses one factory for the reads and the other for the
    write, so this cannot drift from the thing it describes.
    """
    from ion.web.detection_health_api import router as api_router

    by_factory = {}
    for route in api_router.routes:
        for fn in _dependency_calls(route):
            base = getattr(fn, "__qualname__", "").split(".")[0]
            if base in ("require_permission", "require_any_permission"):
                by_factory.setdefault(base, set()).update(_permissions(route))

    assert set(by_factory) == {"require_permission", "require_any_permission"}, (
        "this page's API no longer uses both factories, so this test is no "
        "longer proving the helper handles both")
    assert PROPOSE_PERMISSION in by_factory["require_any_permission"]
    assert READ_PERMISSION in by_factory["require_permission"]


# The API router declares its own `/detection-health` prefix and is mounted
# under /api by server.py, so its route paths carry no /api here.
@pytest.mark.parametrize("api_path,ui_suffix", [
    ("/detection-health/metrics", "/metrics"),
    ("/detection-health/rules/{rule_name}/disagreements", "/disagreements"),
])
def test_the_fragment_permission_matches_the_json_endpoint_exactly(
        api_path, ui_suffix):
    """Read off both routers rather than asserting a literal, so the test
    fails if either side is changed and the other is not."""
    from ion.web.detection_health_api import router as api_router
    from ion.web.ui.detection_health import router as ui_router

    api = [r for r in api_router.routes if r.path == api_path]
    ui = [r for r in ui_router.routes if r.path.endswith(ui_suffix)]
    assert len(api) == 1 and len(ui) == 1

    assert _permissions(ui[0]), "the fragment requires no permission at all"
    assert _permissions(ui[0]) == _permissions(api[0]) == {READ_PERMISSION}


def test_no_fragment_is_gated_on_the_proposal_permission():
    """The three endpoints this page uses do not share one gate. Mirroring
    the POST's de:propose here would lock the read behind a write
    permission, and mirroring neither would open it."""
    from ion.web.ui.detection_health import router as ui_router

    for route in ui_router.routes:
        assert PROPOSE_PERMISSION not in _permissions(route), route.path


def test_the_fragments_do_not_use_a_redirecting_page_dependency():
    """require_page_permission redirects to /login when a session expires,
    and htmx would swap that login form into the middle of the table."""
    from ion.web.ui.detection_health import router as ui_router

    for route in ui_router.routes:
        for call in _dependency_calls(route):
            name = getattr(call, "__qualname__", "")
            assert "require_page_auth" not in name
            assert "require_page_permission" not in name


def test_the_module_exposes_mounted_routes():
    import ion.web.ui as ui

    mounted = {r.path for r in ui.router.routes}
    assert "/ui/detection-health/metrics" in mounted
    assert "/ui/detection-health/disagreements" in mounted


# ---------------------------------------------------------------------------
# The page: the redesign's `server` column, asserted where the work was done
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """Counted inside inline `<script>` blocks only, the same way
    tools/ui_redesign_status.py measures it. A bare search of the file would
    hit `hx-swap="innerHTML"`, which is htmx being told where to put
    server-rendered HTML and is the opposite of the thing being removed."""
    writes = re.findall(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=",
                        _inline_js(PAGE.read_text(encoding="utf-8")))
    assert writes == []


def test_the_page_holds_htmx_slots_rather_than_a_renderer():
    page = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/detection-health/metrics"' in page
    assert 'hx-trigger="load"' in page
    code = _js_code(page)
    for gone in ("dhRender", "dhEsc", "dhStat", "dhSlug", "dhPctCell",
                 "dhLoad", "dhDrill"):
        assert gone not in code, f"{gone} survived the conversion"


def test_the_page_controls_sit_outside_the_swap_target():
    """A window select or Refresh inside the fragment is removed by any
    render that does not include it, so a failed read would take away the
    control that retries."""
    page = PAGE.read_text(encoding="utf-8")
    slot = page.index('id="dh-content"')
    assert page.index('id="dh-days"') < slot
    assert page.index('id="dh-refresh"') < slot


def test_the_page_sends_the_window_with_the_first_paint_too():
    """Firefox restores a select's value across a reload, so without
    hx-include on the load trigger the first paint would report 90 days
    while the select read 7."""
    page = PAGE.read_text(encoding="utf-8")
    slot = page.index('id="dh-content"')
    assert 'hx-include="#dh-days"' in page[slot:slot + 400]


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed swap
    means. A per-page listener is one copy per page of a decision about what
    an expired session does."""
    code = _js_code(PAGE.read_text(encoding="utf-8"))
    assert "htmx:responseError" not in code
    assert "htmx:afterRequest" not in code
    assert "htmx:beforeSwap" not in code


def test_the_page_keeps_the_proposal_post_it_still_owns():
    """The one mutation stays a fetch, gated de:propose on the server."""
    js = _inline_js(PAGE.read_text(encoding="utf-8"))
    assert "'/tuning-proposal'" in js
    assert "dhSubmitProposal" in js
