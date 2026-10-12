"""The DE Workbench's five regions as server-rendered fragments.

de_workbench.html fetched five endpoints and wrote four innerHTML sites from
string concatenation. Each test below names the defect it catches, and the
arrangement is chosen so the defect is reachable: a three-state test that only
arranges None proves nothing, because None behaves the same under `is true`,
truthiness and `is not none`.

Nothing here asserts a substring over the page or the module *source*. A
page-level substring assertion passes on a comment, and these conversions carry
a lot of comments that quote what they removed. Everything is asserted against
rendered output, and the page's own "no innerHTML left" guard strips HTML
comments first and matches an assignment rather than the bare word, because
`hx-swap="innerHTML"` appears nine times on the page by design.

The failure tests call the route with its read stubbed rather than rendering
the template with `failed=True`. The second shape proves the markup and never
that the route picks that state, which is the part that was wrong in the
JavaScript: `r.ok ? r.json() : { requests: [] }` had markup that was fine and
a selection that lied.
"""
from __future__ import annotations

import asyncio
import enum
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.licensing import gating
from ion.models.detection_proposal import (
    DetectionProposal,
    DetectionProposalSource,
    DetectionProposalStatus,
)
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.models.tuning_request import (
    TUNING_REQUEST_REASONS,
    TUNING_REQUEST_STATUSES,
    TuningRequest,
)
from ion.web.templating import make_templates
from ion.web.ui import de_workbench as mod

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "src/ion/web/templates"
PAGE = TEMPLATES / "de_workbench.html"
SERVER = ROOT / "src/ion/web/server.py"

REGIONS = ("requests", "campaigns", "proposals", "quirks", "content-pack")
#: Which KPI tile each region owns. A region painting another's tile, or two
#: regions fighting over one, is a figure that disagrees with the panel under
#: it, which is the whole reason the tile travels with its own read.
TILES = {
    "requests": "kpi-requests",
    "campaigns": "kpi-hours",
    "proposals": "kpi-proposals",
    "quirks": "kpi-quirks",
}


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def flat(text: str) -> str:
    """Whitespace collapsed, because the templates wrap their sentences.

    A prose assertion against a wrapped template looks for a phrase that
    arrives with a newline inside it and fails for a reason that has nothing
    to do with the page.
    """
    return re.sub(r"\s+", " ", text)


def render(name: str, **ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(f"_fragments/de_workbench_{name}.html").render(**ctx)


#: The request table's columns, in order. A whole-fragment substring
#: assertion on a figure hits the KPI tile above the table as readily as the
#: cell it meant, so every per-cell assertion goes through `cell()`.
REQUEST_COLUMNS = ("rule", "reason", "details", "waiting", "fp", "ticket",
                   "status", "actions")


def cell(html: str, column: str, row: int = 0) -> str:
    """One cell of the rendered request table, by column name."""
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S)
    body = [r for r in rows if "<td" in r]
    assert body, "no body rows rendered, so this proves nothing"
    cells = re.findall(r"<td[^>]*>(.*?)</td>", body[row], re.S)
    assert len(cells) == len(REQUEST_COLUMNS), cells
    return flat(cells[REQUEST_COLUMNS.index(column)]).strip()


CAMPAIGN_COLUMNS = ("rule", "fp_alerts", "hours", "actions")


def campaign_cell(html: str, column: str, row: int = 0) -> str:
    """One cell of the rendered campaign table, by column name.

    The KPI tile above the table carries an hours figure of its own, so
    `">0h<" in html` is satisfied by the tile whatever the cell says. A
    mutation pass found exactly that: weakening the cell's gate left the test
    green because it had been reading the tile all along.
    """
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S)
    body = [r for r in rows if "<td" in r]
    assert body, "no campaign rows rendered, so this proves nothing"
    cells = re.findall(r"<td[^>]*>(.*?)</td>", body[row], re.S)
    assert len(cells) == len(CAMPAIGN_COLUMNS), cells
    return flat(cells[CAMPAIGN_COLUMNS.index(column)]).strip()


def tile(html: str, slot: str) -> str:
    """One out-of-band KPI tile's text, so a tile assertion cannot read a
    table cell and a cell assertion cannot read a tile."""
    match = re.search(
        rf'id="{slot}" hx-swap-oob="true">(.*?)\n</div>', html, re.S
    )
    assert match, f"no {slot} tile rendered, so this proves nothing"
    return flat(re.sub(r"<[^>]+>", " ", match.group(1)))


# ---------------------------------------------------------------------------
# Fixtures for a direct render, so a table is tested with rows in it
# ---------------------------------------------------------------------------


def request_row(**over: Any) -> dict:
    base: dict[str, Any] = {
        "id": 7,
        "rule_name": "Suspicious PowerShell",
        "reason": "false_positive",
        "details": "fires on every signed binary",
        "evidence_json": {"fp_alerts_7d": 4},
        "status": "open",
        "gitlab_issue_iid": 11,
        "gitlab_issue_url": "https://gitlab.example.com/x/-/issues/11",
        "created_at": (now() - timedelta(days=2)).isoformat(),
    }
    base.update(over)
    return base


def requests_view(rows: Optional[list] = None, *, can_propose: bool = True) -> dict:
    if rows is None:
        rows = [request_row()]
    return mod._requests_view({"requests": rows}, can_propose=can_propose)


def campaign_payload(**summary: Any) -> dict:
    base = {"addressable_hours": 12.0, "campaign_count": 2}
    base.update(summary)
    return {
        "summary": base,
        "campaigns": [
            {"rule_name": "Noisy Rule", "fp_alerts": 40, "cost_hours": 6.0},
        ],
    }


def proposal(**over: Any) -> dict:
    base: dict[str, Any] = {
        "id": 3,
        "rule_name": "Noisy Rule",
        "title": "Exclude the updater",
        "change_type": "exclusion",
        "status": DetectionProposalStatus.DRAFT.value,
        "expected_fp_reduction": 55.0,
        "expected_hours_reclaimed": 3.0,
        "mitre_techniques": [],
        "source": DetectionProposalSource.HUMAN.value,
        "outcome": None,
        "applied_at": None,
    }
    base.update(over)
    return base


def quirk(**over: Any) -> dict:
    base: dict[str, Any] = {
        "id": 5,
        "title": "Backup agent",
        "status": SystemQuirkStatus.ACTIVE.value,
        "expired": False,
        "review_date": (now() + timedelta(days=3)).isoformat(),
        "scope_rules": [],
        "scope_hosts": [],
        "scope_users": [],
        "scope_ips": [],
        "scope_observables": [],
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Numbers. A measured zero is the finding; `|| 0` and truthiness both lose it
# ---------------------------------------------------------------------------


def test_a_request_with_zero_false_positives_this_week_shows_the_zero():
    """Defect: `{% if r.fp_7d_text %}` renders the measured 0 as a dash.

    Zero FP closures in the last seven days is the interesting measurement on
    this row: the noise the analyst complained about has already stopped, so
    the request may not need a proposal at all. The arrangement is a real 0
    rather than a missing key, which is what makes truthiness and
    `is not none` disagree.
    """
    html = render("requests", failed=False, view=requests_view(
        [request_row(evidence_json={"fp_alerts_7d": 0})]
    ))
    assert cell(html, "fp") == "0"


def test_a_request_with_no_evidence_shows_a_dash_not_a_zero():
    """The other half of the pair, and what makes the test above non-vacuous.

    Defect: `.get('fp_alerts_7d', 0)`. Nobody collected the figure, and
    printing 0 says the noise stopped.
    """
    html = render("requests", failed=False, view=requests_view(
        [request_row(evidence_json={})]
    ))
    assert cell(html, "fp") == '<span class="opacity-60">—</span>'


def test_a_non_numeric_evidence_value_is_not_printed_as_a_figure():
    """Defect: a bool or a string in the evidence column rendering as a count.
    `True` must not read as 1 alert, and a string must not reach the cell."""
    for bad in (True, "many", None, [4]):
        html = render("requests", failed=False, view=requests_view(
            [request_row(evidence_json={"fp_alerts_7d": bad})]
        ))
        assert cell(html, "fp") == '<span class="opacity-60">—</span>', bad


def test_zero_addressable_hours_is_not_the_same_as_unmeasured():
    """Defect: `s.addressable_hours || 0`, which printed a confident 0 for a
    summary that never carried the figure. A measured 0 means the false
    positives in this window cost nothing worth reclaiming; a missing one
    means nobody measured, and on this page the first reads as "this estate
    has no noise"."""
    measured = render("campaigns", failed=False, days=30, can_propose=False,
                      view=mod._campaigns_view(campaign_payload(addressable_hours=0)))
    assert "0h" in tile(measured, "kpi-hours")
    assert "—" not in tile(measured, "kpi-hours")

    unknown = render("campaigns", failed=False, days=30, can_propose=False,
                     view=mod._campaigns_view({"summary": {}, "campaigns": []}))
    assert "0h" not in tile(unknown, "kpi-hours")
    assert "—" in tile(unknown, "kpi-hours")


def test_zero_campaigns_and_an_unknown_count_read_differently():
    """Defect: `campaign_count != null ? ... : '?'` ported as `|| 0`. The
    count is what says whether the hours above it mean anything."""
    measured = render("campaigns", failed=False, days=30, can_propose=False,
                      view=mod._campaigns_view(campaign_payload(campaign_count=0)))
    assert "across 0 campaigns" in tile(measured, "kpi-hours")

    unknown = render("campaigns", failed=False, days=30, can_propose=False,
                     view=mod._campaigns_view(campaign_payload(campaign_count=None)))
    assert "campaign count unknown" in tile(unknown, "kpi-hours")
    assert "across" not in tile(unknown, "kpi-hours")


def test_a_campaign_with_no_cost_does_not_render_the_word_null():
    """Defect, and a live one: `'' + c.cost_hours + 'h'` on a missing value
    produced the literal text "nullh" in the Hours column. The same for
    fp_alerts."""
    view = mod._campaigns_view({
        "summary": {"addressable_hours": 1, "campaign_count": 1},
        "campaigns": [{"rule_name": "Blank Rule", "fp_alerts": None,
                       "cost_hours": None}],
    })
    html = render("campaigns", failed=False, days=30, can_propose=False, view=view)
    assert "null" not in html
    assert "None" not in html
    assert campaign_cell(html, "rule") == "Blank Rule"
    assert campaign_cell(html, "hours") == '<span class="opacity-60">—</span>'
    assert campaign_cell(html, "fp_alerts") == '<span class="opacity-60">—</span>'


def test_a_measured_cost_of_zero_still_prints_zero():
    """What stops the test above being satisfied by hiding every number.

    Asserted on the cells, not on the fragment: the KPI tile above the table
    carries an hours figure too, and `">0h<" in html` was satisfied by the
    tile while the cell rendered a dash. A mutation pass found that.
    """
    view = mod._campaigns_view({
        "summary": {"addressable_hours": 7, "campaign_count": 1},
        "campaigns": [{"rule_name": "Free Rule", "fp_alerts": 0,
                       "cost_hours": 0.0}],
    })
    html = render("campaigns", failed=False, days=30, can_propose=False, view=view)
    assert campaign_cell(html, "hours") == "0h"
    assert campaign_cell(html, "fp_alerts") == "0"


def test_an_expected_reduction_of_zero_is_shown():
    """Defect: `p.expected_fp_reduction != null` ported as truthiness. A
    proposal forecast to change nothing is a forecast somebody made."""
    view = mod._proposals_view([proposal(expected_fp_reduction=0.0)])
    html = render("proposals", failed=False, view=view)
    assert "exp. −0% FP" in html


def test_a_proposal_with_no_forecast_says_nothing_rather_than_zero():
    """The pair for the test above."""
    view = mod._proposals_view([proposal(expected_fp_reduction=None)])
    html = render("proposals", failed=False, view=view)
    assert "exp." not in html


# ---------------------------------------------------------------------------
# The proposal card's measurement, which the JavaScript could not reach
# ---------------------------------------------------------------------------


def _applied(**outcome: Any) -> dict:
    return proposal(
        status=DetectionProposalStatus.APPLIED.value,
        applied_at=(now() - timedelta(days=20)).isoformat(),
        outcome=outcome or None,
    )


def test_an_applied_proposal_quotes_the_comparable_drop_not_the_uneven_one():
    """Two defects at once.

    The JavaScript read `p.outcome_json.fp_reduction_pct`. `to_dict()` emits
    the column as `outcome` and nothing in ION writes `fp_reduction_pct`, so
    that branch was unreachable and an applied proposal with a real
    measurement showed its forecast labelled "exp." instead.

    And the figure quoted is the equal-window `comparable.drop_pct`, never the
    top-level `drop_pct`, which divides a full baseline by however little time
    has passed. The arrangement makes the two disagree, 90 against 91, so
    quoting the wrong one fails here.
    """
    view = mod._proposals_view([_applied(
        drop_pct=91.0,
        comparable={"drop_pct": 90.0, "sufficient_observation": True,
                    "before_count": 120, "after_count": 12,
                    "window_days_exact": 14.0, "reason": ""},
    )])
    html = render("proposals", failed=False, view=view)
    assert "measured −90% FP" in html
    assert "91" not in html


def test_an_applied_but_unmeasured_proposal_says_so():
    """Defect: an applied proposal with no outcome showing only its forecast,
    which reads as a result."""
    view = mod._proposals_view([_applied()])
    html = render("proposals", failed=False, view=view)
    assert "not yet measured" in html
    assert "measured −" not in html


def test_a_short_window_and_no_baseline_are_different_sentences():
    """Defect: folding every unquotable outcome into one word. A window too
    short to judge and a window long enough with nothing to divide by lead to
    different actions: wait, versus stop waiting."""
    short = mod._proposals_view([_applied(
        comparable={"drop_pct": None, "sufficient_observation": False,
                    "before_count": 10, "after_count": 1,
                    "window_days_exact": 1.0, "reason": "too soon"},
    )])
    none_to_divide = mod._proposals_view([_applied(
        comparable={"drop_pct": None, "sufficient_observation": True,
                    "before_count": 0, "after_count": 0,
                    "window_days_exact": 30.0, "reason": "no baseline"},
    )])
    unjudged = mod._proposals_view([_applied(
        comparable={"drop_pct": 40.0, "before_count": 10, "after_count": 6,
                    "window_days_exact": 30.0, "reason": ""},
    )])
    assert "not enough observation yet" in render("proposals", failed=False, view=short)
    assert "no baseline to quote" in render(
        "proposals", failed=False, view=none_to_divide
    )
    # sufficient_observation absent, so neither true nor false. No percentage
    # is quoted, including the one sitting on the row.
    judged = render("proposals", failed=False, view=unjudged)
    assert "comparable window not judged" in judged
    assert "40" not in judged


def test_a_measured_drop_of_zero_is_quoted():
    """Defect: truthiness on the drop. A tuning change measured to have
    changed nothing is the result worth reading."""
    view = mod._proposals_view([_applied(
        comparable={"drop_pct": 0.0, "sufficient_observation": True,
                    "before_count": 10, "after_count": 10,
                    "window_days_exact": 30.0, "reason": ""},
    )])
    assert "measured −0% FP" in render("proposals", failed=False, view=view)


def test_the_board_counts_before_it_slices():
    """Defect: a column heading reporting what fits rather than what exists.
    Six applied proposals show four, and the heading must still say six."""
    applied = [_applied() for _ in range(6)]
    view = mod._proposals_view(applied)
    assert view["applied_count"] == 6
    assert len(view["applied"]) == mod.APPLIED_SHOWN
    html = flat(render("proposals", failed=False, view=view))
    assert "Applied · measuring (6)" in html
    assert "and 2 more on the full board" in html


def test_the_in_flight_count_is_draft_plus_applied_unsliced():
    view = mod._proposals_view(
        [proposal() for _ in range(3)] + [_applied() for _ in range(6)]
    )
    assert view["in_flight"] == 9
    assert ">9</div>" in render("proposals", failed=False, view=view)


def test_a_proposal_with_no_rule_falls_back_to_its_title():
    """The JavaScript's `p.rule_name || p.title`, and never the word None."""
    view = mod._proposals_view([proposal(rule_name=None, title="Narrow it")])
    html = render("proposals", failed=False, view=view)
    assert "Narrow it" in html
    assert "None" not in html


# ---------------------------------------------------------------------------
# Quirks: three states, and a distance the JavaScript could not express
# ---------------------------------------------------------------------------


def test_an_unreported_expiry_flag_does_not_render_as_overdue():
    """Defect: `bool(row['expired'])` instead of `is True`.

    Three states kept at three. A quirk whose expiry nobody computed is not a
    quirk known to have lapsed, and "overdue" is what sends somebody to review
    it. The arrangement includes a truthy non-boolean, because None behaves
    identically under truthiness and `is True` and so proves nothing on its
    own.
    """
    for flag in ("no", 1, [], None, "false"):
        view = mod._quirks_view([quirk(expired=flag)])
        html = render("quirks", failed=False, view=view)
        assert "overdue" not in html, flag
        assert "out" in html, flag


def test_a_real_expiry_flag_does_render_as_overdue():
    """Positive control. Without it the test above passes on a template that
    never renders the badge at all."""
    view = mod._quirks_view([quirk(
        expired=True, review_date=(now() - timedelta(days=2)).isoformat()
    )])
    assert "overdue" in render("quirks", failed=False, view=view)


def test_three_different_distances_read_as_three_different_things():
    """Defect, and a live one: `ageOf()` on a future date divided a negative
    interval, failed its `>= 1` test, and `Math.max(1, ...)` floored the
    result, so every quirk not yet due read "review 1h". A review due in six
    days and one due in two hours were the same word.

    The offsets carry a half-unit of slack on purpose. The view reads its own
    clock a moment after this test reads its, so an interval sitting exactly
    on a unit boundary would land either side of it depending on how long the
    render took, and the assertion would be about scheduling rather than about
    the label.
    """
    view = mod._quirks_view([
        quirk(id=1, title="soon",
              review_date=(now() + timedelta(hours=2, minutes=30)).isoformat()),
        quirk(id=2, title="later",
              review_date=(now() + timedelta(days=6, hours=12)).isoformat()),
        quirk(id=3, title="lapsed", expired=True,
              review_date=(now() - timedelta(days=1)).isoformat()),
    ])
    labels = [r["due_text"] for r in view["rows"]]
    assert labels == [None, "2h out", "6d out"]
    html = render("quirks", failed=False, view=view)
    assert "overdue" in html
    assert "2h out" in html
    assert "6d out" in html


def test_the_distance_wording_rounds_down_so_it_is_never_late():
    """`_due_text` on exact intervals, with no clock in the way.

    Rounding down understates the distance, so a review reads as due sooner
    than it is rather than later. For a deadline that is the safe direction,
    and it is the same direction `_age_text` rounds a wait.
    """
    assert mod._due_text(timedelta(days=6, hours=23)) == "6d out"
    assert mod._due_text(timedelta(days=1)) == "1d out"
    assert mod._due_text(timedelta(hours=23, minutes=59)) == "23h out"
    assert mod._due_text(timedelta(hours=1)) == "1h out"
    assert mod._due_text(timedelta(minutes=59)) == "<1h out"
    assert mod._due_text(timedelta(seconds=0)) == "due now"
    assert mod._due_text(timedelta(seconds=-10)) == "due now"


def test_a_quirk_outside_the_window_is_not_due_and_not_counted():
    view = mod._quirks_view([
        quirk(id=1, review_date=(now() + timedelta(days=3)).isoformat()),
        quirk(id=2, review_date=(now() + timedelta(days=30)).isoformat()),
    ])
    assert view["due_count"] == 1
    assert view["active_count"] == 2
    assert "of 2 active" in flat(render("quirks", failed=False, view=view))


def test_a_quirk_with_no_review_date_is_not_due():
    """Defect: a missing review date sorting as the epoch and reading as
    overdue. The register requires one, so an absent value is a row from
    before that rule or one that could not be parsed, and neither is a review
    somebody has to do this week."""
    view = mod._quirks_view([quirk(review_date=None), quirk(id=6, review_date="")])
    assert view["due_count"] == 0
    assert view["active_count"] == 2


def test_the_due_list_is_soonest_first():
    view = mod._quirks_view([
        quirk(id=1, title="in-five", review_date=(now() + timedelta(days=5)).isoformat()),
        quirk(id=2, title="in-one", review_date=(now() + timedelta(days=1)).isoformat()),
    ])
    assert [r["title"] for r in view["rows"]] == ["in-one", "in-five"]


# ---------------------------------------------------------------------------
# The request queue's own rules
# ---------------------------------------------------------------------------


def test_a_closed_request_is_out_of_the_queue_and_out_of_the_count():
    view = requests_view([request_row(id=1, status="open"),
                          request_row(id=2, status="closed",
                                      rule_name="Closed Rule")])
    assert view["count"] == 1
    assert "Closed Rule" not in render("requests", failed=False, view=view)


def test_the_oldest_age_comes_from_the_oldest_instant_not_the_longest_string():
    """Defect: sorting the age text rather than the instant.

    The pair has to be one where the two orders disagree. "9h" against "10d"
    does not: "10d" sorts first as a string and is also the older row, so
    sorting the text gives the right answer by luck and the mutant survives.
    "10h" against "2d" does disagree, because "1" sorts before "2".
    """
    view = requests_view([
        request_row(id=1, created_at=(now() - timedelta(hours=10)).isoformat()),
        request_row(id=2, created_at=(now() - timedelta(days=2)).isoformat()),
    ])
    assert sorted(r["age_text"] for r in view["rows"]) == ["10h", "2d"]
    assert view["oldest_text"] == "oldest 2d"


def test_a_request_with_no_timestamp_is_not_aged_from_the_epoch():
    """Defect, and a live one: `Math.max.apply(null, ...)` over
    `new Date(null)` measured the wait from 1970 and the tile read
    "oldest 20700d"."""
    view = requests_view([request_row(created_at=None)])
    assert view["rows"][0]["age_text"] is None
    assert view["oldest_text"] == "age unknown"
    html = render("requests", failed=False, view=view)
    assert "unknown" in cell(html, "waiting")
    assert "no timestamp" in cell(html, "waiting")
    assert "1970" not in html
    assert not re.search(r"\d+d", cell(html, "waiting"))


def test_an_empty_queue_says_clear_and_a_dateless_one_does_not():
    assert requests_view([])["oldest_text"] == "queue clear"
    assert requests_view([request_row(created_at=None)])["oldest_text"] != "queue clear"


def test_a_wait_under_an_hour_is_not_rounded_up_to_an_hour():
    """Defect, and a live one: `Math.max(1, Math.round(d * 24))` floored
    everything newer than 90 minutes at "1h", so a request raised a minute
    ago and one raised an hour ago were indistinguishable."""
    view = requests_view([
        request_row(id=1, created_at=(now() - timedelta(minutes=5)).isoformat()),
        request_row(id=2, created_at=(now() - timedelta(hours=3)).isoformat()),
    ])
    assert [r["age_text"] for r in view["rows"]] == ["<1h", "3h"]


def test_a_reason_outside_the_vocabulary_shows_the_raw_value():
    """The JavaScript's `REASON_LABELS[r.reason] || r.reason`. An unlabelled
    reason is still why the request was raised; blanking it hides that."""
    view = requests_view([request_row(reason="brand_new_reason")])
    assert "brand_new_reason" in render("requests", failed=False, view=view)


def test_a_known_reason_shows_its_label():
    view = requests_view([request_row(reason="false_positive")])
    assert "False positive" in render("requests", failed=False, view=view)


def test_the_details_cell_is_clipped_and_an_empty_one_is_not_blank():
    long = "x" * 400
    view = requests_view([request_row(details=long), request_row(id=8, details=None)])
    html = render("requests", failed=False, view=view)
    assert "x" * mod.DETAILS_CHARS in html
    assert "x" * (mod.DETAILS_CHARS + 1) not in html
    assert view["rows"][1]["details"] is None


# ---------------------------------------------------------------------------
# The tables are pinned to the vocabularies they claim to cover
# ---------------------------------------------------------------------------


def test_every_reason_the_model_allows_has_a_label():
    """A reason added to the model and not here renders its raw key. Keyed by
    the model's own tuple so that is a failure rather than a surprise in a
    cell."""
    assert set(mod.REASON_LABELS) == set(TUNING_REQUEST_REASONS)


def test_every_status_the_model_allows_has_an_action_list_and_a_pill():
    """A status added to the model and not here is a row that silently offers
    nothing and wears the fallback pill."""
    assert set(mod.REQUEST_ACTIONS) == set(TUNING_REQUEST_STATUSES)
    assert set(mod.REQUEST_STATUS_CSS) == set(TUNING_REQUEST_STATUSES)


def test_the_action_table_offers_only_what_the_service_accepts(session):
    """Derived from de_tuning_request_service, checked against it.

    The service states its rules as inline refusals, so there is no constant
    to import the way investigation_queue imports CANCELLABLE_STATUSES. This
    drives the real service on a real session instead: triage must be offered
    exactly where triage_request does not raise, and close exactly where
    close_request does not.
    """
    from ion.services import de_tuning_request_service as svc

    class _User:
        id = 1
        username = "t"

    def accepts(call, status) -> bool:
        row = TuningRequest(rule_name="r", reason="other", status=status)
        session.add(row)
        session.commit()
        try:
            asyncio.run(call(session, _User(), row))
            return True
        except ValueError:
            return False

    for status in TUNING_REQUEST_STATUSES:
        offered = {a["label"] for a in mod.REQUEST_ACTIONS[status]}
        assert accepts(svc.triage_request, status) == ("Triage" in offered), status
        assert accepts(
            lambda s, u, r: svc.close_request(s, u, r, "done"), status
        ) == ("Close" in offered), status


# ---------------------------------------------------------------------------
# Action buttons are withheld, not merely refused on click
# ---------------------------------------------------------------------------


def test_a_reader_without_the_write_permission_is_offered_no_request_buttons():
    """Defect: the JavaScript rendered Triage, Draft and Close for every
    reader, so the only way to learn the POST would answer 403 was to click
    it. The three writes behind them are all de:propose."""
    html = render("requests", failed=False,
                  view=requests_view(can_propose=False))
    assert "data-click-action" not in html
    assert "Triage" not in html


def test_a_reader_with_the_write_permission_is_offered_them():
    """Positive control, so the test above is not passing on a table that
    renders no buttons at all."""
    html = render("requests", failed=False, view=requests_view(can_propose=True))
    assert 'data-click-action="dwTriage"' in html
    assert 'data-click-action="dwClose"' in html
    assert 'data-click-action="dwDraftForRequest"' in html


def test_a_request_with_no_id_is_offered_no_buttons():
    """A delegated handler called with a null id posts to
    /api/de/tuning-requests/null. An id of 0 is still an id, so the test in
    the template is `is not none`."""
    html = render("requests", failed=False,
                  view=requests_view([request_row(id=None)]))
    assert "data-click-action" not in html


def test_the_campaign_draft_button_needs_the_write_permission_and_a_rule():
    hidden = render("campaigns", failed=False, days=30, can_propose=False,
                    view=mod._campaigns_view(campaign_payload()))
    shown = render("campaigns", failed=False, days=30, can_propose=True,
                   view=mod._campaigns_view(campaign_payload()))
    assert "dwDraftForRule" not in hidden
    assert 'data-click-action="dwDraftForRule"' in shown

    nameless = render("campaigns", failed=False, days=30, can_propose=True,
                      view=mod._campaigns_view({
                          "summary": {"addressable_hours": 1, "campaign_count": 1},
                          "campaigns": [{"rule_name": None, "fp_alerts": 1,
                                         "cost_hours": 1.0}],
                      }))
    assert "dwDraftForRule" not in nameless


def test_the_import_control_needs_the_write_permission():
    """POST /api/de/content-pack/import is de:propose. /de renders its page
    with no user in the context, which is the whole reason this region is a
    fragment at all."""
    hidden = render("content_pack", can_propose=False)
    shown = render("content_pack", can_propose=True)
    assert "dwImportPack" not in hidden
    assert "de:propose" in hidden
    assert 'data-click-action="dwImportPack"' in shown
    # Export is a read, gated the same as this fragment, so it is always there.
    for html in (hidden, shown):
        assert "/api/de/content-pack/export" in html


# ---------------------------------------------------------------------------
# Escaping, enum unwrapping, and stored URLs
# ---------------------------------------------------------------------------


PAYLOAD = "<script>alert(1)</script>"


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """The hand-rolled `esc()` is deleted, so this is what replaces it.

    Asserted on rendered output in every region that takes free text, not on
    the template source: a source-level assertion that `esc(` is gone matches
    the comment explaining its deletion.
    """
    pages = [
        render("requests", failed=False,
               view=requests_view([request_row(rule_name=PAYLOAD,
                                               details=PAYLOAD)])),
        render("proposals", failed=False,
               view=mod._proposals_view([proposal(rule_name=PAYLOAD)])),
        render("quirks", failed=False, view=mod._quirks_view([quirk(title=PAYLOAD)])),
        render("campaigns", failed=False, days=30, can_propose=True,
               view=mod._campaigns_view({
                   "summary": {"addressable_hours": 1, "campaign_count": 1},
                   "campaigns": [{"rule_name": PAYLOAD, "fp_alerts": 1,
                                  "cost_hours": 1.0}],
               })),
    ]
    for html in pages:
        assert PAYLOAD not in html
        assert "&lt;script&gt;" in html


def test_a_tag_in_a_rule_name_does_not_break_out_of_a_data_args_attribute():
    """`|tojson` inside a single-quoted attribute. A rule name carrying a
    quote or a tag would otherwise end the attribute early and hand the
    delegated handler a truncated argument."""
    html = render("requests", failed=False,
                  view=requests_view([request_row(rule_name="it's " + PAYLOAD)]))
    args = re.findall(r"data-args='([^']*)'", html)
    assert args
    for raw in args:
        assert "<" not in raw
        assert "\\u0027" in raw


def test_a_javascript_scheme_in_the_ticket_column_is_dropped():
    """Defect, and a live one: `href="' + esc(url) + '"` escapes characters,
    not schemes, so a `javascript:` value stored on the row rendered a link
    that executed on click. `|safe_url` is the filter that refuses it."""
    html = render("requests", failed=False, view=requests_view(
        [request_row(gitlab_issue_url="javascript:alert(document.domain)")]
    ))
    assert "javascript:" not in html
    assert cell(html, "ticket") == '<span class="opacity-60">—</span>'


def test_a_real_ticket_url_still_renders_a_link():
    """Positive control for the filter, so the test above is not passing on a
    column that renders no link at all."""
    html = render("requests", failed=False, view=requests_view(
        [request_row(gitlab_issue_url="https://gitlab.example.com/x/-/issues/11")]
    ))
    assert 'href="https://gitlab.example.com/x/-/issues/11"' in html
    assert "#11" in html


def test_a_ticket_url_with_no_number_still_links():
    html = render("requests", failed=False, view=requests_view(
        [request_row(gitlab_issue_iid=None)]
    ))
    assert ">ticket ↗</a>" in html


def test_a_status_arriving_as_an_enum_member_renders_its_value():
    """Defect: the pill reading "Probe.OPEN".

    TuningRequest.status is a String column today, so nothing live carries an
    enum member here. ION keeps status as a SQLEnum on most tables, and if
    this one is tightened the colour map keeps working on value equality
    while the visible text goes wrong, which is why it survives a glance.
    `ui._shared.plain` is on the path and this is the probe that proves it.
    """
    class Probe(str, enum.Enum):
        OPEN = "open"

    view = requests_view([request_row(status=Probe.OPEN)])
    html = render("requests", failed=False, view=view)
    assert ">open</span>" in html
    assert "Probe.OPEN" not in html
    assert "badge-error" in html


def test_timestamps_go_through_the_ts_macro_and_not_a_server_format():
    """A server-formatted clock is the server's. The macro emits the instant
    and a UTC-labelled fallback, and static/js/local-time.js moves it to the
    viewer's clock after every swap."""
    stamp = now() - timedelta(days=2)
    requests_html = render("requests", failed=False, view=requests_view(
        [request_row(created_at=stamp.isoformat())]
    ))
    quirks_html = render("quirks", failed=False, view=mod._quirks_view([quirk()]))
    for html in (requests_html, quirks_html):
        assert "<time datetime=" in html
        assert "data-ts-format=" in html


def test_a_missing_timestamp_renders_a_fallback_not_the_epoch():
    html = render("requests", failed=False,
                  view=requests_view([request_row(created_at=None)]))
    assert "1970" not in html
    assert "no timestamp" in html


# ---------------------------------------------------------------------------
# The gates, read off the live routes
# ---------------------------------------------------------------------------


def _routes() -> dict:
    return {r.path: r for r in mod.router.routes}


def _dependency_names(route) -> list[str]:
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop(0)
        if dep.call is not None:
            out.append(getattr(dep.call, "__qualname__", ""))
        stack.extend(dep.dependencies)
    return out


def test_all_five_regions_are_mounted():
    """Positive control. Every gate test below iterates these paths, and an
    empty or short list would make all of them vacuous."""
    paths = set(_routes())
    assert paths == {f"/de-workbench/{r}" for r in REGIONS}


@pytest.mark.parametrize("region", REGIONS)
def test_the_module_gate_runs_before_the_permission_gate(region):
    """The order decides what an unauthenticated request to an unlicensed
    deployment is told: 404, meaning this does not exist here, rather than
    401, meaning log in and try again. The second answer confirms the paid
    feature is installed."""
    names = _dependency_names(_routes()[f"/de-workbench/{region}"])
    gate = names.index("require_de_module")
    perm = next(i for i, n in enumerate(names)
                if n.startswith("require_permission."))
    assert gate < perm


def _permission_of(fn) -> set[str]:
    qual = getattr(fn, "__qualname__", "")
    if qual.split(".")[0] not in ("require_permission", "require_any_permission"):
        return set()
    cells = dict(zip(fn.__code__.co_freevars,
                     (c.cell_contents for c in (fn.__closure__ or ()))))
    one, many = cells.get("permission_name"), cells.get("permission_names")
    found = set()
    if isinstance(one, str):
        found.add(one)
    if isinstance(many, (list, tuple, set)):
        found.update(str(p) for p in many)
    return found


def _live_permissions(path: str, method: str) -> set[str]:
    """What a request to a mounted JSON route actually meets.

    Read off the live application rather than the decorator text, out of the
    closure cell the factory closed over, because a fragment softer than the
    endpoint it mirrors is invisible in a diff.
    """
    from ion.web.server import app

    found: set[str] = set()
    for route in app.routes:
        if getattr(route, "path", None) != path:
            continue
        if method not in (getattr(route, "methods", None) or set()):
            continue
        stack = list(route.dependant.dependencies)
        while stack:
            dep = stack.pop(0)
            if dep.call is not None:
                found |= _permission_of(dep.call)
            stack.extend(dep.dependencies)
    assert found, f"no permission found on {method} {path}, so this proves nothing"
    return found


#: The read endpoint each region mirrors.
READ_ENDPOINTS = {
    "requests": "/api/de/tuning-requests",
    "campaigns": "/api/de/metrics",
    "proposals": "/api/de/proposals",
    "quirks": "/api/de/quirks",
    "content-pack": "/api/de/content-pack/export",
}


@pytest.mark.parametrize("region,endpoint", sorted(READ_ENDPOINTS.items()))
def test_the_fragment_permission_matches_the_read_it_mirrors(region, endpoint):
    """Not softer and not harder. A read locked behind a write permission is
    a different endpoint from the one the page claims to show."""
    assert _live_permissions(endpoint, "GET") == {mod.PERMISSION}


#: Every write a button on this page triggers.
WRITE_ENDPOINTS = [
    ("/api/de/tuning-requests/{request_id}/triage", "POST"),
    ("/api/de/tuning-requests/{request_id}/close", "POST"),
    ("/api/de/tuning-requests/{request_id}/link-proposal", "POST"),
    ("/api/de/proposals/draft", "POST"),
    ("/api/de/proposals", "POST"),
    ("/api/de/content-pack/import", "POST"),
]


@pytest.mark.parametrize("path,method", WRITE_ENDPOINTS)
def test_the_action_gate_matches_the_write_routes(path, method):
    """PROPOSE_PERMISSION decides every button on the page, and this is what
    keeps it from drifting from the six routes those buttons call. One of
    them changing gate makes a button appear that the server refuses."""
    assert _live_permissions(path, method) == {mod.PROPOSE_PERMISSION}


def test_no_fragment_uses_a_redirecting_page_dependency():
    """require_page_permission redirects to /login, and htmx would swap a
    password box into the middle of the dashboard."""
    for route in mod.router.routes:
        for name in _dependency_names(route):
            assert "require_page_permission" not in name
            assert "require_page_auth" not in name


def test_the_json_router_is_mounted_behind_the_same_gate():
    """The claim the order tests are matching against. If server.py stops
    gating the DE router, the fragments become stricter than the API and this
    says so rather than letting the two drift."""
    src = SERVER.read_text(encoding="utf-8")
    assert re.search(r"include_router\(\s*de_router,[^)]*require_de_module", src)


def test_require_de_module_is_a_404_when_the_module_is_off(monkeypatch):
    """Positive control for the gate itself."""
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with pytest.raises(HTTPException) as excinfo:
        gating.require_de_module()
    assert excinfo.value.status_code == 404


# ---------------------------------------------------------------------------
# The payload helper the fragment and the JSON endpoint now share
# ---------------------------------------------------------------------------


def test_the_extracted_payload_is_what_the_json_endpoint_returns(session):
    """The extraction must not change what /api/de/tuning-requests answers.
    Both are called on the same rows and compared."""
    from ion.web.de_api import list_tuning_requests, tuning_requests_payload

    session.add(TuningRequest(rule_name="a", reason="other", status="open"))
    session.add(TuningRequest(rule_name="b", reason="other", status="closed"))
    session.commit()

    # Explicit arguments: called directly, the route's Query(...) defaults
    # arrive as FieldInfo objects rather than as values.
    assert list_tuning_requests(status=None, limit=100, session=session) == (
        tuning_requests_payload(session)
    )
    assert list_tuning_requests(status="open", limit=100, session=session) == (
        tuning_requests_payload(session, status="open")
    )


def test_the_payload_orders_newest_first_and_honours_the_limit(session):
    """The part of the query worth sharing. A second copy of
    `order_by(id.desc())` is how the page and the API start disagreeing about
    which request is oldest."""
    from ion.web.de_api import tuning_requests_payload

    for name in ("first", "second", "third"):
        session.add(TuningRequest(rule_name=name, reason="other", status="open"))
        session.commit()

    rows = tuning_requests_payload(session)["requests"]
    assert [r["rule_name"] for r in rows] == ["third", "second", "first"]
    assert len(tuning_requests_payload(session, limit=2)["requests"]) == 2


# ---------------------------------------------------------------------------
# Failure states, selected by the route rather than passed to the template
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "de-tester"

    def __init__(self, propose: bool = True):
        self._propose = propose

    def has_permission(self, name):
        if name == mod.PROPOSE_PERMISSION:
            return self._propose
        return True


@pytest.fixture
def app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(mod.router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: session
    yield application
    application.dependency_overrides.clear()


#: What to break to make each region's read fail, and the sentence its
#: fragment must answer with.
BREAKS = {
    "requests": ("ion.web.de_api.tuning_requests_payload",
                 "This is not a clear queue"),
    "campaigns": ("ion.services.de_metrics_service.get_de_metrics",
                  "This is not an estate with no noise"),
    "proposals": ("ion.services.de_proposal_service.list_proposals",
                  "This is not an empty board"),
    "quirks": ("ion.services.de_quirk_service.list_quirks",
               "This is not an empty review list"),
}


@pytest.mark.parametrize("region", sorted(BREAKS))
def test_a_failed_read_says_so_and_prints_no_figure(
    app, region, monkeypatch, caplog
):
    """The route selects the failure state, not the test.

    Rendering the template with `failed=True` proves the markup and never
    that the route picks it, which is exactly what was wrong in the
    JavaScript: `r.ok ? r.json() : { requests: [] }` had markup that was fine
    and a selection that lied.

    200, not a 500: htmx does not swap a 500 and the user is left reading the
    spinner. The exception text stays in the log and off the page.
    """
    target, sentence = BREAKS[region]

    def boom(*_a, **_k):
        raise RuntimeError("de store unreachable secret")

    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    monkeypatch.setattr(target, boom)
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.de_workbench"):
        with TestClient(app) as client:
            resp = client.get(f"/ui/de-workbench/{region}")

    assert resp.status_code == 200
    body = flat(resp.text)
    assert sentence in body
    assert "read failed, " in body
    assert "secret" not in body
    assert ">0<" not in resp.text
    assert ">0h<" not in resp.text
    assert caplog.records, "the failure was not logged"


@pytest.mark.parametrize("region", sorted(BREAKS))
def test_a_failed_read_still_carries_its_own_tile(app, region, monkeypatch):
    """Defect: a failure branch that omits the out-of-band tile leaves the
    page's placeholder, or a previous figure, on screen beside a panel saying
    the read failed."""
    def boom(*_a, **_k):
        raise RuntimeError("down")

    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    monkeypatch.setattr(BREAKS[region][0], boom)
    with TestClient(app) as client:
        resp = client.get(f"/ui/de-workbench/{region}")
    assert f'id="{TILES[region]}" hx-swap-oob="true"' in resp.text


def test_one_regions_failure_leaves_the_others_rendering(app, session, monkeypatch):
    """The reason there are four routes and not one.

    A quirks query that fails must not blank the tuning-request queue the DE
    team works from. With one route and four try blocks the regions would
    still render, but they would share the fate of the one HTTP request: a
    500, a dropped connection or a timeout takes all four down at once.
    """
    def boom(*_a, **_k):
        raise RuntimeError("quirk store down")

    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    session.add(TuningRequest(rule_name="survivor-rule", reason="other",
                              status="open"))
    session.add(DetectionProposal(
        rule_name="survivor-proposal", change_type="exclusion",
        title="kept", suggested_change="x",
        status=DetectionProposalStatus.DRAFT,
        source=DetectionProposalSource.HUMAN,
    ))
    session.commit()
    monkeypatch.setattr("ion.services.de_quirk_service.list_quirks", boom)

    with TestClient(app) as client:
        quirks = client.get("/ui/de-workbench/quirks")
        requests_ = client.get("/ui/de-workbench/requests")
        proposals_ = client.get("/ui/de-workbench/proposals")

    assert "This is not an empty review list" in flat(quirks.text)
    assert "survivor-rule" in requests_.text
    assert "Open requests" in requests_.text
    assert ">1</div>" in requests_.text
    assert "survivor-proposal" in proposals_.text
    assert "could not be read" not in requests_.text
    assert "could not be read" not in proposals_.text


@pytest.mark.parametrize("region", REGIONS)
def test_a_region_404s_when_the_module_is_licence_disabled(
    app, session, region, monkeypatch
):
    """Neither empty nor failed. Nothing about the DE store leaks, and
    htmx-errors.js words the 404.

    The row goes in first on purpose: without it, "the rule name is absent"
    is true of any 404 body and asserts nothing.
    """
    session.add(TuningRequest(rule_name="licence-probe", reason="other",
                              status="open"))
    session.commit()
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with TestClient(app) as client:
        resp = client.get(f"/ui/de-workbench/{region}")
    assert resp.status_code == 404
    assert "licence-probe" not in resp.text


def test_an_unlicensed_deployment_is_a_404_before_authentication(session, monkeypatch):
    """The reason the gate order matters, driven rather than inferred.

    No user override here, so the request carries no session. A 401 would
    confirm the paid module is installed and the caller merely signed out.
    """
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(mod.router, prefix="/ui")
    application.dependency_overrides[get_db_session] = lambda: session
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with TestClient(application) as client:
        for region in REGIONS:
            resp = client.get(f"/ui/de-workbench/{region}")
            assert resp.status_code == 404, region


def test_an_authenticated_request_to_a_licensed_module_is_not_a_404(app, monkeypatch):
    """Positive control, so the 404 tests are not passing on routes that are
    404 for some other reason."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    with TestClient(app) as client:
        for region in REGIONS:
            assert client.get(f"/ui/de-workbench/{region}").status_code == 200


def test_the_route_renders_real_rows_end_to_end(app, session, monkeypatch):
    """One pass through the real services, so the render tests above are not
    the only thing exercising the view functions."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    session.add(TuningRequest(
        rule_name="End " + PAYLOAD, reason="noisy", status="open",
        evidence_json={"fp_alerts_7d": 0},
        gitlab_issue_url="javascript:alert(1)", gitlab_issue_iid=9,
    ))
    session.add(SystemQuirk(
        title="Quirk " + PAYLOAD, status=SystemQuirkStatus.ACTIVE,
        review_date=now() + timedelta(days=2, hours=12),
        annotation="a", justification="j",
    ))
    session.commit()

    with TestClient(app) as client:
        reqs = client.get("/ui/de-workbench/requests")
        quirks = client.get("/ui/de-workbench/quirks")

    assert PAYLOAD not in reqs.text
    assert "&lt;script&gt;" in reqs.text
    assert "Too noisy" in reqs.text
    assert "javascript:" not in reqs.text
    assert ">1</div>" in reqs.text
    assert "2d out" in quirks.text
    assert "SystemQuirkStatus" not in quirks.text


def test_the_write_controls_are_withheld_over_http_without_the_permission(
    app, session, monkeypatch
):
    """The permission read is a real one through the dependency, not a context
    flag a test passed in.

    The open request goes in first on purpose. Without a row the queue is
    empty, so "no Triage button" is true of an empty table and the assertion
    is vacuous: a mutation hardcoding the route's `can_propose` to True
    survived exactly that.
    """
    from ion.auth.dependencies import get_current_user

    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    session.add(TuningRequest(rule_name="gate-probe", reason="other",
                              status="open"))
    session.commit()
    app.dependency_overrides[get_current_user] = lambda: _User(propose=False)
    with TestClient(app) as client:
        pack = client.get("/ui/de-workbench/content-pack")
        reqs = client.get("/ui/de-workbench/requests")
    assert "dwImportPack" not in pack.text
    assert "de:propose" in pack.text
    assert "gate-probe" in reqs.text, "no row rendered, so this proves nothing"
    assert "dwTriage" not in reqs.text
    assert "dwClose" not in reqs.text


def test_the_write_controls_are_offered_over_http_with_the_permission(
    app, session, monkeypatch
):
    """Positive control for the test above, over the same route."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    session.add(TuningRequest(rule_name="gate-probe", reason="other",
                              status="open"))
    session.commit()
    with TestClient(app) as client:
        reqs = client.get("/ui/de-workbench/requests")
    assert 'data-click-action="dwTriage"' in reqs.text


# ---------------------------------------------------------------------------
# One tile per region, no duplicates, no crossed wires
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("region", sorted(TILES))
def test_each_region_sends_exactly_its_own_tile(app, region, monkeypatch):
    """Defect: two regions both claiming a tile, so whichever request lands
    last decides the figure, or a region painting a tile its read cannot
    support."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    with TestClient(app) as client:
        resp = client.get(f"/ui/de-workbench/{region}")
    ids = re.findall(r'id="(kpi-[a-z]+)" hx-swap-oob="true"', resp.text)
    assert ids == [TILES[region]]


def test_the_content_pack_region_claims_no_tile(app, monkeypatch):
    """It reads nothing, so it has no figure to report."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    with TestClient(app) as client:
        resp = client.get("/ui/de-workbench/content-pack")
    assert "hx-swap-oob" not in resp.text


def test_the_page_declares_every_tile_a_region_swaps():
    """An out-of-band swap whose target id is not in the document is silently
    dropped, so the figure would simply never appear."""
    page = PAGE.read_text(encoding="utf-8")
    for slot in TILES.values():
        assert f'id="{slot}"' in page


# ---------------------------------------------------------------------------
# The page shell: controls outside the swap, and no htmx that compiles a string
# ---------------------------------------------------------------------------


def _page_without_comments() -> str:
    """The page with HTML comments removed.

    A whole-file substring assertion passes on a comment, and these
    conversions carry comments that quote what they removed. Three separate
    conversions were caught by exactly that.
    """
    return re.sub(r"<!--.*?-->", "", PAGE.read_text(encoding="utf-8"), flags=re.S)


def test_no_runtime_markup_writes_are_left_in_the_page():
    """`hx-swap="innerHTML"` appears nine times by design, so this matches an
    assignment rather than the bare word."""
    src = _page_without_comments()
    assert not re.search(r"\.innerHTML\s*=", src)
    assert not re.search(r"\.outerHTML\s*=", src)
    assert "insertAdjacentHTML" not in src
    assert re.search(r'hx-swap="innerHTML"', src), "nothing swaps, so this proves nothing"


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    """ION serves no `unsafe-eval`, so anything htmx hands to `Function()`
    throws and the control silently does nothing. Invisible outside a browser
    console: the markup reads right and the fragment is right."""
    for path in [PAGE] + sorted(TEMPLATES.glob("_fragments/de_workbench*.html")):
        src = re.sub(r"<!--.*?-->|\{#.*?#\}", "", path.read_text(encoding="utf-8"),
                     flags=re.S)
        assert "hx-on" not in src, path.name
        assert "js:" not in src, path.name
        assert not re.search(r'hx-trigger="[^"]*\[', src), path.name
        assert not re.search(r"hx-(vals|headers)=\"js:", src), path.name


def test_every_refresh_control_lives_outside_the_region_it_refreshes():
    """A control inside the swapped region is removed by any render that omits
    it, so a failed read can take away the button that would retry.

    Position, not just presence: every Refresh appears in the shell above its
    container, so no render of that container can reach it.
    """
    src = _page_without_comments()
    refreshable = [r for r in REGIONS if r != "content-pack"]
    targets = re.findall(r'hx-target="(#dw-[a-z-]+)"', src)
    assert sorted(targets) == sorted(f"#dw-{r}" for r in refreshable)

    for region in refreshable:
        button = re.search(rf'hx-target="#dw-{region}"', src)
        container = re.search(rf'<div id="dw-{region}"', src)
        assert button and container, region
        assert button.start() < container.start(), region

    for region in REGIONS:
        container = re.search(rf'<div id="dw-{region}"[^>]*>', src)
        assert container, region
        assert f'hx-get="/ui/de-workbench/{region}"' in container.group(0)
        assert 'hx-trigger="load"' in container.group(0)


def test_no_fragment_renders_a_request_of_its_own():
    """Which is why there is no hx-include anywhere, and so no inherited
    parameter to disinherit. If a fragment ever gains a nested request this
    fails, and the hx-include/hx-disinherit pair has to be reconsidered."""
    for path in sorted(TEMPLATES.glob("_fragments/de_workbench*.html")):
        src = re.sub(r"\{#.*?#\}", "", path.read_text(encoding="utf-8"), flags=re.S)
        assert "hx-get" not in src, path.name
        assert "hx-post" not in src, path.name


def test_any_hx_include_on_a_swap_target_also_disinherits_it():
    """No site today: this page has no filter control, so nothing sends a
    value with the request. The guard stays because adding one later is the
    moment the duplicate-parameter defect appears, and it is invisible in the
    markup and invisible to an HTTP check."""
    src = _page_without_comments()
    for match in re.finditer(r"<div[^>]*hx-include[^>]*>", src):
        assert "hx-disinherit" in match.group(0), match.group(0)


def test_the_page_writes_no_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means. A per-page listener is one copy per page of a
    decision about an expired session."""
    src = _page_without_comments()
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_every_delegated_action_the_page_renders_is_defined_on_the_page():
    """A `data-click-action` naming a function that does not exist is a button
    that logs at debug level and does nothing."""
    page = PAGE.read_text(encoding="utf-8")
    rendered = [
        render("requests", failed=False, view=requests_view()),
        render("campaigns", failed=False, days=30, can_propose=True,
               view=mod._campaigns_view(campaign_payload())),
        render("content_pack", can_propose=True),
    ]
    actions = set()
    for html in rendered:
        actions.update(re.findall(r'data-click-action="(\w+)"', html))
    assert actions, "no action buttons rendered, so this proves nothing"
    for action in sorted(actions):
        assert re.search(rf"function {action}\s*\(", page), action
