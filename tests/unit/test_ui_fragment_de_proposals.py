"""The Detection Proposals table as a server-rendered fragment.

de_proposals.html built the rule cell, the change-type badge, the Bob
provenance badge, the outcome block, the expected-reduction cell, the
status pill and the edit/apply/reject/measure buttons out of string
concatenation and wrote the result into `#dp-content` with innerHTML at
four sites. Those are the cases below.

Two of them matter more than the rest. A status pill that reads the enum
repr instead of the value makes the decision unreadable, and a drop of 0
rendered as "not measured" says a tuning did nothing-we-can-see when the
truth is that the noise did not change. A failed read rendered as an empty
table says "nothing is waiting" when the truth is "we could not look".

The rows are fixtures rather than live data for the render tests: an empty
render proves nothing about the table, which is all that moved. The action
buttons are checked against the real service on a real session, because
that is the only way to know the buttons offer what the service will accept.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.licensing import gating
from ion.models.detection_proposal import (
    DetectionProposal,
    DetectionProposalChangeType,
    DetectionProposalSource,
    DetectionProposalStatus,
)
from ion.web.templating import make_templates
from ion.web.ui.de_proposals import (
    _ACTIONS,
    PERMISSION,
    _js_num,
    _outcome_view,
    _row,
    de_proposals_fragment,
    router,
)

FRAGMENT = "_fragments/de_proposals.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/de_proposals.html"
SERVER = ROOT / "src/ion/web/server.py"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _proposal(**over: Any) -> dict:
    base = {
        "id": 7,
        "rule_name": "Suspicious PowerShell",
        "change_type": "exclusion",
        "title": "Tune the SCCM PowerShell rule",
        "suggested_change": "Exclude host web01 during the patch window.",
        "rationale": "Signed binary, 02:00.",
        "scope": "host web01",
        "expected_fp_reduction": 12,
        "expected_hours_reclaimed": 3.5,
        "mitre_techniques": ["T1059.001"],
        "status": "draft",
        "source": "human",
        "alert_id": None,
        "decided_by_username": None,
        "applied_at": None,
        "outcome": None,
    }
    base.update(over)
    return base


def one(**over: Any) -> str:
    return render(
        proposals=[_row(_proposal(**over))], status="all", source="all", failed=False
    )


def _comparable(**over: Any) -> dict:
    base = {
        "window_days_exact": 7.0,
        "before_count": 4,
        "after_count": 4,
        "before_per_day": 0.0,
        "after_per_day": 0.0,
        "drop_pct": 0.0,
        "sufficient_observation": True,
        "reason": "",
    }
    base.update(over)
    return base


def _page_js(src: str) -> str:
    return "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))


# ---------------------------------------------------------------------------
# The row, which is what actually moved
# ---------------------------------------------------------------------------


def test_a_proposal_renders_its_row():
    html = one()
    assert "Tune the SCCM PowerShell rule" in html
    assert "Exclude host web01 during the patch window." in html
    assert "Suspicious PowerShell" in html
    assert "T1059.001" in html
    assert ">exclusion<" in html


def test_the_status_pill_reads_the_value_not_the_enum_repr():
    """The guard the port would silently fail without.

    `DetectionProposal.status` is a SQLEnum column, so `to_dict()` hands
    back a `DetectionProposalStatus` member, not a string. The JavaScript
    never saw one: FastAPI serialised it to "draft" on the way out. Jinja
    renders with str(), and on Python 3.12 that is
    "DetectionProposalStatus.DRAFT", so the pill would read the repr and
    the colour lookup would never match.
    """
    html = one(status=DetectionProposalStatus.DRAFT)
    assert "DetectionProposalStatus" not in html
    assert ">draft<" in html
    assert "badge-info" in html


def test_the_change_type_and_source_are_values_too():
    """Same column type, two more of them. A Bob badge that compares
    against the enum repr never matches, so every Bob draft looks human."""
    html = one(
        change_type=DetectionProposalChangeType.THRESHOLD,
        source=DetectionProposalSource.BOB,
        alert_id="ALT-9",
    )
    assert "DetectionProposalChangeType" not in html
    assert "DetectionProposalSource" not in html
    assert ">threshold<" in html
    assert ">Bob<" in html
    assert "from alert ALT-9" in html


@pytest.mark.parametrize("status,css", [
    ("applied", "badge-success"),
    ("rejected", "badge-error"),
    ("draft", "badge-info"),
    ("duplicate", "badge-info"),
])
def test_each_status_keeps_its_colour(status, css):
    assert css in one(status=status, applied_at="2026-01-01T00:00:00")


def test_an_unknown_status_falls_back_to_the_javascripts_info_pill():
    """The JavaScript's else branch was badge-info, not a neutral ghost.
    draft and duplicate both live there, and so does a value the enum
    has not grown yet."""
    html = one(status="quarantined")
    assert "badge-info" in html
    assert ">quarantined<" in html


def test_decided_by_is_shown_when_present_and_not_invented_when_absent():
    assert "by carol" in one(status="rejected", decided_by_username="carol")
    html = one(decided_by_username=None, source="human")
    assert "by " not in html
    assert "None" not in html


def test_a_missing_rule_name_is_a_dash_not_the_word_none():
    html = one(rule_name=None)
    assert 'class="font-mono text-sm">—</td>' in html
    assert "None" not in html


def test_jinja_escapes_what_the_hand_rolled_dpesc_used_to():
    """dpEsc() is gone. This is what replaces it, including the reason
    and the alert id, which were concatenated into attributes."""
    html = one(
        title="<script>alert(1)</script>",
        suggested_change="<img src=x onerror=1>",
        rule_name="<svg onload=1>",
        change_type="<x>",
        mitre_techniques=["<b>T1</b>"],
        decided_by_username="<i>eve</i>",
        source="bob",
        alert_id="<img src=x onerror=2>",
        status="applied",
        applied_at="2026-01-01T00:00:00",
        outcome={
            "drop_pct": None,
            "comparable": _comparable(
                sufficient_observation=False,
                drop_pct=None,
                reason="<script>reason</script>",
            ),
        },
    )
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "<svg onload=1>" not in html
    assert "<b>T1</b>" not in html
    assert "<i>eve</i>" not in html
    assert "<x>" not in html
    assert "&lt;script&gt;" in html


def test_only_the_first_six_techniques_are_shown():
    """The JavaScript sliced to six. A seventh is not a rounding error;
    the cell is a summary, and the rest stay on the record."""
    techs = [f"T{i:04d}" for i in range(7)]
    html = one(mitre_techniques=techs)
    for tech in techs[:6]:
        assert tech in html
    assert techs[6] not in html


def test_a_technique_list_that_is_not_a_list_is_not_sliced_into_characters():
    """`(p.mitre_techniques || []).slice` on a string yields characters.
    The column is a JSON list. Anything else is no techniques."""
    html = one(mitre_techniques="T1059")
    assert "T1059" not in html


# ---------------------------------------------------------------------------
# Expected reduction, where zero is a decision
# ---------------------------------------------------------------------------


def test_a_reduction_of_zero_is_printed_rather_than_hidden():
    """`is not none`, not truthiness.

    The JavaScript got this right with `!= null`. A port that writes
    `{% if p.expected_fp_reduction %}` renders a recorded reduction of 0
    exactly like a row that never recorded one, and 0 is "we expect this
    change to remove no false positives", which is a reason not to apply it.
    """
    html = one(expected_fp_reduction=0, expected_hours_reclaimed=0)
    assert "0 FP" in html
    assert "0h" in html


def test_recorded_hours_of_zero_are_printed_next_to_a_real_reduction():
    html = one(expected_fp_reduction=4, expected_hours_reclaimed=0)
    assert "4 FP" in html
    assert "0h" in html


def test_a_missing_reduction_is_a_dash_even_when_hours_were_recorded():
    """The JavaScript only printed the cell when the FP figure was present.
    Hours without a reduction is not a reduction of those hours."""
    html = one(expected_fp_reduction=None, expected_hours_reclaimed=5)
    assert "5h" not in html
    assert "—" in html
    assert "None" not in html


def test_missing_hours_print_nothing_rather_than_the_word_none():
    html = one(expected_fp_reduction=0, expected_hours_reclaimed=None)
    assert "0 FP" in html
    assert "0h" not in html
    assert "None" not in html


@pytest.mark.parametrize("raw,expected", [
    (0, "0"),
    (0.0, "0"),
    (96.7, "96.7"),
    (1.5, "1.5"),
    (3, "3"),
])
def test_numbers_print_the_way_javascript_concatenated_them(raw, expected):
    """`str(0.0)` is `0.0`. The old cell concatenated the JSON number, and
    JavaScript prints that as `0`. A trailing `.0` makes a measured zero
    look like a different figure from the one the analyst had yesterday."""
    assert _js_num(raw) == expected


# ---------------------------------------------------------------------------
# Bob's provenance, where an id of 0 is still an alert
# ---------------------------------------------------------------------------


def test_an_alert_id_of_zero_is_still_named():
    """The JavaScript used `p.alert_id ? ...`, so an id of 0 rendered as
    a Bob draft with no alert behind it. 0 is an identifier, not a blank."""
    html = one(source="bob", alert_id=0)
    assert "from alert 0" in html
    assert ">Bob<" in html


def test_a_bob_draft_with_no_alert_does_not_invent_one():
    html = one(source="bob", alert_id=None)
    assert ">Bob<" in html
    assert "from alert" not in html
    assert "Drafted automatically by Bob." in html


def test_an_empty_alert_id_is_not_an_alert():
    html = one(source="bob", alert_id="")
    assert "from alert" not in html


def test_a_human_proposal_is_not_badged_as_bob():
    html = one(source=DetectionProposalSource.HUMAN)
    assert ">Bob<" not in html


# ---------------------------------------------------------------------------
# The outcome block. Zero is a measurement. None is not false.
# ---------------------------------------------------------------------------


def _applied_outcome(comparable: dict, **threats: Any) -> dict:
    return {
        # The uneven figure. Quoting it is the bug the comparable block
        # exists to stop: it flatters a change that has only just landed.
        "drop_pct": 96.7,
        "comparable": comparable,
        "confirmed_threats": {
            "before_count": 2,
            "lost_confirmed_threats": False,
            **threats,
        },
    }


def test_a_drop_of_zero_is_quoted_and_the_uneven_figure_is_not():
    """`drop_pct == 0` means the noise did not change. The JavaScript
    tested `=== null || === undefined`, so 0 was shown. A truthiness port
    falls into "not enough observation" and the analyst re-measures a
    result they already have.

    96.7 is the top-level uneven drop on the same record. It must not
    appear: that is the figure that flatters a recent change.
    """
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome=_applied_outcome(_comparable(
            before_count=0, after_count=0, drop_pct=0.0,
            before_per_day=0.0, after_per_day=0.0,
        )),
    )
    assert _outcome_view("applied", _applied_outcome(_comparable(drop_pct=0.0)))["kind"] == "quoted"
    assert "<strong>0%</strong>" in html
    assert "0 FP before vs 0 after" in html
    assert "0/d" in html
    assert "96.7" not in html
    assert "n/a" not in html
    assert "Not enough observation" not in html
    assert "Not yet measured" not in html


def test_only_a_real_true_says_a_detection_may_have_been_silenced():
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome=_applied_outcome(
            _comparable(drop_pct=10),
            lost_confirmed_threats=True, before_count=0,
        ),
    )
    assert "silenced a real detection" in html
    # 0 threats before is still a count. Hiding it reads as "unknown".
    assert "(0 in the matched window before)" in html


@pytest.mark.parametrize("lost", [None, False, "no", 1, "false"])
def test_a_lost_flag_that_is_not_a_measured_true_raises_no_warning(lost):
    """Three states stay three, and the guard is `is true`.

    The JavaScript's `threats.lost_confirmed_threats ? warning` is
    truthiness, so the string "no" and the number 1 both render as
    "this change silenced a detection". A missing flag is "not judged",
    which is not the same sentence as "judged, and nothing was lost".
    """
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome=_applied_outcome(
            _comparable(drop_pct=10), lost_confirmed_threats=lost,
        ),
    )
    assert "silenced" not in html


def test_a_window_judged_too_short_says_so_and_does_not_quote_a_drop():
    """`sufficient_observation is False` is a measured "too soon". A drop
    sitting on the same object is not quoted: the service withholds the
    percentage until the window is long enough, and a caller that stored
    both must not have the percentage win."""
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome=_applied_outcome(_comparable(
            sufficient_observation=False, drop_pct=50, before_count=0,
            after_count=1, window_days_exact=1.5,
            reason="Only 1.5 days observed",
        )),
    )
    assert "Not enough observation yet" in html
    assert "0 FP before" in html
    assert "1.5d" in html
    assert "Only 1.5 days observed" in html
    assert "Noise drop" not in html
    assert "50%" not in html
    assert "96.7" not in html


def test_no_baseline_is_not_described_as_too_little_observation():
    """sufficient is True and drop_pct is None: the windows were long
    enough and there was nothing to divide by. The JavaScript used one
    heading for that and for a short window (`!sufficient || drop == null`),
    so a rule with no prior false positives read as "come back later".
    The counts are still measurements, including zero."""
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome=_applied_outcome(_comparable(
            sufficient_observation=True, drop_pct=None, before_count=0,
            after_count=0,
            reason="No false-positive closures in the matched window",
        )),
    )
    assert "No percentage to quote" in html
    assert "0 FP before" in html
    assert "No false-positive closures" in html
    assert "Not enough observation yet" not in html
    assert "Noise drop" not in html
    assert "96.7" not in html


@pytest.mark.parametrize("sufficient", [None, "yes", 1])
def test_an_unjudged_window_is_not_a_short_one_and_not_a_drop(sufficient):
    """`!c.sufficient_observation` is true for null, and `{% if not
    sufficient %}` is true for None. Both turn "nobody judged the window"
    into "the window was too short". A truthy non-boolean ("yes", 1) is
    the other direction: it would quote 40.5% as if the windows had been
    compared. Neither is a measured result."""
    outcome = _applied_outcome(_comparable(
        sufficient_observation=sufficient, drop_pct=40.5,
        before_count=1, after_count=2,
    ))
    assert _outcome_view("applied", outcome)["kind"] == "unjudged"
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome=outcome,
    )
    assert "Comparable window not judged" in html
    assert "40.5" not in html
    assert "Noise drop" not in html
    assert "Not enough observation yet" not in html


def test_a_legacy_drop_of_zero_is_zero_and_a_missing_one_is_not_applicable():
    """An outcome recorded before comparable windows existed. 0% is a
    measured flat line. null is "no percentage was stored". The JavaScript
    distinguished them with `=== null` and a truthiness port does not."""
    zero = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome={"drop_pct": 0, "comparable": None},
    )
    assert "Legacy measurement: 0%" in zero
    assert "n/a" not in zero
    assert "Not yet measured" not in zero

    missing = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome={"drop_pct": None},
    )
    assert "Legacy measurement: n/a" in missing
    assert "0%" not in missing


def test_an_applied_proposal_with_no_outcome_says_it_is_not_measured_yet():
    html = one(status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
               outcome=None)
    assert "Not yet measured." in html
    assert "Legacy" not in html
    assert "<table" in html


def test_a_draft_with_no_outcome_does_not_say_it_was_measured():
    html = one(status="draft", outcome=None)
    assert "Not yet measured" not in html
    assert "Legacy" not in html


def test_an_empty_outcome_object_is_a_legacy_record_not_an_unmeasured_one():
    """`{}` is truthy in JavaScript, so the old code took the legacy path.
    `not outcome` in Python is the opposite, and would say "not yet
    measured" about a record that exists and carries no comparable block."""
    html = one(
        status="applied", rule_name="r", applied_at="2026-01-01T00:00:00",
        outcome={},
    )
    assert "Legacy measurement: n/a" in html
    assert "Not yet measured" not in html


# ---------------------------------------------------------------------------
# The action buttons, which were a second copy of the service's rules
# ---------------------------------------------------------------------------


def test_the_action_table_covers_every_status_the_enum_has():
    """A state added to DetectionProposalStatus must fail here rather than
    render a row that silently offers no action at all."""
    assert set(_ACTIONS) == {s.value for s in DetectionProposalStatus}


def _probe(session, status: DetectionProposalStatus, **over: Any) -> DetectionProposal:
    fields: dict[str, Any] = dict(
        title="probe",
        suggested_change="exclude the benign trigger",
        rule_name="rule-a",
        status=status,
        applied_at=datetime(2099, 1, 1),
        change_type=DetectionProposalChangeType.EXCLUSION,
        source=DetectionProposalSource.HUMAN,
    )
    fields.update(over)
    proposal = DetectionProposal(**fields)
    session.add(proposal)
    session.commit()
    session.refresh(proposal)
    return proposal


def _action_keys(actions: list[dict]) -> set[str]:
    keys = set()
    for action in actions:
        if action["action"] == "dpDecide":
            keys.add("decide:" + action["decision"])
        else:
            keys.add(action["action"])
    return keys


def _offered(session, status: DetectionProposalStatus, **over: Any) -> set[str]:
    proposal = _probe(session, status, **over)
    return _action_keys(_row(proposal.to_dict())["actions"])


def _allows(session, status: DetectionProposalStatus, **over: Any) -> set[str]:
    from ion.services.de_proposal_service import (
        decide_proposal,
        measure_outcome,
        update_proposal,
    )

    def attempt(call) -> bool:
        proposal = _probe(session, status, **over)
        try:
            call(proposal.id)
        except ValueError:
            return False
        return True

    allowed = set()
    if attempt(lambda i: update_proposal(session, i, {"title": "renamed probe"})):
        allowed.add("dpEdit")
    if attempt(lambda i: decide_proposal(session, i, "applied", 2)):
        allowed.add("decide:applied")
    if attempt(lambda i: decide_proposal(session, i, "rejected", 2)):
        allowed.add("decide:rejected")
    if attempt(lambda i: measure_outcome(session, i)):
        allowed.add("dpMeasure")
    return allowed


def _stub_counts(monkeypatch):
    """The acceptance rule is status, rule_name and applied_at.

    measure_outcome's FP query needs the alert schema, which is not what
    this assertion is about. Stubbing the counts leaves the ValueError
    checks, which are the rule, on the real service.
    """
    monkeypatch.setattr(
        "ion.services.de_proposal_service.fp_alerts_for_rule", lambda *_a, **_k: 0
    )
    monkeypatch.setattr(
        "ion.services.de_proposal_service.tp_alerts_for_rule", lambda *_a, **_k: 0
    )


@pytest.mark.parametrize("status", list(DetectionProposalStatus))
def test_the_buttons_offer_exactly_what_the_service_accepts(session, monkeypatch, status):
    """update and decide refuse anything that is not draft. measure refuses
    anything that is not applied. The probe has a rule and an applied_at
    so only the status rule is under test, and it drives the real service
    rather than a restatement of the table."""
    _stub_counts(monkeypatch)
    assert _offered(session, status) == _allows(session, status)


def test_measure_is_withheld_when_the_service_would_refuse_it(session, monkeypatch):
    """An applied row with no rule, or no applied_at, makes measure_outcome
    raise. A button that only ever toasts that refusal is not an action.
    The JavaScript showed it anyway. The status table cannot see this;
    the row has to."""
    _stub_counts(monkeypatch)
    for over in (
        {"rule_name": None, "applied_at": datetime(2099, 1, 1)},
        {"rule_name": "rule-a", "applied_at": None},
    ):
        allowed = _allows(session, DetectionProposalStatus.APPLIED, **over)
        assert "dpMeasure" not in allowed
        assert _offered(session, DetectionProposalStatus.APPLIED, **over) == allowed


def test_a_reverted_status_offers_a_dash_rather_than_an_empty_cell():
    """rejected and duplicate are terminal. An empty cell looks like the
    row failed to render; a dash is what the JavaScript showed."""
    for status in ("rejected", "duplicate"):
        html = one(status=status)
        assert 'data-click-action="dpEdit"' not in html
        assert 'data-click-action="dpDecide"' not in html
        assert 'data-click-action="dpMeasure"' not in html
        assert 'class="opacity-50">—</span>' in html


def test_an_applied_row_with_nothing_to_measure_offers_the_dash():
    html = one(status="applied", rule_name=None, applied_at=None)
    assert 'data-click-action="dpMeasure"' not in html
    assert 'class="opacity-50">—</span>' in html


def test_the_action_buttons_carry_parseable_args():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which would leave buttons that look live and do nothing."""
    html = one(status="draft")
    args = [json.loads(raw) for raw in re.findall(r"data-args='([^']*)'", html)]
    assert [7] in args
    assert [7, "applied"] in args
    assert [7, "rejected"] in args


def test_a_measurable_applied_row_offers_measure():
    html = one(status="applied", rule_name="r", applied_at="2026-01-01T00:00:00")
    assert 'data-click-action="dpMeasure"' in html
    assert json.loads(re.search(r"data-args='([^']*)'", html).group(1)) == [7]


# ---------------------------------------------------------------------------
# Empty is not filtered-empty, and neither is failed
# ---------------------------------------------------------------------------


def test_no_proposals_at_all_says_so_and_names_the_next_step():
    html = render(proposals=[], status="all", source="all", failed=False)
    assert "No proposals yet" in html
    assert 'href="/de-metrics"' in html


def test_an_empty_status_filter_does_not_claim_there_are_no_proposals():
    """The JavaScript said "No proposals yet" whichever filter was on,
    which is wrong the moment Draft is selected and applied proposals exist."""
    html = render(proposals=[], status="draft", source="all", failed=False)
    assert "No proposals yet" not in html
    assert "No draft proposals" in html
    assert "other statuses may have some" in html


def test_an_empty_source_filter_does_not_claim_there_are_no_proposals():
    html = render(proposals=[], status="all", source="bob", failed=False)
    assert "No proposals yet" not in html
    assert "No proposals from Bob" in html


def test_both_filters_empty_names_both():
    html = render(proposals=[], status="applied", source="human", failed=False)
    assert "No proposals yet" not in html
    assert "No applied proposals from an analyst" in html


def test_a_failed_read_says_so_rather_than_showing_an_empty_table():
    """"Nothing there" and "we could not look" lead to opposite actions.
    Printing 0 proposals for a failed query is the same lie."""
    html = render(proposals=None, status="all", source="all", failed=True)
    text = " ".join(html.split())
    assert "could not be read" in text
    assert "not an empty list" in text
    assert "unknown rather than zero" in text
    assert "No proposals yet" not in html
    assert "<table" not in html


def test_the_failed_state_keeps_the_card_chrome():
    """The filters and Refresh live in the page shell, so an error swap
    cannot remove the way out. The card stays so the error lands inside
    the panel rather than replacing it with a bare strip."""
    html = render(proposals=None, status="all", source="all", failed=True)
    assert "card bg-base-200" in html


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
        if route.path == "/de/proposals" and "GET" in route.methods:
            return route
    raise AssertionError("GET /de/proposals not found in de_api")


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """A fragment must never be a softer way in than the API it mirrors.
    The permission is read out of the JSON route's own dependency rather
    than restated, so the two cannot drift. GET is de:read. The POST on
    the same path is de:propose and is not the endpoint this mirrors."""
    assert PERMISSION == "de:read"
    assert _permission_of(_json_route()) == PERMISSION
    assert _permission_of(_fragment_route()) == PERMISSION


def test_the_fragment_carries_the_licence_module_gate():
    """/api/de/proposals gets require_de_module from its router mount, so
    a fragment without it would be a way to read proposals out of a
    deployment whose licence does not include the module."""
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


def test_the_filters_accept_exactly_the_services_states():
    """The annotations are spelled out, so this is what keeps them from
    drifting from the enums. A bare `str`, which is what the JSON route
    uses, makes get_args return an empty tuple and this fails: a bad
    filter would then be caught below and worded as a failed read."""
    from typing import get_args, get_type_hints

    hints = get_type_hints(de_proposals_fragment)
    assert set(get_args(hints["status"])) == {"all"} | {
        s.value for s in DetectionProposalStatus
    }
    assert set(get_args(hints["source"])) == {"all"} | {
        s.value for s in DetectionProposalSource
    }


# ---------------------------------------------------------------------------
# The route over HTTP, which is where the gates actually fire
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "de-tester"

    def has_permission(self, _name):
        return True


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


def test_the_route_renders_a_real_proposal_from_the_service(app, session, monkeypatch):
    """The fragment and GET /api/de/proposals share one query, so this
    drives de_proposal_service.list_proposals rather than a stand-in.

    The row is inserted with the enum members the ORM stores and with a
    reduction of 0, which is the value a truthiness port would drop. The
    suggested change carries a tag, which dpEsc() used to neutralise and
    which Jinja now has to.
    """
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    session.add(DetectionProposal(
        title="probe-zero",
        suggested_change="exclude <script>alert(1)</script>",
        rule_name="Suspicious PowerShell",
        status=DetectionProposalStatus.DRAFT,
        change_type=DetectionProposalChangeType.THRESHOLD,
        source=DetectionProposalSource.BOB,
        alert_id="ALT-9",
        expected_fp_reduction=0,
        expected_hours_reclaimed=0,
        mitre_techniques=["T1059"],
        outcome_json={
            "drop_pct": 96.7,
            "comparable": _comparable(drop_pct=0.0, before_count=0, after_count=0),
            "confirmed_threats": {
                "lost_confirmed_threats": False, "before_count": 0,
            },
        },
    ))
    session.commit()
    with TestClient(app) as client:
        resp = client.get("/ui/de-proposals")
    assert resp.status_code == 200
    assert "probe-zero" in resp.text
    assert ">draft<" in resp.text
    assert ">threshold<" in resp.text
    assert "DetectionProposalStatus" not in resp.text
    assert "DetectionProposalChangeType" not in resp.text
    assert "DetectionProposalSource" not in resp.text
    assert "0 FP" in resp.text
    assert "0h" in resp.text
    assert ">Bob<" in resp.text
    assert "from alert ALT-9" in resp.text
    assert "T1059" in resp.text
    assert "<script>alert(1)</script>" not in resp.text
    assert "<strong>0%</strong>" in resp.text
    assert "96.7" not in resp.text


def test_the_route_filters_by_status_and_by_source(app, session, monkeypatch):
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _probe(session, DetectionProposalStatus.DRAFT, title="human-draft",
           source=DetectionProposalSource.HUMAN, applied_at=None)
    _probe(session, DetectionProposalStatus.APPLIED, title="bob-applied",
           source=DetectionProposalSource.BOB)
    with TestClient(app) as client:
        by_status = client.get("/ui/de-proposals", params={"status": "applied"})
        by_source = client.get("/ui/de-proposals", params={"source": "bob"})
        empty = client.get("/ui/de-proposals", params={"status": "rejected"})
    assert by_status.status_code == 200
    assert "bob-applied" in by_status.text
    assert "human-draft" not in by_status.text
    assert "bob-applied" in by_source.text
    assert "human-draft" not in by_source.text
    assert "No rejected proposals" in empty.text
    assert "No proposals yet" not in empty.text


def test_the_route_calls_list_proposals_the_way_the_json_endpoint_does(
    app, monkeypatch
):
    """Reuse the function. A second query here would keep answering after
    the service's filter changed, and a different limit would hide rows
    the JSON endpoint still returns."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    seen: dict[str, Any] = {}

    def fake(_session, status=None, source=None, limit=200):
        seen["status"] = status
        seen["source"] = source
        seen["limit"] = limit
        return []

    monkeypatch.setattr("ion.services.de_proposal_service.list_proposals", fake)
    with TestClient(app) as client:
        resp = client.get(
            "/ui/de-proposals", params={"status": "draft", "source": "bob"}
        )
    assert resp.status_code == 200
    assert seen == {"status": "draft", "source": "bob", "limit": 200}
    assert "No draft proposals from Bob" in resp.text


@pytest.mark.parametrize("params", [
    {"status": "bogus"},
    {"source": "vendor"},
])
def test_an_unparseable_filter_is_a_bad_request_not_a_failed_read(
    app, monkeypatch, params
):
    """"We could not look" is reserved for a read that failed. A filter
    value the service cannot parse is the caller's mistake, and answering
    it with the failure fragment spends that message on the wrong thing."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    with TestClient(app) as client:
        resp = client.get("/ui/de-proposals", params=params)
    assert resp.status_code == 422
    assert "could not be read" not in resp.text


def test_the_route_404s_when_the_module_is_licence_disabled(app, session, monkeypatch):
    """The state that is neither empty nor failed. Nothing about the
    proposal store leaks, and htmx-errors.js words the 404 for the user.

    The row is inserted first on purpose: without it, "the title is absent"
    is true of any 404 body and asserts nothing.
    """
    session.add(DetectionProposal(
        title="probe-secret", suggested_change="x",
        status=DetectionProposalStatus.DRAFT,
    ))
    session.commit()
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with TestClient(app) as client:
        resp = client.get("/ui/de-proposals")
    assert resp.status_code == 404
    assert "probe-secret" not in resp.text


def test_a_read_failure_renders_the_failure_fragment_not_an_empty_table(
    app, monkeypatch
):
    """200 with a fragment that says so, because htmx does not swap a 500
    and the user would be left reading the spinner."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)

    def boom(*_a, **_k):
        raise RuntimeError("proposal store unreachable")

    monkeypatch.setattr("ion.services.de_proposal_service.list_proposals", boom)
    with TestClient(app) as client:
        resp = client.get("/ui/de-proposals")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "No proposals yet" not in resp.text
    assert "<table" not in resp.text


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does. Scoped to the inline script bodies on purpose: `hx-swap="innerHTML"`
    is an attribute telling htmx where to put server-rendered markup, which
    is the opposite of the thing being removed."""
    src = PAGE.read_text(encoding="utf-8")
    js = _page_js(src)
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/de-proposals"' in src
    assert 'hx-trigger="load"' in src
    tag = re.search(r'<div id="dp-content"[^>]*>', src, re.S)
    assert tag, "the swap target is gone"
    assert "dp-status" in tag.group(0)
    assert "dp-source" in tag.group(0)


def test_the_string_building_helpers_are_gone_from_the_page():
    src = PAGE.read_text(encoding="utf-8")
    for name in ("dpEsc", "dpRender", "dpPill", "dpSource", "dpOutcome"):
        assert f"function {name}(" not in src, name
    assert "_dpItems =" not in src, "the row cache was a second copy of the table"
    assert "function _dpFind(" not in src


def test_the_filters_and_refresh_sit_outside_the_swap_target():
    """A control inside the fragment is removed by any render that omits it,
    so a failed read could take away the button that retries."""
    src = PAGE.read_text(encoding="utf-8")
    content = src.index('id="dp-content"')
    assert src.index('id="dp-status"') < content
    assert src.index('id="dp-source"') < content
    assert src.index('id="dp-refresh"') < content


def test_the_source_query_is_applied_while_the_document_is_still_parsing():
    """htmx registers its DOMContentLoaded listener from the head, so it
    runs before any listener this page adds. Deferring `?source=bob` until
    then makes the first request ignore the queue the retired
    /tuning-proposals page redirects here to show."""
    js = _page_js(PAGE.read_text(encoding="utf-8"))
    assert "addEventListener" not in js
    assert "sel.value = q" in js
    assert "dp-source" in js


def test_the_page_filters_offer_every_state_the_service_has():
    src = PAGE.read_text(encoding="utf-8")

    def values(select_id: str) -> set[str]:
        match = re.search(rf'<select id="{select_id}"[\s\S]*?</select>', src)
        assert match, select_id
        return set(re.findall(r'value="([^"]*)"', match.group(0)))

    assert values("dp-status") == {"all"} | {s.value for s in DetectionProposalStatus}
    assert values("dp-source") == {"all"} | {s.value for s in DetectionProposalSource}


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what a 401 does. And no htmx
    feature that compiles a string: ION's CSP blocks it and the control
    silently does nothing."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src
    assert not re.search(r"\bhx-on[a-z:-]*\s*=", src)
    assert "hx-vals" not in src
    assert not re.search(r'hx-trigger="[^"]*\[', src)
