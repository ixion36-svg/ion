"""The Bob improvement page as one server-rendered fragment.

de_bob.html built the scorecard, the disagreement-class table and the
proposals table out of string concatenation and wrote them into three
divs with innerHTML at ten sites. Those are the cases below.

Two of them matter more than the rest, because this page is where an
analyst decides whether Bob is drifting. A rate of zero means every scored
closure disagreed; a rate nobody computed means the ledger could not be
read. The JavaScript's ``|| 0`` printed the second as the first, and its
empty-state copy said the analysts agree whenever the class list was
empty, including when the query had failed. A status pill that reads the
enum repr instead of the value makes the approval state unreadable on a
surface whose approve button changes Bob's live prompt.

The rows are fixtures rather than live data for the render tests: an empty
render proves nothing about the table, which is all that moved. The action
table is checked against the real service on a real session, because that
is the only way to know the buttons offer what the service will consider.
"""
from __future__ import annotations

import inspect
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.licensing import gating
from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.models.bob_tuning_proposal import BobTuningProposal, BobTuningProposalStatus
from ion.web.templating import make_templates
from ion.web.ui.de_bob import (
    _ACTIONS,
    PERMISSION,
    _class_row,
    _proposal_row,
    _view,
    de_bob_fragment,
    router,
)

FRAGMENT = "_fragments/de_bob.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/de_bob.html"
FRAGMENT_PATH = ROOT / "src/ion/web/templates" / FRAGMENT
SERVER = ROOT / "src/ion/web/server.py"


def render(**ctx: Any) -> str:
    base = {
        "days": 90,
        "status": "all",
        "scorecard_failed": False,
        "card": _view(shape()),
        "feedback_failed": False,
        "classes": [],
        "proposals_failed": False,
        "proposals": [],
    }
    base.update(ctx)
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**base)


def shape(**over: Any) -> dict:
    summary: dict[str, Any] = {
        "scored": 4,
        "agreed": 3,
        "agreement_rate": 75.0,
        "drift": {
            "recent_rate": 80.0,
            "older_rate": 70.0,
            "delta": 10.0,
            "direction": "improving",
        },
        "disagreement_classes": 1,
        "total_disagreements": 2,
        "few_shot": {"gold_exemplar_retrieval_enabled": True, "note": ""},
    }
    omit = over.pop("omit", ())
    drift = over.pop("drift", None)
    few = over.pop("few", None)
    if drift is not None:
        summary["drift"].update(drift)
    if few is not None:
        summary["few_shot"].update(few)
    summary.update(over)
    for key in omit:
        summary.pop(key, None)
        summary["drift"].pop(key, None)
        summary["few_shot"].pop(key, None)
    return {"summary": summary}


def card(**over: Any) -> dict:
    return _view(shape(**over))


def klass(**over: Any) -> dict:
    base = {
        "rule_name": "Suspicious PowerShell",
        "bob_verdict": "false_positive",
        "human_verdict": "true_positive",
        "count": 4,
        "sample_reasons": ["signed binary"],
    }
    base.update(over)
    return _class_row(base)


def prop(**over: Any) -> dict:
    base = {
        "id": 7,
        "title": "Abstain less on service accounts",
        "problem_statement": "Bob said false positive.",
        "rule_name": "Suspicious PowerShell",
        "status": "draft",
        "created_by_username": "alice",
        "decided_by_username": None,
        "reverted_by_username": None,
    }
    base.update(over)
    return _proposal_row(base)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# The scorecard, where zero is a measurement
# ---------------------------------------------------------------------------


def test_a_rate_of_zero_is_printed_rather_than_hidden():
    """`is not none`, not truthiness.

    The service returns 0.0 when closures were scored and none of them
    agreed, and None when nothing was scored, because there is nothing to
    divide. `{% if card.agreement_rate %}` renders both as the dash, so an
    analyst cannot tell "Bob disagreed with every closure" from "we have
    not measured Bob at all".
    """
    html = render(card=card(agreement_rate=0.0, agreed=0, scored=4))
    assert ">0%</div>" in html
    assert "0.0%" not in html
    assert "0 / 4 scored closures" in html


def test_a_rate_of_zero_as_an_int_is_the_same_measurement():
    html = render(card=card(agreement_rate=0, agreed=0, scored=4))
    assert ">0%</div>" in html
    assert "0 / 4 scored closures" in html


def test_a_missing_rate_is_not_printed_as_zero():
    """The other half of the same guard. `value || 0` is how None becomes
    zero, and on this page a zero rate is a finding that Bob is wrong every
    time."""
    html = render(card=card(agreement_rate=None, agreed=None, scored=None))
    assert ">0%</div>" not in html
    assert "0 /" not in html
    assert "— / — scored closures" in html
    assert 'class="stat-value">—</div>' in html


def test_a_rate_the_payload_omitted_is_a_missing_rate():
    """A key that is absent and a key that is present and null are the same
    claim: nobody computed it. Both have to miss the zero, or a scorecard
    that forgot the field reads as total disagreement."""
    html = render(card=card(omit=("agreement_rate", "agreed", "scored")))
    assert ">0%</div>" not in html
    assert "— / — scored closures" in html


def test_a_boolean_is_not_a_rate_of_one():
    """`bool` is an `int`. A guard of `isinstance(value, (int, float))` that
    forgets the bool check renders True as 1% and False as 0%, which are
    both findings this page treats as measured."""
    html = render(card=card(agreement_rate=True, agreed=True, scored=True))
    assert ">1%</div>" not in html
    assert ">0%</div>" not in html
    assert "— / — scored closures" in html


def test_a_fractional_rate_keeps_its_decimal_and_a_whole_one_drops_it():
    """The JavaScript concatenated the number, so 85.5 stayed "85.5" and
    100.0 rendered as "100", not "100.0"."""
    assert ">85.5%</div>" in render(card=card(agreement_rate=85.5))
    whole = render(card=card(agreement_rate=100.0))
    assert ">100%</div>" in whole
    assert "100.0%" not in whole


def test_a_zero_disagreement_count_is_printed():
    html = render(card=card(disagreement_classes=0, total_disagreements=0))
    assert ">0</div>" in html
    assert "0 total disagreements" in html


def test_a_missing_disagreement_count_is_not_printed_as_zero():
    html = render(card=card(disagreement_classes=None, total_disagreements=None))
    assert "0 total disagreements" not in html
    assert "— total disagreements" in html


@pytest.mark.parametrize("delta,text", [
    (0, "0 pts"),
    (0.0, "0 pts"),
    (5, "+5 pts"),
    (5.0, "+5 pts"),
    (-6, "-6 pts"),
    (-6.0, "-6 pts"),
    (-2.5, "-2.5 pts"),
])
def test_a_drift_delta_keeps_its_sign_and_a_zero_is_not_blank(delta, text):
    """A delta of 0 is "recent and older agree". The JavaScript's null check
    kept it, and a truthiness test would drop it, which then reads the same
    as a delta nobody computed."""
    html = render(card=card(drift={"delta": delta, "direction": "flat"}))
    assert text in html
    assert "+0" not in html
    assert "-6.0" not in html
    assert "+5.0" not in html


def test_a_missing_delta_prints_no_points():
    html = render(card=card(drift={"delta": None, "direction": "flat"}))
    assert "pts" not in html
    assert ">flat</div>" in html
    assert "not computed" not in html


def test_an_improving_drift_is_marked_as_such():
    html = render(card=card(drift={"delta": 6, "direction": "improving"}))
    assert 'class="stat-value text-success">improving</div>' in html
    assert "+6 pts" in html


def test_a_declining_drift_is_marked_as_such():
    html = render(card=card(drift={"delta": -6, "direction": "declining"}))
    assert 'class="stat-value text-error">declining</div>' in html
    assert "-6 pts" in html


def test_a_missing_direction_is_not_called_flat():
    """`d.direction || 'flat'` turned "we did not compute a direction" into
    "recent and older agree". Flat is what the service says when it did
    compute one and the two halves match."""
    html = render(card=card(drift={"delta": None, "direction": None}))
    assert ">flat</div>" not in html
    assert 'class="stat-value opacity-50">—</div>' in html
    assert "not computed" in html


def test_a_blank_direction_is_the_same_absence():
    html = render(card=card(drift={"delta": None, "direction": ""}))
    assert ">flat</div>" not in html
    assert "not computed" in html


def test_a_direction_the_payload_omitted_is_not_flat():
    html = render(card=card(omit=("direction", "delta")))
    assert ">flat</div>" not in html
    assert "not computed" in html


@pytest.mark.parametrize("enabled,word", [
    (True, "enabled"),
    (False, "disabled"),
    (None, "unknown"),
])
def test_the_retrieval_flag_stays_three_states(enabled, word):
    """`flag ? 'enabled' : 'disabled'` folds "never reported" into
    "disabled", which tells an analyst retrieval is off when the payload
    did not say."""
    html = render(card=card(few={"gold_exemplar_retrieval_enabled": enabled, "note": ""}))
    assert f"</strong> {word}." in html
    for other in {"enabled", "disabled", "unknown"} - {word}:
        assert f"</strong> {other}." not in html


def test_a_non_boolean_retrieval_flag_is_unknown_not_enabled():
    """The string "no" is truthy. A truthiness test reports it as enabled,
    which is the opposite of what the word says, and it is not a bool the
    service would have produced, so it is unknown."""
    html = render(card=card(few={"gold_exemplar_retrieval_enabled": "no", "note": ""}))
    assert "</strong> unknown." in html
    assert "</strong> enabled." not in html
    assert "</strong> disabled." not in html


def test_the_retrieval_note_is_escaped():
    html = render(card=card(few={
        "gold_exemplar_retrieval_enabled": True,
        "note": "<img src=x onerror=1>",
    }))
    assert "<img src=x" not in html
    assert "&lt;img" in html


def test_a_failed_scorecard_says_so_rather_than_showing_zero():
    """"Nothing scored" and "we could not look" lead to opposite actions.
    The JavaScript distinguished them ("Failed to load: 500") and so must
    this, without echoing the exception, which is a server-side detail."""
    html = render(scorecard_failed=True, card=None)
    assert "scorecard could not be read" in html
    assert "not a measured zero" in html
    assert "stats stats-vertical" not in html
    assert ">0%</div>" not in html
    assert "Gold-exemplar retrieval" not in html


# ---------------------------------------------------------------------------
# Disagreement classes
# ---------------------------------------------------------------------------


def test_a_class_renders_its_row():
    html = render(classes=[klass()])
    assert "Suspicious PowerShell" in html
    assert "false_positive" in html
    assert "true_positive" in html
    assert "signed binary" in html
    assert ">4</td>" in html
    assert "Draft tuning proposal" in html


def test_a_count_of_zero_is_a_count_not_a_dash():
    """`c.count || 0` shows 0 for a missing count, and `{% if c.count %}`
    shows a dash for a count of 0. The cell has to do neither."""
    html = render(classes=[klass(count=0)], card=card(agreement_rate=50, agreed=1, scored=2))
    assert "<td>0</td>" in html
    assert "<td>—</td>" not in html


def test_a_missing_count_is_a_dash_not_zero():
    html = render(classes=[klass(count=None)], card=card())
    assert "<td>—</td>" in html
    assert "<td>0</td>" not in html


def test_a_count_the_class_omitted_is_a_missing_count():
    row = {
        "rule_name": "Suspicious PowerShell",
        "bob_verdict": "false_positive",
        "human_verdict": "true_positive",
        "sample_reasons": ["signed binary"],
    }
    html = render(classes=[_class_row(row)])
    assert "<td>—</td>" in html
    assert "<td>0</td>" not in html


def test_sample_reasons_are_joined_and_escaped():
    html = render(classes=[klass(sample_reasons=["one", "<b>two</b>"])])
    assert "one<br>&lt;b&gt;two&lt;/b&gt;" in html


def test_no_sample_reasons_shows_a_dash():
    html = render(classes=[klass(sample_reasons=[])])
    assert 'opacity-50">—</span>' in html


def test_a_string_of_reasons_is_not_split_into_letters():
    """A string is iterable. Walking it renders one letter per line and
    looks like a list of reasons that were never recorded."""
    html = render(classes=[klass(sample_reasons="signed")])
    assert "<br>i<br>" not in html
    assert 'opacity-50">—</span>' in html


def test_a_missing_verdict_is_blank_and_null_in_the_draft_args():
    """bbEsc(null) was ''. The string "None" is not a verdict, and the
    draft request has to send null so it still matches the class the
    service grouped under a null verdict."""
    html = render(classes=[klass(bob_verdict=None, rule_name=None)])
    assert "None" not in html
    args = json.loads(re.search(r"data-args='([^']*)'", html).group(1))
    assert args[0] is None
    assert args[1] is None


def test_draft_args_round_trip_an_apostrophe_and_a_script():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which leaves a button that looks live and does nothing. tojson
    escapes the quote that would break the attribute and the angle bracket
    that would be markup."""
    attack = "O'Brien <script>alert(1)</script>"
    html = render(classes=[klass(rule_name=attack, sample_reasons=[attack])])
    assert attack not in html
    assert "&lt;script&gt;" in html
    assert "\\u003c" in html
    args = json.loads(re.search(r"data-args='([^']*)'", html).group(1))
    assert args[0] == attack


def test_no_classes_says_the_analysts_agree():
    html = render(classes=[], feedback_failed=False)
    assert "Bob and the analysts agree" in html
    assert "<table" not in html


def test_a_failed_feedback_read_does_not_say_the_analysts_agree():
    """An empty class list means Bob and the analysts agree. A query that
    threw means we do not know whether they do. The JavaScript's catch
    branch said "Failed to load"; its empty branch said they agree. The
    failure has to keep saying the first of those."""
    html = render(classes=None, feedback_failed=True, proposals=[])
    assert "feedback could not be read" in html
    assert "not an empty list" in html
    assert "Bob and the analysts agree" not in html
    assert "<table" not in html
    assert "card bg-base-200" in html


def test_a_class_that_is_not_an_object_fails_the_read_rather_than_dropping():
    """Skipping the bad row and rendering the rest under-counts the
    disagreements, which reads as a smaller problem than the one recorded."""
    with pytest.raises(TypeError):
        _class_row("signed binary")


# ---------------------------------------------------------------------------
# Proposals, where the status is an enum and the buttons are a second copy
# ---------------------------------------------------------------------------


def test_a_proposal_renders_its_row():
    html = render(proposals=[prop()])
    assert "Abstain less on service accounts" in html
    assert "Bob said false positive." in html
    assert "Suspicious PowerShell" in html
    assert "drafted: alice" in html
    assert ">draft<" in html
    assert "badge-warning" in html


def test_the_status_pill_reads_the_value_not_the_enum_repr():
    """The guard the port would silently fail without.

    `BobTuningProposal.status` is a SQLEnum column, so `to_dict()` hands
    back a `BobTuningProposalStatus` member, not a string. The JavaScript
    never saw one: FastAPI serialised it to "draft" on the way out. Jinja
    renders with str(), and on Python 3.12 that is
    "BobTuningProposalStatus.DRAFT", so the pill would read the repr and
    the colour lookup would never match.
    """
    html = render(proposals=[prop(status=BobTuningProposalStatus.DRAFT)])
    assert "BobTuningProposalStatus" not in html
    assert ">draft<" in html
    assert "badge-warning" in html


@pytest.mark.parametrize("status,css", [
    ("draft", "badge-warning"),
    ("approved", "badge-success"),
    ("rejected", "badge-error"),
    ("reverted", "badge-ghost"),
])
def test_each_status_keeps_its_colour(status, css):
    assert css in render(proposals=[prop(status=status)])


def test_an_unknown_status_is_neutral_and_offers_no_button():
    """The JavaScript's else branch painted anything it did not recognise
    with the draft colour, which is the colour of a row waiting for a
    decision. An unknown state is not a draft."""
    html = render(proposals=[prop(status="quarantined")])
    assert "badge-ghost" in html
    assert ">quarantined<" in html
    assert "badge-warning" not in html
    assert "bbApprove" not in html
    assert "bbReject" not in html
    assert "bbRevert" not in html


def test_a_missing_status_is_a_dash_not_the_word_none():
    html = render(proposals=[prop(status=None)])
    assert "None" not in html
    assert "bbApprove" not in html


def test_decided_and_reverted_attribution_appear_when_present():
    html = render(proposals=[prop(
        status="reverted", decided_by_username="bob", reverted_by_username="carol",
    )])
    assert "decided: bob" in html
    assert "reverted: carol" in html


def test_an_unattributed_proposal_shows_a_dash_not_the_word_none():
    html = render(proposals=[prop(created_by_username=None, rule_name=None)])
    assert "drafted: —" in html
    assert "None" not in html


def test_an_empty_problem_statement_is_omitted():
    html = render(proposals=[prop(problem_statement="")])
    assert "opacity-50 mt-1" not in html


def test_jinja_escapes_what_the_hand_rolled_bbesc_used_to():
    """bbEsc() is gone. This is what replaces it."""
    html = render(proposals=[prop(
        title="<script>alert(1)</script>",
        problem_statement="<img src=x onerror=1>",
        rule_name="<svg onload=1>",
    )])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "<svg onload=1>" not in html


def test_the_action_table_covers_every_status_the_enum_has():
    """A state added to BobTuningProposalStatus must fail here rather than
    render a row that silently offers no action at all."""
    assert set(_ACTIONS) == {s.value for s in BobTuningProposalStatus}


def test_a_draft_offers_approve_and_reject_with_parseable_args():
    html = render(proposals=[prop(status="draft")])
    assert "Approve &amp; apply" in html
    assert 'data-click-action="bbApprove"' in html
    assert 'data-click-action="bbReject"' in html
    assert 'data-click-action="bbRevert"' not in html
    args = re.findall(r"data-args='([^']*)'", html)
    assert args, "no action buttons rendered"
    for raw in args:
        assert json.loads(raw) == [7]


def test_an_id_of_zero_still_gets_its_button():
    """`if proposal_id` treats 0 as missing and drops the button. 0 is an
    id. The listener would otherwise show no action on a row that has one."""
    html = render(proposals=[prop(id=0)])
    assert "data-args='[0]'" in html
    assert 'data-click-action="bbApprove"' in html


def test_a_missing_id_offers_no_button():
    html = render(proposals=[prop(id=None)])
    assert "bbApprove" not in html
    assert "—" in html


def test_an_approved_proposal_offers_revert_only():
    html = render(proposals=[prop(status="approved")])
    assert 'data-click-action="bbRevert"' in html
    assert 'data-click-action="bbApprove"' not in html
    assert 'data-click-action="bbReject"' not in html


def test_a_reverted_proposal_offers_a_dash_rather_than_an_empty_cell():
    html = render(proposals=[prop(status="reverted")])
    assert "bbApprove" not in html
    assert "bbReject" not in html
    assert "bbRevert" not in html
    assert "—" in html


def _probe(session, status: BobTuningProposalStatus) -> int:
    proposal = BobTuningProposal(
        title="probe", proposed_text="guidance", status=status,
        created_by_id=1, rule_name="r",
    )
    session.add(proposal)
    session.commit()
    return proposal.id


# Phrases the service uses when the status itself is the reason it refuses.
# A refusal for a missing template or a missing evaluation is a different
# reason: the button is still the right one to offer, and the click tells
# the analyst what is actually missing.
_STATUS_REFUSAL = (
    "only a draft can be approved",
    "only a draft can be rejected",
    "only an approved proposal can be reverted",
)


def _refused_for_status(fn: Callable, session, proposal_id: int) -> bool:
    try:
        fn(session, proposal_id, 2)
    except ValueError as exc:
        session.rollback()
        return any(phrase in str(exc) for phrase in _STATUS_REFUSAL)
    return False


@pytest.mark.parametrize("status", list(BobTuningProposalStatus))
def test_the_buttons_offer_exactly_what_the_service_will_consider(session, status):
    """The JavaScript's two-branch `if` was a second copy of rules that live
    in de_bob_proposal_service: approve and reject refuse anything that is
    not a draft, revert refuses anything that is not approved. This drives
    the real service on a real row, so the table cannot offer a button the
    status makes impossible or hide one the status would have allowed.

    Approve on a bare draft still fails, for want of a template and an
    evaluation. That is not a status refusal, and the button stays, because
    the click is what tells the analyst what is missing. The probe drafter
    is user 1 and the actor is user 2, so separation of duties is satisfied
    and only the status rule is under test."""
    from ion.services.de_bob_proposal_service import (
        approve_proposal,
        reject_proposal,
        revert_proposal,
    )

    considered = set()
    for action, fn in (
        ("bbApprove", approve_proposal),
        ("bbReject", reject_proposal),
        ("bbRevert", revert_proposal),
    ):
        if not _refused_for_status(fn, session, _probe(session, status)):
            considered.add(action)
    assert {a["action"] for a in _ACTIONS[status.value]} == considered


def test_no_proposals_at_all_says_so_and_names_the_next_step():
    html = render(proposals=[], status="all", proposals_failed=False)
    assert "No tuning proposals yet" in html
    assert "Draft one from a feedback item above" in html


def test_an_empty_filter_does_not_claim_there_are_no_proposals():
    """The JavaScript said "No tuning proposals yet" whichever filter was
    on, which is wrong the moment Approved is selected and a draft exists."""
    html = render(proposals=[], status="approved", proposals_failed=False)
    assert "No tuning proposals yet" not in html
    assert "No approved proposals" in html
    assert "other statuses may have some" in html


def test_a_failed_proposal_read_says_so_rather_than_showing_an_empty_queue():
    html = render(proposals=None, proposals_failed=True, classes=[])
    assert "proposals could not be read" in html
    assert "not an empty list" in html
    assert "No tuning proposals yet" not in html
    assert "<table" not in html
    assert "card bg-base-200" in html


def test_a_failed_flag_wins_over_an_empty_list():
    """Setting the rows to [] in the except block and also raising the flag
    must still say the read failed. `not proposals` is true of both, so the
    flag has to be the branch that runs first."""
    html = render(proposals=[], proposals_failed=True)
    assert "proposals could not be read" in html
    assert "No tuning proposals yet" not in html


# ---------------------------------------------------------------------------
# One section failing does not rewrite the others
# ---------------------------------------------------------------------------


def test_a_failed_scorecard_does_not_blank_a_class_or_a_proposal():
    html = render(
        scorecard_failed=True, card=None,
        classes=[klass()],
        proposals=[prop(title="kept-proposal")],
    )
    assert "scorecard could not be read" in html
    assert ">0%</div>" not in html
    assert "Suspicious PowerShell" in html
    assert "kept-proposal" in html


def test_a_failed_feedback_read_does_not_blank_a_measured_rate():
    html = render(
        card=card(agreement_rate=0.0, agreed=0, scored=4),
        feedback_failed=True, classes=None,
        proposals=[prop(title="kept-proposal")],
    )
    assert ">0%</div>" in html
    assert "feedback could not be read" in html
    assert "Bob and the analysts agree" not in html
    assert "kept-proposal" in html


def test_a_failed_proposal_read_does_not_blank_a_class():
    html = render(
        classes=[klass()],
        proposals_failed=True, proposals=None,
    )
    assert "Suspicious PowerShell" in html
    assert "proposals could not be read" in html
    assert "No tuning proposals yet" not in html


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


def _json_gets() -> dict:
    from ion.web.de_api import router as de_router

    want = {"/de/bob-feedback", "/de/scorecard", "/de/bob-proposals"}
    found = {}
    for route in de_router.routes:
        if route.path in want and "GET" in (route.methods or ()):
            found[route.path] = route
    assert set(found) == want, set(found)
    return found


def test_the_fragment_permission_matches_every_json_get_it_mirrors():
    """A fragment must never be a softer way in than the API it mirrors, and
    it must not copy a write route's permission either: de:propose and
    de:approve are the draft and decision posts, and locking the read behind
    either of them would hide the scorecard from the people the page is for.

    The permission is read out of each JSON route's own dependency rather
    than restated, so the two cannot drift."""
    assert PERMISSION == "de:read"
    assert _permission_of(_fragment_route()) == PERMISSION
    for path, route in _json_gets().items():
        assert _permission_of(route) == PERMISSION, path


def test_the_fragment_carries_the_licence_module_gate():
    """/api/de/* gets require_de_module from its router mount, so a fragment
    without it would be a way to read the scorecard out of a deployment
    whose licence does not include the module."""
    assert "require_de_module" in _dependency_names(_fragment_route())


def test_the_module_gate_runs_before_the_permission_gate():
    """Same order as the JSON endpoint, where the gate is a router
    dependency and therefore runs first. It decides what an unauthenticated
    request to a licence-disabled deployment is told: 404 (this does not
    exist) rather than 401 (log in and ask again)."""
    names = _dependency_names(_fragment_route())
    gate = names.index("require_de_module")
    perm = next(i for i, name in enumerate(names)
                if name.startswith("require_permission."))
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


def _bounds(fn) -> tuple:
    """(default, constraint reprs). FastAPI stores ge/le on Query.metadata,
    not as attributes, so reading query.ge raises and the comparison never
    runs. Reprs keep the test independent of which annotated type carries
    the bound, and still fail if one side drops ge=1 or le=365."""
    query = inspect.signature(fn).parameters["days"].default
    return (query.default, tuple(sorted(repr(item) for item in query.metadata)))


def test_the_window_bounds_match_the_json_endpoints():
    """A window the scorecard endpoint refuses and the fragment accepts is
    two answers for one question. The numbers are the endpoint's own, read
    off its signature, and then checked against the values it declares so a
    change to both at once is still visible."""
    from ion.web.de_api import bob_feedback, bob_scorecard

    assert _bounds(de_bob_fragment) == _bounds(bob_scorecard)
    assert _bounds(de_bob_fragment) == _bounds(bob_feedback)
    default, constraints = _bounds(bob_scorecard)
    assert default == 90
    joined = " ".join(constraints)
    assert "ge=1" in joined
    assert "le=365" in joined


def test_the_status_filter_accepts_exactly_the_services_states():
    """The annotation is spelled out, so this is what keeps it from drifting
    from the enum. A state added to BobTuningProposalStatus and not here
    would be unreachable from the page, with nothing anywhere saying so."""
    from typing import get_args, get_type_hints

    # get_type_hints, not __annotations__. The module has
    # `from __future__ import annotations`, so the raw annotation is the
    # *string* 'Literal["all", ...]' and get_args on a string returns (),
    # which made the first version of this assertion compare an empty set
    # and fail against correct code.
    hints = get_type_hints(de_bob_fragment)
    allowed = set(get_args(hints["status"]))
    assert allowed == {"all"} | {s.value for s in BobTuningProposalStatus}


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


def _feedback(session, *, rule: str, alert_id: str, when: datetime | None = None,
              reason: str = "signed binary") -> None:
    when = when or _now()
    session.add(AlertTriage(
        es_alert_id=alert_id, status=AlertTriageStatus.CLOSED, rule_name=rule,
    ))
    session.add(AIFeedback(
        alert_id=alert_id,
        bob_suggested_verdict="false_positive",
        human_verdict="true_positive",
        agreement=False,
        delta_reason=reason,
        auto_escalated=False,
        created_at=when,
        updated_at=when,
    ))
    session.commit()


def _stored_proposal(session, **over: Any) -> BobTuningProposal:
    kwargs = dict(
        title="probe", proposed_text="guidance",
        status=BobTuningProposalStatus.DRAFT, rule_name="r",
    )
    kwargs.update(over)
    proposal = BobTuningProposal(**kwargs)
    session.add(proposal)
    session.commit()
    return proposal


def test_the_route_renders_a_real_zero_rate_and_a_real_proposal(app, session, monkeypatch):
    """The fragment and the three GETs share one function each, so this
    drives those functions rather than a stand-in. One scored disagreement
    and no agreement is a rate of zero, which is the case a truthiness test
    renders as a dash. The title and the reason both carry a tag, which is
    the case the hand-rolled escaper existed for."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _feedback(
        session, rule="Suspicious PowerShell", alert_id="alert-bob-1",
        reason="signed <script>alert(1)</script>",
    )
    _stored_proposal(session, title="Tune <script>alert(1)</script>")
    with TestClient(app) as client:
        resp = client.get("/ui/de-bob")
    assert resp.status_code == 200
    assert ">0%</div>" in resp.text
    assert "0 / 1 scored closures" in resp.text
    assert "Suspicious PowerShell" in resp.text
    assert ">draft<" in resp.text
    assert "BobTuningProposalStatus" not in resp.text
    assert "drafted: —" in resp.text
    assert "<script>" not in resp.text
    assert resp.text.count("&lt;script&gt;") >= 2
    assert "not human-approved" in resp.text
    assert 'data-click-action="bbApprove"' in resp.text
    assert 'data-click-action="bbRevert"' not in resp.text
    args = json.loads(re.search(r"data-args='([^']*)'", resp.text).group(1))
    assert args[:2] == ["Suspicious PowerShell", "false_positive"]


def test_the_default_window_is_ninety_days(app, session, monkeypatch):
    """The select defaults to 90 and so does the route, which is what the
    scorecard endpoint defaults to. A row from 100 days ago is outside that
    and inside 180. If the fragment ignored `days` or defaulted wider, the
    ancient rule would show up on the first paint."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _feedback(
        session, rule="Ancient Rule", alert_id="alert-ancient",
        when=_now() - timedelta(days=100),
    )
    with TestClient(app) as client:
        implicit = client.get("/ui/de-bob")
        wide = client.get("/ui/de-bob", params={"days": 180})
    assert implicit.status_code == 200
    assert "Ancient Rule" not in implicit.text
    assert "Bob and the analysts agree" in implicit.text
    assert "Ancient Rule" in wide.text


def test_the_route_filters_proposals_by_status(app, session, monkeypatch):
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _stored_proposal(session, title="filter-me")
    with TestClient(app) as client:
        approved = client.get("/ui/de-bob", params={"status": "approved"})
        draft = client.get("/ui/de-bob", params={"status": "draft"})
    assert approved.status_code == 200
    assert "filter-me" not in approved.text
    assert "No approved proposals" in approved.text
    assert "No tuning proposals yet" not in approved.text
    assert "filter-me" in draft.text


def test_an_unparseable_filter_is_a_bad_request_not_a_failed_read(app, monkeypatch):
    """"We could not look" is reserved for a read that failed. A filter
    value the service cannot parse is the caller's mistake, and answering it
    with the failure fragment spends that message on the wrong thing and
    logs a stack trace for it."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    with TestClient(app) as client:
        status = client.get("/ui/de-bob", params={"status": "bogus"})
        low = client.get("/ui/de-bob", params={"days": 0})
        high = client.get("/ui/de-bob", params={"days": 366})
    for resp in (status, low, high):
        assert resp.status_code == 422
        assert "could not be read" not in resp.text


def test_the_route_404s_when_the_module_is_licence_disabled(app, session, monkeypatch):
    """The state that is neither empty nor failed. Nothing about the ledger
    leaks, and htmx-errors.js words the 404 for the user.

    The row is inserted first on purpose: without it, "the title is absent"
    is true of any 404 body and asserts nothing.
    """
    _stored_proposal(session, title="licence-probe")
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with TestClient(app) as client:
        resp = client.get("/ui/de-bob")
    assert resp.status_code == 404
    assert "licence-probe" not in resp.text


def test_a_scorecard_failure_keeps_the_proposal_and_does_not_echo_the_exception(
    app, session, monkeypatch, caplog
):
    """200 with a fragment that says so, because htmx does not swap a 500
    and the user would be left reading the spinner. The proposal query is a
    different read and has to survive, and the empty class list is a real
    empty list, so it may say the analysts agree. The exception text stays
    in the log."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _stored_proposal(session, title="kept-proposal")

    def boom(*_a, **_k):
        raise RuntimeError("scorecard store unreachable secret")

    monkeypatch.setattr("ion.services.de_bob_service.get_bob_scorecard", boom)
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.de_bob"):
        with TestClient(app) as client:
            resp = client.get("/ui/de-bob")
    assert resp.status_code == 200
    assert "scorecard could not be read" in resp.text
    assert "kept-proposal" in resp.text
    assert "Bob and the analysts agree" in resp.text
    assert "secret" not in resp.text
    assert ">0%</div>" not in resp.text
    assert any(
        r.exc_info and r.exc_info[0] is RuntimeError for r in caplog.records
    )


def test_a_feedback_failure_fails_the_scorecard_too_and_keeps_the_proposal(
    app, session, monkeypatch
):
    """The scorecard is built from the feedback read, so that store being
    down fails both sections. It must not fail the proposal queue, and it
    must not say the analysts agree on the way down."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _stored_proposal(session, title="kept-proposal")

    def boom(*_a, **_k):
        raise RuntimeError("feedback store unreachable")

    monkeypatch.setattr("ion.services.de_bob_service.get_bob_feedback", boom)
    with TestClient(app) as client:
        resp = client.get("/ui/de-bob")
    assert resp.status_code == 200
    assert "scorecard could not be read" in resp.text
    assert "feedback could not be read" in resp.text
    assert "proposals could not be read" not in resp.text
    assert "kept-proposal" in resp.text
    assert "Bob and the analysts agree" not in resp.text
    assert ">0%</div>" not in resp.text
    assert "unreachable" not in resp.text


def test_a_proposal_failure_keeps_a_measured_rate(app, session, monkeypatch):
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _feedback(session, rule="Suspicious PowerShell", alert_id="alert-bob-2")

    def boom(*_a, **_k):
        raise RuntimeError("proposal store unreachable")

    monkeypatch.setattr(
        "ion.services.de_bob_proposal_service.list_proposals", boom
    )
    with TestClient(app) as client:
        resp = client.get("/ui/de-bob")
    assert resp.status_code == 200
    assert ">0%</div>" in resp.text
    assert "Suspicious PowerShell" in resp.text
    assert "proposals could not be read" in resp.text
    assert "No tuning proposals yet" not in resp.text
    assert "scorecard could not be read" not in resp.text
    assert "unreachable" not in resp.text


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


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


def test_the_page_no_longer_defaults_a_missing_number_to_zero():
    """The five `|| 0` sites were the scorecard and the class count. They
    left with the renderers. A comment that quotes one would put the defect
    back, because the measurement does not strip comments."""
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))
    assert not re.search(r"\|\|\s*0", js)


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    tag = re.search(r'<div id="bb-content"[^>]*>', src)
    assert tag, "no swap target"
    assert 'hx-get="/ui/de-bob"' in tag.group(0)
    assert 'hx-trigger="load"' in tag.group(0)
    assert 'hx-include="#bb-days,#bb-status"' in tag.group(0)


def test_the_string_building_helpers_are_gone_from_the_page():
    src = PAGE.read_text(encoding="utf-8")
    for name in (
        "function bbEsc(", "function bbRenderScorecard(", "function bbRenderFeedback(",
        "function bbRenderProposals(", "function bbPill(", "function bbLoadScorecard(",
        "function bbLoadFeedback(", "function bbLoadProposals(",
    ):
        assert name not in src, name
    assert "/scorecard" not in src
    assert "bob-feedback" not in src


def test_the_controls_sit_outside_the_swap_target():
    """A control inside the fragment is removed by any render that omits it,
    so a failed read could take away the button that retries."""
    src = PAGE.read_text(encoding="utf-8")
    content = src.index('id="bb-content"')
    assert src.index('id="bb-days"') < content
    assert src.index('id="bb-status"') < content
    assert src.index('id="bb-refresh"') < content
    assert 'name="days"' in src
    assert 'name="status"' in src
    refresh = re.search(r'<button[^>]*id="bb-refresh"[^>]*>', src)
    assert refresh and "data-click-action" not in refresh.group(0)


def test_the_fragment_does_not_carry_the_controls():
    src = FRAGMENT_PATH.read_text(encoding="utf-8")
    assert 'id="bb-days"' not in src
    assert 'id="bb-status"' not in src
    assert 'id="bb-refresh"' not in src


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what a 401 does."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    """ION's CSP has no unsafe-eval. An hx-trigger filter, a js: hx-vals
    and hx-on all hand a string to Function(), throw, and silently do
    nothing, so the markup looks right and the control is dead."""
    src = PAGE.read_text(encoding="utf-8") + FRAGMENT_PATH.read_text(encoding="utf-8")
    assert "hx-on:" not in src
    assert "hx-on='" not in src
    assert "js:" not in src
    assert "[key==" not in src
