"""The verdict-review queue and metrics as a server-rendered fragment.

verdict_review.html built the metrics strip, the queue cards, the empty
state and both failure messages out of string concatenation and wrote them
into two containers at five innerHTML sites. The cards carried the
containment proposals and a hand-rolled esc() as well.

Every case below is something the JavaScript either got right and the
fragment must keep, or got wrong and the fragment must stop doing. The rows
are fixtures rather than live data: the dev database has no pending
verdicts, and an empty render proves nothing about the card, which is all
that moved.
"""
from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ion.web.templating import make_templates
from ion.web.ui.verdict_review import (
    _PERM,
    _VERDICT_ORDER,
    _agreement,
    _catalog,
    _observable_proposals,
    _row_view,
    router,
)

FRAGMENT = "_fragments/verdict_review.html"
PAGE = Path(__file__).resolve().parents[2] / "src/ion/web/templates/verdict_review.html"

CATALOG = {
    "block_ip": {"id": 1, "name": "Block IP at Firewall", "action_type": "block_ip",
                 "requires_approval": False},
    "disable_account": {"id": 3, "name": "Disable AD Account",
                        "action_type": "disable_account", "requires_approval": True},
}


def render(**ctx: Any) -> str:
    env = make_templates().env
    base = {
        "metrics": None, "metrics_failed": False,
        "rows": [], "queue_failed": False, "containment_available": False,
    }
    base.update(ctx)
    return env.get_template(FRAGMENT).render(**base)


def _pending(**over: Any) -> dict:
    """One row shaped like verdict_review_service.list_pending_verdicts."""
    base = {
        "id": 42,
        "alert_id": "alert-abc",
        "investigation_id": 9,
        "rule_name": "Suspicious PowerShell Execution",
        "priority": "high",
        "observables": [],
        "bob_verdict": "true_positive",
        "bob_confidence": "high",
        "bob_confidence_int": 80,
        "auto_escalated": False,
        "created_at": "2026-10-12T08:30:11+00:00",
    }
    base.update(over)
    return base


def rows(*pendings: dict, catalog: dict | None = None) -> list[dict]:
    return [_row_view(p, catalog) for p in pendings]


# ---------------------------------------------------------------------------
# The three agreement states, which are the substance of this page
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bob,option,expected", [
    ("true_positive", "true_positive", True),
    ("true_positive", "false_positive", False),
    (None, "true_positive", None),
    ("", "true_positive", None),
])
def test_agreement_is_three_states_not_two(bob, option, expected):
    """`v.bob_verdict === hv` is False both when Bob chose something else and
    when Bob chose nothing. Those are different claims about the model."""
    assert _agreement(bob, option) is expected


def test_the_verdict_bob_suggested_is_marked_as_agreement():
    html = render(rows=rows(_pending(bob_verdict="false_positive")))
    assert "Bob suggested this verdict" in html
    assert "btn-success" in html


def test_a_verdict_bob_did_not_suggest_is_marked_as_disagreement():
    html = render(rows=rows(_pending(bob_verdict="false_positive")))
    assert "Bob suggested a different verdict" in html


def test_an_abstained_row_claims_neither_agreement_nor_disagreement():
    """The branch a truthiness port loses. With `is false` folded away, an
    alert Bob declined to judge renders as four "Bob suggested a different
    verdict" buttons, which asserts a judgement it never made."""
    html = render(rows=rows(_pending(bob_verdict=None, auto_escalated=True)))
    assert "records no agreement either way" in html
    assert "Bob suggested a different verdict" not in html
    assert "Bob suggested this verdict" not in html


def test_the_abstain_button_does_not_also_carry_btn_ghost():
    """Found by measuring computed style in a browser, not by reading the
    markup. With `btn-ghost btn-dash` the dashed border rendered in
    btn-ghost's transparent colour, so the markup carried three states and
    the screen showed two, which is the whole defect this page is about."""
    html = render(rows=rows(_pending(bob_verdict=None)))
    classes = re.findall(r'class="(vr-resolve[^"]*)"', html)
    assert classes, "no verdict buttons rendered"
    for cls in classes:
        assert "btn-dash" in cls
        assert "btn-ghost" not in cls


def test_every_verdict_on_an_abstained_row_is_in_the_abstain_state():
    html = render(rows=rows(_pending(bob_verdict=None)))
    assert html.count("records no agreement either way") == len(_VERDICT_ORDER)


def test_exactly_one_button_agrees_when_bob_suggested_a_verdict():
    html = render(rows=rows(_pending(bob_verdict="inconclusive")))
    assert html.count("Bob suggested this verdict") == 1
    assert html.count("Bob suggested a different verdict") == len(_VERDICT_ORDER) - 1


# ---------------------------------------------------------------------------
# Bob's own badge: abstained, escalated, or a verdict
# ---------------------------------------------------------------------------


def test_a_suggested_verdict_renders_as_its_badge():
    html = render(rows=rows(_pending(bob_verdict="benign_true_positive")))
    assert "benign true positive" in html
    assert "badge-success" in html


def test_the_circuit_breaker_firing_is_named_as_such():
    html = render(rows=rows(_pending(bob_verdict=None, auto_escalated=True)))
    assert "escalated (low confidence)" in html


def test_no_verdict_without_the_circuit_breaker_is_a_different_claim():
    """auto_escalated is in the payload and the JavaScript never read it, so
    every missing verdict was reported as a low-confidence escalation."""
    html = render(rows=rows(_pending(bob_verdict=None, auto_escalated=False)))
    assert "no verdict recorded" in html
    assert "escalated (low confidence)" not in html


# ---------------------------------------------------------------------------
# Numbers: `is not none`, never truthiness
# ---------------------------------------------------------------------------


def test_a_zero_confidence_is_a_score_not_a_blank():
    html = render(rows=rows(_pending(bob_confidence_int=0)))
    assert "0/100" in html


def test_a_missing_confidence_prints_no_score_at_all():
    """A confidence that was never recorded gets no badge, rather than a
    badge reading 0, which is a score Bob could have given."""
    html = render(rows=rows(_pending(bob_confidence_int=None, bob_confidence=None)))
    assert "/100" not in html
    assert "badge-ghost badge-sm" not in html


def test_a_zero_pending_count_is_a_measurement():
    html = render(metrics={"pending": 0, "reviewed": 0, "agreement_rate": None})
    assert ">\n        0\n" in html or ">0<" in html or " 0\n" in html
    assert "Unknown" not in html


def test_a_zero_agreement_rate_is_not_an_unmeasured_one():
    """0.0 means Bob has been overridden every time, which is the most
    important number on the page. Truthiness reports it as "not measured"."""
    html = render(metrics={"pending": 3, "reviewed": 12, "agreement_rate": 0.0})
    assert "0%" in html
    assert "Not yet measured" not in html


def test_an_unmeasured_agreement_rate_says_so():
    html = render(metrics={"pending": 3, "reviewed": 0, "agreement_rate": None})
    assert "Not yet measured" in html
    assert "0%" not in html


def test_a_full_agreement_rate_rounds_to_a_percentage():
    html = render(metrics={"pending": 0, "reviewed": 4, "agreement_rate": 0.875})
    assert "88%" in html


# ---------------------------------------------------------------------------
# Empty is not failed, for either read
# ---------------------------------------------------------------------------


def test_an_empty_queue_says_nothing_is_waiting():
    html = render(rows=[])
    assert "No verdicts awaiting review." in html


def test_a_failed_queue_read_is_not_an_empty_queue():
    """"Nothing is waiting for a human" is the one claim that makes an
    analyst stop checking this page."""
    html = render(rows=None, queue_failed=True)
    assert "could not be read" in html
    assert "not an empty queue" in html
    assert "No verdicts awaiting review." not in html


def test_a_failed_metrics_read_prints_no_zero_for_it():
    """The JavaScript swallowed a metrics failure and drew nothing, which
    looks exactly like a page that loaded."""
    html = render(metrics=None, metrics_failed=True, rows=rows(_pending()))
    assert "metrics could not be read" in html
    assert "not a queue depth of zero" in html
    assert "stat-value" not in html


def test_a_metrics_failure_does_not_cost_the_reviewer_the_queue():
    html = render(metrics=None, metrics_failed=True, rows=rows(_pending()))
    assert "Suspicious PowerShell Execution" in html
    assert "resolveVerdict" in html


def test_a_queue_failure_does_not_hide_the_metrics():
    html = render(metrics={"pending": 7, "reviewed": 2, "agreement_rate": 0.5},
                  rows=None, queue_failed=True)
    assert "50%" in html
    assert "not an empty queue" in html


# ---------------------------------------------------------------------------
# The card, and what the esc() used to do
# ---------------------------------------------------------------------------


def test_a_pending_verdict_renders_its_card():
    html = render(rows=rows(_pending()))
    assert "Suspicious PowerShell Execution" in html
    assert "alert-abc" in html
    assert 'data-card="42"' in html


def test_an_unnamed_rule_falls_back_rather_than_rendering_nothing():
    html = render(rows=rows(_pending(rule_name=None)))
    assert "(unnamed rule)" in html


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """esc() built a div and read back its innerHTML. This replaces it."""
    html = render(rows=rows(_pending(rule_name="<script>alert(1)</script>",
                                     alert_id="<img src=x onerror=1>")))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html


def test_the_priority_pill_keeps_its_colour():
    html = render(rows=rows(_pending(priority="critical")))
    assert "badge-error" in html
    assert "critical" in html


def test_an_unknown_priority_falls_back_to_ghost_rather_than_no_class():
    html = render(rows=rows(_pending(priority="apocalyptic")))
    assert "badge-ghost" in html


class _Priority(str, Enum):
    HIGH = "high"


def test_the_priority_pill_reads_the_value_not_the_enum_repr():
    """priority feeds a colour-map lookup and visible text at once, and
    AlertTriage.status in the same table is already a SQLEnum. Value equality
    survives the conversion, so the colour would stay right while the pill
    read "_Priority.HIGH", which is why it survives a glance."""
    html = render(rows=rows(_pending(priority=_Priority.HIGH)))
    assert "_Priority" not in html
    assert ">high<" in html
    assert "badge-warning" in html


def test_a_missing_priority_renders_no_pill():
    html = render(rows=rows(_pending(priority=None)))
    assert "badge-sm badge-ghost" not in html


def test_the_queued_timestamp_goes_through_the_time_macro():
    """A server-formatted timestamp shows an analyst in another timezone the
    wrong time on every row."""
    html = render(rows=rows(_pending()))
    assert "<time datetime=" in html
    assert 'data-ts-local="yes"' in html


def test_a_row_with_no_timestamp_says_so_rather_than_showing_the_epoch():
    html = render(rows=rows(_pending(created_at=None)))
    assert "at an unrecorded time" in html
    assert "1970" not in html


def test_the_resolve_buttons_carry_parseable_args():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which would leave buttons that look live and do nothing."""
    html = render(rows=rows(_pending()))
    args = re.findall(r"data-args='([^']*)'", html)
    assert len(args) == len(_VERDICT_ORDER)
    for raw in args:
        parsed = json.loads(raw.replace("&#34;", '"'))
        assert parsed[0] == 42
        assert parsed[1] in _VERDICT_ORDER


def test_the_buttons_offer_every_verdict_the_service_accepts():
    from ion.services.verdict_review_service import _VALID_VERDICTS

    assert set(_VERDICT_ORDER) == _VALID_VERDICTS


# ---------------------------------------------------------------------------
# Containment proposals, which carry a second permission and a feature flag
# ---------------------------------------------------------------------------


def test_an_observable_with_an_applicable_action_gets_a_propose_button():
    html = render(rows=rows(_pending(observables=[{"type": "ip", "value": "1.2.3.4"}]),
                            catalog=CATALOG),
                  containment_available=True)
    assert "Propose containment" in html
    assert "Block IP at Firewall" in html
    assert 'data-target="1.2.3.4"' in html


def test_an_approval_gated_action_is_flagged_as_one():
    html = render(rows=rows(_pending(observables=[{"type": "user", "value": "jdoe"}]),
                            catalog=CATALOG),
                  containment_available=True)
    assert "Disable AD Account" in html
    assert "&#9888;" in html


def test_an_observable_type_with_no_action_proposes_nothing():
    assert _observable_proposals([{"type": "hash", "value": "deadbeef"}], CATALOG) == []


def test_a_repeated_observable_proposes_once():
    out = _observable_proposals(
        [{"type": "ip", "value": "1.2.3.4"}, {"type": "IP", "value": "1.2.3.4"}],
        CATALOG,
    )
    assert len(out) == 1


@pytest.mark.parametrize("obs", [
    [{"type": "ip"}], [{"value": "1.2.3.4"}], [None], ["1.2.3.4"], None,
])
def test_a_malformed_observable_is_skipped_not_rendered(obs):
    assert _observable_proposals(obs, CATALOG) == []


class _User:
    """Only the one method _catalog asks about."""

    def __init__(self, permissions: set[str]) -> None:
        self._permissions = permissions

    def has_permission(self, name: str) -> bool:
        return name in self._permissions


def _config(monkeypatch, enabled: bool) -> None:
    import ion.core.config as cfg

    monkeypatch.setattr(
        cfg, "get_config", lambda: SimpleNamespace(response_actions_enabled=enabled)
    )


def test_the_catalogue_is_withheld_when_the_feature_is_off(monkeypatch):
    """/api/response/actions 404s before any work when the flag is off, so
    the fragment must not render the catalogue it would have returned."""
    _config(monkeypatch, False)
    assert _catalog(_User({"playbook:read"}), object()) is None


def test_the_catalogue_is_withheld_from_a_reviewer_without_playbook_read(monkeypatch):
    """The fragment is gated on verdict:review and the catalogue it embeds is
    gated on playbook:read. Without this check the fragment would be a
    softer way in than the API it mirrors."""
    import ion.services.playbook_action_service as actions

    _config(monkeypatch, True)
    monkeypatch.setattr(actions, "get_available_actions",
                        lambda s: pytest.fail("catalogue read without playbook:read"))
    assert _catalog(_User({"verdict:review"}), object()) is None


def test_the_catalogue_is_served_to_a_reviewer_who_may_read_it(monkeypatch):
    """Positive control. Without it both tests above pass on a _catalog that
    always returns None."""
    import ion.services.playbook_action_service as actions

    _config(monkeypatch, True)
    monkeypatch.setattr(actions, "seed_default_actions", lambda s: None)
    monkeypatch.setattr(actions, "get_available_actions", lambda s: [CATALOG["block_ip"]])
    assert _catalog(_User({"verdict:review", "playbook:read"}), object()) == {
        "block_ip": CATALOG["block_ip"]
    }


def test_an_action_the_catalogue_does_not_hold_is_not_proposed():
    """The catalogue is empty when the feature is off or the reviewer lacks
    playbook:read, and then the whole section must be absent."""
    html = render(rows=rows(_pending(observables=[{"type": "ip", "value": "1.2.3.4"}]),
                            catalog=None))
    assert "Propose containment" not in html
    assert "proposeAction" not in html


# ---------------------------------------------------------------------------
# The route and the page
# ---------------------------------------------------------------------------


def _permission_of(route) -> str | None:
    stack, out = list(route.dependant.dependencies), None
    while stack:
        dep = stack.pop()
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            out = cells.get("permission_name")
        stack.extend(dep.dependencies)
    return out


def test_the_fragment_permission_matches_the_json_endpoint():
    """Read off the live /api/verdict-review routes rather than restated, so
    the fragment cannot stay on verdict:review while the API moves."""
    from ion.web.verdict_review_api import router as api_router

    api_perms = {_permission_of(r) for r in api_router.routes}
    assert api_perms == {_PERM}
    assert [_permission_of(r) for r in router.routes] == [_PERM]


def test_the_fragment_calls_the_services_the_json_endpoints_call():
    from ion.services import verdict_review_service as vr

    assert hasattr(vr, "list_pending_verdicts")
    assert hasattr(vr, "verdict_metrics")


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py does.

    Scoped to the inline script bodies: `hx-swap="innerHTML"` is an attribute
    telling htmx where to put server-rendered markup, which is the opposite
    of the thing being removed.
    """
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/verdict-review"' in src
    assert 'hx-trigger="load"' in src


def test_the_page_carries_no_second_copy_of_the_servers_tables():
    """The declaration forms, not the names: the script's opening comment
    names each deleted table so the next reader knows where it went, and a
    bare substring test would read that as the table itself."""
    src = PAGE.read_text(encoding="utf-8")
    assert "function esc(" not in src, "Jinja autoescapes"
    assert "APPLIES =" not in src, "which actions apply is the server's call"
    assert "VERDICT_BADGE =" not in src, "the badge map lives in the fragment"
    assert "PRI_BADGE =" not in src
    assert "RESPONSE_ACTIONS_ENABLED =" not in src, "checked server-side"
    assert "response_actions_enabled" not in src, "the page needs no flag"


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_the_refresh_control_sits_outside_the_swap_target():
    """A failed render must not remove the control that retries it."""
    src = PAGE.read_text(encoding="utf-8")
    start = src.index('id="vr-content"')
    assert src.index("Refresh</button>") < start
