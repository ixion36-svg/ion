"""The response-action approval inbox as a server-rendered fragment.

response_approvals.html built the mode banner, the pending cards and the
decision history out of template literals and wrote them into `#rap-mode`
and `#rap-content` with innerHTML at four sites. Each test below is
something the JavaScript either got right and must keep, or got wrong and
must stop doing.

The entries are fixtures rather than live data: the dev database has no
pending response actions, and an empty render proves nothing about the cards,
which is all that moved. The two rules the buttons come from are pinned
against the service itself, with a session, because a fixture cannot prove
the server would accept the decision a button offers.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from ion.web.templating import make_templates
from ion.web.ui.response_approvals import (
    FRAGMENT,
    _decided_view,
    _inbox_view,
    _pending_view,
    router,
)

PAGE = Path(__file__).resolve().parents[2] / "src/ion/web/templates/response_approvals.html"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _entry(**over: Any) -> dict:
    """One inbox entry, shaped like playbook_action_service._inbox_entry."""
    base = {
        "id": 12,
        "action_id": 3,
        "action_name": "Block IP at perimeter firewall",
        "action_type": "block_ip",
        "action_description": "Adds a deny rule for the target address.",
        "case_id": 48,
        "case_title": "Beaconing from 10.2.3.4",
        "case_severity": "high",
        "status": "pending_approval",
        "target": "198.51.100.7",
        "risk_level": "high",
        "requires_second_person": False,
        "requested_by": "analyst",
        "requested_by_id": 5,
        "requested_at": "2026-10-12T08:30:11+00:00",
        "decided_by": None,
        "decided_by_id": None,
        "created_at": "2026-10-12T08:30:11+00:00",
        "updated_at": None,
        "effective_mode": "dry_run",
        "mode_reason": "Dry-run mode: approving simulates the action.",
        "adapter_name": "firewall",
        "adapter_ready": True,
        "adapter_readiness": "ready",
        "adapter_detail": "Adapter configuration is present.",
        "idempotency_key": "ion-act-7f3d",
        "result": None,
        "error": None,
        "outcome": {
            "stage": "requested",
            "label": "Awaiting approval",
            "external_confirmation": "none",
            "changed_anything": False,
            "detail": "Requested by a human; no decision yet.",
        },
    }
    base.update(over)
    return base


def inbox(*, pending=(), decided=(), viewer_id=9, **over: Any) -> dict:
    payload = {
        "mode": {"effective_mode": "dry_run", "reason": "Dry-run mode is on."},
        "pending": list(pending),
        "decided": list(decided),
        "pending_count": len(pending),
    }
    payload.update(over)
    return _inbox_view(payload, viewer_id)


def ok(**over: Any) -> dict:
    ctx = {"inbox": inbox(), "failed": False, "surface_off": False}
    ctx.update(over)
    return ctx


# ---------------------------------------------------------------------------
# The card, which is what actually moved
# ---------------------------------------------------------------------------


def test_a_pending_action_renders_its_card():
    html = render(**ok(inbox=inbox(pending=[_entry()])))
    assert "Block IP at perimeter firewall" in html
    assert "198.51.100.7" in html
    assert "Beaconing from 10.2.3.4" in html
    assert "/cases/48" in html
    assert "analyst" in html
    assert "ion-act-7f3d" in html
    assert "high risk" in html


def test_jinja_escapes_what_the_hand_rolled_rapEsc_used_to():
    """rapEsc() is gone. This is what replaces it."""
    html = render(**ok(inbox=inbox(pending=[
        _entry(action_name="<script>alert(1)</script>",
               target="<img src=x onerror=1>"),
    ])))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html


@pytest.mark.parametrize("risk,css", [
    ("critical", "badge-error"), ("high", "badge-error"),
    ("medium", "badge-warning"), ("low", "badge-info"),
])
def test_risk_keeps_its_badge(risk, css):
    html = render(**ok(inbox=inbox(pending=[_entry(risk_level=risk)])))
    assert css in html


def test_an_unrated_risk_says_unrated_rather_than_nothing():
    html = render(**ok(inbox=inbox(pending=[_entry(risk_level=None)])))
    assert "unrated risk" in html
    assert "badge-ghost" in html


@pytest.mark.parametrize("key,label", [
    ("ready", "Adapter ready"),
    ("not_configured", "Adapter not configured"),
    ("no_adapter", "No adapter registered"),
])
def test_adapter_readiness_keeps_its_wording(key, label):
    html = render(**ok(inbox=inbox(pending=[_entry(adapter_readiness=key)])))
    assert label in html


def test_an_unready_adapter_in_live_mode_shows_why_a_dispatch_would_fail():
    """The one case where the adapter detail is a warning rather than
    background: approving would really dispatch, and the dispatch cannot
    work. In dry-run mode the same row is not blocked, because nothing
    would be sent."""
    live = _entry(adapter_readiness="not_configured", effective_mode="live",
                  adapter_detail="The firewall adapter has no credentials.")
    html = render(**ok(inbox=inbox(pending=[live])))
    assert "text-error" in html
    assert "no credentials" in html

    dry = dict(live, effective_mode="dry_run")
    assert "text-error" not in render(**ok(inbox=inbox(pending=[dry])))


def test_live_and_dry_run_modes_are_labelled_differently():
    dry = render(**ok(inbox=inbox(pending=[_entry()])))
    assert "would simulate" in dry
    assert "alert-info" in dry

    live_entry = _entry(effective_mode="live")
    html = render(**ok(inbox=inbox(
        pending=[live_entry],
        mode={"effective_mode": "live", "reason": "Live mode is on."},
    )))
    assert "would run live" in html
    assert "alert-warning" in html
    assert "Live mode" in html


# ---------------------------------------------------------------------------
# The decision buttons, which were a second copy of the service's rules
# ---------------------------------------------------------------------------


def test_a_pending_action_offers_both_decisions():
    html = render(**ok(inbox=inbox(pending=[_entry()])))
    verbs = _verbs(html)
    assert verbs == ["reject", "approve"]
    assert "Approve (simulate)" in html


def test_approve_says_dispatch_when_approving_would_dispatch():
    html = render(**ok(inbox=inbox(pending=[_entry(effective_mode="live")])))
    assert "Approve &amp; dispatch" in html
    assert "(simulate)" not in html


@pytest.mark.parametrize("status", [
    "approved", "executing", "completed", "failed", "rejected", "",
])
def test_an_already_decided_row_offers_no_decision(status):
    """The service refuses any status outside its own PENDING_STATUSES, in
    both approve_action and reject_action. The fragment reads that tuple
    rather than comparing a string of its own, so it cannot keep offering a
    button after the service stops accepting it."""
    assert _decisions_of(_entry(status=status)) == []


def test_the_pending_status_comes_from_the_service_not_from_this_page():
    from ion.services.playbook_action_service import PENDING_STATUSES

    assert PENDING_STATUSES == ("pending_approval",)
    for status in PENDING_STATUSES:
        assert _decisions_of(_entry(status=status)) != []


def test_a_requester_cannot_be_offered_approval_of_their_own_high_risk_action():
    """Separation of duty, the defect this conversion exists to fix.

    The page rendered Approve on every pending card and printed the warning
    next to it, so the only way to learn the server refuses was to click and
    read the error. approve_action refuses outright; the card now offers
    Reject alone.
    """
    mine = _entry(requires_second_person=True, requested_by_id=9)
    assert _decisions_of(mine, viewer_id=9) == ["reject"]

    html = render(**ok(inbox=inbox(pending=[mine], viewer_id=9)))
    assert "you cannot approve it" in html
    assert _verbs(html) == ["reject"]


def test_another_approver_is_still_offered_the_same_high_risk_action():
    """The negative control. A separation-of-duty rule that hid the button
    from everyone would stop the queue being workable at all."""
    mine = _entry(requires_second_person=True, requested_by_id=5)
    assert _decisions_of(mine, viewer_id=9) == ["reject", "approve"]

    html = render(**ok(inbox=inbox(pending=[mine], viewer_id=9)))
    assert "cannot be approved by analyst" in html


def test_a_high_risk_row_with_no_known_requester_is_not_treated_as_the_viewer():
    """`requested_by_id` is None when the column is empty. A bare equality
    would make None == None true for a viewer with no id and hide the
    button for a reason that does not exist."""
    orphan = _entry(requires_second_person=True, requested_by_id=None,
                    requested_by=None)
    assert _decisions_of(orphan, viewer_id=None) == ["reject", "approve"]


def test_the_decision_buttons_carry_parseable_args():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which would leave buttons that look live and do nothing."""
    html = render(**ok(inbox=inbox(pending=[_entry()])))
    args = re.findall(r"data-args='([^']*)'", html)
    assert args, "no decision buttons rendered"
    for raw in args:
        parsed = json.loads(raw.replace("&#34;", '"'))
        assert parsed[0] == 12
        assert parsed[1] in ("approve", "reject")


# ---------------------------------------------------------------------------
# The rules above, pinned against the service that enforces them
# ---------------------------------------------------------------------------


def _seed_pending(session, *, requires_approval: bool):
    from ion.models.sla import PlaybookAction, PlaybookActionLog
    from ion.models.user import User

    requester = User(username="requester", email="r@example.com",
                     password_hash="x")
    session.add(requester)
    session.commit()

    action = PlaybookAction(
        name="Block IP", action_type="block_ip", target_integration="firewall",
        requires_approval=requires_approval, risk_level="high",
    )
    session.add(action)
    session.commit()

    log = PlaybookActionLog(
        action_id=action.id, executed_by_id=requester.id,
        target="198.51.100.7", status="pending_approval",
    )
    session.add(log)
    session.commit()
    return requester.id, log.id


def test_the_service_really_refuses_the_approval_the_card_withholds(session):
    """The anchor for the separation-of-duty test above.

    Without this, the fragment and the service could both change and stay
    consistent with each other's tests while disagreeing. This asserts the
    behaviour the hidden button corresponds to: the same user who requested a
    high-risk action cannot approve it, and can still reject it.
    """
    from ion.services import playbook_action_service as actions

    requester_id, log_id = _seed_pending(session, requires_approval=True)

    refused = actions.approve_action(session, log_id=log_id,
                                     approved_by_id=requester_id)
    assert refused["status"] == "error"
    assert "Separation of duty" in refused["error"]

    allowed = actions.reject_action(session, log_id=log_id,
                                    approved_by_id=requester_id)
    assert allowed.get("status") == "rejected"


def test_the_service_really_refuses_a_decision_on_a_decided_row(session):
    """The anchor for the status test above: the button is withheld because
    the server answers an error, not because of a rule written here."""
    from ion.services import playbook_action_service as actions

    requester_id, log_id = _seed_pending(session, requires_approval=False)
    assert actions.reject_action(session, log_id=log_id,
                                 approved_by_id=requester_id)["status"] == "rejected"

    for decide in (actions.approve_action, actions.reject_action):
        again = decide(session, log_id=log_id, approved_by_id=requester_id)
        assert again["status"] == "error"


# ---------------------------------------------------------------------------
# Numbers. Zero is a measurement, not a blank.
# ---------------------------------------------------------------------------


def test_case_zero_is_a_case_not_an_absence_of_one():
    """`is not none`, not truthiness. The JavaScript tested `case_id == null`
    and a truthiness port prints "Not linked to a case" for case 0."""
    html = render(**ok(inbox=inbox(pending=[_entry(case_id=0)])))
    assert "/cases/0" in html
    assert "Not linked to a case" not in html


def test_an_unlinked_action_says_so_rather_than_linking_to_nothing():
    html = render(**ok(inbox=inbox(pending=[
        _entry(case_id=None, case_title=None),
    ])))
    assert "Not linked to a case" in html
    assert "/cases/" not in html


def test_user_zero_is_a_user_not_nobody():
    """The JavaScript tested `decided_by_id == null`, with "nobody" reserved
    for a row no one has decided. A truthiness port prints "nobody" for user
    0, which names the wrong fact about who acted."""
    decided = _entry(status="rejected", decided_by=None, decided_by_id=0,
                     requested_by=None, requested_by_id=0)
    html = render(**ok(inbox=inbox(decided=[decided])))
    assert "decided by user 0" in html
    assert "requested by user 0" in html
    assert "nobody" not in html


def test_an_undecided_row_in_the_history_says_nobody_decided_it():
    """The negative control for the test above."""
    html = render(**ok(inbox=inbox(decided=[
        _entry(status="approved", decided_by=None, decided_by_id=None),
    ])))
    assert "decided by nobody" in html


def test_a_pending_count_of_zero_is_rendered_as_zero():
    """`is not none`: the count is a separate query from the rows and is
    capped at a different limit, so it is not the same number as the row
    count, and a truthiness test silently substitutes the row count for it."""
    html = render(**ok(inbox=inbox(pending=[_entry(), _entry(id=13)],
                                   pending_count=0)))
    assert re.search(r'class="badge[^"]*">\s*0\s*<', html), html


def test_the_pending_count_is_the_services_count_not_the_rows_shown():
    html = render(**ok(inbox=inbox(pending=[_entry()], pending_count=204)))
    assert "204" in html


# ---------------------------------------------------------------------------
# Decision history and what it may claim about the outside world
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stage,css", [
    ("requested", "badge-warning"), ("approved", "badge-info"),
    ("dispatched", "badge-success"), ("simulated", "badge-ghost"),
    ("rejected", "badge-ghost"), ("failed", "badge-error"),
    ("unknown", "badge-ghost"),
])
def test_an_outcome_stage_keeps_its_badge(stage, css):
    html = render(**ok(inbox=inbox(decided=[_entry(outcome={
        "stage": stage, "label": stage.title(),
        "external_confirmation": "none", "detail": "",
    })])))
    assert css in html


def test_only_a_real_dispatch_claims_anything_about_the_target():
    """external_confirmation is about the world outside ION, so a simulated
    run must not print it. "No external confirmation" under a dry run reads
    as a dispatch that went unacknowledged, which is the opposite of what
    happened: nothing was sent."""
    simulated = _entry(status="completed", outcome={
        "stage": "simulated", "label": "Simulated (dry run)",
        "external_confirmation": "none", "detail": "Nothing changed.",
    })
    assert "No external confirmation" not in render(
        **ok(inbox=inbox(decided=[simulated]))
    )

    dispatched = _entry(status="completed", outcome={
        "stage": "dispatched", "label": "Dispatched",
        "external_confirmation": "acknowledged", "detail": "Accepted.",
    })
    html = render(**ok(inbox=inbox(decided=[dispatched])))
    assert "Adapter acknowledged the call" in html


def test_acknowledged_is_not_rendered_as_verified():
    for key, label in [
        ("none", "No external confirmation"),
        ("acknowledged", "Adapter acknowledged the call"),
        ("verified", "Adapter verified the target changed"),
    ]:
        html = render(**ok(inbox=inbox(decided=[_entry(outcome={
            "stage": "dispatched", "label": "Dispatched",
            "external_confirmation": key, "detail": "",
        })])))
        assert label in html


def test_a_row_with_no_recorded_outcome_renders_no_badge():
    """An empty outcome dict is not a stage. The JavaScript rendered an empty
    ghost badge for it, which looks like a classified outcome with no name."""
    html = render(**ok(inbox=inbox(decided=[_entry(outcome={})])))
    assert not re.search(r'class="badge[^"]*">\s*</span>', html)


def test_the_history_timestamp_prefers_the_decision_over_the_request():
    row = _decided_view(_entry(created_at="2026-10-12T08:00:00+00:00",
                               updated_at="2026-10-12T09:30:00+00:00"))
    assert row["decided_at"] == "2026-10-12T09:30:00+00:00"

    undecided = _decided_view(_entry(updated_at=None))
    assert undecided["decided_at"] == "2026-10-12T08:30:11+00:00"


# ---------------------------------------------------------------------------
# Timestamps stay on the viewer's clock
# ---------------------------------------------------------------------------


def test_a_timestamp_is_emitted_for_the_viewers_clock_not_the_servers():
    """rapFmtTime called toLocaleString(), which is the viewer's clock. A
    server knows only its own, so the macro emits <time datetime> and
    static/js/local-time.js rewrites the text after every swap."""
    html = render(**ok(inbox=inbox(pending=[_entry()])))
    assert '<time datetime="2026-10-12T08:30:11+00:00"' in html
    assert 'data-ts-local="yes"' in html


def test_a_missing_timestamp_renders_the_fallback_not_the_epoch():
    html = render(**ok(inbox=inbox(pending=[_entry(requested_at=None)])))
    assert "1970" not in html
    assert "<time" not in html


# ---------------------------------------------------------------------------
# Empty, failed and switched off are three different claims
# ---------------------------------------------------------------------------


def test_an_empty_queue_says_nothing_is_waiting():
    html = render(**ok())
    assert "Nothing waiting" in html
    assert "No decisions yet" in html
    assert "could not be read" not in html


def test_a_failed_read_says_so_rather_than_showing_an_empty_queue():
    """The claim this page cannot afford to get wrong. "Nothing is waiting
    for you" ends the shift; "we could not look" means containment decisions
    may be sitting unanswered."""
    html = render(inbox=None, failed=True, surface_off=False)
    assert "could not be read" in html
    assert "not an empty queue" in html
    assert "Nothing waiting" not in html
    assert "No response action is awaiting a decision" not in html


def test_a_failed_read_prints_no_count_at_all():
    """Not 0. The count is unknown, and 0 is the one number that would be
    read as an answer."""
    html = render(inbox=None, failed=True, surface_off=False)
    assert not re.search(r'class="badge', html)
    assert "Awaiting decision" in html, "the heading locates the error"


def test_a_disabled_surface_is_neither_empty_nor_failed():
    """A 404 from the API meant the feature is off, which the JavaScript said
    in its own words. htmx does not swap a non-2xx body, so the route answers
    200 with this instead of letting the generic handler say "no longer
    available"."""
    html = render(inbox=None, failed=False, surface_off=True)
    assert "ION_RESPONSE_ACTIONS_ENABLED" in html
    assert "Nothing waiting" not in html
    assert "could not be read" not in html


def test_the_decisions_are_absent_from_every_non_data_state():
    """No state but the data one may render a button that posts a decision."""
    for ctx in (
        dict(inbox=None, failed=True, surface_off=False),
        dict(inbox=None, failed=False, surface_off=True),
        ok(),
    ):
        assert 'data-click-action="rapDecide"' not in render(**ctx)


# ---------------------------------------------------------------------------
# Enum unwrapping, kept as a guard rather than a live need
# ---------------------------------------------------------------------------


def test_a_status_handed_over_as_an_enum_member_is_still_read_by_value():
    """`PlaybookActionLog.status` is a String column today, so nothing here
    carries an enum member. The unwrap goes through ui._shared.plain anyway,
    because the comparison against the service's PENDING_STATUSES is by
    string: tightening that column to SQLEnum would otherwise silently stop
    every pending row offering a decision, with no error anywhere."""
    import enum

    class Status(str, enum.Enum):
        PENDING_APPROVAL = "pending_approval"

    assert _decisions_of(_entry(status=Status.PENDING_APPROVAL)) == [
        "reject", "approve",
    ]
    html = render(**ok(inbox=inbox(pending=[
        _entry(risk_level=Status.PENDING_APPROVAL),
    ])))
    assert "Status." not in html


# ---------------------------------------------------------------------------
# The route, the permission and the page
# ---------------------------------------------------------------------------


def _permissions_of(route) -> list[str]:
    """Every permission a route's dependency tree closes over."""
    out, stack = [], list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            out.append(cells["permission_name"])
        stack.extend(dep.dependencies)
    return out


def _api_permissions(path: str, method: str) -> list[str]:
    """What a live /api route really requires, read off the app."""
    from ion.web.server import app

    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", ()
        ):
            return _permissions_of(route)
    raise AssertionError(f"{method} {path} is not mounted")


def test_the_fragment_permission_matches_the_endpoint_it_mirrors():
    """A fragment must never be a softer way in than the API it mirrors.
    Read off the live routes rather than assumed from the decorators."""
    fragment = [p for r in router.routes for p in _permissions_of(r)]
    assert fragment == ["response:approve"]
    assert _api_permissions("/api/response/actions/inbox", "GET") == fragment


def test_the_actions_are_gated_on_the_same_permission_as_the_fragment():
    """What decides whether a viewer may approve. Both decisions take the
    same permission as reading the inbox, so a user who can see a button can
    use it and there is no button to hide on permission grounds. Asserted
    rather than assumed, because if approve ever takes a permission of its
    own this page starts offering it to people who lack it."""
    fragment = [p for r in router.routes for p in _permissions_of(r)]
    for path in ("/api/response/actions/{log_id}/approve",
                 "/api/response/actions/{log_id}/reject"):
        assert _api_permissions(path, "POST") == fragment, path


def _call_route(monkeypatch, **patches) -> str:
    """The route itself, not the template, with its reads stubbed.

    The template tests above render the three states directly, which proves
    the markup but not that the route ever selects the right one. Mutating
    the except-handler to pass an empty payload with `failed=False` left
    every one of those tests green, so this is the test that was missing.
    """
    from starlette.requests import Request

    from ion.web.ui import response_approvals as mod

    for name, value in patches.items():
        monkeypatch.setattr(mod, name, value)

    request = Request({
        "type": "http", "method": "GET", "path": "/ui/response-approvals",
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("testserver", 80), "root_path": "",
    })

    class _Viewer:
        id = 9

    body = mod.response_approvals_fragment(
        request=request, user=_Viewer(), session=object(),
    ).body
    return body.decode("utf-8")


def test_the_route_renders_the_failure_fragment_when_the_read_raises(monkeypatch):
    """Not an empty queue, and not a 500 either: htmx does not swap a non-2xx
    body, so a raising route would leave the spinner's generic alert instead
    of the wording that says what is and is not known."""
    def boom(session, decided_limit=50):
        raise RuntimeError("the inbox query failed")

    html = _call_route(monkeypatch, response_actions_enabled=lambda: True,
                       response_inbox_payload=boom)
    assert "could not be read" in html
    assert "not an empty queue" in html
    assert "Nothing waiting" not in html


def test_the_route_renders_the_disabled_fragment_when_the_surface_is_off(monkeypatch):
    html = _call_route(monkeypatch, response_actions_enabled=lambda: False)
    assert "ION_RESPONSE_ACTIONS_ENABLED" in html
    assert "could not be read" not in html


def test_the_route_renders_the_queue_when_the_read_succeeds(monkeypatch):
    """The positive control. Without it the two tests above pass for a route
    that only ever renders a failure."""
    html = _call_route(
        monkeypatch,
        response_actions_enabled=lambda: True,
        response_inbox_payload=lambda session, decided_limit=50: {
            "mode": {"effective_mode": "dry_run", "reason": "Dry-run mode."},
            "pending": [_entry()], "decided": [], "pending_count": 1,
        },
    )
    assert "Block IP at perimeter firewall" in html
    assert "could not be read" not in html
    assert _verbs(html) == ["reject", "approve"]


def test_the_json_endpoint_and_the_fragment_share_one_payload():
    from ion.web import response_api

    assert hasattr(response_api, "response_inbox_payload")
    assert hasattr(response_api, "response_actions_enabled")


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py does.

    Scoped to the inline script bodies on purpose: `hx-swap="innerHTML"` is
    an attribute telling htmx where to put server-rendered markup, which is
    the opposite of the thing being removed.
    """
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def _page_code() -> str:
    """The page's inline JavaScript with its comments removed.

    The comments name the helpers that were deleted, which is the point of
    them, so a test for those names has to read the code rather than the
    prose about it.
    """
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))
    assert js.strip(), "no inline script found, so this proves nothing"
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", js, flags=re.S)


def test_the_page_requests_the_fragment_on_load_and_on_refresh():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-trigger="load"' in src
    assert src.count('hx-get="/ui/response-approvals"') >= 2, (
        "Refresh re-requests the same URL, so refresh has one definition"
    )


def test_the_markup_builders_are_gone_from_the_page():
    code = _page_code()
    assert "rapEsc" not in code, "Jinja autoescapes"
    assert "rapFmtTime" not in code, "the ts macro emits timestamps"
    assert "RAP_RISK_BADGE" not in code, "the badge maps live on the server"
    assert "RAP_READINESS" not in code
    assert "RAP_CONFIRMATION" not in code
    assert "RAP_STAGE_BADGE" not in code
    assert "rapPendingCard" not in code and "rapDecidedRow" not in code


def test_the_decision_still_posts_and_then_re_requests_the_fragment():
    """The mutation stays a mutation. What changed is what follows it: it
    re-requests the fragment instead of rebuilding the cards, so a decision
    that raced another approver shows the winner's state."""
    code = _page_code()
    assert "/actions/${id}/${verb}" in code
    assert "method: 'POST'" in code
    assert "htmx.ajax('GET', '/ui/response-approvals'" in code


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means. A per-page listener is one copy per page of a
    decision about what an expired session is."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:afterRequest" not in src


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decisions_of(entry: dict, viewer_id: object = 9) -> list[str]:
    return [d["verb"] for d in _pending_view(entry, viewer_id)["decisions"]]


def _verbs(html: str) -> list[str]:
    return [
        json.loads(raw.replace("&#34;", '"'))[1]
        for raw in re.findall(r"data-args='([^']*)'", html)
    ]
