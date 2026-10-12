"""The System Quirks table as a server-rendered fragment.

de_quirks.html built the scope chips, the status pill, the attribution cell,
the Review date and the verify/revert buttons out of string concatenation
and wrote the result into `#qk-content` with innerHTML at four sites. Those
are the cases below: each one is something the JavaScript either got right
and must keep, or got wrong and must stop doing.

Quirks are an advisory-suppression surface, so two of these matter more than
the rest. A status pill that reads the enum repr instead of the value makes
the SoD state unreadable, and a failed read rendered as an empty table says
"nothing is annotating your alerts" when the truth is "we could not look".

The rows are fixtures rather than live data for the render tests: the dev
database has no quirks, and an empty render proves nothing about the table,
which is all that moved. The action table is checked against the real
service on a real session, because that is the only way to know the buttons
offer what the service will accept.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.licensing import gating
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.web.templating import make_templates
from ion.web.ui.de_quirks import (
    _ACTIONS,
    PERMISSION,
    _as_dt,
    _row,
    _scope_chips,
    router,
)

FRAGMENT = "_fragments/de_quirks.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/de_quirks.html"
SERVER = ROOT / "src/ion/web/server.py"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _quirk(**over: Any) -> dict:
    base = {
        "id": 7,
        "title": "SCCM agent trips PowerShell rule nightly",
        "annotation": "Known-benign: the SCCM patch cycle on the web tier.",
        "justification": "Confirmed with platform team; signed binary, 02:00.",
        "priority_nudge": -3,
        "status": "pending",
        "expired": False,
        "review_date": "2026-11-01T00:00:00",
        "scope_rules": ["suspicious powershell execution"],
        "scope_hosts": ["web01"],
        "scope_users": [],
        "scope_ips": [],
        "scope_observables": [],
        "raised_by_username": "alice",
        "verified_by_username": None,
        "reverted_by_username": None,
    }
    base.update(over)
    return base


def rows(*quirks: dict) -> list[dict]:
    return [_row(q) for q in quirks]


def one(**over: Any) -> str:
    return render(quirks=rows(_quirk(**over)), status="all", failed=False)


# ---------------------------------------------------------------------------
# The row, which is what actually moved
# ---------------------------------------------------------------------------


def test_a_quirk_renders_its_row():
    html = one()
    assert "SCCM agent trips PowerShell rule nightly" in html
    assert "Known-benign: the SCCM patch cycle on the web tier." in html
    assert "raised: alice" in html
    assert "rule:suspicious powershell execution" in html
    assert "host:web01" in html


def test_the_status_pill_reads_the_value_not_the_enum_repr():
    """The guard the port would silently fail without.

    `SystemQuirk.status` is a SQLEnum column, so `to_dict()` hands back a
    `SystemQuirkStatus` member, not a string. The JavaScript never saw one:
    FastAPI serialised it to "pending" on the way out. Jinja renders with
    str(), and on Python 3.12 that is "SystemQuirkStatus.PENDING", so the
    pill would read the repr and the colour lookup would never match.
    """
    html = one(status=SystemQuirkStatus.PENDING)
    assert "SystemQuirkStatus" not in html
    assert ">pending<" in html
    assert "badge-warning" in html


@pytest.mark.parametrize("status,css", [
    ("pending", "badge-warning"),
    ("active", "badge-success"),
    ("reverted", "badge-error"),
])
def test_each_status_keeps_its_colour(status, css):
    assert css in one(status=status, expired=False)


def test_an_unknown_status_falls_back_to_a_neutral_pill():
    html = one(status="quarantined")
    assert "badge-ghost" in html
    assert ">quarantined<" in html


def test_an_expired_active_quirk_says_expired_instead_of_active():
    """An active quirk past its review date is inert, and the pill is the
    only place the table says so."""
    html = one(status="active", expired=True)
    assert ">expired<" in html
    assert ">active<" not in html


def test_an_unexpired_active_quirk_says_active():
    html = one(status="active", expired=False)
    assert ">active<" in html
    assert ">expired<" not in html


@pytest.mark.parametrize("expired", [None, "no"])
def test_an_expiry_that_is_not_a_measured_true_is_not_expired(expired):
    """Three states stay three, and the guard is `is True`, not truthiness.

    Absent means the expiry was never computed, and a quirk whose expiry is
    unknown is not a quirk known to have lapsed. A non-boolean is the same
    case and is the one a weaker guard gets wrong in both directions:
    truthiness reads the string "no" as expired, and `is not None` reads an
    honest False as expired. Either shows a quirk that is still in force as
    inert, which is the opposite of what the analyst needs.
    """
    html = one(status="active", expired=expired)
    assert ">active<" in html
    assert ">expired<" not in html


def test_a_reverted_quirk_is_never_labelled_expired():
    """Expiry only means something for a quirk that is otherwise live. A
    reverted quirk is already inert, and the JavaScript's `q.status ===
    'active' && q.expired` said so."""
    html = one(status="reverted", expired=True)
    assert ">reverted<" in html
    assert ">expired<" not in html


def test_verified_and_reverted_attribution_appear_when_present():
    html = one(status="reverted", verified_by_username="bob",
               reverted_by_username="carol")
    assert "verified: bob" in html
    assert "reverted: carol" in html


def test_an_unattributed_quirk_shows_a_dash_not_the_word_none():
    html = one(raised_by_username=None)
    assert "raised: —" in html
    assert "None" not in html


def test_jinja_escapes_what_the_hand_rolled_qkesc_used_to():
    """qkEsc() is gone. This is what replaces it."""
    html = one(title="<script>alert(1)</script>",
               annotation="<img src=x onerror=1>",
               scope_hosts=["<svg onload=1>"])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "<svg onload=1>" not in html


# ---------------------------------------------------------------------------
# priority_nudge, where zero is a decision
# ---------------------------------------------------------------------------


def test_a_nudge_of_zero_is_printed_rather_than_hidden():
    """`is not none`, not truthiness.

    The JavaScript did `q.priority_nudge ? ' · nudge ' + ... : ''`, so a
    recorded nudge of 0 rendered exactly like a row that never recorded one.
    0 is a decision not to deprioritise, and on a suppression surface the
    difference between "deliberately neutral" and "unknown" is the whole
    point of the column.
    """
    assert "nudge 0" in one(priority_nudge=0)


def test_a_negative_nudge_is_printed():
    assert "nudge -3" in one(priority_nudge=-3)


def test_a_missing_nudge_prints_nothing():
    html = one(priority_nudge=None)
    assert "nudge" not in html
    assert "None" not in html


# ---------------------------------------------------------------------------
# Scope, which is the quirk's blast radius
# ---------------------------------------------------------------------------


def test_every_scope_kind_gets_its_prefix():
    assert _scope_chips(_quirk(
        scope_rules=["r1"], scope_hosts=["h1"], scope_users=["u1"],
        scope_ips=["10.0.0.1"],
        scope_observables=[{"type": "domain", "value": "vendor.com"}],
    )) == ["rule:r1", "host:h1", "user:u1", "ip:10.0.0.1", "domain:vendor.com"]


def test_a_typeless_observable_still_shows_its_value():
    """qkEsc(undefined) returned '', so the JavaScript rendered ":value".
    Same shape here rather than the string "None"."""
    assert _scope_chips(_quirk(
        scope_rules=[], scope_hosts=[],
        scope_observables=[{"value": "vendor.com"}],
    )) == [":vendor.com"]


def test_a_non_dict_observable_is_skipped_not_crashed():
    assert _scope_chips(_quirk(
        scope_rules=[], scope_hosts=[], scope_observables=["vendor.com"],
    )) == []


def test_a_scopeless_quirk_shows_a_dash():
    """A quirk cannot be raised without a scope, so an empty one means the
    row lost its scope rather than never having had one. A dash is what the
    JavaScript showed and it is visible; an empty cell is not."""
    html = one(scope_rules=[], scope_hosts=[], scope_users=[], scope_ips=[],
               scope_observables=[])
    assert "—" in html


# ---------------------------------------------------------------------------
# The Review date, which is the expiry
# ---------------------------------------------------------------------------


def test_the_review_date_is_emitted_for_the_viewers_clock():
    """Never formatted into a locale string on the server. The macro emits
    the machine-readable instant and static/js/local-time.js decides."""
    html = one()
    assert '<time datetime="2026-11-01T00:00:00"' in html
    assert 'data-ts-format="date"' in html


def test_the_review_date_keeps_its_time_of_day():
    """`quirk_match` compares against the instant, so a quirk goes inert at
    that time of day. The JavaScript's `.slice(0,10)` dropped it."""
    assert "2026-11-01 00:00" in one()


def test_a_missing_review_date_says_so_rather_than_showing_the_epoch():
    html = one(review_date=None)
    assert "No review date" in html
    assert "1970" not in html


def test_an_unparseable_review_date_is_a_missing_one_not_a_crash():
    assert "No review date" in one(review_date="not a date")


@pytest.mark.parametrize("raw,expected", [
    ("2026-11-01T00:00:00", datetime(2026, 11, 1, 0, 0)),
    ("2026-11-01T00:00:00Z", datetime(2026, 11, 1, 0, 0)),
    (None, None),
    ("", None),
    ("nonsense", None),
])
def test_as_dt_parses_what_to_dict_emits(raw, expected):
    assert _as_dt(raw) == expected


def test_as_dt_passes_a_datetime_through():
    value = datetime(2026, 11, 1)
    assert _as_dt(value) is value


# ---------------------------------------------------------------------------
# The action buttons, which were a second copy of the service's rules
# ---------------------------------------------------------------------------


def test_the_action_table_covers_every_status_the_enum_has():
    """A state added to SystemQuirkStatus must fail here rather than render
    a row that silently offers no action at all."""
    assert set(_ACTIONS) == {s.value for s in SystemQuirkStatus}


def _probe(session, status: SystemQuirkStatus) -> int:
    quirk = SystemQuirk(
        title="probe", annotation="a", justification="j",
        status=status, review_date=datetime(2099, 1, 1),
        priority_nudge=0, raised_by_id=1, scope_rules=["r"],
    )
    session.add(quirk)
    session.commit()
    return quirk.id


def _accepts(fn: Callable, session, quirk_id: int) -> bool:
    try:
        fn(session, quirk_id, 2)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("status", list(SystemQuirkStatus))
def test_the_buttons_offer_exactly_what_the_service_accepts(session, status):
    """The JavaScript's two-branch `if` was a second copy of rules that live
    in de_quirk_service: verify refuses anything not pending, revert refuses
    anything already reverted. This drives the real service on a real row,
    so the table cannot offer a button the server will reject or hide one it
    would have allowed. The probe user is 2 and the raiser 1, so separation
    of duties is satisfied and only the status rule is under test."""
    from ion.services.de_quirk_service import revert_quirk, verify_quirk

    allowed = set()
    if _accepts(verify_quirk, session, _probe(session, status)):
        allowed.add("qkVerify")
    if _accepts(revert_quirk, session, _probe(session, status)):
        allowed.add("qkRevert")

    assert {a["action"] for a in _ACTIONS[status.value]} == allowed


def test_a_reverted_quirk_offers_a_dash_rather_than_an_empty_cell():
    html = one(status="reverted")
    assert 'data-click-action="qkVerify"' not in html
    assert 'data-click-action="qkRevert"' not in html
    assert "—" in html


def test_the_action_buttons_carry_parseable_args():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which would leave buttons that look live and do nothing."""
    html = one(status="pending")
    args = re.findall(r"data-args='([^']*)'", html)
    assert args, "no action buttons rendered"
    for raw in args:
        assert json.loads(raw.replace("&#34;", '"'))[0] == 7


# ---------------------------------------------------------------------------
# Empty is not filtered-empty, and neither is failed
# ---------------------------------------------------------------------------


def test_no_quirks_at_all_says_so_and_names_the_next_step():
    html = render(quirks=[], status="all", failed=False)
    assert "No quirks yet" in html
    assert "a different teammate verifies it" in html


def test_an_empty_filter_does_not_claim_there_are_no_quirks():
    """The JavaScript said "No quirks yet" whichever filter was on, which is
    wrong the moment Pending is selected and active quirks exist."""
    html = render(quirks=[], status="pending", failed=False)
    assert "No quirks yet" not in html
    assert "No pending quirks" in html
    assert "other statuses may have some" in html


def test_a_failed_read_says_so_rather_than_showing_an_empty_table():
    """"Nothing there" and "we could not look" lead to opposite actions on a
    surface whose rows annotate alerts. The JavaScript distinguished them
    ("Failed to load: 500") and so must this."""
    html = render(quirks=None, status="all", failed=True)
    assert "could not be read" in html
    assert "not an empty list" in html
    assert "No quirks yet" not in html
    assert "<table" not in html


def test_the_failed_state_keeps_the_card_chrome():
    """The filter and Refresh live in the page shell, so an error swap
    cannot remove the way out. The card stays so the error lands inside the
    panel rather than replacing it with a bare strip."""
    html = render(quirks=None, status="all", failed=True)
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
        if route.path == "/de/quirks" and "GET" in route.methods:
            return route
    raise AssertionError("GET /de/quirks not found in de_api")


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """A fragment must never be a softer way in than the API it mirrors. The
    permission is read out of the JSON route's own dependency rather than
    restated, so the two cannot drift."""
    assert PERMISSION == "de:read"
    assert _permission_of(_json_route()) == PERMISSION
    assert _permission_of(_fragment_route()) == PERMISSION


def test_the_fragment_carries_the_licence_module_gate():
    """/api/de/quirks gets require_de_module from its router mount, so a
    fragment without it would be a way to read quirks out of a deployment
    whose licence does not include the module."""
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


def test_the_route_renders_a_real_quirk_from_the_service(app, session, monkeypatch):
    """The fragment and GET /api/de/quirks share one query, so this drives
    de_quirk_service.list_quirks rather than a stand-in for it."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _probe(session, SystemQuirkStatus.PENDING)
    with TestClient(app) as client:
        resp = client.get("/ui/de-quirks")
    assert resp.status_code == 200
    assert "probe" in resp.text
    assert ">pending<" in resp.text
    assert "SystemQuirkStatus" not in resp.text


def test_the_route_filters_by_status(app, session, monkeypatch):
    monkeypatch.setattr(gating, "de_module_available", lambda: True)
    _probe(session, SystemQuirkStatus.PENDING)
    with TestClient(app) as client:
        resp = client.get("/ui/de-quirks", params={"status": "active"})
    assert resp.status_code == 200
    assert "probe" not in resp.text
    assert "No active quirks" in resp.text


def test_the_route_404s_when_the_module_is_licence_disabled(app, monkeypatch):
    """The state that is neither empty nor failed. Nothing about the quirk
    store leaks, and htmx-errors.js words the 404 for the user."""
    monkeypatch.setattr(gating, "de_module_available", lambda: False)
    with TestClient(app) as client:
        resp = client.get("/ui/de-quirks")
    assert resp.status_code == 404
    assert "probe" not in resp.text


def test_a_read_failure_renders_the_failure_fragment_not_an_empty_table(
    app, monkeypatch
):
    """200 with a fragment that says so, because htmx does not swap a 500
    and the user would be left reading the spinner."""
    monkeypatch.setattr(gating, "de_module_available", lambda: True)

    def boom(*_a, **_k):
        raise RuntimeError("quirk store unreachable")

    monkeypatch.setattr("ion.services.de_quirk_service.list_quirks", boom)
    with TestClient(app) as client:
        resp = client.get("/ui/de-quirks")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "No quirks yet" not in resp.text


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


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/de-quirks"' in src
    assert 'hx-trigger="load"' in src


def test_the_string_building_helpers_are_gone_from_the_page():
    src = PAGE.read_text(encoding="utf-8")
    assert "function qkEsc(" not in src, "Jinja autoescapes"
    assert "function qkRender(" not in src, "a row has one definition"
    assert "function qkPill(" not in src
    assert "function qkScope(" not in src


def test_the_filter_and_refresh_sit_outside_the_swap_target():
    """A control inside the fragment is removed by any render that omits it,
    so a failed read could take away the button that retries."""
    src = PAGE.read_text(encoding="utf-8")
    content = src.index('id="qk-content"')
    assert src.index('id="qk-status"') < content
    assert src.index('id="qk-refresh"') < content


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what a 401 does."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src
