"""The /profile account card and Elastic lookup result as fragments.

profile.html built four blocks of markup with innerHTML: the six-field
account grid, the "Error loading profile" message it fell back to, and the
two outcomes of the Elastic UID lookup. Those are the cases below. Each one
is something the JavaScript either got right and must keep, or got wrong and
must stop doing.

Two of them matter more than the rest on this page. An account card that
renders an empty roles list the same way it renders a failed read tells a
user they have no roles when the truth is that nobody looked, and a Kibana
outage rendered as "no exact match found" tells them to go and change their
Elastic username over a result that is not one.

This page also handles a password change, and the form for it is
deliberately NOT a fragment. The guard for that is at the bottom: nothing
server-rendered may carry a password field or its value.
"""
from __future__ import annotations

import inspect
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.templating import make_templates
from ion.web.ui.profile import (
    ACCOUNT_FRAGMENT,
    RESOLVE_FRAGMENT,
    profile_fragment,
    profile_resolve_elastic_fragment,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/profile.html"
ACCOUNT_TPL = ROOT / "src/ion/web/templates" / ACCOUNT_FRAGMENT
RESOLVE_TPL = ROOT / "src/ion/web/templates" / RESOLVE_FRAGMENT


def render(name: str, **ctx: Any) -> str:
    return make_templates().env.get_template(name).render(**ctx)


def _flat(html: str) -> str:
    """One line of single-spaced text.

    The templates wrap their sentences, so a prose assertion against the raw
    output fails on the newline and indentation between two words rather
    than on the claim it was written to check. An earlier conversion lost a
    round to exactly that.
    """
    return re.sub(r"\s+", " ", html)


# ---------------------------------------------------------------------------
# The account card, which is what moved
# ---------------------------------------------------------------------------


def _user(**over: Any) -> dict:
    """The shape api.current_user_payload returns."""
    base = {
        "id": 3,
        "username": "lyndon",
        "email": "lyndon@example.test",
        "display_name": "Lyndon",
        "is_active": True,
        "must_change_password": False,
        "last_login": "2026-10-11T08:30:00",
        "roles": ["analyst", "lead"],
        "focus_role": None,
        "employment_type": "cs",
        "permissions": ["alert:read", "case:write"],
        "gitlab_username": "lyn",
        "elastic_username": "lyndon.k",
        "elastic_uid": "u_abc123",
        "keycloak_sub": "kc-sub-1",
    }
    base.update(over)
    return base


def account(user: Any = None, **over: Any) -> str:
    user = _user() if user is None else user
    ctx = {
        "user": user,
        "last_login": datetime(2026, 10, 11, 8, 30),
        "permissions": sorted(user["permissions"]) if user else None,
        "failed": False,
    }
    ctx.update(over)
    return render(ACCOUNT_FRAGMENT, **ctx)


def test_the_account_card_renders_every_field_the_javascript_built():
    html = account()
    assert "lyndon" in html
    assert "lyndon@example.test" in html
    assert "Lyndon" in html
    assert 'class="role-badge role-analyst"' in html
    assert 'class="role-badge role-lead"' in html
    assert "alert:read, case:write" in html


def test_the_permission_list_is_sorted_the_way_the_javascript_sorted_it():
    """`currentUser.permissions.sort().join(', ')`. The payload builds the
    list from a set, so its order is arbitrary and an unsorted render is a
    list that reshuffles itself on every refresh."""
    user = _user(permissions=["case:write", "alert:read", "system:settings"])
    html = account(user)
    assert "alert:read, case:write, system:settings" in html


def test_jinja_escapes_what_the_hand_rolled_escapehtml_used_to():
    """The JavaScript called `escapeHtml()` over username, email and display
    name. Jinja autoescapes, which retires it; this proves the replacement
    actually escapes rather than merely assuming it."""
    html = account(_user(display_name="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_a_role_name_cannot_inject_an_attribute():
    """The role name goes into a class attribute, which the JavaScript
    interpolated raw: `class="role-badge role-${r}"` with no escaping at
    all, unlike the fields around it."""
    html = account(_user(roles=['x" onmouseover="alert(1)']))
    assert 'onmouseover="alert(1)"' not in html
    assert "&#34;" in html or "&quot;" in html


def test_an_unset_display_name_says_so_rather_than_printing_a_dash():
    """A field the user has not set is not a field that failed to load. The
    JavaScript printed `-` for both, which reads as a value that is missing
    rather than one that was never given."""
    html = _flat(account(_user(display_name=None)))
    assert "Not set" in html
    assert "could not be read" not in html


@pytest.mark.parametrize("empty", [None, ""])
def test_a_blank_display_name_is_the_same_claim_as_none(empty):
    """PUT /api/auth/profile stores a blank as NULL, so both are "not set".
    This is the one field here where truthiness is the right test, and it is
    safe only because a failed read is a different branch."""
    assert "Not set" in _flat(account(_user(display_name=empty)))


def test_an_account_with_no_roles_says_so_instead_of_rendering_nothing():
    """`currentUser.roles.map(...).join(' ')` on an empty array is the empty
    string, so the Roles row rendered blank and looked like the load had not
    finished. An account with no roles is a real state and a visible one."""
    html = _flat(account(_user(roles=[])))
    assert "No roles assigned" in html
    assert "role-badge" not in html
    assert "could not be read" not in html


def test_an_account_with_no_permissions_says_so_instead_of_rendering_nothing():
    html = _flat(account(_user(permissions=[]), permissions=[]))
    assert "No permissions granted" in html
    assert "could not be read" not in html


def test_last_login_goes_through_the_time_macro_not_a_server_format():
    """The JavaScript called `toLocaleString()`, which is the viewer's
    clock. A server knows only its own, so a server-formatted string shows
    an analyst in another timezone the wrong time. The macro emits
    `<time datetime>` and static/js/local-time.js rewrites the text."""
    html = account()
    assert "<time datetime=" in html
    assert "data-ts-local=" in html
    assert "2026-10-11 08:30" in html


def test_a_user_who_has_never_signed_in_reads_never_not_an_epoch():
    """`last_login` is nullable and a null means the account has not signed
    in. The fallback must be that word, never a blank cell and never
    1 January 1970."""
    html = _flat(account(_user(last_login=None), last_login=None))
    assert "Never" in html
    assert "1970" not in html


def test_a_failed_read_says_so_and_never_borrows_the_empty_wording():
    """"You have no roles" and "we could not look" lead to opposite actions.
    A failure rendered as an empty account tells a user their access was
    revoked."""
    html = _flat(render(ACCOUNT_FRAGMENT, user=None, last_login=None,
                        permissions=None, failed=True))
    assert "could not be read" in html
    assert "unknown rather than none" in html
    assert "No roles assigned" not in html
    assert "No permissions granted" not in html
    assert "Not set" not in html


# ---------------------------------------------------------------------------
# The Elastic lookup result, where two states became three
# ---------------------------------------------------------------------------


def _resolve(**over: Any) -> dict:
    base = {
        "resolved": True,
        "elastic_uid": "u_abc123",
        "matched_username": "lyndon.k",
        "candidates_tried": ["lyndon.k", "lyndon"],
        "profiles_found": [
            {"uid": "u_abc123", "username": "lyndon.k",
             "email": "lyndon@example.test", "full_name": "Lyndon K"},
        ],
    }
    base.update(over)
    return base


def test_a_match_names_the_username_and_the_uid():
    html = _flat(render(RESOLVE_FRAGMENT, result=_resolve(), lookup_error=None))
    assert "alert-success" in html
    assert "lyndon.k" in html
    assert "u_abc123" in html


def test_no_match_lists_what_was_tried_and_what_was_found():
    html = _flat(render(
        RESOLVE_FRAGMENT,
        result=_resolve(resolved=False, elastic_uid=None,
                        matched_username=None),
        lookup_error=None,
    ))
    assert "alert-warning" in html
    assert 'Tried: "lyndon.k", "lyndon"' in html
    assert "Available profiles found" in html
    assert "Lyndon K" in html


def test_no_match_and_no_profiles_is_not_a_silent_empty_list():
    """`if (result.profiles_found && result.profiles_found.length)` left the
    whole explanation out, so the user saw the names tried and nothing about
    what to do next."""
    html = _flat(render(
        RESOLVE_FRAGMENT,
        result=_resolve(resolved=False, elastic_uid=None,
                        matched_username=None, profiles_found=[]),
        lookup_error=None,
    ))
    assert "no profiles for any of those names" in html
    assert "Available profiles found" not in html


def test_a_failed_lookup_is_not_a_no_match():
    """The third state the JavaScript did not have. resolve-elastic is an
    integration call, and it failing says nothing about whether the user has
    an Elastic identity. Worded as "no exact match found" it tells them to
    go and change their Elastic username over a non-result."""
    html = _flat(render(RESOLVE_FRAGMENT, result=None,
                        lookup_error="Kibana integration is not configured"))
    assert "alert-error" in html
    assert "Kibana integration is not configured" in html
    assert "unknown rather than no" in html
    assert "No exact match found" not in html
    assert "alert-warning" not in html


def test_a_profile_name_from_kibana_cannot_inject_markup():
    """These names come from another system's directory, which is the one
    place on this page the data is not the user's own typing."""
    html = render(
        RESOLVE_FRAGMENT,
        result=_resolve(resolved=False, elastic_uid=None, matched_username=None,
                        profiles_found=[{"uid": "u1",
                                         "username": "<img src=x onerror=1>",
                                         "email": "", "full_name": ""}]),
        lookup_error=None,
    )
    assert "<img src=x" not in html
    assert "&lt;img" in html


# ---------------------------------------------------------------------------
# The routes, which is where the state actually gets chosen
# ---------------------------------------------------------------------------


class _Role:
    def __init__(self, name, permissions=()):
        self.name = name
        self.permissions = [type("P", (), {"name": p})() for p in permissions]


class _User:
    id = 3
    username = "lyndon"
    email = "lyndon@example.test"
    display_name = "Lyndon"
    is_active = True
    must_change_password = False
    last_login = datetime(2026, 10, 11, 8, 30)
    employment_type = "cs"
    gitlab_username = "lyn"
    elastic_username = "lyndon.k"
    elastic_uid = "u_abc123"
    keycloak_sub = "kc-sub-1"
    roles = [_Role("analyst", ["case:write"]), _Role("lead", ["alert:read"])]
    effective_roles = roles


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


def test_the_route_renders_the_card_from_the_endpoints_own_payload(app):
    """The fragment and GET /api/auth/me share api.current_user_payload, so
    this drives that function rather than a stand-in for it. The permissions
    it lists come from effective_roles, which focus mode filters."""
    with TestClient(app) as client:
        resp = client.get("/ui/profile")
    assert resp.status_code == 200
    assert "lyndon@example.test" in resp.text
    assert "role-badge role-analyst" in resp.text
    assert "alert:read, case:write" in resp.text


def test_a_read_failure_renders_the_failure_fragment_not_an_empty_account(
    app, monkeypatch
):
    """Rendering the template with failed=True proves the template. This
    proves the ROUTE selects that state, which is the part that can be
    wrong. 200 with a fragment that says so, because htmx does not swap a
    500 and the user would be left reading the spinner."""
    def boom(*_a, **_k):
        raise RuntimeError("session gone")

    monkeypatch.setattr("ion.web.api.current_user_payload", boom)
    with TestClient(app) as client:
        resp = client.get("/ui/profile")
    assert resp.status_code == 200
    body = _flat(resp.text)
    assert "could not be read" in body
    assert "No roles assigned" not in body
    assert "role-badge" not in body


def test_a_payload_missing_its_permissions_is_a_failed_read_not_a_500(
    app, monkeypatch
):
    """The sort sits inside the try on purpose. A payload that did not give
    us what we asked for is a read that failed, and htmx cannot swap the
    alternative."""
    monkeypatch.setattr("ion.web.api.current_user_payload",
                        lambda _u: {"username": "lyndon"})
    with TestClient(app) as client:
        resp = client.get("/ui/profile")
    assert resp.status_code == 200
    assert "could not be read" in _flat(resp.text)


def test_neither_route_accepts_any_input_naming_an_account():
    """How "the caller only ever sees their own row" is enforced: there is
    no input to point somewhere else. get_current_user resolves the User
    from the session cookie, the payload helpers read that object, and
    neither route declares a path or query parameter, so there is no
    object-level check to mirror because there is no object to choose.

    Asserted against the mounted routes rather than read off the source, so
    adding `user_id: int = Query(...)` to either one fails here.
    """
    routes = {r.path: r for r in router.routes}
    assert set(routes) == {"/profile", "/profile/resolve-elastic"}
    for path, route in routes.items():
        assert route.dependant.query_params == [], path
        assert route.dependant.path_params == [], path
        assert route.dependant.body_params == [], path


def test_the_payload_helpers_take_the_authenticated_user_and_no_identifier():
    """The other half of the same claim, one level down. A helper taking a
    user id would let a future caller pass one."""
    from ion.web.api import current_user_payload, resolve_elastic_payload

    assert list(inspect.signature(current_user_payload).parameters) == [
        "current_user"
    ]
    assert list(inspect.signature(resolve_elastic_payload).parameters) == [
        "current_user", "session"
    ]


def test_resolve_renders_a_match_and_asks_the_page_to_re_read_its_fields(
    app, monkeypatch
):
    """The UID this persisted lives in an input the page owns, not in the
    fragment, so a match has to tell the page to re-read. Without the
    header the field stays stale until a reload and the user sees a match
    announced next to an empty UID box."""
    monkeypatch.setattr("ion.web.api.resolve_elastic_payload",
                        lambda _u, _s: _resolve())
    with TestClient(app) as client:
        resp = client.post("/ui/profile/resolve-elastic")
    assert resp.status_code == 200
    assert "lyndon.k" in resp.text
    assert resp.headers.get("HX-Trigger") == "profile:changed"


def test_resolve_does_not_ask_for_a_re_read_when_nothing_was_resolved(
    app, monkeypatch
):
    """Nothing was written, so there is nothing to re-read, and firing the
    event anyway would overwrite whatever the user had just typed into the
    Elastic username box with what is stored."""
    monkeypatch.setattr(
        "ion.web.api.resolve_elastic_payload",
        lambda _u, _s: _resolve(resolved=False, elastic_uid=None,
                                matched_username=None),
    )
    with TestClient(app) as client:
        resp = client.post("/ui/profile/resolve-elastic")
    assert resp.status_code == 200
    assert "HX-Trigger" not in resp.headers


def test_an_unconfigured_integration_is_the_error_state_not_the_no_match_state(
    app, monkeypatch
):
    """resolve_elastic_payload raises HTTPException(400) when Kibana is off.
    Letting that 400 out would hand the user htmx-errors.js's generic
    wording; answering it with the no-match fragment would be a lie. 200
    with the third state."""
    def unconfigured(*_a, **_k):
        raise HTTPException(status_code=400,
                            detail="Kibana integration is not configured")

    monkeypatch.setattr("ion.web.api.resolve_elastic_payload", unconfigured)
    with TestClient(app) as client:
        resp = client.post("/ui/profile/resolve-elastic")
    assert resp.status_code == 200
    body = _flat(resp.text)
    assert "Kibana integration is not configured" in body
    assert "No exact match found" not in body
    assert "HX-Trigger" not in resp.headers


def test_a_lookup_that_raises_anything_else_is_also_the_error_state(
    app, monkeypatch
):
    def boom(*_a, **_k):
        raise RuntimeError("kibana unreachable")

    monkeypatch.setattr("ion.web.api.resolve_elastic_payload", boom)
    with TestClient(app) as client:
        resp = client.post("/ui/profile/resolve-elastic")
    assert resp.status_code == 200
    body = _flat(resp.text)
    assert "could not be completed" in body
    assert "No exact match found" not in body


def test_both_routes_are_named_in_the_bare_auth_list():
    """The drop to bare authentication is a claim somebody made on purpose,
    and this is the other end of it. Asserted here as well so that removing
    the entries to make the registry test pass fails something local too."""
    from tests.unit.test_ui_fragment_registry import BARE_AUTH_FRAGMENTS

    assert "/ui/profile" in BARE_AUTH_FRAGMENTS
    assert "/ui/profile/resolve-elastic" in BARE_AUTH_FRAGMENTS


# ---------------------------------------------------------------------------
# The page, which keeps the credential entry and gives up the markup
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    src = PAGE.read_text(encoding="utf-8")
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", src, re.S))
    assert not re.search(r"innerHTML\s*\+?=", scripts)
    assert "insertAdjacentHTML" not in scripts
    assert not re.search(r"outerHTML\s*\+?=", scripts)


def test_the_page_requests_both_fragments_at_the_paths_they_are_mounted_on():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/profile"' in src
    assert 'hx-post="/ui/profile/resolve-elastic"' in src
    assert 'hx-trigger="load"' in src
    assert 'hx-target="#profile-info"' in src
    assert 'hx-target="#resolve-result"' in src


def test_the_controls_sit_outside_the_targets_they_replace():
    """A render that fails must not be able to remove the control that
    retries it. Refresh and Resolve are both in the page shell, and this is
    the assertion that keeps them there: a swap target holding its own
    trigger strands the panel on the first failure.
    """
    src = PAGE.read_text(encoding="utf-8")

    def inner(open_tag_id: str) -> str:
        start = src.index(f'id="{open_tag_id}"')
        start = src.index(">", start) + 1
        return src[start:src.index("</div>", start)]

    assert "Refresh" not in inner("profile-info")
    assert "hx-get" not in inner("profile-info")
    assert inner("resolve-result").strip() == ""
    assert 'id="profile-refresh"' in src
    assert 'id="resolve-btn"' in src


def _tag(src: str, element_id: str) -> str:
    """The one tag carrying this id, from `<` to the matching `>`.

    Asserted against the tag rather than the whole file on purpose. The
    first version of this looked for the attribute anywhere in the page,
    and the comment two lines above the button quotes the attribute by
    name, so removing it from the button left the test green. The mutation
    pass is what found that; nothing about reading the test showed it.
    """
    at = src.index(f'id="{element_id}"')
    start = src.rindex("<", 0, at)
    return src[start:src.index(">", at) + 1]


def test_the_resolve_button_posts_nothing_from_the_form_it_sits_in():
    """htmx includes an enclosing form's values with a non-GET request from
    a button inside it. The endpoint takes no input beyond who is asking,
    and this button is inside the identity form, so the values would travel
    for nothing."""
    tag = _tag(PAGE.read_text(encoding="utf-8"), "resolve-btn")
    assert 'hx-params="none"' in tag
    assert 'hx-post="/ui/profile/resolve-elastic"' in tag
    assert 'hx-target="#resolve-result"' in tag
    assert 'hx-disabled-elt="this"' in tag


def test_the_account_card_asks_for_its_fragment_on_load():
    """The same shape of claim, on the tag rather than the file, for the
    same reason."""
    tag = _tag(PAGE.read_text(encoding="utf-8"), "profile-info")
    assert 'hx-get="/ui/profile"' in tag
    assert 'hx-trigger="load"' in tag
    assert 'hx-swap="innerHTML"' in tag


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    """ION serves script-src without unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing. The markup
    still reads correctly and every HTTP check still passes, which is how
    one converted page shipped a dead Enter key."""
    src = PAGE.read_text(encoding="utf-8")
    assert not re.search(r'hx-trigger="[^"]*\[[^]"]*\]', src)
    assert not re.search(r'hx-(?:vals|headers)="\s*js:', src)
    assert not re.search(r"\bhx-on[a-z:-]*\s*=", src)


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means. A per-page listener is one copy per page of a
    decision about what an expired session is."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


# ---------------------------------------------------------------------------
# The credential rule, which overrides the conversion
# ---------------------------------------------------------------------------


def test_no_server_rendered_fragment_touches_the_password_form():
    """The one part of this page a fragment is the wrong answer for.
    Re-rendering the change-password form from the server means the server
    echoing field values back into markup, so the form stays on the page and
    neither fragment knows it exists.

    This is a guard against a later well-meant "finish the conversion",
    which is exactly the change that would introduce it.
    """
    for tpl in (ACCOUNT_TPL, RESOLVE_TPL):
        text = tpl.read_text(encoding="utf-8").lower()
        assert "password" not in text, tpl.name
        assert 'type="password"' not in text, tpl.name


def test_the_password_inputs_carry_no_server_rendered_value():
    """Three inputs of type password on the page, and not one of them may
    have a value attribute, templated or literal."""
    src = PAGE.read_text(encoding="utf-8")
    inputs = re.findall(r"<input[^>]*type=\"password\"[^>]*>", src)
    assert len(inputs) == 3, inputs
    for tag in inputs:
        assert "value" not in tag, tag


def test_the_password_result_goes_to_a_toast_and_not_into_the_page():
    """The outcome of a password change says whether it succeeded and
    nothing more, and it leaves nothing behind. showToast in app.js assigns
    textContent on an element it removes after three seconds, so the
    response never becomes markup and never persists.

    The handler is also the only place the change-password response is read,
    which is what this keeps true: it must not reach a swap target.
    """
    src = PAGE.read_text(encoding="utf-8")
    body = src[src.index("async function changePassword"):]
    body = body[:body.index("\nasync function logout")]
    assert "showToast('Password changed successfully', 'success')" in body
    assert "hx-" not in body
    assert "resolve-result" not in body
    assert "profile-info" not in body


def test_the_page_still_reads_its_identity_fields_from_the_json_endpoint():
    """Deliberate, not left over. Serving the identity inputs from a
    fragment would put the Save control inside a swap target and would mean
    the server echoing entry-field values back. It also keeps the page
    usable for a must_change_password account, which is refused every path
    outside _PWD_CHANGE_ALLOWED_PREFIXES: /api/auth/me is on that list and
    /ui/profile is not.
    """
    from ion.auth.dependencies import _PWD_CHANGE_ALLOWED_PREFIXES

    src = PAGE.read_text(encoding="utf-8")
    assert "fetch('/api/auth/me')" in src
    assert "id-elastic-username').value" in src
    assert "/api/auth/me" in _PWD_CHANGE_ALLOWED_PREFIXES
    assert not any("/ui/profile".startswith(p)
                   for p in _PWD_CHANGE_ALLOWED_PREFIXES), (
        "/ui/profile is now allowlisted for a flagged user, so the account "
        "card loads for them too and this comment is stale"
    )
