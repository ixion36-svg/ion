"""A joiner must be able to open their own onboarding.

Demonstrated live, 8 October 2026. A new account was created, the baseline
induction opened for it automatically, and the person signed in and went to
/workforce -- the page whose own docstring is "A person's own journey: the
gate, then role readiness". They got::

    {"detail":"Permission denied"}

The page required ``workforce:read``, which on this estate only ``admin``
and ``principal_analyst`` hold. So the page that shows somebody what they
have to do before they are allowed to do anything was visible to everybody
except the people it is for.

The circularity is the point: the permissions are withheld until the
mandatory training is verified, and the training is listed on a page that
needs permissions. A joiner could not start.

The API was never wrong. ``GET /api/workforce/journeys/me`` takes
``get_current_user`` and resolves the caller's own journeys, so there is
nothing to leak by letting anybody signed in open the page -- it can only
ever render their own. Only the page route was over-gated.

The other three workforce pages keep their permissions: profiles is the
schema a SOC edits for itself, people is the lead's verification queue,
and orbat is everybody's roster. Those are other people's business.

The four pages are now one. /workforce/people and /workforce/orbat are
gone and their content is the Team tab of /workforce; Setup holds the
establishment and offboarding. The page stayed open to anybody signed in,
for the reason above, and the gates moved to the TABS and the fragments
behind them -- so this file now checks them there. The guarantee is
unchanged and is the one this class has always made: opening the joiner's
own page must not open everybody else's.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_SERVER = (_SRC / "ion" / "web" / "server.py").read_text(encoding="utf-8")


_UI = _SRC / "ion" / "web" / "ui"


def _route(path: str) -> str:
    """The decorator and signature for a page route."""
    match = re.search(
        r'@app\.get\("' + re.escape(path) + r'".*?\n(async def .*?\):)',
        _SERVER, re.DOTALL)
    assert match, f"no route found for {path}"
    return match.group(1)


def _fragment(module: str, path: str) -> str:
    """The decorator block for one /ui fragment route.

    Read from the source rather than off the live app, like _route above,
    so a gate that is present but wired wrong still reads as present here
    and the complementary runtime check in test_workforce_who_verifies.py
    is what catches that.
    """
    source = (_UI / f"{module}.py").read_text(encoding="utf-8")
    match = re.search(
        r'@router\.(?:get|post)\(\s*"' + re.escape(path) + r'"\s*\)'
        r'|@router\.(?:get|post)\(\s*\n\s*"' + re.escape(path) + r'",.*?\n\)',
        source, re.DOTALL)
    assert match, f"no route found for {path} in ui/{module}.py"
    return match.group(0)


class TestTheJoinersOwnPage:
    def test_it_does_not_require_a_workforce_permission(self):
        """The whole point is that somebody with no role can open it."""
        sig = _route("/workforce")
        assert "require_page_permission" not in sig, (
            "/workforce shows a person their own journey. Requiring a "
            "permission makes it unreachable for exactly the people being "
            "onboarded, who have none yet."
        )

    def test_it_still_requires_signing_in(self):
        """Scoped to the caller, so it has to know who the caller is.

        require_page_auth rather than get_current_user: on a page route an
        unauthenticated visitor should be redirected to /login, not handed
        a raw JSON 401."""
        sig = _route("/workforce")
        assert "require_page_auth" in sig

    def test_it_is_still_behind_the_module_gate(self):
        """A deployment with the module off should still 404, not render an
        empty page."""
        sig = _route("/workforce")
        assert "require_workforce_module" in sig


class TestTheOtherPagesAreUnchanged:
    """Opening the joiner's own page must not open everybody else's."""

    def test_profiles_still_needs_manage(self):
        """The schema editor, now part of the Setup tab."""
        assert 'require_permission("workforce:manage")' in _fragment(
            "workforce_setup", "/workforce/setup")

    def test_editing_the_schema_still_needs_manage(self):
        """Every write behind Setup, not just the view of it.

        The old page put one gate on the route and the editor's writes
        went to /api, which carried their own. Both halves live here now,
        so each write states it rather than inheriting from a page.
        """
        setup = (_UI / "workforce_setup.py").read_text(encoding="utf-8")
        writes = setup.count('require_permission("workforce:manage")')
        assert writes >= 8, (
            f"only {writes} routes in ui/workforce_setup.py carry "
            "workforce:manage; the schema, establishment and offboarding "
            "writes must each hold it"
        )

    def test_the_team_fragment_still_needs_read(self):
        """The roster and the order of battle, now the Team tab."""
        assert 'require_permission("workforce:read")' in _fragment(
            "workforce_team", "/workforce/team")

    def test_the_setup_fragment_still_needs_manage(self):
        """The establishment and offboarding, now the Setup tab."""
        assert 'require_permission("workforce:manage")' in _fragment(
            "workforce_setup", "/workforce/setup")

    def test_verifying_still_needs_verify(self):
        """The write the old /workforce/people page gated by being behind
        workforce:verify. The page is gone; the write is not."""
        assert 'require_permission("workforce:verify")' in _fragment(
            "workforce_team", "/workforce/requirements/{requirement_id}/verify")

    def test_the_me_fragment_is_open_like_its_page(self):
        """Same reasoning as the page: a joiner has no permission yet, and
        the route resolves their own journeys and nobody else's."""
        assert "require_permission" not in _fragment(
            "workforce_journey", "/workforce/me")


class TestTheApiWasAlreadyRight:
    """It resolves the caller's own journeys, so there is nothing to leak."""

    def test_journeys_me_is_scoped_to_the_caller(self):
        api = (_SRC / "ion" / "web" / "workforce_api.py").read_text(
            encoding="utf-8")
        block = api.split('@router.get("/journeys/me"')[1][:600]
        assert "get_current_user" in block
        assert "live_journeys(session, user.id)" in block

    def test_journeys_me_takes_no_workforce_permission(self):
        api = (_SRC / "ion" / "web" / "workforce_api.py").read_text(
            encoding="utf-8")
        block = api.split('@router.get("/journeys/me"')[1][:600]
        assert "require_permission" not in block


class TestNavigation:
    def test_the_link_is_not_hidden_behind_a_permission_either(self):
        """nav_permissions hides a link the user cannot use. Now that
        anyone may open their own journey, hiding it would leave a joiner
        with no way to find the thing they are told to do."""
        from ion.web.nav_permissions import EXEMPT_PATHS

        assert "/workforce" in EXEMPT_PATHS, (
            "/workforce has no page permission, so it belongs in "
            "EXEMPT_PATHS or the nav will treat it as unmapped"
        )
