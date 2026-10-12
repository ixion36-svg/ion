"""The GitLab issue browser as server-rendered fragments.

gitlab.html built the banner, the cards, the selects, the detail pane and
the comment thread with innerHTML, and escaped them with escapeHtml().
Those are the cases below. Each one names the defect it is there to catch,
and the arrangement is a value the defective version handles wrongly:

  * a non-boolean where a truthiness test and ``is true`` disagree,
  * a number that is 0, which a truthiness test treats as missing,
  * a read that raised, which must not render as an empty list,
  * a stored URL whose scheme is not one a link may use.

The rows are fixtures. Nothing here talks to a GitLab instance; the route
tests stub the endpoint functions the fragment calls, which is also how
they prove the fragment did not grow a second copy of the my-issues merge.
"""
from __future__ import annotations

import enum
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web import gitlab_api
from ion.web.templating import make_templates
from ion.web.ui.gitlab import (
    PERMISSION,
    _issue_view,
    _safe_color,
    flags_phase,
    result_phase,
    router,
)

FRAGMENT = "_fragments/gitlab.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/gitlab.html"
SERVER = ROOT / "src/ion/web/server.py"
MODULE = ROOT / "src/ion/web/ui/gitlab.py"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _issue(**over: Any) -> dict:
    base = {
        "id": 9,
        "iid": 9,
        "title": "Packet loss on the sensor",
        "description": "See the graph.",
        "state": "opened",
        "labels": ["bug"],
        "assignees": ["ada"],
        "author": "grace",
        "created_at": "2026-10-12T15:04:00+00:00",
        "updated_at": "2026-10-12T16:40:00+00:00",
        "web_url": "https://gitlab.example/acme/widgets/-/issues/9",
        "milestone": "Sprint",
        "due_date": "2026-11-01",
    }
    base.update(over)
    return base


def _cards(*issues: dict, colors: dict | None = None) -> str:
    views = [_issue_view(issue, colors or {"bug": "#ff0000"}) for issue in issues]
    return render(view="issues", failed=False, issues=views)


class _State(enum.Enum):
    """Not a str mixin, so str() is the repr. That is the defect."""

    OPENED = "opened"


class _User:
    id = 1
    username = "gitlab-tester"
    gitlab_username = "gl-tester"

    def has_permission(self, _name: str) -> bool:
        return True


class _Denied:
    id = 2
    username = "nobody"

    def has_permission(self, _name: str) -> bool:
        return False


def _deps(route) -> list:
    out, stack = [], list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _permissions(fn) -> set[str]:
    qual = getattr(fn, "__qualname__", "")
    if not qual.startswith("require_permission"):
        return set()
    cells = dict(zip(
        fn.__code__.co_freevars,
        (c.cell_contents for c in (fn.__closure__ or ())),
    ))
    name = cells.get("permission_name")
    return {name} if isinstance(name, str) else set()


@pytest.fixture
def app():
    from ion.auth.dependencies import get_current_user

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    yield application
    application.dependency_overrides.clear()


def _client(app) -> TestClient:
    return TestClient(app)


def _page() -> str:
    """The page with comments removed, so a comment cannot satisfy an assertion."""
    src = PAGE.read_text(encoding="utf-8")
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    return src


def _script(src: str) -> str:
    return "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))


# ---------------------------------------------------------------------------
# The gate. template:read, and not the detection-engineering licence.
# ---------------------------------------------------------------------------


def test_every_route_requires_template_read_and_not_the_de_licence():
    """fragment_plan.py reports require_permission('template:read') on every
    GitLab GET, and server.py mounts gitlab_router with no licence
    dependency. require_de_module would 404 a deployment that has GitLab
    and is not licensed for detection engineering, while those JSON routes
    would still answer. That is a softer story than the API, in the
    direction that hides a feature which is actually there.
    """
    routes = [r for r in router.routes if getattr(r, "dependant", None)]
    assert routes, "no routes, so this proves nothing"
    for route in routes:
        names = [getattr(call, "__qualname__", "") for call in _deps(route)]
        assert not any("require_de_module" in name for name in names), route.path
        assert not any("require_page_permission" in name for name in names), route.path
        found = set().union(*(_permissions(call) for call in _deps(route)))
        assert found == {PERMISSION} == {"template:read"}, route.path


def test_the_json_router_is_not_mounted_behind_the_de_licence():
    """The claim the test above is matching. If GitLab ever gains the
    licence gate, the fragment has to gain it too, in front of the
    permission, and this is what says they drifted."""
    src = SERVER.read_text(encoding="utf-8")
    mount = re.search(r"include_router\(\s*gitlab_router[^)]*\)", src)
    assert mount, "gitlab_router is no longer mounted"
    assert "require_de_module" not in mount.group(0)


def test_a_caller_without_template_read_is_forbidden(app):
    """The dependency runs. A route that forgot it would answer 200 with
    the banner to an account the JSON endpoint would refuse."""
    from ion.auth.dependencies import get_current_user

    app.dependency_overrides[get_current_user] = lambda: _Denied()
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert resp.status_code == 403
    assert "Connected to GitLab" not in resp.text


# ---------------------------------------------------------------------------
# Connection flags. Non-booleans are the case None does not catch.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("enabled,has_token,phase", [
    (True, True, "ready"),
    (False, True, "unconfigured"),
    (True, False, "unconfigured"),
    (False, False, "unconfigured"),
    (0, True, "unknown"),
    (True, 0, "unknown"),
    ("no", True, "unknown"),
    (True, "no", "unknown"),
    (None, True, "unknown"),
])
def test_flag_phase_keeps_non_booleans_out_of_the_false_branch(enabled, has_token, phase):
    """``if not enabled`` reads 0 and None as unconfigured, and ``if enabled``
    reads the string "no" as configured. Both are the wrong action."""
    assert flags_phase(enabled, has_token) == phase


@pytest.mark.parametrize("connected,phase", [
    (True, "connected"),
    (False, "refused"),
    ("no", "unknown"),
    (0, "unknown"),
    (None, "unknown"),
])
def test_a_connection_result_that_is_not_a_boolean_is_unknown(connected, phase):
    """The JavaScript's ``if (testResult.connected)`` treats "no" as
    connected, and ``if (!connected)`` treats 0 as refused. Neither was a
    boolean answer."""
    assert result_phase(connected) == phase


def _status(monkeypatch, config, test=None, test_calls=None):
    async def fake_config(_user):
        if isinstance(config, Exception):
            raise config
        return config

    async def fake_test(_user):
        if test_calls is not None:
            test_calls.append(True)
        if isinstance(test, Exception):
            raise test
        return test

    monkeypatch.setattr(gitlab_api, "get_gitlab_config_endpoint", fake_config)
    monkeypatch.setattr(gitlab_api, "test_gitlab_connection", fake_test)


def test_enabled_zero_is_not_reported_as_unconfigured(app, monkeypatch):
    """0 is not False. The false branch tells the operator to configure
    GitLab. That is the wrong instruction when the flag was not a boolean."""
    calls = []
    _status(monkeypatch, {"enabled": 0, "has_token": True, "token": "glpat-SECRET-VALUE"},
            test_calls=calls)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert resp.status_code == 200
    assert "connection state is unknown" in resp.text
    assert "GitLab Not Configured" not in resp.text
    assert "Connection Failed" not in resp.text
    assert "could not be read" not in resp.text
    assert calls == []
    assert "glpat-SECRET-VALUE" not in resp.text
    assert "hx-trigger" not in resp.headers


def test_has_token_string_no_does_not_count_as_configured(app, monkeypatch):
    """"no" is truthy. ``if enabled and has_token`` would call the test and,
    given a boolean refusal, print Connection Failed for a flag we never
    accepted as a boolean."""
    calls = []
    _status(
        monkeypatch,
        {"enabled": True, "has_token": "no"},
        test={"connected": False, "error": "token rejected"},
        test_calls=calls,
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "connection state is unknown" in resp.text
    assert "Connection Failed" not in resp.text
    assert "Connected to GitLab" not in resp.text
    assert "token rejected" not in resp.text
    assert calls == []


@pytest.mark.parametrize("connected", ["no", 0])
def test_a_non_boolean_connection_is_not_a_refusal_or_a_success(app, monkeypatch, connected):
    _status(
        monkeypatch,
        {"enabled": True, "has_token": True},
        test={"connected": connected, "error": "token rejected", "project_path": "acme/widgets"},
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "connection state is unknown" in resp.text
    assert "Connection Failed" not in resp.text
    assert "Connected to GitLab" not in resp.text
    assert "token rejected" not in resp.text
    assert "acme/widgets" not in resp.text


def test_a_boolean_refusal_says_connection_failed_and_not_unconfigured(app, monkeypatch):
    _status(
        monkeypatch,
        {"enabled": True, "has_token": True},
        test={"connected": False, "error": "token rejected"},
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "Connection Failed" in resp.text
    assert "token rejected" in resp.text
    assert "GitLab Not Configured" not in resp.text
    assert "could not be read" not in resp.text
    assert "connection state is unknown" not in resp.text
    assert resp.headers["hx-trigger"] == "gitlab-unconfigured"


def test_boolean_false_flags_say_not_configured_and_do_not_test(app, monkeypatch):
    calls = []
    _status(monkeypatch, {"enabled": False, "has_token": True}, test_calls=calls)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "GitLab Not Configured" in resp.text
    assert "Connection Failed" not in resp.text
    assert "could not be read" not in resp.text
    assert calls == []
    assert resp.headers["hx-trigger"] == "gitlab-unconfigured"


def test_a_live_connection_names_the_project_and_arms_the_list(app, monkeypatch):
    _status(
        monkeypatch,
        {"enabled": True, "has_token": True, "token": "glpat-SECRET-VALUE"},
        test={
            "connected": True,
            "project_path": "acme/widgets",
            "web_url": "https://gitlab.example/acme/widgets",
            "token": "glpat-SECRET-VALUE",
        },
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "Connected to GitLab" in resp.text
    assert "acme/widgets" in resp.text
    assert 'href="https://gitlab.example/acme/widgets"' in resp.text
    assert "glpat-SECRET-VALUE" not in resp.text
    assert resp.headers["hx-trigger"] == "gitlab-ready"


def test_the_token_from_the_real_config_reader_is_not_rendered(app, monkeypatch):
    """The route has to call get_gitlab_config_endpoint, which already
    drops the token. Reading the config dict itself and rendering it would
    put the personal access token in the banner."""
    monkeypatch.setattr(gitlab_api, "get_gitlab_config", lambda: {
        "enabled": True,
        "url": "https://gitlab.example",
        "project_id": "acme/widgets",
        "token": "glpat-SECRET-VALUE",
        "verify_ssl": True,
        "sudo_enabled": False,
    })

    async def fake_test(_user):
        return {
            "connected": True,
            "project_path": "acme/widgets",
            "web_url": "https://gitlab.example/acme/widgets",
        }

    monkeypatch.setattr(gitlab_api, "test_gitlab_connection", fake_test)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert resp.status_code == 200
    assert "Connected to GitLab" in resp.text
    assert "glpat-SECRET-VALUE" not in resp.text


def test_a_javascript_project_url_is_not_a_link(app, monkeypatch):
    _status(
        monkeypatch,
        {"enabled": True, "has_token": True},
        test={
            "connected": True,
            "project_path": "acme/widgets",
            "web_url": "javascript:alert(1)",
        },
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    hrefs = re.findall(r'href="([^"]*)"', resp.text)
    assert hrefs == []
    assert "acme/widgets" in resp.text
    assert "javascript:alert(1)" not in resp.text


def test_a_protocol_relative_project_url_is_not_a_link(app, monkeypatch):
    _status(
        monkeypatch,
        {"enabled": True, "has_token": True},
        test={
            "connected": True,
            "project_path": "acme/widgets",
            "web_url": "//evil.example/phish",
        },
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert 'href="//' not in resp.text
    assert "acme/widgets" in resp.text


def test_a_thrown_config_read_is_not_a_refusal_or_an_empty_install(app, monkeypatch):
    _status(monkeypatch, RuntimeError("disk gone"))
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "Connection Failed" not in resp.text
    assert "GitLab Not Configured" not in resp.text
    assert "connection state is unknown" not in resp.text
    assert "hx-trigger" not in resp.headers


def test_a_thrown_connection_test_is_not_a_refusal(app, monkeypatch):
    _status(
        monkeypatch,
        {"enabled": True, "has_token": True},
        test=RuntimeError("gitlab down"),
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "could not be read" in resp.text
    assert "Connection Failed" not in resp.text
    assert "Connected to GitLab" not in resp.text
    assert "hx-trigger" not in resp.headers


def test_a_non_dict_test_result_is_unknown(app, monkeypatch):
    _status(monkeypatch, {"enabled": True, "has_token": True}, test=["nope"])
    with _client(app) as client:
        resp = client.get("/ui/gitlab/status")
    assert "connection state is unknown" in resp.text
    assert "Connected to GitLab" not in resp.text


# ---------------------------------------------------------------------------
# Issues. Zero, the scope word "my", and a failed read.
# ---------------------------------------------------------------------------


def _install_issues(monkeypatch, issues_fn, labels_fn=None):
    async def labels(_user=None, **_k):
        return {"labels": []}

    monkeypatch.setattr(gitlab_api, "list_gitlab_labels", labels_fn or labels)
    monkeypatch.setattr(gitlab_api, "list_gitlab_issues", issues_fn)


def test_scope_my_is_the_my_issues_merge_not_gitlabs_scope(app, monkeypatch):
    """The select says my/all. GitLab's scope is created_by_me /
    assigned_to_me. Forwarding "my" as scope asks for a scope that does
    not exist. The merge lives in list_gitlab_issues; this only sets the
    flag that turns it on, and it asks for the 50 the page used to ask for
    rather than the endpoint's default of 20."""
    seen = []

    async def fake(**kwargs):
        seen.append(kwargs)
        return {"issues": []}

    _install_issues(monkeypatch, fake)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues", params={"scope": "my", "state": "opened"})
    assert resp.status_code == 200
    assert seen[0]["my_issues"] is True
    assert seen[0]["scope"] is None
    assert seen[0]["per_page"] == 50
    assert seen[0]["state"] == "opened"
    assert seen[0]["current_user"].username == "gitlab-tester"


def test_a_search_for_zero_is_forwarded(app, monkeypatch):
    """``int(search) or None`` turns a search for 0 into no search, and the
    list that comes back is every issue. ``"0"`` is a search."""
    seen = []

    async def fake(**kwargs):
        seen.append(kwargs)
        return {"issues": []}

    _install_issues(monkeypatch, fake)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues", params={"search": "0", "scope": "all", "labels": ""})
    assert resp.status_code == 200
    assert seen[0]["search"] == "0"
    assert seen[0]["labels"] is None
    assert seen[0]["my_issues"] is False


def test_a_blank_search_is_not_a_filter(app, monkeypatch):
    seen = []

    async def fake(**kwargs):
        seen.append(kwargs)
        return {"issues": []}

    _install_issues(monkeypatch, fake)
    with _client(app) as client:
        client.get("/ui/gitlab/issues", params={"search": "", "labels": ""})
    assert seen[0]["search"] is None
    assert seen[0]["labels"] is None


@pytest.mark.parametrize("params", [
    {"scope": "bogus"},
    {"state": "bogus"},
    {"scope": "created_by_me"},
])
def test_an_unparseable_filter_is_a_bad_request_not_a_failed_read(app, monkeypatch, params):
    """"We could not look" is reserved for a read that failed. A filter
    value the endpoint cannot use is the caller's mistake."""
    called = []

    async def fake(**_kwargs):
        called.append(True)
        return {"issues": []}

    _install_issues(monkeypatch, fake)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues", params=params)
    assert resp.status_code == 422
    assert "could not be read" not in resp.text
    assert called == []


def test_a_failed_issue_read_is_not_an_empty_list(app, monkeypatch):
    async def boom(**_kwargs):
        raise RuntimeError("gitlab unreachable")

    _install_issues(monkeypatch, boom)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "No issues found" not in resp.text


def test_an_empty_issue_list_says_none_were_found(app, monkeypatch):
    async def fake(**_kwargs):
        return {"issues": []}

    _install_issues(monkeypatch, fake)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues")
    assert "No issues found." in resp.text
    assert "could not be read" not in resp.text


def test_a_missing_issues_key_is_not_an_empty_list():
    """None and [] are different claims, including when the flag was left
    at the success value. ``{% if not issues %}`` prints the empty state
    for both."""
    html = render(view="issues", failed=False, issues=None)
    assert "could not be read" in html
    assert "No issues found" not in html


def test_a_non_dict_issue_is_skipped_rather_than_crashing(app, monkeypatch):
    async def fake(**_kwargs):
        return {"issues": ["nope", _issue(title="real row")]}

    _install_issues(monkeypatch, fake)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues")
    assert resp.status_code == 200
    assert "real row" in resp.text
    assert "nope" not in resp.text


def test_iid_zero_and_title_zero_are_shown():
    """``{% if issue.iid %}`` and ``{% if issue.title %}`` both drop 0.
    Issue 0 with a title of 0 then looks like a row that has neither."""
    html = _cards(_issue(iid=0, title=0, labels=[], assignees=[]))
    assert "#0" in html
    assert "<strong>0</strong>" in html
    assert "None" not in html


def test_a_missing_title_is_blank_rather_than_the_word_none():
    html = _cards(_issue(title=None, labels=[], assignees=[], author=None))
    assert "<strong></strong>" in html
    assert "None" not in html
    assert "Created by —" in html


def test_the_state_pill_reads_the_value_not_the_enum_repr():
    """GitLab's state is a string today. plain() is what stops a SQLEnum
    member rendering as ``_State.OPENED``, which is what str() of a
    non-str enum is on 3.12. A str-mixin enum would hide this, so the
    fixture is not one."""
    html = _cards(_issue(state=_State.OPENED, labels=[], assignees=[]))
    assert "_State" not in html
    assert ">opened<" in html
    assert "issue-state opened" in html


def test_jinja_escapes_the_title_the_hand_rolled_helper_used_to():
    html = _cards(_issue(title="<script>alert(1)</script>", labels=[], assignees=[]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_a_hostile_label_colour_falls_back_and_a_hex_colour_is_kept(app, monkeypatch):
    """The colour is applied with setProperty from data-ion-style. A value
    that is not a bare hex colour must not be able to add a second
    declaration, and the fallback the JavaScript used was #6c757d."""
    async def labels(_user=None, **_k):
        return {"labels": [
            {"name": "hot", "color": "#ff00aa; background: url(javascript:alert(1))"},
            {"name": "ok", "color": "#FFFFFF"},
            {"name": "short", "color": "#fff"},
            {"name": "red", "color": "red"},
        ]}

    async def issues(**_kwargs):
        return {"issues": [_issue(
            labels=["hot", "ok", "short", "red"], title="coloured", assignees=[],
        )]}

    _install_issues(monkeypatch, issues, labels)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues")
    styles = re.findall(r'data-ion-style="([^"]*)"', resp.text)
    assert "background: #6c757d" in styles
    assert "background: #FFFFFF" in styles
    assert "background: #fff" in styles
    assert all(re.fullmatch(r"background: #[0-9A-Fa-f]{3,8}", style) for style in styles)
    assert "javascript" not in resp.text
    # data-ion-style is the allowed carrier. A real style attribute is not,
    # and a substring search for style= matches the data attribute.
    assert not re.search(r"(?<![\w-])style=", resp.text)


def test_safe_color_rejects_a_declaration_smuggled_after_the_hex():
    assert _safe_color("#ff00aa; background: url(javascript:alert(1))") == "#6c757d"
    assert _safe_color("#FFFFFF") == "#FFFFFF"
    assert _safe_color("#fff") == "#fff"
    assert _safe_color("  #abc  ") == "#abc"
    assert _safe_color(None) == "#6c757d"


def test_dates_are_not_rewritten_and_instants_use_the_ts_macro():
    """due_date is a date. Parsing it would print midnight, which the issue
    never carried. created_at is an instant, and the macro marks it for the
    viewer's clock instead of a server-formatted locale string."""
    html = _cards(_issue(
        due_date="2026-10-12",
        created_at="2026-10-12T15:04:00+00:00",
        labels=[],
        assignees=[],
    ))
    # The card shows created_at, not due_date. The detail test covers the
    # date-only field; this one covers the instant.
    assert 'data-ts-local="yes"' in html
    assert "2026-10-12 15:04 UTC" in html
    assert "Oct" not in html


def test_a_date_only_due_date_is_not_given_a_midnight(app, monkeypatch):
    async def labels(_user=None, **_k):
        return {"labels": []}

    async def one(issue_iid, current_user=None):
        return _issue(iid=issue_iid, due_date="2026-10-12", description="x", labels=[])

    monkeypatch.setattr(gitlab_api, "list_gitlab_labels", labels)
    monkeypatch.setattr(gitlab_api, "get_gitlab_issue", one)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues/9")
    due = re.search(r"Due Date</h4>\s*<div>(.*?)</div>", resp.text, re.S)
    assert due, resp.text
    assert ">2026-10-12</time>" in due.group(1)
    assert "00:00" not in due.group(1)
    assert "2026-10-12 00:00" not in resp.text


def test_a_javascript_issue_url_is_text_not_a_link():
    html = render(
        view="detail", failed=False, not_found=False, iid=9,
        issue=_issue_view(_issue(web_url="java\tscript:alert(1)", labels=[], assignees=[]), {}),
    )
    hrefs = re.findall(r'href="([^"]*)"', html)
    assert all(not h.lower().startswith("javascript") for h in hrefs)
    assert all(not h.startswith("//") for h in hrefs)
    assert "View in GitLab" in html


def test_a_real_issue_url_is_a_link():
    html = render(
        view="detail", failed=False, not_found=False, iid=9,
        issue=_issue_view(_issue(labels=[], assignees=[]), {}),
    )
    assert 'href="https://gitlab.example/acme/widgets/-/issues/9"' in html
    assert 'rel="noopener noreferrer"' in html


def test_description_zero_is_not_the_empty_state():
    """``{% if issue.description %}`` renders 0 as "No description"."""
    html = render(
        view="detail", failed=False, not_found=False, iid=4,
        issue=_issue_view(_issue(
            iid=4, description=0, title="t", labels=[], assignees=[], milestone=0,
        ), {}),
    )
    assert "No description" not in html
    assert "No milestone" not in html
    assert ">0</textarea>" in html
    assert "<div>0</div>" in html


def test_an_empty_description_is_the_empty_state_not_the_word_none():
    html = render(
        view="detail", failed=False, not_found=False, iid=4,
        issue=_issue_view(_issue(
            iid=4, description="", title=None, milestone=None, labels=[], assignees=[],
        ), {}),
    )
    assert "No description" in html
    assert "None" not in html
    assert "No milestone" in html


def test_a_comment_cannot_break_out_of_its_textarea():
    """Markdown is not passed through |safe. A body that closes the
    textarea and opens a script tag has to stay text inside the textarea."""
    html = render(
        view="comments", failed=False, not_found=False, iid=4,
        comments=[{
            "author": "ada",
            "created_at": "2026-10-12T15:04:00+00:00",
            "body": "</textarea><script>alert(1)</script>",
        }],
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;/textarea&gt;" in html
    assert "data-md-source" in html


def test_the_fragment_does_not_mark_markdown_safe():
    src = (ROOT / "src/ion/web/templates" / FRAGMENT).read_text(encoding="utf-8")
    code = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    assert "markdown.markdown" not in code
    assert "|safe" not in code.replace("|safe_url", "")
    assert "data-md-source" in code


# ---------------------------------------------------------------------------
# Detail and comments: 404, failure, empty, and inherited filters.
# ---------------------------------------------------------------------------


def _install_detail(monkeypatch, issue_fn, labels_fn=None):
    async def labels(_user=None, **_k):
        return {"labels": []}

    monkeypatch.setattr(gitlab_api, "list_gitlab_labels", labels_fn or labels)
    monkeypatch.setattr(gitlab_api, "get_gitlab_issue", issue_fn)


def test_issue_404_is_not_a_failed_read_and_not_an_empty_issue(app, monkeypatch):
    async def missing(issue_iid, current_user=None):
        raise HTTPException(status_code=404, detail="no such issue")

    _install_detail(monkeypatch, missing)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues/0")
    assert resp.status_code == 200
    assert "Issue #0 was not found" in resp.text
    assert "not a failed read" in resp.text
    assert "could not be read" not in resp.text
    assert "No description" not in resp.text


def test_issue_500_is_a_failed_read_and_not_a_missing_issue(app, monkeypatch):
    async def down(issue_iid, current_user=None):
        raise HTTPException(status_code=503, detail="down")

    _install_detail(monkeypatch, down)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues/4")
    assert resp.status_code == 200
    assert "Issue #4 could not be read" in resp.text
    assert "not a missing one" in resp.text
    assert "was not found" not in resp.text
    assert "No description" not in resp.text


def test_detail_and_comments_ignore_the_list_filters(app, monkeypatch):
    """Cards inherit #issues-list's hx-include, so a click sends state,
    labels and scope. Declaring those parameters on the detail route 422s
    the click, because an empty state is not in the Literal."""
    async def one(issue_iid, current_user=None):
        return _issue(iid=issue_iid, title="kept")

    async def notes(issue_iid, current_user=None, **kwargs):
        notes.seen = kwargs
        return {"comments": []}

    _install_detail(monkeypatch, one)
    monkeypatch.setattr(gitlab_api, "list_gitlab_issue_comments", notes)
    with _client(app) as client:
        detail = client.get("/ui/gitlab/issues/4", params={"state": "", "labels": "", "scope": "my", "search": "0"})
        comments = client.get(
            "/ui/gitlab/issues/4/comments",
            params={"state": "", "labels": "", "scope": "my", "search": "0"},
        )
    assert detail.status_code == 200
    assert "kept" in detail.text
    assert comments.status_code == 200
    assert "No comments yet." in comments.text
    assert "per_page" not in notes.seen


def test_comments_404_is_not_an_empty_thread(app, monkeypatch):
    async def missing(issue_iid, current_user=None, **_k):
        raise HTTPException(status_code=404, detail="no such issue")

    monkeypatch.setattr(gitlab_api, "list_gitlab_issue_comments", missing)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues/4/comments")
    assert "was not found" in resp.text
    assert "unknown rather than empty" in resp.text
    assert "No comments yet" not in resp.text
    assert "could not be read" not in resp.text


def test_a_failed_comment_read_is_not_an_empty_thread(app, monkeypatch):
    async def down(issue_iid, current_user=None, **_k):
        raise HTTPException(status_code=502, detail="bad gateway")

    monkeypatch.setattr(gitlab_api, "list_gitlab_issue_comments", down)
    with _client(app) as client:
        resp = client.get("/ui/gitlab/issues/4/comments")
    assert "could not be read" in resp.text
    assert "not an empty thread" in resp.text
    assert "No comments yet" not in resp.text
    assert "was not found" not in resp.text


def test_comments_none_is_not_the_empty_state():
    html = render(view="comments", failed=False, not_found=False, iid=4, comments=None)
    assert "could not be read" in html
    assert "No comments yet" not in html


def test_the_comment_box_sits_outside_the_comments_swap():
    """Refreshing the thread swaps #issue-comments-list. The draft has to
    be outside that element or the refresh deletes what the analyst typed."""
    html = render(
        view="detail", failed=False, not_found=False, iid=4,
        issue=_issue_view(_issue(iid=4, labels=[], assignees=[]), {}),
    )
    start = html.index('id="issue-comments-list"')
    end = html.index("</div>", start)
    box = html.index('id="new-comment"')
    assert end < box
    assert 'id="new-comment"' not in html[start:end]


# ---------------------------------------------------------------------------
# Catalogue. Id 0, a failed read, and filters that are not this route's.
# ---------------------------------------------------------------------------


def _install_catalog(monkeypatch, labels, members, milestones):
    async def lab(_user=None, **_k):
        if isinstance(labels, Exception):
            raise labels
        return {"labels": labels}

    async def mem(_user=None, **_k):
        if isinstance(members, Exception):
            raise members
        return {"members": members}

    async def mile(_user=None, **_k):
        if isinstance(milestones, Exception):
            raise milestones
        return {"milestones": milestones}

    monkeypatch.setattr(gitlab_api, "list_gitlab_labels", lab)
    monkeypatch.setattr(gitlab_api, "list_gitlab_members", mem)
    monkeypatch.setattr(gitlab_api, "list_gitlab_milestones", mile)


def _select(html: str, element_id: str) -> str:
    match = re.search(rf'<select id="{element_id}".*?</select>', html, re.S)
    assert match, element_id
    return match.group(0)


def test_member_and_milestone_zero_are_selectable(app, monkeypatch):
    """``if member["id"]`` drops id 0, and ``{% if milestone.title %}``
    drops a title of 0. The option then does not exist, so it cannot be
    the current selection either. Ids are compared as strings because the
    query arrives as "0". The milestone select is extracted on its own:
    a label whose name is 0 would otherwise satisfy a whole-page search
    for the same option text."""
    _install_catalog(
        monkeypatch,
        labels=[{"name": 0, "color": "#abc"}, {"name": "bug", "color": "#111111"}],
        members=[{"id": 0, "name": "Zero", "username": "z"}],
        milestones=[{"id": 0, "title": 0}],
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/catalog", params={
            "labels": "0",
            "assignee_id": "0",
            "milestone_id": "0",
            "issue_labels": "0",
            "state": "closed",
            "scope": "my",
        })
    assert resp.status_code == 200
    assert "could not be read" not in resp.text
    label_filter = _select(resp.text, "label-filter")
    issue_labels = _select(resp.text, "issue-labels")
    assignee = _select(resp.text, "issue-assignee")
    milestone = _select(resp.text, "issue-milestone")
    assert re.search(r'<option value="0" selected>0</option>', label_filter)
    assert re.search(r'<option value="0" selected>0</option>', issue_labels)
    assert 'value="0" selected' in assignee
    assert "Zero (@z)" in assignee
    assert re.search(r'<option value="0" selected>0</option>', milestone)


def test_a_failed_catalogue_read_keeps_the_select_and_says_so(app, monkeypatch):
    """Omitting the select on failure deletes it, because the select is
    only known to this response. An empty select with no sentence is the
    other lie: it says the project has no labels."""
    _install_catalog(
        monkeypatch,
        labels=RuntimeError("labels down"),
        members=RuntimeError("members down"),
        milestones=[],
    )
    with _client(app) as client:
        resp = client.get("/ui/gitlab/catalog", params={"assignee_id": "0"})
    assert "Labels could not be read" in resp.text
    assert "not an empty label list" in resp.text
    assert "Members could not be read" in resp.text
    assert "not an empty member list" in resp.text
    assert "Milestones could not be read" not in resp.text
    assert 'id="label-filter"' in resp.text
    assert 'id="issue-milestone"' in resp.text
    assignee = _select(resp.text, "issue-assignee")
    assert 'value="0" selected' in assignee


def test_an_empty_catalogue_is_not_a_failed_read(app, monkeypatch):
    _install_catalog(monkeypatch, labels=[], members=[], milestones=[])
    with _client(app) as client:
        resp = client.get("/ui/gitlab/catalog")
    assert resp.status_code == 200
    assert "could not be read" not in resp.text
    assert 'id="label-filter"' in resp.text


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """The server column, measured the way tools/ui_redesign_status.py does.
    Scoped to the inline script: hx-swap="innerHTML" is an attribute, and
    the string passed to htmx.ajax is the same attribute, not an assignment."""
    js = _script(_page())
    assert js.strip()
    assert not re.findall(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js)


def test_the_string_building_helpers_are_gone():
    js = _script(_page())
    assert "function escapeHtml" not in js
    assert "function formatDate" not in js
    assert "function loadIssues" not in js
    assert "toLocaleDateString" not in js


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    src = _page()
    assert not re.search(r'hx-trigger="[^"]*\[[^"]*\]', src)
    assert not re.search(r"hx-on[\s:=]", src)
    assert not re.search(r'hx-(?:vals|headers)="\s*js:', src)
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_zero_is_not_treated_as_a_missing_iid_in_the_script():
    """``if (!iid)`` is false for the string "0" only by accident of it
    being a string, and false for the number 0. The script rejects null
    and '' and keeps "0". It also must not parse a number and then drop 0
    with ``||``."""
    js = _script(_page())
    assert "if (!iid)" not in js
    assert "if (!currentIssue)" not in js
    assert "iid === null || iid === ''" in js
    assert re.search(r"parseInt\([^)]*\)\s*\|\|", js) is None
    assert "assigneeId !== ''" in js
    assert "milestoneId !== ''" in js


def test_the_filters_and_retry_sit_outside_the_swap_targets():
    src = _page()
    form_start = src.index('<form id="gl-filters"')
    form_end = src.index("</form>", form_start)
    form = src[form_start:form_end]
    list_at = src.index('id="issues-list"')
    assert form_end < list_at
    assert 'hx-get="/ui/gitlab/issues"' in form
    assert 'hx-trigger="change, submit"' in form
    assert "hx-include" not in form
    assert 'id="search-input"' in form
    assert 'id="label-filter"' in form
    list_tag = re.search(r'<div id="issues-list"[^>]*>', src).group(0)
    assert 'hx-include="#gl-filters"' in list_tag
    assert 'hx-trigger="gitlab-ready from:body"' in list_tag
    retry = src.index('id="gl-status-retry"')
    status = src.index('id="connection-status"')
    assert retry < status
    catalog = src.index('id="gl-catalog"')
    catalog_end = src.index("</div>", catalog)
    reload_at = src.index('id="gl-catalog-reload"')
    assert catalog_end < reload_at
    modal = src.index('id="issue-detail-modal"')
    close = src.index('data-click-action="closeIssueDetailModal"', modal)
    body = src.index('id="issue-detail-body"', modal)
    assert close < body


def test_the_page_keeps_the_settings_link_and_the_issue_api():
    """Route audit phase 6: configuration lives on /settings, and the issue
    browser's POST still names /api/gitlab/issues."""
    src = _page()
    assert 'href="/settings#gitlab"' in src
    assert 'id="config-modal"' not in src
    assert 'id="gitlab-token"' not in src
    for name in ("showConfigModal", "closeConfigModal", "saveConfig", "disableGitLab"):
        assert f"function {name}(" not in src
    assert "/api/gitlab/issues" in src
    for name in (
        "showCreateIssueModal", "closeCreateIssueModal", "createIssue",
        "closeIssueDetailModal", "addComment", "toggleIssueState",
    ):
        assert f"function {name}(" in src


def test_an_unknown_issue_state_is_not_reopened_by_default():
    """The old toggle used ``state === 'opened' ? 'close' : 'reopen'``, so
    any other state posted reopen. The script now refuses that state."""
    js = _script(_page())
    assert "state === 'opened'" in js
    assert "state === 'closed'" in js
    assert "was not changed" in js
