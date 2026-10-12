"""The /ui router discovers its page modules instead of listing them.

A module list would be one line that all 35 remaining conversions edit,
which is the single thing that turns independent work into conflicts.
Discovery removes it, and these tests are what discovery costs: a listed
module announces itself, a discovered one has to be checked for.

The failure discovery invites is a module that exists and serves nothing,
which on a fragment endpoint shows the user an empty panel that reads as
"no data" rather than "not wired up".
"""
from __future__ import annotations

import importlib
import pathlib
import pkgutil
import re
import sys

import pytest
from fastapi import APIRouter

import ion.web.ui as ui


def _module_names() -> list[str]:
    return sorted(
        m.name for m in pkgutil.iter_modules(ui.__path__)
        if not m.name.startswith("_")
    )


def test_discovery_finds_the_page_modules():
    """Positive control. An empty list would make every test below vacuous."""
    found = ui._page_modules()
    assert "service_accounts" in found
    assert "bob_eval" in found
    assert found == _module_names()


def test_helpers_are_excluded_by_the_underscore_convention():
    assert "_shared" not in ui._page_modules()


def test_every_page_module_exposes_a_router():
    for name in ui._page_modules():
        mod = importlib.import_module(f"ion.web.ui.{name}")
        assert getattr(mod, "router", None) is not None, name


def test_every_module_route_is_actually_mounted():
    """The test that catches the real failure mode.

    A module can define a perfectly good router and still serve nothing if
    the loader drops it. Compare what the modules declare against what the
    package mounts, rather than trusting the loop that does the mounting.
    """
    declared = set()
    for name in ui._page_modules():
        mod = importlib.import_module(f"ion.web.ui.{name}")
        for route in mod.router.routes:
            declared.add("/ui" + route.path)

    mounted = {r.path for r in ui.router.routes}
    assert declared, "no module declared any route, so this proves nothing"
    assert declared <= mounted, f"declared but not mounted: {declared - mounted}"


def _throwaway_package(tmp_path, name, body):
    """A real, importable package holding one module, outside the live tree.

    The loader is exercised against this rather than against ion/web/ui. An
    earlier version of these tests planted the probe in the live package and
    reimported it, which is a race: a sibling process starting a server
    inside that window imports a package containing a deliberately broken
    module and dies at startup. A guard that breaks the thing it guards
    during a parallel run is not a guard, and one of the conversions skipped
    running this file for exactly that reason.
    """
    # The package name has to be unique per call. Reusing one meant the
    # second test imported the first test's cached package out of
    # sys.modules, found no module of its own in it, and failed with a
    # ModuleNotFoundError that looked like the loader's fault.
    pkg_name = "zztmp_ui_pkg_" + name
    pkg = tmp_path / pkg_name
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / (name + ".py")).write_text(body, encoding="utf-8")
    sys.path.insert(0, str(tmp_path))
    return pkg_name, [str(pkg)]


def test_a_module_without_a_router_is_an_error_not_a_skip(tmp_path):
    """A silent skip is the whole hazard, so prove the loader refuses."""
    package, search_path = _throwaway_package(
        tmp_path, "no_router", "# deliberately defines no router\n"
    )
    with pytest.raises(ImportError, match="defines no `router`"):
        ui.mount_page_modules(APIRouter(), search_path, package)


def test_a_module_that_cannot_be_imported_is_not_swallowed(tmp_path):
    """A fragment module with a broken import must take startup down, not
    leave one page quietly serving 404s into an empty panel."""
    package, search_path = _throwaway_package(
        tmp_path, "broken", "import ion_module_that_does_not_exist\n"
    )
    with pytest.raises(ModuleNotFoundError):
        ui.mount_page_modules(APIRouter(), search_path, package)


def test_the_loader_mounts_what_it_discovers(tmp_path):
    """Positive control for the loader, not just for the live package."""
    module = (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/probe')\n"
        "def probe():\n"
        "    return 'ok'\n"
    )
    package, search_path = _throwaway_package(tmp_path, "good", module)
    target = APIRouter()
    assert ui.mount_page_modules(target, search_path, package) == ["good"]
    assert "/probe" in {r.path for r in target.routes}


# ---------------------------------------------------------------------------
# Guards that hold for every fragment, written once instead of per page
# ---------------------------------------------------------------------------


def _dependency_calls(route) -> list:
    """Every dependency callable reachable from a route, flattened."""
    out, stack = [], list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _required_permission(fn) -> str | None:
    """The permission string closed over by a require_permission dependency.

    require_permission returns a closure, so the name it checks is only in
    the closure cell. Reading it is what lets a test see the permission
    rather than merely see that some dependency exists.
    """
    if not getattr(fn, "__qualname__", "").startswith("require_permission."):
        return None
    cells = dict(zip(fn.__code__.co_freevars,
                     (c.cell_contents for c in (fn.__closure__ or ()))))
    return cells.get("permission_name")


def _fragment_routes() -> list:
    return [r for r in ui.router.routes if getattr(r, "dependant", None)]


# Fragments whose JSON counterpart gates on bare authentication rather than
# a named permission. The list is explicit so that dropping from a named
# permission to "any logged-in user" cannot happen quietly: it fails here
# and someone has to say why.
#
#   /ui/bug-reports   /api/bug-reports takes get_current_user. Filing and
#                     reading bug reports is open to every user by design.
BARE_AUTH_FRAGMENTS = {"/ui/bug-reports"}


def test_every_fragment_requires_authentication():
    """No fragment is an unauthenticated way to read data.

    Written once here rather than trusted 35 times. A conversion that
    forgets the dependency produces an endpoint serving the same rows to
    anyone who can reach the port, and nothing about the page it came from
    would look different.

    The check is `get_current_user` being reachable, not require_permission
    being present, because require_permission depends on it and because a
    fragment mirroring an endpoint that gates on bare authentication is
    correct. The first version of this test asserted a named permission and
    failed a conversion that had matched its API exactly.
    """
    routes = _fragment_routes()
    assert routes, "no fragment routes found, so this proves nothing"
    for route in routes:
        names = [getattr(c, "__qualname__", "") for c in _dependency_calls(route)]
        assert any(n.startswith("get_current_user") for n in names), (
            f"{route.path} requires no authentication"
        )


def test_only_the_listed_fragments_skip_a_named_permission():
    """A fragment must never be a softer way in than the API it mirrors.

    Authentication alone is the right gate for a few endpoints and the
    wrong one for most, and the difference is invisible in a diff. Keeping
    the exceptions in a list turns "this one is open to all users" into a
    claim somebody made on purpose.
    """
    bare = {
        route.path for route in _fragment_routes()
        if not any(_required_permission(c) for c in _dependency_calls(route))
    }
    assert bare == BARE_AUTH_FRAGMENTS, (
        f"newly on bare authentication: {bare - BARE_AUTH_FRAGMENTS}; "
        f"listed but now permissioned: {BARE_AUTH_FRAGMENTS - bare}"
    )


def test_no_fragment_uses_a_redirecting_page_dependency():
    """require_page_permission redirects to /login when a session expires.

    htmx would swap that login form into the middle of a dashboard, so the
    user is handed a password box that appears to be part of the page they
    were reading. A 403 is not swapped by default, which leaves the stale
    content visible and tells the truth.
    """
    for route in _fragment_routes():
        for call in _dependency_calls(route):
            name = getattr(call, "__qualname__", "")
            assert "require_page_permission" not in name, route.path
            assert "require_page_auth" not in name, route.path


def test_every_fragment_declares_an_html_response():
    """A fragment that forgets response_class is documented as JSON in the
    OpenAPI schema, and the next person wires a caller against that."""
    from fastapi.responses import HTMLResponse

    for route in _fragment_routes():
        assert route.response_class is HTMLResponse or issubclass(
            route.response_class, HTMLResponse
        ), f"{route.path} does not declare an HTML response"


def _html_literals(module_name: str) -> set[str]:
    """Every template path a fragment module mentions, however it is named.

    Matching `name="..."` was the obvious thing and it was wrong: six of
    the thirteen modules assign their template to a module-level constant
    and pass that, so the regex found nothing for them and the guard below
    passed while proving nothing. Hiding a template by hand is what showed
    it, not reading the code.
    """
    source = (pathlib.Path(ui.__path__[0]) / f"{module_name}.py").read_text(
        encoding="utf-8"
    )
    return set(re.findall(r"""['"]([\w./-]+\.html)['"]""", source))


def test_every_template_a_fragment_names_exists():
    """A module without its template is a route that 500s on every request.

    This happened. A `git add -A` while a conversion was still in progress
    committed ui/canaries.py without _fragments/canaries.html, so that
    route would have raised TemplateNotFound on every commit until the
    conversion landed. Nothing else would have caught it: the module
    imports, the route mounts, and every other guard here passes. Only a
    request fails.

    In a work tree where conversions are in progress this fails honestly
    and transiently, naming a module whose template has not been written
    yet. That is the guard doing its job, not a defect in it: check the
    committed tree rather than the working one before concluding anything.
    """
    templates_dir = pathlib.Path(ui.__file__).parent.parent / "templates"
    checked, missing = 0, []
    for name in ui._page_modules():
        for referenced in _html_literals(name):
            checked += 1
            if not (templates_dir / referenced).exists():
                missing.append(f"{name}.py -> {referenced}")
    assert checked, "no module named a template, so this proves nothing"
    assert not missing, f"fragment templates that do not exist: {missing}"


# Fragments that must carry a licence module gate as well as a permission.
# ION's detection-engineering pages are a paid module: /api/de/* gets
# require_de_module from the router mount in server.py, so a /ui fragment
# mirroring one has to declare the gate itself or it is reachable on a
# deployment that is not licensed for it.
#
# The convention is the check. Every DE page is named de_*, so the rule is
# derivable rather than a list somebody has to remember to extend, which is
# the point: the first DE fragment carried the gate correctly and nothing
# here would have noticed if the second did not.
MODULE_GATED_PREFIXES = {"de_": "require_de_module"}


def test_a_licence_gated_fragment_carries_its_module_gate():
    """A fragment is reachable on an unlicensed deployment without this.

    The gate also has to come before the permission, because router
    dependencies resolve first on the JSON side and the order decides what
    an unauthenticated request to a disabled module is told: 404, meaning
    this does not exist here, rather than 401, meaning log in and try
    again. The second answer tells an unlicensed caller that the feature is
    there and they are merely not signed in.
    """
    for name in ui._page_modules():
        gate = next((g for p, g in MODULE_GATED_PREFIXES.items()
                     if name.startswith(p)), None)
        if gate is None:
            continue
        mod = importlib.import_module(f"ion.web.ui.{name}")
        found = [
            getattr(c, "__qualname__", "")
            for route in mod.router.routes
            for c in _dependency_calls(route)
        ]
        assert any(gate in n for n in found), (
            f"ion.web.ui.{name} mirrors a licence-gated API but declares no "
            f"{gate}, so its fragment is reachable on a deployment that is "
            "not licensed for the module"
        )
