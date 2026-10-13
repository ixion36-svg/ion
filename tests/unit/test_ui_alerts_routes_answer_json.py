"""Every alerts fragment route hands its whole context to render_view.

The rollout's invariant, asserted once over all of them rather than
seventeen times. What it is for:

  A route that assembles its template context inline has no name for the
  thing it renders. Nothing can be built against it, no type checker can
  hold it, and the markup ends up partly built on values the view function
  does not describe. Measured across the ui package before this work, 57
  of 132 fragment routes did that and only 27 handed over a single object.

  Once the context is one object, the same route can answer the markup or
  the object itself, which is what turns a change of rendering stack from
  a rewrite into something done one page at a time with the old page still
  working.

These tests read the source, because the question is structural: it is
about how the handler is written, not about what one payload renders. The
per-route behaviour is covered by the suites beside this one.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / "src/ion/web/ui/alerts.py"
SHARED = ROOT / "src/ion/web/ui/_shared.py"


def tree() -> ast.Module:
    return ast.parse(MODULE.read_text(encoding="utf-8"))


def route_handlers() -> list[ast.FunctionDef]:
    out = []
    for node in ast.walk(tree()):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and getattr(d.func, "attr", None) in (
                    "get", "post", "put", "patch", "delete"):
                out.append(node)
                break
    return out


def renders(fn: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(fn) if isinstance(n, ast.Call)
            and (getattr(n.func, "attr", None) or getattr(n.func, "id", None))
            in ("TemplateResponse", "render_view")]


def test_there_are_routes_to_check():
    """Guards every assertion below from passing on an empty list."""
    handlers = route_handlers()
    assert len(handlers) >= 15, f"only {len(handlers)} route handlers found"


def test_no_alerts_route_renders_a_template_directly():
    """templates.TemplateResponse takes a context expression, so a route
    calling it can assemble one inline. render_view takes an object."""
    offenders = [fn.name for fn in route_handlers()
                 if any(getattr(c.func, "attr", None) == "TemplateResponse"
                        for c in renders(fn))]
    assert offenders == [], offenders


def test_the_module_no_longer_reaches_for_the_jinja_environment():
    """`templates` is render_view's to use. An import of it here is the
    beginning of a route rendering its own way again."""
    text = MODULE.read_text(encoding="utf-8")
    assert "import plain, render_view" in text
    assert "templates." not in text


@pytest.mark.parametrize("fn", route_handlers(), ids=lambda f: f.name)
def test_every_render_hands_over_one_object(fn):
    """render_view's third argument must be a name, not a dict literal
    built at the call site. A literal there is the inline assembly this
    rollout removed, in a different shape."""
    for call in renders(fn):
        assert len(call.args) == 3, f"{fn.name}: render_view takes three"
        view = call.args[2]
        assert isinstance(view, (ast.Name, ast.Dict)), type(view).__name__
        if isinstance(view, ast.Dict):
            # A dict is allowed only where it is the complete context and
            # short enough to read at the call site, which is how the
            # closures that merge a route value into a view function read.
            assert any(k is None for k in view.keys), (
                f"{fn.name}: a context assembled key by key at the call "
                f"site has no name and nothing can be built against it")


def test_render_view_is_the_only_way_these_routes_answer():
    text = MODULE.read_text(encoding="utf-8")
    assert text.count("render_view(") >= 15
    assert text.count("templates.TemplateResponse(") == 0


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------


def test_the_helper_refuses_to_guess_when_the_caller_did_not_ask():
    """Imported and driven rather than read, because the negotiation is the
    one piece whose behaviour matters at runtime."""
    from ion.web.ui._shared import wants_json

    class Req:
        def __init__(self, accept):
            self.headers = {"accept": accept} if accept is not None else {}

    assert wants_json(Req("application/json")) is True
    # htmx, a browser, a bare client: all markup
    assert wants_json(Req("text/html, */*; q=0.01")) is False
    assert wants_json(Req("*/*")) is False
    assert wants_json(Req(None)) is False
    assert wants_json(Req("")) is False
    # naming both is taken as wanting the markup these routes are for
    assert wants_json(Req("application/json, text/html")) is False


def test_the_helper_does_not_mutate_the_view_it_is_given():
    """A route may read its own view after answering, and two of them do.
    render_view copies into the response rather than handing the object on.

    The JSON branch never touches the request, so a Starlette Request built
    from a bare scope is enough and no application is needed."""
    import json

    from starlette.requests import Request

    from ion.web.ui._shared import render_view

    request = Request({
        "type": "http", "method": "GET", "path": "/probe", "query_string": b"",
        "headers": [(b"accept", b"application/json")], "root_path": "",
    })
    view = {"a": 1, "rows": [1, 2]}
    before = json.dumps(view, sort_keys=True)
    res = render_view(request, "_fragments/alerts_systems.html", view)
    assert json.dumps(view, sort_keys=True) == before
    assert res.media_type == "application/json"
