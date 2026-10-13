"""Every converted page hands its fragment routes one named view model.

A route that assembles its template context inline has no name for the
thing it renders. Nothing can be built against it, no type checker can hold
it, and the markup ends up partly built on values the view function does
not describe. Measured across the ui package before this work, 57 of 132
fragment routes did that and only 27 handed over a single object.

Once the context is one object, the same route can answer the markup or the
object itself, which is what turns a change of rendering stack from a
rewrite into something done one page at a time with the old page still
working.

SCOPE IS BY ADOPTION, NOT BY A LIST

This checks every module in ion/web/ui that imports render_view. A page
converts by using the helper, and is covered from that moment; a page that
has not converted yet is not failed for it. The alternative, a list of
module names in this file, is a line every future conversion has to edit,
which is the one thing that makes independent work conflict.

The modules are discovered the same way the package discovers its routers.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
UI = ROOT / "src/ion/web/ui"


def converted() -> list[pathlib.Path]:
    """The ui modules that render through the shared helper."""
    out = []
    for path in sorted(UI.glob("*.py")):
        # _shared is the helper itself. Everything else is a page module,
        # including the underscore-prefixed ones a page splits itself into:
        # skipping those by prefix left ui/_training_plans.py, which is
        # converted, outside this suite entirely.
        if path.name in ("_shared.py", "__init__.py"):
            continue
        text = path.read_text(encoding="utf-8")
        if "render_view" in text and "import" in text:
            out.append(path)
    return out


def tree(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def route_handlers(path: pathlib.Path) -> list[ast.AST]:
    out = []
    for node in ast.walk(tree(path)):
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
            in ("TemplateResponse", "render_view", "_render")]


MODULES = converted()
IDS = [p.stem for p in MODULES]


def test_some_pages_have_converted():
    """Guards every assertion below from passing on an empty list."""
    assert MODULES, "no ui module imports render_view"
    assert "alerts" in IDS


@pytest.mark.parametrize("path", MODULES, ids=IDS)
def test_a_converted_module_renders_no_template_directly(path):
    """templates.TemplateResponse takes a context expression, so a route
    calling it can assemble one inline. render_view takes an object."""
    text = path.read_text(encoding="utf-8")
    assert "templates.TemplateResponse(" not in text
    assert "templates." not in text, (
        f"{path.name} still reaches for the Jinja environment; rendering "
        "is render_view's to do")


@pytest.mark.parametrize("path", MODULES, ids=IDS)
def test_every_render_in_a_converted_module_hands_over_one_object(path):
    """The third argument must be a name, not a dict literal built at the
    call site. A dict is allowed only where it spreads a view function's
    own result, which is how the closures that merge a route value into a
    view read."""
    for fn in route_handlers(path):
        for call in renders(fn):
            name = getattr(call.func, "attr", None) or getattr(call.func, "id", None)
            args = call.args
            view = args[-1] if args else None
            if name == "_render":
                # a page-local wrapper over render_view, same contract
                assert len(args) == 2, f"{path.name}:{fn.name}"
            else:
                assert len(args) == 3, f"{path.name}:{fn.name}"
            # The shape has to come from somewhere named: a local bound
            # to a view function's result, the call to one directly, or a
            # dict that spreads one. A bare literal at the call site names
            # nothing, which is the shape this rollout removed.
            assert isinstance(view, (ast.Name, ast.Call, ast.Dict)), (
                f"{path.name}:{fn.name} -> {type(view).__name__}")
            if isinstance(view, ast.Dict):
                assert any(k is None for k in view.keys), (
                    f"{path.name}:{fn.name}: a context assembled key by key "
                    "at the call site has no name and nothing can be built "
                    "against it")


@pytest.mark.parametrize("path", MODULES, ids=IDS)
def test_a_converted_module_puts_no_presentation_in_its_models(path):
    """A view model is the contract a renderer is built on. A CSS variable
    or a hex in it makes every reader inherit this theme's vocabulary, and
    two passes on alerts had to undo exactly that."""
    import re

    text = path.read_text(encoding="utf-8")
    hits = re.findall(r"""["'](var\(--[\w-]+\)|#[0-9a-fA-F]{6})["']""", text)
    assert hits == [], f"{path.name}: {hits}"


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------


def test_the_helper_refuses_to_guess_when_the_caller_did_not_ask():
    """The negotiation is the one piece whose behaviour matters at runtime,
    and a loose check would have htmx inserting a JSON document into every
    panel it swaps."""
    from ion.web.ui._shared import wants_json

    class Req:
        def __init__(self, accept):
            self.headers = {"accept": accept} if accept is not None else {}

    assert wants_json(Req("application/json")) is True
    assert wants_json(Req("text/html, */*; q=0.01")) is False
    assert wants_json(Req("*/*")) is False
    assert wants_json(Req(None)) is False
    assert wants_json(Req("")) is False
    # naming both is taken as wanting the markup these routes are for
    assert wants_json(Req("application/json, text/html")) is False


def test_the_helper_does_not_mutate_the_view_it_is_given():
    """A route may read its own view after answering. The JSON branch never
    touches the request, so a bare scope is enough and no app is needed."""
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
