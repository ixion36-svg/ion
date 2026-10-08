"""A literal path must not be shadowed by an earlier parameterised one.

``GET /api/observables/allowlist`` returned::

    422 {"loc": ["path", "observable_id"],
         "msg": "Input should be a valid integer, ...", "input": "allowlist"}

because ``/observables/{observable_id}`` was registered earlier in the same
module and FastAPI matches in registration order. The new endpoint was
never reached, and the error named a parameter the caller had not sent,
which is a confusing way to be told the route does not exist.

This is a quiet failure mode: the route is defined, it appears in the
OpenAPI schema, and it 422s with a message about something else entirely.
It only shows up when somebody calls it. "Declare literal paths above
parameterised ones" is a rule that holds right up until the next person
appends an endpoint to the end of a long file, which is exactly what
happened here.

So the guard is structural rather than a convention: for every route in
the app, no earlier-registered route may swallow it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web.server import app

_PARAM = re.compile(r"\{[^}]+\}")


def _segments(path: str):
    return [s for s in path.split("/") if s]


def _shadows(earlier: str, later: str) -> bool:
    """Whether ``earlier`` matches every request ``later`` would."""
    a, b = _segments(earlier), _segments(later)
    if len(a) != len(b):
        return False
    saw_param_over_literal = False
    for seg_a, seg_b in zip(a, b):
        a_param = bool(_PARAM.fullmatch(seg_a))
        b_param = bool(_PARAM.fullmatch(seg_b))
        if a_param and not b_param:
            # A parameter standing where the later route has a literal:
            # this is the shadowing case.
            saw_param_over_literal = True
            continue
        if seg_a != seg_b:
            return False
    return saw_param_over_literal


def _routes():
    out = []
    for r in app.routes:
        path = getattr(r, "path", None)
        methods = getattr(r, "methods", None)
        if not path or not methods:
            continue
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            out.append((m, path))
    return out


def test_no_route_is_shadowed_by_an_earlier_one():
    routes = _routes()
    problems = []
    for i, (method, path) in enumerate(routes):
        for earlier_method, earlier_path in routes[:i]:
            if earlier_method != method:
                continue
            if _shadows(earlier_path, path):
                problems.append(
                    f"{method} {path} is unreachable: {earlier_method} "
                    f"{earlier_path} is registered first and matches it"
                )
    assert not problems, (
        "Routes registered earlier swallow these:\n  " + "\n  ".join(problems)
    )


def test_the_allowlist_routes_are_reachable():
    """The specific case that was broken."""
    paths = {p for _, p in _routes()}
    assert "/api/observable-allowlist" in paths
    assert "/api/observable-allowlist/{entry_id}" in paths


class TestTheShadowCheckItself:
    """A guard that cannot detect the thing it guards is worse than none."""

    def test_it_spots_the_real_case(self):
        assert _shadows("/observables/{observable_id}", "/observables/allowlist")

    def test_a_literal_does_not_shadow_a_parameter(self):
        assert not _shadows("/observables/allowlist", "/observables/{id}")

    def test_different_lengths_do_not_shadow(self):
        assert not _shadows("/observables/{id}", "/observables/allowlist/preview")

    def test_identical_paths_do_not_count(self):
        assert not _shadows("/observables/{id}", "/observables/{id}")

    def test_a_different_literal_prefix_does_not_shadow(self):
        assert not _shadows("/cases/{id}", "/observables/allowlist")
