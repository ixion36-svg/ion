"""Every /api and /ui URL the front end names must be a route ION serves.

A fetch to a path no route answers does not raise anything a reader sees.
alerts.html posted its Translate button to /api/ai/translate for as long as
the button existed; the route is /api/translator/translate, so the request
404d, `resp.ok` was false, and the handler's catch showed "The comment
could not be translated" every time. Nothing in the test suite could see
it, because no test drove a URL string.

Three things make the question hard to answer by reading:

  server.py registers 19 canonical path aliases after the routers are
  mounted, so /api/alerts/triage/batch is real and appears in no decorator

  a router's prefix is applied at include_router, so the decorator's path
  is never the caller's path

  a base such as `const DE_API = '/api/de'` is concatenated at the call
  site and is correct despite matching no route on its own

tools/route_map.py already answers all three, by reading the built
application rather than the source. This drives it.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "route_map.py"


@pytest.fixture(scope="module")
def route_map():
    spec = importlib.util.spec_from_file_location("route_map", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def result(route_map):
    rows = route_map.collect()
    unmatched = route_map.match_references(rows, route_map.references())
    return rows, unmatched


def test_the_route_table_was_read_at_all(result):
    """Guards the two tests below from passing on an empty table."""
    rows, _ = result
    assert len(rows) > 500, f"only {len(rows)} routes built"
    assert any(r["path"].startswith("/ui/alerts/") for r in rows)


def test_every_referenced_path_resolves_to_a_route(result):
    _, unmatched = result
    assert unmatched == {}, "\n".join(
        f"  {url}  named in {', '.join(sorted(files))}"
        for url, files in sorted(unmatched.items()))


def test_the_alias_the_alerts_page_depends_on_is_still_registered(result):
    """/api/alerts/triage/batch is an alias, not a decorated route, and the
    queue's triage column comes through it. A change to the alias list in
    server.py would take it away silently."""
    rows, _ = result
    assert any(r["path"] == "/api/alerts/triage/batch" for r in rows)


def test_the_generated_map_is_current(route_map):
    """docs/ROUTE_MAP.md is checked in so it can be read without running
    anything. A route added without regenerating it makes the file wrong,
    which is worse than not having it."""
    rows = route_map.collect()
    unmatched = route_map.match_references(rows, route_map.references())
    expected = route_map.render_markdown(rows, unmatched)
    current = route_map.OUT.read_text(encoding="utf-8") if route_map.OUT.exists() else ""
    assert current == expected, (
        "docs/ROUTE_MAP.md is out of date; run python tools/route_map.py")
