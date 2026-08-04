"""Route audit phase 4 — canonical /api/cases + /api/alerts/triage aliases.

`/api/elasticsearch/alerts/cases/*` and `/api/elasticsearch/alerts-triage/*`
read Postgres AlertCase / AlertTriage rows and call Ollama — nothing about them
is Elasticsearch. The prefix is a lineage artifact from when api.py was one
module.

Phase 4 publishes the accurate paths as ALIASES rather than re-prefixing, so the
legacy paths keep working byte-for-byte (docs/API.md is a PUBLIC integration
contract, and a 3xx preserving method+body across POST/PATCH/DELETE is fragile).

These tests pin the invariant that matters: every legacy route has a canonical
twin bound to the SAME endpoint object, so the two can never drift apart.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from ion.web.server import _PATH_ALIASES, app


def _api_routes():
    return [r for r in app.routes if isinstance(r, APIRoute)]


def _canonical_for(path: str):
    for legacy, canonical in _PATH_ALIASES:
        if path == legacy or path.startswith(legacy + "/"):
            return canonical + path[len(legacy):]
    return None


def test_every_legacy_route_has_a_canonical_alias():
    by_path = {}
    for r in _api_routes():
        by_path.setdefault(r.path, set()).update(r.methods or [])

    legacy = [p for p in by_path if _canonical_for(p)]
    assert legacy, "expected legacy case/triage routes to exist"

    missing = []
    for p in legacy:
        alias = _canonical_for(p)
        if alias not in by_path:
            missing.append((p, alias))
        elif not by_path[p].issubset(by_path[alias]):
            missing.append((p, f"{alias} (method mismatch)"))
    assert not missing, f"legacy routes without a matching alias: {missing}"


def test_alias_and_legacy_share_the_same_endpoint():
    """The whole point: one handler, two paths. If these ever became separate
    functions the two URLs could silently diverge."""
    endpoints = {}
    for r in _api_routes():
        endpoints.setdefault(r.path, set()).add(r.endpoint)

    checked = 0
    for path, eps in endpoints.items():
        alias = _canonical_for(path)
        if alias and alias in endpoints:
            assert eps == endpoints[alias], (
                f"{path} and {alias} are bound to different endpoints"
            )
            checked += 1
    assert checked >= 16, f"expected >=16 aliased routes, checked {checked}"


def test_canonical_paths_are_actually_accurate():
    """Sanity: the new names describe the resource, and no doubled prefixes."""
    paths = {r.path for r in _api_routes()}
    assert "/api/cases" in paths
    assert "/api/cases/{case_id}" in paths
    assert "/api/alerts/triage/batch" in paths
    assert not any("/api/api/" in p for p in paths)
    # legacy still served — this migration must not break integrators
    assert "/api/elasticsearch/alerts/cases" in paths
    assert "/api/elasticsearch/alerts/cases/{case_id}" in paths


@pytest.mark.parametrize("legacy,canonical", _PATH_ALIASES)
def test_alias_rules_are_prefix_shaped(legacy, canonical):
    assert legacy.startswith("/api/")
    assert canonical.startswith("/api/")
    assert not legacy.endswith("/") and not canonical.endswith("/")
