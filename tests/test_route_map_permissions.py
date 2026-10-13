"""The route map must name a permission the route actually enforces.

A blank cell reads as unauthenticated. require_page_permission gates the
page routes and the tool did not recognise it, so those rows were blank.
require_permission was already recognised; this pins both, and a route
that really has no gate, so a matcher that stamps a permission on
everything cannot pass.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "route_map.py"


@pytest.fixture(scope="module")
def rows():
    spec = importlib.util.spec_from_file_location("route_map_permissions", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.collect()


def _one(rows, path: str, method: str) -> dict:
    found = [r for r in rows if r["path"] == path and method in r["methods"]]
    assert len(found) == 1, (path, method, found)
    return found[0]


def test_alerts_page_reports_alert_read_and_login_reports_nothing(rows):
    """/alerts is require_page_permission("alert:read"). /login has no gate."""
    assert _one(rows, "/alerts", "GET")["permission"] == "alert:read"
    assert _one(rows, "/login", "GET")["permission"] == ""
    # slowapi wraps the API login. The handler site is outside src/, and a
    # junctioned .venv makes Path.resolve() leave the repo. Blanking that
    # cell is not a permission result.
    api_login = _one(rows, "/api/auth/login", "POST")
    assert api_login["permission"] == ""
    assert api_login["file"].endswith("slowapi/extension.py")


def test_an_api_route_still_reports_require_permission(rows):
    """The old qualname match. A fix that only special-cases pages would
    leave this blank, and a fix that reads every string in the closure
    would add more than the permission."""
    assert _one(rows, "/api/users", "GET")["permission"] == "user:read"


def test_integration_access_names_both_permissions_it_accepts(rows):
    """require_integration_access is a gate with no closure cell: the names
    are literals. Either permission passes, and the map already joins a
    set with ' + '."""
    assert _one(rows, "/api/integrations/status", "GET")["permission"] == (
        "alert:read + integration:read"
    )
    # The public health check is not that helper and must stay blank.
    assert _one(rows, "/api/health", "GET")["permission"] == ""


def test_enrichment_lookup_reports_observable_enrich(rows):
    """_require_enrich checks observable:enrich in its body. The session
    dependency under it is not a second permission."""
    assert _one(rows, "/api/enrichment/lookup", "POST")["permission"] == (
        "observable:enrich"
    )


def test_a_module_gate_is_not_reported_as_a_permission(rows):
    """require_workforce_module 404s when the feature is off. It is not a
    permission, and it sits beside workforce:manage on this page."""
    assert _one(rows, "/workforce/profiles", "GET")["permission"] == "workforce:manage"
