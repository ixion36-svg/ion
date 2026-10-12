"""The URL matcher in tools/fragment_plan.py.

The tool's job is to tell a conversion which permission its page's API is
behind, because a fragment that is softer than the API it mirrors is not
visible in a diff. Two bugs in the first version made it answer confidently
and wrongly, which is worse than not answering, so both are pinned here.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import fragment_plan  # noqa: E402


GATES = {
    "/api/users": {"GET": ["require_permission('user:read')"],
                   "POST": ["require_permission('user:create')"]},
    "/api/users/assignable": {"GET": ["require_permission('alert:read')"]},
    "/api/users/{user_id}": {"GET": ["require_permission('user:read')"],
                             "DELETE": ["require_permission('user:delete')"]},
    "/api/admin/config/arkime": {"PUT": ["require_permission('system:settings')"]},
}


def _routes(url):
    return [r for r, _ in fragment_plan._match_gate(url, GATES)]


def test_an_interpolated_segment_does_not_match_a_literal_one():
    """The first version treated `${x}` as matching anything, so
    /api/users/${userId} resolved to /api/users/assignable and reported
    alert:read for an endpoint gated on user:read."""
    assert _routes("/api/users/${userId}") == ["/api/users/{user_id}"]


def test_a_literal_segment_prefers_the_literal_route():
    assert _routes("/api/users/assignable") == ["/api/users/assignable"]


def test_every_method_on_a_path_is_reported_separately():
    """Merging them reported user:create for a GET of /api/users, because
    POST has the stricter gate and the first version kept whichever had
    more of them."""
    hits = fragment_plan._match_gate("/api/users", GATES)
    assert len(hits) == 1
    methods = hits[0][1]
    assert methods["GET"] == ["require_permission('user:read')"]
    assert methods["POST"] == ["require_permission('user:create')"]


def test_an_unresolvable_url_returns_nothing_rather_than_a_wrong_answer():
    assert fragment_plan._match_gate("/api/nothing/here", GATES) == []


def test_a_selector_over_literal_routes_falls_back_but_is_labelled():
    """A page sometimes picks among literal routes with an interpolation.
    That is a guess, and the label is what keeps it from being read as the
    answer."""
    hits = _routes("/api/admin/config/${section}")
    assert hits == ["MAYBE /api/admin/config/arkime"]


def test_a_base_path_held_in_a_constant_is_substituted():
    js = "const CMP_API = '/api/compliance';\nfetch(`${CMP_API}/posture`)"
    assert fragment_plan._resolve_js_constants(js, ["${CMP_API}/posture"]) == [
        "/api/compliance/posture"
    ]


def test_a_computed_base_path_is_left_alone():
    """Substituting a guess here would report a permission for the wrong
    endpoint, which is the failure this whole file exists to prevent."""
    js = "const X = BASE + '/v2';\nfetch(`${X}/thing`)"
    assert fragment_plan._resolve_js_constants(js, ["${X}/thing"]) == ["${X}/thing"]
