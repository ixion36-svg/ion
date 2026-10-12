"""The URL extraction and matching in tools/fragment_plan.py.

The tool's job is to tell a conversion which permission its page's API sits
behind, because a fragment softer than the API it mirrors is not visible in
a diff. Every test here pins a bug that made it answer confidently and
wrongly, or not answer at all, which for this tool are both failures.
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


# ---------------------------------------------------------------------------
# Matching a fetched URL to a declared route
# ---------------------------------------------------------------------------


def test_an_interpolated_segment_does_not_match_a_literal_one():
    """The first version treated `${x}` as matching anything, so
    /api/users/${userId} resolved to the literal /api/users/assignable and
    reported alert:read for an endpoint gated on user:read."""
    assert _routes("/api/users/${userId}") == ["/api/users/{user_id}"]


def test_a_literal_segment_prefers_the_literal_route():
    assert _routes("/api/users/assignable") == ["/api/users/assignable"]


def test_every_method_on_a_path_is_reported_separately():
    """Merging them reported user:create for a GET of /api/users, because
    POST has the stricter gate and the first version kept whichever route
    carried more of them."""
    hits = fragment_plan._match_gate("/api/users", GATES)
    assert len(hits) == 1
    methods = hits[0][1]
    assert methods["GET"] == ["require_permission('user:read')"]
    assert methods["POST"] == ["require_permission('user:create')"]


def test_an_unresolvable_url_returns_nothing_rather_than_a_wrong_answer():
    assert fragment_plan._match_gate("/api/nothing/here", GATES) == []


def test_a_selector_over_literal_routes_falls_back_but_is_labelled():
    """A page sometimes picks among literal routes with an interpolation.
    That is a guess, and the label is what stops it being read as the
    answer."""
    assert _routes("/api/admin/config/${section}") == [
        "MAYBE /api/admin/config/arkime"
    ]


# ---------------------------------------------------------------------------
# Finding the fetches in the first place
# ---------------------------------------------------------------------------


def test_a_plain_string_url_is_found():
    assert fragment_plan._fetch_urls("fetch('/api/x')") == ["/api/x"]


def test_a_base_path_held_in_a_constant_is_substituted():
    js = "const CMP_API = '/api/compliance';\nfetch(`${CMP_API}/posture`)"
    assert fragment_plan._fetch_urls(js) == ["/api/compliance/posture"]


def test_a_url_built_by_concatenation_is_found():
    """The idiom that was invisible. detection_health.html fetches

        fetch(DH_API + '/metrics?days=' + encodeURIComponent(days))

    and the tool reported "0 fetches" for it, so the page it exists to help
    got no help at all. A regex anchored on a quote straight after
    `fetch(` cannot see this, which is why the argument is parsed instead.
    Fixing it took the tree-wide total from 381 resolved fetches to 621.
    """
    js = ("const DH_API = '/api/detection-health';\n"
          "fetch(DH_API + '/metrics?days=' + encodeURIComponent(days))")
    assert fragment_plan._fetch_urls(js) == [
        "/api/detection-health/metrics?days=${encodeURIComponent(days)}"
    ]


def test_a_nested_call_does_not_end_the_argument_early():
    """encodeURIComponent(x) contains a closing paren, so a scan to the
    first `)` truncates the path and changes its shape, which then matches
    a different endpoint or none."""
    js = "fetch('/api/x/' + encodeURIComponent(id) + '/y')"
    assert fragment_plan._fetch_urls(js) == ["/api/x/${encodeURIComponent(id)}/y"]


def test_a_second_argument_is_not_read_as_part_of_the_url():
    js = "fetch('/api/x', {method: 'POST', body: '/api/decoy'})"
    assert fragment_plan._fetch_urls(js) == ["/api/x"]


def test_a_computed_base_path_is_left_alone():
    """Substituting a guess here would report a permission for the wrong
    endpoint, which is the failure this whole file exists to prevent."""
    js = "const X = BASE + '/v2';\nfetch(`${X}/thing`)"
    assert fragment_plan._fetch_urls(js) == ["${X}/thing"]


def test_a_word_ending_in_fetch_is_not_the_global_fetch():
    """`prefetch(` is not fetch, and attributing a permission to a call
    that never happens is the same kind of wrong answer as the rest."""
    assert fragment_plan._fetch_urls("prefetch('/api/x')") == []
