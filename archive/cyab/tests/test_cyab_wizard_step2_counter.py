"""Integration test: wizard Step 2 live counter is driven by the shared
scoping engine — same engine that powers /cyab/scoping.

This proves the spec's "engine architecture: scope for all" promise: the
scoping page and the wizard Step 2 intake share one scoring backend, so
the live counter (use-case count, threat-actor matches, MITRE coverage)
agrees on every answer set.
"""

import re

# Use the established conftest ``client`` fixture (auth-overridden TestClient
# bound to a temp DB), matching every other CyAB integration test in this
# directory. The plan sketch redefined a local admin_session fixture, but
# that bypassed the dependency_overrides wired up in conftest.
#
# The same client is used for both surfaces — anonymous /cyab/scoping is
# public, and the wizard handler's auth dependency is already overridden
# to inject a fake admin.


def _start_wizard(client) -> str:
    """Start a wizard session and return its wid so step=2 has context."""
    r = client.get("/cyab/onboard", follow_redirects=False)
    assert r.status_code in (302, 303), r.text
    loc = r.headers["location"]
    return loc.split("wid=")[1].split("&")[0]


def test_wizard_step2_includes_counter_widget(client):
    """GET /cyab/onboard?wid=...&step=2 must render the counter region and
    point its HTMX form at the shared score endpoint."""
    wid = _start_wizard(client)
    r = client.get(f"/cyab/onboard?wid={wid}&step=2")
    assert r.status_code == 200, r.text
    body = r.text
    # HTMX swap target id for the live counter region
    assert "wizard-counter" in body
    # The intake form posts to the new shared score endpoint on every change
    assert "/api/cyab/onboard/score" in body


def test_onboard_score_endpoint_returns_counter_partial(client):
    """POST /api/cyab/onboard/score returns the same _scoping_counter.html
    partial that the scoping page uses (HTMX innerHTML swap)."""
    r = client.post(
        "/api/cyab/onboard/score",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200, r.text
    body = r.text
    # Counter partial has these headline labels
    assert "use cases" in body
    assert "MITRE" in body


def test_onboard_score_uses_same_engine_as_scoping(client):
    """Same answers must produce the same headline numbers on both surfaces.
    Confirms the 'one engine, two surfaces' architecture from the spec."""
    payload = {"org_sector": "tech", "concern_top": "supply_chain"}
    r1 = client.post("/api/cyab/scoping/score", data=payload)
    r2 = client.post("/api/cyab/onboard/score", data=payload)
    assert r1.status_code == 200 and r2.status_code == 200

    # Extract the headline numbers from the counter partial. The shared
    # partial renders three big numbers (use cases / actor matches /
    # MITRE %) inside coloured divs — pull them out by stripping HTML
    # tags and extracting integers in order.
    def headline_nums(html: str) -> list[str]:
        text = re.sub(r"<[^>]+>", " ", html)
        # First three integers in the partial are the three counters.
        return re.findall(r"\b\d+\b", text)[:3]

    nums1 = headline_nums(r1.text)
    nums2 = headline_nums(r2.text)
    assert nums1 == nums2, f"scoping={nums1} wizard={nums2}"
    # Sanity: the partial really did render three numeric counters
    assert len(nums1) == 3, f"got {len(nums1)} numbers: {nums1}"
