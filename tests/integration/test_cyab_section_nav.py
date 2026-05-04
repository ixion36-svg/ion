"""Integration tests for the CyAB secondary tab strip + placeholder routes."""

import pytest


def test_coverage_route_responds(client):
    """Sub-plan C Task 9 replaced the 'coming soon' placeholder with the
    real fleet matrix; just assert the page returns 200 with coverage chrome.
    """
    r = client.get("/cyab/coverage")
    assert r.status_code == 200
    body = r.text.lower()
    assert "coverage" in body


def test_audit_placeholder_route_responds(client):
    """Sub-plan C Task 11 replaced the 'coming soon' placeholder with the
    real audit-trail page; just assert the page returns 200 with audit chrome.
    """
    r = client.get("/cyab/audit")
    assert r.status_code == 200
    body = r.text.lower()
    assert "audit" in body


def test_coverage_page_includes_section_nav(client):
    r = client.get("/cyab/coverage")
    assert "cyab-section-nav" in r.text
    # All 6 nav entries present
    for label in ("Overview", "Systems", "Scoping", "Onboard", "Coverage", "Audit"):
        assert label in r.text


def test_section_nav_marks_active_tab(client):
    r = client.get("/cyab/coverage")
    # Coverage tab should be flagged active when on /cyab/coverage
    assert 'data-active="coverage"' in r.text or 'is-active' in r.text


# ---------------------------------------------------------------------------
# Cross-page nav verification (Sub-plan B Task 8): every top-level CyAB URL
# must render the section nav with the correct tab marked active. Catches
# "I forgot to include the partial" regressions when adding a new page.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path,active", [
    ("/cyab",          "overview"),
    ("/cyab/systems",  "systems"),
    ("/cyab/onboard",  "onboard"),
    ("/cyab/coverage", "coverage"),
    ("/cyab/audit",    "audit"),
])
def test_every_cyab_page_renders_section_nav(client, path, active):
    r = client.get(path, follow_redirects=True)
    assert r.status_code == 200
    assert "cyab-section-nav" in r.text, f"{path} missing section nav"
    assert f'data-active="{active}"' in r.text, f"{path} wrong active tab"


def test_section_nav_includes_link_to_per_system_pages_via_systems(client):
    """The Systems link in the nav strip points to /cyab/systems."""
    r = client.get("/cyab")
    assert 'href="/cyab/systems"' in r.text
