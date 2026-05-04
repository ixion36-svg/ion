"""Integration tests for the CyAB secondary tab strip + placeholder routes."""

import pytest


def test_coverage_placeholder_route_responds(client):
    r = client.get("/cyab/coverage")
    assert r.status_code == 200
    body = r.text.lower()
    assert "coverage" in body
    assert "sub-plan c" in body or "coming soon" in body


def test_audit_placeholder_route_responds(client):
    r = client.get("/cyab/audit")
    assert r.status_code == 200
    body = r.text.lower()
    assert "audit" in body
    assert "sub-plan c" in body or "coming soon" in body


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
