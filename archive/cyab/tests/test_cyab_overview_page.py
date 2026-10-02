"""Integration tests for the new /cyab Overview landing page."""

import pytest


@pytest.fixture
def seeded_systems(temp_db):
    """3 systems: 1 fully onboarded, 1 in-progress, 1 with critical-missing."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    a = CyabSystem(name="prod-onb", department="Identity", readiness_score=95, status="ACTIVE")
    b = CyabSystem(name="prod-wip", department="Net", readiness_score=40, status="DRAFT")
    c = CyabSystem(name="prod-crit", department="Endpoint", readiness_score=10, status="DRAFT")
    s.add_all([a, b, c])
    s.commit()
    ids = [a.id, b.id, c.id]
    s.close()
    yield ids


def test_overview_page_renders_with_kpi_strip(client, seeded_systems):
    r = client.get("/cyab")
    assert r.status_code == 200
    body = r.text.lower()
    # KPI labels per the spec
    assert "total systems" in body or "systems" in body
    assert "% onboarded" in body or "onboarded" in body
    assert "critical" in body
    assert "sign-off" in body or "signoff" in body


def test_overview_page_includes_section_nav(client):
    r = client.get("/cyab")
    assert "cyab-section-nav" in r.text
    # Overview tab marked active
    assert 'data-active="overview"' in r.text or "is-active" in r.text


def test_overview_page_includes_in_progress_feed(client, seeded_systems):
    r = client.get("/cyab")
    body = r.text
    assert "In progress" in body or "in-progress" in body.lower()
    # Most-recently-edited surfaces at least one of our seeded names
    assert any(name in body for name in ("prod-onb", "prod-wip", "prod-crit"))


def test_overview_page_has_ctas(client):
    r = client.get("/cyab")
    body = r.text
    assert "/cyab/onboard" in body
    assert "/cyab/systems" in body


def test_dashboard_api_includes_signoffs_this_week(client, seeded_systems):
    r = client.get("/api/cyab/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "signoffs_this_week" in data
    assert isinstance(data["signoffs_this_week"], int)


def test_legacy_cyab_html_template_not_referenced(client):
    """Confirm `/cyab` no longer renders cyab.html — bust any stale cache."""
    r = client.get("/cyab")
    # The legacy template had a unique `cyab-legacy` class marker we add to
    # the body in tests; if we see it, the migration didn't happen.
    assert "cyab-legacy" not in r.text
