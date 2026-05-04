"""Integration tests for the new per-system CyAB page."""

import pytest


@pytest.fixture
def admin_session(client):
    """Authenticated client (auth bypassed via dependency override)."""
    return client


@pytest.fixture
def seeded_system(temp_db):
    """Create a CyabSystem row to point the test at."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="prod-sso-test", department="Identity")
    s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_per_system_page_renders_with_system_name(admin_session, seeded_system):
    r = admin_session.get(f"/cyab/systems/{seeded_system}")
    assert r.status_code == 200, r.text
    assert "prod-sso-test" in r.text
    assert "system-detail" in r.text  # page-level marker class


def test_per_system_page_404_for_unknown_id(admin_session):
    r = admin_session.get("/cyab/systems/999999")
    assert r.status_code == 404


def test_progress_header_shows_completion_count(client, make_system):
    """Sticky header should show progress like '0 / 20' for a fresh system."""
    sys_id = make_system(name="ph-test")
    r = client.get(f"/cyab/systems/{sys_id}")
    assert r.status_code == 200
    # Default checklist is lazy-seeded with 20 items, all 'unknown'
    assert "0 / 20" in r.text or "0/20" in r.text
    assert "onboarding-progress" in r.text  # class on the partial


def test_progress_header_marks_critical_missing(client, make_system):
    """Critical-missing pill appears when critical items aren't done."""
    sys_id = make_system(name="ph-test-2")
    r = client.get(f"/cyab/systems/{sys_id}")
    assert r.status_code == 200
    # Default checklist has 3 critical items: HLD, NETWORK_TOPOLOGY, OWNERS
    assert "critical missing" in r.text.lower()


@pytest.mark.parametrize("tab", [
    "overview", "intake", "sources", "data-health",
    "detection", "audit-use-cases", "signoff",
])
def test_each_tab_endpoint_returns_partial(client, make_system, tab):
    """HTMX tab endpoint returns the partial HTML (no full page chrome)."""
    sys_id = make_system(name=f"tab-{tab}")
    r = client.get(f"/cyab/systems/{sys_id}/tab/{tab}")
    assert r.status_code == 200
    assert "<html" not in r.text  # partial, not full doc
    assert tab in r.text.lower() or "placeholder" in r.text.lower()


def test_unknown_tab_returns_404(client, make_system):
    sys_id = make_system(name="unknown-tab")
    r = client.get(f"/cyab/systems/{sys_id}/tab/bogus")
    assert r.status_code == 404
