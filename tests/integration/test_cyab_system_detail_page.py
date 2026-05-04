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
