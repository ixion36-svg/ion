"""Integration tests for the new per-system CyAB page."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(temp_db, monkeypatch):
    """TestClient with the FastAPI app and a fresh DB.

    Overrides the page-level auth dependency to inject a fake admin user so
    page handlers can be exercised without a real login flow.
    """
    monkeypatch.setattr(
        "ion.storage.database.get_engine", lambda *_a, **_k: temp_db
    )
    from ion.auth.dependencies import require_page_permission
    from ion.models.user import User
    from ion.web.server import app

    fake_admin = User(
        id=1,
        username="admin",
        email="admin@localhost",
        password_hash="x",
        display_name="Administrator",
        is_active=True,
    )

    # Override every cached require_page_permission dependency with a no-op
    # that returns the fake admin. The factory builds a fresh callable per
    # call site, so we register one override per (perm) signature we care
    # about — for now just "alert:read" used by the new page handler.
    def _fake_require():
        return fake_admin

    # Override by replacing the actual dependency callable. FastAPI matches
    # overrides by the original callable identity, so we need to override
    # each instance returned by require_page_permission(...) used in routes.
    # Easiest: monkey-patch the factory to return our fake _before_ routes
    # are imported is too late; instead, override at the app level for the
    # specific dependency callables already registered.
    for route in app.router.routes:
        for dep in getattr(route, "dependant", None).dependencies if getattr(route, "dependant", None) else []:
            call = dep.call
            # require_page_permission returns a closure named "dependency"
            if getattr(call, "__name__", "") == "dependency":
                app.dependency_overrides[call] = _fake_require

    yield TestClient(app)
    app.dependency_overrides.clear()


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
