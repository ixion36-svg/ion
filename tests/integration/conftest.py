"""Shared fixtures for integration tests."""

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
    # The session-factory module-level cache binds to the first engine it
    # sees; reset it before each test so the per-test temp_db is actually used.
    from ion.storage.database import reset_engine
    reset_engine()
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
    reset_engine()


@pytest.fixture
def make_system(temp_db):
    """Factory: make_system(name='X', department='Y', subprofile_id=N) -> CyabSystem.id

    Creates a CyabSystem row with the given kwargs and returns its id.
    Defaults: name='test-system'. Multiple calls in one test allowed.
    """
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    created = []

    def _make(**kw):
        kw.setdefault("name", "test-system")
        kw.setdefault("department", "TestDept")
        sys = CyabSystem(**kw)
        s.add(sys)
        s.commit()
        created.append(sys.id)
        return sys.id

    yield _make
    s.close()
