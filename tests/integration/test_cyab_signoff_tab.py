"""Integration tests for the Sign-off tab — governance + Onboarding Pack
PDF link + signoff history.

The plan literal references ``admin_session`` + ``system_id`` fixtures.
We use the project-wide ``client`` + ``make_system`` from conftest (the
client fixture already injects an admin user via dependency overrides,
so no login is needed). ``make_system`` accepts arbitrary CyabSystem
kwargs incl. ``containment_authority``.
"""


def test_sign_onboarding_pack_requires_auth(temp_db, make_system):
    """POST /api/cyab/systems/{id}/onboarding-pack/sign returns 401 without auth."""
    from fastapi.testclient import TestClient
    from ion.storage.database import reset_engine
    import ion.models  # noqa: F401
    from ion.models.base import Base
    from ion.models.cyab import CyabSystem
    from ion.web.server import app
    from sqlalchemy.orm import sessionmaker

    Base.metadata.create_all(temp_db)
    s = sessionmaker(bind=temp_db)()
    sys = CyabSystem(name="auth-test", department="X")
    s.add(sys)
    s.commit()
    sys_id = sys.id
    s.close()

    import ion.storage.database as _db_mod
    _db_mod._engine = temp_db
    reset_engine()

    unauthenticated = TestClient(app, raise_server_exceptions=False)
    r = unauthenticated.post(
        f"/api/cyab/systems/{sys_id}/onboarding-pack/sign",
        json={"sign_soc_name": "Eve"},
    )
    assert r.status_code == 401

    reset_engine()


def test_patch_system_answers_requires_auth(temp_db, make_system):
    """POST /api/cyab/systems/{id}/answers returns 401 without auth."""
    from fastapi.testclient import TestClient
    from ion.storage.database import reset_engine
    import ion.models  # noqa: F401
    from ion.models.base import Base
    from ion.models.cyab import CyabSystem
    from ion.web.server import app
    from sqlalchemy.orm import sessionmaker

    Base.metadata.create_all(temp_db)
    s = sessionmaker(bind=temp_db)()
    sys = CyabSystem(name="auth-test-answers", department="X")
    s.add(sys)
    s.commit()
    sys_id = sys.id
    s.close()

    import ion.storage.database as _db_mod
    _db_mod._engine = temp_db
    reset_engine()

    unauthenticated = TestClient(app, raise_server_exceptions=False)
    r = unauthenticated.post(
        f"/api/cyab/systems/{sys_id}/answers",
        json={"answers": {"q_foo": "bar"}},
    )
    assert r.status_code == 401

    reset_engine()

