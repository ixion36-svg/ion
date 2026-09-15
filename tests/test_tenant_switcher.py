"""The estate switcher: request binding, the API, and what it refuses.

Switching decides *which* estate an analyst looks at, never what they may do
there. The property worth pinning is that it cannot widen access: the cookie is
caller-controlled, and the same resolver runs on every subsequent request, so a
forged value buys nothing a legitimate switch would not also have given.

The second property is that a single-estate deploy is untouched — no binding,
no switcher rendered, no behaviour change.
"""

import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ion.core.config as config_mod  # noqa: E402
import ion.models  # noqa: F401,E402
from ion.auth.dependencies import TENANT_COOKIE, _bind_tenant  # noqa: E402
from ion.core.tenant_context import (  # noqa: E402
    current_tenant_connection,
    current_tenant_id,
    tenant_scope,
)
from ion.models.base import Base  # noqa: E402
from ion.models.tenant import Tenant  # noqa: E402
from ion.services import tenant_service as ts  # noqa: E402


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def estates(db):
    default = ts.ensure_default_tenant(db)
    legacy = Tenant(slug="legacy", name="Legacy estate")
    migrated = Tenant(slug="migrated", name="Migrated estate")
    gone = Tenant(slug="gone", name="Gone", is_active=False)
    db.add_all([legacy, migrated, gone])
    db.commit()
    return types.SimpleNamespace(
        default=default, legacy=legacy, migrated=migrated, gone=gone
    )


@pytest.fixture
def multi_tenant(monkeypatch):
    monkeypatch.setenv("ION_MULTI_TENANT", "true")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    yield
    monkeypatch.setattr(config_mod, "_config", None, raising=False)


def fake_request(cookie=None, header=None):
    return types.SimpleNamespace(
        cookies={TENANT_COOKIE: cookie} if cookie else {},
        headers={"X-ION-Tenant": header} if header else {},
    )


def fake_auth(db):
    return types.SimpleNamespace(db_session=db)


def user(tenant_id=None, uid=1, is_admin=True):
    """Platform-global now requires NULL tenant_id AND the admin role, so the
    default stand-in is an admin; pass is_admin=False for a pre-tenancy analyst."""
    return types.SimpleNamespace(id=uid, tenant_id=tenant_id, is_admin=is_admin)


# --------------------------------------------------------------------------
# Binding on the request.
# --------------------------------------------------------------------------


def test_single_estate_deploys_bind_nothing(db, estates, monkeypatch):
    """Multi-tenancy off must leave the context exactly as it was."""
    monkeypatch.delenv("ION_MULTI_TENANT", raising=False)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    _bind_tenant(fake_request(cookie="legacy"), user(), fake_auth(db))
    assert current_tenant_id() is None
    assert current_tenant_connection() is None


def test_the_cookie_selects_the_estate(db, estates, multi_tenant):
    with tenant_scope(None):
        _bind_tenant(fake_request(cookie="migrated"), user(), fake_auth(db))
        assert current_tenant_id() == estates.migrated.id


def test_a_header_works_too_for_api_callers(db, estates, multi_tenant):
    with tenant_scope(None):
        _bind_tenant(fake_request(header="legacy"), user(), fake_auth(db))
        assert current_tenant_id() == estates.legacy.id


def test_no_selection_falls_back_to_the_default(db, estates, multi_tenant):
    with tenant_scope(None):
        _bind_tenant(fake_request(), user(), fake_auth(db))
        assert current_tenant_id() == estates.default.id


def test_a_forged_cookie_cannot_move_a_bound_analyst(db, estates, multi_tenant):
    """The cookie is caller-controlled; the resolver is what makes it safe."""
    with tenant_scope(None):
        _bind_tenant(
            fake_request(cookie="migrated"), user(tenant_id=estates.legacy.id), fake_auth(db)
        )
        assert current_tenant_id() == estates.legacy.id


def test_an_unknown_cookie_binds_nothing_rather_than_everything(db, estates, multi_tenant):
    with tenant_scope(None):
        _bind_tenant(fake_request(cookie="does-not-exist"), user(), fake_auth(db))
        assert current_tenant_id() is None


def test_binding_failure_refuses_rather_than_serving_the_default(db, estates, multi_tenant):
    """An unbound context reads as the default estate's ES, so a resolution
    failure must refuse the request instead of falling open to another estate."""
    from fastapi import HTTPException

    class Exploding:
        @property
        def db_session(self):
            raise RuntimeError("database is gone")

    with tenant_scope(None):
        with pytest.raises(HTTPException) as exc:
            _bind_tenant(fake_request(cookie="legacy"), user(), Exploding())
        assert exc.value.status_code == 503
        assert current_tenant_id() is None


def test_a_bound_user_with_a_dead_estate_is_refused(db, estates, multi_tenant):
    """Deactivating a tenant must cut its users off, not show them the default."""
    from fastapi import HTTPException

    with tenant_scope(None):
        with pytest.raises(HTTPException) as exc:
            _bind_tenant(fake_request(), user(tenant_id=estates.gone.id), fake_auth(db))
        assert exc.value.status_code == 403
        assert current_tenant_id() is None


# --------------------------------------------------------------------------
# The API's refusals.
# --------------------------------------------------------------------------


def test_switching_to_an_unavailable_estate_is_refused(db, estates, multi_tenant):
    """Refused rather than ignored, so a switch that appears to work did."""
    from fastapi import HTTPException

    from ion.web.tenant_api import SwitchRequest, switch_tenant

    bound = user(tenant_id=estates.legacy.id)
    with pytest.raises(HTTPException) as exc:
        switch_tenant(
            SwitchRequest(slug="migrated"),
            types.SimpleNamespace(set_cookie=lambda *a, **k: None),
            current_user=bound,
            db=db,
        )
    assert exc.value.status_code == 403


def test_switching_is_404_when_multi_tenancy_is_off(db, estates, monkeypatch):
    from fastapi import HTTPException

    from ion.web.tenant_api import SwitchRequest, switch_tenant

    monkeypatch.delenv("ION_MULTI_TENANT", raising=False)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    with pytest.raises(HTTPException) as exc:
        switch_tenant(
            SwitchRequest(slug="legacy"),
            types.SimpleNamespace(set_cookie=lambda *a, **k: None),
            current_user=user(),
            db=db,
        )
    assert exc.value.status_code == 404


def test_a_successful_switch_sets_the_cookie(db, estates, multi_tenant):
    from ion.web.tenant_api import SwitchRequest, switch_tenant

    captured = {}

    def set_cookie(name, value, **kw):
        captured["name"], captured["value"], captured["kw"] = name, value, kw

    state = switch_tenant(
        SwitchRequest(slug="migrated"),
        types.SimpleNamespace(set_cookie=set_cookie),
        current_user=user(),
        db=db,
    )
    assert state.active.slug == "migrated"
    assert captured["name"] == TENANT_COOKIE
    assert captured["value"] == "migrated"
    assert captured["kw"]["samesite"] == "strict"
    assert captured["kw"]["httponly"] is False, "the header toggle has to read it"


def test_the_cookie_secure_flag_follows_the_session_cookie(db, estates, multi_tenant, monkeypatch):
    """Pinning Secure on would break the switcher on a dev box exactly as it
    would break login — a Secure cookie is never returned over plain HTTP."""
    from ion.web.tenant_api import _cookie_secure

    monkeypatch.setattr(config_mod.get_config(), "cookie_secure", False, raising=False)
    assert _cookie_secure() is False
    monkeypatch.setattr(config_mod.get_config(), "cookie_secure", True, raising=False)
    assert _cookie_secure() is True


# --------------------------------------------------------------------------
# What the toggle renders from.
# --------------------------------------------------------------------------


def test_state_reports_disabled_for_a_single_estate_deploy(db, estates, monkeypatch):
    from ion.web.tenant_api import get_tenant_state

    monkeypatch.delenv("ION_MULTI_TENANT", raising=False)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    state = get_tenant_state(fake_request(), current_user=user(), db=db)
    assert state.enabled is False
    assert state.can_switch is False
    assert state.available == []


def test_a_bound_analyst_cannot_switch(db, estates, multi_tenant):
    """They see which estate they are on; there is no control to change it."""
    from ion.web.tenant_api import get_tenant_state

    state = get_tenant_state(
        fake_request(), current_user=user(tenant_id=estates.legacy.id), db=db
    )
    assert state.enabled is True
    assert state.can_switch is False
    assert state.active.slug == "legacy"


def test_a_platform_analyst_sees_every_estate(db, estates, multi_tenant):
    from ion.web.tenant_api import get_tenant_state

    state = get_tenant_state(fake_request(cookie="migrated"), current_user=user(), db=db)
    assert state.can_switch is True
    assert state.active.slug == "migrated"
    assert {t.slug for t in state.available} == {"default", "legacy", "migrated"}


def test_an_inactive_estate_is_not_offered(db, estates, multi_tenant):
    from ion.web.tenant_api import get_tenant_state

    estates.migrated.is_active = False
    db.commit()
    state = get_tenant_state(fake_request(), current_user=user(), db=db)
    assert "migrated" not in {t.slug for t in state.available}


# --------------------------------------------------------------------------
# Wiring that is easy to leave half-done.
# --------------------------------------------------------------------------


def test_the_default_tenant_is_seeded_at_startup():
    """Without this the first request has no tenant to resolve to."""
    import inspect

    from ion.web import server

    src = inspect.getsource(server._startup_event)
    assert "ensure_default_tenant" in src
    assert "LOCK_SEED_TENANTS" in src, "seed must hold an advisory lock like its siblings"


def test_the_switcher_is_served_by_base_html():
    base = (
        Path(__file__).resolve().parent.parent
        / "src/ion/web/templates/base.html"
    ).read_text(encoding="utf-8", errors="replace")
    assert 'id="tenant-switcher"' in base, "no mount point in the header"
    assert "tenant-switcher.js" in base, "the script is never loaded"


def test_the_switcher_starts_hidden():
    """A single-estate deploy must not flash a control it will then remove."""
    base = (
        Path(__file__).resolve().parent.parent
        / "src/ion/web/templates/base.html"
    ).read_text(encoding="utf-8", errors="replace")
    line = next(ln for ln in base.splitlines() if 'id="tenant-switcher"' in ln)
    assert "hidden" in line


def test_tenant_names_are_escaped_before_render():
    """Names come from the database and reach innerHTML."""
    js = (
        Path(__file__).resolve().parent.parent
        / "src/ion/web/static/js/tenant-switcher.js"
    ).read_text(encoding="utf-8", errors="replace")
    assert "esc(t.name)" in js
    assert "esc(t.slug)" in js
