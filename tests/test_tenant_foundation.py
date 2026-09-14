"""Tenant identity: resolution, scoping, and the property the design rests on.

ION served exactly one Elastic estate for 95 releases. Multi-tenancy adds the
idea of *which* estate a request acts for, and the dangerous failure is not an
error — it is a request that resolves to no tenant and is treated as entitled to
every tenant. Vector search makes this worse: it always returns its k nearest
rows, so an unscoped similarity query looks like a working feature while
surfacing another client's case text.

So the rule these tests exist to pin: **unresolved means no rows, never all
rows.** Forgetting a tenant must hide data, not leak it.
"""

import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ion.models  # noqa: F401,E402  (registers every table for create_all)
from ion.core.tenant_context import (  # noqa: E402
    cross_tenant_scope,
    current_tenant_id,
    is_cross_tenant,
    reset_tenant_id,
    set_tenant_id,
    tenant_scope,
)
from ion.models.base import Base  # noqa: E402
from ion.models.tenant import Tenant  # noqa: E402
from ion.models.user import User  # noqa: E402
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
    acme = Tenant(slug="acme", name="Acme")
    beta = Tenant(slug="beta", name="Beta")
    gone = Tenant(slug="gone", name="Gone", is_active=False)
    db.add_all([acme, beta, gone])
    db.commit()
    return types.SimpleNamespace(default=default, acme=acme, beta=beta, gone=gone)


def user(tenant_id=None, uid=1):
    """A stand-in for User — resolution reads only .id and .tenant_id."""
    return types.SimpleNamespace(id=uid, tenant_id=tenant_id)


# --------------------------------------------------------------------------
# The safety property.
# --------------------------------------------------------------------------


def test_no_ambient_tenant_by_default():
    """Nothing has resolved a tenant, so nothing may claim one."""
    assert current_tenant_id() is None
    assert is_cross_tenant() is False


def test_an_unmatched_selection_resolves_to_nothing(db, estates):
    """Not to the default, and not to 'all' — a bad selection shows no data."""
    assert ts.resolve_tenant_for_user(db, user(), "does-not-exist") is None


def test_an_inactive_tenant_is_not_resolvable(db, estates):
    assert ts.get_tenant_by_slug(db, "gone") is None
    assert ts.resolve_tenant_for_user(db, user(), "gone") is None


def test_a_user_bound_to_an_inactive_tenant_gets_nothing(db, estates):
    """Not a promotion to platform-wide access, which is the tempting bug."""
    orphan = user(tenant_id=estates.gone.id, uid=9)
    assert ts.resolve_tenant_for_user(db, orphan) is None
    assert ts.accessible_tenants(db, orphan) == []


def test_crossing_tenants_is_separate_from_having_none():
    """`no tenant` and `all tenants` must never be the same state."""
    assert current_tenant_id() is None
    assert is_cross_tenant() is False
    with cross_tenant_scope():
        assert is_cross_tenant() is True
        assert current_tenant_id() is None, "crossing must not invent a tenant"
    assert is_cross_tenant() is False


# --------------------------------------------------------------------------
# Resolution.
# --------------------------------------------------------------------------


def test_a_bound_user_gets_their_own_tenant(db, estates):
    assert ts.resolve_tenant_for_user(db, user(estates.acme.id)).slug == "acme"


def test_a_bound_user_cannot_request_another_tenant(db, estates):
    """The caller supplies this value, so it is untrusted input."""
    got = ts.resolve_tenant_for_user(db, user(estates.acme.id), "beta")
    assert got.slug == "acme", "a bound user was handed someone else's estate"


def test_a_bound_user_cannot_request_by_numeric_id_either(db, estates):
    got = ts.resolve_tenant_for_user(db, user(estates.acme.id), str(estates.beta.id))
    assert got.slug == "acme"


def test_a_platform_user_falls_back_to_the_default(db, estates):
    assert ts.resolve_tenant_for_user(db, user()).slug == "default"


def test_a_platform_user_may_select_by_slug_or_id(db, estates):
    assert ts.resolve_tenant_for_user(db, user(), "beta").slug == "beta"
    assert ts.resolve_tenant_for_user(db, user(), str(estates.beta.id)).slug == "beta"


def test_accessible_tenants_is_one_for_bound_and_all_for_platform(db, estates):
    assert [t.slug for t in ts.accessible_tenants(db, user(estates.acme.id))] == ["acme"]
    slugs = {t.slug for t in ts.accessible_tenants(db, user())}
    assert slugs == {"default", "acme", "beta"}
    assert "gone" not in slugs, "an inactive tenant is offered for selection"


@pytest.mark.parametrize(
    "slug,ok",
    [
        ("acme", True),
        ("acme-uk", True),
        ("a1", True),
        ("Acme", False),
        ("-acme", False),
        ("acme-", False),
        ("acme_uk", False),
        ("../etc", False),
        ("", False),
        ("a" * 100, False),
    ],
)
def test_slug_validation(slug, ok):
    """Slugs reach audit records, filenames and URLs, so they are constrained."""
    assert ts.valid_slug(slug) is ok


# --------------------------------------------------------------------------
# The default tenant.
# --------------------------------------------------------------------------


def test_the_default_tenant_is_created_once(db):
    first = ts.ensure_default_tenant(db)
    assert ts.ensure_default_tenant(db).id == first.id
    assert db.query(Tenant).filter(Tenant.slug == "default").count() == 1


def test_the_default_tenant_inherits_the_process_config(db, monkeypatch):
    """No ION_TENANT_DEFAULT_* variables means no overlay, which is what makes
    enabling this a no-op on an existing single-estate deploy."""
    monkeypatch.setenv("ION_MULTI_TENANT", "true")
    import ion.core.config as config_mod

    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    d = ts.ensure_default_tenant(db)
    assert ts.tenant_connection(d) is None


def test_connection_settings_come_from_the_environment(db, monkeypatch):
    """Identity in the table, connection in .env — so credentials stay where
    every other ION credential lives rather than becoming a database secret."""
    monkeypatch.setenv("ION_MULTI_TENANT", "true")
    import ion.core.config as config_mod

    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    monkeypatch.setenv("ION_TENANT_ACME_ES_URL", "https://es-acme:9200")
    monkeypatch.setenv("ION_TENANT_ACME_KIBANA_SPACE", "acme")

    t = Tenant(slug="acme", name="Acme")
    conn = ts.tenant_connection(t)
    assert conn["es"]["url"] == "https://es-acme:9200"
    assert conn["kibana"]["space_id"] == "acme"


def test_unset_variables_are_omitted_not_blanked(db, monkeypatch):
    """A tenant setting only a URL must inherit the rest, not blank it."""
    monkeypatch.setenv("ION_MULTI_TENANT", "true")
    import ion.core.config as config_mod

    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    monkeypatch.setenv("ION_TENANT_ACME_ES_URL", "https://es-acme:9200")
    monkeypatch.setenv("ION_TENANT_ACME_ES_USERNAME", "   ")

    conn = ts.tenant_connection(Tenant(slug="acme", name="Acme"))
    assert conn["es"] == {"url": "https://es-acme:9200"}
    assert "username" not in conn["es"]


def test_no_connection_leaks_while_multi_tenancy_is_off(db, monkeypatch):
    """Stray variables must not reroute a single-estate deploy."""
    monkeypatch.delenv("ION_MULTI_TENANT", raising=False)
    import ion.core.config as config_mod

    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    monkeypatch.setenv("ION_TENANT_ACME_ES_URL", "https://es-acme:9200")
    assert ts.tenant_connection(Tenant(slug="acme", name="Acme")) is None


@pytest.mark.parametrize(
    "slug,prefix",
    [("acme", "ION_TENANT_ACME"), ("acme-uk", "ION_TENANT_ACME_UK"), ("a1", "ION_TENANT_A1")],
)
def test_env_prefix_derivation(slug, prefix):
    assert Tenant(slug=slug, name="x").env_prefix == prefix


def test_verify_ssl_is_parsed_as_a_boolean(db, monkeypatch):
    monkeypatch.setenv("ION_MULTI_TENANT", "true")
    import ion.core.config as config_mod

    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    monkeypatch.setenv("ION_TENANT_ACME_ES_URL", "https://es-acme:9200")
    monkeypatch.setenv("ION_TENANT_ACME_ES_VERIFY_SSL", "true")
    conn = ts.tenant_connection(Tenant(slug="acme", name="Acme"))
    assert conn["es"]["verify_ssl"] is True


# --------------------------------------------------------------------------
# Scoping.
# --------------------------------------------------------------------------


def test_scope_sets_and_restores():
    with tenant_scope(7):
        assert current_tenant_id() == 7
    assert current_tenant_id() is None


def test_scope_restores_after_an_exception():
    """A failed background iteration must not leak its tenant into the next."""
    with pytest.raises(RuntimeError):
        with tenant_scope(7):
            raise RuntimeError("iteration failed")
    assert current_tenant_id() is None


def test_scopes_nest():
    with tenant_scope(1):
        with tenant_scope(2):
            assert current_tenant_id() == 2
        assert current_tenant_id() == 1
    assert current_tenant_id() is None


def test_set_and_reset_round_trip():
    token = set_tenant_id(42)
    assert current_tenant_id() == 42
    reset_tenant_id(token)
    assert current_tenant_id() is None


def test_bind_request_tenant_installs_and_unbinds(db, estates):
    tenant, tokens = ts.bind_request_tenant(db, user(estates.acme.id))
    try:
        assert tenant.slug == "acme"
        assert current_tenant_id() == estates.acme.id
    finally:
        ts.unbind_request_tenant(tokens)
    assert current_tenant_id() is None


def test_binding_an_unresolvable_tenant_installs_none(db, estates):
    _, tokens = ts.bind_request_tenant(db, user(), "does-not-exist")
    try:
        assert current_tenant_id() is None
    finally:
        ts.unbind_request_tenant(tokens)


# --------------------------------------------------------------------------
# Off by default, and off means unchanged.
# --------------------------------------------------------------------------


def test_multi_tenancy_is_off_by_default(monkeypatch):
    import ion.core.config as config_mod

    monkeypatch.delenv("ION_MULTI_TENANT", raising=False)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    assert config_mod.get_config().multi_tenant is False
    assert ts.multi_tenant_enabled() is False


def test_multi_tenancy_can_be_switched_on(monkeypatch):
    import ion.core.config as config_mod

    monkeypatch.setenv("ION_MULTI_TENANT", "true")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    assert config_mod.get_config().multi_tenant is True


def test_users_carry_a_nullable_tenant(db):
    """NULL is platform-global, a real privileged state -- not a pending backfill."""
    col = User.__table__.columns["tenant_id"]
    assert col.nullable is True
    assert any(fk.column.table.name == "tenants" for fk in col.foreign_keys)


def test_arkime_and_opencti_are_deliberately_not_per_tenant():
    """They are shared estate-wide services. Columns here would imply an
    isolation this design does not provide."""
    cols = set(Tenant.__table__.columns.keys())
    leaked = {c for c in cols if "arkime" in c or "opencti" in c}
    assert leaked == set(), f"tenant gained shared-service columns: {leaked}"
