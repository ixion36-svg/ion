"""Keycloak adds roles. It does not take away the ones a human gave.

``_sync_roles`` called ``set_roles``, which replaces the list outright.
In a deployment that signs in exclusively through Keycloak while roles
are still assigned by hand, that is a trap with a delay on it: today no
realm role matches an ION role name so nothing is lost, and the day
somebody adds a realm role called ``analyst`` or ``lead``, every manual
assignment for everyone who holds it disappears on their next login.
No error, no audit entry, and the symptom (people losing access
overnight) points nowhere near Keycloak.

So the sync is additive. The trade that buys, stated plainly rather
than discovered later:

  **Removing a role in Keycloak no longer revokes it in ION.**

That is the right way round while ION is the place roles are decided --
an admin removes by hand, the same way they granted. It would be the
wrong way round if Keycloak ever became authoritative, and the test
below says so out loud so that change is made on purpose.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.auth.oidc import OIDCUserSync
from ion.auth.oidc_config import OIDCConfig
from ion.models.base import Base
from ion.models.user import Role, User


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def roles(db):
    made = {}
    for name in ("analyst", "lead", "grc", "engineering"):
        r = Role(name=name)
        db.add(r)
        made[name] = r
    db.commit()
    return made


@pytest.fixture
def sync(db):
    return OIDCUserSync(db, OIDCConfig(enabled=True))


def person(db, *held):
    u = User(username="kc.user", email="kc@example.test", password_hash="",
             display_name="Kai Chen", is_active=True)
    u.roles = list(held)
    db.add(u)
    db.commit()
    return u


def names(user):
    return sorted(r.name for r in user.roles)


class TestItAdds:
    def test_a_mapped_keycloak_role_is_granted(self, db, sync, roles):
        user = person(db)
        sync._sync_roles(user, ["analyst"])
        assert names(user) == ["analyst"]

    def test_several_at_once(self, db, sync, roles):
        user = person(db)
        sync._sync_roles(user, ["analyst", "lead"])
        assert names(user) == ["analyst", "lead"]

    def test_a_configured_mapping_still_works(self, db, roles):
        s = OIDCUserSync(db, OIDCConfig(
            enabled=True, role_mapping={"soc-tier1": "analyst"}))
        user = person(db)
        s._sync_roles(user, ["soc-tier1"])
        assert names(user) == ["analyst"]

    def test_an_unknown_keycloak_role_is_ignored(self, db, sync, roles):
        user = person(db)
        sync._sync_roles(user, ["some-unrelated-realm-role"])
        assert names(user) == []


class TestItDoesNotTakeAway:
    def test_a_hand_assigned_role_survives(self, db, sync, roles):
        """The whole point. An admin gave them grc; Keycloak has never
        heard of it; they keep it."""
        user = person(db, roles["grc"])
        sync._sync_roles(user, ["analyst"])
        assert names(user) == ["analyst", "grc"]

    def test_every_manual_role_survives_a_login_that_maps_nothing(
            self, db, sync, roles):
        user = person(db, roles["grc"], roles["engineering"])
        sync._sync_roles(user, ["nothing-ion-knows"])
        assert names(user) == ["engineering", "grc"]

    def test_dropping_a_role_in_keycloak_does_not_revoke_it(
            self, db, sync, roles):
        """Asserted so the trade-off is a decision rather than a
        surprise. Revocation is a deliberate act by an admin while ION
        is where roles are decided. If Keycloak ever becomes
        authoritative, this test is the thing to come and change."""
        user = person(db)
        sync._sync_roles(user, ["analyst", "lead"])
        assert names(user) == ["analyst", "lead"]

        sync._sync_roles(user, ["analyst"])      # lead removed upstream
        assert names(user) == ["analyst", "lead"]


class TestItIsIdempotent:
    def test_signing_in_twice_does_not_duplicate(self, db, sync, roles):
        user = person(db)
        sync._sync_roles(user, ["analyst"])
        sync._sync_roles(user, ["analyst"])
        assert [r.name for r in user.roles] == ["analyst"]

    def test_an_empty_claim_changes_nothing(self, db, sync, roles):
        user = person(db, roles["analyst"])
        sync._sync_roles(user, [])
        assert names(user) == ["analyst"]


class TestItIsAuditable:
    def test_granting_a_role_is_written_down(self, db, sync, roles):
        """A role appearing out of an SSO claim should be traceable
        later without reading the Keycloak logs."""
        from ion.models.user import AuditLog

        user = person(db)
        sync._sync_roles(user, ["analyst"])
        db.commit()
        entries = db.query(AuditLog).filter(
            AuditLog.action == "oidc_role_granted").all()
        assert entries, "granting a role from an OIDC claim must be audited"
        assert "analyst" in (entries[0].details or "")

    def test_nothing_is_logged_when_nothing_changed(self, db, sync, roles):
        from ion.models.user import AuditLog

        user = person(db, roles["analyst"])
        sync._sync_roles(user, ["analyst"])
        db.commit()
        assert db.query(AuditLog).filter(
            AuditLog.action == "oidc_role_granted").count() == 0


class TestTheReplacementIsGone:
    def test_set_roles_is_not_called_on_the_sync_path(self):
        """set_roles replaces the list; that is what caused this."""
        import io
        import tokenize

        src = (_SRC / "ion" / "auth" / "oidc.py").read_text(encoding="utf-8")
        code, prev = [], tokenize.INDENT
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                continue
            if tok.type == tokenize.STRING and prev in (
                    tokenize.INDENT, tokenize.NEWLINE, tokenize.NL):
                prev = tok.type
                continue
            code.append(tok.string)
            if tok.type != tokenize.NL:
                prev = tok.type
        assert "set_roles" not in " ".join(code)
