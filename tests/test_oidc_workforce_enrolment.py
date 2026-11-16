"""A Keycloak first login puts somebody in the workforce, and nothing else.

ION's local ``AuthService.create_user`` enrols a new account on the
baseline journey. The OIDC path builds its user through
``user_repo.create`` instead, so somebody who only ever signs in through
Keycloak appeared in ION with roles and no onboarding record at all --
no induction, no certificate tracking, invisible to the ORBAT. In a
deployment that logs in exclusively through Keycloak, that is everybody.

The enrolment is a RECORD, not a gate. Roles are assigned by hand at the
moment, so:

* nothing is withheld on the strength of an unfinished journey;
* a role somebody was given by hand survives the next login;
* a failure anywhere in the workforce module must never stop a login.

``sync_granted_roles`` is what withholds roles, and it runs on
verification and offboarding -- never on login. These tests pin that
down, because the day it creeps into the login path, Keycloak users stop
being able to work and the cause will not be obvious.
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

from ion.models.base import Base
from ion.models.user import Role, User
from ion.models.workforce import PHASE_GATE, STAGE_PRE_ACCESS, UserJourney
from ion.services import workforce_service as wf


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def admin(db):
    from ion.models.user import Permission

    role = Role(name="admin")
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce",
                   action="manage"),
    ]
    u = User(username="admin", email="a@x", password_hash="x",
             is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def baseline(db, admin):
    """A published baseline with one gate item, as a real SOC would have."""
    profile = wf.create_profile(db, name="SOC Induction", is_baseline=True)
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="Acceptable use agreement",
                       kind="document", phase=PHASE_GATE)
    db.commit()
    wf.publish_version(db, version, admin)
    db.commit()
    return profile


def oidc_user(db, username="kc.user", display="Kai Chen"):
    """A user created the way ion.auth.oidc._create_user builds one."""
    u = User(username=username, email=f"{username}@example.test",
             password_hash="", display_name=display, is_active=True,
             must_change_password=False)
    db.add(u)
    db.commit()
    return u


class TestTheRecordIsCreated:
    def test_a_keycloak_first_login_opens_the_baseline_journey(
            self, db, baseline):
        user = oidc_user(db)
        journey = wf.enrol_on_baseline(db, user)
        assert journey is not None
        assert journey.user_id == user.id
        assert journey.stage == STAGE_PRE_ACCESS

    def test_they_become_visible_to_the_workforce(self, db, baseline):
        """The point of enrolling: somebody who signs in only through
        Keycloak should not be invisible to the people tracking
        induction and certificates."""
        user = oidc_user(db)
        wf.enrol_on_baseline(db, user)
        found = db.query(UserJourney).filter(
            UserJourney.user_id == user.id).all()
        assert len(found) == 1

    def test_signing_in_twice_does_not_open_a_second_journey(
            self, db, baseline):
        user = oidc_user(db)
        wf.enrol_on_baseline(db, user)
        wf.enrol_on_baseline(db, user)
        assert db.query(UserJourney).filter(
            UserJourney.user_id == user.id).count() == 1


class TestItIsNotAGate:
    def test_enrolling_grants_nothing(self, db, baseline):
        user = oidc_user(db)
        wf.enrol_on_baseline(db, user)
        assert user.roles == []

    def test_a_hand_assigned_role_survives_enrolment(self, db, baseline):
        """Roles are assigned by hand at the moment. Opening an induction
        record must not take one away."""
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()

        wf.enrol_on_baseline(db, user)
        assert [r.name for r in user.roles] == ["analyst"]

    def test_the_unfinished_journey_does_not_withhold_a_manual_role(
            self, db, baseline):
        """sync_granted_roles only touches roles a profile GRANTS. A
        baseline that grants nothing cannot withhold a role an admin
        assigned, however unfinished the journey is."""
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()
        wf.enrol_on_baseline(db, user)

        wf.sync_granted_roles(db, user)
        assert [r.name for r in user.roles] == ["analyst"]


class TestItNeverBreaksTheLogin:
    def test_no_baseline_profile_is_not_an_error(self, db):
        """A deployment that has not defined an induction yet must still
        be able to log people in."""
        user = oidc_user(db)
        assert wf.enrol_on_baseline(db, user) is None

    def test_a_broken_workforce_module_does_not_raise(self, db, baseline,
                                                      monkeypatch):
        """Returning None beats refusing the login. Somebody locked out
        of the console because the induction table has a problem is a
        worse failure than a missing journey."""
        monkeypatch.setattr(wf, "_baseline_version",
                            lambda *a, **k: (_ for _ in ()).throw(
                                RuntimeError("workforce is down")))
        user = oidc_user(db)
        assert wf.enrol_on_baseline(db, user) is None


class TestTheWiring:
    """Checks the code, not the prose around it.

    An earlier version of these asserted on the raw file and tripped on
    this module's own docstrings -- which name ``sync_granted_roles``
    precisely to explain why it is not called here.
    """

    def _source(self):
        return (_SRC / "ion" / "auth" / "oidc.py").read_text(encoding="utf-8")

    def _code_only(self) -> str:
        """Source with comments and docstrings stripped."""
        import io
        import tokenize

        src = self._source()
        out = []
        prev = tokenize.INDENT
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                continue
            # A STRING alone on a logical line is a docstring.
            if tok.type == tokenize.STRING and prev in (
                    tokenize.INDENT, tokenize.NEWLINE, tokenize.NL):
                prev = tok.type
                continue
            out.append(tok.string)
            if tok.type not in (tokenize.NL,):
                prev = tok.type
        return " ".join(out)

    def test_the_oidc_path_enrols_the_new_user(self):
        code = self._code_only()
        assert "_enrol_on_workforce" in code, (
            "a Keycloak first login must open the induction record; "
            "AuthService.create_user does this for local accounts"
        )
        assert "enrol_on_baseline" in code

    def test_the_login_path_never_withholds_roles(self):
        """sync_granted_roles belongs to verification and offboarding.
        Called on the login path it would strip the roles an admin
        assigned by hand, which is exactly what we are not doing yet."""
        code = self._code_only()
        assert "sync_granted_roles" not in code


class TestRolesHeldAtSignInReachTheOrderOfBattle:
    """Somebody signs in through Keycloak holding a role, and from then on
    they are on that role's profile and seated on the chart, with the role
    intact."""

    def _signed_in(self, db, user):
        from types import SimpleNamespace

        from ion.auth.oidc import OIDCUserSync

        OIDCUserSync(db, SimpleNamespace())._follow_held_roles(user)

    def _l1(self, db, admin, analyst):
        from ion.models.workforce import OrgPost, OrgUnit

        profile = wf.create_profile(db, name="SOC Analyst (L1)")
        profile.grants_role_id = analyst.id
        version = wf.draft_version(db, profile)
        wf.add_requirement(db, version, name="Acceptable use agreement",
                           kind="document", phase=PHASE_GATE)
        db.commit()
        wf.publish_version(db, version, admin)
        unit = OrgUnit(name="Operations")
        db.add(unit)
        db.flush()
        db.add(OrgPost(unit_id=unit.id, title="SOC Analyst (L1) #1",
                       profile_id=profile.id))
        db.commit()
        return profile

    def test_the_role_they_hold_puts_them_in_a_post(self, db, admin):
        from ion.models.workforce import OrgPost

        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        self._l1(db, admin, analyst)
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()

        self._signed_in(db, user)

        journey = db.query(UserJourney).filter_by(user_id=user.id).one()
        assert journey.role_already_held is True
        assert db.query(OrgPost).one().filled_by_journey_id == journey.id
        assert [r.name for r in user.roles] == ["analyst"]

    def test_signing_in_again_changes_nothing(self, db, admin):
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        self._l1(db, admin, analyst)
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()

        self._signed_in(db, user)
        self._signed_in(db, user)

        assert db.query(UserJourney).filter_by(user_id=user.id).count() == 1

    def test_a_workforce_failure_does_not_stop_the_sign_in(self, db, admin,
                                                           monkeypatch):
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        self._l1(db, admin, analyst)
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()

        def boom(*_a, **_k):
            raise RuntimeError("workforce is down")

        monkeypatch.setattr(wf, "assign_profile", boom)
        self._signed_in(db, user)

        assert [r.name for r in user.roles] == ["analyst"]
        assert db.query(UserJourney).filter_by(user_id=user.id).count() == 0

    def test_a_sign_in_that_cannot_be_saved_fails_as_itself(self, db, admin,
                                                            monkeypatch):
        """The commit before the workforce call is the login's own write. If
        it fails the login has failed, and saying it continues would hand the
        caller a session that raises on its next statement."""
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        self._l1(db, admin, analyst)
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()

        def refuse():
            raise RuntimeError("database refused the sign-in")

        monkeypatch.setattr(db, "commit", refuse)
        with pytest.raises(RuntimeError, match="database refused the sign-in"):
            self._signed_in(db, user)

    def test_the_session_is_still_usable_after_a_workforce_failure(
            self, db, admin, monkeypatch):
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        self._l1(db, admin, analyst)
        user = oidc_user(db)
        user.roles = [analyst]
        db.commit()

        def broken_lookup(session):
            from sqlalchemy import text

            session.execute(text("SELECT * FROM no_such_table"))

        monkeypatch.setattr(wf, "a_workforce_manager", broken_lookup)
        self._signed_in(db, user)

        assert db.query(User).filter_by(username=user.username).count() == 1
        assert [r.name for r in user.roles] == ["analyst"]
