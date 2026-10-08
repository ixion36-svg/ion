"""Role training must be done before the role's permissions arrive, and a
cert may be met by demonstrated proficiency -- recorded as what it is.

Two things, both seen on the live estate on 8 October 2026.

**The role was conferred before its training was done.** A joiner cleared
the four mandatory induction items, was assigned SOC Analyst L1, and
immediately held the ``analyst`` role with 18 permissions and access to
cases and observables -- with role readiness at 0 of 3. The ION platform
training, the triage sign-off and the SIEM access had not been touched.

``confers_role`` asked only about the gate. That is right for what the
gate is for -- it is person-level, and a lapse there withdraws every role
at once -- but it is not the whole condition. The readiness items are the
role's own training, and handing someone the role's permissions before
they have done it is the thing the module exists to prevent.

So conferral now needs both. The distinction between the phases is
untouched and still load-bearing: a lapsed gate item suspends everything,
a lapsed readiness item withdraws that one role.

**Not everyone holds the certificate.** A requirement like "CompTIA
Security+ (or equivalent)" is routinely met by somebody who demonstrates
the same competence without the certificate. Recording that as
``verified`` would be a lie -- an assessor asking "does your L2 hold
GCIA" would be told yes. Recording it as ``waived`` is also wrong:
waived means the requirement was set aside, not met.

``equivalent`` is its own status: the requirement is satisfied, and the
record says it was satisfied by assessed proficiency rather than by the
named certificate, with who assessed it and on what basis. It still
expires, because demonstrated proficiency goes stale exactly like a
certificate does.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import (
    KIND_CERT,
    PHASE_GATE,
    PHASE_READINESS,
    STATUS_EQUIVALENT,
    STATUS_VERIFIED,
)
from ion.services import workforce_service as wf

GATE = dict(name="Security induction", kind="course", phase=PHASE_GATE,
            validity_months=12)
TRAINING = dict(name="ION platform training", kind="course",
                phase=PHASE_READINESS, validity_months=24)
CERT = dict(name="CompTIA Security+ (or equivalent)", kind=KIND_CERT,
            phase=PHASE_READINESS, validity_months=36)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def lead(db):
    role = Role(name="lead")
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce", action="manage"),
        Permission(name="workforce:verify", resource="workforce", action="verify"),
    ]
    u = User(username="lead", email="l@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def analyst_role(db):
    r = Role(name="analyst")
    db.add(r)
    db.commit()
    return r


@pytest.fixture
def joiner(db):
    u = User(username="joiner", email="j@x", password_hash="x", is_active=True)
    db.add(u)
    db.commit()
    return u


def journey_for(db, lead, analyst_role, joiner, requirements=(GATE, TRAINING)):
    profile = wf.create_profile(db, name="SOC Analyst L1")
    profile.grants_role_id = analyst_role.id
    version = wf.draft_version(db, profile)
    for req in requirements:
        wf.add_requirement(db, version, **req)
    wf.publish_version(db, version, lead)
    db.commit()
    return wf.assign_profile(db, user=joiner, version=version, assigner=lead)


def verify_named(db, journey, lead, name):
    req = next(r for r in journey.requirements if r.name == name)
    return wf.verify_requirement(db, requirement=req, verifier=lead)


# -- Readiness is part of the condition -----------------------------------


class TestReadinessGatesTheRole:
    def test_a_cleared_gate_alone_does_not_confer(self, db, lead, analyst_role,
                                                  joiner):
        """The case seen live: induction done, ION training untouched, and
        the analyst role already held."""
        journey = journey_for(db, lead, analyst_role, joiner)
        verify_named(db, journey, lead, "Security induction")
        db.commit()
        assert wf.confers_role(journey) is False

    def test_both_phases_complete_confers(self, db, lead, analyst_role, joiner):
        journey = journey_for(db, lead, analyst_role, joiner)
        verify_named(db, journey, lead, "Security induction")
        verify_named(db, journey, lead, "ION platform training")
        db.commit()
        assert wf.confers_role(journey) is True

    def test_readiness_alone_does_not_confer(self, db, lead, analyst_role,
                                             joiner):
        """The gate is still a precondition, not an alternative."""
        journey = journey_for(db, lead, analyst_role, joiner)
        verify_named(db, journey, lead, "ION platform training")
        db.commit()
        assert wf.confers_role(journey) is False

    def test_the_ion_role_is_not_granted_until_training_is_done(
        self, db, lead, analyst_role, joiner
    ):
        journey = journey_for(db, lead, analyst_role, joiner)
        verify_named(db, journey, lead, "Security induction")
        db.commit()
        wf.sync_granted_roles(db, joiner)
        db.refresh(joiner)
        assert [r.name for r in joiner.roles] == []

        verify_named(db, journey, lead, "ION platform training")
        db.commit()
        wf.sync_granted_roles(db, joiner)
        db.refresh(joiner)
        assert [r.name for r in joiner.roles] == ["analyst"]

    def test_a_profile_with_no_readiness_still_confers_on_the_gate(
        self, db, lead, analyst_role, joiner
    ):
        """A role whose only requirements are the mandatory ones is a
        legitimate shape. Requiring readiness that does not exist would
        make it permanently inert -- the trap the publish guard exists to
        stop."""
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE,))
        verify_named(db, journey, lead, "Security induction")
        db.commit()
        assert wf.confers_role(journey) is True

    def test_the_grace_window_on_a_suspended_journey_is_unchanged(
        self, db, lead, analyst_role, joiner
    ):
        """A certificate lapsing overnight must not strip access from
        somebody on shift before anyone has seen the alert."""
        journey = journey_for(db, lead, analyst_role, joiner)
        verify_named(db, journey, lead, "Security induction")
        verify_named(db, journey, lead, "ION platform training")
        db.commit()
        journey.stage = "suspended"
        journey.grace_until = datetime.utcnow() + timedelta(days=3)
        db.commit()
        assert wf.confers_role(journey) is True

        journey.grace_until = datetime.utcnow() - timedelta(days=1)
        db.commit()
        assert wf.confers_role(journey) is False


# -- Proficiency instead of the certificate -------------------------------


class TestEquivalence:
    def test_a_cert_can_be_met_by_assessed_proficiency(
        self, db, lead, analyst_role, joiner
    ):
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(
            db, requirement=req, assessor=lead,
            basis="Four years on an L2 queue; assessed against the Security+ "
                  "objectives in a live triage scenario on 2026-10-08.")
        db.commit()
        assert req.satisfied is True

    def test_it_is_not_recorded_as_verified(self, db, lead, analyst_role,
                                            joiner):
        """An assessor asking "does your L2 hold Security+" must be told
        no, with what was done instead -- not yes."""
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(db, requirement=req, assessor=lead,
                              basis="Assessed in a live triage scenario.")
        db.commit()
        assert req.status == STATUS_EQUIVALENT
        assert req.status != STATUS_VERIFIED

    def test_it_counts_towards_conferral(self, db, lead, analyst_role, joiner):
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        verify_named(db, journey, lead, "Security induction")
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(db, requirement=req, assessor=lead,
                              basis="Assessed in a live triage scenario.")
        db.commit()
        assert wf.confers_role(journey) is True

    def test_the_basis_is_required(self, db, lead, analyst_role, joiner):
        """An equivalence with no stated basis is a tick. The whole value
        is that somebody has to write down what they assessed."""
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        with pytest.raises(wf.WorkforceError):
            wf.record_equivalence(db, requirement=req, assessor=lead,
                                  basis="   ")

    def test_who_assessed_it_is_recorded(self, db, lead, analyst_role, joiner):
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(db, requirement=req, assessor=lead,
                              basis="Assessed in a live triage scenario.")
        db.commit()
        assert req.verified_by_id == lead.id
        assert req.verified_at is not None

    def test_the_basis_is_kept_on_the_record(self, db, lead, analyst_role,
                                             joiner):
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(db, requirement=req, assessor=lead,
                              basis="Four years on an L2 queue.")
        db.commit()
        assert "Four years on an L2 queue." in (req.notes or "")

    def test_it_still_expires(self, db, lead, analyst_role, joiner):
        """Demonstrated proficiency goes stale exactly like a certificate.
        An equivalence that never expires is a permanent exemption."""
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(db, requirement=req, assessor=lead,
                              basis="Assessed in a live triage scenario.")
        db.commit()
        assert req.expires_on is not None
        assert req.expires_on > date.today()

    def test_only_somebody_who_could_verify_may_assess(
        self, db, lead, analyst_role, joiner
    ):
        """Otherwise it is a way round the submit/verify split: declare
        your own proficiency and award yourself the role."""
        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        with pytest.raises(wf.WorkforceError):
            wf.record_equivalence(db, requirement=req, assessor=joiner,
                                  basis="I am good at this.")

    def test_equivalence_is_audited(self, db, lead, analyst_role, joiner):
        from ion.models.user import AuditLog

        journey = journey_for(db, lead, analyst_role, joiner,
                              requirements=(GATE, CERT))
        req = next(r for r in journey.requirements if r.kind == KIND_CERT)
        wf.record_equivalence(db, requirement=req, assessor=lead,
                              basis="Assessed in a live triage scenario.")
        db.commit()
        actions = [a.action for a in db.query(AuditLog).all()]
        assert "workforce_requirement_equivalence" in actions


class TestEquivalenceIsVisibleAsSuch:
    def test_satisfied_includes_it(self):
        from ion.models.workforce import JourneyRequirement

        req = JourneyRequirement(name="x", kind=KIND_CERT,
                                 phase=PHASE_READINESS,
                                 status=STATUS_EQUIVALENT)
        assert req.satisfied is True

    def test_the_status_is_in_the_vocabulary(self):
        from ion.models.workforce import STATUSES

        assert STATUS_EQUIVALENT in STATUSES
