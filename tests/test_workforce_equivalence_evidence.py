"""A skills assessment is evidence for an equivalence, never the decision.

ION already scores people against a career role: ``RoleAssessment`` holds
the per-area scores and an overall match percentage for L1/L2/L3 analyst,
SOC engineer and threat hunter. The obvious thing to do with that is let a
high score satisfy a certificate requirement by itself.

It must not, and the reason is in the model's own docstring: "A user's
**self-assessment**". The person answered the questionnaire about
themselves. Letting that clear a requirement means somebody gets a role,
and its permissions, because they rated themselves highly. The
submit/verify split exists precisely so that nobody's own account of
their competence is the thing that grants them access.

So an assessment is citable, not decisive. Recording an equivalence still
needs a human with verify rights and still needs a written basis. What
citing the assessment adds is that the basis becomes checkable: whoever
reviews it later can see which assessment was considered, what it scored,
and when it was taken, instead of a sentence asserting that proficiency
was demonstrated.

The record says the score was self-rated. Six months on, "scored 4.6"
reads as a measurement unless something tells the reader otherwise.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.skills import RoleAssessment
from ion.models.user import Permission, Role, User
from ion.models.workforce import (
    KIND_CERT,
    PHASE_GATE,
    PHASE_READINESS,
    STATUS_EQUIVALENT,
)
from ion.services import workforce_service as wf

GATE = dict(name="Security induction", kind="course", phase=PHASE_GATE,
            validity_months=12)
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
def joiner(db):
    u = User(username="joiner", email="j@x", password_hash="x", is_active=True)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def requirement(db, lead, joiner):
    analyst = Role(name="analyst")
    db.add(analyst)
    db.commit()
    profile = wf.create_profile(db, name="SOC Analyst L2")
    profile.grants_role_id = analyst.id
    version = wf.draft_version(db, profile)
    for req in (GATE, CERT):
        wf.add_requirement(db, version, **req)
    wf.publish_version(db, version, lead)
    db.commit()
    journey = wf.assign_profile(db, user=joiner, version=version,
                                assigner=lead)
    return next(r for r in journey.requirements if r.kind == KIND_CERT)


def assessment_for(db, user, *, pct=86, role_id="l2_soc_analyst",
                   taken_at=None):
    a = RoleAssessment(
        user_id=user.id, role_id=role_id, role_name="L2 SOC Analyst",
        responses={"elastic_alerts": {"q1": 5, "q2": 4}},
        scores={"elastic_alerts": {"avg": 4.5, "total": 9, "max": 10,
                                   "pct": 90}},
        overall_match_pct=pct, overall_level="Proficient",
        taken_at=taken_at or datetime.utcnow(),
    )
    db.add(a)
    db.commit()
    return a


# -- The assessment never decides on its own ------------------------------


class TestItIsNotTheDecision:
    def test_a_basis_is_still_required_with_an_assessment(
        self, db, lead, joiner, requirement
    ):
        """Citing an assessment is not writing down what you assessed."""
        a = assessment_for(db, joiner)
        with pytest.raises(wf.WorkforceError):
            wf.record_equivalence(db, requirement=requirement, assessor=lead,
                                  basis="   ", assessment_id=a.id)

    def test_the_person_still_cannot_do_it_themselves(
        self, db, lead, joiner, requirement
    ):
        """A high self-assessment plus self-service would be: rate yourself
        well, grant yourself the role."""
        a = assessment_for(db, joiner, pct=100)
        with pytest.raises(wf.WorkforceError):
            wf.record_equivalence(db, requirement=requirement, assessor=joiner,
                                  basis="I scored full marks.",
                                  assessment_id=a.id)

    def test_a_low_score_is_not_refused_automatically(
        self, db, lead, joiner, requirement
    ):
        """There is no threshold, on purpose. A number deciding this would
        make it the decision again, just with a cutoff. The human decides
        and the score is one of the things in front of them."""
        a = assessment_for(db, joiner, pct=31)
        wf.record_equivalence(
            db, requirement=requirement, assessor=lead,
            basis="Low self-rating, but observed handling three live "
                  "escalations unaided; the questionnaire undersells it.",
            assessment_id=a.id)
        db.commit()
        assert requirement.status == STATUS_EQUIVALENT


# -- What citing one adds -------------------------------------------------


class TestTheCitation:
    def test_the_assessment_is_named_on_the_record(
        self, db, lead, joiner, requirement
    ):
        a = assessment_for(db, joiner)
        wf.record_equivalence(db, requirement=requirement, assessor=lead,
                              basis="Assessed against the L2 objectives.",
                              assessment_id=a.id)
        db.commit()
        assert f"assessment {a.id}" in (requirement.notes or "").lower()

    def test_the_score_and_date_are_recorded(self, db, lead, joiner,
                                             requirement):
        """So a reviewer can check the basis instead of taking it on
        trust, without going and finding the assessment."""
        taken = datetime.utcnow() - timedelta(days=10)
        a = assessment_for(db, joiner, pct=86, taken_at=taken)
        wf.record_equivalence(db, requirement=requirement, assessor=lead,
                              basis="Assessed against the L2 objectives.",
                              assessment_id=a.id)
        db.commit()
        notes = requirement.notes or ""
        assert "86" in notes
        assert taken.strftime("%Y-%m-%d") in notes

    def test_the_record_says_the_score_was_self_rated(
        self, db, lead, joiner, requirement
    ):
        """Six months on, "scored 86%" reads as a measurement unless
        something says who did the rating."""
        a = assessment_for(db, joiner)
        wf.record_equivalence(db, requirement=requirement, assessor=lead,
                              basis="Assessed against the L2 objectives.",
                              assessment_id=a.id)
        db.commit()
        assert "self-rated" in (requirement.notes or "").lower()

    def test_citing_none_still_works(self, db, lead, joiner, requirement):
        """Not every equivalence has an assessment behind it. Observed
        competence on live work is a perfectly good basis."""
        wf.record_equivalence(
            db, requirement=requirement, assessor=lead,
            basis="Four years on an L2 queue at a previous employer, "
                  "confirmed by reference.")
        db.commit()
        assert requirement.status == STATUS_EQUIVALENT


# -- The citation has to be real ------------------------------------------


class TestTheCitationIsChecked:
    def test_an_assessment_belonging_to_somebody_else_is_refused(
        self, db, lead, joiner, requirement
    ):
        """Otherwise a strong assessment can be cited for anybody, and the
        evidence trail points at the wrong person."""
        other = User(username="other", email="o@x", password_hash="x",
                     is_active=True)
        db.add(other)
        db.commit()
        a = assessment_for(db, other)
        with pytest.raises(wf.WorkforceError) as exc:
            wf.record_equivalence(db, requirement=requirement, assessor=lead,
                                  basis="Assessed against the objectives.",
                                  assessment_id=a.id)
        assert "assessment" in str(exc.value).lower()

    def test_an_unknown_assessment_is_refused(self, db, lead, joiner,
                                              requirement):
        with pytest.raises(wf.WorkforceError):
            wf.record_equivalence(db, requirement=requirement, assessor=lead,
                                  basis="Assessed against the objectives.",
                                  assessment_id=999999)

    def test_nothing_is_written_when_the_citation_is_refused(
        self, db, lead, joiner, requirement
    ):
        """A refusal must leave the requirement untouched, not half-set."""
        before = requirement.status
        with pytest.raises(wf.WorkforceError):
            wf.record_equivalence(db, requirement=requirement, assessor=lead,
                                  basis="Assessed.", assessment_id=999999)
        db.refresh(requirement)
        assert requirement.status == before


# -- The audit trail ------------------------------------------------------


class TestAudit:
    def test_the_cited_assessment_reaches_the_audit_row(
        self, db, lead, joiner, requirement
    ):
        from ion.models.user import AuditLog

        a = assessment_for(db, joiner)
        wf.record_equivalence(db, requirement=requirement, assessor=lead,
                              basis="Assessed against the L2 objectives.",
                              assessment_id=a.id)
        db.commit()
        row = next(r for r in db.query(AuditLog).all()
                   if r.action == "workforce_requirement_equivalence")
        assert str(a.id) in (row.details or "")
