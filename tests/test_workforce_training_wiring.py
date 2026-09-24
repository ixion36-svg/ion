"""The workforce module writes into the training stores, it does not shadow them.

TrainingPlan/TrainingPlanItem and TeamCertification predate this module and
feed the /training page. The defect class this pins: the same cert or cost
tracked in two places, agreeing on day one and drifting forever after.
"""

from datetime import date, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.course import Course, UserEnrolment
from ion.models.skills import TeamCertification, TrainingPlan, TrainingPlanItem
from ion.models.user import Permission, Role, User
from ion.models.workforce import KIND_CERT, KIND_DOCUMENT, PHASE_GATE, PHASE_READINESS
from ion.services import workforce_service as wf


@pytest.fixture(scope="module")
def _engine(tmp_path_factory):
    engine = create_engine(f"sqlite:///{tmp_path_factory.mktemp('wft') / 'wft.db'}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db(_engine):
    s = sessionmaker(bind=_engine)()
    for table in ("role_permissions", "user_roles", "audit_logs"):
        s.execute(text(f"DELETE FROM {table}"))
    for model in (wf.JourneyRequirement, wf.UserJourney, wf.ProfileRequirement,
                  wf.RoleProfileVersion, wf.RoleProfile, wf.LeaverRecord,
                  TrainingPlanItem, TrainingPlan, TeamCertification,
                  UserEnrolment, Course, User, Role, Permission):
        s.query(model).delete()
    s.commit()
    yield s
    s.close()


def _user(db, username, perms=()):
    role = Role(name=f"role_{username}", description="test")
    for p in perms:
        role.permissions.append(
            Permission(name=p, resource=p.split(":")[0], action=p.split(":")[1]))
    u = User(username=username, email=f"{username}@x.y", password_hash="x",
             display_name=username)
    u.roles.append(role)
    db.add(u)
    db.commit()
    return u


def _assign(db, admin, person):
    profile = wf.create_profile(db, name="L2 SOC Analyst")
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="AUP", kind=KIND_DOCUMENT, phase=PHASE_GATE)
    wf.add_requirement(db, version, name="GCIH", kind=KIND_CERT,
                       phase=PHASE_READINESS, cost=1200.0, validity_months=48,
                       funding_type="split")
    db.refresh(version)
    wf.publish_version(db, version, admin)
    return wf.assign_profile(db, user=person, version=version, assigner=admin)


def test_assignment_materialises_the_training_plan(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    _assign(db, admin, person)

    plan = db.query(TrainingPlan).filter_by(user_id=person.id).one()
    assert plan.name == "Onboarding: L2 SOC Analyst"
    assert plan.target_role == "L2 SOC Analyst"

    items = db.query(TrainingPlanItem).filter_by(plan_id=plan.id).all()
    assert [(i.cert_name, i.price, i.funding_type, i.status) for i in items] == \
        [("GCIH", 1200.0, "split", "planned")], \
        "the cost lives in the plan item the /training forecast already reads"


def test_gate_documents_do_not_become_plan_items(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    _assign(db, admin, person)
    names = [i.cert_name for i in db.query(TrainingPlanItem).all()]
    assert "AUP" not in names, "an acknowledgement is not a training cost"


def test_assigning_twice_does_not_duplicate_items(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    journey = _assign(db, admin, person)
    wf._sync_training_artifacts(db, journey)
    wf._sync_training_artifacts(db, journey)
    assert db.query(TrainingPlanItem).count() == 1


def test_verifying_the_cert_completes_the_item_and_records_the_certification(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    journey = _assign(db, admin, person)

    cert_req = next(r for r in journey.requirements if r.name == "GCIH")
    wf.submit_requirement(db, requirement=cert_req, submitter=person,
                          completed_on=date(2026, 9, 1), evidence_ref="GIAC #1")
    wf.verify_requirement(db, requirement=cert_req, verifier=admin)

    item = db.query(TrainingPlanItem).filter_by(cert_name="GCIH").one()
    assert item.status == "completed"
    assert item.completed_at is not None

    cert = db.query(TeamCertification).filter_by(
        user_id=person.id, cert_name="GCIH").one()
    assert cert.status == "active"
    assert cert.obtained_date == date(2026, 9, 1), \
        "the date the person claimed, not the day the lead got to the queue"
    assert cert.expiry_date == cert_req.expires_on


def test_a_lapsed_cert_flips_the_certification_record_too(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    journey = _assign(db, admin, person)
    cert_req = next(r for r in journey.requirements if r.name == "GCIH")
    wf.verify_requirement(db, requirement=cert_req, verifier=admin)

    cert_req.expires_on = date.today() - timedelta(days=1)
    db.commit()
    wf.sweep_expiries(db)

    cert = db.query(TeamCertification).filter_by(
        user_id=person.id, cert_name="GCIH").one()
    assert cert.status == "expired", \
        "the /training roadmap must not keep showing a lapsed cert as active"
