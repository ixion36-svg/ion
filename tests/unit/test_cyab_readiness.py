"""Stage, readiness and SAL rules, against an in-memory database."""

import json
from datetime import date, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import ion.models  # noqa: F401  (registers every table)
from ion.models.base import Base
from ion.models.cyab import CyabDataSource, CyabSystem, CyabSystemAssessment
from ion.models.cyab_assurance import CyabChecklistException, CyabSignoff
from ion.models.cyab_doc_checklist import CyabDocChecklistItem
from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile
from ion.services import cyab_assurance_service as assurance
from ion.services import cyab_readiness_service as rs
from ion.services import cyab_sal
from ion.services.cyab_doc_checklist_service import seed_for_system
from ion.services.cyab_subprofile_catalogue import NEXT_GEN_FIREWALL, PILLARS, SUBPROFILES

TODAY = date(2026, 11, 10)
CAT = NEXT_GEN_FIREWALL["catalogue"]


class _User:
    id = None
    display_name = "Dana"
    username = "dana"


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as s:
        for p in PILLARS:
            s.add(CyabPillar(id=p["id"], label=p["label"], icon=p["icon"], priority=p["priority"]))
        for sp in SUBPROFILES:
            s.add(CyabSubProfile(id=sp["id"], pillar_id=sp["pillar_id"], label=sp["label"],
                                 icon=sp["icon"], catalogue_json=json.dumps(sp["catalogue"])))
        s.commit()
        yield s


def _ready_for_signoff(db, sal="SAL-2"):
    system = CyabSystem(name="fw", department="IT", department_lead="L", soc_analyst_owner="O",
                        data_classification="OFFICIAL", sal_tier=sal)
    db.add(system)
    db.commit()
    db.add(CyabDataSource(system_id=system.id, name="fw", subprofile_id=NEXT_GEN_FIREWALL["id"],
                          use_case_status=json.dumps({u["id"]: "shipped" for u in
                                                      CAT["detection_use_cases"] + CAT["audit_use_cases"]})))
    db.add(CyabSystemAssessment(system_id=system.id,
                                responses_json=json.dumps({q["key"]: "yes" for q in CAT["intake_questions"]})))
    seed_for_system(db, system.id)
    for item in db.query(CyabDocChecklistItem).filter_by(system_id=system.id):
        item.status = "done"
    db.commit()
    return system


def test_a_bare_system_starts_at_profile_and_names_what_is_missing(db):
    system = CyabSystem(name="x", department="IT")
    db.add(system)
    db.commit()
    r = rs.compute(db, system, TODAY)
    assert r.stage == "profile"
    assert r.next_action == "Add department lead, SOC owner, data classification"
    assert r.pct == 0


def test_sal_decides_which_documents_are_required():
    assert "THREAT_MODEL" not in cyab_sal.required_kinds("SAL-1")
    assert {"THREAT_MODEL", "DECOMMISSIONING", "HLD"} <= cyab_sal.required_kinds("SAL-4")
    assert cyab_sal.normalise("3") == cyab_sal.normalise("sal3") == "SAL-3"
    assert cyab_sal.normalise("SAL-9") == cyab_sal.DEFAULT


def test_raising_the_sal_reopens_documents(db):
    system = _ready_for_signoff(db, "SAL-1")
    item = db.query(CyabDocChecklistItem).filter_by(system_id=system.id, kind="THREAT_MODEL").one()
    item.status = "missing"
    db.commit()
    assert rs.compute(db, system, TODAY).stage == "signoff"
    system.sal_tier = "SAL-4"
    db.commit()
    r = rs.compute(db, system, TODAY)
    assert r.stage == "docs" and r.next_action == "Attach Threat Model"


def test_an_expired_acceptance_stops_counting(db):
    system = _ready_for_signoff(db)
    hld = db.query(CyabDocChecklistItem).filter_by(system_id=system.id, kind="HLD").one()
    hld.status = "missing"
    db.add(CyabChecklistException(item_id=hld.id, system_id=system.id, reason="r", approver="a",
                                  until=TODAY + timedelta(days=5)))
    db.commit()
    assert rs.compute(db, system, TODAY).stage == "signoff"
    assert rs.compute(db, system, TODAY + timedelta(days=6)).stage == "docs"


def test_signing_needs_both_roles_and_then_review_falls_due(db):
    system = _ready_for_signoff(db, "SAL-5")
    assurance.sign(db, system, "department", _User(), today=TODAY)
    assert rs.compute(db, system, TODAY).stage == "signoff"
    assurance.sign(db, system, "soc", _User(), today=TODAY)
    assert system.next_review_date == TODAY + timedelta(days=91)
    assert rs.compute(db, system, TODAY).stage == "signed"
    assert rs.compute(db, system, TODAY + timedelta(days=92)).stage == "review_due"
    assurance.mark_reviewed(db, system, _User(), today=TODAY + timedelta(days=92))
    assert rs.compute(db, system, TODAY + timedelta(days=92)).stage == "signed"
    assert [s.role for s in assurance.history(db, system.id)].count("review") == 1


def test_compute_many_matches_compute_one_at_a_time(db):
    systems = [_ready_for_signoff(db), CyabSystem(name="bare", department="IT")]
    db.add(systems[1])
    db.commit()
    db.add(CyabSignoff(system_id=systems[0].id, role="soc", signer_name="x"))
    db.commit()
    many = rs.compute_many(db, systems, TODAY)
    for s in systems:
        assert many[s.id] == rs.compute(db, s, TODAY)


def test_retired_systems_are_retired_whatever_else_is_true(db):
    system = _ready_for_signoff(db)
    system.status = "RETIRED"
    db.commit()
    assert rs.compute(db, system, TODAY).stage == "retired"


def test_a_burst_of_document_edits_reads_as_one_line():
    from datetime import datetime
    t = datetime(2026, 11, 10, 12, 0)
    ev = lambda kind, minutes, sid=1, uid=1: {"kind": kind, "at": t - timedelta(minutes=minutes),
                                              "system_id": sid, "user_id": uid, "text": "set x"}
    out = assurance._collapse_checklist_runs([
        ev("checklist", 0), ev("checklist", 2), ev("checklist", 9),
        ev("signoff", 10),
        ev("checklist", 11), ev("checklist", 12, sid=2), ev("checklist", 40, sid=2),
    ])
    assert [e["text"] for e in out] == ["updated 3 documents", "set x", "set x", "set x", "set x"]
