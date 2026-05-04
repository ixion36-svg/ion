"""Unit tests for cyab_wizard_service — session state machine."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", future=True)
    from ion.models.base import Base
    # Importing the model registers it on Base.metadata
    import ion.models.cyab_wizard  # noqa: F401
    import ion.models.cyab          # noqa: F401  (FK target tables)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_start_wizard_returns_uuid_and_persists_row(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)
    assert isinstance(wid, str) and len(wid) >= 16

    state = svc.load_state(s, wid)
    assert state["step"] == 1
    assert state["identity"] == {}
    assert state["system_id"] is None


def test_save_step_1_creates_cyab_system_and_persists_id(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)

    state = svc.save_identity(s, wid, identity={
        "name": "prod-sso-test",
        "hostname": "sso01.corp",
        "pillar": "identity",
        "owner": "alice",
        "department": "Identity",
        "containment_authority": "SOC L2 on-call",
    })
    assert state["system_id"] is not None
    assert state["step"] == 2
    assert state["identity"]["name"] == "prod-sso-test"

    # Verify the CyabSystem row was created
    from ion.models.cyab import CyabSystem
    sys_row = s.get(CyabSystem, state["system_id"])
    assert sys_row.name == "prod-sso-test"
    assert sys_row.department == "Identity"
    assert sys_row.soc_analyst_owner == "alice"
    assert sys_row.containment_authority == "SOC L2 on-call"


def test_save_step_3_creates_data_source_with_subprofile(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)
    svc.save_identity(s, wid, identity={
        "name": "prod-dns", "hostname": "dns01", "pillar": "network",
        "owner": "bob", "department": "Net", "containment_authority": "n/a",
    })
    svc.save_intake(s, wid, answers={"q_traffic_volume": "high"})
    state = svc.save_source(s, wid, source={
        "name": "dns01", "data_source_type": "generic-syslog",
        "subprofile_id": "ad_dns_logs",
    })
    assert state["source_id"] is not None
    from ion.models.cyab import CyabDataSource
    src = s.get(CyabDataSource, state["source_id"])
    assert src.data_source_type == "generic-syslog"
    assert src.subprofile_id == "ad_dns_logs"


def test_finish_seeds_doc_checklist_and_returns_system_id(db, monkeypatch):
    from ion.services import cyab_wizard_service as svc

    seeded = {}
    def fake_seed(session, sys_id):
        seeded["sys_id"] = sys_id
        return 20
    monkeypatch.setattr(
        "ion.services.cyab_doc_checklist_service.seed_for_system", fake_seed,
    )

    s = db()
    wid = svc.start_wizard(s, user_id=1)
    svc.save_identity(s, wid, identity={
        "name": "prod-x", "hostname": "x", "pillar": "endpoint",
        "owner": "c", "department": "Ops", "containment_authority": "x",
    })
    svc.save_intake(s, wid, answers={})
    svc.save_source(s, wid, source={
        "name": "x", "data_source_type": "edr-generic", "subprofile_id": None,
    })
    sys_id = svc.finish(s, wid, doc_overrides={})
    assert seeded["sys_id"] == sys_id


def test_resume_returns_same_state(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)
    svc.save_identity(s, wid, identity={
        "name": "n", "hostname": "h", "pillar": "p",
        "owner": "o", "department": "d", "containment_authority": "c",
    })
    state = svc.load_state(s, wid)
    assert state["step"] == 2
    assert state["identity"]["name"] == "n"


def test_load_state_unknown_wid_raises(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    with pytest.raises(LookupError):
        svc.load_state(s, "does-not-exist")
