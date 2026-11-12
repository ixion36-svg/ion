"""CyAB pages and forms, end to end through the app.

Each form posts through htmx and answers 303 to the page it belongs to, so
these tests post, read where they were sent, and check the database.
"""

import csv
import io
import json
from datetime import date, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from ion.models.cyab import CyabDataSource, CyabSystem
from ion.models.cyab_assurance import CyabChecklistException, CyabSignoff
from ion.models.cyab_doc_checklist import CyabDocChecklistItem
from ion.services import cyab_sal
from ion.services.cyab_subprofile_catalogue import NEXT_GEN_FIREWALL

SUB = NEXT_GEN_FIREWALL["id"]
CAT = NEXT_GEN_FIREWALL["catalogue"]


@pytest.fixture
def app_client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from ion.storage.database import reset_engine
    from tests.integration.conftest import _pin_engine
    reset_engine()
    _pin_engine(temp_db)
    from ion.models.user import User
    from ion.services.cyab_subprofile_service import seed_catalogue
    from ion.web.server import app

    db = sessionmaker(bind=temp_db)()
    db.add(User(id=1, username="admin", email="admin@localhost", password_hash="x",
                display_name="Administrator", is_active=True))
    db.commit()
    db.close()
    seed_catalogue()

    fake = User(id=1, username="admin", email="admin@localhost", password_hash="x",
                display_name="Administrator", is_active=True)
    monkeypatch.setattr(User, "has_permission", lambda self, name: True)
    for route in app.router.routes:
        dependant = getattr(route, "dependant", None)
        for dep in (dependant.dependencies if dependant else []):
            if getattr(dep.call, "__name__", "") == "dependency":
                app.dependency_overrides[dep.call] = lambda: fake
    from ion.auth.dependencies import get_current_user
    app.dependency_overrides[get_current_user] = lambda: fake
    yield TestClient(app)
    app.dependency_overrides.clear()
    reset_engine()


@pytest.fixture
def db(temp_db):
    s = sessionmaker(bind=temp_db, expire_on_commit=False)()
    yield s
    s.close()


def _system(db, **kw):
    kw.setdefault("name", "Payroll DB")
    kw.setdefault("department", "Finance")
    s = CyabSystem(**kw)
    db.add(s)
    db.commit()
    return s


def _post(client, url, data):
    r = client.post(url, data=data, follow_redirects=False)
    assert r.status_code == 303, r.text
    loc = urlparse(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    return loc.path, q


def _complete_up_to_signoff(client, db, sys_id):
    _post(client, f"/cyab/systems/{sys_id}/profile", {
        "name": "Payroll DB", "department": "Finance", "department_lead": "Dana",
        "soc_analyst_owner": "Administrator", "data_classification": "OFFICIAL", "sal_tier": "SAL-2",
    })
    _post(client, f"/cyab/systems/{sys_id}/sources", {"name": "Edge firewall", "subprofile_id": SUB})
    ds = db.scalars(select(CyabDataSource).where(CyabDataSource.system_id == sys_id)).one()
    _post(client, f"/cyab/systems/{sys_id}/intake",
          {f"q:{q['key']}": (q["options"][0]["value"] if q.get("options") else "yes") for q in CAT["intake_questions"]})
    for uc in CAT["detection_use_cases"] + CAT["audit_use_cases"]:
        _post(client, f"/cyab/sources/{ds.id}/use-case", {"uc": uc["id"], "status": "shipped"})
    client.get(f"/cyab/systems/{sys_id}/signoff")
    for item in db.scalars(select(CyabDocChecklistItem).where(CyabDocChecklistItem.system_id == sys_id)):
        _post(client, f"/cyab/checklist/{item.id}", {"status": "done", "url": "https://docs.example/x"})
    return ds


def test_onboard_creates_a_draft_and_sends_you_to_sources(app_client, db):
    path, q = _post(app_client, "/cyab/onboard", {
        "name": "VPN gateway", "department": "IT", "sal_tier": "SAL-4", "soc_analyst_owner": "Administrator",
    })
    system = db.scalars(select(CyabSystem).where(CyabSystem.name == "VPN gateway")).one()
    assert path == f"/cyab/systems/{system.id}/sources"
    assert system.status == "DRAFT" and system.sal_tier == "SAL-4"
    assert system.review_cadence_days == cyab_sal.REVIEW_DAYS["SAL-4"]
    assert db.scalars(select(CyabDocChecklistItem).where(CyabDocChecklistItem.system_id == system.id)).all()


def test_onboard_without_a_name_comes_back_with_the_reason(app_client, db):
    path, q = _post(app_client, "/cyab/onboard", {"name": "", "department": "IT"})
    assert path == "/cyab/onboard" and "name" in q["err"]
    assert db.scalars(select(CyabSystem)).all() == []


def test_onboard_keeps_answers_carried_from_scoping(app_client, db):
    from ion.services.cyab_assessment_service import load_answers
    _post(app_client, "/cyab/onboard", {"name": "Mail relay", "department": "IT",
                                         "scoping_answers": json.dumps({"stack_email": "exchange"})})
    system = db.scalars(select(CyabSystem).where(CyabSystem.name == "Mail relay")).one()
    assert load_answers(db, system.id)["stack_email"] == "exchange"


def test_every_tab_renders_and_unknown_ones_do_not(app_client, db):
    sid = _system(db).id
    for tab in ("summary", "profile", "sources", "use-cases", "signoff"):
        r = app_client.get(f"/cyab/systems/{sid}/{tab}")
        assert r.status_code == 200, (tab, r.text[:500])
        assert 'id="cyab-main"' in r.text and "Payroll DB" in r.text
    assert app_client.get(f"/cyab/systems/{sid}/nope").status_code == 404
    assert app_client.get("/cyab/systems/999999/summary").status_code == 404
    r = app_client.get(f"/cyab/systems/{sid}", follow_redirects=False)
    assert r.headers["location"] == f"/cyab/systems/{sid}/summary"


def test_the_stage_moves_as_each_step_is_finished(app_client, db):
    from ion.services.cyab_readiness_service import compute
    sid = _system(db).id
    assert compute(db, db.get(CyabSystem, sid)).stage == "profile"
    _complete_up_to_signoff(app_client, db, sid)
    db.expire_all()
    r = compute(db, db.get(CyabSystem, sid))
    assert r.stage == "signoff", [(s.key, s.done, s.total) for s in r.steps]
    page = app_client.get(f"/cyab/systems/{sid}/signoff").text
    assert "Sign off as department and SOC" in page


def test_sign_off_names_the_signed_in_user_and_starts_the_review_clock(app_client, db):
    sid = _system(db).id
    _complete_up_to_signoff(app_client, db, sid)
    _post(app_client, f"/cyab/systems/{sid}/sign", {"role": "department", "note": "ok"})
    path, q = _post(app_client, f"/cyab/systems/{sid}/sign", {"role": "soc"})
    assert q["msg"] == "Signed off as SOC"
    db.expire_all()
    system = db.get(CyabSystem, sid)
    rows = db.scalars(select(CyabSignoff).where(CyabSignoff.system_id == sid)).all()
    assert {r.role for r in rows} == {"department", "soc"}
    assert {r.signer_name for r in rows} == {"Administrator"}
    assert system.sign_dept_name == "Administrator" and system.status == "ACTIVE"
    assert system.next_review_date == date.today() + timedelta(days=cyab_sal.REVIEW_DAYS["SAL-2"])
    assert "signed off as SOC" in app_client.get("/cyab/history").text


def test_sign_off_is_refused_until_the_earlier_steps_are_done(app_client, db):
    sid = _system(db).id
    path, q = _post(app_client, f"/cyab/systems/{sid}/sign", {"role": "department"})
    assert path == f"/cyab/systems/{sid}/signoff" and q["err"].startswith("Finish profile")
    assert db.scalars(select(CyabSignoff)).all() == []


def test_the_json_sign_endpoint_ignores_typed_names(app_client, db):
    sid = _system(db).id
    assert app_client.post(f"/api/cyab/systems/{sid}/onboarding-pack/sign",
                           json={"sign_dept_name": "Someone Else"}).status_code == 409
    _complete_up_to_signoff(app_client, db, sid)
    r = app_client.post(f"/api/cyab/systems/{sid}/onboarding-pack/sign", json={"sign_dept_name": "Someone Else"})
    assert r.status_code == 200 and r.json()["sign_dept_name"] == "Administrator"


def test_a_gap_is_accepted_within_the_sal_limit_and_reopens_when_revoked(app_client, db):
    from ion.services.cyab_readiness_service import compute
    sid = _system(db, sal_tier="SAL-4").id
    app_client.get(f"/cyab/systems/{sid}/signoff")
    hld = db.scalars(select(CyabDocChecklistItem).where(
        CyabDocChecklistItem.system_id == sid, CyabDocChecklistItem.kind == "HLD")).one()
    too_long = (date.today() + timedelta(days=cyab_sal.MAX_EXCEPTION_DAYS["SAL-4"] + 1)).isoformat()
    _, q = _post(app_client, f"/cyab/checklist/{hld.id}/accept", {"reason": "r", "approver": "CISO", "until": too_long})
    assert "at most 91 days" in q["err"]
    until = (date.today() + timedelta(days=30)).isoformat()
    _, q = _post(app_client, f"/cyab/checklist/{hld.id}/accept",
                 {"reason": "Design under rewrite", "approver": "J. CISO", "until": until})
    assert "accepted" in q["msg"]
    assert "High-Level Design" not in compute(db, db.get(CyabSystem, sid)).missing_docs
    exc = db.scalars(select(CyabChecklistException)).one()
    _post(app_client, f"/cyab/exceptions/{exc.id}/revoke", {})
    db.expire_all()
    assert "High-Level Design" in compute(db, db.get(CyabSystem, sid)).missing_docs


def test_checklist_links_must_be_web_links(app_client, db):
    sid = _system(db).id
    app_client.get(f"/cyab/systems/{sid}/signoff")
    item = db.scalars(select(CyabDocChecklistItem).where(CyabDocChecklistItem.system_id == sid)).first()
    _, q = _post(app_client, f"/cyab/checklist/{item.id}", {"status": "done", "url": "javascript:alert(1)"})
    assert "http" in q["err"]
    db.expire_all()
    assert db.get(CyabDocChecklistItem, item.id).url is None


def test_use_case_status_is_kept_per_source_and_only_for_its_sub_profile(app_client, db):
    sid = _system(db).id
    _post(app_client, f"/cyab/systems/{sid}/sources", {"name": "fw", "subprofile_id": SUB})
    ds = db.scalars(select(CyabDataSource)).one()
    _, q = _post(app_client, f"/cyab/sources/{ds.id}/use-case", {"uc": "ad_kerberoasting", "status": "shipped"})
    assert "does not belong" in q["err"]
    every = CAT["detection_use_cases"] + CAT["audit_use_cases"]
    for uc in every:
        _post(app_client, f"/cyab/sources/{ds.id}/use-case", {"uc": uc["id"], "status": "partial"})
    db.expire_all()
    assert len(json.loads(db.get(CyabDataSource, ds.id).use_case_status)) == len(every)
    page = app_client.get(f"/cyab/systems/{sid}/use-cases").text
    assert every[0]["title"] in page


def test_systems_list_filters_pages_and_switches_to_matrix(app_client, db):
    for i in range(30):
        _system(db, name=f"sys-{i:02d}", soc_analyst_owner="Administrator" if i < 3 else "someone")
    page1 = app_client.get("/cyab/systems?sort=name").text
    assert "sys-00" in page1 and "sys-29" not in page1 and "Page 1 of 2" in page1
    assert "sys-29" in app_client.get("/cyab/systems?sort=name&page=2").text
    mine = app_client.get("/cyab/systems?view=mine").text
    assert "sys-02" in mine and "sys-03" not in mine
    assert "No systems match" in app_client.get("/cyab/systems?stage=signed").text
    matrix = app_client.get("/cyab/systems?mode=matrix&sort=name").text
    assert ">1/3</span>" in matrix and ">0/2</span>" in matrix and "<progress" not in matrix
    assert app_client.get("/cyab/coverage", follow_redirects=False).headers["location"] == "/cyab/systems?mode=matrix"


def test_bulk_assigns_owner_and_sal(app_client, db):
    a, b = _system(db, name="a"), _system(db, name="b")
    _, q = _post(app_client, "/cyab/systems/bulk", {"ids": [a.id, b.id], "action": "owner", "owner": "Tomo",
                                                     "back": "/cyab/systems?view=all"})
    assert q["msg"] == "Tomo now owns 2 systems"
    path, _ = _post(app_client, "/cyab/systems/bulk", {"ids": [a.id], "action": "sal", "sal": "SAL-5",
                                                        "back": "https://evil.example/"})
    assert path == "/cyab/systems"
    db.expire_all()
    assert db.get(CyabSystem, a.id).sal_tier == "SAL-5" and db.get(CyabSystem, b.id).soc_analyst_owner == "Tomo"
    _, q = _post(app_client, "/cyab/systems/bulk", {"action": "owner", "owner": "x"})
    assert "Select" in q["err"]


def test_csv_export_neutralises_formulas(app_client, db):
    _system(db, name="=HYPERLINK(\"x\")")
    r = app_client.get("/cyab/systems.csv")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:3] == ["id", "name", "department"]
    assert rows[1][1].startswith("'=")


def test_board_counts_stages_and_lists_my_queue(app_client, db):
    _system(db, name="Mine", soc_analyst_owner="administrator")
    _system(db, name="Theirs", soc_analyst_owner="tomo")
    page = app_client.get("/cyab").text
    assert "Onboarding board" in page and "/cyab/systems?stage=profile" in page
    queue = page.split('aria-label="My queue"')[1].split("</section>")[0]
    assert "Mine" in queue and "Theirs" not in queue


def test_history_filters_by_system_and_exports(app_client, db):
    a = _system(db, name="Alpha")
    _system(db, name="Beta")
    page = app_client.get(f"/cyab/history?system={a.id}").text
    assert "Alpha" in page and ">Beta</a>" not in page
    assert app_client.get("/cyab/audit", follow_redirects=False).headers["location"] == "/cyab/history"
    assert "onboarded the system" in app_client.get("/cyab/history.csv").text


def test_scoping_convert_navigates_an_htmx_caller(app_client):
    r = app_client.post("/api/cyab/scoping/convert", data={"stack_os": "windows"},
                        headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 204 and r.headers["HX-Redirect"].startswith("/cyab/onboard?from_scoping=1")


def _permissions(dependant):
    found = set()
    for dep in dependant.dependencies:
        if getattr(dep.call, "__name__", "") == "dependency":
            for cell in dep.call.__closure__ or ():
                if isinstance(cell.cell_contents, str):
                    found.add(cell.cell_contents)
        found |= _permissions(dep)
    return found


def test_every_cyab_write_needs_more_than_read():
    from fastapi.routing import APIRoute
    from ion.web.server import app
    public = {"/api/cyab/scoping/score", "/api/cyab/scoping/pdf"}
    # Stashes questionnaire answers for the onboard form; writes nothing.
    read_ok = {"/api/cyab/scoping/convert"}
    checked = 0
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.endpoint.__module__ not in ("ion.web.cyab_api", "ion.web.cyab_pages"):
            continue
        if not route.methods & {"POST", "PUT", "PATCH", "DELETE"} or route.path in public:
            continue
        perms = _permissions(route.dependant)
        if route.path in read_ok:
            assert perms, route.path
            continue
        assert perms & {"case:update", "case:close"}, (route.path, perms)
        checked += 1
    assert checked > 30


def test_a_field_edit_cannot_sign_or_activate_a_system(app_client, db):
    sid = _system(db).id
    r = app_client.put(f"/api/cyab/systems/{sid}", json={"status": "ACTIVE"})
    assert r.status_code == 409
    app_client.put(f"/api/cyab/systems/{sid}", json={"sign_dept_name": "Forged", "sign_dept_date": "2026-01-01"})
    db.expire_all()
    assert db.get(CyabSystem, sid).sign_dept_name is None
    assert app_client.post(f"/api/cyab/systems/{sid}/mark-reviewed").status_code == 409


def test_lowering_sal_needs_approval(app_client, db, monkeypatch):
    from ion.models.user import User
    sid = _system(db, sal_tier="SAL-4").id
    monkeypatch.setattr(User, "has_permission", lambda self, name: name != "case:close")
    _, q = _post(app_client, f"/cyab/systems/{sid}/profile", {"name": "Payroll DB", "department": "Finance", "sal_tier": "SAL-1"})
    assert "case:close" in q["err"]
    _, q = _post(app_client, f"/cyab/systems/{sid}/profile", {"name": "Payroll DB", "department": "Finance", "sal_tier": "SAL-5"})
    assert q["msg"] == "Profile saved"
    db.expire_all()
    assert db.get(CyabSystem, sid).sal_tier == "SAL-5"
    assert db.get(CyabSystem, sid).review_cadence_days == cyab_sal.REVIEW_DAYS["SAL-5"]


def test_creating_a_system_cannot_sign_or_activate_it(app_client, db):
    forged = {"sign_dept_name": "Forged", "sign_dept_date": "2026-01-01",
              "sign_soc_name": "Forged", "sign_soc_date": "2026-01-01"}
    assert app_client.post("/api/cyab/systems", json={"name": "a", "department": "d", "status": "ACTIVE"}).status_code == 409
    assert app_client.post("/api/cyab/onboarding", json={"name": "b", "department": "d", "status": "ACTIVE"}).status_code == 409
    for url, name in (("/api/cyab/systems", "c"), ("/api/cyab/onboarding", "e")):
        r = app_client.post(url, json={"name": name, "department": "d", **forged})
        assert r.status_code < 300, r.text
    db.expire_all()
    rows = db.scalars(select(CyabSystem)).all()
    assert {s.name for s in rows} == {"c", "e"}
    assert all(s.status == "DRAFT" and s.sign_dept_name is None and s.sign_soc_date is None for s in rows)
