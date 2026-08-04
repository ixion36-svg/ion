"""Route-audit Phase 0 — correctness fixes.

1. Chain-of-custody ledger gap: `forensics_api` evidence/custody mutations wrote
   nothing to the tamper-evident ledger, while `/ledger/verify` attested the chain
   as complete. Only the Workbench multipart upload appended. These tests pin that
   the JSON evidence path and custody entries now appear in the ledger and that the
   chain still verifies.
2. LAB lessons could be completed through the generic
   `POST /api/lessons/{id}/complete`, skipping LabGradingService and the teardown of
   materialised mock data.
3. `/tuning-proposals` had no nav link anywhere while two live write paths kept
   filling it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ion.auth.dependencies import get_current_user, get_db_session
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import reset_engine

_PERMS = (
    "forensic:read", "forensic:create", "forensic:update", "forensic:close",
    "case:read", "case:update",
)


@pytest.fixture(scope="module")
def db_engine(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("p0") / "phase0.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    import ion.models  # noqa: F401 — registers all models
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def db_session(db_engine) -> Generator[Session, None, None]:
    session = sessionmaker(bind=db_engine, expire_on_commit=False)()
    yield session
    session.close()


@pytest.fixture(scope="module")
def admin_user(db_session: Session) -> User:
    perms = []
    for pname in _PERMS:
        resource, action = pname.split(":", 1)
        p = Permission(name=pname, resource=resource, action=action)
        db_session.add(p)
        perms.append(p)
    role = Role(name="p0_forensic_admin")
    db_session.add(role)
    db_session.flush()
    for p in perms:
        db_session.execute(role_permissions.insert().values(role_id=role.id, permission_id=p.id))
    user = User(username="p0_admin", email="p0@localhost", password_hash="x",
                display_name="P0 Admin", is_active=True)
    db_session.add(user)
    db_session.flush()
    db_session.execute(user_roles.insert().values(user_id=user.id, role_id=role.id))
    db_session.commit()
    return user


@pytest.fixture(scope="module")
def app_client(db_engine, admin_user: User) -> Generator[TestClient, None, None]:
    from ion.web.server import app
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)

    def _session():
        s = factory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_current_user] = lambda: admin_user
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()
    reset_engine()


@pytest.fixture(scope="module")
def case_id(app_client: TestClient) -> int:
    r = app_client.post("/api/forensics/cases", json={
        "title": "Phase 0 ledger case",
        "investigation_type": "malware_analysis",
        "description": "ledger gap regression",
        "priority": "high",
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ── 1. chain-of-custody ledger ───────────────────────────────────────────


def _ledger_actions(client: TestClient, case_id: int) -> list[str]:
    r = client.get(f"/api/forensics/cases/{case_id}/ledger")
    assert r.status_code == 200, r.text
    body = r.json()
    rows = body if isinstance(body, list) else body.get("entries", body.get("items", []))
    return [row["action"] for row in rows]


def test_json_evidence_add_is_ledgered(app_client: TestClient, case_id: int):
    """The JSON evidence path hits the same repo.add_evidence() as the Workbench
    upload — it must leave a ledger entry too, or /ledger/verify lies."""
    r = app_client.post(f"/api/forensics/cases/{case_id}/evidence", json={
        "name": "memory.dmp",
        "evidence_type": "memory_dump",
        "description": "json path",
        "hash_sha256": "a" * 64,
    })
    assert r.status_code == 200, r.text
    assert "evidence_add" in _ledger_actions(app_client, case_id)


def test_custody_entry_is_ledgered(app_client: TestClient, case_id: int):
    ev = app_client.post(f"/api/forensics/cases/{case_id}/evidence", json={
        "name": "disk.img", "evidence_type": "disk_image",
    })
    assert ev.status_code == 200, ev.text
    evidence_id = ev.json()["id"]

    r = app_client.post(f"/api/forensics/evidence/{evidence_id}/custody", json={
        "action": "transferred", "location": "evidence locker B", "notes": "handover",
    })
    assert r.status_code == 200, r.text
    assert "custody_entry" in _ledger_actions(app_client, case_id)


def test_evidence_update_is_ledgered(app_client: TestClient, case_id: int):
    ev = app_client.post(f"/api/forensics/cases/{case_id}/evidence", json={
        "name": "pcap.bin", "evidence_type": "network_capture",
    })
    evidence_id = ev.json()["id"]
    r = app_client.patch(f"/api/forensics/evidence/{evidence_id}",
                         json={"hash_sha256": "b" * 64})
    assert r.status_code == 200, r.text
    assert "evidence_update" in _ledger_actions(app_client, case_id)


def test_chain_still_verifies_after_new_appends(app_client: TestClient, case_id: int):
    """The new appends must not break the sha256 chain, and must actually be in it
    (seq_count guards against a vacuous pass on an empty ledger)."""
    # Ensure at least one append exists regardless of test ordering.
    app_client.post(f"/api/forensics/cases/{case_id}/evidence",
                    json={"name": "chain.bin", "evidence_type": "other"})
    r = app_client.get(f"/api/forensics/cases/{case_id}/ledger/verify")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_valid"] is True, body
    assert body["seq_count"] > 0, body
    assert body["first_break_seq"] is None, body


# ── 2. LAB completion guard ──────────────────────────────────────────────


def test_lab_guard_present_in_source():
    """A LAB lesson must not be completable via the generic reading endpoint —
    that path skips LabGradingService and the materialised-fixture teardown."""
    src = Path("src/ion/web/course_api.py").read_text(encoding="utf-8")
    fn = src.split("def mark_lesson_complete", 1)[1].split("\ndef ", 1)[0]
    assert "LessonType.LAB" in fn, "LAB guard missing from mark_lesson_complete"
    assert "lab/complete" in fn, "guard should point the caller at the lab endpoint"


# ── 3. tuning-proposals reachability ─────────────────────────────────────


def test_tuning_proposals_queue_is_reachable():
    """Bob files proposals unattended, so the review queue must be reachable.

    v0.67.0 satisfied this with a stop-gap nav link to /tuning-proposals.
    v0.72.0 (phase 8) superseded that: the pipeline was migrated into the DE
    module's governed queue, the legacy page retired, and its URL now redirects
    to /de-proposals?source=bob — which IS linked from the Engineering nav. The
    invariant is unchanged; only the destination moved.
    """
    base = Path("src/ion/web/templates/base.html").read_text(encoding="utf-8")
    assert 'href="/de-proposals"' in base, "the governed queue must be in the nav"

    from ion.web.server import app
    paths = {r.path for r in app.routes}
    assert "/tuning-proposals" in paths, "legacy bookmarks must redirect, not 404"
