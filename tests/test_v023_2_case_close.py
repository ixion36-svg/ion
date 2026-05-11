"""Backend regression for the v0.23.2 case-close fix.

The operator-reported bug was a UI one: closing a case via the panel
dropdown sometimes appeared to do nothing, while drag-and-dropping the
card to the kanban "closed" column worked every time. Investigation
showed the server-side PATCH path was identical for both — the
divergence was in the post-PATCH JS, where the panel refresh was gated
on `allCases.find(c => c.id === caseId)` returning a row. If allCases
hadn't yet been repopulated (network race or list-endpoint failure),
the gate silently failed and left the panel showing pre-close state.

The JS fix tracks the panel's open caseId on `panel.dataset.caseId` and
no longer consults allCases. There's no JS test harness here, so this
suite at least pins down the backend half of the contract:

- ``PATCH /api/elasticsearch/alerts/cases/{id}`` with
  ``{status: 'closed', closure_reason: 'true_positive'}`` actually sets
  ``status=CLOSED``, ``closure_reason='true_positive'``, ``closed_at``,
  and ``closed_by_id`` and persists across a fresh read.
- The same PATCH without ``closure_reason`` is rejected with 400.
- The same PATCH with an invalid ``closure_reason`` is rejected.

If the panel-dropdown bug returns, we'll know it's NOT the server side.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, selectinload, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import _run_migrations, reset_engine


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "v023_2_close.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    _run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def db(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture()
def case_updater(db: Session) -> User:
    p_update = Permission(name="case:update", resource="case", action="update")
    p_read = Permission(name="case:read", resource="case", action="read")
    db.add_all([p_update, p_read])
    db.flush()
    role = Role(name="case-updater", description="Case updater", is_system=False)
    db.add(role)
    db.flush()
    db.execute(role_permissions.insert().values(role_id=role.id, permission_id=p_update.id))
    db.execute(role_permissions.insert().values(role_id=role.id, permission_id=p_read.id))
    u = User(
        username="case_updater",
        email="case_updater@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Case Updater",
    )
    db.add(u)
    db.flush()
    db.execute(user_roles.insert().values(user_id=u.id, role_id=role.id))
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def app_client(engine, case_updater):
    reset_engine()
    from ion.web.server import app
    from ion.auth.dependencies import get_current_user, get_db_session
    from ion.web.api import get_db_session as api_get_db_session

    test_sf = sessionmaker(bind=engine, expire_on_commit=False)

    def _session_factory():
        s = test_sf()
        try:
            yield s
        finally:
            s.close()

    def _fake_user():
        s = test_sf()
        try:
            u = (
                s.query(User)
                .options(selectinload(User.roles).selectinload(Role.permissions))
                .filter_by(id=case_updater.id)
                .one()
            )
            s.expunge(u)
            return u
        finally:
            s.close()

    app.dependency_overrides[get_db_session] = _session_factory
    app.dependency_overrides[api_get_db_session] = _session_factory
    app.dependency_overrides[get_current_user] = _fake_user

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client

    app.dependency_overrides.clear()
    reset_engine()


def _make_open_case(db: Session, user: User) -> AlertCase:
    case = AlertCase(
        case_number=f"CLOSE-{user.id}-{datetime.utcnow().timestamp():.0f}",
        title="Test case for closure",
        status="open",
        severity="medium",
        created_by_id=user.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


# ── Tests ─────────────────────────────────────────────────────────────────


class TestPatchCloseFlow:
    def test_patch_with_valid_closure_reason_closes_case(
        self, app_client, db, case_updater
    ):
        case = _make_open_case(db, case_updater)
        case_id = case.id

        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case_id}",
            json={
                "status": "closed",
                "closure_reason": "true_positive",
                "closure_notes": "Confirmed lateral movement on PT-LAB-04.",
            },
        )
        assert r.status_code == 200, r.text

        # Read back in a fresh session — proves the close was committed.
        eng = db.bind
        fresh_factory = sessionmaker(bind=eng, expire_on_commit=False)
        fresh = fresh_factory()
        try:
            row = fresh.execute(
                text(
                    "SELECT status, closure_reason, closure_notes, "
                    "       closed_at, closed_by_id "
                    "FROM alert_cases WHERE id = :cid"
                ),
                {"cid": case_id},
            ).fetchone()
        finally:
            fresh.close()

        # SQLAlchemy SQLEnum with native_enum=False stores enum NAME (uppercase).
        assert row.status == "CLOSED"
        assert row.closure_reason == "true_positive"
        assert row.closure_notes == "Confirmed lateral movement on PT-LAB-04."
        assert row.closed_at is not None
        assert row.closed_by_id == case_updater.id

    def test_patch_without_closure_reason_returns_400(
        self, app_client, db, case_updater
    ):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"status": "closed"},
        )
        assert r.status_code == 400
        assert "closure_reason" in r.text.lower()

        # Case must NOT have transitioned.
        eng = db.bind
        fresh = sessionmaker(bind=eng, expire_on_commit=False)()
        try:
            row = fresh.execute(
                text("SELECT status FROM alert_cases WHERE id = :cid"),
                {"cid": case.id},
            ).fetchone()
        finally:
            fresh.close()
        assert row.status != "CLOSED"

    def test_patch_with_invalid_closure_reason_returns_400(
        self, app_client, db, case_updater
    ):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={
                "status": "closed",
                "closure_reason": "not_a_real_reason",
            },
        )
        assert r.status_code == 400
        assert "closure_reason" in r.text.lower()

    def test_patch_close_then_get_returns_closed_status(
        self, app_client, db, case_updater
    ):
        """Round-trip: after closure, the GET endpoint serializes status='closed'.

        This is the contract the JS panel relies on when re-rendering.
        """
        case = _make_open_case(db, case_updater)
        case_id = case.id

        r1 = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case_id}",
            json={
                "status": "closed",
                "closure_reason": "false_positive",
            },
        )
        assert r1.status_code == 200, r1.text

        r2 = app_client.get(f"/api/elasticsearch/alerts/cases/{case_id}")
        assert r2.status_code == 200, r2.text
        data = r2.json()
        assert data["status"] == "closed"
        assert data["closure_reason"] == "false_positive"
        assert data["closed_at"] is not None
