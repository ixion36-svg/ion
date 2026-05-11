"""Smoke for the v0.25.0 audit events that feed adaptive lab grading.

Pins the contract that:
- ``PATCH /api/elasticsearch/alerts/cases/{id}`` with ``status=closed`` and a
  valid ``closure_reason`` writes a single ``case_closed`` audit_logs row,
  with the closure_reason serialised in the ``details`` JSON.
- A subsequent PATCH that does NOT close the case (e.g. setting
  ``assigned_to_id`` while status is still closed) does not write another
  ``case_closed`` audit_logs row.

The observable_linked audit event (also added in v0.25.0) is exercised
indirectly via tests/test_lab_grading.py's TestObservableCreatedEvaluator,
which synthesises the audit rows that the api-layer writers produce.
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
from ion.models.alert_triage import AlertCase
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import _run_migrations, reset_engine


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "v025_audit.db"
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
def case_user(db: Session) -> User:
    p_update = Permission(name="case:update", resource="case", action="update")
    p_read = Permission(name="case:read", resource="case", action="read")
    db.add_all([p_update, p_read])
    db.flush()
    role = Role(name="closer", description="Case closer", is_system=False)
    db.add(role)
    db.flush()
    db.execute(role_permissions.insert().values(
        role_id=role.id, permission_id=p_update.id
    ))
    db.execute(role_permissions.insert().values(
        role_id=role.id, permission_id=p_read.id
    ))
    u = User(
        username="closer_user",
        email="closer@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Closer",
    )
    db.add(u)
    db.flush()
    db.execute(user_roles.insert().values(user_id=u.id, role_id=role.id))
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def app_client(engine, case_user):
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
                .filter_by(id=case_user.id)
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
        case_number=f"V025-{user.id}-{datetime.utcnow().timestamp():.0f}",
        title="Test case for v0.25.0 audit smoke",
        status="open",
        severity="medium",
        created_by_id=user.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _count_case_closed_audits(engine, case_id: int) -> int:
    fresh = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        n = fresh.execute(
            text(
                "SELECT COUNT(*) FROM audit_logs "
                "WHERE action = 'case_closed' "
                "  AND resource_type = 'alert_case' "
                "  AND resource_id = :cid"
            ),
            {"cid": case_id},
        ).scalar()
        return int(n or 0)
    finally:
        fresh.close()


class TestCaseClosedAuditEvent:
    def test_close_writes_audit_row(self, app_client, db, case_user):
        case = _make_open_case(db, case_user)
        case_id = case.id

        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case_id}",
            json={
                "status": "closed",
                "closure_reason": "true_positive",
                "closure_notes": "Confirmed.",
            },
        )
        assert r.status_code == 200, r.text

        assert _count_case_closed_audits(db.bind, case_id) == 1

    def test_audit_row_details_carry_closure_reason(
        self, app_client, db, case_user
    ):
        case = _make_open_case(db, case_user)
        case_id = case.id

        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case_id}",
            json={
                "status": "closed",
                "closure_reason": "false_positive",
                "closure_notes": "Tuning fix landed.",
            },
        )
        assert r.status_code == 200, r.text

        fresh = sessionmaker(bind=db.bind, expire_on_commit=False)()
        try:
            row = fresh.execute(
                text(
                    "SELECT details FROM audit_logs "
                    "WHERE action = 'case_closed' "
                    "  AND resource_id = :cid"
                ),
                {"cid": case_id},
            ).fetchone()
        finally:
            fresh.close()

        assert row is not None
        import json
        details = json.loads(row.details) if isinstance(row.details, str) else row.details
        assert details.get("closure_reason") == "false_positive"
        assert details.get("case_id") == case_id

    def test_subsequent_non_close_patch_does_not_write_extra_audit(
        self, app_client, db, case_user
    ):
        case = _make_open_case(db, case_user)
        case_id = case.id

        # First PATCH closes the case → 1 audit row.
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case_id}",
            json={"status": "closed", "closure_reason": "true_positive"},
        )
        assert r.status_code == 200, r.text
        assert _count_case_closed_audits(db.bind, case_id) == 1

        # Second PATCH only mutates assigned_to_id (does NOT re-close).
        # The audit row count must stay at 1.
        r2 = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case_id}",
            json={"assigned_to_id": case_user.id},
        )
        assert r2.status_code == 200, r2.text
        assert _count_case_closed_audits(db.bind, case_id) == 1
