"""Case-update API contract tests from the 8 Oct 2026 feature review.

The review reproduced three defects in the single ``PATCH
/api/elasticsearch/alerts/cases/{id}`` handler, all of which are
analyst-visible:

1. **P1 — invalid status breaks subsequent reads.** ``CaseUpdate.status``
   was a bare ``Optional[str]``, so any string was written straight into
   the ``AlertCaseStatus`` enum column. Committing ``status="banana"``
   then blew up on refresh with ``LookupError``, and — worse — a later
   ORM query for *all* cases also failed, taking the case board down for
   everyone after one malformed request.

2. **P2 — "Unassigned" reported success without removing the owner.**
   The UI sends ``assigned_to_id: null`` for the Unassigned option, but
   the handler guarded on ``is not None``, so an explicit null was
   indistinguishable from an omitted field and silently kept the
   original owner.

3. **P2 — rejected updates persisted partial edits.** Title, description,
   severity and assignment were applied (and assignment *committed*)
   before closure validation ran. A request carrying a new title, an
   assignee and ``status="closed"`` with no ``closure_reason`` returned
   400 having already saved the title and the assignment.

These tests pin the corrected contract: validate the whole transition
first, mutate once, commit once, and treat omitted and explicitly-null
fields as different requests.
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
    db_path = tmp_path / "review_case_update.db"
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
def second_analyst(db: Session) -> User:
    u = User(
        username="second_analyst",
        email="second@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Second Analyst",
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def app_client(engine, case_updater):
    reset_engine()
    from ion.auth.dependencies import get_current_user, get_db_session
    from ion.web.api import get_db_session as api_get_db_session
    from ion.web.server import app

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


def _make_open_case(db: Session, user: User, owner: User | None = None) -> AlertCase:
    case = AlertCase(
        case_number=f"REV-{user.id}-{datetime.utcnow().timestamp():.0f}",
        title="Original title",
        description="Original description",
        status="open",
        severity="medium",
        created_by_id=user.id,
        assigned_to_id=owner.id if owner else None,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _read_row(engine, case_id: int):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    fresh = factory()
    try:
        return fresh.execute(
            text(
                "SELECT status, title, description, severity, assigned_to_id "
                "FROM alert_cases WHERE id = :cid"
            ),
            {"cid": case_id},
        ).fetchone()
    finally:
        fresh.close()


# ── Finding 1: invalid status must never reach the database ───────────────


class TestInvalidStatusRejected:
    def test_unknown_status_returns_422(self, app_client, db, case_updater):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"status": "banana"},
        )
        assert r.status_code == 422, r.text

    def test_unknown_status_leaves_case_unchanged(self, app_client, db, engine, case_updater):
        case = _make_open_case(db, case_updater)
        app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"status": "banana"},
        )
        row = _read_row(engine, case.id)
        # SQLEnum(native_enum=False) stores the enum NAME.
        assert row.status == "OPEN"
        assert row.title == "Original title"

    def test_case_board_still_loads_after_rejected_status(
        self, app_client, db, case_updater
    ):
        """The whole point of P1: one bad PATCH must not break list reads."""
        case = _make_open_case(db, case_updater)
        app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"status": "banana"},
        )
        listing = app_client.get("/api/elasticsearch/alerts/cases")
        assert listing.status_code == 200, listing.text
        assert any(c["id"] == case.id for c in listing.json()["cases"])

    def test_valid_status_still_accepted(self, app_client, db, engine, case_updater):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"status": "acknowledged"},
        )
        assert r.status_code == 200, r.text
        assert _read_row(engine, case.id).status == "ACKNOWLEDGED"


# ── Finding 4: explicit null means unassign, omission means leave alone ───


class TestAssignmentNullSemantics:
    def test_explicit_null_clears_the_owner(
        self, app_client, db, engine, case_updater, second_analyst
    ):
        case = _make_open_case(db, case_updater, owner=second_analyst)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"assigned_to_id": None},
        )
        assert r.status_code == 200, r.text
        assert _read_row(engine, case.id).assigned_to_id is None

    def test_omitted_assignee_preserves_the_owner(
        self, app_client, db, engine, case_updater, second_analyst
    ):
        case = _make_open_case(db, case_updater, owner=second_analyst)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"title": "Retitled only"},
        )
        assert r.status_code == 200, r.text
        row = _read_row(engine, case.id)
        assert row.assigned_to_id == second_analyst.id
        assert row.title == "Retitled only"

    def test_assigning_a_new_owner_still_works(
        self, app_client, db, engine, case_updater, second_analyst
    ):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={"assigned_to_id": second_analyst.id},
        )
        assert r.status_code == 200, r.text
        assert _read_row(engine, case.id).assigned_to_id == second_analyst.id


# ── Finding 5: a rejected patch must change nothing at all ────────────────


class TestRejectedUpdateIsAtomic:
    def test_mixed_patch_rejected_for_missing_closure_reason_saves_nothing(
        self, app_client, db, engine, case_updater, second_analyst
    ):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={
                "title": "Half-applied title",
                "description": "Half-applied description",
                "severity": "critical",
                "assigned_to_id": second_analyst.id,
                "status": "closed",
            },
        )
        assert r.status_code == 400, r.text

        row = _read_row(engine, case.id)
        assert row.title == "Original title"
        assert row.description == "Original description"
        assert row.severity == "medium"
        assert row.assigned_to_id is None
        assert row.status == "OPEN"

    def test_mixed_patch_rejected_for_bad_closure_reason_saves_nothing(
        self, app_client, db, engine, case_updater, second_analyst
    ):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={
                "title": "Half-applied title",
                "assigned_to_id": second_analyst.id,
                "status": "closed",
                "closure_reason": "not_a_real_reason",
            },
        )
        assert r.status_code == 400, r.text

        row = _read_row(engine, case.id)
        assert row.title == "Original title"
        assert row.assigned_to_id is None
        assert row.status == "OPEN"

    def test_accepted_mixed_patch_applies_every_field(
        self, app_client, db, engine, case_updater, second_analyst
    ):
        case = _make_open_case(db, case_updater)
        r = app_client.patch(
            f"/api/elasticsearch/alerts/cases/{case.id}",
            json={
                "title": "Confirmed intrusion",
                "severity": "critical",
                "assigned_to_id": second_analyst.id,
                "status": "closed",
                "closure_reason": "true_positive",
                "closure_notes": "Lateral movement confirmed.",
            },
        )
        assert r.status_code == 200, r.text

        row = _read_row(engine, case.id)
        assert row.title == "Confirmed intrusion"
        assert row.severity == "critical"
        assert row.assigned_to_id == second_analyst.id
        assert row.status == "CLOSED"
