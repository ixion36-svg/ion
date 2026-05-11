"""Tests for the v0.23.1 investigation queue-control surface.

Covers:

- ``system_flags`` get/set/clear and truthy parsing.
- Pause/resume endpoints flip the ``investigation_loop_paused`` flag.
- Bulk-cancel sets pending rows to ``cancelled`` and leaves running rows alone.
- Per-row cancel: 404 on missing id, 0 on terminal status, 1 on pending/running.
- The sweep loop short-circuits when the pause flag is set (asserted at the
  ``investigate_open_alerts_sweep`` level — we mock ``_fetch_open_alerts``
  so the test does not require ES).

Uses SQLite in-memory; no Postgres required. Auth dependencies are
overridden so the tests do not depend on bcrypt password hashes etc.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.investigation import Investigation
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.services import system_flags
from ion.storage.database import _run_migrations, reset_engine


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "v023_1_queue.db"
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
def triage_user(db: Session) -> User:
    p_read = Permission(name="alert:read", resource="alert", action="read")
    p_triage = Permission(name="alert:triage", resource="alert", action="triage")
    db.add_all([p_read, p_triage])
    db.flush()
    role = Role(name="triage-role", description="Triage", is_system=False)
    db.add(role)
    db.flush()
    db.execute(role_permissions.insert().values(role_id=role.id, permission_id=p_read.id))
    db.execute(role_permissions.insert().values(role_id=role.id, permission_id=p_triage.id))
    u = User(
        username="triage_user",
        email="triage_user@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Triage User",
    )
    db.add(u)
    db.flush()
    db.execute(user_roles.insert().values(user_id=u.id, role_id=role.id))
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def app_client(engine, triage_user):
    """TestClient with overridden auth + DB dependencies."""
    from sqlalchemy.orm import selectinload

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
        # Fetch the user with roles + role.permissions eager-loaded so the
        # has_permission walk works after the session closes (the auth
        # dependency reads user.effective_roles → user.roles → role.permissions).
        s = test_sf()
        try:
            u = (
                s.query(User)
                .options(selectinload(User.roles).selectinload(Role.permissions))
                .filter_by(id=triage_user.id)
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


def _seed_investigation(db: Session, *, status: str, alert_id: str) -> int:
    inv = Investigation(
        alert_id_ref=alert_id,
        alert_signature=f"sig-{alert_id}",
        status=status,
    )
    db.add(inv)
    db.commit()
    return inv.id


# ── system_flags unit tests ──────────────────────────────────────────────


class TestSystemFlags:
    def test_get_missing_returns_none(self, db):
        assert system_flags.get_flag(db, "nope") is None

    def test_set_and_get_roundtrip(self, db, triage_user):
        system_flags.set_flag(
            db, system_flags.INVESTIGATION_LOOP_PAUSED, "true",
            user_id=triage_user.id,
        )
        db.commit()
        assert system_flags.get_flag(db, system_flags.INVESTIGATION_LOOP_PAUSED) == "true"
        assert system_flags.is_flag_true(db, system_flags.INVESTIGATION_LOOP_PAUSED) is True

    def test_set_upserts_on_existing_key(self, db, triage_user):
        system_flags.set_flag(db, "k", "first", user_id=triage_user.id)
        system_flags.set_flag(db, "k", "second", user_id=triage_user.id)
        db.commit()
        assert system_flags.get_flag(db, "k") == "second"

    def test_clear_removes_row(self, db, triage_user):
        system_flags.set_flag(db, "k", "true", user_id=triage_user.id)
        system_flags.clear_flag(db, "k")
        db.commit()
        assert system_flags.get_flag(db, "k") is None

    def test_is_truthy_variants(self):
        assert system_flags.is_truthy("true") is True
        assert system_flags.is_truthy("TRUE") is True
        assert system_flags.is_truthy("1") is True
        assert system_flags.is_truthy("yes") is True
        assert system_flags.is_truthy("on") is True
        assert system_flags.is_truthy("false") is False
        assert system_flags.is_truthy("") is False
        assert system_flags.is_truthy(None) is False


# ── Endpoint tests ───────────────────────────────────────────────────────


class TestLoopStatusEndpoint:
    def test_initial_status_is_not_paused(self, app_client):
        r = app_client.get("/api/investigate/loop/status")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["paused"] is False

    def test_pause_flips_status(self, app_client):
        r = app_client.post("/api/investigate/loop/pause")
        assert r.status_code == 200, r.text
        assert r.json()["paused"] is True
        s = app_client.get("/api/investigate/loop/status")
        assert s.json()["paused"] is True

    def test_resume_clears_pause(self, app_client):
        app_client.post("/api/investigate/loop/pause")
        r = app_client.post("/api/investigate/loop/resume")
        assert r.status_code == 200, r.text
        assert r.json()["paused"] is False


class TestBulkCancel:
    def test_cancel_all_pending_marks_pending_only(self, app_client, db):
        p1 = _seed_investigation(db, status="pending", alert_id="a-1")
        p2 = _seed_investigation(db, status="pending", alert_id="a-2")
        running = _seed_investigation(db, status="running", alert_id="a-3")
        completed = _seed_investigation(db, status="completed", alert_id="a-4")

        r = app_client.post("/api/investigate/jobs/cancel-pending")
        assert r.status_code == 200, r.text
        assert r.json()["cancelled_count"] == 2

        # Re-read statuses.
        statuses = {
            row[0]: row[1]
            for row in db.execute(
                text("SELECT id, status FROM investigations")
            ).fetchall()
        }
        assert statuses[p1] == "cancelled"
        assert statuses[p2] == "cancelled"
        assert statuses[running] == "running"
        assert statuses[completed] == "completed"

    def test_cancel_all_pending_idempotent(self, app_client, db):
        _seed_investigation(db, status="pending", alert_id="b-1")
        r1 = app_client.post("/api/investigate/jobs/cancel-pending")
        r2 = app_client.post("/api/investigate/jobs/cancel-pending")
        assert r1.json()["cancelled_count"] == 1
        assert r2.json()["cancelled_count"] == 0


class TestPerRowCancel:
    def test_cancel_missing_returns_404(self, app_client):
        r = app_client.post("/api/investigate/jobs/999999/cancel")
        assert r.status_code == 404

    def test_cancel_pending_returns_1(self, app_client, db):
        inv_id = _seed_investigation(db, status="pending", alert_id="c-1")
        r = app_client.post(f"/api/investigate/jobs/{inv_id}/cancel")
        assert r.status_code == 200, r.text
        assert r.json()["cancelled_count"] == 1

    def test_cancel_terminal_returns_0(self, app_client, db):
        inv_id = _seed_investigation(db, status="completed", alert_id="c-2")
        r = app_client.post(f"/api/investigate/jobs/{inv_id}/cancel")
        assert r.status_code == 200, r.text
        assert r.json()["cancelled_count"] == 0


# ── Sweep loop respects pause flag ───────────────────────────────────────


class TestSweepRespectsPauseFlag:
    def test_sweep_short_circuits_when_paused(self, db, monkeypatch, triage_user):
        from ion.services import investigation_service
        from ion.storage.database import get_engine, get_session_factory

        # Wire the pause flag.
        system_flags.set_flag(
            db, system_flags.INVESTIGATION_LOOP_PAUSED, "true",
            user_id=triage_user.id,
        )
        db.commit()

        # Make get_session_factory / get_engine return the test engine so the
        # sweep's pause check reads from our test DB.
        eng = db.bind
        monkeypatch.setattr(
            investigation_service, "get_engine", lambda: eng, raising=False
        )
        # Patched module-level imports inside sweep block use these names.
        monkeypatch.setattr(
            "ion.storage.database.get_engine", lambda: eng, raising=False
        )
        monkeypatch.setattr(
            "ion.storage.database.get_session_factory",
            lambda engine=None: sessionmaker(bind=eng, expire_on_commit=False),
            raising=False,
        )

        # Stub _fetch_open_alerts so a non-paused sweep would NOT hang on ES.
        async def _no_alerts(self, *args, **kwargs):
            return []
        monkeypatch.setattr(
            investigation_service.InvestigationService,
            "_fetch_open_alerts",
            _no_alerts,
        )

        svc = investigation_service.InvestigationService()
        import asyncio
        summary = asyncio.run(svc.investigate_open_alerts_sweep(max_alerts=10))

        assert summary.get("paused") is True
        assert summary["scanned"] == 0
        assert summary["investigated"] == 0
