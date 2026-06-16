"""Tests for v0.41.0 staff-schedule enhancements — capability thresholds CRUD
and roster CSV export (backend).

Strategy: call the skills_api endpoint functions directly with the ``session``
fixture (SQLite temp DB) and a dummy user — the route's permission gate is a
FastAPI ``Depends`` that direct calls bypass, so we exercise the core logic
without a TestClient/auth harness (matches the codebase's unit-test style).
"""

from __future__ import annotations

import csv
import io
from datetime import date

import pytest

from ion.models.skills import CapabilityThreshold, TeamScheduleEntry
from ion.models.user import User
from ion.web import skills_api
from ion.web.skills_api import (
    ThresholdBulkSave,
    ThresholdItem,
    export_schedule_csv,
    get_coverage_thresholds,
    save_coverage_thresholds,
)


@pytest.fixture
def user(session):
    u = User(username="lead1", email="lead1@test.ion", password_hash="x",
             is_active=True, display_name="Lead One")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


# ---------------------------------------------------------------------------
# Capability thresholds CRUD
# ---------------------------------------------------------------------------


class TestThresholds:
    def test_get_empty(self, session, user):
        out = get_coverage_thresholds(current_user=user, session=session)
        assert out == {"thresholds": []}

    def test_upsert_then_get(self, session, user):
        payload = ThresholdBulkSave(thresholds=[
            ThresholdItem(capability_key="Incident Response", min_staff=2, min_level=3),
            ThresholdItem(capability_key="Digital Forensics", min_staff=1, min_level=4, notes="GCFA on shift"),
        ])
        res = save_coverage_thresholds(payload=payload, current_user=user, session=session)
        assert res["saved"] == 2

        out = get_coverage_thresholds(current_user=user, session=session)
        by_key = {t["capability_key"]: t for t in out["thresholds"]}
        assert by_key["Incident Response"]["min_staff"] == 2
        assert by_key["Digital Forensics"]["min_level"] == 4
        assert by_key["Digital Forensics"]["notes"] == "GCFA on shift"

    def test_update_existing_in_place(self, session, user):
        save_coverage_thresholds(
            payload=ThresholdBulkSave(thresholds=[ThresholdItem(capability_key="SIEM & Log Analysis", min_staff=1, min_level=2)]),
            current_user=user, session=session,
        )
        save_coverage_thresholds(
            payload=ThresholdBulkSave(thresholds=[ThresholdItem(capability_key="SIEM & Log Analysis", min_staff=3, min_level=4)]),
            current_user=user, session=session,
        )
        rows = session.query(CapabilityThreshold).filter_by(capability_key="SIEM & Log Analysis").all()
        assert len(rows) == 1  # upsert, not duplicate
        assert rows[0].min_staff == 3 and rows[0].min_level == 4

    def test_min_staff_zero_deletes(self, session, user):
        save_coverage_thresholds(
            payload=ThresholdBulkSave(thresholds=[ThresholdItem(capability_key="Network Defense", min_staff=2, min_level=3)]),
            current_user=user, session=session,
        )
        assert session.query(CapabilityThreshold).filter_by(capability_key="Network Defense").count() == 1
        save_coverage_thresholds(
            payload=ThresholdBulkSave(thresholds=[ThresholdItem(capability_key="Network Defense", min_staff=0)]),
            current_user=user, session=session,
        )
        assert session.query(CapabilityThreshold).filter_by(capability_key="Network Defense").count() == 0

    def test_blank_key_skipped(self, session, user):
        res = save_coverage_thresholds(
            payload=ThresholdBulkSave(thresholds=[ThresholdItem(capability_key="   ", min_staff=2)]),
            current_user=user, session=session,
        )
        assert res["saved"] == 0
        assert session.query(CapabilityThreshold).count() == 0

    def test_item_validation_bounds(self):
        # min_level must be 1..5, min_staff 0..50 (Pydantic Field constraints).
        with pytest.raises(Exception):
            ThresholdItem(capability_key="X", min_staff=2, min_level=9)
        with pytest.raises(Exception):
            ThresholdItem(capability_key="X", min_staff=-1)


# ---------------------------------------------------------------------------
# Roster CSV export
# ---------------------------------------------------------------------------


class TestRosterExport:
    def _seed(self, session):
        u1 = User(username="a1", email="a1@t.ion", password_hash="x", is_active=True, display_name="Analyst One")
        u2 = User(username="a2", email="a2@t.ion", password_hash="x", is_active=True, display_name="Analyst Two")
        session.add_all([u1, u2])
        session.commit()
        session.add_all([
            TeamScheduleEntry(user_id=u1.id, date=date(2026, 6, 1), status="working", shift="day"),
            TeamScheduleEntry(user_id=u1.id, date=date(2026, 6, 2), status="leave", shift=None, notes="Annual\nleave"),
            TeamScheduleEntry(user_id=u2.id, date=date(2026, 6, 1), status="working", shift="night"),
            # Out-of-month row must be excluded:
            TeamScheduleEntry(user_id=u2.id, date=date(2026, 7, 1), status="working", shift="day"),
        ])
        session.commit()
        return u1, u2

    def test_export_csv_content(self, session, user):
        u1, u2 = self._seed(session)
        resp = export_schedule_csv(month="2026-06", current_user=user, session=session)
        assert resp.media_type == "text/csv"
        assert "ion-roster-2026-06.csv" in resp.headers["Content-Disposition"]

        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        reader = list(csv.reader(io.StringIO(body)))
        header = reader[0]
        assert header == ["date", "user_id", "username", "display_name", "status", "shift", "notes"]
        data_rows = reader[1:]
        # 3 June rows; the July row is excluded.
        assert len(data_rows) == 3
        assert all(r[0].startswith("2026-06") for r in data_rows)
        # newline in notes is flattened to a space
        leave_row = [r for r in data_rows if r[4] == "leave"][0]
        assert "\n" not in leave_row[6]
        assert leave_row[2] == "a1"

    def test_export_bad_month(self, session, user):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            export_schedule_csv(month="June-2026", current_user=user, session=session)
        assert exc.value.status_code == 400

    def test_export_empty_month_just_header(self, session, user):
        resp = export_schedule_csv(month="2030-01", current_user=user, session=session)
        body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
        rows = list(csv.reader(io.StringIO(body)))
        assert len(rows) == 1  # header only


def test_module_imports_cleanly():
    # Guard: the new endpoints are wired on the skills router.
    paths = {getattr(r, "path", "") for r in skills_api.router.routes}
    assert "/coverage/thresholds" in paths
    assert "/schedule/export.csv" in paths
