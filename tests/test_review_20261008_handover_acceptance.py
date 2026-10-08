"""Shift handover as an accountable transfer (8 Oct 2026 review, §17).

    "Observed gap: handover generates a report rather than persisting an
    accountable transfer with incoming acceptance and owned actions."

    "Improve: a shared operational snapshot with source timestamps.
    Preserve outgoing/incoming leads, unresolved actions, owners, deadlines
    and acceptance. Show changes since the last accepted handover."

    "Measure: unaccepted handovers, overdue transferred actions."

``generate_shift_report`` computed a fresh view of the last N hours every
time it was called. Nothing was stored, so there was no answer to "what did
the night shift hand us", no record that anyone took the handover, and no
owner for the work that crossed the boundary. Two shifts could each believe
the other was carrying a case.

What accountability needs, and what these tests pin:

* **A frozen snapshot.** A report recomputed at read time shows the estate as
  it is now, not as it was when the shift ended. The numbers the outgoing
  lead signed off on have to survive, with the timestamp they were taken at.
* **Named leads on both sides.** A transfer with one name is a note.
* **Acceptance by someone other than the outgoing lead.** Accepting your own
  handover is the one thing the record exists to rule out.
* **Owned actions with deadlines**, carried forward when they are not done,
  so a task that crosses three shifts is visibly a task that crossed three
  shifts rather than a fresh one each time.
* **Atomic acceptance**, because two people reaching for the same handover
  must resolve to one — the same conditional-UPDATE discipline stage 1
  applied to response actions.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase
from ion.models.base import Base
from ion.models.shift_handover import (
    HandoverActionStatus,
    HandoverStatus,
    ShiftHandover,
    ShiftHandoverAction,
)
from ion.models.user import User
from ion.services import shift_handover_record_service as handovers
from ion.services.shift_handover_record_service import HandoverError
from ion.storage.database import _run_migrations


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'handover.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def sf(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def db(sf):
    s = sf()
    for uid, name in ((1, "night_lead"), (2, "day_lead"), (3, "analyst"),
                      (4, "other_lead")):
        s.add(User(id=uid, username=name, email=f"{name}@x", password_hash="x",
                   display_name=name, is_active=True))
    s.add(AlertCase(id=1, case_number="CASE-0001", title="Carried case",
                    severity="high", created_by_id=1))
    s.commit()
    yield s
    s.close()


def _draft(db, **over):
    kwargs = dict(outgoing_lead_id=1, incoming_lead_id=2, hours=8,
                  summary="Quiet night, one case still open.")
    kwargs.update(over)
    return handovers.create_handover(db, **kwargs)


def _accepted(db, **over):
    h = _draft(db, **over)
    handovers.submit_handover(db, handover_id=h.id, actor_id=1)
    handovers.accept_handover(db, handover_id=h.id, actor_id=2)
    return db.get(ShiftHandover, h.id)


# ── Schema ───────────────────────────────────────────────────────────────


class TestSchema:
    def test_the_tables_exist_on_a_fresh_database(self, engine):
        names = set(inspect(engine).get_table_names())
        assert "shift_handovers" in names
        assert "shift_handover_actions" in names

    def test_the_migration_creates_them_on_an_upgrade(self, tmp_path):
        """An existing deployment has no models-driven create_all for these."""
        eng = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
        try:
            # Everything except the two new tables, as an older deployment has.
            Base.metadata.create_all(
                eng,
                tables=[t for n, t in Base.metadata.tables.items()
                        if n not in ("shift_handovers", "shift_handover_actions")],
            )
            assert not inspect(eng).has_table("shift_handovers")
            _run_migrations(eng)
            names = set(inspect(eng).get_table_names())
            assert "shift_handovers" in names
            assert "shift_handover_actions" in names
        finally:
            eng.dispose()

    def test_the_migration_is_idempotent(self, engine):
        _run_migrations(engine)
        _run_migrations(engine)


# ── The frozen snapshot ──────────────────────────────────────────────────


class TestSnapshot:
    def test_a_draft_freezes_the_shift_report(self, db):
        h = _draft(db)
        assert isinstance(h.snapshot, dict)
        assert h.snapshot["pending"]["open_cases"] >= 0

    def test_the_snapshot_records_when_it_was_taken(self, db):
        h = _draft(db)
        assert h.snapshot_taken_at is not None
        assert h.snapshot["snapshot_taken_at"]

    def test_the_snapshot_does_not_move_when_the_estate_does(self, db):
        """The whole point: the numbers the outgoing lead signed off survive."""
        h = _draft(db)
        before = h.snapshot["pending"]["open_cases"]

        db.add(AlertCase(id=50, case_number="CASE-0050", title="New after handover",
                         severity="low", created_by_id=3))
        db.commit()

        db.expire_all()
        again = db.get(ShiftHandover, h.id)
        assert again.snapshot["pending"]["open_cases"] == before

    def test_the_snapshot_states_its_window(self, db):
        h = _draft(db, hours=12)
        assert h.snapshot["shift_hours"] == 12
        assert h.shift_start is not None
        assert h.shift_end is not None

    def test_the_snapshot_names_its_sources_with_timestamps(self, db):
        """Review: "a shared operational snapshot with source timestamps"."""
        h = _draft(db)
        sources = h.snapshot["sources"]
        assert sources
        for source in sources:
            assert source["name"]
            assert source["as_of"]


# ── Leads and status ─────────────────────────────────────────────────────


class TestLifecycle:
    def test_a_new_handover_is_a_draft(self, db):
        assert _draft(db).status == HandoverStatus.DRAFT.value

    def test_both_leads_are_recorded(self, db):
        h = _draft(db)
        assert h.outgoing_lead_id == 1
        assert h.incoming_lead_id == 2

    def test_an_incoming_lead_may_be_decided_later(self, db):
        h = _draft(db, incoming_lead_id=None)
        assert h.incoming_lead_id is None

    def test_submitting_without_an_incoming_lead_is_refused(self, db):
        """A transfer needs someone on the other end to be a transfer."""
        h = _draft(db, incoming_lead_id=None)
        with pytest.raises(HandoverError):
            handovers.submit_handover(db, handover_id=h.id, actor_id=1)

    def test_the_incoming_lead_can_be_set_before_submitting(self, db):
        h = _draft(db, incoming_lead_id=None)
        handovers.set_incoming_lead(db, handover_id=h.id, incoming_lead_id=2,
                                    actor_id=1)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        assert db.get(ShiftHandover, h.id).status == HandoverStatus.SUBMITTED.value

    def test_the_outgoing_lead_cannot_be_the_incoming_lead(self, db):
        with pytest.raises(HandoverError):
            _draft(db, outgoing_lead_id=1, incoming_lead_id=1)

    def test_submitting_stamps_the_time(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        assert db.get(ShiftHandover, h.id).submitted_at is not None

    def test_only_the_outgoing_lead_may_submit(self, db):
        h = _draft(db)
        with pytest.raises(HandoverError):
            handovers.submit_handover(db, handover_id=h.id, actor_id=3)

    def test_submitting_twice_is_refused(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        with pytest.raises(HandoverError):
            handovers.submit_handover(db, handover_id=h.id, actor_id=1)

    def test_a_draft_cannot_be_accepted(self, db):
        """Nothing has been handed over yet."""
        h = _draft(db)
        with pytest.raises(HandoverError):
            handovers.accept_handover(db, handover_id=h.id, actor_id=2)


# ── Acceptance ───────────────────────────────────────────────────────────


class TestAcceptance:
    def test_accepting_records_who_and_when(self, db):
        h = _accepted(db)
        assert h.status == HandoverStatus.ACCEPTED.value
        assert h.accepted_by_id == 2
        assert h.accepted_at is not None

    def test_the_outgoing_lead_cannot_accept_their_own_handover(self, db):
        """The one thing the record exists to rule out."""
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        with pytest.raises(HandoverError):
            handovers.accept_handover(db, handover_id=h.id, actor_id=1)

    def test_the_designated_lead_accepting_is_marked_as_such(self, db):
        h = _accepted(db)
        assert h.accepted_by_designated_lead is True

    def test_someone_else_accepting_is_allowed_but_flagged(self, db):
        """The named lead going off sick must not block the shift. The record
        says who actually took it, which is the accountable fact."""
        h = _draft(db, incoming_lead_id=2)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        handovers.accept_handover(db, handover_id=h.id, actor_id=4)
        h = db.get(ShiftHandover, h.id)
        assert h.status == HandoverStatus.ACCEPTED.value
        assert h.accepted_by_id == 4
        assert h.incoming_lead_id == 2
        assert h.accepted_by_designated_lead is False

    def test_rejecting_needs_a_reason(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        with pytest.raises(HandoverError):
            handovers.reject_handover(db, handover_id=h.id, actor_id=2, reason="")

    def test_rejecting_records_the_reason(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        handovers.reject_handover(db, handover_id=h.id, actor_id=2,
                                  reason="Three cases have no notes at all.")
        h = db.get(ShiftHandover, h.id)
        assert h.status == HandoverStatus.REJECTED.value
        assert "no notes" in h.rejection_reason

    def test_a_rejected_handover_can_be_resubmitted(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        handovers.reject_handover(db, handover_id=h.id, actor_id=2, reason="thin")
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        assert db.get(ShiftHandover, h.id).status == HandoverStatus.SUBMITTED.value

    def test_an_accepted_handover_cannot_be_rejected(self, db):
        h = _accepted(db)
        with pytest.raises(HandoverError):
            handovers.reject_handover(db, handover_id=h.id, actor_id=2, reason="x")

    def test_acceptance_is_atomic(self, sf, db):
        """Two leads reaching for the same handover resolve to one.

        Both sessions observe `submitted` before either writes, which is the
        interleaving a read-then-write makes inevitable.
        """
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)

        s_a, s_b = sf(), sf()
        try:
            assert s_a.get(ShiftHandover, h.id).status == HandoverStatus.SUBMITTED.value
            assert s_b.get(ShiftHandover, h.id).status == HandoverStatus.SUBMITTED.value

            handovers.accept_handover(s_a, handover_id=h.id, actor_id=2)
            with pytest.raises(HandoverError):
                handovers.accept_handover(s_b, handover_id=h.id, actor_id=4)
        finally:
            s_a.close()
            s_b.close()

        db.expire_all()
        assert db.get(ShiftHandover, h.id).accepted_by_id == 2


# ── Owned actions ────────────────────────────────────────────────────────


class TestActions:
    def test_an_action_can_be_added_to_a_draft(self, db):
        h = _draft(db)
        action = handovers.add_action(
            db, handover_id=h.id, actor_id=1,
            description="Chase the EDR agent on fin-07",
            owner_id=3, due_at=datetime.now(timezone.utc) + timedelta(hours=4),
            case_id=1,
        )
        assert action.status == HandoverActionStatus.OPEN.value
        assert action.owner_id == 3
        assert action.case_id == 1

    def test_an_action_needs_a_description(self, db):
        h = _draft(db)
        with pytest.raises(HandoverError):
            handovers.add_action(db, handover_id=h.id, actor_id=1, description="  ")

    def test_an_action_may_have_no_owner_yet_but_it_is_visible(self, db):
        """An unowned action is a real state, and worth surfacing as a gap."""
        h = _draft(db)
        handovers.add_action(db, handover_id=h.id, actor_id=1,
                            description="Review the proxy logs", owner_id=None)
        detail = handovers.get_handover(db, h.id)
        assert detail["unowned_action_count"] == 1

    def test_actions_cannot_be_added_after_acceptance(self, db):
        """The accepted record is what both leads agreed to."""
        h = _accepted(db)
        with pytest.raises(HandoverError):
            handovers.add_action(db, handover_id=h.id, actor_id=2, description="late")

    def test_completing_an_action_records_who_and_when(self, db):
        h = _draft(db)
        a = handovers.add_action(db, handover_id=h.id, actor_id=1,
                                 description="Chase fin-07", owner_id=3)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        handovers.accept_handover(db, handover_id=h.id, actor_id=2)
        handovers.complete_action(db, action_id=a.id, actor_id=3)
        a = db.get(ShiftHandoverAction, a.id)
        assert a.status == HandoverActionStatus.DONE.value
        assert a.completed_by_id == 3
        assert a.completed_at is not None

    def test_completing_twice_is_refused(self, db):
        h = _draft(db)
        a = handovers.add_action(db, handover_id=h.id, actor_id=1,
                                 description="x", owner_id=3)
        handovers.complete_action(db, action_id=a.id, actor_id=3)
        with pytest.raises(HandoverError):
            handovers.complete_action(db, action_id=a.id, actor_id=3)

    def test_an_action_can_be_cancelled_with_a_reason(self, db):
        h = _draft(db)
        a = handovers.add_action(db, handover_id=h.id, actor_id=1,
                                 description="x", owner_id=3)
        handovers.cancel_action(db, action_id=a.id, actor_id=1,
                                reason="Duplicate of the ticket raised at 02:10")
        a = db.get(ShiftHandoverAction, a.id)
        assert a.status == HandoverActionStatus.CANCELLED.value
        assert "Duplicate" in (a.resolution_note or "")

    def test_cancelling_needs_a_reason(self, db):
        h = _draft(db)
        a = handovers.add_action(db, handover_id=h.id, actor_id=1,
                                 description="x", owner_id=3)
        with pytest.raises(HandoverError):
            handovers.cancel_action(db, action_id=a.id, actor_id=1, reason="")


# ── Overdue ──────────────────────────────────────────────────────────────


class TestOverdue:
    def test_a_past_deadline_is_overdue(self, db):
        h = _draft(db)
        handovers.add_action(
            db, handover_id=h.id, actor_id=1, description="late one", owner_id=3,
            due_at=datetime.now(timezone.utc) - timedelta(hours=2))
        detail = handovers.get_handover(db, h.id)
        assert detail["actions"][0]["overdue"] is True
        assert detail["overdue_action_count"] == 1

    def test_a_future_deadline_is_not_overdue(self, db):
        h = _draft(db)
        handovers.add_action(
            db, handover_id=h.id, actor_id=1, description="soon", owner_id=3,
            due_at=datetime.now(timezone.utc) + timedelta(hours=2))
        assert handovers.get_handover(db, h.id)["actions"][0]["overdue"] is False

    def test_an_action_with_no_deadline_is_not_overdue(self, db):
        """No deadline means no deadline, not an immediately breached one."""
        h = _draft(db)
        handovers.add_action(db, handover_id=h.id, actor_id=1,
                            description="whenever", owner_id=3)
        action = handovers.get_handover(db, h.id)["actions"][0]
        assert action["overdue"] is False
        assert action["due_at"] is None

    def test_a_completed_action_past_its_deadline_is_not_overdue(self, db):
        h = _draft(db)
        a = handovers.add_action(
            db, handover_id=h.id, actor_id=1, description="done late", owner_id=3,
            due_at=datetime.now(timezone.utc) - timedelta(hours=2))
        handovers.complete_action(db, action_id=a.id, actor_id=3)
        assert handovers.get_handover(db, h.id)["overdue_action_count"] == 0


# ── Carry-forward ────────────────────────────────────────────────────────


class TestCarryForward:
    def test_open_actions_carry_into_the_next_handover(self, db):
        first = _draft(db)
        handovers.add_action(db, handover_id=first.id, actor_id=1,
                            description="Chase fin-07", owner_id=3)
        handovers.submit_handover(db, handover_id=first.id, actor_id=1)
        handovers.accept_handover(db, handover_id=first.id, actor_id=2)

        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        descriptions = [a["description"]
                        for a in handovers.get_handover(db, second.id)["actions"]]
        assert "Chase fin-07" in descriptions

    def test_completed_actions_do_not_carry(self, db):
        first = _draft(db)
        a = handovers.add_action(db, handover_id=first.id, actor_id=1,
                                 description="Done already", owner_id=3)
        handovers.complete_action(db, action_id=a.id, actor_id=3)
        handovers.submit_handover(db, handover_id=first.id, actor_id=1)
        handovers.accept_handover(db, handover_id=first.id, actor_id=2)

        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        assert handovers.get_handover(db, second.id)["actions"] == []

    def test_a_carried_action_counts_its_crossings(self, db):
        """An action that crossed three shifts should look like one."""
        prev = None
        for i in range(3):
            out_lead, in_lead = (1, 2) if i % 2 == 0 else (2, 1)
            h = handovers.create_handover(db, outgoing_lead_id=out_lead,
                                          incoming_lead_id=in_lead, hours=8)
            if prev is None:
                handovers.add_action(db, handover_id=h.id, actor_id=out_lead,
                                    description="Long runner", owner_id=3)
            handovers.submit_handover(db, handover_id=h.id, actor_id=out_lead)
            handovers.accept_handover(db, handover_id=h.id, actor_id=in_lead)
            prev = h

        final = handovers.create_handover(db, outgoing_lead_id=1,
                                          incoming_lead_id=2, hours=8)
        action = handovers.get_handover(db, final.id)["actions"][0]
        assert action["description"] == "Long runner"
        assert action["carry_count"] == 3

    def test_a_carried_action_keeps_its_owner_and_deadline(self, db):
        due = (datetime.now(timezone.utc) + timedelta(hours=6)).replace(microsecond=0)
        first = _draft(db)
        handovers.add_action(db, handover_id=first.id, actor_id=1,
                            description="Keep me", owner_id=3, due_at=due,
                            case_id=1)
        handovers.submit_handover(db, handover_id=first.id, actor_id=1)
        handovers.accept_handover(db, handover_id=first.id, actor_id=2)

        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        carried = handovers.get_handover(db, second.id)["actions"][0]
        assert carried["owner_id"] == 3
        assert carried["case_id"] == 1
        assert carried["due_at"].startswith(due.isoformat()[:16])

    def test_only_the_last_accepted_handover_is_the_source(self, db):
        """A draft nobody accepted must not become the baseline."""
        accepted = _draft(db)
        handovers.add_action(db, handover_id=accepted.id, actor_id=1,
                            description="From the accepted one", owner_id=3)
        handovers.submit_handover(db, handover_id=accepted.id, actor_id=1)
        handovers.accept_handover(db, handover_id=accepted.id, actor_id=2)

        abandoned = handovers.create_handover(db, outgoing_lead_id=2,
                                              incoming_lead_id=1, hours=8)
        handovers.add_action(db, handover_id=abandoned.id, actor_id=2,
                            description="From the abandoned draft", owner_id=3)

        third = handovers.create_handover(db, outgoing_lead_id=1,
                                          incoming_lead_id=2, hours=8)
        descriptions = [a["description"]
                        for a in handovers.get_handover(db, third.id)["actions"]]
        assert "From the accepted one" in descriptions
        assert "From the abandoned draft" not in descriptions

    def test_the_previous_accepted_handover_is_linked(self, db):
        first = _accepted(db)
        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        assert second.previous_handover_id == first.id

    def test_the_first_handover_has_no_predecessor(self, db):
        assert _draft(db).previous_handover_id is None


# ── Changes since the last accepted handover ─────────────────────────────


class TestChangesSince:
    def test_a_first_handover_reports_no_baseline(self, db):
        h = _draft(db)
        changes = handovers.get_handover(db, h.id)["changes_since_previous"]
        assert changes["baseline"] is None
        assert changes["metrics"] == []

    def test_a_later_handover_compares_against_the_baseline(self, db):
        first = _accepted(db)
        db.add(AlertCase(id=60, case_number="CASE-0060", title="Opened since",
                         severity="medium", created_by_id=3))
        db.commit()

        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        changes = handovers.get_handover(db, second.id)["changes_since_previous"]
        assert changes["baseline"] == first.id
        by_name = {m["name"]: m for m in changes["metrics"]}
        assert by_name["open_cases"]["delta"] == 1
        assert by_name["open_cases"]["direction"] == "up"

    def test_an_unchanged_metric_reports_a_flat_direction(self, db):
        _accepted(db)
        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        changes = handovers.get_handover(db, second.id)["changes_since_previous"]
        by_name = {m["name"]: m for m in changes["metrics"]}
        assert by_name["open_cases"]["delta"] == 0
        assert by_name["open_cases"]["direction"] == "flat"

    def test_a_metric_missing_from_the_baseline_is_not_a_delta_of_itself(self, db):
        """An older snapshot shape has no value to compare; say so."""
        first = _accepted(db)
        snapshot = dict(first.snapshot)
        snapshot["pending"] = {k: v for k, v in snapshot["pending"].items()
                               if k != "open_cases"}
        first.snapshot = snapshot
        db.commit()

        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        changes = handovers.get_handover(db, second.id)["changes_since_previous"]
        by_name = {m["name"]: m for m in changes["metrics"]}
        assert by_name["open_cases"]["delta"] is None
        assert by_name["open_cases"]["direction"] == "unknown"


# ── The measures the review asks for ─────────────────────────────────────
#
# "Measure: unaccepted handovers, overdue transferred actions."


class TestMetrics:
    def test_a_submitted_handover_nobody_took_is_unaccepted(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        metrics = handovers.handover_metrics(db)
        assert metrics["unaccepted_count"] == 1
        assert metrics["unaccepted"][0]["id"] == h.id

    def test_an_accepted_handover_is_not_counted_as_unaccepted(self, db):
        _accepted(db)
        assert handovers.handover_metrics(db)["unaccepted_count"] == 0

    def test_a_draft_is_not_yet_unaccepted(self, db):
        """Nobody was asked to take it, so nobody failed to."""
        _draft(db)
        assert handovers.handover_metrics(db)["unaccepted_count"] == 0

    def test_a_rejected_handover_counts_as_unaccepted(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        handovers.reject_handover(db, handover_id=h.id, actor_id=2, reason="thin")
        assert handovers.handover_metrics(db)["unaccepted_count"] == 1

    def test_unaccepted_handovers_report_how_long_they_have_waited(self, db):
        h = _draft(db)
        handovers.submit_handover(db, handover_id=h.id, actor_id=1)
        entry = handovers.handover_metrics(db)["unaccepted"][0]
        assert entry["waiting_hours"] is not None
        assert entry["waiting_hours"] >= 0

    def test_overdue_transferred_actions_are_counted(self, db):
        h = _draft(db)
        handovers.add_action(
            db, handover_id=h.id, actor_id=1, description="late", owner_id=3,
            due_at=datetime.now(timezone.utc) - timedelta(hours=3))
        metrics = handovers.handover_metrics(db)
        assert metrics["overdue_action_count"] == 1
        assert metrics["overdue_actions"][0]["description"] == "late"

    def test_a_completed_overdue_action_is_not_counted(self, db):
        h = _draft(db)
        a = handovers.add_action(
            db, handover_id=h.id, actor_id=1, description="late but done",
            owner_id=3, due_at=datetime.now(timezone.utc) - timedelta(hours=3))
        handovers.complete_action(db, action_id=a.id, actor_id=3)
        assert handovers.handover_metrics(db)["overdue_action_count"] == 0

    def test_overdue_actions_report_their_carry_count(self, db):
        """A repeatedly carried overdue action is the signal worth seeing."""
        first = _draft(db)
        handovers.add_action(
            db, handover_id=first.id, actor_id=1, description="runner", owner_id=3,
            due_at=datetime.now(timezone.utc) - timedelta(hours=3))
        handovers.submit_handover(db, handover_id=first.id, actor_id=1)
        handovers.accept_handover(db, handover_id=first.id, actor_id=2)
        handovers.create_handover(db, outgoing_lead_id=2, incoming_lead_id=1,
                                  hours=8)

        overdue = handovers.handover_metrics(db)["overdue_actions"]
        assert max(a["carry_count"] for a in overdue) == 1

    def test_unowned_open_actions_are_surfaced(self, db):
        h = _draft(db)
        handovers.add_action(db, handover_id=h.id, actor_id=1,
                            description="nobody's job", owner_id=None)
        assert handovers.handover_metrics(db)["unowned_action_count"] == 1


# ── Listing ──────────────────────────────────────────────────────────────


class TestListing:
    def test_handovers_are_listed_newest_first(self, db):
        first = _accepted(db)
        second = handovers.create_handover(db, outgoing_lead_id=2,
                                           incoming_lead_id=1, hours=8)
        ids = [h["id"] for h in handovers.list_handovers(db)]
        assert ids == [second.id, first.id]

    def test_a_listed_handover_names_both_leads(self, db):
        _accepted(db)
        row = handovers.list_handovers(db)[0]
        assert row["outgoing_lead"] == "night_lead"
        assert row["incoming_lead"] == "day_lead"
        assert row["accepted_by"] == "day_lead"

    def test_a_listed_handover_counts_its_open_actions(self, db):
        h = _draft(db)
        handovers.add_action(db, handover_id=h.id, actor_id=1, description="a",
                            owner_id=3)
        handovers.add_action(db, handover_id=h.id, actor_id=1, description="b",
                            owner_id=3)
        assert handovers.list_handovers(db)[0]["open_action_count"] == 2

    def test_the_limit_is_honoured(self, db):
        for _ in range(4):
            handovers.create_handover(db, outgoing_lead_id=1, incoming_lead_id=2,
                                      hours=8)
        assert len(handovers.list_handovers(db, limit=2)) == 2

    def test_a_missing_handover_is_an_error_not_a_blank(self, db):
        with pytest.raises(HandoverError):
            handovers.get_handover(db, 9999)


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "shift_handover_api.py").read_text(
            encoding="utf-8")

    def test_the_handover_routes_exist(self):
        src = self._api()
        for route in ('"/handovers"', '"/handovers/{handover_id}"',
                      '"/handovers/{handover_id}/submit"',
                      '"/handovers/{handover_id}/accept"',
                      '"/handovers/{handover_id}/reject"',
                      '"/handovers/{handover_id}/actions"',
                      '"/handovers/metrics"'):
            assert route in src, route

    def test_creating_a_handover_is_a_mutation(self):
        block = self._api().split('@router.post(\n    "/handovers",')[1][:300]
        assert "require_permission" in block
        assert "alert:read" not in block.split("dependencies")[1][:120]

    def test_the_metrics_route_is_declared_before_the_detail_route(self):
        """Otherwise /handovers/metrics matches {handover_id} and 422s.

        Matched on the decorator, not on any occurrence of the path: the
        comment explaining this very ordering quotes the path too.
        """
        src = self._api()
        metrics = '@router.get(\n    "/handovers/metrics",'
        detail = '@router.get(\n    "/handovers/{handover_id}",'
        assert metrics in src and detail in src
        assert src.index(metrics) < src.index(detail)

    def test_the_page_calls_the_handover_endpoints(self):
        """The page builds URLs from its own API prefix constant, so the
        assertion is on the paths it appends, not the whole URL."""
        tpl = (_SRC / "ion" / "web" / "templates" / "shift_handover.html"
               ).read_text(encoding="utf-8")
        assert "/shift-handover" in tpl           # the API prefix constant
        assert "SH_TRANSFERS" in tpl
        assert "/metrics" in tpl

    def test_the_page_exposes_the_whole_decision_flow(self):
        tpl = (_SRC / "ion" / "web" / "templates" / "shift_handover.html"
               ).read_text(encoding="utf-8")
        for control in ("shRaiseHandover", "shSubmit", "shAccept", "shReject",
                        "shAddAction", "shCompleteAction", "shCancelAction"):
            assert control in tpl, control

    def test_the_page_renders_carry_count_and_overdue(self):
        """The two signals the review asked to be measurable."""
        tpl = (_SRC / "ion" / "web" / "templates" / "shift_handover.html"
               ).read_text(encoding="utf-8")
        assert "carry_count" in tpl
        assert "overdue_action_count" in tpl
        assert "unowned_action_count" in tpl


# ── Timestamps carry their zone ──────────────────────────────────────────
#
# Found by rendering the page: the transfer showed "21:20 - 05:20" beside a
# live shift report showing "22:19 - 06:19" for the same window. An hour
# out, silently.
#
# These columns store naive UTC. A bare "2026-10-07T21:20:00" makes
# `new Date(...)` in the browser read it as *local* time, so a shift
# recorded at 21:20 UTC renders as 21:20 in BST instead of 22:20. It is only
# visible next to a timestamp that was serialised correctly, which is why no
# unit test caught it.


class TestTimestampZones:
    @pytest.mark.parametrize("field", [
        "shift_start", "shift_end", "snapshot_taken_at", "created_at",
    ])
    def test_handover_timestamps_carry_an_offset(self, db, field):
        payload = _draft(db).to_dict()
        assert payload[field], field
        assert payload[field].endswith("+00:00"), (
            f"{field} has no UTC offset, so the browser will read it as "
            f"local time: {payload[field]}"
        )

    def test_submitted_and_accepted_carry_an_offset(self, db):
        h = _accepted(db)
        payload = h.to_dict()
        assert payload["submitted_at"].endswith("+00:00")
        assert payload["accepted_at"].endswith("+00:00")

    def test_an_absent_timestamp_stays_none(self, db):
        """Stamping must not turn a missing value into a fake one."""
        payload = _draft(db).to_dict()
        assert payload["accepted_at"] is None
        assert payload["submitted_at"] is None

    def test_action_timestamps_carry_an_offset(self, db):
        h = _draft(db)
        a = handovers.add_action(
            db, handover_id=h.id, actor_id=1, description="x", owner_id=3,
            due_at=datetime.now(timezone.utc) + timedelta(hours=2))
        handovers.complete_action(db, action_id=a.id, actor_id=3)
        payload = db.get(ShiftHandoverAction, a.id).to_dict()
        assert payload["due_at"].endswith("+00:00")
        assert payload["completed_at"].endswith("+00:00")

    def test_an_already_aware_value_is_not_double_stamped(self, db):
        h = _draft(db)
        h.shift_start = datetime(2026, 10, 7, 21, 20, tzinfo=timezone.utc)
        assert h.to_dict()["shift_start"] == "2026-10-07T21:20:00+00:00"
