"""Durable sync status and retry (8 Oct 2026 review, stage 3).

Review §2: *"Put failed sync and pending approval beside the affected
action."* Stage 3's exit condition: *"alert → investigation → response →
handover leaves durable records and **recoverable failures**."*

Every outbound sync in ION was fire-and-forget::

    try:
        service.add_comment(kibana_case_id, comment_text)
    except Exception as e:
        logger.warning("Failed to sync note to Kibana: %s", e)

Three consequences, all of them the same consequence:

* The failure existed only in a log line, so the case page showed a note
  that ION believed was mirrored to Kibana and was not.
* Nothing could retry it, because nothing recorded what to retry with.
* Nobody could see how much had silently drifted.

The journal is one durable row per logical sync, keyed by a dedupe key so a
repeat of the same sync reuses its row instead of piling up. It records what
was attempted, what came back, how many times, and when the next attempt is
due.

Two distinctions the tests insist on:

* ``abandoned`` is not ``failed``. After the retry budget is spent ION has
  stopped trying, and the row says so, rather than sitting at ``failed`` with
  a ``next_retry_at`` that will never be honoured. A queue that looks like it
  is still working is worse than one that admits it gave up.
* A **skip** is not a success. When Kibana is not configured there is nothing
  to sync and nothing failed, so the journal records neither — claiming
  success would assert a mirror that does not exist.
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
from ion.models.integration_sync import SyncAttempt, SyncStatus
from ion.models.user import User
from ion.services import integration_sync_journal_service as journal
from ion.services.integration_sync_journal_service import SyncJournalError
from ion.storage.database import _run_migrations


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'sync_journal.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    s.add(User(id=1, username="alice", email="a@x", password_hash="x",
               display_name="Alice", is_active=True))
    s.add(AlertCase(id=1, case_number="CASE-0001", title="Linked case",
                    severity="high", created_by_id=1, kibana_case_id="kb-1"))
    s.commit()
    yield s
    s.close()


def _record(db, **over):
    kwargs = dict(
        target="kibana",
        operation="note_add",
        entity_type="note",
        entity_id="77",
        case_id=1,
        payload={"kibana_case_id": "kb-1", "username": "alice",
                 "content": "Observed beaconing"},
        dedupe_key="kibana:note_add:77",
    )
    kwargs.update(over)
    return journal.record_attempt(db, **kwargs)


# ── Schema ───────────────────────────────────────────────────────────────


class TestSchema:
    def test_the_table_exists_on_a_fresh_database(self, engine):
        assert inspect(engine).has_table("integration_sync_attempts")

    def test_the_migration_creates_it_on_an_upgrade(self, tmp_path):
        eng = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
        try:
            Base.metadata.create_all(
                eng,
                tables=[t for n, t in Base.metadata.tables.items()
                        if n != "integration_sync_attempts"],
            )
            assert not inspect(eng).has_table("integration_sync_attempts")
            _run_migrations(eng)
            assert inspect(eng).has_table("integration_sync_attempts")
        finally:
            eng.dispose()


# ── Recording ────────────────────────────────────────────────────────────


class TestRecording:
    def test_a_recorded_attempt_starts_pending(self, db):
        attempt = _record(db)
        assert attempt.status == SyncStatus.PENDING.value
        assert attempt.attempt_count == 0

    def test_the_attempt_keeps_what_it_needs_to_retry_with(self, db):
        attempt = _record(db)
        assert attempt.payload["kibana_case_id"] == "kb-1"
        assert attempt.payload["content"] == "Observed beaconing"

    def test_the_attempt_names_the_target_and_operation(self, db):
        attempt = _record(db)
        assert attempt.target == "kibana"
        assert attempt.operation == "note_add"

    def test_the_attempt_is_linked_to_the_case(self, db):
        """So the failure can be shown beside the affected case."""
        assert _record(db).case_id == 1

    def test_the_same_dedupe_key_reuses_the_row(self, db):
        first = _record(db)
        second = _record(db)
        assert second.id == first.id
        assert db.query(SyncAttempt).count() == 1

    def test_a_different_dedupe_key_is_a_different_row(self, db):
        _record(db, dedupe_key="kibana:note_add:77")
        _record(db, dedupe_key="kibana:note_add:78", entity_id="78")
        assert db.query(SyncAttempt).count() == 2

    def test_re_recording_refreshes_the_payload(self, db):
        """The newest intent is what a retry should send."""
        _record(db)
        _record(db, payload={"kibana_case_id": "kb-1", "username": "alice",
                             "content": "Corrected text"})
        attempt = db.query(SyncAttempt).one()
        assert attempt.payload["content"] == "Corrected text"

    def test_an_unknown_target_is_refused(self, db):
        with pytest.raises(SyncJournalError):
            _record(db, target="myspace")

    def test_an_unknown_operation_is_refused(self, db):
        with pytest.raises(SyncJournalError):
            _record(db, operation="teleport")

    def test_a_dedupe_key_is_required(self, db):
        with pytest.raises(SyncJournalError):
            _record(db, dedupe_key="  ")


# ── Outcomes ─────────────────────────────────────────────────────────────


class TestOutcomes:
    def test_success_resolves_the_attempt(self, db):
        attempt = _record(db)
        journal.mark_succeeded(db, attempt_id=attempt.id)
        attempt = db.get(SyncAttempt, attempt.id)
        assert attempt.status == SyncStatus.SUCCEEDED.value
        assert attempt.resolved_at is not None
        assert attempt.next_retry_at is None

    def test_success_counts_the_attempt(self, db):
        attempt = _record(db)
        journal.mark_succeeded(db, attempt_id=attempt.id)
        assert db.get(SyncAttempt, attempt.id).attempt_count == 1

    def test_success_clears_a_previous_error(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="502 bad gateway")
        journal.mark_succeeded(db, attempt_id=attempt.id)
        assert db.get(SyncAttempt, attempt.id).last_error is None

    def test_failure_records_the_error_and_schedules_a_retry(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="502 bad gateway")
        attempt = db.get(SyncAttempt, attempt.id)
        assert attempt.status == SyncStatus.FAILED.value
        assert "502" in attempt.last_error
        assert attempt.next_retry_at is not None
        assert attempt.attempt_count == 1

    def test_the_backoff_grows(self, db):
        attempt = _record(db)
        gaps = []
        for _ in range(3):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
            row = db.get(SyncAttempt, attempt.id)
            last = row.last_attempt_at.replace(tzinfo=timezone.utc)
            nxt = row.next_retry_at.replace(tzinfo=timezone.utc)
            gaps.append((nxt - last).total_seconds())
        assert gaps[0] < gaps[1] < gaps[2]

    def test_the_backoff_is_capped(self, db):
        attempt = _record(db)
        for _ in range(journal.MAX_ATTEMPTS - 1):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        row = db.get(SyncAttempt, attempt.id)
        last = row.last_attempt_at.replace(tzinfo=timezone.utc)
        nxt = row.next_retry_at.replace(tzinfo=timezone.utc)
        assert (nxt - last).total_seconds() <= journal.MAX_BACKOFF_SECONDS

    def test_the_retry_budget_ends_in_abandoned_not_failed(self, db):
        """A queue that looks like it is still working is worse than one
        that admits it gave up."""
        attempt = _record(db)
        for _ in range(journal.MAX_ATTEMPTS):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        attempt = db.get(SyncAttempt, attempt.id)
        assert attempt.status == SyncStatus.ABANDONED.value
        assert attempt.next_retry_at is None
        assert attempt.attempt_count == journal.MAX_ATTEMPTS

    def test_an_abandoned_attempt_is_not_retried(self, db):
        attempt = _record(db)
        for _ in range(journal.MAX_ATTEMPTS):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        assert journal.due_for_retry(db) == []

    def test_an_abandoned_attempt_can_be_revived_by_a_human(self, db):
        """Someone who has fixed the integration should not have to wait."""
        attempt = _record(db)
        for _ in range(journal.MAX_ATTEMPTS):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        journal.requeue(db, attempt_id=attempt.id, actor_id=1)
        attempt = db.get(SyncAttempt, attempt.id)
        assert attempt.status == SyncStatus.PENDING.value
        assert attempt.attempt_count == 0

    def test_marking_a_missing_attempt_is_an_error(self, db):
        with pytest.raises(SyncJournalError):
            journal.mark_succeeded(db, attempt_id=9999)

    def test_an_error_message_is_truncated_not_dropped(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="x" * 5000)
        stored = db.get(SyncAttempt, attempt.id).last_error
        assert stored.startswith("x")
        assert len(stored) <= journal.MAX_ERROR_CHARS


# ── Due for retry ────────────────────────────────────────────────────────


class TestDueForRetry:
    def test_a_pending_attempt_is_due_immediately(self, db):
        attempt = _record(db)
        assert [a.id for a in journal.due_for_retry(db)] == [attempt.id]

    def test_a_failed_attempt_is_not_due_before_its_backoff(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        assert journal.due_for_retry(db) == []

    def test_a_failed_attempt_is_due_after_its_backoff(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        later = datetime.now(timezone.utc) + timedelta(days=1)
        assert [a.id for a in journal.due_for_retry(db, now=later)] == [attempt.id]

    def test_a_succeeded_attempt_is_never_due(self, db):
        attempt = _record(db)
        journal.mark_succeeded(db, attempt_id=attempt.id)
        later = datetime.now(timezone.utc) + timedelta(days=30)
        assert journal.due_for_retry(db, now=later) == []

    def test_the_oldest_is_returned_first(self, db):
        a = _record(db, dedupe_key="k1", entity_id="1")
        b = _record(db, dedupe_key="k2", entity_id="2")
        assert [x.id for x in journal.due_for_retry(db)] == [a.id, b.id]

    def test_the_limit_is_honoured(self, db):
        for i in range(5):
            _record(db, dedupe_key=f"k{i}", entity_id=str(i))
        assert len(journal.due_for_retry(db, limit=2)) == 2


# ── Driving a retry ──────────────────────────────────────────────────────


class TestRetryDispatch:
    def test_a_successful_retry_resolves_the_row(self, db, monkeypatch):
        attempt = _record(db)
        calls = []
        monkeypatch.setitem(journal.RETRY_HANDLERS, ("kibana", "note_add"),
                            lambda payload: calls.append(payload) or True)
        result = journal.retry_attempt(db, attempt_id=attempt.id)
        assert result["outcome"] == "succeeded"
        assert len(calls) == 1
        assert db.get(SyncAttempt, attempt.id).status == SyncStatus.SUCCEEDED.value

    def test_a_handler_returning_false_is_a_failure_not_a_success(self, db, monkeypatch):
        attempt = _record(db)
        monkeypatch.setitem(journal.RETRY_HANDLERS, ("kibana", "note_add"),
                            lambda payload: False)
        result = journal.retry_attempt(db, attempt_id=attempt.id)
        assert result["outcome"] == "failed"
        assert db.get(SyncAttempt, attempt.id).status == SyncStatus.FAILED.value

    def test_a_raising_handler_records_the_error(self, db, monkeypatch):
        attempt = _record(db)

        def _boom(payload):
            raise RuntimeError("connection refused")

        monkeypatch.setitem(journal.RETRY_HANDLERS, ("kibana", "note_add"), _boom)
        result = journal.retry_attempt(db, attempt_id=attempt.id)
        assert result["outcome"] == "failed"
        assert db.get(SyncAttempt, attempt.id).last_error

    def test_a_missing_handler_abandons_rather_than_looping(self, db, monkeypatch):
        """Retrying something with no way to perform it would spin forever."""
        attempt = _record(db)
        monkeypatch.delitem(journal.RETRY_HANDLERS, ("kibana", "note_add"),
                            raising=False)
        result = journal.retry_attempt(db, attempt_id=attempt.id)
        assert result["outcome"] == "abandoned"
        assert db.get(SyncAttempt, attempt.id).status == SyncStatus.ABANDONED.value

    def test_draining_processes_every_due_attempt(self, db, monkeypatch):
        for i in range(3):
            _record(db, dedupe_key=f"k{i}", entity_id=str(i))
        monkeypatch.setitem(journal.RETRY_HANDLERS, ("kibana", "note_add"),
                            lambda payload: True)
        summary = journal.drain_retries(db)
        assert summary["attempted"] == 3
        assert summary["succeeded"] == 3

    def test_draining_reports_mixed_outcomes(self, db, monkeypatch):
        _record(db, dedupe_key="good", entity_id="1",
                payload={"kibana_case_id": "kb-1", "content": "good"})
        _record(db, dedupe_key="bad", entity_id="2",
                payload={"kibana_case_id": "kb-1", "content": "bad"})
        monkeypatch.setitem(
            journal.RETRY_HANDLERS, ("kibana", "note_add"),
            lambda payload: payload.get("content") == "good",
        )
        summary = journal.drain_retries(db)
        assert summary["attempted"] == 2
        assert summary["succeeded"] == 1
        assert summary["failed"] == 1

    def test_draining_an_empty_journal_is_not_an_error(self, db):
        assert journal.drain_retries(db)["attempted"] == 0


# ── What the case page shows ─────────────────────────────────────────────


class TestCaseSyncStatus:
    def test_a_clean_case_reports_no_problems(self, db):
        status = journal.case_sync_status(db, case_id=1)
        assert status["has_problems"] is False
        assert status["unresolved"] == []

    def test_a_failure_shows_up_against_the_case(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="502 bad gateway")
        status = journal.case_sync_status(db, case_id=1)
        assert status["has_problems"] is True
        assert status["unresolved"][0]["operation"] == "note_add"
        assert "502" in status["unresolved"][0]["last_error"]

    def test_a_resolved_failure_stops_showing(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="502")
        journal.mark_succeeded(db, attempt_id=attempt.id)
        assert journal.case_sync_status(db, case_id=1)["has_problems"] is False

    def test_an_abandoned_sync_is_called_out_separately(self, db):
        """Still waiting and given up on are different things to an analyst."""
        attempt = _record(db)
        for _ in range(journal.MAX_ATTEMPTS):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        status = journal.case_sync_status(db, case_id=1)
        assert status["abandoned_count"] == 1
        assert status["retrying_count"] == 0

    def test_each_unresolved_entry_says_what_it_will_do_next(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        entry = journal.case_sync_status(db, case_id=1)["unresolved"][0]
        assert entry["next_retry_at"]
        assert entry["attempts_remaining"] == journal.MAX_ATTEMPTS - 1

    def test_an_abandoned_entry_has_no_attempts_remaining(self, db):
        attempt = _record(db)
        for _ in range(journal.MAX_ATTEMPTS):
            journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        entry = journal.case_sync_status(db, case_id=1)["unresolved"][0]
        assert entry["attempts_remaining"] == 0
        assert entry["next_retry_at"] is None

    def test_another_case_is_unaffected(self, db):
        db.add(AlertCase(id=2, case_number="CASE-0002", title="Other",
                         created_by_id=1))
        db.commit()
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        assert journal.case_sync_status(db, case_id=2)["has_problems"] is False


# ── The estate-wide view ─────────────────────────────────────────────────


class TestSummary:
    def test_an_empty_journal_summarises_cleanly(self, db):
        summary = journal.journal_summary(db)
        assert summary["unresolved_count"] == 0
        assert summary["by_target"] == {}

    def test_counts_are_broken_down_by_status(self, db):
        ok = _record(db, dedupe_key="ok", entity_id="1")
        journal.mark_succeeded(db, attempt_id=ok.id)
        bad = _record(db, dedupe_key="bad", entity_id="2")
        journal.mark_failed(db, attempt_id=bad.id, error="boom")
        gone = _record(db, dedupe_key="gone", entity_id="3")
        for _ in range(journal.MAX_ATTEMPTS):
            journal.mark_failed(db, attempt_id=gone.id, error="boom")

        summary = journal.journal_summary(db)
        assert summary["by_status"][SyncStatus.SUCCEEDED.value] == 1
        assert summary["by_status"][SyncStatus.FAILED.value] == 1
        assert summary["by_status"][SyncStatus.ABANDONED.value] == 1
        assert summary["unresolved_count"] == 2

    def test_counts_are_broken_down_by_target(self, db):
        _record(db, dedupe_key="a", entity_id="1")
        _record(db, target="dfir_iris", operation="case_create",
                entity_type="alert_case", entity_id="1", dedupe_key="b")
        summary = journal.journal_summary(db)
        assert summary["by_target"]["kibana"] == 1
        assert summary["by_target"]["dfir_iris"] == 1

    def test_the_oldest_unresolved_age_is_reported(self, db):
        attempt = _record(db)
        journal.mark_failed(db, attempt_id=attempt.id, error="boom")
        summary = journal.journal_summary(db)
        assert summary["oldest_unresolved_hours"] is not None
        assert summary["oldest_unresolved_hours"] >= 0

    def test_a_clean_journal_has_no_oldest_age(self, db):
        """Zero would read as "something is an hour old"."""
        assert journal.journal_summary(db)["oldest_unresolved_hours"] is None


# ── Wrapping the real sync helpers ───────────────────────────────────────


class TestHelperIntegration:
    def test_a_failed_note_sync_lands_in_the_journal(self, db, monkeypatch):
        """The central requirement: the failure stops being only a log line."""
        from ion.services import kibana_sync_helpers as helpers

        class _Broken:
            enabled = True

            def add_comment(self, *a, **k):
                raise RuntimeError("kibana is down")

        monkeypatch.setattr(helpers, "get_kibana_cases_service", lambda: _Broken())
        helpers.sync_note_to_kibana("kb-1", "alice", "Observed beaconing",
                                    session=db, case_id=1, note_id=77)

        rows = db.query(SyncAttempt).all()
        assert len(rows) == 1
        assert rows[0].status == SyncStatus.FAILED.value
        assert rows[0].case_id == 1

    def test_a_successful_note_sync_is_recorded_as_resolved(self, db, monkeypatch):
        from ion.services import kibana_sync_helpers as helpers

        class _Working:
            enabled = True

            def add_comment(self, *a, **k):
                return {"id": "c-1"}

        monkeypatch.setattr(helpers, "get_kibana_cases_service", lambda: _Working())
        helpers.sync_note_to_kibana("kb-1", "alice", "ok",
                                    session=db, case_id=1, note_id=77)
        rows = db.query(SyncAttempt).all()
        assert len(rows) == 1
        assert rows[0].status == SyncStatus.SUCCEEDED.value

    def test_a_disabled_integration_records_nothing(self, db, monkeypatch):
        """Nothing was attempted and nothing failed. Writing a success row
        would assert a mirror that does not exist."""
        from ion.services import kibana_sync_helpers as helpers

        class _Off:
            enabled = False

            def add_comment(self, *a, **k):  # pragma: no cover
                raise AssertionError("must not be called")

        monkeypatch.setattr(helpers, "get_kibana_cases_service", lambda: _Off())
        helpers.sync_note_to_kibana("kb-1", "alice", "ok",
                                    session=db, case_id=1, note_id=77)
        assert db.query(SyncAttempt).count() == 0

    def test_a_sync_without_a_session_still_does_not_raise(self, db, monkeypatch):
        """Call sites that have no session must keep working unchanged."""
        from ion.services import kibana_sync_helpers as helpers

        class _Broken:
            enabled = True

            def add_comment(self, *a, **k):
                raise RuntimeError("kibana is down")

        monkeypatch.setattr(helpers, "get_kibana_cases_service", lambda: _Broken())
        helpers.sync_note_to_kibana("kb-1", "alice", "no session here")
        assert db.query(SyncAttempt).count() == 0

    def test_journalling_failure_does_not_break_the_caller(self, db, monkeypatch):
        """The journal is diagnostics. It must never be the thing that
        turns a Kibana outage into a failed ION request."""
        from ion.services import kibana_sync_helpers as helpers

        class _Broken:
            enabled = True

            def add_comment(self, *a, **k):
                raise RuntimeError("kibana is down")

        monkeypatch.setattr(helpers, "get_kibana_cases_service", lambda: _Broken())
        monkeypatch.setattr(
            journal, "record_attempt",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("journal broken")))
        helpers.sync_note_to_kibana("kb-1", "alice", "x",
                                    session=db, case_id=1, note_id=77)


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    def test_a_scheduler_handler_drains_the_journal(self):
        from ion.services import scheduler_service

        assert "sync_retry" in scheduler_service.list_handlers()

    def test_the_handler_is_described_for_the_form(self):
        from ion.services import scheduler_service

        # describe_handlers() returns a list of metadata dicts, one per key.
        meta = {h["key"]: h for h in scheduler_service.describe_handlers()}
        assert meta["sync_retry"]["label"]
        assert meta["sync_retry"]["description"]
        assert meta["sync_retry"]["parameters"], "the limit must be settable"

    def test_the_api_exposes_the_journal(self):
        src = (_SRC / "ion" / "web" / "integration_api.py").read_text(encoding="utf-8")
        assert "sync-journal" in src

    def test_requeue_is_a_mutation(self):
        src = (_SRC / "ion" / "web" / "integration_api.py").read_text(encoding="utf-8")
        block = src.split("sync-journal/{attempt_id}/requeue")[1][:400]
        assert 'require_permission("integration:manage")' in block
