"""Response-action decision atomicity and dry-run honesty.

From the 8 Oct 2026 feature review, findings 3 (P1) and 6 (P2).

**Finding 3.** Both decision transitions were read-then-write:

    if log_entry.status != "pending_approval": return error
    log_entry.status = "approved"; session.commit()

and execution likewise checked ``status`` before writing ``executing``.
Nothing was conditional on the state still being what was read, so two
approvals could both pass the check, and a delayed approval could
overwrite a state another request had already advanced — dispatching the
containment action a second time. Approve and reject could race the same
way, leaving the losing decision silently discarded.

The tests below do not rely on thread timing. They hold two sessions
open on the same database, let both observe ``pending_approval``, and
then require that only the first claim wins — which is exactly the
interleaving a conditional ``UPDATE ... WHERE status = :expected`` makes
impossible and a read-then-write makes inevitable.

**Finding 6.** A successful dry run is stored with status ``completed``,
and the case-note writer printed that status while ignoring the nested
``result.dry_run`` flag. The case journal (and its Kibana mirror) therefore
claimed a response action completed when nothing had been done. A note
saying an account was disabled, when it was not, is worse than no note.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.sla import PlaybookAction, PlaybookActionLog
from ion.models.user import User
from ion.services import playbook_action_service as actions


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(
        f"sqlite:///{tmp_path / 'review_atomicity.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def sf(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def db(sf):
    s = sf()
    yield s
    s.close()


def _user(session, uid, name):
    u = User(id=uid, username=name, email=f"{name}@x", password_hash="x",
             display_name=name, is_active=True)
    session.add(u)
    session.flush()
    return u


def _pending(session, action_type="disable_account", target="svc-x"):
    actions.seed_default_actions(session)
    a = session.query(PlaybookAction).filter_by(action_type=action_type).first()
    req = actions.request_action(
        session, action_id=a.id, executed_by_id=1, target=target
    )
    session.commit()
    return req["id"]


# ── The claim primitive ───────────────────────────────────────────────────


class TestClaimTransition:
    def test_claim_succeeds_once(self, db):
        _user(db, 1, "req")
        log_id = _pending(db)
        assert actions._claim_status_transition(
            db, log_id, expected="pending_approval", new="approved"
        ) is True

    def test_second_claim_of_the_same_transition_fails(self, db):
        _user(db, 1, "req")
        log_id = _pending(db)
        actions._claim_status_transition(
            db, log_id, expected="pending_approval", new="approved"
        )
        assert actions._claim_status_transition(
            db, log_id, expected="pending_approval", new="approved"
        ) is False

    def test_claim_loses_against_a_concurrent_winner(self, sf, db):
        """The interleaving that broke the old code.

        Both sessions read ``pending_approval`` before either writes. The
        read-then-write version let both proceed; a conditional update
        lets exactly one.
        """
        _user(db, 1, "req")
        log_id = _pending(db)

        s_a, s_b = sf(), sf()
        try:
            # Both observe the pending state first — no writes yet.
            assert s_a.get(PlaybookActionLog, log_id).status == "pending_approval"
            assert s_b.get(PlaybookActionLog, log_id).status == "pending_approval"

            won_a = actions._claim_status_transition(
                s_a, log_id, expected="pending_approval", new="approved"
            )
            won_b = actions._claim_status_transition(
                s_b, log_id, expected="pending_approval", new="rejected"
            )
            assert [won_a, won_b] == [True, False]

            s_b.expire_all()
            assert s_b.get(PlaybookActionLog, log_id).status == "approved"
        finally:
            s_a.close()
            s_b.close()


# ── Approve / reject / execute decisions ──────────────────────────────────


class TestOneWinningDecision:
    def test_double_approve_dispatches_once(self, db, monkeypatch):
        _user(db, 1, "req")
        _user(db, 2, "lead")
        log_id = _pending(db)

        calls: list[str] = []
        _orig = actions.execute_action

        def _counting_execute(session, lid):
            calls.append("dispatch")
            return _orig(session, lid)

        monkeypatch.setattr(actions, "execute_action", _counting_execute)

        first = actions.approve_action(db, log_id=log_id, approved_by_id=2)
        second = actions.approve_action(db, log_id=log_id, approved_by_id=2)

        assert first.get("status") != "error", first
        assert second.get("status") == "error", second
        assert len(calls) == 1, f"adapter dispatched {len(calls)} times"

    def test_reject_after_approve_is_refused(self, db):
        _user(db, 1, "req")
        _user(db, 2, "lead")
        log_id = _pending(db)

        actions.approve_action(db, log_id=log_id, approved_by_id=2)
        rejected = actions.reject_action(db, log_id=log_id, approved_by_id=2)

        assert rejected.get("status") == "error"
        db.expire_all()
        assert db.get(PlaybookActionLog, log_id).status != "rejected"

    def test_approve_after_reject_is_refused(self, db):
        _user(db, 1, "req")
        _user(db, 2, "lead")
        log_id = _pending(db)

        actions.reject_action(db, log_id=log_id, approved_by_id=2)
        approved = actions.approve_action(db, log_id=log_id, approved_by_id=2)

        assert approved.get("status") == "error"
        db.expire_all()
        assert db.get(PlaybookActionLog, log_id).status == "rejected"

    def test_execute_cannot_be_claimed_twice(self, db):
        _user(db, 1, "req")
        _user(db, 2, "lead")
        log_id = _pending(db)

        # Approve without executing, so the row sits at `approved`.
        actions._claim_status_transition(
            db, log_id, expected="pending_approval", new="approved"
        )
        first = actions.execute_action(db, log_id)
        second = actions.execute_action(db, log_id)

        assert first.get("status") != "error", first
        assert second.get("status") == "error", second

    def test_separation_of_duty_leaves_the_row_pending(self, db):
        """A refused self-approval must not consume the decision."""
        _user(db, 1, "req")
        log_id = _pending(db)

        res = actions.approve_action(db, log_id=log_id, approved_by_id=1)
        assert res.get("status") == "error"
        assert "Separation of duty" in res["error"]

        db.expire_all()
        assert db.get(PlaybookActionLog, log_id).status == "pending_approval"


class TestIdempotencyKey:
    def test_each_request_gets_a_stable_idempotency_key(self, db):
        _user(db, 1, "req")
        log_id = _pending(db)

        key_one = actions.dispatch_idempotency_key(db, log_id)
        key_two = actions.dispatch_idempotency_key(db, log_id)

        assert key_one
        assert key_one == key_two, "the key must be stable across reads"

    def test_keys_differ_between_requests(self, db):
        _user(db, 1, "req")
        a = _pending(db, target="svc-a")
        b = _pending(db, target="svc-b")
        assert actions.dispatch_idempotency_key(db, a) != \
            actions.dispatch_idempotency_key(db, b)


# ── Finding 6: a dry run must not read as containment ─────────────────────


class TestDryRunNoteHonesty:
    def _note_for(self, result: dict) -> str:
        return actions.format_action_note(result, username="lead")

    def test_dry_run_note_says_so(self):
        note = self._note_for({
            "action_type": "disable_account",
            "target": "svc-x",
            "status": "completed",
            "id": 7,
            "result": {"dry_run": True, "adapter": "active_directory_ldap",
                       "message": "DRY_RUN — would disable AD account svc-x"},
        })
        assert "DRY RUN" in note.upper()
        assert "no action performed" in note.lower()

    def test_dry_run_note_cannot_claim_completion(self):
        note = self._note_for({
            "action_type": "disable_account",
            "target": "svc-x",
            "status": "completed",
            "id": 7,
            "result": {"dry_run": True, "adapter": "active_directory_ldap"},
        })
        # The exact failure mode from the review: a simulated disable
        # producing a note that reads like a real one.
        assert "completed" not in note.lower(), note

    def test_live_note_records_execution_id_and_adapter(self):
        note = self._note_for({
            "action_type": "disable_account",
            "target": "svc-x",
            "status": "completed",
            "id": 42,
            "result": {"dry_run": False, "adapter": "active_directory_ldap",
                       "message": "Disabled AD account svc-x"},
        })
        assert "42" in note
        assert "active_directory_ldap" in note
        assert "dry run" not in note.lower()

    def test_failed_note_is_not_reported_as_success(self):
        note = self._note_for({
            "action_type": "block_ip",
            "target": "1.2.3.4",
            "status": "failed",
            "id": 9,
            "result": {"dry_run": False, "adapter": "firewall_rest"},
            "error": "upstream 503",
        })
        assert "failed" in note.lower()

    def test_approval_through_the_service_stores_the_dry_run_flag(self, db):
        """End-to-end: live off, so the stored result must say dry_run."""
        _user(db, 1, "req")
        _user(db, 2, "lead")
        log_id = _pending(db)

        res = actions.approve_action(db, log_id=log_id, approved_by_id=2)
        assert res["status"] == "completed"
        assert res["result"]["dry_run"] is True

        stored = json.loads(db.get(PlaybookActionLog, log_id).result)
        assert stored["dry_run"] is True

        # And the note built from that result must not imply containment.
        note = actions.format_action_note(res, username="lead")
        assert "DRY RUN" in note.upper()
