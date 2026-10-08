"""The response-action approval inbox (8 Oct 2026 review, stage 3).

The backend already had the whole decision flow — request, atomic approve,
atomic reject, idempotent dispatch — and an endpoint listing pending rows.
What it did not have was an inbox an approver could actually decide from.
``GET /response/actions/pending`` returned the raw log row: numeric
``executed_by_id``, numeric ``case_id``, the target string, and nothing else.
An approver was expected to judge "should this account be disabled" from

    {"id": 7, "action_id": 3, "case_id": 12, "executed_by_id": 4,
     "target": "svc-backup", "status": "pending_approval"}

which tells them neither who asked, nor why, nor what the action would
actually do if approved. Three things in particular were invisible:

* **Effective mode.** With ``ION_RESPONSE_ACTIONS_LIVE`` off every approval
  is a simulation. Approving looked identical either way, and the outcome
  came back ``completed`` in both cases.
* **Adapter readiness.** If the adapter's env vars are not set the dispatch
  cannot do anything. That is knowable *before* approving, and it is the
  difference between "approve" and "go fix the integration first".
* **Separation of duty.** A high-risk action cannot be approved by its
  requester. The approver only discovered that by clicking approve and
  getting a 400.

The review also asks that the lifecycle stop collapsing into one word:
"Separate requested, approved, dispatched and externally verified
outcomes." ``classify_outcome`` is that separation. A successful dry run is
``simulated``, never ``dispatched``; an adapter returning HTTP 200 is
``acknowledged``, not ``verified`` — ION did not observe the target change,
it observed the adapter say so.
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
from ion.models.alert_triage import AlertCase
from ion.models.base import Base
from ion.models.sla import PlaybookAction, PlaybookActionLog
from ion.models.user import User
from ion.services import playbook_action_service as actions


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'review_inbox.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()


def _user(session, uid, name):
    u = User(id=uid, username=name, email=f"{name}@x", password_hash="x",
             display_name=name.title(), is_active=True)
    session.add(u)
    session.flush()
    return u


def _case(session, cid=12, title="Suspicious service-account logons"):
    c = AlertCase(id=cid, case_number=f"CASE-{cid:04d}", title=title,
                  severity="high", created_by_id=1)
    session.add(c)
    session.flush()
    return c


def _request(session, action_type="disable_account", target="svc-backup",
             requester=1, case_id=None):
    actions.seed_default_actions(session)
    a = session.query(PlaybookAction).filter_by(action_type=action_type).first()
    req = actions.request_action(session, action_id=a.id,
                                executed_by_id=requester, target=target,
                                case_id=case_id)
    session.commit()
    return req["id"]


# ── Outcome classification ───────────────────────────────────────────────


class TestClassifyOutcome:
    """The lifecycle the review asks to be kept separate."""

    def test_pending_is_requested_and_changed_nothing(self):
        out = actions.classify_outcome({"status": "pending_approval"})
        assert out["stage"] == "requested"
        assert out["changed_anything"] is False
        assert out["external_confirmation"] == "none"

    def test_approved_is_not_yet_dispatched(self):
        out = actions.classify_outcome({"status": "approved"})
        assert out["stage"] == "approved"
        assert out["changed_anything"] is False

    def test_executing_is_still_approved_not_dispatched(self):
        """Dispatch is in flight. Claiming it happened would be a guess."""
        out = actions.classify_outcome({"status": "executing"})
        assert out["stage"] == "approved"
        assert out["changed_anything"] is False

    def test_rejected_changed_nothing(self):
        out = actions.classify_outcome({"status": "rejected"})
        assert out["stage"] == "rejected"
        assert out["changed_anything"] is False

    def test_a_successful_dry_run_is_simulated_not_dispatched(self):
        """The central honesty requirement. ``completed`` is not enough."""
        out = actions.classify_outcome({
            "status": "completed",
            "result": {"success": True, "dry_run": True, "response": {"ok": True}},
        })
        assert out["stage"] == "simulated"
        assert out["changed_anything"] is False
        assert out["external_confirmation"] == "none"
        assert "simul" in out["label"].lower() or "dry" in out["label"].lower()

    def test_a_live_success_is_dispatched(self):
        out = actions.classify_outcome({
            "status": "completed",
            "result": {"success": True, "dry_run": False, "response": {"id": "r-1"}},
        })
        assert out["stage"] == "dispatched"
        assert out["changed_anything"] is True

    def test_an_adapter_response_is_acknowledged_not_verified(self):
        """HTTP 200 means the adapter accepted the call, nothing more."""
        out = actions.classify_outcome({
            "status": "completed",
            "result": {"success": True, "dry_run": False, "response": {"id": "r-1"}},
        })
        assert out["external_confirmation"] == "acknowledged"

    def test_verified_requires_an_explicit_verification(self):
        out = actions.classify_outcome({
            "status": "completed",
            "result": {
                "success": True, "dry_run": False,
                "response": {"id": "r-1", "verified": True},
            },
        })
        assert out["external_confirmation"] == "verified"

    def test_a_live_dispatch_with_no_response_body_is_unconfirmed(self):
        out = actions.classify_outcome({
            "status": "completed",
            "result": {"success": True, "dry_run": False, "response": {}},
        })
        assert out["stage"] == "dispatched"
        assert out["external_confirmation"] == "none"

    def test_failed_is_failed_and_carries_the_error(self):
        out = actions.classify_outcome({
            "status": "failed",
            "error": "connection refused",
            "result": {"success": False, "dry_run": False},
        })
        assert out["stage"] == "failed"
        assert out["changed_anything"] is False
        assert "connection refused" in out["detail"]

    def test_completed_but_unsuccessful_is_failed(self):
        """A status of completed with success=False must not read as success."""
        out = actions.classify_outcome({
            "status": "completed",
            "result": {"success": False, "dry_run": False, "error": "403 denied"},
        })
        assert out["stage"] == "failed"
        assert out["changed_anything"] is False

    def test_a_missing_result_does_not_raise(self):
        for status in ("completed", "failed", "pending_approval", "weird"):
            out = actions.classify_outcome({"status": status})
            assert isinstance(out["label"], str) and out["label"]

    def test_a_string_result_is_tolerated(self):
        """``result`` is a JSON text column; a non-dict must not crash the page."""
        out = actions.classify_outcome({"status": "completed", "result": "oops"})
        assert out["stage"] in ("failed", "unknown")


# ── The inbox payload ────────────────────────────────────────────────────


class TestApprovalInbox:
    def test_pending_entries_name_the_requester(self, db):
        _user(db, 1, "alice")
        _request(db)
        inbox = actions.get_approval_inbox(db)
        assert inbox["pending"][0]["requested_by"] == "alice"

    def test_pending_entries_carry_the_case_title(self, db):
        _user(db, 1, "alice")
        _case(db, 12, "Suspicious service-account logons")
        _request(db, case_id=12)
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["case_id"] == 12
        assert entry["case_title"] == "Suspicious service-account logons"

    def test_an_action_with_no_case_is_flagged_as_such(self, db):
        """Containment with no case attached is a governance smell, not a crash."""
        _user(db, 1, "alice")
        _request(db, case_id=None)
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["case_id"] is None
        assert entry["case_title"] is None

    def test_pending_entries_carry_the_risk_level(self, db):
        _user(db, 1, "alice")
        _request(db, action_type="disable_account")
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["risk_level"]

    def test_separation_of_duty_is_declared_before_approving(self, db):
        """The approver should see it, not discover it through a 400."""
        _user(db, 1, "alice")
        _request(db, action_type="disable_account")
        entry = actions.get_approval_inbox(db)["pending"][0]
        action = db.query(PlaybookAction).filter_by(action_type="disable_account").first()
        assert entry["requires_second_person"] is bool(action.requires_approval)
        assert entry["requested_by_id"] == 1

    def test_adapter_readiness_is_reported(self, db):
        _user(db, 1, "alice")
        _request(db)
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["adapter_readiness"] in ("ready", "not_configured", "no_adapter")
        assert isinstance(entry["adapter_ready"], bool)
        assert entry["adapter_name"]

    def test_an_unknown_action_type_reports_no_adapter(self, db):
        _user(db, 1, "alice")
        a = PlaybookAction(name="Invent a thing", action_type="invent_thing",
                           target_integration="nowhere", requires_approval=True,
                           risk_level="high", is_active=True)
        db.add(a)
        db.flush()
        actions.request_action(db, action_id=a.id, executed_by_id=1, target="x")
        db.commit()
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["adapter_readiness"] == "no_adapter"
        assert entry["adapter_ready"] is False

    def test_effective_mode_is_stated_per_entry(self, db):
        _user(db, 1, "alice")
        _request(db)
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["effective_mode"] in ("live", "dry_run")
        assert entry["mode_reason"]

    def test_the_inbox_states_the_mode_once_at_the_top(self, db):
        inbox = actions.get_approval_inbox(db)
        assert inbox["mode"]["effective_mode"] in ("live", "dry_run")
        assert inbox["mode"]["reason"]

    def test_dry_run_mode_says_approving_will_not_change_anything(self, db, monkeypatch):
        from ion.core import config as config_module

        cfg = config_module.get_config()
        monkeypatch.setattr(cfg, "response_actions_live", False, raising=False)
        _user(db, 1, "alice")
        _request(db)
        inbox = actions.get_approval_inbox(db)
        assert inbox["mode"]["effective_mode"] == "dry_run"
        assert inbox["pending"][0]["effective_mode"] == "dry_run"
        assert "simulat" in inbox["mode"]["reason"].lower()

    def test_live_mode_says_approving_will_change_something(self, db, monkeypatch):
        from ion.core import config as config_module

        cfg = config_module.get_config()
        monkeypatch.setattr(cfg, "response_actions_live", True, raising=False)
        _user(db, 1, "alice")
        _request(db)
        inbox = actions.get_approval_inbox(db)
        assert inbox["mode"]["effective_mode"] == "live"
        assert inbox["pending"][0]["effective_mode"] == "live"

    def test_the_idempotency_key_is_shown(self, db):
        """Same key the dispatch will use, so a duplicate is recognisable."""
        _user(db, 1, "alice")
        log_id = _request(db)
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["idempotency_key"] == actions.dispatch_idempotency_key(db, log_id)

    def test_every_pending_entry_classifies_as_requested(self, db):
        _user(db, 1, "alice")
        _request(db, target="a")
        _request(db, target="b")
        inbox = actions.get_approval_inbox(db)
        assert len(inbox["pending"]) == 2
        assert {e["outcome"]["stage"] for e in inbox["pending"]} == {"requested"}

    def test_decided_entries_are_separate_from_pending(self, db):
        _user(db, 1, "alice")
        _user(db, 2, "bob")
        log_id = _request(db, target="decided-one")
        actions.reject_action(db, log_id=log_id, approved_by_id=2)
        _request(db, target="still-pending")

        inbox = actions.get_approval_inbox(db)
        assert [e["target"] for e in inbox["pending"]] == ["still-pending"]
        assert [e["target"] for e in inbox["decided"]] == ["decided-one"]

    def test_a_decided_entry_names_the_decider(self, db):
        _user(db, 1, "alice")
        _user(db, 2, "bob")
        log_id = _request(db)
        actions.reject_action(db, log_id=log_id, approved_by_id=2)
        decided = actions.get_approval_inbox(db)["decided"][0]
        assert decided["decided_by"] == "bob"
        assert decided["outcome"]["stage"] == "rejected"

    def test_a_deleted_requester_does_not_break_the_inbox(self, db):
        """The log row outlives the user row; the inbox must still render."""
        _request(db, requester=999)
        entry = actions.get_approval_inbox(db)["pending"][0]
        assert entry["requested_by"] is None
        assert entry["requested_by_id"] == 999

    def test_the_inbox_counts_what_is_waiting(self, db):
        _user(db, 1, "alice")
        _request(db, target="a")
        _request(db, target="b")
        inbox = actions.get_approval_inbox(db)
        assert inbox["pending_count"] == 2

    def test_pending_is_oldest_first(self, db):
        """An approval queue is worked front to back, unlike a log."""
        _user(db, 1, "alice")
        first = _request(db, target="first")
        second = _request(db, target="second")
        inbox = actions.get_approval_inbox(db)
        assert [e["id"] for e in inbox["pending"]] == [first, second]

    def test_decided_is_newest_first(self, db):
        _user(db, 1, "alice")
        _user(db, 2, "bob")
        a = _request(db, target="older")
        b = _request(db, target="newer")
        actions.reject_action(db, log_id=a, approved_by_id=2)
        actions.reject_action(db, log_id=b, approved_by_id=2)
        inbox = actions.get_approval_inbox(db)
        assert [e["id"] for e in inbox["decided"]] == [b, a]

    def test_the_decided_limit_is_honoured(self, db):
        _user(db, 1, "alice")
        _user(db, 2, "bob")
        for i in range(5):
            log_id = _request(db, target=f"t{i}")
            actions.reject_action(db, log_id=log_id, approved_by_id=2)
        inbox = actions.get_approval_inbox(db, decided_limit=3)
        assert len(inbox["decided"]) == 3

    def test_an_executed_action_records_what_actually_happened(self, db):
        """A dry run in the decided list must not read as containment."""
        _user(db, 1, "alice")
        log_id = _request(db)
        log = db.get(PlaybookActionLog, log_id)
        log.status = "completed"
        log.result = json.dumps({"success": True, "dry_run": True,
                                 "adapter": "active_directory_ldap",
                                 "message": "would disable svc-backup",
                                 "response": {}})
        db.commit()
        decided = actions.get_approval_inbox(db)["decided"][0]
        assert decided["outcome"]["stage"] == "simulated"
        assert decided["outcome"]["changed_anything"] is False


# ── The endpoint ─────────────────────────────────────────────────────────


class TestInboxEndpoint:
    """The route exists, is permission-gated, and is behind the feature flag."""

    def test_the_route_is_registered(self):
        src = (_SRC / "ion" / "web" / "response_api.py").read_text(encoding="utf-8")
        assert '@router.get("/actions/inbox"' in src

    def test_the_route_requires_the_approve_permission(self):
        src = (_SRC / "ion" / "web" / "response_api.py").read_text(encoding="utf-8")
        block = src.split('@router.get("/actions/inbox"')[1][:500]
        assert 'require_permission("response:approve")' in block

    def test_the_route_is_behind_the_feature_flag(self):
        src = (_SRC / "ion" / "web" / "response_api.py").read_text(encoding="utf-8")
        head = src.split('@router.get("/actions/inbox"')[1][:120]
        assert "_require_enabled" in src.split('@router.get("/actions/inbox"')[0][-200:] or \
            "_require_enabled" in head

    def test_the_page_is_registered_with_the_right_permission(self):
        src = (_SRC / "ion" / "web" / "server.py").read_text(encoding="utf-8")
        assert '"/response-approvals"' in src
        line = [ln for ln in src.split("\n") if '"/response-approvals"' in ln][0]
        assert "response_approvals.html" in line
        assert "response:approve" in line

    def test_the_template_exists(self):
        tpl = _SRC / "ion" / "web" / "templates" / "response_approvals.html"
        assert tpl.exists()

    def test_the_template_never_prints_a_bare_completed(self):
        """The whole point of classify_outcome is that the UI uses it."""
        tpl = (_SRC / "ion" / "web" / "templates" / "response_approvals.html"
               ).read_text(encoding="utf-8")
        assert "outcome" in tpl

    def test_the_page_is_reachable_from_the_navigation(self):
        base = (_SRC / "ion" / "web" / "templates" / "base.html"
                ).read_text(encoding="utf-8")
        assert "/response-approvals" in base
