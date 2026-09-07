"""Phase 1 — Response Actions: human-in-the-loop, separation of duty, dry-run-first.

Covers the service-layer contract the API rests on:
- every request lands ``pending_approval`` (no auto-execute in v1);
- a high-risk action cannot be approved by its requester (separation of duty);
- with ``ION_RESPONSE_ACTIONS_LIVE`` off (default) approval executes as a
  dry-run — no real adapter dispatch.
"""

from ion.models.sla import PlaybookAction
from ion.models.user import User
from ion.services import playbook_action_service as actions


def _user(session, uid, name):
    u = User(id=uid, username=name, email=f"{name}@x", password_hash="x",
             display_name=name, is_active=True)
    session.add(u)
    session.flush()
    return u


def _action(session, action_type):
    actions.seed_default_actions(session)
    return session.query(PlaybookAction).filter_by(action_type=action_type).first()


def test_request_always_pending_even_for_low_risk(session):
    _user(session, 1, "req")
    a = _action(session, "block_ip")            # catalogue default: requires_approval=False
    assert a.requires_approval is False
    res = actions.request_action(session, action_id=a.id, executed_by_id=1, target="1.2.3.4")
    assert res["status"] == "pending_approval"  # v1: no auto-execute path


def test_separation_of_duty_blocks_self_approval(session):
    _user(session, 1, "req")
    a = _action(session, "disable_account")     # high-risk: requires_approval=True
    req = actions.request_action(session, action_id=a.id, executed_by_id=1, target="svc-x")
    res = actions.approve_action(session, log_id=req["id"], approved_by_id=1)
    assert res["status"] == "error"
    assert "Separation of duty" in res["error"]


def test_different_approver_executes_dry_run(session):
    _user(session, 1, "req")
    _user(session, 2, "lead")
    a = _action(session, "disable_account")
    req = actions.request_action(session, action_id=a.id, executed_by_id=1, target="svc-x")
    res = actions.approve_action(session, log_id=req["id"], approved_by_id=2)
    # live off by default → executed as a dry-run, never a real adapter call
    assert res["status"] == "completed"
    assert res.get("result", {}).get("dry_run") is True


def test_low_risk_may_be_approved_by_requester(session):
    # Separation of duty only gates high-risk (requires_approval) actions.
    _user(session, 1, "req")
    a = _action(session, "block_ip")
    req = actions.request_action(session, action_id=a.id, executed_by_id=1, target="1.2.3.4")
    res = actions.approve_action(session, log_id=req["id"], approved_by_id=1)
    assert res["status"] == "completed"
    assert res.get("result", {}).get("dry_run") is True
