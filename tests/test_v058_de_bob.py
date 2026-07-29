"""v0.58.0 — Detection Engineering module, Phase 3 (Bob improvement loop).

Pins the governance guarantees (roadmap §3 — "applied only after human approval,
versioned, and reversible; no silent online learning"):
- feedback grouping counts ONLY scored disagreements (agreement False, not abstentions),
- scorecard agreement rate + drift direction,
- draft_from_feedback is deterministic (no LLM): proposed = current + tuning comment,
- create requires title + proposed_text,
- approval SoD: approver must differ from the drafter; on approve the target
  template's prompt_text becomes proposed_text and before_text is snapshotted,
- revert restores the template's prompt_text to before_text (status REVERTED),
- NO auto-apply: a draft never mutates the template until approved,
- reject sets REJECTED without touching the template,
- full audit trail on approve/reject/revert.
"""

from datetime import datetime, timedelta, timezone

import pytest

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_prompt import AlertPromptTemplate
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.models.bob_tuning_proposal import BobTuningProposalStatus
from ion.models.user import AuditLog
from ion.services import de_bob_proposal_service as psvc
from ion.services import de_bob_service as svc

_NOW = datetime.now(timezone.utc).replace(tzinfo=None)

_ORIGINAL = "ORIGINAL GUIDE: investigate the alert."


# ── seed helpers ──────────────────────────────────────────────────────────────


def _template(session, name="Suspicious PowerShell Execution", text=_ORIGINAL):
    t = AlertPromptTemplate(name=name, prompt_text=text, priority=100, enabled=True)
    session.add(t)
    session.flush()
    return t


def _triage(session, alert_id, rule_name):
    session.add(AlertTriage(
        es_alert_id=alert_id, rule_name=rule_name, status=AlertTriageStatus.CLOSED,
    ))
    session.flush()


def _fb(session, alert_id, rule_name, template_id, *, bob, human, agreement,
        auto=False, reason=None, days_ago=1):
    """Seed a triage + a deduped-friendly feedback row."""
    _triage(session, alert_id, rule_name)
    f = AIFeedback(
        alert_id=alert_id, alert_prompt_template_id=template_id,
        bob_suggested_verdict=bob, human_verdict=human, agreement=agreement,
        auto_escalated=auto, delta_reason=reason,
        created_at=_NOW - timedelta(days=days_ago),
    )
    session.add(f)
    session.flush()
    return f


# ── feedback grouping ─────────────────────────────────────────────────────────


def test_feedback_groups_disagreements_and_excludes_abstentions(session):
    t = _template(session)
    # 3 scored disagreements on the same class (bob false_positive → human true_positive)
    _fb(session, "a1", "Suspicious PowerShell Execution", t.id,
        bob="false_positive", human="true_positive", agreement=False, reason="real C2")
    _fb(session, "a2", "Suspicious PowerShell Execution", t.id,
        bob="false_positive", human="true_positive", agreement=False, reason="beaconing")
    _fb(session, "a3", "Suspicious PowerShell Execution", t.id,
        bob="false_positive", human="true_positive", agreement=False)
    # an AGREEMENT (should not count as disagreement)
    _fb(session, "a4", "Suspicious PowerShell Execution", t.id,
        bob="true_positive", human="true_positive", agreement=True)
    # an ABSTENTION (agreement None) — not scored
    _fb(session, "a5", "Suspicious PowerShell Execution", t.id,
        bob=None, human="true_positive", agreement=None)
    # an auto-escalated row — not scored
    _fb(session, "a6", "Suspicious PowerShell Execution", t.id,
        bob="false_positive", human="true_positive", agreement=False, auto=True)

    fb = svc.get_bob_feedback(session, days=90)
    assert fb["class_count"] == 1
    assert fb["total_disagreements"] == 3
    cls = fb["classes"][0]
    assert cls["rule_name"] == "Suspicious PowerShell Execution"
    assert cls["bob_verdict"] == "false_positive"
    assert cls["human_verdict"] == "true_positive"
    assert cls["count"] == 3
    assert cls["template_id"] == t.id
    assert "real C2" in cls["sample_reasons"]


def test_feedback_separate_classes_per_verdict_shift(session):
    t = _template(session)
    _fb(session, "a1", "R", t.id, bob="false_positive", human="true_positive", agreement=False)
    _fb(session, "a2", "R", t.id, bob="true_positive", human="false_positive", agreement=False)
    fb = svc.get_bob_feedback(session, days=90)
    assert fb["class_count"] == 2


# ── scorecard ─────────────────────────────────────────────────────────────────


def test_scorecard_agreement_rate_and_drift(session):
    t = _template(session)
    # older half (~80 days ago): 1 agree / 2 scored = 50%
    _fb(session, "o1", "R", t.id, bob="tp", human="tp", agreement=True, days_ago=80)
    _fb(session, "o2", "R", t.id, bob="fp", human="tp", agreement=False, days_ago=80)
    # recent half (~5 days ago): 2 agree / 2 scored = 100% → improving
    _fb(session, "r1", "R", t.id, bob="tp", human="tp", agreement=True, days_ago=5)
    _fb(session, "r2", "R", t.id, bob="tp", human="tp", agreement=True, days_ago=5)

    sc = svc.get_bob_scorecard(session, days=90)
    s = sc["summary"]
    assert s["scored"] == 4
    assert s["agreed"] == 3
    assert s["agreement_rate"] == 75.0
    assert s["drift"]["recent_rate"] == 100.0
    assert s["drift"]["older_rate"] == 50.0
    assert s["drift"]["direction"] == "improving"
    assert "few_shot" in s


# ── deterministic draft ───────────────────────────────────────────────────────


def test_draft_from_feedback_is_deterministic(session):
    t = _template(session)
    _fb(session, "a1", "Suspicious PowerShell Execution", t.id,
        bob="false_positive", human="true_positive", agreement=False, reason="beaconing")

    draft = psvc.draft_from_feedback(
        session, "Suspicious PowerShell Execution", "false_positive", "true_positive", days=90)
    assert draft is not None
    assert draft["template_id"] == t.id
    assert draft["current_text"] == _ORIGINAL
    # proposed = current template text + a tuning comment appended
    assert draft["proposed_text"].startswith(_ORIGINAL)
    assert "DE tuning" in draft["proposed_text"]
    assert "beaconing" in draft["problem_statement"]

    # unknown class → None
    assert psvc.draft_from_feedback(
        session, "Suspicious PowerShell Execution", "true_positive", "false_positive", days=90) is None


# ── create validation ─────────────────────────────────────────────────────────


def test_create_requires_title_and_proposed_text(session):
    with pytest.raises(ValueError, match="title"):
        psvc.create_proposal(session, {"proposed_text": "x"}, user_id=1)
    with pytest.raises(ValueError, match="proposed_text"):
        psvc.create_proposal(session, {"title": "t"}, user_id=1)
    p = psvc.create_proposal(session, {"title": "t", "proposed_text": "x"}, user_id=1)
    assert p.id and p.status == BobTuningProposalStatus.DRAFT


# ── no auto-apply ─────────────────────────────────────────────────────────────


def test_draft_does_not_mutate_template(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW GUIDANCE", "template_id": t.id,
    }, user_id=1)
    psvc.update_proposal(session, p.id, {"proposed_text": "EVEN NEWER"})
    session.refresh(t)
    assert t.prompt_text == _ORIGINAL  # untouched while still a draft


# ── approval SoD + apply + snapshot ───────────────────────────────────────────


def test_approve_requires_different_user_and_applies(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW GUIDANCE", "template_id": t.id,
    }, user_id=1)

    # SoD: drafter cannot approve their own
    with pytest.raises(ValueError, match="separation of duties"):
        psvc.approve_proposal(session, p.id, user_id=1)

    # a different user approves → applied to the live template
    approved = psvc.approve_proposal(session, p.id, user_id=2, notes="LGTM")
    assert approved.status == BobTuningProposalStatus.APPROVED
    assert approved.decided_by_id == 2
    assert approved.before_text == _ORIGINAL  # snapshot captured before write
    session.refresh(t)
    assert t.prompt_text == "NEW GUIDANCE"  # applied live


def test_approve_needs_target_template(session):
    p = psvc.create_proposal(session, {"title": "t", "proposed_text": "x"}, user_id=1)
    with pytest.raises(ValueError, match="template"):
        psvc.approve_proposal(session, p.id, user_id=2)


# ── revert restores ───────────────────────────────────────────────────────────


def test_revert_restores_before_text(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW GUIDANCE", "template_id": t.id,
    }, user_id=1)
    psvc.approve_proposal(session, p.id, user_id=2)
    session.refresh(t)
    assert t.prompt_text == "NEW GUIDANCE"

    reverted = psvc.revert_proposal(session, p.id, user_id=3)
    assert reverted.status == BobTuningProposalStatus.REVERTED
    assert reverted.reverted_by_id == 3
    session.refresh(t)
    assert t.prompt_text == _ORIGINAL  # restored exactly

    # only an approved proposal can be reverted
    with pytest.raises(ValueError):
        psvc.revert_proposal(session, p.id, user_id=3)


# ── reject ────────────────────────────────────────────────────────────────────


def test_reject_sets_status_without_touching_template(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW GUIDANCE", "template_id": t.id,
    }, user_id=1)
    rejected = psvc.reject_proposal(session, p.id, user_id=2, notes="not needed")
    assert rejected.status == BobTuningProposalStatus.REJECTED
    assert rejected.decided_by_id == 2
    session.refresh(t)
    assert t.prompt_text == _ORIGINAL  # untouched
    # cannot approve a rejected proposal
    with pytest.raises(ValueError):
        psvc.approve_proposal(session, p.id, user_id=3)


# ── audit trail ───────────────────────────────────────────────────────────────


def _audit_actions(session, proposal_id):
    return {a.action for a in session.query(AuditLog)
            .filter(AuditLog.resource_type == "bob_tuning_proposal",
                    AuditLog.resource_id == proposal_id).all()}


def test_audit_trail_on_approve_and_revert(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW", "template_id": t.id,
    }, user_id=1)
    psvc.approve_proposal(session, p.id, user_id=2)
    psvc.revert_proposal(session, p.id, user_id=3)
    assert _audit_actions(session, p.id) == {"bob_tuning_approved", "bob_tuning_reverted"}


def test_audit_trail_on_reject(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW", "template_id": t.id,
    }, user_id=1)
    psvc.reject_proposal(session, p.id, user_id=2)
    assert _audit_actions(session, p.id) == {"bob_tuning_rejected"}


# ── list / get ────────────────────────────────────────────────────────────────


def test_list_and_get_proposals(session):
    t = _template(session)
    p = psvc.create_proposal(session, {
        "title": "tune", "proposed_text": "NEW", "template_id": t.id,
    }, user_id=1)
    rows = psvc.list_proposals(session, status="draft")
    assert len(rows) == 1 and rows[0]["id"] == p.id
    assert psvc.list_proposals(session, status="approved") == []
    got = psvc.get_proposal(session, p.id)
    assert got["title"] == "tune"
    assert psvc.get_proposal(session, 9999) is None
