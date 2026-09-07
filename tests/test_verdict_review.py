"""Phase 2 — Verdict Review: surface + resolve Bob's pending per-alert verdicts.

- the queue lists latest-pending rows with alert context;
- resolving stamps human_verdict + agreement (accept or override);
- a resolved row can't be re-resolved; an invalid verdict is refused;
- a pending row superseded by a later resolved row for the same alert/template
  drops out of the queue (canonical MAX(id) dedup);
- metrics report queue depth + agreement rate.
"""

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage
from ion.services import verdict_review_service as vr


def _pending(session, alert_id, bob="true_positive", tpl=None):
    fb = AIFeedback(
        alert_id=alert_id, alert_prompt_template_id=tpl,
        bob_suggested_verdict=bob, bob_confidence="high", human_verdict="pending",
    )
    session.add(fb)
    session.flush()
    return fb


def test_list_pending_with_alert_context(session):
    session.add(AlertTriage(
        es_alert_id="es-1", rule_name="T1021 - Remote Services", priority="high",
        observables=[{"type": "ip", "value": "185.22.11.9"}],
    ))
    fb = _pending(session, "es-1", bob="true_positive")
    session.commit()
    rows = vr.list_pending_verdicts(session)
    assert len(rows) == 1
    r = rows[0]
    assert r["id"] == fb.id
    assert r["bob_verdict"] == "true_positive"
    assert r["rule_name"] == "T1021 - Remote Services"
    assert r["priority"] == "high"
    assert r["observables"] == [{"type": "ip", "value": "185.22.11.9"}]


def test_resolve_agreement_true(session):
    fb = _pending(session, "es-2", bob="true_positive")
    session.commit()
    res = vr.resolve_verdict(session, fb.id, "true_positive", reviewer_id=1)
    assert res["status"] == "resolved"
    assert res["agreement"] is True
    session.refresh(fb)
    assert fb.human_verdict == "true_positive"
    assert fb.human_closed_by_id == 1


def test_resolve_override_disagreement(session):
    fb = _pending(session, "es-3", bob="true_positive")
    session.commit()
    res = vr.resolve_verdict(session, fb.id, "false_positive", reviewer_id=2, delta_reason="benign scanner")
    assert res["agreement"] is False
    session.refresh(fb)
    assert fb.delta_reason == "benign scanner"


def test_resolve_already_resolved_errors(session):
    fb = _pending(session, "es-4")
    session.commit()
    vr.resolve_verdict(session, fb.id, "true_positive", reviewer_id=1)
    res = vr.resolve_verdict(session, fb.id, "false_positive", reviewer_id=1)
    assert res["status"] == "error"
    assert "Already resolved" in res["error"]


def test_invalid_verdict_errors(session):
    fb = _pending(session, "es-5")
    session.commit()
    res = vr.resolve_verdict(session, fb.id, "not_a_verdict", reviewer_id=1)
    assert res["status"] == "error"


def test_superseded_pending_excluded(session):
    _pending(session, "es-6", tpl=7)  # earlier pending
    later = AIFeedback(
        alert_id="es-6", alert_prompt_template_id=7,
        bob_suggested_verdict="true_positive", human_verdict="true_positive", agreement=True,
    )
    session.add(later)
    session.commit()
    # neither row should appear: `later` is resolved, and the earlier pending
    # row is not the MAX id for (es-6, 7) so it's superseded.
    assert all(r["alert_id"] != "es-6" for r in vr.list_pending_verdicts(session))


def test_metrics(session):
    _pending(session, "es-7")
    fb = _pending(session, "es-8", bob="true_positive")
    session.commit()
    vr.resolve_verdict(session, fb.id, "true_positive", reviewer_id=1)
    m = vr.verdict_metrics(session)
    assert m["pending"] >= 1
    assert m["reviewed"] >= 1
    assert m["agreement_rate"] == 1.0
