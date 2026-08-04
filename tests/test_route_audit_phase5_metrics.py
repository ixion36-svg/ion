"""Route audit phase 5 — metric consolidation.

5a. The AIFeedback `MAX(id) per (alert_id, template_id)` dedupe contract existed
    in SEVEN hand-maintained copies whose docstrings each insisted they stay
    identical. One had already drifted: the /ai-scorecard reader counted
    `auto_escalated` circuit-breaker abstentions in its denominator, so it
    reported a different agreement rate than every other Bob-quality surface for
    the same data. `services/ai_feedback_dedupe` now owns the contract.

5b. `/bob-eval` reported Precision, Recall and F1 that were mathematically
    forced to be the SAME number: every disagreement did `fp += 1; fn += 1`, so
    fp == fn always, so precision == recall == f1 == the agreement rate. Three
    statistical names, one value, on a page whose entire purpose is measurement.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ion.services.ai_feedback_dedupe import deduped_feedback_ids, is_scored, pct
from ion.services.bob_eval_service import _compute_metrics, _is_threat_verdict
from ion.services.case_metrics import case_metrics

# ── 5a: the shared dedupe contract ───────────────────────────────────────


def test_is_scored_excludes_circuit_breaker_abstentions():
    """The exclusion /ai-scorecard was missing."""
    assert is_scored("true_positive", True, False) is True
    assert is_scored("true_positive", False, False) is True     # scored disagreement
    assert is_scored("true_positive", True, True) is False      # auto_escalated
    assert is_scored(None, True, False) is False                # Bob never suggested
    assert is_scored("true_positive", None, False) is False     # never adjudicated


def test_deduped_ids_groups_by_alert_and_template():
    sql = str(deduped_feedback_ids(None).compile(
        compile_kwargs={"literal_binds": True}))
    assert "max(" in sql.lower()
    assert "GROUP BY" in sql.upper()
    assert "alert_id" in sql and "alert_prompt_template_id" in sql


def test_deduped_ids_cutoff_and_template_filters_are_optional():
    from datetime import datetime

    no_filter = str(deduped_feedback_ids(None).compile(
        compile_kwargs={"literal_binds": True}))
    assert "created_at" not in no_filter, "cutoff=None must dedupe across all time"

    windowed = str(deduped_feedback_ids(datetime(2026, 1, 1)).compile(
        compile_kwargs={"literal_binds": True}))
    assert "created_at" in windowed

    templated = str(deduped_feedback_ids(None, require_template=True).compile(
        compile_kwargs={"literal_binds": True}))
    assert "alert_prompt_template_id IS NOT NULL" in templated


def test_pct_handles_empty_denominator():
    assert pct(3, 4) == 75.0
    assert pct(0, 0) is None


def test_dedupe_contract_is_not_re_copied():
    """Guard against the contract being hand-rolled again.

    Only two sites may group by (alert_id, alert_prompt_template_id) outside the
    shared module: investigation_memory_repository (signature-scoped join — a
    different question) and bob_eval_service (raw SQL with PG/sqlite branches).
    Anything new should call deduped_feedback_ids() instead.
    """
    allowed = {"investigation_memory_repository.py", "bob_eval_service.py",
               "ai_feedback_dedupe.py"}
    offenders = []
    for path in Path("src/ion").rglob("*.py"):
        if path.name in allowed:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"group_by\(\s*AIFeedback\.alert_id", text) or \
           "GROUP BY alert_id, alert_prompt_template_id" in text:
            offenders.append(str(path))
    assert not offenders, (
        f"hand-rolled AIFeedback dedupe reintroduced in: {offenders} — "
        "use ai_feedback_dedupe.deduped_feedback_ids()"
    )


# ── 5b: bob-eval confusion matrix ────────────────────────────────────────


def test_threat_verdict_positive_class():
    assert _is_threat_verdict("true_positive") is True
    assert _is_threat_verdict("TP") is True
    assert _is_threat_verdict("true-positive") is True
    for negative in ("false_positive", "benign_true_positive", "duplicate",
                     "not_applicable", "insufficient_data", None, ""):
        assert _is_threat_verdict(negative) is False, negative


def test_precision_and_recall_can_now_differ():
    """The old scoring forced fp == fn, collapsing all three metrics to one."""
    precision, recall, f1 = _compute_metrics(tp=8, fp=4, fn=1, tn=7)
    assert precision != recall, "a real confusion matrix must separate P and R"
    assert round(precision, 3) == 0.667   # 8 / (8+4)
    assert round(recall, 3) == 0.889      # 8 / (8+1)
    assert precision < f1 < recall


def test_scoring_no_longer_increments_fp_and_fn_together():
    """Pin the actual defect: `fp += 1` and `fn += 1` on the same branch."""
    src = Path("src/ion/services/bob_eval_service.py").read_text(encoding="utf-8")
    body = src.split("def run_evaluation", 1)[-1]
    assert not re.search(r"fp \+= 1\s*\n\s*fn \+= 1", body), (
        "disagreements are being counted as both FP and FN again — that forces "
        "precision == recall == f1"
    )
    assert "_is_threat_verdict(" in body


@pytest.mark.parametrize("tp,fp,fn,tn", [(5, 0, 0, 5), (0, 3, 2, 1), (7, 2, 3, 0)])
def test_compute_metrics_stays_in_range(tp, fp, fn, tn):
    for score in _compute_metrics(tp, fp, fn, tn):
        assert score is None or 0.0 <= score <= 1.0


# ── 5c: shared case metrics ──────────────────────────────────────────────


def _case_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import ion.models  # noqa: F401 — registers models
    from ion.models.base import Base

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _seed_closed(session, now):
    from datetime import timedelta

    from ion.models.alert_triage import AlertCase, AlertCaseStatus

    def mk(number, reason, age_hours):
        c = AlertCase(
            case_number=number, title=number, created_by_id=1,
            status=AlertCaseStatus.CLOSED, severity="high", closure_reason=reason,
        )
        session.add(c)
        session.flush()
        c.created_at = now - timedelta(hours=age_hours + 1)
        c.closed_at = now - timedelta(hours=1)

    for i in range(6):
        mk(f"FP-{i}", "false_positive", 2)
    for i in range(2):
        mk(f"TP-{i}", "true_positive", 10)
    for i in range(2):
        mk(f"DUP-{i}", "duplicate", 4)   # administrative closure
    session.commit()


def test_the_two_fp_denominators_really_differ():
    """The concrete defect: identical data, identical label, different number.

    /executive-report + /soc-health divide FPs by ALL closures (60%);
    /analyst-efficiency divides by real dispositions only (75%). Both are
    computed here so neither page can drift, and each names which it uses.
    """
    from datetime import datetime, timedelta

    session = _case_db()
    now = datetime.utcnow()
    _seed_closed(session, now)

    from ion.services.case_metrics import case_metrics
    m = case_metrics(session, now - timedelta(days=30))

    assert m["closed"] == 10
    assert m["fp_count"] == 6 and m["tp_count"] == 2
    assert m["dispositions"] == 8              # duplicates excluded
    assert m["fp_rate_of_closed"] == 60.0      # 6/10
    assert m["fp_rate_of_dispositions"] == 75.0  # 6/8
    assert m["fp_rate_of_closed"] != m["fp_rate_of_dispositions"]


def test_case_metrics_handles_empty_window():
    from datetime import datetime, timedelta

    session = _case_db()
    m = case_metrics(session, datetime.utcnow() - timedelta(days=30))
    assert m["closed"] == 0 and m["opened"] == 0
    assert m["fp_rate_of_closed"] is None
    assert m["fp_rate_of_dispositions"] is None
    assert m["avg_mttr_hours"] is None


def test_mttr_is_computed_once():
    """MTTR was the same formula in four services with different rounding."""
    from datetime import datetime, timedelta

    session = _case_db()
    now = datetime.utcnow()
    _seed_closed(session, now)
    m = case_metrics(session, now - timedelta(days=30))
    # 6 x 2h + 2 x 10h + 2 x 4h = 40h over 10 cases
    assert m["avg_mttr_hours"] == 4.0
    assert m["mttr_sample_size"] == 10
