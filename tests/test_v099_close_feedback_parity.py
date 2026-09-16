"""Every case-close path writes the AIFeedback close row.

CLAUDE.md pins the AIFeedback ledger as a dual-write on fire-time AND
case-close. Before this, only the manual PATCH endpoint wrote the close half:
the KFP auto-close, close-as-known-FP, the alert-close parent cascade and the
bulk-close cascade all left a case closed with no close-side row, so Bob's
verdict was never scored against the human outcome on four of five paths.

These pin the shared helper and the fact that all five paths reach it.
"""

import re
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
from ion.models.base import Base
from ion.models.user import User
from ion.services.ai_feedback_service import record_close_feedback_safe

SRC = Path(__file__).resolve().parents[1] / "src" / "ion"


def _session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _case_with_triage(session, tag):
    user = User(username=f"u{tag}", email=f"{tag}@x.y", password_hash="x", display_name="U")
    session.add(user)
    session.flush()
    case = AlertCase(
        title=tag, case_number=tag, status=AlertCaseStatus.OPEN,
        severity="high", created_by_id=user.id,
    )
    session.add(case)
    session.flush()
    session.add(AlertTriage(
        es_alert_id=f"alert-{tag}", case_id=case.id,
        suggested_verdict="true_positive", suggested_verdict_confidence="high",
    ))
    session.flush()
    session.refresh(case)
    return case, user


def test_helper_writes_a_close_row_per_triage_entry():
    session = _session()
    case, user = _case_with_triage(session, "A")
    case.status = AlertCaseStatus.CLOSED
    case.closure_reason = "false_positive"

    written = record_close_feedback_safe(session, case, "false_positive", user.id, "note")
    session.commit()

    assert written == 1
    assert session.query(AIFeedback).filter(AIFeedback.alert_id == "alert-A").count() == 1


def test_helper_never_raises_and_no_ops_without_a_verdict():
    session = _session()
    case, user = _case_with_triage(session, "B")

    # A ledger failure must never fail the close itself.
    assert record_close_feedback_safe(session, None, "false_positive", user.id) == 0
    assert record_close_feedback_safe(session, case, None, user.id) == 0
    assert session.query(AIFeedback).count() == 0


def test_every_close_path_reaches_the_ledger_helper():
    """Guard against a sixth close path landing without the ledger write.

    Counts call sites rather than behaviour: the paths live in three modules
    and each needs its own integration harness to drive end to end.
    """
    sites = {
        "web/case_lifecycle_api.py": 2,   # KFP auto-close, close-as-known-FP
        "web/api.py": 1,                  # alert-close parent cascade
        "services/bulk_operations_service.py": 1,  # bulk-close cascade
    }
    for rel, expected in sites.items():
        text = (SRC / rel).read_text(encoding="utf-8")
        # strip comments so a mention in prose cannot satisfy the count
        code = "\n".join(re.sub(r"#.*$", "", ln) for ln in text.splitlines())
        found = len(re.findall(r"_?record_close_feedback_safe\s*\(|_record_close_feedback\s*\(", code))
        assert found >= expected, f"{rel}: expected >= {expected} ledger calls, found {found}"

    # the fifth path is the original manual PATCH endpoint
    lifecycle = (SRC / "web/case_lifecycle_api.py").read_text(encoding="utf-8")
    assert "record_case_close_feedback(" in lifecycle
