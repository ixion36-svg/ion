"""Case metrics are counted in the database and match a row-by-row count."""

import random
from datetime import datetime, timedelta

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services.case_metrics import case_metrics, mean_hours_to_close

NOW = datetime(2026, 11, 11, 12, 0, 0)
REASONS = ["true_positive", "false_positive", "duplicate", None, "benign_true_positive"]


def _seed(session, n=300):
    session.add(User(id=1, username="u", email="u@x.test", password_hash="x"))
    rnd = random.Random(7)
    cases = []
    for i in range(n):
        created = NOW - timedelta(days=rnd.randint(0, 400), minutes=rnd.randint(0, 1440))
        closed = None
        if i % 5:
            closed = created + timedelta(minutes=rnd.randint(1, 60 * 24 * 9), seconds=rnd.randint(0, 59))
        cases.append(AlertCase(
            case_number=f"C-{i}", title="t", severity="low", created_by_id=1,
            status=AlertCaseStatus.CLOSED if closed else AlertCaseStatus.OPEN,
            created_at=created, closed_at=closed,
            closure_reason=rnd.choice(REASONS) if closed else None,
        ))
    session.add_all(cases)
    session.commit()
    return cases


def _reference(cases, since, until=None):
    closed = [c for c in cases if c.closed_at and c.closed_at >= since and (until is None or c.closed_at <= until)]
    reasons = {}
    for c in closed:
        key = c.closure_reason or "unspecified"
        reasons[key] = reasons.get(key, 0) + 1
    hours = [(c.closed_at - c.created_at).total_seconds() / 3600 for c in closed]
    return reasons, len(closed), (round(sum(hours) / len(hours), 1) if hours else None), len(hours)


def test_metrics_match_a_row_by_row_count(session):
    cases = _seed(session)
    for since, until in [(datetime(1970, 1, 1), None), (NOW - timedelta(days=30), None),
                         (NOW - timedelta(days=200), NOW - timedelta(days=100))]:
        got = case_metrics(session, since=since, until=until)
        reasons, closed, mttr, n = _reference(cases, since, until)
        assert got["closure_reasons"] == reasons
        assert got["closed"] == closed
        assert got["avg_mttr_hours"] == mttr
        assert got["mttr_sample_size"] == n
        assert got["fp_count"] == reasons.get("false_positive", 0)


def test_a_window_with_no_closures_has_no_average(session):
    _seed(session, n=5)
    got = case_metrics(session, since=NOW + timedelta(days=1))
    assert got["closed"] == 0 and got["avg_mttr_hours"] is None and got["closure_reasons"] == {}
    assert mean_hours_to_close(session, AlertCase.closed_at >= NOW + timedelta(days=1)) == (None, 0)
