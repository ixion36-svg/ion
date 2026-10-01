"""Tests for incident_cost_service — analyst labour and downtime estimates.

This module was at 0% when the coverage ratchet first measured the tree. It
produces money figures that end up in executive reporting, so a silent
arithmetic change matters more than an exception: nobody questions a plausible
number.

The two things most worth pinning are the cost formula itself and the
zero-safety around it — a case that never closed, a period with no cases, and
a case id that does not exist all have to produce a usable shape rather than
a crash or a division by zero.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services import incident_cost_service as svc

RATE = 100.0          # £/hour analyst time, chosen so the sums are readable
DOWNTIME = 2400.0     # £/hour per affected host, /24 in the formula -> 100/h


@pytest.fixture
def creator(session):
    u = User(username="analyst", email="a@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


def _case(session, creator, number="CASE-1", *, hours=None, hosts=None,
          severity=None, reason=None, closed=True, closed_days_ago=1):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    closed_at = now - timedelta(days=closed_days_ago) if closed else None
    created_at = (closed_at - timedelta(hours=hours)) if (closed and hours) else now
    c = AlertCase(
        case_number=number, title=f"title {number}", created_by_id=creator.id,
        status=AlertCaseStatus.CLOSED if closed else AlertCaseStatus.OPEN,
        closed_at=closed_at, severity=severity, closure_reason=reason,
        affected_hosts=hosts,
    )
    session.add(c)
    session.flush()
    c.created_at = created_at
    session.flush()
    return c


class TestCostFormula:
    def test_analyst_cost_is_hours_times_rate(self, session, creator):
        case = _case(session, creator, hours=10, hosts=[])

        out = svc.calculate_incident_cost(session, case_id=case.id,
                                          hourly_rate=RATE,
                                          downtime_cost_per_hour=DOWNTIME)

        assert out["breakdown"]["analyst_cost"] == 1000.0
        assert out["breakdown"]["downtime_cost"] == 0.0
        assert out["total_cost"] == 1000.0

    def test_downtime_scales_with_the_number_of_affected_hosts(self, session, creator):
        """Two hosts cost twice one; the per-hour figure is divided by 24."""
        one = _case(session, creator, "C1", hours=10, hosts=["h1"])
        two = _case(session, creator, "C2", hours=10, hosts=["h1", "h2"])

        a = svc.calculate_incident_cost(session, case_id=one.id, hourly_rate=RATE,
                                        downtime_cost_per_hour=DOWNTIME)
        b = svc.calculate_incident_cost(session, case_id=two.id, hourly_rate=RATE,
                                        downtime_cost_per_hour=DOWNTIME)

        assert a["breakdown"]["downtime_cost"] == 1000.0   # 1 * 10 * 2400 / 24
        assert b["breakdown"]["downtime_cost"] == 2000.0

    def test_no_affected_hosts_means_no_downtime_cost(self, session, creator):
        case = _case(session, creator, hours=5, hosts=None)
        out = svc.calculate_incident_cost(session, case_id=case.id,
                                          hourly_rate=RATE,
                                          downtime_cost_per_hour=DOWNTIME)
        assert out["breakdown"]["downtime_cost"] == 0.0

    def test_an_unclosed_case_costs_nothing_rather_than_raising(self, session, creator):
        """An open case has no duration yet; it must not read as free labour."""
        case = _case(session, creator, closed=False)

        out = svc.calculate_incident_cost(session, case_id=case.id)

        assert out["total_cost"] == 0
        assert out["breakdown"] == {"analyst_cost": 0, "downtime_cost": 0}

    def test_the_default_rates_are_applied_when_none_are_given(self, session, creator):
        case = _case(session, creator, hours=2, hosts=[])
        out = svc.calculate_incident_cost(session, case_id=case.id)
        assert out["total_cost"] == 150.0  # 2h * the 75.0 default


class TestSingleCase:
    def test_a_missing_case_reports_an_error(self, session):
        assert svc.calculate_incident_cost(session, case_id=999_999) == {
            "error": "Case not found"
        }

    def test_the_single_case_shape_carries_its_own_buckets(self, session, creator):
        case = _case(session, creator, hours=4, hosts=[], severity="high",
                     reason="true_positive")

        out = svc.calculate_incident_cost(session, case_id=case.id, hourly_rate=RATE)

        assert out["cases_analyzed"] == 1
        assert out["period_days"] is None
        assert out["by_severity"]["high"]["count"] == 1
        assert out["by_closure_reason"]["true_positive"]["count"] == 1
        assert out["top_expensive_cases"][0]["case_number"] == "CASE-1"

    def test_missing_severity_and_reason_get_placeholders(self, session, creator):
        case = _case(session, creator, hours=1, hosts=[])
        out = svc.calculate_incident_cost(session, case_id=case.id)
        assert "unknown" in out["by_severity"]
        assert "unspecified" in out["by_closure_reason"]


class TestPeriodAggregate:
    def test_an_empty_period_returns_a_usable_zeroed_shape(self, session):
        """No closed cases must not divide by zero when averaging."""
        out = svc.calculate_incident_cost(session)

        assert out["cases_analyzed"] == 0
        assert out["total_cost"] == 0
        assert out["avg_cost_per_incident"] == 0
        assert out["by_severity"] == {}
        assert out["top_expensive_cases"] == []

    def test_only_closed_cases_inside_the_window_are_counted(self, session, creator):
        _case(session, creator, "recent", hours=1, hosts=[], closed_days_ago=1)
        _case(session, creator, "old", hours=1, hosts=[], closed_days_ago=60)
        _case(session, creator, "open", closed=False)

        out = svc.calculate_incident_cost(session, hourly_rate=RATE)

        assert out["cases_analyzed"] == 1
        assert out["period_days"] == 30

    def test_costs_and_averages_add_up(self, session, creator):
        _case(session, creator, "C1", hours=10, hosts=[], severity="high")
        _case(session, creator, "C2", hours=20, hosts=[], severity="high")

        out = svc.calculate_incident_cost(session, hourly_rate=RATE,
                                          downtime_cost_per_hour=DOWNTIME)

        assert out["total_cost"] == 3000.0
        assert out["avg_cost_per_incident"] == 1500.0
        assert out["by_severity"]["high"] == {"count": 2, "avg_cost": 1500.0}

    def test_buckets_split_by_severity_and_by_reason(self, session, creator):
        _case(session, creator, "C1", hours=10, hosts=[], severity="high",
              reason="true_positive")
        _case(session, creator, "C2", hours=10, hosts=[], severity="low",
              reason="false_positive")

        out = svc.calculate_incident_cost(session, hourly_rate=RATE)

        assert set(out["by_severity"]) == {"high", "low"}
        assert set(out["by_closure_reason"]) == {"true_positive", "false_positive"}

    def test_the_internal_running_total_does_not_leak(self, session, creator):
        """`_total_cost` is an accumulator, not part of the contract."""
        _case(session, creator, "C1", hours=1, hosts=[], severity="high")

        out = svc.calculate_incident_cost(session)

        assert set(out["by_severity"]["high"]) == {"count", "avg_cost"}

    def test_most_expensive_first(self, session, creator):
        _case(session, creator, "cheap", hours=1, hosts=[])
        _case(session, creator, "dear", hours=50, hosts=[])

        names = [c["case_number"]
                 for c in svc.calculate_incident_cost(session)["top_expensive_cases"]]

        assert names == ["dear", "cheap"]

    def test_the_expensive_list_is_capped_at_ten(self, session, creator):
        for i in range(14):
            _case(session, creator, f"C{i}", hours=i + 1, hosts=[])

        out = svc.calculate_incident_cost(session)

        assert out["cases_analyzed"] == 14
        assert len(out["top_expensive_cases"]) == 10
        assert out["top_expensive_cases"][0]["case_number"] == "C13"
