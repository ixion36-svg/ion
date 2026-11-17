"""One measure of how each rule's alerts were closed, read by every page.

The defect this guards: Detection Health counted only the alerts Bob had seen
while DE Metrics counted every closure, so the same rule showed two
false-positive rates, and "noisy" meant three different things.
"""

from datetime import datetime, timedelta, timezone

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
from ion.services.de_metrics_service import get_de_metrics
from ion.services.detection_health_service import get_detection_health
from ion.services.rule_outcome_service import (
    NoisyPolicy,
    RuleKey,
    Window,
    rule_outcomes,
)

NOW = datetime.now(timezone.utc).replace(tzinfo=None)


class Estate:
    """Closed cases and their alerts, written the way ION writes them."""

    def __init__(self, session):
        self.session = session
        self.n = 0

    def close(self, rule_name, reason, *, rule_id=None, days_ago=1, hours_open=2):
        self.n += 1
        closed_at = NOW - timedelta(days=days_ago)
        case = AlertCase(case_number=f"C-{self.n}", title=f"case {self.n}", created_by_id=1,
                         status=AlertCaseStatus.CLOSED, closure_reason=reason,
                         severity="medium")
        case.closed_at = closed_at
        self.session.add(case)
        self.session.flush()
        triage = AlertTriage(es_alert_id=f"a-{self.n}", rule_name=rule_name, rule_id=rule_id,
                             status=AlertTriageStatus.CLOSED, case_id=case.id)
        triage.created_at = closed_at - timedelta(hours=hours_open)
        self.session.add(triage)
        self.session.flush()
        return triage

    def fire(self, rule_name, *, rule_id=None, days_ago=1):
        self.n += 1
        triage = AlertTriage(es_alert_id=f"a-{self.n}", rule_name=rule_name, rule_id=rule_id,
                             status=AlertTriageStatus.OPEN)
        triage.created_at = NOW - timedelta(days=days_ago)
        self.session.add(triage)
        self.session.flush()


@pytest.fixture
def estate(session):
    return Estate(session)


def _dh_rule(health, name):
    return next(r for r in health["rules"] if r["rule_name"] == name)


def _dem_campaign(metrics, name):
    return next(c for c in metrics["campaigns"] if c["rule_name"] == name)


def test_de_metrics_and_detection_health_show_one_fp_rate_for_one_rule(session, estate):
    for _ in range(3):
        estate.close("PowerShell Encoded", "false_positive", rule_id="r-ps")
    estate.close("PowerShell Encoded", "true_positive", rule_id="r-ps")
    estate.close("PowerShell Encoded", "benign_true_positive", rule_id="r-ps")
    session.commit()

    dh = _dh_rule(get_detection_health(session, days=90), "PowerShell Encoded")
    dem = _dem_campaign(get_de_metrics(session, days=90), "PowerShell Encoded")

    assert dh["fp_rate"] == dem["fp_rate"] == 60.0
    assert dh["closed"] == dem["closed"] == 5
    assert dh["rule_id"] == dem["rule_id"] == "r-ps"


def test_detection_health_counts_closures_bob_never_saw(session, estate):
    """No AIFeedback rows at all: the old ledger basis showed nothing here."""
    for _ in range(2):
        estate.close("Quiet Rule", "false_positive")
    session.commit()

    rule = _dh_rule(get_detection_health(session, days=90), "Quiet Rule")
    assert rule["closed"] == 2
    assert rule["fp_rate"] == 100.0


def test_closures_outside_the_window_are_not_counted(session, estate):
    estate.close("Windowed", "false_positive", days_ago=10)
    estate.close("Windowed", "true_positive", days_ago=40)
    estate.close("Windowed", "true_positive", days_ago=400)
    session.commit()

    last_30 = rule_outcomes(session, Window.last(30, now=NOW)).get(RuleKey(rule_name="Windowed"))
    last_90 = rule_outcomes(session, Window.last(90, now=NOW)).get(RuleKey(rule_name="Windowed"))

    assert last_30.outcomes["false_positive"] == 1 and last_30.closed == 1
    assert last_90.closed == 2 and last_90.fp_rate == 50.0


def test_the_window_end_is_exclusive(session, estate):
    estate.close("Edge", "false_positive", days_ago=0)
    session.commit()
    closed_at = NOW
    window = Window(since=closed_at - timedelta(days=1), until=closed_at)

    assert rule_outcomes(session, window).get(RuleKey(rule_name="Edge")).closed == 0


def test_a_window_longer_than_a_year_is_refused():
    with pytest.raises(ValueError):
        Window(since=NOW - timedelta(days=366), until=NOW)


def test_noisy_flags_the_rule_over_the_threshold_and_not_the_others(session, estate, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "5")
    monkeypatch.setenv("ION_DH_NOISY_FP_PCT", "70")
    for _ in range(4):
        estate.close("Noisy", "false_positive")
    estate.close("Noisy", "true_positive")             # 80% FP over 5 closures
    for _ in range(3):
        estate.close("Mixed", "false_positive")
    for _ in range(2):
        estate.close("Mixed", "true_positive")         # 60% FP
    for _ in range(4):
        estate.close("Thin", "false_positive")         # 100% FP, only 4 closures
    session.commit()

    flags = {r["rule_name"]: r["flags"]["noisy"]
             for r in get_detection_health(session, days=90)["rules"]}
    campaigns = {c["rule_name"]: c["noisy"]
                 for c in get_de_metrics(session, days=90)["campaigns"]}

    assert flags == {"Noisy": True, "Mixed": False, "Thin": False}
    assert campaigns == flags


def test_benign_closures_are_not_false_positives(session, estate):
    estate.close("Admin Tool", "benign_true_positive")
    estate.close("Admin Tool", "false_positive")
    session.commit()

    rec = rule_outcomes(session, Window.last(90)).get(RuleKey(rule_name="Admin Tool"))
    assert rec.fp_rate == 50.0
    assert rec.outcomes["benign_true_positive"] == 1


def test_rows_with_only_a_name_join_the_rule_that_now_has_an_id(session, estate):
    estate.close("Brute Force", "false_positive")                 # alert aged out, no id
    estate.close("Brute Force", "true_positive", rule_id="r-bf")
    session.commit()

    outcomes = rule_outcomes(session, Window.last(90))
    assert set(outcomes.records) == {RuleKey(rule_id="r-bf")}
    assert outcomes.get(RuleKey(rule_id="r-bf")).closed == 2


def test_a_shared_name_is_not_guessed_onto_either_rule(session, estate):
    estate.close("Generic", "false_positive", rule_id="r-1")
    estate.close("Generic", "false_positive", rule_id="r-2")
    estate.close("Generic", "true_positive")
    session.commit()

    outcomes = rule_outcomes(session, Window.last(90))
    assert outcomes.get(RuleKey(rule_name="Generic")).closed == 1
    assert outcomes.get(RuleKey(rule_id="r-1")).closed == 1


def test_median_time_to_close_and_last_closed(session, estate):
    estate.close("Timed", "false_positive", hours_open=1, days_ago=3)
    estate.close("Timed", "false_positive", hours_open=3, days_ago=2)
    last = estate.close("Timed", "true_positive", hours_open=10, days_ago=1)
    session.commit()

    rec = rule_outcomes(session, Window.last(90)).get(RuleKey(rule_name="Timed"))
    assert rec.median_seconds_to_close == 3 * 3600
    assert rec.last_closed_at == last.case.closed_at


def test_alerts_count_what_fired_in_the_window(session, estate):
    estate.fire("Firing", days_ago=1)
    estate.fire("Firing", days_ago=2)
    estate.fire("Firing", days_ago=200)
    session.commit()

    rec = rule_outcomes(session, Window.last(90)).get(RuleKey(rule_name="Firing"))
    assert rec.alerts == 2 and rec.closed == 0 and rec.fp_rate is None


def test_noisy_policy_needs_a_sample():
    from ion.services.rule_outcome_service import RuleOutcome

    rec = RuleOutcome(key=RuleKey(rule_id="x"))
    rec.outcomes["false_positive"] = 4
    assert NoisyPolicy(min_closed=5, fp_rate_pct=70).is_noisy(rec) is False
    rec.outcomes["false_positive"] = 5
    assert NoisyPolicy(min_closed=5, fp_rate_pct=70).is_noisy(rec) is True


def test_workbench_campaigns_use_the_same_window_as_de_metrics():
    from ion.services.rule_outcome_service import DEFAULT_WINDOW_DAYS
    from ion.web.ui import de_workbench

    assert de_workbench.CAMPAIGN_DAYS == DEFAULT_WINDOW_DAYS == 90
