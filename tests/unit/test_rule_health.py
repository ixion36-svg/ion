"""Rule health: TIDE 7 Rule Monitoring when the tenant has it, ION's thresholds when not."""
from __future__ import annotations

import asyncio
from datetime import date, timedelta

import pytest

from ion.services import rule_health_service as rh
from ion.services.tide_service import TableAbsent, TideFailure, TideService

RULES = [
    {"rule_id": "r-noisy", "name": "Noisy rule", "severity": "high", "enabled": 1, "quality_score": 64,
     "mitre_ids": ["T1059.001"], "siem_id": "elastic", "space": "default", "kind": "elastic", "rule_uuid": "u-1"},
    {"rule_id": "5712", "name": "SSHD brute force", "severity": "medium", "enabled": 1, "quality_score": None,
     "mitre_ids": ["T1110"], "siem_id": "wazuh", "space": "linux", "kind": "wazuh", "rule_uuid": "5712"},
    {"rule_id": "r-quiet", "name": "Quiet rule", "severity": "critical", "enabled": 1, "quality_score": 90,
     "mitre_ids": [], "siem_id": "elastic", "space": "default", "kind": "elastic", "rule_uuid": "u-3"},
]


def _days(per_day: list[int]) -> list[dict]:
    today = date.today()
    return [{"siem_id": "elastic", "space": "default", "rule_uuid": "u-1", "rule_id": "r-noisy",
             "day": (today - timedelta(days=len(per_day) - 1 - i)).isoformat(), "alerts": n}
            for i, n in enumerate(per_day) if n]


class _Tide(TideService):
    """A TIDE whose tenant answers the given tables; any other is unknown."""

    def __init__(self, tables: dict):
        self.enabled = True
        self.scope = None
        self.tables = tables

    def _rule_columns(self):
        from ion.services.tide_service import _RuleColumns
        return _RuleColumns()

    def _run(self, sql: str, retries: int = 1):
        for table, rows in self.tables.items():
            if f"FROM {table} " in sql or sql.rstrip().endswith(f"FROM {table}"):
                return rows if isinstance(rows, TideFailure) else {"rows": rows}
        name = sql.split("FROM ")[1].split()[0]
        return TideFailure("bad_request", f"Unknown table: {name}", 400)


def _report(tables, monkeypatch, kibana=None):
    async def fake_kibana(*a, **k):
        return kibana
    monkeypatch.setattr(rh, "kibana_alert_days", fake_kibana)
    return asyncio.run(rh.rule_health(None, _Tide(tables)))


def test_an_unknown_table_is_absent_not_a_failure():
    svc = _Tide({})
    assert svc.get_rule_issues() == TableAbsent("rule_issues")
    assert svc.get_gitlab_issues() == TableAbsent("gitlab_issues")


def test_a_refused_key_stays_a_failure():
    svc = _Tide({"rule_issues": TideFailure("auth_rejected", "bad key", 401)})
    assert isinstance(svc.get_rule_issues(), TideFailure)


def test_tide_rule_monitoring_supplies_the_problems_when_present(monkeypatch):
    issues = [
        {"issue": "no_recent_data", "cause": "logs-x-*", "siem_id": "elastic", "space": "default",
         "rule_id": "r-quiet", "severity": "error", "detail": "No new event in logs-x-* for 3 days."},
        {"issue": "wazuh_agents_disconnected", "cause": "", "siem_id": "wazuh", "space": "*",
         "rule_id": "", "severity": "warning", "detail": "2 of 6 agents not seen."},
    ]
    report = _report({"detection_rules": RULES, "rule_issues": issues,
                      "rule_alert_counts": _days([30] * 14)}, monkeypatch)
    rules = report.by_key()
    assert report.monitoring == "tide"
    assert [(p.title, p.level) for p in rules["r-quiet|elastic|default"].problems] == [
        ("No recent events in the index pattern", "error")]
    # 420 alerts in 14 days would trip ION's own threshold; TIDE said nothing, so nothing.
    assert rules["r-noisy|elastic|default"].alerts == 420
    assert rules["r-noisy|elastic|default"].problems == []
    assert [d.problem.kind for d in report.destination_problems] == ["wazuh_agents_disconnected"]
    assert report.rules[0].rule_id == "r-quiet", "errors sort first"


def test_without_rule_monitoring_ion_judges_volume_from_tide_alert_counts(monkeypatch):
    report = _report({"detection_rules": RULES, "rule_alert_counts": _days([10] * 12 + [90, 120])}, monkeypatch)
    noisy = report.by_key()["r-noisy|elastic|default"]
    assert report.monitoring == "ion" and report.alerts_from == "tide"
    assert {p.kind for p in noisy.problems} == {"too_many", "spike"}
    assert {p.kind for p in report.by_key()["r-quiet|elastic|default"].problems} == {"silent"}
    assert any("Rule Monitoring needs TIDE 7" in n for n in report.notes)


def test_without_tide_alert_counts_the_fallback_reads_kibana(monkeypatch):
    kibana = {("r-noisy", "default"): ([0] * 13 + [250], 250)}
    report = _report({"detection_rules": RULES}, monkeypatch, kibana=kibana)
    assert report.alerts_from == "kibana"
    noisy = report.by_key()["r-noisy|elastic|default"]
    assert noisy.alerts == 250 and {p.kind for p in noisy.problems} == {"too_many", "spike"}
    assert report.by_key()["5712|wazuh|linux"].alerts is None, "Kibana holds no Wazuh alerts"


@pytest.mark.parametrize("days,expect", [
    ([14] * 14, set()),
    ([0] * 12 + [3, 3], set()),
    ([1] * 12 + [5, 5], {"spike"}),
    ([20] * 14, {"too_many"}),
])
def test_ion_thresholds(days, expect):
    assert {p.kind for p in rh.ion_problems(days, sum(days), True)} == expect


def test_a_rule_with_no_rule_table_is_a_failed_read(monkeypatch):
    report = _report({"detection_rules": TideFailure("unreachable", "ConnectError")}, monkeypatch)
    assert report.state == "failed" and report.failure.kind == "unreachable"


def test_a_column_probe_shed_for_load_is_not_remembered_as_a_missing_column():
    class _Shedding(TideService):
        def __init__(self):
            self.enabled, self.scope, self.shed = True, None, True
            self.last_failure = None

        def _query(self, sql, retries=1):
            if self.shed and "LIMIT 0" in sql:
                self.last_failure = TideFailure("overloaded", "too many TIDE queries in flight")
                return None
            self.last_failure = None
            return {"rows": []}

    svc = _Shedding()
    assert svc._rule_columns().rule_type is True and svc._columns is None
    svc.shed = False
    assert svc._rule_columns().rule_type is True and svc._columns is not None
