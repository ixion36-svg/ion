"""A disabled rule is not coverage.

ION decided a technique was covered the moment any rule mentioned it, with no
test on `enabled`. Measured on the live TIDE tenant 2026-10-12: of the
techniques the 1,859 synced rules touch, 164 had a rule and only 94 had an
enabled one. Only 224 of the 1,859 rules are enabled at all. So 70 techniques
were reported as covered by rules nothing was running, and appeared as a gap
nowhere: not in blind_spots, not in the gaps analysis, not in SOC Health's
detection coverage grade, and not in the compliance scorecards.

The fix is not "use enabled_rules instead of rule_count". That collapses two
genuinely different situations. A technique with rules that are all switched
off is not the same as one nobody has written a rule for: the detection
exists, and enabling it is far cheaper than authoring one. So coverage now has
three states, and `inactive_techniques` carries the middle one.

Five call sites had the bug. Two are covered here directly through
get_global_mitre_coverage and the compliance scorecard's technique set; the
three SQL sites (get_posture_stats' coverage CTE, get_mitre_coverage's
per-system join, and get_gaps_analysis) are pinned by asserting the emitted
SQL carries the filter, because their work happens inside DuckDB where a unit
test has no database to run it against.

test_the_old_rule_count_test_and_the_new_one_disagree is the control. Every
other test here passes trivially against a fixture where no rule is disabled.
"""
from __future__ import annotations

from typing import Any, Optional

import pytest

from ion.services.compliance_mapping_service import _covered_techniques
from ion.services.tide_service import TideService


# ---------------------------------------------------------------------------
# A fake shaped like the three queries get_global_mitre_coverage runs.
# Hand-written, per test_de_tide_api's reasoning: a Mock answers every shape
# alike, and the shape of these rows is the thing under test.
# ---------------------------------------------------------------------------

#: One technique per state, so every assertion has a negative case.
_CATALOG = [
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter",
     "tactic": "execution"},
    {"technique_id": "T1021", "name": "Remote Services",
     "tactic": "lateral-movement"},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact",
     "tactic": "impact"},
]


def _stats_row(tid: str, rule_count: int, enabled: int) -> dict:
    return {
        "technique_id": tid,
        "rule_count": rule_count,
        "avg_quality": 2.0,
        "critical_rules": 0, "high_rules": 0, "medium_rules": 0, "low_rules": 0,
        "enabled_rules": enabled,
    }


class _FakeTide(TideService):
    def __init__(self, stats_rows: list[dict]):
        self.enabled = True
        self.space = "default"
        self._stats_rows = stats_rows
        self.sent: list[str] = []

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        self.sent.append(sql)
        if "FROM mitre_techniques" in sql:
            return {"rows": list(_CATALOG)}
        if "GROUP BY t.technique_id, s.name, s.id" in sql:
            return {"rows": []}
        if "GROUP BY t.technique_id" in sql:
            return {"rows": list(self._stats_rows)}
        if "count(DISTINCT rule_id) as total" in sql:
            return {"rows": [{"total": 9}]}
        return {"rows": []}


@pytest.fixture
def coverage() -> dict:
    """T1059 has a running rule. T1021's rules are all off. T1486 has none."""
    return _FakeTide([
        _stats_row("T1059", rule_count=3, enabled=1),
        _stats_row("T1021", rule_count=2, enabled=0),
    ]).get_global_mitre_coverage()


# ---------------------------------------------------------------------------
# The control
# ---------------------------------------------------------------------------


def test_the_old_rule_count_test_and_the_new_one_disagree(coverage):
    """The fixture must actually exercise the bug, or nothing here is proven."""
    techs = coverage["techniques"]
    old = {tid for tid, i in techs.items() if i["rule_count"] > 0}
    new = {tid for tid, i in techs.items() if i["enabled_rules"] > 0}
    assert old - new == {"T1021"}, (
        "the fixture no longer contains a technique whose rules are all "
        "disabled, so every other test in this module is vacuous"
    )


# ---------------------------------------------------------------------------
# Three states, kept apart
# ---------------------------------------------------------------------------


def test_a_technique_with_only_disabled_rules_is_not_covered(coverage):
    assert coverage["covered_techniques"] == 1
    assert "T1021" not in coverage["blind_spots"]


def test_it_is_reported_as_inactive_rather_than_silently_dropped(coverage):
    """Not covered and not a blind spot still has to appear somewhere."""
    assert coverage["inactive_techniques"] == ["T1021"]


def test_a_technique_with_no_rules_at_all_stays_a_blind_spot(coverage):
    assert coverage["blind_spots"] == ["T1486"]
    assert "T1486" not in coverage["inactive_techniques"]


def test_inactive_and_blind_are_disjoint_and_cover_the_uncovered(coverage):
    inactive = set(coverage["inactive_techniques"])
    blind = set(coverage["blind_spots"])
    assert not inactive & blind
    assert len(inactive | blind) == (
        coverage["total_techniques"] - coverage["covered_techniques"]
    )


def test_the_basis_is_stated_not_inferred_from_the_name(coverage):
    assert coverage["coverage_basis"] == "at least one enabled rule"


def test_every_rule_enabled_means_nothing_is_inactive():
    cov = _FakeTide([
        _stats_row("T1059", rule_count=3, enabled=3),
        _stats_row("T1021", rule_count=2, enabled=2),
    ]).get_global_mitre_coverage()
    assert cov["covered_techniques"] == 2
    assert cov["inactive_techniques"] == []
    assert cov["blind_spots"] == ["T1486"]


def test_subtechnique_rollup_keeps_the_enabled_distinction():
    """A parent is covered if any of its subtechniques has a running rule."""
    cov = _FakeTide([
        _stats_row("T1059.001", rule_count=1, enabled=0),
        _stats_row("T1059.003", rule_count=1, enabled=1),
        _stats_row("T1021.001", rule_count=2, enabled=0),
    ]).get_global_mitre_coverage()
    assert "T1059" not in cov["inactive_techniques"]
    assert cov["inactive_techniques"] == ["T1021"]
    assert cov["covered_techniques"] == 1


# ---------------------------------------------------------------------------
# The three SQL sites
# ---------------------------------------------------------------------------


def test_the_per_system_coverage_join_filters_enabled():
    svc = _FakeTide([])
    svc.get_mitre_coverage("sys-1")
    joined = [s for s in svc.sent if "applied_detections" in s]
    assert joined, "expected a query against applied_detections"
    assert all("dr.enabled = 1" in s for s in joined), (
        "a rule applied to a system but switched off is not covering it"
    )


def test_the_gaps_analysis_filters_enabled():
    svc = _FakeTide([])
    svc.get_gaps_analysis()
    covered = [s for s in svc.sent
               if "SELECT DISTINCT t.technique_id" in s
               and "detection_rules dr" in s]
    assert covered, "expected the gaps analysis covered-technique query"
    assert all("dr.enabled = 1" in s for s in covered), (
        "total_blind_spots must not be flattered by disabled rules"
    )


def test_the_posture_stats_coverage_cte_filters_enabled():
    """This figure becomes SOC Health's technique_coverage_pct and its grade."""
    svc = _FakeTide([])
    svc.get_posture_stats()
    ctes = [s for s in svc.sent if "AS covered" in s]
    assert ctes, "expected the posture-stats coverage CTE"
    assert all("r.enabled = 1" in s for s in ctes)


# ---------------------------------------------------------------------------
# The compliance scorecard, where the docstring already promised enabled
# ---------------------------------------------------------------------------


class _StubCoverageService:
    """Only what _covered_techniques touches."""

    def __init__(self, techniques: dict):
        self.enabled = True
        self._techniques = techniques

    def get_global_mitre_coverage(self) -> dict:
        return {"techniques": self._techniques}


def test_compliance_counts_only_enabled_rules():
    covered = _covered_techniques(_StubCoverageService({
        "T1059": {"rule_count": 3, "enabled_rules": 1},
        "T1021": {"rule_count": 2, "enabled_rules": 0},
        "T1486": {"rule_count": 0, "enabled_rules": 0},
    }))
    assert covered == {"T1059"}


def test_compliance_treats_a_missing_enabled_count_as_not_covered():
    """Absent evidence of a running rule is not evidence of one."""
    covered = _covered_techniques(_StubCoverageService({
        "T1059": {"rule_count": 5},
    }))
    assert covered == set()


def test_compliance_survives_a_disabled_tide():
    assert _covered_techniques(None) == set()
