"""An uncounted ATT&CK catalogue is not a catalogue of nothing.

TIDE 6 moved ATT&CK, NIST and Sigma into a shared reference database attached
as `ref`, and dropped the per-tenant copies so they cannot shadow it. The
external query API's allow-list is built from `duckdb_tables() WHERE
database_name = current_database()`, which is the tenant, so
`FROM mitre_techniques` is refused in every form: bare, `ref.` and
`ref.main.`. ATTACH and SET are both blocklisted, so ION cannot reach it.
Verified against sigeauk/tide 6.0.2 on 2026-10-12 by reproducing the guard.

That makes an absent technique total the ORDINARY case against a current
TIDE, not an edge case, which is what made the old handling dangerous:

  * get_posture_stats asked for the technique count and the system count in
    one statement, so the refusal also destroyed the system count, which is
    perfectly readable. They are now separate queries.
  * A missing count defaulted to 0. _detection_coverage then took its
    `else 0` branch and published technique_coverage_pct = 0.0 next to
    tide_available = True. With rule quality weighted at 40% the dimension
    graded F, and nothing said the count had been refused. A query nobody
    answered was being reported as coverage of nothing.

So the rule this module pins: no denominator, no percentage, and say why.
"""
from __future__ import annotations

from typing import Any, Optional

import pytest

from ion.services.tide_service import TideService


class _FakeTide(TideService):
    """Hand-written, per test_de_tide_api's reasoning: a Mock answers every
    shape alike, and the shape of the refusal is the thing under test."""

    def __init__(self, *, refuse: tuple[str, ...] = ()):
        self.enabled = True
        self.space = "default"
        self.refuse = refuse
        self.sent: list[str] = []

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        self.sent.append(sql)
        for needle in self.refuse:
            if needle in sql:
                return None  # what _query returns for a 4xx from TIDE
        if "FROM mitre_techniques" in sql:
            return {"rows": [{"total_techniques": 918}]}
        if "FROM systems" in sql:
            return {"rows": [{"total_systems": 4}]}
        if "AS covered" in sql or "total_rules" in sql:
            return {"rows": [{
                "total_rules": 1859, "enabled_rules": 224, "disabled_rules": 1635,
                "unmapped_rules": 12, "q_excellent": 27, "q_good": 33,
                "q_fair": 52, "q_poor": 1747, "avg_quality": 1.9,
                "min_quality": 0, "max_quality": 53,
                "covered_techniques": 94, "severity_json": "[]",
            }]}
        return {"rows": []}


# ---------------------------------------------------------------------------
# The split: one refusal must not take a readable figure with it
# ---------------------------------------------------------------------------


def test_the_two_counts_are_asked_for_separately():
    """Pre-fix they shared a statement, so a refused technique count also
    zeroed the system count. This is the control for that regression."""
    svc = _FakeTide()
    svc.get_posture_stats()
    combined = [s for s in svc.sent
                if "FROM mitre_techniques" in s and "FROM systems" in s]
    assert not combined, (
        "the technique and system counts are back in one statement, so a "
        "refusal of the first destroys the second"
    )


def test_a_refused_technique_count_leaves_the_system_count_intact():
    svc = _FakeTide(refuse=("FROM mitre_techniques",))
    stats = svc.get_posture_stats()
    assert stats["total_techniques"] is None
    assert stats["total_systems"] == 4


def test_a_served_technique_count_comes_through():
    stats = _FakeTide().get_posture_stats()
    assert stats["total_techniques"] == 918
    assert stats["total_systems"] == 4


def test_a_refused_count_is_none_not_zero():
    """Zero is a measurement. None is the absence of one."""
    stats = _FakeTide(refuse=("FROM mitre_techniques",)).get_posture_stats()
    assert stats["total_techniques"] is not None or True  # readability
    assert stats["total_techniques"] is None
    assert stats["total_techniques"] != 0


# ---------------------------------------------------------------------------
# SOC Health: no denominator, no grade
# ---------------------------------------------------------------------------


def _coverage(stats: dict) -> dict:
    """Run _detection_coverage against a stubbed posture.

    _detection_coverage imports get_tide_service from ion.services.tide_service
    inside the function, so the patch target is there rather than on
    soc_health_service, matching tests/test_soc_health_unmeasured.py.
    """
    from unittest.mock import patch

    from ion.services import soc_health_service as shs

    class _Stub:
        enabled = True

        def get_posture_stats(self):
            return stats

    with patch("ion.services.tide_service.get_tide_service",
               return_value=_Stub()):
        return shs._detection_coverage()


_FULL = {
    "total_rules": 1859, "enabled_rules": 224, "disabled_rules": 1635,
    "covered_techniques": 94, "total_systems": 4,
    "quality": {"avg_quality": 1.9},
}


def test_an_uncounted_catalogue_is_unavailable_not_zero_percent():
    result = _coverage({**_FULL, "total_techniques": None})
    assert result["score"] is None
    assert result["label"] == "Unavailable"
    # Present and None, not absent. A consumer calling .get() on a missing
    # key supplies its own default, and the defaults in this codebase were
    # the problem: `.get("technique_coverage_pct", 0)` is what published a
    # confident zero. None travels; an absent key invites a 0.
    assert result["details"]["technique_coverage_pct"] is None
    assert result["details"]["total_techniques"] is None


def test_the_reason_names_the_cause_and_is_not_generic():
    result = _coverage({**_FULL, "total_techniques": None})
    reason = (result["details"].get("reason") or "").lower()
    assert "denominator" in reason or "technique count" in reason
    assert "reference database" in reason, (
        "a reader needs to know TIDE will not serve it, not just that it "
        "is missing"
    )


def test_a_zero_total_is_also_refused_as_a_denominator():
    """DuckDB cannot return 0 techniques for a catalogue that exists, so a
    zero here means the same thing a None does."""
    result = _coverage({**_FULL, "total_techniques": 0})
    assert result["score"] is None
    assert result["label"] == "Unavailable"


def test_a_real_total_still_scores():
    result = _coverage({**_FULL, "total_techniques": 918})
    assert result["score"] is not None
    assert result["details"]["technique_coverage_pct"] == pytest.approx(
        94 / 918 * 100, abs=0.1
    )


def test_the_old_behaviour_would_have_graded_this():
    """The control. With total 0 the previous code computed 0% coverage and
    scored the dimension from rule quality alone, which on the live tenant
    (avg_quality 1.9 of 40) grades F. If this ever scores again, the
    regression is back."""
    result = _coverage({**_FULL, "total_techniques": 0})
    assert result["score"] is None, (
        "a refused technique count is being graded again"
    )


def _all_dimensions(detection_details: dict, score=50) -> dict:
    """_build_recommendations walks every dimension, so a partial dict raises
    KeyError on the next one. Only detection_coverage varies here."""
    filler = {"score": 80, "details": {}}
    return {
        "detection_coverage": {"score": score, "details": detection_details},
        "operational_efficiency": dict(filler),
        "team_readiness": dict(filler),
        "knowledge_completeness": dict(filler),
        "integration_health": dict(filler),
    }


# ---------------------------------------------------------------------------
# Rule quality: an absent modifier is not a zero one
# ---------------------------------------------------------------------------


def test_absent_quality_scores_on_coverage_alone_and_says_so():
    """`or 0` made "TIDE returned no quality figure" identical to "the rules
    average zero". Only one of those is a measurement."""
    result = _coverage({**_FULL, "total_techniques": 100,
                        "covered_techniques": 50, "quality": {}})
    assert result["score"] is not None, (
        "coverage is known, so the dimension is not unavailable"
    )
    assert result["details"]["rule_quality_pct"] is None
    assert result["details"]["score_basis"] == "technique coverage only"
    # 50 of 100 covered, scored on coverage alone rather than 50*0.6 + 0*0.4.
    assert result["score"] == 50


def test_a_measured_zero_quality_still_counts_against_the_score():
    """The distinction has to cut both ways: a real zero is a real result."""
    result = _coverage({**_FULL, "total_techniques": 100,
                        "covered_techniques": 50,
                        "quality": {"avg_quality": 0}})
    assert result["details"]["rule_quality_pct"] == 0
    assert result["details"]["score_basis"] == "technique coverage and rule quality"
    assert result["score"] == 30  # 50*0.6 + 0*0.4


def test_absent_quality_does_not_advise_tuning_rules():
    """Advising rule tuning from a figure TIDE never returned is the same
    defect in the recommendation layer."""
    from ion.services.soc_health_service import _build_recommendations

    recs = _build_recommendations(_all_dimensions({
        "tide_available": True, "technique_coverage_pct": 50,
        "rule_quality_pct": None, "avg_quality": None,
        "total_techniques": 100, "covered_techniques": 50,
    }))
    messages = " ".join(r["message"] for r in recs).lower()
    assert "tune low-quality rules" not in messages
    assert any(r.get("priority") == "visibility" for r in recs), (
        "an excluded half of a dimension has to be visible somewhere"
    )


def test_a_none_quality_does_not_raise_in_the_recommendation_gate():
    """`details.get("rule_quality_pct", 0) < 50` would be None < 50, which is
    a TypeError in Python 3, so this was a latent crash as well."""
    from ion.services.soc_health_service import _build_recommendations

    _build_recommendations(_all_dimensions({
        "tide_available": True, "technique_coverage_pct": None,
        "rule_quality_pct": None, "avg_quality": None,
        "total_techniques": None, "covered_techniques": None,
    }, score=None))
