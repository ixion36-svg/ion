"""Tests for soc_health_service — the SOC health scorecard.

This module was at 0% when the coverage ratchet first measured the tree. It
is almost entirely arithmetic over other people's numbers, and its output is
a grade a SOC manager acts on, so the risk is not that it crashes but that it
scores something wrongly and nobody notices.

Two kinds of behaviour are pinned: the scoring curves at their boundaries,
and what each dimension does when the system it reads from is unavailable.
Those fallbacks differ on purpose — a missing TIDE scores 0 because coverage
genuinely is unknown, while a failed case query scores a neutral 50 rather
than branding a healthy SOC as failing.
"""

from __future__ import annotations

import httpx
import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services import soc_health_service as svc

# --- helpers ---------------------------------------------------------------

class _Tide:
    def __init__(self, posture=None, enabled=False, ok=False, raises=False):
        self._posture, self.enabled, self._ok, self._raises = posture, enabled, ok, raises

    def get_posture_stats(self):
        if self._raises:
            raise RuntimeError("TIDE down")
        return self._posture

    def test_connection(self):
        return {"ok": self._ok}


@pytest.fixture
def tide(monkeypatch):
    def _install(**kw):
        import ion.services.tide_service as ts
        monkeypatch.setattr(ts, "get_tide_service", lambda: _Tide(**kw))
    return _install


def _metrics(**kw):
    base = {
        "opened": 0, "closed": 0, "closure_rate_pct": 0.0,
        "fp_rate_of_closed": 0.0, "avg_mttr_hours": None, "mttr_sample_size": 0,
    }
    base.update(kw)
    return base


def _user(session, name, active=True):
    u = User(username=name, email=f"{name}@example.com", password_hash="x",
             is_active=active)
    session.add(u)
    session.flush()
    return u


def _case(session, creator, number, status=AlertCaseStatus.OPEN):
    c = AlertCase(case_number=number, title="t", status=status,
                  created_by_id=creator.id)
    session.add(c)
    session.flush()
    return c


# --- pure helpers ----------------------------------------------------------

class TestWeightsAndGrading:
    def test_the_weights_sum_to_one(self):
        """If they drift, every overall score is quietly wrong."""
        assert sum(svc.WEIGHTS.values()) == pytest.approx(1.0)

    @pytest.mark.parametrize("value,expected", [
        (-20, 0), (0, 0), (50.7, 50), (100, 100), (250, 100),
    ])
    def test_clamp_bounds_and_truncates(self, value, expected):
        assert svc._clamp(value) == expected

    @pytest.mark.parametrize("score,grade", [
        (100, "A"), (80, "A"), (79, "B"), (65, "B"), (64, "C"),
        (50, "C"), (49, "D"), (35, "D"), (34, "F"), (0, "F"),
    ])
    def test_grade_boundaries(self, score, grade):
        assert svc._grade(score) == grade

    @pytest.mark.parametrize("score,label", [
        (80, "Excellent"), (65, "Good"), (50, "Fair"),
        (35, "Needs Improvement"), (34, "Critical"),
    ])
    def test_label_boundaries(self, score, label):
        assert svc._label(score) == label


# --- detection coverage ----------------------------------------------------

class TestDetectionCoverage:
    def test_no_posture_stats_scores_zero(self, tide):
        """Unknown coverage is scored as none, not as neutral."""
        tide(posture=None)
        out = svc._detection_coverage()
        assert out["score"] == 0
        assert out["details"]["tide_available"] is False

    def test_a_tide_failure_scores_zero_without_raising(self, tide):
        tide(raises=True)
        assert svc._detection_coverage()["score"] == 0

    def test_full_coverage_and_quality_scores_one_hundred(self, tide):
        tide(posture={"total_techniques": 100, "covered_techniques": 100,
                      "quality": {"avg_quality": 40}})
        out = svc._detection_coverage()
        assert out["score"] == 100
        assert out["details"]["technique_coverage_pct"] == 100.0
        assert out["details"]["rule_quality_pct"] == 100.0

    def test_coverage_is_weighted_sixty_forty_against_quality(self, tide):
        """50% of techniques at full quality: 50*0.6 + 100*0.4 = 70."""
        tide(posture={"total_techniques": 100, "covered_techniques": 50,
                      "quality": {"avg_quality": 40}})
        assert svc._detection_coverage()["score"] == 70

    def test_zero_techniques_does_not_divide_by_zero(self, tide):
        tide(posture={"total_techniques": 0, "covered_techniques": 0,
                      "quality": {"avg_quality": 0}})
        assert svc._detection_coverage()["score"] == 0

    def test_a_null_quality_is_treated_as_zero(self, tide):
        tide(posture={"total_techniques": 10, "covered_techniques": 10,
                      "quality": {"avg_quality": None}})
        out = svc._detection_coverage()
        assert out["details"]["rule_quality_pct"] == 0
        assert out["score"] == 60


# --- operational efficiency ------------------------------------------------

class TestOperationalEfficiency:
    def test_no_cases_at_all_is_neutral(self, session, monkeypatch):
        """A quiet month is not a failing SOC."""
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics())
        assert svc._operational_efficiency(session)["score"] == 50

    def test_a_metrics_failure_is_neutral_rather_than_failing(self, session, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("db gone")
        monkeypatch.setattr(svc, "case_metrics", boom)
        assert svc._operational_efficiency(session)["score"] == 50

    def test_a_healthy_month_scores_high(self, session, monkeypatch):
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
            opened=100, closed=95, closure_rate_pct=95.0,
            fp_rate_of_closed=10.0, avg_mttr_hours=2.0, mttr_sample_size=95,
        ))
        out = svc._operational_efficiency(session)
        assert out["score"] >= 90
        assert out["details"]["cases_opened_30d"] == 100

    @pytest.mark.parametrize("mttr,expected_band", [
        (1.0, "fast"), (4.0, "fast"), (24.0, "slow"), (48.0, "slow"),
    ])
    def test_mttr_curve_saturates_at_both_ends(self, session, monkeypatch,
                                               mttr, expected_band):
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
            opened=10, closed=10, closure_rate_pct=100.0,
            fp_rate_of_closed=0.0, avg_mttr_hours=mttr, mttr_sample_size=10,
        ))
        score = svc._operational_efficiency(session)["score"]
        assert (score == 100) if expected_band == "fast" else (score < 100)

    def test_no_mttr_sample_is_neutral_for_that_component(self, session, monkeypatch):
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
            opened=10, closed=10, closure_rate_pct=100.0,
            fp_rate_of_closed=0.0, avg_mttr_hours=None, mttr_sample_size=0,
        ))
        out = svc._operational_efficiency(session)
        assert out["details"]["avg_mttr_hours"] is None
        assert out["score"] == 85  # 100*.4 + 100*.3 + 50*.3

    def test_a_high_false_positive_rate_drags_the_score_down(self, session, monkeypatch):
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
            opened=10, closed=10, closure_rate_pct=100.0,
            fp_rate_of_closed=60.0, avg_mttr_hours=1.0, mttr_sample_size=10,
        ))
        out = svc._operational_efficiency(session)
        assert out["details"]["fp_rate_pct"] == 60.0
        assert out["score"] == 70  # the FP component is zero

    def test_nothing_opened_treats_closure_rate_as_perfect(self, session, monkeypatch):
        """Closing a backlog with no new intake is not a 0% closure rate."""
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
            opened=0, closed=5, closure_rate_pct=0.0,
            fp_rate_of_closed=0.0, avg_mttr_hours=1.0, mttr_sample_size=5,
        ))
        assert svc._operational_efficiency(session)["details"]["closure_rate_pct"] == 100


# --- team readiness --------------------------------------------------------

class TestTeamReadiness:
    def test_no_active_analysts_scores_zero(self, session):
        assert svc._team_readiness(session)["score"] == 0

    def test_inactive_users_do_not_count(self, session):
        _user(session, "gone", active=False)
        assert svc._team_readiness(session)["details"]["active_analysts"] == 0

    def test_a_small_team_with_no_load_is_capped_by_team_size(self, session):
        """One analyst, no cases: load is perfect but the team is a bus factor."""
        _user(session, "solo")
        out = svc._team_readiness(session)
        assert out["details"]["cases_per_analyst"] == 0.0
        assert out["score"] == 76  # 100*0.6 + 40*0.4

    def test_three_analysts_remove_the_team_size_penalty(self, session):
        for n in ("a", "b", "c"):
            _user(session, n)
        assert svc._team_readiness(session)["score"] == 100

    def test_two_analysts_sit_between(self, session):
        _user(session, "a")
        _user(session, "b")
        assert svc._team_readiness(session)["score"] == 88  # 100*0.6 + 70*0.4

    def test_a_heavy_case_load_drags_the_score_down(self, session):
        u = _user(session, "solo")
        for i in range(30):
            _case(session, u, f"C{i}")
        out = svc._team_readiness(session)
        assert out["details"]["cases_per_analyst"] == 30.0
        assert out["score"] == 16  # load 0, size 40 -> 0*0.6 + 40*0.4

    def test_closed_cases_are_not_counted_as_load(self, session):
        u = _user(session, "solo")
        _case(session, u, "C1", status=AlertCaseStatus.CLOSED)
        assert svc._team_readiness(session)["details"]["open_cases"] == 0


# --- knowledge completeness ------------------------------------------------

class TestKnowledgeCompleteness:
    def test_an_empty_knowledge_base_scores_zero(self, session):
        out = svc._knowledge_completeness(session)
        assert out["score"] == 0
        assert out["details"]["target"] == 200

    def test_the_score_is_linear_to_the_target(self, session, monkeypatch):
        import ion.services.soc_health_service as mod

        class _Result:
            @staticmethod
            def scalar():
                return 100

        monkeypatch.setattr(session, "execute", lambda *a, **k: _Result())
        out = mod._knowledge_completeness(session)
        assert out["details"]["article_count"] == 100
        assert out["score"] == 50

    def test_exceeding_the_target_is_capped(self, session, monkeypatch):
        class _Result:
            @staticmethod
            def scalar():
                return 10_000

        monkeypatch.setattr(session, "execute", lambda *a, **k: _Result())
        assert svc._knowledge_completeness(session)["score"] == 100


# --- integration health ----------------------------------------------------

class TestIntegrationHealth:
    def test_nothing_configured_scores_zero(self, tide, monkeypatch):
        tide(enabled=False)
        monkeypatch.setattr(httpx, "get", lambda *a, **k: None)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: None)
        out = svc._integration_health()
        assert out["score"] == 0
        assert out["details"]["tide"]["configured"] is False

    def test_a_healthy_tide_contributes_its_share(self, tide, monkeypatch):
        tide(enabled=True, ok=True)
        monkeypatch.setattr(httpx, "get", lambda *a, **k: None)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: None)
        out = svc._integration_health()
        assert out["details"]["tide"] == {"configured": True, "healthy": True}
        assert out["score"] == 33

    def test_a_configured_but_unreachable_tide_scores_nothing(self, tide, monkeypatch):
        tide(enabled=True, ok=False)
        monkeypatch.setattr(httpx, "get", lambda *a, **k: None)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: None)
        out = svc._integration_health()
        assert out["details"]["tide"] == {"configured": True, "healthy": False}
        assert out["score"] == 0

    def test_one_integration_failing_does_not_stop_the_others(self, tide, monkeypatch):
        """Each probe is independent; a raising httpx must not zero the rest."""
        tide(enabled=True, ok=True)

        def boom(*a, **k):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx, "get", boom)
        monkeypatch.setattr(httpx, "post", boom)
        assert svc._integration_health()["score"] == 33


# --- recommendations -------------------------------------------------------

def _dims(**scores):
    out = {}
    for name in svc.WEIGHTS:
        out[name] = {"score": scores.get(name, 100), "details": {}}
    return out


class TestRecommendations:
    def test_a_healthy_scorecard_recommends_nothing(self):
        assert svc._build_recommendations(_dims()) == []

    def test_a_dimension_at_the_threshold_is_not_flagged(self):
        """60 is the cut-off; exactly 60 is acceptable."""
        assert svc._build_recommendations(_dims(team_readiness=60)) == []

    def test_a_missing_tide_is_called_out_before_coverage_numbers(self):
        dims = _dims(detection_coverage=0)
        dims["detection_coverage"]["details"] = {"tide_available": False}

        recs = svc._build_recommendations(dims)

        assert len(recs) == 1
        assert "TIDE integration is not configured" in recs[0]["message"]
        assert recs[0]["priority"] == "high"

    def test_low_coverage_and_low_quality_each_get_their_own_advice(self):
        dims = _dims(detection_coverage=10)
        dims["detection_coverage"]["details"] = {
            "tide_available": True, "technique_coverage_pct": 10,
            "rule_quality_pct": 10, "covered_techniques": 5,
            "total_techniques": 50, "avg_quality": 4,
        }

        recs = svc._build_recommendations(dims)

        assert len(recs) == 2
        assert "5 of 50 MITRE techniques" in recs[0]["message"]
        assert recs[1]["priority"] == "medium"

    def test_every_recommendation_carries_an_area_and_a_priority(self):
        dims = _dims(**{k: 0 for k in svc.WEIGHTS})
        for d in dims.values():
            d["details"] = {}

        recs = svc._build_recommendations(dims)

        assert recs, "a scorecard of zeroes must produce advice"
        for r in recs:
            assert set(r) == {"area", "message", "priority"}
            assert r["priority"] in {"high", "medium", "low"}


# --- the whole scorecard ---------------------------------------------------

class TestScorecard:
    def test_it_returns_every_dimension_and_a_grade(self, session, tide, monkeypatch):
        tide(posture=None, enabled=False)
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics())
        monkeypatch.setattr(httpx, "get", lambda *a, **k: None)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: None)

        card = svc.get_soc_health_scorecard(session)

        assert set(card) == {"overall_score", "grade", "dimensions", "recommendations"}
        assert set(card["dimensions"]) == set(svc.WEIGHTS)
        assert card["grade"] in {"A", "B", "C", "D", "F"}

    def test_the_overall_score_is_the_weighted_sum(self, session, tide, monkeypatch):
        tide(posture=None, enabled=False)
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics())
        monkeypatch.setattr(httpx, "get", lambda *a, **k: None)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: None)

        card = svc.get_soc_health_scorecard(session)
        expected = svc._clamp(sum(
            card["dimensions"][d]["score"] * w for d, w in svc.WEIGHTS.items()
        ))

        assert card["overall_score"] == expected

    def test_a_failing_scorecard_comes_with_advice(self, session, tide, monkeypatch):
        tide(posture=None, enabled=False)
        monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics())
        monkeypatch.setattr(httpx, "get", lambda *a, **k: None)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: None)

        card = svc.get_soc_health_scorecard(session)

        assert card["grade"] in {"D", "F"}
        assert card["recommendations"]


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


class TestElasticsearchProbe:
    """The ES leg of integration health, which needs config as well as a socket."""

    def _config(self, monkeypatch, *, enabled=True, url="http://es:9200", key="k"):
        import ion.core.config as cfg

        class _C:
            elasticsearch_enabled = enabled
            elasticsearch_url = url
            elasticsearch_api_key = key

        monkeypatch.setattr(cfg, "get_config", lambda: _C())
        monkeypatch.setattr(cfg, "get_ssl_verify", lambda: True)
        monkeypatch.setattr(cfg, "get_opencti_config", lambda: {"enabled": False})

    def test_a_reachable_cluster_contributes_its_share(self, tide, monkeypatch):
        tide(enabled=False)
        self._config(monkeypatch)
        monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp(200))

        out = svc._integration_health()

        assert out["details"]["elasticsearch"] == {"configured": True, "healthy": True}
        assert out["score"] == 33

    def test_a_non_200_counts_as_unhealthy(self, tide, monkeypatch):
        tide(enabled=False)
        self._config(monkeypatch)
        monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp(503))

        out = svc._integration_health()

        assert out["details"]["elasticsearch"] == {"configured": True, "healthy": False}
        assert out["score"] == 0

    def test_enabled_without_a_url_is_not_configured(self, tide, monkeypatch):
        tide(enabled=False)
        self._config(monkeypatch, url="")
        monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp(200))

        assert svc._integration_health()["details"]["elasticsearch"]["configured"] is False

    def test_no_api_key_still_probes(self, tide, monkeypatch):
        """An unauthenticated cluster is a valid deployment, not a crash."""
        tide(enabled=False)
        self._config(monkeypatch, key=None)
        monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp(200))

        assert svc._integration_health()["details"]["elasticsearch"]["healthy"] is True


class TestOpenCtiProbe:
    def _config(self, monkeypatch, octi):
        import ion.core.config as cfg

        class _C:
            elasticsearch_enabled = False
            elasticsearch_url = ""
            elasticsearch_api_key = None

        monkeypatch.setattr(cfg, "get_config", lambda: _C())
        monkeypatch.setattr(cfg, "get_ssl_verify", lambda: True)
        monkeypatch.setattr(cfg, "get_opencti_config", lambda: octi)

    def test_a_reachable_opencti_contributes_the_remainder(self, tide, monkeypatch):
        """TIDE and ES take 33 each; OpenCTI takes 34 so the three sum to 100."""
        tide(enabled=False)
        self._config(monkeypatch, {"enabled": True, "url": "http://octi",
                                   "token": "t", "verify_ssl": True})
        monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(200))

        out = svc._integration_health()

        assert out["details"]["opencti"] == {"configured": True, "healthy": True}
        assert out["score"] == 34

    def test_all_three_healthy_sums_to_one_hundred(self, tide, monkeypatch):
        tide(enabled=True, ok=True)
        import ion.core.config as cfg

        class _C:
            elasticsearch_enabled = True
            elasticsearch_url = "http://es:9200"
            elasticsearch_api_key = "k"

        monkeypatch.setattr(cfg, "get_config", lambda: _C())
        monkeypatch.setattr(cfg, "get_ssl_verify", lambda: True)
        monkeypatch.setattr(cfg, "get_opencti_config", lambda: {
            "enabled": True, "url": "http://octi", "token": "t", "verify_ssl": True})
        monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp(200))
        monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(200))

        assert svc._integration_health()["score"] == 100

    def test_verify_ssl_false_is_honoured_without_error(self, tide, monkeypatch):
        tide(enabled=False)
        self._config(monkeypatch, {"enabled": True, "url": "http://octi",
                                   "token": "t", "verify_ssl": False})
        seen = {}

        def post(*a, **k):
            seen["verify"] = k.get("verify")
            return _Resp(200)

        monkeypatch.setattr(httpx, "post", post)
        svc._integration_health()

        assert seen["verify"] is False


class TestRemainingRecommendations:
    def test_poor_operations_produce_three_distinct_pieces_of_advice(self):
        dims = _dims(operational_efficiency=10)
        dims["operational_efficiency"]["details"] = {
            "closure_rate_pct": 40, "fp_rate_pct": 55, "avg_mttr_hours": 30,
        }

        recs = svc._build_recommendations(dims)

        assert len(recs) == 3
        assert {r["priority"] for r in recs} == {"high", "medium"}

    def test_a_fast_mttr_produces_no_mttr_advice(self, ):
        dims = _dims(operational_efficiency=10)
        dims["operational_efficiency"]["details"] = {
            "closure_rate_pct": 95, "fp_rate_pct": 5, "avg_mttr_hours": 2,
        }
        assert svc._build_recommendations(dims) == []

    def test_a_missing_mttr_produces_no_mttr_advice(self):
        dims = _dims(operational_efficiency=10)
        dims["operational_efficiency"]["details"] = {
            "closure_rate_pct": 95, "fp_rate_pct": 5, "avg_mttr_hours": None,
        }
        assert svc._build_recommendations(dims) == []

    def test_a_thin_and_overloaded_team_gets_both_warnings(self):
        dims = _dims(team_readiness=10)
        dims["team_readiness"]["details"] = {
            "active_analysts": 1, "cases_per_analyst": 25.0,
        }

        recs = svc._build_recommendations(dims)

        assert len(recs) == 2
        assert "1 active analyst" in recs[0]["message"]
        assert "25.0 open cases each" in recs[1]["message"]

    def test_a_thin_knowledge_base_is_called_out_with_its_numbers(self):
        dims = _dims(knowledge_completeness=10)
        dims["knowledge_completeness"]["details"] = {"article_count": 12, "target": 200}

        recs = svc._build_recommendations(dims)

        assert len(recs) == 1
        assert "12 articles" in recs[0]["message"]
        assert "target: 200" in recs[0]["message"]

    def test_unconfigured_and_broken_integrations_are_worded_differently(self):
        dims = _dims(integration_health=0)
        dims["integration_health"]["details"] = {
            "tide": {"configured": False, "healthy": False},
            "elasticsearch": {"configured": True, "healthy": False},
            "opencti": {"configured": True, "healthy": True},
        }

        recs = svc._build_recommendations(dims)

        assert len(recs) == 2
        assert "TIDE is not configured" in recs[0]["message"]
        assert recs[0]["priority"] == "medium"
        assert "configured but not responding" in recs[1]["message"]
        assert recs[1]["priority"] == "high"


def test_a_team_readiness_failure_scores_zero(session, monkeypatch):
    """A broken query must not read as a healthy team."""
    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(session, "execute", boom)
    assert svc._team_readiness(session)["score"] == 0


def test_a_knowledge_query_failure_scores_zero(session, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(session, "execute", boom)
    assert svc._knowledge_completeness(session)["score"] == 0


def test_a_null_mttr_with_a_sample_is_neutral(session, monkeypatch):
    """mttr_sample_size says there was data; a None average is still neutral."""
    monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
        opened=10, closed=10, closure_rate_pct=100.0,
        fp_rate_of_closed=0.0, avg_mttr_hours=None, mttr_sample_size=10,
    ))
    assert svc._operational_efficiency(session)["score"] == 85


class TestProbeFailuresAreContained:
    """Each integration probe swallows its own failure independently."""

    def _cfg(self, monkeypatch, *, es=False, octi=False):
        import ion.core.config as cfg

        class _C:
            elasticsearch_enabled = es
            elasticsearch_url = "http://es:9200" if es else ""
            elasticsearch_api_key = "k"

        monkeypatch.setattr(cfg, "get_config", lambda: _C())
        monkeypatch.setattr(cfg, "get_ssl_verify", lambda: True)
        monkeypatch.setattr(cfg, "get_opencti_config", lambda: (
            {"enabled": True, "url": "http://octi", "token": "t", "verify_ssl": True}
            if octi else {"enabled": False}
        ))

    def test_a_raising_tide_probe_is_contained(self, monkeypatch):
        import ion.services.tide_service as ts

        def boom():
            raise RuntimeError("tide exploded")

        monkeypatch.setattr(ts, "get_tide_service", boom)
        self._cfg(monkeypatch)

        out = svc._integration_health()

        assert out["score"] == 0
        assert out["details"]["tide"] == {"configured": False, "healthy": False}

    def test_a_raising_elasticsearch_probe_is_contained(self, tide, monkeypatch):
        tide(enabled=False)
        self._cfg(monkeypatch, es=True)

        def boom(*a, **k):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx, "get", boom)

        out = svc._integration_health()

        assert out["score"] == 0
        assert out["details"]["elasticsearch"]["configured"] is True
        assert out["details"]["elasticsearch"]["healthy"] is False

    def test_a_raising_opencti_probe_is_contained(self, tide, monkeypatch):
        tide(enabled=False)
        self._cfg(monkeypatch, octi=True)

        def boom(*a, **k):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx, "post", boom)

        out = svc._integration_health()

        assert out["score"] == 0
        assert out["details"]["opencti"]["healthy"] is False


def test_mttr_interpolates_between_four_and_twenty_four_hours(session, monkeypatch):
    """14h is the midpoint of the 4-24h ramp, so the MTTR component is 50."""
    monkeypatch.setattr(svc, "case_metrics", lambda *a, **k: _metrics(
        opened=10, closed=10, closure_rate_pct=100.0,
        fp_rate_of_closed=0.0, avg_mttr_hours=14.0, mttr_sample_size=10,
    ))
    # 100*0.4 (closure) + 100*0.3 (fp) + 50*0.3 (mttr) = 85
    assert svc._operational_efficiency(session)["score"] == 85


def test_case_load_interpolates_between_ten_and_thirty(session):
    """20 cases per analyst is the midpoint of the 10-30 ramp: load component 50."""
    users = [_user(session, n) for n in ("a", "b", "c")]
    for i in range(60):  # 60 open cases across 3 analysts = 20 each
        _case(session, users[0], f"C{i}")

    out = svc._team_readiness(session)

    assert out["details"]["cases_per_analyst"] == 20.0
    # load 50 * 0.6 + size 100 * 0.4 = 70
    assert out["score"] == 70
