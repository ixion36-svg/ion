"""Metric definitions must match their labels (review 2026-10-08, §18).

Three scores claimed more than they measured.

**Knowledge completeness** divided a count of ``KnowledgeArticle`` rows by
a target of 200 "articles". But ``KnowledgeArticle`` is one row per SOC
capability area carrying a ``doc_status``, with a unique constraint on
``capability_key`` — there are 91 capabilities in the catalogue, and the
server seeds all of them as ``undocumented`` at startup. So a fresh
install with no documentation at all scored 45/100, and the dimension
could never exceed 46 however well documented the SOC was. The count was
of *placeholders*, not of written knowledge.

**Team readiness** counted rows in ``users`` where ``is_active``, and
open cases per head. An active account is not a verified, on-duty
analyst: the workforce module already tracks who has reached the
operational stage of a role journey, and that is the number this score
was claiming to use.

**Compliance scoring** returned the fraction of a framework's mapped
MITRE techniques that have at least one detection rule, under the name
``overall_score`` on a "compliance posture" scorecard. Detection coverage
is evidence toward a control, not an implemented or independently
reviewed one. Controls with no mapped techniques also contributed a
hard 0 to the mean while being labelled ``unknown``, so unmappable
controls silently depressed the score.

The contract these tests pin: a score states its definition, its
denominator and whether it is an estimate; an unavailable input reads as
unavailable rather than zero; and detection coverage is never presented
as compliance.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.skills import KnowledgeArticle
from ion.models.user import User
from ion.services import compliance_mapping_service as compliance
from ion.services import soc_health_service as health


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(
        f"sqlite:///{tmp_path / 'review_metrics.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()


def _capability(db, key: str, *, doc_status="undocumented",
                runbooks=False, procedures=False):
    db.add(KnowledgeArticle(
        capability_key=key,
        doc_status=doc_status,
        has_runbooks=runbooks,
        has_procedures=procedures,
    ))
    db.flush()


# ── Knowledge completeness ────────────────────────────────────────────────


class TestKnowledgeCompleteness:
    def test_all_undocumented_scores_zero_not_forty_five(self, db):
        """The headline bug: seeded placeholders used to score ~45/100."""
        for i in range(91):
            _capability(db, f"cap_{i}")
        db.commit()

        result = health._knowledge_completeness(db)
        assert result["score"] == 0, result

    def test_fully_documented_can_reach_one_hundred(self, db):
        for i in range(20):
            _capability(db, f"cap_{i}", doc_status="comprehensive",
                        runbooks=True, procedures=True)
        db.commit()

        result = health._knowledge_completeness(db)
        assert result["score"] == 100, result

    def test_partial_documentation_scores_between(self, db):
        for i in range(10):
            _capability(db, f"cap_{i}", doc_status="comprehensive",
                        runbooks=True, procedures=True)
        for i in range(10, 20):
            _capability(db, f"cap_{i}")
        db.commit()

        result = health._knowledge_completeness(db)
        assert 40 <= result["score"] <= 60, result

    def test_basic_counts_for_less_than_comprehensive(self, db):
        for i in range(10):
            _capability(db, f"cap_{i}", doc_status="basic")
        db.commit()
        basic = health._knowledge_completeness(db)["score"]

        for row in db.query(KnowledgeArticle).all():
            row.doc_status = "comprehensive"
        db.commit()
        comprehensive = health._knowledge_completeness(db)["score"]

        assert 0 < basic < comprehensive

    def test_denominator_is_the_capability_count_not_two_hundred(self, db):
        for i in range(7):
            _capability(db, f"cap_{i}")
        db.commit()

        details = health._knowledge_completeness(db)["details"]
        assert details["capabilities_tracked"] == 7
        assert details.get("target") != 200

    def test_definition_is_stated(self, db):
        _capability(db, "cap_0")
        db.commit()
        details = health._knowledge_completeness(db)["details"]
        assert details.get("definition"), "the score must say what it measures"

    def test_status_breakdown_is_available_for_drill_down(self, db):
        _capability(db, "a", doc_status="comprehensive")
        _capability(db, "b", doc_status="basic")
        _capability(db, "c")
        db.commit()

        details = health._knowledge_completeness(db)["details"]
        assert details["by_doc_status"]["comprehensive"] == 1
        assert details["by_doc_status"]["basic"] == 1
        assert details["by_doc_status"]["undocumented"] == 1

    def test_no_capabilities_reads_as_unavailable_not_zero(self, db):
        result = health._knowledge_completeness(db)
        assert result["details"]["available"] is False
        assert result["score"] is None or result["label"].lower() in (
            "unavailable", "not assessed", "no data"
        )


# ── Team readiness ────────────────────────────────────────────────────────


class TestTeamReadiness:
    def test_active_account_fallback_is_labelled_an_estimate(self, db):
        for i in range(1, 4):
            db.add(User(id=i, username=f"u{i}", email=f"u{i}@x",
                        password_hash="x", display_name=f"U{i}", is_active=True))
        db.commit()

        details = health._team_readiness(db)["details"]
        # No role journeys exist, so this can only be an account count.
        assert details["capacity_source"] == "active_accounts"
        assert details["estimated"] is True

    def test_definition_names_what_was_counted(self, db):
        db.add(User(id=1, username="u1", email="u1@x", password_hash="x",
                    display_name="U1", is_active=True))
        db.commit()
        details = health._team_readiness(db)["details"]
        assert details.get("definition")
        assert "account" in details["definition"].lower()

    def test_verified_capacity_is_preferred_when_journeys_exist(self, db, monkeypatch):
        for i in range(1, 6):
            db.add(User(id=i, username=f"u{i}", email=f"u{i}@x",
                        password_hash="x", display_name=f"U{i}", is_active=True))
        db.commit()

        # Two people verified operational, against five accounts.
        monkeypatch.setattr(
            health, "_verified_operational_headcount", lambda _s: 2, raising=False
        )
        details = health._team_readiness(db)["details"]
        assert details["capacity_source"] == "verified_journeys"
        assert details["estimated"] is False
        assert details["analyst_capacity"] == 2

    def test_no_people_at_all_is_not_a_silent_zero_score(self, db):
        result = health._team_readiness(db)
        assert result["details"]["available"] is False


# ── Compliance scoring ────────────────────────────────────────────────────


class _FakeTide:
    enabled = True

    def __init__(self, covered):
        self._covered = covered

    def get_global_mitre_coverage(self):
        return {"techniques": {t: {"rule_count": 1} for t in self._covered}}


class TestComplianceLabelling:
    def test_posture_states_it_measures_detection_coverage(self):
        posture = compliance.get_compliance_posture(
            _FakeTide({"T1059", "T1078"}), "nist_csf"
        )
        assert posture["measure"] == "detection_coverage"
        assert posture["detection_coverage_score"] == posture["overall_score"]

    def test_posture_says_what_it_does_not_measure(self):
        posture = compliance.get_compliance_posture(
            _FakeTide({"T1059"}), "nist_csf"
        )
        text = " ".join(posture["does_not_measure"]).lower()
        assert "implement" in text
        assert "effective" in text

    def test_unmappable_controls_do_not_depress_the_score(self):
        """A control with no mapped techniques must not count as a zero."""
        framework = {
            "id": "test_fw",
            "name": "Test Framework",
            "version": "1.0",
            "url": "https://example.invalid",
            "controls": [
                {"id": "C1", "name": "Mapped", "techniques": ["T1059"]},
                {"id": "C2", "name": "Unmappable", "techniques": []},
            ],
        }
        scored = compliance._score_framework(framework, {"T1059"})

        # C1 is fully covered; C2 cannot be assessed and is excluded.
        assert scored["overall_score"] == 100
        assert scored["summary"]["not_assessable"] == 1
        assert scored["summary"]["scored_controls"] == 1

    def test_summary_counts_add_up_to_the_control_total(self):
        framework = {
            "id": "test_fw",
            "name": "Test Framework",
            "version": "1.0",
            "url": "https://example.invalid",
            "controls": [
                {"id": "C1", "name": "Covered", "techniques": ["T1059"]},
                {"id": "C2", "name": "Partial", "techniques": ["T1059", "T1078"]},
                {"id": "C3", "name": "Blind", "techniques": ["T1486"]},
                {"id": "C4", "name": "Unmappable", "techniques": []},
            ],
        }
        s = compliance._score_framework(framework, {"T1059"})["summary"]
        total = (s["fully_covered"] + s["partial"] + s["no_coverage"]
                 + s["not_assessable"])
        assert total == s["total_controls"] == 4

    def test_all_controls_unmappable_reads_as_unavailable(self):
        framework = {
            "id": "test_fw",
            "name": "Test Framework",
            "version": "1.0",
            "url": "https://example.invalid",
            "controls": [{"id": "C1", "name": "Unmappable", "techniques": []}],
        }
        scored = compliance._score_framework(framework, {"T1059"})
        assert scored["overall_score"] is None
        assert scored["summary"]["scored_controls"] == 0

    def test_tide_unavailable_is_distinct_from_zero_coverage(self):
        class _Off:
            enabled = False

        result = compliance.get_compliance_posture(_Off(), "nist_csf")
        assert "error" in result
        assert result.get("overall_score") is None
