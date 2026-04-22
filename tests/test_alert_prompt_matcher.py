"""Tests for AlertPromptRepository.find_matching tiered matcher.

Tier precedence: exact rule_id > regex > MITRE technique (parent<->sub
tolerant) > MITRE tactic > rule.groups overlap. Tier-1 always wins over
Tier-N (N>1) regardless of priority.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.alert_prompt import AlertPromptTemplate  # noqa: F401 — registers table
from ion.models.user import User  # noqa: F401 — FK target
from ion.storage.alert_prompt_repository import (
    AlertPromptRepository,
    _techniques_overlap,
)


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'matcher.db'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    yield s
    s.close()


def _make(repo, **kwargs):
    defaults = {
        "name": kwargs.pop("name"),
        "prompt_text": "PROMPT",
        "priority": kwargs.pop("priority", 100),
    }
    defaults.update(kwargs)
    return repo.create(**defaults)


# ---------------------------------------------------------------------------
# Parent<->sub technique helper
# ---------------------------------------------------------------------------


class TestTechniquesOverlap:
    def test_exact_match(self):
        assert _techniques_overlap(["T1059"], ["T1059"])

    def test_parent_matches_sub(self):
        # Template has parent; alert has sub-technique
        assert _techniques_overlap(["T1059.001"], ["T1059"])

    def test_sub_matches_parent(self):
        # Template has sub; alert has parent
        assert _techniques_overlap(["T1059"], ["T1059.001"])

    def test_different_parents_do_not_match(self):
        assert not _techniques_overlap(["T1110"], ["T1059"])

    def test_empty_inputs(self):
        assert not _techniques_overlap([], ["T1059"])
        assert not _techniques_overlap(["T1059"], [])


# ---------------------------------------------------------------------------
# Matcher tier precedence
# ---------------------------------------------------------------------------


class TestFindMatching:
    def test_exact_rule_id_beats_technique(self, session):
        repo = AlertPromptRepository(session)
        # Higher-numbered priority (= lower precedence) but Tier-1 exact match
        t_exact = _make(repo, name="exact", rule_ids=["alert-42"], priority=500)
        # Tier-3 technique candidate with better priority
        _make(repo, name="tech", mitre_techniques=["T1059"], priority=1)
        session.flush()

        alert = {
            "rule_id": "alert-42",
            "rule": {"mitre": {"id": ["T1059.001"]}},
        }
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t_exact.name

    def test_regex_beats_technique(self, session):
        repo = AlertPromptRepository(session)
        t_regex = _make(
            repo,
            name="regex",
            rule_id_pattern=r"(?i)cobalt.?strike",
            priority=500,
        )
        _make(repo, name="tech", mitre_techniques=["T1059"], priority=1)
        session.flush()

        alert = {"rule_id": "cobalt-strike-beacon",
                 "rule": {"mitre": {"id": ["T1059"]}}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t_regex.name

    def test_technique_parent_to_sub(self, session):
        """Template T1059 should match alert tagged T1059.001."""
        repo = AlertPromptRepository(session)
        t = _make(repo, name="parent_tech", mitre_techniques=["T1059"])
        session.flush()

        alert = {"rule": {"mitre": {"id": ["T1059.001"]}}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t.name

    def test_technique_sub_to_parent(self, session):
        """Template T1059.001 should match alert tagged T1059."""
        repo = AlertPromptRepository(session)
        t = _make(repo, name="sub_tech", mitre_techniques=["T1059.001"])
        session.flush()

        alert = {"rule": {"mitre": {"id": ["T1059"]}}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t.name

    def test_technique_beats_tactic(self, session):
        repo = AlertPromptRepository(session)
        t_tech = _make(
            repo, name="tech_only", mitre_techniques=["T1059"], priority=500
        )
        _make(repo, name="tactic_only", mitre_tactics=["TA0002"], priority=1)
        session.flush()

        alert = {"rule": {"mitre": {"id": ["T1059"], "tactic": ["execution"]}}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t_tech.name

    def test_tactic_beats_groups(self, session):
        repo = AlertPromptRepository(session)
        t_tac = _make(
            repo, name="tactic_only", mitre_tactics=["TA0002"], priority=500
        )
        _make(repo, name="groups_only", rule_groups=["sysmon_event_1"], priority=1)
        session.flush()

        alert = {
            "rule": {
                "mitre": {"tactic": ["TA0002"]},
                "groups": ["sysmon_event_1"],
            }
        }
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t_tac.name

    def test_tactic_name_matches_tactic_id_case_insensitive(self, session):
        repo = AlertPromptRepository(session)
        t = _make(repo, name="tac_name", mitre_tactics=["Execution"])
        session.flush()

        # Alert uses the lowercase tactic name; templates were stored as
        # "Execution". Matcher should lowercase both sides.
        alert = {"rule": {"mitre": {"tactic": ["execution"]}}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t.name

    def test_groups_overlap_fallback(self, session):
        repo = AlertPromptRepository(session)
        t = _make(repo, name="grp", rule_groups=["sysmon_event_1"])
        session.flush()

        alert = {"rule": {"id": "unused", "groups": ["sysmon_event_1"]}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == t.name

    def test_priority_tiebreak_within_tier(self, session):
        repo = AlertPromptRepository(session)
        _make(repo, name="low_priority", rule_groups=["sysmon_event_1"], priority=500)
        winner = _make(
            repo, name="high_priority", rule_groups=["sysmon_event_1"], priority=1
        )
        session.flush()

        alert = {"rule": {"groups": ["sysmon_event_1"]}}
        match = repo.find_matching(alert)
        assert match is not None
        assert match.name == winner.name

    def test_no_match_returns_none(self, session):
        repo = AlertPromptRepository(session)
        _make(repo, name="any", rule_groups=["other"])
        session.flush()

        alert = {"rule": {"id": "nothing", "groups": ["unrelated"]}}
        assert repo.find_matching(alert) is None

    def test_empty_alert_returns_none(self, session):
        repo = AlertPromptRepository(session)
        _make(repo, name="any", rule_groups=["x"])
        session.flush()

        assert repo.find_matching({}) is None
        assert repo.find_matching(None) is None  # type: ignore[arg-type]

    def test_disabled_templates_ignored(self, session):
        repo = AlertPromptRepository(session)
        _make(repo, name="disabled", rule_groups=["sysmon_event_1"], enabled=False)
        session.flush()

        alert = {"rule": {"groups": ["sysmon_event_1"]}}
        assert repo.find_matching(alert) is None


# ---------------------------------------------------------------------------
# Alert-shape extractors
# ---------------------------------------------------------------------------


class TestExtractors:
    def test_elastic_threat_shape(self):
        alert = {
            "kibana.alert.rule.threat": [
                {
                    "tactic": {"id": "TA0002", "name": "Execution"},
                    "technique": [
                        {"id": "T1059",
                         "subtechnique": [{"id": "T1059.001"}]}
                    ],
                }
            ]
        }
        techs = AlertPromptRepository._extract_mitre_techniques(alert)
        tactics = AlertPromptRepository._extract_mitre_tactics(alert)
        assert "T1059" in techs
        assert "T1059.001" in techs
        assert "TA0002" in tactics or "Execution" in tactics

    def test_wazuh_sigma_shape(self):
        alert = {"rule": {"mitre": {"id": ["T1110.003"], "tactic": ["TA0006"]}}}
        assert "T1110.003" in AlertPromptRepository._extract_mitre_techniques(alert)
        assert "TA0006" in AlertPromptRepository._extract_mitre_tactics(alert)

    def test_raw_data_fallback(self):
        alert = {
            "raw_data": {
                "kibana.alert.rule.threat": [
                    {
                        "tactic": {"id": "TA0011"},
                        "technique": [{"id": "T1071.004"}],
                    }
                ]
            }
        }
        assert "T1071.004" in AlertPromptRepository._extract_mitre_techniques(alert)
        assert "TA0011" in AlertPromptRepository._extract_mitre_tactics(alert)

    def test_tactic_ids_excluded_from_techniques(self):
        """TA0002 in a technique list is ignored (defensive)."""
        alert = {"mitre_techniques": ["TA0002", "T1059"]}
        techs = AlertPromptRepository._extract_mitre_techniques(alert)
        assert techs == ["T1059"]
