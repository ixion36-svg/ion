"""Tests for attack_story_service — multi-step intrusions as a narrative.

This module was at 0% when the coverage ratchet first measured the tree. It
decides which host an analyst looks at first, so the failures that cost
something are ordering and arithmetic: a kill chain reported out of phase order
(so an intrusion at ``impact`` reads as reconnaissance), a score that caps or
misweights so the worst story is not at the top, and the crash below that
emptied the whole list.

The crash is the same one found in ``alert_pattern_service`` and from the same
source: ``ElasticsearchService`` parses ``@timestamp`` into an offset-AWARE
datetime when it ends in ``Z`` and falls back to NAIVE ``utcnow()`` when the
field is missing, so one such alert in an entity's bucket made ``sort()`` raise
``TypeError``, which the API turned into an empty story list. ``_parse_timestamp``
now normalises to UTC; ``TestRobustness`` pins it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ion.services.attack_story_service import (
    KILL_CHAIN_ORDER,
    _build_narrative,
    _normalise_tactic,
    _parse_timestamp,
    _score_story,
    _severity_label,
    build_attack_stories,
)

T0 = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)


def _alert(*, host="web-01", user=None, tactic=None, rule="R", severity="low",
           ts=T0, technique=None, technique_id=None):
    return {
        "host": host,
        "user": user,
        "rule_name": rule,
        "severity": severity,
        "timestamp": ts.isoformat() if isinstance(ts, datetime) else ts,
        "mitre_tactic_name": tactic,
        "mitre_technique_name": technique,
        "mitre_technique_id": technique_id,
    }


def _story(alerts):
    out = build_attack_stories(alerts)
    assert out["stories"], "expected at least one story"
    return out["stories"][0]


class TestNormaliseTactic:
    @pytest.mark.parametrize("raw,expected", [
        ("initial-access", "initial-access"),
        ("Initial Access", "initial-access"),
        ("PRIVILEGE_ESCALATION", "privilege-escalation"),
        ("  Lateral Movement  ", "lateral-movement"),
    ])
    def test_tactic_names_are_canonicalised(self, raw, expected):
        assert _normalise_tactic(raw) == expected

    def test_a_missing_tactic_is_none(self):
        assert _normalise_tactic(None) is None
        assert _normalise_tactic("") is None


class TestSeverityLabel:
    @pytest.mark.parametrize("score,label", [
        (100, "critical"), (75, "critical"), (74, "high"), (50, "high"),
        (49, "medium"), (25, "medium"), (24, "low"), (0, "low"),
    ])
    def test_the_bands(self, score, label):
        assert _severity_label(score) == label


class TestScoring:
    def test_each_kill_chain_stage_is_worth_eight(self):
        assert _score_story(["execution", "persistence"], {}) == 16

    def test_a_critical_alert_is_worth_fifteen(self):
        assert _score_story([], {"critical": 2}) == 30

    def test_a_high_alert_is_worth_eight(self):
        assert _score_story([], {"high": 3}) == 24

    def test_a_medium_alert_is_worth_three(self):
        assert _score_story([], {"medium": 4}) == 12

    def test_low_alerts_add_nothing(self):
        assert _score_story([], {"low": 50}) == 0

    def test_breadth_and_severity_add_together(self):
        assert _score_story(["execution"], {"critical": 1, "high": 1}) == 31

    def test_the_score_is_capped_at_one_hundred(self):
        """Thirteen stages alone would reach 104."""
        assert _score_story(list(KILL_CHAIN_ORDER), {}) == 100
        assert _score_story(list(KILL_CHAIN_ORDER), {"critical": 20}) == 100

    def test_nothing_scores_zero(self):
        assert _score_story([], {}) == 0


class TestGrouping:
    def test_alerts_against_one_host_become_one_story(self):
        out = build_attack_stories([_alert(), _alert(ts=T0 + timedelta(hours=1))])
        assert out["total_stories"] == 1
        assert out["stories"][0]["entity"] == "web-01"
        assert out["stories"][0]["entity_type"] == "host"

    def test_two_hosts_become_two_stories(self):
        alerts = [_alert(host="a"), _alert(host="a", ts=T0 + timedelta(hours=1)),
                  _alert(host="b"), _alert(host="b", ts=T0 + timedelta(hours=1))]
        assert build_attack_stories(alerts)["total_stories"] == 2

    def test_a_user_is_its_own_entity(self):
        alerts = [_alert(host=None, user="alice"),
                  _alert(host=None, user="alice", ts=T0 + timedelta(hours=1))]

        story = _story(alerts)

        assert story["entity"] == "alice"
        assert story["entity_type"] == "user"

    def test_an_alert_naming_both_feeds_both_stories(self):
        """Deliberate: the same intrusion is worth seeing per host AND per user,
        so an alert is counted in both buckets rather than assigned to one."""
        alerts = [_alert(host="web-01", user="alice"),
                  _alert(host="web-01", user="alice", ts=T0 + timedelta(hours=1))]

        out = build_attack_stories(alerts)

        assert out["total_stories"] == 2
        assert {s["entity_type"] for s in out["stories"]} == {"host", "user"}
        assert out["total_alerts"] == 2

    def test_an_alert_with_no_entity_is_skipped(self):
        alerts = [_alert(host=None, user=None) for _ in range(5)]
        out = build_attack_stories(alerts)
        assert out["total_stories"] == 0
        assert out["total_alerts"] == 5

    def test_no_alerts_returns_the_empty_shape(self):
        out = build_attack_stories([])
        assert out["total_alerts"] == 0
        assert out["total_stories"] == 0
        assert out["stories"] == []


class TestThreshold:
    def test_a_lone_alert_is_not_a_story(self):
        """One alert is an alert; a story needs a progression."""
        assert build_attack_stories([_alert()])["total_stories"] == 0

    def test_the_default_minimum_is_two(self):
        assert build_attack_stories(
            [_alert(), _alert(ts=T0 + timedelta(hours=1))])["total_stories"] == 1

    def test_the_minimum_is_configurable(self):
        alerts = [_alert(ts=T0 + timedelta(hours=i)) for i in range(3)]
        assert build_attack_stories(alerts, min_alerts=4)["total_stories"] == 0
        assert build_attack_stories(alerts, min_alerts=3)["total_stories"] == 1

    def test_undateable_alerts_do_not_count_toward_the_minimum(self):
        """A story is a sequence; an alert we cannot place in time is not part
        of one, so the threshold is re-checked after parsing."""
        alerts = [_alert(ts=T0), _alert(ts="not a date")]

        assert build_attack_stories(alerts)["total_stories"] == 0

    def test_a_story_survives_one_undateable_alert_if_enough_remain(self):
        alerts = [_alert(ts=T0), _alert(ts=T0 + timedelta(hours=1)),
                  _alert(ts="not a date")]

        story = _story(alerts)

        assert story["alert_count"] == 2


class TestKillChain:
    def test_tactics_are_ordered_by_phase_not_by_occurrence(self):
        """An alert at 'impact' arriving first must not make it stage one."""
        alerts = [_alert(tactic="impact", ts=T0),
                  _alert(tactic="initial-access", ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["tactics_progression"] == ["initial-access", "impact"]

    def test_tactics_are_deduplicated(self):
        alerts = [_alert(tactic="execution", ts=T0),
                  _alert(tactic="Execution", ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["tactics_progression"] == ["execution"]

    def test_an_unrecognised_tactic_is_ignored(self):
        """A rule tagged with a non-ATT&CK phase must not break the ordering."""
        alerts = [_alert(tactic="execution", ts=T0),
                  _alert(tactic="havoc", ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["tactics_progression"] == ["execution"]

    def test_a_story_with_no_tactics_is_still_reported(self):
        alerts = [_alert(tactic=None), _alert(tactic=None,
                                             ts=T0 + timedelta(hours=1))]

        story = _story(alerts)

        assert story["tactics_progression"] == []
        assert story["score"] == 0

    def test_the_canonical_order_is_returned_for_the_ui(self):
        assert build_attack_stories([])["kill_chain_order"] == KILL_CHAIN_ORDER

    def test_the_returned_order_is_a_copy(self):
        """A caller mutating it would corrupt the module constant for the life
        of the process."""
        returned = build_attack_stories([])["kill_chain_order"]
        returned.append("tampered")
        assert "tampered" not in KILL_CHAIN_ORDER

    def test_the_canonical_order_has_no_duplicates(self):
        assert len(set(KILL_CHAIN_ORDER)) == len(KILL_CHAIN_ORDER)


class TestRulesAndTechniques:
    def test_unique_rules_keep_first_seen_order(self):
        alerts = [_alert(rule="second", ts=T0 + timedelta(hours=1)),
                  _alert(rule="first", ts=T0),
                  _alert(rule="second", ts=T0 + timedelta(hours=2))]

        assert _story(alerts)["unique_rules"] == ["first", "second"]

    def test_an_alert_with_no_rule_name_contributes_none(self):
        alerts = [_alert(rule=None), _alert(rule=None, ts=T0 + timedelta(hours=1))]
        assert _story(alerts)["unique_rules"] == []

    def test_a_technique_name_is_preferred_over_its_id(self):
        alerts = [_alert(technique="Command and Scripting Interpreter",
                         technique_id="T1059"),
                  _alert(ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["unique_techniques"] == [
            "Command and Scripting Interpreter"]

    def test_the_technique_id_is_used_when_the_name_is_missing(self):
        alerts = [_alert(technique=None, technique_id="T1059"),
                  _alert(ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["unique_techniques"] == ["T1059"]

    def test_techniques_are_deduplicated_in_first_seen_order(self):
        alerts = [_alert(technique="B", ts=T0 + timedelta(hours=1)),
                  _alert(technique="A", ts=T0),
                  _alert(technique="B", ts=T0 + timedelta(hours=2))]

        assert _story(alerts)["unique_techniques"] == ["A", "B"]


class TestSeverityBreakdown:
    def test_severities_are_counted_and_lowercased(self):
        alerts = [_alert(severity="CRITICAL"), _alert(severity="critical",
                                                     ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["severity_breakdown"] == {"critical": 2}

    def test_an_absent_severity_is_not_counted(self):
        alerts = [_alert(severity=None), _alert(severity="high",
                                                ts=T0 + timedelta(hours=1))]

        assert _story(alerts)["severity_breakdown"] == {"high": 1}

    def test_the_breakdown_drives_the_score_and_label(self):
        """Recorded, not endorsed: two CRITICAL alerts spanning two kill-chain
        stages score 46, which the bands call "medium". Reaching "high" needs
        four criticals, or two plus four stages. If that ever reads as too
        forgiving, the fix is `_severity_label`'s thresholds or `_score_story`'s
        weights — not this test."""
        alerts = [_alert(severity="critical", tactic="execution"),
                  _alert(severity="critical", tactic="impact",
                         ts=T0 + timedelta(hours=1))]

        story = _story(alerts)

        assert story["score"] == 16 + 30
        assert story["severity"] == "medium"


class TestTimeSpan:
    def test_the_span_brackets_the_story(self):
        alerts = [_alert(ts=T0 + timedelta(hours=3)), _alert(ts=T0)]

        story = _story(alerts)

        assert story["first_seen"] == T0.isoformat()
        assert story["last_seen"] == (T0 + timedelta(hours=3)).isoformat()
        assert story["time_span_hours"] == 3.0

    def test_the_span_is_rounded_to_two_places(self):
        alerts = [_alert(ts=T0), _alert(ts=T0 + timedelta(minutes=20))]
        assert _story(alerts)["time_span_hours"] == 0.33

    def test_simultaneous_alerts_span_zero_hours(self):
        assert _story([_alert(), _alert(rule="R2")])["time_span_hours"] == 0.0

    def test_the_window_argument_drops_nothing(self):
        """Documented as advisory only — a slow intrusion is the interesting
        case, so widening past the window must not hide it."""
        alerts = [_alert(ts=T0), _alert(ts=T0 + timedelta(days=30))]

        story = build_attack_stories(alerts, time_window_hours=24)["stories"][0]

        assert story["alert_count"] == 2
        assert story["time_span_hours"] == 720.0

    def test_the_stored_alerts_are_in_chronological_order(self):
        alerts = [_alert(rule="late", ts=T0 + timedelta(hours=5)),
                  _alert(rule="early", ts=T0)]

        assert [a["rule_name"] for a in _story(alerts)["alerts"]] == [
            "early", "late"]


class TestOrdering:
    def test_stories_are_sorted_by_score_descending(self):
        quiet = [_alert(host="quiet", severity="low", tactic="execution",
                        ts=T0 + timedelta(hours=i)) for i in range(2)]
        loud = [_alert(host="loud", severity="critical", tactic=t,
                       ts=T0 + timedelta(hours=i))
                for i, t in enumerate(["initial-access", "impact"])]

        out = build_attack_stories(quiet + loud)

        assert [s["entity"] for s in out["stories"]] == ["loud", "quiet"]


class TestNarrative:
    def test_a_single_stage_story_names_the_phase_and_time(self):
        text = _build_narrative("web-01", ["execution"], T0, T0, 0.0, 3)
        assert "web-01" in text
        assert "execution phase" in text
        assert "2026-06-01 09:00 UTC" in text
        assert "3 unique detection rules fired" in text

    def test_a_story_with_no_tactics_says_unknown_rather_than_crashing(self):
        text = _build_narrative("web-01", [], T0, T0, 0.0, 1)
        assert "unknown phase" in text

    def test_one_rule_is_singular(self):
        assert "1 unique detection rule fired" in _build_narrative(
            "web-01", ["execution"], T0, T0, 0.0, 1)

    def test_two_stages_go_straight_from_first_to_last(self):
        text = _build_narrative("web-01", ["initial-access", "impact"],
                                T0, T0 + timedelta(hours=2), 2.0, 2)
        assert "across 2 stages" in text
        assert "Starting with initial-access" in text
        assert "reaching impact" in text
        assert "progressing through" not in text

    def test_three_or_more_stages_list_the_middle_phases(self):
        text = _build_narrative(
            "web-01", ["initial-access", "execution", "persistence", "impact"],
            T0, T0 + timedelta(hours=4), 4.0, 5)
        assert "progressing through execution, persistence, reaching impact" in text

    def test_the_span_is_stated_to_one_decimal(self):
        text = _build_narrative("web-01", ["initial-access", "impact"],
                                T0, T0 + timedelta(hours=2), 2.25, 2)
        assert "over 2.2 hours" in text

    def test_the_story_payload_carries_the_narrative(self):
        alerts = [_alert(tactic="initial-access", ts=T0),
                  _alert(tactic="impact", ts=T0 + timedelta(hours=2))]

        assert "across 2 stages" in _story(alerts)["narrative"]


class TestRobustness:
    def test_a_z_suffix_is_parsed_as_utc(self):
        assert _parse_timestamp("2026-06-01T09:00:00Z") == T0

    def test_a_datetime_passes_through_as_utc(self):
        assert _parse_timestamp(T0) == T0

    def test_a_naive_timestamp_is_read_as_utc(self):
        """ES falls back to naive ``utcnow()``, so a bare timestamp is UTC."""
        assert _parse_timestamp("2026-06-01T09:00:00") == T0
        assert _parse_timestamp(datetime(2026, 6, 1, 9, 0, 0)) == T0

    def test_an_offset_timestamp_keeps_its_instant(self):
        assert _parse_timestamp("2026-06-01T11:00:00+02:00") == T0

    def test_an_unparsable_timestamp_is_none(self):
        assert _parse_timestamp("yesterday") is None

    def test_a_non_string_timestamp_is_none(self):
        assert _parse_timestamp(1780000000) is None
        assert _parse_timestamp(None) is None

    def test_mixed_aware_and_naive_timestamps_do_not_crash(self):
        """One alert with a missing ``@timestamp`` used to empty the whole list."""
        alerts = [_alert(ts="2026-06-01T09:00:00Z"),
                  _alert(ts="2026-06-01T10:00:00"),
                  _alert(ts=datetime(2026, 6, 1, 11, 0, 0))]

        story = _story(alerts)

        assert story["alert_count"] == 3
        assert story["time_span_hours"] == 2.0

    def test_the_narrative_timestamp_is_genuinely_utc(self):
        """The narrative hard-codes the string "UTC", so an offset timestamp has
        to be converted rather than printed in its own zone."""
        alerts = [_alert(tactic="initial-access", ts="2026-06-01T11:00:00+02:00"),
                  _alert(tactic="impact", ts="2026-06-01T12:00:00+02:00")]

        assert "09:00 UTC" in _story(alerts)["narrative"]
