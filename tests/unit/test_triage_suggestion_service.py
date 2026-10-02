"""Tests for triage_suggestion_service — "what did we do last time this fired?".

This module was at 0% when the coverage ratchet first measured the tree. It
reads an analyst's closure history back to them as a recommendation, which is
the most dangerous shape a dark module can take: a suggestion of
``likely_false_positive`` with the word "high" next to it will close an alert.

So the tests target the ways a suggestion could be *more confident than the
evidence*: a verdict drawn from one or two cases, a dominant reason computed
over the wrong denominator, a host-specific figure that silently reuses the
rule-wide one, and a confidence band that rounds up at the boundary.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services.triage_suggestion_service import (
    _MIN_CASES_FOR_SUGGESTION,
    _avg_resolution_hours,
    _compute_confidence,
    _parse_json_list,
    get_triage_suggestion,
)

NOW = datetime(2026, 6, 1, 12, 0, 0)


@pytest.fixture
def analyst(session):
    u = User(username="analyst", email="a@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


class _Counter:
    """Case numbers must be unique; this keeps the fixtures readable."""

    n = 0

    @classmethod
    def next(cls):
        cls.n += 1
        return f"CASE-{cls.n:05d}"


def _case(session, analyst, *, rules=("Suspicious PowerShell",),
          reason="false_positive", status=AlertCaseStatus.CLOSED, hosts=None,
          created=None, closed=None):
    c = AlertCase(
        case_number=_Counter.next(), title="t", status=status,
        created_by_id=analyst.id, triggered_rules=list(rules),
        affected_hosts=list(hosts) if hosts is not None else None,
        closure_reason=reason, created_at=created or NOW,
        closed_at=closed, updated_at=created or NOW,
    )
    session.add(c)
    session.flush()
    return c


def _closed_run(session, analyst, n, *, reason="false_positive",
                rule="Suspicious PowerShell", hosts=None):
    return [_case(session, analyst, rules=(rule,), reason=reason, hosts=hosts)
            for _ in range(n)]


class TestParseJsonList:
    def test_a_real_list_passes_through(self):
        assert _parse_json_list(["a", "b"]) == ["a", "b"]

    def test_none_is_an_empty_list(self):
        assert _parse_json_list(None) == []

    def test_a_json_string_is_decoded(self):
        """Legacy rows stored these columns as serialised text."""
        assert _parse_json_list('["a", "b"]') == ["a", "b"]

    def test_malformed_json_is_an_empty_list_not_a_crash(self):
        assert _parse_json_list("{not json") == []

    def test_a_json_object_is_not_treated_as_a_list(self):
        assert _parse_json_list('{"a": 1}') == []

    def test_an_unexpected_type_is_an_empty_list(self):
        assert _parse_json_list(42) == []


class TestConfidence:
    @pytest.mark.parametrize("top,total,expected", [
        (10, 10, "high"),      # 100%
        (8, 10, "high"),       # exactly 80% — the boundary
        (79, 100, "medium"),   # just under
        (6, 10, "medium"),     # exactly 60% — the boundary
        (59, 100, "low"),      # just under
        (1, 10, "low"),
    ])
    def test_the_bands(self, top, total, expected):
        assert _compute_confidence(top, total) == expected

    def test_no_cases_is_low_not_a_division_by_zero(self):
        assert _compute_confidence(0, 0) == "low"


class TestAvgResolutionHours:
    def test_the_average_is_in_hours(self, session, analyst):
        cases = [
            _case(session, analyst, created=NOW, closed=NOW + timedelta(hours=2)),
            _case(session, analyst, created=NOW, closed=NOW + timedelta(hours=4)),
        ]
        assert _avg_resolution_hours(cases) == 3.0

    def test_an_unclosed_case_is_excluded_rather_than_counted_as_zero(
        self, session, analyst
    ):
        cases = [
            _case(session, analyst, created=NOW, closed=NOW + timedelta(hours=6)),
            _case(session, analyst, created=NOW, closed=None),
        ]
        assert _avg_resolution_hours(cases) == 6.0

    def test_a_negative_duration_is_discarded(self, session, analyst):
        """Clock skew between ION and Kibana must not produce a negative MTTR."""
        cases = [_case(session, analyst, created=NOW,
                       closed=NOW - timedelta(hours=1))]
        assert _avg_resolution_hours(cases) is None

    def test_nothing_timed_is_unknown_not_zero(self, session, analyst):
        assert _avg_resolution_hours([_case(session, analyst, closed=None)]) is None

    def test_no_cases_is_unknown(self):
        assert _avg_resolution_hours([]) is None

    def test_the_average_is_rounded_to_two_places(self, session, analyst):
        cases = [
            _case(session, analyst, created=NOW, closed=NOW + timedelta(minutes=20)),
            _case(session, analyst, created=NOW, closed=NOW + timedelta(minutes=41)),
        ]
        # 0.33333... and 0.68333... hours -> 0.50833... -> 0.51
        assert _avg_resolution_hours(cases) == 0.51


class TestInsufficientData:
    def test_no_history_at_all_is_insufficient_data(self, session):
        out = get_triage_suggestion(session, "Never Seen")
        assert out["suggested_action"] == "insufficient_data"
        assert out["confidence"] == "low"
        assert out["total_matching_cases"] == 0

    def test_the_reasoning_says_how_thin_the_evidence_is(self, session, analyst):
        _closed_run(session, analyst, 2)

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["suggested_action"] == "insufficient_data"
        assert "Only 2 closed case(s)" in out["reasoning"]
        assert "Not enough data" in out["reasoning"]

    def test_two_unanimous_cases_still_do_not_earn_a_verdict(self, session, analyst):
        """Two false positives in a row is a coincidence, not a pattern."""
        _closed_run(session, analyst, 2, reason="false_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["suggested_action"] == "insufficient_data"
        assert out["confidence"] == "low"

    def test_the_threshold_is_three(self, session, analyst):
        assert _MIN_CASES_FOR_SUGGESTION == 3
        _closed_run(session, analyst, 3, reason="false_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["suggested_action"] == "likely_false_positive"

    def test_the_distribution_is_still_returned_below_the_threshold(
        self, session, analyst
    ):
        """The analyst can read the raw history even when we will not judge it."""
        _closed_run(session, analyst, 2, reason="true_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["closure_distribution"] == {"true_positive": 2}


class TestSuggestedAction:
    @pytest.mark.parametrize("reason,action", [
        ("false_positive", "likely_false_positive"),
        ("true_positive", "likely_true_positive"),
        ("benign_true_positive", "likely_benign"),
    ])
    def test_a_known_closure_reason_maps_to_an_action(self, session, analyst,
                                                      reason, action):
        _closed_run(session, analyst, 4, reason=reason)
        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "suggested_action"] == action

    def test_an_unmapped_closure_reason_asks_for_investigation(
        self, session, analyst
    ):
        """'duplicate' and 'risk_accepted' are not verdicts about the alert."""
        _closed_run(session, analyst, 4, reason="duplicate")

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "suggested_action"] == "needs_investigation"

    def test_an_absent_closure_reason_is_recorded_as_unknown(
        self, session, analyst
    ):
        _closed_run(session, analyst, 4, reason=None)

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["closure_distribution"] == {"unknown": 4}
        assert out["suggested_action"] == "needs_investigation"

    def test_the_majority_reason_wins(self, session, analyst):
        _closed_run(session, analyst, 4, reason="false_positive")
        _closed_run(session, analyst, 1, reason="true_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["suggested_action"] == "likely_false_positive"
        assert out["confidence"] == "high"   # 4/5 = 80%
        assert out["closure_distribution"] == {"false_positive": 4,
                                              "true_positive": 1}

    def test_a_split_history_lowers_the_confidence_not_the_verdict(
        self, session, analyst
    ):
        """3 of 5 is still the majority, but 60% is only medium confidence."""
        _closed_run(session, analyst, 3, reason="false_positive")
        _closed_run(session, analyst, 2, reason="true_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["suggested_action"] == "likely_false_positive"
        assert out["confidence"] == "medium"

    def test_an_evenly_split_history_is_low_confidence(self, session, analyst):
        _closed_run(session, analyst, 3, reason="false_positive")
        _closed_run(session, analyst, 3, reason="true_positive")

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "confidence"] == "low"

    def test_the_reasoning_quotes_the_proportion_it_judged_on(
        self, session, analyst
    ):
        _closed_run(session, analyst, 3, reason="false_positive")
        _closed_run(session, analyst, 1, reason="true_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert "closed as false_positive in 3/4 cases (75%)" in out["reasoning"]


class TestCaseSelection:
    def test_only_closed_cases_count(self, session, analyst):
        """An open case has no verdict to learn from."""
        _closed_run(session, analyst, 3, reason="false_positive")
        for _ in range(5):
            _case(session, analyst, status=AlertCaseStatus.OPEN,
                  reason="true_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["total_matching_cases"] == 3
        assert out["suggested_action"] == "likely_false_positive"

    def test_an_acknowledged_case_does_not_count_either(self, session, analyst):
        _closed_run(session, analyst, 3)
        _case(session, analyst, status=AlertCaseStatus.ACKNOWLEDGED)

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "total_matching_cases"] == 3

    def test_another_rules_history_is_not_borrowed(self, session, analyst):
        _closed_run(session, analyst, 3, rule="Other Rule",
                    reason="true_positive")

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["total_matching_cases"] == 0
        assert out["suggested_action"] == "insufficient_data"

    def test_a_case_triggering_several_rules_counts_for_the_named_one(
        self, session, analyst
    ):
        for _ in range(3):
            _case(session, analyst, rules=("Other Rule", "Suspicious PowerShell"),
                  reason="true_positive")

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "total_matching_cases"] == 3

    def test_the_rule_match_is_exact_not_a_substring(self, session, analyst):
        """'PowerShell' must not inherit 'Suspicious PowerShell' history."""
        _closed_run(session, analyst, 4, rule="Suspicious PowerShell")

        assert get_triage_suggestion(session, "PowerShell")[
            "total_matching_cases"] == 0

    def test_a_case_with_no_triggered_rules_is_skipped(self, session, analyst):
        for _ in range(4):
            _case(session, analyst, rules=())

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "total_matching_cases"] == 0

    def test_rules_stored_as_a_json_string_still_match(self, session, analyst):
        """Legacy rows; the JSON column tolerates a bare string."""
        for _ in range(3):
            c = _case(session, analyst, reason="true_positive")
            c.triggered_rules = '["Suspicious PowerShell"]'
        session.flush()

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "total_matching_cases"] == 3


class TestHostSpecific:
    def test_no_host_asked_means_no_host_section(self, session, analyst):
        _closed_run(session, analyst, 4, hosts=["web-01"])

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert out["host"] is None
        assert out["host_specific"] is None

    def test_a_host_with_its_own_history_gets_its_own_figures(
        self, session, analyst
    ):
        """The point of the section: this rule is noise everywhere EXCEPT here."""
        _closed_run(session, analyst, 5, reason="false_positive",
                    hosts=["web-01"])
        _closed_run(session, analyst, 3, reason="true_positive",
                    hosts=["dc-01"])

        out = get_triage_suggestion(session, "Suspicious PowerShell", host="dc-01")

        assert out["suggested_action"] == "likely_false_positive"   # rule-wide
        assert out["host_specific"] == {"total": 3,
                                       "top_closure": "true_positive",
                                       "confidence": "high"}

    def test_a_host_with_no_history_gets_no_section(self, session, analyst):
        _closed_run(session, analyst, 4, hosts=["web-01"])

        out = get_triage_suggestion(session, "Suspicious PowerShell",
                                    host="unknown-host")

        assert out["host"] == "unknown-host"
        assert out["host_specific"] is None

    def test_host_matches_are_drawn_from_the_rule_matches_only(
        self, session, analyst
    ):
        """A host's history under a different rule must not leak in."""
        _closed_run(session, analyst, 3, rule="Suspicious PowerShell",
                    reason="false_positive", hosts=["dc-01"])
        _closed_run(session, analyst, 9, rule="Other Rule",
                    reason="true_positive", hosts=["dc-01"])

        out = get_triage_suggestion(session, "Suspicious PowerShell", host="dc-01")

        assert out["host_specific"]["total"] == 3

    def test_a_single_host_case_still_reports_its_own_confidence(
        self, session, analyst
    ):
        """The minimum-cases guard is rule-wide only; the host section says 1 of
        1, so the count travels with the confidence for the analyst to weigh."""
        _closed_run(session, analyst, 3, reason="false_positive",
                    hosts=["web-01"])
        _closed_run(session, analyst, 1, reason="true_positive", hosts=["dc-01"])

        out = get_triage_suggestion(session, "Suspicious PowerShell", host="dc-01")

        assert out["host_specific"] == {"total": 1,
                                       "top_closure": "true_positive",
                                       "confidence": "high"}

    def test_a_case_with_no_affected_hosts_is_not_a_host_match(
        self, session, analyst
    ):
        _closed_run(session, analyst, 4, hosts=None)

        assert get_triage_suggestion(session, "Suspicious PowerShell",
                                     host="web-01")["host_specific"] is None

    def test_the_host_match_is_exact_not_a_substring(self, session, analyst):
        _closed_run(session, analyst, 4, hosts=["web-01.corp.local"])

        assert get_triage_suggestion(session, "Suspicious PowerShell",
                                     host="web-01")["host_specific"] is None


class TestPayload:
    def test_the_payload_echoes_what_was_asked(self, session, analyst):
        _closed_run(session, analyst, 3, hosts=["web-01"])

        out = get_triage_suggestion(session, "Suspicious PowerShell",
                                    host="web-01", severity="high")

        assert out["rule_name"] == "Suspicious PowerShell"
        assert out["host"] == "web-01"

    def test_severity_is_accepted_but_does_not_filter(self, session, analyst):
        """Documented as context-only; a filter here would quietly halve the
        evidence behind every suggestion."""
        _closed_run(session, analyst, 4, reason="false_positive")

        with_sev = get_triage_suggestion(session, "Suspicious PowerShell",
                                         severity="critical")
        without = get_triage_suggestion(session, "Suspicious PowerShell")

        assert with_sev == without

    def test_the_payload_shape_is_stable(self, session, analyst):
        _closed_run(session, analyst, 3)

        out = get_triage_suggestion(session, "Suspicious PowerShell")

        assert set(out) == {
            "rule_name", "host", "total_matching_cases", "suggested_action",
            "confidence", "closure_distribution", "avg_resolution_hours",
            "reasoning", "host_specific",
        }

    def test_the_resolution_average_covers_the_rule_matches(self, session, analyst):
        for _ in range(3):
            _case(session, analyst, reason="false_positive", created=NOW,
                  closed=NOW + timedelta(hours=5))

        assert get_triage_suggestion(session, "Suspicious PowerShell")[
            "avg_resolution_hours"] == 5.0
