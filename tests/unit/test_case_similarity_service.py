"""Tests for case_similarity_service — "have we investigated this before?".

This module was at 0% when the coverage ratchet first measured the tree. It
surfaces resolved cases alongside a live one, and the ``resolution_stats`` it
returns — most common closure, average time to close — is what an analyst reads
as "this will probably be a false positive, about an hour's work". So the tests
target the ways that figure could be drawn from the wrong population: stats
computed over every scored case rather than the ones actually shown, a case
matched to itself, an open case offered as precedent, or a score of zero
appearing as a match at all.

The weights (rules 30, hosts 25, observables 20, severity 15, title 10) sum to
100 and are pinned individually, because a silent change to one reorders every
list the page shows without failing anything else.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services.case_similarity_service import (
    SEVERITY_ORDER,
    STOP_WORDS,
    _jaccard,
    _safe_list,
    _severity_score,
    _title_words,
    find_similar_cases,
)

NOW = datetime(2026, 6, 1, 12, 0, 0)


@pytest.fixture
def analyst(session):
    u = User(username="analyst", email="a@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


class _Seq:
    n = 0

    @classmethod
    def next(cls):
        cls.n += 1
        return f"SIM-{cls.n:05d}"


def _case(session, analyst, *, title="Suspicious PowerShell execution",
          severity="high", rules=(), hosts=(), observables=(),
          status=AlertCaseStatus.CLOSED, reason="false_positive",
          created=None, closed=None):
    c = AlertCase(
        case_number=_Seq.next(), title=title, severity=severity,
        status=status, created_by_id=analyst.id,
        triggered_rules=list(rules), affected_hosts=list(hosts),
        observables=list(observables), closure_reason=reason,
        created_at=created or NOW, updated_at=created or NOW, closed_at=closed,
    )
    session.add(c)
    session.flush()
    return c


def _target(session, analyst, **kw):
    kw.setdefault("status", AlertCaseStatus.OPEN)
    kw.setdefault("reason", None)
    return _case(session, analyst, **kw)


class TestSafeList:
    def test_a_list_passes_through(self):
        assert _safe_list(["a"]) == ["a"]

    def test_none_is_empty(self):
        assert _safe_list(None) == []

    def test_a_json_string_is_decoded(self):
        assert _safe_list('["a", "b"]') == ["a", "b"]

    def test_malformed_json_is_empty(self):
        assert _safe_list("{nope") == []

    def test_a_json_object_is_not_a_list(self):
        assert _safe_list('{"a": 1}') == []

    def test_an_unexpected_type_is_empty(self):
        assert _safe_list(7) == []


class TestJaccard:
    def test_identical_sets_are_one(self):
        assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint_sets_are_zero(self):
        assert _jaccard({"a"}, {"b"}) == 0.0

    def test_partial_overlap_is_the_ratio_over_the_union(self):
        assert _jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)

    def test_two_empty_sets_are_zero_not_a_division_by_zero(self):
        """Two cases that both record no hosts are not therefore alike."""
        assert _jaccard(set(), set()) == 0.0

    def test_one_empty_set_is_zero(self):
        assert _jaccard({"a"}, set()) == 0.0


class TestSeverityScore:
    def test_the_same_severity_scores_one(self):
        assert _severity_score("high", "high") == 1.0

    def test_comparison_ignores_case_and_padding(self):
        assert _severity_score("  HIGH ", "high") == 1.0

    def test_an_adjacent_severity_scores_a_half(self):
        assert _severity_score("high", "critical") == 0.5
        assert _severity_score("low", "medium") == 0.5

    def test_two_steps_apart_scores_nothing(self):
        assert _severity_score("low", "high") == 0.0

    def test_an_unknown_severity_scores_nothing(self):
        assert _severity_score("catastrophic", "high") == 0.0

    def test_a_missing_severity_scores_nothing(self):
        assert _severity_score(None, "high") == 0.0
        assert _severity_score("high", "") == 0.0

    def test_the_ladder_is_ordered_low_to_critical(self):
        assert SEVERITY_ORDER == ["low", "medium", "high", "critical"]


class TestTitleWords:
    def test_words_are_lowercased(self):
        assert _title_words("Suspicious POWERSHELL") == {"suspicious", "powershell"}

    def test_stop_words_are_dropped(self):
        assert _title_words("the alert on a host") == {"host"}

    def test_single_characters_are_dropped(self):
        """A stray 'a' or digit carries no signal and inflates the union."""
        assert _title_words("x ransomware 1") == {"ransomware"}

    def test_no_title_is_an_empty_set(self):
        assert _title_words(None) == set()
        assert _title_words("") == set()

    def test_the_stop_list_covers_soc_filler(self):
        """'alert', 'case' and 'detected' appear in nearly every title, so they
        would make every pair of cases look related."""
        for w in ("alert", "case", "detected", "detection"):
            assert w in STOP_WORDS


class TestTargetLookup:
    def test_an_unknown_case_returns_the_empty_shape(self, session):
        assert find_similar_cases(session, 999_999) == {
            "case_id": 999_999, "case_number": "", "similar_cases": [],
            "resolution_stats": {},
        }

    def test_the_payload_identifies_the_target(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",))

        out = find_similar_cases(session, t.id)

        assert out["case_id"] == t.id
        assert out["case_number"] == t.case_number


class TestCandidateSelection:
    def test_only_closed_cases_are_offered_as_precedent(self, session, analyst):
        """An unresolved case has no resolution to learn from."""
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), status=AlertCaseStatus.OPEN)

        assert find_similar_cases(session, t.id)["similar_cases"] == []

    def test_an_acknowledged_case_is_not_offered_either(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",),
              status=AlertCaseStatus.ACKNOWLEDGED)

        assert find_similar_cases(session, t.id)["similar_cases"] == []

    def test_a_case_is_never_similar_to_itself(self, session, analyst):
        """A closed case asked about itself would score 100 and top its own list."""
        t = _case(session, analyst, rules=("R",), hosts=("h",))

        out = find_similar_cases(session, t.id)

        assert [c["case_id"] for c in out["similar_cases"]] == []

    def test_a_case_sharing_nothing_is_not_listed(self, session, analyst):
        t = _target(session, analyst, title="ransomware on fileserver",
                    severity="critical", rules=("A",), hosts=("h1",))
        _case(session, analyst, title="phishing report", severity="low",
              rules=("B",), hosts=("h2",))

        assert find_similar_cases(session, t.id)["similar_cases"] == []


class TestScoring:
    def test_identical_rules_alone_score_thirty(self, session, analyst):
        t = _target(session, analyst, title="", severity=None, rules=("R",))
        _case(session, analyst, title="", severity=None, rules=("R",))

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 30

    def test_identical_hosts_alone_score_twenty_five(self, session, analyst):
        t = _target(session, analyst, title="", severity=None, hosts=("web-01",))
        _case(session, analyst, title="", severity=None, hosts=("web-01",))

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 25

    def test_identical_observables_alone_score_twenty(self, session, analyst):
        t = _target(session, analyst, title="", severity=None,
                    observables=("1.2.3.4",))
        _case(session, analyst, title="", severity=None, observables=("1.2.3.4",))

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 20

    def test_the_same_severity_alone_scores_fifteen(self, session, analyst):
        t = _target(session, analyst, title="", severity="high")
        _case(session, analyst, title="", severity="high")

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 15

    def test_an_identical_title_alone_scores_ten(self, session, analyst):
        t = _target(session, analyst, title="ransomware fileserver", severity=None)
        _case(session, analyst, title="ransomware fileserver", severity=None)

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 10

    def test_an_identical_case_scores_one_hundred(self, session, analyst):
        """The weights sum to 100, so a perfect match is a full score."""
        kw = dict(title="ransomware fileserver", severity="critical",
                  rules=("R",), hosts=("fs-01",), observables=("1.2.3.4",))
        t = _target(session, analyst, **kw)
        _case(session, analyst, **kw)

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 100

    def test_an_adjacent_severity_contributes_half_its_weight(self, session,
                                                              analyst):
        t = _target(session, analyst, title="", severity="high")
        _case(session, analyst, title="", severity="critical")

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 8    # round(7.5)

    def test_partial_overlap_scores_proportionally(self, session, analyst):
        t = _target(session, analyst, title="", severity=None, rules=("A", "B"))
        _case(session, analyst, title="", severity=None, rules=("B", "C"))

        # jaccard 1/3 of 30 = 10
        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "similarity_score"] == 10


class TestOrderingAndLimit:
    def test_the_closest_match_comes_first(self, session, analyst):
        t = _target(session, analyst, title="", severity=None,
                    rules=("R",), hosts=("h",))
        _case(session, analyst, title="", severity=None, hosts=("h",))     # 25
        _case(session, analyst, title="", severity=None, rules=("R",),
              hosts=("h",))                                               # 55

        scores = [c["similarity_score"]
                  for c in find_similar_cases(session, t.id)["similar_cases"]]

        assert scores == sorted(scores, reverse=True)
        assert scores[0] == 55

    def test_the_list_is_capped_at_the_limit(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        for _ in range(5):
            _case(session, analyst, rules=("R",))

        assert len(find_similar_cases(session, t.id, limit=2)["similar_cases"]) == 2

    def test_the_default_limit_is_ten(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        for _ in range(12):
            _case(session, analyst, rules=("R",))

        assert len(find_similar_cases(session, t.id)["similar_cases"]) == 10


class TestMatchReasons:
    def test_shared_rules_are_counted_and_pluralised(self, session, analyst):
        t = _target(session, analyst, title="", severity=None, rules=("A", "B"))
        _case(session, analyst, title="", severity=None, rules=("A", "B"))

        reasons = find_similar_cases(session, t.id)["similar_cases"][0][
            "match_reasons"]

        assert "2 shared rules" in reasons

    def test_one_shared_rule_is_singular(self, session, analyst):
        t = _target(session, analyst, title="", severity=None, rules=("A",))
        _case(session, analyst, title="", severity=None, rules=("A",))

        assert "1 shared rule" in find_similar_cases(session, t.id)[
            "similar_cases"][0]["match_reasons"]

    def test_shared_hosts_are_named_in_sorted_order(self, session, analyst):
        """Named rather than counted, because a shared host is the reason an
        analyst actually clicks through."""
        t = _target(session, analyst, title="", severity=None,
                    hosts=("web-02", "web-01"))
        _case(session, analyst, title="", severity=None,
              hosts=("web-01", "web-02"))

        reasons = find_similar_cases(session, t.id)["similar_cases"][0][
            "match_reasons"]

        assert reasons[:2] == ["same host: web-01", "same host: web-02"]

    def test_only_three_hosts_are_named_and_the_rest_counted(self, session,
                                                             analyst):
        hosts = tuple(f"web-{i:02d}" for i in range(5))
        t = _target(session, analyst, title="", severity=None, hosts=hosts)
        _case(session, analyst, title="", severity=None, hosts=hosts)

        reasons = find_similar_cases(session, t.id)["similar_cases"][0][
            "match_reasons"]

        named = [r for r in reasons if r.startswith("same host:")]
        assert len(named) == 3
        assert "+2 more shared hosts" in reasons

    def test_exactly_three_shared_hosts_add_no_overflow_line(self, session,
                                                             analyst):
        hosts = ("a", "b", "c")
        t = _target(session, analyst, title="", severity=None, hosts=hosts)
        _case(session, analyst, title="", severity=None, hosts=hosts)

        reasons = find_similar_cases(session, t.id)["similar_cases"][0][
            "match_reasons"]

        assert not any("more shared hosts" in r for r in reasons)

    def test_shared_observables_are_counted(self, session, analyst):
        t = _target(session, analyst, title="", severity=None,
                    observables=("1.2.3.4", "evil.com"))
        _case(session, analyst, title="", severity=None,
              observables=("1.2.3.4", "evil.com"))

        assert "2 shared observables" in find_similar_cases(session, t.id)[
            "similar_cases"][0]["match_reasons"]

    def test_the_same_severity_is_given_as_a_reason(self, session, analyst):
        t = _target(session, analyst, title="", severity="CRITICAL")
        _case(session, analyst, title="", severity="critical")

        assert "same severity: critical" in find_similar_cases(session, t.id)[
            "similar_cases"][0]["match_reasons"]

    def test_an_adjacent_severity_is_not_given_as_a_reason(self, session,
                                                           analyst):
        """It contributes to the score, but "same severity" would be a lie."""
        t = _target(session, analyst, title="", severity="high")
        _case(session, analyst, title="", severity="critical")

        reasons = find_similar_cases(session, t.id)["similar_cases"][0][
            "match_reasons"]

        assert not any("severity" in r for r in reasons)

    def test_a_title_only_match_lists_no_reasons(self, session, analyst):
        """Recorded: a case can be listed with an empty reason list, because the
        title overlap that scored it is not reported as a reason."""
        t = _target(session, analyst, title="ransomware fileserver",
                    severity=None)
        _case(session, analyst, title="ransomware fileserver", severity=None)

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "match_reasons"] == []


class TestResolutionStats:
    def test_the_most_common_closure_across_the_matches_is_reported(
        self, session, analyst
    ):
        t = _target(session, analyst, rules=("R",))
        for _ in range(3):
            _case(session, analyst, rules=("R",), reason="false_positive")
        _case(session, analyst, rules=("R",), reason="true_positive")

        stats = find_similar_cases(session, t.id)["resolution_stats"]

        assert stats["most_common_closure"] == "false_positive"

    def test_the_average_resolution_time_is_reported_in_hours(self, session,
                                                              analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), created=NOW,
              closed=NOW + timedelta(hours=2))
        _case(session, analyst, rules=("R",), created=NOW,
              closed=NOW + timedelta(hours=5))

        stats = find_similar_cases(session, t.id)["resolution_stats"]

        assert stats["avg_resolution_hours"] == 3.5

    def test_a_case_with_no_closure_time_is_excluded_from_the_average(
        self, session, analyst
    ):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), created=NOW,
              closed=NOW + timedelta(hours=4))
        _case(session, analyst, rules=("R",), created=NOW, closed=None)

        assert find_similar_cases(session, t.id)["resolution_stats"][
            "avg_resolution_hours"] == 4.0

    def test_no_timings_leaves_the_average_unknown_not_zero(self, session,
                                                            analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), closed=None)

        assert find_similar_cases(session, t.id)["resolution_stats"][
            "avg_resolution_hours"] is None

    def test_matches_with_no_closure_reason_leave_it_unknown(self, session,
                                                             analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), reason=None)

        assert find_similar_cases(session, t.id)["resolution_stats"][
            "most_common_closure"] is None

    def test_no_matches_at_all_still_returns_both_keys(self, session, analyst):
        """The page reads these unconditionally."""
        t = _target(session, analyst, title="nothing alike", severity=None)

        assert find_similar_cases(session, t.id)["resolution_stats"] == {
            "most_common_closure": None, "avg_resolution_hours": None,
        }

    def test_the_stats_describe_the_shown_matches_not_every_candidate(
        self, session, analyst
    ):
        """The headline figure has to match the list under it. A strong match
        closed as true_positive and a long tail of weak false_positives must
        not average out to "probably a false positive" when only the strong one
        is on screen."""
        t = _target(session, analyst, title="", severity=None,
                    rules=("R",), hosts=("h",), observables=("o",))
        _case(session, analyst, title="", severity=None, rules=("R",),
              hosts=("h",), observables=("o",), reason="true_positive",
              created=NOW, closed=NOW + timedelta(hours=10))
        for _ in range(5):
            _case(session, analyst, title="", severity=None, hosts=("h",),
                  reason="false_positive", created=NOW,
                  closed=NOW + timedelta(hours=1))

        out = find_similar_cases(session, t.id, limit=1)

        assert len(out["similar_cases"]) == 1
        assert out["resolution_stats"]["most_common_closure"] == "true_positive"
        assert out["resolution_stats"]["avg_resolution_hours"] == 10.0


class TestMatchPayload:
    def test_a_match_carries_what_the_card_shows(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        c = _case(session, analyst, rules=("R",), title="Known phishing wave",
                  severity="medium", reason="benign_true_positive",
                  created=NOW, closed=NOW + timedelta(hours=3))

        match = find_similar_cases(session, t.id)["similar_cases"][0]

        assert match["case_id"] == c.id
        assert match["case_number"] == c.case_number
        assert match["title"] == "Known phishing wave"
        assert match["severity"] == "medium"
        assert match["closure_reason"] == "benign_true_positive"
        assert match["closed_at"] == (NOW + timedelta(hours=3)).isoformat()
        assert match["resolution_time_hours"] == 3.0

    def test_an_unclosed_timestamp_reads_as_none(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), closed=None)

        match = find_similar_cases(session, t.id)["similar_cases"][0]

        assert match["closed_at"] is None
        assert match["resolution_time_hours"] is None

    def test_the_resolution_time_is_rounded_to_one_place(self, session, analyst):
        t = _target(session, analyst, rules=("R",))
        _case(session, analyst, rules=("R",), created=NOW,
              closed=NOW + timedelta(minutes=100))

        assert find_similar_cases(session, t.id)["similar_cases"][0][
            "resolution_time_hours"] == 1.7
