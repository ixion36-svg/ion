"""Tests for analyst_efficiency_service — per-analyst and team metrics.

This module was at 0% when the coverage ratchet first measured the tree. It is
read by SOC leads, and "busiest analyst" / "most efficient" are attributed to
named people, so the failures that cost something are attribution and
denominator errors — which look like facts about someone's work.

The sharpest one is the FP rate. This page divides false positives by TP + FP
(the cases where an analyst actually made a threat/not-threat call), while
/executive-report and /soc-health divide by ALL closures. Both are legitimate;
they are not the same number, and the two pages once showed them under the
identical heading "FP Rate". `fp_rate_basis` exists so a consumer can tell which
it has, and `TestFpRate` pins the denominator here with administrative closures
present, which is exactly the data that makes the two diverge.

"Most efficient" is a low average MTTR, so the guard that matters is the
three-closure minimum: without it, one lucky fast case wins the title.

Two defensive branches are unreachable from here and left uncovered on purpose,
rather than contorted around: ``_bucket_key``'s already-aware path (the
``DateTime`` columns are timezone-naive, so a loaded timestamp never arrives
aware) and the ``if c.closed_at and c.created_at`` false arm in the team-MTTR
loop (``closed_at`` is guaranteed non-NULL by the query filter and
``created_at`` is NOT NULL). Both would matter on a timezone-aware dialect or a
looser schema, so neither is removed.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
)
from ion.models.user import AuditLog, User
from ion.services.analyst_efficiency_service import (
    _alerts_triaged_per_analyst,
    _audit_actions_per_analyst,
    _avg_mttr,
    _build_user_lookup,
    _cases_closed_per_analyst,
    _cases_opened_per_analyst,
    _closure_reason_counts,
    _hourly_activity,
    _time_window,
    get_analyst_efficiency,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
RECENT = NOW - timedelta(hours=2)
OLD = NOW - timedelta(days=30)
CUTOFF = NOW - timedelta(hours=168)


class _Seq:
    n = 0

    @classmethod
    def next(cls):
        cls.n += 1
        return f"EFF-{cls.n:05d}"


def _user(session, name, *, active=True):
    u = User(username=name, email=f"{name}@example.com", password_hash="x",
             is_active=active)
    session.add(u)
    session.flush()
    return u


@pytest.fixture
def alice(session):
    return _user(session, "alice")


@pytest.fixture
def bob(session):
    return _user(session, "bob")


def _case(session, *, creator, closer=None, reason="true_positive",
          status=AlertCaseStatus.CLOSED, created=RECENT, closed=None,
          severity="high"):
    c = AlertCase(
        case_number=_Seq.next(), title="t", severity=severity, status=status,
        created_by_id=creator.id, closed_by_id=closer.id if closer else None,
        closure_reason=reason, created_at=created, updated_at=created,
        closed_at=closed if closed is not None else (RECENT if closer else None),
    )
    session.add(c)
    session.flush()
    return c


def _triage(session, *, analyst=None, status=AlertTriageStatus.CLOSED,
            when=RECENT):
    t = AlertTriage(es_alert_id=_Seq.next(), status=status,
                    assigned_to_id=analyst.id if analyst else None,
                    created_at=when, updated_at=when)
    session.add(t)
    session.flush()
    return t


def _audit(session, user, action="alert.view", when=RECENT):
    e = AuditLog(user_id=user.id if user else None, action=action, timestamp=when)
    session.add(e)
    session.flush()
    return e


class TestTimeWindow:
    def test_the_cutoff_is_the_requested_span_back(self):
        now, cutoff = _time_window(168)
        assert (now - cutoff) == timedelta(hours=168)

    def test_both_ends_are_timezone_aware(self):
        """They are compared against stored timestamps and formatted into keys."""
        now, cutoff = _time_window(24)
        assert now.tzinfo is not None and cutoff.tzinfo is not None


class TestUserLookup:
    def test_active_users_are_mapped_id_to_name(self, session, alice):
        assert _build_user_lookup(session) == {alice.id: "alice"}

    def test_a_deactivated_account_is_not_in_the_lookup(self, session):
        """Consequence, pinned below: their activity still appears, under a
        synthetic `user_<id>` label rather than silently vanishing."""
        u = _user(session, "departed", active=False)

        assert u.id not in _build_user_lookup(session)


class TestCasesClosed:
    def test_closures_are_grouped_by_the_closing_analyst(self, session, alice,
                                                         bob):
        _case(session, creator=alice, closer=alice)
        _case(session, creator=alice, closer=bob)

        out = _cases_closed_per_analyst(session, CUTOFF)

        assert len(out[alice.id]) == 1 and len(out[bob.id]) == 1

    def test_the_creator_is_not_credited_with_the_closure(self, session, alice,
                                                          bob):
        """Opening a case is not closing it; conflating them would let one
        analyst's throughput show up on another's row."""
        _case(session, creator=alice, closer=bob)

        assert alice.id not in _cases_closed_per_analyst(session, CUTOFF)

    def test_an_open_case_is_not_a_closure(self, session, alice):
        _case(session, creator=alice, closer=alice,
              status=AlertCaseStatus.OPEN)

        assert _cases_closed_per_analyst(session, CUTOFF) == {}

    def test_a_closure_before_the_window_is_excluded(self, session, alice):
        _case(session, creator=alice, closer=alice, created=OLD, closed=OLD)

        assert _cases_closed_per_analyst(session, CUTOFF) == {}

    def test_a_closure_with_no_recorded_closer_is_excluded(self, session, alice):
        c = _case(session, creator=alice, closer=alice)
        c.closed_by_id = None
        session.flush()

        assert _cases_closed_per_analyst(session, CUTOFF) == {}


class TestCasesOpened:
    def test_openings_are_counted_per_creator(self, session, alice, bob):
        _case(session, creator=alice, status=AlertCaseStatus.OPEN, reason=None)
        _case(session, creator=alice, status=AlertCaseStatus.OPEN, reason=None)
        _case(session, creator=bob, status=AlertCaseStatus.OPEN, reason=None)

        assert _cases_opened_per_analyst(session, CUTOFF) == {alice.id: 2,
                                                             bob.id: 1}

    def test_an_opening_before_the_window_is_excluded(self, session, alice):
        _case(session, creator=alice, status=AlertCaseStatus.OPEN, reason=None,
              created=OLD)

        assert _cases_opened_per_analyst(session, CUTOFF) == {}

    def test_a_closed_case_still_counts_as_opened_in_the_window(self, session,
                                                                alice):
        """Opened and closed are independent counts, not a funnel."""
        _case(session, creator=alice, closer=alice)

        assert _cases_opened_per_analyst(session, CUTOFF) == {alice.id: 1}


class TestAlertsTriaged:
    def test_closed_triage_is_counted_per_analyst(self, session, alice):
        _triage(session, analyst=alice)
        _triage(session, analyst=alice)

        assert _alerts_triaged_per_analyst(session, CUTOFF) == {alice.id: 2}

    def test_open_triage_is_not_counted(self, session, alice):
        """Triaged means finished, not picked up."""
        _triage(session, analyst=alice, status=AlertTriageStatus.OPEN)
        _triage(session, analyst=alice, status=AlertTriageStatus.ACKNOWLEDGED)

        assert _alerts_triaged_per_analyst(session, CUTOFF) == {}

    def test_unassigned_triage_is_not_counted(self, session):
        _triage(session, analyst=None)
        assert _alerts_triaged_per_analyst(session, CUTOFF) == {}

    def test_triage_before_the_window_is_excluded(self, session, alice):
        _triage(session, analyst=alice, when=OLD)
        assert _alerts_triaged_per_analyst(session, CUTOFF) == {}


class TestClosureReasonCounts:
    def test_true_and_false_positives_are_counted(self, session, alice):
        cases = [_case(session, creator=alice, closer=alice,
                       reason="true_positive"),
                 _case(session, creator=alice, closer=alice,
                       reason="false_positive"),
                 _case(session, creator=alice, closer=alice,
                       reason="false_positive")]

        assert _closure_reason_counts(cases) == (1, 2)

    def test_administrative_closures_count_as_neither(self, session, alice):
        """duplicate / not_applicable / insufficient_data are not a verdict
        about the alert, and including them would dilute the FP rate."""
        cases = [_case(session, creator=alice, closer=alice, reason=r)
                 for r in ("duplicate", "not_applicable", "insufficient_data",
                           "benign_true_positive", None)]

        assert _closure_reason_counts(cases) == (0, 0)

    def test_no_cases_counts_zero(self):
        assert _closure_reason_counts([]) == (0, 0)


class TestAvgMttr:
    def test_the_average_is_in_hours(self, session, alice):
        cases = [_case(session, creator=alice, closer=alice, created=NOW,
                       closed=NOW + timedelta(hours=2)),
                 _case(session, creator=alice, closer=alice, created=NOW,
                       closed=NOW + timedelta(hours=4))]

        assert _avg_mttr(cases) == 3.0

    def test_naive_timestamps_are_read_as_utc(self, session, alice):
        """The DateTime columns are naive while `now` is aware, so without the
        coercion this raises TypeError and takes the page down."""
        naive = datetime(2026, 6, 1, 9, 0, 0)
        c = _case(session, creator=alice, closer=alice, created=naive,
                  closed=naive + timedelta(hours=5))

        assert _avg_mttr([c]) == 5.0

    def test_a_negative_duration_is_discarded(self, session, alice):
        c = _case(session, creator=alice, closer=alice, created=NOW,
                  closed=NOW - timedelta(hours=1))

        assert _avg_mttr([c]) is None

    def test_a_case_missing_a_timestamp_is_skipped(self, session, alice):
        c = _case(session, creator=alice, closer=alice, created=NOW,
                  closed=NOW + timedelta(hours=3))
        unclosed = _case(session, creator=alice, closer=alice, created=NOW)
        unclosed.closed_at = None
        session.flush()

        assert _avg_mttr([c, unclosed]) == 3.0

    def test_no_timed_cases_is_unknown_not_zero(self):
        assert _avg_mttr([]) is None

    def test_the_average_is_rounded_to_two_places(self, session, alice):
        c = _case(session, creator=alice, closer=alice, created=NOW,
                  closed=NOW + timedelta(minutes=20))

        assert _avg_mttr([c]) == 0.33


class TestAuditActions:
    def test_actions_are_totalled_and_broken_down_per_analyst(self, session,
                                                              alice):
        _audit(session, alice, "alert.view")
        _audit(session, alice, "alert.view")
        _audit(session, alice, "case.close")

        out = _audit_actions_per_analyst(session, CUTOFF)

        assert out[alice.id]["total"] == 3
        assert out[alice.id]["counter"] == Counter({"alert.view": 2,
                                                   "case.close": 1})

    def test_actions_before_the_window_are_excluded(self, session, alice):
        _audit(session, alice, when=OLD)
        assert _audit_actions_per_analyst(session, CUTOFF) == {}

    def test_an_action_with_no_user_is_excluded(self, session):
        """System actions are not somebody's workload."""
        _audit(session, None)
        assert _audit_actions_per_analyst(session, CUTOFF) == {}

    def test_an_unseen_analyst_defaults_rather_than_raising(self, session):
        out = _audit_actions_per_analyst(session, CUTOFF)
        assert out[999]["total"] == 0


class TestHourlyActivity:
    def test_there_are_twenty_four_buckets(self, session):
        assert len(_hourly_activity(session, NOW)) == 24

    def test_the_buckets_are_in_chronological_order(self, session):
        hours = [h["hour"] for h in _hourly_activity(session, NOW)]
        assert hours == sorted(hours)

    def test_every_bucket_carries_both_counters(self, session):
        for bucket in _hourly_activity(session, NOW):
            assert set(bucket) == {"hour", "cases_closed", "alerts_triaged"}

    def test_a_recent_closure_lands_in_a_bucket(self, session, alice):
        _case(session, creator=alice, closer=alice, created=RECENT,
              closed=RECENT)

        assert sum(h["cases_closed"]
                   for h in _hourly_activity(session, NOW)) == 1

    def test_a_recent_triage_lands_in_a_bucket(self, session, alice):
        _triage(session, analyst=alice, when=RECENT)

        assert sum(h["alerts_triaged"]
                   for h in _hourly_activity(session, NOW)) == 1

    def test_activity_older_than_a_day_is_not_bucketed(self, session, alice):
        _case(session, creator=alice, closer=alice, created=OLD, closed=OLD)
        _triage(session, analyst=alice, when=OLD)

        hourly = _hourly_activity(session, NOW)

        assert sum(h["cases_closed"] for h in hourly) == 0
        assert sum(h["alerts_triaged"] for h in hourly) == 0

    def test_a_naive_timestamp_is_bucketed_as_utc(self, session, alice):
        """Dropping it instead would under-report the last 24 hours."""
        naive = NOW.replace(tzinfo=None) - timedelta(hours=3)
        _case(session, creator=alice, closer=alice, created=naive, closed=naive)

        assert sum(h["cases_closed"]
                   for h in _hourly_activity(session, NOW)) == 1

    def test_a_future_dated_row_is_skipped_without_losing_the_rest(
        self, session, alice
    ):
        """The queries bound the window from below only, so clock skew on an
        ingest host can produce a timestamp past the last bucket. The lookup is
        a guard inside a loop: such a row must be skipped, not end the scan.
        (Both loops behave the same way; the triage one is checked here because
        a future `updated_at` is the case that actually occurs.)"""
        _triage(session, analyst=alice, when=NOW + timedelta(hours=3))
        _triage(session, analyst=alice, when=RECENT)

        assert sum(h["alerts_triaged"]
                   for h in _hourly_activity(session, NOW)) == 1

    def test_a_future_dated_closure_is_skipped_too(self, session, alice):
        _case(session, creator=alice, closer=alice, created=RECENT,
              closed=NOW + timedelta(hours=3))
        _case(session, creator=alice, closer=alice, created=RECENT,
              closed=RECENT)

        assert sum(h["cases_closed"]
                   for h in _hourly_activity(session, NOW)) == 1

    def test_an_open_triage_row_is_not_bucketed(self, session, alice):
        _triage(session, analyst=alice, status=AlertTriageStatus.OPEN,
                when=RECENT)

        assert sum(h["alerts_triaged"]
                   for h in _hourly_activity(session, NOW)) == 0


class TestPerAnalyst:
    def test_an_analyst_with_only_audit_activity_still_appears(self, session,
                                                              alice):
        """The roster is the union of all four sources, so somebody who spent
        the week reading alerts is not reported as idle."""
        _audit(session, alice)

        out = get_analyst_efficiency(session)

        assert [a["username"] for a in out["analysts"]] == ["alice"]
        assert out["analysts"][0]["total_actions"] == 1

    def test_the_row_carries_every_figure_the_table_shows(self, session, alice):
        _case(session, creator=alice, closer=alice, reason="true_positive",
              created=NOW, closed=NOW + timedelta(hours=2))
        _triage(session, analyst=alice)
        _audit(session, alice, "case.close")

        row = get_analyst_efficiency(session)["analysts"][0]

        assert row["user_id"] == alice.id
        assert row["username"] == "alice"
        assert row["cases_closed"] == 1
        assert row["cases_opened"] == 1
        assert row["alerts_triaged"] == 1
        assert row["true_positives"] == 1
        assert row["false_positives"] == 0
        assert row["fp_rate"] == 0.0
        assert row["avg_mttr_hours"] == 2.0
        assert row["total_actions"] == 1
        assert row["top_actions"] == {"case.close": 1}

    def test_a_deactivated_analyst_is_labelled_rather_than_dropped(self, session):
        """Their work in the window still happened; the synthetic label makes
        clear the account is no longer active."""
        gone = _user(session, "departed", active=False)
        _audit(session, gone)

        row = get_analyst_efficiency(session)["analysts"][0]

        assert row["username"] == f"user_{gone.id}"

    def test_analysts_come_back_in_stable_id_order(self, session, alice, bob):
        _audit(session, bob)
        _audit(session, alice)

        ids = [a["user_id"] for a in get_analyst_efficiency(session)["analysts"]]

        assert ids == sorted(ids)

    def test_only_the_ten_most_common_actions_are_listed(self, session, alice):
        for i in range(15):
            for _ in range(i + 1):
                _audit(session, alice, f"action.{i:02d}")

        row = get_analyst_efficiency(session)["analysts"][0]

        assert len(row["top_actions"]) == 10
        assert "action.14" in row["top_actions"]
        assert "action.00" not in row["top_actions"]
        assert row["total_actions"] == sum(range(1, 16))


class TestFpRate:
    def test_the_denominator_is_dispositions_not_all_closures(self, session,
                                                              alice):
        """One FP, one TP and two administrative closures: 50% here, 25% on
        /executive-report. Both correct, different questions."""
        _case(session, creator=alice, closer=alice, reason="false_positive")
        _case(session, creator=alice, closer=alice, reason="true_positive")
        _case(session, creator=alice, closer=alice, reason="duplicate")
        _case(session, creator=alice, closer=alice, reason="not_applicable")

        out = get_analyst_efficiency(session)

        assert out["analysts"][0]["fp_rate"] == 50.0
        assert out["team_summary"]["overall_fp_rate"] == 50.0

    def test_the_basis_is_declared_so_a_consumer_cannot_mix_them_up(self,
                                                                   session):
        assert get_analyst_efficiency(session)["team_summary"][
            "fp_rate_basis"] == "of_dispositions"

    def test_no_dispositions_reads_as_zero(self, session, alice):
        _case(session, creator=alice, closer=alice, reason="duplicate")

        out = get_analyst_efficiency(session)

        assert out["analysts"][0]["fp_rate"] == 0.0
        assert out["team_summary"]["overall_fp_rate"] == 0.0

    def test_the_rate_is_rounded_to_one_place(self, session, alice):
        for _ in range(2):
            _case(session, creator=alice, closer=alice, reason="false_positive")
        _case(session, creator=alice, closer=alice, reason="true_positive")

        assert get_analyst_efficiency(session)["analysts"][0]["fp_rate"] == 66.7


class TestTeamSummary:
    def test_the_totals_sum_the_analyst_rows(self, session, alice, bob):
        _case(session, creator=alice, closer=alice)
        _case(session, creator=bob, closer=bob)
        _triage(session, analyst=alice)

        team = get_analyst_efficiency(session)["team_summary"]

        assert team["total_cases_closed"] == 2
        assert team["total_cases_opened"] == 2
        assert team["total_alerts_triaged"] == 1

    def test_the_team_mttr_averages_cases_not_analyst_averages(self, session,
                                                              alice, bob):
        """Averaging the two per-analyst averages would weight an analyst who
        closed one case the same as one who closed three."""
        _case(session, creator=alice, closer=alice, created=NOW,
              closed=NOW + timedelta(hours=9))
        for _ in range(3):
            _case(session, creator=bob, closer=bob, created=NOW,
                  closed=NOW + timedelta(hours=1))

        team = get_analyst_efficiency(session)["team_summary"]

        # (9 + 1 + 1 + 1) / 4 = 3.0, not (9 + 1) / 2 = 5.0
        assert team["avg_mttr_hours"] == 3.0

    def test_no_timed_closures_leaves_the_team_mttr_unknown(self, session,
                                                            alice):
        _audit(session, alice)
        assert get_analyst_efficiency(session)["team_summary"][
            "avg_mttr_hours"] is None

    def test_the_busiest_analyst_is_the_one_with_most_actions(self, session,
                                                             alice, bob):
        _audit(session, alice)
        for _ in range(5):
            _audit(session, bob)

        assert get_analyst_efficiency(session)["team_summary"][
            "busiest_analyst"] == "bob"

    def test_nobody_active_leaves_the_busiest_unset(self, session):
        assert get_analyst_efficiency(session)["team_summary"][
            "busiest_analyst"] is None

    def test_a_tie_keeps_the_first_analyst_by_id(self, session, alice, bob):
        """Strictly-greater comparison, so the title does not flap between two
        people doing identical amounts of work."""
        _audit(session, alice)
        _audit(session, bob)

        assert get_analyst_efficiency(session)["team_summary"][
            "busiest_analyst"] == "alice"


class TestMostEfficient:
    def test_the_lowest_average_mttr_wins(self, session, alice, bob):
        for _ in range(3):
            _case(session, creator=alice, closer=alice, created=NOW,
                  closed=NOW + timedelta(hours=10))
        for _ in range(3):
            _case(session, creator=bob, closer=bob, created=NOW,
                  closed=NOW + timedelta(hours=1))

        assert get_analyst_efficiency(session)["team_summary"][
            "most_efficient"] == "bob"

    def test_fewer_than_three_closures_cannot_win(self, session, alice, bob):
        """Otherwise one lucky fast case takes the title off someone who closed
        thirty."""
        _case(session, creator=alice, closer=alice, created=NOW,
              closed=NOW + timedelta(minutes=1))
        for _ in range(3):
            _case(session, creator=bob, closer=bob, created=NOW,
                  closed=NOW + timedelta(hours=5))

        assert get_analyst_efficiency(session)["team_summary"][
            "most_efficient"] == "bob"

    def test_exactly_three_closures_qualifies(self, session, alice):
        for _ in range(3):
            _case(session, creator=alice, closer=alice, created=NOW,
                  closed=NOW + timedelta(hours=2))

        assert get_analyst_efficiency(session)["team_summary"][
            "most_efficient"] == "alice"

    def test_nobody_qualifying_leaves_it_unset_rather_than_blank(self, session,
                                                                alice):
        _case(session, creator=alice, closer=alice, created=NOW,
              closed=NOW + timedelta(hours=2))

        assert get_analyst_efficiency(session)["team_summary"][
            "most_efficient"] is None

    def test_closures_with_unusable_timing_cannot_win(self, session, alice):
        """Clock skew between ION and Kibana can close a case "before" it was
        created. Those are discarded, so the analyst has no average and cannot
        take the title on a negative one."""
        for _ in range(3):
            _case(session, creator=alice, closer=alice, created=NOW,
                  closed=NOW - timedelta(hours=1))

        out = get_analyst_efficiency(session)

        assert out["analysts"][0]["cases_closed"] == 3
        assert out["analysts"][0]["avg_mttr_hours"] is None
        assert out["team_summary"]["most_efficient"] is None
        assert out["team_summary"]["avg_mttr_hours"] is None


class TestPayload:
    def test_the_payload_shape_is_stable(self, session):
        out = get_analyst_efficiency(session)
        assert set(out) == {"period_hours", "analysts", "team_summary",
                            "hourly_activity"}
        assert set(out["team_summary"]) == {
            "total_cases_closed", "total_cases_opened", "total_alerts_triaged",
            "overall_fp_rate", "fp_rate_basis", "avg_mttr_hours",
            "busiest_analyst", "most_efficient",
        }

    def test_the_default_window_is_seven_days(self, session):
        assert get_analyst_efficiency(session)["period_hours"] == 168

    def test_the_window_is_configurable_and_narrows_the_data(self, session,
                                                             alice):
        _audit(session, alice, when=NOW - timedelta(hours=48))

        assert get_analyst_efficiency(session, hours=168)["analysts"] != []
        assert get_analyst_efficiency(session, hours=24)["analysts"] == []

    def test_the_hourly_breakdown_always_covers_a_day(self, session):
        """It is 24 hours regardless of the lookback, which is why it is named
        separately from the window."""
        out = get_analyst_efficiency(session, hours=720)
        assert len(out["hourly_activity"]) == 24

    def test_an_empty_estate_returns_zeroes_not_nulls(self, session):
        out = get_analyst_efficiency(session)
        assert out["analysts"] == []
        assert out["team_summary"]["total_cases_closed"] == 0
        assert out["team_summary"]["overall_fp_rate"] == 0.0
