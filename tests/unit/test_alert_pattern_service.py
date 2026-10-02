"""Tests for alert_pattern_service — recurring-alert detection.

This module was at 0% when the coverage ratchet first measured the tree. It
answers "what keeps firing, and is it noise or a campaign", so the failures
that matter are a misclassification (a burst reported as sporadic, so nobody
looks) and a crash on one malformed alert — the API wraps the whole call in
``try/except`` and returns ``{"enabled": false}``, so a single bad timestamp
used to take the entire report down with no sign of why.

Two of those crashes are fixed here and pinned by ``TestRobustness``:

* a non-string, non-datetime ``timestamp`` (an epoch int) raised
  ``AttributeError``, which the function's own ``except (ValueError, TypeError)``
  did not catch, despite the docstring promising a best-effort parse;
* a group mixing offset-aware and naive timestamps raised ``TypeError`` on
  ``sort()``. That mix is reachable: ``ElasticsearchService`` parses
  ``@timestamp`` to an aware datetime when it ends in ``Z``, and falls back to
  naive ``utcnow()`` when the field is missing or unparsable, so one odd
  document in a batch was enough.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ion.services.alert_pattern_service import (
    _classify_pattern,
    _parse_ts,
    detect_alert_patterns,
)

BASE = datetime(2026, 6, 1, 3, 0, 0, tzinfo=timezone.utc)


def _alert(rule="Suspicious PowerShell", host="web-01", severity="high",
           ts=BASE):
    return {
        "rule_name": rule,
        "host": host,
        "severity": severity,
        "timestamp": ts.isoformat() if isinstance(ts, datetime) else ts,
    }


def _series(n, *, gap_hours, rule="R", host="h", severity="high", start=BASE):
    return [_alert(rule, host, severity, start + timedelta(hours=gap_hours * i))
            for i in range(n)]


class TestParseTs:
    def test_a_z_suffix_is_understood(self):
        assert _parse_ts("2026-06-01T10:00:00Z") == datetime(
            2026, 6, 1, 10, 0, tzinfo=timezone.utc)

    def test_an_explicit_offset_is_understood(self):
        assert _parse_ts("2026-06-01T10:00:00+00:00") == datetime(
            2026, 6, 1, 10, 0, tzinfo=timezone.utc)

    def test_a_datetime_passes_through(self):
        assert _parse_ts(BASE) == BASE

    def test_none_is_none(self):
        assert _parse_ts(None) is None

    def test_an_unparsable_string_is_none_not_an_exception(self):
        assert _parse_ts("last tuesday") is None

    def test_an_empty_string_is_none(self):
        assert _parse_ts("") is None


class TestGrouping:
    def test_alerts_group_by_rule_and_host(self):
        alerts = _series(3, gap_hours=1, rule="R", host="a") + \
                 _series(3, gap_hours=1, rule="R", host="b")

        out = detect_alert_patterns(alerts)

        assert out["total_patterns"] == 2
        assert {p["host"] for p in out["patterns"]} == {"a", "b"}

    def test_the_same_host_under_different_rules_is_two_patterns(self):
        alerts = _series(3, gap_hours=1, rule="R1", host="a") + \
                 _series(3, gap_hours=1, rule="R2", host="a")

        assert detect_alert_patterns(alerts)["total_patterns"] == 2

    def test_an_alert_with_no_rule_name_is_dropped(self):
        """Grouping on a missing rule would lump unrelated alerts together."""
        alerts = _series(3, gap_hours=1) + [
            {"host": "h", "severity": "high", "timestamp": BASE.isoformat()}
        ]

        out = detect_alert_patterns(alerts)

        assert out["total_patterns"] == 1
        assert out["patterns"][0]["count"] == 3

    def test_an_empty_rule_name_is_dropped_too(self):
        assert detect_alert_patterns(
            [{"rule_name": "", "timestamp": BASE.isoformat()}] * 3
        )["total_patterns"] == 0

    def test_a_missing_host_is_its_own_group_not_an_error(self):
        alerts = [{"rule_name": "R", "severity": "low",
                   "timestamp": (BASE + timedelta(hours=i)).isoformat()}
                  for i in range(3)]

        out = detect_alert_patterns(alerts)

        assert out["patterns"][0]["host"] is None

    def test_no_alerts_returns_the_zeroed_shape(self):
        assert detect_alert_patterns([]) == {
            "total_patterns": 0, "patterns": [], "persistent_count": 0,
            "burst_count": 0,
        }


class TestThreshold:
    def test_a_group_below_the_threshold_is_not_a_pattern(self):
        assert detect_alert_patterns(_series(2, gap_hours=1))[
            "total_patterns"] == 0

    def test_exactly_the_threshold_qualifies(self):
        assert detect_alert_patterns(_series(3, gap_hours=1))[
            "total_patterns"] == 1

    def test_the_threshold_is_configurable(self):
        alerts = _series(4, gap_hours=1)
        assert detect_alert_patterns(alerts, min_occurrences=5)[
            "total_patterns"] == 0
        assert detect_alert_patterns(alerts, min_occurrences=4)[
            "total_patterns"] == 1


class TestIntervalsAndTiming:
    def test_the_average_interval_is_in_hours(self):
        out = detect_alert_patterns(_series(3, gap_hours=6))
        assert out["patterns"][0]["avg_interval_hours"] == 6.0

    def test_the_average_is_rounded_to_two_places(self):
        alerts = [_alert(ts=BASE), _alert(ts=BASE + timedelta(minutes=20)),
                  _alert(ts=BASE + timedelta(minutes=41))]
        # gaps of 20 and 21 minutes -> (0.3333 + 0.35) / 2
        assert detect_alert_patterns(alerts)["patterns"][0][
            "avg_interval_hours"] == 0.34

    def test_first_and_last_seen_bracket_the_group(self):
        alerts = _series(3, gap_hours=5)

        p = detect_alert_patterns(alerts)["patterns"][0]

        assert p["first_seen"] == BASE.isoformat()
        assert p["last_seen"] == (BASE + timedelta(hours=10)).isoformat()

    def test_out_of_order_input_is_sorted_before_bracketing(self):
        """ES returns newest-first; first_seen must still be the oldest."""
        alerts = list(reversed(_series(3, gap_hours=5)))

        p = detect_alert_patterns(alerts)["patterns"][0]

        assert p["first_seen"] == BASE.isoformat()

    def test_the_peak_hour_is_the_dominant_hour_of_day(self):
        """A rule that only fires at 02:00 is a scheduled job, not an attack."""
        alerts = [
            _alert(ts=datetime(2026, 6, 1, 2, 10, tzinfo=timezone.utc)),
            _alert(ts=datetime(2026, 6, 2, 2, 15, tzinfo=timezone.utc)),
            _alert(ts=datetime(2026, 6, 3, 9, 0, tzinfo=timezone.utc)),
        ]

        assert detect_alert_patterns(alerts)["patterns"][0]["peak_hour"] == 2


class TestClassification:
    def test_tight_regular_intervals_are_persistent(self):
        out = detect_alert_patterns(_series(3, gap_hours=2))
        assert out["patterns"][0]["pattern_type"] == "persistent"
        assert out["persistent_count"] == 1

    def test_four_hours_is_periodic_not_persistent(self):
        """The boundary: < 4 h is persistent, 4 h itself is periodic."""
        assert detect_alert_patterns(_series(3, gap_hours=4))["patterns"][0][
            "pattern_type"] == "periodic"

    def test_two_days_is_still_periodic(self):
        assert detect_alert_patterns(_series(3, gap_hours=48))["patterns"][0][
            "pattern_type"] == "periodic"

    def test_beyond_two_days_is_sporadic(self):
        assert detect_alert_patterns(_series(3, gap_hours=49))["patterns"][0][
            "pattern_type"] == "sporadic"

    def test_six_alerts_inside_an_hour_is_a_burst(self):
        out = detect_alert_patterns(_series(6, gap_hours=0.15))  # 9-minute gaps

        assert out["patterns"][0]["pattern_type"] == "burst"
        assert out["burst_count"] == 1

    def test_exactly_five_in_the_window_classifies_on_interval_instead(self):
        out = detect_alert_patterns(_series(5, gap_hours=0.15))
        assert out["patterns"][0]["pattern_type"] == "persistent"
        assert out["burst_count"] == 0

    def test_a_burst_outranks_the_interval_classification(self):
        """Six alerts in ten minutes then silence for a week averages out to a
        long interval; what matters is the ten minutes."""
        alerts = _series(6, gap_hours=0.03) + [
            _alert("R", "h", ts=BASE + timedelta(days=7))]

        p = detect_alert_patterns(alerts)["patterns"][0]

        assert p["count"] == 7
        assert p["avg_interval_hours"] > 4
        assert p["pattern_type"] == "burst"

    def test_a_burst_later_in_the_series_is_still_found(self):
        """The window scan has to slide, not just look at the first alert."""
        alerts = _series(3, gap_hours=30) + [
            _alert("R", "h", ts=BASE + timedelta(hours=100, minutes=m))
            for m in (0, 5, 10, 15, 20, 25)
        ]

        p = detect_alert_patterns(alerts)["patterns"][0]

        assert p["count"] == 9
        assert p["pattern_type"] == "burst"


class TestSeverity:
    def test_the_most_common_severity_is_reported(self):
        alerts = [_alert(severity="low"), _alert(severity="critical"),
                  _alert(severity="critical")]
        assert detect_alert_patterns(alerts)["patterns"][0][
            "severity"] == "critical"

    def test_absent_severities_read_as_unknown(self):
        alerts = [{"rule_name": "R", "host": "h",
                   "timestamp": (BASE + timedelta(hours=i)).isoformat()}
                  for i in range(3)]
        assert detect_alert_patterns(alerts)["patterns"][0][
            "severity"] == "unknown"

    def test_an_empty_severity_string_does_not_win(self):
        alerts = [_alert(severity=""), _alert(severity=""),
                  _alert(severity="high")]
        assert detect_alert_patterns(alerts)["patterns"][0][
            "severity"] == "high"


class TestOrdering:
    def test_patterns_are_sorted_by_count_descending(self):
        alerts = _series(3, gap_hours=1, rule="quiet") + \
                 _series(7, gap_hours=1, rule="loud")

        names = [p["rule_name"] for p in detect_alert_patterns(alerts)["patterns"]]

        assert names == ["loud", "quiet"]


class TestRobustness:
    def test_unparsable_timestamps_leave_the_count_but_blank_the_window(self):
        """The group is still worth reporting — we just cannot date it."""
        alerts = [_alert(ts="not a date") for _ in range(3)]

        p = detect_alert_patterns(alerts)["patterns"][0]

        assert p["count"] == 3
        assert p["first_seen"] == "" and p["last_seen"] == ""
        assert p["peak_hour"] is None
        assert p["avg_interval_hours"] == 0.0
        assert p["pattern_type"] == "sporadic"

    def test_a_missing_timestamp_key_is_tolerated(self):
        alerts = [{"rule_name": "R", "host": "h", "severity": "low"}] * 3
        assert detect_alert_patterns(alerts)["patterns"][0]["first_seen"] == ""

    def test_an_epoch_integer_timestamp_does_not_crash(self):
        """ES documents are not guaranteed to carry an ISO string, and the API
        turns any exception into a blank report for every pattern."""
        assert _parse_ts(1780000000) is None

        alerts = [_alert("R", "h", ts=BASE),
                  _alert("R", "h", ts=BASE + timedelta(hours=1)),
                  {"rule_name": "R", "host": "h", "severity": "low",
                   "timestamp": 1780000000}]

        out = detect_alert_patterns(alerts)

        assert out["patterns"][0]["count"] == 3
        assert out["patterns"][0]["first_seen"] == BASE.isoformat()

    def test_mixed_aware_and_naive_timestamps_do_not_crash(self):
        """Reachable: ElasticsearchService parses a ``Z`` timestamp to an aware
        datetime but falls back to naive ``utcnow()`` when the field is missing,
        so one such document used to break the whole report."""
        alerts = [
            _alert(ts="2026-06-01T03:00:00Z"),
            _alert(ts="2026-06-01T04:00:00"),          # naive
            _alert(ts=datetime(2026, 6, 1, 5, 0, 0)),  # naive datetime
        ]

        p = detect_alert_patterns(alerts)["patterns"][0]

        assert p["count"] == 3
        assert p["avg_interval_hours"] == 1.0
        assert p["first_seen"].startswith("2026-06-01T03:00:00")

    def test_a_naive_timestamp_is_read_as_utc(self):
        """ION is air-gapped and its upstream fallback is ``utcnow()``, so a
        bare timestamp is UTC rather than local time."""
        assert _parse_ts("2026-06-01T10:00:00") == datetime(
            2026, 6, 1, 10, 0, tzinfo=timezone.utc)

    def test_a_naive_datetime_object_is_normalised_too(self):
        assert _parse_ts(datetime(2026, 6, 1, 10, 0)) == datetime(
            2026, 6, 1, 10, 0, tzinfo=timezone.utc)

    def test_an_aware_non_utc_timestamp_keeps_its_instant(self):
        assert _parse_ts("2026-06-01T12:00:00+02:00") == datetime(
            2026, 6, 1, 10, 0, tzinfo=timezone.utc)


class TestClassifyDirectly:
    def test_a_single_timestamp_cannot_burst(self):
        assert _classify_pattern([BASE], 0.0) == "persistent"

    @pytest.mark.parametrize("avg,expected", [
        (0.0, "persistent"), (3.99, "persistent"), (4.0, "periodic"),
        (48.0, "periodic"), (48.01, "sporadic"),
    ])
    def test_the_interval_bands(self, avg, expected):
        assert _classify_pattern([BASE], avg) == expected
