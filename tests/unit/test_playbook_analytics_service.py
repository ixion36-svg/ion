"""Tests for playbook_analytics_service — per-playbook execution statistics.

This module was at 0% when the coverage ratchet first measured the tree. It
tells a SOC lead which playbooks are earning their place and which have never
been run, so the failures that matter are arithmetic and omission: a
completion rate that flatters, a never-executed playbook missing from the
list, or a "fastest" chosen from playbooks that have no timing data at all.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from ion.models.playbook import Playbook, PlaybookExecution
from ion.models.user import User
from ion.services import playbook_analytics_service as svc

NOW = datetime(2026, 6, 1, 12, 0, 0)


@pytest.fixture
def owner(session):
    u = User(username="lead", email="lead@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


def _playbook(session, owner, name, *, active=True):
    p = Playbook(name=name, is_active=active, trigger_conditions={},
                 created_by_id=owner.id)
    session.add(p)
    session.flush()
    return p


def _run(session, pb, *, status="completed", started=None, finished=None,
         alert="a1"):
    e = PlaybookExecution(playbook_id=pb.id, es_alert_id=alert, status=status,
                          started_at=started, completed_at=finished)
    session.add(e)
    session.flush()
    return e


class TestAggregates:
    def test_an_empty_estate_returns_the_zeroed_shape(self, session):
        out = svc.get_playbook_analytics(session)
        assert out == {
            "total_playbooks": 0, "active_playbooks": 0, "total_executions": 0,
            "playbooks": [], "never_executed": [], "most_used": None,
            "fastest": None,
        }

    def test_playbooks_are_counted_and_active_ones_separately(self, session, owner):
        _playbook(session, owner, "live")
        _playbook(session, owner, "retired", active=False)

        out = svc.get_playbook_analytics(session)

        assert out["total_playbooks"] == 2
        assert out["active_playbooks"] == 1

    def test_playbooks_come_back_in_name_order(self, session, owner):
        _playbook(session, owner, "zulu")
        _playbook(session, owner, "alpha")

        names = [p["name"] for p in svc.get_playbook_analytics(session)["playbooks"]]

        assert names == ["alpha", "zulu"]

    def test_executions_are_counted_across_all_playbooks(self, session, owner):
        a = _playbook(session, owner, "a")
        b = _playbook(session, owner, "b")
        _run(session, a)
        _run(session, b)
        _run(session, b)

        assert svc.get_playbook_analytics(session)["total_executions"] == 3


class TestNeverExecuted:
    def test_an_unused_playbook_is_listed_and_zeroed(self, session, owner):
        pb = _playbook(session, owner, "unused")

        out = svc.get_playbook_analytics(session)

        assert out["never_executed"] == [{"id": pb.id, "name": "unused"}]
        stat = out["playbooks"][0]
        assert stat["execution_count"] == 0
        assert stat["completion_rate"] == 0.0
        assert stat["avg_duration_hours"] is None
        assert stat["last_executed"] is None

    def test_a_used_playbook_is_not_listed_as_unused(self, session, owner):
        pb = _playbook(session, owner, "used")
        _run(session, pb)

        assert svc.get_playbook_analytics(session)["never_executed"] == []


class TestCompletionRate:
    def test_all_completed_is_one_hundred_percent(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, status="completed")
        _run(session, pb, status="completed", alert="a2")

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "completion_rate"] == 100.0

    def test_a_mixed_run_history_is_a_proportion(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, status="completed")
        _run(session, pb, status="failed", alert="a2")
        _run(session, pb, status="in_progress", alert="a3")

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "completion_rate"] == 33.3

    def test_nothing_completed_is_zero_not_absent(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, status="failed")

        stat = svc.get_playbook_analytics(session)["playbooks"][0]
        assert stat["completion_rate"] == 0.0
        assert stat["execution_count"] == 1


class TestDurations:
    def test_the_average_is_in_hours(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=NOW, finished=NOW + timedelta(hours=2))
        _run(session, pb, started=NOW, finished=NOW + timedelta(hours=4),
             alert="a2")

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "avg_duration_hours"] == 3.0

    def test_runs_without_both_timestamps_are_excluded(self, session, owner):
        """A run still in flight must not be averaged in as zero."""
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=NOW, finished=NOW + timedelta(hours=6))
        _run(session, pb, started=NOW, finished=None, alert="a2")

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "avg_duration_hours"] == 6.0

    def test_no_timed_runs_leaves_the_average_unknown(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=None, finished=None)

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "avg_duration_hours"] is None

    def test_a_negative_duration_is_discarded(self, session, owner):
        """Clock skew must not produce a negative average."""
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=NOW, finished=NOW - timedelta(hours=1))

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "avg_duration_hours"] is None

    def test_last_executed_is_the_most_recent_start(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=NOW - timedelta(days=5))
        _run(session, pb, started=NOW, alert="a2")

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "last_executed"] == NOW.isoformat()

    def test_last_executed_ignores_runs_with_no_start(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=None)
        _run(session, pb, started=NOW, alert="a2")

        assert svc.get_playbook_analytics(session)["playbooks"][0][
            "last_executed"] == NOW.isoformat()


class TestHeadlines:
    def test_most_used_is_the_one_run_most_often(self, session, owner):
        a = _playbook(session, owner, "a")
        b = _playbook(session, owner, "b")
        _run(session, a)
        _run(session, b)
        _run(session, b, alert="a2")

        assert svc.get_playbook_analytics(session)["most_used"] == "b"

    def test_a_tie_keeps_the_first_seen_in_name_order(self, session, owner):
        """Strictly-greater comparison, so the alphabetical winner holds."""
        a = _playbook(session, owner, "alpha")
        b = _playbook(session, owner, "bravo")
        _run(session, a)
        _run(session, b)

        assert svc.get_playbook_analytics(session)["most_used"] == "alpha"

    def test_fastest_is_the_lowest_average_duration(self, session, owner):
        slow = _playbook(session, owner, "slow")
        quick = _playbook(session, owner, "quick")
        _run(session, slow, started=NOW, finished=NOW + timedelta(hours=10))
        _run(session, quick, started=NOW, finished=NOW + timedelta(hours=1),
             alert="a2")

        assert svc.get_playbook_analytics(session)["fastest"] == "quick"

    def test_playbooks_without_timing_cannot_be_fastest(self, session, owner):
        """An untimed playbook is not infinitely fast."""
        untimed = _playbook(session, owner, "a-untimed")
        timed = _playbook(session, owner, "b-timed")
        _run(session, untimed, started=None, finished=None)
        _run(session, timed, started=NOW, finished=NOW + timedelta(hours=9),
             alert="a2")

        assert svc.get_playbook_analytics(session)["fastest"] == "b-timed"

    def test_no_timing_anywhere_leaves_fastest_unknown(self, session, owner):
        pb = _playbook(session, owner, "p")
        _run(session, pb, started=None, finished=None)

        assert svc.get_playbook_analytics(session)["fastest"] is None

    def test_no_executions_leaves_both_headlines_unset(self, session, owner):
        _playbook(session, owner, "p")
        out = svc.get_playbook_analytics(session)
        assert out["most_used"] is None and out["fastest"] is None


class TestDegradedPaths:
    def test_absent_models_return_the_empty_shape(self, session, monkeypatch):
        monkeypatch.setattr(svc, "Playbook", None)
        assert svc.get_playbook_analytics(session)["total_playbooks"] == 0

    def test_a_playbook_query_failure_returns_the_empty_shape(
        self, session, monkeypatch
    ):
        def boom(*a, **k):
            raise RuntimeError("db gone")

        monkeypatch.setattr(session, "query", boom)
        assert svc.get_playbook_analytics(session)["playbooks"] == []

    def test_an_execution_query_failure_still_lists_the_playbooks(
        self, session, owner, monkeypatch
    ):
        """Losing the run history must not hide the catalogue itself."""
        _playbook(session, owner, "p")
        real = session.query
        calls = {"n": 0}

        def flaky(model):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("executions table is wrong")
            return real(model)

        monkeypatch.setattr(session, "query", flaky)
        out = svc.get_playbook_analytics(session)

        assert out["total_playbooks"] == 1
        assert out["total_executions"] == 0
        assert out["never_executed"] == [{"id": 1, "name": "p"}]
