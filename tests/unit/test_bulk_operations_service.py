"""Tests for bulk_operations_service — bulk acknowledge, assign and close.

This module was at 0% when the coverage ratchet first measured the tree. It
mutates many alerts at once and cascades into closing their parent cases, so
the costly failures are not crashes but quiet wrong answers: a case closed
while one of its alerts is still open, a batch abandoned halfway because one
row misbehaved, or an analyst's assignment silently taken from them.
"""

from __future__ import annotations

import pytest

from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
)
from ion.models.user import User
from ion.services import bulk_operations_service as svc


@pytest.fixture(autouse=True)
def _no_external_calls(monkeypatch):
    """Neither the AI-feedback write nor the Kibana push belongs in a unit test."""
    monkeypatch.setattr(svc, "record_close_feedback_safe", lambda *a, **k: None)
    import ion.services.kibana_sync_helpers as kib
    monkeypatch.setattr(kib, "push_case_status_to_kibana", lambda *a, **k: None)


def _user(session, username="analyst"):
    u = User(username=username, email=f"{username}@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


def _case(session, creator, number="CASE-1", status=AlertCaseStatus.OPEN):
    c = AlertCase(case_number=number, title="t", status=status,
                  created_by_id=creator.id)
    session.add(c)
    session.flush()
    return c


def _triage(session, es_id, status=AlertTriageStatus.OPEN, **kw):
    t = AlertTriage(es_alert_id=es_id, status=status, **kw)
    session.add(t)
    session.flush()
    return t


def _get(session, es_id):
    return session.query(AlertTriage).filter_by(es_alert_id=es_id).one()


class TestBulkAcknowledge:
    def test_acknowledges_an_open_alert(self, session):
        _triage(session, "a1")
        out = svc.bulk_acknowledge_alerts(session, ["a1"], analyst_id=7)
        assert out == {"processed": 1, "skipped": 0, "errors": []}
        assert _get(session, "a1").status is AlertTriageStatus.ACKNOWLEDGED

    def test_an_unknown_alert_gets_a_triage_row(self, session):
        """Alerts live in Elasticsearch; the triage row may not exist yet."""
        out = svc.bulk_acknowledge_alerts(session, ["new1"], analyst_id=7)
        assert out["processed"] == 1
        row = _get(session, "new1")
        assert row.status is AlertTriageStatus.ACKNOWLEDGED
        assert row.assigned_to_id == 7

    @pytest.mark.parametrize(
        "status", [AlertTriageStatus.ACKNOWLEDGED, AlertTriageStatus.CLOSED]
    )
    def test_already_handled_alerts_are_skipped(self, session, status):
        _triage(session, "a1", status=status)
        out = svc.bulk_acknowledge_alerts(session, ["a1"], analyst_id=7)
        assert out == {"processed": 0, "skipped": 1, "errors": []}

    def test_an_existing_assignment_is_not_taken_over(self, session):
        """Acknowledging someone else's alert must not reassign it."""
        _triage(session, "a1", assigned_to_id=42)
        svc.bulk_acknowledge_alerts(session, ["a1"], analyst_id=7)
        assert _get(session, "a1").assigned_to_id == 42

    def test_an_unassigned_alert_picks_up_the_acting_analyst(self, session):
        _triage(session, "a1", assigned_to_id=None)
        svc.bulk_acknowledge_alerts(session, ["a1"], analyst_id=7)
        assert _get(session, "a1").assigned_to_id == 7

    def test_counts_split_across_a_mixed_batch(self, session):
        _triage(session, "open1")
        _triage(session, "done1", status=AlertTriageStatus.CLOSED)
        out = svc.bulk_acknowledge_alerts(session, ["open1", "done1"], analyst_id=7)
        assert out["processed"] == 1 and out["skipped"] == 1

    def test_an_empty_batch_is_a_no_op(self, session):
        assert svc.bulk_acknowledge_alerts(session, [], analyst_id=7) == {
            "processed": 0, "skipped": 0, "errors": [],
        }


class TestBulkAssign:
    def test_reassigns_from_another_analyst(self, session):
        """Unlike acknowledge, assign is meant to take ownership."""
        _triage(session, "a1", assigned_to_id=42)
        out = svc.bulk_assign_alerts(session, ["a1"], analyst_id=7)
        assert out["processed"] == 1
        assert _get(session, "a1").assigned_to_id == 7

    def test_assigning_to_the_current_owner_is_skipped(self, session):
        _triage(session, "a1", assigned_to_id=7)
        out = svc.bulk_assign_alerts(session, ["a1"], analyst_id=7)
        assert out == {"processed": 0, "skipped": 1, "errors": []}

    def test_an_unknown_alert_gets_an_open_triage_row(self, session):
        svc.bulk_assign_alerts(session, ["new1"], analyst_id=7)
        row = _get(session, "new1")
        assert row.status is AlertTriageStatus.OPEN
        assert row.assigned_to_id == 7

    def test_assigning_does_not_change_status(self, session):
        _triage(session, "a1", status=AlertTriageStatus.ACKNOWLEDGED)
        svc.bulk_assign_alerts(session, ["a1"], analyst_id=7)
        assert _get(session, "a1").status is AlertTriageStatus.ACKNOWLEDGED


class TestBulkClose:
    def test_closes_an_open_alert(self, session):
        _triage(session, "a1")
        out = svc.bulk_close_alerts(session, ["a1"], analyst_id=7)
        assert out["processed"] == 1
        assert _get(session, "a1").status is AlertTriageStatus.CLOSED

    def test_an_already_closed_alert_is_skipped(self, session):
        _triage(session, "a1", status=AlertTriageStatus.CLOSED)
        out = svc.bulk_close_alerts(session, ["a1"], analyst_id=7)
        assert out == {"processed": 0, "skipped": 1, "errors": []}

    def test_an_unknown_alert_gets_a_closed_triage_row(self, session):
        svc.bulk_close_alerts(session, ["new1"], analyst_id=7)
        assert _get(session, "new1").status is AlertTriageStatus.CLOSED

    def test_closing_does_not_take_over_an_existing_assignment(self, session):
        """Closing someone else's alert must leave it attributed to them."""
        _triage(session, "a1", assigned_to_id=42)
        svc.bulk_close_alerts(session, ["a1"], analyst_id=7)
        assert _get(session, "a1").assigned_to_id == 42

    def test_closing_an_unassigned_alert_attributes_it_to_the_closer(self, session):
        _triage(session, "a1", assigned_to_id=None)
        svc.bulk_close_alerts(session, ["a1"], analyst_id=7)
        assert _get(session, "a1").assigned_to_id == 7

    def test_acknowledged_alerts_still_close(self, session):
        _triage(session, "a1", status=AlertTriageStatus.ACKNOWLEDGED)
        out = svc.bulk_close_alerts(session, ["a1"], analyst_id=7)
        assert out["processed"] == 1


class TestCaseCascade:
    """The expensive mistake: closing a case that still has live alerts."""

    def test_a_case_closes_when_its_last_alert_closes(self, session):
        u = _user(session)
        case = _case(session, u)
        _triage(session, "a1", case_id=case.id)
        _triage(session, "a2", case_id=case.id)

        svc.bulk_close_alerts(session, ["a1", "a2"], analyst_id=u.id,
                              closure_reason="false_positive")

        assert case.status is AlertCaseStatus.CLOSED
        assert case.closure_reason == "false_positive"
        assert case.closed_by_id == u.id
        assert case.closed_at is not None

    def test_a_case_stays_open_while_any_alert_is_open(self, session):
        u = _user(session)
        case = _case(session, u)
        _triage(session, "a1", case_id=case.id)
        _triage(session, "a2", case_id=case.id)

        svc.bulk_close_alerts(session, ["a1"], analyst_id=u.id)

        assert case.status is AlertCaseStatus.OPEN
        assert case.closed_at is None

    def test_an_acknowledged_sibling_also_holds_the_case_open(self, session):
        u = _user(session)
        case = _case(session, u)
        _triage(session, "a1", case_id=case.id)
        _triage(session, "a2", case_id=case.id,
                status=AlertTriageStatus.ACKNOWLEDGED)

        svc.bulk_close_alerts(session, ["a1"], analyst_id=u.id)

        assert case.status is AlertCaseStatus.OPEN

    def test_an_already_closed_case_is_left_alone(self, session, monkeypatch):
        """Re-closing would write a second AI-feedback row for one decision."""
        u = _user(session)
        case = _case(session, u, status=AlertCaseStatus.CLOSED)
        case.closure_reason = "true_positive"
        _triage(session, "a1", case_id=case.id)

        calls = []
        monkeypatch.setattr(svc, "record_close_feedback_safe",
                            lambda *a, **k: calls.append(a))

        svc.bulk_close_alerts(session, ["a1"], analyst_id=u.id,
                              closure_reason="false_positive")

        assert case.closure_reason == "true_positive"
        assert calls == []

    def test_feedback_is_recorded_once_for_the_closed_case(self, session, monkeypatch):
        u = _user(session)
        case = _case(session, u)
        _triage(session, "a1", case_id=case.id)
        _triage(session, "a2", case_id=case.id)

        calls = []
        monkeypatch.setattr(svc, "record_close_feedback_safe",
                            lambda *a, **k: calls.append(a))

        svc.bulk_close_alerts(session, ["a1", "a2"], analyst_id=u.id)

        assert len(calls) == 1

    def test_the_close_is_mirrored_to_kibana(self, session, monkeypatch):
        u = _user(session)
        case = _case(session, u)
        _triage(session, "a1", case_id=case.id)

        pushed = []
        import ion.services.kibana_sync_helpers as kib
        monkeypatch.setattr(kib, "push_case_status_to_kibana",
                            lambda _s, c: pushed.append(c.case_number))

        svc.bulk_close_alerts(session, ["a1"], analyst_id=u.id)

        assert pushed == ["CASE-1"]

    def test_alerts_with_no_case_close_without_a_cascade(self, session):
        _triage(session, "orphan", case_id=None)
        out = svc.bulk_close_alerts(session, ["orphan"], analyst_id=1)
        assert out["processed"] == 1 and out["errors"] == []


class TestErrorIsolation:
    """One bad row must not abandon the rest of the batch."""

    def test_a_failure_on_one_alert_leaves_the_others_processed(
        self, session, monkeypatch
    ):
        _triage(session, "a1")
        _triage(session, "a2")
        _triage(session, "a3")

        real_select, seen = svc.select, {"n": 0}

        def flaky(*a, **kw):
            seen["n"] += 1
            if seen["n"] == 2:
                raise RuntimeError("transient database hiccup")
            return real_select(*a, **kw)

        monkeypatch.setattr(svc, "select", flaky)
        out = svc.bulk_acknowledge_alerts(session, ["a1", "a2", "a3"], analyst_id=7)

        assert out["processed"] == 2
        assert len(out["errors"]) == 1
        assert out["errors"][0].startswith("a2:")
        assert _get(session, "a3").status is AlertTriageStatus.ACKNOWLEDGED

    def test_the_error_text_names_the_alert_but_not_the_internals(
        self, session, monkeypatch
    ):
        """safe_error keeps the raw exception out of an analyst-facing string."""
        _triage(session, "a1")

        def boom(*a, **kw):
            raise RuntimeError("connection string postgres://user:pw@host/db")

        monkeypatch.setattr(svc, "select", boom)
        out = svc.bulk_close_alerts(session, ["a1"], analyst_id=7)

        assert len(out["errors"]) == 1
        assert "postgres://" not in out["errors"][0]

    def test_a_cascade_failure_is_reported_not_raised(self, session, monkeypatch):
        u = _user(session)
        case = _case(session, u)
        _triage(session, "a1", case_id=case.id)

        monkeypatch.setattr(svc, "record_close_feedback_safe",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))

        out = svc.bulk_close_alerts(session, ["a1"], analyst_id=u.id)

        assert out["processed"] == 1
        assert any(e.startswith(f"case-{case.id}:") for e in out["errors"])

    def test_assign_also_isolates_a_failing_alert(self, session, monkeypatch):
        _triage(session, "a1")
        _triage(session, "a2")

        real_select, seen = svc.select, {"n": 0}

        def flaky(*a, **kw):
            seen["n"] += 1
            if seen["n"] == 1:
                raise RuntimeError("hiccup")
            return real_select(*a, **kw)

        monkeypatch.setattr(svc, "select", flaky)
        out = svc.bulk_assign_alerts(session, ["a1", "a2"], analyst_id=7)

        assert out["processed"] == 1
        assert len(out["errors"]) == 1
        assert _get(session, "a2").assigned_to_id == 7

    def test_a_triage_pointing_at_a_missing_case_is_survivable(self, session):
        """A deleted case must not strand the alerts that referenced it."""
        _triage(session, "a1", case_id=999_999)

        out = svc.bulk_close_alerts(session, ["a1"], analyst_id=7)

        assert out["processed"] == 1
        assert out["errors"] == []
        assert _get(session, "a1").status is AlertTriageStatus.CLOSED
