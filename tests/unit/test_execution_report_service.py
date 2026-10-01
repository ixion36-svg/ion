"""Tests for execution_report_service — investigation reports from playbook runs.

This module was at 0% when the coverage ratchet first measured the tree. The
report it writes is the record of an investigation: what was done, by whom,
in what order. It is read after the fact, often by someone who was not there,
so the failures that cost something are a step missing from the table, a
timeline out of order, or a regeneration that silently forks a second
document instead of amending the first.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from ion.models.playbook import Playbook, PlaybookExecution, PlaybookStep
from ion.models.user import User
from ion.services.execution_report_service import (
    REPORT_COLLECTION_NAME,
    ExecutionReportService,
)


@pytest.fixture
def owner(session):
    u = User(username="analyst", email="a@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


@pytest.fixture
def service(session):
    return ExecutionReportService(session)


def _playbook(session, owner, name="Phishing Triage"):
    p = Playbook(name=name, is_active=True, trigger_conditions={},
                 created_by_id=owner.id)
    session.add(p)
    session.flush()
    return p


def _step(session, pb, order, title, step_type="manual"):
    s = PlaybookStep(playbook_id=pb.id, step_order=order, step_type=step_type,
                     title=title)
    session.add(s)
    session.flush()
    return s


def _execution(session, pb, *, statuses=None, outcome=None, notes=None,
               started=None, finished=None, executed_by=None, alert="alert-1"):
    e = PlaybookExecution(
        playbook_id=pb.id, es_alert_id=alert, status="completed",
        step_statuses=statuses, outcome=outcome, outcome_notes=notes,
        started_at=started, completed_at=finished,
        executed_by_id=executed_by.id if executed_by else None,
    )
    session.add(e)
    session.flush()
    return e


class TestReportData:
    def test_steps_appear_in_playbook_order(self, session, service, owner):
        pb = _playbook(session, owner)
        _step(session, pb, 2, "Second")
        _step(session, pb, 1, "First")
        ex = _execution(session, pb)

        data = service._build_report_data(ex)

        assert [s["title"] for s in data["steps"]] == ["First", "Second"]

    def test_a_step_with_no_recorded_status_reads_as_pending(
        self, session, service, owner
    ):
        """An abandoned run must still produce a complete step table."""
        pb = _playbook(session, owner)
        _step(session, pb, 1, "Untouched")
        ex = _execution(session, pb, statuses=None)

        step = service._build_report_data(ex)["steps"][0]

        assert step["status"] == "pending"
        assert step["action_taken"] == ""
        assert step["findings"] == ""

    def test_recorded_action_data_is_carried_into_the_table(
        self, session, service, owner
    ):
        pb = _playbook(session, owner)
        s1 = _step(session, pb, 1, "Check sender")
        ex = _execution(session, pb, statuses={str(s1.id): {
            "status": "completed",
            "completed_at": "2026-06-01T10:00:00",
            "notes": "looked fine",
            "action_data": {
                "action_taken": "checked headers",
                "findings": "spoofed",
                "evidence_collected": "headers.txt",
                "risk_assessment": "medium",
            },
        }})

        step = service._build_report_data(ex)["steps"][0]

        assert step["status"] == "completed"
        assert step["action_taken"] == "checked headers"
        assert step["findings"] == "spoofed"
        assert step["evidence"] == "headers.txt"
        assert step["risk"] == "medium"
        assert step["notes"] == "looked fine"

    def test_a_playbook_with_no_steps_yields_an_empty_table(
        self, session, service, owner
    ):
        ex = _execution(session, _playbook(session, owner))
        data = service._build_report_data(ex)
        assert data["steps"] == [] and data["timeline"] == []


class TestTimeline:
    def test_only_completed_steps_become_timeline_events(
        self, session, service, owner
    ):
        pb = _playbook(session, owner)
        s1 = _step(session, pb, 1, "Done")
        s2 = _step(session, pb, 2, "Not done")
        ex = _execution(session, pb, statuses={
            str(s1.id): {"status": "completed", "completed_at": "2026-06-01T10:00:00"},
            str(s2.id): {"status": "pending"},
        })

        timeline = service._build_report_data(ex)["timeline"]

        assert len(timeline) == 1
        assert "Step 1" in timeline[0]["description"]

    def test_the_timeline_is_chronological_not_step_order(
        self, session, service, owner
    ):
        """Steps are often completed out of order; the record must say so."""
        pb = _playbook(session, owner)
        s1 = _step(session, pb, 1, "First step")
        s2 = _step(session, pb, 2, "Second step")
        ex = _execution(session, pb, statuses={
            str(s1.id): {"status": "completed", "completed_at": "2026-06-01T18:00:00"},
            str(s2.id): {"status": "completed", "completed_at": "2026-06-01T09:00:00"},
        })

        times = [e["time"] for e in service._build_report_data(ex)["timeline"]]

        assert times == ["2026-06-01T09:00:00", "2026-06-01T18:00:00"]

    def test_an_unattributed_step_is_recorded_as_system(
        self, session, service, owner
    ):
        pb = _playbook(session, owner)
        s1 = _step(session, pb, 1, "Automated")
        ex = _execution(session, pb, statuses={
            str(s1.id): {"status": "completed", "completed_at": "2026-06-01T10:00:00"},
        })

        assert "by system" in service._build_report_data(ex)["timeline"][0]["description"]

    def test_the_completing_analyst_is_named(self, session, service, owner):
        pb = _playbook(session, owner)
        s1 = _step(session, pb, 1, "Manual")
        ex = _execution(session, pb, statuses={
            str(s1.id): {"status": "completed", "completed_at": "2026-06-01T10:00:00",
                         "completed_by_username": "bob"},
        })

        assert "by bob" in service._build_report_data(ex)["timeline"][0]["description"]


class TestAttribution:
    def test_an_explicit_analyst_wins(self, session, service, owner):
        ex = _execution(session, _playbook(session, owner), executed_by=owner)
        assert service._build_report_data(ex, "override")["analyst"] == "override"

    def test_otherwise_the_executing_user_is_used(self, session, service, owner):
        ex = _execution(session, _playbook(session, owner), executed_by=owner)
        assert service._build_report_data(ex)["analyst"] == "analyst"

    def test_an_unattributed_run_says_unknown(self, session, service, owner):
        ex = _execution(session, _playbook(session, owner), executed_by=None)
        assert service._build_report_data(ex)["analyst"] == "Unknown"


class TestOutcomeAndMetadata:
    @pytest.mark.parametrize("raw,label", [
        ("true_positive", "True Positive"),
        ("false_positive", "False Positive"),
        ("benign_true_positive", "Benign True Positive"),
        ("risk_accepted", "Risk Accepted"),
        ("inconclusive", "Inconclusive"),
        ("escalated", "Escalated"),
    ])
    def test_known_outcomes_are_given_their_label(self, session, service, owner,
                                                  raw, label):
        ex = _execution(session, _playbook(session, owner), outcome=raw)
        assert service._build_report_data(ex)["outcome_label"] == label

    def test_an_unrecognised_outcome_is_shown_verbatim(self, session, service, owner):
        """Better a raw value in the report than a silently blank field."""
        ex = _execution(session, _playbook(session, owner), outcome="custom_thing")
        assert service._build_report_data(ex)["outcome_label"] == "custom_thing"

    def test_no_outcome_reads_as_not_applicable(self, session, service, owner):
        ex = _execution(session, _playbook(session, owner), outcome=None)
        assert service._build_report_data(ex)["outcome_label"] == "N/A"

    def test_timestamps_are_isoformatted_and_blank_when_absent(
        self, session, service, owner
    ):
        pb = _playbook(session, owner)
        started = datetime(2026, 6, 1, 9, 0, 0)
        with_times = _execution(session, pb, started=started, finished=None)

        data = service._build_report_data(with_times)

        assert data["started_at"] == started.isoformat()
        assert data["completed_at"] == ""

    def test_an_unlinked_case_leaves_the_case_fields_blank(
        self, session, service, owner
    ):
        ex = _execution(session, _playbook(session, owner))
        data = service._build_report_data(ex)
        assert data["case_number"] == "" and data["case_title"] == ""


class TestGenerateReport:
    def test_a_document_is_created_and_linked_back(self, session, service, owner):
        pb = _playbook(session, owner)
        _step(session, pb, 1, "Check sender")
        ex = _execution(session, pb, outcome="true_positive")

        doc = service.generate_report(ex, analyst_username="bob")

        assert doc.id is not None
        assert ex.report_document_id == doc.id

    def test_the_rendered_report_carries_the_investigation_detail(
        self, session, service, owner
    ):
        pb = _playbook(session, owner, name="Phishing Triage")
        s1 = _step(session, pb, 1, "Check sender")
        ex = _execution(session, pb, outcome="true_positive",
                        notes="confirmed credential harvest",
                        statuses={str(s1.id): {"status": "completed",
                                               "completed_at": "2026-06-01T10:00:00"}})

        doc = service.generate_report(ex, analyst_username="bob")
        body = doc.rendered_content

        assert "Phishing Triage" in body
        assert "Check sender" in body
        assert "True Positive" in body
        assert "confirmed credential harvest" in body
        assert "bob" in body

    def test_the_document_name_identifies_the_execution(
        self, session, service, owner
    ):
        pb = _playbook(session, owner, name="Phishing Triage")
        ex = _execution(session, pb)

        doc = service.generate_report(ex)

        assert "Phishing Triage" in doc.name
        assert f"Exec #{ex.id}" in doc.name

    def test_reports_land_in_their_own_collection(self, session, service, owner):
        ex = _execution(session, _playbook(session, owner))

        service.generate_report(ex)

        assert service.collection_repo.get_by_name(REPORT_COLLECTION_NAME) is not None

    def test_the_collection_is_reused_not_duplicated(self, session, service, owner):
        pb = _playbook(session, owner)
        service.generate_report(_execution(session, pb, alert="a1"))
        first = service.collection_repo.get_by_name(REPORT_COLLECTION_NAME)

        service.generate_report(_execution(session, pb, alert="a2"))

        assert service.collection_repo.get_by_name(REPORT_COLLECTION_NAME).id == first.id


class TestRegenerateReport:
    def test_an_existing_report_is_amended_in_place(self, session, service, owner):
        """Forking a second document would leave two versions of the record."""
        pb = _playbook(session, owner)
        ex = _execution(session, pb, outcome="inconclusive")
        first = service.generate_report(ex)
        first_id = first.id

        ex.outcome = "true_positive"
        session.flush()
        again = service.regenerate_report(ex, analyst_username="bob")

        assert again.id == first_id
        assert "True Positive" in again.rendered_content

    def test_amending_bumps_the_document_version(self, session, service, owner):
        ex = _execution(session, _playbook(session, owner))
        first = service.generate_report(ex)
        before = first.current_version

        again = service.regenerate_report(ex)

        assert again.current_version > before

    def test_regenerating_without_a_prior_report_creates_one(
        self, session, service, owner
    ):
        ex = _execution(session, _playbook(session, owner))
        assert ex.report_document_id is None

        doc = service.regenerate_report(ex)

        assert doc.id is not None
        assert ex.report_document_id == doc.id

    def test_a_dangling_report_link_falls_back_to_creating(
        self, session, service, owner
    ):
        """A deleted document must not strand the execution without a report."""
        ex = _execution(session, _playbook(session, owner))
        ex.report_document_id = 999_999
        session.flush()

        doc = service.regenerate_report(ex)

        assert doc.id != 999_999
        assert ex.report_document_id == doc.id
