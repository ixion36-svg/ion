"""Triaging one alert inside a case must not close the case.

POST /elasticsearch/alerts/{id}/close is the alert window's close: the
first alert closed this way closes its case and every other alert in it.
The case window triages a case's alerts one at a time through the same
endpoint, so it sends close_case=false. Pinned here: with the flag the
verdict is recorded (the alert's status, the case note, Elasticsearch for
that alert only) and nothing else moves; without it the old close stands.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ion.models  # noqa: F401
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    Note,
)
from ion.models.base import Base
from ion.models.user import User
import ion.services.kibana_cases_service as kcs


@pytest.fixture
def session(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'close.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(User(id=1, username="admin", email="a@x", password_hash="x", is_active=True))
    s.commit()
    disabled = kcs.KibanaCasesService.__new__(kcs.KibanaCasesService)
    disabled.config = {"enabled": False}
    disabled._client = None
    monkeypatch.setattr(kcs, "_kibana_service", disabled)
    yield s
    s.close()


@pytest.fixture
def es_writes(monkeypatch):
    calls: list[tuple[list[str], str]] = []

    class FakeES:
        is_configured = True
        assignment_field = None

        async def update_alert_workflow_status(self, alert_ids, ion_status):
            calls.append((sorted(alert_ids), ion_status))
            return True

    import ion.services.elasticsearch_service as ess
    monkeypatch.setattr(ess, "ElasticsearchService", FakeES)
    return calls


@pytest.fixture
def kibana_pushes(monkeypatch):
    calls: list[int] = []
    import ion.services.kibana_sync_helpers as helpers
    monkeypatch.setattr(helpers, "push_case_status_to_kibana",
                        lambda session, case: calls.append(case.id))
    return calls


def _case(session, *alert_ids) -> AlertCase:
    case = AlertCase(case_number="CASE-1", title="t", severity="high",
                     status=AlertCaseStatus.OPEN, created_by_id=1,
                     source_alert_ids=list(alert_ids))
    session.add(case)
    session.flush()
    for aid in alert_ids:
        session.add(AlertTriage(es_alert_id=aid, status=AlertTriageStatus.OPEN, case_id=case.id))
    session.commit()
    return case


def _close(session, alert_id, closure_type, **extra):
    import ion.web.api as api
    return asyncio.run(api.close_alert(
        alert_id=alert_id,
        data=api.AlertClosureRequest(closure_type=closure_type, **extra),
        current_user=session.get(User, 1), session=session))


def _status(session, alert_id):
    session.expire_all()
    return session.query(AlertTriage).filter_by(es_alert_id=alert_id).one().status


@pytest.mark.parametrize("closure_type, status", [
    ("benign", AlertTriageStatus.CLOSED),
    ("false_positive", AlertTriageStatus.CLOSED),
    ("escalated", AlertTriageStatus.ACKNOWLEDGED),
])
def test_close_case_false_records_the_verdict_and_leaves_the_case_open(
        session, es_writes, kibana_pushes, closure_type, status):
    case = _case(session, "a-1", "a-2", "a-3")

    result = _close(session, "a-1", closure_type, close_case=False)

    assert result["case_closed"] is False
    assert result["note_added_to_case"] is True
    assert result["status"] == status.value
    session.expire_all()
    assert session.get(AlertCase, case.id).status == AlertCaseStatus.OPEN
    assert session.get(AlertCase, case.id).closure_reason is None
    assert _status(session, "a-1") == status
    assert [_status(session, a) for a in ("a-2", "a-3")] == [AlertTriageStatus.OPEN] * 2
    assert es_writes == [(["a-1"], status.value)]
    assert kibana_pushes == []
    label = closure_type.replace("_", " ").title()
    notes = session.query(Note).filter_by(entity_id=str(case.id)).all()
    assert [n.content.splitlines()[:2] for n in notes] == [
        ["**Alert closed as %s**" % label, "Alert: `a-1`"]]


def test_the_alert_windows_close_still_closes_the_case_and_its_alerts(
        session, es_writes, kibana_pushes):
    case = _case(session, "a-1", "a-2")

    result = _close(session, "a-1", "false_positive")

    assert result["case_closed"] is True
    session.expire_all()
    closed = session.get(AlertCase, case.id)
    assert closed.status == AlertCaseStatus.CLOSED
    assert closed.closure_reason == "false_positive"
    assert _status(session, "a-2") == AlertTriageStatus.CLOSED
    assert es_writes == [(["a-1", "a-2"], "closed")]
    assert kibana_pushes == [case.id]
