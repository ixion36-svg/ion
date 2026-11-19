"""Alerts going into, and out of, a case.

- A repeat create for the same alerts returns the first case, not a second.
- Alerts linked to an open case are acknowledged, and ES is told, so the
  alert queue stops reading them back as open.
- The triage batch sync no longer reopens an acknowledged alert of an open
  case from a stale ES "open".
- Alerts can be removed from a case; acknowledged ones go back to open.
- Adding to an existing case acknowledges and records the ids on the case.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

import ion.web.case_lifecycle_api as cl
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
from ion.models.user import User


@pytest.fixture
def db(session):
    User.metadata.create_all(session.get_bind())
    user = User(username="analyst", email="a@ion.lab", password_hash="x")
    session.add(user)
    session.commit()
    return session, user


@pytest.fixture
def es_pushes(monkeypatch):
    calls = []
    monkeypatch.setattr(cl, "_spawn_alert_workflow_sync",
                        lambda ids, status: calls.append((sorted(ids), status)) if ids else None)
    return calls


def _create(session, user, alert_ids, title="t"):
    data = cl.CaseCreate(title=title, alert_ids=alert_ids)
    obs = MagicMock()
    obs.enrich_and_link_observables_for_case = AsyncMock(return_value=[])
    with patch("ion.services.observable_service.get_observable_service", return_value=obs), \
         patch.object(cl, "_match_known_false_positives", return_value=[]), \
         patch.object(cl, "_should_investigate_new_case", return_value=False), \
         patch.object(cl, "get_kibana_cases_service", return_value=SimpleNamespace(enabled=False)):
        return asyncio.run(cl.create_case(data, user, session))


def _triage(session, alert_id):
    return session.query(AlertTriage).filter_by(es_alert_id=alert_id).one()


def test_a_repeat_create_for_the_same_alerts_returns_the_first_case(db, es_pushes):
    session, user = db
    first = _create(session, user, ["a1", "a2"])
    again = _create(session, user, ["a2", "a1"])

    assert again["duplicate"] is True
    assert again["id"] == first["id"]
    assert session.query(AlertCase).count() == 1


def test_a_different_selection_still_makes_a_new_case(db, es_pushes):
    session, user = db
    first = _create(session, user, ["a1", "a2"])
    other = _create(session, user, ["a1", "a2", "a3"])

    assert not other.get("duplicate")
    assert other["id"] != first["id"]


def test_linked_alerts_are_acknowledged_in_ion_and_es(db, es_pushes):
    session, user = db
    session.add_all([
        AlertTriage(es_alert_id="open1", status=AlertTriageStatus.OPEN),
        AlertTriage(es_alert_id="closed1", status=AlertTriageStatus.CLOSED),
    ])
    session.commit()

    _create(session, user, ["open1", "closed1", "new1"])

    assert _triage(session, "open1").status == AlertTriageStatus.ACKNOWLEDGED
    assert _triage(session, "new1").status == AlertTriageStatus.ACKNOWLEDGED
    assert _triage(session, "closed1").status == AlertTriageStatus.CLOSED
    assert es_pushes == [(["new1", "open1"], "acknowledged")]


def test_removing_alerts_unlinks_and_reopens_them(db, es_pushes):
    session, user = db
    case = _create(session, user, ["a1", "a2", "a3"])
    es_pushes.clear()
    _triage(session, "a3").status = AlertTriageStatus.CLOSED
    session.commit()

    out = asyncio.run(cl.remove_alerts_from_case(
        case["id"], cl.CaseAlertRemove(alert_ids=["a1", "a3", "elsewhere"]), user, session))

    assert out["removed"] == 2 and out["reopened"] == 1
    assert out["not_in_case"] == ["elsewhere"]
    a1 = _triage(session, "a1")
    assert a1.case_id is None and a1.status == AlertTriageStatus.OPEN
    assert _triage(session, "a3").status == AlertTriageStatus.CLOSED
    assert _triage(session, "a2").case_id == case["id"]
    assert session.get(AlertCase, case["id"]).source_alert_ids == ["a2"]
    assert es_pushes == [(["a1"], "open")]


def test_a_closed_case_keeps_its_alerts(db, es_pushes):
    session, user = db
    case = _create(session, user, ["a1"])
    session.get(AlertCase, case["id"]).status = AlertCaseStatus.CLOSED
    session.commit()

    with pytest.raises(HTTPException) as e:
        asyncio.run(cl.remove_alerts_from_case(
            case["id"], cl.CaseAlertRemove(alert_ids=["a1"]), user, session))
    assert e.value.status_code == 409


def test_batch_sync_does_not_reopen_an_alert_of_an_open_case(db, es_pushes, monkeypatch):
    from ion.web import api

    session, user = db
    _create(session, user, ["a1"])
    user.has_permission = lambda p: True
    monkeypatch.setattr(api, "_observable_threat_levels", lambda s, rows: {})

    out = asyncio.run(api.get_batch_triage(
        api.BatchTriageRequestWithStatus(alert_ids=["a1"], es_statuses={"a1": "open"}),
        user, session))

    assert out["triage"]["a1"]["status"] == "acknowledged"


def test_adding_to_an_existing_case_acknowledges_and_records_the_ids(db, es_pushes, monkeypatch):
    from ion.web import api

    session, user = db
    target = _create(session, user, ["a1"])
    other = _create(session, user, ["b1", "b2"])
    pushed = []

    class FakeES:
        is_configured = True
        assignment_field = None

        async def update_alert_workflow_status(self, ids, status):
            pushed.append((sorted(ids), status))

    monkeypatch.setattr("ion.services.elasticsearch_service.ElasticsearchService", FakeES)
    asyncio.run(api.bulk_update_triage(
        api.BulkTriageUpdate(alert_ids=["b1", "c1"], case_id=target["id"]), user, session))

    assert set(session.get(AlertCase, target["id"]).source_alert_ids) == {"a1", "b1", "c1"}
    assert session.get(AlertCase, other["id"]).source_alert_ids == ["b2"]
    assert _triage(session, "c1").status == AlertTriageStatus.ACKNOWLEDGED
    assert pushed == [(["c1"], "acknowledged")]
