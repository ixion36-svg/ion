"""A false-positive close must stay closed.

Reported as "the FP sometimes doesn't actually update the statuses". The
close itself was right: the case, its triage rows and the Kibana case all
closed. What undid it was the alerts page. ``loadTriageBatch`` sends each
alert's Elasticsearch status, from a list fetched when the page loaded, and
``/alerts-triage/batch`` copied it onto the triage rows. Three close paths
(close-as-FP, the known-FP auto-close in create_case, bulk close) never set
the alerts closed in Elasticsearch, so ES still said "open", and the next
page load reopened every alert the close had just closed.

Pinned here: each of those paths closes the alerts in ES, the batch sync
never reopens an alert on a closed case, and the page stops replaying its
stale snapshot.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ion.models  # noqa: F401
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    KnownFalsePositive,
)
from ion.models.base import Base
from ion.models.user import User
import ion.services.kibana_cases_service as kcs


@pytest.fixture
def session(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'fp.db'}")
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
def es_closes(monkeypatch):
    """Every (alert_ids, status) ION asks Elasticsearch to set."""
    calls: list[tuple[list[str], str]] = []

    class FakeES:
        is_configured = True
        user_mapping_configured = False
        assignment_field = None

        async def update_alert_workflow_status(self, alert_ids, ion_status):
            calls.append((sorted(alert_ids), ion_status))
            return True

        async def get_alerts_by_ids(self, *a, **k):
            return []

        async def index_case(self, *a, **k):
            return None

    import ion.services.elasticsearch_service as ess
    monkeypatch.setattr(ess, "ElasticsearchService", FakeES)
    return calls


def _case_with_alerts(session, *alert_ids, status=AlertCaseStatus.OPEN) -> AlertCase:
    case = AlertCase(case_number="CASE-1", title="t", severity="high",
                     status=status, created_by_id=1, source_alert_ids=list(alert_ids))
    session.add(case)
    session.flush()
    for aid in alert_ids:
        session.add(AlertTriage(es_alert_id=aid, status=AlertTriageStatus.OPEN,
                                case_id=case.id))
    session.commit()
    return case


class TestClosePathsCloseTheAlertsInElasticsearch:
    def test_close_as_fp(self, session, es_closes):
        import ion.web.case_lifecycle_api as api

        case = _case_with_alerts(session, "a-1", "a-2")
        kfp = KnownFalsePositive(title="scanner", description="d", created_by_id=1)
        session.add(kfp)
        session.commit()

        asyncio.run(api.close_case_as_known_fp(
            case_id=case.id, data=api.CloseAsFPRequest(known_fp_id=kfp.id),
            current_user=session.get(User, 1), session=session))

        assert (["a-1", "a-2"], "closed") in es_closes

    def test_known_fp_auto_close_on_create(self, session, es_closes, monkeypatch):
        import ion.web.case_lifecycle_api as api
        from ion.core.config import get_config

        monkeypatch.setattr(get_config(), "case_grouper_auto_investigate", False)
        monkeypatch.setattr(api, "_match_known_false_positives", lambda *a, **k: [
            {"id": 1, "title": "scanner", "matched_fields": ["rules", "hosts"]}])

        result = asyncio.run(api.create_case(
            data=api.CaseCreate(title="t", alert_ids=["a-1", "a-2"],
                                triggered_rules=["r"], affected_hosts=["h"]),
            current_user=session.get(User, 1), session=session))

        assert result["auto_closed"] is True
        assert (["a-1", "a-2"], "closed") in es_closes

    def test_bulk_close(self, session, es_closes):
        from ion.web import bulk_ops_api

        _case_with_alerts(session, "a-1", "a-2")
        bulk_ops_api.bulk_close(
            request=None, data=bulk_ops_api.BulkCloseRequest(alert_ids=["a-1", "a-2"]),
            current_user=session.get(User, 1), session=session)

        assert (["a-1", "a-2"], "closed") in es_closes


class TestBatchSyncKeepsClosedCasesClosed:
    @staticmethod
    def _batch(session, es_statuses):
        from ion.web import api

        user = SimpleNamespace(has_permission=lambda perm: True)
        return asyncio.run(api.get_batch_triage(
            data=api.BatchTriageRequestWithStatus(
                alert_ids=list(es_statuses), es_statuses=es_statuses),
            current_user=user, session=session))

    def test_a_stale_open_does_not_reopen_an_alert_on_a_closed_case(self, session):
        _case_with_alerts(session, "a-1", status=AlertCaseStatus.CLOSED)
        row = session.query(AlertTriage).filter_by(es_alert_id="a-1").one()
        row.status = AlertTriageStatus.CLOSED
        session.commit()

        result = self._batch(session, {"a-1": "open"})

        session.expire_all()
        assert session.query(AlertTriage).filter_by(es_alert_id="a-1").one().status \
            == AlertTriageStatus.CLOSED
        assert result["triage"]["a-1"]["status"] == "closed"

    def test_a_kibana_reopen_still_reaches_an_alert_outside_a_closed_case(self, session):
        session.add(AlertTriage(es_alert_id="a-2", status=AlertTriageStatus.CLOSED))
        session.commit()

        self._batch(session, {"a-2": "open"})

        session.expire_all()
        assert session.query(AlertTriage).filter_by(es_alert_id="a-2").one().status \
            == AlertTriageStatus.OPEN


def test_the_page_adopts_the_servers_status_after_a_batch():
    page = (Path(__file__).resolve().parent.parent
            / "src/ion/web/templates/alerts.html").read_text(encoding="utf-8")
    start = page.index("async function loadTriageBatch()")
    body = page[start:page.index("\n}\n", start)]
    assert "a.status = t.status" in body
