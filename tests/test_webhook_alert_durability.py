"""A webhook alert that is acknowledged must be reconstructable afterwards.

POST /api/webhooks/alert accepted a title, severity, message, host, user, tags
and raw_data, wrote an AlertTriage row holding only a generated id, OPEN status
and the source, and returned ok:true. The title reached a log line; everything
else was dropped at request end. There is no Elasticsearch document behind a
webhook alert_id, so nothing ION stored could rebuild the incident.

The submitted payload now lands in an IntegrationEvent row — the same durable
record the integration webhook receiver writes — in the triage row's
transaction.
"""

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from ion.models.alert_triage import AlertTriage
from ion.models.base import Base
from ion.models.integration import IntegrationEvent
from ion.storage import database as storage
from ion.web.webhook_api import WebhookAlert, receive_alert_webhook

SECRET = "test-webhook-secret"


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setenv("ION_WEBHOOK_SECRET", SECRET)
    monkeypatch.setattr(storage, "get_engine", lambda *a, **k: engine)
    monkeypatch.setattr(storage, "get_session_factory", lambda *a, **k: factory)
    yield factory
    engine.dispose()


def _request():
    return Request({"type": "http", "method": "POST", "path": "/api/webhooks/alert",
                    "headers": [], "client": ("192.0.2.1", 1234), "query_string": b""})


def _alert():
    return WebhookAlert(
        title="Credential dumping on host-01", severity="critical", source="edr",
        message="lsass access by unsigned binary", host="host-01", user="svc-backup",
        tags=["t1003", "endpoint"], raw_data={"evidence": "procdump.exe lsass.exe"},
    )


def _ingest(factory):
    response = asyncio.run(receive_alert_webhook(_alert(), _request(), SECRET))
    assert response["ok"] is True
    return response


def test_every_submitted_field_survives(db):
    _ingest(db)
    with db() as s:
        event = s.query(IntegrationEvent).one()
    payload = event.payload
    assert payload["title"] == "Credential dumping on host-01"
    assert payload["severity"] == "critical"
    assert payload["message"] == "lsass access by unsigned binary"
    assert payload["host"] == "host-01"
    assert payload["user"] == "svc-backup"
    assert payload["tags"] == ["t1003", "endpoint"]
    assert payload["raw_data"] == {"evidence": "procdump.exe lsass.exe"}


def test_evidence_links_back_to_the_triage_row(db):
    response = _ingest(db)
    with db() as s:
        event = s.query(IntegrationEvent).one()
        triage = s.query(AlertTriage).one()
    assert event.details["es_alert_id"] == response["alert_id"]
    assert triage.es_alert_id == response["alert_id"]


def test_triage_row_carries_severity_and_title(db):
    _ingest(db)
    with db() as s:
        triage = s.query(AlertTriage).one()
    assert triage.priority == "critical"
    assert triage.rule_name == "Credential dumping on host-01"
    assert triage.source_system == "edr"


def test_source_ip_is_recorded(db):
    _ingest(db)
    with db() as s:
        assert s.query(IntegrationEvent).one().source_ip == "192.0.2.1"


def test_acknowledgement_is_not_sent_without_the_evidence_row(db, monkeypatch):
    """ok:true must not outlive a failed commit."""
    from fastapi import HTTPException

    def exploding_commit(self):
        raise RuntimeError("durable write failed")

    monkeypatch.setattr("sqlalchemy.orm.Session.commit", exploding_commit)

    with pytest.raises(HTTPException) as caught:
        asyncio.run(receive_alert_webhook(_alert(), _request(), SECRET))
    assert caught.value.status_code == 500
    # The sanitized label, not the internal exception text.
    assert "durable write failed" not in str(caught.value.detail)


def test_bad_secret_is_refused(db):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        asyncio.run(receive_alert_webhook(_alert(), _request(), "wrong"))
    assert caught.value.status_code == 401
    with db() as s:
        assert s.query(IntegrationEvent).count() == 0
        assert s.query(AlertTriage).count() == 0


def test_disabled_without_a_configured_secret(db, monkeypatch):
    from fastapi import HTTPException

    monkeypatch.delenv("ION_WEBHOOK_SECRET")
    with pytest.raises(HTTPException) as caught:
        asyncio.run(receive_alert_webhook(_alert(), _request(), SECRET))
    assert caught.value.status_code == 503
