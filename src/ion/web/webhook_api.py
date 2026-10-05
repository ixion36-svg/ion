"""Webhook receiver -- generic POST endpoint to ingest alerts from external tools."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class WebhookAlert(BaseModel):
    title: str
    severity: str = "medium"
    source: str = "webhook"
    message: str = ""
    host: Optional[str] = None
    user: Optional[str] = None
    tags: list[str] = []
    raw_data: Optional[dict] = None


@router.post("/alert")
async def receive_alert_webhook(
    alert: WebhookAlert,
    request: Request,
    x_webhook_secret: str = Header(None, alias="X-Webhook-Secret"),
):
    """Receive an alert from an external tool via webhook.

    Validates the webhook secret (ION_WEBHOOK_SECRET env var), then writes the
    triage state and the submitted payload in one transaction, so a successful
    acknowledgement means the evidence is durable.

    Fail-closed: if the secret is not configured, the endpoint is disabled.
    Previously the check was bypassed when the env var was empty, allowing
    unauthenticated alert injection.

    Not idempotent: each delivery gets a fresh alert_id, so a sender that
    retries creates a second alert. Deduplicating needs a caller-supplied key,
    which would be a change to this endpoint's contract.
    """
    import hmac
    import os
    expected_secret = os.environ.get("ION_WEBHOOK_SECRET", "")
    if not expected_secret:
        raise HTTPException(
            status_code=503,
            detail="Webhook receiver disabled: set ION_WEBHOOK_SECRET to enable.",
        )
    if not x_webhook_secret or not hmac.compare_digest(x_webhook_secret, expected_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    from ion.core.config import get_config
    from ion.core.safe_errors import safe_error
    from ion.models.alert_triage import AlertTriage, AlertTriageStatus
    from ion.models.integration import (
        IntegrationEvent,
        IntegrationEventType,
        IntegrationType,
        WebhookStatus,
    )
    from ion.storage.database import get_engine, get_session_factory

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    source_ip = request.client.host if request.client else None

    try:
        # Create a triage record for the webhook alert
        alert_id = f"webhook-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        triage = AlertTriage(
            es_alert_id=alert_id,
            status=AlertTriageStatus.OPEN,
            source_system=alert.source,
            priority=alert.severity,
            rule_name=alert.title,
        )
        session.add(triage)

        # The submitted alert, kept verbatim. The triage row carries workflow
        # state, not evidence: there is no Elasticsearch document behind a
        # webhook alert_id, so without this row the message, host, user, tags
        # and raw payload were acknowledged and then dropped, leaving an
        # incident that could not be reconstructed from anything ION stored.
        session.add(IntegrationEvent(
            event_type=IntegrationEventType.WEBHOOK,
            integration_type=IntegrationType.CUSTOM,
            status=WebhookStatus.SUCCESS,
            webhook_event_type="alert",
            action="receive_alert",
            message=alert.title,
            payload=alert.model_dump(),
            source_ip=source_ip,
            details={"es_alert_id": alert_id},
        ))

        # One transaction: the acknowledgement below must not claim durability
        # the evidence row did not get.
        session.commit()

        logger.info(
            "Webhook alert received: %s from %s (source=%s)",
            alert.title, source_ip, alert.source,
        )

        return {
            "ok": True,
            "alert_id": alert_id,
            "message": f"Alert '{alert.title}' ingested",
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=safe_error(e, "webhook_alert_ingest"))
    finally:
        session.close()


@router.get("/health")
async def webhook_health():
    """Health check for webhook endpoint."""
    return {"status": "ok", "endpoint": "/api/webhooks/alert"}
