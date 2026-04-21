"""Webhook receiver -- generic POST endpoint to ingest alerts from external tools."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, Request
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

    Validates the webhook secret (ION_WEBHOOK_SECRET env var) and
    creates an AlertTriage record.
    """
    import os
    expected_secret = os.environ.get("ION_WEBHOOK_SECRET", "")
    if expected_secret and x_webhook_secret != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    from ion.core.config import get_config
    from ion.storage.database import get_engine, get_session_factory
    from ion.models.alert_triage import AlertTriage, AlertTriageStatus

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    try:
        # Create a triage record for the webhook alert
        alert_id = f"webhook-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        triage = AlertTriage(
            es_alert_id=alert_id,
            status=AlertTriageStatus.OPEN,
            source_system=alert.source,
        )
        session.add(triage)
        session.commit()

        logger.info(
            "Webhook alert received: %s from %s (source=%s)",
            alert.title, request.client.host, alert.source,
        )

        return {
            "ok": True,
            "alert_id": alert_id,
            "message": f"Alert '{alert.title}' ingested",
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/health")
async def webhook_health():
    """Health check for webhook endpoint."""
    return {"status": "ok", "endpoint": "/api/webhooks/alert"}
