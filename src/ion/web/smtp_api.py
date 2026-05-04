"""Admin API endpoints for the SMTP notification service.

All endpoints require the ``admin:manage`` permission. They expose:

- ``POST /api/smtp/test``   — send a test email to a given address.
- ``GET  /api/smtp/status`` — report whether SMTP is enabled, configured,
  and available, along with non-secret connection parameters.

The router is mounted at ``/api/smtp`` by ``ion.web.server`` (see
Integration Checklist).
"""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.smtp_service import get_smtp_service, reset_smtp_service

router = APIRouter()


class SMTPTestRequest(BaseModel):
    """Body for POST /api/smtp/test."""

    to: EmailStr


class SMTPTestResponse(BaseModel):
    """Response body for POST /api/smtp/test."""

    ok: bool
    message: str


@router.get("/status")
async def smtp_status(
    current_user: User = Depends(require_permission("system:settings")),
):
    """Return SMTP service status (enabled, configured, available).

    Secret values are never returned — only boolean ``*_set`` flags.
    """
    service = get_smtp_service()
    return service.status()


@router.post("/test", response_model=SMTPTestResponse)
async def smtp_send_test(
    body: SMTPTestRequest,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Send a test email to the given address.

    Picks up the latest persisted config by resetting the service singleton
    before sending, so the test reflects in-flight admin changes.
    """
    # Reset so any config changes are picked up immediately.
    reset_smtp_service()
    service = get_smtp_service()

    if not service.enabled:
        raise HTTPException(status_code=400, detail="SMTP is disabled in configuration")
    if not service.is_configured:
        raise HTTPException(
            status_code=400,
            detail="SMTP is not fully configured (host and from address are required)",
        )

    ok, message = await service.send_test(body.to)
    return SMTPTestResponse(ok=ok, message=message)
