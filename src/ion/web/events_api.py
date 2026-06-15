"""Server-Sent Events change-notification endpoint (v0.39.9).

A single long-lived ``GET /api/events/stream?topic=<name>`` per browser tab
replaces the old per-page ``setInterval`` pollers. See
``ion.services.event_stream`` for the cross-worker design rationale.

Auth model: the stream is **authentication-only** (any logged-in user). It
carries no sensitive payload — only opaque "something changed" signals — and
the browser reacts by calling the existing per-view JSON endpoints, which
enforce the fine-grained permissions. Authentication is done with a
short-lived session that is closed *before* streaming starts: a normal
``Depends(get_db_session)`` would keep its pooled connection open for the
entire (indefinite) life of the SSE response.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from ion.auth.dependencies import SESSION_COOKIE_NAME
from ion.auth.service import AuthService
from ion.services import event_stream
from ion.storage.database import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])


def _authenticate(request: Request) -> bool:
    """Validate the session token (cookie first, then Bearer) on a short-lived
    session that we close immediately. Returns True iff authenticated."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return False

    session = get_session_factory()()
    try:
        user = AuthService(session).validate_session(token)
        return user is not None
    finally:
        session.close()


@router.get("/api/events/stream")
async def events_stream(
    request: Request,
    topic: str = Query(..., min_length=1, max_length=64),
) -> StreamingResponse:
    """Long-lived SSE stream emitting ``refresh`` events for ``topic``.

    Status codes are chosen so the browser ``EventSource`` transitions to
    CLOSED (rather than retrying forever) when it should: the client helper
    in ``live-updates.js`` then falls back to ``setInterval`` polling.
    """
    if not event_stream.sse_enabled():
        # Feature disabled — CLOSED -> client polls instead.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SSE disabled"
        )
    if not _authenticate(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    if not event_stream.is_valid_topic(topic):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown topic"
        )

    return StreamingResponse(
        event_stream.event_generator(request, topic),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            # Disable nginx proxy buffering so events flush immediately.
            "X-Accel-Buffering": "no",
        },
    )
