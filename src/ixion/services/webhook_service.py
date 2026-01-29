"""Webhook service for receiving events from external services.

Provides CRUD operations for webhooks and event processing with
token authentication and optional HMAC signature verification.
"""

import hmac
import hashlib
import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable, Awaitable

from sqlalchemy.orm import Session

from ixion.models.integration import (
    Webhook,
    WebhookLog,
    WebhookStatus,
    IntegrationType,
    generate_webhook_token,
)
from ixion.storage.database import get_session

logger = logging.getLogger(__name__)

# Type for webhook event handlers
WebhookHandler = Callable[[str, Dict[str, Any], Dict[str, Any]], Awaitable[Dict[str, Any]]]


class WebhookService:
    """Service for managing webhooks and processing events."""

    def __init__(self):
        self._handlers: Dict[str, Dict[str, WebhookHandler]] = {}

    # ==========================================================================
    # CRUD Operations
    # ==========================================================================

    def create_webhook(
        self,
        name: str,
        created_by_id: Optional[int] = None,
        source_type: IntegrationType = IntegrationType.CUSTOM,
        description: Optional[str] = None,
        secret: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        session: Optional[Session] = None,
    ) -> Webhook:
        """Create a new webhook.

        Args:
            name: Display name for the webhook.
            created_by_id: ID of the user creating the webhook.
            source_type: Type of integration this webhook receives from.
            description: Optional description.
            secret: Optional HMAC secret for signature verification.
            event_types: Optional list of event types to accept.
            session: Optional database session.

        Returns:
            The created Webhook instance.
        """
        def _create(sess: Session) -> Webhook:
            webhook = Webhook(
                name=name,
                description=description,
                token=generate_webhook_token(),
                secret=secret,
                source_type=source_type,
                event_types=event_types,
                created_by_id=created_by_id,
            )
            sess.add(webhook)
            sess.flush()
            sess.refresh(webhook)
            return webhook

        if session:
            return _create(session)

        for sess in get_session():
            return _create(sess)

    def get_webhook(self, webhook_id: int, session: Optional[Session] = None) -> Optional[Webhook]:
        """Get a webhook by ID.

        Args:
            webhook_id: The webhook ID.
            session: Optional database session.

        Returns:
            The Webhook instance or None.
        """
        def _get(sess: Session) -> Optional[Webhook]:
            return sess.query(Webhook).filter(Webhook.id == webhook_id).first()

        if session:
            return _get(session)

        for sess in get_session():
            return _get(sess)

    def get_webhook_by_token(self, token: str, session: Optional[Session] = None) -> Optional[Webhook]:
        """Get a webhook by its token.

        Args:
            token: The webhook token.
            session: Optional database session.

        Returns:
            The Webhook instance or None.
        """
        def _get(sess: Session) -> Optional[Webhook]:
            return sess.query(Webhook).filter(Webhook.token == token).first()

        if session:
            return _get(session)

        for sess in get_session():
            return _get(sess)

    def list_webhooks(
        self,
        source_type: Optional[IntegrationType] = None,
        is_active: Optional[bool] = None,
        session: Optional[Session] = None,
    ) -> List[Webhook]:
        """List webhooks with optional filters.

        Args:
            source_type: Filter by source type.
            is_active: Filter by active status.
            session: Optional database session.

        Returns:
            List of matching Webhook instances.
        """
        def _list(sess: Session) -> List[Webhook]:
            query = sess.query(Webhook)
            if source_type is not None:
                query = query.filter(Webhook.source_type == source_type)
            if is_active is not None:
                query = query.filter(Webhook.is_active == is_active)
            return query.order_by(Webhook.created_at.desc()).all()

        if session:
            return _list(session)

        for sess in get_session():
            return _list(sess)

    def update_webhook(
        self,
        webhook_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        secret: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        session: Optional[Session] = None,
    ) -> Optional[Webhook]:
        """Update a webhook.

        Args:
            webhook_id: The webhook ID to update.
            name: New name (optional).
            description: New description (optional).
            secret: New HMAC secret (optional).
            event_types: New event types (optional).
            is_active: New active status (optional).
            session: Optional database session.

        Returns:
            The updated Webhook instance or None.
        """
        def _update(sess: Session) -> Optional[Webhook]:
            webhook = sess.query(Webhook).filter(Webhook.id == webhook_id).first()
            if not webhook:
                return None

            if name is not None:
                webhook.name = name
            if description is not None:
                webhook.description = description
            if secret is not None:
                webhook.secret = secret
            if event_types is not None:
                webhook.event_types = event_types
            if is_active is not None:
                webhook.is_active = is_active

            sess.flush()
            sess.refresh(webhook)
            return webhook

        if session:
            return _update(session)

        for sess in get_session():
            return _update(sess)

    def delete_webhook(self, webhook_id: int, session: Optional[Session] = None) -> bool:
        """Delete a webhook.

        Args:
            webhook_id: The webhook ID to delete.
            session: Optional database session.

        Returns:
            True if deleted, False if not found.
        """
        def _delete(sess: Session) -> bool:
            webhook = sess.query(Webhook).filter(Webhook.id == webhook_id).first()
            if not webhook:
                return False
            sess.delete(webhook)
            return True

        if session:
            return _delete(session)

        for sess in get_session():
            return _delete(sess)

    def regenerate_token(self, webhook_id: int, session: Optional[Session] = None) -> Optional[str]:
        """Regenerate the token for a webhook.

        Args:
            webhook_id: The webhook ID.
            session: Optional database session.

        Returns:
            The new token or None if webhook not found.
        """
        def _regenerate(sess: Session) -> Optional[str]:
            webhook = sess.query(Webhook).filter(Webhook.id == webhook_id).first()
            if not webhook:
                return None

            new_token = generate_webhook_token()
            webhook.token = new_token
            sess.flush()
            return new_token

        if session:
            return _regenerate(session)

        for sess in get_session():
            return _regenerate(sess)

    # ==========================================================================
    # Signature Verification
    # ==========================================================================

    def verify_signature(
        self,
        webhook: Webhook,
        payload: bytes,
        signature: str,
    ) -> bool:
        """Verify HMAC signature of a webhook payload.

        Args:
            webhook: The webhook to verify against.
            payload: The raw request body as bytes.
            signature: The signature header value.

        Returns:
            True if signature is valid or webhook has no secret.
        """
        if not webhook.secret:
            # No secret configured, signature not required
            return True

        if not signature:
            return False

        # Support common signature formats
        # GitHub: sha256=<signature>
        # GitLab: <signature> (just the hex)
        expected_prefix = "sha256="
        if signature.startswith(expected_prefix):
            signature = signature[len(expected_prefix):]

        expected = hmac.new(
            webhook.secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected, signature)

    # ==========================================================================
    # Event Processing
    # ==========================================================================

    def register_handler(
        self,
        source_type: str,
        event_type: str,
        handler: WebhookHandler,
    ) -> None:
        """Register a handler for webhook events.

        Args:
            source_type: The source type (e.g., 'gitlab', 'custom').
            event_type: The event type (e.g., 'push', 'issue').
            handler: Async function to handle the event.
        """
        if source_type not in self._handlers:
            self._handlers[source_type] = {}
        self._handlers[source_type][event_type] = handler
        logger.debug("Registered handler for %s/%s", source_type, event_type)

    async def process_webhook(
        self,
        token: str,
        event_type: Optional[str],
        payload: Dict[str, Any],
        headers: Dict[str, str],
        source_ip: Optional[str] = None,
        signature: Optional[str] = None,
        raw_payload: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Process an incoming webhook event.

        Args:
            token: The webhook token from the URL.
            event_type: The event type (from header or payload).
            payload: The parsed JSON payload.
            headers: Request headers.
            source_ip: Source IP address.
            signature: Optional signature header for verification.
            raw_payload: Raw payload bytes for signature verification.

        Returns:
            Dictionary with processing result.
        """
        start_time = time.perf_counter()

        for session in get_session():
            # Find webhook by token
            webhook = session.query(Webhook).filter(Webhook.token == token).first()

            if not webhook:
                return {
                    "success": False,
                    "error": "Invalid webhook token",
                    "status": "not_found",
                }

            if not webhook.is_active:
                return {
                    "success": False,
                    "error": "Webhook is disabled",
                    "status": "disabled",
                }

            # Verify signature if webhook has a secret
            if webhook.secret and raw_payload:
                if not self.verify_signature(webhook, raw_payload, signature or ""):
                    log_entry = WebhookLog(
                        webhook_id=webhook.id,
                        event_type=event_type,
                        payload=payload,
                        headers=dict(headers),
                        source_ip=source_ip,
                        status=WebhookStatus.INVALID_SIGNATURE,
                        error_message="Signature verification failed",
                        processing_time_ms=(time.perf_counter() - start_time) * 1000,
                    )
                    session.add(log_entry)
                    session.flush()

                    return {
                        "success": False,
                        "error": "Invalid signature",
                        "status": "invalid_signature",
                    }

            # Check if event type is allowed
            if webhook.event_types and event_type:
                if event_type not in webhook.event_types:
                    return {
                        "success": False,
                        "error": f"Event type '{event_type}' not allowed",
                        "status": "event_not_allowed",
                    }

            # Process the event
            result = {"processed": True}
            status = WebhookStatus.SUCCESS
            error_message = None

            try:
                # Find and execute handler
                source_type = webhook.source_type.value if hasattr(webhook.source_type, 'value') else str(webhook.source_type)
                handlers = self._handlers.get(source_type, {})
                handler = handlers.get(event_type) or handlers.get("*")

                if handler:
                    result = await handler(event_type, payload, dict(headers))
            except Exception as e:
                logger.exception("Error processing webhook %s: %s", webhook.id, e)
                status = WebhookStatus.HANDLER_ERROR
                error_message = str(e)
                result = {"processed": False, "error": str(e)}

            # Update webhook stats
            webhook.trigger_count += 1
            webhook.last_triggered_at = datetime.utcnow()

            # Log the event
            processing_time_ms = (time.perf_counter() - start_time) * 1000
            log_entry = WebhookLog(
                webhook_id=webhook.id,
                event_type=event_type,
                payload=payload,
                headers=dict(headers),
                source_ip=source_ip,
                status=status,
                error_message=error_message,
                processing_time_ms=processing_time_ms,
            )
            session.add(log_entry)
            session.flush()

            return {
                "success": status == WebhookStatus.SUCCESS,
                "webhook_id": webhook.id,
                "event_type": event_type,
                "processing_time_ms": processing_time_ms,
                "result": result,
            }

    # ==========================================================================
    # Log Operations
    # ==========================================================================

    def get_webhook_logs(
        self,
        webhook_id: int,
        status: Optional[WebhookStatus] = None,
        limit: int = 50,
        offset: int = 0,
        session: Optional[Session] = None,
    ) -> List[WebhookLog]:
        """Get logs for a webhook.

        Args:
            webhook_id: The webhook ID.
            status: Optional status filter.
            limit: Maximum number of logs to return.
            offset: Number of logs to skip.
            session: Optional database session.

        Returns:
            List of WebhookLog instances.
        """
        def _get_logs(sess: Session) -> List[WebhookLog]:
            query = sess.query(WebhookLog).filter(WebhookLog.webhook_id == webhook_id)
            if status is not None:
                query = query.filter(WebhookLog.status == status)
            return query.order_by(WebhookLog.created_at.desc()).offset(offset).limit(limit).all()

        if session:
            return _get_logs(session)

        for sess in get_session():
            return _get_logs(sess)


# Singleton instance
_webhook_service: Optional[WebhookService] = None


def get_webhook_service() -> WebhookService:
    """Get the global WebhookService instance."""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService()
    return _webhook_service


def reset_webhook_service() -> None:
    """Reset the global WebhookService instance."""
    global _webhook_service
    _webhook_service = None
