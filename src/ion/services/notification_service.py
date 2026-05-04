"""High-level email notification helpers for ION.

This service sits on top of :class:`ion.services.smtp_service.SMTPService`
and renders Jinja2 templates from ``src/ion/web/templates/emails/`` to
produce transactional notifications — alert digests, case updates, SLA
breaches, and scheduled report deliveries.

All helpers are best-effort: if SMTP is disabled or fails, they log and
return ``False`` so callers (background jobs, SLA workers, report
schedulers) can treat notifications as advisory.
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ion.core.config import get_config
from ion.services.smtp_service import (
    EmailAttachment,
    SMTPService,
    get_smtp_service,
)

logger = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "web" / "templates" / "emails"


def _build_env() -> Environment:
    """Build the Jinja2 environment used for rendering email bodies."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["datetimeformat"] = _datetime_filter
    return env


def _datetime_filter(value: Any, fmt: str = "%Y-%m-%d %H:%M UTC") -> str:
    """Jinja filter: format a datetime / iso-string as a readable UTC stamp."""
    if value is None or value == "":
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime(fmt)
    return str(value)


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _html_to_text(html: str) -> str:
    """Very small HTML-to-text converter for generating a plain alternative."""
    if not html:
        return ""
    text = _HTML_TAG_RE.sub(" ", html)
    # Unescape common entities
    for entity, char in (
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
    ):
        text = text.replace(entity, char)
    return _WHITESPACE_RE.sub(" ", text).strip()


class NotificationService:
    """High-level email notifications, keyed off Jinja2 templates."""

    def __init__(self, smtp_service: Optional[SMTPService] = None):
        self.smtp = smtp_service or get_smtp_service()
        self._env = _build_env()

    # ------------------------------------------------------------------
    # Template rendering
    # ------------------------------------------------------------------

    def _render(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render a Jinja2 template from the emails/ directory."""
        template = self._env.get_template(template_name)
        return template.render(**context)

    def _common_context(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build a context dict with values shared across all emails."""
        config = get_config()
        ctx: Dict[str, Any] = {
            "ion_base_url": (config.base_url or "").rstrip("/"),
            "generated_at": datetime.now(timezone.utc),
            "from_name": config.smtp_from_name or "ION",
        }
        if extra:
            ctx.update(extra)
        return ctx

    # ------------------------------------------------------------------
    # High-level notification methods
    # ------------------------------------------------------------------

    async def send_alert_digest(
        self,
        alerts: Sequence[Dict[str, Any]],
        recipients: List[str],
        subject: Optional[str] = None,
    ) -> bool:
        """Send an alert digest email.

        Args:
            alerts: Iterable of alert dicts. Each alert should expose at
                minimum ``id``, ``title`` / ``rule_name``, ``severity``,
                ``created_at`` / ``@timestamp``, and optionally ``source``.
            recipients: Email addresses.
            subject: Override the default subject line.
        """
        if not self.smtp.is_available():
            logger.info("notification.alert_digest skipped: SMTP unavailable")
            return False
        if not recipients:
            logger.warning("notification.alert_digest skipped: no recipients")
            return False

        alert_list = list(alerts)
        subject = subject or f"ION alert digest — {len(alert_list)} alert(s)"
        context = self._common_context(
            {
                "alerts": alert_list,
                "alert_count": len(alert_list),
                "subject": subject,
            }
        )
        html_body = self._render("alert_digest.html", context)
        text_body = _html_to_text(html_body)
        return await self.smtp.send_email(
            to=recipients,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )

    async def send_case_update(
        self,
        case: Dict[str, Any],
        actors: Iterable[str],
        recipients: List[str],
        change_summary: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> bool:
        """Send a case-updated notification.

        Args:
            case: Dict describing the case. Expected keys: ``id`` / ``uuid``,
                ``title``, ``status``, ``severity``, ``assignee``,
                ``updated_at``.
            actors: Usernames responsible for the update (for the "updated by"
                line). Passed as an iterable to support multi-actor updates.
            recipients: Email addresses.
            change_summary: Optional free-form summary of what changed.
            subject: Override the default subject line.
        """
        if not self.smtp.is_available():
            logger.info("notification.case_update skipped: SMTP unavailable")
            return False
        if not recipients:
            logger.warning("notification.case_update skipped: no recipients")
            return False

        actor_list = [a for a in actors if a]
        case_title = case.get("title") or f"Case {case.get('id') or case.get('uuid') or ''}"
        subject = subject or f"[ION] Case update: {case_title}"
        context = self._common_context(
            {
                "case": case,
                "actors": actor_list,
                "change_summary": change_summary or "",
                "subject": subject,
            }
        )
        html_body = self._render("case_update.html", context)
        text_body = _html_to_text(html_body)
        return await self.smtp.send_email(
            to=recipients,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )

    async def send_sla_breach(
        self,
        case: Dict[str, Any],
        sla: Dict[str, Any],
        recipients: List[str],
        subject: Optional[str] = None,
    ) -> bool:
        """Send an SLA-breach alert email.

        Args:
            case: Dict describing the case.
            sla: Dict describing the SLA breach. Expected keys: ``name``,
                ``target_minutes``, ``elapsed_minutes``, ``breached_at``.
            recipients: Email addresses.
            subject: Override the default subject line.
        """
        if not self.smtp.is_available():
            logger.info("notification.sla_breach skipped: SMTP unavailable")
            return False
        if not recipients:
            logger.warning("notification.sla_breach skipped: no recipients")
            return False

        case_title = case.get("title") or f"Case {case.get('id') or case.get('uuid') or ''}"
        sla_name = sla.get("name") or "SLA"
        subject = subject or f"[ION] SLA breach — {sla_name}: {case_title}"
        context = self._common_context(
            {
                "case": case,
                "sla": sla,
                "subject": subject,
            }
        )
        html_body = self._render("sla_breach.html", context)
        text_body = _html_to_text(html_body)
        return await self.smtp.send_email(
            to=recipients,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )

    async def send_scheduled_report(
        self,
        report_bytes: bytes,
        filename: str,
        recipients: List[str],
        subject: Optional[str] = None,
        body_text: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> bool:
        """Deliver a scheduled report as an email attachment.

        Args:
            report_bytes: Raw bytes of the report artifact.
            filename: Suggested filename (used both for the attachment name
                and to infer content-type if not supplied).
            recipients: Email addresses.
            subject: Override the default subject line.
            body_text: Override the default text body.
            content_type: Override the attachment MIME type.
        """
        if not self.smtp.is_available():
            logger.info("notification.scheduled_report skipped: SMTP unavailable")
            return False
        if not recipients:
            logger.warning("notification.scheduled_report skipped: no recipients")
            return False

        subject = subject or f"[ION] Scheduled report: {filename}"
        body_text = body_text or (
            f"Attached is the scheduled ION report: {filename}.\n\n"
            f"Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}."
        )
        body_html = (
            f"<html><body style='font-family: sans-serif;'>"
            f"<p>Attached is the scheduled ION report: <strong>{filename}</strong>.</p>"
            f"<p>Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.</p>"
            f"</body></html>"
        )

        if not content_type:
            content_type = _infer_content_type(filename)

        attachment = EmailAttachment(
            filename=filename,
            content=report_bytes,
            content_type=content_type,
        )
        return await self.smtp.send_email(
            to=recipients,
            subject=subject,
            text_body=body_text,
            html_body=body_html,
            attachments=[attachment],
        )


def _infer_content_type(filename: str) -> str:
    """Guess a MIME content type from the filename extension."""
    lower = filename.lower()
    if lower.endswith(".pdf"):
        return "application/pdf"
    if lower.endswith(".csv"):
        return "text/csv"
    if lower.endswith(".json"):
        return "application/json"
    if lower.endswith(".html") or lower.endswith(".htm"):
        return "text/html"
    if lower.endswith(".xlsx"):
        return (
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        )
    if lower.endswith(".xls"):
        return "application/vnd.ms-excel"
    if lower.endswith(".zip"):
        return "application/zip"
    if lower.endswith(".txt") or lower.endswith(".log"):
        return "text/plain"
    return "application/octet-stream"


# Singleton instance
_notification_service: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    """Get the global notification service instance."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service


def reset_notification_service() -> None:
    """Reset the global notification service instance (for config changes)."""
    global _notification_service
    _notification_service = None
