"""SMTP email service for ION.

Provides a real asynchronous SMTP client (via aiosmtplib) with support for
both STARTTLS (default, e.g. port 587) and implicit TLS (e.g. port 465).
All configuration is driven by the global :mod:`ion.core.config` Config
dataclass — see the ``smtp_*`` fields.

The service degrades gracefully when SMTP is disabled or misconfigured:
``send_email`` returns ``False`` and logs a warning rather than raising,
so callers can treat email notification as best-effort.
"""

from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import List, Optional, Sequence, Tuple, Dict, Any
import logging
import ssl
from pathlib import Path

try:
    import aiosmtplib  # type: ignore
except ImportError:  # pragma: no cover - optional at import time
    aiosmtplib = None  # type: ignore

from ion.core.config import get_config, get_ssl_verify


logger = logging.getLogger(__name__)


@dataclass
class EmailAttachment:
    """Represents an email attachment."""

    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


class SMTPError(Exception):
    """Exception raised for SMTP errors."""


class SMTPService:
    """Async SMTP client for sending transactional email.

    Supports two TLS modes:
    - Implicit TLS (``use_tls=True``) — TLS from the first byte, typically port 465.
    - STARTTLS (``use_starttls=True``, default) — plaintext then upgrade, typically port 587.

    If both flags are false, the connection is plaintext — use only for
    testing against a local catcher such as MailHog / Mailpit.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_address: Optional[str] = None,
        from_name: Optional[str] = None,
        use_tls: Optional[bool] = None,
        use_starttls: Optional[bool] = None,
        timeout: Optional[int] = None,
        verify_ssl: Optional[bool] = None,
    ):
        """Initialize the SMTP service.

        If any parameter is omitted the value is read from the global
        configuration (``get_config()``).
        """
        config = get_config()
        self.enabled = enabled if enabled is not None else config.smtp_enabled
        self.host = host if host is not None else config.smtp_host
        self.port = port if port is not None else config.smtp_port
        self.username = username if username is not None else config.smtp_username
        self.password = password if password is not None else config.smtp_password
        self.from_address = (
            from_address if from_address is not None else config.smtp_from_address
        )
        self.from_name = from_name if from_name is not None else config.smtp_from_name
        self.use_tls = use_tls if use_tls is not None else config.smtp_use_tls
        self.use_starttls = (
            use_starttls if use_starttls is not None else config.smtp_use_starttls
        )
        self.timeout = timeout if timeout is not None else config.smtp_timeout
        self.verify_ssl = (
            verify_ssl if verify_ssl is not None else config.smtp_verify_ssl
        )

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """Return True if SMTP has the minimum required configuration."""
        return bool(self.host and self.from_address and self.port)

    def is_available(self) -> bool:
        """Return True if SMTP is enabled AND configured AND aiosmtplib is installed."""
        if aiosmtplib is None:
            return False
        return bool(self.enabled) and self.is_configured

    def status(self) -> Dict[str, Any]:
        """Return a serializable status snapshot (no secrets)."""
        return {
            "enabled": bool(self.enabled),
            "configured": self.is_configured,
            "available": self.is_available(),
            "host": self.host or "",
            "port": self.port,
            "username_set": bool(self.username),
            "password_set": bool(self.password),
            "from_address": self.from_address or "",
            "from_name": self.from_name or "",
            "use_tls": bool(self.use_tls),
            "use_starttls": bool(self.use_starttls),
            "timeout": self.timeout,
            "verify_ssl": bool(self.verify_ssl),
            "aiosmtplib_installed": aiosmtplib is not None,
        }

    # ------------------------------------------------------------------
    # Message building
    # ------------------------------------------------------------------

    def _format_from(self) -> str:
        """Format the From header using name + address when a name is set."""
        if self.from_name:
            return formataddr((self.from_name, self.from_address))
        return self.from_address

    def _build_message(
        self,
        to: Sequence[str],
        subject: str,
        text_body: str,
        html_body: Optional[str] = None,
        attachments: Optional[Sequence[EmailAttachment]] = None,
        cc: Optional[Sequence[str]] = None,
        bcc: Optional[Sequence[str]] = None,
        reply_to: Optional[str] = None,
    ) -> EmailMessage:
        """Build an :class:`email.message.EmailMessage`."""
        msg = EmailMessage()
        msg["From"] = self._format_from()
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        if reply_to:
            msg["Reply-To"] = reply_to
        msg["Subject"] = subject
        msg["Message-ID"] = make_msgid(domain=self._sender_domain())

        # Always set a plaintext body; add HTML as an alternative if provided.
        msg.set_content(text_body or "")
        if html_body:
            msg.add_alternative(html_body, subtype="html")

        if attachments:
            for att in attachments:
                maintype, _, subtype = att.content_type.partition("/")
                if not subtype:
                    maintype, subtype = "application", "octet-stream"
                msg.add_attachment(
                    att.content,
                    maintype=maintype,
                    subtype=subtype,
                    filename=att.filename,
                )
        return msg

    def _sender_domain(self) -> str:
        """Extract domain from the from_address for Message-ID."""
        if self.from_address and "@" in self.from_address:
            return self.from_address.split("@", 1)[1]
        return "ion.local"

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Construct an SSL context honouring verify_ssl + ION_CA_BUNDLE."""
        verify = get_ssl_verify(self.verify_ssl)
        if isinstance(verify, str):
            # Custom CA bundle path
            ctx = ssl.create_default_context(cafile=verify)
        else:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def send_email(
        self,
        to: List[str],
        subject: str,
        text_body: str,
        html_body: Optional[str] = None,
        attachments: Optional[List[EmailAttachment]] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
    ) -> bool:
        """Send an email. Returns True on success, False on graceful failure.

        Raises :class:`SMTPError` only when explicitly requested to send but
        the service is not available — callers that want best-effort delivery
        should check :meth:`is_available` first or just inspect the return
        value.
        """
        if not to:
            logger.warning("smtp.send_email called with empty recipient list")
            return False

        if aiosmtplib is None:
            logger.warning(
                "smtp.send_email skipped: aiosmtplib is not installed"
            )
            return False

        if not self.enabled:
            logger.info("smtp.send_email skipped: SMTP is disabled in config")
            return False

        if not self.is_configured:
            logger.warning(
                "smtp.send_email skipped: SMTP is not fully configured (host/from required)"
            )
            return False

        message = self._build_message(
            to=to,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            attachments=attachments,
            cc=cc,
            bcc=bcc,
            reply_to=reply_to,
        )

        # Compute envelope recipients (To + Cc + Bcc)
        recipients: List[str] = list(to)
        if cc:
            recipients.extend(cc)
        if bcc:
            recipients.extend(bcc)

        tls_context = self._build_ssl_context()

        try:
            await aiosmtplib.send(
                message,
                hostname=self.host,
                port=self.port,
                username=self.username or None,
                password=self.password or None,
                use_tls=bool(self.use_tls),
                start_tls=bool(self.use_starttls) and not bool(self.use_tls),
                tls_context=tls_context,
                timeout=self.timeout,
                recipients=recipients,
                sender=self.from_address,
            )
            logger.info(
                "smtp.send_email ok host=%s port=%s to=%s subject=%r",
                self.host,
                self.port,
                ",".join(to),
                subject,
            )
            return True
        except Exception as e:  # broad: aiosmtplib exposes many error classes
            logger.error(
                "smtp.send_email failed host=%s port=%s err=%s",
                self.host,
                self.port,
                e,
                exc_info=True,
            )
            return False

    async def send_test(self, to: str) -> Tuple[bool, str]:
        """Send a test email and return ``(ok, message)``.

        This always surfaces an explanatory message (success or failure cause)
        so the admin UI can display it without needing to parse logs.
        """
        if aiosmtplib is None:
            return False, "aiosmtplib is not installed on the server"
        if not self.enabled:
            return False, "SMTP is disabled in configuration"
        if not self.is_configured:
            return False, "SMTP is not fully configured (host and from address are required)"

        subject = "ION SMTP test"
        text_body = (
            "This is a test email sent from ION.\n\n"
            f"Host: {self.host}\nPort: {self.port}\n"
            f"TLS: {self.use_tls}\nSTARTTLS: {self.use_starttls}\n\n"
            "If you received this message, ION's SMTP notification "
            "service is working correctly."
        )
        html_body = (
            "<html><body style='font-family: sans-serif;'>"
            "<h2>ION SMTP test</h2>"
            "<p>This is a test email sent from ION.</p>"
            f"<p><strong>Host:</strong> {self.host}<br/>"
            f"<strong>Port:</strong> {self.port}<br/>"
            f"<strong>TLS:</strong> {self.use_tls}<br/>"
            f"<strong>STARTTLS:</strong> {self.use_starttls}</p>"
            "<p>If you received this message, ION's SMTP notification "
            "service is working correctly.</p>"
            "</body></html>"
        )

        ok = await self.send_email(
            to=[to],
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )
        if ok:
            return True, f"Test email sent to {to}"
        return False, "SMTP send failed — check server logs for details"


# Singleton instance
_smtp_service: Optional[SMTPService] = None


def get_smtp_service() -> SMTPService:
    """Get the global SMTP service instance."""
    global _smtp_service
    if _smtp_service is None:
        _smtp_service = SMTPService()
    return _smtp_service


def reset_smtp_service() -> None:
    """Reset the global SMTP service instance (call after config changes)."""
    global _smtp_service
    _smtp_service = None
