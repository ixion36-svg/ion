"""SIEM export service for shipping security alerts."""

import json
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ixion.models.security import SecurityEvent, SecurityEventSeverity
from ixion.storage.security_repository import SecurityEventRepository
from ixion.core.logging import get_structured_logger


logger = get_structured_logger(__name__)


class SIEMFormat(str, Enum):
    """Supported SIEM export formats."""

    JSON = "json"
    CEF = "cef"  # Common Event Format (ArcSight, etc.)
    LEEF = "leef"  # Log Event Extended Format (QRadar)
    SYSLOG = "syslog"  # RFC 5424
    SPLUNK_HEC = "splunk_hec"  # Splunk HTTP Event Collector


@dataclass
class SIEMConfig:
    """SIEM export configuration."""

    enabled: bool = False
    format: SIEMFormat = SIEMFormat.JSON

    # Webhook settings
    webhook_url: Optional[str] = None
    webhook_headers: Optional[Dict[str, str]] = None
    webhook_batch_size: int = 100

    # Syslog settings
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp, tcp, tls
    syslog_facility: int = 1  # user-level messages

    # Splunk settings
    splunk_hec_url: Optional[str] = None
    splunk_hec_token: Optional[str] = None
    splunk_index: str = "security"
    splunk_source: str = "ixion"
    splunk_sourcetype: str = "ixion:security"

    # File output
    file_path: Optional[str] = None

    # Filtering
    min_severity: SecurityEventSeverity = SecurityEventSeverity.LOW


class SIEMExporter:
    """Exports security events to SIEM systems."""

    def __init__(self, session: Session, config: Optional[SIEMConfig] = None):
        self.session = session
        self.config = config or SIEMConfig()
        self.event_repo = SecurityEventRepository(session)

    def get_unexported_events(
        self,
        limit: int = 1000,
        min_severity: Optional[SecurityEventSeverity] = None,
    ) -> List[SecurityEvent]:
        """Get events that haven't been exported yet."""
        events = self.event_repo.get_unexported(limit)

        if min_severity:
            severity_order = {
                SecurityEventSeverity.INFO: 0,
                SecurityEventSeverity.LOW: 1,
                SecurityEventSeverity.MEDIUM: 2,
                SecurityEventSeverity.HIGH: 3,
                SecurityEventSeverity.CRITICAL: 4,
            }
            min_level = severity_order.get(min_severity, 0)
            events = [
                e for e in events
                if severity_order.get(e.severity, 0) >= min_level
            ]

        return events

    def mark_exported(self, event_ids: List[int]) -> int:
        """Mark events as exported."""
        return self.event_repo.mark_exported(event_ids)

    def format_event(self, event: SecurityEvent, format: SIEMFormat) -> str:
        """Format event for the specified SIEM."""
        if format == SIEMFormat.JSON:
            return self._format_json(event)
        elif format == SIEMFormat.CEF:
            return self._format_cef(event)
        elif format == SIEMFormat.LEEF:
            return self._format_leef(event)
        elif format == SIEMFormat.SYSLOG:
            return self._format_syslog(event)
        elif format == SIEMFormat.SPLUNK_HEC:
            return self._format_splunk_hec(event)
        else:
            return self._format_json(event)

    def _format_json(self, event: SecurityEvent) -> str:
        """Format as JSON."""
        return json.dumps(event.to_siem_format(), default=str)

    def _format_cef(self, event: SecurityEvent) -> str:
        """Format as CEF (Common Event Format).

        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        severity_map = {
            SecurityEventSeverity.CRITICAL: 10,
            SecurityEventSeverity.HIGH: 8,
            SecurityEventSeverity.MEDIUM: 5,
            SecurityEventSeverity.LOW: 3,
            SecurityEventSeverity.INFO: 1,
        }

        # Escape CEF special characters
        def cef_escape(s: str) -> str:
            if not s:
                return ""
            return s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")

        extensions = [
            f"src={event.source_ip}",
            f"act={cef_escape(event.detection_rule)}",
            f"outcome={'blocked' if event.blocked else 'detected'}",
            f"msg={cef_escape(event.description[:1000])}",
        ]

        if event.username:
            extensions.append(f"suser={cef_escape(event.username)}")
        if event.request_path:
            extensions.append(f"request={cef_escape(event.request_path)}")
        if event.request_method:
            extensions.append(f"requestMethod={event.request_method}")
        if event.user_agent:
            extensions.append(f"requestClientApplication={cef_escape(event.user_agent[:200])}")

        extensions.append(f"cn1={event.event_count}")
        extensions.append("cn1Label=EventCount")
        extensions.append(f"cn2={event.confidence_score}")
        extensions.append("cn2Label=ConfidenceScore")

        if event.created_at:
            extensions.append(f"rt={int(event.created_at.timestamp() * 1000)}")

        return (
            f"CEF:0|IXION|SecurityMonitor|1.0|"
            f"{event.event_type.value}|{cef_escape(event.title)}|"
            f"{severity_map.get(event.severity, 5)}|"
            f"{' '.join(extensions)}"
        )

    def _format_leef(self, event: SecurityEvent) -> str:
        """Format as LEEF (Log Event Extended Format) for IBM QRadar.

        LEEF:Version|Vendor|Product|Version|EventID|Key=Value
        """
        severity_map = {
            SecurityEventSeverity.CRITICAL: 10,
            SecurityEventSeverity.HIGH: 8,
            SecurityEventSeverity.MEDIUM: 5,
            SecurityEventSeverity.LOW: 3,
            SecurityEventSeverity.INFO: 1,
        }

        attributes = [
            f"cat={event.event_type.value}",
            f"sev={severity_map.get(event.severity, 5)}",
            f"src={event.source_ip}",
            f"msg={event.description.replace(chr(9), ' ')}",
        ]

        if event.username:
            attributes.append(f"usrName={event.username}")
        if event.request_path:
            attributes.append(f"url={event.request_path}")
        if event.request_method:
            attributes.append(f"method={event.request_method}")
        if event.created_at:
            attributes.append(f"devTime={event.created_at.isoformat()}")

        return (
            f"LEEF:2.0|IXION|SecurityMonitor|1.0|{event.event_type.value}|"
            f"{chr(9).join(attributes)}"
        )

    def _format_syslog(self, event: SecurityEvent) -> str:
        """Format as RFC 5424 syslog message."""
        # PRI = facility * 8 + severity
        # Using facility 1 (user-level) and mapping our severity
        severity_map = {
            SecurityEventSeverity.CRITICAL: 2,  # Critical
            SecurityEventSeverity.HIGH: 3,  # Error
            SecurityEventSeverity.MEDIUM: 4,  # Warning
            SecurityEventSeverity.LOW: 5,  # Notice
            SecurityEventSeverity.INFO: 6,  # Informational
        }

        pri = self.config.syslog_facility * 8 + severity_map.get(event.severity, 6)
        timestamp = event.created_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if event.created_at else "-"
        hostname = socket.gethostname()
        app_name = "ixion"
        proc_id = "-"
        msg_id = event.event_type.value

        # Structured data
        sd_elements = [
            f"[ixion@0 "
            f'eventType="{event.event_type.value}" '
            f'severity="{event.severity.value}" '
            f'sourceIP="{event.source_ip}" '
            f'blocked="{event.blocked}" '
            f'confidence="{event.confidence_score}"'
            f"]"
        ]

        msg = f"{event.title}: {event.description}"

        return f"<{pri}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {''.join(sd_elements)} {msg}"

    def _format_splunk_hec(self, event: SecurityEvent) -> str:
        """Format for Splunk HTTP Event Collector."""
        data = {
            "time": event.created_at.timestamp() if event.created_at else None,
            "host": socket.gethostname(),
            "source": self.config.splunk_source,
            "sourcetype": self.config.splunk_sourcetype,
            "index": self.config.splunk_index,
            "event": event.to_siem_format(),
        }
        return json.dumps(data, default=str)

    async def export_to_webhook(
        self,
        events: List[SecurityEvent],
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Export events to a webhook endpoint."""
        import httpx

        url = url or self.config.webhook_url
        if not url:
            logger.error("No webhook URL configured")
            return False

        headers = headers or self.config.webhook_headers or {}
        headers.setdefault("Content-Type", "application/json")

        # Format events
        formatted_events = [event.to_siem_format() for event in events]

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    json={"events": formatted_events, "count": len(formatted_events)},
                    headers=headers,
                )
                response.raise_for_status()

            logger.access_event(
                resource_type="siem_export",
                resource_id="webhook",
                action="export",
                outcome="success",
            )
            return True

        except Exception as e:
            logger.error(f"Webhook export failed: {e}", error_type=type(e).__name__)
            return False

    def export_to_syslog(
        self,
        events: List[SecurityEvent],
        host: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> bool:
        """Export events to a syslog server."""
        host = host or self.config.syslog_host
        port = port or self.config.syslog_port
        protocol = protocol or self.config.syslog_protocol

        if not host:
            logger.error("No syslog host configured")
            return False

        try:
            if protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for event in events:
                    message = self._format_syslog(event)
                    sock.sendto(message.encode("utf-8"), (host, port))
                sock.close()

            elif protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                for event in events:
                    message = self._format_syslog(event) + "\n"
                    sock.send(message.encode("utf-8"))
                sock.close()

            elif protocol == "tls":
                context = ssl.create_default_context()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                secure_sock = context.wrap_socket(sock, server_hostname=host)
                secure_sock.connect((host, port))
                for event in events:
                    message = self._format_syslog(event) + "\n"
                    secure_sock.send(message.encode("utf-8"))
                secure_sock.close()

            logger.access_event(
                resource_type="siem_export",
                resource_id="syslog",
                action="export",
                outcome="success",
            )
            return True

        except Exception as e:
            logger.error(f"Syslog export failed: {e}", error_type=type(e).__name__)
            return False

    async def export_to_splunk_hec(
        self,
        events: List[SecurityEvent],
        url: Optional[str] = None,
        token: Optional[str] = None,
    ) -> bool:
        """Export events to Splunk HTTP Event Collector."""
        import httpx

        url = url or self.config.splunk_hec_url
        token = token or self.config.splunk_hec_token

        if not url or not token:
            logger.error("Splunk HEC URL or token not configured")
            return False

        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }

        # Format events for HEC
        payload = "\n".join(self._format_splunk_hec(e) for e in events)

        try:
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                response = await client.post(
                    url,
                    content=payload,
                    headers=headers,
                )
                response.raise_for_status()

            logger.access_event(
                resource_type="siem_export",
                resource_id="splunk_hec",
                action="export",
                outcome="success",
            )
            return True

        except Exception as e:
            logger.error(f"Splunk HEC export failed: {e}", error_type=type(e).__name__)
            return False

    def export_to_file(
        self,
        events: List[SecurityEvent],
        file_path: Optional[str] = None,
        format: Optional[SIEMFormat] = None,
    ) -> bool:
        """Export events to a file."""
        file_path = file_path or self.config.file_path
        format = format or self.config.format

        if not file_path:
            logger.error("No file path configured")
            return False

        try:
            with open(file_path, "a", encoding="utf-8") as f:
                for event in events:
                    formatted = self.format_event(event, format)
                    f.write(formatted + "\n")

            logger.access_event(
                resource_type="siem_export",
                resource_id="file",
                action="export",
                outcome="success",
            )
            return True

        except Exception as e:
            logger.error(f"File export failed: {e}", error_type=type(e).__name__)
            return False

    def generate_alerts_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Generate a summary of alerts for reporting."""
        stats = self.event_repo.get_statistics(hours)
        recent = self.event_repo.get_recent(hours=hours, limit=10)

        # Determine overall threat level
        critical = stats["by_severity"].get("critical", 0)
        high = stats["by_severity"].get("high", 0)

        if critical > 0:
            threat_level = "CRITICAL"
        elif high > 5:
            threat_level = "HIGH"
        elif stats["total_events"] > 50:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "time_period_hours": hours,
            "threat_level": threat_level,
            "summary": {
                "total_events": stats["total_events"],
                "blocked_attacks": stats["blocked_count"],
                "unique_attackers": len(stats["top_source_ips"]),
            },
            "by_severity": stats["by_severity"],
            "by_type": stats["by_type"],
            "top_attackers": stats["top_source_ips"],
            "recent_events": [
                {
                    "id": e.id,
                    "time": e.created_at.isoformat() if e.created_at else None,
                    "type": e.event_type.value,
                    "severity": e.severity.value,
                    "source_ip": e.source_ip,
                    "title": e.title,
                    "blocked": e.blocked,
                }
                for e in recent
            ],
        }
