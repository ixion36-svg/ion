"""Security detection and monitoring service for ION."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ion.models.security import (
    BlockedIP,
    SecurityAlertRule,
    SecurityEvent,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityEventType,
)
from ion.storage.security_repository import (
    BlockedIPRepository,
    SecurityAlertRuleRepository,
    SecurityEventRepository,
)


# =============================================================================
# Attack Detection Patterns
# =============================================================================

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\b(union|select|insert|update|delete|drop|truncate|alter)\b.*\b(from|into|table|database)\b)",
    r"(\b(or|and)\b\s+[\d\w]+\s*[=<>]+\s*[\d\w]+)",
    r"(--|\#|\/\*|\*\/)",
    r"(\bexec\b|\bexecute\b|\bsp_|\bxp_)",
    r"(\'|\"|;)\s*(or|and)\s*(\'|\"|\d)",
    r"(\bwaitfor\b\s+\bdelay\b|\bbenchmark\b\s*\()",
    r"(\bload_file\b|\binto\s+outfile\b|\binto\s+dumpfile\b)",
]

# XSS patterns
XSS_PATTERNS = [
    r"(<script[^>]*>.*?<\/script>)",
    r"(javascript\s*:)",
    r"(on\w+\s*=)",
    r"(<img[^>]+onerror\s*=)",
    r"(<svg[^>]+onload\s*=)",
    r"(<iframe[^>]*>)",
    r"(document\.(cookie|location|write))",
    r"(eval\s*\()",
    r"(<[^>]+style\s*=\s*[\"'][^\"']*expression\s*\()",
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"(\.\.\/|\.\.\\)",
    r"(%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)",
    r"(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)",
    r"(c:\\windows|c:\\boot\.ini|c:\\system32)",
    r"(%00|%0a|%0d)",
]

# Command injection patterns
COMMAND_INJECTION_PATTERNS = [
    r"([;&|`$])",
    r"(\|\||&&)",
    r"(\$\(|\`)",
    r"(\beval\b|\bexec\b|\bsystem\b|\bpassthru\b)",
    r"(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)",
]

# Template injection patterns (Jinja2, etc.)
TEMPLATE_INJECTION_PATTERNS = [
    r"(\{\{.*\}\})",
    r"(\{%.*%\})",
    r"(__class__|__mro__|__subclasses__|__builtins__|__import__)",
    r"(config\[|request\[|self\.__)",
]

# Scanner/reconnaissance signatures
SCANNER_SIGNATURES = [
    r"(nikto|nmap|sqlmap|burp|acunetix|nessus|qualys)",
    r"(dirbuster|gobuster|wfuzz|ffuf)",
    r"(metasploit|cobalt\s*strike)",
    r"(masscan|zmap|shodan)",
]

# Suspicious user agents
SUSPICIOUS_USER_AGENTS = [
    r"^$",  # Empty user agent
    r"^-$",
    r"(curl|wget|python-requests|httpx|axios|node-fetch)\/",
    r"(bot|crawler|spider|scraper)",
    r"(nikto|sqlmap|nmap|masscan)",
]


@dataclass
class DetectionResult:
    """Result of attack detection."""

    detected: bool
    event_type: Optional[SecurityEventType] = None
    severity: Optional[SecurityEventSeverity] = None
    title: str = ""
    description: str = ""
    matched_patterns: List[str] = field(default_factory=list)
    matched_content: Optional[str] = None  # The actual malicious content that was detected
    confidence_score: int = 50
    should_block: bool = False


@dataclass
class RequestContext:
    """Context information for a request."""

    source_ip: str
    request_path: str
    request_method: str
    user_agent: Optional[str] = None
    query_string: Optional[str] = None
    body: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    user_id: Optional[int] = None
    username: Optional[str] = None


class SecurityDetectionService:
    """Service for detecting security threats."""

    def __init__(self, session: Session):
        self.session = session
        self.event_repo = SecurityEventRepository(session)
        self.blocked_repo = BlockedIPRepository(session)
        self.rule_repo = SecurityAlertRuleRepository(session)

        # Compile patterns for performance
        self._sql_patterns = [re.compile(p, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS]
        self._xss_patterns = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
        self._traversal_patterns = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]
        self._command_patterns = [re.compile(p, re.IGNORECASE) for p in COMMAND_INJECTION_PATTERNS]
        self._template_patterns = [re.compile(p, re.IGNORECASE) for p in TEMPLATE_INJECTION_PATTERNS]
        self._scanner_patterns = [re.compile(p, re.IGNORECASE) for p in SCANNER_SIGNATURES]
        self._suspicious_ua_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_USER_AGENTS]

    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked."""
        return self.blocked_repo.is_blocked(ip_address)

    def analyze_request(self, ctx: RequestContext) -> List[DetectionResult]:
        """Analyze a request for potential attacks."""
        results = []

        # Combine all input for scanning
        scan_targets = [
            ctx.request_path or "",
            ctx.query_string or "",
            ctx.body or "",
        ]
        combined_input = " ".join(scan_targets)

        # Check for SQL injection
        sql_result = self._check_sql_injection(combined_input)
        if sql_result.detected:
            results.append(sql_result)

        # Check for XSS
        xss_result = self._check_xss(combined_input)
        if xss_result.detected:
            results.append(xss_result)

        # Check for path traversal
        traversal_result = self._check_path_traversal(ctx.request_path or "")
        if traversal_result.detected:
            results.append(traversal_result)

        # Check for command injection
        cmd_result = self._check_command_injection(combined_input)
        if cmd_result.detected:
            results.append(cmd_result)

        # Check for template injection
        template_result = self._check_template_injection(combined_input)
        if template_result.detected:
            results.append(template_result)

        # Check for scanner/recon
        scanner_result = self._check_scanner(ctx.user_agent or "")
        if scanner_result.detected:
            results.append(scanner_result)

        # Check for suspicious user agent
        ua_result = self._check_suspicious_user_agent(ctx.user_agent or "")
        if ua_result.detected:
            results.append(ua_result)

        return results

    def _extract_matches(self, patterns: List, input_data: str) -> Tuple[List[str], List[str]]:
        """Extract matched patterns and the actual matched content."""
        matched_patterns = []
        matched_content = []
        for pattern in patterns:
            match = pattern.search(input_data)
            if match:
                matched_patterns.append(pattern.pattern)
                # Extract the actual matched text
                matched_text = match.group(0)
                if matched_text and len(matched_text) <= 500:  # Limit size
                    matched_content.append(matched_text)
        return matched_patterns, matched_content

    def _check_sql_injection(self, input_data: str) -> DetectionResult:
        """Check for SQL injection attempts."""
        matched_patterns, matched_content = self._extract_matches(self._sql_patterns, input_data)

        if matched_patterns:
            return DetectionResult(
                detected=True,
                event_type=SecurityEventType.SQL_INJECTION,
                severity=SecurityEventSeverity.HIGH,
                title="SQL Injection Attempt Detected",
                description=f"Potential SQL injection patterns found in request",
                matched_patterns=matched_patterns,
                matched_content="; ".join(matched_content[:5]) if matched_content else None,
                confidence_score=min(50 + len(matched_patterns) * 15, 95),
                should_block=len(matched_patterns) >= 2,
            )
        return DetectionResult(detected=False)

    def _check_xss(self, input_data: str) -> DetectionResult:
        """Check for XSS attempts."""
        matched_patterns, matched_content = self._extract_matches(self._xss_patterns, input_data)

        if matched_patterns:
            return DetectionResult(
                detected=True,
                event_type=SecurityEventType.XSS_ATTEMPT,
                severity=SecurityEventSeverity.HIGH,
                title="XSS Attempt Detected",
                description=f"Potential cross-site scripting patterns found",
                matched_patterns=matched_patterns,
                matched_content="; ".join(matched_content[:5]) if matched_content else None,
                confidence_score=min(50 + len(matched_patterns) * 15, 95),
                should_block=len(matched_patterns) >= 2,
            )
        return DetectionResult(detected=False)

    def _check_path_traversal(self, path: str) -> DetectionResult:
        """Check for path traversal attempts."""
        matched_patterns, matched_content = self._extract_matches(self._traversal_patterns, path)

        if matched_patterns:
            return DetectionResult(
                detected=True,
                event_type=SecurityEventType.PATH_TRAVERSAL,
                severity=SecurityEventSeverity.HIGH,
                title="Path Traversal Attempt Detected",
                description=f"Directory traversal patterns found in path",
                matched_patterns=matched_patterns,
                matched_content="; ".join(matched_content[:5]) if matched_content else None,
                confidence_score=min(60 + len(matched_patterns) * 15, 95),
                should_block=True,
            )
        return DetectionResult(detected=False)

    def _check_command_injection(self, input_data: str) -> DetectionResult:
        """Check for command injection attempts."""
        matched_patterns, matched_content = self._extract_matches(self._command_patterns, input_data)

        if matched_patterns:
            return DetectionResult(
                detected=True,
                event_type=SecurityEventType.COMMAND_INJECTION,
                severity=SecurityEventSeverity.CRITICAL,
                title="Command Injection Attempt Detected",
                description=f"Potential command injection patterns found",
                matched_patterns=matched_patterns,
                matched_content="; ".join(matched_content[:5]) if matched_content else None,
                confidence_score=min(40 + len(matched_patterns) * 20, 95),
                should_block=len(matched_patterns) >= 2,
            )
        return DetectionResult(detected=False)

    def _check_template_injection(self, input_data: str) -> DetectionResult:
        """Check for template injection attempts."""
        matched_patterns, matched_content = self._extract_matches(self._template_patterns, input_data)

        if matched_patterns:
            return DetectionResult(
                detected=True,
                event_type=SecurityEventType.TEMPLATE_INJECTION,
                severity=SecurityEventSeverity.CRITICAL,
                title="Template Injection Attempt Detected",
                description=f"Server-side template injection patterns found",
                matched_patterns=matched_patterns,
                matched_content="; ".join(matched_content[:5]) if matched_content else None,
                confidence_score=min(60 + len(matched_patterns) * 15, 95),
                should_block=True,
            )
        return DetectionResult(detected=False)

    def _check_scanner(self, user_agent: str) -> DetectionResult:
        """Check for known scanner signatures."""
        matched_patterns, matched_content = self._extract_matches(self._scanner_patterns, user_agent)

        if matched_patterns:
            return DetectionResult(
                detected=True,
                event_type=SecurityEventType.SCANNER_DETECTED,
                severity=SecurityEventSeverity.MEDIUM,
                title="Security Scanner Detected",
                description=f"Known security scanner identified in user agent",
                matched_patterns=matched_patterns,
                matched_content="; ".join(matched_content[:3]) if matched_content else user_agent[:200],
                confidence_score=85,
                should_block=False,
            )
        return DetectionResult(detected=False)

    def _check_suspicious_user_agent(self, user_agent: str) -> DetectionResult:
        """Check for suspicious user agents."""
        for pattern in self._suspicious_ua_patterns:
            match = pattern.search(user_agent)
            if match:
                return DetectionResult(
                    detected=True,
                    event_type=SecurityEventType.SUSPICIOUS_USER_AGENT,
                    severity=SecurityEventSeverity.LOW,
                    title="Suspicious User Agent",
                    description=f"Unusual or automated user agent detected",
                    matched_patterns=[pattern.pattern],
                    matched_content=user_agent[:300] if user_agent else None,
                    confidence_score=40,
                    should_block=False,
                )
        return DetectionResult(detected=False)

    def record_event(
        self,
        ctx: RequestContext,
        result: DetectionResult,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """Record a security event."""
        # Check for existing aggregated event
        existing, is_new = self.event_repo.get_or_create_aggregated(
            event_type=result.event_type,
            source_ip=ctx.source_ip,
            detection_rule=result.title,
            window_minutes=5,
        )

        if not is_new and existing:
            # Update existing event
            existing.matched_patterns = list(
                set((existing.matched_patterns or []) + result.matched_patterns)
            )
            return existing

        # Create new event
        event = self.event_repo.create(
            event_type=result.event_type,
            severity=result.severity,
            title=result.title,
            description=result.description,
            source_ip=ctx.source_ip,
            user_agent=ctx.user_agent,
            request_path=ctx.request_path,
            request_method=ctx.request_method,
            user_id=ctx.user_id,
            username=ctx.username,
            detection_rule=result.title,
            confidence_score=result.confidence_score,
            matched_patterns=result.matched_patterns,
            blocked=result.should_block,
            raw_data=raw_data,
        )
        return event

    def check_brute_force(
        self,
        source_ip: str,
        username: Optional[str] = None,
        threshold: int = 5,
        window_minutes: int = 5,
    ) -> Tuple[bool, int]:
        """Check for brute force attacks based on failed login count."""
        # Count failed auth events from this IP
        count = self.event_repo.count_by_ip_and_type(
            source_ip=source_ip,
            event_type=SecurityEventType.BRUTE_FORCE,
            minutes=window_minutes,
        )
        return count >= threshold, count

    def record_failed_login(
        self,
        source_ip: str,
        username: str,
        user_agent: Optional[str] = None,
    ) -> Tuple[SecurityEvent, bool]:
        """Record a failed login attempt and check for brute force."""
        # Record the attempt
        ctx = RequestContext(
            source_ip=source_ip,
            request_path="/api/auth/login",
            request_method="POST",
            user_agent=user_agent,
            username=username,
        )

        # Check for brute force
        is_brute_force, count = self.check_brute_force(source_ip, username)

        if is_brute_force:
            severity = SecurityEventSeverity.HIGH
            should_block = count >= 10
        else:
            severity = SecurityEventSeverity.LOW
            should_block = False

        result = DetectionResult(
            detected=True,
            event_type=SecurityEventType.BRUTE_FORCE,
            severity=severity,
            title="Failed Login Attempt" if not is_brute_force else "Brute Force Attack Detected",
            description=f"Failed login for user '{username}' from {source_ip}. "
                       f"Attempts in last 5 minutes: {count + 1}",
            confidence_score=min(30 + count * 10, 95) if is_brute_force else 30,
            should_block=should_block,
        )

        event = self.record_event(ctx, result)

        # Block IP if threshold exceeded
        if should_block:
            self.blocked_repo.block(
                ip_address=source_ip,
                reason=f"Brute force attack detected ({count + 1} failed attempts)",
                duration_minutes=30,
                security_event_id=event.id,
            )

        return event, should_block

    def record_rate_limit_exceeded(
        self,
        source_ip: str,
        request_path: str,
        user_agent: Optional[str] = None,
    ) -> SecurityEvent:
        """Record a rate limit violation."""
        ctx = RequestContext(
            source_ip=source_ip,
            request_path=request_path,
            request_method="",
            user_agent=user_agent,
        )

        result = DetectionResult(
            detected=True,
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity=SecurityEventSeverity.MEDIUM,
            title="Rate Limit Exceeded",
            description=f"Rate limit exceeded for {request_path} from {source_ip}",
            confidence_score=70,
            should_block=False,
        )

        return self.record_event(ctx, result)

    def block_ip(
        self,
        ip_address: str,
        reason: str,
        duration_minutes: Optional[int] = 60,
        permanent: bool = False,
        security_event_id: Optional[int] = None,
    ) -> BlockedIP:
        """Block an IP address."""
        return self.blocked_repo.block(
            ip_address=ip_address,
            reason=reason,
            duration_minutes=duration_minutes,
            permanent=permanent,
            security_event_id=security_event_id,
        )

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address."""
        return self.blocked_repo.unblock(ip_address)

    def get_blocked_ips(self) -> List[BlockedIP]:
        """Get all blocked IPs."""
        return self.blocked_repo.get_all_active()

    def get_statistics(self, hours: int = 24) -> dict:
        """Get security statistics."""
        return self.event_repo.get_statistics(hours)

    def get_timeline(self, hours: int = 24) -> List[dict]:
        """Get event timeline."""
        return self.event_repo.get_timeline(hours)

    def get_recent_events(
        self,
        hours: int = 24,
        severity: Optional[SecurityEventSeverity] = None,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """Get recent security events."""
        return self.event_repo.get_recent(
            hours=hours,
            severity=severity,
            limit=limit,
        )

    def update_event_status(
        self,
        event_id: int,
        status: SecurityEventStatus,
    ) -> Optional[SecurityEvent]:
        """Update event status."""
        return self.event_repo.update_status(event_id, status)


class SIEMExportService:
    """Service for exporting security events to SIEM systems."""

    def __init__(self, session: Session):
        self.session = session
        self.event_repo = SecurityEventRepository(session)

    def get_unexported_events(self, limit: int = 1000) -> List[SecurityEvent]:
        """Get events not yet exported."""
        return self.event_repo.get_unexported(limit)

    def mark_exported(self, event_ids: List[int]) -> int:
        """Mark events as exported."""
        return self.event_repo.mark_exported(event_ids)

    def export_to_syslog_format(self, events: List[SecurityEvent]) -> List[str]:
        """Convert events to syslog format."""
        syslog_messages = []
        for event in events:
            # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            severity_map = {
                SecurityEventSeverity.CRITICAL: 10,
                SecurityEventSeverity.HIGH: 8,
                SecurityEventSeverity.MEDIUM: 5,
                SecurityEventSeverity.LOW: 3,
                SecurityEventSeverity.INFO: 1,
            }

            cef_msg = (
                f"CEF:0|ION|SecurityMonitor|1.0|"
                f"{event.event_type.value}|{event.title}|"
                f"{severity_map.get(event.severity, 5)}|"
                f"src={event.source_ip} "
                f"act={event.detection_rule} "
                f"outcome={'blocked' if event.blocked else 'detected'} "
                f"msg={event.description}"
            )

            if event.username:
                cef_msg += f" suser={event.username}"
            if event.request_path:
                cef_msg += f" request={event.request_path}"

            syslog_messages.append(cef_msg)

        return syslog_messages

    def export_to_json(self, events: List[SecurityEvent]) -> List[dict]:
        """Export events in JSON format for SIEM ingestion."""
        return [event.to_siem_format() for event in events]
