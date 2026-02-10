"""URL validation utilities for SSRF protection."""

import ipaddress
import re
from urllib.parse import urlparse
from typing import Tuple, Optional


# Private/internal IP ranges that should be blocked
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS metadata
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",  # GCP metadata
    "metadata.google.com",
}

# Allowed URL schemes
ALLOWED_SCHEMES = {"http", "https"}

# Blocked ports (common internal services)
BLOCKED_PORTS = {
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    135,   # Windows RPC
    137,   # NetBIOS
    138,   # NetBIOS
    139,   # NetBIOS
    445,   # SMB
    1433,  # MSSQL
    1521,  # Oracle
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
    11211, # Memcached
    27017, # MongoDB
}


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/internal range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in PRIVATE_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def validate_url(
    url: str,
    allow_private: bool = False,
    allowed_schemes: Optional[set] = None,
) -> Tuple[bool, Optional[str]]:
    """Validate a URL for SSRF protection.

    Args:
        url: The URL to validate
        allow_private: If True, allow private/internal IPs (default False)
        allowed_schemes: Set of allowed URL schemes (default: http, https)

    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is None
    """
    if allowed_schemes is None:
        allowed_schemes = ALLOWED_SCHEMES

    if not url:
        return False, "URL is required"

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL format: {e}"

    # Check scheme
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        return False, f"URL scheme '{scheme}' not allowed. Allowed: {', '.join(allowed_schemes)}"

    # Check for empty hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must have a hostname"

    hostname_lower = hostname.lower()

    # Check blocked hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Hostname '{hostname}' is not allowed"

    # Check for AWS/cloud metadata endpoints
    if "169.254.169.254" in hostname or "metadata" in hostname_lower:
        return False, "Cloud metadata endpoints are not allowed"

    # Check if hostname is an IP address
    if not allow_private:
        # Try to parse as IP
        if is_private_ip(hostname):
            return False, f"Private/internal IP addresses are not allowed"

        # Check for decimal/octal/hex IP obfuscation
        # e.g., 2130706433 = 127.0.0.1, 0x7f000001 = 127.0.0.1
        if re.match(r'^[0-9]+$', hostname):
            try:
                decimal_ip = int(hostname)
                ip_str = str(ipaddress.ip_address(decimal_ip))
                if is_private_ip(ip_str):
                    return False, "Obfuscated private IP addresses are not allowed"
            except (ValueError, ipaddress.AddressValueError):
                pass

        # Check hex format
        if re.match(r'^0x[0-9a-fA-F]+$', hostname):
            try:
                hex_ip = int(hostname, 16)
                ip_str = str(ipaddress.ip_address(hex_ip))
                if is_private_ip(ip_str):
                    return False, "Obfuscated private IP addresses are not allowed"
            except (ValueError, ipaddress.AddressValueError):
                pass

    # Check port
    port = parsed.port
    if port and port in BLOCKED_PORTS:
        return False, f"Port {port} is not allowed for security reasons"

    # Check for URL encoding tricks
    if "%00" in url or "\x00" in url:
        return False, "Null bytes in URL are not allowed"

    # Check for CRLF injection
    if "\r" in url or "\n" in url or "%0d" in url.lower() or "%0a" in url.lower():
        return False, "CRLF characters in URL are not allowed"

    return True, None


def validate_integration_url(url: str, integration_type: str) -> Tuple[bool, Optional[str]]:
    """Validate a URL for integration configuration.

    This applies standard SSRF protections while allowing Docker network
    hostnames that are commonly used in containerized deployments.

    Args:
        url: The URL to validate
        integration_type: Type of integration (elasticsearch, kibana, etc.)

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Local services that should allow localhost (internal Docker services)
    LOCAL_SERVICES = {"ollama"}

    # First apply standard validation
    is_valid, error = validate_url(url, allow_private=(integration_type in LOCAL_SERVICES))

    if not is_valid:
        # Check if this might be a Docker network hostname
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname

            # Allow common Docker service names (alphanumeric with hyphens)
            # These resolve only within Docker networks
            if hostname and re.match(r'^[a-zA-Z][a-zA-Z0-9\-]*$', hostname):
                # Re-validate allowing the hostname but still checking other aspects
                if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                    return False, error
                if parsed.port and parsed.port in BLOCKED_PORTS:
                    return False, f"Port {parsed.port} is not allowed"
                # Allow Docker service names
                return True, None
        except Exception:
            pass

        return False, error

    return True, None
