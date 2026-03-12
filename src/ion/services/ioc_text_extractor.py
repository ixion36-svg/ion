"""Extract IOCs (Indicators of Compromise) from freeform text, CSV, and documents.

Supports: IPv4, IPv6, MD5, SHA-1, SHA-256, domains, URLs, email addresses,
CVE IDs, MAC addresses, and hostnames.
"""

import csv
import io
import re
from typing import Optional


# ── Regex Patterns ──────────────────────────────────────────────────────

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)

_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|mil|int|io|co|uk|de|fr|ru|cn|jp|au|ca|"
    r"br|in|it|nl|se|no|fi|dk|pl|cz|es|pt|ch|at|be|ie|nz|za|mx|ar|"
    r"info|biz|name|pro|xyz|top|club|site|online|tech|store|app|dev|"
    r"onion|bit|tk|ml|ga|cf|gq|pw|cc|tv|ws|ly|me|us|eu)\b",
    re.IGNORECASE,
)

_URL = re.compile(
    r"https?://[^\s<>\"'\)\]}{,]+",
    re.IGNORECASE,
)

# Defanged URL patterns: hxxp[s]://, [.] instead of .
_URL_DEFANGED = re.compile(
    r"hxxps?://[^\s<>\"'\)\]}{,]+",
    re.IGNORECASE,
)

_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_MAC = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"
)

# Hostname patterns (WORKSTATION-XX, SRV-XX, DC01, etc.)
_HOSTNAME = re.compile(
    r"\b(?:[A-Z][A-Z0-9]*[\-_][A-Z0-9\-_]+)\b"
)

# Private/reserved IPv4 ranges to skip when extracting "external" IPs
_PRIVATE_IPV4 = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)

# Common false-positive domains
_FP_DOMAINS = {
    "example.com", "example.org", "example.net",
    "localhost.localdomain", "schema.org", "w3.org",
}


def _is_valid_ipv4(ip: str) -> bool:
    """Check if an IPv4 string is a real routable or internal address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    # Skip 0.0.0.0, 255.255.255.255, and multicast
    if nums == [0, 0, 0, 0] or nums == [255, 255, 255, 255]:
        return False
    if nums[0] >= 224:
        return False
    return True


def _refang(text: str) -> str:
    """Convert defanged indicators back to standard form for extraction."""
    t = text.replace("[.]", ".").replace("(.)",".")
    t = t.replace("hxxp://", "http://").replace("hxxps://", "https://")
    t = t.replace("[://]", "://").replace("[:]", ":")
    return t


def extract_iocs(text: str) -> dict:
    """Extract all IOC types from freeform text.

    Returns a dict keyed by IOC type, each containing a deduplicated list of values.
    """
    # Refang common defanging patterns
    clean = _refang(text)

    # Extract SHA-256 first (longest), then SHA-1, then MD5
    # to avoid substring matches
    sha256_set = set()
    sha1_set = set()
    md5_set = set()

    for m in _SHA256.finditer(clean):
        sha256_set.add(m.group().lower())

    for m in _SHA1.finditer(clean):
        val = m.group().lower()
        # Skip if it's a substring of a SHA-256
        if not any(val in s for s in sha256_set):
            sha1_set.add(val)

    for m in _MD5.finditer(clean):
        val = m.group().lower()
        # Skip if substring of SHA-1 or SHA-256
        if not any(val in s for s in sha256_set) and not any(val in s for s in sha1_set):
            md5_set.add(val)

    # IPs
    ipv4_set = set()
    for m in _IPV4.finditer(clean):
        ip = m.group()
        if _is_valid_ipv4(ip):
            ipv4_set.add(ip)

    ipv6_set = set()
    for m in _IPV6.finditer(clean):
        ipv6_set.add(m.group().lower())

    # Domains — exclude IPs and FPs
    domain_set = set()
    for m in _DOMAIN.finditer(clean):
        d = m.group().lower().rstrip(".")
        if d not in _FP_DOMAINS and not _IPV4.match(d):
            domain_set.add(d)

    # URLs — extract from refanged text to avoid partial matches on defanged brackets
    _strip_chars = ".,;:]}"
    url_set = set()
    for m in _URL.finditer(clean):
        u = m.group().rstrip(_strip_chars)
        # Skip if it still contains defanging artifacts
        if "[" not in u:
            url_set.add(u)

    # Emails
    email_set = set()
    for m in _EMAIL.finditer(clean):
        email_set.add(m.group().lower())

    # CVEs
    cve_set = set()
    for m in _CVE.finditer(clean):
        cve_set.add(m.group().upper())

    # MAC addresses
    mac_set = set()
    for m in _MAC.finditer(clean):
        mac_set.add(m.group().upper().replace("-", ":"))

    # Hostnames — only uppercase patterns that aren't domains or CVEs
    hostname_set = set()
    for m in _HOSTNAME.finditer(text):  # Use original text (case-sensitive)
        h = m.group()
        if len(h) >= 4 and h.lower() not in domain_set and not h.upper().startswith("CVE-"):
            hostname_set.add(h)

    result = {}
    if ipv4_set:
        result["ipv4"] = sorted(ipv4_set)
    if ipv6_set:
        result["ipv6"] = sorted(ipv6_set)
    if md5_set:
        result["md5"] = sorted(md5_set)
    if sha1_set:
        result["sha1"] = sorted(sha1_set)
    if sha256_set:
        result["sha256"] = sorted(sha256_set)
    if domain_set:
        result["domains"] = sorted(domain_set)
    if url_set:
        result["urls"] = sorted(url_set)
    if email_set:
        result["emails"] = sorted(email_set)
    if cve_set:
        result["cves"] = sorted(cve_set)
    if mac_set:
        result["mac_addresses"] = sorted(mac_set)
    if hostname_set:
        result["hostnames"] = sorted(hostname_set)

    # Summary count
    total = sum(len(v) for v in result.values())
    result["_total"] = total

    return result


def extract_from_csv(content: str) -> dict:
    """Parse CSV content and extract IOCs from all cells."""
    all_text_parts = []
    try:
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            for cell in row:
                if cell and cell.strip():
                    all_text_parts.append(cell.strip())
    except csv.Error:
        # Fall back to treating as plain text
        all_text_parts.append(content)
    return extract_iocs("\n".join(all_text_parts))


def extract_from_file(content: bytes, filename: str) -> dict:
    """Extract IOCs from an uploaded file based on its extension.

    Supports: .csv, .txt, .log, .json, .md, .tsv, .ioc
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    text: Optional[str] = None

    # Try UTF-8 first, then latin-1 as fallback
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = content.decode(encoding)
            break
        except (UnicodeDecodeError, ValueError):
            continue

    if text is None:
        return {"error": "Could not decode file content", "_total": 0}

    if ext == "csv":
        return extract_from_csv(text)
    elif ext == "tsv":
        # Convert TSV to CSV-like for processing
        return extract_from_csv(text.replace("\t", ","))
    else:
        # txt, log, json, md, ioc, etc. — treat as freeform text
        return extract_iocs(text)
