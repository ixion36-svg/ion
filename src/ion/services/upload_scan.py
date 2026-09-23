"""Content indicators for uploaded text.

This is not an antivirus and does not pretend to be one. ION ships air-gapped,
so there is no engine to call out to, and a SOC analyst uploads malicious
content as a matter of course — refusing it would break the product's job.

What this does give is *provenance*: every upload is hashed, and recognisable
offensive patterns are named so the upload can be labelled, audited, and passed
to the model already marked as hostile data.

Matches are deliberately reported as named categories rather than a verdict. A
Sigma rule that hunts ``powershell -enc`` contains ``powershell -enc``; that is
a true match on the pattern and a false one on intent, which is tolerable when
the output annotates rather than refuses.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Pattern, Tuple

# Known test files, by digest. Hashes rather than literals so a host AV does not
# quarantine this source file.
_KNOWN_DIGESTS: Dict[str, str] = {
    # EICAR standard antivirus test file (68 bytes, no trailing newline).
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "av-test-file",
}

# The EICAR body can arrive padded, so also match the signature itself. Built
# from fragments for the same reason the digests are hashes.
_EICAR_SIGNATURE = (
    "X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}$"
    + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
# GTUBE, the equivalent test string for spam filters.
_GTUBE_SIGNATURE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*" + "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    (
        "reverse-shell",
        re.compile(
            r"/dev/tcp/\d|"
            r"\bnc\b[^\n]{0,40}\s-[a-z]*e[a-z]*\s+/bin/(?:ba)?sh|"
            r"New-Object\s+System\.Net\.Sockets\.TCPClient|"
            r"socket\.socket\([^\n]{0,60}\)[\s\S]{0,200}?(?:subprocess|os\.dup2|pty\.spawn)|"
            r"pty\.spawn\(",
            re.IGNORECASE,
        ),
    ),
    (
        "encoded-execution",
        re.compile(
            r"powershell(?:\.exe)?[^\n]{0,80}\s-(?:e|en|enc|encodedcommand)\b|"
            r"FromBase64String\s*\(|"
            r"\bIEX\s*\(|Invoke-Expression|"
            r"eval\s*\(\s*base64_decode|"
            r"certutil(?:\.exe)?[^\n]{0,40}-decode",
            re.IGNORECASE,
        ),
    ),
    (
        "webshell",
        re.compile(
            r"(?:eval|system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            re.IGNORECASE,
        ),
    ),
    (
        "credential-material",
        re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|"
            r"\bAKIA[0-9A-Z]{16}\b|"
            r"\bghp_[A-Za-z0-9]{36}\b|"
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
        ),
    ),
    (
        "obfuscation",
        re.compile(
            r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){19,}|"          # long hex-escape runs
            r"(?:chr\(\d{1,3}\)\s*\+\s*){8,}|"                  # chr() concat chains
            r"[A-Za-z0-9+/]{400,}={0,2}",                       # very long base64 blob
            re.IGNORECASE,
        ),
    ),
)


def sha256_of(content: bytes) -> str:
    """Digest of the uploaded bytes, for the audit record."""
    return hashlib.sha256(content).hexdigest()


def scan_text(content: bytes, text: str) -> List[str]:
    """Return the sorted indicator categories observed, or an empty list.

    ``content`` is the raw bytes (hashed) and ``text`` its decoded form. An
    empty list means nothing recognisable matched, NOT that the file is safe.
    """
    found = set()

    digest = sha256_of(content)
    if digest in _KNOWN_DIGESTS:
        found.add(_KNOWN_DIGESTS[digest])
    if _EICAR_SIGNATURE in text or _GTUBE_SIGNATURE in text:
        found.add("av-test-file")

    for name, pattern in _PATTERNS:
        if pattern.search(text):
            found.add(name)

    return sorted(found)
