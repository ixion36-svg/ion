"""Deterministic command-line deobfuscation for the log-analysis path.

Foundation-Sec (and LLMs generally) *hallucinate* base64 decodes — in live
testing the model invented a benign ``Get-Process OneNote`` command for what was
actually an ``IEX ... DownloadString`` cradle. So ION must decode deterministically
(here, in Python) and hand the model the decoded string as a **fact to reason
over**, never asking the model to decode it itself.

Scope: PowerShell ``-EncodedCommand`` / ``-enc`` payloads (UTF-16LE base64), the
dominant real-world obfuscation on the Windows command-line. Conservative by
design — only decodes when the flag is unambiguously an EncodedCommand prefix and
the blob is a plausible base64 string; returns nothing otherwise (no guessing).
"""
from __future__ import annotations

import base64
import re
from typing import Any, Dict, List

# `-e` … `-encodedcommand`: PowerShell accepts any unambiguous prefix. We match a
# `-e<letters>` flag followed by a base64-ish blob, then confirm the flag letters
# are a prefix of "encodedcommand" so `-ExecutionPolicy` etc. never match.
_FLAG_BLOB = re.compile(r"-(e[a-z]*)\s+\"?([A-Za-z0-9+/=]{16,})\"?", re.IGNORECASE)


def _looks_printable(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c == "\t" or c == "\n" or 0x20 <= ord(c) < 0x7F)
    return printable / len(s) >= 0.85


def _try_b64(blob: str) -> str | None:
    """Base64-decode a blob, preferring UTF-16LE (PowerShell -enc), then UTF-8."""
    pad = "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob + pad, validate=True)
    except Exception:  # noqa: BLE001 - malformed input is expected, decode is best-effort
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc).rstrip("\x00").strip()
        except (UnicodeDecodeError, ValueError):
            continue
        if text and _looks_printable(text):
            return text
    return None


def decode_powershell_encoded(text: Any) -> List[str]:
    """Return the decoded string(s) for every PowerShell -EncodedCommand in ``text``.

    Deterministic and side-effect-free. Returns ``[]`` for plain commands,
    non-EncodedCommand flags, malformed base64, or non-string input.
    """
    if not isinstance(text, str) or not text:
        return []
    out: List[str] = []
    for m in _FLAG_BLOB.finditer(text):
        flag = m.group(1).lower()
        if not "encodedcommand".startswith(flag):
            continue  # e.g. -executionpolicy is not an EncodedCommand prefix
        decoded = _try_b64(m.group(2))
        if decoded:
            out.append(decoded)
    return out


def decoded_ioc_text(text: Any) -> str:
    """Newline-joined decoded PowerShell payloads found in ``text``.

    Feed this alongside the raw alert text into the IOC extractor so that C2
    URLs/IPs/hashes hidden inside a base64 ``-EncodedCommand`` become
    observables. Returns "" when nothing decodes.
    """
    return "\n".join(decode_powershell_encoded(text))


# Fields most likely to carry a command line, checked first for a tidy label.
_CMD_FIELDS = (
    "process.command_line", "command_line", "commandLine",
    "data.win.eventdata.commandLine", "process_command_line",
)


def deobfuscate_alert(alert_summary: Dict[str, Any]) -> List[Dict[str, str]]:
    """Scan an alert's string values for encoded commands, decode deterministically.

    Returns ``[{"field": <key>, "decoded": <plaintext>}, ...]`` — the facts to
    inject into the LLM prompt so the model reasons over the *decoded* content.
    """
    if not isinstance(alert_summary, dict):
        return []
    results: List[Dict[str, str]] = []
    seen: set = set()

    def _scan(key: str, value: Any) -> None:
        for decoded in decode_powershell_encoded(value):
            sig = (key, decoded)
            if sig in seen:
                continue
            seen.add(sig)
            results.append({"field": key, "decoded": decoded})

    # Preferred command fields first (stable ordering), then any other string.
    for k in _CMD_FIELDS:
        if k in alert_summary:
            _scan(k, alert_summary[k])
    for k, v in alert_summary.items():
        if k not in _CMD_FIELDS and isinstance(v, str):
            _scan(k, v)
    return results
