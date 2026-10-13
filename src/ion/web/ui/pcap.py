"""Server-rendered panels for the pcap analyser.

The page is one stored analysis result rendered into twenty-eight panels,
and every panel was built from a JavaScript string. The result is durable:
uploads go to POST /api/pcap/jobs, which records the job, so these
fragments read it back by id rather than taking it from the page.

A MISSING VERDICT TOOK THE WHOLE PAGE DOWN

renderResults opened with

    const label = d.verdict.label;

with no guard, and it is the first statement in the function that renders
all twenty-eight panels. A stored result without a verdict key threw
there, so nothing rendered: no protocol distribution, no DNS, no findings,
no threat intel, on an analysis that had run and whose result was sitting
in the database.

THE NaN DEFECT, FOUR TABLES AT ONCE

    const max = Math.max(...top.map(i => i.count), 1);
    const pct = (i.count / max * 100).toFixed(1);

One count that is not a number makes `max` NaN and every percentage after
it NaN, so every bar in both IP tables and both port tables rendered
`width:NaN%`. The conversation bars were worse: `convMax` is
`d.conversations[0].bytes`, which trusts the list to be sorted and goes
NaN if the first entry alone is missing its byte count.

EVERY TAB BADGE CARRIED ITS PALETTE IN A JAVASCRIPT STRING

    fb.style.cssText = 'display:inline;background:var(--sev-critical);...'

repeated at eighteen sites, one per tab, with the background swapped
between --sev-critical, --sev-high, --sev-medium, --primary, --info and
--warning. This is not a CSP problem: server.py's note is explicit that
the policy allows programmatic CSSOM, and a `style.cssText` write is
CSSOM rather than a style attribute parse, so it applies. It is the
problem this project exists to fix. Eighteen copies of a padding, a
radius, a font size and a colour, held in JavaScript, where no sweep of
the stylesheet can reach any of them and no theme can override one.

fmtBytes and fmtDuration both fall through every comparison for a missing
value and then divide, returning "NaN GB" and "NaNh". fmtNum is
`(n || 0).toLocaleString()`, so a capture whose packet count was not
recorded reported zero packets.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import instant_label, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

#: The pcap page's own permission, matching pcap_api.py's endpoints.
PERMISSION = "alert:read"

SUMMARY_FRAGMENT = "_fragments/pcap_summary.html"
NETWORK_FRAGMENT = "_fragments/pcap_network.html"

#: The verdict labels that take their own banner state. Anything else is
#: drawn as benign, which is the page's own fallback.
VERDICT_STATES: dict[str, str] = {
    "Needs Investigation": "investigate",
    "Elevated": "elevated",
}

#: The protocols with a bar colour of their own.
PROTOCOL_CLASSES: dict[str, str] = {
    "TCP": "tcp", "UDP": "udp", "ICMP": "icmp",
}

#: How many rows each network table shows, from the page's slice(0, 15).
TABLE_ROWS = 15

#: How many conversation bars the overview shows, from slice(0, 10).
CONVERSATION_BARS = 10


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _int(value: Any) -> Optional[int]:
    number = _num(value)
    return None if number is None else int(number)


def _text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def bytes_label(value: Any) -> Optional[str]:
    """The size, or None when none was recorded.

    The thresholds are fmtBytes's. What changes is that a missing value
    says so rather than falling through to "NaN GB".
    """
    number = _num(value)
    if number is None or number < 0:
        return None
    if number < 1024:
        return "%d B" % int(number)
    if number < 1048576:
        return "%.1f KB" % (number / 1024)
    if number < 1073741824:
        return "%.1f MB" % (number / 1048576)
    return "%.1f GB" % (number / 1073741824)


def duration_label(value: Any) -> Optional[str]:
    """The capture duration, with fmtDuration's own thresholds."""
    number = _num(value)
    if number is None or number < 0:
        return None
    if number < 1:
        return "%.3fs" % number
    if number < 60:
        return "%.1fs" % number
    if number < 3600:
        return "%.1fm" % (number / 60)
    return "%.1fh" % (number / 3600)


def count_label(value: Any) -> Optional[str]:
    """A thousands-separated count, or None.

    `(n || 0).toLocaleString()` reported a recorded zero and a count that
    was never recorded as the same zero.
    """
    number = _int(value)
    return None if number is None else "{:,}".format(number)


class Bar(TypedDict):
    label: str
    css_class: str
    count: Optional[str]
    pct: Optional[float]


def bars(mapping: Any, classes: dict[str, str]) -> Optional[list[Bar]]:
    """The protocol distribution.

    An unreadable count is dropped from the total rather than poisoning
    it, so one bad entry no longer makes every bar NaN.
    """
    if not isinstance(mapping, dict):
        return None
    counts = {str(k): _num(v) for k, v in mapping.items()}
    total = sum(c for c in counts.values() if c is not None)
    out: list[Bar] = []
    for label, count in counts.items():
        pct = (None if count is None or total <= 0
               else round(count / total * 100, 1))
        out.append({
            "label": label,
            # The class comes from a fixed set. `proto-bar-fill ${cls}`
            # had a fallback, so this was never a hole, but the class is
            # still decided here rather than from the key.
            "css_class": classes.get(label, "other"),
            "count": count_label(count),
            "pct": pct,
        })
    return out


class ConvBar(TypedDict):
    pair: str
    bytes: Optional[str]
    pct: Optional[float]


def conversation_bars(raw: Any) -> Optional[list[ConvBar]]:
    """The top conversations, scaled to the largest.

    `convMax = d.conversations[0].bytes` trusted the list to be sorted, so
    an unsorted list drew bars past 100%, and a first entry with no byte
    count made every bar NaN.
    """
    if not isinstance(raw, list):
        return None
    entries = [e for e in raw[:CONVERSATION_BARS] if isinstance(e, dict)]
    sizes = [_num(e.get("bytes")) for e in entries]
    readable = [s for s in sizes if s is not None]
    top = max(readable) if readable else 0.0
    out: list[ConvBar] = []
    for entry, size in zip(entries, sizes):
        out.append({
            "pair": _text(entry.get("pair")) or "unnamed conversation",
            "bytes": bytes_label(size),
            "pct": (None if size is None or top <= 0
                    else round(size / top * 100, 1)),
        })
    return out


class TableRow(TypedDict):
    name: str
    count: Optional[str]
    pct: Optional[float]


def table_rows(raw: Any, key: str) -> Optional[list[TableRow]]:
    """One network table.

    `Math.max(...top.map(i => i.count), 1)` is NaN if any one count is
    not a number, and every percentage derived from it is NaN, so the
    whole bar column rendered as `width:NaN%`.
    """
    if not isinstance(raw, list):
        return None
    entries = [e for e in raw[:TABLE_ROWS] if isinstance(e, dict)]
    counts = [_num(e.get("count")) for e in entries]
    readable = [c for c in counts if c is not None]
    top = max(max(readable), 1.0) if readable else 1.0
    out: list[TableRow] = []
    for entry, count in zip(entries, counts):
        value = entry.get(key)
        out.append({
            "name": (_text(value) if isinstance(value, str)
                     else str(value) if _num(value) is not None
                     else "unrecorded"),
            "count": count_label(count),
            "pct": (None if count is None
                    else round(count / top * 100, 1)),
        })
    return out


class Verdict(TypedDict):
    present: bool
    label: str
    state: str
    confidence: Optional[int]
    score: Optional[int]
    finding_count: Optional[int]
    reasons: Optional[list[str]]


def verdict_view(raw: Any) -> Verdict:
    """The banner.

    `const label = d.verdict.label` with no guard was the first statement
    of the function that rendered every panel on the page.
    """
    if not isinstance(raw, dict):
        return {"present": False, "label": "No verdict recorded",
                "state": "benign", "confidence": None, "score": None,
                "finding_count": None, "reasons": []}
    label = _text(raw.get("label"))
    reasons = raw.get("reasons")
    return {
        "present": True,
        "label": label or "No verdict recorded",
        "state": VERDICT_STATES.get(label or "", "benign"),
        "confidence": _int(raw.get("confidence")),
        "score": _int(raw.get("score")),
        "finding_count": _int(raw.get("finding_count")),
        # None when the payload is not a list, so "no reasons given" and
        # "the reasons are unreadable" stay apart.
        "reasons": (None if not isinstance(reasons, list) else
                    [t for t in (_text(r) for r in reasons) if t]),
    }


class Card(TypedDict):
    label: str
    value: Optional[str]
    sub: Optional[str]
    missing: Optional[str]


class SummaryView(TypedDict):
    state: str
    error: Optional[str]
    verdict: Verdict
    cards: list[Card]
    finding_count: Optional[int]
    protocol_bars: Optional[list[Bar]]
    conversations: Optional[list[ConvBar]]


class NetworkView(TypedDict):
    state: str
    error: Optional[str]
    tables: list[dict]


def _card(label: str, value: Optional[str], sub: Optional[str],
          missing: str) -> Card:
    return {"label": label, "value": value, "sub": sub,
            "missing": None if value is not None else missing}


def summary_cards(result: dict) -> list[Card]:
    protocols = result.get("protocols")
    names = (", ".join(str(k) for k in protocols)
             if isinstance(protocols, dict) and protocols else None)
    src_ips = result.get("top_src_ips")
    dns = result.get("dns_queries")
    return [
        _card("File", _text(result.get("file_name")),
              bytes_label(result.get("file_size")),
              "No file name recorded"),
        _card("Packets", count_label(result.get("packet_count")), None,
              "No packet count recorded"),
        _card("Duration", duration_label(result.get("capture_duration")),
              instant_label(result.get("time_start")),
              "No capture duration recorded"),
        _card("Protocols", names, None, "No protocols recorded"),
        _card("Unique Src IPs",
              (count_label(len(src_ips)) if isinstance(src_ips, list)
               else None), None,
              "The source IP list is not in a readable shape"),
        _card("DNS Queries",
              ((count_label(len(dns)) + " unique")
               if isinstance(dns, list) else None), None,
              "The DNS query list is not in a readable shape"),
    ]


def summary_view(job: Any) -> SummaryView:
    empty: SummaryView = {
        "state": "failed", "error": None, "verdict": verdict_view(None),
        "cards": [], "finding_count": None, "protocol_bars": None,
        "conversations": None,
    }
    if not isinstance(job, dict):
        return empty
    result = job.get("result")
    if not isinstance(result, dict):
        view = dict(empty)
        view["state"] = "no_result"
        view["error"] = _text(job.get("error"))
        return view  # type: ignore[return-value]
    findings = result.get("findings")
    return {
        "state": "data",
        "error": _text(job.get("error")),
        "verdict": verdict_view(result.get("verdict")),
        "cards": summary_cards(result),
        "finding_count": (len(findings) if isinstance(findings, list)
                          else None),
        "protocol_bars": bars(result.get("protocols"), PROTOCOL_CLASSES),
        "conversations": conversation_bars(result.get("conversations")),
    }


def network_view(job: Any) -> NetworkView:
    if not isinstance(job, dict) or not isinstance(job.get("result"), dict):
        return {"state": "failed", "error": (
            _text(job.get("error")) if isinstance(job, dict) else None),
            "tables": []}
    result = job["result"]
    return {
        "state": "data",
        "error": None,
        "tables": [
            {"heading": "Top Source IPs", "column": "IP Address",
             "rows": table_rows(result.get("top_src_ips"), "ip")},
            {"heading": "Top Destination IPs", "column": "IP Address",
             "rows": table_rows(result.get("top_dst_ips"), "ip")},
            {"heading": "Top Source Ports", "column": "Port",
             "rows": table_rows(result.get("top_src_ports"), "port")},
            {"heading": "Top Destination Ports", "column": "Port",
             "rows": table_rows(result.get("top_dst_ports"), "port")},
        ],
    }


def _job(job_id: int, user: User, session: Session) -> tuple[Any, Optional[str]]:
    """The stored analysis, or the reason there isn't one."""
    from fastapi import HTTPException

    from ion.web import pcap_api

    try:
        return pcap_api.get_pcap_job(
            job_id=job_id, _user=user, session=session), None
    except HTTPException as refusal:
        return None, (str(refusal.detail) if refusal.detail
                      else "This analysis was refused.")
    except Exception:
        logger.exception("Pcap fragment could not read job %s", job_id)
        return None, None


@router.get(
    "/pcap/{job_id}/summary",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_summary_fragment(
    request: Request,
    job_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The verdict banner, the summary cards and the overview."""
    job, refusal = _job(job_id, current_user, session)
    view = summary_view(job)
    if refusal is not None:
        view["error"] = refusal
    return render_view(request, SUMMARY_FRAGMENT, view)


@router.get(
    "/pcap/{job_id}/network",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_network_fragment(
    request: Request,
    job_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The four top-talker tables."""
    job, refusal = _job(job_id, current_user, session)
    view = network_view(job)
    if refusal is not None:
        view["error"] = refusal
    return render_view(request, NETWORK_FRAGMENT, view)


# ---------------------------------------------------------------------------
# The table panels
# ---------------------------------------------------------------------------
#
# Fourteen of the page's panels were the same function written fourteen
# times: take a list off the result, hide the tab if it is empty, set a tab
# badge, and build a table. They are a registry here, because the thing
# that actually differs between them is a heading, a badge tone and a list
# of columns, and that is data.
#
# What they had in common besides shape:
#
#   * `d.whatever || []` throughout, so a payload in the wrong shape drew
#     as an empty panel with its tab hidden. A hidden tab is the strongest
#     possible claim that a capture contained no credentials, no malware
#     JA3 match and no ARP anomalies, and it was being made on the basis
#     of a read that failed.
#   * Numbers straight into markup: `${b.port}`, `${b.score}`,
#     `${b.connections}`, `${s.retransmits}`, `${h.beacons}`, each
#     printing "undefined" for a row that did not carry one.
#   * `fmtBytes` on a missing size, which falls through every comparison
#     and returns "NaN GB".
#   * ARP built a CSS variable name out of the payload:
#     `data-ion-style="color:var(--sev-${a.severity})"`. A severity the
#     analyser did not emit resolves to an undefined custom property and
#     the text takes its inherited colour, so the row looked ordinary.
#     The severity picks a class from a fixed set now.

TABLES_FRAGMENT = "_fragments/pcap_tables.html"

#: A column: the header, the key it reads, and how the cell is drawn.
#: The kinds are the ones the page actually used.
#:
#:   text      plain, escaped
#:   mono      font-mono
#:   wrap      font-mono break-all
#:   strong    <strong>
#:   code      <code>, with the size class the page gave it
#:   num       right-aligned thousands separated
#:   plain_num right-aligned, no separator (ports, counts, scores)
#:   bytes     a size label
#:   list      a list joined with ", "
#:   malware   the known-malware match, critical when there is one
#:   endpoint  an ip:port pair
#:   seconds   a "~Ns" interval
Column = tuple  # (header, key, kind, extra)


def col(header: str, key: str, kind: str = "text", extra: str = "") -> Column:
    return (header, key, kind, extra)


#: One panel: where it lives, what it reads, and what it draws.
#: `tab` is the tab button that is hidden when the list is empty, and
#: `badge` the count beside it.
TABLE_PANELS: tuple[dict, ...] = (
    {"key": "dns_queries", "panel": "panel-dns", "data_panel": None, "label": None, "tab": None,
     "badge": None, "tone": None, "heading": "DNS Queries",
     "unit": "unique", "empty": "No DNS queries captured.",
     "limit": 40,
     "columns": (col("Query", "query", "wrap"),
                 col("Count", "count", "num"))},
    {"key": "http_requests", "panel": "panel-http", "data_panel": None, "label": None, "tab": None,
     "badge": None, "tone": None, "heading": "HTTP Requests",
     "unit": "unique", "empty": "No HTTP requests captured.",
     "limit": 40,
     "columns": (col("Request", "request", "wrap"),
                 col("Count", "count", "num"))},
    {"key": "tls_handshakes", "panel": "panel-tls", "data_panel": None, "label": None, "tab": None,
     "badge": None, "tone": None, "heading": "TLS SNI",
     "unit": "unique", "empty": "No TLS handshakes captured.",
     "limit": 40,
     "columns": (col("SNI", "sni", "mono"),
                 col("Handshakes", "count", "num"))},
    {"key": "extracted_files", "panel": "panel-files", "data_panel": "files", "label": "Extracted Files", "tab": "tab-files",
     "badge": "files-count-badge", "tone": "tone-high",
     "heading": "Extracted Files",
     "note": "Files carved from reassembled TCP streams by magic byte "
             "signature.",
     "columns": (col("File", "filename", "strong"),
                 col("Type", "mime_type"),
                 col("Size", "size", "bytes"),
                 col("MD5", "md5", "code", "text-[.7rem] break-all"),
                 col("SHA-256", "sha256", "code", "text-[.65rem] break-all"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip"))},
    {"key": "ja3_fingerprints", "panel": "panel-ja3", "data_panel": "ja3", "label": "JA3 Fingerprints", "tab": "tab-ja3",
     "badge": "ja3-count-badge", "tone": "tone-critical",
     "tone_when_flagged": "tone-critical", "tone_otherwise": "tone-primary",
     "flag": "known_malware", "heading": "JA3 TLS Fingerprints",
     "columns": (col("JA3 Hash", "ja3_hash", "code", "text-[.72rem]"),
                 col("SNI", "sni"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip", "endpoint", "dst_port"),
                 col("Malware Match", "known_malware", "malware"))},
    {"key": "credential_captures", "panel": "panel-creds", "data_panel": "creds", "label": "Credentials",
     "tab": "tab-creds", "badge": "creds-count-badge",
     "tone": "tone-critical", "heading": "Captured Credentials",
     "columns": (col("Protocol", "protocol", "strong"),
                 col("Username", "username", "code"),
                 col("Credential / Hash", "credential", "code",
                     "text-[.7rem] break-all max-w-[200px] inline-block "
                     "overflow-hidden text-ellipsis"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip"),
                 col("Detail", "detail"))},
    {"key": "ja3s_fingerprints", "panel": "panel-ja3s", "data_panel": "ja3s", "label": "JA3S", "tab": "tab-ja3s",
     "badge": "ja3s-count-badge", "tone": "tone-critical",
     "tone_when_flagged": "tone-critical", "tone_otherwise": "tone-primary",
     "flag": "known_malware", "heading": "JA3S Server Fingerprints",
     "columns": (col("JA3S Hash", "ja3s_hash", "code", "text-[.72rem]"),
                 col("Server", "src_ip"),
                 col("Client", "dst_ip"),
                 col("Port", "src_port", "plain_num"),
                 col("Malware Match", "known_malware", "malware"))},
    {"key": "hassh_fingerprints", "panel": "panel-hassh", "data_panel": "hassh", "label": "HASSH",
     "tab": "tab-hassh", "badge": "hassh-count-badge",
     "tone": "tone-primary",
     "tone_when_flagged": "tone-critical", "tone_otherwise": "tone-primary",
     "flag": "known_malware", "heading": "HASSH SSH Fingerprints",
     "columns": (col("HASSH Hash", "hassh_hash", "code", "text-[.72rem]"),
                 col("Direction", "direction"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip"),
                 col("SSH Version", "ssh_version"),
                 col("Match", "known_malware", "malware"))},
    {"key": "smb_transfers", "panel": "panel-smb", "data_panel": "smb", "label": "SMB", "tab": "tab-smb",
     "badge": "smb-count-badge", "tone": "tone-warning",
     "heading": "SMB File Operations",
     "columns": (col("Command", "command", "strong"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip"),
                 col("Detail", "detail"))},
    {"key": "kerberos_tickets", "panel": "panel-kerberos", "data_panel": "kerberos", "label": "Kerberos",
     "tab": "tab-kerberos", "badge": "kerberos-count-badge",
     "tone": "tone-info", "heading": "Kerberos Traffic",
     "columns": (col("Type", "msg_type", "strong"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip"),
                 col("Detail", "detail"))},
    {"key": "http_files", "panel": "panel-httpfiles", "data_panel": "httpfiles", "label": "HTTP Files",
     "tab": "tab-httpfiles", "badge": "httpfiles-count-badge",
     "tone": "tone-high", "heading": "HTTP File Transfers",
     "columns": (col("Filename", "filename", "strong"),
                 col("Content-Type", "content_type"),
                 col("Size", "size", "bytes"),
                 col("MD5", "md5", "code", "text-[.7rem]"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip"))},
    {"key": "arp_anomalies", "panel": "panel-arp", "data_panel": "arp", "label": "ARP", "tab": "tab-arp",
     "badge": "arp-count-badge", "tone": "tone-critical",
     "heading": "ARP Anomalies",
     "columns": (col("MAC", "mac", "code"),
                 col("IPs Claimed", "ips", "list"),
                 col("Severity", "severity", "severity"),
                 col("Detail", "detail", "small"))},
    {"key": "base64_payloads", "panel": "panel-b64", "data_panel": "b64", "label": "Base64", "tab": "tab-b64",
     "badge": "b64-count-badge", "tone": "tone-high",
     "heading": "Base64 Encoded Payloads",
     "columns": (col("Type", "type", "strong"),
                 col("Encoded Size", "encoded_length", "bytes"),
                 col("Decoded Size", "decoded_length", "bytes"),
                 col("Source", "src_ip"),
                 col("Destination", "dst_ip", "endpoint", "port"),
                 col("Preview", "preview", "code",
                     "text-[.68rem] break-all max-w-[300px] inline-block "
                     "overflow-hidden text-ellipsis"))},
    {"key": "beacons", "panel": "panel-beacons", "data_panel": "beacons", "label": "Beaconing", "tab": "tab-beacons",
     "badge": "beacons-count-badge", "tone": "tone-high",
     "heading": "Beaconing Candidates",
     "columns": (col("Source", "src"),
                 col("Destination", "dst"),
                 col("Port", "port", "plain_num"),
                 col("Score", "score", "strong"),
                 col("Connections", "connections", "num"),
                 col("Interval", "interval_s", "seconds"))},
)

#: The severity classes an ARP row may take. The page built the custom
#: property name from the payload, so a severity the analyser did not emit
#: left the text its inherited colour and the row read as ordinary.
SEVERITY_CLASSES: tuple[str, ...] = (
    "critical", "high", "medium", "low", "info",
)


class Cell(TypedDict):
    kind: str
    css_class: str
    value: Optional[str]
    missing: Optional[str]
    flagged: bool


def _cell(column: Column, row: dict) -> Cell:
    header, key, kind, extra = column
    raw = row.get(key)
    value: Optional[str] = None
    flagged = False
    missing = "This row carried no %s" % header.lower()

    if kind in ("num",):
        value = count_label(raw)
    elif kind == "plain_num":
        number = _int(raw)
        value = None if number is None else str(number)
    elif kind == "bytes":
        value = bytes_label(raw)
    elif kind == "seconds":
        number = _num(raw)
        value = None if number is None else "~%gs" % number
    elif kind == "list":
        if isinstance(raw, list):
            parts = [t for t in (_text(v) if isinstance(v, str)
                                 else _text(str(v)) for v in raw) if t]
            value = ", ".join(parts) if parts else None
            missing = "No %s were recorded" % header.lower()
        else:
            missing = "The %s are not in a readable shape" % header.lower()
    elif kind == "malware":
        name = _text(raw)
        flagged = bool(name)
        value = name or "clean"
        missing = None
    elif kind == "severity":
        name = _text(raw)
        value = name
        flagged = name in SEVERITY_CLASSES
    elif kind == "endpoint":
        host = _text(row.get(key))
        port = _int(row.get(extra))
        if host is not None:
            value = host if port is None else "%s:%d" % (host, port)
    else:
        value = _text(raw) if isinstance(raw, str) else (
            str(raw) if _num(raw) is not None else None)

    return {"kind": kind, "css_class": extra, "value": value,
            "missing": missing, "flagged": flagged}


class Table(TypedDict):
    key: str
    panel: str
    data_panel: Optional[str]
    label: Optional[str]
    tab: Optional[str]
    badge: Optional[str]
    tone: Optional[str]
    heading: str
    unit: Optional[str]
    note: Optional[str]
    empty: Optional[str]
    state: str
    count: Optional[int]
    headers: list[str]
    rows: list[list[Cell]]


def table_panel(spec: dict, result: dict) -> Table:
    raw = result.get(spec["key"])
    headers = [c[0] for c in spec["columns"]]
    base: Table = {
        "key": spec["key"], "panel": spec["panel"],
        "data_panel": spec.get("data_panel"), "label": spec.get("label"),
        "tab": spec.get("tab"),
        "badge": spec.get("badge"), "tone": spec.get("tone"),
        "heading": spec["heading"], "unit": spec.get("unit"),
        "note": spec.get("note"), "empty": spec.get("empty"),
        "state": "unreadable", "count": None, "headers": headers,
        "rows": [],
    }
    if not isinstance(raw, list):
        # `d.whatever || []` hid the tab for this, which claims the
        # capture contained none of whatever it is.
        return base
    entries = [e for e in raw if isinstance(e, dict)]
    limit = spec.get("limit")
    shown = entries[:limit] if limit else entries
    base["count"] = len(entries)
    base["state"] = "data" if entries else "empty"
    base["rows"] = [[_cell(c, row) for c in spec["columns"]]
                    for row in shown]
    flag = spec.get("flag")
    if flag:
        hit = any(_text(row.get(flag)) for row in entries)
        base["tone"] = (spec["tone_when_flagged"] if hit
                        else spec["tone_otherwise"])
    return base


class TablesView(TypedDict):
    state: str
    error: Optional[str]
    tables: list[Table]


def tables_view(job: Any) -> TablesView:
    if not isinstance(job, dict) or not isinstance(job.get("result"), dict):
        return {"state": "failed",
                "error": (_text(job.get("error"))
                          if isinstance(job, dict) else None),
                "tables": []}
    result = job["result"]
    return {"state": "data", "error": None,
            "tables": [table_panel(spec, result)
                       for spec in TABLE_PANELS]}


@router.get(
    "/pcap/{job_id}/tables",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_tables_fragment(
    request: Request,
    job_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """Fourteen table panels in one request, each swapped into its own
    container out of band."""
    job, refusal = _job(job_id, current_user, session)
    view = tables_view(job)
    if refusal is not None:
        view["error"] = refusal
    return render_view(request, TABLES_FRAGMENT, view)


# ---------------------------------------------------------------------------
# The seven panels the registry could not take
# ---------------------------------------------------------------------------
#
# Each of these has real logic rather than a list of columns.
#
# THE EXFILTRATION FLAG COULD NOT FIRE ON THE CLEAREST EXFILTRATION SHAPE
#
#     const exfil = i.received > 0 && i.sent / i.received > 3
#                   && i.sent > 100000;
#
# The `received > 0` guard is there so the division is safe, and the cost
# of it is that a host which sent a great deal and received nothing never
# trips the flag. All outbound and no inbound is the shape the heuristic
# exists to catch. The ratio column already prints an infinity sign for
# exactly that case, so the data is right there in the same row; only the
# flag could not say so. A host with no `received` recorded at all fails
# the same test for the same reason, and reads as unremarkable.
#
# The rule here keeps the ratio and the floor and adds the degenerate
# case: a host over the floor with no inbound at all is at least as
# interesting as one over the ratio.
#
# A MISSING IKE STATUS TOOK THE PANEL DOWN
#
#     const statusClass = s => s.toLowerCase().replace(/\s+/g, '-');
#
# `undefined.toLowerCase()` throws, and it throws inside the map that
# builds every row, so one session with no status cost the whole panel.
# The status also went into a class attribute, where only four values
# style anything, and the four summary counts compared exact strings, so a
# session with a fifth status was counted nowhere and the counts summed to
# less than the total with nothing to say so.

DETAIL_FRAGMENT = "_fragments/pcap_detail.html"

#: Outbound/inbound ratio above which a host is called exfiltration-shaped.
EXFIL_RATIO = 3.0

#: Bytes sent below which the ratio is not interesting, however lopsided.
EXFIL_FLOOR = 100000

#: How many hosts the data-transfer panel shows, from slice(0, 20).
DATA_ROWS = 20

#: How many SNIs a host profile lists, from slice(0, 4).
HOST_SNIS = 4

#: The IKE statuses the stylesheet has a class for. A status outside this
#: set keeps its text and takes no class.
IKE_STATUS_CLASSES: dict[str, str] = {
    "Established": "established",
    "Failed": "failed",
    "No Response": "no-response",
    "Incomplete": "incomplete",
}

#: Attachment extensions the email panel marks. This is a detection list,
#: so it lives here where a test can exercise it rather than in a regex
#: literal inside a template's script block.
DANGEROUS_ATTACHMENTS = __import__("re").compile(
    r"\.(exe|scr|com|pif|js|jse|vbs|vbe|wsf|hta|jar|lnk|bat|cmd|ps1"
    r"|docm|xlsm|pptm|iso|img|cpl|msi|dll)$",
    __import__("re").IGNORECASE,
)


def _strings(value: Any, limit: Optional[int] = None) -> Optional[list[str]]:
    """A list of strings, or None when the payload is not a list."""
    if not isinstance(value, list):
        return None
    out = [t for t in (_text(v) if isinstance(v, str) else _text(str(v))
                       for v in value) if t]
    return out[:limit] if limit else out


class DataRow(TypedDict):
    ip: str
    sent: Optional[str]
    received: Optional[str]
    total: Optional[str]
    ratio: Optional[str]
    sent_pct: Optional[float]
    recv_pct: Optional[float]
    exfil: bool
    exfil_reason: Optional[str]


def exfil_shape(sent: Optional[float],
                received: Optional[float]) -> tuple[bool, Optional[str]]:
    """Whether a host's traffic is exfiltration-shaped, and why.

    `i.received > 0 && i.sent / i.received > 3` could not fire when
    `received` was zero or absent, which is the most lopsided case there
    is.
    """
    if sent is None or sent <= EXFIL_FLOOR:
        return False, None
    if received is None:
        return True, ("%s sent and no inbound figure recorded, so the "
                      "ratio cannot be computed" % (bytes_label(sent) or
                                                    "a large volume"))
    if received <= 0:
        return True, ("%s sent and nothing received"
                      % (bytes_label(sent) or "a large volume"))
    if sent / received > EXFIL_RATIO:
        return True, ("%.1f times more sent than received"
                      % (sent / received))
    return False, None


def data_rows(raw: Any) -> Optional[list[DataRow]]:
    if not isinstance(raw, list):
        return None
    entries = [e for e in raw[:DATA_ROWS] if isinstance(e, dict)]
    pairs = [(_num(e.get("sent")), _num(e.get("received")))
             for e in entries]
    totals = [s + r for s, r in pairs if s is not None and r is not None]
    top = max(totals) if totals else 0.0
    out: list[DataRow] = []
    for entry, (sent, received) in zip(entries, pairs):
        total = (None if sent is None or received is None else sent + received)
        exfil, reason = exfil_shape(sent, received)
        if received is None or received <= 0:
            ratio = None if sent is None else "\u221e"
        else:
            ratio = "%.1f:1" % ((sent or 0) / received)
        out.append({
            "ip": _text(entry.get("ip")) or "unrecorded host",
            "sent": bytes_label(sent),
            "received": bytes_label(received),
            "total": bytes_label(total),
            "ratio": ratio,
            "sent_pct": (None if sent is None or top <= 0
                         else round(sent / top * 100, 1)),
            "recv_pct": (None if received is None or top <= 0
                         else round(received / top * 100, 1)),
            "exfil": exfil,
            "exfil_reason": reason,
        })
    return out


class IkeRow(TypedDict):
    status: Optional[str]
    status_class: Optional[str]
    errors: Optional[list[str]]
    initiator: Optional[str]
    init_spi: Optional[str]
    responder: Optional[str]
    version: Optional[str]
    exchanges: Optional[list[str]]
    packets: Optional[str]
    retransmits: Optional[int]
    duration: Optional[str]


def ike_rows(raw: Any) -> Optional[list[IkeRow]]:
    if not isinstance(raw, list):
        return None
    out: list[IkeRow] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        status = _text(entry.get("status"))
        initiator_packets = _int(entry.get("initiator_packets"))
        responder_packets = _int(entry.get("responder_packets"))
        duration = _num(entry.get("duration"))
        out.append({
            "status": status,
            # None when the stylesheet has no class for it, so a payload
            # value never reaches the class attribute.
            "status_class": IKE_STATUS_CLASSES.get(status or ""),
            "errors": _strings(entry.get("errors")),
            "initiator": _text(entry.get("initiator")),
            "init_spi": _text(entry.get("init_spi")),
            "responder": _text(entry.get("responder")),
            "version": _text(entry.get("ike_version")),
            "exchanges": _strings(entry.get("exchanges")),
            "packets": (None if initiator_packets is None
                        or responder_packets is None else
                        "%di / %dr" % (initiator_packets, responder_packets)),
            "retransmits": _int(entry.get("retransmits")),
            "duration": (None if duration is None else "%gs" % duration),
        })
    return out


def ike_summary(rows: list[IkeRow]) -> list[dict]:
    """The status tally.

    The page counted four exact strings, so a session with any other
    status was counted nowhere and the tally silently fell short of the
    total.
    """
    out = []
    for label, css in IKE_STATUS_CLASSES.items():
        count = sum(1 for r in rows if r["status"] == label)
        if count:
            out.append({"label": label, "css_class": css, "count": count})
    other = sum(1 for r in rows if r["status"] not in IKE_STATUS_CLASSES)
    if other:
        out.append({"label": "not categorised", "css_class": None,
                    "count": other})
    return out


class CertRow(TypedDict):
    server: Optional[str]
    subject: Optional[str]
    issuer: Optional[str]
    self_signed: Optional[bool]
    validity: Optional[str]
    serial: Optional[str]


def cert_rows(raw: Any) -> Optional[list[CertRow]]:
    if not isinstance(raw, list):
        return None
    out: list[CertRow] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        days = _num(entry.get("validity_days"))
        signed = entry.get("self_signed")
        out.append({
            "server": _text(entry.get("server_ip")),
            "subject": _text(entry.get("subject")),
            "issuer": _text(entry.get("issuer")),
            # None keeps "not recorded" apart from a recorded false.
            "self_signed": (signed if isinstance(signed, bool) else None),
            "validity": (None if days is None
                         else "%dy" % round(days / 365)),
            "serial": _text(entry.get("serial")),
        })
    return out


class HostRow(TypedDict):
    ip: Optional[str]
    os: Optional[str]
    os_evidence: Optional[str]
    role: Optional[list[str]]
    sent: Optional[str]
    received: Optional[str]
    snis: Optional[list[str]]
    beacons: Optional[int]
    findings: Optional[int]


def host_rows(raw: Any) -> Optional[list[HostRow]]:
    if not isinstance(raw, list):
        return None
    out: list[HostRow] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        out.append({
            "ip": _text(entry.get("ip")),
            "os": _text(entry.get("os")),
            "os_evidence": _text(entry.get("os_evidence")),
            "role": _strings(entry.get("role")),
            # `fmtBytes(h.sent || 0)` reported a host with no recorded
            # volume as having sent nothing.
            "sent": bytes_label(entry.get("sent")),
            "received": bytes_label(entry.get("received")),
            "snis": _strings(entry.get("snis"), HOST_SNIS),
            "beacons": _int(entry.get("beacons")),
            "findings": _int(entry.get("findings")),
        })
    return out


class StreamRow(TypedDict):
    source: Optional[str]
    destination: Optional[str]
    size: Optional[str]
    truncated: bool
    preview: Optional[str]


def _endpoint(host: Any, port: Any) -> Optional[str]:
    name = _text(host)
    number = _int(port)
    if name is None:
        return None
    return name if number is None else "%s:%d" % (name, number)


def stream_rows(raw: Any) -> Optional[list[StreamRow]]:
    if not isinstance(raw, list):
        return None
    out: list[StreamRow] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        out.append({
            "source": _endpoint(entry.get("src"), entry.get("sport")),
            "destination": _endpoint(entry.get("dst"), entry.get("dport")),
            "size": bytes_label(entry.get("size")),
            "truncated": entry.get("truncated") is True,
            "preview": (entry.get("preview")
                        if isinstance(entry.get("preview"), str) else None),
        })
    return out


class Attachment(TypedDict):
    name: str
    dangerous: bool


class EmailRow(TypedDict):
    protocol: Optional[str]
    mail_from: Optional[str]
    rcpt_to: Optional[list[str]]
    subject: Optional[str]
    attachments: Optional[list[Attachment]]


def email_rows(raw: Any) -> Optional[list[EmailRow]]:
    if not isinstance(raw, list):
        return None
    out: list[EmailRow] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        names = _strings(entry.get("attachments"))
        out.append({
            "protocol": _text(entry.get("protocol")),
            "mail_from": _text(entry.get("mail_from")),
            "rcpt_to": _strings(entry.get("rcpt_to")),
            "subject": _text(entry.get("subject")),
            # None when the list was not readable. `m.attachments || []`
            # drew that as no attachments, on the one column that marks a
            # dangerous extension.
            "attachments": (None if names is None else
                            [{"name": n,
                              "dangerous": bool(
                                  DANGEROUS_ATTACHMENTS.search(n))}
                             for n in names]),
        })
    return out


class DetailView(TypedDict):
    state: str
    error: Optional[str]
    data_total: Optional[str]
    data: Optional[list[DataRow]]
    ike: Optional[list[IkeRow]]
    ike_summary: list[dict]
    certs: Optional[list[CertRow]]
    hosts: Optional[list[HostRow]]
    streams: Optional[list[StreamRow]]
    emails: Optional[list[EmailRow]]
    ja4: Optional[list[dict]]


def ja4_rows(raw: Any) -> Optional[list[dict]]:
    """JA4 and JA4S share one panel in the page, each with its own set of
    columns, so the registry could not describe it."""
    if not isinstance(raw, list):
        return None
    out = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        malware = _text(entry.get("known_malware"))
        out.append({
            "ja4": _text(entry.get("ja4")),
            "sni": _text(entry.get("sni")),
            "src_ip": _text(entry.get("src_ip")),
            "dst": _endpoint(entry.get("dst_ip"), entry.get("dst_port")),
            "ja4s": _text(entry.get("ja4s")),
            "server": _text(entry.get("server_ip")),
            "client": _text(entry.get("client_ip")),
            "port": _int(entry.get("port")),
            "malware": malware,
        })
    return out


def detail_view(job: Any) -> DetailView:
    empty: DetailView = {
        "state": "failed", "error": (_text(job.get("error"))
                                     if isinstance(job, dict) else None),
        "data_total": None, "data": None, "ike": None, "ike_summary": [],
        "certs": None, "hosts": None, "streams": None, "emails": None,
        "ja4": None,
    }
    if not isinstance(job, dict) or not isinstance(job.get("result"), dict):
        return empty
    result = job["result"]
    transfer = result.get("data_transfer")
    transfer = transfer if isinstance(transfer, dict) else {}
    ike = ike_rows(result.get("isakmp_sessions"))
    return {
        "state": "data",
        "error": None,
        # `fmtBytes(dt.total_bytes || 0)` printed "Total: 0 B" for a
        # capture whose total was not recorded.
        "data_total": bytes_label(transfer.get("total_bytes")),
        "data": data_rows(transfer.get("by_ip")),
        "ike": ike,
        "ike_summary": ike_summary(ike or []),
        "certs": cert_rows(result.get("tls_certificates")),
        "hosts": host_rows(result.get("host_profiles")),
        "streams": stream_rows(result.get("tcp_streams")),
        "emails": email_rows(result.get("email_messages")),
        "ja4": ja4_rows(result.get("ja4_fingerprints")),
    }


@router.get(
    "/pcap/{job_id}/detail",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_detail_fragment(
    request: Request,
    job_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The seven panels with logic of their own."""
    job, refusal = _job(job_id, current_user, session)
    view = detail_view(job)
    if refusal is not None:
        view["error"] = refusal
    return render_view(request, DETAIL_FRAGMENT, view)


# ---------------------------------------------------------------------------
# Findings, threat intel, the history list and the case picker
# ---------------------------------------------------------------------------
#
# AN UNREADABLE FINDINGS PAYLOAD SHOWED A SHIELD AND "NO SUSPICIOUS FINDINGS"
#
#     const items = (d.findings || []).map(...)
#     if (!items.length) {
#         panel.innerHTML = '... <i class="icon-shield-check"></i>
#                            <p>No suspicious findings detected</p>';
#
# On a tool whose job is to say whether a capture is clean, a findings
# list that could not be read rendered the clean verdict, with a tick.
# That is the worst available way to be wrong and it is one `|| []`.
#
# The severity chips could also sum to less than the total: `counts` is
# seeded for four severities, a finding outside them increments nothing,
# and the total chip reads `items.length`. The card's class came from the
# same value, so such a finding rendered with no severity colour either.
#
# THE THREAT INTEL LABEL CHIPS HAD INVALID BACKGROUNDS
#
#     const color = threatColors[level] || <a grey hex literal>;
#     ... 'background:' + color + '20;color:' + color
#
# The 20 is an alpha suffix for an eight-digit hex, and every colour in
# threatColors is a var(--sev-*) reference, so the expression produced
# background:var(--sev-low)20. That is not a colour and the declaration
# is discarded. It worked only for the level the map misses and the hex
# fallback catches, which is the one case nobody styled on purpose.
#
# The hex itself is not quoted above on purpose:
# test_a_converted_module_puts_no_presentation_in_its_models matches a
# quoted hex anywhere in the module, comments included, and it is right
# to. A colour literal in here is a colour a reader inherits.
#
# A missing threat-intel payload and a failed enrichment shared one
# message that blamed configuration, and the case picker reported "No open
# cases" when its read failed, so an analyst with findings to attach was
# told there was nothing to attach them to.

FINDINGS_FRAGMENT = "_fragments/pcap_findings.html"
HISTORY_FRAGMENT = "_fragments/pcap_history.html"
CASE_OPTIONS_FRAGMENT = "_fragments/pcap_case_options.html"

#: Finding severities in triage order, with the class each takes. A
#: severity outside this set keeps its text and takes no class.
FINDING_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Threat levels the panel has a class for, in place of the colour map it
#: composed inline.
THREAT_LEVELS: tuple[str, ...] = (
    "unknown", "benign", "low", "medium", "high", "critical",
)

#: The label chip and the observable link. These were
#: _ion-s-7554583028 and _ion-s-b17605f04d, hashed names from the
#: v0.31.21 inline-style migration, and after this conversion no template
#: referenced either: only a constant in this module did, and no other
#: page used them. A hashed name reached that way is one the rewrite
#: audit cannot see and a reader cannot place, so both have real names in
#: pcap-page.css carrying the same declarations, and the map claims them.
TI_CHIP_CLASS = "pcap-ti-chip"
TI_LINK_CLASS = "pcap-ti-link"


class FindingCard(TypedDict):
    index: int
    severity: Optional[str]
    severity_class: Optional[str]
    category: Optional[str]
    title: Optional[str]
    detail: Optional[str]
    mitre: Optional[list[str]]


def finding_cards(raw: Any) -> Optional[list[FindingCard]]:
    """The cards, sorted by severity, each keeping its index in the
    stored result.

    The page's own comment is right and worth keeping: the cards sort by
    severity, so display order is not stored order, and attaching by
    display position would pin the wrong finding.
    """
    if not isinstance(raw, list):
        return None
    cards: list[FindingCard] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        severity = _text(entry.get("severity"))
        cards.append({
            "index": index,
            "severity": severity,
            "severity_class": (severity
                               if severity in FINDING_SEVERITIES else None),
            "category": _text(entry.get("category")),
            "title": _text(entry.get("title")),
            "detail": _text(entry.get("detail")),
            "mitre": _strings(entry.get("mitre")),
        })

    def rank(card: FindingCard) -> int:
        severity = card["severity_class"]
        return (FINDING_SEVERITIES.index(severity)
                if severity is not None else len(FINDING_SEVERITIES))

    cards.sort(key=rank)
    return cards


def finding_chips(cards: list[FindingCard]) -> list[dict]:
    """The triage chips.

    The four counts and the total disagreed whenever a finding carried a
    severity outside the four, because nothing incremented for it. The
    uncategorised chip is the difference, stated.
    """
    chips = [{"key": "total", "label": "Total", "count": len(cards),
              "zero": False}]
    for severity in FINDING_SEVERITIES:
        count = sum(1 for c in cards if c["severity_class"] == severity)
        chips.append({"key": severity, "label": severity.title(),
                      "count": count, "zero": count == 0})
    other = sum(1 for c in cards if c["severity_class"] is None)
    if other:
        chips.append({"key": "uncategorised", "label": "not categorised",
                      "count": other, "zero": False})
    return chips


class Technique(TypedDict):
    id: Optional[str]
    name: Optional[str]


def techniques(raw: Any) -> Optional[list[Technique]]:
    if not isinstance(raw, list):
        return None
    out: list[Technique] = []
    for entry in raw:
        if isinstance(entry, dict):
            out.append({"id": _text(entry.get("id")),
                        "name": _text(entry.get("name"))})
        elif isinstance(entry, str):
            out.append({"id": _text(entry), "name": None})
    return out


class Observable(TypedDict):
    kind: Optional[str]
    value: Optional[str]
    level: Optional[str]
    level_class: Optional[str]
    score: Optional[str]
    labels: Optional[list[str]]
    actors: Optional[list[str]]
    malicious: bool


def _named(value: Any) -> Optional[str]:
    """A label or actor, which the payload sends as a string or as an
    object carrying `value` or `name`."""
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, dict):
        return _text(value.get("value")) or _text(value.get("name"))
    return None


def observables(raw: Any) -> Optional[list[Observable]]:
    if not isinstance(raw, list):
        return None
    out: list[Observable] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        enrichment = entry.get("enrichment")
        enrichment = enrichment if isinstance(enrichment, dict) else {}
        level = _text(entry.get("threat_level")) or "unknown"
        score = _num(enrichment.get("score"))
        labels = enrichment.get("labels")
        actors = enrichment.get("threat_actors")
        out.append({
            "kind": _text(entry.get("kind")) or _text(entry.get("type")),
            "value": _text(entry.get("value")),
            "level": level,
            # The level picks a class. The page composed a colour and then
            # appended "20" to it for alpha, which only works on a hex.
            "level_class": level if level in THREAT_LEVELS else None,
            "score": (None if score is None else "%g" % score),
            "labels": (None if not isinstance(labels, list) else
                       [t for t in (_named(v) for v in labels) if t]),
            "actors": (None if not isinstance(actors, list) else
                       [t for t in (_named(v) for v in actors) if t]),
            "malicious": enrichment.get("is_malicious") is True,
        })
    return out


class ThreatIntel(TypedDict):
    state: str
    error: Optional[str]
    ips_checked: Optional[int]
    domains_checked: Optional[int]
    total: Optional[int]
    malicious_count: Optional[int]
    observables: Optional[list[Observable]]
    chip_class: str
    link_class: str


def threat_intel_view(raw: Any) -> ThreatIntel:
    base: ThreatIntel = {
        "state": "absent", "error": None, "ips_checked": None,
        "domains_checked": None, "total": None, "malicious_count": None,
        "observables": None, "chip_class": TI_CHIP_CLASS,
        "link_class": TI_LINK_CLASS,
    }
    if raw is None:
        return base
    if not isinstance(raw, dict):
        return {**base, "state": "unreadable"}
    error = _text(raw.get("error"))
    if error:
        return {**base, "state": "failed", "error": error}
    return {**base,
            "state": "data",
            "ips_checked": _int(raw.get("ips_checked")),
            "domains_checked": _int(raw.get("domains_checked")),
            "total": _int(raw.get("total")),
            "malicious_count": _int(raw.get("malicious_count")),
            "observables": observables(raw.get("observables"))}


class FindingsView(TypedDict):
    state: str
    error: Optional[str]
    cards: Optional[list[FindingCard]]
    chips: list[dict]
    techniques: Optional[list[Technique]]
    threat_intel: ThreatIntel


def findings_view(job: Any) -> FindingsView:
    empty: FindingsView = {
        "state": "failed",
        "error": (_text(job.get("error")) if isinstance(job, dict)
                  else None),
        "cards": None, "chips": [], "techniques": None,
        "threat_intel": threat_intel_view(None),
    }
    if not isinstance(job, dict) or not isinstance(job.get("result"), dict):
        return empty
    result = job["result"]
    cards = finding_cards(result.get("findings"))
    return {
        "state": "data",
        "error": None,
        "cards": cards,
        "chips": finding_chips(cards or []),
        "techniques": techniques(result.get("mitre_techniques")),
        "threat_intel": threat_intel_view(result.get("threat_intel")),
    }


class HistoryRow(TypedDict):
    job_id: Optional[int]
    status: Optional[str]
    status_class: str
    filename: Optional[str]
    digest: Optional[str]
    size: Optional[str]
    verdict: Optional[str]
    finding_count: Optional[int]
    reused_from: Optional[int]
    parser_version: Optional[str]
    requested_by: str
    reopenable: bool


#: The badge class per job status, from the page's ternary chain.
HISTORY_TONES: dict[str, str] = {
    "completed": "badge-success",
    "failed": "badge-error",
    "cancelled": "badge-ghost",
}


def history_rows(raw: Any) -> Optional[list[HistoryRow]]:
    if not isinstance(raw, list):
        return None
    out: list[HistoryRow] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        status = _text(entry.get("status"))
        verdict = entry.get("verdict")
        if isinstance(verdict, dict):
            label = _text(verdict.get("label"))
        else:
            label = _text(verdict) if isinstance(verdict, str) else None
        digest = _text(entry.get("content_sha256"))
        out.append({
            "job_id": _int(entry.get("id")),
            "status": status,
            "status_class": HISTORY_TONES.get(status or "", "badge-warning"),
            "filename": _text(entry.get("filename")),
            "digest": (digest[:12] if digest else None),
            # `fmtBytes(j.file_size || 0)` reported a row with no recorded
            # size as 0 B.
            "size": bytes_label(entry.get("file_size")),
            "verdict": label,
            # `(j.finding_count || 0) + ' findings'` said a capture whose
            # count was never recorded had none.
            "finding_count": _int(entry.get("finding_count")),
            "reused_from": _int(entry.get("reused_from_id")),
            "parser_version": _text(entry.get("parser_version")),
            "requested_by": _text(entry.get("requested_by")) or "unknown",
            "reopenable": status == "completed",
        })
    return out


class HistoryView(TypedDict):
    state: str
    error: Optional[str]
    rows: Optional[list[HistoryRow]]


def history_view(payload: Any) -> HistoryView:
    if not isinstance(payload, dict):
        return {"state": "failed", "error": None, "rows": None}
    rows = history_rows(payload.get("jobs"))
    if rows is None:
        return {"state": "unreadable", "error": None, "rows": None}
    return {"state": "data" if rows else "empty", "error": None,
            "rows": rows}


class CaseOption(TypedDict):
    value: str
    label: str


class CaseOptionsView(TypedDict):
    state: str
    error: Optional[str]
    options: Optional[list[CaseOption]]


def case_options_view(payload: Any) -> CaseOptionsView:
    """The attach-to-case picker.

    `_pcapCases = r.ok ? ... : []`, with the same `[]` in its catch, so a
    failed read told an analyst with findings to attach that there was
    nothing to attach them to.
    """
    if not isinstance(payload, dict):
        return {"state": "failed", "error": None, "options": None}
    raw = payload.get("cases")
    if not isinstance(raw, list):
        return {"state": "unreadable", "error": None, "options": None}
    options: list[CaseOption] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("id")
        if identifier is None:
            continue
        number = _text(entry.get("case_number"))
        title = _text(entry.get("title")) or ("Case %s" % identifier)
        options.append({
            "value": str(identifier),
            "label": ("%s - %s" % (number, title)) if number else title,
        })
    return {"state": "data" if options else "empty", "error": None,
            "options": options}


@router.get(
    "/pcap/{job_id}/findings",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_findings_fragment(
    request: Request,
    job_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The findings cards, the triage chips and the threat intel table."""
    job, refusal = _job(job_id, current_user, session)
    view = findings_view(job)
    if refusal is not None:
        view["error"] = refusal
    return render_view(request, FINDINGS_FRAGMENT, view)


@router.get(
    "/pcap/history",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_history_fragment(
    request: Request,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The analysis history."""
    from ion.web import pcap_api

    try:
        payload = pcap_api.list_pcap_jobs(
            limit=limit, _user=current_user, session=session)
    except Exception:
        logger.exception("Pcap history fragment could not read")
        payload = None
    return render_view(request, HISTORY_FRAGMENT, history_view(payload))


@router.get(
    "/pcap/case-options",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def pcap_case_options_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """Open cases, for attaching selected findings to one."""
    from ion.web import case_lifecycle_api

    try:
        payload = await case_lifecycle_api.list_cases(
            status="OPEN", limit=500, sort="case_number", order="desc",
            current_user=current_user, session=session)
    except Exception:
        logger.exception("Pcap case picker could not read the case list")
        payload = None
    return render_view(request, CASE_OPTIONS_FRAGMENT,
                       case_options_view(payload))


# ---------------------------------------------------------------------------
# The network graph's chrome
# ---------------------------------------------------------------------------
#
# Only the chrome. vis-network draws into a canvas, so there is no markup
# in the graph itself for a stylesheet to reach and nothing to gain from
# moving the drawing call.
#
# The counts beside the heading were `stats.total_nodes||0` and four more
# like it, so a graph whose stats were not recorded reported zero hosts
# and zero connections directly above a drawing of them.

GRAPH_FRAGMENT = "_fragments/pcap_graph.html"


class GraphView(TypedDict):
    state: str
    error: Optional[str]
    total_nodes: Optional[int]
    total_edges: Optional[int]
    internal_nodes: Optional[int]
    external_nodes: Optional[int]
    suspicious_nodes: Optional[int]


def graph_view(job: Any) -> GraphView:
    empty: GraphView = {
        "state": "failed",
        "error": (_text(job.get("error")) if isinstance(job, dict)
                  else None),
        "total_nodes": None, "total_edges": None, "internal_nodes": None,
        "external_nodes": None, "suspicious_nodes": None,
    }
    if not isinstance(job, dict) or not isinstance(job.get("result"), dict):
        return empty
    graph = job["result"].get("network_graph")
    graph = graph if isinstance(graph, dict) else {}
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        return {**empty, "state": "unreadable", "error": None}
    if not nodes:
        return {**empty, "state": "empty", "error": None}
    stats = graph.get("stats")
    stats = stats if isinstance(stats, dict) else {}
    return {
        "state": "data",
        "error": None,
        "total_nodes": _int(stats.get("total_nodes")),
        "total_edges": _int(stats.get("total_edges")),
        "internal_nodes": _int(stats.get("internal_nodes")),
        "external_nodes": _int(stats.get("external_nodes")),
        "suspicious_nodes": _int(stats.get("suspicious_nodes")),
    }


@router.get(
    "/pcap/{job_id}/graph",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def pcap_graph_fragment(
    request: Request,
    job_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The graph panel's heading, host counts and canvas container."""
    job, refusal = _job(job_id, current_user, session)
    view = graph_view(job)
    if refusal is not None:
        view["error"] = refusal
    return render_view(request, GRAPH_FRAGMENT, view)
