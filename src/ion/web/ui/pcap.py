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
