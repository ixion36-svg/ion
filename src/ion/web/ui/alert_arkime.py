"""The Arkime PCAP workspace: session, verdict, findings and the attach form.

Replaces the innerHTML writes in alert_arkime.html. The page used to POST
/api/alerts/{id}/arkime/preview, then build the findings list, the
destination table, the protocol bars, the observable cards and the attach
result out of strings. Those are one fragment now, and Jinja escapes them.
escHtml() is gone with the markup it served.

The preview and the commit are the two functions the JSON routes already
are. Nothing about how a capture is fetched, parsed or attached is
reimplemented here: a second copy would keep analysing after the endpoint
stopped, or attach differently from the button the analyst already trusts.

Gates, read off the live routes rather than assumed from the page living
near the detection-engineering templates:

  * POST /api/alerts/{alert_id}/arkime/preview is require_permission("alert:read").
  * POST /api/alerts/{alert_id}/arkime/commit is the same permission.
  * arkime_router is mounted at /api with no module dependency.
    require_de_module belongs to de_router, and this page is not on it.
    Putting that gate here would answer 404 on a deployment that is not
    licensed for detection engineering, while the page and the JSON both
    still answer, so the fragment would be the one path that hides a
    workspace the licence does not gate.

Not require_page_permission: that redirects to /login, and htmx would swap
a login form into the middle of the workspace.

Three outcomes, three renders, because they lead to different actions:

  read failed   200, a fragment that says the read failed. Never 0 findings,
                because "the capture is clean" and "we could not look" are
                opposite findings on a PCAP the analyst is about to attach
                to a case.
  no findings   200, the empty state the JavaScript had, and the counts are
                0 because they were measured.
  preview ok    200, the workspace. The attach form is in this render only,
                because only a preview that ran has a payload to echo back.
                The Refresh button stays in the page shell, so a failed
                render cannot take away the control that retries.
"""
from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/alert_arkime.html"

#: The permission both JSON routes name. Spelled once so the fragment cannot
#: drift into being a softer way in than the endpoint it mirrors.
PERMISSION = "alert:read"

KIND_PREVIEW = "preview"
KIND_FAILED = "failed"
KIND_COMMIT_OK = "commit_ok"
KIND_COMMIT_BAD = "commit_bad"

#: What the JavaScript showed, and no further. The rest is still in the
#: payload the attach form echoes, so truncating the card does not truncate
#: what gets written to the case.
FINDINGS_LIMIT = 25
DEST_LIMIT = 8
PROTO_LIMIT = 8
LABEL_LIMIT = 3
ACTOR_LIMIT = 2

_SEV_CSS = {
    "critical": "badge-error",
    "high": "badge-warning",
    "medium": "badge-accent",
    "low": "badge-ghost",
    "info": "badge-info",
}

_KB = 1024
_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024


def _html(request: Request, context: dict[str, Any]) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context
    )


def _failed(request: Request, alert_id: str, message: str) -> HTMLResponse:
    return _html(request, {
        "kind": KIND_FAILED,
        "alert_id": alert_id,
        "message": message,
    })


def _commit_bad(request: Request, message: str) -> HTMLResponse:
    return _html(request, {
        "kind": KIND_COMMIT_BAD,
        "message": message,
    })


def _number(value: object) -> Optional[float]:
    """A measured number, or None when the field was not a number.

    Bool is a subclass of int, so True would otherwise format as 1. A
    missing count and a count of zero are different claims, and this is the
    function that keeps them apart: zero comes back as zero.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return None
        return value
    return None


def _fmt_bytes(value: object) -> Optional[str]:
    """The JavaScript's fmtBytes, without its `if (!n) return '0 B'`.

    That branch printed 0 B for a size nobody sent. Zero is a real empty
    capture and comes back as "0 B"; None comes back as None so the template
    can say the size is unknown.
    """
    n = _number(value)
    if n is None or n < 0:
        return None
    if n < _KB:
        shown = str(int(n)) if float(n).is_integer() else str(n)
        return f"{shown} B"
    if n < _MB:
        return f"{n / _KB:.1f} KB"
    if n < _GB:
        return f"{n / _MB:.1f} MB"
    return f"{n / _GB:.2f} GB"


def _text(value: object) -> Optional[str]:
    """A display string, or None when there is nothing to show.

    plain() first, so a SQLEnum member renders as its value. str() of the
    member on 3.12 is the enum repr, which is what a pill would otherwise
    say. An empty string is absence, not the word "None".
    """
    if value is None:
        return None
    value = plain(value)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _packet_time(raw: object) -> object:
    """firstPacket / lastPacket as a datetime the ts macro can place.

    The numeric split is ArkimeService._packet_epoch: milliseconds on
    current builds, seconds on older ones. Reimplementing the threshold
    would show one of those clocks an hour off by a factor of a thousand.

    Zero is Arkime's empty sentinel, not a capture at the epoch. Returning
    it as a datetime would render 1970, which is the failure the macro's
    fallback exists to prevent. A string that is not a number is handed
    through: the macro parses an ISO timestamp and echoes anything else,
    and an unreadable timestamp is still evidence.
    """
    if raw is None or raw is False or raw == "":
        return None
    from ion.services.arkime_service import ArkimeService

    seconds = ArkimeService._packet_epoch(raw)
    if seconds is None:
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        return None
    if seconds == 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, timezone.utc)
    except (OverflowError, OSError, ValueError):
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        return None


def _as_list(value: object) -> list:
    """The JavaScript's `v == null ? [] : Array.isArray(v) ? v : [v]`.

    A string is one value, not a list of characters. None is nothing.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _pick(meta: dict, flat: str, parent: str, child: str) -> object:
    """Flat Arkime key, else the nested one. Only None falls through.

    `??` does not treat 0 or "" as missing, and neither does this. An
    explicit empty is what the capture stored.
    """
    if flat in meta and meta[flat] is not None:
        return meta[flat]
    nested = meta.get(parent)
    if isinstance(nested, dict) and nested.get(child) is not None:
        return nested.get(child)
    return None


def _indexed(meta: dict) -> list[str]:
    """JA4 / JA3 / user-agent / URI, in the order the JavaScript emitted."""
    parts: list[str] = []

    def take(value: object, limit: int, width: Optional[int]) -> list[str]:
        out: list[str] = []
        for item in _as_list(value):
            if item is None:
                continue
            text = str(item).strip()
            if not text:
                continue
            if width is not None:
                text = text[:width]
            out.append(text)
            if len(out) >= limit:
                break
        return out

    ja4 = take(_pick(meta, "tls.ja4", "tls", "ja4"), 3, None)
    ja3 = take(_pick(meta, "tls.ja3", "tls", "ja3"), 3, None)
    ua = take(_pick(meta, "http.useragent", "http", "useragent"), 1, 90)
    uri = take(_pick(meta, "http.uri", "http", "uri"), 2, 100)
    if ja4:
        parts.append("JA4 " + ", ".join(ja4))
    if ja3:
        parts.append("JA3 " + ", ".join(ja3))
    if ua:
        parts.append("UA " + ua[0])
    if uri:
        parts.append("URI " + " ".join(uri))
    return parts


def _proto(meta: dict) -> Optional[str]:
    """ipProtocol, else protocol. Zero is a protocol number, not absence.

    The JavaScript's `meta.ipProtocol || meta.protocol` dropped a measured
    0 (HOPOPT, and any other zero the capture stored) and read the next
    field instead.
    """
    for key in ("ipProtocol", "protocol"):
        if key not in meta or meta[key] is None:
            continue
        value = meta[key]
        if isinstance(value, list):
            shown = [str(plain(item)) for item in value if item is not None and str(item) != ""]
            if shown:
                return ", ".join(shown)
            continue
        text = _text(value)
        if text is not None:
            return text
    return None


def _endpoint(ip: object, port: object) -> Optional[str]:
    if ip is None or ip == "":
        return None
    if port is None or port == "" or isinstance(port, bool):
        return f"{ip}:?"
    return f"{ip}:{port}"


def _finding(raw: object) -> Optional[dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    severity = _text(raw.get("severity"))
    severity = severity.lower() if severity else None
    title = _text(raw.get("title")) or _text(raw.get("type")) or "(no title)"
    # The analyser emits `detail`. The JavaScript read `description`, which
    # the payload does not have, so every finding rendered with no body.
    # Either key is shown; detail wins only when description was not sent.
    description = _text(raw.get("description"))
    if description is None:
        description = _text(raw.get("detail"))
    return {
        "severity": severity,
        "severity_css": _SEV_CSS.get(severity or "", "badge-ghost"),
        "title": title,
        "description": description,
    }


def _destination(raw: object) -> Optional[dict[str, Any]]:
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        return {"ip": text, "bytes_label": None, "count": None}
    if not isinstance(raw, dict):
        return None
    ip = raw.get("ip")
    ip_text = None if ip is None else str(ip).strip()
    if not ip_text:
        return None
    # Key absent and value null are both "not measured". Zero is measured,
    # so the lookup is `in`, not truthiness, and _fmt_bytes keeps the zero.
    bytes_label = _fmt_bytes(raw["bytes"]) if "bytes" in raw else None
    count = _number(raw["count"]) if "count" in raw else None
    return {"ip": ip_text, "bytes_label": bytes_label, "count": count}


def _protocols(raw: object) -> Optional[list[dict[str, Any]]]:
    """Top protocols by count, percentages only when the total is positive.

    The percentage is a share of the rows actually shown, which is what the
    JavaScript computed (it summed the sliced entries, not the whole map).
    A total of zero has no share: printing 0% would say each protocol was
    measured as none of the traffic, and dividing by 1 to avoid the zero
    is how that lie gets produced.
    """
    if not isinstance(raw, dict):
        return None
    measured: list[dict[str, Any]] = []
    unmeasured: list[dict[str, Any]] = []
    for name, count in raw.items():
        number = _number(count)
        row: dict[str, Any] = {"name": str(plain(name)), "count": number, "pct": None}
        (measured if number is not None else unmeasured).append(row)
    measured.sort(key=lambda r: r["count"], reverse=True)
    shown = (measured + unmeasured)[:PROTO_LIMIT]
    total = sum(
        r["count"] for r in shown if r["count"] is not None and r["count"] > 0
    )
    if total > 0:
        for row in shown:
            count = row["count"]
            if count is not None and count >= 0:
                row["pct"] = int(math.floor(count / total * 100 + 0.5))
    return shown


def _labels(raw: object, limit: int) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        text = _text(item)
        if text:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _observables(raw: object) -> Optional[list[dict[str, Any]]]:
    if not isinstance(raw, list):
        return None
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rows.append({
            "type": _text(item.get("type")) or "—",
            "value": _text(item.get("value")) or "—",
            "source": _text(item.get("source")),
            # Left raw on purpose. The template tests `is true`, so a
            # truthy string and a missing value do not become a hit.
            "found": item.get("found"),
            "labels": _labels(item.get("labels"), LABEL_LIMIT),
            "actors": _labels(item.get("threat_actors"), ACTOR_LIMIT),
            "error": _text(item.get("error")),
        })
    return rows


def _hits(observables: Optional[list[dict[str, Any]]]) -> Optional[int]:
    if observables is None:
        return None
    return sum(1 for row in observables if row.get("found") is True)


def _payload_dict(payload: object) -> dict[str, Any]:
    """What arkime_preview returns, as a dict.

    The route returns an ArkimePreviewResponse. model_dump is how FastAPI
    would have serialised it for the JavaScript; calling it here is what
    keeps a str-enum, were one ever added, on the same path. A dict is
    accepted so a test can hand the interesting row over directly.
    """
    if isinstance(payload, dict):
        return payload
    dump = getattr(payload, "model_dump", None)
    if callable(dump):
        return dump()
    as_dict = getattr(payload, "dict", None)
    if callable(as_dict):
        return as_dict()
    raise TypeError(f"preview payload is {type(payload).__name__}, not a mapping")


def _rows(
    analysis_ok: bool, analysis: dict, key: str, parse: Any,
) -> tuple[Optional[list], Optional[int]]:
    """A list section of the analysis, and how many entries it had.

    Missing key on an analysis that ran is an empty section: the parser
    always emits the key, and an empty list is what "none of these" means.
    A value that is not a list, or a list whose entries are all unreadable,
    is None. That is "we could not read it", and the count stays None so
    the template cannot print 0 for it.
    """
    if not analysis_ok:
        return None, None
    if key not in analysis:
        return [], 0
    raw = analysis[key]
    if not isinstance(raw, list):
        return None, None
    rows = [row for row in (parse(item) for item in raw) if row is not None]
    if raw and not rows:
        return None, None
    return rows, len(raw)


def _view(payload: object, alert_id: str) -> dict[str, Any]:
    """The fields the workspace renders, derived from the preview payload."""
    data = _payload_dict(payload)
    meta = data.get("session_metadata")
    if not isinstance(meta, dict):
        meta = {}
    analysis = data.get("analysis")
    analysis_ok = isinstance(analysis, dict)
    analysis_dict: dict[str, Any] = analysis if analysis_ok else {}

    findings, findings_total = _rows(analysis_ok, analysis_dict, "findings", _finding)
    destinations, dest_total = _rows(
        analysis_ok, analysis_dict, "top_dst_ips", _destination
    )

    if not analysis_ok:
        protocols: Optional[list[dict[str, Any]]] = None
        protocols_total: Optional[int] = None
    elif "protocols" not in analysis_dict:
        protocols = []
        protocols_total = 0
    else:
        protocols = _protocols(analysis_dict.get("protocols"))
        proto_raw = analysis_dict.get("protocols")
        protocols_total = len(proto_raw) if isinstance(proto_raw, dict) else None

    if "observables" not in data or not isinstance(data.get("observables"), list):
        observables: Optional[list[dict[str, Any]]] = None
    else:
        observables = _observables(data["observables"])

    verdict_raw = analysis_dict.get("verdict") if analysis_ok else None
    verdict = verdict_raw if isinstance(verdict_raw, dict) else {}
    label = _text(verdict.get("label")) if analysis_ok and isinstance(verdict_raw, dict) else None
    score = (
        _number(verdict["score"])
        if isinstance(verdict_raw, dict) and "score" in verdict_raw
        else None
    )

    src = _endpoint(meta.get("srcIp"), meta.get("srcPort"))
    dst = _endpoint(meta.get("dstIp"), meta.get("dstPort"))
    if src is None and dst is None:
        flow = None
    else:
        flow = f"{src or '—'} → {dst or '—'}"

    enrichment = data.get("enrichment_enabled")
    if not isinstance(enrichment, bool):
        enrichment = None

    warnings_raw = data.get("warnings")
    warnings = [text for text in (_text(item) for item in warnings_raw) if text] if isinstance(warnings_raw, list) else []

    shown_findings = findings[:FINDINGS_LIMIT] if findings is not None else None
    shown_dest = destinations[:DEST_LIMIT] if destinations is not None else None

    # The form echoes the payload the commit endpoint already accepts, which
    # is the whole analysis, not the sliced card. default=str so a value the
    # analyser left as a non-JSON object cannot take the render down. The
    # form is withheld when either side is unreadable: echoing [] for an
    # observable list we never received would attach "nothing extracted".
    obs_raw = data.get("observables")
    analysis_json = (
        json.dumps(analysis_dict, default=str) if analysis_ok else None
    )
    observables_json = (
        json.dumps(obs_raw, default=str) if isinstance(obs_raw, list) else None
    )

    # A negative, a bool or a NaN is not a size. _fmt_bytes refuses those,
    # and the value echoed into the attach form has to refuse them too:
    # showing "unknown" while submitting -1 would attach a capture size the
    # card said it could not read. Zero still passes, because _fmt_bytes
    # renders it as "0 B".
    if "pcap_size_bytes" in data:
        pcap_size = _fmt_bytes(data.get("pcap_size_bytes"))
        pcap_size_raw = (
            _number(data.get("pcap_size_bytes")) if pcap_size is not None else None
        )
    else:
        pcap_size = None
        pcap_size_raw = None

    return {
        "kind": KIND_PREVIEW,
        "alert_id": alert_id,
        "node": _text(data.get("arkime_node")),
        "session_id": _text(data.get("arkime_session_id")),
        "community_id": _text(data.get("network_community_id")),
        "flow": flow,
        "proto": _proto(meta),
        "first_packet": _packet_time(meta.get("firstPacket")),
        "last_packet": _packet_time(meta.get("lastPacket")),
        "packets": _number(meta.get("packets")) if "packets" in meta else None,
        "pcap_size": pcap_size,
        "pcap_size_raw": pcap_size_raw,
        "raw_bytes": _number(meta.get("bytes")) if "bytes" in meta else None,
        "arkime_web_url": data.get("arkime_web_url") or "",
        "indexed": _indexed(meta),
        "verdict_label": label,
        "verdict_score": score,
        "findings": shown_findings,
        "findings_count": findings_total,
        "findings_total": findings_total,
        "destinations": shown_dest,
        "destinations_total": dest_total,
        "protocols": protocols,
        "protocols_total": protocols_total,
        "observables": observables,
        "observables_count": None if observables is None else len(observables),
        "hits": _hits(observables),
        "enrichment_enabled": enrichment,
        "warnings": warnings,
        "analysis_ok": analysis_ok,
        "analysis_json": analysis_json if analysis_ok else None,
        "observables_json": observables_json if analysis_ok else None,
    }


def _detail_text(detail: object) -> str:
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    return "The Arkime request was refused, with no reason given."


@router.post(
    "/alerts/{alert_id}/arkime",
    response_class=HTMLResponse,
)
async def alert_arkime_fragment(
    alert_id: str,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION)),
) -> HTMLResponse:
    """The PCAP workspace for one alert.

    Calls arkime_preview, which is the whole body of
    POST /api/alerts/{alert_id}/arkime/preview. An HTTP error from that
    route is a 200 fragment carrying its detail: htmx does not swap a 503,
    and the analyst would be left on the spinner instead of reading "Arkime
    is not configured". A 401 from Arkime is Arkime's credential, not the
    analyst's session; letting it propagate would send them to /login.
    """
    from ion.web.arkime_api import arkime_preview

    try:
        payload = await arkime_preview(alert_id, current_user)
        context = _view(payload, alert_id)
    except HTTPException as exc:
        logger.info(
            "Arkime preview fragment refused for alert %s: HTTP %s",
            alert_id, exc.status_code,
        )
        return _failed(
            request, alert_id,
            f"Preview failed (HTTP {exc.status_code}). {_detail_text(exc.detail)}",
        )
    except Exception:
        logger.exception("Arkime preview fragment could not be rendered for alert %s", alert_id)
        return _failed(
            request, alert_id,
            "PCAP analysis could not be read. This is not an empty capture: "
            "the query failed, so the verdict, the findings and the observables "
            "are unknown rather than zero. Refresh to try again.",
        )
    return _html(request, context)


def _parse_json(raw: object, what: str) -> tuple[object, Optional[str]]:
    if raw is None or str(raw).strip() == "":
        return None, (
            f"The {what} was missing from the submission, so nothing was "
            "attached. A missing payload is not an empty one. Refresh the "
            "analysis and try again."
        )
    try:
        return json.loads(str(raw)), None
    except json.JSONDecodeError:
        return None, (
            f"The {what} could not be read back, so nothing was attached. "
            "Refresh the analysis and try again."
        )


def _commit_request(form: Any) -> tuple[Optional[Any], Optional[str]]:
    """The form, as the ArkimeCommitRequest the JSON route already validates.

    A blank, a zero and a missing field stay distinct on the way in. The
    size in particular: an empty box is not zero bytes, and zero bytes is
    a capture the analyst may still want on the case.
    """
    from ion.web.arkime_api import ArkimeCommitRequest

    mode = str(form.get("commit_mode") or "").strip()
    if mode not in ("new", "existing"):
        return None, (
            "Say whether this attaches to a new case or an existing one. "
            "Nothing was written."
        )

    raw_id = form.get("case_id")
    case_id: Optional[int]
    if raw_id is None or str(raw_id).strip() == "":
        case_id = None
    else:
        try:
            case_id = int(str(raw_id).strip())
        except ValueError:
            return None, "The case id is not a number, so nothing was written."
    if mode == "existing" and case_id is None:
        return None, (
            "A case id is required to attach to an existing case. "
            "Nothing was written."
        )

    raw_size = form.get("pcap_size_bytes")
    if raw_size is None or str(raw_size).strip() == "":
        return None, (
            "The capture size was missing, so nothing was attached. "
            "A missing size is not zero bytes. Refresh the analysis and "
            "try again."
        )
    size_text = str(raw_size).strip()
    try:
        size = int(size_text)
    except ValueError:
        try:
            as_float = float(size_text)
        except ValueError:
            return None, (
                "The capture size could not be read, so nothing was attached."
            )
        # 1024.0 is a size; "1.5" is not a byte count the endpoint can store.
        if not as_float.is_integer():
            return None, (
                "The capture size could not be read, so nothing was attached."
            )
        size = int(as_float)

    analysis, error = _parse_json(form.get("analysis"), "analysis")
    if error:
        return None, error
    if not isinstance(analysis, dict):
        return None, (
            "The analysis was not a result object, so nothing was attached."
        )
    observables, error = _parse_json(form.get("observables"), "observable list")
    if error:
        return None, error
    if not isinstance(observables, list):
        return None, (
            "The observable list was unreadable, so nothing was attached."
        )

    title = str(form.get("case_title") or "").strip() or None
    severity = str(form.get("case_severity") or "").strip() or "medium"
    try:
        body = ArkimeCommitRequest(
            case_id=None if mode == "new" else case_id,
            create_new_case=mode == "new",
            case_title=title if mode == "new" else None,
            case_severity=severity,
            pcap_size_bytes=size,
            analysis=analysis,
            observables=observables,
        )
    except ValidationError:
        return None, (
            "The preview payload did not match what attach accepts, so "
            "nothing was written. Refresh the analysis and try again."
        )
    return body, None


@router.post(
    "/alerts/{alert_id}/arkime/commit",
    response_class=HTMLResponse,
)
async def alert_arkime_commit_fragment(
    alert_id: str,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Attach the preview to a case, and say what happened.

    Calls arkime_commit, the body of POST /api/alerts/{id}/arkime/commit.
    The result is a fragment swapped into the result slot, not a new copy
    of the workspace, so a refusal leaves the form in place. The form is
    the control that retries, and it lives outside this swap target.
    """
    from ion.web.arkime_api import arkime_commit

    form = await request.form()
    body, error = _commit_request(form)
    if error or body is None:
        return _commit_bad(request, error or "Nothing was written.")

    try:
        result = await arkime_commit(alert_id, body, current_user, session)
    except HTTPException as exc:
        logger.info(
            "Arkime commit fragment refused for alert %s: HTTP %s",
            alert_id, exc.status_code,
        )
        return _commit_bad(
            request,
            f"Attach failed (HTTP {exc.status_code}). {_detail_text(exc.detail)} "
            "Nothing was written.",
        )
    except Exception:
        logger.exception(
            "Arkime commit fragment could not attach alert %s", alert_id
        )
        return _commit_bad(
            request,
            "The analysis could not be attached. This is not a successful "
            "attach with zero observables: the write failed, so whether a "
            "case was updated is unknown. Try again.",
        )

    created = getattr(result, "observables_created", None)
    case_id = getattr(result, "case_id", None)
    case_number = getattr(result, "case_number", None)
    try:
        case_url = f"/cases?id={int(case_id)}"
    except (TypeError, ValueError):
        case_url = ""
    return _html(request, {
        "kind": KIND_COMMIT_OK,
        "case_url": case_url,
        "case_number": case_number,
        "observables_created": created,
    })
