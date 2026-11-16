"""SOC Command Centre: the queue, cases, KPIs, IOC lookup and knowledge base.

analyst.html built every one of those by concatenating strings and writing
them with innerHTML. The same reads now render here, one route per read,
because they are not the same permission:

    GET  /api/elasticsearch/alerts          alert:read
    GET  /api/cases?status=open             case:read
    GET  /api/dashboard/team-metrics        alert:read
    GET  /api/observables/stats             observable:read
    POST /api/opencti/enrich                get_current_user, no named permission
    GET  /api/analyst/knowledge-base        document:read

One route could carry only one of those. The loosest would make the case
list and the library a softer way in than their own endpoints.

This is not a detection-engineering page. /analyst is the SOC workspace
(server.py grants it alert:read) and none of those JSON routes is mounted
under /api/de, so none of them carries require_de_module. The licence gate
is for modules named de_*. Putting it on this fragment would 404 the
workspace on a deployment that simply is not licensed for detection
engineering, and would answer an unauthenticated caller as though the
command centre did not exist.

POST /api/opencti/enrich is the exception that has no named permission.
The fragment is alert:read anyway: that is the page's own gate, it is
stricter than the JSON route rather than softer, and the registry's
bare-auth allow-list is not this conversion's file.

What the JavaScript got wrong, as opposed to merely built badly:

  * The queue sliced to eight and only then sorted, so a critical alert in
    ninth place never appeared and the eight that did were the oldest.
  * Severity fell back to "low" when it was missing, which is a different
    finding from a severity nobody set.
  * Open-alert and critical/high figures used `|| 0`. A missing total became
    the length of a capped page, and a failed read became an empty queue.
  * My Cases fetched the first page of every open case and filtered it in
    the browser, then reported the length of that filtered page. Past the
    page the analyst's own count silently fell, and it was never the query's
    own count.
  * Watched IOCs read `watched || total || 0`. The stats payload has no
    `watched` key, so the tile was the total, and a missing total was zero.
  * The lookup posted `{value}` only. The endpoint requires a type as well,
    so the request 422d before OpenCTI was asked. The service returns a
    nested observable, and labels are `{value, color}` objects; the old
    renderer stringified those as "[object Object]".
  * A topic chip searched for the collection's name. The name is a shelf
    label and appears in no article, so the click returned nothing.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/analyst.html"

#: The page's own permission (server.py, the /analyst entry). The IOC
#: fragment uses it because the JSON route has nothing stricter to copy.
ALERT_READ = "alert:read"
CASE_READ = "case:read"
OBSERVABLE_READ = "observable:read"
DOCUMENT_READ = "document:read"

# The JSON calls, copied as values rather than left as the endpoint's
# defaults. GET /api/elasticsearch/alerts defaults limit to 500, but the
# service it calls defaults to 50: omitting the argument here would be a
# different queue from the one the page asked for.
ALERT_HOURS = 24
ALERT_LIMIT = 500
QUEUE_CAP = 8
CASE_ROWS = 5
TOPIC_CHIPS = 12
KB_RECENT = 6
KB_SEARCH_LIMIT = 8
KB_TOPIC_LIMIT = 12
MIN_QUERY = 2
DESCRIPTION_CAP = 200

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_UNKNOWN_RANK = 4

_HASH = (
    (64, "file-sha256"),
    (40, "file-sha1"),
    (32, "file-md5"),
)


class AnalystPanel(TypedDict):
    """What every panel of this fragment carries.

    One fragment renders six panels and `view` is the discriminator it
    switches on. `failed` is the read's outcome and is never inferred from
    an empty list: a panel that could not be read and a panel with nothing
    in it are different renders.
    """
    view: str
    failed: bool


class AlertsPanel(AnalystPanel):
    rows: list
    total: Optional[int | float]
    critical: int
    high: int
    es_state: str


class CasesPanel(AnalystPanel):
    rows: list
    total: Optional[int | float]


class MttrPanel(AnalystPanel):
    mttr: Optional[int | float]


class WatchedPanel(AnalystPanel):
    total: Optional[int | float]


class KbPanel(AnalystPanel):
    """The knowledge base's three shapes, told apart by `mode`.

    `unconfigured` is its own state and not an empty library: a deployment
    with no knowledge base at all and one with nothing in it yet are
    different things to say to the reader.
    """
    mode: str
    unconfigured: bool
    articles: list
    topics: list
    hidden: int
    recent: list
    topic_name: str


def _failed(view: str, **extra: Any) -> AnalystPanel:
    """The model for a panel whose read did not happen.

    One definition rather than the same two keys written at seven call
    sites. `failed` is always True here and is never inferred from an empty
    list: a panel that could not be read and a panel with nothing in it are
    different renders.
    """
    panel: AnalystPanel = {"view": view, "failed": True}
    panel.update(extra)  # type: ignore[typeddict-item]
    return panel


def _render(request: Request, view: AnalystPanel) -> Response:
    """One panel, as markup or as the model itself.

    render_view answers JSON to a caller that asks for it, so each panel
    is a contract rather than a detail of this template. The whole context
    is the one object: a model the caller has to complete is not a
    contract.
    """
    return render_view(request, FRAGMENT, view)


def _number(value: object) -> Optional[int | float]:
    """A measured figure, or None when there is not one.

    `bool` is a subclass of `int`, so a check that only rejects non-numbers
    turns True into 1. A float that is a whole number is returned as an int
    so a mean of 0.0 renders as 0 rather than 0.0; a fractional mean is
    kept, because rounding it again would not be the figure the endpoint
    computed.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else value
    return None


def _present_text(value: object) -> Optional[str]:
    """A display string, or None when there is nothing to show.

    `plain` first, because a SQLEnum member's str() on 3.12 is the repr.
    "0" is kept: it is a value. "" and None are not.
    """
    value = plain(value)
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text or None


def _severity(raw: object) -> tuple[str, int]:
    """The pill's word and its sort rank.

    Missing is "unknown", rank 4. The JavaScript used `(sev || 'low')`, so a
    row nobody had classified looked like a row classified as low, and it
    sorted with the lows. An unrecognised word is shown as itself, at the
    same rank as info: it is not low either.
    """
    text = _present_text(raw)
    if text is None:
        return "unknown", _UNKNOWN_RANK
    key = text.lower()
    return key, _SEV_RANK.get(key, _UNKNOWN_RANK)


def _first_timestamp(alert: dict[str, Any]) -> object:
    raw = alert.get("timestamp")
    if raw is None or raw == "":
        raw = alert.get("@timestamp")
    if raw is None or raw == "":
        return None
    return raw


def _sort_stamp(raw: object) -> float:
    """Newest-first key. Unparseable and missing sort as the oldest.

    `new Date(b.timestamp || 0)` treated a missing timestamp as the epoch,
    which is a real instant and the wrong claim. Naive values are UTC for
    ordering only; the cell still goes through the `ts` macro.
    """
    if isinstance(raw, datetime):
        dt = raw
    elif raw is None:
        return float("-inf")
    else:
        text = str(raw).strip()
        if not text:
            return float("-inf")
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return float("-inf")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _alert_title(alert: dict[str, Any]) -> str:
    for key in ("rule_name", "title"):
        text = _present_text(alert.get(key))
        if text is not None:
            return text
    return "Untitled"


def _priority(alerts: list[Any]) -> tuple[list[dict[str, Any]], int, int]:
    """Sort, then cap. Counts are taken before the cap.

    Slicing first is what dropped a critical alert that arrived ninth and
    what kept the oldest eight of a run of lows. Both counts are over the
    whole list, including the rows the panel does not have room to show.
    """
    prepared: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        label, rank = _severity(alert.get("severity"))
        when = _first_timestamp(alert)
        prepared.append({
            "severity": label,
            "rank": rank,
            "title": _alert_title(alert),
            "host": _present_text(alert.get("host")),
            "user": _present_text(alert.get("user")),
            "timestamp": when,
            "stamp": _sort_stamp(when),
        })
    prepared.sort(key=lambda row: (row["rank"], -row["stamp"]))
    critical = sum(1 for row in prepared if row["severity"] == "critical")
    high = sum(1 for row in prepared if row["severity"] == "high")
    return prepared[:QUEUE_CAP], critical, high


def _es_state(payload: dict[str, Any]) -> str:
    """Connected, degraded, or unknown. Identity, not truthiness.

    `connection_error: "yes"` and `configured: "false"` are neither boolean
    and must not pick a state. A failed read does not come through here: the
    caller has no flags, and "degraded" would be a claim about Elasticsearch
    the read never made.
    """
    if (
        payload.get("connection_error") is True
        or payload.get("configured") is False
        or payload.get("enabled") is False
    ):
        return "degraded"
    if payload.get("configured") is True and payload.get("enabled") is not False:
        return "connected"
    return "unknown"


def _case_row(raw: dict[str, Any]) -> Optional[dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    label, _rank = _severity(raw.get("severity"))
    case_id = raw.get("id")
    if isinstance(case_id, bool) or not isinstance(case_id, int):
        case_id = None
    number = _present_text(raw.get("case_number"))
    if number is None and case_id is not None:
        number = f"#{case_id}"
    when = raw.get("updated_at")
    if when == "":
        when = None
    return {
        "reference": number,
        "title": _present_text(raw.get("title")) or "Untitled",
        "severity": label,
        "alert_count": _number(raw.get("alert_count")),
        "updated_at": when,
        "href": f"/cases?id={case_id}" if case_id is not None else None,
    }


def _ioc_type(value: str) -> str:
    """The OpenCTI type for a value the analyst pasted.

    The same order as tools.html `detectIOCType`, plus IPv6 via
    `ipaddress` (the old check was a dotted-quad only). Every name returned
    is a key of `OpenCTIService.TYPE_MAP`. `javascript:alert(1)` is not a
    URL: only an http(s) scheme is.
    """
    text = value.strip()
    for length, name in _HASH:
        if re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", text):
            return name
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if isinstance(ip, ipaddress.IPv4Address):
        return "ipv4-addr"
    if isinstance(ip, ipaddress.IPv6Address):
        return "ipv6-addr"
    if re.match(r"https?://", text, re.IGNORECASE):
        return "url"
    if "@" in text:
        return "email-addr"
    return "domain-name"


def _as_dict(result: object) -> Optional[dict[str, Any]]:
    """A JSON object out of a dict, a response, or a pydantic model.

    `enrich_observable` returns a `JSONResponse` (503) when OpenCTI is off,
    and a dict when it ran. htmx will not swap an error status, so the
    fragment is always 200 and the body is what the JSON route would have
    said. A body that is not an object is not a result.
    """
    if isinstance(result, JSONResponse):
        try:
            data = json.loads(result.body)
        except (TypeError, ValueError):
            return None
        return data if isinstance(data, dict) else None
    if isinstance(result, dict):
        return result
    dump = getattr(result, "model_dump", None) or getattr(result, "dict", None)
    if dump is None:
        return None
    data = dump()
    return data if isinstance(data, dict) else None


def _score(payload: dict[str, Any]) -> Optional[int | float]:
    """`observable.score` when that key is present, otherwise the top level.

    The service nests the score. The old page read a flat `data.score` and
    so showed nothing for a real hit. A present key whose value is 0 is a
    measured zero; it must not fall through to some other number. A present
    key whose value is not a number is "no score", not an invitation to
    read a second field.
    """
    observable = payload.get("observable")
    if isinstance(observable, dict) and "score" in observable:
        return _number(observable.get("score"))
    if "score" in payload:
        return _number(payload.get("score"))
    return None


def _labels(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    labels: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            text = _present_text(item.get("value"))
        else:
            text = _present_text(item)
        if text is not None:
            labels.append(text)
    return labels


def _description(payload: dict[str, Any]) -> Optional[str]:
    text = _present_text(payload.get("description"))
    if text is None:
        observable = payload.get("observable")
        if isinstance(observable, dict):
            text = _present_text(observable.get("description"))
    if text is None:
        return None
    if len(text) > DESCRIPTION_CAP:
        return text[:DESCRIPTION_CAP] + "..."
    return text


def _ioc_view(payload: dict[str, Any], value: str) -> dict[str, Any]:
    found = payload.get("found")
    if found is not True and found is not False:
        found = None
    return {
        "error": _present_text(payload.get("error")),
        "found": found,
        "score": _score(payload),
        "labels": _labels(payload.get("labels")),
        "description": _description(payload),
        # One value, then the template's safe_url. Mixing a literal "&"
        # with an escaped variable is how a query was double-escaped.
        "observables_url": "/observables?search=" + quote(value, safe=""),
    }


def _article_row(raw: dict[str, Any]) -> Optional[dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    doc_id = raw.get("id")
    if isinstance(doc_id, bool) or not isinstance(doc_id, int):
        return None
    snippet = raw.get("snippet")
    return {
        "id": doc_id,
        "name": _present_text(raw.get("name")) or "Untitled",
        "collection_name": _present_text(raw.get("collection_name")),
        "matched_in": raw.get("matched_in"),
        "snippet": snippet if isinstance(snippet, str) else None,
        "href": f"/documents#doc-{doc_id}",
    }


def _topic_chips(
    collections: list[Any],
) -> tuple[list[dict[str, Any]], int]:
    """The biggest topics, and how many did not fit.

    `article_count > 0` on its own is wrong twice: `True > 0` is true
    because bool is an int, and a numeric string would have to be coerced
    into a count nobody computed. Zero is a measured empty shelf and is
    not a chip.
    """
    rows: list[dict[str, Any]] = []
    for collection in collections:
        if not isinstance(collection, dict):
            continue
        count = collection.get("article_count")
        if isinstance(count, bool) or not isinstance(count, (int, float)):
            continue
        if isinstance(count, float):
            if not count.is_integer():
                continue
            count = int(count)
        if count <= 0:
            continue
        name = _present_text(collection.get("name"))
        cid = collection.get("id")
        if name is None or isinstance(cid, bool) or not isinstance(cid, int):
            continue
        rows.append({"id": cid, "name": name, "article_count": count})
    rows.sort(key=lambda row: (-row["article_count"], row["name"]))
    shown = rows[:TOPIC_CHIPS]
    return shown, len(rows) - len(shown)


@router.get(
    "/analyst/alerts",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
async def analyst_alerts(
    request: Request,
    current_user: User = Depends(require_permission(ALERT_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The priority queue, the open-alert tile and the ES pill.

    Calls `get_es_alerts`, which is the whole of GET
    /api/elasticsearch/alerts. hours and limit are passed explicitly: the
    route's limit default is not the service's.
    """
    from ion.web.elasticsearch_api import get_es_alerts

    try:
        result = await get_es_alerts(
            hours=ALERT_HOURS,
            limit=ALERT_LIMIT,
            current_user=current_user,
            session=session,
        )
    except Exception:
        logger.exception("analyst alerts fragment could not be rendered")
        return _render(request, _failed("alerts", es_state="unknown"))

    payload = result if isinstance(result, dict) else None
    alerts = payload.get("alerts") if payload is not None else None
    if not isinstance(alerts, list):
        # A payload that is not a list of alerts is a read we cannot show.
        # It is not an empty queue, and its total is not a number of alerts.
        return _render(request, _failed("alerts", es_state="unknown"))

    rows, critical, high = _priority(alerts)
    total = _number(payload.get("total")) if "total" in payload else None
    view: AlertsPanel = {
        "view": "alerts", "failed": False, "rows": rows, "total": total,
        "critical": critical, "high": high, "es_state": _es_state(payload),
    }
    return _render(request, view)


@router.get(
    "/analyst/cases",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(CASE_READ))],
)
def analyst_cases(
    request: Request,
    current_user: User = Depends(require_permission(CASE_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The caller's open cases, and the count the query actually matched.

    `list_cases_page` is what GET /api/cases runs, inside `asyncio.to_thread`.
    Called directly here so the request session is not handed to another
    thread. status=open is only AlertCaseStatus.OPEN; acknowledged is a
    different state and the tile's "Open / Investigating" wording is the
    label the page already had, not a second status.
    """
    from ion.services.case_query_service import list_cases_page

    try:
        page = list_cases_page(
            session,
            status="open",
            assigned_to_id=current_user.id,
            limit=CASE_ROWS,
        )
    except Exception:
        logger.exception("analyst cases fragment could not be rendered")
        return _render(request, _failed("cases"))

    cases = page.get("cases") if isinstance(page, dict) else None
    if not isinstance(cases, list):
        return _render(request, _failed("cases"))
    rows = [row for row in (_case_row(c) for c in cases) if row is not None]
    total = _number(page.get("total")) if "total" in page else None
    view: CasesPanel = {"view": "cases", "failed": False,
                        "rows": rows, "total": total}
    return _render(request, view)


@router.get(
    "/analyst/mttr",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def analyst_mttr(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Mean time to resolve, from the body of GET /api/dashboard/team-metrics.

    `get_team_metrics` runs that body in a worker thread. The fragment calls
    `team_metrics_payload` itself, which is the function the endpoint calls,
    so the session stays on this thread. None means no case closed in the
    window. Zero would mean they closed instantly. A thrown read is neither.
    """
    from ion.web.api import team_metrics_payload

    try:
        payload = team_metrics_payload(session)
    except Exception:
        logger.exception("analyst MTTR fragment could not be rendered")
        return _render(request, _failed("mttr"))
    if not isinstance(payload, dict):
        return _render(request, _failed("mttr"))
    view: MttrPanel = {
        "view": "mttr", "failed": False,
        "mttr": _number(payload.get("mttr_hours")) if "mttr_hours" in payload else None,
    }
    return _render(request, view)


@router.get(
    "/analyst/watched",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(OBSERVABLE_READ))],
)
def analyst_watched(
    request: Request,
    current_user: User = Depends(require_permission(OBSERVABLE_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The observables total. The stats payload has no `watched` field.

    The tile keeps its "Watched IOCs" label because that is what the page
    called the number it was already displaying (`watched || total`). The
    number is `total` from `get_observable_stats`, not a second query.
    """
    from ion.web.observable_api import get_observable_stats

    try:
        payload = _as_dict(get_observable_stats(session=session, user=current_user))
    except Exception:
        logger.exception("analyst observables fragment could not be rendered")
        return _render(request, _failed("watched"))
    if payload is None:
        return _render(request, _failed("watched"))
    total = _number(payload.get("total")) if "total" in payload else None
    view: WatchedPanel = {"view": "watched", "failed": False, "total": total}
    return _render(request, view)


@router.post(
    "/analyst/ioc",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
async def analyst_ioc(
    request: Request,
    value: str = Form(""),
    current_user: User = Depends(require_permission(ALERT_READ)),
) -> HTMLResponse:
    """One indicator, typed and then handed to POST /api/opencti/enrich.

    An empty value is a bad request, not a failed lookup: the failure
    sentence is reserved for a check that did not run. The endpoint's
    disabled and unconfigured branches return JSONResponse 503; that body
    is rendered here at 200 so htmx can show the reason.
    """
    from ion.web.api import OpenCTIEnrichRequest, enrich_observable

    text = value.strip()
    if not text:
        raise HTTPException(status_code=422, detail="A value is required")
    try:
        result = await enrich_observable(
            OpenCTIEnrichRequest(type=_ioc_type(text), value=text),
            current_user=current_user,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("analyst IOC fragment could not be rendered")
        return _render(request, _failed("ioc"))
    payload = _as_dict(result)
    if payload is None:
        return _render(request, _failed("ioc"))
    return _render(request, {"view": "ioc", "failed": False,
                             **_ioc_view(payload, text)})


def _kb_failed(request: Request) -> Response:
    return _render(request, _failed("kb"))


@router.get(
    "/analyst/kb",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(DOCUMENT_READ))],
)
def analyst_kb(
    request: Request,
    q: str = "",
    collection_id: Optional[int] = None,
    current_user: User = Depends(require_permission(DOCUMENT_READ)),
    session: Session = Depends(get_db_session),
) -> Response:
    """Browse, search, or list one shelf.

    A query shorter than two characters is browsing, unless a collection id
    came with it: that is a topic chip, and the chip lists the shelf instead
    of searching for its name. An empty shelf answers 204 so htmx leaves the
    browse view standing. An empty search answers 200 and says it found
    nothing. Those are different claims, and a search miss must not restore
    the shelf the analyst just left.
    """
    from ion.web.api import (
        get_analyst_knowledge_base,
        search_analyst_knowledge_base,
    )

    text = (q or "").strip()
    topic = collection_id is not None and len(text) < MIN_QUERY
    try:
        if topic or len(text) >= MIN_QUERY:
            payload = search_analyst_knowledge_base(
                q="" if topic else text,
                collection_id=collection_id if topic else None,
                limit=KB_TOPIC_LIMIT if topic else KB_SEARCH_LIMIT,
                current_user=current_user,
                session=session,
            )
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list):
                return _kb_failed(request)
            articles = [
                row for row in (_article_row(r) for r in results) if row is not None
            ]
            if topic and not articles:
                return Response(status_code=204)
            topic_name = "Topic"
            if articles and articles[0].get("collection_name"):
                topic_name = articles[0]["collection_name"]
            found: KbPanel = {
                "view": "kb", "failed": False,
                "mode": "topic" if topic else "search",
                "articles": articles, "topic_name": topic_name,
            }
            return _render(request, found)

        payload = get_analyst_knowledge_base(
            include_articles=False,
            recent=KB_RECENT,
            current_user=current_user,
            session=session,
        )
    except Exception:
        logger.exception("analyst knowledge base fragment could not be rendered")
        return _kb_failed(request)

    if not isinstance(payload, dict):
        return _kb_failed(request)
    # Exact match. Any other status is not "the library was never configured".
    if payload.get("status") == "not_found":
        absent: KbPanel = {"view": "kb", "failed": False,
                           "unconfigured": True}
        return _render(request, absent)

    collections = payload.get("collections", [])
    if not isinstance(collections, list):
        return _kb_failed(request)
    recent_raw = payload.get("recent", [])
    if recent_raw is None:
        recent_raw = []
    if not isinstance(recent_raw, list):
        return _kb_failed(request)
    topics, hidden = _topic_chips(collections)
    recent = [row for row in (_article_row(r) for r in recent_raw) if row is not None]
    browse: KbPanel = {
        "view": "kb", "failed": False, "mode": "browse",
        "unconfigured": False, "topics": topics, "hidden": hidden,
        "recent": recent,
    }
    return _render(request, browse)
