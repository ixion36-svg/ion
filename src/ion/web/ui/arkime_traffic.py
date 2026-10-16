"""Traffic analytics at /arkime-traffic: stats, talkers, hunts, exclusions, AI.

arkime_traffic.html wrote six regions with innerHTML behind its own
`escHtml()`, plus a `_deltaHtml()` that returned a span with a Tailwind
colour class picked in JavaScript. All of that renders here and Jinja
escapes it.

Five routes, all `alert:read`, which is what every endpoint they mirror
requires:

    GET  /api/arkime/traffic/overview       alert:read
    GET  /api/arkime/traffic/top-talkers    alert:read
    GET  /api/arkime/hunts                  alert:read
    GET  /api/arkime/traffic/exclusions     alert:read
    POST /api/arkime/traffic/ai-review      alert:read

Nothing here mirrors a write. POST /api/arkime/hunts and POST and DELETE
/api/arkime/traffic/exclusions require `security:read`, and the page still
calls those directly: a fragment route for a write would have to carry the
stricter gate, and a reader would then be shown a control whose GET
answered 200 and whose POST answered 403.

Not require_page_permission: it redirects to /login, and htmx would swap a
login form into the middle of the dashboard.

Three regions are deliberately NOT fragments, because they contain no
markup the browser assembles. The geographic map, the per-sensor bar chart
and the RTMON doughnuts are drawn by jsvectormap and Chart.js from JSON,
through `replaceChildren` and canvas calls, so there is nothing for a
server partial to own and a second read of the same endpoint to paint a
dropdown would double an Arkime aggregation on every range change. The
volume and protocol charts stay client-drawn for the same reason, but
their series now arrive inside the overview fragment rather than from a
second fetch, so the figures in the stats bar and the shape beside them
come from one read and cannot disagree.

What the JavaScript got wrong, as opposed to merely built badly:

  * `fmtBytes` began `b = Number(b) || 0; if (b === 0) return '0 B'`, and
    `fmtNum` was `Number(n).toLocaleString()`, which is "NaN" for a missing
    field. So a top talker whose byte count Arkime did not return read
    "0 B" and its session count read "NaN", in the same row.
  * `data.total_sessions || 0` and `data.total_bytes || 0` in the stats
    bar. An Arkime that was reachable and refusing reported zero sessions
    and zero bytes, which is what a genuinely silent link looks like.
  * `talkersData.by_src || []` and `countryData.by_src || []`. A refused
    query rendered "No data for this range".
  * `_deltaHtml` returned the empty string for a missing percentage, so a
    trend that could not be computed and a trend of exactly nothing looked
    identical, and `_pct` returns None whenever the previous window was
    zero, which is every new deployment.
  * `h.matched_sessions == null ? '—' : fmtNum(...)` was right, and is the
    only one of these that was. It is kept.
  * The hunt deep link was built only after GET
    /api/arkime/traffic/retention resolved, because that is where the page
    read `web_url` from. A retention query that failed left every finished
    hunt without its link. The viewer URL comes from
    `arkime_public_url()` here, which is the same function that endpoint
    calls, so the link no longer depends on an unrelated read.
  * `escHtml(e.id)` built `data-excl-id="..."` by concatenation. The id is
    an integer column, so nothing could go wrong today, which is exactly
    the kind of place that stops being true quietly.

DEMO MODE MOVED WITH THE MARKUP, AND HAD TO

The page showed synthetic traffic when Arkime is unconfigured, so that
somebody evaluating ION sees the shape of the thing. Those payloads were
JavaScript literals feeding the same render path. With the render path on
the server the literals have to be here too, or an unconfigured deployment
would show synthetic node, country and RTMON charts beside an overview
that says Arkime is not configured, which is worse than either answer
alone. They are marked `demo` in the view model and the fragment says so
on the panel, which the page's own banner did not: a reader who scrolled
past the banner had no way to tell the numbers were invented.
"""
from __future__ import annotations

import logging
import math
import time
from typing import Any, Optional, TypedDict
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.arkime_api import list_arkime_hunts as list_hunts
from ion.web.arkime_traffic_analytics_api import (
    list_exclusions,
    traffic_ai_review,
    traffic_overview,
    traffic_top_talkers,
)
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)

router = APIRouter()

OVERVIEW_FRAGMENT = "_fragments/arkime_traffic_overview.html"
TALKERS_FRAGMENT = "_fragments/arkime_traffic_talkers.html"
HUNTS_FRAGMENT = "_fragments/arkime_traffic_hunts.html"
EXCLUSIONS_FRAGMENT = "_fragments/arkime_traffic_exclusions.html"
REVIEW_FRAGMENT = "_fragments/arkime_traffic_review.html"

#: The permission every endpoint these fragments mirror requires.
PERMISSION = "alert:read"

#: The windows the API accepts, with the seconds the demo generator needs.
#: Spelled here rather than imported so a fragment cannot be the thing that
#: starts accepting a range the endpoint would refuse.
RANGES: dict[str, int] = {"24h": 24 * 3600, "7d": 7 * 24 * 3600,
                          "30d": 30 * 24 * 3600}

_KB = 1024
_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024
_TB = 1024 * 1024 * 1024 * 1024

#: Hunt status, as a state the stylesheet paints. The JavaScript held a map
#: of Tailwind colour classes, which is why a restyle never reached it.
_HUNT_STATES = {
    "running": "working", "submitted": "working",
    "finished": "done", "failed": "failed",
}


def arkime_configured() -> bool:
    """Whether Arkime is configured, read from the service the API reads.

    A function rather than an inline call so the demo branch has one name,
    is testable, and cannot drift from `is_configured`, which is what every
    endpoint on this page checks before it refuses.
    """
    from ion.services.arkime_service import get_arkime_service

    return bool(get_arkime_service().is_configured)


def arkime_web_url() -> Optional[str]:
    """The analyst-browser viewer base for deep links, or None.

    `arkime_public_url` returns "" when Arkime is unconfigured, and the
    caller is meant to omit the link rather than emit one to nowhere. None
    says that in a way a template cannot accidentally render.
    """
    from ion.services.arkime_service import arkime_public_url

    return arkime_public_url() or None


# ---------------------------------------------------------------------------
# Reading and formatting one value
# ---------------------------------------------------------------------------


def _num(value: object) -> Optional[int | float]:
    """A measured figure, or None. `bool` is an int, so True is refused."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return int(value) if value.is_integer() else value
    return None


def _text(value: object) -> Optional[str]:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text or None


def _fmt_n(value: object) -> Optional[str]:
    """Thousands separated, or None.

    `Number(n).toLocaleString()` was the page's version and it printed
    "NaN" for a field Arkime had not sent, which reads as a measurement
    that went wrong rather than one that never happened.
    """
    n = _num(value)
    if n is None:
        return None
    return f"{n:,.1f}" if isinstance(n, float) else f"{n:,}"


def _fmt_bytes(value: object) -> Optional[str]:
    """A size, or None. Zero is "0 B" because zero can be measured.

    The page's `fmtBytes` coerced with `Number(b) || 0` and then returned
    "0 B" for the zero it had just invented, so an unanswered byte count
    and an idle link were the same string.
    """
    n = _num(value)
    if n is None or n < 0:
        return None
    if n < _KB:
        return f"{int(n)} B"
    if n < _MB:
        return f"{n / _KB:.0f} KB"
    if n < _GB:
        return f"{n / _MB:.1f} MB"
    if n < _TB:
        return f"{n / _GB:.1f} GB"
    return f"{n / _TB:.1f} TB"


def _detail(exc: HTTPException) -> str:
    text = _text(exc.detail)
    return text or "Arkime refused the query and gave no reason."


# ---------------------------------------------------------------------------
# View models
# ---------------------------------------------------------------------------


class OverviewPanel(TypedDict):
    """The stats bar's first three tiles, the two trends, and the series the
    volume and protocol charts are drawn from.

    `series` is a JSON string rather than a nested object because it exists
    to be handed to Chart.js through a data attribute. It goes out through
    |tojson in the fragment all the same, so a value Arkime sent cannot
    break out of the attribute.
    """
    failed: bool
    reason: Optional[str]
    demo: bool
    range: str
    sessions: Optional[str]
    bytes: Optional[str]
    top_protocol: Optional[str]
    points: Optional[int]
    empty: bool
    sessions_trend: Optional[dict]
    bytes_trend: Optional[dict]
    series: dict


class TalkersPanel(TypedDict):
    failed: bool
    reason: Optional[str]
    demo: bool
    by_src: Optional[list]
    by_dst: Optional[list]
    method: Optional[str]
    top_src: Optional[str]


class HuntsPanel(TypedDict):
    failed: bool
    hunts: Optional[list]


class ExclusionsPanel(TypedDict):
    failed: bool
    exclusions: Optional[list]


class ReviewPanel(TypedDict):
    failed: bool
    reason: Optional[str]
    needs_node: bool
    node: Optional[str]
    range: Optional[str]
    analysis: Optional[str]
    model: Optional[str]


# ---------------------------------------------------------------------------
# Demo payloads, ported from the page's own literals
# ---------------------------------------------------------------------------


def _demo_overview(window: str) -> dict:
    """`_demoOverview`, as it was. The clock is the server's rather than the
    browser's, which only moves the labels by the viewer's offset; they are
    formatted from epoch milliseconds in the browser either way."""
    seconds = RANGES.get(window, RANGES["24h"])
    step_ms = {"24h": 30 * 60_000, "7d": 3 * 3_600_000,
               "30d": 24 * 3_600_000}.get(window, 30 * 60_000)
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - seconds * 1000
    src: list[list[int]] = []
    dst: list[list[int]] = []
    stamp = start_ms
    while stamp <= now_ms:
        hour = time.gmtime(stamp / 1000).tm_hour
        factor = 1 + 2 * max(0.0, 1 - abs(hour - 13) / 6)
        noise = 0.65 + 0.7 * (math.sin(stamp / 1e8) * 0.5 + 0.5)
        value = int(1_800_000 * factor * noise)
        src.append([stamp, value])
        dst.append([stamp, int(value * 0.62)])
        stamp += step_ms
    return {
        "src_histo": src,
        "dst_histo": dst,
        "protocols": {"tcp": 15420, "udp": 3210, "tls": 892, "dns": 1205,
                      "http": 445, "smb": 189},
        "total_sessions": 21361,
        "total_bytes": sum(p[1] for p in src) + sum(p[1] for p in dst),
        "trend": None,
        "range": window,
    }


_DEMO_TALKERS: dict[str, Any] = {
    "by_src": [
        {"ip": "10.10.45.23", "bytes": 8547291648, "sessions": 2341},
        {"ip": "192.168.1.105", "bytes": 6213847552, "sessions": 1876},
        {"ip": "172.16.0.88", "bytes": 4102938624, "sessions": 1234},
        {"ip": "10.0.0.45", "bytes": 2847293440, "sessions": 987},
        {"ip": "203.0.113.67", "bytes": 1934857216, "sessions": 543},
        {"ip": "10.20.5.12", "bytes": 1247293440, "sessions": 412},
        {"ip": "172.31.0.100", "bytes": 934857216, "sessions": 287},
    ],
    "by_dst": [
        {"ip": "8.8.8.8", "bytes": 12045678592, "sessions": 4521},
        {"ip": "1.1.1.1", "bytes": 8934857216, "sessions": 3210},
        {"ip": "185.199.108.153", "bytes": 5123847168, "sessions": 1876},
        {"ip": "140.82.121.4", "bytes": 3847293440, "sessions": 1123},
        {"ip": "151.101.193.69", "bytes": 2134857216, "sessions": 876},
        {"ip": "104.21.45.12", "bytes": 1547293440, "sessions": 543},
        {"ip": "172.217.169.46", "bytes": 934857216, "sessions": 312},
    ],
    "method": "demo",
}


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


def _trend(raw: object, key: str) -> Optional[dict]:
    """A percentage and a direction, or None when it was not computed.

    `_pct` returns None whenever the previous window was zero, which is
    every new deployment, so None is common and is not an error. The
    direction is a state, not a colour: the JavaScript chose
    `text-emerald-400` or `text-rose-400` itself, which is why the arrows
    could not be restyled with the rest of the page.
    """
    if not isinstance(raw, dict):
        return None
    pct = _num(raw.get(key))
    if pct is None:
        return None
    return {"pct": abs(pct), "direction": "up" if pct >= 0 else "down"}


def _top_protocol(raw: object) -> Optional[str]:
    """The busiest protocol, upper-cased, or None.

    Sorted on a measured count only. `Object.entries(p).sort((a,b)=>b[1]-a[1])`
    put a protocol whose count was a string or null at an arbitrary place
    and then read `[0][0]`, so the headline protocol could be whichever one
    had the unreadable count.
    """
    if not isinstance(raw, dict):
        return None
    ranked = [(name, _num(count)) for name, count in raw.items()]
    measured = [(name, count) for name, count in ranked if count is not None]
    if not measured:
        return None
    measured.sort(key=lambda row: row[1], reverse=True)
    name = _text(measured[0][0])
    return name.upper() if name else None


def _series(payload: dict, window: str) -> tuple[dict, Optional[int], bool]:
    """The chart series, the number of volume points, and whether it is empty.

    A histogram key that is not a list is not an empty histogram, so it
    travels as null and the page's chart code draws nothing rather than a
    flat line at zero. `points` is None in that case, which is what stops
    the subtitle claiming a count.
    """
    src = payload.get("src_histo")
    dst = payload.get("dst_histo")
    src_ok = isinstance(src, list)
    dst_ok = isinstance(dst, list)
    protocols = payload.get("protocols")
    series = {
        "src_histo": src if src_ok else None,
        "dst_histo": dst if dst_ok else None,
        "protocols": protocols if isinstance(protocols, dict) else None,
        "range": window,
    }
    if not src_ok and not dst_ok:
        return series, None, False
    stamps = set()
    for histo in (src if src_ok else [], dst if dst_ok else []):
        for point in histo:
            if isinstance(point, (list, tuple)) and point:
                stamps.add(point[0])
    return series, len(stamps), not stamps


def _overview_view(payload: object, window: str, demo: bool) -> OverviewPanel:
    blank: OverviewPanel = {
        "failed": True, "reason": None, "demo": demo, "range": window,
        "sessions": None, "bytes": None, "top_protocol": None,
        "points": None, "empty": False, "sessions_trend": None,
        "bytes_trend": None,
        "series": {"src_histo": None, "dst_histo": None, "protocols": None,
                   "range": window},
    }
    if not isinstance(payload, dict):
        return blank
    series, points, empty = _series(payload, window)
    trend = payload.get("trend")
    return {
        "failed": False, "reason": None, "demo": demo, "range": window,
        "sessions": _fmt_n(payload.get("total_sessions")),
        "bytes": _fmt_bytes(payload.get("total_bytes")),
        "top_protocol": _top_protocol(payload.get("protocols")),
        "points": points, "empty": empty,
        "sessions_trend": _trend(trend, "sessions_pct"),
        "bytes_trend": _trend(trend, "bytes_pct"),
        "series": series,
    }


def _refused(window: str, demo: bool, reason: str) -> OverviewPanel:
    view = _overview_view(None, window, demo)
    view["reason"] = reason
    return view


@router.get("/arkime-traffic/overview", response_class=HTMLResponse)
async def overview_fragment(
    request: Request,
    range: str = "24h",
    demo: bool = False,
    _user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> Response:
    """The first three stats tiles, both trends, and the chart series.

    `traffic_overview` is the whole body of GET /api/arkime/traffic/overview.
    The range is checked here first, because that endpoint answers 400 for a
    bad one and htmx does not swap a 400: the panel would keep whatever it
    last showed while the tab said something else.

    An HTTPException from the endpoint is a 200 fragment carrying its
    detail, for the same reason. 503 is "Arkime is not configured" and 502
    is Arkime refusing, and neither is zero traffic.
    """
    if range not in RANGES:
        return render_view(request, OVERVIEW_FRAGMENT, _refused(
            "24h", False,
            f"'{range}' is not a window this page can ask for. "
            "Use 24h, 7d or 30d."))

    # `demo` is the page's own ?demo=1, which ION's demos use on a
    # deployment that IS configured. Either condition is demo mode, which
    # is how the page decided it, and the fragment says so on the panel.
    if demo or not arkime_configured():
        return render_view(request, OVERVIEW_FRAGMENT,
                           _overview_view(_demo_overview(range), range, True))

    try:
        payload = await traffic_overview(range=range, user=_user,
                                        session=session)
    except HTTPException as exc:
        logger.info("traffic overview fragment refused: HTTP %s",
                    exc.status_code)
        return render_view(request, OVERVIEW_FRAGMENT, _refused(
            range, False, f"HTTP {exc.status_code}. {_detail(exc)}"))
    except Exception:
        logger.exception("traffic overview fragment could not be rendered")
        return render_view(request, OVERVIEW_FRAGMENT, _refused(
            range, False,
            "The traffic overview could not be read. Session and byte totals "
            "are unknown rather than zero."))
    return render_view(request, OVERVIEW_FRAGMENT,
                       _overview_view(payload, range, False))


# ---------------------------------------------------------------------------
# Top talkers
# ---------------------------------------------------------------------------


def _talker_row(raw: object, rank: int) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    return {
        "rank": rank,
        "ip": _text(raw.get("ip")),
        "bytes": _fmt_bytes(raw.get("bytes")),
        "sessions": _fmt_n(raw.get("sessions")),
    }


def _talker_rows(payload: dict, key: str) -> Optional[list]:
    found = payload.get(key)
    if not isinstance(found, list):
        return None
    rows = []
    for index, item in enumerate(found, start=1):
        row = _talker_row(item, index)
        if row is not None:
            rows.append(row)
    return rows


def _talkers_view(payload: object, demo: bool) -> TalkersPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "reason": None, "demo": demo, "by_src": None,
                "by_dst": None, "method": None, "top_src": None}
    by_src = _talker_rows(payload, "by_src")
    by_dst = _talker_rows(payload, "by_dst")
    if by_src is None and by_dst is None:
        return {"failed": True, "reason": None, "demo": demo, "by_src": None,
                "by_dst": None, "method": None, "top_src": None}
    # `spigraph` is a server-side aggregation over every session in the
    # window; anything else is sampled from the top flows and the note has
    # to say so. A method the payload did not state is not spigraph.
    return {
        "failed": False, "reason": None, "demo": demo,
        "by_src": by_src, "by_dst": by_dst,
        "method": _text(payload.get("method")),
        "top_src": by_src[0]["ip"] if by_src else None,
    }


@router.get("/arkime-traffic/talkers", response_class=HTMLResponse)
async def talkers_fragment(
    request: Request,
    range: str = "24h",
    exclude_private: bool = True,
    demo: bool = False,
    _user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> Response:
    """Both directions of the top-talker table, from one read.

    Which direction is on screen is control state the browser holds, so
    both tbodies are rendered and the tab toggles between them. Asking
    Arkime again for the half of a payload it already sent would be a
    second aggregation per click, and `by_src` and `by_dst` come out of the
    same spigraph query.
    """
    if range not in RANGES:
        view = _talkers_view(None, False)
        view["reason"] = (f"'{range}' is not a window this page can ask for. "
                          "Use 24h, 7d or 30d.")
        return render_view(request, TALKERS_FRAGMENT, view)

    if demo or not arkime_configured():
        return render_view(request, TALKERS_FRAGMENT,
                           _talkers_view(_DEMO_TALKERS, True))

    try:
        payload = await traffic_top_talkers(
            range=range, exclude_private=exclude_private, user=_user,
            session=session,
        )
    except HTTPException as exc:
        logger.info("top-talkers fragment refused: HTTP %s", exc.status_code)
        view = _talkers_view(None, False)
        view["reason"] = f"HTTP {exc.status_code}. {_detail(exc)}"
        return render_view(request, TALKERS_FRAGMENT, view)
    except Exception:
        logger.exception("top-talkers fragment could not be rendered")
        view = _talkers_view(None, False)
        view["reason"] = (
            "The top-talker query could not be read. Which hosts moved the "
            "most traffic is unknown, not none.")
        return render_view(request, TALKERS_FRAGMENT, view)
    return render_view(request, TALKERS_FRAGMENT, _talkers_view(payload, False))


# ---------------------------------------------------------------------------
# Packet hunts
# ---------------------------------------------------------------------------


def _hunt_row(raw: object, viewer: Optional[str]) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    status = _text(raw.get("status"))
    hunt_id = _text(raw.get("arkime_hunt_id"))
    # The link is offered only for a finished hunt with an Arkime id and a
    # viewer URL to point at. quote(..., safe="") is encodeURIComponent,
    # which is what the page used; the expression is one value, so no
    # literal "&" is mixed with an escaped one.
    link = None
    if viewer and hunt_id and status == "finished":
        link = f"{viewer}/sessions?expression=" + quote(
            f"huntId == {hunt_id}", safe="")
    return {
        "name": _text(raw.get("name")),
        "search": _text(raw.get("search")),
        "search_type": _text(raw.get("search_type")),
        "status": status,
        "state": _HUNT_STATES.get((status or "").lower(), "unknown"),
        # `== null ? '—' : fmtNum()` was the one guard the page got right,
        # and a hunt still running has not matched zero sessions.
        "matched": _fmt_n(raw.get("matched_sessions")),
        "created_at": raw.get("created_at") or None,
        "link": link,
    }


def _hunts_view(payload: object, viewer: Optional[str]) -> HuntsPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "hunts": None}
    found = payload.get("hunts")
    if not isinstance(found, list):
        return {"failed": True, "hunts": None}
    return {"failed": False,
            "hunts": [row for row in (_hunt_row(h, viewer) for h in found)
                      if row is not None]}


@router.get("/arkime-traffic/hunts", response_class=HTMLResponse)
async def hunts_fragment(
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> Response:
    """ION-submitted packet hunts, from GET /api/arkime/hunts.

    Rendered whether or not Arkime is reachable: the hunt history is ION's
    own table, and the page already made that call deliberately. Only the
    deep link needs the viewer, and it is withheld rather than pointed at
    nothing.
    """
    try:
        payload = await list_hunts(current_user=current_user, session=session)
        view = _hunts_view(payload, arkime_web_url())
    except Exception:
        logger.exception("hunts fragment could not be rendered")
        view = _hunts_view(None, None)
    return render_view(request, HUNTS_FRAGMENT, view)


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


def _exclusions_view(payload: object) -> ExclusionsPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "exclusions": None}
    found = payload.get("exclusions")
    if not isinstance(found, list):
        return {"failed": True, "exclusions": None}
    rows = []
    for item in found:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr"))
        row_id = item.get("id")
        if cidr is None or row_id is None:
            continue
        rows.append({"id": row_id, "cidr": cidr,
                     "note": _text(item.get("note"))})
    return {"failed": False, "exclusions": rows}


@router.get("/arkime-traffic/exclusions", response_class=HTMLResponse)
def exclusions_fragment(
    request: Request,
    _user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> Response:
    """The shared exclusion list, from GET /api/arkime/traffic/exclusions.

    Read only. Adding and removing an exclusion requires `security:read`
    and the page still posts to the API for those, so a reader is not shown
    a control that would answer 403.
    """
    try:
        payload = list_exclusions(user=_user, session=session)
        view = _exclusions_view(payload)
    except Exception:
        logger.exception("exclusions fragment could not be rendered")
        view = _exclusions_view(None)
    return render_view(request, EXCLUSIONS_FRAGMENT, view)


# ---------------------------------------------------------------------------
# AI review
# ---------------------------------------------------------------------------


def _review_view(payload: object, node: str, window: str) -> ReviewPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "reason": None, "needs_node": False,
                "node": node, "range": window, "analysis": None,
                "model": None}
    return {
        "failed": False, "reason": None, "needs_node": False,
        "node": node, "range": window,
        "analysis": _text(payload.get("analysis")),
        "model": _text(payload.get("model")),
    }


@router.post("/arkime-traffic/ai-review", response_class=HTMLResponse)
async def review_fragment(
    request: Request,
    node: str = Form(""),
    range: str = Form("24h"),
    _user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> Response:
    """Bob's read of one sensor node's traffic.

    The node is checked before the model is called, because an empty node
    is a request that should not have been made rather than a review that
    failed, and the two sentences send the reader to different places.

    The analysis comes back as markdown text in a hidden textarea for the
    page's own `safeMarkdown` (marked plus DOMPurify) to paint. ION ships
    no HTML sanitiser, `markdown.markdown` passes raw HTML and
    `javascript:` hrefs straight through, and this is model output, so
    rendering it here and marking it safe would be a scripting hole.
    template_render made the same call for the same reason.
    """
    name = node.strip()
    window = range.strip() or "24h"
    base: ReviewPanel = {"failed": False, "reason": None, "needs_node": True,
                         "node": None, "range": window, "analysis": None,
                         "model": None}
    if not name:
        return render_view(request, REVIEW_FRAGMENT, base)
    if window not in RANGES:
        bad = dict(base)
        bad.update(needs_node=False, failed=True, node=name, reason=(
            f"'{window}' is not a window this page can ask for. "
            "Use 24h, 7d or 30d."))
        return render_view(request, REVIEW_FRAGMENT, bad)

    from ion.web.arkime_traffic_analytics_api import AIReviewRequest

    try:
        payload = await traffic_ai_review(
            payload=AIReviewRequest(node=name, range=window),
            user=_user, session=session,
        )
        view = _review_view(payload, name, window)
    except HTTPException as exc:
        logger.info("traffic AI review fragment refused: HTTP %s",
                    exc.status_code)
        view = _review_view(None, name, window)
        view["reason"] = f"HTTP {exc.status_code}. {_detail(exc)}"
    except Exception:
        logger.exception("traffic AI review fragment could not be rendered")
        view = _review_view(None, name, window)
        view["reason"] = (
            "The request did not complete, so there is no analysis. This is "
            "not a clean bill of health for the node.")
    return render_view(request, REVIEW_FRAGMENT, view)
