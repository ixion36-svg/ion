"""The Network Mapper / CMDB page: tiles, asset table, drawer and topology.

network_map.html built every one of those by concatenating strings and
writing them with innerHTML. The same reads now render here, one route per
read, because they are the four reads the page makes:

    GET /api/network-map/stats                alert:read
    GET /api/network-map/assets               alert:read
    GET /api/network-map/assets/{asset_id}    alert:read
    GET /api/network-map/subnets              alert:read

Every one of those is `alert:read` (network_map_api.py), so every fragment
here is `alert:read`. The page itself is weaker than that: /network-map
takes `require_page_auth` and no named permission, so a fragment copying
the *page* would be a softer way to read the estate's host inventory than
the JSON routes are. The endpoint is what a fragment mirrors, not the page.

POST /api/network-map/sync is `integration:manage` and has no fragment:
there is nothing to render, only a button that posts and then asks these
routes to read again. Mirroring it here would put an `integration:manage`
route in a module whose other four are reads.

`require_permission`, never `require_page_permission`: the page dependency
redirects to /login on an expired session and htmx would swap a password
box into the middle of the asset table.

What the JavaScript got wrong, as opposed to merely built badly:

  * Every "no data" sentence was also the failure sentence. A non-ok
    /assets response rendered "Error loading assets", but a thrown fetch
    rendered "Failed to load" and an ok response with a payload that was
    not a list rendered "No assets found. Run a sync or adjust filters.",
    which tells the reader to sync an estate ION never managed to read.
  * `d.assets || []` and `d.subnets || d` collapsed a refusal into an
    empty estate. A /subnets call that answered 403 fell through to
    `subnets = null`, which silently switched to grouping client-side, so
    a permission failure rendered as a topology built from a different
    query.
  * `$('results-count').textContent = d.total + ' asset'` printed
    "undefined assets" when total was missing, and the pager divided by a
    missing total to get `NaN` pages, which `pages <= 1` then swallowed
    into an empty pager.
  * `relTime` did `new Date(iso)` on `last_seen`. Those values are
    `isoformat()` of a naive column, and JavaScript parses a zoneless
    string as the viewer's local time, so every age on the page was wrong
    by the viewer's offset.
  * `a.event_count?.toLocaleString() || '—'` printed an em dash for an
    asset with a measured zero events, which is exactly the asset worth
    noticing.
  * The drawer's four enrichment fields were built with
    `${a.environment==='unknown'?'selected':''}`, so an asset whose
    environment is NULL in the database showed "Unknown" selected and
    saving the form wrote the string "unknown" over the null. The select
    now carries a distinct blank option for a value nobody has set.
  * The drawer's `title="${esc(a.last_index)}"` rendered the string
    "null" as the tooltip of a dash.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import age_label, plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

STATS = "_fragments/network_map_stats.html"
SYSTEMS = "_fragments/network_map_systems.html"
ASSETS = "_fragments/network_map_assets.html"
ASSET = "_fragments/network_map_asset.html"
TOPOLOGY = "_fragments/network_map_topology.html"

#: Every /api/network-map read requires it. See the module docstring for why
#: the page's own (absent) gate is not the one copied here.
ALERT_READ = "alert:read"

#: The page size the table paged by. `list_assets` defaults to 50; the page
#: asked for 200, so the argument is passed rather than left to the default.
PAGE_SIZE = 200

#: The enrichment selects' options, in the order the drawer showed them.
#: A blank is first and is not "unknown": an asset nobody has classified
#: and one somebody classified as unknown are different records, and the
#: old markup could not tell them apart.
ENVIRONMENTS = (
    ("", "Not set"),
    ("unknown", "Unknown"),
    ("prod", "Production"),
    ("staging", "Staging"),
    ("dev", "Development"),
)
CRITICALITIES = (
    ("", "Not set"),
    ("unknown", "Unknown"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
)

#: The criticality words the stylesheet paints, and the one a value it has
#: never seen falls back to. Returned as a word, never as a colour: the
#: sheet decides what critical looks like.
CRITICALITY_WORDS = ("critical", "high", "medium", "low", "unknown")
ENVIRONMENT_WORDS = ("prod", "staging", "dev", "unknown")


class Panel(TypedDict):
    """What every panel of this page carries.

    `view` is the discriminator each fragment switches on and `failed` is
    the read's outcome. `failed` is never inferred from an empty list: a
    panel ION could not read and a panel with nothing in it are different
    renders, and on this page the difference is between "we have no record
    of this estate" and "this estate has no hosts".
    """
    view: str
    failed: bool


class StatsPanel(Panel):
    total: Optional[int]
    seen_24h: Optional[int]
    total_ips: Optional[int]
    os_families: Optional[int]


class SystemsPanel(Panel):
    systems: Optional[list]
    selected: str


class AssetsPanel(Panel):
    rows: list
    total: Optional[int]
    page: int
    pages: Optional[int]
    page_size: int


class AssetPanel(Panel):
    found: bool
    asset_id: Optional[int]
    hostname: Optional[str]
    os: Optional[str]
    architecture: Optional[str]
    first_seen: Any
    last_seen: Any
    age: Optional[str]
    event_count: Optional[int]
    last_index: Optional[str]
    systems: list
    ips: list
    macs: list
    environment: str
    criticality: str
    owner: str
    notes: str
    environments: tuple
    criticalities: tuple


class TopologyPanel(Panel):
    subnets: Optional[list]


def _render(request: Request, view: Panel) -> HTMLResponse:
    """One panel, as markup or as the model itself.

    render_view answers JSON to a caller that asks for it, so each panel is
    a contract rather than a detail of one template. The whole context is
    the one object: a model the caller has to complete is not a contract,
    which is why the page number and the page size travel inside the view
    even though the route already knows them.
    """
    return render_view(request, _FRAGMENT_OF[view["view"]], view)


def _failed(view: str, **extra: Any) -> Panel:
    """The model for a panel whose read did not happen.

    One definition rather than the same two keys at six call sites.
    """
    panel: Panel = {"view": view, "failed": True}
    panel.update(extra)  # type: ignore[typeddict-item]
    return panel


def _number(value: object) -> Optional[int]:
    """A measured count, or None when there is not one.

    `bool` is a subclass of `int`, so a check that only rejects non-numbers
    turns True into 1. A float that is a whole number is accepted because
    `func.count` comes back as one on some drivers; a fractional value is
    not a count of anything.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _text(value: object) -> Optional[str]:
    """A display string, or None when there is nothing to show.

    `plain` first, because a SQLEnum member's str() on 3.12 is its repr.
    "0" is kept: it is a value. "" and None are not. A NULL column reaches
    here as None and leaves as None, where `esc(a.last_index)` turned it
    into the four-letter string "null" and put that in a tooltip.
    """
    value = plain(value)
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text or None


def _word(value: object, allowed: tuple[str, ...]) -> str:
    """One of the words the stylesheet paints, or "unknown".

    Returned as the semantic value. A hex or a `var(--x)` here would make
    every reader of this model inherit this theme's vocabulary, which is
    what `CRIT_CLS` in the template did.
    """
    text = _text(value)
    if text is None:
        return "unknown"
    lowered = text.lower()
    return lowered if lowered in allowed else "unknown"


def _systems(value: object) -> list:
    """The source systems recorded against an asset.

    Not `|| []`: the column is a JSON array and a row whose value is not
    one has no systems recorded rather than an empty set of them. Both
    render as nothing here, which is honest for a chip strip, but a
    non-string entry is dropped rather than stringified into "[object
    Object]".
    """
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        text = _text(item)
        if text is not None:
            out.append(text)
    return out


def _asset_row(raw: object) -> Optional[dict]:
    """One table row, or None for a payload entry that is not an asset."""
    if not isinstance(raw, dict):
        return None
    asset_id = _number(raw.get("id"))
    if asset_id is None:
        return None
    os_parts = [p for p in (_text(raw.get("os_name")), _text(raw.get("os_version")))
                if p is not None]
    return {
        "id": asset_id,
        "hostname": _text(raw.get("display_hostname")) or _text(raw.get("hostname")),
        "ip": _text(raw.get("primary_ip")),
        "os": " ".join(os_parts) if os_parts else None,
        "environment": _word(raw.get("environment"), ENVIRONMENT_WORDS),
        "criticality": _word(raw.get("criticality"), CRITICALITY_WORDS),
        "systems": _systems(raw.get("source_systems")),
        "last_seen": raw.get("last_seen"),
        # An age, not a wall-clock reading. A relative figure needs no
        # timezone, so computing it here is correct where rendering an
        # absolute time server-side would not be. None means no timestamp,
        # which the fragment says rather than printing "0m".
        "age": age_label(raw.get("last_seen")),
        "event_count": _number(raw.get("event_count")),
    }


def _host_card(raw: object) -> Optional[dict]:
    """One topology host card.

    /subnets names its columns differently from /assets: `hostname` and
    `ip` rather than `display_hostname` and `primary_ip`, and a single
    pre-joined `os`. The old renderer read both spellings from one object
    because it could not tell which endpoint had answered.
    """
    if not isinstance(raw, dict):
        return None
    host_id = _number(raw.get("id"))
    if host_id is None:
        return None
    return {
        "id": host_id,
        "hostname": _text(raw.get("hostname")),
        "ip": _text(raw.get("ip")),
        "os": _text(raw.get("os")),
        "criticality": _word(raw.get("criticality"), CRITICALITY_WORDS),
        "age": age_label(raw.get("last_seen")),
    }


def _subnet(raw: object, index: int) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    hosts = raw.get("hosts")
    cards = []
    if isinstance(hosts, list):
        cards = [c for c in (_host_card(h) for h in hosts) if c is not None]
    environments = []
    if isinstance(raw.get("environments"), list):
        for item in raw["environments"]:
            word = _text(item)
            if word is not None:
                environments.append(_word(word, ENVIRONMENT_WORDS))
    return {
        "index": index,
        "subnet": _text(raw.get("subnet")),
        "host_count": _number(raw.get("host_count")),
        "worst_criticality": _word(raw.get("worst_criticality"), CRITICALITY_WORDS),
        "environments": environments,
        "total_events": _number(raw.get("total_events")),
        "hosts": cards,
    }


def _stats_view(payload: object) -> StatsPanel:
    """The four tiles. Each figure is its own outcome.

    The JavaScript used `d.total_assets ?? '—'`, which is right, and then
    `Object.keys(d.os_breakdown || {}).length`, which is not: a missing
    breakdown became a measured zero OS families.
    """
    if not isinstance(payload, dict):
        return _failed("stats", total=None, seen_24h=None,  # type: ignore[return-value]
                       total_ips=None, os_families=None)
    breakdown = payload.get("os_breakdown")
    families = len(breakdown) if isinstance(breakdown, dict) else None
    view: StatsPanel = {
        "view": "stats", "failed": False,
        "total": _number(payload.get("total_assets")),
        "seen_24h": _number(payload.get("seen_24h")),
        "total_ips": _number(payload.get("total_ips")),
        "os_families": families,
    }
    return view


@router.get(
    "/network-map/stats",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def network_map_stats(
    request: Request,
    current_user: User = Depends(require_permission(ALERT_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The four summary tiles, from the body of GET /api/network-map/stats."""
    from ion.web.network_map_api import get_stats

    try:
        payload = get_stats(current_user=current_user, session=session)
    except Exception:
        logger.exception("network map stats fragment could not be rendered")
        return _render(request, _failed(
            "stats", total=None, seen_24h=None, total_ips=None, os_families=None))
    return _render(request, _stats_view(payload))


@router.get(
    "/network-map/systems",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def network_map_systems(
    request: Request,
    source_system: str = "",
    current_user: User = Depends(require_permission(ALERT_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The source-system filter, built from the same stats read.

    The select is rendered whole rather than having its options swapped in,
    and the current choice travels in the model, so a refresh after a sync
    does not silently move the reader back to All Systems.
    """
    from ion.web.network_map_api import get_stats

    selected = (source_system or "").strip()
    try:
        payload = get_stats(current_user=current_user, session=session)
    except Exception:
        logger.exception("network map systems fragment could not be rendered")
        return _render(request, _failed("systems", systems=None, selected=selected))
    found = payload.get("source_systems") if isinstance(payload, dict) else None
    if not isinstance(found, list):
        # Not an estate reporting from nowhere. With the list unread, "no
        # system reports into ION" is a claim this read did not make.
        return _render(request, _failed("systems", systems=None, selected=selected))
    view: SystemsPanel = {
        "view": "systems", "failed": False,
        "systems": [s for s in (_text(i) for i in found) if s is not None],
        "selected": selected,
    }
    return _render(request, view)


@router.get(
    "/network-map/assets",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def network_map_assets(
    request: Request,
    search: str = "",
    environment: str = "",
    criticality: str = "",
    source_system: str = "",
    last_seen_within: str = "",
    page: int = 0,
    current_user: User = Depends(require_permission(ALERT_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One page of the asset table, its pager and its result count.

    `list_assets` is the whole of GET /api/network-map/assets. A negative
    page is clamped rather than rejected: the pager never emits one, and a
    422 here would blank the table for a hand-typed URL.
    """
    from ion.web.network_map_api import list_assets

    page = max(0, page)
    try:
        payload = list_assets(
            search=search,
            os_filter="",
            environment=environment,
            criticality=criticality,
            source_system=source_system,
            last_seen_within=last_seen_within,
            archived=False,
            offset=page * PAGE_SIZE,
            limit=PAGE_SIZE,
            current_user=current_user,
            session=session,
        )
    except Exception:
        logger.exception("network map assets fragment could not be rendered")
        return _render(request, _failed(
            "assets", rows=[], total=None, page=page, pages=None,
            page_size=PAGE_SIZE))

    found = payload.get("assets") if isinstance(payload, dict) else None
    if not isinstance(found, list):
        return _render(request, _failed(
            "assets", rows=[], total=None, page=page, pages=None,
            page_size=PAGE_SIZE))

    total = _number(payload.get("total")) if "total" in payload else None
    # Pages only where there is a total to divide. The JavaScript computed
    # `Math.ceil(undefined / 200)`, which is NaN, and `NaN <= 1` is false,
    # so it rendered "Page 1 of NaN".
    pages = None if total is None else max(1, -(-total // PAGE_SIZE))
    view: AssetsPanel = {
        "view": "assets", "failed": False,
        "rows": [r for r in (_asset_row(a) for a in found) if r is not None],
        "total": total, "page": page, "pages": pages, "page_size": PAGE_SIZE,
    }
    return _render(request, view)


def _not_found(asset_id: Optional[int]) -> AssetPanel:
    """A drawer for an asset the read did not find.

    Answered 200 so htmx swaps it. A 404 would leave whichever asset the
    reader opened last in the drawer, under the new hostname.
    """
    panel: AssetPanel = _failed(  # type: ignore[assignment]
        "asset", found=False, asset_id=asset_id, hostname=None, os=None,
        architecture=None, first_seen=None, last_seen=None, age=None,
        event_count=None, last_index=None, systems=[], ips=[], macs=[],
        environment="", criticality="", owner="", notes="",
        environments=ENVIRONMENTS, criticalities=CRITICALITIES,
    )
    return panel


@router.get(
    "/network-map/assets/{asset_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def network_map_asset(
    request: Request,
    asset_id: int,
    current_user: User = Depends(require_permission(ALERT_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One asset's detail drawer, from GET /api/network-map/assets/{id}.

    The enrichment form is part of this fragment because only this read
    knows what is currently stored. Its Save button still posts to the
    JSON route: a PATCH is not a view and has no fragment here.
    """
    from ion.web.network_map_api import get_asset

    try:
        payload = get_asset(
            asset_id=asset_id, current_user=current_user, session=session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return _render(request, _not_found(asset_id))
        logger.warning("network map asset %s refused: %s", asset_id, exc.detail)
        return _render(request, _not_found(asset_id))
    except Exception:
        logger.exception("network map asset fragment could not be rendered")
        return _render(request, _not_found(asset_id))

    if not isinstance(payload, dict):
        return _render(request, _not_found(asset_id))

    os_parts = [p for p in (_text(payload.get("os_name")),
                            _text(payload.get("os_version"))) if p is not None]
    ips = []
    for row in (payload.get("ips") if isinstance(payload.get("ips"), list) else []):
        if not isinstance(row, dict):
            continue
        address = _text(row.get("ip"))
        if address is None:
            continue
        ips.append({
            "ip": address,
            "age": age_label(row.get("last_seen")),
            "event_count": _number(row.get("event_count")),
        })
    macs = []
    for row in (payload.get("macs") if isinstance(payload.get("macs"), list) else []):
        if isinstance(row, dict):
            mac = _text(row.get("mac"))
            if mac is not None:
                macs.append(mac)

    stored_env = _text(payload.get("environment"))
    stored_crit = _text(payload.get("criticality"))
    view: AssetPanel = {
        "view": "asset", "failed": False, "found": True,
        "asset_id": _number(payload.get("id")) or asset_id,
        "hostname": (_text(payload.get("display_hostname"))
                     or _text(payload.get("hostname"))),
        "os": " ".join(os_parts) if os_parts else None,
        "architecture": _text(payload.get("architecture")),
        "first_seen": payload.get("first_seen"),
        "last_seen": payload.get("last_seen"),
        "age": age_label(payload.get("last_seen")),
        "event_count": _number(payload.get("event_count")),
        "last_index": _text(payload.get("last_index")),
        "systems": _systems(payload.get("source_systems")),
        "ips": ips,
        "macs": macs,
        # The stored value, not a word from the display vocabulary: this
        # drives which option is selected, so coercing a null to "unknown"
        # here is what made Save write "unknown" over an unset column.
        "environment": stored_env or "",
        "criticality": stored_crit or "",
        "owner": _text(payload.get("owner")) or "",
        "notes": payload.get("notes") if isinstance(payload.get("notes"), str) else "",
        "environments": ENVIRONMENTS,
        "criticalities": CRITICALITIES,
    }
    return _render(request, view)


@router.get(
    "/network-map/topology",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def network_map_topology(
    request: Request,
    current_user: User = Depends(require_permission(ALERT_READ)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Assets grouped by /24, from GET /api/network-map/subnets.

    `list_subnets` is called directly, which retires the page's fallback
    path. That fallback fetched /assets and grouped in the browser whenever
    the subnets call was anything but ok, so a 403 rendered a topology
    built from a different query and nothing said so. There is one query
    now and a failed read says it failed.
    """
    from ion.web.network_map_api import list_subnets

    try:
        payload = list_subnets(current_user=current_user, session=session)
    except Exception:
        logger.exception("network map topology fragment could not be rendered")
        return _render(request, _failed("topology", subnets=None))
    found = payload.get("subnets") if isinstance(payload, dict) else None
    if not isinstance(found, list):
        return _render(request, _failed("topology", subnets=None))
    subnets = [s for s in (_subnet(raw, i) for i, raw in enumerate(found))
               if s is not None]
    # Largest first, the order the page sorted by. A subnet whose host
    # count did not read sorts last rather than as zero hosts.
    subnets.sort(key=lambda s: (s["host_count"] is None,
                                -(s["host_count"] or 0),
                                s["subnet"] or ""))
    for position, subnet in enumerate(subnets):
        subnet["index"] = position
    view: TopologyPanel = {
        "view": "topology", "failed": False, "subnets": subnets,
    }
    return _render(request, view)


#: Which template renders which panel. Declared after the routes so the
#: discriminator and the file it reaches are one mapping rather than a
#: `name=` argument repeated at six call sites, where one of them being
#: wrong renders another panel's markup against this panel's model.
_FRAGMENT_OF = {
    "stats": STATS,
    "systems": SYSTEMS,
    "assets": ASSETS,
    "asset": ASSET,
    "topology": TOPOLOGY,
}
