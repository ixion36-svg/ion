"""Observable list, detail and watchlist read panels."""

from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import observable_api as api
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)
PERMISSION = require_permission("observable:read")
router = APIRouter()
State = Literal["failed", "empty", "data"]


class CollectionPanel(TypedDict):
    state: State
    items: list[dict[str, Any]] | None
    total: int | None
    page: int
    pages: int | None
    can_update: bool
    can_enrich: bool


class DetailPanel(TypedDict):
    state: State
    observable: dict[str, Any] | None
    alerts: list[dict[str, Any]] | None
    cases: list[dict[str, Any]] | None
    co_occurring: list[dict[str, Any]] | None
    can_update: bool
    can_enrich: bool


class StatsPanel(TypedDict):
    state: State
    figures: dict[str, int | None]


class CountPanel(TypedDict):
    state: State
    total: int | None


def read(handler, **kwargs):
    try:
        value = handler(**kwargs)
        return value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    except Exception:
        logger.exception("Observable panel read failed")
        return None


def records(payload, key):
    result = rows(payload, key)
    if result is None:
        return None
    output = []
    for item in result:
        item = item.model_dump(mode="json") if hasattr(item, "model_dump") else item
        if not isinstance(item, dict):
            return None
        output.append(item)
    return output


def number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def collection(payload, key, user, limit=50, offset=0):
    items = records(payload, key)
    total = number(payload.get("total")) if isinstance(payload, dict) else None
    view: CollectionPanel = {
        "state": "failed" if items is None else "data" if items else "empty",
        "items": items,
        "total": total,
        "page": offset // limit + 1,
        "pages": (total + limit - 1) // limit if total is not None else None,
        "can_update": user.has_permission("observable:update"),
        "can_enrich": user.has_permission("observable:enrich"),
    }
    return view


@router.get("/observables/list", response_class=HTMLResponse)
def observable_list(
    request: Request,
    query: str | None = None,
    type: str | None = None,
    threat_level: str | None = None,
    is_whitelisted: bool | None = None,
    is_enriched: bool | None = None,
    include_ignored: bool = False,
    only_ignored: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user=Depends(PERMISSION),
):
    payload = read(
        api.search_observables,
        query=query,
        type=type,
        threat_level=threat_level,
        is_whitelisted=is_whitelisted,
        is_enriched=is_enriched,
        include_ignored=include_ignored,
        only_ignored=only_ignored,
        limit=limit,
        offset=offset,
        session=session,
        user=user,
    )
    view: CollectionPanel = collection(payload, "observables", user, limit, offset)
    return render_view(request, "_fragments/observables_list.html", view)


@router.get("/observables/watchlist", response_class=HTMLResponse)
def watchlist(request: Request, session: Session = Depends(get_db_session), user=Depends(PERMISSION)):
    payload = read(api.get_watchlist, limit=100, offset=0, session=session, user=user)
    view: CollectionPanel = collection(payload, "items", user, 100)
    return render_view(request, "_fragments/observables_watchlist.html", view)


@router.get("/observables/watchlist/alerts", response_class=HTMLResponse)
def watchlist_alerts(request: Request, is_read: bool | None = None, session: Session = Depends(get_db_session), user=Depends(PERMISSION)):
    payload = read(api.get_watchlist_alerts, is_read=is_read, limit=50, offset=0, session=session, user=user)
    view: CollectionPanel = collection(payload, "items", user)
    return render_view(request, "_fragments/observables_watchlist_alerts.html", view)


@router.get("/observables/stats", response_class=HTMLResponse)
def stats(request: Request, session: Session = Depends(get_db_session), user=Depends(PERMISSION)):
    payload = read(api.get_observable_stats, session=session, user=user)
    data = payload if isinstance(payload, dict) else {}
    figures = {key: number(data.get(key)) for key in ("total", "enriched")}
    for name, group, keys in [("ips", "by_type", ("ipv4", "ipv6")), ("domains", "by_type", ("domain", "hostname")), ("critical", "by_threat_level", ("critical", "high"))]:
        values = data.get(group)
        counts = [number(values.get(key)) for key in keys] if isinstance(values, dict) else [None]
        figures[name] = sum(counts) if all(v is not None for v in counts) else None
    view: StatsPanel = {"state": "data" if isinstance(payload, dict) else "failed", "figures": figures}
    return render_view(request, "_fragments/observables_stats.html", view)


@router.get("/observables/watched-count", response_class=HTMLResponse)
def watched_count(request: Request, session: Session = Depends(get_db_session), user=Depends(PERMISSION)):
    payload = read(api.get_watchlist, limit=1, offset=0, session=session, user=user)
    total = number(payload.get("total")) if isinstance(payload, dict) else None
    view: CountPanel = {"state": "failed" if total is None else "data" if total else "empty", "total": total}
    return render_view(request, "_fragments/observables_watched_count.html", view)


@router.get("/observables/watchlist/banner", response_class=HTMLResponse)
def watchlist_banner(request: Request, session: Session = Depends(get_db_session), user=Depends(PERMISSION)):
    payload = read(api.get_watchlist_alerts, is_read=False, limit=1, offset=0, session=session, user=user)
    total = number(payload.get("total")) if isinstance(payload, dict) else None
    view: CountPanel = {"state": "failed" if total is None else "data" if total else "empty", "total": total}
    return render_view(request, "_fragments/observables_watchlist_banner.html", view)


@router.get("/observables/{observable_id}/detail", response_class=HTMLResponse)
def detail(request: Request, observable_id: int, session: Session = Depends(get_db_session), user=Depends(PERMISSION)):
    obs = read(api.get_observable, observable_id=observable_id, session=session, user=user)
    obs = obs if isinstance(obs, dict) and obs.get("id") is not None else None
    related = {}
    for key, handler in [("alerts", api.get_observable_alerts), ("cases", api.get_observable_cases), ("co_occurring", api.get_co_occurring_observables)]:
        related[key] = records(read(handler, observable_id=observable_id, limit=10, session=session, user=user), key) if obs is not None else None
    view: DetailPanel = {
        "state": "data" if obs is not None else "failed",
        "observable": obs,
        "alerts": related["alerts"],
        "cases": related["cases"],
        "co_occurring": related["co_occurring"],
        "can_update": user.has_permission("observable:update"),
        "can_enrich": user.has_permission("observable:enrich"),
    }
    return render_view(request, "_fragments/observables_detail.html", view)
