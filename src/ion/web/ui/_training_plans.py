"""Training plan reads, with the same permissions and scope as the JSON API."""
from __future__ import annotations

import logging
import math
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web import skills_api
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter()


class TrainingPlanItemsView(TypedDict):
    state: Literal['failed', 'empty', 'data']
    plan_id: int
    items: list[dict[str, Any]] | None


class TrainingForecastView(TypedDict):
    state: Literal['failed', 'empty', 'data']
    forecasts: list[dict[str, Any]] | None
    totals: dict[str, Any] | None
    by_employment_type: dict[str, Any] | None
    plan_count: int | None
    total_certs: int | None
    completion: int | None
    company_liability: float | None


def _liability(values: dict[str, Any] | None) -> float | None:
    if values is None or any(values.get(key) is None for key in ('company', 'split', 'tbd')):
        return None
    try:
        liability = values['company'] + values['split'] * .5 + values['tbd']
        return liability if math.isfinite(liability) else None
    except OverflowError:
        return None


def _valid_numbers(values: object, money: tuple[str, ...] = (), counts: tuple[str, ...] = ()) -> bool:
    if not isinstance(values, dict):
        return False
    for key in money + counts:
        value = values.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if (isinstance(value, float) and not math.isfinite(value)) or value < 0 or (key in counts and not isinstance(value, int)):
            return False
    return True


@router.get('/training/plans/{plan_id}/items', response_class=HTMLResponse)
def training_plan_items(request: Request, plan_id: int,
                        current_user: User = Depends(require_permission('alert:read')),
                        session: Session = Depends(get_db_session)):
    items = None
    try:
        plans = rows(skills_api.get_training_plans(current_user=current_user, session=session), 'plans')
        plan = next((p for p in plans if isinstance(p, dict) and p.get('id') == plan_id), None) if plans is not None else None
        items = rows(plan, 'items')
        if items is not None and not all(_valid_numbers(item, ('price',)) for item in items):
            items = None
    except Exception:
        logger.exception('Could not read training plan items')
    view: TrainingPlanItemsView = {
        'state': 'failed' if items is None else 'data' if items else 'empty',
        'plan_id': plan_id, 'items': items,
    }
    return render_view(request, '_fragments/training_plans_items.html', view)


@router.get('/training/forecast', response_class=HTMLResponse)
def training_forecast(request: Request,
                      current_user: User = Depends(require_permission('security:read')),
                      session: Session = Depends(get_db_session)):
    payload = None
    try:
        payload = skills_api.get_training_forecast(current_user=current_user, session=session)
    except Exception:
        logger.exception('Could not read training forecast')
    forecasts = rows(payload, 'forecasts')
    data = payload if isinstance(payload, dict) else {}
    totals = data.get('totals') if isinstance(data.get('totals'), dict) else None
    employment = data.get('by_employment_type') if isinstance(data.get('by_employment_type'), dict) else None
    valid = (
        forecasts is not None
        and all(_valid_numbers(f, ('total_cost', 'company_cost', 'self_cost'), ('item_count', 'completed_count')) for f in forecasts)
        and (data.get('totals') is None or _valid_numbers(data['totals'], ('total', 'company', 'self', 'split', 'tbd')))
        and (data.get('by_employment_type') is None or employment is not None and all(_valid_numbers(d, ('total', 'company', 'self', 'split', 'tbd'), ('headcount', 'certs')) for d in employment.values()))
        and _valid_numbers(data, counts=('plan_count',))
    )
    if not valid:
        forecasts, totals, employment = None, None, None
        data = {}
    elif employment is not None:
        employment = {kind: {**values, 'company_liability': _liability(values)} for kind, values in employment.items()}
    total_certs = sum(f['item_count'] for f in forecasts) if forecasts is not None and all(f.get('item_count') is not None for f in forecasts) else None
    completed = sum(f['completed_count'] for f in forecasts) if forecasts is not None and all(f.get('completed_count') is not None for f in forecasts) else None
    completion = (round(completed / total_certs * 100) if total_certs else 0) if total_certs is not None and completed is not None else None
    view: TrainingForecastView = {
        'state': 'failed' if forecasts is None else 'data' if forecasts else 'empty',
        'forecasts': forecasts, 'totals': totals, 'by_employment_type': employment,
        'plan_count': data.get('plan_count'), 'total_certs': total_certs,
        'completion': completion, 'company_liability': _liability(totals),
    }
    return render_view(request, '_fragments/training_plans_forecast.html', view)
