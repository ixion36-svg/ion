"""The one AlertCase metrics computation (route audit phase 5).

Before this module, "cases opened / closed / FP rate / average MTTR" were
computed independently in **four** places — `soc_health_service`,
`executive_report_service`, `analyst_efficiency_service` and `analytics_engine`
— behind identically-worded headings on adjacent nav items.

MTTR was the same formula four times with different rounding: pure duplication.

**FP rate genuinely diverged**, and that is why two pages could show a different
"FP Rate" for the same window:

- `fp / closed` — of *everything* we closed, what fraction was a false positive.
  Dilutes with administrative closures (duplicate, not_applicable,
  insufficient_data), so it reads lower.
- `fp / (tp + fp)` — of the cases where an analyst actually made a
  threat/not-threat call, what fraction was a false positive. Excludes
  administrative noise, so it reads higher.

Both are legitimate; neither is "the" FP rate. This module computes both and
names them distinctly (`fp_rate_of_closed` vs `fp_rate_of_dispositions`) so a
caller has to say which one it means, and two callers asking the same question
can no longer get different answers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus

# Closure reasons that represent a real threat/not-threat judgement, as opposed
# to an administrative disposal. Used for the dispositions denominator.
_TRUE_POSITIVE = "true_positive"
_FALSE_POSITIVE = "false_positive"


def _round(value: Optional[float], digits: int = 1) -> Optional[float]:
    return round(value, digits) if value is not None else None


def case_metrics(
    session: Session,
    since: datetime,
    until: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Canonical AlertCase metrics for a window.

    ``since``/``until`` bound `closed_at` for closure-derived figures and
    `created_at` for the opened count. ``open_backlog`` is a point-in-time count
    and deliberately ignores the window.

    Returns a dict with, among others:
        opened, closed, closure_reasons, tp_count, fp_count,
        fp_rate_of_closed, fp_rate_of_dispositions, avg_mttr_hours,
        closure_rate_pct, open_backlog
    """
    closed_filters = [AlertCase.closed_at.isnot(None), AlertCase.closed_at >= since]
    if until is not None:
        closed_filters.append(AlertCase.closed_at <= until)

    closed_rows = session.execute(
        select(
            AlertCase.closure_reason,
            AlertCase.created_at,
            AlertCase.closed_at,
        ).where(*closed_filters)
    ).all()

    opened_filters = [AlertCase.created_at >= since]
    if until is not None:
        opened_filters.append(AlertCase.created_at <= until)
    opened = session.execute(
        select(func.count(AlertCase.id)).where(*opened_filters)
    ).scalar() or 0

    closure_reasons: Dict[str, int] = {}
    mttr_hours: list[float] = []
    for reason, created_at, closed_at in closed_rows:
        key = reason or "unspecified"
        closure_reasons[key] = closure_reasons.get(key, 0) + 1
        if created_at and closed_at:
            mttr_hours.append((closed_at - created_at).total_seconds() / 3600.0)

    closed = len(closed_rows)
    fp_count = closure_reasons.get(_FALSE_POSITIVE, 0)
    tp_count = closure_reasons.get(_TRUE_POSITIVE, 0)
    dispositions = tp_count + fp_count

    open_backlog = session.execute(
        select(func.count(AlertCase.id)).where(
            AlertCase.status != AlertCaseStatus.CLOSED
        )
    ).scalar() or 0

    return {
        "opened": opened,
        "closed": closed,
        "closure_reasons": closure_reasons,
        "tp_count": tp_count,
        "fp_count": fp_count,
        "dispositions": dispositions,
        # See the module docstring — these are different questions.
        "fp_rate_of_closed": _round(fp_count / closed * 100) if closed else None,
        "fp_rate_of_dispositions": (
            _round(fp_count / dispositions * 100) if dispositions else None
        ),
        "avg_mttr_hours": (
            _round(sum(mttr_hours) / len(mttr_hours)) if mttr_hours else None
        ),
        "closure_rate_pct": _round(closed / opened * 100) if opened else None,
        "open_backlog": open_backlog,
        "mttr_sample_size": len(mttr_hours),
    }
