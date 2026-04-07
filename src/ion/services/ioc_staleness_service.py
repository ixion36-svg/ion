"""Track stale observables that need re-enrichment."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import func, case
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Graceful model imports — tables may not exist yet.
try:
    from ion.models.observable import Observable, ObservableEnrichment
except ImportError:
    Observable = None  # type: ignore[assignment,misc]
    ObservableEnrichment = None  # type: ignore[assignment,misc]

try:
    from ion.models.alert_triage import AlertCase, AlertCaseStatus
except ImportError:
    AlertCase = None  # type: ignore[assignment,misc]
    AlertCaseStatus = None  # type: ignore[assignment,misc]


def _empty_result() -> dict:
    return {
        "total_observables": 0,
        "stale_count": 0,
        "never_enriched_count": 0,
        "stale_iocs": [],
        "by_type": {},
        "by_threat_level": {},
    }


def get_stale_iocs(
    session: Session,
    stale_days: int = 30,
    limit: int = 100,
) -> dict:
    """Identify observables whose enrichment data is outdated or missing.

    Args:
        session: An active SQLAlchemy session.
        stale_days: Number of days after which an enrichment is
            considered stale.
        limit: Maximum number of stale IOCs to return.

    Returns:
        A dict with stale IOC details, counts by type/threat-level, and
        an indicator of whether the IOC is referenced in an open case.
    """

    if Observable is None or ObservableEnrichment is None:
        logger.warning("Observable models not available — returning empty result")
        return _empty_result()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=stale_days)

    try:
        total_observables = (
            session.query(func.count(Observable.id))
            .filter(Observable.is_whitelisted == False)  # noqa: E712
            .scalar()
        ) or 0

        # Subquery: latest enrichment date per observable
        latest_enrichment = (
            session.query(
                ObservableEnrichment.observable_id,
                func.max(ObservableEnrichment.enriched_at).label("last_enriched"),
            )
            .group_by(ObservableEnrichment.observable_id)
            .subquery("latest_enrichment")
        )

        # Main query: non-whitelisted observables left-joined with their
        # latest enrichment, filtering to stale or never-enriched.
        query = (
            session.query(
                Observable,
                latest_enrichment.c.last_enriched,
            )
            .outerjoin(
                latest_enrichment,
                Observable.id == latest_enrichment.c.observable_id,
            )
            .filter(Observable.is_whitelisted == False)  # noqa: E712
            .filter(
                (latest_enrichment.c.last_enriched == None)  # noqa: E711  — never enriched
                | (latest_enrichment.c.last_enriched < cutoff)
            )
            .order_by(
                # Never-enriched first, then oldest enrichment
                case(
                    (latest_enrichment.c.last_enriched == None, 0),  # noqa: E711
                    else_=1,
                ),
                latest_enrichment.c.last_enriched.asc(),
            )
            .limit(limit)
        )

        rows = query.all()

    except Exception:
        logger.exception("Failed to query stale observables")
        return _empty_result()

    # -- Determine which observable IDs appear in open cases -------------------
    open_case_observable_ids: set[int] = set()
    if AlertCase is not None and AlertCaseStatus is not None:
        try:
            open_cases = (
                session.query(AlertCase.observables)
                .filter(AlertCase.status.in_([
                    AlertCaseStatus.OPEN.value,
                    AlertCaseStatus.ACKNOWLEDGED.value,
                ]))
                .filter(AlertCase.observables != None)  # noqa: E711
                .all()
            )
            for (obs_json,) in open_cases:
                if isinstance(obs_json, list):
                    for entry in obs_json:
                        if isinstance(entry, dict) and "id" in entry:
                            open_case_observable_ids.add(entry["id"])
                        elif isinstance(entry, int):
                            open_case_observable_ids.add(entry)
        except Exception:
            logger.debug("Could not check open-case observables", exc_info=True)

    # -- Build result lists ----------------------------------------------------
    stale_iocs: list[dict] = []
    never_enriched_count = 0
    by_type: dict[str, int] = {}
    by_threat_level: dict[str, int] = {}

    for obs, last_enriched in rows:
        if last_enriched is None:
            days_stale = (now - obs.created_at.replace(tzinfo=timezone.utc)).days if obs.created_at else stale_days
            never_enriched_count += 1
        else:
            last_enriched_aware = last_enriched.replace(tzinfo=timezone.utc) if last_enriched.tzinfo is None else last_enriched
            days_stale = (now - last_enriched_aware).days

        obs_type = obs.type.value if hasattr(obs.type, "value") else str(obs.type)
        threat = obs.threat_level.value if hasattr(obs.threat_level, "value") else str(obs.threat_level)

        stale_iocs.append({
            "id": obs.id,
            "value": obs.value,
            "type": obs_type,
            "threat_level": threat,
            "last_enriched": last_enriched.isoformat() if last_enriched else None,
            "days_stale": days_stale,
            "sighting_count": obs.sighting_count,
            "in_open_case": obs.id in open_case_observable_ids,
        })

        by_type[obs_type] = by_type.get(obs_type, 0) + 1
        by_threat_level[threat] = by_threat_level.get(threat, 0) + 1

    # Sort by days_stale descending
    stale_iocs.sort(key=lambda x: x["days_stale"], reverse=True)

    return {
        "total_observables": total_observables,
        "stale_count": len(stale_iocs),
        "never_enriched_count": never_enriched_count,
        "stale_iocs": stale_iocs,
        "by_type": by_type,
        "by_threat_level": by_threat_level,
    }
