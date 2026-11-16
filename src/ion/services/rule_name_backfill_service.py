"""Fill in the rule name on triage rows that were saved without one.

``AlertTriage.rule_name`` is a snapshot: Detection Health, DE Metrics and the
case rail read it instead of asking Elasticsearch per alert. About a dozen
code paths create a triage row, and most of them have only the alert id in
hand, so the row is saved with no name and every report buckets the alert as
``(unmapped)``. Rather than teach each path to look the name up, this loop
reconciles the table against Elasticsearch, which also repairs rows written
by older releases.

Rows whose alert Elasticsearch no longer holds stay empty and are asked for
again on the next pass: ``get_alerts_by_ids`` answers an outage and a missing
document the same way, so a row can never be marked as permanently unknown.
"""

import asyncio
import logging
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertTriage

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_FIRST_PASS_DELAY_SECONDS = 30
_INTERVAL_SECONDS = 15 * 60
_BATCH = 200


async def fill_missing_rule_names(session: Session, es, batch: int = _BATCH) -> int:
    """Copy rule names from Elasticsearch onto every triage row lacking one.

    Returns how many rows were filled. Arkime rows are skipped: their ids are
    ION-made markers, not Elasticsearch document ids.
    """
    filled = 0
    last_id = None
    while True:
        query = session.query(AlertTriage).filter(
            or_(AlertTriage.rule_name.is_(None), AlertTriage.rule_name == ""),
            or_(
                AlertTriage.source_system.is_(None),
                ~AlertTriage.source_system.like("arkime%"),
            ),
        )
        if last_id is not None:
            query = query.filter(AlertTriage.id < last_id)
        rows = query.order_by(AlertTriage.id.desc()).limit(batch).all()
        if not rows:
            return filled
        last_id = rows[-1].id

        alerts = await es.get_alerts_by_ids([r.es_alert_id for r in rows]) or []
        names = {a.id: a.rule_name for a in alerts if a.rule_name}
        for row in rows:
            name = names.get(row.es_alert_id)
            if name:
                row.rule_name = name
                filled += 1
        session.commit()


async def _loop(engine: Engine) -> None:
    from ion.services.elasticsearch_service import ElasticsearchService
    from ion.storage.database import get_session_factory

    delay = _FIRST_PASS_DELAY_SECONDS
    while _running:
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            break
        delay = _INTERVAL_SECONDS
        if not _running:
            break
        try:
            es = ElasticsearchService()
            if not es.is_configured:
                continue
            session = get_session_factory(engine)()
            try:
                filled = await fill_missing_rule_names(session, es)
                if filled:
                    logger.info("Rule-name backfill: named %d triage rows", filled)
            finally:
                session.close()
        except Exception as exc:
            logger.error("Rule-name backfill pass failed: %s", exc)


def start_background_loop(engine: Engine) -> Optional[asyncio.Task]:
    """Start the backfill task. A second call returns the running task."""
    global _task, _running
    if _running:
        return _task
    _running = True
    _task = asyncio.create_task(_loop(engine))
    return _task


def stop_background_loop() -> None:
    global _task, _running
    _running = False
    if _task is not None:
        _task.cancel()
        _task = None
