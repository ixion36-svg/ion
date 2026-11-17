"""Copy each triage row's rule identity from the alert Elasticsearch holds.

``AlertTriage`` snapshots which rule fired an alert: ``rule_name`` for the
pages, ``rule_id`` and ``rule_uuid`` for rule outcomes, which leave ION keyed
on the id. About a dozen code paths create a triage row and most have only the
alert id in hand, so this loop reconciles the table against Elasticsearch
instead of teaching each path to look the rule up. It also fills rows written
before the id columns existed.

A row is asked about once. ``rule_identity_checked_at`` records that
Elasticsearch answered, so a row whose alert has aged out keeps NULL ids and is
not asked again on every pass. The answer is only recorded when it is
definitive: ``find_alerts_by_ids`` raises for an outage or a partial-shard
answer, and the pass stops there with that batch unmarked, to be asked again.
"""

import asyncio
import logging
from datetime import datetime, timezone
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


def _fit(value: Optional[str], column) -> Optional[str]:
    return value[: column.type.length] if value else None


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def apply_alert_identity(row: AlertTriage, alert, checked_at: Optional[datetime] = None) -> None:
    """Record what Elasticsearch said about this row's rule, keeping saved values.

    ``alert`` is the Elasticsearch alert, or None when a definitive search did
    not find it. Only call this with an answer from Elasticsearch: the row is
    marked as checked, and a checked row is never asked about again.
    """
    if alert is not None:
        if not row.rule_name:
            row.rule_name = _fit(alert.rule_name, AlertTriage.rule_name)
        if not row.rule_id:
            row.rule_id = _fit(alert.rule_id, AlertTriage.rule_id)
        if not row.rule_uuid:
            row.rule_uuid = _fit(alert.rule_uuid, AlertTriage.rule_uuid)
    row.rule_identity_checked_at = checked_at or _now()


async def fill_rule_identity(session: Session, es, batch: int = _BATCH) -> int:
    """Fill rule name, id and uuid on every triage row not yet checked.

    Existing values are kept. Returns how many rows gained a rule id. Arkime
    rows are skipped: their ids are ION-made markers, not Elasticsearch
    document ids. Each batch commits on its own, so an interrupted run resumes
    where it stopped.
    """
    filled = 0
    last_id = None
    while True:
        query = session.query(AlertTriage).filter(
            AlertTriage.rule_identity_checked_at.is_(None),
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

        alerts = {
            a.id: a for a in await es.find_alerts_by_ids([r.es_alert_id for r in rows])
        }
        checked_at = _now()
        for row in rows:
            had_id = bool(row.rule_id)
            apply_alert_identity(row, alerts.get(row.es_alert_id), checked_at)
            filled += bool(row.rule_id) and not had_id
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
                filled = await fill_rule_identity(session, es)
                if filled:
                    logger.info("Rule-identity backfill: %d triage rows gained a rule id", filled)
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        except Exception as exc:
            logger.error("Rule-identity backfill pass failed: %s", exc)


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
