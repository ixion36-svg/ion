"""Auto-case creation for alerts with Arkime PCAP capture data.

When an alert carries both ``network.community_id`` (the Zeek/Arkime flow
hash) and ``arkime_node`` (the capture node name), a case is automatically
created and PCAP analysis queued — no analyst action required.

Each pass:
  1. Fetches recent ES alerts via ``ElasticsearchService.get_alerts``.
  2. Filters to those with both ``network_community_id`` and ``arkime_node``.
  3. Excludes alert IDs already present in ``alert_triage`` (touched by an
     analyst or by a previous pass of this service).
  4. For each genuinely new alert: creates an ``AlertCase`` + ``AlertTriage``
     row and enqueues PCAP analysis via ``pcap_analysis_service``.

Environment variables:

* ``ION_ARKIME_AUTO_CASE_ENABLED``            (default ``true``)
* ``ION_ARKIME_AUTO_CASE_INTERVAL_MINUTES``   (default ``5``)
* ``ION_ARKIME_AUTO_CASE_SCAN_HOURS``         (default ``1``) — look-back window per pass
"""

import asyncio
import logging
import os
from typing import Optional

from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_DEFAULT_INTERVAL_MINUTES = 5.0
_DEFAULT_SCAN_HOURS = 1
_MIN_INTERVAL_SECONDS = 60


def _interval_seconds() -> int:
    raw = os.environ.get(
        "ION_ARKIME_AUTO_CASE_INTERVAL_MINUTES", str(_DEFAULT_INTERVAL_MINUTES)
    )
    try:
        minutes = float(raw)
    except (TypeError, ValueError):
        minutes = _DEFAULT_INTERVAL_MINUTES
    return max(_MIN_INTERVAL_SECONDS, int(minutes * 60))


def _scan_hours() -> int:
    raw = os.environ.get("ION_ARKIME_AUTO_CASE_SCAN_HOURS", str(_DEFAULT_SCAN_HOURS))
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return _DEFAULT_SCAN_HOURS


def _enabled() -> bool:
    val = os.environ.get("ION_ARKIME_AUTO_CASE_ENABLED", "true").strip().lower()
    return val not in ("false", "0", "no", "off", "")


async def _run_pass(engine: Engine) -> None:
    """One sweep: find new Arkime-bearing alerts, create cases."""
    try:
        from ion.models.alert_triage import AlertTriage
        from ion.services.ai_user import get_bob_user_id

        # NOTE: the factory lives in connectors.elasticsearch_connector, NOT
        # elasticsearch_service. Importing it from the latter raised ImportError
        # on every pass (caught below as "import failed"), so the auto-case loop
        # silently created nothing from v0.34.0 until v0.39.1. Pinned by test.
        from ion.services.connectors.elasticsearch_connector import (
            get_elasticsearch_service,
        )
        from ion.services.pcap_analysis_service import enqueue_pcap_analysis_for_case
        from ion.storage.database import get_session_factory
    except Exception as exc:
        logger.warning("arkime_auto_case: import failed: %s", exc)
        return

    # 1. Fetch recent alerts from ES.
    try:
        es = get_elasticsearch_service()
        if not es.is_configured:
            return
        alerts = await es.get_alerts(hours=_scan_hours(), limit=500, include_closed=False)
    except Exception as exc:
        logger.debug("arkime_auto_case: ES fetch failed: %s", exc)
        return

    # 2. Keep only alerts with both community_id and arkime_node.
    arkime_alerts = [
        a for a in alerts
        if a.network_community_id and a.arkime_node
    ]
    if not arkime_alerts:
        # Diagnostic funnel (v0.39.1): "no auto-cases" was previously silent,
        # giving no clue whether the cause was zero alerts, missing
        # community_id, or a missing/unrecognised Arkime node field. Log the
        # breakdown once per pass when there are alerts but none qualify.
        if alerts:
            with_cid = sum(1 for a in alerts if a.network_community_id)
            with_node = sum(1 for a in alerts if a.arkime_node)
            logger.info(
                "arkime_auto_case: %d alert(s) in last %dh — %d with community_id, "
                "%d with arkime_node, 0 with BOTH → no cases. (Need network.community_id "
                "AND a node field: `node` / `observer.name` / `arkime.node`.)",
                len(alerts), _scan_hours(), with_cid, with_node,
            )
        return

    alert_ids = [a.id for a in arkime_alerts]
    logger.info(
        "arkime_auto_case: %d of %d alert(s) carry Arkime PCAP linkage",
        len(arkime_alerts), len(alerts),
    )

    factory = get_session_factory(engine)
    session = factory()
    # v0.49.3: all sync work below (SQLAlchemy + the blocking Kibana HTTP in
    # _create_case_for_alert — up to 2 sync round-trips per alert, 5s timeout)
    # runs via asyncio.to_thread. This pass lives on the uvicorn event loop; a
    # slow Kibana used to freeze every request/SSE stream on the worker for up
    # to ~10s per new alert. The session is used from one call at a time, so
    # hopping it between worker threads is safe.
    try:
        # 3. Exclude alert IDs already recorded in alert_triage.
        def _already_triaged() -> set:
            return {
                row[0]
                for row in session.query(AlertTriage.es_alert_id).filter(
                    AlertTriage.es_alert_id.in_(alert_ids)
                ).all()
            }

        existing = await asyncio.to_thread(_already_triaged)
        new_alerts = [a for a in arkime_alerts if a.id not in existing]
        if not new_alerts:
            logger.info(
                "arkime_auto_case: all %d Arkime-linked alert(s) already have "
                "triage/cases — nothing new this pass", len(arkime_alerts),
            )
            return
        logger.info(
            "arkime_auto_case: creating %d new case(s) from Arkime-linked alerts",
            len(new_alerts),
        )

        bob_id = await asyncio.to_thread(get_bob_user_id, session)
        if not bob_id:
            logger.warning(
                "arkime_auto_case: Bob user not seeded; skipping pass"
            )
            return

        # 4. Create case + triage for each new alert.
        for alert in new_alerts:
            try:
                await asyncio.to_thread(
                    _create_case_for_alert,
                    session, alert, bob_id, enqueue_pcap_analysis_for_case,
                )
            except Exception as exc:
                await asyncio.to_thread(session.rollback)
                logger.warning(
                    "arkime_auto_case: failed to create case for alert %s: %s",
                    alert.id, exc,
                )
    finally:
        await asyncio.to_thread(session.close)


def _create_case_for_alert(session, alert, bob_id: int, enqueue_fn) -> None:
    """Create AlertCase + AlertTriage and enqueue PCAP for one alert."""
    from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
    from ion.services.case_numbering import assign_case_number

    node_label = f" [{alert.arkime_node}]" if alert.arkime_node else ""
    case = AlertCase(
        title=f"[Auto] {alert.title}{node_label}",
        description=(
            f"Automatically created from Arkime-captured alert {alert.id}. "
            f"PCAP analysis queued."
        ),
        status=AlertCaseStatus.OPEN,
        severity=alert.severity,
        created_by_id=bob_id,
        assigned_to_id=bob_id,
        source_alert_ids=[alert.id],
    )
    # Collision-free number from the DB-assigned id (was max(id)+1 — raced).
    case_number = assign_case_number(session, case)

    triage = AlertTriage(
        es_alert_id=alert.id,
        case_id=case.id,
        source_system=alert.source_system,
    )
    session.add(triage)
    session.commit()

    # Push the case to Kibana AND attach the source alert — mirroring the manual
    # Arkime-commit path (arkime_api.py) and the case grouper. Without this the
    # alert was never linked to the Kibana case on auto-create. (The case-close
    # path updates the alert's workflow_status in ES via a separate mechanism,
    # which is why closing the case worked while attach-on-create did not.)
    # Best-effort: a Kibana failure must never break the auto-case loop.
    try:
        from ion.services.kibana_sync_helpers import sync_new_case_to_kibana
        kibana_result = sync_new_case_to_kibana(
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=case.severity,
            affected_hosts=None,
            affected_users=None,
            evidence_summary=None,
            observables=None,
            alert_ids=[alert.id],
            triggered_rules=None,
        )
        if kibana_result:
            case.kibana_case_id = kibana_result.get("kibana_case_id")
            case.kibana_case_version = kibana_result.get("kibana_case_version")
            session.commit()
            logger.info(
                "arkime_auto_case: synced %s to Kibana case %s with alert %s attached",
                case_number, kibana_result.get("kibana_case_id"), alert.id,
            )
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning(
            "arkime_auto_case: Kibana sync/attach failed for %s: %s",
            case_number, exc,
        )
        try:
            session.rollback()
        except Exception:
            pass

    logger.info(
        "arkime_auto_case: created %s for alert %s (community_id=%s node=%s)",
        case_number, alert.id, alert.network_community_id, alert.arkime_node,
    )

    enqueue_fn(
        case_id=case.id,
        flows=[{
            "community_id": alert.network_community_id,
            "node_hint": alert.arkime_node,
            "alert_id": alert.id,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "alert_timestamp": (
                alert.timestamp.isoformat() if alert.timestamp else None
            ),
        }],
    )


async def _loop(engine: Engine) -> None:
    global _running
    interval = _interval_seconds()
    logger.info(
        "Arkime auto-case loop started; interval=%ds scan_hours=%d",
        interval, _scan_hours(),
    )
    while _running:
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        if not _running:
            break
        await _run_pass(engine)


def start_background_loop(engine: Engine) -> Optional[asyncio.Task]:
    """Start the Arkime auto-case loop. Idempotent."""
    global _task, _running
    if not _enabled():
        logger.info(
            "Arkime auto-case disabled (ION_ARKIME_AUTO_CASE_ENABLED=false)"
        )
        return None
    if _running:
        return _task
    _running = True
    _task = asyncio.create_task(_loop(engine))
    return _task


def stop_background_loop() -> None:
    """Cancel the loop. Used in tests."""
    global _task, _running
    _running = False
    if _task is not None:
        _task.cancel()
        _task = None
