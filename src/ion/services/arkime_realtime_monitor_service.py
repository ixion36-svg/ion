"""Realtime Arkime IOC monitor.

Arkime keeps full PCAP only for a short retention window (≈3 days here) before
ageing down to metadata-only. This loop watches live traffic for known-bad
IPs while the capture is still pullable: each pass it loads ION's IOC IP set
(observables flagged is_ioc / is_watched / high-or-critical, or OpenCTI-
malicious) and asks Arkime whether any session in the recent window touched
one. A hit auto-creates a case wired to the session's ``communityId`` + node
and enqueues PCAP analysis — so the full capture is grabbed before it expires.

Dedup: a synthetic ``AlertTriage.es_alert_id = "rtmon:<node>:<communityId>"``
marks already-actioned flows so re-runs don't re-alert the same session.

Environment variables:
* ``ION_ARKIME_RTMON_ENABLED``           (default ``false`` — opt-in)
* ``ION_ARKIME_RTMON_INTERVAL_MINUTES``  (default ``10``)
* ``ION_ARKIME_RTMON_WINDOW_MINUTES``    (default ``20`` — overlaps interval, no gaps)
* ``ION_ARKIME_RTMON_MAX_CASES_PER_PASS``(default ``25`` — backstop)
"""

import asyncio
import logging
import os
from typing import Optional

from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_DEFAULT_INTERVAL_MINUTES = 10.0
_DEFAULT_WINDOW_MINUTES = 20
_DEFAULT_MAX_CASES = 25
_MIN_INTERVAL_SECONDS = 60


def _enabled() -> bool:
    val = os.environ.get("ION_ARKIME_RTMON_ENABLED", "false").strip().lower()
    return val in ("true", "1", "yes", "on")


def _interval_seconds() -> int:
    try:
        minutes = float(os.environ.get("ION_ARKIME_RTMON_INTERVAL_MINUTES", str(_DEFAULT_INTERVAL_MINUTES)))
    except (TypeError, ValueError):
        minutes = _DEFAULT_INTERVAL_MINUTES
    return max(_MIN_INTERVAL_SECONDS, int(minutes * 60))


def _window_minutes() -> int:
    try:
        return max(1, int(os.environ.get("ION_ARKIME_RTMON_WINDOW_MINUTES", str(_DEFAULT_WINDOW_MINUTES))))
    except (TypeError, ValueError):
        return _DEFAULT_WINDOW_MINUTES


def _max_cases() -> int:
    try:
        return max(1, int(os.environ.get("ION_ARKIME_RTMON_MAX_CASES_PER_PASS", str(_DEFAULT_MAX_CASES))))
    except (TypeError, ValueError):
        return _DEFAULT_MAX_CASES


def _load_ioc_ips(session) -> dict:
    """Map IOC IP value → {threat_level, source, label} for the active IOC set.

    Includes observables that are explicitly IOC/watched, high/critical threat
    level, or carry an OpenCTI 'malicious' enrichment. IP-typed only — that's
    what Arkime sessions can be matched on.
    """
    from sqlalchemy import or_

    from ion.models.observable import (
        Observable,
        ObservableEnrichment,
        ObservableType,
        ThreatLevel,
    )

    out: dict = {}
    try:
        rows = (
            session.query(Observable)
            .filter(Observable.type.in_([ObservableType.IPV4, ObservableType.IPV6]))
            .filter(Observable.is_whitelisted.is_(False))
            .filter(
                or_(
                    Observable.is_ioc.is_(True),
                    Observable.is_watched.is_(True),
                    Observable.threat_level.in_([ThreatLevel.HIGH, ThreatLevel.CRITICAL]),
                )
            )
            .all()
        )
        for o in rows:
            out[o.value] = {
                "threat_level": str(getattr(o, "threat_level", "") or "unknown"),
                "label": "IOC" if o.is_ioc else ("watched" if o.is_watched else "high-risk"),
                "observable_id": o.id,
            }
        # Also pull OpenCTI-malicious IPs not already captured above.
        mal = (
            session.query(Observable)
            .join(ObservableEnrichment, ObservableEnrichment.observable_id == Observable.id)
            .filter(Observable.type.in_([ObservableType.IPV4, ObservableType.IPV6]))
            .filter(Observable.is_whitelisted.is_(False))
            .filter(ObservableEnrichment.is_malicious.is_(True))
            .all()
        )
        for o in mal:
            out.setdefault(o.value, {
                "threat_level": "high",
                "label": "OpenCTI-malicious",
                "observable_id": o.id,
            })
    except Exception as exc:  # noqa: BLE001
        logger.debug("rtmon: IOC load failed: %s", exc)
    return out


def _severity_for(threat_level: str) -> str:
    tl = (threat_level or "").lower()
    if tl == "critical":
        return "critical"
    if tl == "high":
        return "high"
    return "medium"


async def _run_pass(engine: Engine) -> None:
    try:
        from ion.models.alert_triage import AlertTriage
        from ion.services.ai_user import get_bob_user_id
        from ion.services.arkime_service import ArkimeError, get_arkime_service
        from ion.services.pcap_analysis_service import enqueue_pcap_analysis_for_case
        from ion.storage.database import get_session_factory
    except Exception as exc:  # noqa: BLE001
        logger.warning("rtmon: import failed: %s", exc)
        return

    svc = get_arkime_service()
    if not svc.is_configured:
        return

    factory = get_session_factory(engine)
    session = factory()
    try:
        iocs = _load_ioc_ips(session)
        if not iocs:
            logger.debug("rtmon: no IOC IPs in the active set — nothing to watch")
            return
        try:
            sessions = await svc.find_recent_sessions_for_ips(
                list(iocs.keys()), window_minutes=_window_minutes(), limit=500
            )
        except ArkimeError as exc:
            logger.debug("rtmon: Arkime query failed: %s", exc)
            return
        if not sessions:
            return

        bob_id = get_bob_user_id(session)
        if not bob_id:
            logger.warning("rtmon: Bob user not seeded; skipping pass")
            return

        created = 0
        for s in sessions:
            if created >= _max_cases():
                logger.info("rtmon: hit max cases/pass (%d) — remaining flows next pass", _max_cases())
                break
            cid = s.get("communityId") or s.get("community_id")
            node = s.get("node")
            if not cid or not node:
                continue
            marker = f"rtmon:{node}:{cid}"
            if session.query(AlertTriage).filter(AlertTriage.es_alert_id == marker).first():
                continue  # already actioned this flow
            src = s.get("srcIp") or ""
            dst = s.get("dstIp") or ""
            hit_ip = src if src in iocs else (dst if dst in iocs else "")
            meta = iocs.get(hit_ip, {})
            try:
                _create_rtmon_case(
                    session, bob_id, marker, node, cid, src, dst, hit_ip, meta,
                    s.get("totBytes", 0), enqueue_pcap_analysis_for_case,
                )
                created += 1
            except Exception as exc:  # noqa: BLE001
                session.rollback()
                logger.warning("rtmon: failed to create case for flow %s: %s", marker, exc)
        if created:
            logger.info("rtmon: created %d IOC-traffic case(s) this pass", created)
    finally:
        session.close()


def _create_rtmon_case(
    session, bob_id, marker, node, cid, src, dst, hit_ip, meta, tot_bytes, enqueue_fn
) -> None:
    from ion.models.alert_triage import (
        AlertCase,
        AlertCaseStatus,
        AlertTriage,
        Note,
        NoteEntityType,
    )

    last_case = session.query(AlertCase).order_by(AlertCase.id.desc()).first()
    next_num = 1 if not last_case else last_case.id + 1
    case_number = f"CASE-{next_num:04d}"
    severity = _severity_for(meta.get("threat_level"))

    case = AlertCase(
        case_number=case_number,
        title=f"[RT-Netmon] Known-bad traffic with {hit_ip or 'IOC'} on {node}",
        description=(
            f"Realtime Arkime monitor observed live traffic involving IOC "
            f"`{hit_ip}` ({meta.get('label', 'IOC')}, threat={meta.get('threat_level')}). "
            f"Flow {src} → {dst} on node {node} (communityId {cid}). PCAP analysis "
            f"queued while the full capture is still in Arkime's retention window."
        ),
        status=AlertCaseStatus.OPEN,
        severity=severity,
        created_by_id=bob_id,
        assigned_to_id=bob_id,
        source_alert_ids=[],
    )
    session.add(case)
    session.flush()

    session.add(AlertTriage(es_alert_id=marker, case_id=case.id, source_system="arkime-rtmon"))
    session.add(Note(
        entity_type=NoteEntityType.CASE,
        entity_id=str(case.id),
        user_id=bob_id,
        content=(
            f"**Realtime IOC traffic match**\n\n"
            f"- IOC: `{hit_ip}` — {meta.get('label')} (threat: {meta.get('threat_level')})\n"
            f"- Flow: `{src}` → `{dst}`\n"
            f"- Node: `{node}`  ·  communityId: `{cid}`  ·  bytes: {tot_bytes}\n\n"
            f"Full PCAP queued for analysis — pull it before it ages to metadata-only."
        ),
    ))
    session.commit()

    logger.info("rtmon: created %s for IOC %s (flow %s→%s node=%s)", case_number, hit_ip, src, dst, node)
    enqueue_fn(
        case_id=case.id,
        flows=[{
            "community_id": cid,
            "node_hint": node,
            "alert_id": None,
            "source_ip": src,
            "destination_ip": dst,
            "alert_timestamp": None,
        }],
    )


async def _loop(engine: Engine) -> None:
    global _running
    interval = _interval_seconds()
    logger.info(
        "Arkime realtime IOC monitor started; interval=%ds window=%dm",
        interval, _window_minutes(),
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
    """Start the realtime IOC monitor. Opt-in; idempotent."""
    global _task, _running
    if not _enabled():
        logger.info("Arkime realtime IOC monitor disabled (ION_ARKIME_RTMON_ENABLED=false)")
        return None
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
