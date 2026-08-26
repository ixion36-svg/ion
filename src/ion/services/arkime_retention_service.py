"""Arkime PCAP-retention awareness — analysis-before-expiry rescue.

ION never stores raw PCAP. The durable record of a capture is the analysis
output (notes, findings, observables); the bytes live only inside Arkime's
retention window (≈3 days on typical deployments). That makes one failure mode
expensive: an open case whose PCAP analysis never completed — a transient
Arkime outage at enqueue time, a dead queue worker — silently loses its
packet-level evidence when the capture ages out.

This loop closes that gap without storing a byte:

1. Ask Arkime for its retention horizon (oldest available session, per node
   and cluster-wide — :meth:`ArkimeService.get_retention_horizons`).
2. Find OPEN cases with an Arkime linkage whose traffic is inside the closing
   margin and whose PCAP analysis is missing or failed:
   * RTMON cases (``AlertTriage.source_system == 'arkime-rtmon'``) — the flow
     (communityId + node) is recoverable from the triage marker, so the
     analysis is re-enqueued immediately.
   * Cases with a "PCAP download failed" analysis note — the communityId is
     recoverable from the note heading, so the analysis is re-enqueued.
   * Auto-created Arkime cases (``[Auto]`` title) with no analysis note at
     all — the flow is not recoverable cheaply, so the case gets a warning
     note pointing the analyst at the alert's Arkime workspace.
3. Post an attributed note describing what happened (synced to Kibana), and
   mark the case with a ``retention:<case_id>`` triage marker so it is only
   ever rescued once.
4. Reconcile ION-submitted hunt jobs against the viewer
   (:func:`arkime_hunt_service.refresh_hunts`) — piggybacked here so hunts
   don't need their own background loop.

An unknown horizon (Arkime unreachable, empty cluster) skips the pass —
"unknown" must never be read as "expired".

Environment variables:
* ``ION_ARKIME_RETENTION_ENABLED``            (default ``true``)
* ``ION_ARKIME_RETENTION_INTERVAL_MINUTES``   (default ``60``)
* ``ION_ARKIME_RETENTION_MARGIN_HOURS``       (default ``12``)
* ``ION_ARKIME_RETENTION_MAX_RESCUES_PER_PASS`` (default ``10``)
"""

import asyncio
import logging
import os
import re
from datetime import timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_MIN_INTERVAL_SECONDS = 300

# Heading emitted by pcap_analysis_service._render_pcap_markdown — the
# communityId recovery below breaks if that format changes. The capture group
# is restricted to the Community ID charset (version:base64) on purpose: note
# content is analyst-writable, and anything recovered here ends up inside an
# Arkime expression.
_NOTE_CID_RE = re.compile(r"`community_id`\s*=\s*`([A-Za-z0-9+/=:_.-]+)`")
_FAILED_MARKER = "PCAP download failed"
_ANALYSIS_HEADING = "PCAP auto-analysis"


def _flag(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on")


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _enabled() -> bool:
    return _flag("ION_ARKIME_RETENTION_ENABLED", True)


def _interval_seconds() -> int:
    minutes = _int_env("ION_ARKIME_RETENTION_INTERVAL_MINUTES", 60)
    return max(_MIN_INTERVAL_SECONDS, minutes * 60)


def _margin_seconds() -> int:
    return _int_env("ION_ARKIME_RETENTION_MARGIN_HOURS", 12) * 3600


def _max_rescues() -> int:
    return _int_env("ION_ARKIME_RETENTION_MAX_RESCUES_PER_PASS", 10)


def parse_rtmon_marker_flow(marker: str) -> Optional[Dict[str, str]]:
    """Recover ``{node, community_id}`` from a per-session RTMON marker
    (``rtmon:<detector>:<node>:<communityId>``). Beacon markers are tuple-
    scoped (``rtmon:beacon:<src>:<dst>:<port>`` — no communityId) and return
    None; a failed beacon-case analysis is recovered via its note instead.
    """
    parts = (marker or "").split(":", 3)
    if len(parts) != 4 or parts[0] != "rtmon" or parts[1] == "beacon":
        return None
    node, cid = parts[2], parts[3]
    if not node or not cid:
        return None
    return {"node": node, "community_id": cid}


def note_cids(notes: List[str]) -> Dict[str, bool]:
    """Map communityId → analysis-completed for a case's analysis notes.

    A note both mentioning a communityId and carrying the download-failed
    marker counts as NOT completed (retryable); any clean analysis note for
    the same communityId wins.
    """
    out: Dict[str, bool] = {}
    for content in notes:
        if _ANALYSIS_HEADING not in (content or ""):
            continue
        m = _NOTE_CID_RE.search(content)
        if not m:
            continue
        cid = m.group(1)
        completed = _FAILED_MARKER not in content
        out[cid] = out.get(cid, False) or completed
    return out


def _case_epoch(case) -> Optional[float]:
    created = getattr(case, "created_at", None)
    if created is None:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created.timestamp()


def _horizon_for(horizons: Dict[str, int], node: Optional[str]) -> Optional[int]:
    if node and node in horizons:
        return horizons[node]
    return horizons.get("*")


async def _run_pass(engine: Engine) -> None:
    try:
        from ion.models.alert_triage import (
            AlertCase,
            AlertCaseStatus,
            AlertTriage,
            Note,
            NoteEntityType,
        )
        from ion.services.ai_user import get_bob_user_id
        from ion.services.arkime_service import ArkimeError, get_arkime_service
        from ion.services.kibana_sync_helpers import sync_note_to_kibana
        from ion.services.pcap_analysis_service import enqueue_pcap_analysis_for_case
        from ion.storage.database import get_session_factory
    except Exception as exc:  # noqa: BLE001
        logger.warning("arkime_retention: import failed: %s", exc)
        return

    svc = get_arkime_service()
    if not svc.is_configured:
        return
    try:
        horizons = await svc.get_retention_horizons()
    except ArkimeError as exc:
        logger.debug("arkime_retention: horizon query failed: %s", exc)
        return
    if not horizons:
        return  # horizon unknown — never treat as "everything expired"

    margin = _margin_seconds()
    factory = get_session_factory(engine)
    session = factory()
    # Sync SQLAlchemy work hops through asyncio.to_thread — this pass lives on
    # the uvicorn event loop (same rule as the other two Arkime loops).
    try:
        # Piggybacked hunt reconciliation — hunts share this loop rather than
        # getting a fourth Arkime background task.
        try:
            from ion.services.arkime_hunt_service import refresh_hunts
            await refresh_hunts(session, svc)
        except Exception as exc:  # noqa: BLE001
            logger.debug("arkime_retention: hunt refresh failed: %s", exc)

        def _candidates() -> List[Dict[str, Any]]:
            """Open Arkime-linked cases + their triage markers and notes."""
            rows = (
                session.query(AlertCase, AlertTriage.es_alert_id)
                .join(AlertTriage, AlertTriage.case_id == AlertCase.id)
                .filter(AlertCase.status == AlertCaseStatus.OPEN)
                .filter(AlertTriage.source_system == "arkime-rtmon")
                .all()
            )
            by_case: Dict[int, Dict[str, Any]] = {}
            for case, marker in rows:
                entry = by_case.setdefault(case.id, {"case": case, "markers": []})
                entry["markers"].append(marker or "")

            auto_cases = (
                session.query(AlertCase)
                .filter(AlertCase.status == AlertCaseStatus.OPEN)
                .filter(AlertCase.title.like("[Auto]%"))
                .all()
            )
            for case in auto_cases:
                by_case.setdefault(case.id, {"case": case, "markers": []})

            case_ids = list(by_case)
            if not case_ids:
                return []
            rescued = {
                m for (m,) in session.query(AlertTriage.es_alert_id)
                .filter(AlertTriage.es_alert_id.in_(
                    [f"retention:{cid}" for cid in case_ids]
                ))
                .all()
            }
            notes = (
                session.query(Note.entity_id, Note.content)
                .filter(Note.entity_type == NoteEntityType.CASE)
                .filter(Note.entity_id.in_([str(cid) for cid in case_ids]))
                .all()
            )
            notes_by_case: Dict[str, List[str]] = {}
            for entity_id, content in notes:
                notes_by_case.setdefault(entity_id, []).append(content or "")

            out: List[Dict[str, Any]] = []
            for cid, entry in by_case.items():
                if f"retention:{cid}" in rescued:
                    continue
                entry["notes"] = notes_by_case.get(str(cid), [])
                out.append(entry)
            return out

        candidates = await asyncio.to_thread(_candidates)
        if not candidates:
            return

        bob_id = await asyncio.to_thread(get_bob_user_id, session)
        if not bob_id:
            logger.warning("arkime_retention: Bob user not seeded; skipping pass")
            return

        rescued_count = 0
        for entry in candidates:
            if rescued_count >= _max_rescues():
                logger.info(
                    "arkime_retention: hit max rescues/pass (%d) — rest next pass",
                    _max_rescues(),
                )
                break
            case = entry["case"]
            case_epoch = _case_epoch(case)
            if case_epoch is None:
                continue

            # Flow recovery: rtmon markers first, then failed-note communityIds.
            flows: List[Dict[str, Any]] = []
            marker_node: Optional[str] = None
            cid_state = note_cids(entry.get("notes", []))
            for marker in entry["markers"]:
                flow = parse_rtmon_marker_flow(marker)
                if not flow:
                    continue
                marker_node = marker_node or flow["node"]
                if cid_state.get(flow["community_id"]) is True:
                    continue  # completed analysis exists for this flow
                flows.append({
                    "community_id": flow["community_id"],
                    "node_hint": flow["node"],
                    "alert_id": None,
                    "source_ip": None,
                    "destination_ip": None,
                    "alert_timestamp": None,
                })
            for note_cid, completed in cid_state.items():
                if completed or any(f["community_id"] == note_cid for f in flows):
                    continue
                flows.append({
                    "community_id": note_cid,
                    "node_hint": marker_node,
                    "alert_id": None,
                    "source_ip": None,
                    "destination_ip": None,
                    "alert_timestamp": None,
                })

            has_completed_analysis = any(cid_state.values())
            if not flows and has_completed_analysis:
                continue  # nothing missing — case is fully analysed

            horizon = _horizon_for(horizons, marker_node)
            if horizon is None or case_epoch > horizon + margin:
                continue  # capture comfortably inside retention — check later

            expired = case_epoch < horizon
            window_txt = (
                "has likely already aged out of Arkime's PCAP retention"
                if expired
                else "is about to age out of Arkime's PCAP retention"
            )
            if flows:
                action_txt = (
                    f"Re-queued PCAP analysis for {len(flows)} flow(s) now — "
                    "the earlier analysis is missing or failed."
                )
            else:
                action_txt = (
                    "The flow reference is not recoverable automatically — "
                    "open the source alert's Arkime workspace to pull the "
                    "capture manually while it lasts."
                )
            content = (
                "**PCAP retention warning**\n\n"
                f"The capture behind this case {window_txt} "
                f"(node horizon: {marker_node or 'cluster'}). {action_txt}"
            )

            def _persist(case=case, content=content) -> None:
                session.add(AlertTriage(
                    es_alert_id=f"retention:{case.id}",
                    case_id=case.id,
                    source_system="arkime-retention",
                ))
                session.add(Note(
                    entity_type=NoteEntityType.CASE,
                    entity_id=str(case.id),
                    user_id=bob_id,
                    content=content,
                ))
                session.commit()

            try:
                await asyncio.to_thread(_persist)
            except Exception as exc:  # noqa: BLE001
                await asyncio.to_thread(session.rollback)
                logger.warning(
                    "arkime_retention: rescue persist failed for case %s: %s",
                    case.id, exc,
                )
                continue

            # Case is already Kibana-linked by its creator — new notes must be
            # pushed explicitly (the export loop only carries notes at
            # case-creation time).
            if case.kibana_case_id:
                await asyncio.to_thread(
                    sync_note_to_kibana, case.kibana_case_id, "Bob", content
                )
            if flows:
                enqueue_pcap_analysis_for_case(case_id=case.id, flows=flows)
            rescued_count += 1
            logger.info(
                "arkime_retention: %s case %s (%d flow(s) re-queued)",
                "warned" if not flows else "rescued", case.id, len(flows),
            )
        if rescued_count:
            logger.info("arkime_retention: acted on %d case(s) this pass", rescued_count)
    finally:
        await asyncio.to_thread(session.close)


async def _loop(engine: Engine) -> None:
    global _running
    interval = _interval_seconds()
    logger.info(
        "Arkime retention-awareness loop started; interval=%ds margin=%dh",
        interval, _margin_seconds() // 3600,
    )
    while _running:
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        if not _running:
            break
        try:
            await _run_pass(engine)
        except Exception as exc:  # noqa: BLE001
            logger.warning("arkime_retention: pass raised: %s", exc)


def start_background_loop(engine: Engine) -> Optional[asyncio.Task]:
    """Start the retention-awareness loop. Idempotent."""
    global _task, _running
    if not _enabled():
        logger.info(
            "Arkime retention-awareness loop disabled (ION_ARKIME_RETENTION_ENABLED=false)"
        )
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
