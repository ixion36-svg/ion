"""ION-side lifecycle for Arkime packet-search (hunt) jobs.

Arkime runs the hunt; ION tracks it in the ``arkime_hunts`` table (multi-worker
rule: job state lives in the DB, never module globals). This module owns the
two shared operations:

* :func:`refresh_hunts` — reconcile unfinished rows against the viewer's
  ``/api/hunts`` list. Called from the hunts API (so the panel shows live
  status) and from the retention-awareness loop (so completion is noticed
  even when nobody is watching).
* Completion notes — a finished hunt linked to a case gets ONE note on that
  case (claimed atomically via ``notified``, so the API and the loop can both
  call refresh without double-posting), synced to Kibana.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Arkime hunt statuses that mean "still moving" — anything else is terminal.
_LIVE_STATUSES = {"queued", "paused", "running"}


def _map_status(arkime_status: str) -> str:
    s = (arkime_status or "").strip().lower()
    if s in _LIVE_STATUSES:
        return "running"
    if s == "finished":
        return "finished"
    return "failed" if s else "running"


async def refresh_hunts(session, svc) -> int:
    """Reconcile unfinished DB rows against the viewer. Returns the number of
    rows that changed. Never raises — an unreachable viewer leaves rows as
    they were (the next refresh catches up)."""
    from ion.models.arkime_hunt import ArkimeHunt
    from ion.services.arkime_service import ArkimeError

    def _pending() -> List[Any]:
        return (
            session.query(ArkimeHunt)
            .filter(ArkimeHunt.status.in_(("submitted", "running")))
            .filter(ArkimeHunt.arkime_hunt_id.isnot(None))
            .all()
        )

    rows = await asyncio.to_thread(_pending)
    if not rows:
        return 0
    try:
        hunts = await svc.list_hunts()
    except ArkimeError as exc:
        logger.debug("hunt refresh: viewer list failed: %s", exc)
        return 0
    by_id: Dict[str, Dict[str, Any]] = {str(h.get("id") or ""): h for h in hunts}

    changed = 0
    finished_case_rows: List[Any] = []
    for row in rows:
        h = by_id.get(str(row.arkime_hunt_id))
        if not h:
            continue
        new_status = _map_status(str(h.get("status") or ""))
        matched = h.get("matchedSessions")
        try:
            matched = int(matched) if matched is not None else None
        except (TypeError, ValueError):
            matched = None

        def _apply(row=row, new_status=new_status, matched=matched) -> bool:
            dirty = False
            if row.status != new_status:
                row.status = new_status
                dirty = True
            if matched is not None and row.matched_sessions != matched:
                row.matched_sessions = matched
                dirty = True
            if dirty:
                session.commit()
            return dirty

        if await asyncio.to_thread(_apply):
            changed += 1
        if new_status == "finished" and row.case_id and not row.notified:
            finished_case_rows.append(row)

    for row in finished_case_rows:
        await _notify_case(session, row)
    return changed


async def _notify_case(session, row) -> None:
    """Post the completion note for a finished case-linked hunt — exactly once
    across workers (atomic ``notified`` claim)."""
    from ion.models.alert_triage import AlertCase, Note, NoteEntityType
    from ion.models.arkime_hunt import ArkimeHunt
    from ion.services.ai_user import get_bob_user_id
    from ion.services.arkime_service import arkime_sessions_link
    from ion.services.kibana_sync_helpers import sync_note_to_kibana

    def _claim() -> bool:
        claimed = (
            session.query(ArkimeHunt)
            .filter(ArkimeHunt.id == row.id, ArkimeHunt.notified.is_(False))
            .update({"notified": True}, synchronize_session=False)
        )
        session.commit()
        return bool(claimed)

    try:
        if not await asyncio.to_thread(_claim):
            return  # another worker got there first
    except Exception as exc:  # noqa: BLE001
        await asyncio.to_thread(session.rollback)
        logger.warning("hunt notify: claim failed for hunt %s: %s", row.id, exc)
        return

    matched = row.matched_sessions
    matched_txt = f"**{matched}** session(s) matched" if matched is not None else "Finished"
    link = arkime_sessions_link(f"huntId == {row.arkime_hunt_id}")
    content = (
        f"**Arkime hunt finished — {row.name}**\n\n"
        f"{matched_txt} packet search `{row.search}` ({row.search_type})."
        + (f"\n\n[Open matched sessions in Arkime]({link})" if link else "")
    )

    def _persist() -> Optional[str]:
        bob_id = get_bob_user_id(session)
        case = session.get(AlertCase, row.case_id)
        if not bob_id or case is None:
            return None
        session.add(Note(
            entity_type=NoteEntityType.CASE,
            entity_id=str(case.id),
            user_id=bob_id,
            content=content,
        ))
        session.commit()
        return case.kibana_case_id

    try:
        kibana_case_id = await asyncio.to_thread(_persist)
    except Exception as exc:  # noqa: BLE001
        await asyncio.to_thread(session.rollback)
        logger.warning("hunt notify: note persist failed for hunt %s: %s", row.id, exc)
        return
    # Existing Kibana-linked case → the export loop won't carry a new note;
    # push it explicitly.
    if kibana_case_id:
        await asyncio.to_thread(sync_note_to_kibana, kibana_case_id, "Bob", content)
    logger.info("hunt notify: posted completion note for hunt %s (case %s)", row.id, row.case_id)
