"""Case grouper: clusters ungrouped alerts into AlertCases and triggers investigation.

Background loop runs every ``ION_CASE_GROUPER_INTERVAL_S`` seconds (default 60s)
under advisory lock 1017 (hold_until_close).

Responsibilities
----------------
* Pulls OPEN alerts from Elasticsearch via the shared ``ElasticsearchService``.
* Skips any alert that already has an ``AlertTriage.case_id`` set — this is
  the contract the manual case-creation flow relies on. The grouper never
  steals alerts that an analyst has already claimed.
* Groups remaining alerts by ``(rule, host, user)`` tuple. Alerts missing
  all three of those fields go to a single catch-all
  ``[Auto] Uncategorised alerts`` case so nothing silently falls on the
  floor.
* If there's already an OPEN ``[Auto]`` case with the same grouping key
  created in the last 15 minutes, the alerts are appended to it.
  Otherwise a fresh case is created. The 15-minute window prevents
  ever-growing "noisy rule" cases while still coalescing bursts.
* Pushes auto-created cases to Kibana best-effort (failure is logged and
  swallowed; the ION case still exists).
* Enqueues an autonomous investigation for each newly-grouped alert via
  the existing fire-and-forget helper pattern.

Coexistence with the manual flow
--------------------------------
The manual ``POST /api/cases`` endpoint in ``web/api.py:4096`` stays
authoritative — the grouper will not touch any alert whose triage row
already points at a case. In practice this means:

* Analyst creates a case manually → triage rows get case_id set → grouper
  skips those alerts on the next pass.
* Grouper creates an auto-case → triage rows get case_id set → analyst
  can still re-assign the alert to a different case through the existing
  UI; the grouper's 15-minute window will not re-attach it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_
from sqlalchemy.orm import Session

from ion.core.config import get_config
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
)
from ion.models.user import User
from ion.storage.database import (
    get_engine,
    get_session_factory,
    run_locked,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_stop_event = threading.Event()
_loop_thread: Optional[threading.Thread] = None

# Last-run telemetry (read by the status endpoint). Written from both the
# background loop and the /run-now endpoint.
_last_run_at: Optional[datetime] = None
_last_result: Optional[Dict[str, Any]] = None
_last_run_lock = threading.Lock()

# Catch-all grouping key used for alerts that have no rule/host/user.
UNCATEGORISED_KEY = ("", "", "")


# ---------------------------------------------------------------------------
# Grouping key extraction
# ---------------------------------------------------------------------------


def _safe_get(d: Any, *keys: str) -> Any:
    """Walk nested dicts returning None on any miss. Accepts dict-or-not."""
    for key in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _coerce_scalar(value: Any) -> str:
    """Coerce a possibly dict/list/None field to a string. Empty on miss."""
    if value is None:
        return ""
    if isinstance(value, dict):
        # host/user are sometimes {"name": "..."} or {"id": "..."}
        for key in ("name", "id", "value"):
            v = value.get(key)
            if isinstance(v, str) and v:
                return v
        return ""
    if isinstance(value, list):
        if not value:
            return ""
        return _coerce_scalar(value[0])
    return str(value)


def compute_group_key(alert: Dict[str, Any]) -> Tuple[str, str, str]:
    """Return the ``(rule_key, host, user)`` grouping tuple for an alert dict.

    Inputs are intentionally permissive because alerts come from multiple
    ES shapes (Elastic Security signals, watchers, custom). The order of
    rule lookup mirrors ``_parse_alert`` in elasticsearch_service.py so
    the same rule is consistently identified regardless of the upstream
    format.

    * ``rule_key``: ``raw_data.rule.id`` → ``rule_name`` →
      ``raw_data.kibana.alert.rule.name`` → ``"unknown"``.
    * ``host``: top-level ``host`` (string or {name}), falling back to
      ``raw_data.host.name``.
    * ``user``: top-level ``user`` similarly.

    All three are empty strings (not None) when missing — this keeps the
    key hashable and makes the "catch-all" check trivial
    (``key == UNCATEGORISED_KEY``).
    """
    raw = alert.get("raw_data") if isinstance(alert, dict) else None
    raw = raw if isinstance(raw, dict) else {}

    rule_id = _safe_get(raw, "rule", "id")
    rule_key = _coerce_scalar(rule_id)
    if not rule_key:
        rule_name = alert.get("rule_name") if isinstance(alert, dict) else None
        rule_key = _coerce_scalar(rule_name)
    if not rule_key:
        kib_rule_name = _safe_get(raw, "kibana", "alert", "rule", "name")
        rule_key = _coerce_scalar(kib_rule_name)
    if not rule_key:
        rule_key = "unknown"

    host = _coerce_scalar(alert.get("host") if isinstance(alert, dict) else None)
    if not host:
        host = _coerce_scalar(_safe_get(raw, "host", "name"))

    user = _coerce_scalar(alert.get("user") if isinstance(alert, dict) else None)
    if not user:
        user = _coerce_scalar(_safe_get(raw, "user", "name"))

    return (rule_key, host, user)


# ---------------------------------------------------------------------------
# Alert discovery
# ---------------------------------------------------------------------------


def find_ungrouped_alerts(es_service: Any, limit: int = 200) -> List[Dict[str, Any]]:
    """Return OPEN alert dicts that have no case attached yet.

    The ES service is async, so we wrap a small coroutine runner here;
    callers are synchronous (the grouper loop runs in a plain thread).
    We reuse ``get_alerts(status="open", ...)`` since that's the closest
    available search method in ``ElasticsearchService``.

    The filter step queries ``AlertTriage`` for every row whose
    ``es_alert_id`` appears in the fetched set and excludes any that
    already have ``case_id`` set. This is intentionally done with a
    single IN-query to stay O(1) round-trips regardless of ``limit``.
    """
    from ion.services.elasticsearch_service import ElasticsearchService  # local import

    if es_service is None:
        es_service = ElasticsearchService()

    async def _fetch() -> List[Dict[str, Any]]:
        # Look back a full day so the grouper picks up alerts that came
        # in during a short outage of this loop. Duplicates are cheap:
        # they're filtered out by the case_id check below.
        try:
            alerts = await es_service.get_alerts(
                hours=168, status="open", limit=limit, include_closed=False,
            )
        except Exception as exc:
            logger.warning("Case grouper ES fetch failed: %s", exc)
            return []
        # Convert to dicts — downstream code only needs field access.
        return [a.to_dict(include_raw=True) for a in alerts]

    try:
        # Prefer a brand-new event loop; this code runs from a background
        # thread so there's never a running loop on the current thread.
        alerts = asyncio.run(_fetch())
    except RuntimeError:
        # If somehow we ARE inside an event loop, schedule and wait.
        loop = asyncio.get_event_loop()
        alerts = loop.run_until_complete(_fetch())

    if not alerts:
        return []

    # Filter out alerts already attached to a case.
    factory = get_session_factory()
    session = factory()
    try:
        alert_ids = [a["id"] for a in alerts if a.get("id")]
        if not alert_ids:
            return []
        attached = {
            row.es_alert_id
            for row in session.query(AlertTriage.es_alert_id)
            .filter(AlertTriage.es_alert_id.in_(alert_ids))
            .filter(AlertTriage.case_id.isnot(None))
            .all()
        }
    finally:
        session.close()

    return [a for a in alerts if a.get("id") and a["id"] not in attached]


# ---------------------------------------------------------------------------
# Case lookup / create / extend
# ---------------------------------------------------------------------------


def _max_alerts_per_case() -> int:
    try:
        from ion.core.config import get_config
        return int(getattr(get_config(), "case_grouper_max_alerts_per_case", 20))
    except Exception:
        return 20


def _min_cluster_size() -> int:
    try:
        from ion.core.config import get_config
        return int(getattr(get_config(), "case_grouper_min_cluster_size", 1))
    except Exception:
        return 1


def _investigate_per_case() -> bool:
    try:
        from ion.core.config import get_config
        return bool(getattr(get_config(), "case_grouper_investigate_per_case", True))
    except Exception:
        return True


def find_matching_open_auto_case(
    db: Session,
    rule_key: str,
    host: str,
    user: str,
    window_minutes: int = 15,
) -> Optional[AlertCase]:
    """Return the most recent OPEN ``[Auto]`` case matching this group key.

    Matching rule: case title starts with ``[Auto]``, status is OPEN,
    was created inside ``window_minutes``, and its
    ``triggered_rules``/``affected_hosts``/``affected_users`` JSON
    contain the given values. Because those columns are plain JSON
    arrays (not typed JSONB with a GIN index), we do the
    membership check in Python after pulling the candidate window —
    this stays cheap because the window is small (15 minutes by
    default) and the ``[Auto]`` prefix is selective.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    # Naive-datetime fallback: some SQLAlchemy setups strip tzinfo on
    # comparison. Use cutoff with tzinfo stripped if the DB column is naive.
    candidates = (
        db.query(AlertCase)
        .filter(AlertCase.status == AlertCaseStatus.OPEN)
        .filter(AlertCase.title.like("[Auto]%"))
        .filter(AlertCase.created_at >= cutoff.replace(tzinfo=None))
        .order_by(AlertCase.created_at.desc())
        .limit(50)
        .all()
    )

    max_cap = _max_alerts_per_case()
    for case in candidates:
        rules = case.triggered_rules or []
        hosts = case.affected_hosts or []
        users = case.affected_users or []
        # Rule must match (rule_key is always non-empty — "unknown" for
        # rule-less alerts), host/user must match only if the grouping
        # key has them (preserves catch-all coalescing).
        if rule_key and rule_key not in rules:
            continue
        if host and host not in hosts:
            continue
        if user and user not in users:
            continue
        # Also make sure the case's key set is not strictly larger —
        # otherwise a case with rule=A,host=X,user=Y would swallow an
        # alert that has rule=A but no host/user. We want to
        # coalesce only exact-key matches.
        if not host and hosts:
            continue
        if not user and users:
            continue
        # Respect the per-case cap — a "full" case gets skipped so the
        # next iteration falls through to create a fresh one.
        if max_cap > 0 and len(case.source_alert_ids or []) >= max_cap:
            continue
        return case
    return None


def _next_case_number(db: Session) -> str:
    """Pick the next ``CASE-NNNN`` number, same pattern as kibana_sync_service."""
    max_case = db.query(AlertCase).order_by(AlertCase.id.desc()).first()
    next_num = (max_case.id + 1) if max_case else 1
    return f"CASE-{next_num:04d}"


def create_auto_case(
    db: Session,
    rule_key: str,
    host: str,
    user: str,
    alert_ids: List[str],
    admin_user_id: int,
    severity: Optional[str] = None,
) -> AlertCase:
    """Build + persist a new ``[Auto]`` case for this grouping key.

    ``db.flush()`` is called so the caller can reliably read
    ``case.id`` before linking triage rows. The caller is responsible
    for the final ``commit()``.
    """
    if rule_key == "" and host == "" and user == "":
        # Pure catch-all — use a stable title so the 15-minute window
        # coalesces unrelated "unknown" alerts into a single case.
        title = "[Auto] Uncategorised alerts"
    else:
        host_part = host if host else "unknown host"
        title = f"[Auto] {rule_key} — {host_part}"
    # Clamp to the column length (500) just in case a rule name is wild.
    if len(title) > 500:
        title = title[:497] + "..."

    description = (
        f"Auto-grouped by rule + host + user. "
        f"Contributing alerts: {len(alert_ids)}. "
        f"Grouping key: rule='{rule_key}', host='{host}', user='{user}'."
    )

    case = AlertCase(
        case_number=_next_case_number(db),
        title=title,
        description=description,
        status=AlertCaseStatus.OPEN,
        severity=severity,
        created_by_id=admin_user_id,
        source_alert_ids=list(alert_ids),
        triggered_rules=[rule_key] if rule_key else [],
        affected_hosts=[host] if host else [],
        affected_users=[user] if user else [],
    )
    db.add(case)
    db.flush()
    return case


def extend_auto_case(case: AlertCase, alert_ids: List[str], db: Session) -> None:
    """Append ``alert_ids`` to the case's ``source_alert_ids`` (de-duped).

    JSON columns on SQLAlchemy are mutable-by-reference but SQLAlchemy
    only flushes when the attribute is reassigned, so we always build a
    fresh list and assign it back. Host/user/rule lists are left as-is
    here — ``run_grouper_once`` only extends cases whose key already
    matches, so by definition the new alerts don't contribute new
    hosts/users/rules.
    """
    existing = list(case.source_alert_ids or [])
    seen = set(existing)
    for aid in alert_ids:
        if aid not in seen:
            existing.append(aid)
            seen.add(aid)
    case.source_alert_ids = existing
    db.flush()


def link_triage(db: Session, alert_id: str, case_id: int) -> AlertTriage:
    """Get-or-create an ``AlertTriage`` row linking ``alert_id`` → ``case_id``.

    Mirrors the pattern in ``kibana_sync_service.py`` around lines
    479-489. Sets status to ACKNOWLEDGED because once an alert is on a
    case (even an auto-generated one) it's no longer "open / untouched".
    """
    triage = db.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    if triage is None:
        triage = AlertTriage(
            es_alert_id=alert_id,
            status=AlertTriageStatus.ACKNOWLEDGED,
        )
        db.add(triage)
        db.flush()
    triage.case_id = case_id
    return triage


# ---------------------------------------------------------------------------
# Side-effects: Kibana push + investigation enqueue
# ---------------------------------------------------------------------------


def push_to_kibana_best_effort(case: AlertCase) -> Optional[str]:
    """POST the auto-case to Kibana. Return Kibana case id or None on failure.

    Never raises. If the Kibana service is disabled or unreachable the
    ION case continues to exist with ``kibana_case_id=None`` — the
    existing ``kibana_sync_service`` will NOT re-import it because the
    ION case already has ``kibana_case_id`` unset AND the existing
    inbound sync only creates cases that aren't already in ION's
    ``kibana_case_id`` set (a case that came from Kibana will carry the
    id; a pure ION case without the id is simply not re-imported).
    """
    try:
        from ion.services.kibana_cases_service import get_kibana_cases_service
        kibana_service = get_kibana_cases_service()
    except Exception as exc:
        logger.debug("Kibana cases service not available: %s", exc)
        return None

    try:
        severity = (case.severity or "low").lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "low"
        result = kibana_service.create_case(
            title=case.title,
            description=case.description or "",
            severity=severity,
            tags=["ion-auto"],
        )
    except Exception as exc:
        logger.warning(
            "Kibana push failed for auto-case %s: %s", case.case_number, exc
        )
        return None

    if not result:
        # create_case swallows its own errors and returns None when
        # disabled/failed — don't overwrite kibana_case_id.
        return None

    kibana_id = result.get("id")
    if kibana_id:
        case.kibana_case_id = kibana_id
        case.kibana_case_version = result.get("version")

        # Attach the linked alerts to the Kibana case
        alert_ids = list(case.source_alert_ids or [])
        if alert_ids:
            try:
                space_id = kibana_service.config.get("space_id", "default")
                alert_index = f".alerts-security.alerts-{space_id}"
                kibana_service.attach_alerts_to_case(
                    case_id=kibana_id,
                    alert_ids=alert_ids,
                    alert_index=alert_index,
                )
                logger.info(
                    "Attached %d alerts to Kibana case %s", len(alert_ids), kibana_id,
                )
            except Exception as e:
                logger.warning("Failed to attach alerts to Kibana case %s: %s", kibana_id, e)

    return kibana_id


def enqueue_investigation(alert_id: str) -> None:
    """Fire-and-forget autonomous investigation for ``alert_id``.

    Uses the same pattern as ``web/investigation_api._spawn_investigation``:
    if a running loop exists (we're inside FastAPI), schedule a task;
    otherwise spawn a short-lived thread that calls ``asyncio.run``.
    Never raises.
    """
    try:
        from ion.services.investigation_service import get_investigation_service
        service = get_investigation_service()
    except Exception as exc:
        logger.debug("Investigation service not available: %s", exc)
        return

    async def _runner() -> None:
        try:
            await service.investigate_alert(
                alert_id=alert_id, force=False, triggered_by="case_grouper",
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.info("Auto-investigation for %s stopped: %s", alert_id, exc)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_runner())
        return
    except RuntimeError:
        pass

    # No running loop — use a daemon thread so we never block the
    # grouper tick. Each thread gets its own asyncio loop via run().
    def _bg() -> None:
        try:
            asyncio.run(_runner())
        except Exception as exc:
            logger.debug("Background investigation thread failed: %s", exc)

    threading.Thread(target=_bg, daemon=True, name=f"ion-inv-{alert_id[:12]}").start()


def enqueue_case_investigation(case_id: int) -> None:
    """Fire-and-forget cluster-level investigation covering every alert on the case.

    Mirrors ``enqueue_investigation`` but calls ``investigate_case`` so the
    LLM sees all grouped alerts at once — one call per case, not N.
    Never raises.
    """
    try:
        from ion.services.investigation_service import get_investigation_service
        service = get_investigation_service()
    except Exception as exc:
        logger.debug("Investigation service not available: %s", exc)
        return

    async def _runner() -> None:
        try:
            await service.investigate_case(
                case_id=case_id, force=False, triggered_by="case_grouper",
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.info("Auto-case-investigation for #%s stopped: %s", case_id, exc)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_runner())
        return
    except RuntimeError:
        pass

    def _bg() -> None:
        try:
            asyncio.run(_runner())
        except Exception as exc:
            logger.debug("Background case-investigation thread failed: %s", exc)

    threading.Thread(target=_bg, daemon=True, name=f"ion-case-inv-{case_id}").start()


# ---------------------------------------------------------------------------
# Main pass
# ---------------------------------------------------------------------------


def _admin_user_id(db: Session) -> Optional[int]:
    """Resolve the system-admin user id. Falls back to user id=1."""
    admin = db.query(User).filter_by(username="admin").first()
    if admin is not None:
        return admin.id
    fallback = db.query(User).filter_by(id=1).first()
    return fallback.id if fallback else None


def _should_push_kibana() -> bool:
    val = os.environ.get("ION_CASE_GROUPER_PUSH_TO_KIBANA", "").lower()
    if val in ("false", "0", "no"):
        return False
    return True


def _should_auto_investigate() -> bool:
    val = os.environ.get("ION_CASE_GROUPER_AUTO_INVESTIGATE", "").lower()
    if val in ("false", "0", "no"):
        return False
    return True


def _window_minutes() -> int:
    try:
        return int(os.environ.get("ION_CASE_GROUPER_WINDOW_MINUTES", "15"))
    except ValueError:
        return 15


def run_grouper_once(
    db: Session,
    es_service: Any = None,
) -> Dict[str, int]:
    """Single grouping pass. Commits at the end on success.

    Returns a summary dict suitable for the API and telemetry storage.
    The caller provides the session so tests can wrap this in their own
    transaction — the background loop opens a session per tick.
    """
    summary: Dict[str, int] = {
        "scanned": 0,
        "grouped_new_cases": 0,
        "grouped_extended_cases": 0,
        "alerts_attached": 0,
        "investigations_queued": 0,
        "errors": 0,
    }

    alerts = find_ungrouped_alerts(es_service)
    summary["scanned"] = len(alerts)
    if not alerts:
        return summary

    admin_id = _admin_user_id(db)
    if admin_id is None:
        logger.warning(
            "Case grouper: no admin user found (username=admin or id=1). Skipping pass."
        )
        summary["errors"] = 1
        return summary

    # Group alerts by (rule, host, user)
    groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for alert in alerts:
        key = compute_group_key(alert)
        groups.setdefault(key, []).append(alert)

    window = _window_minutes()
    push_kibana = _should_push_kibana()
    investigate = _should_auto_investigate()
    per_case_investigate = _investigate_per_case()
    min_cluster = _min_cluster_size()
    max_cap = _max_alerts_per_case()
    newly_grouped_alert_ids: List[str] = []
    new_cases: List[AlertCase] = []
    touched_case_ids: List[int] = []

    for key, members in groups.items():
        rule_key, host, user = key
        alert_ids = [a["id"] for a in members if a.get("id")]
        if not alert_ids:
            continue

        # Choose a severity for the case — take the highest we see.
        severity = _pick_max_severity(members)

        try:
            existing = find_matching_open_auto_case(
                db, rule_key, host, user, window_minutes=window
            )
            if existing is not None:
                # Respect cap: chunk leftovers into fresh cases.
                remaining = alert_ids
                current = existing
                while remaining:
                    free = (max_cap - len(current.source_alert_ids or [])) if max_cap > 0 else len(remaining)
                    if free <= 0:
                        current = create_auto_case(
                            db, rule_key, host, user, [],
                            admin_user_id=admin_id, severity=severity,
                        )
                        new_cases.append(current)
                        summary["grouped_new_cases"] += 1
                        free = max_cap if max_cap > 0 else len(remaining)
                    chunk, remaining = remaining[:free], remaining[free:]
                    extend_auto_case(current, chunk, db)
                    for aid in chunk:
                        link_triage(db, aid, current.id)
                    if current is existing:
                        summary["grouped_extended_cases"] += 1
                    summary["alerts_attached"] += len(chunk)
                    newly_grouped_alert_ids.extend(chunk)
                    if current.id not in touched_case_ids:
                        touched_case_ids.append(current.id)
            else:
                # Defer grouping until the cluster is large enough
                # (ION_CASE_GROUPER_MIN_CLUSTER_SIZE). Smaller groups
                # stay ungrouped and accumulate on the next tick.
                if min_cluster > 1 and len(alert_ids) < min_cluster:
                    logger.debug(
                        "Case grouper: deferring cluster of %d < min=%d (key=%s)",
                        len(alert_ids), min_cluster, key,
                    )
                    continue
                remaining = alert_ids
                first_case: Optional[AlertCase] = None
                while remaining:
                    chunk_size = max_cap if max_cap > 0 else len(remaining)
                    chunk, remaining = remaining[:chunk_size], remaining[chunk_size:]
                    case = create_auto_case(
                        db, rule_key, host, user, chunk,
                        admin_user_id=admin_id, severity=severity,
                    )
                    for aid in chunk:
                        link_triage(db, aid, case.id)
                    summary["grouped_new_cases"] += 1
                    summary["alerts_attached"] += len(chunk)
                    new_cases.append(case)
                    newly_grouped_alert_ids.extend(chunk)
                    touched_case_ids.append(case.id)
                    if first_case is None:
                        first_case = case
        except Exception as exc:
            logger.exception("Case grouper group failed (key=%s): %s", key, exc)
            summary["errors"] += 1
            db.rollback()
            continue

    # Commit the case+triage rows before any external side-effects so a
    # Kibana outage or investigation crash doesn't leave the DB half-updated.
    try:
        db.commit()
    except Exception as exc:
        logger.exception("Case grouper commit failed: %s", exc)
        db.rollback()
        summary["errors"] += 1
        return summary

    # Best-effort side-effects. Each is wrapped so one failure doesn't
    # abort the rest of the batch.
    if push_kibana and new_cases:
        for case in new_cases:
            try:
                push_to_kibana_best_effort(case)
            except Exception as exc:
                logger.warning(
                    "Kibana push failed for %s: %s", case.case_number, exc
                )
                summary["errors"] += 1
        # Persist kibana_case_id if it was set.
        try:
            db.commit()
        except Exception as exc:
            logger.warning("Kibana-id commit failed: %s", exc)
            db.rollback()

    if investigate and (touched_case_ids or newly_grouped_alert_ids):
        if per_case_investigate and touched_case_ids:
            # One LLM call per case — see ION_CASE_GROUPER_INVESTIGATE_PER_CASE.
            # Stagger between cases keeps Ollama's parallel slots from
            # saturating when a burst of new clusters lands at once.
            import time as _time
            try:
                from ion.core.config import get_config as _get_cfg
                stagger = float(getattr(_get_cfg(), "case_grouper_stagger_s", 3.0))
            except Exception:
                stagger = 3.0
            for i, cid in enumerate(touched_case_ids):
                if i > 0 and stagger > 0:
                    _time.sleep(stagger)
                try:
                    enqueue_case_investigation(cid)
                    summary["investigations_queued"] += 1
                except Exception as exc:
                    logger.debug("enqueue_case_investigation(%s) failed: %s", cid, exc)
                    summary["errors"] += 1
        elif newly_grouped_alert_ids:
            # Legacy path: one investigation per alert. Still staggered.
            import time as _time
            try:
                from ion.core.config import get_config as _get_cfg
                stagger = float(getattr(_get_cfg(), "case_grouper_stagger_s", 3.0))
            except Exception:
                stagger = 3.0
            for i, aid in enumerate(newly_grouped_alert_ids):
                if i > 0 and stagger > 0:
                    _time.sleep(stagger)
                try:
                    enqueue_investigation(aid)
                    summary["investigations_queued"] += 1
                except Exception as exc:
                    logger.debug("enqueue_investigation(%s) failed: %s", aid, exc)
                    summary["errors"] += 1

    return summary


def _pick_max_severity(members: List[Dict[str, Any]]) -> Optional[str]:
    """Return the most severe string severity seen in ``members`` (or None)."""
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    best: Optional[str] = None
    best_score = -1
    for m in members:
        sev = m.get("severity")
        if not isinstance(sev, str):
            continue
        score = order.get(sev.lower(), -1)
        if score > best_score:
            best_score = score
            best = sev
    return best


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------


def _record_run(summary: Dict[str, Any]) -> None:
    global _last_run_at, _last_result
    with _last_run_lock:
        _last_run_at = datetime.now(timezone.utc)
        _last_result = summary


def _tick() -> Dict[str, Any]:
    """One grouper iteration against a fresh session."""
    factory = get_session_factory()
    session = factory()
    try:
        summary = run_grouper_once(session)
    except Exception as exc:
        logger.exception("Case grouper tick crashed: %s", exc)
        summary = {
            "scanned": 0,
            "grouped_new_cases": 0,
            "grouped_extended_cases": 0,
            "alerts_attached": 0,
            "investigations_queued": 0,
            "errors": 1,
            "error": str(exc),
        }
    finally:
        session.close()
    _record_run(summary)
    return summary


def run_grouper_loop(interval_s: int = 60) -> None:
    """Spawn the background grouper thread. Idempotent per-process."""
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("Case grouper loop already running — skipping")
        return

    def _loop() -> None:
        logger.info(
            "Case grouper background loop started (interval: %ds)", interval_s
        )
        while not _stop_event.is_set():
            try:
                _tick()
            except Exception as exc:
                logger.warning("Case grouper loop error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("Case grouper loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-case-grouper"
    )
    _loop_thread.start()


def stop_grouper_loop() -> None:
    _stop_event.set()


def start_grouper_if_enabled(engine=None, lock_id: Optional[int] = None) -> bool:
    """Honour ``case_grouper_enabled`` + advisory lock; return True if started.

    Mirrors ``start_scheduler_if_enabled`` in scheduler_service.py.
    """
    enabled_env = os.environ.get("ION_CASE_GROUPER_ENABLED", "").lower()
    if enabled_env in ("false", "0", "no"):
        logger.info(
            "Case grouper disabled by ION_CASE_GROUPER_ENABLED=%s", enabled_env
        )
        return False

    # Also honour the config-file flag if the env var is unset.
    try:
        config = get_config()
        if not enabled_env and not getattr(config, "case_grouper_enabled", True):
            logger.info("Case grouper disabled (config.case_grouper_enabled=False)")
            return False
    except Exception:
        pass

    try:
        interval_s = int(os.environ.get("ION_CASE_GROUPER_INTERVAL_S", "60"))
    except ValueError:
        interval_s = 60

    if engine is None:
        engine = get_engine(get_config().db_path)

    if lock_id is None:
        try:
            from ion.storage.database import LOCK_CASE_GROUPER_BG  # type: ignore
            lock_id = LOCK_CASE_GROUPER_BG
        except ImportError:
            lock_id = 1017

    def _start() -> None:
        run_grouper_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "case_grouper_bg_loop", _start, hold_until_close=True
    )


# ---------------------------------------------------------------------------
# Telemetry accessors (used by the API)
# ---------------------------------------------------------------------------


def get_last_run_info() -> Tuple[Optional[datetime], Optional[Dict[str, Any]]]:
    with _last_run_lock:
        return _last_run_at, (dict(_last_result) if _last_result else None)


def count_auto_cases(db: Session) -> int:
    """Total number of auto-grouped cases in the DB (all statuses)."""
    return (
        db.query(AlertCase)
        .filter(AlertCase.title.like("[Auto]%"))
        .count()
    )


# ---------------------------------------------------------------------------
# Singleton facade (ION naming convention)
# ---------------------------------------------------------------------------


class _CaseGrouperService:
    def run_once(self, db: Session) -> Dict[str, int]:
        return run_grouper_once(db)

    def start(self, engine=None) -> bool:
        return start_grouper_if_enabled(engine=engine)

    def stop(self) -> None:
        stop_grouper_loop()

    def last_run(self) -> Tuple[Optional[datetime], Optional[Dict[str, Any]]]:
        return get_last_run_info()


_case_grouper_service: Optional[_CaseGrouperService] = None


def get_case_grouper_service() -> _CaseGrouperService:
    """Return the singleton grouper service facade."""
    global _case_grouper_service
    if _case_grouper_service is None:
        _case_grouper_service = _CaseGrouperService()
    return _case_grouper_service


# Silence the unused-import warning from static checkers for ``and_``.
_ = and_
