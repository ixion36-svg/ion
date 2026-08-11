"""Case-lifecycle API — investigation cases: list/create/detail/update,
notes, timeline, similarity, PDF export, DFIR-IRIS escalation, close-as-known-FP.

Extracted from web/api.py (god-module split, increment 3 - finding #14).
Mounted at /api in server.py, preserving the original
/api/elasticsearch/alerts/cases/* paths. The known-false-positive subsystem and
alert triage stay in api.py (KFP is entangled with the staying close_alert
route); this module imports the few shared helpers it needs from api.py.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session, selectinload

from ion.auth.dependencies import require_permission
from ion.core.config import get_elasticsearch_config
from ion.core.safe_errors import safe_error
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    CaseClosureReason,
    KnownFalsePositive,
    Note,
    NoteEntityType,
)
from ion.models.playbook import PlaybookExecution
from ion.models.user import User
from ion.services.dfir_iris_service import get_dfir_iris_service
from ion.services.kibana_cases_service import get_kibana_cases_service
from ion.services.kibana_sync_helpers import (
    get_kibana_case_url,
    sync_case_update_to_kibana,
    sync_new_case_to_kibana,
    sync_note_to_kibana,
)
from ion.storage.auth_repository import AuditLogRepository
from ion.storage.database import get_db_session
from ion.storage.playbook_repository import PlaybookRepository

# Shared helpers that remain in api.py (KFP subsystem, triage, ES service factory).
from ion.web.api import (
    _match_known_false_positives,
    _populate_triage_observables,
    get_elasticsearch_service,
)

logger = logging.getLogger(__name__)
_case_es_logger = logging.getLogger(__name__)

router = APIRouter()


# Request models (moved from api.py with their routes).
class AlertContext(BaseModel):
    alert_id: str
    host: Optional[str] = None
    user: Optional[str] = None
    raw_data: Optional[dict] = None


class CaseNoteCreate(BaseModel):
    content: str


class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    assigned_to_id: Optional[int] = None
    alert_ids: Optional[List[str]] = None
    affected_hosts: Optional[List[str]] = None
    affected_users: Optional[List[str]] = None
    triggered_rules: Optional[List[str]] = None
    evidence_summary: Optional[str] = None
    alert_contexts: Optional[List["AlertContext"]] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    closure_reason: Optional[str] = None
    closure_notes: Optional[str] = None


class CloseAsFPRequest(BaseModel):
    known_fp_id: int


@router.get("/elasticsearch/alerts/cases")
async def list_cases(
    status: Optional[str] = None,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """List all investigation cases."""
    # Wrapped in to_thread — query + serialization access relationships
    # (created_by, assigned_to, triage_entries, observables) so both must
    # run in the same thread while the session is open.
    def _query_cases():
        query = session.query(AlertCase).options(
            selectinload(AlertCase.created_by),
            selectinload(AlertCase.assigned_to),
            selectinload(AlertCase.triage_entries),
        )
        if status:
            query = query.filter(AlertCase.status == status)
        cases = query.order_by(AlertCase.created_at.desc()).all()

        iris_service = get_dfir_iris_service()

        def get_iris_url(case):
            if case.dfir_iris_case_id:
                return iris_service.get_case_url(case.dfir_iris_case_id)
            return None

        return {
            "cases": [
                {
                    "id": c.id,
                    "case_number": c.case_number,
                    "title": c.title,
                    "description": c.description,
                    "status": c.status.value if hasattr(c.status, "value") else c.status,
                    "severity": c.severity,
                    "created_by": c.created_by.username if c.created_by else None,
                    "assigned_to": c.assigned_to.username if c.assigned_to else None,
                    "assigned_to_id": c.assigned_to_id,
                    "alert_count": len(c.triage_entries),
                    "affected_hosts": c.affected_hosts,
                    "affected_users": c.affected_users,
                    "triggered_rules": c.triggered_rules,
                    "evidence_summary": c.evidence_summary,
                    "source_alert_ids": c.source_alert_ids,
                    "observables_count": len(c.observables) if c.observables else 0,
                    "kibana_case_id": c.kibana_case_id,
                    "kibana_url": get_kibana_case_url(c.kibana_case_id),
                    "dfir_iris_case_id": c.dfir_iris_case_id,
                    "dfir_iris_url": get_iris_url(c),
                    "closure_reason": c.closure_reason,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                }
                for c in cases
            ]
        }

    return await asyncio.to_thread(_query_cases)

def _build_case_es_doc(case, session) -> dict:
    """Build the full Elasticsearch document from an AlertCase ORM object."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": case.id,
        "@timestamp": now,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "severity": case.severity,
        "created_by": case.created_by.username if case.created_by else None,
        "assigned_to": case.assigned_to.username if case.assigned_to else None,
        "affected_hosts": case.affected_hosts or [],
        "affected_users": case.affected_users or [],
        "triggered_rules": case.triggered_rules or [],
        "evidence_summary": case.evidence_summary,
        "source_alert_ids": case.source_alert_ids or [],
        "alert_count": len(case.source_alert_ids) if case.source_alert_ids else 0,
        "notes": [
            {
                "user": n.user.username if n.user else "Unknown",
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in case.notes
        ],
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }

async def _sync_case_to_es(case, session):
    """Sync a case to Elasticsearch. Logs warnings on failure, never raises."""
    try:
        es_config = get_elasticsearch_config()
        if not es_config.get("enabled"):
            return
        es_service = get_elasticsearch_service()
        if not es_service.is_configured:
            return
        doc = _build_case_es_doc(case, session)
        await es_service.index_case(doc)
    except Exception as e:
        _case_es_logger.warning("Failed to sync case %s to ES: %s", getattr(case, "id", "?"), e)

def _new_background_session():
    """Open a fresh DB session bound to the app engine. Caller is responsible
    for closing it. Used by BackgroundTasks helpers because the request-scoped
    session from Depends(get_db_session) is already closed by the time they run.
    """
    from ion.storage.database import get_session_factory
    return get_session_factory()()

async def _background_case_sync(case_id: int) -> None:
    """Re-index a case into Elasticsearch with its latest state."""
    _session = _new_background_session()
    try:
        _case = _session.query(AlertCase).filter_by(id=case_id).first()
        if _case is None:
            return
        await _sync_case_to_es(_case, _session)
    except Exception as e:
        logger.warning("Background case ES sync failed for %s: %s", case_id, e)
    finally:
        _session.close()

async def _background_alert_workflow_sync(alert_ids: list, mapped_triage: str) -> None:
    """Push linked alert workflow_status changes to Elasticsearch."""
    if not alert_ids or not mapped_triage:
        return
    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        es = ElasticsearchService()
        if es.is_configured:
            await es.update_alert_workflow_status(alert_ids, mapped_triage)
    except Exception as e:
        logger.warning("Background alert workflow_status sync failed: %s", e)

async def _background_kibana_case_sync(
    case_id: int,
    case_number: str,
    kibana_case_id: str,
    fields: dict,
    assignee_user_id: int | None,
) -> None:
    """Push a Kibana case update + optional assignee resolution.

    Runs in FastAPI's BackgroundTasks pool so slow Kibana responses
    (which used to trip the 30s nginx upstream timeout and surface as
    502s) are invisible to the user. Opens its own DB session to resolve
    the assignee UID and persist the Kibana version after a successful sync.
    """
    _session = _new_background_session()
    assignee_elastic_uid = None
    try:
        if assignee_user_id is not None:
            assignee = _session.query(User).filter_by(id=assignee_user_id).first()
            if assignee:
                if assignee.elastic_uid:
                    assignee_elastic_uid = assignee.elastic_uid
                else:
                    try:
                        from ion.services.elasticsearch_service import ElasticsearchService
                        _es = ElasticsearchService()
                        if _es.is_configured:
                            lookup_name = getattr(assignee, "elastic_username", None) or assignee.username
                            uid = await _es.resolve_user_uid(lookup_name)
                            if not uid and lookup_name != assignee.username:
                                uid = await _es.resolve_user_uid(assignee.username)
                            if uid:
                                assignee_elastic_uid = uid
                                assignee.elastic_uid = uid
                                _session.commit()
                    except Exception as e:
                        logger.debug("Background Elastic UID resolve failed: %s", e)

        new_version, _ = sync_case_update_to_kibana(
            kibana_case_id=kibana_case_id,
            case_number=case_number,
            title=fields.get("title"),
            description=fields.get("description"),
            status=fields.get("status"),
            severity=fields.get("severity"),
            assignee_elastic_uid=assignee_elastic_uid,
        )
        if new_version:
            _case_row = _session.query(AlertCase).filter_by(id=case_id).first()
            if _case_row is not None:
                _case_row.kibana_case_version = new_version
                _session.commit()
    except Exception as e:
        logger.warning("Background Kibana case sync failed for %s: %s", case_id, e)
    finally:
        _session.close()

async def _background_ai_case_summary(case_id: int, user_id: int) -> None:
    """Generate AI executive summary when a case is closed."""
    try:
        from ion.services.ollama_service import get_ollama_service
        ollama = get_ollama_service()
        if not await ollama.is_available():
            return

        _session = _new_background_session()
        try:
            case = _session.query(AlertCase).filter_by(id=case_id).first()
            if not case:
                return

            # Build context from case data
            context = f"Case: {case.case_number} - {case.title}\n"
            context += f"Severity: {case.severity}\n"
            context += f"Status: {case.status.value if hasattr(case.status, 'value') else case.status}\n"
            if case.description:
                context += f"Description: {case.description[:500]}\n"
            if case.affected_hosts:
                context += f"Affected hosts: {', '.join(case.affected_hosts)}\n"
            if case.affected_users:
                context += f"Affected users: {', '.join(case.affected_users)}\n"
            if case.triggered_rules:
                context += f"Rules: {', '.join(case.triggered_rules)}\n"
            if case.closure_reason:
                context += f"Closure reason: {case.closure_reason}\n"
            if case.closure_notes:
                context += f"Closure notes: {case.closure_notes}\n"

            # Get notes for context
            notes = _session.query(Note).filter_by(
                entity_type=NoteEntityType.CASE,
                entity_id=str(case_id)
            ).order_by(Note.created_at.desc()).limit(5).all()
            if notes:
                context += "\nInvestigation notes:\n"
                for n in notes:
                    context += f"- {n.content[:200]}\n"

            # (P3b): analyst persona + explicit anti-fabrication
            # grounding, and fence the case/notes context in the untrusted
            # trust boundary (it carries observable values + free-text notes).
            from ion.services.prompt_safety import (
                UNTRUSTED_DIRECTIVE,
                sanitize_untrusted,
                wrap_untrusted,
            )
            prompt = (
                "You are a SOC analyst writing a concise executive summary "
                "(2-3 paragraphs) for this closed security case. Cover: what "
                "happened, what was investigated, the outcome, and any follow-up "
                "actions. Write in professional incident-report style, plain text "
                "(no markdown). Ground every statement in the case data below — "
                "never invent hosts, users, IOCs, or findings that are not "
                "present.\n\n"
                f"{wrap_untrusted(sanitize_untrusted(context, max_chars=0))}\n\n"
                f"{UNTRUSTED_DIRECTIVE}"
            )

            result = await ollama.chat(
                messages=[{"role": "user", "content": prompt}],
                context_type="analyst",
                temperature=0.3,
                user_id=user_id,
            )

            summary_note = Note(
                entity_type=NoteEntityType.CASE,
                entity_id=str(case_id),
                user_id=user_id,
                content=f"**AI Executive Summary**\n\n{result['content']}",
            )
            _session.add(summary_note)
            _session.commit()

            # Mirror the AI summary onto the linked Kibana case, matching the
            # interactive add_case_note path — otherwise the summary lives only
            # in ION's DB and never appears in Kibana. Fire-and-forget; a no-op
            # when Kibana is disabled or the case has no Kibana link.
            author = _session.get(User, user_id)
            sync_note_to_kibana(
                case.kibana_case_id,
                author.username if author else "ion",
                summary_note.content,
            )
        finally:
            _session.close()
    except Exception as e:
        logger.warning("AI case summary failed for case %s: %s", case_id, e)

# Contract: enrichable ObservableType members whose enrichment is worth
# summarizing in the auto-note. Display-only types (hostname, user, file,
# process, registry) never carry OpenCTI enrichment and are excluded.
_ENRICHMENT_NOTE_TYPES = None  # lazily built to avoid an import at module load


def _enrichment_note_types():
    global _ENRICHMENT_NOTE_TYPES
    if _ENRICHMENT_NOTE_TYPES is None:
        from ion.models.observable import ObservableType
        _ENRICHMENT_NOTE_TYPES = frozenset({
            ObservableType.IPV4, ObservableType.IPV6, ObservableType.DOMAIN,
            ObservableType.URL, ObservableType.EMAIL,
            ObservableType.FILE_HASH_SHA256, ObservableType.FILE_HASH_SHA1,
            ObservableType.FILE_HASH_MD5,
        })
    return _ENRICHMENT_NOTE_TYPES


async def post_enrichment_note(session, case_id: int, user_id: int, username: str = "system"):
    """Compose + post a Threat Enrichment Summary note for a case's observables.

    Summarizes the case's *enriched* observables into a Markdown case Note,
    mirroring the AI Executive Summary auto-note pattern (create ``Note`` with
    ``entity_type=CASE``, commit, then replicate the ``_sync_case_to_es`` +
    ``sync_note_to_kibana`` side-effects).

    No-op / air-gap safe: returns ``None`` when the case has no enrichable
    observables or none of them actually carry enrichment to report (the
    OpenCTI-unconfigured case, where every threat_level stays "unknown").
    Idempotent-ish: skips if an identical enrichment note already exists.
    """
    try:
        from collections import Counter

        from ion.models.observable import (
            Observable,
            ObservableLink,
            ObservableLinkType,
        )

        case = session.query(AlertCase).filter_by(id=case_id).first()
        if not case:
            return None

        links = (
            session.query(ObservableLink)
            .filter(
                ObservableLink.link_type == ObservableLinkType.CASE,
                ObservableLink.entity_id == case_id,
            )
            .all()
        )
        obs_ids = [l.observable_id for l in links]
        if not obs_ids:
            return None

        observables = (
            session.query(Observable).filter(Observable.id.in_(obs_ids)).all()
        )

        enrichable_types = _enrichment_note_types()
        order = ["critical", "high", "medium", "low", "benign", "unknown"]

        # Keep only enrichable observables that carry something to report:
        # an enrichment record, or a non-"unknown" threat level.
        reported = []
        for o in observables:
            if o.type not in enrichable_types:
                continue
            enr = o.latest_enrichment
            level = o.threat_level.value if hasattr(o.threat_level, "value") else str(o.threat_level)
            if enr is None and (level is None or level == "unknown"):
                continue
            reported.append((o, enr, level or "unknown"))

        if not reported:
            return None

        counts = Counter(level for _, _, level in reported)
        counts_str = ", ".join(f"{counts[l]} {l}" for l in order if counts.get(l))

        reported.sort(key=lambda t: order.index(t[2]) if t[2] in order else 99)
        lines = []
        for o, enr, level in reported:
            score = enr.score if enr else None
            labels = list(enr.labels) if (enr and enr.labels) else []
            actors = (
                [a.get("name") for a in (enr.threat_actors or []) if isinstance(a, dict) and a.get("name")]
                if enr else []
            )
            line = f"- `{o.value}` — {level}"
            if score is not None:
                line += f" ({score})"
            if labels:
                line += f" [{', '.join(str(x) for x in labels)}]"
            if actors:
                line += f" - {', '.join(actors)}"
            lines.append(line)

        content = (
            "**Threat Enrichment Summary** (OpenCTI, TLP:AMBER)\n\n"
            f"{len(reported)} enrichable observable(s): {counts_str}\n\n"
            + "\n".join(lines)
        )

        # Idempotent-ish: don't spam duplicate identical enrichment notes.
        existing = (
            session.query(Note)
            .filter(
                Note.entity_type == NoteEntityType.CASE,
                Note.entity_id == str(case_id),
            )
            .all()
        )
        if any(n.content == content for n in existing):
            return None

        note = Note(
            entity_type=NoteEntityType.CASE,
            entity_id=str(case_id),
            user_id=user_id,
            content=content,
        )
        session.add(note)
        session.commit()
        session.refresh(case)

        # Replicate the auto-note side-effects (best-effort, non-raising).
        await _sync_case_to_es(case, session)
        sync_note_to_kibana(case.kibana_case_id, username, content)
        return note
    except Exception as e:
        logger.warning("post_enrichment_note failed for case %s: %s", case_id, e)
        return None

def _extract_community_and_node(
    raw_data: Optional[dict],
) -> tuple[Optional[str], Optional[str]]:
    """Extract ``(network.community_id, arkime_node)`` from a raw ES doc.

    ECS surface is ``network.community_id`` (nested dict). Some pipelines
    flatten it as ``"network.community_id"`` (literal key) or strip the
    namespace entirely. ``arkime_node`` is custom (non-ECS); it lives
    top-level on many setups and nested under ``arkime.node`` on others.

    Returns ``(None, None)`` when raw_data is unusable.
    """
    if not isinstance(raw_data, dict):
        return None, None

    # community_id — nested ECS first, then flattened variants.
    net = raw_data.get("network")
    cid: Optional[str] = None
    if isinstance(net, dict):
        cid = net.get("community_id")
    if not cid:
        cid = raw_data.get("community_id") or raw_data.get("network.community_id")

    # arkime_node — top-level OR nested. The previous v0.16.0 form had an
    # ``or`` + ternary precedence bug that dropped the top-level value
    # when no nested ``arkime`` dict was present.
    node: Optional[str] = raw_data.get("arkime_node")
    if not node:
        arkime = raw_data.get("arkime")
        if isinstance(arkime, dict):
            node = arkime.get("node")

    return (str(cid) if cid else None, str(node) if node else None)

def _extract_ip_and_timestamp(
    raw_data: Optional[dict],
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """v0.29.1: extract ``(source_ip, destination_ip, timestamp)`` for the
    PCAP auto-analysis IP-fallback path.

    Mirrors what ``arkime_api.preview_arkime`` does on the manual
    button: when ``find_sessions_by_community_id`` returns empty, the
    service falls back to ``find_sessions_by_ip`` anchored on the alert
    timestamp. The auto path needs the same data for parity.

    Handles ECS-nested (``source.ip``), flattened (``source.ip``), and
    plain (``source_ip``) forms. Timestamp falls through several
    well-known keys.
    """
    if not isinstance(raw_data, dict):
        return None, None, None

    def _nested(top: str, leaf: str) -> Optional[str]:
        v = raw_data.get(top)
        if isinstance(v, dict):
            inner = v.get(leaf)
            return str(inner) if inner else None
        return None

    src_ip = (
        _nested("source", "ip")
        or raw_data.get("source.ip")
        or raw_data.get("source_ip")
    )
    dst_ip = (
        _nested("destination", "ip")
        or raw_data.get("destination.ip")
        or raw_data.get("destination_ip")
    )
    ts = (
        raw_data.get("@timestamp")
        or raw_data.get("timestamp")
        or raw_data.get("kibana.alert.original_time")
    )
    return (
        str(src_ip) if src_ip else None,
        str(dst_ip) if dst_ip else None,
        str(ts) if ts else None,
    )

async def _build_pcap_flows(
    *,
    alert_ids: List[str],
    alert_contexts: Optional[List["AlertContext"]],
) -> List[Dict[str, Optional[str]]]:
    """Build the per-alert PCAP-analysis flow list for ``create_case``.

    Walks every alert_id; reads raw_data from the matching alert_context
    when available, falls back to ``ElasticsearchService.get_alerts_by_ids``
    for alerts whose context was sent without raw_data (the alerts list
    endpoint defaults to ``include_raw=False`` so multi-select case
    creation hits this path on most alerts).

    Returns a list of ``{"community_id", "node_hint", "alert_id"}`` dicts
    suitable for ``enqueue_pcap_analysis_for_case``. Deduping by
    community_id happens later in the service.
    """
    context_map: Dict[str, "AlertContext"] = {}
    if alert_contexts:
        for ctx in alert_contexts:
            if ctx and getattr(ctx, "alert_id", None):
                context_map[ctx.alert_id] = ctx

    flows: List[Dict[str, Optional[str]]] = []
    needs_es: List[str] = []
    for aid in alert_ids:
        ctx = context_map.get(aid)
        rd = getattr(ctx, "raw_data", None) if ctx else None
        if isinstance(rd, dict) and rd:
            cid, node = _extract_community_and_node(rd)
            if cid:
                # also carry IPs + timestamp for the IP-fallback
                # path that fires when Arkime's community_id index misses.
                src_ip, dst_ip, ts = _extract_ip_and_timestamp(rd)
                flows.append({
                    "community_id": cid, "node_hint": node, "alert_id": aid,
                    "source_ip": src_ip, "destination_ip": dst_ip,
                    "alert_timestamp": ts,
                })
                continue
            # context present but no community_id in it — no need to
            # round-trip ES for this alert; the doc genuinely doesn't
            # carry the flow hash.
            continue
        # context missing or raw_data empty — needs ES fallback.
        needs_es.append(aid)

    if needs_es:
        try:
            es = get_elasticsearch_service()
            es_alerts = await es.get_alerts_by_ids(needs_es)
        except Exception as exc:
            logger.debug(
                "create_case: ES fallback for PCAP raw_data failed: %s", exc,
            )
            es_alerts = []
        for alert in es_alerts or []:
            rd = getattr(alert, "raw_data", None)
            cid, node = _extract_community_and_node(rd)
            if cid:
                src_ip, dst_ip, ts = _extract_ip_and_timestamp(rd)
                flows.append({
                    "community_id": cid,
                    "node_hint": node,
                    "alert_id": getattr(alert, "id", None),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "alert_timestamp": ts,
                })

    return flows


def _should_investigate_new_case(
    auto_closed: bool,
    source_alert_ids,
    auto_investigate_enabled: bool,
) -> bool:
    """Whether Bob should investigate a just-created case and post a comment.

    True for a manually-created case with alerts when case auto-investigation is
    enabled — the same behaviour as auto-grouped cases. Skipped when the case was
    auto-closed as a known FP (nothing to investigate) or has no alerts.
    """
    return bool(auto_investigate_enabled) and not auto_closed and bool(source_alert_ids)


@router.post("/elasticsearch/alerts/cases")
async def create_case(
    data: CaseCreate,
    current_user: User = Depends(require_permission("case:create")),
    session: Session = Depends(get_db_session),
):
    """Create a new investigation case, optionally linking alert IDs."""
    from ion.services.case_numbering import assign_case_number

    new_case = AlertCase(
        title=data.title,
        description=data.description,
        status=AlertCaseStatus.OPEN,
        severity=data.severity,
        created_by_id=current_user.id,
        assigned_to_id=data.assigned_to_id if data.assigned_to_id else current_user.id,
        affected_hosts=data.affected_hosts,
        affected_users=data.affected_users,
        triggered_rules=data.triggered_rules,
        evidence_summary=data.evidence_summary,
        source_alert_ids=data.alert_ids,
    )
    # Collision-free number from the DB-assigned id (was max(id)+1 — raced).
    case_number = assign_case_number(session, new_case)

    # Link alert IDs if provided
    linked = 0
    if data.alert_ids:
        # (Bug 2): build a lookup of alert_id -> rule_name from
        # the supplied raw_data so newly-created triage rows carry a
        # human-readable name. Falls through to None where raw_data
        # wasn't sent or doesn't expose rule.name.
        rule_name_by_alert: Dict[str, Optional[str]] = {}
        if data.alert_contexts:
            for ctx in data.alert_contexts:
                rd = ctx.raw_data or {}
                rule_name_by_alert[ctx.alert_id] = (
                    (rd.get("rule") or {}).get("name")
                    or rd.get("kibana.alert.rule.name")
                    or (rd.get("_source", {}).get("rule") or {}).get("name")
                    if isinstance(rd, dict) else None
                )

        for alert_id in data.alert_ids:
            triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
            if not triage:
                triage = AlertTriage(
                    es_alert_id=alert_id,
                    status=AlertTriageStatus.ACKNOWLEDGED,
                    rule_name=rule_name_by_alert.get(alert_id),
                )
                session.add(triage)
                session.flush()
            else:
                # (Bug 3): if the alert was already linked to a
                # different case, the previous case's source_alert_ids
                # JSON still references it. That divergence is what made
                # "linked cases" displays disagree with the FK-driven
                # truth. Strip this alert from the prior case's JSON so
                # the two views stay consistent.
                if triage.case_id is not None and triage.case_id != new_case.id:
                    old_case = session.query(AlertCase).filter_by(id=triage.case_id).first()
                    if old_case is not None and old_case.source_alert_ids:
                        try:
                            old_ids = list(old_case.source_alert_ids)
                            if alert_id in old_ids:
                                old_case.source_alert_ids = [x for x in old_ids if x != alert_id]
                                logger.warning(
                                    "create_case: alert %s reassigned %s -> %s; pruned old source_alert_ids",
                                    alert_id, old_case.case_number, case_number,
                                )
                        except Exception as exc:
                            logger.warning(
                                "create_case: failed to prune old source_alert_ids on %s: %s",
                                old_case.case_number, exc,
                            )
                # Backfill rule_name on legacy rows if we now have it.
                if not triage.rule_name and rule_name_by_alert.get(alert_id):
                    triage.rule_name = rule_name_by_alert[alert_id]
            triage.case_id = new_case.id
            linked += 1
            # emit alert_linked audit row keyed on the triage PK so
            # the adaptive lab grader's linked_to_case evaluator can match
            # via lab_session_fixtures (which stores materialised_row_id =
            # AlertTriage.id). Best-effort — failure logs and proceeds, the
            # case link itself has already been set above.
            try:
                AuditLogRepository(session).create(
                    action="alert_linked",
                    user_id=current_user.id,
                    resource_type="alert_triage",
                    resource_id=triage.id,
                    details={"case_id": new_case.id, "es_alert_id": alert_id},
                )
            except Exception:
                logger.exception(
                    "alert_linked audit write failed (case-create path, non-fatal)"
                )

    # harvest observables from EVERY linked AlertTriage rather
    # than only those the client supplied alert_contexts for. The earlier
    # path was lossy — if the frontend linked 5 alerts but only sent
    # raw_data for 2 of them, the remaining 3 alerts contributed zero
    # observables, even though their triage rows already had the full
    # observable list extracted at triage time.
    #
    # Primary source: AlertTriage.observables (pre-extracted JSON list).
    # Fallback: re-extract from any client-supplied raw_data — covers
    # alerts whose triage rows are freshly created by the loop above
    # and therefore have observables=None.
    context_map: Dict[str, Any] = {}
    if data.alert_contexts:
        context_map = {ctx.alert_id: ctx for ctx in data.alert_contexts}

    harvested_observables: List[Dict[str, Any]] = []
    raw_data_fallback: List[Dict[str, Any]] = []

    for alert_id in (data.alert_ids or []):
        triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
        ctx = context_map.get(alert_id)

        # Top up triage.observables from raw_data when both are present —
        # this keeps the legacy triage-side observable list current.
        if triage and ctx:
            _populate_triage_observables(triage, ctx.host, ctx.user, ctx.raw_data)

        if triage and triage.observables:
            for obs in triage.observables:
                if isinstance(obs, dict) and obs.get("type") and obs.get("value"):
                    harvested_observables.append({"type": obs["type"], "value": obs["value"]})
        elif ctx and ctx.raw_data:
            # Triage has no observables yet — fall back to extracting
            # from this alert's raw_data on the spot.
            raw_data_fallback.append(ctx.raw_data)
        else:
            logger.info("create_case: alert %s has neither triage observables nor raw_data", alert_id)

    logger.info(
        "create_case: harvested %d observables from triage; %d raw_data items pending fallback extraction",
        len(harvested_observables), len(raw_data_fallback),
    )

    session.commit()
    session.refresh(new_case)

    # Extract, normalize, enrich, and link observables to case
    from ion.services.observable_service import get_observable_service
    obs_service = get_observable_service(session)

    # snapshot ObservableLink.id BEFORE the extract calls so the
    # audit pass below knows which links are genuinely new. Feeds the
    # adaptive lab-grading observable_created evaluator.
    from sqlalchemy import func as _func

    from ion.models.observable import ObservableLink as _ObservableLink
    _max_link_id_before = (
        session.query(_func.coalesce(_func.max(_ObservableLink.id), 0)).scalar() or 0
    )

    # Primary path — pre-extracted observables from every linked triage.
    enriched_observables = await obs_service.enrich_and_link_observables_for_case(
        case_id=new_case.id,
        observables=harvested_observables,
    )

    # Fallback path — extract from raw_data for alerts whose triage rows
    # are empty. This still hits OpenCTI for enrichment and links the
    # observables to the case; results are merged into the same list.
    if raw_data_fallback:
        fallback_results = await obs_service.extract_enrich_for_case(
            case_id=new_case.id,
            raw_data_list=raw_data_fallback,
        )
        # De-dup by (type, value) so the same observable isn't double-counted
        # if it shows up in both the harvest and the fallback.
        seen_keys = {(r.get("type"), r.get("value")) for r in (enriched_observables or [])}
        for r in (fallback_results or []):
            if (r.get("type"), r.get("value")) not in seen_keys:
                enriched_observables.append(r)
                seen_keys.add((r.get("type"), r.get("value")))

    # Store enriched observables on the case (for display and Kibana sync)
    case_observables = enriched_observables or []
    logger.info("create_case: %d observables enriched for case %s", len(case_observables), case_number)
    if case_observables:
        new_case.observables = case_observables
        session.commit()

    # emit observable_linked audit rows for new ObservableLink rows
    # created by the extract calls above. Best-effort; never blocks the
    # response. Feeds the adaptive lab-grading observable_created evaluator.
    try:
        from sqlalchemy.orm import joinedload as _joinedload
        new_links = (
            session.query(_ObservableLink)
            .options(_joinedload(_ObservableLink.observable))
            .filter(_ObservableLink.id > int(_max_link_id_before))
            .all()
        )
        for link in new_links:
            obs = link.observable
            obs_type = (
                obs.type.value if obs and hasattr(obs.type, "value")
                else str(getattr(obs, "type", "")) if obs else ""
            )
            try:
                AuditLogRepository(session).create(
                    action="observable_linked",
                    user_id=current_user.id,
                    resource_type="observable",
                    resource_id=link.observable_id,
                    details={
                        "observable_id": link.observable_id,
                        "observable_type": obs_type,
                        "link_type": (
                            link.link_type.value
                            if hasattr(link.link_type, "value")
                            else str(link.link_type)
                        ),
                        "entity_id": link.entity_id,
                        "context": link.context,
                    },
                )
            except Exception:
                logger.exception(
                    "observable_linked audit write failed in create_case (non-fatal)"
                )
    except Exception:
        logger.exception(
            "observable_linked audit batch failed in create_case (non-fatal)"
        )

    # ── v0.16.0 / v0.25.x: PCAP auto-analysis ────────────────────────────
    #
    # For every linked alert that carries ``network.community_id`` (the
    # Zeek/Arkime flow hash), fire a background task that:
    #   1. resolves the community_id to an Arkime session,
    #   2. downloads the matching PCAP,
    #   3. parses it via ``pcap_service.parse_pcap`` (dpkt),
    #   4. posts a markdown analysis as a case Note attributed to Bob.
    #
    # v0.25.x changes:
    #   - **Multi-alert support.** Previously the runner took a single
    #     ``alert_node_hint`` for all flows; now each flow carries its
    #     own node hint so cases with alerts on different capture nodes
    #     work correctly.
    #   - **ES fallback for missing raw_data.** The alerts list endpoint
    #     sends ``include_raw=False`` to cut payload, so multi-select
    #     case creation has empty ``ctx.raw_data`` per alert. We now
    #     fetch the missing alerts via ``get_alerts_by_ids`` (one round
    #     trip, source = the full _source doc) so community_id can be
    #     extracted from the actual ES document.
    #   - **Node-hint bug fix.** The previous ``or`` + ternary form
    #     dropped the top-level ``arkime_node`` when no nested
    #     ``arkime`` dict was present.
    #
    # Best-effort: never blocks case creation, never raises into the
    # response.
    try:
        pcap_flows = await _build_pcap_flows(
            alert_ids=(data.alert_ids or []),
            alert_contexts=data.alert_contexts,
        )
        if pcap_flows:
            from ion.services.pcap_analysis_service import enqueue_pcap_analysis_for_case
            enqueue_pcap_analysis_for_case(
                case_id=new_case.id,
                flows=pcap_flows,
            )
            logger.info(
                "create_case: queued PCAP auto-analysis for case %s (%d flows)",
                case_number, len(pcap_flows),
            )
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("create_case: PCAP auto-analysis enqueue failed: %s", exc)

    await _sync_case_to_es(new_case, session)

    # Cases redesign: summarize enriched observables into a case Note.
    # Gated / air-gap safe — a no-op when there's no enrichment to report
    # (OpenCTI unconfigured), so nothing is written for air-gapped deployments.
    try:
        await post_enrichment_note(
            session, new_case.id, current_user.id, current_user.username
        )
    except Exception:
        logger.debug("post_enrichment_note skipped for case %s", new_case.id, exc_info=True)

    # Resolve Kibana assignee UID for case creation.
    # Read the assignee from `new_case.assigned_to_id` (already persisted) rather than
    # `data.assigned_to_id`. Line 4319 falls back to `current_user.id` when the request
    # body has no assignee, so reading `data.*` here misses the auto-assigned creator
    # and produced the symptom: ION case had an assignee but the Kibana case did not.
    create_assignee_uid = None
    if new_case.assigned_to_id:
        assignee_user = session.query(User).filter_by(id=new_case.assigned_to_id).first()
        if assignee_user:
            if assignee_user.elastic_uid:
                create_assignee_uid = assignee_user.elastic_uid
            else:
                try:
                    from ion.services.kibana_cases_service import get_kibana_cases_service
                    kb_svc = get_kibana_cases_service()
                    if kb_svc.enabled:
                        # Try elastic_username first, then ION username
                        lookup_name = getattr(assignee_user, 'elastic_username', None) or assignee_user.username
                        uid = kb_svc.resolve_user_uid(lookup_name)
                        if not uid and lookup_name != assignee_user.username:
                            uid = kb_svc.resolve_user_uid(assignee_user.username)
                        if uid:
                            create_assignee_uid = uid
                            assignee_user.elastic_uid = uid
                            session.commit()
                except Exception:
                    pass

    # Sync to Kibana Cases if enabled
    kibana_url = None
    kibana_result = sync_new_case_to_kibana(
        case_number=case_number,
        title=data.title,
        description=data.description,
        severity=data.severity,
        affected_hosts=data.affected_hosts,
        affected_users=data.affected_users,
        evidence_summary=data.evidence_summary,
        observables=case_observables,
        alert_ids=data.alert_ids,
        triggered_rules=data.triggered_rules,
        assignee_elastic_uid=create_assignee_uid,
    )
    if kibana_result:
        new_case.kibana_case_id = kibana_result["kibana_case_id"]
        new_case.kibana_case_version = kibana_result["kibana_case_version"]
        kibana_url = kibana_result["kibana_url"]
        session.commit()

    # Auto-check KFP registry for matches
    fp_suggestions = _match_known_false_positives(
        session,
        hosts=data.affected_hosts,
        users=data.affected_users,
        ips=[o["value"] for o in (case_observables or []) if o.get("type") in ("source_ip", "destination_ip")],
        rules=data.triggered_rules,
    )

    # Auto-close case if strong KFP match (rules + at least one other field)
    auto_closed = False
    auto_closed_kfp = None
    for fp in fp_suggestions:
        matched = fp.get("matched_fields", [])
        if "rules" in matched and len(matched) >= 2:
            # Strong match — auto-close the case
            new_case.status = AlertCaseStatus.CLOSED
            new_case.closure_reason = "false_positive"
            new_case.closed_by_id = current_user.id
            new_case.closed_at = datetime.utcnow()

            # Set all linked triage entries to CLOSED
            for triage_entry in new_case.triage_entries:
                triage_entry.status = AlertTriageStatus.CLOSED

            # Add auto-closure note
            auto_note = Note(
                entity_type=NoteEntityType.CASE,
                entity_id=str(new_case.id),
                user_id=current_user.id,
                content=f"**Auto-closed as Known False Positive**\n\nMatched KFP: {fp['title']} (ID: {fp['id']})\nMatched fields: {', '.join(matched)}",
            )
            session.add(auto_note)
            session.commit()

            if new_case.kibana_case_id:
                sync_note_to_kibana(new_case.kibana_case_id, current_user.username, auto_note.content)

            auto_closed = True
            auto_closed_kfp = fp
            break

    # run Bob on the freshly-created case (single OR multi alert) and
    # post its analysis as a case comment — same as auto-grouped cases, so
    # manually-created cases get Bob too. Fire-and-forget; gated by the unified
    # case auto-investigate switch, skipped for auto-closed FP cases.
    try:
        from ion.core.config import get_config
        if _should_investigate_new_case(
            auto_closed, new_case.source_alert_ids,
            getattr(get_config(), "case_grouper_auto_investigate", True),
        ):
            from ion.services.case_grouper_service import enqueue_case_investigation
            enqueue_case_investigation(new_case.id)
            logger.info("Bob case investigation enqueued for new case %s", new_case.case_number)
    except Exception:
        logger.debug("enqueue_case_investigation failed for new case %s",
                     getattr(new_case, "id", "?"), exc_info=True)

    return {
        "id": new_case.id,
        "case_number": new_case.case_number,
        "title": new_case.title,
        "status": new_case.status.value if hasattr(new_case.status, "value") else new_case.status,
        "linked_alerts": linked,
        "observables": new_case.observables or [],
        "kibana_case_id": new_case.kibana_case_id,
        "kibana_url": kibana_url,
        "dfir_iris_case_id": new_case.dfir_iris_case_id,
        "dfir_iris_url": None,
        "fp_suggestions": fp_suggestions,
        "auto_closed": auto_closed,
        "auto_closed_kfp": auto_closed_kfp,
    }

@router.post("/elasticsearch/alerts/cases/{case_id}/notes")
async def add_case_note(
    case_id: int,
    data: CaseNoteCreate,
    current_user: User = Depends(require_permission("case:update")),
    session: Session = Depends(get_db_session),
):
    """Add an investigation note to a case."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    note = Note(
        entity_type=NoteEntityType.CASE,
        entity_id=str(case_id),
        user_id=current_user.id,
        content=data.content,
    )
    session.add(note)
    session.commit()
    session.refresh(case)
    await _sync_case_to_es(case, session)

    # Sync note to Kibana as comment
    sync_note_to_kibana(case.kibana_case_id, current_user.username, data.content)

    return {
        "id": note.id,
        "case_id": note.case_id,
        "user": current_user.username,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }

@router.get("/elasticsearch/alerts/cases/{case_id}/similar")
async def get_similar_cases(
    case_id: int,
    limit: int = 5,
    min_similarity: float = 0.5,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """Top-N closed cases most similar to this one (pgvector cosine distance).

    Used by the "Similar cases" sidebar to help analysts spot campaigns and
    reuse prior closure verdicts. Only returns cases where a human set a
    closure_reason — excludes open cases and the query case itself.
    """
    # Narrow to cases that actually have a human verdict we can trust.
    # Empty list is a valid answer (Ollama unreachable, or not embedded yet).
    from ion.models.case_embedding import CaseEmbedding

    target = session.query(CaseEmbedding).filter_by(case_id=case_id).first()
    if target is None:
        return {"similar": [], "reason": "query case not embedded yet"}

    # Use pgvector's ORM method so SQLAlchemy + psycopg2 handle type
    # conversion (numpy ndarray → pgvector literal) via the registered
    # adapter. Cosine distance: 0 = identical, 1 = orthogonal, 2 = opposite.
    safe_limit = max(1, min(int(limit), 25))
    distance = CaseEmbedding.embedding.cosine_distance(target.embedding)
    rows = (
        session.query(AlertCase, distance.label("distance"))
        .join(CaseEmbedding, CaseEmbedding.case_id == AlertCase.id)
        .filter(AlertCase.id != case_id)
        .filter(AlertCase.closure_reason.isnot(None))
        .order_by(distance.asc())
        .limit(safe_limit)
        .all()
    )
    items = []
    for case, dist in rows:
        similarity = 1.0 - float(dist)
        if similarity < float(min_similarity):
            continue
        items.append({
            "case_id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "severity": case.severity,
            "closure_reason": case.closure_reason,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "similarity": round(similarity, 3),
        })
    return {"similar": items, "count": len(items)}

@router.get("/elasticsearch/alerts/cases/{case_id}/timeline")
async def get_case_timeline(
    case_id: int,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """v0.10.20 — Attack Story Timeline (Hunters-inspired).

    Aggregates every chronological event tied to a case into a single
    sorted feed:

    - **system** — case creation, alert linkage, observable extraction,
      playbook starts/completions, kibana sync events
    - **analyst** — investigation notes, status changes, sign-offs
    - **bob** — autonomous investigations with verdict, key observations,
      and a narrative reference back to the prompt template

    Each event carries ``ts``, ``kind``, ``phase`` (MITRE tactic when
    derivable), ``title``, ``detail``, ``source_type``, ``source_id``
    so the UI can render parallel lanes + drill-down.

    Heavy lifting is small: every source already stamps timestamps; this
    just unions them and sorts.
    """
    from ion.models.investigation import Investigation
    from ion.models.observable import Observable, ObservableLink, ObservableLinkType

    case: Optional[AlertCase] = session.get(AlertCase, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    events: List[dict] = []

    def _ev(ts, kind, title, *, phase=None, detail=None, source_type=None, source_id=None, citations=None):
        if ts is None:
            return
        events.append({
            "ts": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
            "kind": kind,
            "phase": phase,
            "title": title,
            "detail": detail,
            "source_type": source_type,
            "source_id": source_id,
            "citations": citations or [],
        })

    # ── Case lifecycle (system) ────────────────────────────────────────────
    _ev(
        case.created_at, "system", f"Case opened: {case.title or case.case_number}",
        detail=f"Severity: {case.severity or 'unspecified'}",
        source_type="case", source_id=case.id,
    )
    if case.closed_at:
        _ev(
            case.closed_at, "system", "Case closed",
            detail=f"Closure reason: {case.closure_reason or 'unspecified'}",
            source_type="case", source_id=case.id,
        )

    # ── Notes (analyst) ────────────────────────────────────────────────────
    note_rows = (
        session.query(Note)
        .filter(Note.entity_type == NoteEntityType.CASE)
        .filter(Note.entity_id == str(case_id))
        .order_by(Note.created_at.asc())
        .all()
    )
    for n in note_rows:
        author = "Analyst"
        try:
            if n.user and getattr(n.user, "username", None):
                author = n.user.username
        except Exception:
            pass
        # Bob-authored notes start with the "🤖 Bob (AI analyst)" marker
        # added by _render_bob_alert_note. Tagging them as `bob` keeps the
        # parallel-lane render clean — analyst notes vs Bob commentary.
        kind = "bob" if (n.content or "").lstrip().startswith("**🤖 Bob") else "analyst"
        title = "Bob commentary" if kind == "bob" else f"Note from {author}"
        _ev(
            n.created_at, kind, title,
            detail=(n.content or "")[:1200],
            source_type="note", source_id=n.id,
        )

    # ── Linked alerts (system) ─────────────────────────────────────────────
    triage_entries = list(case.triage_entries or [])
    for t in triage_entries:
        ts = getattr(t, "created_at", None) or getattr(t, "first_seen_at", None)
        _ev(
            ts, "system", f"Alert linked: {(t.es_alert_id or '')[:24]}",
            detail=f"Status: {getattr(t, 'status', '')}",
            source_type="alert", source_id=t.es_alert_id,
        )

    # ── Investigations (Bob) ───────────────────────────────────────────────
    alert_ids = [t.es_alert_id for t in triage_entries if t.es_alert_id]
    if alert_ids:
        inv_rows = (
            session.query(Investigation)
            .filter(Investigation.alert_id_ref.in_(alert_ids))
            .order_by(Investigation.created_at.asc())
            .all()
        )
        for inv in inv_rows:
            citations = []
            if inv.key_observations_json:
                try:
                    obs_data = json.loads(inv.key_observations_json)
                    if isinstance(obs_data, list):
                        citations = obs_data[:5]
                except Exception:
                    pass
            verdict = inv.verdict or "in-progress"
            ts = inv.completed_at or inv.created_at
            _ev(
                ts, "bob",
                f"Bob investigated alert {(inv.alert_id_ref or '')[:24]} → {verdict}",
                detail=(inv.summary_text or "")[:1200],
                source_type="investigation", source_id=inv.id,
                citations=citations,
            )

    # ── Observable extraction (system) ─────────────────────────────────────
    case_obs_links = (
        session.query(ObservableLink)
        .filter(ObservableLink.link_type == ObservableLinkType.CASE)
        .filter(ObservableLink.entity_id == case_id)
        .all()
    )
    if case_obs_links:
        obs_ids = [l.observable_id for l in case_obs_links]
        obs_rows = session.query(Observable).filter(Observable.id.in_(obs_ids)).all()
        obs_by_id = {o.id: o for o in obs_rows}
        for link in case_obs_links:
            o = obs_by_id.get(link.observable_id)
            if not o:
                continue
            _ev(
                link.created_at, "system",
                f"Observable: {o.value[:64]}",
                detail=f"Type: {o.type.value if hasattr(o.type, 'value') else o.type} · Threat: {o.threat_level.value if hasattr(o.threat_level, 'value') else o.threat_level}",
                source_type="observable", source_id=o.id,
            )

    # ── Playbook executions (system) ───────────────────────────────────────
    pb_runs = (
        session.query(PlaybookExecution)
        .filter(PlaybookExecution.case_id == case_id)
        .all()
    )
    for run in pb_runs:
        if run.started_at:
            pb_name = ""
            try:
                pb_name = run.playbook.name if run.playbook else ""
            except Exception:
                pass
            _ev(
                run.started_at, "system",
                f"Playbook started: {pb_name or '#' + str(run.playbook_id)}",
                detail=f"Status: {run.status}",
                source_type="playbook", source_id=run.id,
            )
        if run.completed_at:
            _ev(
                run.completed_at, "system",
                f"Playbook finished: outcome={run.outcome or 'n/a'}",
                detail=(run.outcome_notes or "")[:600],
                source_type="playbook", source_id=run.id,
            )

    # Sort chronologically. Stable sort means events at the same instant
    # keep the order they were appended, which is good — case-creation
    # naturally precedes first note etc.
    events.sort(key=lambda e: e["ts"])

    # Surface the latest Bob investigation as the "narrative" header so
    # the UI can show "Bob's current take" without an extra LLM call.
    narrative: Optional[dict] = None
    bob_events = [e for e in events if e["kind"] == "bob" and e["source_type"] == "investigation"]
    if bob_events:
        latest = bob_events[-1]
        narrative = {
            "summary": latest.get("detail") or latest.get("title"),
            "verdict": latest["title"].split("→")[-1].strip() if "→" in latest["title"] else None,
            "investigation_id": latest.get("source_id"),
            "citations": latest.get("citations") or [],
            "ts": latest.get("ts"),
        }

    return {
        "case_id": case_id,
        "events": events,
        "narrative": narrative,
        "counts": {
            "total": len(events),
            "system": sum(1 for e in events if e["kind"] == "system"),
            "analyst": sum(1 for e in events if e["kind"] == "analyst"),
            "bob": sum(1 for e in events if e["kind"] == "bob"),
        },
    }

@router.get("/elasticsearch/alerts/cases/{case_id}/attack-path")
async def get_case_attack_path(
    case_id: int,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """Attack Path (Bob Pathfinding) — Phase 0.

    Deterministic, compute-on-read attack-path graph for a case: dedupes the
    entities across the case's alerts into typed nodes, derives the four edge
    types (process lineage, network flow, user→host presence, shared-observable
    cross-alert linkage), and orders nodes/alerts into MITRE-tactic "lanes"
    along the kill chain (initial-access → impact).

    Advisory, read-only, air-gap-safe: no LLM, no writes, and no network beyond
    the existing ES alert fetch (a no-op when ES is unconfigured — the graph is
    still valid, just empty). See ``attack_path_service.build_attack_path`` for
    the emitted schema (``nodes``/``edges``/``phases``/``stats``).
    """
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    from ion.services.attack_path_service import build_attack_path
    return await build_attack_path(session, case_id)

@router.get("/elasticsearch/alerts/cases/{case_id}/similar-observables")
async def get_case_similar_observables(
    case_id: int,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """v0.10.19 — TheHive-style observable linking.

    For each observable attached to this case, finds OTHER cases that
    share the same (type, normalized_value). The pgvector "similar cases"
    endpoint above is semantic ("looks like"); this is deterministic
    ("literally the same indicator").

    Filters out:
    - Observables marked ``ignore_similarity`` (high-noise values like
      8.8.8.8, internal DNS resolvers)
    - Observables marked ``is_whitelisted``
    - Self-referential matches (same case)

    Response shape:
    ``{"shared": [{observable, sightings: [{case_id, case_number, title,
    severity, status, last_seen}, ...]}, ...]}``
    """
    from ion.models.observable import Observable, ObservableLink, ObservableLinkType

    # Walk all observables linked to this case via ObservableLink. The
    # case's `observables` relationship may not exist on every schema
    # variant, so go through the link table directly.
    case_links = (
        session.query(ObservableLink)
        .filter(ObservableLink.link_type == ObservableLinkType.CASE)
        .filter(ObservableLink.entity_id == case_id)
        .all()
    )
    case_observable_ids = {link.observable_id for link in case_links}
    if not case_observable_ids:
        return {"shared": [], "count": 0}

    case_observables = (
        session.query(Observable)
        .filter(Observable.id.in_(case_observable_ids))
        .filter(Observable.ignore_similarity.is_(False))
        .filter(Observable.is_whitelisted.is_(False))
        # analyst-ignored indicators must not drive cross-case
        # correlation either (baseline F1 — this path was never filtered).
        .filter(Observable.is_ignored.is_(False))
        .all()
    )

    shared_out: List[dict] = []
    for obs in case_observables:
        # Find other cases linking the same observable. The Observable row
        # is unique per (type, normalized_value), so other-case-link rows
        # pointing at this same observable.id give us the answer directly
        # — no need to fan out via normalized_value.
        sightings_links = (
            session.query(ObservableLink)
            .filter(ObservableLink.observable_id == obs.id)
            .filter(ObservableLink.link_type == ObservableLinkType.CASE)
            .filter(ObservableLink.entity_id != case_id)
            .order_by(ObservableLink.created_at.desc())
            .limit(25)
            .all()
        )
        if not sightings_links:
            continue
        # Pull the matched cases in one round-trip.
        other_case_ids = list({l.entity_id for l in sightings_links})
        other_cases = (
            session.query(AlertCase)
            .filter(AlertCase.id.in_(other_case_ids))
            .all()
        )
        case_by_id = {c.id: c for c in other_cases}
        sightings_payload = []
        for link in sightings_links:
            c = case_by_id.get(link.entity_id)
            if not c:
                continue
            sightings_payload.append({
                "case_id": c.id,
                "case_number": c.case_number,
                "title": c.title,
                "severity": c.severity,
                "status": c.status.value if hasattr(c.status, "value") else str(c.status),
                "last_seen": link.created_at.isoformat() if link.created_at else None,
            })
        if not sightings_payload:
            continue
        shared_out.append({
            "observable": {
                "id": obs.id,
                "type": obs.type.value if hasattr(obs.type, "value") else str(obs.type),
                "value": obs.value,
                "normalized_value": obs.normalized_value,
                "tlp": obs.tlp,
                "pap": obs.pap,
                "is_ioc": obs.is_ioc,
                "threat_level": obs.threat_level.value if hasattr(obs.threat_level, "value") else str(obs.threat_level),
                "sighting_count": obs.sighting_count,
                "first_seen": obs.first_seen.isoformat() if obs.first_seen else None,
                "last_seen": obs.last_seen.isoformat() if obs.last_seen else None,
            },
            "sightings": sightings_payload,
        })

    # Sort observables by number of cross-case sightings so the analyst
    # sees the most-shared indicators first.
    shared_out.sort(key=lambda r: len(r["sightings"]), reverse=True)
    return {"shared": shared_out, "count": len(shared_out)}

@router.get("/elasticsearch/alerts/cases/{case_id}")
async def get_case_detail(
    case_id: int,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """Get case detail with linked alerts."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # never serve analyst-ignored observables, even if this case
    # hasn't been re-investigated since the flag was set (baseline F1).
    from ion.services.investigation_service import (
        _ignored_normalized_values,
        _prune_ignored_observables,
    )
    _case_observables_view = _prune_ignored_observables(
        list(case.observables or []), _ignored_normalized_values(session)
    )

    # Get Kibana URL if available
    kibana_url = get_kibana_case_url(case.kibana_case_id)

    # Resolve Kibana assignees (read direction): if the case is linked to a
    # Kibana case, fetch its current assignees, resolve the opaque UIDs to
    # user profiles via the ES native API, and map each profile back to an
    # ION user via users.elastic_uid. The UI uses this to show whichever
    # state Kibana actually has — useful when assignment was made externally.
    #
    # Self-healing: if a UID isn't cached on any ION user but the resolved
    # ES username matches an ION user that has no elastic_uid yet, the
    # mapping is filled in. This means the FIRST read after an external
    # Kibana assignment is enough to bind the ION user to its Kibana profile.
    #
    # SYNC RACE GRACE WINDOW: v0.9.81 moved the Kibana case sync
    # off the request path into a BackgroundTask, which introduced a ~1s
    # race where a PATCH returns success and the UI refreshes faster than
    # Kibana has accepted the new assignee. During that window the mismatch
    # pill ("ION and Kibana disagree") was firing as a false positive.
    # Fix: if the case was updated within the grace window, skip the live
    # Kibana fetch entirely — the UI falls back to ION's local state which
    # is what the user just set. Next refresh after grace expires reads
    # real Kibana state and mismatch detection works normally.
    kibana_sync_pending = False
    if case.updated_at is not None:
        _age_s = (datetime.utcnow() - case.updated_at).total_seconds()
        if 0 <= _age_s < 15:
            kibana_sync_pending = True

    kibana_assignees: list[dict] = []
    if case.kibana_case_id and not kibana_sync_pending:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            from ion.services.kibana_cases_service import get_kibana_cases_service
            kb = get_kibana_cases_service()
            if kb.enabled:
                kb_case = kb.get_case(case.kibana_case_id)
                if kb_case:
                    raw_assignees = kb_case.get("assignees") or []
                    uids = [a.get("uid") for a in raw_assignees if isinstance(a, dict) and a.get("uid")]
                    if uids:
                        es = ElasticsearchService()
                        if es.is_configured:
                            profile_map = await es.bulk_get_user_profiles(uids)
                            # Reverse-lookup ION users in one query
                            ion_users = session.query(User).filter(User.elastic_uid.in_(uids)).all()
                            ion_by_uid = {u.elastic_uid: u for u in ion_users}
                            self_healed = False
                            for uid in uids:
                                profile = profile_map.get(uid) or {}
                                puser = profile.get("user") if isinstance(profile, dict) else None
                                puser = puser if isinstance(puser, dict) else {}
                                ion_user = ion_by_uid.get(uid)

                                # Self-heal: bind a UID-less ION user to this profile
                                # by exact username match.
                                if not ion_user and puser.get("username"):
                                    candidate = (
                                        session.query(User)
                                        .filter(User.username == puser["username"])
                                        .filter((User.elastic_uid.is_(None)) | (User.elastic_uid == ""))
                                        .first()
                                    )
                                    if candidate:
                                        candidate.elastic_uid = uid
                                        ion_user = candidate
                                        self_healed = True
                                        logger.info(
                                            "Auto-cached elastic_uid for %s from Kibana case read: %s",
                                            candidate.username, uid,
                                        )

                                kibana_assignees.append({
                                    "uid": uid,
                                    "username": puser.get("username"),
                                    "full_name": puser.get("full_name"),
                                    "email": puser.get("email"),
                                    "ion_user_id": ion_user.id if ion_user else None,
                                    "ion_username": ion_user.username if ion_user else None,
                                    "ion_display_name": (ion_user.display_name or ion_user.username) if ion_user else None,
                                })
                            if self_healed:
                                session.commit()
        except Exception as e:
            logger.debug(f"Failed to resolve Kibana assignees for case {case_id}: {e}")

    # Get DFIR-IRIS URL if available
    dfir_iris_url = None
    if case.dfir_iris_case_id:
        try:
            iris_svc = get_dfir_iris_service()
            dfir_iris_url = iris_svc.get_case_url(case.dfir_iris_case_id)
        except Exception:
            pass

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "severity": case.severity,
        "created_by": case.created_by.username if case.created_by else None,
        "assigned_to": case.assigned_to.username if case.assigned_to else None,
        "assigned_to_id": case.assigned_to_id,
        # Live Kibana-side assignees, resolved through ES profile API.
        # Empty when no Kibana case is linked OR Kibana has no assignees
        # OR we're inside the post-write grace window (see kibana_sync_pending).
        "kibana_assignees": kibana_assignees,
        # True if the case was written within the last 15s and the
        # background Kibana sync may not yet have propagated. UI can use
        # this to hint "syncing…" instead of rendering stale state.
        "kibana_sync_pending": kibana_sync_pending,
        "affected_hosts": case.affected_hosts,
        "affected_users": case.affected_users,
        "triggered_rules": case.triggered_rules,
        "evidence_summary": case.evidence_summary,
        "source_alert_ids": case.source_alert_ids,
        "observables": _case_observables_view,
        "kibana_case_id": case.kibana_case_id,
        "kibana_url": kibana_url,
        "dfir_iris_case_id": case.dfir_iris_case_id,
        "dfir_iris_url": dfir_iris_url,
        "closure_reason": case.closure_reason,
        "closure_notes": case.closure_notes,
        "closed_by": case.closed_by.username if case.closed_by else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "alerts": [
            {
                "es_alert_id": t.es_alert_id,
                # (Bug 2): rule_name surfaced so the case detail
                # card shows "Suspicious PowerShell Execution" instead
                # of an opaque ES alert id. Falls back null on legacy
                # rows; template handles by showing id-substring.
                "rule_name": t.rule_name,
                "status": t.status.value if hasattr(t.status, "value") else t.status,
                "priority": t.priority,
                "observables": t.observables or [],
                "mitre_techniques": t.mitre_techniques or [],
                "analyst_notes": t.analyst_notes,
            }
            for t in case.triage_entries
        ],
        "notes": [
            {
                "id": n.id,
                "user": n.user.username if n.user else "Unknown",
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in case.notes
        ],
    }

@router.patch("/elasticsearch/alerts/cases/{case_id}")
async def update_case(
    case_id: int,
    data: CaseUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("case:update")),
    session: Session = Depends(get_db_session),
):
    """Update case status, assignee, title, etc.

    v0.9.81: external syncs (Kibana case sync, ES case mirror, alert
    workflow_status) moved to FastAPI BackgroundTasks so the response
    returns as soon as the Postgres commit lands. Previously a slow Kibana
    could block this endpoint for the full 30s nginx upstream timeout and
    surface as a 502 to the user.

    The Kibana sync is also short-circuited when none of the
    Kibana-relevant fields (title/description/status/severity/assignee)
    actually changed — so edits on case type, notes, etc. never touch
    Kibana at all.
    """
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if data.title is not None:
        case.title = data.title
    if data.description is not None:
        case.description = data.description
    if data.severity is not None:
        case.severity = data.severity
    if data.assigned_to_id is not None:
        case.assigned_to_id = data.assigned_to_id
        # Commit the assignment immediately so it persists even if Kibana sync fails
        session.commit()
    _synced_alert_ids = []
    _mapped_triage = None
    if data.status is not None:
        old_status = case.status.value if hasattr(case.status, "value") else case.status
        new_status = data.status
        # Closing: require closure_reason
        if new_status == "closed" and old_status != "closed":
            if not data.closure_reason:
                raise HTTPException(
                    status_code=400,
                    detail="closure_reason is required when closing a case",
                )
            valid_reasons = {r.value for r in CaseClosureReason}
            if data.closure_reason not in valid_reasons:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid closure_reason. Must be one of: {', '.join(sorted(valid_reasons))}",
                )
            case.closure_reason = data.closure_reason
            case.closure_notes = data.closure_notes
            case.closed_by_id = current_user.id
            case.closed_at = datetime.utcnow()

            # audit the transition for the adaptive lab-grading
            # case_closed_with_reason evaluator. Best-effort; never blocks
            # the close. The guard at line 5269 ensures we only fire on a
            # real OPEN→CLOSED transition (not re-PATCHing closure_notes
            # on an already-closed case).
            try:
                AuditLogRepository(session).create(
                    action="case_closed",
                    user_id=current_user.id,
                    resource_type="alert_case",
                    resource_id=case.id,
                    details={
                        "case_id": case.id,
                        "case_number": case.case_number,
                        "closure_reason": data.closure_reason,
                        "closure_notes": data.closure_notes,
                    },
                )
            except Exception:
                logger.exception(
                    "case_closed audit write failed (non-fatal)"
                )

            # Capture AIFeedback ledger rows — per-template agreement metrics
            # feed the detection-engineering scorecard. Best-effort; never
            # blocks the close.
            try:
                from ion.services.ai_feedback_service import (
                    record_case_close_feedback,
                )
                record_case_close_feedback(
                    case=case,
                    human_verdict=data.closure_reason,
                    human_closed_by_id=current_user.id,
                    delta_reason=data.closure_notes,
                    session=session,
                )
            except Exception as _fb_exc:
                logger.debug("AIFeedback capture skipped: %s", _fb_exc)

            # Add closure note to the case journal and sync to Kibana
            reason_label = data.closure_reason.replace("_", " ").title()
            closure_note = Note(
                entity_type=NoteEntityType.CASE,
                entity_id=str(case_id),
                user_id=current_user.id,
                content=f"**Case closed as {reason_label}**\n\nNotes: {data.closure_notes or 'N/A'}",
            )
            session.add(closure_note)
            if case.kibana_case_id:
                sync_note_to_kibana(case.kibana_case_id, current_user.username, closure_note.content)

            # --- Auto-FP suppression: create KFP + investigation memory ---
            if data.closure_reason == "false_positive":
                try:
                    _fp_rule_names: list[str] = []
                    _fp_hosts: list[str] = []
                    _fp_users: list[str] = []

                    # Pull matching info from case-level structured fields
                    if case.triggered_rules:
                        _fp_rule_names.extend(case.triggered_rules)
                    if case.affected_hosts:
                        _fp_hosts.extend(case.affected_hosts)
                    if case.affected_users:
                        _fp_users.extend(case.affected_users)

                    # Supplement from linked ES alerts when possible
                    if case.source_alert_ids:
                        try:
                            from ion.services.elasticsearch_service import ElasticsearchService
                            _es_svc = ElasticsearchService()
                            if _es_svc.is_configured:
                                _linked = await _es_svc.get_alerts_by_ids(case.source_alert_ids)
                                for _la in _linked:
                                    if _la.rule_name and _la.rule_name not in _fp_rule_names:
                                        _fp_rule_names.append(_la.rule_name)
                                    if _la.host and _la.host not in _fp_hosts:
                                        _fp_hosts.append(_la.host)
                                    if _la.user and _la.user not in _fp_users:
                                        _fp_users.append(_la.user)
                        except Exception as _es_err:
                            logger.debug("Auto-FP: could not enrich from ES: %s", _es_err)

                    kfp = KnownFalsePositive(
                        title=f"Auto-FP: {case.title}",
                        description=f"Automatically created when case {case.case_number} was closed as false positive. {data.closure_notes or ''}".strip(),
                        match_rules=_fp_rule_names or None,
                        match_hosts=_fp_hosts or None,
                        match_users=_fp_users or None,
                        is_active=True,
                        created_by_id=current_user.id,
                        source_case_id=case.id,
                    )
                    session.add(kfp)

                    # Also record in investigation memory for future FP detection
                    try:
                        from ion.services.investigation_memory_service import (
                            get_investigation_memory_service,
                        )
                        _mem = get_investigation_memory_service()
                        for _rn in (_fp_rule_names or []):
                            _mem.record_fp(
                                reason=f"Case {case.case_number} closed as FP",
                                confidence=80,
                                recorded_by=current_user.id,
                                rule_name=_rn,
                                alert_signature=_rn,
                                host_pattern=_fp_hosts[0] if _fp_hosts else None,
                                user_pattern=_fp_users[0] if _fp_users else None,
                            )
                        if not _fp_rule_names:
                            _mem.record_fp(
                                reason=f"Case {case.case_number} closed as FP",
                                confidence=70,
                                recorded_by=current_user.id,
                                alert_signature=case.title,
                                host_pattern=_fp_hosts[0] if _fp_hosts else None,
                                user_pattern=_fp_users[0] if _fp_users else None,
                            )
                    except Exception as _mem_err:
                        logger.warning("Auto-FP: investigation memory record failed: %s", _mem_err)

                    logger.info(
                        "Auto-FP created for case %s (rules=%s, hosts=%s)",
                        case.case_number, _fp_rule_names, _fp_hosts,
                    )
                except Exception as _fp_err:
                    logger.warning("Auto-FP creation failed for case %s: %s", case.case_number, _fp_err)

        # Reopening: clear closure fields
        elif new_status != "closed" and old_status == "closed":
            case.closure_reason = None
            case.closure_notes = None
            case.closed_by_id = None
            case.closed_at = None
        case.status = new_status

        # Sync linked alert triage statuses to match case status
        _case_to_triage = {
            "open": "open",
            "acknowledged": "acknowledged",
            "closed": "closed",
        }
        _mapped_triage = _case_to_triage.get(new_status)
        _synced_alert_ids = []
        if _mapped_triage:
            linked_triages = session.query(AlertTriage).filter_by(case_id=case.id).all()
            for t in linked_triages:
                t.status = _mapped_triage
                _synced_alert_ids.append(t.es_alert_id)

    session.commit()
    session.refresh(case)

    # Cache fields the background tasks will need before the session closes
    _case_id = case.id
    _case_number = case.case_number
    _kibana_case_id = case.kibana_case_id
    _kibana_touches = {
        "title": data.title,
        "description": data.description,
        "status": data.status,
        "severity": data.severity,
    }
    _kibana_relevant_change = (
        data.title is not None
        or data.description is not None
        or data.status is not None
        or data.severity is not None
        or data.assigned_to_id is not None
    )
    _assignee_changed = data.assigned_to_id is not None
    _assignee_id = data.assigned_to_id
    _status_changed = data.status is not None
    _alert_ids_to_sync = list(_synced_alert_ids)
    _mapped_triage_status = _mapped_triage
    _dfir_iris_case_id = case.dfir_iris_case_id

    # Kick every external sync off the request path. The handler now
    # returns as soon as Postgres commits — total latency ~20ms instead
    # of 30+s when Kibana is degraded.
    background_tasks.add_task(_background_case_sync, _case_id)
    if _status_changed and _alert_ids_to_sync:
        background_tasks.add_task(
            _background_alert_workflow_sync,
            _alert_ids_to_sync,
            _mapped_triage_status,
        )
    if _kibana_case_id and _kibana_relevant_change:
        background_tasks.add_task(
            _background_kibana_case_sync,
            _case_id,
            _case_number,
            _kibana_case_id,
            _kibana_touches,
            _assignee_id if _assignee_changed else None,
        )

    # Build Kibana URL locally without an external call (it's just a
    # predictable path on the kibana host).
    kibana_url = None
    if _kibana_case_id:
        try:
            kibana_url = get_kibana_cases_service().get_case_url(_kibana_case_id)
        except Exception:
            kibana_url = None

    # DFIR-IRIS URL — local computation only (no HTTP call).
    dfir_iris_url = None
    if _dfir_iris_case_id:
        try:
            iris_svc = get_dfir_iris_service()
            dfir_iris_url = iris_svc.get_case_url(_dfir_iris_case_id)
        except Exception:
            pass

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "closure_reason": case.closure_reason,
        "closure_notes": case.closure_notes,
        "closed_by": case.closed_by.username if case.closed_by else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "kibana_url": kibana_url,
        "dfir_iris_case_id": case.dfir_iris_case_id,
        "dfir_iris_url": dfir_iris_url,
        "message": "Case updated",
    }

@router.get("/elasticsearch/alerts/cases/{case_id}/pdf")
async def export_case_pdf(
    case_id: int,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """Export a case as a PDF report."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Build HTML for the PDF
    notes = session.query(Note).filter_by(
        entity_type=NoteEntityType.CASE,
        entity_id=str(case_id)
    ).order_by(Note.created_at.asc()).all()

    # Build the HTML content (use inline styles since WeasyPrint doesn't load external CSS)
    html = """<html><head><style>
        body { font-family: 'Helvetica', sans-serif; color: #1a1a2e; padding: 40px; font-size: 12px; line-height: 1.6; }
        h1 { color: #0f172a; font-size: 24px; border-bottom: 2px solid #6de4ff; padding-bottom: 8px; }
        h2 { color: #334155; font-size: 16px; margin-top: 24px; }
        .meta { background: #f1f5f9; padding: 16px; border-radius: 8px; margin: 16px 0; }
        .meta td { padding: 4px 16px 4px 0; vertical-align: top; }
        .meta .label { color: #64748b; font-weight: 600; font-size: 11px; text-transform: uppercase; }
        .severity { display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 600; font-size: 11px; }
        .severity-critical { background: #fecaca; color: #991b1b; }
        .severity-high { background: #fed7aa; color: #9a3412; }
        .severity-medium { background: #e9d5ff; color: #6b21a8; }
        .severity-low { background: #e2e8f0; color: #475569; }
        .note { border-left: 3px solid #e2e8f0; padding: 8px 16px; margin: 12px 0; }
        .note-meta { color: #64748b; font-size: 10px; margin-bottom: 4px; }
        .footer { margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; color: #94a3b8; font-size: 10px; text-align: center; }
    </style></head><body>"""

    sev = case.severity or "medium"
    status_val = case.status.value if hasattr(case.status, 'value') else str(case.status)

    from markupsafe import escape as _esc
    html += f"<h1>{_esc(case.case_number)} — {_esc(case.title or 'Untitled')}</h1>"
    html += '<div class="meta"><table>'
    html += f'<tr><td class="label">Status</td><td>{_esc(status_val)}</td></tr>'
    html += f'<tr><td class="label">Severity</td><td><span class="severity severity-{_esc(sev)}">{_esc(sev.upper())}</span></td></tr>'
    if case.created_at:
        html += f'<tr><td class="label">Created</td><td>{case.created_at.strftime("%d %b %Y %H:%M UTC")}</td></tr>'
    if case.closed_at:
        html += f'<tr><td class="label">Closed</td><td>{case.closed_at.strftime("%d %b %Y %H:%M UTC")}</td></tr>'
    if case.closure_reason:
        html += f'<tr><td class="label">Closure Reason</td><td>{_esc(case.closure_reason)}</td></tr>'
    if case.assigned_to:
        html += f'<tr><td class="label">Assigned To</td><td>{_esc(case.assigned_to.display_name or case.assigned_to.username)}</td></tr>'
    if case.created_by:
        html += f'<tr><td class="label">Created By</td><td>{_esc(case.created_by.display_name or case.created_by.username)}</td></tr>'
    if case.affected_hosts:
        html += f'<tr><td class="label">Affected Hosts</td><td>{_esc(", ".join(case.affected_hosts))}</td></tr>'
    if case.affected_users:
        html += f'<tr><td class="label">Affected Users</td><td>{_esc(", ".join(case.affected_users))}</td></tr>'
    if case.triggered_rules:
        html += f'<tr><td class="label">Triggered Rules</td><td>{_esc(", ".join(case.triggered_rules))}</td></tr>'
    html += '</table></div>'

    if case.description:
        html += f'<h2>Description</h2><p>{_esc(case.description)}</p>'

    if case.evidence_summary:
        html += f'<h2>Evidence Summary</h2><p>{_esc(case.evidence_summary)}</p>'

    if case.closure_notes:
        html += f'<h2>Closure Notes</h2><p>{_esc(case.closure_notes)}</p>'

    if notes:
        html += '<h2>Investigation Notes</h2>'
        for n in notes:
            user_name = ""
            if n.user_id:
                from ion.models.user import User as UserModel
                note_user = session.query(UserModel).get(n.user_id)
                user_name = _esc((note_user.display_name or note_user.username) if note_user else "System")
            html += '<div class="note">'
            html += f'<div class="note-meta">{user_name} — {n.created_at.strftime("%d %b %Y %H:%M") if n.created_at else ""}</div>'
            content = _esc(n.content or "").replace("\n", "<br>")
            html += f'{content}</div>'

    from datetime import datetime as _dt
    html += f'<div class="footer">Generated by ION · {_dt.utcnow().strftime("%d %b %Y %H:%M UTC")} · {_esc(case.case_number)}</div>'
    html += '</body></html>'

    try:
        from weasyprint import HTML as _WeasyHTML
        pdf_bytes = _WeasyHTML(string=html).write_pdf()
    except (ImportError, OSError):
        # WeasyPrint not available (Windows dev) — return HTML instead
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html)

    filename = f"{case.case_number}-report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@router.post("/elasticsearch/alerts/cases/{case_id}/escalate/dfir-iris")
async def escalate_case_to_dfir_iris(
    case_id: int,
    current_user: User = Depends(require_permission("case:update")),
    session: Session = Depends(get_db_session),
):
    """Escalate an ION case to DFIR-IRIS for incident response."""
    from datetime import datetime, timezone

    from ion.models.integration import (
        IntegrationEvent,
        IntegrationEventType,
        IntegrationType,
        LogLevel,
    )

    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Check if already escalated
    if case.dfir_iris_case_id:
        iris_svc = get_dfir_iris_service()
        return {
            "status": "already_escalated",
            "iris_case_id": case.dfir_iris_case_id,
            "iris_url": iris_svc.get_case_url(case.dfir_iris_case_id),
            "message": "Case was already escalated to DFIR-IRIS",
        }

    # Check service availability
    iris_service = get_dfir_iris_service()
    if not iris_service.enabled:
        raise HTTPException(
            status_code=400,
            detail="DFIR-IRIS integration is not enabled or not configured",
        )

    # Build rich description
    desc_parts = [case.description or "No description provided."]
    if case.affected_hosts:
        desc_parts.append(f"\n**Affected Hosts:** {', '.join(case.affected_hosts)}")
    if case.affected_users:
        desc_parts.append(f"\n**Affected Users:** {', '.join(case.affected_users)}")
    if case.triggered_rules:
        desc_parts.append(f"\n**Triggered Rules:** {', '.join(case.triggered_rules)}")
    if case.evidence_summary:
        desc_parts.append(f"\n**Evidence Summary:**\n{case.evidence_summary}")
    if case.source_alert_ids:
        desc_parts.append(f"\n**Linked ION Alerts ({len(case.source_alert_ids)}):**")
        for aid in case.source_alert_ids[:20]:
            desc_parts.append(f"- `{aid}`")
        if len(case.source_alert_ids) > 20:
            desc_parts.append(f"- ... and {len(case.source_alert_ids) - 20} more")
    if case.observables:
        desc_parts.append(f"\n**Observables ({len(case.observables)}):**")
        for obs in case.observables[:20]:
            desc_parts.append(f"- [{obs.get('type', '?')}] {obs.get('value', '?')}")
        if len(case.observables) > 20:
            desc_parts.append(f"- ... and {len(case.observables) - 20} more")

    description = "\n".join(desc_parts)

    try:
        # 1. Create IRIS case
        iris_case = await iris_service.create_case(
            title=f"[{case.case_number}] {case.title}",
            description=description,
            severity=case.severity or "medium",
            soc_id=case.case_number,
        )
        iris_case_id = iris_case.get("case_id")
        if not iris_case_id:
            raise HTTPException(status_code=502, detail="DFIR-IRIS did not return a case ID")

        # 2. Push observables as IOCs
        iocs_pushed = 0
        if case.observables:
            for obs in case.observables:
                obs_type = obs.get("type", "")
                obs_value = obs.get("value", "")
                if not obs_value:
                    continue
                try:
                    iris_ioc_type_id = iris_service.map_ioc_type(obs_type)
                    await iris_service.add_ioc(
                        case_id=iris_case_id,
                        value=obs_value,
                        ioc_type_id=iris_ioc_type_id,
                        description=f"Auto-imported from ION {case.case_number} ({obs_type})",
                        tags=["ion", obs_type],
                    )
                    iocs_pushed += 1
                except Exception as ioc_err:
                    _case_es_logger.warning("Failed to push IOC %s to IRIS: %s", obs_value, ioc_err)

        # 3. Push case notes
        notes_pushed = 0
        for note in case.notes:
            try:
                await iris_service.add_note(
                    case_id=iris_case_id,
                    title=f"Note by {note.user.username if note.user else 'Unknown'} ({note.created_at.strftime('%Y-%m-%d %H:%M') if note.created_at else 'N/A'})",
                    content=note.content,
                )
                notes_pushed += 1
            except Exception as note_err:
                _case_es_logger.warning("Failed to push note to IRIS: %s", note_err)

        # 4. Add timeline events for each alert in the case
        now_iso = datetime.now(timezone.utc).isoformat()
        events_pushed = 0
        if case.source_alert_ids:
            try:
                es_service = get_elasticsearch_service()
                es_alerts = await es_service.get_alerts_by_ids(case.source_alert_ids)

                for alert in es_alerts:
                    try:
                        event_content_parts = []
                        if alert.message:
                            event_content_parts.append(alert.message)
                        if alert.host:
                            event_content_parts.append(f"**Host:** {alert.host}")
                        if alert.user:
                            event_content_parts.append(f"**User:** {alert.user}")
                        if alert.severity:
                            event_content_parts.append(f"**Severity:** {alert.severity}")
                        if alert.mitre_technique_id:
                            technique = alert.mitre_technique_id
                            if alert.mitre_technique_name:
                                technique += f" ({alert.mitre_technique_name})"
                            event_content_parts.append(f"**MITRE:** {technique}")
                        if alert.mitre_tactic_name:
                            event_content_parts.append(f"**Tactic:** {alert.mitre_tactic_name}")

                        event_tags = ["ion", "alert"]
                        if alert.severity:
                            event_tags.append(alert.severity)
                        if alert.mitre_technique_id:
                            event_tags.append(alert.mitre_technique_id)

                        category_id = iris_service.map_tactic_to_category(
                            alert.mitre_tactic_name or ""
                        )
                        await iris_service.add_event(
                            case_id=iris_case_id,
                            title=f"[{alert.severity.upper()}] {alert.rule_name or alert.title}",
                            date=alert.timestamp.isoformat() if alert.timestamp else now_iso,
                            content="\n".join(event_content_parts),
                            source=f"ION ({alert.source})",
                            tags=event_tags,
                            category_id=category_id,
                        )
                        events_pushed += 1
                    except Exception as evt_err:
                        _case_es_logger.warning(
                            "Failed to push alert %s as timeline event: %s", alert.id, evt_err
                        )
            except Exception as es_err:
                _case_es_logger.warning("Failed to fetch alerts from ES for timeline: %s", es_err)

        # Add escalation summary event
        try:
            await iris_service.add_event(
                case_id=iris_case_id,
                title=f"Case escalated from ION ({case.case_number})",
                date=now_iso,
                content=f"Escalated by {current_user.username}. {iocs_pushed} IOCs, {notes_pushed} notes, and {events_pushed} alert timeline events transferred.",
                source="ION",
                tags=["escalation", "ion"],
                category_id=1,
            )
        except Exception as evt_err:
            _case_es_logger.warning("Failed to add escalation event to IRIS: %s", evt_err)

        # 5. Store link back on the ION case
        case.dfir_iris_case_id = iris_case_id
        session.commit()

        # 6. Log integration event
        try:
            event = IntegrationEvent(
                event_type=IntegrationEventType.ACTIVITY,
                integration_type=IntegrationType.DFIR_IRIS,
                action="escalate_case",
                level=LogLevel.INFO,
                message=f"Case {case.case_number} escalated to DFIR-IRIS (IRIS case #{iris_case_id})",
                details={
                    "ion_case_id": case.id,
                    "iris_case_id": iris_case_id,
                    "iocs_pushed": iocs_pushed,
                    "notes_pushed": notes_pushed,
                    "events_pushed": events_pushed,
                },
                user_id=current_user.id,
            )
            session.add(event)
            session.commit()
        except Exception:
            pass

        return {
            "status": "escalated",
            "iris_case_id": iris_case_id,
            "iris_url": iris_service.get_case_url(iris_case_id),
            "iocs_pushed": iocs_pushed,
            "notes_pushed": notes_pushed,
            "events_pushed": events_pushed,
        }

    except HTTPException:
        raise
    except httpx.HTTPStatusError as e:
        # Log the full error server-side; surface only a generic auth/API
        # failure message and the upstream HTTP status to the client.
        logger.warning("DFIR-IRIS escalation HTTP error: %s", e)
        try:
            status = e.response.status_code
        except Exception:
            status = "?"
        if status in (401, 403):
            detail = f"DFIR-IRIS authentication failed (HTTP {status})"
        else:
            detail = f"DFIR-IRIS API error (HTTP {status})"
        raise HTTPException(status_code=502, detail=detail)
    except httpx.ConnectError as e:
        logger.warning("DFIR-IRIS connection error: %s", e)
        raise HTTPException(
            status_code=502,
            detail="Cannot connect to DFIR-IRIS",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Escalation failed: {safe_error(e, 'dfir_iris_escalation')}",
        )

@router.post("/elasticsearch/alerts/cases/{case_id}/close-as-fp")
async def close_case_as_known_fp(
    case_id: int,
    data: CloseAsFPRequest,
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Close a case as a known false positive, setting all linked alerts to false_positive."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    kfp = session.query(KnownFalsePositive).filter_by(id=data.known_fp_id).first()
    if not kfp:
        raise HTTPException(status_code=404, detail="Known false positive entry not found")

    # Close the case
    case.status = AlertCaseStatus.CLOSED
    case.closure_reason = CaseClosureReason.FALSE_POSITIVE.value
    case.closure_notes = f"Matched known FP: {kfp.title}\n\n{kfp.description}"
    case.closed_by_id = current_user.id
    case.closed_at = datetime.utcnow()

    # Set all linked AlertTriage entries to closed
    updated_alerts = 0
    for triage in case.triage_entries:
        triage.status = AlertTriageStatus.CLOSED
        updated_alerts += 1

    session.commit()
    session.refresh(case)
    await _sync_case_to_es(case, session)

    return {
        "id": case.id,
        "case_number": case.case_number,
        "status": "closed",
        "closure_reason": "false_positive",
        "known_fp_title": kfp.title,
        "updated_alerts": updated_alerts,
        "message": "Case closed as known false positive",
    }


# ===========================================================================
# Case playbook sub-resources — moved from api.py (route audit phase 2).
# These are /elasticsearch/alerts/cases/{case_id}/* sub-resources, i.e. this
# module's declared charter. They were left behind in api.py's increment-4
# remainder even though they are NOT entangled with the KFP <-> close_alert
# knot that deferred it. Paths are unchanged: both modules mount at prefix="/api".
# ===========================================================================

@router.get("/elasticsearch/alerts/cases/{case_id}/playbook-executions")
async def get_case_playbook_executions(
    case_id: int,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Get playbook executions linked to a case, auto-backfilling from alert triage."""
    from ion.models.alert_triage import AlertCase, AlertTriage

    # Verify case exists
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    repo = PlaybookRepository(session)

    # Get directly linked executions
    linked = repo.get_executions_for_case(case_id)
    linked_ids = {e.id for e in linked}

    # Discover unlinked executions via alert triage entries
    triage_entries = session.query(AlertTriage).filter_by(case_id=case_id).all()
    alert_ids = [t.es_alert_id for t in triage_entries]

    discovered = []
    for alert_id in alert_ids:
        execs = repo.get_executions_for_alert(alert_id)
        for e in execs:
            if e.id not in linked_ids:
                # Auto-backfill case_id
                e.case_id = case_id
                linked_ids.add(e.id)
                discovered.append(e)

    if discovered:
        session.commit()

    all_executions = linked + discovered

    results = []
    for e in all_executions:
        data = e.to_dict(include_playbook=True)
        steps = e.playbook.steps if e.playbook else []
        step_statuses = e.step_statuses or {}
        total_steps = len(steps)
        completed_steps = sum(
            1 for s in step_statuses.values()
            if isinstance(s, dict) and s.get("status") in ("completed", "skipped")
        )
        data["total_steps"] = total_steps
        data["completed_steps"] = completed_steps
        data["progress_pct"] = round((completed_steps / total_steps) * 100) if total_steps > 0 else 0
        results.append(data)

    return {"executions": results, "total": len(results)}

@router.post("/elasticsearch/alerts/cases/{case_id}/playbook/{playbook_id}/start")
async def start_playbook_from_case(
    case_id: int,
    playbook_id: int,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Start a playbook execution from a case context."""
    from ion.models.alert_triage import AlertCase, AlertTriage

    # Verify case exists
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    repo = PlaybookRepository(session)
    playbook = repo.get_playbook_by_id(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if not playbook.is_active:
        raise HTTPException(status_code=400, detail="Playbook is not active")

    # Find first alert in the case to use as target
    triage_entry = session.query(AlertTriage).filter_by(case_id=case_id).first()
    if not triage_entry:
        raise HTTPException(status_code=400, detail="Case has no linked alerts")

    alert_id = triage_entry.es_alert_id

    # Check for existing active execution
    existing = repo.get_active_execution_for_alert(alert_id, playbook_id)
    if existing:
        # Link to case if not already
        if not existing.case_id:
            existing.case_id = case_id
            session.commit()
        return {
            "execution": existing.to_dict(include_playbook=True),
            "message": "Execution already in progress",
            "already_started": True,
        }

    execution = repo.start_execution(
        playbook=playbook,
        es_alert_id=alert_id,
        executed_by_id=current_user.id,
        case_id=case_id,
    )
    session.commit()

    execution = repo.get_execution(execution.id)
    return {
        "execution": execution.to_dict(include_playbook=True),
        "message": "Playbook execution started from case",
    }
