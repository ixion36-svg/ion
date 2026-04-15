"""Arkime ↔ Alert ↔ Case workflow.

Given an ES alert with `network.id` + `node` fields, this router pulls the
associated PCAP from the Arkime viewer, runs it through the existing
`pcap_service` analyser (12 heuristic detectors + file extraction + JA3 +
credentials + network graph), extracts observables from the analysis, and
batch-enriches them through OpenCTI.

Two endpoints support a preview-then-commit flow:

- `POST /api/alerts/{alert_id}/arkime/preview` — does the Arkime fetch +
  analysis + enrichment and returns the full result without touching the
  database. Intended to drive the investigation UI at /alerts/{id}/arkime.

- `POST /api/alerts/{alert_id}/arkime/commit` — takes the payload the preview
  returned plus a target case (`case_id` or `create_new_case`), then creates
  observable records, attaches a structured note containing the analysis to
  the case, and links the alert into `source_alert_ids`.

Auth:
- Both endpoints require `alert:read` for fetching the alert + running the
  Arkime/PCAP analysis.
- `commit` additionally requires `case:create` (when creating a new case) or
  `case:write` (when appending to an existing one).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Generator, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.config import get_config
from ion.core.safe_errors import safe_error
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    Note,
    NoteEntityType,
)
from ion.models.user import User
from ion.services import pcap_service
from ion.services.arkime_service import ArkimeError, get_arkime_service
from ion.services.elasticsearch_service import ElasticsearchService
from ion.services.observable_service import ObservableService
from ion.services.opencti_service import get_opencti_service
from ion.storage.database import get_engine, get_session_factory


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency for a scoped database session (matches api.py)."""
    engine = get_engine(get_config().db_path)
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["arkime"])


# ════════════════════════════════ Schemas ════════════════════════════════

class ArkimeStatusResponse(BaseModel):
    configured: bool
    connected: bool
    url: Optional[str] = None
    user: Optional[str] = None
    error: Optional[str] = None


class EnrichedObservable(BaseModel):
    type: str
    value: str
    source: str  # pcap analysis field that surfaced it (e.g., "top_dst_ips")
    found: bool = False
    labels: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    indicator_count: int = 0
    error: Optional[str] = None


class ArkimePreviewResponse(BaseModel):
    alert_id: str
    network_community_id: str
    arkime_node: str
    arkime_session_id: Optional[str] = None  # resolved internal session id
    session_metadata: Optional[Dict[str, Any]] = None
    other_matches: int = 0  # extra sessions matching the same community_id
    pcap_size_bytes: int
    analysis: Dict[str, Any]
    observables: List[EnrichedObservable]
    enrichment_enabled: bool
    warnings: List[str] = Field(default_factory=list)


class ArkimeCommitRequest(BaseModel):
    # EITHER case_id is set (attach to existing) OR create_new_case=True
    case_id: Optional[int] = None
    create_new_case: bool = False
    case_title: Optional[str] = None
    case_severity: str = "medium"
    # Echo of the preview payload so commit is stateless (no server-side cache)
    pcap_size_bytes: int
    analysis: Dict[str, Any]
    observables: List[EnrichedObservable]


class ArkimeCommitResponse(BaseModel):
    case_id: int
    case_number: str
    note_id: Optional[int] = None
    observables_created: int
    alert_linked: bool


# ════════════════════════════════ Helpers ════════════════════════════════

def _extract_observables_from_pcap(analysis: Dict[str, Any]) -> List[EnrichedObservable]:
    """Walk a `PcapResult.to_dict()` payload and pull IOCs for enrichment.

    Dedupes by (type, value) pair; records the source field so the UI can
    explain why each row is in the list.
    """
    seen: Dict[tuple, EnrichedObservable] = {}

    def add(obs_type: str, value: Any, source: str) -> None:
        if value is None:
            return
        s = str(value).strip()
        if not s:
            return
        key = (obs_type, s.lower())
        if key in seen:
            return
        seen[key] = EnrichedObservable(type=obs_type, value=s, source=source)

    # Top talkers — IPs
    for row in analysis.get("top_src_ips") or []:
        ip = row.get("ip") if isinstance(row, dict) else row
        add("ipv4-addr", ip, "top_src_ips")
    for row in analysis.get("top_dst_ips") or []:
        ip = row.get("ip") if isinstance(row, dict) else row
        add("ipv4-addr", ip, "top_dst_ips")

    # DNS queries → domain names
    for q in analysis.get("dns_queries") or []:
        if isinstance(q, dict):
            name = q.get("name") or q.get("query")
            add("domain-name", name, "dns_queries")
        else:
            add("domain-name", q, "dns_queries")

    # HTTP hosts → domain / url
    for req in analysis.get("http_requests") or []:
        if isinstance(req, dict):
            host = req.get("host")
            add("domain-name", host, "http_requests")
            uri = req.get("uri") or req.get("url")
            if host and uri:
                add("url", f"http://{host}{uri}", "http_requests")

    # TLS SNI
    for tls in analysis.get("tls_handshakes") or []:
        if isinstance(tls, dict):
            add("domain-name", tls.get("sni") or tls.get("server_name"), "tls_handshakes")

    # Extracted files — hashes (use observable_service's STIX type strings
    # so the commit step can resolve them via _resolve_type())
    for f in analysis.get("extracted_files") or []:
        if isinstance(f, dict):
            for stix_type, key in (
                ("file-md5", "md5"),
                ("file-sha1", "sha1"),
                ("file-sha256", "sha256"),
            ):
                add(stix_type, f.get(key), "extracted_files")

    return list(seen.values())


async def _enrich_observables(
    observables: List[EnrichedObservable],
) -> List[EnrichedObservable]:
    """Batch-enrich an observable list via OpenCTI. Mutates in place and
    returns the same list for chaining. Swallows per-item errors into the
    `error` field so one bad lookup doesn't poison the whole batch."""
    opencti = get_opencti_service()
    if not opencti.is_configured:
        for o in observables:
            o.error = "opencti not configured"
        return observables
    payload = [{"type": o.type, "value": o.value} for o in observables]
    try:
        results = await opencti.enrich_batch(payload)
    except Exception as e:
        err = safe_error(e)
        for o in observables:
            o.error = err
        return observables

    # Zip results back onto the observables in order
    for o, res in zip(observables, results):
        if not isinstance(res, dict):
            continue
        if res.get("error"):
            o.error = res.get("error")
            continue
        o.found = bool(res.get("found"))
        labels = res.get("labels") or []
        o.labels = [l for l in labels if isinstance(l, str)]
        actors = res.get("threat_actors") or []
        o.threat_actors = [
            a.get("name") if isinstance(a, dict) else str(a)
            for a in actors
            if a
        ]
        indicators = res.get("indicators") or []
        o.indicator_count = len(indicators) if isinstance(indicators, list) else 0
    return observables


async def _fetch_alert_for_arkime(alert_id: str) -> Dict[str, Any]:
    """Fetch an alert from ES and verify it has the Arkime linkage fields."""
    es = ElasticsearchService()
    if not es.is_configured:
        raise HTTPException(status_code=503, detail="Elasticsearch is not configured")
    alerts = await es.get_alerts_by_ids([alert_id])
    if not alerts:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert = alerts[0]
    if not alert.network_community_id or not alert.arkime_node:
        missing = []
        if not alert.network_community_id:
            missing.append("network.community_id")
        if not alert.arkime_node:
            missing.append("node")
        raise HTTPException(
            status_code=400,
            detail=(
                f"Alert {alert_id} has no Arkime linkage — missing: {', '.join(missing)}"
            ),
        )
    return alert.to_dict()


# ════════════════════════════════ Routes ════════════════════════════════

@router.get("/arkime/status", response_model=ArkimeStatusResponse)
async def arkime_status(
    current_user: User = Depends(require_permission("alert:read")),
):
    """Health check for the Arkime integration."""
    svc = get_arkime_service()
    if not svc.is_configured:
        return ArkimeStatusResponse(
            configured=False,
            connected=False,
            error="Arkime is not configured — set ION_ARKIME_URL + auth",
        )
    result = await svc.test_connection()
    return ArkimeStatusResponse(
        configured=True,
        connected=bool(result.get("connected")),
        url=result.get("url"),
        user=result.get("user"),
        error=result.get("error"),
    )


@router.post("/alerts/{alert_id}/arkime/preview", response_model=ArkimePreviewResponse)
async def arkime_preview(
    alert_id: str,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Pull the PCAP from Arkime, analyse it, enrich observables via OpenCTI.

    Returns the full analysis WITHOUT committing to the database so the UI
    can render a preview workspace. The commit endpoint echoes this payload
    back when the analyst picks a case to attach it to.
    """
    alert = await _fetch_alert_for_arkime(alert_id)
    community_id = alert.get("network_community_id") or ""
    node = alert.get("arkime_node") or ""

    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(
            status_code=503,
            detail="Arkime is not configured — set ION_ARKIME_URL + Keycloak creds",
        )

    warnings: List[str] = []

    # Resolve the Community ID to an Arkime session and download the PCAP.
    try:
        result = await svc.download_pcap_by_community_id(node, community_id)
    except ArkimeError as e:
        status = e.status_code if e.status_code in (401, 403, 404) else 502
        raise HTTPException(status_code=status, detail=safe_error(e))
    pcap_bytes: bytes = result["pcap"]
    session_meta: Dict[str, Any] = result.get("session") or {}
    other_matches: List[Dict[str, Any]] = result.get("other_matches") or []
    arkime_session_id = str(session_meta.get("id") or "") or None
    if other_matches:
        warnings.append(
            f"{len(other_matches)} additional Arkime session(s) matched this "
            f"Community ID — only the first was downloaded."
        )

    # Parse + analyse
    try:
        parse_result = pcap_service.parse_pcap(
            pcap_bytes, f"arkime-{node}-{arkime_session_id or 'session'}.pcap"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"PCAP parse failed: {safe_error(e)}",
        )
    analysis = parse_result.to_dict()

    # Observable extraction + enrichment
    observables = _extract_observables_from_pcap(analysis)
    enrichment_enabled = get_opencti_service().is_configured
    if enrichment_enabled and observables:
        observables = await _enrich_observables(observables)

    return ArkimePreviewResponse(
        alert_id=alert_id,
        network_community_id=community_id,
        arkime_node=node,
        arkime_session_id=arkime_session_id,
        session_metadata=session_meta,
        other_matches=len(other_matches),
        pcap_size_bytes=len(pcap_bytes),
        analysis=analysis,
        observables=observables,
        enrichment_enabled=enrichment_enabled,
        warnings=warnings,
    )


@router.post("/alerts/{alert_id}/arkime/commit", response_model=ArkimeCommitResponse)
async def arkime_commit(
    alert_id: str,
    body: ArkimeCommitRequest,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Persist the preview output to a case.

    Creates a new case (when `create_new_case=True`) or attaches to an
    existing one (`case_id`). In both cases:
    - A structured note with the PCAP analysis + observable enrichment is
      added to the case.
    - Each unique observable from the preview is attached to the case via
      the per-case observables relationship (with enrichment metadata).
    - The alert's `AlertTriage` row is linked into `case.triage_entries`
      and added to `source_alert_ids`.
    """
    if not body.create_new_case and not body.case_id:
        raise HTTPException(
            status_code=400,
            detail="Must set either `case_id` or `create_new_case=true`",
        )

    # Re-verify the alert exists and still has Arkime linkage
    alert = await _fetch_alert_for_arkime(alert_id)

    # ── Resolve or create the case ──
    case: Optional[AlertCase] = None
    case_just_created = False
    if body.create_new_case:
        last_case = (
            session.query(AlertCase)
            .order_by(AlertCase.id.desc())
            .first()
        )
        next_num = 1 if not last_case else last_case.id + 1
        case_number = f"CASE-{next_num:04d}"
        title = body.case_title or f"PCAP investigation — {alert.get('title') or alert_id}"
        case = AlertCase(
            case_number=case_number,
            title=title,
            description=(
                f"Auto-generated from Arkime PCAP analysis of alert {alert_id} "
                f"(community_id={alert.get('network_community_id')}, "
                f"node={alert.get('arkime_node')})."
            ),
            status=AlertCaseStatus.OPEN,
            severity=body.case_severity,
            created_by_id=current_user.id,
            assigned_to_id=current_user.id,
            affected_hosts=[alert.get("host")] if alert.get("host") else [],
            affected_users=[alert.get("user")] if alert.get("user") else [],
            triggered_rules=[alert.get("rule_name")] if alert.get("rule_name") else [],
            evidence_summary=f"Arkime PCAP — {body.pcap_size_bytes} bytes",
            source_alert_ids=[alert_id],
        )
        session.add(case)
        session.flush()
        case_just_created = True
    else:
        case = session.query(AlertCase).filter_by(id=body.case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail=f"Case {body.case_id} not found")
        # Link the alert into source_alert_ids if not already present
        ids = list(case.source_alert_ids or [])
        if alert_id not in ids:
            ids.append(alert_id)
            case.source_alert_ids = ids

    # Link the AlertTriage row so the alert shows up in the case feed
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    alert_linked = False
    if not triage:
        triage = AlertTriage(
            es_alert_id=alert_id,
            status=AlertTriageStatus.ACKNOWLEDGED,
        )
        session.add(triage)
        session.flush()
    if triage.case_id != case.id:
        triage.case_id = case.id
        alert_linked = True

    # ── Build and attach the analysis note ──
    note_id: Optional[int] = None
    try:
        note = Note(
            entity_type=NoteEntityType.CASE,
            entity_id=str(case.id),
            user_id=current_user.id,
            content=_render_arkime_note_markdown(alert, body),
        )
        session.add(note)
        session.flush()
        note_id = note.id
    except Exception as e:
        logger.warning("Failed to attach Arkime note to case %s: %s", case.id, e)

    # ── Create observable records for each enriched IOC via the shared
    #    observable_service (type resolution, normalisation, dedup) ──
    obs_svc = ObservableService(session)
    observables_created = 0
    for obs in body.observables:
        try:
            observable, created = obs_svc.get_or_create(obs.type, obs.value)
            if created:
                observables_created += 1
                # Record the Arkime provenance in the notes field
                provenance = (
                    f"Arkime PCAP of alert {alert_id} (via {obs.source})."
                )
                if obs.labels:
                    provenance += f" OpenCTI labels: {', '.join(obs.labels)}."
                if obs.threat_actors:
                    provenance += f" Actors: {', '.join(obs.threat_actors)}."
                observable.notes = (
                    (observable.notes + "\n" if observable.notes else "") + provenance
                )
        except ValueError:
            # Unknown observable type for this normaliser — skip silently
            continue
        except Exception as e:
            logger.warning(
                "Failed to persist observable %s=%s: %s", obs.type, obs.value, e
            )

    session.commit()

    return ArkimeCommitResponse(
        case_id=case.id,
        case_number=case.case_number,
        note_id=note_id,
        observables_created=observables_created,
        alert_linked=alert_linked,
    )


def _render_arkime_note_markdown(
    alert: Dict[str, Any], body: ArkimeCommitRequest
) -> str:
    """Render the preview payload as markdown suitable for a case note."""
    lines: List[str] = [
        "## Arkime PCAP Analysis",
        "",
        f"**Alert:** `{alert.get('id')}` — {alert.get('title') or '(no title)'}",
        f"**Community ID:** `{alert.get('network_community_id')}`",
        f"**Arkime node:** `{alert.get('arkime_node')}`",
        f"**PCAP size:** {body.pcap_size_bytes:,} bytes",
        "",
    ]
    verdict = body.analysis.get("verdict") if isinstance(body.analysis, dict) else None
    if isinstance(verdict, dict) and verdict.get("label"):
        lines += [
            f"**Verdict:** {verdict.get('label')} (score {verdict.get('score', '?')})",
            "",
        ]

    protocols = body.analysis.get("protocols") if isinstance(body.analysis, dict) else {}
    if isinstance(protocols, dict) and protocols:
        lines.append("### Protocols")
        for p, count in sorted(protocols.items(), key=lambda kv: -kv[1])[:10]:
            lines.append(f"- `{p}` — {count}")
        lines.append("")

    findings = body.analysis.get("findings") if isinstance(body.analysis, dict) else []
    if isinstance(findings, list) and findings:
        lines.append("### Findings")
        for f in findings[:25]:
            if isinstance(f, dict):
                sev = f.get("severity", "info").upper()
                title = f.get("title") or f.get("type") or "(no title)"
                desc = f.get("description") or ""
                lines.append(f"- **[{sev}]** {title}" + (f" — {desc}" if desc else ""))
        lines.append("")

    if body.observables:
        lines.append("### Observables")
        lines.append("| Type | Value | OpenCTI | Labels | Actors |")
        lines.append("|---|---|---|---|---|")
        for o in body.observables[:50]:
            found = "✓" if o.found else "—"
            labels = ", ".join(o.labels[:4]) if o.labels else ""
            actors = ", ".join(o.threat_actors[:3]) if o.threat_actors else ""
            lines.append(
                f"| `{o.type}` | `{o.value}` | {found} | {labels} | {actors} |"
            )
        lines.append("")

    return "\n".join(lines)
