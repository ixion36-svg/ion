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
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    Note,
    NoteEntityType,
)
from ion.models.arkime_hunt import ArkimeHunt
from ion.models.user import AuditLog, User
from ion.services import pcap_service
from ion.services.arkime_service import ArkimeError, get_arkime_service
from ion.services.elasticsearch_service import ElasticsearchService
from ion.services.observable_service import ObservableService
from ion.services.opencti_service import get_opencti_service
from ion.storage.database import get_db_session

logger = logging.getLogger(__name__)
# Mounted at prefix="/api" in server.py (was self-prefixed, the only
# router in the app that did so).
router = APIRouter(tags=["arkime"])


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
    network_community_id: Optional[str] = None
    arkime_node: str
    search_mode: str = "community_id"  # "community_id" or "ip_time"
    arkime_session_id: Optional[str] = None  # resolved internal session id
    session_metadata: Optional[Dict[str, Any]] = None
    other_matches: int = 0  # extra sessions matching the same community_id
    pcap_size_bytes: int
    analysis: Dict[str, Any]
    observables: List[EnrichedObservable]
    enrichment_enabled: bool
    warnings: List[str] = Field(default_factory=list)
    # Analyst-browser deep link into the Arkime sessions view ('' when no
    # public viewer URL is resolvable).
    arkime_web_url: str = ""


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
    """Batch-enrich an observable list via OpenCTI, VirusTotal, and Shodan.

    Enrichment sources:
    - OpenCTI: all observable types (threat intel, labels, actors)
    - VirusTotal: IPs, domains, URLs, file hashes (malicious score)
    - Shodan: IPs (open ports, services, org)

    Swallows per-item errors so one bad lookup doesn't poison the batch.
    """
    # 1. OpenCTI enrichment
    opencti = get_opencti_service()
    if opencti.is_configured:
        payload = [{"type": o.type, "value": o.value} for o in observables]
        try:
            results = await opencti.enrich_batch(payload)
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
                    for a in actors if a
                ]
                indicators = res.get("indicators") or []
                o.indicator_count = len(indicators) if isinstance(indicators, list) else 0
        except Exception as e:
            logger.debug("OpenCTI batch enrichment failed: %s", e)

    # 2. VirusTotal enrichment (IPs, domains, hashes)
    try:
        from ion.services.virustotal_service import get_virustotal_service
        vt = get_virustotal_service()
        if vt and vt.is_configured:
            vt_types = {"ipv4-addr", "domain-name", "url", "file-sha256", "file-sha1", "file-md5"}
            for o in observables:
                if o.type in vt_types and not o.found:
                    try:
                        result = await vt.lookup(o.type, o.value)
                        if result and result.get("found"):
                            o.found = True
                            if result.get("malicious"):
                                o.labels = list(set(o.labels + ["malicious"]))
                            if result.get("score") is not None:
                                o.indicator_count = max(o.indicator_count, result["score"])
                    except Exception:
                        pass
    except ImportError:
        pass

    # 3. Shodan enrichment (IPs only)
    try:
        from ion.services.shodan_service import get_shodan_service
        shodan = get_shodan_service()
        if shodan and shodan.is_configured:
            for o in observables:
                if o.type == "ipv4-addr" and not o.found:
                    try:
                        result = await shodan.lookup(o.value)
                        if result and result.get("found"):
                            o.found = True
                            ports = result.get("ports", [])
                            if ports:
                                o.labels = list(set(o.labels + [f"ports:{','.join(str(p) for p in ports[:5])}"]))
                    except Exception:
                        pass
    except ImportError:
        pass

    return observables


async def _fetch_alert_for_arkime(alert_id: str) -> Dict[str, Any]:
    """Fetch an alert from ES for the Arkime workflow.

    The alert needs at least one piece of network context — community_id,
    source/destination IP, or arkime_node — so we can search Arkime for
    matching sessions.  The node field is optional: when absent, the
    Arkime session search runs without a node filter and the node is
    resolved from the matched session result.
    """
    es = ElasticsearchService()
    if not es.is_configured:
        raise HTTPException(status_code=503, detail="Elasticsearch is not configured")
    alerts = await es.get_alerts_by_ids([alert_id])
    if not alerts:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert = alerts[0]
    d = alert.to_dict()
    has_network = (
        d.get("network_community_id")
        or d.get("arkime_node")
        or d.get("source_ip")
        or d.get("destination_ip")
    )
    if not has_network:
        raise HTTPException(
            status_code=400,
            detail=f"Alert {alert_id} has no network context (community_id, "
                   f"node, or IPs) — cannot search Arkime",
        )
    return d


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
            detail="Arkime is not configured — set ION_ARKIME_URL + ION_ARKIME_USERNAME + ION_ARKIME_PASSWORD",
        )

    warnings: List[str] = []
    search_mode = "community_id"

    if community_id:
        # Exact match via Community ID flow hash (preferred path).
        try:
            result = await svc.download_pcap_by_community_id(node, community_id)
        except ArkimeError as e:
            # Fall back to IP search on ANY ArkimeError when the alert has
            # IPs — community_id indexing varies across Arkime installs and
            # a lookup miss (empty result → 404), timeout, or 5xx should all
            # hand off to the IP path instead of blocking the investigation.
            # Only propagate the error when there's no IP fallback possible.
            has_ips = bool(alert.get("source_ip") or alert.get("destination_ip"))
            logger.info(
                "Arkime community_id path failed for alert=%s: %s "
                "(status=%s, has_ips=%s) — %s",
                alert_id, e, e.status_code, has_ips,
                "falling back to IP search" if has_ips else "no IP fallback available",
            )
            if has_ips:
                warnings.append(
                    f"Arkime community_id lookup failed ({safe_error(e)}) — "
                    f"falling back to IP search. Results may include unrelated "
                    f"sessions from the same hosts."
                )
                community_id = ""  # triggers the IP-search branch below
            else:
                status = e.status_code if e.status_code in (401, 403, 404) else 502
                raise HTTPException(status_code=status, detail=safe_error(e))

    if not community_id:
        # Fallback: no community_id — search Arkime by source/dest IP from
        # the alert. Broader results, but still useful for investigation.
        search_mode = "ip_time"
        src_ip = alert.get("source_ip") or ""
        dst_ip = alert.get("destination_ip") or ""
        search_ip = src_ip or dst_ip
        if not search_ip:
            raise HTTPException(
                status_code=400,
                detail=f"Alert {alert_id} has no community_id, source_ip, or "
                       f"destination_ip — cannot search Arkime",
            )
        warnings.append(
            f"No community_id on this alert — searched Arkime by IP "
            f"({search_ip}) instead. Results may include unrelated sessions."
        )
        # anchor the Arkime search window on the alert timestamp,
        # not on "now". Non-24/7 SOCs investigate alerts hours after they
        # fire; a now-anchored window would miss the traffic. Falls through
        # to a now-anchored window inside the service if no timestamp.
        alert_ts = (
            alert.get("@timestamp")
            or alert.get("timestamp")
            or alert.get("kibana.alert.original_time")
        )
        try:
            sessions = await svc.find_sessions_by_ip(
                node, search_ip, alert_timestamp=alert_ts,
            )
        except ArkimeError as e:
            status = e.status_code if e.status_code in (401, 403, 404) else 502
            raise HTTPException(status_code=status, detail=safe_error(e))
        if not sessions:
            raise HTTPException(
                status_code=404,
                detail=f"No Arkime sessions found for IP {search_ip}"
                       + (f" on node {node}" if node else ""),
            )
        primary = sessions[0]
        arkime_sid = primary.get("id") or primary.get("_id")
        if not arkime_sid:
            raise HTTPException(status_code=500, detail="Arkime session missing id")
        resolved_node = node or primary.get("node") or ""
        if not resolved_node:
            raise HTTPException(
                status_code=500,
                detail="Cannot determine Arkime node from session result",
            )
        pcap_bytes = await svc.download_pcap(resolved_node, str(arkime_sid))
        result = {"pcap": pcap_bytes, "session": primary, "other_matches": sessions[1:]}

    pcap_bytes: bytes = result["pcap"]
    session_meta: Dict[str, Any] = result.get("session") or {}
    other_matches: List[Dict[str, Any]] = result.get("other_matches") or []
    arkime_session_id = str(session_meta.get("id") or "") or None
    # Resolve the definitive node from the session when the alert didn't carry one
    resolved_node = node or session_meta.get("node") or ""
    if other_matches:
        warnings.append(
            f"{len(other_matches)} additional Arkime session(s) matched — "
            f"only the first was downloaded."
        )

    # Parse + analyse
    try:
        parse_result = pcap_service.parse_pcap(
            pcap_bytes, f"arkime-{resolved_node or 'unknown'}-{arkime_session_id or 'session'}.pcap"
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

    from ion.services.arkime_service import arkime_sessions_link, escape_arkime_quoted

    if community_id:
        link_expr = f'communityId == "{escape_arkime_quoted(community_id)}"'
    else:
        link_expr = f"(ip.src == {search_ip} || ip.dst == {search_ip})" if search_ip else ""

    return ArkimePreviewResponse(
        alert_id=alert_id,
        network_community_id=community_id or None,
        arkime_node=resolved_node,
        search_mode=search_mode,
        arkime_session_id=arkime_session_id,
        session_metadata=session_meta,
        other_matches=len(other_matches),
        pcap_size_bytes=len(pcap_bytes),
        analysis=analysis,
        observables=observables,
        enrichment_enabled=enrichment_enabled,
        warnings=warnings,
        arkime_web_url=arkime_sessions_link(link_expr) if link_expr else "",
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
        from ion.services.case_numbering import assign_case_number

        title = body.case_title or f"PCAP investigation — {alert.get('title') or alert_id}"
        case = AlertCase(
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
        # Collision-free number from the DB-assigned id (was max(id)+1 — raced).
        assign_case_number(session, case)
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

    # Sync new case to Kibana with alert attachment
    if case_just_created:
        try:
            from ion.services.kibana_sync_helpers import sync_new_case_to_kibana
            kibana_result = sync_new_case_to_kibana(
                case_number=case.case_number,
                title=case.title,
                description=case.description,
                severity=case.severity or "medium",
                alert_ids=[alert_id],
            )
            if kibana_result:
                case.kibana_case_id = kibana_result["kibana_case_id"]
                case.kibana_case_version = kibana_result.get("kibana_case_version")
                session.commit()
        except Exception as e:
            logger.warning("Failed to sync Arkime case to Kibana: %s", e)

    # The export loop only carries notes for cases it links itself — a case
    # that already has (or was just given) kibana_case_id needs the explicit
    # push or the analysis note never reaches Kibana.
    if note_id and case.kibana_case_id:
        try:
            from ion.services.kibana_sync_helpers import sync_note_to_kibana
            sync_note_to_kibana(case.kibana_case_id, current_user.username, note.content)
        except Exception as e:
            logger.warning("Failed to sync Arkime note to Kibana: %s", e)

    # Best-effort viewer-side pivot tag (no-op unless ION_ARKIME_TAG_WRITEBACK).
    community_id = alert.get("network_community_id")
    if community_id:
        from ion.services.arkime_service import spawn_case_tag_writeback
        spawn_case_tag_writeback(case.case_number, [community_id])

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
        f"**Community ID:** `{alert.get('network_community_id') or '(none — IP search)'}`",
        f"**Arkime node:** `{alert.get('arkime_node') or '(auto-resolved)'}`",
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


# ═══════════════════════════ Hunts (packet search) ═══════════════════════
# Submissions are lead-gated (security:read, same posture as the traffic
# exclusions) and audit-logged — a hunt scans raw packets on the sensors.
# Status reads are alert:read like the rest of the Arkime surface.

_HUNT_NAME_SAFE_RE = re.compile(r"[^\w .-]")


class HuntCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    search: str = Field(..., min_length=1, max_length=512)
    search_type: str = Field(default="ascii")
    expression: Optional[str] = Field(default=None, max_length=1024)
    hours: int = Field(default=24, ge=1, le=168)
    case_id: Optional[int] = None


@router.post("/arkime/hunts")
async def create_arkime_hunt(
    payload: HuntCreateRequest,
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Submit a packet-search job to Arkime and track it in ION."""
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    if payload.case_id is not None and session.get(AlertCase, payload.case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")

    name = _HUNT_NAME_SAFE_RE.sub("", payload.name).strip() or "ION hunt"
    row = ArkimeHunt(
        name=name,
        search=payload.search,
        search_type=payload.search_type,
        expression=payload.expression,
        case_id=payload.case_id,
        created_by_id=current_user.id,
        status="submitted",
    )
    session.add(row)
    session.add(AuditLog(
        user_id=current_user.id, action="arkime_hunt_submitted",
        resource_type="arkime_hunt", resource_id=None,
        details=f"{name} — search={payload.search[:120]!r} hours={payload.hours}"
        + (f" case={payload.case_id}" if payload.case_id else ""),
    ))
    session.commit()
    session.refresh(row)

    now = int(time.time())
    try:
        result = await svc.create_hunt(
            name=name,
            search=payload.search,
            search_type=payload.search_type,
            expression=payload.expression,
            start_ts=now - payload.hours * 3600,
            stop_ts=now,
        )
    except ArkimeError as e:
        row.status = "failed"
        session.commit()
        status = e.status_code if e.status_code in (401, 403) else 502
        raise HTTPException(status_code=status, detail=safe_error(e))

    row.arkime_hunt_id = result.get("id")
    row.status = "running"
    session.commit()
    session.refresh(row)
    return {"hunt": row.to_dict()}


@router.get("/arkime/hunts")
async def list_arkime_hunts(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """ION-submitted hunts, newest first, statuses refreshed from the viewer."""
    svc = get_arkime_service()
    if svc.is_configured:
        from ion.services.arkime_hunt_service import refresh_hunts
        await refresh_hunts(session, svc)
    rows = session.query(ArkimeHunt).order_by(ArkimeHunt.id.desc()).limit(50).all()
    return {"hunts": [r.to_dict() for r in rows]}


@router.get("/arkime/hunts/{hunt_id}")
async def get_arkime_hunt(
    hunt_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    svc = get_arkime_service()
    if svc.is_configured:
        from ion.services.arkime_hunt_service import refresh_hunts
        await refresh_hunts(session, svc)
    row = session.get(ArkimeHunt, hunt_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return {"hunt": row.to_dict()}


# ═══════════════════════ Merged case PCAP (stream-through) ═══════════════


def _case_community_ids(session: Session, case: AlertCase) -> List[str]:
    """Every communityId linked to the case — RTMON triage markers plus the
    headings of its PCAP-analysis notes. Order-preserving, deduped."""
    from ion.services.arkime_retention_service import (
        note_cids,
        parse_rtmon_marker_flow,
    )

    cids: List[str] = []
    markers = (
        session.query(AlertTriage.es_alert_id)
        .filter(AlertTriage.case_id == case.id)
        .all()
    )
    for (marker,) in markers:
        flow = parse_rtmon_marker_flow(marker or "")
        if flow and flow["community_id"] not in cids:
            cids.append(flow["community_id"])
    notes = (
        session.query(Note.content)
        .filter(Note.entity_type == NoteEntityType.CASE)
        .filter(Note.entity_id == str(case.id))
        .all()
    )
    for cid in note_cids([content or "" for (content,) in notes]):
        if cid not in cids:
            cids.append(cid)
    return cids


@router.get("/cases/{case_id}/arkime/pcap")
async def download_case_merged_pcap(
    case_id: int,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """Stream the merged PCAP for every Arkime flow linked to a case.

    Pure pass-through from Arkime's multi-session export — nothing is written
    server-side (ION never stores raw PCAP).
    """
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    case = session.get(AlertCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    cids = _case_community_ids(session, case)
    if not cids:
        raise HTTPException(
            status_code=404, detail="No Arkime flows are linked to this case"
        )
    from ion.services.arkime_service import escape_arkime_quoted
    expression = " || ".join(
        f'communityId == "{escape_arkime_quoted(c)}"' for c in cids[:20]
    )
    created = case.created_at
    start_ts = int(created.timestamp()) - 86400 if created else 0
    try:
        body = await svc.stream_sessions_pcap(expression, start_ts, int(time.time()))
    except ArkimeError as e:
        status = e.status_code if e.status_code in (401, 403, 404) else 502
        raise HTTPException(status_code=status, detail=safe_error(e))
    filename = f"{case.case_number or f'case-{case.id}'}-arkime.pcap"
    return StreamingResponse(
        body,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
