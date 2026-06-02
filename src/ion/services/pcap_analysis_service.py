"""PCAP auto-analysis service (v0.16.0).

When a case is created from alerts that carry ``network.community_id``
(the Zeek/Arkime flow hash), this service fires fire-and-forget Arkime
session lookups, downloads the matching PCAP, parses it with the
existing ``pcap_service`` (dpkt-based), and posts a markdown summary as
a case Note attributed to Bob.

The whole chain is best-effort:
- If Arkime is unconfigured / unreachable, the case is still created.
- If the PCAP download fails, the markdown still includes the Arkime
  session metadata so analysts can see the flow exists.
- If parsing fails, only the metadata block is posted.

The 5-min wallboard cache and OpenCTI enrichment in case creation are
unaffected — this service runs on its own background thread.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# Header rendered into the markdown comment so analysts can spot
# auto-generated PCAP analysis at a glance in the case timeline.
_ICON = "[network]"


# ──────────────────────────────────────────────────────────────────────────
# Verdict → case severity (v0.39.0)
# ──────────────────────────────────────────────────────────────────────────
#
# The packet-level analysis produces a deterministic verdict (findings +
# score). We map that to a case severity so the network evidence actually
# drives triage instead of only landing as a Note. Policy: **two-way auto** —
# the PCAP verdict may raise OR lower the case severity (operator choice at
# v0.39.0). Driven by the highest-severity finding; the cumulative verdict
# score escalates a pile of lower-severity findings at the boundary.

_CASE_SEVERITY_BY_RANK = ["low", "medium", "high", "critical"]
_FINDING_RANK = {"info": 0, "low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_rank(severity: Optional[str]) -> int:
    """Rank a severity string (low/medium/high/critical) → 0..3; unknown → 0."""
    return _FINDING_RANK.get((severity or "").lower(), 0)


def pcap_case_severity(pcap_result: Optional[Any]) -> Optional[str]:
    """Derive a case severity from a parsed ``PcapResult``.

    Returns ``low|medium|high|critical``, or ``None`` when there is nothing
    to go on (no result, or a result with no findings *and* no verdict) so
    the caller can leave the case severity untouched. Deterministic: the same
    capture always yields the same severity.

    Rule: take the highest finding severity, then apply a score floor — a
    large cumulative score (many mediums) escalates one tier, matching the
    ``_compute_verdict`` "Needs Investigation" threshold (score ≥ 50).
    """
    if pcap_result is None:
        return None
    findings = getattr(pcap_result, "findings", None) or []
    verdict = getattr(pcap_result, "verdict", None) or {}
    if not findings:
        # Explicit benign verdict with zero findings → a calm "low"; nothing
        # at all (parse failed / empty) → None so the caller holds.
        return "low" if verdict.get("label") else None
    rank = max(
        severity_rank(f.get("severity") if isinstance(f, dict) else None)
        for f in findings
    )
    score = verdict.get("score") or 0
    if score >= 100 and rank < 2:
        rank = 2  # escalate to high
    elif score >= 50 and rank < 1:
        rank = 1  # escalate to medium
    return _CASE_SEVERITY_BY_RANK[rank]


def _apply_case_severity(
    case_id: int,
    severity: str,
    reasons: List[str],
    techniques: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Set ``AlertCase.severity`` (two-way) and post a short attribution note.

    Runs in the background thread; owns its own session. No-op when the case
    already carries that severity, so re-runs don't churn the timeline.

    ``techniques`` is the deduped MITRE ATT&CK rollup across the case's flows
    ([{id, name}, ...]); when present it's echoed on the decision note so the
    case-level technique summary is one scannable line.
    """
    try:
        from ion.core.config import get_config
        from ion.models.alert_triage import AlertCase
        from ion.storage.database import get_engine, get_session_factory
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("pcap_analysis: cannot import deps for severity update: %s", exc)
        return

    config = get_config()
    factory = get_session_factory(get_engine(config.db_path))
    session: Session = factory()
    try:
        case = session.get(AlertCase, case_id)
        if case is None:
            return
        old = (case.severity or "").lower() or None
        if old == severity:
            return
        case.severity = severity
        session.commit()
        logger.info(
            "pcap_analysis: case %s severity %s → %s (PCAP verdict)",
            case_id, old or "unset", severity,
        )
        direction = (
            "raised" if severity_rank(severity) > severity_rank(old) else "lowered"
        )
        bullet = "\n".join(f"  - {r}" for r in reasons[:4]) if reasons else ""
        mitre_line = ""
        if techniques:
            ids = ", ".join(f"`{t['id']}`" for t in techniques[:12])
            mitre_line = f"\n\nMITRE ATT&CK: {ids}"
        note = (
            f"### {_ICON} Triage — case severity {direction} to **{severity}**\n\n"
            f"Set by Bob from packet-level PCAP analysis"
            + (f" (was `{old}`)." if old else ".")
            + (f"\n\nDriving evidence:\n{bullet}" if bullet else "")
            + mitre_line
        )
        _post_case_note(case_id, note)
    except Exception as exc:
        session.rollback()
        logger.warning("pcap_analysis: severity update failed for case %s: %s", case_id, exc)
    finally:
        session.close()


# ──────────────────────────────────────────────────────────────────────────
# Markdown rendering
# ──────────────────────────────────────────────────────────────────────────


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"


def _session_table(sessions: List[Dict[str, Any]]) -> str:
    """Compact markdown table of Arkime session metadata."""
    if not sessions:
        return "_No matching Arkime sessions._"
    rows = [
        "| Node | Source | Destination | Protocol | Packets | Bytes | First | Last |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in sessions[:10]:
        src = f"{s.get('srcIp', '?')}:{s.get('srcPort', '?')}"
        dst = f"{s.get('dstIp', '?')}:{s.get('dstPort', '?')}"
        proto = s.get("protocol") or s.get("ipProtocol") or "?"
        if isinstance(proto, list):
            proto = ", ".join(str(p) for p in proto)
        first = str(s.get("firstPacket", ""))[:19].replace("T", " ")
        last = str(s.get("lastPacket", ""))[:19].replace("T", " ")
        bytes_n = int(s.get("bytes", 0) or 0)
        rows.append(
            f"| `{s.get('node', '?')}` | `{src}` | `{dst}` | {proto} | "
            f"{int(s.get('packets', 0) or 0):,} | {_format_bytes(bytes_n)} | "
            f"{first} | {last} |"
        )
    return "\n".join(rows)


def _top_list(items: List[Dict[str, Any]], key: str, value_key: str = "count", limit: int = 5) -> str:
    """Render a top-N list as markdown bullets."""
    if not items:
        return "_(none)_"
    out: List[str] = []
    for it in items[:limit]:
        if isinstance(it, dict):
            label = it.get(key) or "?"
            count = it.get(value_key)
            out.append(f"- `{label}`" + (f" — {count}" if count is not None else ""))
        else:
            out.append(f"- `{it}`")
    return "\n".join(out)


def _render_pcap_markdown(
    community_id: str,
    sessions: List[Dict[str, Any]],
    pcap_result: Optional[Any],
    arkime_url_root: Optional[str] = None,
    pcap_error: Optional[str] = None,
    fallback_warning: Optional[str] = None,
) -> str:
    """Render the full markdown report for one community_id.

    v0.29.1: emits an italic warning block when the analysis used the
    IP-fallback path (community_id index missed but IP search hit).
    Lets analysts know the sessions below may include unrelated traffic
    from the same host.
    """
    parts: List[str] = []
    parts.append(f"### {_ICON} PCAP auto-analysis — `community_id` = `{community_id}`")
    parts.append("")

    if fallback_warning:
        parts.append(f"⚠️ _{fallback_warning}_")
        parts.append("")

    if arkime_url_root:
        parts.append(
            f"[Open in Arkime]({arkime_url_root.rstrip('/')}/sessions?expression="
            f"communityId%20%3D%3D%20%22{community_id}%22)"
        )
        parts.append("")

    parts.append("**Arkime sessions matched:**")
    parts.append(_session_table(sessions))
    parts.append("")

    if pcap_error:
        parts.append(f"_PCAP download failed:_ `{pcap_error}`")
        parts.append("_Session metadata above is from Arkime; packet-level analysis was not run._")
        return "\n".join(parts)

    if not pcap_result:
        parts.append("_No PCAP available for packet-level analysis._")
        return "\n".join(parts)

    # Headline counters
    parts.append("**Packet capture summary:**")
    parts.append(
        f"- Packets: **{pcap_result.packet_count:,}** · "
        f"Size: **{_format_bytes(pcap_result.file_size)}** · "
        f"Duration: **{pcap_result.capture_duration:.1f}s**"
    )
    if pcap_result.time_start:
        parts.append(f"- Window: `{pcap_result.time_start}` → `{pcap_result.time_end}`")

    if pcap_result.protocols:
        proto_summary = ", ".join(
            f"{k}: {v:,}" for k, v in
            sorted(pcap_result.protocols.items(), key=lambda x: -x[1])[:6]
        )
        parts.append(f"- Protocols: {proto_summary}")
    parts.append("")

    # Top talkers
    if pcap_result.top_src_ips or pcap_result.top_dst_ips:
        parts.append("**Top talkers:**")
        parts.append("")
        parts.append("Sources:")
        parts.append(_top_list(pcap_result.top_src_ips, "ip"))
        parts.append("")
        parts.append("Destinations:")
        parts.append(_top_list(pcap_result.top_dst_ips, "ip"))
        parts.append("")

    # DNS / TLS / HTTP signals
    if pcap_result.dns_queries:
        parts.append("**DNS queries:**")
        parts.append(_top_list(pcap_result.dns_queries, "query"))
        parts.append("")

    if pcap_result.tls_handshakes:
        parts.append("**TLS SNI:**")
        parts.append(_top_list(pcap_result.tls_handshakes, "sni"))
        parts.append("")

    if pcap_result.http_requests:
        parts.append("**HTTP hosts:**")
        parts.append(_top_list(pcap_result.http_requests, "host"))
        parts.append("")

    # v0.39.0 enhanced analyzers — TLS certs, OS fingerprints, RITA beacons
    tls_certs = getattr(pcap_result, "tls_certificates", None) or []
    if tls_certs:
        parts.append("**TLS certificates:**")
        for c in tls_certs[:5]:
            flags = []
            if c.get("self_signed"):
                flags.append("self-signed")
            if c.get("validity_days"):
                flags.append(f"{c['validity_days'] // 365}y validity")
            flag_str = f" _({', '.join(flags)})_" if flags else ""
            parts.append(
                f"- `{c.get('server_ip', '?')}` — {c.get('subject', '?')} "
                f"(issuer {c.get('issuer', '?')}){flag_str}"
            )
        parts.append("")

    os_fps = getattr(pcap_result, "os_fingerprints", None) or []
    if os_fps:
        parts.append("**Passive OS fingerprints:**")
        for o in os_fps[:8]:
            parts.append(f"- `{o.get('ip')}` → **{o.get('os')}** ({o.get('evidence')})")
        parts.append("")

    beacons = [b for b in (getattr(pcap_result, "beacons", None) or []) if b.get("score", 0) >= 0.85]
    if beacons:
        parts.append("**Beaconing candidates (RITA-style score):**")
        for b in beacons[:5]:
            parts.append(
                f"- `{b.get('src')}` → `{b.get('dst')}:{b.get('port')}` — "
                f"score **{b.get('score')}**, {b.get('connections')} conns every ~{b.get('interval_s')}s"
            )
        parts.append("")

    # Findings + verdict
    if pcap_result.findings:
        parts.append("**Findings:**")
        for f in pcap_result.findings[:8]:
            if isinstance(f, dict):
                sev = f.get("severity", "info")
                msg = f.get("title") or f.get("message") or f.get("detail") or str(f)
                mitre = f.get("mitre") or []
                mitre_str = f"  _[{', '.join(mitre)}]_" if mitre else ""
            else:
                sev, msg, mitre_str = "info", str(f), ""
            parts.append(f"- **{sev}**: {msg}{mitre_str}")
        parts.append("")

    # v0.39.0 — MITRE ATT&CK technique rollup
    techniques = getattr(pcap_result, "mitre_techniques", None) or []
    if techniques:
        parts.append("**MITRE ATT&CK techniques observed:**")
        for t in techniques:
            name = f" — {t['name']}" if t.get("name") else ""
            parts.append(f"- `{t['id']}`{name}")
        parts.append("")

    if pcap_result.verdict:
        v = pcap_result.verdict
        label = v.get("label", "unknown")
        score = v.get("score")
        line = f"**Verdict:** `{label}`"
        if score is not None:
            line += f" (score {score})"
        parts.append(line)

    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────
# Per-community_id pipeline
# ──────────────────────────────────────────────────────────────────────────


async def _analyze_one(
    community_id: str,
    *,
    alert_node_hint: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    alert_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the Arkime → PCAP → dpkt pipeline for one community_id.

    Returns ``{"sessions": [...], "pcap_result": PcapResult|None,
    "arkime_url_root": str, "pcap_error": str|None,
    "search_mode": "community_id"|"ip_time"}``. Never raises — failures
    land in ``pcap_error`` so the renderer can fall back gracefully to
    metadata-only output.

    v0.29.1: when ``find_sessions_by_community_id`` returns empty, fall
    back to ``find_sessions_by_ip`` anchored on the alert timestamp.
    Mirrors the manual /api/arkime/.../preview path so the auto pipeline
    surfaces sessions in the same deployments the manual button does.
    Many Arkime installs have a sparse community_id index (older
    captures, mismatched hash algorithms) but a complete IP index.
    """
    out: Dict[str, Any] = {
        "sessions": [], "pcap_result": None,
        "arkime_url_root": None, "pcap_error": None,
        "search_mode": "community_id",
        "fallback_warning": None,
    }
    try:
        from ion.services.arkime_service import get_arkime_service
    except Exception as exc:
        out["pcap_error"] = f"Arkime service unavailable: {exc}"
        return out

    svc = get_arkime_service()
    if not getattr(svc, "is_configured", False):
        out["pcap_error"] = "Arkime not configured"
        return out
    out["arkime_url_root"] = getattr(svc, "url", None)

    # ── Step 1: community_id lookup (preferred path) ────────────────────
    sessions = None
    try:
        sessions = await svc.find_sessions_by_community_id(
            alert_node_hint or "", community_id,
        )
    except Exception as exc:
        logger.info(
            "pcap_analysis: community_id lookup raised for %s: %s — "
            "will try IP fallback if available", community_id, exc,
        )

    # ── Step 2: IP-fallback when community_id lookup returns empty ──────
    # Matches arkime_api.preview_arkime's manual-button logic. Only fires
    # when we have a usable IP + the community_id path produced no hits.
    ip_to_use = source_ip or destination_ip
    if not sessions and ip_to_use:
        try:
            sessions = await svc.find_sessions_by_ip(
                alert_node_hint or "", ip_to_use,
                alert_timestamp=alert_timestamp,
            )
            if sessions:
                out["search_mode"] = "ip_time"
                out["fallback_warning"] = (
                    f"community_id `{community_id}` returned no matches in "
                    f"Arkime; fell back to IP search on `{ip_to_use}` "
                    f"anchored on the alert timestamp. Sessions below may "
                    f"include unrelated traffic from the same host."
                )
        except Exception as exc:
            logger.info(
                "pcap_analysis: IP-fallback also failed for %s/%s: %s",
                community_id, ip_to_use, exc,
            )

    out["sessions"] = sessions or []
    if not sessions:
        out["pcap_error"] = (
            "No Arkime sessions matched (community_id lookup empty"
            + (f"; IP fallback on {ip_to_use} also empty)" if ip_to_use else "; no IP available for fallback)")
        )
        return out

    # ── Step 3: PCAP download ───────────────────────────────────────────
    # If we reached here via the IP-fallback, prefer downloading by
    # the session id we already resolved rather than re-querying by
    # community_id (which would just miss again).
    try:
        if out["search_mode"] == "community_id":
            download = await svc.download_pcap_by_community_id(
                alert_node_hint or "", community_id,
            )
            pcap_bytes = download.get("pcap")
        else:
            # Pull the PCAP for the first matching IP session.
            primary = sessions[0]
            session_id = primary.get("id") or primary.get("_id")
            resolved_node = primary.get("node") or alert_node_hint or ""
            if not (session_id and resolved_node):
                raise RuntimeError(
                    "IP-fallback session missing id/node; can't download PCAP"
                )
            pcap_bytes = await svc.download_pcap(
                resolved_node, str(session_id),
            )
    except Exception as exc:
        out["pcap_error"] = f"PCAP download failed: {exc}"
        return out

    if not pcap_bytes:
        out["pcap_error"] = "PCAP download returned no bytes"
        return out

    try:
        from ion.services.pcap_service import parse_pcap
        out["pcap_result"] = parse_pcap(pcap_bytes, f"arkime-{community_id[:16]}.pcap")
    except Exception as exc:
        out["pcap_error"] = f"PCAP parse failed: {type(exc).__name__}: {exc}"

    return out


def _link_pcap_observables(case_id: int, pcap_result: Optional[Any]) -> None:
    """Extract observables from a PCAP analysis result and link to the case.

    v0.30.1: pre-fix the auto-PCAP service only wrote a markdown Note,
    so IPs / DNS queries / TLS SNIs / HTTP hosts surfaced in the note
    text but never got rolled up into the case's observable list. The
    standard observable enrichment + watchlist + correlation pipelines
    therefore couldn't see PCAP findings. We now also create Observable
    rows (via ObservableService.get_or_create) and link them to the
    case (via link_to_case) with context strings that preserve the
    PCAP role (auto_pcap_source / _destination / _dns / _tls / _http).
    Best-effort: any per-observable failure is logged and the chain
    continues so one bad value can't poison the whole batch.
    """
    if pcap_result is None:
        return
    try:
        from ion.core.config import get_config
        from ion.models.observable import ObservableType
        from ion.services.observable_service import ObservableService
        from ion.storage.database import get_engine, get_session_factory
    except Exception as exc:
        logger.warning("pcap_analysis: cannot import deps for observable link: %s", exc)
        return

    # Collect (type, value, context) triples from each pcap_result field.
    # Field shapes mirror the dict keys used by _render_pcap_markdown above.
    items: list[tuple[ObservableType, str, str]] = []
    for entry in (getattr(pcap_result, "top_src_ips", None) or []):
        ip = entry.get("ip") if isinstance(entry, dict) else None
        if ip:
            items.append((ObservableType.IPV4, ip, "auto_pcap_source"))
    for entry in (getattr(pcap_result, "top_dst_ips", None) or []):
        ip = entry.get("ip") if isinstance(entry, dict) else None
        if ip:
            items.append((ObservableType.IPV4, ip, "auto_pcap_destination"))
    for entry in (getattr(pcap_result, "dns_queries", None) or []):
        q = entry.get("query") if isinstance(entry, dict) else None
        if q:
            items.append((ObservableType.DOMAIN, q, "auto_pcap_dns"))
    for entry in (getattr(pcap_result, "tls_handshakes", None) or []):
        sni = entry.get("sni") if isinstance(entry, dict) else None
        if sni:
            items.append((ObservableType.DOMAIN, sni, "auto_pcap_tls_sni"))
    for entry in (getattr(pcap_result, "http_requests", None) or []):
        host = entry.get("host") if isinstance(entry, dict) else None
        if host:
            items.append((ObservableType.DOMAIN, host, "auto_pcap_http_host"))

    if not items:
        return

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session: Session = factory()
    try:
        service = ObservableService(session)
        created_count = 0
        linked_count = 0
        for obs_type, value, context in items:
            try:
                obs, created = service.get_or_create(obs_type, value)
                if created:
                    created_count += 1
                link = service.link_to_case(obs.id, case_id, context=context)
                if link is not None:
                    linked_count += 1
            except Exception as exc:
                logger.debug(
                    "pcap_analysis: linking %s=%s failed: %s", obs_type, value, exc
                )
        session.commit()
        logger.info(
            "pcap_analysis: linked %d observable(s) to case %s (%d newly created)",
            linked_count, case_id, created_count,
        )
    except Exception as exc:
        session.rollback()
        logger.warning("pcap_analysis: observable linking failed: %s", exc)
    finally:
        session.close()


def _post_case_note(case_id: int, content: str) -> None:
    """Open a fresh DB session, attribute the note to Bob, commit.

    Runs inside the background thread, so it manages its own session.
    """
    try:
        from ion.core.config import get_config
        from ion.models.alert_triage import Note, NoteEntityType
        from ion.services.ai_user import get_bob_user_id
        from ion.storage.database import get_engine, get_session_factory
    except Exception as exc:
        logger.warning("pcap_analysis: cannot import deps for note write: %s", exc)
        return

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session: Session = factory()
    try:
        bob_id = get_bob_user_id(session)
        if not bob_id:
            logger.warning("pcap_analysis: Bob user not seeded; skipping case note")
            return
        note = Note(
            entity_type=NoteEntityType.CASE,
            entity_id=str(case_id),
            user_id=bob_id,
            content=content,
        )
        session.add(note)
        session.commit()
        logger.info("pcap_analysis: posted note id=%s to case %s", note.id, case_id)
    except Exception as exc:
        session.rollback()
        logger.warning("pcap_analysis: failed to write case note: %s", exc)
    finally:
        session.close()


async def _runner(
    case_id: int,
    flows: List[Dict[str, Optional[str]]],
) -> None:
    """One analysis pass per flow; one Note per result.

    Each flow is a ``{"community_id": str, "node_hint": Optional[str],
    "alert_id": Optional[str], "source_ip": Optional[str],
    "destination_ip": Optional[str], "alert_timestamp": Optional[str]}``
    dict. The IP + timestamp fields (v0.29.1) feed the IP-fallback path
    inside ``_analyze_one`` when Arkime's community_id index misses.

    Flows are processed sequentially so the case timeline accumulates
    notes in a predictable order and Arkime doesn't get hammered with
    parallel PCAP-assembly requests.
    """
    # Track the strongest PCAP-derived severity across all flows in this
    # case; apply it once at the end (a case spanning several flows takes the
    # highest). v0.39.0.
    best_severity: Optional[str] = None
    best_reasons: List[str] = []
    case_techniques: Dict[str, Dict[str, Any]] = {}  # id → {id, name} union across flows
    for flow in flows:
        cid = flow.get("community_id") or ""
        if not cid:
            continue
        node_hint = flow.get("node_hint")
        alert_id = flow.get("alert_id")
        try:
            r = await _analyze_one(
                cid,
                alert_node_hint=node_hint,
                source_ip=flow.get("source_ip"),
                destination_ip=flow.get("destination_ip"),
                alert_timestamp=flow.get("alert_timestamp"),
            )
            md = _render_pcap_markdown(
                community_id=cid,
                sessions=r["sessions"],
                pcap_result=r["pcap_result"],
                arkime_url_root=r["arkime_url_root"],
                pcap_error=r["pcap_error"],
                fallback_warning=r.get("fallback_warning"),
            )
            footer = f"\n\n_Generated by Bob · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
            if alert_id:
                footer = (
                    f"\n\n_Source alert: `{alert_id}`_"
                    + footer
                )
            md += footer
            _post_case_note(case_id, md)
            # v0.30.1: also surface PCAP findings as Observable rows linked
            # to the case so they participate in enrichment / watchlist /
            # correlation. Best-effort — never blocks the Note write.
            _link_pcap_observables(case_id, r["pcap_result"])
            # v0.39.0: let the verdict drive case severity (two-way auto).
            sev = pcap_case_severity(r["pcap_result"])
            if sev and severity_rank(sev) > severity_rank(best_severity):
                best_severity = sev
                verdict = getattr(r["pcap_result"], "verdict", None) or {}
                best_reasons = list(verdict.get("reasons") or [])
            # v0.39.0: accumulate the MITRE technique union across all flows.
            for t in (getattr(r["pcap_result"], "mitre_techniques", None) or []):
                if t.get("id"):
                    case_techniques.setdefault(t["id"], {"id": t["id"], "name": t.get("name", "")})
        except Exception as exc:
            logger.warning("pcap_analysis: %s failed: %s", cid, exc)

    # Apply the aggregate severity once (after every flow's note is posted so
    # the timeline reads analysis-then-decision).
    if best_severity:
        techniques = [case_techniques[k] for k in sorted(case_techniques)]
        _apply_case_severity(case_id, best_severity, best_reasons, techniques)


def enqueue_pcap_analysis_for_case(
    case_id: int,
    flows: Optional[List[Dict[str, Optional[str]]]] = None,
    *,
    # Legacy kw-args kept so older callers don't break; deprecated v0.25.x.
    community_ids: Optional[List[str]] = None,
    alert_node_hint: Optional[str] = None,
) -> None:
    """Fire-and-forget PCAP analysis for one or more flows.

    Each flow is a ``{"community_id": str, "node_hint": Optional[str],
    "alert_id": Optional[str]}`` dict so per-alert node hints survive
    into the Arkime lookup (different capture nodes for different
    alerts). Flows are deduped by ``community_id`` — if two alerts in
    the same case carry the same flow hash they get one note.

    Mirrors ``case_grouper_service.enqueue_investigation``: prefer the
    running event loop when one exists (we're inside FastAPI), fall
    back to a daemon thread that owns its own asyncio loop. Never
    raises so case creation isn't blocked or broken by Arkime issues.

    Legacy callers passing ``community_ids`` + ``alert_node_hint`` are
    accepted; the kwargs are mapped into the flow shape internally.
    """
    # Backwards-compat: build flows from legacy kwargs if used.
    if flows is None:
        flows = []
        for cid in (community_ids or []):
            cid = (cid or "").strip()
            if cid:
                flows.append({
                    "community_id": cid,
                    "node_hint": alert_node_hint,
                    "alert_id": None,
                })

    # Dedup by community_id while preserving order so the comment list
    # is stable across re-invocations. Keep the FIRST occurrence's node
    # hint and alert id — multi-alert cases that share a flow hash all
    # converge on one note attributed to the earliest alert.
    seen: set = set()
    unique: List[Dict[str, Optional[str]]] = []
    for flow in flows:
        cid = (flow.get("community_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        unique.append({
            "community_id": cid,
            "node_hint": flow.get("node_hint"),
            "alert_id": flow.get("alert_id"),
            # v0.39.1: preserve the IP + timestamp fields so _analyze_one's
            # IP-fallback path (v0.29.1) survives the dedup. Dropping them here
            # silently disabled the fallback for the auto-case flow — when
            # Arkime's community_id index missed, the analysis found no sessions
            # and posted an empty note.
            "source_ip": flow.get("source_ip"),
            "destination_ip": flow.get("destination_ip"),
            "alert_timestamp": flow.get("alert_timestamp"),
        })
    if not unique:
        return

    logger.info(
        "pcap_analysis: enqueued case=%s flows=%d",
        case_id, len(unique),
    )

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_runner(case_id, unique))
        return
    except RuntimeError:
        pass

    def _bg() -> None:
        try:
            asyncio.run(_runner(case_id, unique))
        except Exception as exc:
            logger.debug("pcap_analysis bg thread failed: %s", exc)

    threading.Thread(
        target=_bg, daemon=True, name=f"ion-pcap-{case_id}",
    ).start()
