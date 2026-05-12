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

    # Findings + verdict
    if pcap_result.findings:
        parts.append("**Findings:**")
        for f in pcap_result.findings[:8]:
            sev = f.get("severity", "info") if isinstance(f, dict) else "info"
            msg = f.get("message", str(f)) if isinstance(f, dict) else str(f)
            parts.append(f"- **{sev}**: {msg}")
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
        except Exception as exc:
            logger.warning("pcap_analysis: %s failed: %s", cid, exc)


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
