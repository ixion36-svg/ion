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
) -> str:
    """Render the full markdown report for one community_id."""
    parts: List[str] = []
    parts.append(f"### {_ICON} PCAP auto-analysis — `community_id` = `{community_id}`")
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
) -> Dict[str, Any]:
    """Run the Arkime → PCAP → dpkt pipeline for one community_id.

    Returns ``{"sessions": [...], "pcap_result": PcapResult|None,
    "arkime_url_root": str, "pcap_error": str|None}``. Never raises —
    failures land in ``pcap_error`` so the renderer can fall back
    gracefully to metadata-only output.
    """
    out: Dict[str, Any] = {
        "sessions": [], "pcap_result": None,
        "arkime_url_root": None, "pcap_error": None,
    }
    try:
        from ion.services.arkime_service import get_arkime_service, ArkimeError
    except Exception as exc:
        out["pcap_error"] = f"Arkime service unavailable: {exc}"
        return out

    svc = get_arkime_service()
    if not getattr(svc, "is_configured", False):
        out["pcap_error"] = "Arkime not configured"
        return out
    out["arkime_url_root"] = getattr(svc, "url", None)

    try:
        sessions = await svc.find_sessions_by_community_id(
            alert_node_hint or "", community_id,
        )
        out["sessions"] = sessions or []
    except Exception as exc:
        out["pcap_error"] = f"Arkime session lookup failed: {exc}"
        return out

    if not sessions:
        out["pcap_error"] = "No Arkime sessions matched"
        return out

    try:
        download = await svc.download_pcap_by_community_id(
            alert_node_hint or "", community_id,
        )
        pcap_bytes = download.get("pcap")
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
        from ion.storage.database import get_engine, get_session_factory
        from ion.models.alert_triage import Note, NoteEntityType
        from ion.services.ai_user import get_bob_user_id
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
    community_ids: List[str],
    alert_node_hint: Optional[str],
) -> None:
    """One analysis pass per community_id; one Note per result."""
    for cid in community_ids:
        try:
            r = await _analyze_one(cid, alert_node_hint=alert_node_hint)
            md = _render_pcap_markdown(
                community_id=cid,
                sessions=r["sessions"],
                pcap_result=r["pcap_result"],
                arkime_url_root=r["arkime_url_root"],
                pcap_error=r["pcap_error"],
            )
            md += f"\n\n_Generated by Bob · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
            _post_case_note(case_id, md)
        except Exception as exc:
            logger.warning("pcap_analysis: %s failed: %s", cid, exc)


def enqueue_pcap_analysis_for_case(
    case_id: int,
    community_ids: List[str],
    *,
    alert_node_hint: Optional[str] = None,
) -> None:
    """Fire-and-forget PCAP analysis for one or more community_ids.

    Mirrors ``case_grouper_service.enqueue_investigation``: prefer the
    running event loop when one exists (we're inside FastAPI), fall back
    to a daemon thread that owns its own asyncio loop. Never raises so
    case creation isn't blocked or broken by Arkime issues.
    """
    if not community_ids:
        return
    # Dedup while preserving order so the comment list is stable.
    seen: set = set()
    unique: List[str] = []
    for cid in community_ids:
        cid = (cid or "").strip()
        if cid and cid not in seen:
            seen.add(cid)
            unique.append(cid)
    if not unique:
        return

    logger.info(
        "pcap_analysis: enqueued case=%s community_ids=%d node_hint=%r",
        case_id, len(unique), alert_node_hint,
    )

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_runner(case_id, unique, alert_node_hint))
        return
    except RuntimeError:
        pass

    def _bg() -> None:
        try:
            asyncio.run(_runner(case_id, unique, alert_node_hint))
        except Exception as exc:
            logger.debug("pcap_analysis bg thread failed: %s", exc)

    threading.Thread(
        target=_bg, daemon=True, name=f"ion-pcap-{case_id}",
    ).start()
