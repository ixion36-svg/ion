"""Realtime Arkime traffic monitor — content & behaviour detection.

Arkime keeps full PCAP only for a short retention window (≈3 days here) before
ageing down to metadata-only. This loop sweeps recent traffic for *intrinsically
suspicious* sessions while the capture is still pullable — it does NOT rely on a
pre-existing IOC set. (Whether Arkime captures live off a SPAN port or ingests
forwarded/imported PCAPs is irrelevant here: RTMON consumes Arkime's parsed
session/SPI API either way, and the retention window applies to stored PCAP
regardless of how it got there.) Each pass runs a panel of cheap Arkime
SPI-metadata detectors, and every hit auto-creates a case wired to the session's
``communityId`` + node and enqueues the full PCAP analyzer (which extracts the
actual cleartext credential / command payload / RITA beacon score / JA3-JA4
fingerprint as deep evidence) before the capture expires.

Detectors (each independently toggleable; all default ON except the legacy IOC
matcher):

* ``cleartext_credentials`` — Arkime's aggregate ``user`` field (a username it
  already parsed out of a cleartext-auth exchange) or a cleartext-credential
  protocol (FTP/Telnet/POP3/IMAP/SMTP/SNMP/LDAP). Opens a case immediately;
  the PCAP analyzer recovers the password/hash itself. (low FP)
* ``command_channel`` — Telnet/IRC, or egress to a shell / known-C2 port
  (4444, 1337, 512–514 rsh/rexec, 5555/6666/8888/9001/31337…). Reverse shells
  and interactive C2. Opens a case immediately. (low FP)
* ``c2_beacon_shape`` — groups recent *egress* sessions by (src, dst, dstPort)
  and scores interval+size regularity with the same RITA-style scorer the PCAP
  pipeline uses. CONFIRM-FIRST: a candidate must clear a strict score +
  connection-count gate before a case is opened (a single session's PCAP can't
  prove a beacon — beaconing lives across many sessions over time — so the gate
  is the metadata score, and the PCAP is pulled afterward for deep evidence).
* ``dns_tunneling`` — DNS sessions whose queried names are long / high-entropy.
  CONFIRM-FIRST: a candidate is verified by pulling its PCAP and re-running the
  pipeline's DNS-tunnel/DGA detector before a case is opened (budget-capped).
* ``ioc_ip`` — LEGACY. The original v0.45.0 behaviour: match live sessions
  against ION's IOC IP set. OFF by default (``…_IOC_ENABLED``); kept so the
  capability isn't lost.

Dedup: a synthetic ``AlertTriage.es_alert_id`` marker
(``rtmon:<detector>:<node>:<communityId>`` for per-session detectors, or
``rtmon:beacon:<src>:<dst>:<port>`` for the grouped beacon detector) marks
already-actioned flows so re-runs don't re-alert the same traffic.

Environment variables:
* ``ION_ARKIME_RTMON_ENABLED``              (default ``false`` — master opt-in)
* ``ION_ARKIME_RTMON_INTERVAL_MINUTES``     (default ``10``)
* ``ION_ARKIME_RTMON_WINDOW_MINUTES``       (default ``20`` — content detectors)
* ``ION_ARKIME_RTMON_BEACON_WINDOW_MINUTES``(default ``180`` — beacon needs history)
* ``ION_ARKIME_RTMON_MAX_CASES_PER_PASS``   (default ``25`` — backstop)
* ``ION_ARKIME_RTMON_CLEARTEXT_ENABLED``    (default ``true``)
* ``ION_ARKIME_RTMON_COMMAND_ENABLED``      (default ``true``)
* ``ION_ARKIME_RTMON_BEACON_ENABLED``       (default ``true``)
* ``ION_ARKIME_RTMON_DNS_ENABLED``          (default ``true``)
* ``ION_ARKIME_RTMON_IOC_ENABLED``          (default ``false`` — legacy)
* ``ION_ARKIME_RTMON_BEACON_MIN_CONN``      (default ``6``)
* ``ION_ARKIME_RTMON_BEACON_SCORE``         (default ``0.9`` — confirm gate)
* ``ION_ARKIME_RTMON_DNS_MIN_QLEN``         (default ``40``)
* ``ION_ARKIME_RTMON_DNS_CONFIRM_BUDGET``   (default ``5`` — PCAP pulls/pass)
"""

import asyncio
import ipaddress
import logging
import math
import os
from typing import Any, Dict, List, Optional

from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_DEFAULT_INTERVAL_MINUTES = 10.0
_DEFAULT_WINDOW_MINUTES = 20
_DEFAULT_BEACON_WINDOW_MINUTES = 180
_DEFAULT_MAX_CASES = 25
_MIN_INTERVAL_SECONDS = 60

# Egress to any of these destination ports is a shell / known-C2 signal. Mirrors
# the SUSPICIOUS_PORTS map in pcap_service (kept in sync deliberately).
_SHELL_C2_PORTS = {4444, 1337, 1234, 3333, 5555, 6666, 6667, 6697, 8888, 9001, 9050, 9150, 31337, 14444}
# rsh/rexec/rlogin — interactive remote-command channels.
_RSH_PORTS = {512, 513, 514}
# Cleartext-credential-bearing protocols (Arkime ``protocols`` tag values).
_CLEARTEXT_PROTOCOLS = ("ftp", "telnet", "pop3", "imap", "smtp", "snmp", "ldap")
# Ports we treat as benign for beacon scoring even when periodic (NTP).
_BEACON_BENIGN_PORTS = {123}


# ── env helpers ────────────────────────────────────────────────────────────
def _flag(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on")


def _enabled() -> bool:
    return _flag("ION_ARKIME_RTMON_ENABLED", False)


def _interval_seconds() -> int:
    try:
        minutes = float(os.environ.get("ION_ARKIME_RTMON_INTERVAL_MINUTES", str(_DEFAULT_INTERVAL_MINUTES)))
    except (TypeError, ValueError):
        minutes = _DEFAULT_INTERVAL_MINUTES
    return max(_MIN_INTERVAL_SECONDS, int(minutes * 60))


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _window_minutes() -> int:
    return _int_env("ION_ARKIME_RTMON_WINDOW_MINUTES", _DEFAULT_WINDOW_MINUTES)


def _beacon_window_minutes() -> int:
    return _int_env("ION_ARKIME_RTMON_BEACON_WINDOW_MINUTES", _DEFAULT_BEACON_WINDOW_MINUTES)


def _max_cases() -> int:
    return _int_env("ION_ARKIME_RTMON_MAX_CASES_PER_PASS", _DEFAULT_MAX_CASES)


def _severity_for(threat_level: str) -> str:
    tl = (threat_level or "").lower()
    if tl == "critical":
        return "critical"
    if tl == "high":
        return "high"
    return "medium"


# ── session-field helpers (tolerant of Arkime's flat/nested shapes) ─────────
def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _is_external(ip: str) -> bool:
    """External = a routable, non-private, non-loopback address."""
    try:
        addr = ipaddress.ip_address(str(ip))
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _dst_port(s: Dict[str, Any]) -> Optional[int]:
    for k in ("dstPort", "port.dst"):
        v = s.get(k)
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                continue
    return None


def _session_user(s: Dict[str, Any]) -> str:
    """Arkime's aggregate ``user`` field — may be a str or a list of usernames."""
    u = s.get("user")
    if isinstance(u, (list, tuple)):
        u = next((x for x in u if x), None)
    return str(u).strip() if u else ""


def _session_protocols(s: Dict[str, Any]) -> List[str]:
    p = s.get("protocol") or s.get("protocols")
    if isinstance(p, str):
        p = [p]
    return [str(x).strip().lower() for x in (p or []) if x]


def _session_dns_names(s: Dict[str, Any]) -> List[str]:
    names = s.get("dns.host")
    if names is None:
        dns = s.get("dns")
        if isinstance(dns, dict):
            names = dns.get("host")
    if isinstance(names, str):
        names = [names]
    return [str(n).strip() for n in (names or []) if n]


def _shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy (bits). High for random/encoded subdomains."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _community_id(s: Dict[str, Any]) -> str:
    return str(s.get("communityId") or s.get("community_id") or "").strip()


# ── detector: cleartext credentials ────────────────────────────────────────
def _detect_cleartext_credentials(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in sessions:
        cid, node = _community_id(s), (s.get("node") or "")
        if not cid or not node:
            continue
        protos = _session_protocols(s)
        user = _session_user(s)
        cleartext_proto = next((p for p in protos if p in _CLEARTEXT_PROTOCOLS), None)
        if not user and not cleartext_proto:
            continue
        src, dst = s.get("srcIp") or "", s.get("dstIp") or ""
        why = []
        if user:
            why.append(f"Arkime parsed a cleartext username `{user}`")
        if cleartext_proto:
            why.append(f"cleartext-auth protocol `{cleartext_proto}`")
        out.append({
            "detector": "cleartext_credentials",
            "marker": f"rtmon:cleartext_credentials:{node}:{cid}",
            "node": node, "community_id": cid, "src": src, "dst": dst,
            "dst_port": _dst_port(s), "tot_bytes": int(s.get("totBytes") or 0),
            "severity": "high", "confirm_first": False,
            "title": f"[RT-Netmon] Cleartext credentials on the wire ({cleartext_proto or 'auth'}) {src} → {dst}",
            "summary": " and ".join(why) + ".",
            "evidence": {"protocols": protos, "user": user, "cleartext_protocol": cleartext_proto},
        })
    return out


# ── detector: interactive command / C2 channel ─────────────────────────────
def _detect_command_channel(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in sessions:
        cid, node = _community_id(s), (s.get("node") or "")
        if not cid or not node:
            continue
        protos = _session_protocols(s)
        dport = _dst_port(s)
        src, dst = s.get("srcIp") or "", s.get("dstIp") or ""
        reasons = []
        if "telnet" in protos:
            reasons.append("Telnet (interactive cleartext shell)")
        if "irc" in protos:
            reasons.append("IRC (classic botnet C2 channel)")
        if dport in _SHELL_C2_PORTS:
            reasons.append(f"egress to known shell/C2 port {dport}")
        elif dport in _RSH_PORTS:
            reasons.append(f"egress to rsh/rexec port {dport} (remote command exec)")
        if not reasons:
            continue
        # Port-based hits only count when the destination is external — internal
        # service traffic on these ports would otherwise flood the detector.
        port_only = not ("telnet" in protos or "irc" in protos)
        if port_only and not _is_external(dst):
            continue
        out.append({
            "detector": "command_channel",
            "marker": f"rtmon:command_channel:{node}:{cid}",
            "node": node, "community_id": cid, "src": src, "dst": dst,
            "dst_port": dport, "tot_bytes": int(s.get("totBytes") or 0),
            "severity": "high", "confirm_first": False,
            "title": f"[RT-Netmon] Possible command/C2 channel {src} → {dst}:{dport}",
            "summary": "; ".join(reasons) + ".",
            "evidence": {"protocols": protos, "dst_port": dport},
        })
    return out


# ── detector: C2 beacon shape (grouped, confirm-first via score gate) ───────
def _detect_beacon_shape(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group recent egress sessions by (src, dst, dstPort) and score the cadence.

    Uses the SAME RITA-style scorer as the PCAP pipeline so behaviour is
    consistent. Beaconing only manifests across many sessions, so the metadata
    score IS the confirmation signal (see module docstring); candidates below
    the gate never become cases.
    """
    try:
        from ion.services.pcap_service import _compute_beacon_scores
    except Exception as exc:  # noqa: BLE001
        logger.debug("rtmon: beacon scorer import failed: %s", exc)
        return []

    min_conn = _int_env("ION_ARKIME_RTMON_BEACON_MIN_CONN", 6)
    score_gate = _float_env("ION_ARKIME_RTMON_BEACON_SCORE", 0.9)

    conn_times: Dict[tuple, List[float]] = {}
    conn_sizes: Dict[tuple, List[int]] = {}
    rep: Dict[tuple, Dict[str, Any]] = {}  # representative (most-recent) session per tuple
    for s in sessions:
        src, dst, dport = s.get("srcIp") or "", s.get("dstIp") or "", _dst_port(s)
        if not src or not dst or dport is None:
            continue
        if not _is_external(dst) or dport in _BEACON_BENIGN_PORTS:
            continue
        # Arkime firstPacket is epoch milliseconds; the scorer is unit-agnostic
        # for regularity but we pass seconds so interval_s reads correctly.
        fp = s.get("firstPacket")
        try:
            t = float(fp) / 1000.0
        except (TypeError, ValueError):
            continue
        key = (src, dst, dport)
        conn_times.setdefault(key, []).append(t)
        conn_sizes.setdefault(key, []).append(int(s.get("totBytes") or 0))
        prev = rep.get(key)
        if prev is None or t >= (float(prev.get("firstPacket") or 0) / 1000.0):
            rep[key] = s

    scored = _compute_beacon_scores(conn_times, conn_sizes)
    out: List[Dict[str, Any]] = []
    for b in scored:
        if b["connections"] < min_conn or b["score"] < score_gate:
            continue
        key = (b["src"], b["dst"], b["port"])
        s = rep.get(key, {})
        cid, node = _community_id(s), (s.get("node") or "")
        sev = "high" if b["score"] >= 0.95 else "medium"
        out.append({
            "detector": "c2_beacon_shape",
            # tuple-scoped marker — dedup the beacon, not each constituent session
            "marker": f"rtmon:beacon:{b['src']}:{b['dst']}:{b['port']}",
            "node": node, "community_id": cid, "src": b["src"], "dst": b["dst"],
            "dst_port": b["port"], "tot_bytes": 0,
            "severity": sev, "confirm_first": True, "confirmed": True,  # score gate already passed
            "title": f"[RT-Netmon] C2 beacon shape {b['src']} → {b['dst']}:{b['port']} (score {b['score']})",
            "summary": (
                f"{b['connections']} egress connections every ~{b['interval_s']}s with high "
                f"interval+size regularity (RITA-style score {b['score']}). Hallmark of automated C2."
            ),
            "evidence": {k: b.get(k) for k in ("connections", "interval_s", "cv", "interval_score", "size_score", "score")},
        })
    return out


# ── detector: DNS tunneling (confirm-first via PCAP re-analysis) ────────────
def _detect_dns_tunneling(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    min_qlen = _int_env("ION_ARKIME_RTMON_DNS_MIN_QLEN", 40)
    out: List[Dict[str, Any]] = []
    for s in sessions:
        cid, node = _community_id(s), (s.get("node") or "")
        if not cid or not node:
            continue
        names = _session_dns_names(s)
        if not names:
            continue
        longest = max(names, key=len)
        # Strip the registrable tail so entropy is measured on the encoded label.
        label = longest.split(".")[0] if "." in longest else longest
        if len(longest) < min_qlen and _shannon_entropy(label) < 3.5:
            continue
        src, dst = s.get("srcIp") or "", s.get("dstIp") or ""
        out.append({
            "detector": "dns_tunneling",
            "marker": f"rtmon:dns_tunneling:{node}:{cid}",
            "node": node, "community_id": cid, "src": src, "dst": dst,
            "dst_port": _dst_port(s) or 53, "tot_bytes": int(s.get("totBytes") or 0),
            "severity": "high", "confirm_first": True, "confirmed": False,
            "title": f"[RT-Netmon] Possible DNS tunneling {src} → {dst}",
            "summary": (
                f"Long/high-entropy DNS query observed (e.g. `{longest[:80]}`, "
                f"len={len(longest)}, label-entropy={_shannon_entropy(label):.1f} bits). "
                f"Verifying against the PCAP DNS-tunnel detector."
            ),
            "evidence": {"sample_query": longest[:120], "query_len": len(longest),
                         "label_entropy": round(_shannon_entropy(label), 2)},
        })
    return out


# ── confirm-first: DNS tunneling via PCAP re-analysis ───────────────────────
async def _confirm_dns_tunnel(cand: Dict[str, Any]) -> bool:
    """Pull the candidate's PCAP and re-run the pipeline's DNS-tunnel/DGA
    detector. Returns True only if the deep analyzer corroborates the metadata
    heuristic. Fail-open is avoided: an unreachable/empty PCAP → not confirmed.
    """
    try:
        from ion.services.pcap_analysis_service import _analyze_one
    except Exception as exc:  # noqa: BLE001
        logger.debug("rtmon: dns-confirm import failed: %s", exc)
        return False
    try:
        res = await _analyze_one(
            cand["community_id"],
            alert_node_hint=cand.get("node"),
            source_ip=cand.get("src"),
            destination_ip=cand.get("dst"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("rtmon: dns-confirm analyze raised: %s", exc)
        return False
    pcap_result = res.get("pcap_result")
    findings = getattr(pcap_result, "findings", None) or []
    dns_cats = {"DNS Tunneling", "DNS Anomaly", "DGA Detection"}

    def _cat(f: Any) -> str:
        # parse_pcap stores findings as dicts; tolerate Finding objects too.
        return f.get("category", "") if isinstance(f, dict) else getattr(f, "category", "")

    return any(_cat(f) in dns_cats for f in findings)


# ── legacy detector: IOC IP set (opt-in) ────────────────────────────────────
def _load_ioc_ips(session) -> dict:
    """Map IOC IP value → {threat_level, label, observable_id} for the active set.

    Includes observables that are explicitly IOC/watched, high/critical threat
    level, or carry an OpenCTI 'malicious' enrichment. IP-typed only.
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
        mal = (
            session.query(Observable)
            .join(ObservableEnrichment, ObservableEnrichment.observable_id == Observable.id)
            .filter(Observable.type.in_([ObservableType.IPV4, ObservableType.IPV6]))
            .filter(Observable.is_whitelisted.is_(False))
            .filter(ObservableEnrichment.is_malicious.is_(True))
            .all()
        )
        for o in mal:
            out.setdefault(o.value, {"threat_level": "high", "label": "OpenCTI-malicious", "observable_id": o.id})
    except Exception as exc:  # noqa: BLE001
        logger.debug("rtmon: IOC load failed: %s", exc)
    return out


def _detect_ioc_ip(sessions: List[Dict[str, Any]], iocs: dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in sessions:
        cid, node = _community_id(s), (s.get("node") or "")
        if not cid or not node:
            continue
        src, dst = s.get("srcIp") or "", s.get("dstIp") or ""
        hit_ip = src if src in iocs else (dst if dst in iocs else "")
        if not hit_ip:
            continue
        meta = iocs.get(hit_ip, {})
        out.append({
            "detector": "ioc_ip",
            "marker": f"rtmon:ioc_ip:{node}:{cid}",
            "node": node, "community_id": cid, "src": src, "dst": dst,
            "dst_port": _dst_port(s), "tot_bytes": int(s.get("totBytes") or 0),
            "severity": _severity_for(meta.get("threat_level")), "confirm_first": False,
            "title": f"[RT-Netmon] Known-bad IP in live traffic ({hit_ip}) on {node}",
            "summary": (
                f"Live traffic involving IOC `{hit_ip}` "
                f"({meta.get('label', 'IOC')}, threat={meta.get('threat_level')})."
            ),
            "evidence": {"ioc_ip": hit_ip, **meta},
        })
    return out


# ── case creation ───────────────────────────────────────────────────────────
def _open_case(session, bob_id: int, cand: Dict[str, Any], enqueue_fn) -> None:
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

    src, dst, node = cand.get("src", ""), cand.get("dst", ""), cand.get("node", "")
    cid, dport = cand.get("community_id", ""), cand.get("dst_port")
    case = AlertCase(
        case_number=case_number,
        title=cand["title"][:200],
        description=(
            f"Realtime Arkime monitor [{cand['detector']}] flagged recent traffic. "
            f"{cand['summary']} Flow {src} → {dst}"
            + (f":{dport}" if dport else "")
            + f" on node {node} (communityId {cid}). "
            f"Full PCAP analysis queued while the capture is still in Arkime's retention window."
        ),
        status=AlertCaseStatus.OPEN,
        severity=cand.get("severity", "medium"),
        created_by_id=bob_id,
        assigned_to_id=bob_id,
        source_alert_ids=[],
    )
    session.add(case)
    session.flush()

    session.add(AlertTriage(es_alert_id=cand["marker"], case_id=case.id, source_system="arkime-rtmon"))

    evidence_lines = "\n".join(f"  - {k}: `{v}`" for k, v in (cand.get("evidence") or {}).items() if v not in (None, "", []))
    session.add(Note(
        entity_type=NoteEntityType.CASE,
        entity_id=str(case.id),
        user_id=bob_id,
        content=(
            f"**Realtime traffic detection — {cand['detector']}**\n\n"
            f"{cand['summary']}\n\n"
            f"- Flow: `{src}` → `{dst}`" + (f":`{dport}`" if dport else "") + "\n"
            f"- Node: `{node}`  ·  communityId: `{cid}`\n"
            + (f"- Evidence:\n{evidence_lines}\n" if evidence_lines else "")
            + "\nFull PCAP queued for analysis — pull it before it ages to metadata-only."
        ),
    ))
    session.commit()

    logger.info("rtmon: opened %s [%s] for %s → %s node=%s", case_number, cand["detector"], src, dst, node)
    if cid and node:
        enqueue_fn(
            case_id=case.id,
            flows=[{
                "community_id": cid, "node_hint": node, "alert_id": None,
                "source_ip": src, "destination_ip": dst, "alert_timestamp": None,
            }],
        )


# ── pass orchestration ──────────────────────────────────────────────────────
async def _gather_candidates(svc) -> List[Dict[str, Any]]:
    """Run every enabled content/behaviour detector and return raw candidates."""
    from ion.services.arkime_service import ArkimeError

    cands: List[Dict[str, Any]] = []
    window = _window_minutes()

    async def _sweep(expr: str, win: int) -> List[Dict[str, Any]]:
        try:
            return await svc.find_recent_sessions_by_expression(expr, window_minutes=win, limit=1000)
        except ArkimeError as exc:
            logger.debug("rtmon: sweep failed (%s): %s", expr[:60], exc)
            return []

    if _flag("ION_ARKIME_RTMON_CLEARTEXT_ENABLED", True):
        expr = "(user == EXISTS!) || " + " || ".join(f"protocols == {p}" for p in _CLEARTEXT_PROTOCOLS)
        cands += _detect_cleartext_credentials(await _sweep(expr, window))

    if _flag("ION_ARKIME_RTMON_COMMAND_ENABLED", True):
        ports = sorted(_SHELL_C2_PORTS | _RSH_PORTS)
        expr = "protocols == telnet || protocols == irc || port.dst == [" + ",".join(map(str, ports)) + "]"
        cands += _detect_command_channel(await _sweep(expr, window))

    if _flag("ION_ARKIME_RTMON_BEACON_ENABLED", True):
        # Egress only — exclude private destinations at the query to bound volume.
        expr = "ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16"
        cands += _detect_beacon_shape(await _sweep(expr, _beacon_window_minutes()))

    if _flag("ION_ARKIME_RTMON_DNS_ENABLED", True):
        cands += _detect_dns_tunneling(await _sweep("protocols == dns", window))

    return cands


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

    candidates = await _gather_candidates(svc)

    factory = get_session_factory(engine)
    session = factory()
    try:
        # Legacy IOC-IP detector (opt-in) — needs a DB session for the IOC set.
        if _flag("ION_ARKIME_RTMON_IOC_ENABLED", False):
            iocs = _load_ioc_ips(session)
            if iocs:
                try:
                    ioc_sessions = await svc.find_recent_sessions_for_ips(
                        list(iocs.keys()), window_minutes=_window_minutes(), limit=500
                    )
                    candidates += _detect_ioc_ip(ioc_sessions, iocs)
                except ArkimeError as exc:
                    logger.debug("rtmon: IOC sweep failed: %s", exc)

        if not candidates:
            return

        bob_id = get_bob_user_id(session)
        if not bob_id:
            logger.warning("rtmon: Bob user not seeded; skipping pass")
            return

        dns_budget = _int_env("ION_ARKIME_RTMON_DNS_CONFIRM_BUDGET", 5)
        created = 0
        seen_markers: set = set()
        for cand in candidates:
            if created >= _max_cases():
                logger.info("rtmon: hit max cases/pass (%d) — remaining candidates next pass", _max_cases())
                break
            marker = cand["marker"]
            if marker in seen_markers:
                continue  # de-dupe within this pass (e.g. multiple sessions same beacon tuple)
            seen_markers.add(marker)
            if session.query(AlertTriage).filter(AlertTriage.es_alert_id == marker).first():
                continue  # already actioned a prior pass

            # Confirm-first detectors must clear their gate before a case opens.
            if cand.get("confirm_first") and not cand.get("confirmed"):
                if cand["detector"] == "dns_tunneling":
                    if dns_budget <= 0:
                        continue  # out of PCAP-confirm budget this pass
                    dns_budget -= 1
                    if not await _confirm_dns_tunnel(cand):
                        continue
                else:
                    continue  # unknown unconfirmed candidate — never auto-case

            try:
                _open_case(session, bob_id, cand, enqueue_pcap_analysis_for_case)
                created += 1
            except Exception as exc:  # noqa: BLE001
                session.rollback()
                logger.warning("rtmon: failed to open case for %s: %s", marker, exc)
        if created:
            logger.info("rtmon: opened %d traffic-detection case(s) this pass", created)
    finally:
        session.close()


async def _loop(engine: Engine) -> None:
    global _running
    interval = _interval_seconds()
    logger.info(
        "Arkime realtime traffic monitor started; interval=%ds window=%dm beacon_window=%dm",
        interval, _window_minutes(), _beacon_window_minutes(),
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
            logger.warning("rtmon: pass raised: %s", exc)


def start_background_loop(engine: Engine) -> Optional[asyncio.Task]:
    """Start the realtime traffic monitor. Opt-in; idempotent."""
    global _task, _running
    if not _enabled():
        logger.info("Arkime realtime traffic monitor disabled (ION_ARKIME_RTMON_ENABLED=false)")
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
