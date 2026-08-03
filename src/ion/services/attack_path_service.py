"""Attack Path (Bob Pathfinding) — Phase 0 deterministic path-graph builder.

Compute-on-read, read-only, air-gap-safe. Assembles a structured directed
attack-path graph for a case *deterministically* from that case's alerts —
NO LLM, NO network (beyond the existing ES alert fetch), NO DB writes.

Mirrors the DE-module Phase-0 / v0.59.0 observable pattern: everything is
derived on the fly from data the case already carries
(``ElasticsearchAlert.to_dict`` common fields + the v0.59.0 ``observables``
contract list). A malformed alert is skipped, never fatal; an empty or
single-alert case still returns a valid (possibly single-node) graph.

Governing rule: *Extract → link (deterministic) → trace path → human decides.*
The graph surfaces and prioritises; it never auto-closes, auto-suppresses, or
mutates stored alert/case state.

Emitted schema (the Phase-1 UI binds to this)::

    {
      "case_id": int,
      "generated_at": ISO-8601 str,
      "nodes": [ {"id","type","value","label","threat_level"} ],
      "edges": [ {"source","target","type","label","alert_ids":[...]} ],
      "phases": [ {"tactic","rank","node_ids":[...],"alert_ids":[...]} ],
      "stats": {
        "nodes": int,
        "edges": {"total","process_lineage","network_flow",
                  "auth_presence","shared_observable"},
        "alerts": int,
        "tactics_reached": [slug, ...],   # kill-chain order, excludes unknown
        "reaches_impact": bool,
      }
    }

Node ``id`` is stable + unique: ``"<prefix>:<value>"`` where prefix is one of
host / user / proc / ip / domain / file / hash. ``threat_level`` is populated for
observable-backed nodes (ip/domain/hash) from the alert's ``observables`` entry,
and ``None`` when the entity is not observable-backed.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── MITRE kill-chain ordering ────────────────────────────────────────────────
# Canonical tactic slug -> kill-chain rank. Unmapped / unknown sorts last.
KILL_CHAIN_RANK: Dict[str, int] = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}
UNKNOWN_RANK = 99
UNKNOWN_TACTIC = "unknown"

# MITRE tactic IDs (TAxxxx) -> canonical slug, for feeds that emit the ID in
# the ``mitre_tactic_name`` field.
_TA_ID_MAP: Dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}

# Tactics whose presence means the chain reaches "something that matters" — a
# cheap precursor to the Phase-2 reachability score.
_IMPACTFUL_TACTICS = frozenset(
    {"impact", "exfiltration", "credential-access", "lateral-movement"}
)

# ── Phase-2 reachability weights (Fork D: MITRE-tactic-reached heuristic) ─────
# Per-tactic weight (0-100) for the "how far / how bad does this chain reach"
# score. Deterministic, no config, no LLM: the SOC analogue of Maze's
# exploitability-in-context over raw severity. The furthest (highest-weight)
# tactic present dominates; breadth of tactics and a high/critical threat node
# add on top. Ordering follows the kill chain — impact/exfil highest, recon /
# resource-development lowest.
_TACTIC_WEIGHT: Dict[str, int] = {
    "impact": 95,
    "exfiltration": 90,
    "credential-access": 78,
    "lateral-movement": 78,
    "privilege-escalation": 72,
    "command-and-control": 62,
    "collection": 58,
    "execution": 45,
    "persistence": 45,
    "defense-evasion": 45,
    "discovery": 38,
    "initial-access": 25,
    "reconnaissance": 12,
    "resource-development": 12,
}

# Threat levels that count as "a node that matters" for the scoring boost.
_HIGH_THREATS = ("critical", "high")

# ── Node model ───────────────────────────────────────────────────────────────
# The 7 path-entity node types and their stable id prefixes.
_NODE_PREFIX: Dict[str, str] = {
    "host": "host",
    "user": "user",
    "process": "proc",
    "ip": "ip",
    "domain": "domain",
    "file": "file",
    "hash": "hash",
}

# Map the v0.59.0 observable contract types onto the node model. url / email /
# registry observables are not part of the path-entity node set and are skipped.
_OBS_TYPE_TO_NODE: Dict[str, str] = {
    "ip": "ip",
    "domain": "domain",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "host": "host",
    "user": "user",
    "file": "file",
    "process": "process",
}

# Threat-level ordering so a node backed by several observables keeps the
# highest severity seen. ``None`` (not observable-backed) is lowest.
_THREAT_ORDER: Dict[str, int] = {
    "unknown": 0,
    "benign": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _normalize_tactic(name: Any) -> Optional[str]:
    """Normalize a MITRE tactic name/id to a canonical kill-chain slug."""
    if not name:
        return None
    s = str(name).strip()
    if not s:
        return None
    if s.upper() in _TA_ID_MAP:
        return _TA_ID_MAP[s.upper()]
    s = s.lower().replace("&", " and ")
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or None


def _map_tactic(alert: Dict[str, Any]) -> Tuple[str, int]:
    """Return ``(slug, rank)`` for an alert, falling back to unknown/last."""
    slug = _normalize_tactic(alert.get("mitre_tactic_name"))
    if slug and slug in KILL_CHAIN_RANK:
        return slug, KILL_CHAIN_RANK[slug]
    # No convenient technique->tactic lookup exists in the codebase; per the
    # roadmap we use mitre_tactic_name directly and treat the rest as unknown.
    return UNKNOWN_TACTIC, UNKNOWN_RANK


def _parse_ts(raw: Any) -> Optional[datetime]:
    """Best-effort ISO-8601 parse; returns None on anything unparseable."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw
    try:
        s = str(raw).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _ts_sort_key(raw: Any) -> Tuple[int, float]:
    """Sortable key for a timestamp; unparseable values sort last, stable."""
    dt = _parse_ts(raw)
    if dt is None:
        return (1, 0.0)
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (0, dt.timestamp())
    except Exception:
        return (1, 0.0)


def _better_threat(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return the higher-severity of two threat levels (None = lowest)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if _THREAT_ORDER.get(a, -1) >= _THREAT_ORDER.get(b, -1) else b


def _clean(v: Any) -> Optional[str]:
    """Coerce a field to a non-empty stripped string, else None."""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def build_attack_path_from_alerts(
    case_id: int,
    alerts: List[Dict[str, Any]],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Pure, deterministic graph assembly from a list of alert dicts.

    ``alerts`` are dicts in the ``ElasticsearchAlert.to_dict`` shape, each
    optionally carrying an ``observables`` contract list. No I/O — fully
    testable with crafted dicts.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()
    alerts = alerts or []

    nodes: Dict[str, Dict[str, Any]] = {}
    node_first_key: Dict[str, Tuple[int, float]] = {}
    node_rank: Dict[str, int] = {}
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    alert_tactic: Dict[str, Tuple[str, int]] = {}
    alert_ts_raw: Dict[str, Any] = {}
    alert_anchor: Dict[str, str] = {}
    # (node_type, value) -> best observed threat level
    obs_threat: Dict[Tuple[str, str], Optional[str]] = {}
    # (node_type, value) -> ordered list of distinct alert ids carrying it
    obs_alerts: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    # ── Pass 1: harvest observable threat levels (final before nodes exist) ──
    for a in alerts:
        try:
            for o in a.get("observables") or []:
                nt = _OBS_TYPE_TO_NODE.get(o.get("type"))
                val = _clean(o.get("value"))
                if not nt or not val:
                    continue
                key = (nt, val)
                obs_threat[key] = _better_threat(
                    obs_threat.get(key), o.get("threat_level")
                )
        except Exception:
            logger.debug("attack_path: pass1 skipped a malformed alert", exc_info=True)
            continue

    def _add_node(ntype: str, value: Optional[str], key: Tuple[int, float], rank: int) -> Optional[str]:
        if not value:
            return None
        nid = f"{_NODE_PREFIX[ntype]}:{value}"
        threat = obs_threat.get((ntype, value))
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "type": ntype,
                "value": value,
                "label": value,
                "threat_level": threat,
            }
            node_first_key[nid] = key
            node_rank[nid] = rank
        else:
            if key < node_first_key[nid]:
                node_first_key[nid] = key
            if rank < node_rank[nid]:
                node_rank[nid] = rank
            nodes[nid]["threat_level"] = _better_threat(
                nodes[nid]["threat_level"], threat
            )
        return nid

    def _add_edge(source: str, target: str, etype: str, label: str, alert_ids: List[str]) -> None:
        if not source or not target or source == target:
            return
        k = (source, target, etype)
        e = edges.get(k)
        if e is None:
            edges[k] = {
                "source": source,
                "target": target,
                "type": etype,
                "label": label,
                "alert_ids": [aid for aid in alert_ids if aid],
            }
        else:
            for aid in alert_ids:
                if aid and aid not in e["alert_ids"]:
                    e["alert_ids"].append(aid)

    # ── Pass 2: nodes + per-alert (lineage / flow / auth) edges ──────────────
    for a in alerts:
        try:
            aid = _clean(a.get("id")) or _clean(a.get("alert_id"))
            slug, rank = _map_tactic(a)
            ts_raw = a.get("timestamp")
            key = _ts_sort_key(ts_raw)
            if aid:
                alert_tactic[aid] = (slug, rank)
                alert_ts_raw[aid] = ts_raw

            host = _clean(a.get("host"))
            user = _clean(a.get("user"))
            proc = _clean(a.get("process_name"))
            pproc = _clean(a.get("parent_process_name"))
            sip = _clean(a.get("source_ip"))
            dip = _clean(a.get("destination_ip"))
            fhash = _clean(a.get("file_hash"))

            host_id = _add_node("host", host, key, rank)
            user_id = _add_node("user", user, key, rank)
            proc_id = _add_node("process", proc, key, rank)
            pproc_id = _add_node("process", pproc, key, rank)
            sip_id = _add_node("ip", sip, key, rank)
            dip_id = _add_node("ip", dip, key, rank)
            hash_id = _add_node("hash", fhash, key, rank)

            first_obs_id: Optional[str] = None
            seen_pairs: set = set()
            for o in a.get("observables") or []:
                nt = _OBS_TYPE_TO_NODE.get(o.get("type"))
                val = _clean(o.get("value"))
                if not nt or not val:
                    continue
                oid = _add_node(nt, val, key, rank)
                if oid and first_obs_id is None:
                    first_obs_id = oid
                pair = (nt, val)
                if aid and pair not in seen_pairs:
                    seen_pairs.add(pair)
                    if aid not in obs_alerts[pair]:
                        obs_alerts[pair].append(aid)

            # Per-alert edges.
            if pproc_id and proc_id:
                _add_edge(pproc_id, proc_id, "process_lineage", "spawned", [aid])
            if sip_id and dip_id:
                _add_edge(sip_id, dip_id, "network_flow", "network flow", [aid])
            if user_id and host_id:
                _add_edge(user_id, host_id, "auth_presence", "active on", [aid])

            # Remember a stable anchor node for cross-alert (shared-observable)
            # linkage: prefer host, then user/process/ip/hash, then observable.
            anchor = (
                host_id or user_id or proc_id or sip_id or dip_id
                or hash_id or pproc_id or first_obs_id
            )
            if aid and anchor:
                alert_anchor[aid] = anchor
        except Exception:
            logger.debug("attack_path: pass2 skipped a malformed alert", exc_info=True)
            continue

    # ── Pass 3: shared-observable cross-alert edges (the path linkage) ───────
    for (nt, val), aids in obs_alerts.items():
        try:
            distinct = list(dict.fromkeys(aids))
            if len(distinct) < 2:
                continue
            distinct.sort(key=lambda x: _ts_sort_key(alert_ts_raw.get(x)))
            obs_node_id = f"{_NODE_PREFIX[nt]}:{val}"
            label = f"shares {nt} {val}"
            for i in range(len(distinct) - 1):
                a1, a2 = distinct[i], distinct[i + 1]
                src = alert_anchor.get(a1)
                tgt = alert_anchor.get(a2)
                if not src or not tgt:
                    continue
                if src == tgt:
                    # Both alerts anchor to the same entity — link that anchor
                    # to the shared observable node so the linkage is still
                    # represented (unless the anchor IS the observable).
                    if src != obs_node_id:
                        _add_edge(src, obs_node_id, "shared_observable", label, [a1, a2])
                    continue
                _add_edge(src, tgt, "shared_observable", label, [a1, a2])
        except Exception:
            logger.debug("attack_path: pass3 skipped a shared observable", exc_info=True)
            continue

    # ── Phases (tactic lanes) ────────────────────────────────────────────────
    ranks_present: Dict[int, str] = {}
    for slug, rank in alert_tactic.values():
        ranks_present[rank] = slug

    phases: List[Dict[str, Any]] = []
    for rank in sorted(ranks_present):
        slug = ranks_present[rank]
        lane_node_ids = [nid for nid, r in node_rank.items() if r == rank]
        lane_node_ids.sort(key=lambda nid: (node_first_key[nid], nid))
        lane_alert_ids = [aid for aid, (s, r) in alert_tactic.items() if r == rank]
        lane_alert_ids.sort(key=lambda aid: (_ts_sort_key(alert_ts_raw.get(aid)), aid))
        phases.append({
            "tactic": slug,
            "rank": rank,
            "node_ids": lane_node_ids,
            "alert_ids": lane_alert_ids,
        })

    # ── Ordered output ───────────────────────────────────────────────────────
    node_list = sorted(
        nodes.values(),
        key=lambda n: (node_rank[n["id"]], node_first_key[n["id"]], n["id"]),
    )
    edge_list = sorted(
        edges.values(),
        key=lambda e: (e["type"], e["source"], e["target"]),
    )

    edge_counts = {
        "total": len(edge_list),
        "process_lineage": 0,
        "network_flow": 0,
        "auth_presence": 0,
        "shared_observable": 0,
    }
    for e in edge_list:
        edge_counts[e["type"]] = edge_counts.get(e["type"], 0) + 1

    tactics_reached = sorted(
        {slug for slug, _ in alert_tactic.values() if slug != UNKNOWN_TACTIC},
        key=lambda s: KILL_CHAIN_RANK.get(s, UNKNOWN_RANK),
    )
    reaches_impact = any(
        slug in _IMPACTFUL_TACTICS for slug, _ in alert_tactic.values()
    )

    return {
        "case_id": case_id,
        "generated_at": generated_at,
        "nodes": node_list,
        "edges": edge_list,
        "phases": phases,
        "stats": {
            "nodes": len(node_list),
            "edges": edge_counts,
            "alerts": len(alerts),
            "tactics_reached": tactics_reached,
            "reaches_impact": reaches_impact,
        },
    }


def _band_for_score(score: int) -> str:
    """Map a 0-100 reachability score to a severity band."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score_reachability(path_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic reachability score for a built attack-path graph.

    Fork D — *MITRE-tactic-reached heuristic*, no new config, no LLM, no
    network. Answers "does this chain reach something that matters, and how
    far" rather than merely counting alerts: the SOC analogue of Maze's
    exploitability-in-context. Score is a function of

    * the **furthest (highest-weight) tactic** the path reaches (dominant term),
    * the **breadth** of distinct tactics across the chain (small bonus), and
    * a boost when any path node carries a high/critical ``threat_level``.

    Returns::

        {"score": int 0-100, "band": "low|medium|high|critical",
         "rationale": str, "impact_tactics": [slug, ...],
         "top_threat_nodes": [{"id","type","value","threat_level"}, ...]}

    Pure and deterministic: identical input → identical output. Safe on an
    empty / malformed dict (returns a zero, ``low`` result).
    """
    path_dict = path_dict or {}
    stats = path_dict.get("stats") or {}
    nodes = path_dict.get("nodes") or []

    # Tactics present — prefer the pre-computed kill-chain-ordered list, fall
    # back to deriving from the phase lanes (excluding the unknown lane).
    tactics = list(stats.get("tactics_reached") or [])
    if not tactics:
        tactics = [
            p.get("tactic")
            for p in (path_dict.get("phases") or [])
            if p.get("tactic") and p.get("tactic") != UNKNOWN_TACTIC
        ]
    tactics = [t for t in tactics if t in _TACTIC_WEIGHT]

    # High/critical-scored nodes drive the threat boost + the surfaced list.
    threat_nodes = [
        n for n in nodes
        if isinstance(n, dict) and n.get("threat_level") in _HIGH_THREATS
    ]
    threat_nodes.sort(
        key=lambda n: (-_THREAT_ORDER.get(n.get("threat_level"), 0), str(n.get("id")))
    )
    has_critical = any(n.get("threat_level") == "critical" for n in threat_nodes)
    has_high = any(n.get("threat_level") == "high" for n in threat_nodes)

    if not tactics:
        base = 0
        furthest: Optional[str] = None
    else:
        furthest = max(tactics, key=lambda t: _TACTIC_WEIGHT[t])
        base = _TACTIC_WEIGHT[furthest]

    breadth = len(set(tactics))
    breadth_bonus = min(max(breadth - 1, 0), 6) * 2  # up to +12
    threat_boost = 12 if has_critical else (6 if has_high else 0)

    score = 0 if base == 0 else min(100, base + breadth_bonus + threat_boost)
    band = _band_for_score(score)

    impact_tactics = sorted(
        {t for t in tactics if t in _IMPACTFUL_TACTICS},
        key=lambda s: KILL_CHAIN_RANK.get(s, UNKNOWN_RANK),
    )
    top_threat_nodes = [
        {
            "id": n.get("id"),
            "type": n.get("type"),
            "value": n.get("value"),
            "threat_level": n.get("threat_level"),
        }
        for n in threat_nodes[:5]
    ]

    # Human rationale.
    if furthest is None:
        rationale = "No MITRE tactics mapped on this path; reachability undetermined."
    else:
        bits = [f"Furthest tactic reached: {furthest}"]
        if impact_tactics:
            bits[0] = f"Reaches {furthest} (impact-class chain)"
        bits.append(
            f"{breadth} distinct tactic{'s' if breadth != 1 else ''} across the chain"
        )
        if has_critical or has_high:
            level = "critical" if has_critical else "high"
            bits.append(f"{len(threat_nodes)} {level}-scored node(s)")
        rationale = "; ".join(bits) + "."

    return {
        "score": int(score),
        "band": band,
        "rationale": rationale,
        "impact_tactics": impact_tactics,
        "top_threat_nodes": top_threat_nodes,
    }


# ── Phase-3: path signature + DE recurrence link ─────────────────────────────
# The "attack shape" of a case = the ordered kill-chain tactics it reaches plus
# the set of MITRE technique ids present. Two cases with the *same* shape are the
# same recurring attack path — the hook that lets Bob Pathfinding surface "this
# path recurs across N cases → root-cause detection/tuning here" and cross-link
# to the DE module (Noise Campaigns / Detection Proposals). Advisory ONLY: this
# computes a hint; it never creates a proposal or mutates state.

# Technique ids look like Txxxx or Txxxx.yyy (sub-technique).
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

# Compute-on-read recurrence scan bounds / threshold (env-overridable).
_RECURRENCE_DEFAULT_DAYS = 30
_RECURRENCE_MAX_CASES = 50  # cap the on-read scan so a busy SOC can't stall Bob


def attack_path_enabled() -> bool:
    """Master feature flag for the Attack Path (Bob Pathfinding) surface.

    Env ``ION_ATTACK_PATH_ENABLED`` (default ON) gates the whole feature — the
    compute-on-read endpoint, Bob's case-analysis path-injection, and the
    Phase-3 recurrence link. The existing ``ION_ATTACK_PATH_RECURRENCE_ENABLED``
    / ``_THRESHOLD`` sub-flags continue to work UNDER this switch. Air-gap-safe:
    disabling degrades to the prior (pre-Attack-Path) behaviour, never an error.

    Resolution: env wins (operators flip without a config rewrite), then
    ``Config.attack_path_enabled``, then default ON.
    """
    val = os.environ.get("ION_ATTACK_PATH_ENABLED")
    if val is not None and val.strip() != "":
        return val.strip().lower() not in ("0", "false", "no", "off")
    try:
        from ion.core.config import get_config
        return bool(getattr(get_config(), "attack_path_enabled", True))
    except Exception:
        return True


def _recurrence_threshold() -> int:
    """Min *other* same-shape cases before we hint a detection proposal."""
    try:
        return max(1, int(os.environ.get("ION_ATTACK_PATH_RECURRENCE_THRESHOLD", "2")))
    except (TypeError, ValueError):
        return 2


def _naive_utc_now() -> datetime:
    """Naive UTC — matches ``AlertCase.created_at`` (TimestampMixin)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _collect_technique_ids(alerts: Optional[List[Dict[str, Any]]]) -> List[str]:
    """Sorted set of MITRE technique ids present across a case's alerts.

    Pure + deterministic. Robust to ``mitre_technique_id`` being a scalar, a
    list, or embedded in a longer string; anything not matching the Txxxx shape
    is ignored. Empty when no techniques are mapped (air-gap / sparse feeds).
    """
    ids: set = set()
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        for raw in (a.get("mitre_technique_id"), a.get("mitre_technique")):
            if raw is None:
                continue
            vals = raw if isinstance(raw, (list, tuple, set)) else [raw]
            for v in vals:
                for m in _TECHNIQUE_RE.findall(str(v)):
                    ids.add(m.upper())
    return sorted(ids)


def _signature_components(path_dict: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """(kill-chain-ordered tactics, sorted technique ids) for a path dict.

    Tactics come from ``stats.tactics_reached`` (falling back to the phase
    lanes); technique ids from ``stats.techniques`` when the caller has attached
    them (``_collect_technique_ids``), else empty → tactics-only signature.
    """
    path_dict = path_dict or {}
    stats = path_dict.get("stats") or {}

    tactics = list(stats.get("tactics_reached") or [])
    if not tactics:
        tactics = [
            p.get("tactic")
            for p in (path_dict.get("phases") or [])
            if p.get("tactic") and p.get("tactic") != UNKNOWN_TACTIC
        ]
    ordered_tactics = sorted(
        {t for t in tactics if t and t != UNKNOWN_TACTIC},
        key=lambda s: KILL_CHAIN_RANK.get(s, UNKNOWN_RANK),
    )
    techniques = sorted(
        {str(t).strip().upper() for t in (stats.get("techniques") or []) if str(t).strip()}
    )
    return ordered_tactics, techniques


def path_signature(path_dict: Dict[str, Any]) -> str:
    """Stable, deterministic signature of a case's attack shape.

    The signature is a function of the ordered list of kill-chain tactics the
    path reaches and the sorted set of MITRE technique ids present (when the
    caller has attached ``stats.techniques``; otherwise tactics-only). Identical
    shape → identical signature; independent of node/edge counts, timestamps, or
    the ``generated_at`` field. Safe on an empty / malformed dict.
    """
    tactics, techniques = _signature_components(path_dict)
    payload = "t:" + ">".join(tactics) + "|k:" + ",".join(techniques)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"ap1:{digest}"


def _is_trivial_signature(path_dict: Dict[str, Any]) -> bool:
    """A shape with no tactics AND no techniques can't meaningfully recur."""
    tactics, techniques = _signature_components(path_dict)
    return not tactics and not techniques


def _recent_case_ids(session, exclude_case_id: int, days: int, limit: int) -> List[int]:
    """Ids of the most recent cases in the window, excluding this one.

    Isolated so tests can monkeypatch the case enumeration without a DB (mirrors
    how the Phase-0 tests monkeypatch the alert fetch).
    """
    from ion.models.alert_triage import AlertCase

    cutoff = _naive_utc_now() - timedelta(days=days)
    rows = (
        session.query(AlertCase.id)
        .filter(AlertCase.created_at >= cutoff)
        .filter(AlertCase.id != exclude_case_id)
        .order_by(AlertCase.created_at.desc())
        .limit(limit)
        .all()
    )
    return [r[0] for r in rows]


async def _signature_for_case(session, case_id: int) -> Optional[str]:
    """Build a case's path (deterministic) and return its shape signature.

    Returns ``None`` when the case has no alerts / trivial shape (nothing to
    match on). Air-gap safe: ES-less fetch yields ``[]`` → ``None``.
    """
    alerts = await _fetch_case_alert_dicts(session, case_id)
    if not alerts:
        return None
    path = build_attack_path_from_alerts(case_id, alerts)
    path["stats"]["techniques"] = _collect_technique_ids(alerts)
    if _is_trivial_signature(path):
        return None
    return path_signature(path)


async def find_recurring_path(session, case_id: int, days: int = _RECURRENCE_DEFAULT_DAYS) -> Dict[str, Any]:
    """Count how many *other* recent cases share this case's attack shape.

    Compute-on-read, read-only, air-gap-safe. Signs this case's path, then scans
    the most recent cases in the window (bounded by ``_RECURRENCE_MAX_CASES``)
    and counts those with an identical signature. The ``suggests_detection_proposal``
    flag is an **advisory hint only** — the "this path recurs across N cases →
    root-cause detection/tuning" link into the DE module (Noise Campaigns /
    Detection Proposals). It NEVER creates a proposal or mutates any state.

    Returns::

        {"signature": str|None, "recurrence_count": int,
         "case_ids": [int, ...], "suggests_detection_proposal": bool}

    A trivial / empty shape (no tactics, no techniques — e.g. air-gapped with no
    ES) yields a null signature, zero recurrence, and no suggestion.
    """
    empty = {
        "signature": None,
        "recurrence_count": 0,
        "case_ids": [],
        "suggests_detection_proposal": False,
    }
    try:
        sig = await _signature_for_case(session, case_id)
    except Exception:
        logger.debug("attack_path: signature build failed for case %s", case_id, exc_info=True)
        return empty
    if not sig:
        return empty

    try:
        candidate_ids = _recent_case_ids(session, case_id, days, _RECURRENCE_MAX_CASES)
    except Exception:
        logger.debug("attack_path: recent-case enumeration failed", exc_info=True)
        return {**empty, "signature": sig}

    matches: List[int] = []
    for cid in candidate_ids:
        try:
            if await _signature_for_case(session, cid) == sig:
                matches.append(cid)
        except Exception:
            logger.debug("attack_path: signature build failed for case %s", cid, exc_info=True)
            continue

    count = len(matches)
    return {
        "signature": sig,
        "recurrence_count": count,
        "case_ids": matches,
        "suggests_detection_proposal": count >= _recurrence_threshold(),
    }


async def _fetch_case_alert_dicts(session, case_id: int) -> Optional[List[Dict[str, Any]]]:
    """Fetch a case's alerts as enriched contract dicts.

    Reuses ``ElasticsearchService.get_alerts_by_ids`` (the same fetch the case
    detail / close paths use) driven by ``AlertCase.source_alert_ids``, attaches
    on-render ``observables`` (``to_contract_observables``), and back-fills
    persisted enrichment (``hydrate_persisted_enrichment``). Air-gap safe: with
    ES unconfigured, returns ``[]`` (a valid empty case).

    Returns ``None`` when the case does not exist so callers can 404.
    """
    from ion.models.alert_triage import AlertCase

    case = session.query(AlertCase).filter_by(id=case_id).first()
    if case is None:
        return None

    alert_ids = list(case.source_alert_ids or [])
    if not alert_ids:
        return []

    dicts: List[Dict[str, Any]] = []
    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        es = ElasticsearchService()
        if not getattr(es, "is_configured", False):
            return []
        alerts = await es.get_alerts_by_ids(alert_ids)
    except Exception as exc:
        logger.debug("attack_path: ES alert fetch failed for case %s: %s", case_id, exc)
        return []

    from ion.services.observable_extractor import to_contract_observables

    for a in alerts or []:
        try:
            d = a.to_dict(include_raw=False)
            try:
                d["observables"] = to_contract_observables(getattr(a, "raw_data", None) or {})
            except Exception:
                d["observables"] = []
            dicts.append(d)
        except Exception:
            logger.debug("attack_path: skipped an unserializable alert", exc_info=True)
            continue

    try:
        from ion.services.observable_service import hydrate_persisted_enrichment
        hydrate_persisted_enrichment(session, dicts)
    except Exception:
        logger.debug("attack_path: enrichment hydration skipped", exc_info=True)

    return dicts


async def build_attack_path(session, case_id: int) -> Dict[str, Any]:
    """Compute-on-read attack-path graph for a case.

    Deterministic, read-only, air-gap-safe. Returns a valid (possibly empty)
    graph even when the case has no alerts. When the case does not exist a
    valid empty graph is still returned — callers that need a 404 should check
    case existence first (the endpoint does).
    """
    if not attack_path_enabled():
        # Master flag OFF — degrade to a valid but empty graph (no ES fetch,
        # no reachability, no recurrence scan). The endpoint returns empty,
        # Bob's path-injection sees an empty block and narrates from prose as
        # before. Air-gap-safe, no LLM, no writes.
        return build_attack_path_from_alerts(case_id, [])
    alerts = await _fetch_case_alert_dicts(session, case_id)
    path = build_attack_path_from_alerts(case_id, alerts or [])
    # Phase 2: fold in the deterministic reachability score so the Phase-1 UI
    # and Bob both see it. Additive under stats.reachability — the pure builder
    # keeps its stable Phase-0 schema; only the compute-on-read wrapper enriches.
    try:
        path["stats"]["reachability"] = score_reachability(path)
    except Exception:
        logger.debug("attack_path: reachability scoring skipped", exc_info=True)
    # Phase 3: fold a COMPACT recurrence hint into the payload so the UI/Bob can
    # surface "recurs across N cases" and offer the DE root-cause link. The full
    # case-id list stays out of the Bob payload (size/privacy) — callers wanting
    # it call find_recurring_path directly. Best-effort + air-gap safe: any
    # failure (or ES-less) leaves the graph exactly as before.
    if os.environ.get("ION_ATTACK_PATH_RECURRENCE_ENABLED", "1") not in ("0", "false", "False"):
        try:
            rec = await find_recurring_path(session, case_id, days=_RECURRENCE_DEFAULT_DAYS)
            path["stats"]["recurrence"] = {
                "signature": rec["signature"],
                "recurrence_count": rec["recurrence_count"],
                "suggests_detection_proposal": rec["suggests_detection_proposal"],
            }
        except Exception:
            logger.debug("attack_path: recurrence scan skipped", exc_info=True)
    return path
