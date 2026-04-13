"""Knowledge Graph service.

Builds a single graph linking the entities ION already tracks:

- Cases   ↔  alerts
- Cases   ↔  observables
- Alerts  ↔  observables  (via shared values)
- Cases / alerts ↔ MITRE techniques
- Observables ↔ MITRE techniques (via case/alert linkage)

The graph is computed on demand from the SQL database — no new tables.
Returns a ``{nodes: [...], edges: [...]}`` shape that vis-network can render
directly.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.observable import Observable, ObservableLink, ObservableLinkType

logger = logging.getLogger(__name__)


# Vis-network compatible colors per node type
NODE_COLORS = {
    "case":       {"background": "#58a6ff", "border": "#1f6feb"},
    "alert":      {"background": "#d29922", "border": "#9e6a03"},
    "observable": {"background": "#3fb950", "border": "#1a7f37"},
    "actor":      {"background": "#f85149", "border": "#a40e26"},
    "technique":  {"background": "#bc8cff", "border": "#6e40c9"},
    "host":       {"background": "#79c0ff", "border": "#1f6feb"},
    "user":       {"background": "#ffa657", "border": "#bc4c00"},
}

NODE_SHAPES = {
    "case":       "box",
    "alert":      "ellipse",
    "observable": "dot",
    "actor":      "diamond",
    "technique":  "triangle",
    "host":       "square",
    "user":       "hexagon",
}


def _node(node_id: str, label: str, ntype: str, **extra) -> dict:
    return {
        "id": node_id,
        "label": label[:60],
        "type": ntype,
        "color": NODE_COLORS.get(ntype, {"background": "#8b949e", "border": "#484f58"}),
        "shape": NODE_SHAPES.get(ntype, "ellipse"),
        **extra,
    }


def _edge(src: str, dst: str, label: str = "", **extra) -> dict:
    return {"from": src, "to": dst, "label": label, **extra}


def build_graph(
    session: Session,
    *,
    case_limit: int = 50,
    include_closed: bool = False,
    seed_value: Optional[str] = None,
) -> dict:
    """Compose the knowledge graph.

    Args:
        session: SQLAlchemy session.
        case_limit: number of most-recent cases to include.
        include_closed: include closed cases (default: only open/acknowledged).
        seed_value: if provided, narrow the graph to nodes connected to an
            observable with this value (case-insensitive substring match).
    """
    nodes: dict[str, dict] = {}
    edges: List[dict] = []

    # 1. Cases
    case_stmt = select(AlertCase).order_by(AlertCase.created_at.desc())
    if not include_closed:
        case_stmt = case_stmt.where(AlertCase.status != AlertCaseStatus.CLOSED.value)
    case_stmt = case_stmt.limit(case_limit)
    cases = session.execute(case_stmt).scalars().all()

    for c in cases:
        nid = f"case:{c.id}"
        label = c.case_number or f"Case #{c.id}"
        if c.title:
            label += f" — {c.title[:50]}"
        nodes[nid] = _node(
            nid,
            label,
            "case",
            severity=c.severity,
            status=c.status,
            url=f"/cases?id={c.id}",
        )

        # Linked source alerts
        for alert_id in (c.source_alert_ids or []):
            an = f"alert:{alert_id}"
            if an not in nodes:
                nodes[an] = _node(an, str(alert_id)[:30], "alert")
            edges.append(_edge(nid, an, "from"))

        # Affected hosts as nodes
        for host in (c.affected_hosts or []):
            if not host:
                continue
            hn = f"host:{host}"
            if hn not in nodes:
                nodes[hn] = _node(hn, str(host), "host")
            edges.append(_edge(nid, hn, "host"))

        # Affected users as nodes
        for user in (c.affected_users or []):
            if not user:
                continue
            un = f"user:{user}"
            if un not in nodes:
                nodes[un] = _node(un, str(user), "user")
            edges.append(_edge(nid, un, "user"))

        # Triggered MITRE techniques
        for tid in (c.triggered_rules or []):
            if isinstance(tid, dict):
                tid = tid.get("technique") or tid.get("id")
            if not tid or not isinstance(tid, str):
                continue
            tn = f"technique:{tid}"
            if tn not in nodes:
                nodes[tn] = _node(tn, tid, "technique")
            edges.append(_edge(nid, tn, "ttp"))

    # 2. Observables linked to those cases (via the link table)
    # ObservableLink uses (link_type, entity_id) — case_id/alert_id are
    # @property accessors, so we have to query by entity_id directly.
    case_ids = [c.id for c in cases]
    if case_ids:
        link_rows = session.execute(
            select(ObservableLink).where(
                ObservableLink.link_type == ObservableLinkType.CASE.value,
                ObservableLink.entity_id.in_(case_ids),
            )
        ).scalars().all()
        # Pull the actual observable rows in one go
        obs_ids = list({l.observable_id for l in link_rows if l.observable_id})
        if obs_ids:
            obs_rows = session.execute(
                select(Observable).where(Observable.id.in_(obs_ids))
            ).scalars().all()
            obs_by_id = {o.id: o for o in obs_rows}
            for link in link_rows:
                obs = obs_by_id.get(link.observable_id)
                if not obs:
                    continue
                on = f"observable:{obs.id}"
                if on not in nodes:
                    nodes[on] = _node(
                        on,
                        f"{obs.value[:40]}",
                        "observable",
                        obs_type=obs.observable_type,
                        threat_level=obs.threat_level,
                        url=f"/observables?id={obs.id}",
                    )
                edges.append(_edge(f"case:{link.entity_id}", on, "ioc"))

    # 3. If a seed value was provided, restrict the graph to nodes reachable
    #    from any observable matching that value.
    if seed_value:
        seed_lc = seed_value.strip().lower()
        seed_obs_ids = set()
        for nid, n in nodes.items():
            if n["type"] == "observable" and seed_lc in n["label"].lower():
                seed_obs_ids.add(nid)
        if seed_obs_ids:
            # Walk edges to find connected component(s) reachable from seeds
            adj = defaultdict(set)
            for e in edges:
                adj[e["from"]].add(e["to"])
                adj[e["to"]].add(e["from"])
            keep = set()
            stack = list(seed_obs_ids)
            while stack:
                cur = stack.pop()
                if cur in keep:
                    continue
                keep.add(cur)
                for nb in adj[cur]:
                    if nb not in keep:
                        stack.append(nb)
            nodes = {nid: n for nid, n in nodes.items() if nid in keep}
            edges = [e for e in edges if e["from"] in keep and e["to"] in keep]

    # Stats
    counts = defaultdict(int)
    for n in nodes.values():
        counts[n["type"]] += 1

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "by_type": dict(counts),
        },
    }
