"""Network threat-correlation report.

Stitches the netmon → case → threat-intel chain into one view:

    AlertCase (network-linked) → ObservableLink → Observable
        → ObservableEnrichment (OpenCTI: malicious?, score, threat actors, labels)

and rolls it up cross-case (which threat actors / IOCs span multiple cases).
"Network-linked" = the case carries at least one IP/domain/url observable, or
was raised by the Arkime auto-case / realtime-monitor pipeline.

Two render paths mirror the executive report: ``generate_*_report`` (dict) and
``generate_*_html`` (standalone, CSP-safe HTML).
"""

from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session

_NET_TYPES = {"ipv4", "ipv6", "domain", "url", "hostname"}


def _latest_enrichment(obs) -> Any:
    enr = getattr(obs, "enrichments", None) or []
    return enr[0] if enr else None


def generate_network_correlation_report(session: Session, days: int = 7) -> Dict[str, Any]:
    """Build the correlation report dict for cases in the last ``days``."""
    from ion.models.alert_triage import AlertCase, AlertTriage
    from ion.models.observable import Observable, ObservableLink, ObservableLinkType

    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    cases = (
        session.query(AlertCase)
        .filter(AlertCase.created_at >= cutoff)
        .order_by(AlertCase.created_at.desc())
        .all()
    )

    # Map case_id → [Observable] via ObservableLink (CASE links).
    case_ids = [c.id for c in cases]
    links: List[Any] = []
    if case_ids:
        links = (
            session.query(ObservableLink)
            .filter(
                ObservableLink.link_type == ObservableLinkType.CASE,
                ObservableLink.entity_id.in_(case_ids),
            )
            .all()
        )
    obs_ids = list({l.observable_id for l in links if l.observable_id})
    obs_by_id: Dict[int, Any] = {}
    if obs_ids:
        for o in session.query(Observable).filter(Observable.id.in_(obs_ids)).all():
            obs_by_id[o.id] = o
    case_obs: Dict[int, List[Any]] = {}
    for link in links:
        o = obs_by_id.get(link.observable_id)
        if o is not None:
            case_obs.setdefault(link.entity_id, []).append(o)

    # Which cases came from the netmon pipelines (auto-case / rtmon)?
    netmon_case_ids = set()
    if case_ids:
        for (cid,) in (
            session.query(AlertTriage.case_id)
            .filter(AlertTriage.case_id.in_(case_ids))
            .filter(AlertTriage.source_system.like("arkime%"))
            .all()
        ):
            netmon_case_ids.add(cid)

    report_cases: List[Dict[str, Any]] = []
    actor_rollup: Dict[str, Dict[str, Any]] = {}
    ioc_rollup: Dict[str, Dict[str, Any]] = {}
    malicious_count = 0

    for c in cases:
        obs_list = case_obs.get(c.id, [])
        net_obs = [o for o in obs_list if str(getattr(o, "type", "")).lower() in _NET_TYPES]
        is_netmon = c.id in netmon_case_ids
        if not net_obs and not is_netmon:
            continue  # not a network-relevant case

        obs_entries: List[Dict[str, Any]] = []
        for o in net_obs:
            enr = _latest_enrichment(o)
            actors = []
            score = None
            malicious = False
            labels: List[str] = []
            if enr is not None:
                malicious = bool(getattr(enr, "is_malicious", False))
                score = getattr(enr, "score", None)
                actors = [a.get("name") for a in (getattr(enr, "threat_actors", None) or []) if a.get("name")]
                labels = [
                    (lab.get("value") if isinstance(lab, dict) else str(lab))
                    for lab in (getattr(enr, "labels", None) or [])
                ]
            if malicious:
                malicious_count += 1
            val = getattr(o, "value", "")
            obs_entries.append({
                "type": str(getattr(o, "type", "")),
                "value": val,
                "threat_level": str(getattr(o, "threat_level", "") or "unknown"),
                "malicious": malicious,
                "score": score,
                "threat_actors": actors,
                "labels": labels,
            })
            # cross-case rollups
            ie = ioc_rollup.setdefault(val, {"value": val, "type": str(getattr(o, "type", "")),
                                             "malicious": malicious, "cases": set(), "actors": set()})
            ie["cases"].add(c.case_number)
            ie["malicious"] = ie["malicious"] or malicious
            for a in actors:
                ie["actors"].add(a)
                ae = actor_rollup.setdefault(a, {"name": a, "cases": set(), "iocs": set()})
                ae["cases"].add(c.case_number)
                ae["iocs"].add(val)

        report_cases.append({
            "case_number": c.case_number,
            "title": c.title,
            "severity": str(getattr(c, "severity", "") or ""),
            "status": str(getattr(c, "status", "") or ""),
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "from_netmon": is_netmon,
            "observables": obs_entries,
        })

    actors = sorted(
        [{"name": a["name"], "case_count": len(a["cases"]), "ioc_count": len(a["iocs"]),
          "cases": sorted(a["cases"])} for a in actor_rollup.values()],
        key=lambda x: x["case_count"], reverse=True,
    )
    iocs = sorted(
        [{"value": i["value"], "type": i["type"], "malicious": i["malicious"],
          "case_count": len(i["cases"]), "cases": sorted(i["cases"]), "actors": sorted(i["actors"])}
         for i in ioc_rollup.values()],
        key=lambda x: (x["malicious"], x["case_count"]), reverse=True,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days": days,
        "summary": {
            "network_cases": len(report_cases),
            "iocs": len(iocs),
            "malicious_iocs": malicious_count,
            "threat_actors": len(actors),
            "from_netmon_pipeline": sum(1 for c in report_cases if c["from_netmon"]),
        },
        "cases": report_cases,
        "threat_actors": actors,
        "iocs": iocs,
    }


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def generate_network_correlation_html(report: Dict[str, Any]) -> str:
    """Standalone, CSP-safe HTML (inline styles only; no scripts, no remote)."""
    s = report.get("summary", {})
    parts: List[str] = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Network Threat Correlation Report</title>",
        "<style>",
        "body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1220;color:#e2e8f0;margin:0;padding:32px;}",
        "h1{font-size:24px;margin:0 0 4px;color:#fff;} h2{font-size:16px;margin:28px 0 10px;color:#6de4ff;border-bottom:1px solid #1e293b;padding-bottom:6px;}",
        ".sub{color:#94a3b8;font-size:13px;margin-bottom:20px;}",
        ".cards{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0 8px;}",
        ".card{background:#111a2e;border:1px solid #1e293b;border-radius:8px;padding:14px 18px;min-width:120px;}",
        ".card .v{font-size:26px;font-weight:600;color:#fff;} .card .l{font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;}",
        "table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px;} th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1e293b;vertical-align:top;}",
        "th{color:#94a3b8;font-weight:500;font-size:11px;text-transform:uppercase;}",
        ".mal{color:#f87171;font-weight:600;} .tag{display:inline-block;background:#1e293b;border-radius:4px;padding:1px 7px;margin:1px;font-size:11px;color:#cbd5e1;}",
        ".sev-critical{color:#f87171;} .sev-high{color:#fb923c;} .sev-medium{color:#fbbf24;} .sev-low{color:#94a3b8;}",
        ".muted{color:#64748b;}",
        "</style></head><body>",
        "<h1>Network Threat Correlation Report</h1>",
        f"<div class='sub'>Generated {_esc(report.get('generated_at'))} · last {_esc(report.get('days'))} day(s) · "
        "auto-cases &rarr; OpenCTI &rarr; netmon</div>",
        "<div class='cards'>",
        f"<div class='card'><div class='v'>{_esc(s.get('network_cases', 0))}</div><div class='l'>Network cases</div></div>",
        f"<div class='card'><div class='v'>{_esc(s.get('iocs', 0))}</div><div class='l'>IOCs</div></div>",
        f"<div class='card'><div class='v mal'>{_esc(s.get('malicious_iocs', 0))}</div><div class='l'>Malicious IOCs</div></div>",
        f"<div class='card'><div class='v'>{_esc(s.get('threat_actors', 0))}</div><div class='l'>Threat actors</div></div>",
        f"<div class='card'><div class='v'>{_esc(s.get('from_netmon_pipeline', 0))}</div><div class='l'>From netmon</div></div>",
        "</div>",
    ]

    # Threat-actor correlation (cross-case)
    parts.append("<h2>Threat actors across cases</h2>")
    actors = report.get("threat_actors", [])
    if actors:
        parts.append("<table><tr><th>Actor</th><th>Cases</th><th>IOCs</th><th>Case numbers</th></tr>")
        for a in actors:
            parts.append(
                f"<tr><td>{_esc(a['name'])}</td><td>{_esc(a['case_count'])}</td>"
                f"<td>{_esc(a['ioc_count'])}</td><td class='muted'>{_esc(', '.join(a['cases']))}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<div class='muted'>No threat-actor attribution found for network IOCs in this window.</div>")

    # IOC correlation
    parts.append("<h2>IOCs (network) and their case spread</h2>")
    iocs = report.get("iocs", [])
    if iocs:
        parts.append("<table><tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Cases</th><th>Actors</th></tr>")
        for i in iocs[:200]:
            verdict = "<span class='mal'>malicious</span>" if i["malicious"] else "<span class='muted'>—</span>"
            parts.append(
                f"<tr><td>{_esc(i['value'])}</td><td>{_esc(i['type'])}</td><td>{verdict}</td>"
                f"<td>{_esc(i['case_count'])} ({_esc(', '.join(i['cases']))})</td>"
                f"<td>{''.join(f'<span class=tag>{_esc(x)}</span>' for x in i['actors']) or '<span class=muted>—</span>'}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<div class='muted'>No network IOCs in this window.</div>")

    # Per-case detail
    parts.append("<h2>Network-linked cases</h2>")
    cases = report.get("cases", [])
    if cases:
        for c in cases:
            sev = _esc(c["severity"]).lower()
            badge = " · <span class='tag'>from netmon</span>" if c["from_netmon"] else ""
            parts.append(
                f"<div style='margin:14px 0;'><strong class='sev-{sev}'>{_esc(c['case_number'])}</strong> "
                f"— {_esc(c['title'])} <span class='muted'>({_esc(c['severity'])}, {_esc(c['status'])})</span>{badge}"
            )
            if c["observables"]:
                parts.append("<table><tr><th>Observable</th><th>Type</th><th>Threat</th><th>OpenCTI</th><th>Actors</th></tr>")
                for o in c["observables"]:
                    octi = []
                    if o["malicious"]:
                        octi.append("<span class='mal'>malicious</span>")
                    if o["score"] is not None:
                        octi.append(f"score {_esc(o['score'])}")
                    octi.extend(f"<span class=tag>{_esc(lab)}</span>" for lab in o["labels"][:6])
                    parts.append(
                        f"<tr><td>{_esc(o['value'])}</td><td>{_esc(o['type'])}</td>"
                        f"<td>{_esc(o['threat_level'])}</td><td>{' '.join(octi) or '<span class=muted>—</span>'}</td>"
                        f"<td>{', '.join(_esc(x) for x in o['threat_actors']) or '<span class=muted>—</span>'}</td></tr>"
                    )
                parts.append("</table>")
            parts.append("</div>")
    else:
        parts.append("<div class='muted'>No network-linked cases in this window.</div>")

    parts.append("</body></html>")
    return "".join(parts)
