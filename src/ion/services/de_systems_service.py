"""Each TIDE system as Detection Engineering sees it: its platforms, coverage,
open CVEs (KEV marked from ION's own catalogue), CIS hardening, Wazuh agents
and log source freshness.

Hosts, agents, findings and SCA results are TIDE 7's Wazuh assets. A tenant
without them (older TIDE, or no Wazuh link) reads as "needs TIDE 7", never as
a clean estate. Log freshness is each Wazuh agent's last keepalive, plus ION's
log source register for sources tagged with the system's name or id.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ion.services import attack_catalogue
from ion.services.attack_detection_service import technique_platforms
from ion.services.tide_service import TableAbsent, TideFailure, TideService

logger = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low")
#: An agent unseen for longer than this is disconnected even if TIDE's last
#: read still called it active.
AGENT_STALE_HOURS = 24
#: Weeks of CIS score history drawn as the trend line.
CIS_WEEKS = 10


@dataclass
class Agent:
    name: str
    status: str
    last_seen: Optional[datetime]
    system_id: Optional[str] = None
    siem_id: str = ""
    space: str = ""

    @property
    def connected(self) -> bool:
        return self.status == "active" and self.age_hours is not None and self.age_hours <= AGENT_STALE_HOURS

    @property
    def age_hours(self) -> Optional[float]:
        if self.last_seen is None:
            return None
        return max((_utcnow() - self.last_seen).total_seconds() / 3600, 0.0)


@dataclass
class Freshness:
    name: str
    age_hours: Optional[float]
    state: str           # ok | warn | bad | unknown
    source: str          # agent | register


@dataclass
class SystemProfile:
    id: str
    name: str
    platforms: Optional[list[str]]
    #: TIDE's own grade: covered baseline steps of the system's baselines.
    baseline_covered: Optional[int] = None
    baseline_total: Optional[int] = None
    #: Secondary: catalogue techniques and sub-techniques on the system's
    #: platforms with an enabled rule applied to it (the Coverage tab's universe).
    covered: Optional[int] = None
    applicable: Optional[int] = None
    vulns: Optional[dict[str, int]] = None
    kev: Optional[list[dict]] = None
    cves: Optional[list[dict]] = None
    cis_score: Optional[float] = None
    cis_trend: Optional[list[float]] = None
    cis_policies: Optional[list[str]] = None
    failing_checks: Optional[list[dict]] = None
    agents: Optional[list[Agent]] = None
    freshness: list[Freshness] = field(default_factory=list)
    covered_ids: Optional[set] = None

    @property
    def baseline_pct(self) -> Optional[int]:
        if self.baseline_covered is None or not self.baseline_total:
            return None
        return round(self.baseline_covered / self.baseline_total * 100)

    @property
    def coverage_pct(self) -> Optional[int]:
        if self.covered is None or not self.applicable:
            return None
        return round(self.covered / self.applicable * 100)

    @property
    def vuln_total(self) -> Optional[int]:
        return sum(self.vulns.values()) if self.vulns is not None else None


@dataclass
class SystemsReport:
    state: str  # unconfigured | failed | data
    failure: Optional[TideFailure] = None
    systems: list[SystemProfile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Disconnected agents of a Wazuh destination that no system claims.
    unassigned_agents: list[Agent] = field(default_factory=list)
    has_assets: bool = False

    def get(self, system_id: str) -> Optional[SystemProfile]:
        return next((s for s in self.systems if s.id == system_id), None)

    @property
    def disconnected(self) -> list[Agent]:
        agents = [a for s in self.systems for a in s.agents or [] if not a.connected]
        return sorted(agents + self.unassigned_agents, key=lambda a: -(a.age_hours or 1e9))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _when(value: object) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def freshness_state(age_hours: Optional[float], expected_minutes: int = 60) -> str:
    if age_hours is None:
        return "unknown"
    minutes = age_hours * 60
    if minutes <= expected_minutes:
        return "ok"
    if minutes <= expected_minutes * 3:
        return "warn"
    return "bad"


def _note(what: str, outcome: object, notes: list[str]) -> None:
    if isinstance(outcome, TableAbsent):
        notes.append(f"{what} needs TIDE 7 with Wazuh linked ({outcome.table} is not in this tenant).")
    elif isinstance(outcome, TideFailure):
        notes.append(f"{what} could not be read from TIDE: {outcome.message}")


def applicable_techniques(platforms: Optional[list[str]]) -> Optional[set[str]]:
    """Catalogue techniques whose analytics apply to any of these platforms."""
    if not platforms:
        return None
    wanted = set(platforms)
    by_tid = technique_platforms()
    return {t["technique_id"] for t in attack_catalogue.techniques() if by_tid.get(t["technique_id"], set()) & wanted}


def systems_report(svc: TideService, session: Optional[Session], *, with_coverage: bool = True,
                   register: Optional[list[dict]] = None, baselines: Optional[dict] = None) -> SystemsReport:
    """Every TIDE system with what TIDE 7 and ION know about it. Synchronous:
    run it in a worker thread from an async route. `baselines` is
    get_system_baseline_summaries' answer, usually from the sync snapshot;
    `with_coverage` adds the platform-scoped ATT&CK breadth."""
    report = SystemsReport(state="data")
    if not svc.enabled:
        report.state = "unconfigured"
        return report
    systems = svc.get_system_platforms()
    if isinstance(systems, TableAbsent):
        plain = svc._run("SELECT s.id, s.name FROM systems s ORDER BY s.name")
        systems = plain if isinstance(plain, TideFailure) else [dict(r, platforms=None) for r in plain.get("rows") or []]
        report.notes.append("Platforms need TIDE 7 (systems.platforms), so coverage cannot be scoped by platform.")
    if isinstance(systems, TideFailure):
        report.state, report.failure = "failed", systems
        return report
    for row in systems:
        platforms = row.get("platforms")
        report.systems.append(SystemProfile(
            id=str(row.get("id")), name=str(row.get("name") or row.get("id")),
            platforms=[str(p) for p in platforms] if isinstance(platforms, list) else None))
    by_id = {s.id: s for s in report.systems}

    for system in report.systems:
        baseline = (baselines or {}).get(system.id)
        if isinstance(baseline, dict):
            system.baseline_covered = int(baseline.get("covered_steps") or 0)
            system.baseline_total = int(baseline.get("total_steps") or 0)
    if with_coverage:
        for system in report.systems:
            try:
                covered = svc.get_mitre_coverage(system.id).get("covered") or []
            except Exception:
                logger.exception("Coverage for system %s could not be read", system.id)
                continue
            # A covered sub-technique covers its parent, as on the coverage map.
            ids = set(covered) | {tid.split(".")[0] for tid in covered}
            system.covered_ids = ids
            applicable = applicable_techniques(system.platforms)
            if applicable is None:
                system.covered, system.applicable = len(ids), len(attack_catalogue.techniques())
            else:
                system.covered, system.applicable = len(ids & applicable), len(applicable)

    hosts = svc.get_hosts()
    host_system = {str(h.get("id")): str(h.get("system_id")) for h in hosts} if isinstance(hosts, list) else {}
    host_name = {str(h.get("id")): str(h.get("name")) for h in hosts} if isinstance(hosts, list) else {}

    vulns = svc.get_system_vulnerabilities()
    if isinstance(vulns, list):
        report.has_assets = report.has_assets or bool(vulns)
        kev_ids = _kev_ids(session, [str(v.get("cve_id")) for v in vulns])
        for system in report.systems:
            system.vulns = dict.fromkeys(SEVERITIES, 0)
            system.kev, system.cves = [], []
        for v in vulns:
            system = by_id.get(str(v.get("system_id")))
            if system is None:
                continue
            sev = str(v.get("severity") or "").lower()
            if sev in system.vulns:
                system.vulns[sev] += 1
            entry = {"cve": v.get("cve_id"), "severity": sev, "description": v.get("description"),
                     "package": v.get("package"), "hosts": v.get("hosts"), "cvss": v.get("cvss"),
                     "kev": kev_ids is not None and v.get("cve_id") in kev_ids}
            system.cves.append(entry)
            if entry["kev"]:
                system.kev.append(entry)
        for system in report.systems:
            system.kev.sort(key=lambda e: SEVERITIES.index(e["severity"]) if e["severity"] in SEVERITIES else 9)
        if kev_ids is None:
            report.notes.append("ION's KEV catalogue could not be read, so no CVE is marked known-exploited.")
    else:
        _note("Open CVEs", vulns, report.notes)

    scores = svc.get_system_sca_scores()
    if isinstance(scores, list):
        report.has_assets = report.has_assets or bool(scores)
        grouped: dict[str, list[dict]] = {}
        for row in scores:
            grouped.setdefault(str(row.get("system_id")), []).append(row)
        for sid, rows in grouped.items():
            system = by_id.get(sid)
            if system is None:
                continue
            total_hosts = sum(int(r.get("hosts") or 0) for r in rows) or 1
            system.cis_score = round(sum(float(r.get("score") or 0) * int(r.get("hosts") or 0) for r in rows) / total_hosts)
            system.cis_policies = [str(r.get("name") or r.get("policy_id")) for r in rows]
        history = svc.get_system_sca_history(CIS_WEEKS * 7)
        if isinstance(history, list):
            trend: dict[str, list[float]] = {}
            for row in history:
                trend.setdefault(str(row.get("system_id")), []).append(float(row.get("score") or 0))
            for sid, series in trend.items():
                if sid in by_id and len(series) >= 2:
                    by_id[sid].cis_trend = series[-CIS_WEEKS:]
        checks = svc.get_system_failed_checks()
        if isinstance(checks, list):
            for system in report.systems:
                system.failing_checks = []
            for row in checks:
                system = by_id.get(str(row.get("system_id")))
                if system is not None:
                    system.failing_checks.append({
                        "check": row.get("cis") or row.get("check_id"), "title": row.get("title"),
                        "hosts": row.get("hosts"), "host_count": int(row.get("host_count") or 0)})
            for system in report.systems:
                system.failing_checks.sort(key=lambda c: -c["host_count"])
    else:
        _note("CIS hardening", scores, report.notes)

    _agents(svc, report, by_id, host_system, host_name)
    _register_freshness(report, register)
    return report


def _kev_ids(session: Optional[Session], cve_ids: list[str]) -> Optional[set[str]]:
    if session is None:
        return None
    try:
        from ion.services.kev_service import lookup_many

        return set(lookup_many(session, [c for c in cve_ids if c]).keys())
    except Exception:
        logger.exception("KEV catalogue lookup failed")
        return None


def _agents(svc: TideService, report: SystemsReport, by_id: dict, host_system: dict, host_name: dict) -> None:
    host_agents = svc.get_host_agents()
    group = svc.get_wazuh_agents()
    if not isinstance(host_agents, list) and not isinstance(group, list):
        _note("Wazuh agents", group, report.notes)
        return
    report.has_assets = True
    for system in report.systems:
        system.agents = []
    claimed: set[tuple] = set()
    for row in host_agents if isinstance(host_agents, list) else []:
        sid = host_system.get(str(row.get("host_id")))
        agent = Agent(name=host_name.get(str(row.get("host_id")), str(row.get("agent_id"))),
                      status=str(row.get("status") or ""), last_seen=_when(row.get("last_seen")),
                      system_id=sid, siem_id=str(row.get("siem_id") or ""), space=str(row.get("space") or ""))
        claimed.add((agent.siem_id, str(row.get("agent_id"))))
        if sid in by_id:
            by_id[sid].agents.append(agent)
    sources = svc.get_system_wazuh_sources()
    patterns = [(str(r.get("system_id")), str(r.get("siem_id")), str(r.get("space")), r.get("name_pattern") or "*")
                for r in sources] if isinstance(sources, list) else []
    for row in group if isinstance(group, list) else []:
        key = (str(row.get("siem_id") or ""), str(row.get("agent_id")))
        if key in claimed:
            continue
        claimed.add(key)
        agent = Agent(name=str(row.get("name") or row.get("agent_id")), status=str(row.get("status") or ""),
                      last_seen=_when(row.get("last_seen")), siem_id=key[0], space=str(row.get("space") or ""))
        owner = next((sid for sid, siem, space, pattern in patterns
                      if siem == agent.siem_id and space in (agent.space, "*") and fnmatch.fnmatch(agent.name, pattern)), None)
        if owner in by_id:
            agent.system_id = owner
            by_id[owner].agents.append(agent)
        elif not agent.connected:
            report.unassigned_agents.append(agent)
    for system in report.systems:
        for agent in system.agents or []:
            system.freshness.append(Freshness(f"{agent.name} · Wazuh agent", agent.age_hours,
                                              "ok" if agent.connected else "bad",
                                              "agent"))


def _register_freshness(report: SystemsReport, register: Optional[list[dict]]) -> None:
    """ION register sources tagged with a system's name or id join its card."""
    for source in register or []:
        tags = {str(t).strip().lower() for t in source.get("tags") or []}
        for system in report.systems:
            if system.name.lower() in tags or system.id.lower() in tags:
                last = _when(source.get("last_event_at"))
                age = (_utcnow() - last).total_seconds() / 3600 if last else None
                system.freshness.append(Freshness(str(source.get("name")), age,
                                                  freshness_state(age, int(source.get("expected_interval_minutes") or 60)),
                                                  "register"))
