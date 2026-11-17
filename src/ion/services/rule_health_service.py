"""What is wrong with each detection rule, from one definition per signal.

Every Detection Engineering surface that flags a rule reads it from here:

* False-positive rate and "mostly false positive" are ION's own case closures
  (``rule_outcome_service`` and its NoisyPolicy). An alert's workflow status
  in Kibana is not a verdict, so it is never read as one.
* Rule Monitoring problems (silent, too many alerts, spikes, indexes with no
  recent events, Elastic validator failures, disconnected Wazuh agents and
  the rest of TIDE's vocabulary) are TIDE 7's ``rule_issues``.
* Only when the tenant has no ``rule_issues`` table (TIDE before 7, or Rule
  Monitoring never run) does ION judge volume itself, from alert counts per
  day, with the thresholds below. Those counts come from TIDE's
  ``rule_alert_counts`` when it keeps them, else from ION's own Kibana alerts.
* Bob agreeing with the analyst is a separate measure and is not here.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any, Literal, Optional

from sqlalchemy.orm import Session

from ion.services.rule_outcome_service import (
    DEFAULT_WINDOW_DAYS,
    NoisyPolicy,
    RuleKey,
    RuleOutcome,
    Window,
    rule_outcomes,
)
from ion.services.tide_service import TableAbsent, TideFailure, TideService, get_tide_service

logger = logging.getLogger(__name__)

# Thresholds for what ION judges itself, used only without TIDE Rule Monitoring.
#: Days of alert counts the Rules table draws and "too many" is judged over.
ALERT_WINDOW_DAYS = 14
#: More alerts than this in ALERT_WINDOW_DAYS is too many.
TOO_MANY_ALERTS = 200
#: The last SPIKE_DAYS (48h) against the daily mean of the rest of the window.
SPIKE_DAYS = 2
SPIKE_RATIO = 4.0
#: An enabled rule with no alert in this many days is silent.
SILENT_DAYS = 90
#: ION case closures are read over this window.
CLOSURE_DAYS = DEFAULT_WINDOW_DAYS

Level = Literal["error", "warning", "info"]
LEVELS: tuple[Level, ...] = ("error", "warning", "info")

#: TIDE 7.0.0's rule_issues.KNOWN: each issue's default severity and title.
TIDE_ISSUES: dict[str, tuple[Level, str]] = {
    "stale_data": ("error", "Rule data not synced recently"),
    "no_index": ("error", "No index matches the index pattern"),
    "no_recent_data": ("error", "No recent events in the index pattern"),
    "override_missing": ("warning", "Indexes missing the timestamp override field"),
    "field_missing": ("warning", "Field not in the index mappings"),
    "field_conflict": ("warning", "Field mapped with conflicting types"),
    "field_empty": ("warning", "Field mapped but has no data"),
    "unknown_field": ("error", "Query uses a field Elasticsearch can't find"),
    "query_syntax": ("error", "Query won't parse"),
    "query_invalid": ("error", "Query refused by Elasticsearch"),
    "elastic_query": ("error", "Query fails Elastic's validation"),
    "elastic_field": ("warning", "Field in no Elastic schema"),
    "privileges": ("warning", "Missing index privileges"),
    "max_alerts": ("warning", "Reached the maximum alerts per run"),
    "gap": ("warning", "Runs were missed"),
    "timeout": ("warning", "Search timed out"),
    "slow": ("warning", "Searches getting slow"),
    "overloaded": ("warning", "Elasticsearch refused the search (overloaded)"),
    "ml_job": ("error", "Machine learning job not running"),
    "schedule_gap": ("error", "Blind windows between runs"),
    "short_lookback": ("warning", "Little or no additional look-back"),
    "ingest_late": ("warning", "Events arrive later than the rule looks back"),
    "noisy": ("warning", "Too many alerts"),
    "silent": ("warning", "No alerts for a long time"),
    "alert_spike": ("warning", "Alerts spiked"),
    "wazuh_agents_disconnected": ("warning", "Wazuh agents disconnected"),
    "wazuh_read_incomplete": ("warning", "Wazuh read incomplete"),
    "alerts_unreadable": ("warning", "Alerts couldn't be read"),
    "never_run": ("warning", "Enabled but never run"),
    "siem_offline": ("warning", "SIEM didn't answer at the last sync"),
    "sync_incomplete": ("warning", "Syncs couldn't read every rule"),
    "sync_step_failed": ("warning", "A step of the last sync failed"),
    "shared_rule_id": ("warning", "Rules sharing a rule id in Kibana"),
    "custom_elastic_id": ("warning", "Custom rule using one of Elastic's rule ids"),
    "elastic_link_differs": ("warning", "Linked to an Elastic rule it doesn't match"),
    "exceptions_many": ("warning", "Many exceptions"),
    "exception_broad": ("warning", "Exception matches almost anything"),
    "exception_recent": ("info", "Exception added recently"),
    "duplicate_query": ("warning", "Same detection deployed twice"),
    "upstream_update_pending": ("warning", "Upstream update not reviewed"),
    "prebuilt_updates": ("info", "Elastic's prebuilt rules have updates"),
    "upstream_deprecated": ("warning", "Retired upstream"),
    "validation_stale": ("info", "Validation expired or out of date"),
    "change_pending": ("warning", "Change not finished in TIDE"),
}

#: The problems ION raises itself when TIDE has no Rule Monitoring.
ION_PROBLEMS: dict[str, tuple[Level, str, str]] = {
    "too_many": ("warning", "Too many alerts", f"Over {TOO_MANY_ALERTS} alerts in {ALERT_WINDOW_DAYS} days"),
    "spike": ("warning", "Alert spike",
              f"Last {SPIKE_DAYS * 24}h is more than {SPIKE_RATIO:g}x the {ALERT_WINDOW_DAYS}-day baseline"),
    "silent": ("info", "No alerts for a long time", f"Enabled, but has not fired in {SILENT_DAYS} days"),
}

AlertSource = Literal["tide", "kibana"]


@dataclass(frozen=True)
class Problem:
    kind: str
    level: Level
    title: str
    detail: str
    cause: str = ""
    source: Literal["tide", "ion"] = "tide"


@dataclass(frozen=True)
class Destination:
    siem_id: str
    space: str

    @property
    def label(self) -> str:
        return f"{self.siem_id} · {self.space}" if self.siem_id else self.space


@dataclass
class RuleHealth:
    rule_id: str
    name: str
    kind: str
    severity: str
    enabled: bool
    quality: Optional[float]
    mitre_ids: list
    dest: Destination
    rule_uuid: Optional[str] = None
    #: Alerts per day, oldest first, ALERT_WINDOW_DAYS long; None when unmeasured.
    days: Optional[list[int]] = None
    alerts_silent_window: Optional[int] = None
    outcome: Optional[RuleOutcome] = None
    noisy: bool = False
    problems: list[Problem] = field(default_factory=list)
    gitlab: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.rule_id}|{self.dest.siem_id}|{self.dest.space}"

    @property
    def alerts(self) -> Optional[int]:
        return sum(self.days) if self.days is not None else None

    def count(self, level: Level) -> int:
        return sum(p.level == level for p in self.problems)

    @property
    def worst(self) -> int:
        """Sort weight: errors, then warnings, then info."""
        return min((LEVELS.index(p.level) for p in self.problems), default=len(LEVELS))


@dataclass(frozen=True)
class DestinationProblem:
    dest: Destination
    problem: Problem
    gitlab: tuple = ()


@dataclass
class RuleHealthReport:
    state: Literal["unconfigured", "failed", "data"]
    failure: Optional[TideFailure] = None
    rules: list[RuleHealth] = field(default_factory=list)
    destination_problems: list[DestinationProblem] = field(default_factory=list)
    #: Where the problems came from: TIDE Rule Monitoring, or ION's thresholds.
    monitoring: Literal["tide", "ion"] = "ion"
    alerts_from: Optional[AlertSource] = None
    #: What could not be read, or needs TIDE 7, in words for the page.
    notes: list[str] = field(default_factory=list)
    closures: Optional[dict[str, int]] = None
    closure_failed: bool = False
    policy: NoisyPolicy = field(default_factory=NoisyPolicy.from_env)

    def by_key(self) -> dict[str, RuleHealth]:
        return {r.key: r for r in self.rules}

    def problem_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(LEVELS, 0)
        for r in self.rules:
            for p in r.problems:
                counts[p.level] += 1
        for d in self.destination_problems:
            counts[d.problem.level] += 1
        return counts


def _level(value: object, default: Level) -> Level:
    return value if value in LEVELS else default  # type: ignore[return-value]


def tide_problem(row: dict) -> Problem:
    issue = str(row.get("issue") or "")
    default, title = TIDE_ISSUES.get(issue, ("warning", issue.replace("_", " ").capitalize() or "Rule Monitoring finding"))
    return Problem(kind=issue, level=_level(row.get("severity"), default), title=title,
                   detail=str(row.get("detail") or ""), cause=str(row.get("cause") or ""), source="tide")


def ion_problems(days: Optional[list[int]], silent_total: Optional[int], enabled: bool) -> list[Problem]:
    """ION's own volume verdicts on one rule's alert counts."""
    found: list[Problem] = []

    def make(kind: str, detail: str) -> Problem:
        level, title, _ = ION_PROBLEMS[kind]
        return Problem(kind=kind, level=level, title=title, detail=detail, source="ion")

    if days is not None:
        total = sum(days)
        if total > TOO_MANY_ALERTS:
            found.append(make("too_many", f"{total:,} alerts in {ALERT_WINDOW_DAYS} days (threshold {TOO_MANY_ALERTS})."))
        recent = days[-SPIKE_DAYS:]
        base = days[:-SPIKE_DAYS]
        if base:
            base_mean = sum(base) / len(base)
            recent_mean = sum(recent) / len(recent)
            if recent_mean > SPIKE_RATIO * max(base_mean, 1.0):
                found.append(make("spike", f"{SPIKE_DAYS * 24}h: {sum(recent):,} alerts vs a daily mean of "
                                           f"{base_mean:.0f} over the {len(base)} days before."))
    if enabled and silent_total == 0:
        found.append(make("silent", f"No alert in {SILENT_DAYS} days."))
    return found


def _json_list(raw: object) -> list:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            return []
        return parsed if isinstance(parsed, list) else []
    return []


def _series(by_day: dict[str, int], today: date, days: int) -> list[int]:
    return [by_day.get((today - timedelta(days=offset)).isoformat(), 0) for offset in range(days - 1, -1, -1)]


def _number(value: object) -> Optional[float]:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


@dataclass
class _TideReads:
    inventory: Any
    issues: Any
    alert_days: Any
    gitlab: Any
    checks: Any


def _read_tide(svc: TideService) -> _TideReads:
    inventory = svc.get_rule_inventory()
    if not isinstance(inventory, list):
        return _TideReads(inventory, None, None, None, None)
    return _TideReads(inventory, svc.get_rule_issues(), svc.get_rule_alert_days(SILENT_DAYS),
                      svc.get_gitlab_issues(), svc.get_elastic_checks())


def _needs_tide7(what: str, outcome: object) -> Optional[str]:
    if isinstance(outcome, TableAbsent):
        return f"{what} needs TIDE 7 ({outcome.table} is not in this tenant)."
    if isinstance(outcome, TideFailure):
        return f"{what} could not be read from TIDE: {outcome.message}"
    return None


def _closures(session: Optional[Session], report: RuleHealthReport) -> Any:
    if session is None:
        return None
    try:
        return rule_outcomes(session, Window.last(CLOSURE_DAYS))
    except Exception:
        logger.exception("ION rule closures could not be read")
        report.closure_failed = True
        return None


def _closure_totals(outcomes: Any) -> dict[str, int]:
    totals = {"tp": 0, "fp": 0, "benign": 0, "other": 0, "closed": 0}
    for rec in outcomes.records.values():
        totals["tp"] += rec.true_positive
        totals["fp"] += rec.false_positive
        totals["benign"] += rec.outcomes.get("benign_true_positive", 0)
        totals["closed"] += rec.closed
    totals["other"] = totals["closed"] - totals["tp"] - totals["fp"] - totals["benign"]
    return totals


async def kibana_alert_days(days: int = ALERT_WINDOW_DAYS, silent_days: int = SILENT_DAYS) -> Optional[dict]:
    """{(rule_id, space): (daily counts oldest first, alerts in silent_days)} from
    ION's Kibana alerts index, or None when it cannot be read."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return None
    query = {
        "size": 0,
        "query": {"bool": {
            "must": [{"range": {"@timestamp": {"gte": f"now-{silent_days}d/d"}}}],
            "must_not": [{"term": {"kibana.alert.building_block_type": "default"}}],
        }},
        "aggs": {"by_rule": {
            "terms": {"field": "kibana.alert.rule.rule_id", "size": 5000},
            "aggs": {"by_space": {
                "terms": {"field": "kibana.space_ids", "size": 50},
                "aggs": {"recent": {
                    "filter": {"range": {"@timestamp": {"gte": f"now-{days - 1}d/d"}}},
                    "aggs": {"per_day": {"date_histogram": {
                        "field": "@timestamp", "calendar_interval": "1d", "format": "yyyy-MM-dd",
                        "time_zone": "UTC"}}},
                }},
            }},
        }},
    }
    try:
        result = await es._request("POST", f"/{es.alert_index.replace(',', '%2C')}/_search", json=query)
    except Exception:
        logger.exception("Kibana alert counts could not be read")
        return None
    today = date.today()
    out: dict = {}
    for rule in ((result.get("aggregations") or {}).get("by_rule") or {}).get("buckets") or []:
        for space in (rule.get("by_space") or {}).get("buckets") or []:
            by_day = {b.get("key_as_string"): int(b.get("doc_count") or 0)
                      for b in ((space.get("recent") or {}).get("per_day") or {}).get("buckets") or []}
            out[(str(rule.get("key")), str(space.get("key")))] = (_series(by_day, today, days), int(space.get("doc_count") or 0))
    return out


async def rule_health(session: Optional[Session], svc: Optional[TideService] = None) -> RuleHealthReport:
    """Every rule in the active destination scope, with its problems,
    alerts, closures, GitLab issues and Elastic validator findings."""
    svc = svc or get_tide_service()
    report = RuleHealthReport(state="data")
    if not svc.enabled:
        report.state = "unconfigured"
        return report
    reads = await asyncio.to_thread(_read_tide, svc)
    if not isinstance(reads.inventory, list):
        report.state = "failed"
        report.failure = reads.inventory if isinstance(reads.inventory, TideFailure) else TideFailure("bad_request", "no rule table")
        # The analyst FP rate is ION's own and does not need TIDE.
        outcomes = await asyncio.to_thread(_closures, session, report)
        report.closures = _closure_totals(outcomes) if outcomes is not None else None
        return report

    for row in reads.inventory:
        report.rules.append(RuleHealth(
            rule_id=str(row.get("rule_id") or ""), name=str(row.get("name") or row.get("rule_id") or "Unnamed rule"),
            kind="wazuh" if row.get("kind") == "wazuh" else "elastic",
            severity=str(row.get("severity") or "").lower(), enabled=bool(row.get("enabled")),
            quality=_number(row.get("quality_score")), mitre_ids=list(row.get("mitre_ids") or []),
            dest=Destination(str(row.get("siem_id") or ""), str(row.get("space") or "")),
            rule_uuid=row.get("rule_uuid") or None,
        ))
    by_key = report.by_key()
    by_uuid = {(r.dest.siem_id, r.dest.space, r.rule_uuid): r for r in report.rules if r.rule_uuid}

    # Alert counts: TIDE's when it keeps them, else ION's Kibana alerts.
    today = date.today()
    if isinstance(reads.alert_days, list):
        report.alerts_from = "tide"
        per_rule: dict[str, dict[str, int]] = {}
        for row in reads.alert_days:
            siem, space = str(row.get("siem_id") or ""), str(row.get("space") or "")
            rule = by_uuid.get((siem, space, row.get("rule_uuid"))) or by_key.get(f"{row.get('rule_id')}|{siem}|{space}")
            if rule is not None:
                bucket = per_rule.setdefault(rule.key, {})
                bucket[str(row.get("day"))[:10]] = bucket.get(str(row.get("day"))[:10], 0) + int(row.get("alerts") or 0)
        for rule in report.rules:
            counts = per_rule.get(rule.key, {})
            rule.days = _series(counts, today, ALERT_WINDOW_DAYS)
            rule.alerts_silent_window = sum(counts.values())
    else:
        kibana = await kibana_alert_days()
        if kibana is not None:
            report.alerts_from = "kibana"
            for rule in report.rules:
                if rule.kind == "elastic":
                    rule.days, rule.alerts_silent_window = kibana.get((rule.rule_id, rule.dest.space), ([0] * ALERT_WINDOW_DAYS, 0))
        note = _needs_tide7("Alert counts per rule", reads.alert_days)
        if note:
            report.notes.append(note + (" Elastic rules use ION's Kibana alerts instead." if kibana is not None else ""))

    # Problems: TIDE Rule Monitoring, else ION's thresholds.
    issue_rules: dict[tuple, list[RuleHealth]] = {}
    if isinstance(reads.issues, list):
        report.monitoring = "tide"
        for row in reads.issues:
            problem = tide_problem(row)
            siem, space, rule_id = str(row.get("siem_id") or ""), str(row.get("space") or ""), str(row.get("rule_id") or "")
            cause_key = (problem.kind, problem.cause, siem, space)
            if rule_id:
                rule = by_key.get(f"{rule_id}|{siem}|{space}")
                if rule is not None:
                    rule.problems.append(problem)
                    issue_rules.setdefault(cause_key, []).append(rule)
            else:
                report.destination_problems.append(DestinationProblem(Destination(siem, space), problem))
    else:
        report.monitoring = "ion"
        note = _needs_tide7("Rule Monitoring", reads.issues)
        if note:
            report.notes.append(note + " ION judges alert volume itself until it is.")
        for rule in report.rules:
            rule.problems.extend(ion_problems(rule.days, rule.alerts_silent_window if report.alerts_from else None, rule.enabled))

    if isinstance(reads.gitlab, list):
        dest_issues: dict[tuple, list[dict]] = {}
        for row in reads.gitlab:
            issue = {"iid": row.get("iid"), "title": row.get("title"), "url": row.get("web_url"), "state": row.get("state")}
            linked: dict[str, RuleHealth] = {}
            for ref in _json_list(row.get("rules")):
                if isinstance(ref, list) and len(ref) >= 3:
                    rule = by_key.get(f"{ref[0]}|{ref[1]}|{ref[2]}")
                    if rule is not None:
                        linked[rule.key] = rule
            for cause in _json_list(row.get("causes")):
                if isinstance(cause, list) and len(cause) >= 4:
                    key = tuple(str(c) for c in cause[:4])
                    for rule in issue_rules.get(key, []):
                        linked[rule.key] = rule
                    dest_issues.setdefault(key, []).append(issue)
            for rule in linked.values():
                rule.gitlab.append(issue)
        report.destination_problems = [
            DestinationProblem(d.dest, d.problem, tuple(dest_issues.get((d.problem.kind, d.problem.cause, d.dest.siem_id, d.dest.space), ())))
            for d in report.destination_problems
        ]
    elif note := _needs_tide7("GitLab issues", reads.gitlab):
        report.notes.append(note)

    if isinstance(reads.checks, list):
        for row in reads.checks:
            rule = by_key.get(f"{row.get('rule_id')}|{row.get('siem_id')}|{row.get('space')}")
            if rule is not None:
                rule.checks = [p for p in _json_list(row.get("problems")) if isinstance(p, dict)]

    outcomes = await asyncio.to_thread(_closures, session, report)
    if outcomes is not None:
        report.closures = _closure_totals(outcomes)
        for rule in report.rules:
            rec = outcomes.get(RuleKey(rule_id=rule.rule_id)) or outcomes.get(RuleKey(rule_name=rule.name))
            if rec is not None and rec.closed:
                rule.outcome = rec
                rule.noisy = report.policy.is_noisy(rec)

    report.rules.sort(key=lambda r: (r.worst, -r.count("error"), -r.count("warning"), -r.count("info"),
                                     ("critical", "high", "medium", "low").index(r.severity)
                                     if r.severity in ("critical", "high", "medium", "low") else 4, r.name.lower()))
    return report


def recent_closures(session: Session, rule_id: str, rule_name: str, limit: int = 6) -> list[dict]:
    """The rule's latest closed cases inside CLOSURE_DAYS, newest first."""
    from sqlalchemy import or_, select

    from ion.models.alert_triage import AlertCase, AlertTriage
    from ion.models.user import User

    window = Window.last(CLOSURE_DAYS)
    match = AlertTriage.rule_id == rule_id
    if rule_name:
        match = or_(match, (AlertTriage.rule_id.is_(None)) & (AlertTriage.rule_name == rule_name))
    rows = session.execute(
        select(AlertCase.case_number, AlertCase.closed_at, AlertCase.closure_reason, User.username)
        .join(AlertTriage, AlertTriage.case_id == AlertCase.id)
        .outerjoin(User, User.id == AlertCase.closed_by_id)
        .where(match, AlertCase.closure_reason.is_not(None),
               AlertCase.closed_at >= window.since, AlertCase.closed_at < window.until)
        .group_by(AlertCase.id, AlertCase.case_number, AlertCase.closed_at, AlertCase.closure_reason, User.username)
        .order_by(AlertCase.closed_at.desc()).limit(limit)
    ).all()
    return [{"case": r[0], "closed_at": r[1], "reason": r[2], "by": r[3]} for r in rows]


_REPORT_TTL_S = 8.0
_report_cache: dict[str, tuple[float, RuleHealthReport]] = {}


async def cached_rule_health(session: Optional[Session]) -> RuleHealthReport:
    """rule_health for the shared TIDE service, reused for a few seconds so
    the Overview, Rules and Health panels of one page load build it once."""
    import time

    from ion.services.tide_service import scope_label

    svc = get_tide_service()
    key = scope_label(svc.scope) if svc.enabled else ""
    hit = _report_cache.get(key)
    if hit and time.monotonic() - hit[0] < _REPORT_TTL_S:
        return hit[1]
    report = await rule_health(session, svc)
    if report.state == "data":
        _report_cache[key] = (time.monotonic(), report)
    return report
