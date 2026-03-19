"""Analytics Engine for ION.

Scheduled background jobs that analyze ION's internal database to surface
entity risk scores, repeat offenders, rule noise, observable trends,
case metrics, and stale investigations.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from ion.models.analytics import AnalyticsJob, AnalyticsJobType, AnalyticsSnapshot
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus, Note, NoteEntityType
from ion.models.observable import Observable, ObservableLink, ThreatLevel
from ion.storage.database import get_engine, get_session_factory

logger = logging.getLogger(__name__)

# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    "critical": 50,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 1,
}

THREAT_LEVEL_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 3,
    "benign": 0,
    "unknown": 1,
}


class AnalyticsEngine:
    """Runs scheduled analytics jobs against ION's internal database."""

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None

    # =====================================================================
    # Background Loop
    # =====================================================================

    async def _background_loop(self):
        """Main loop — checks for due jobs every 60 seconds."""
        logger.info("Analytics Engine background loop started")
        while self._running:
            try:
                engine = get_engine()
                factory = get_session_factory(engine)
                session = factory()
                try:
                    now = datetime.utcnow()
                    jobs = session.query(AnalyticsJob).filter(
                        AnalyticsJob.enabled == True,  # noqa: E712
                    ).all()

                    for job in jobs:
                        if job.next_run_at and job.next_run_at > now:
                            continue
                        try:
                            self._execute_job(session, job)
                        except Exception as e:
                            logger.error("Analytics job %s failed: %s", job.job_type, e)
                            job.last_error = str(e)
                            job.next_run_at = now + timedelta(minutes=job.schedule_minutes)
                            session.commit()

                    # Purge old snapshots (>30 days)
                    cutoff = now - timedelta(days=30)
                    session.query(AnalyticsSnapshot).filter(
                        AnalyticsSnapshot.created_at < cutoff
                    ).delete()
                    session.commit()
                finally:
                    session.close()
            except Exception as e:
                logger.error("Analytics Engine loop error: %s", e)

            await asyncio.sleep(60)

    def _execute_job(self, session: Session, job: AnalyticsJob):
        """Run a single analytics job and store results."""
        now = datetime.utcnow()
        start = time.monotonic()

        analyzer = self._get_analyzer(job.job_type)
        if not analyzer:
            job.last_error = f"Unknown job type: {job.job_type}"
            job.next_run_at = now + timedelta(minutes=job.schedule_minutes)
            session.commit()
            return

        result = analyzer(session)
        duration_ms = int((time.monotonic() - start) * 1000)

        job.last_result = result
        job.last_run_at = now
        job.last_duration_ms = duration_ms
        job.last_error = None
        job.run_count += 1
        job.next_run_at = now + timedelta(minutes=job.schedule_minutes)

        # Save snapshot for trend tracking
        snapshot = AnalyticsSnapshot(
            job_type=job.job_type,
            snapshot_data=result,
            created_at=now,
        )
        session.add(snapshot)
        session.commit()

        logger.debug("Analytics job %s completed in %dms", job.job_type, duration_ms)

    def _get_analyzer(self, job_type: str):
        """Map job type to analyzer method."""
        return {
            AnalyticsJobType.ENTITY_RISK_SCORE.value: self._analyze_entity_risk,
            AnalyticsJobType.REPEAT_OFFENDERS.value: self._analyze_repeat_offenders,
            AnalyticsJobType.RULE_NOISE.value: self._analyze_rule_noise,
            AnalyticsJobType.OBSERVABLE_VELOCITY.value: self._analyze_observable_velocity,
            AnalyticsJobType.CASE_METRICS.value: self._analyze_case_metrics,
            AnalyticsJobType.STALE_INVESTIGATIONS.value: self._analyze_stale_investigations,
        }.get(job_type)

    def run_job_now(self, session: Session, job_type: str) -> Dict[str, Any]:
        """Manually trigger a single job and return results."""
        job = session.query(AnalyticsJob).filter_by(job_type=job_type).first()
        if not job:
            return {"error": f"Job not found: {job_type}"}

        self._execute_job(session, job)
        return job.last_result or {}

    # =====================================================================
    # Analyzers
    # =====================================================================

    def _analyze_entity_risk(self, session: Session) -> Dict[str, Any]:
        """Score hosts and users by aggregated alert/observable risk."""
        now = datetime.utcnow()
        window = now - timedelta(days=30)

        # Get all cases with their hosts/users and severity
        cases = session.query(AlertCase).filter(
            AlertCase.created_at >= window
        ).all()

        entity_scores: Dict[str, Dict[str, Any]] = {}

        for case in cases:
            severity = (case.severity or "medium").lower()
            weight = SEVERITY_WEIGHTS.get(severity, 5)
            is_open = case.status != AlertCaseStatus.CLOSED.value

            # Score affected hosts
            for host in (case.affected_hosts or []):
                if not host:
                    continue
                key = f"host:{host}"
                if key not in entity_scores:
                    entity_scores[key] = {
                        "entity": host, "type": "host", "risk_score": 0,
                        "alert_count": 0, "open_cases": 0, "closed_cases": 0,
                        "severities": {}, "rules": set(),
                    }
                entity_scores[key]["risk_score"] += weight
                entity_scores[key]["alert_count"] += 1
                if is_open:
                    entity_scores[key]["open_cases"] += 1
                else:
                    entity_scores[key]["closed_cases"] += 1
                entity_scores[key]["severities"][severity] = entity_scores[key]["severities"].get(severity, 0) + 1
                for rule in (case.triggered_rules or []):
                    entity_scores[key]["rules"].add(rule)

            # Score affected users
            for user in (case.affected_users or []):
                if not user:
                    continue
                key = f"user:{user}"
                if key not in entity_scores:
                    entity_scores[key] = {
                        "entity": user, "type": "user", "risk_score": 0,
                        "alert_count": 0, "open_cases": 0, "closed_cases": 0,
                        "severities": {}, "rules": set(),
                    }
                entity_scores[key]["risk_score"] += weight
                entity_scores[key]["alert_count"] += 1
                if is_open:
                    entity_scores[key]["open_cases"] += 1
                else:
                    entity_scores[key]["closed_cases"] += 1
                entity_scores[key]["severities"][severity] = entity_scores[key]["severities"].get(severity, 0) + 1

        # Add observable threat level scores per entity
        obs_links = session.query(ObservableLink, Observable.threat_level).join(
            Observable, ObservableLink.observable_id == Observable.id
        ).filter(
            Observable.threat_level.notin_(["unknown", "benign"])
        ).all()

        for link, threat_level in obs_links:
            # Observable links are to alerts/cases — map to entities via cases
            if link.link_type.value == "case":
                case = session.query(AlertCase).filter_by(id=link.entity_id).first()
                if case:
                    for host in (case.affected_hosts or []):
                        key = f"host:{host}"
                        if key in entity_scores:
                            entity_scores[key]["risk_score"] += THREAT_LEVEL_WEIGHTS.get(threat_level, 0)

        # Open case bonus
        for ent in entity_scores.values():
            ent["risk_score"] += ent["open_cases"] * 15

        # Convert sets to lists for JSON serialization and sort
        results = []
        for ent in entity_scores.values():
            ent["rules"] = sorted(ent.get("rules", set()))
            results.append(ent)

        results.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "entities": results[:25],
            "total_scored": len(results),
            "calculated_at": now.isoformat(),
        }

    def _analyze_repeat_offenders(self, session: Session) -> Dict[str, Any]:
        """Find hosts/users appearing in many alerts across time windows."""
        now = datetime.utcnow()
        window_7d = now - timedelta(days=7)
        window_30d = now - timedelta(days=30)

        # Get cases in 30d window
        cases_30d = session.query(AlertCase).filter(
            AlertCase.created_at >= window_30d
        ).all()

        entity_counts: Dict[str, Dict[str, Any]] = {}

        for case in cases_30d:
            in_7d = case.created_at >= window_7d if case.created_at else False

            for host in (case.affected_hosts or []):
                if not host:
                    continue
                key = f"host:{host}"
                if key not in entity_counts:
                    entity_counts[key] = {
                        "entity": host, "type": "host",
                        "count_7d": 0, "count_30d": 0,
                        "rules": set(), "severities": [],
                    }
                entity_counts[key]["count_30d"] += 1
                if in_7d:
                    entity_counts[key]["count_7d"] += 1
                for rule in (case.triggered_rules or []):
                    entity_counts[key]["rules"].add(rule)
                if case.severity:
                    entity_counts[key]["severities"].append(case.severity)

            for user in (case.affected_users or []):
                if not user:
                    continue
                key = f"user:{user}"
                if key not in entity_counts:
                    entity_counts[key] = {
                        "entity": user, "type": "user",
                        "count_7d": 0, "count_30d": 0,
                        "rules": set(), "severities": [],
                    }
                entity_counts[key]["count_30d"] += 1
                if in_7d:
                    entity_counts[key]["count_7d"] += 1
                if case.severity:
                    entity_counts[key]["severities"].append(case.severity)

        # Filter to entities with 3+ alerts in 30d
        offenders = []
        for ent in entity_counts.values():
            if ent["count_30d"] >= 3:
                ent["rules"] = sorted(ent["rules"])
                ent["top_severity"] = _worst_severity(ent["severities"])
                ent["severities"] = len(ent["severities"])
                offenders.append(ent)

        offenders.sort(key=lambda x: x["count_30d"], reverse=True)

        return {
            "offenders": offenders[:25],
            "total_flagged": len(offenders),
            "threshold": 3,
            "calculated_at": now.isoformat(),
        }

    def _analyze_rule_noise(self, session: Session) -> Dict[str, Any]:
        """Analyze which rules generate the most alerts vs. case creation rate."""
        now = datetime.utcnow()
        window = now - timedelta(days=30)

        # Count triage entries per ES alert rule (stored in AlertCase.triggered_rules)
        cases = session.query(AlertCase).filter(
            AlertCase.created_at >= window
        ).all()

        rule_stats: Dict[str, Dict[str, Any]] = {}

        for case in cases:
            for rule in (case.triggered_rules or []):
                if not rule:
                    continue
                if rule not in rule_stats:
                    rule_stats[rule] = {
                        "rule_name": rule, "alert_count": 0,
                        "case_count": 0, "closed_fp": 0, "closed_tp": 0,
                    }
                rule_stats[rule]["alert_count"] += 1
                rule_stats[rule]["case_count"] += 1

                if case.status == AlertCaseStatus.CLOSED.value:
                    if case.closure_reason in ("false_positive", "benign_true_positive", "not_applicable"):
                        rule_stats[rule]["closed_fp"] += 1
                    else:
                        rule_stats[rule]["closed_tp"] += 1

        # Also count triage entries without cases
        triages_no_case = session.query(AlertTriage).filter(
            AlertTriage.created_at >= window,
            AlertTriage.case_id == None,  # noqa: E711
        ).all()

        # We don't have the rule name on AlertTriage directly,
        # but we have analyst_notes and es_alert_id

        rules = []
        for rule_name, stats in rule_stats.items():
            total = stats["alert_count"]
            fp = stats["closed_fp"]
            fp_ratio = round(fp / total, 2) if total > 0 else 0.0
            stats["fp_ratio"] = fp_ratio
            stats["noise_score"] = round(fp_ratio * total, 1)
            rules.append(stats)

        rules.sort(key=lambda x: x["noise_score"], reverse=True)

        return {
            "rules": rules[:25],
            "total_rules": len(rules),
            "uncased_triages": len(triages_no_case),
            "calculated_at": now.isoformat(),
        }

    def _analyze_observable_velocity(self, session: Session) -> Dict[str, Any]:
        """Track observable ingestion rate, threat levels, and stale IOCs."""
        now = datetime.utcnow()
        window = now - timedelta(days=30)

        # Daily new observable counts
        daily_counts: Dict[str, int] = {}
        observables = session.query(
            Observable.created_at
        ).filter(
            Observable.created_at >= window
        ).all()

        for (created_at,) in observables:
            if created_at:
                day = created_at.strftime("%Y-%m-%d")
                daily_counts[day] = daily_counts.get(day, 0) + 1

        # Fill in missing days with 0
        daily_series = []
        for i in range(30):
            day = (now - timedelta(days=29 - i)).strftime("%Y-%m-%d")
            daily_series.append({"date": day, "count": daily_counts.get(day, 0)})

        # Threat level distribution
        threat_dist = {}
        dist_rows = session.query(
            Observable.threat_level, func.count(Observable.id)
        ).group_by(Observable.threat_level).all()
        for level, count in dist_rows:
            threat_dist[level] = count

        # Total counts
        total = session.query(func.count(Observable.id)).scalar() or 0
        total_watched = session.query(func.count(Observable.id)).filter(
            Observable.is_watched == True  # noqa: E712
        ).scalar() or 0

        # Stale watched IOCs (not seen in 14+ days)
        stale_cutoff = now - timedelta(days=14)
        stale = session.query(Observable).filter(
            Observable.is_watched == True,  # noqa: E712
            Observable.last_seen < stale_cutoff,
        ).order_by(Observable.last_seen).limit(20).all()

        stale_list = [{
            "id": o.id, "type": o.type, "value": o.value,
            "threat_level": o.threat_level,
            "last_seen": o.last_seen.isoformat() if o.last_seen else None,
            "days_stale": (now - o.last_seen).days if o.last_seen else 0,
        } for o in stale]

        # Velocity: avg new per day over last 7 days vs previous 7 days
        recent_7d = sum(1 for (c,) in observables if c and c >= now - timedelta(days=7))
        prev_7d = sum(1 for (c,) in observables if c and now - timedelta(days=14) <= c < now - timedelta(days=7))
        velocity_change = recent_7d - prev_7d

        return {
            "daily_counts": daily_series,
            "threat_distribution": threat_dist,
            "total_observables": total,
            "total_watched": total_watched,
            "stale_iocs": stale_list,
            "velocity_7d": recent_7d,
            "velocity_prev_7d": prev_7d,
            "velocity_change": velocity_change,
            "calculated_at": now.isoformat(),
        }

    def _analyze_case_metrics(self, session: Session) -> Dict[str, Any]:
        """Calculate MTTR, closure reasons, and case volume metrics."""
        now = datetime.utcnow()
        window = now - timedelta(days=30)

        # All cases in window
        cases = session.query(AlertCase).filter(
            AlertCase.created_at >= window
        ).all()

        total = len(cases)
        open_count = sum(1 for c in cases if c.status != AlertCaseStatus.CLOSED.value)
        closed_count = total - open_count

        # MTTR for closed cases
        resolve_times: List[float] = []
        closure_reasons: Dict[str, int] = {}
        by_severity: Dict[str, Dict[str, int]] = {}

        for case in cases:
            sev = (case.severity or "medium").lower()
            if sev not in by_severity:
                by_severity[sev] = {"open": 0, "closed": 0, "total": 0}
            by_severity[sev]["total"] += 1

            if case.status == AlertCaseStatus.CLOSED.value:
                by_severity[sev]["closed"] += 1
                if case.closed_at and case.created_at:
                    hours = (case.closed_at - case.created_at).total_seconds() / 3600
                    resolve_times.append(hours)
                reason = case.closure_reason or "unspecified"
                closure_reasons[reason] = closure_reasons.get(reason, 0) + 1
            else:
                by_severity[sev]["open"] += 1

        mttr = round(sum(resolve_times) / len(resolve_times), 1) if resolve_times else None

        # Daily case creation trend
        daily_cases: Dict[str, int] = {}
        for case in cases:
            if case.created_at:
                day = case.created_at.strftime("%Y-%m-%d")
                daily_cases[day] = daily_cases.get(day, 0) + 1

        daily_series = []
        for i in range(30):
            day = (now - timedelta(days=29 - i)).strftime("%Y-%m-%d")
            daily_series.append({"date": day, "count": daily_cases.get(day, 0)})

        return {
            "total_cases": total,
            "open_cases": open_count,
            "closed_cases": closed_count,
            "mttr_hours": mttr,
            "closure_reasons": closure_reasons,
            "by_severity": by_severity,
            "daily_trend": daily_series,
            "calculated_at": now.isoformat(),
        }

    def _analyze_stale_investigations(self, session: Session) -> Dict[str, Any]:
        """Find open cases and alerts with no recent activity."""
        now = datetime.utcnow()
        stale_case_days = 3
        stale_alert_days = 5

        # Open cases with no notes in X days
        open_cases = session.query(AlertCase).filter(
            AlertCase.status != AlertCaseStatus.CLOSED.value
        ).all()

        stale_cases = []
        for case in open_cases:
            latest_note = session.query(func.max(Note.created_at)).filter(
                Note.entity_type == NoteEntityType.CASE,
                Note.entity_id == str(case.id),
            ).scalar()

            last_activity = latest_note or case.created_at
            if last_activity and (now - last_activity).days >= stale_case_days:
                stale_cases.append({
                    "case_id": case.id,
                    "case_number": case.case_number,
                    "title": case.title,
                    "status": case.status,
                    "severity": case.severity,
                    "assigned_to": case.assigned_to.display_name if case.assigned_to else None,
                    "last_activity": last_activity.isoformat(),
                    "days_stale": (now - last_activity).days,
                })

        # Open triages with no notes in X days
        open_triages = session.query(AlertTriage).filter(
            AlertTriage.status != AlertTriageStatus.CLOSED.value,
            AlertTriage.case_id == None,  # noqa: E711 — only uncased alerts
        ).all()

        stale_alerts = []
        for triage in open_triages:
            latest_note = session.query(func.max(Note.created_at)).filter(
                Note.entity_type == NoteEntityType.ALERT,
                Note.entity_id == triage.es_alert_id,
            ).scalar()

            last_activity = latest_note or triage.created_at
            if last_activity and (now - last_activity).days >= stale_alert_days:
                stale_alerts.append({
                    "triage_id": triage.id,
                    "es_alert_id": triage.es_alert_id,
                    "status": triage.status,
                    "assigned_to": triage.assigned_to.display_name if triage.assigned_to else None,
                    "last_activity": last_activity.isoformat(),
                    "days_stale": (now - last_activity).days,
                })

        stale_cases.sort(key=lambda x: x["days_stale"], reverse=True)
        stale_alerts.sort(key=lambda x: x["days_stale"], reverse=True)

        return {
            "stale_cases": stale_cases[:25],
            "stale_alerts": stale_alerts[:25],
            "total_stale_cases": len(stale_cases),
            "total_stale_alerts": len(stale_alerts),
            "case_threshold_days": stale_case_days,
            "alert_threshold_days": stale_alert_days,
            "calculated_at": now.isoformat(),
        }

    # =====================================================================
    # Lifecycle
    # =====================================================================

    def start_background_loop(self):
        """Start the background analytics loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._background_loop())

    def stop_background_loop(self):
        """Stop the background analytics loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None


# =========================================================================
# Helpers
# =========================================================================

def _worst_severity(severities: List[str]) -> str:
    """Return the worst severity from a list."""
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        if sev in severities:
            return sev
    return "unknown"


# =========================================================================
# Singleton
# =========================================================================

_analytics_engine: Optional[AnalyticsEngine] = None


def get_analytics_engine() -> AnalyticsEngine:
    """Get the singleton analytics engine instance."""
    global _analytics_engine
    if _analytics_engine is None:
        _analytics_engine = AnalyticsEngine()
    return _analytics_engine


def reset_analytics_engine():
    """Reset the singleton analytics engine instance."""
    global _analytics_engine
    if _analytics_engine is not None:
        _analytics_engine.stop_background_loop()
    _analytics_engine = None


# =========================================================================
# Seed Default Jobs
# =========================================================================

def seed_default_jobs(session: Session):
    """Create the 6 default analytics jobs if they don't exist (idempotent)."""
    defaults = [
        {
            "job_type": AnalyticsJobType.ENTITY_RISK_SCORE.value,
            "display_name": "Entity Risk Scoring",
            "description": "Aggregate risk scores for hosts and users based on alert severity, observable threat levels, and open case count.",
            "schedule_minutes": 30,
        },
        {
            "job_type": AnalyticsJobType.REPEAT_OFFENDERS.value,
            "display_name": "Repeat Offenders",
            "description": "Identify hosts and users that appear in alerts repeatedly across 7-day and 30-day windows.",
            "schedule_minutes": 30,
        },
        {
            "job_type": AnalyticsJobType.RULE_NOISE.value,
            "display_name": "Rule Noise Analysis",
            "description": "Analyze which detection rules generate the most alerts relative to actual case creation — find noisy rules.",
            "schedule_minutes": 60,
        },
        {
            "job_type": AnalyticsJobType.OBSERVABLE_VELOCITY.value,
            "display_name": "Observable Velocity",
            "description": "Track new IOC ingestion rate, threat level distribution, and identify stale watched observables.",
            "schedule_minutes": 30,
        },
        {
            "job_type": AnalyticsJobType.CASE_METRICS.value,
            "display_name": "Case Metrics",
            "description": "Calculate mean time to resolve, closure reason breakdown, and case volume trends.",
            "schedule_minutes": 30,
        },
        {
            "job_type": AnalyticsJobType.STALE_INVESTIGATIONS.value,
            "display_name": "Stale Investigations",
            "description": "Find open cases and alerts with no recent activity that may need attention.",
            "schedule_minutes": 360,
        },
    ]

    now = datetime.utcnow()
    created = 0

    for job_def in defaults:
        existing = session.query(AnalyticsJob).filter_by(
            job_type=job_def["job_type"]
        ).first()
        if existing:
            continue

        job = AnalyticsJob(
            job_type=job_def["job_type"],
            display_name=job_def["display_name"],
            description=job_def["description"],
            schedule_minutes=job_def["schedule_minutes"],
            enabled=True,
            next_run_at=now,  # Run immediately on first startup
        )
        session.add(job)
        created += 1

    if created:
        session.commit()
        logger.info("Seeded %d default analytics jobs", created)
