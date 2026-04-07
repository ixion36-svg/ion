"""TIDE integration service — queries TIDE's external SQL API for detection data."""

import logging
import time
from typing import Any, Optional

import httpx

from ion.core.config import get_tide_config, get_ssl_verify
from ion.core.circuit_breaker import tide_breaker

logger = logging.getLogger(__name__)


class TideService:
    """Client for TIDE's /api/external/query endpoint."""

    def __init__(self):
        cfg = get_tide_config()
        self.url = (cfg.get("url") or "").rstrip("/")
        self.api_key = cfg.get("api_key") or ""
        self.enabled = cfg.get("enabled", False) and bool(self.url) and bool(self.api_key)
        self.verify = get_ssl_verify() if cfg.get("verify_ssl", True) else False

    def _query(self, sql: str, retries: int = 2) -> Optional[dict]:
        if not self.enabled:
            return None
        if not tide_breaker.can_execute():
            logger.warning("TIDE circuit breaker OPEN — skipping query")
            return None
        for attempt in range(retries + 1):
            try:
                resp = httpx.post(
                    f"{self.url}/api/external/query",
                    json={"sql": sql},
                    headers={"X-TIDE-API-KEY": self.api_key, "Content-Type": "application/json"},
                    verify=self.verify,
                    timeout=30.0,
                )
                if resp.status_code == 200:
                    tide_breaker.record_success()
                    return resp.json()
                # Retry on 500 (DuckDB concurrency issue)
                if resp.status_code == 500 and attempt < retries:
                    logger.info("TIDE 500, retrying (%d/%d)...", attempt + 1, retries)
                    time.sleep(0.5 * (attempt + 1))
                    continue
                logger.warning("TIDE query failed: %s %s", resp.status_code, resp.text[:300])
                tide_breaker.record_failure()
                return None
            except Exception as e:
                if attempt < retries:
                    logger.info("TIDE connection error, retrying (%d/%d): %s", attempt + 1, retries, e)
                    time.sleep(0.5 * (attempt + 1))
                    continue
                logger.error("TIDE connection error: %s", e)
                tide_breaker.record_failure()
                return None
        return None

    def get_systems(self) -> list[dict[str, Any]]:
        result = self._query(
            "SELECT id, name, classification, description FROM systems ORDER BY name"
        )
        return result["rows"] if result else []

    def get_system_detail(self, system_id: str) -> Optional[dict]:
        result = self._query(
            f"SELECT id, name, classification, description FROM systems WHERE id = '{system_id}'"
        )
        if not result or not result["rows"]:
            return None
        system = result["rows"][0]

        # Get applied detections with rule details
        det_result = self._query(f"""
            SELECT dr.rule_id, dr.name, dr.severity, dr.enabled, dr.quality_score,
                   dr.mitre_ids, dr.space
            FROM applied_detections ad
            JOIN detection_rules dr ON dr.rule_id = ad.detection_id AND dr.space = 'default'
            WHERE ad.system_id = '{system_id}'
            ORDER BY dr.severity DESC, dr.name
        """)
        system["detections"] = det_result["rows"] if det_result else []

        # Get total rules count for coverage calculation
        total_result = self._query(
            "SELECT count(DISTINCT rule_id) as total FROM detection_rules WHERE space = 'default'"
        )
        system["total_rules"] = total_result["rows"][0]["total"] if total_result and total_result["rows"] else 0

        return system

    def get_detection_rules(self, search: str = "", limit: int = 50) -> list[dict]:
        where = ""
        if search:
            safe = search.replace("'", "''")
            where = f"WHERE name ILIKE '%{safe}%' OR array_to_string(mitre_ids, ',') ILIKE '%{safe}%'"
        result = self._query(f"""
            SELECT DISTINCT rule_id, name, severity, enabled, quality_score, mitre_ids
            FROM detection_rules
            {where}
            ORDER BY name
            LIMIT {limit}
        """)
        return result["rows"] if result else []

    def get_mitre_coverage(self, system_id: str) -> dict:
        """Get MITRE technique coverage for a system."""
        # Techniques covered by this system's detections
        covered = self._query(f"""
            SELECT DISTINCT t.technique_id
            FROM applied_detections ad
            JOIN detection_rules dr ON dr.rule_id = ad.detection_id AND dr.space = 'default',
            LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE ad.system_id = '{system_id}'
        """)
        covered_ids = {r["technique_id"] for r in (covered["rows"] if covered else [])}

        # All techniques in the MITRE database
        all_tech = self._query(
            "SELECT id as technique_id, name, tactic FROM mitre_techniques ORDER BY id"
        )
        techniques = all_tech["rows"] if all_tech else []

        return {
            "covered": list(covered_ids),
            "total_techniques": len(techniques),
            "techniques": techniques,
        }

    def get_global_mitre_coverage(self) -> Optional[dict]:
        """Get global MITRE technique coverage across all detection rules and systems."""
        if not self.enabled:
            return None

        # 1. All known MITRE techniques
        all_tech = self._query(
            "SELECT id as technique_id, name, tactic FROM mitre_techniques ORDER BY id"
        )
        if not all_tech:
            return None
        techniques = all_tech["rows"]
        tech_catalog = {t["technique_id"]: t for t in techniques}

        # 2. Per-technique rule stats (LATERAL unnest for DuckDB compatibility)
        stats = self._query("""
            SELECT
                t.technique_id,
                count(DISTINCT dr.rule_id) as rule_count,
                round(avg(dr.quality_score), 1) as avg_quality,
                count(DISTINCT dr.rule_id) FILTER (WHERE dr.severity = 'critical') as critical_rules,
                count(DISTINCT dr.rule_id) FILTER (WHERE dr.severity = 'high') as high_rules,
                count(DISTINCT dr.rule_id) FILTER (WHERE dr.severity = 'medium') as medium_rules,
                count(DISTINCT dr.rule_id) FILTER (WHERE dr.severity = 'low') as low_rules,
                count(DISTINCT dr.rule_id) FILTER (WHERE dr.enabled = 1) as enabled_rules
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE dr.space = 'default'
              AND dr.mitre_ids IS NOT NULL
            GROUP BY t.technique_id
        """)
        stats_map = {}
        if stats:
            for r in stats["rows"]:
                # Roll up sub-techniques to parent for the main key
                tid = r["technique_id"]
                parent = tid.split(".")[0]
                if parent not in stats_map:
                    stats_map[parent] = {
                        "rule_count": 0, "avg_quality": 0, "enabled_rules": 0,
                        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        "_quality_sum": 0, "_quality_n": 0,
                    }
                s = stats_map[parent]
                s["rule_count"] += r["rule_count"]
                s["enabled_rules"] += r["enabled_rules"]
                s["severity"]["critical"] += r["critical_rules"]
                s["severity"]["high"] += r["high_rules"]
                s["severity"]["medium"] += r["medium_rules"]
                s["severity"]["low"] += r["low_rules"]
                s["_quality_sum"] += (r["avg_quality"] or 0) * r["rule_count"]
                s["_quality_n"] += r["rule_count"]

            for s in stats_map.values():
                s["avg_quality"] = round(s["_quality_sum"] / s["_quality_n"], 1) if s["_quality_n"] else 0
                del s["_quality_sum"]
                del s["_quality_n"]

        # 3. Per-technique system coverage (LATERAL unnest for DuckDB)
        sys_cov = self._query("""
            SELECT
                t.technique_id,
                s.name as system_name,
                s.id as system_id
            FROM applied_detections ad
            JOIN detection_rules dr ON dr.rule_id = ad.detection_id AND dr.space = 'default'
            JOIN systems s ON s.id = ad.system_id,
            LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE dr.mitre_ids IS NOT NULL
            GROUP BY t.technique_id, s.name, s.id
        """)
        sys_map: dict[str, list] = {}
        if sys_cov:
            for r in sys_cov["rows"]:
                parent = r["technique_id"].split(".")[0]
                if parent not in sys_map:
                    sys_map[parent] = []
                entry = {"id": r["system_id"], "name": r["system_name"]}
                if entry not in sys_map[parent]:
                    sys_map[parent].append(entry)

        # 4. Build result
        result_techs = {}
        covered_ids = set()
        blind_spots = []
        for tid, info in tech_catalog.items():
            entry = {
                "name": info["name"],
                "tactic": info["tactic"],
                "rule_count": 0,
                "avg_quality": 0,
                "enabled_rules": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "systems": [],
            }
            if tid in stats_map:
                entry.update(stats_map[tid])
                covered_ids.add(tid)
            if tid in sys_map:
                entry["systems"] = sys_map[tid]
            if entry["rule_count"] == 0:
                blind_spots.append(tid)
            result_techs[tid] = entry

        # Total rules
        total_result = self._query(
            "SELECT count(DISTINCT rule_id) as total FROM detection_rules WHERE space = 'default'"
        )
        total_rules = total_result["rows"][0]["total"] if total_result and total_result["rows"] else 0

        return {
            "techniques": result_techs,
            "total_techniques": len(tech_catalog),
            "covered_techniques": len(covered_ids),
            "blind_spots": blind_spots,
            "total_rules": total_rules,
        }

    # -----------------------------------------------------------------------
    # Detection Engineering endpoints
    # -----------------------------------------------------------------------

    def get_posture_stats(self) -> Optional[dict]:
        """Overall detection posture: totals, severity breakdown, quality, coverage."""
        if not self.enabled:
            return None

        # Total rules + enabled/disabled
        totals = self._query("""
            SELECT
                count(DISTINCT rule_id) as total_rules,
                count(DISTINCT rule_id) FILTER (WHERE enabled = 1) as enabled_rules,
                count(DISTINCT rule_id) FILTER (WHERE enabled = 0) as disabled_rules
            FROM detection_rules WHERE space = 'default'
        """)
        if not totals or not totals["rows"]:
            return None
        t = totals["rows"][0]

        # By severity
        sev = self._query("""
            SELECT severity,
                   count(DISTINCT rule_id) as count,
                   count(DISTINCT rule_id) FILTER (WHERE enabled = 1) as enabled,
                   count(DISTINCT rule_id) FILTER (WHERE enabled = 0) as disabled
            FROM detection_rules WHERE space = 'default'
            GROUP BY severity ORDER BY severity
        """)
        severity = {}
        if sev:
            for r in sev["rows"]:
                severity[r["severity"]] = {
                    "total": r["count"], "enabled": r["enabled"], "disabled": r["disabled"]
                }

        # Quality distribution (TIDE scores typically 7-39 range)
        qual = self._query("""
            SELECT
                count(DISTINCT rule_id) FILTER (WHERE quality_score >= 30) as excellent,
                count(DISTINCT rule_id) FILTER (WHERE quality_score >= 20 AND quality_score < 30) as good,
                count(DISTINCT rule_id) FILTER (WHERE quality_score >= 10 AND quality_score < 20) as fair,
                count(DISTINCT rule_id) FILTER (WHERE quality_score < 10) as poor,
                round(avg(quality_score), 1) as avg_quality,
                min(quality_score) as min_quality,
                max(quality_score) as max_quality
            FROM detection_rules WHERE space = 'default'
        """)
        quality = {}
        if qual and qual["rows"]:
            quality = qual["rows"][0]

        # Unmapped rules (no MITRE IDs)
        unmapped = self._query("""
            SELECT count(DISTINCT rule_id) as count
            FROM detection_rules
            WHERE space = 'default' AND (mitre_ids IS NULL OR len(mitre_ids) = 0)
        """)
        unmapped_count = unmapped["rows"][0]["count"] if unmapped and unmapped["rows"] else 0

        # MITRE coverage
        coverage = self._query("""
            SELECT count(DISTINCT t.technique_id) as covered
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE dr.space = 'default' AND dr.mitre_ids IS NOT NULL
        """)
        covered_count = coverage["rows"][0]["covered"] if coverage and coverage["rows"] else 0

        total_tech = self._query("SELECT count(*) as total FROM mitre_techniques")
        total_techniques = total_tech["rows"][0]["total"] if total_tech and total_tech["rows"] else 0

        # Systems
        sys_result = self._query("SELECT count(*) as total FROM systems")
        total_systems = sys_result["rows"][0]["total"] if sys_result and sys_result["rows"] else 0

        return {
            "total_rules": t["total_rules"],
            "enabled_rules": t["enabled_rules"],
            "disabled_rules": t["disabled_rules"],
            "severity": severity,
            "quality": quality,
            "unmapped_rules": unmapped_count,
            "covered_techniques": covered_count,
            "total_techniques": total_techniques,
            "total_systems": total_systems,
        }

    def get_disabled_critical_high(self) -> list[dict]:
        """Return disabled rules with critical or high severity — quick wins to enable."""
        if not self.enabled:
            return []
        result = self._query("""
            SELECT DISTINCT rule_id, name, severity, quality_score, mitre_ids
            FROM detection_rules
            WHERE space = 'default' AND enabled = 0
              AND severity IN ('critical', 'high')
            ORDER BY
                CASE severity WHEN 'critical' THEN 0 ELSE 1 END,
                quality_score DESC
        """)
        return result["rows"] if result else []

    def get_playbooks_with_kill_chains(self) -> list[dict]:
        """Return playbooks with their steps and linked MITRE techniques."""
        if not self.enabled:
            return []
        pb = self._query("SELECT id, name, description FROM playbooks ORDER BY name")
        if not pb or not pb["rows"]:
            return []
        playbooks = pb["rows"]

        for p in playbooks:
            steps = self._query(f"""
                SELECT id as step_id, step_number, title, description,
                       technique_id, required_rule, tactic
                FROM playbook_steps
                WHERE playbook_id = '{p["id"]}'
                ORDER BY step_number
            """)
            step_list = []
            all_tids = set()
            if steps:
                for r in steps["rows"]:
                    step_list.append({
                        "step_id": r["step_id"],
                        "order": r["step_number"],
                        "name": r["title"],
                        "description": r["description"],
                        "techniques": [r["technique_id"]] if r.get("technique_id") else [],
                        "required_rule": r.get("required_rule"),
                        "tactic": r.get("tactic"),
                    })
                    if r.get("technique_id"):
                        all_tids.add(r["technique_id"])
            p["steps"] = step_list

            # For each technique in steps, get rule coverage
            if all_tids:
                tid_list = ",".join(f"'{t}'" for t in all_tids)
                cov = self._query(f"""
                    SELECT t.technique_id,
                           count(DISTINCT dr.rule_id) as rule_count,
                           count(DISTINCT dr.rule_id) FILTER (WHERE dr.enabled = 1) as enabled_rules
                    FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
                    WHERE dr.space = 'default' AND t.technique_id IN ({tid_list})
                    GROUP BY t.technique_id
                """)
                cov_map = {}
                if cov:
                    for r in cov["rows"]:
                        cov_map[r["technique_id"]] = {
                            "rule_count": r["rule_count"],
                            "enabled_rules": r["enabled_rules"],
                        }
                p["technique_coverage"] = cov_map
            else:
                p["technique_coverage"] = {}

        return playbooks

    def get_rules_paginated(
        self, search: str = "", severity: str = "", enabled: str = "",
        offset: int = 0, limit: int = 50
    ) -> dict:
        """Paginated rule browser with filters."""
        if not self.enabled:
            return {"rows": [], "total": 0}

        conditions = ["space = 'default'"]
        if search:
            safe = search.replace("'", "''")
            conditions.append(
                f"(name ILIKE '%{safe}%' OR array_to_string(mitre_ids, ',') ILIKE '%{safe}%')"
            )
        if severity:
            safe_sev = severity.replace("'", "''")
            conditions.append(f"severity = '{safe_sev}'")
        if enabled in ("1", "0"):
            conditions.append(f"enabled = {enabled}")

        where = "WHERE " + " AND ".join(conditions)

        count_result = self._query(f"SELECT count(DISTINCT rule_id) as total FROM detection_rules {where}")
        total = count_result["rows"][0]["total"] if count_result and count_result["rows"] else 0

        rows_result = self._query(f"""
            SELECT DISTINCT rule_id, name, severity, enabled, quality_score, mitre_ids
            FROM detection_rules {where}
            ORDER BY name
            LIMIT {int(limit)} OFFSET {int(offset)}
        """)
        rows = rows_result["rows"] if rows_result else []

        return {"rows": rows, "total": total}

    def get_gaps_analysis(self) -> Optional[dict]:
        """Blind spots by tactic, unmapped rules, quick-win suggestions."""
        if not self.enabled:
            return None

        # All techniques with tactic
        all_tech = self._query(
            "SELECT id as technique_id, name, tactic FROM mitre_techniques ORDER BY tactic, id"
        )
        if not all_tech:
            return None
        techniques = all_tech["rows"]

        # Covered techniques
        covered = self._query("""
            SELECT DISTINCT t.technique_id
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE dr.space = 'default' AND dr.mitre_ids IS NOT NULL
        """)
        covered_set = set()
        if covered:
            for r in covered["rows"]:
                covered_set.add(r["technique_id"].split(".")[0])

        # Group blind spots by tactic
        by_tactic: dict[str, list] = {}
        for t in techniques:
            tid = t["technique_id"]
            if tid not in covered_set:
                tac = t["tactic"] or "unknown"
                if tac not in by_tactic:
                    by_tactic[tac] = []
                by_tactic[tac].append({"id": tid, "name": t["name"]})

        # Unmapped rules (rules with no MITRE mapping)
        unmapped = self._query("""
            SELECT DISTINCT rule_id, name, severity, enabled, quality_score
            FROM detection_rules
            WHERE space = 'default' AND (mitre_ids IS NULL OR len(mitre_ids) = 0)
            ORDER BY severity, name
            LIMIT 100
        """)
        unmapped_rules = unmapped["rows"] if unmapped else []

        # Quick wins: disabled higher-quality rules (quality >= 20, severity critical/high)
        quick = self._query("""
            SELECT DISTINCT rule_id, name, severity, quality_score, mitre_ids
            FROM detection_rules
            WHERE space = 'default' AND enabled = 0
              AND quality_score >= 20 AND severity IN ('critical', 'high')
            ORDER BY quality_score DESC, severity
            LIMIT 20
        """)
        quick_wins = quick["rows"] if quick else []

        # Systems with lowest coverage
        sys_cov = self._query("""
            SELECT s.id, s.name,
                   count(DISTINCT ad.detection_id) as applied_rules
            FROM systems s
            LEFT JOIN applied_detections ad ON ad.system_id = s.id
            GROUP BY s.id, s.name
            ORDER BY applied_rules ASC
        """)
        systems_coverage = sys_cov["rows"] if sys_cov else []

        return {
            "blind_spots_by_tactic": by_tactic,
            "total_blind_spots": sum(len(v) for v in by_tactic.values()),
            "unmapped_rules": unmapped_rules,
            "quick_wins": quick_wins,
            "systems_coverage": systems_coverage,
        }

    def test_connection(self) -> dict:
        if not self.enabled:
            return {"ok": False, "error": "TIDE integration not configured"}
        result = self._query("SELECT count(*) as rule_count FROM detection_rules WHERE space = 'default'")
        if result and result["rows"]:
            return {"ok": True, "rule_count": result["rows"][0]["rule_count"]}
        return {"ok": False, "error": "Failed to query TIDE"}


_tide_service: Optional[TideService] = None


def get_tide_service() -> TideService:
    global _tide_service
    if _tide_service is None:
        _tide_service = TideService()
    return _tide_service


def reset_tide_service():
    global _tide_service
    _tide_service = None
