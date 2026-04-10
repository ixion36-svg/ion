"""TIDE integration service — queries TIDE's external SQL API for detection data."""

import asyncio
import logging
import os
import threading
import time
from typing import Any, Optional

import httpx

from ion.core.config import get_tide_config, get_ssl_verify
from ion.core.circuit_breaker import tide_breaker

logger = logging.getLogger(__name__)


# Per-process micro-cache for identical SQL within a short window. Detection
# Engineering pages fan out 6+ parallel queries on load; without this, every
# concurrent fetch hits TIDE independently and a slow DuckDB amplifies into a
# storm of 504s.
_QUERY_CACHE: dict[str, tuple[float, Optional[dict]]] = {}
_CACHE_TTL_SECONDS = 8.0
_CACHE_LOCK = threading.Lock()
_MAX_CACHE_ENTRIES = 256


# Statuses we consider transient and retry with backoff.
_RETRY_STATUSES = {429, 500, 502, 503, 504}


# ION-side throttle. TIDE's DuckDB serializes writes and is slow under
# contention; if we let every parallel caller hit it at once, the upstream
# proxy starts returning 504 and our worker pool gets stuck waiting. The
# semaphore enforces a max concurrent in-flight TIDE query count per process.
# Acquired non-blockingly inside _query — if we can't get a slot, we treat it
# as an immediate transient failure (cached negative + breaker tick) so the
# caller returns fast instead of pinning a worker thread.
_TIDE_MAX_CONCURRENT = int(os.environ.get("ION_TIDE_MAX_CONCURRENT", "3"))
_TIDE_SEMAPHORE = threading.BoundedSemaphore(_TIDE_MAX_CONCURRENT)
# Hard upper bound on how long _query is allowed to hold a worker thread,
# regardless of httpx timeout / retries / waits. Used as a sanity check.
_TIDE_TOTAL_BUDGET_S = float(os.environ.get("ION_TIDE_TOTAL_BUDGET_S", "20"))


def _cache_get(sql: str) -> tuple[bool, Optional[dict]]:
    """Return (hit, value) — hit=True means we returned a cached entry."""
    with _CACHE_LOCK:
        entry = _QUERY_CACHE.get(sql)
        if not entry:
            return False, None
        ts, val = entry
        if time.time() - ts > _CACHE_TTL_SECONDS:
            _QUERY_CACHE.pop(sql, None)
            return False, None
        return True, val


def _cache_put(sql: str, value: Optional[dict]) -> None:
    with _CACHE_LOCK:
        if len(_QUERY_CACHE) >= _MAX_CACHE_ENTRIES:
            # Drop the oldest entry to bound memory
            oldest_key = min(_QUERY_CACHE, key=lambda k: _QUERY_CACHE[k][0])
            _QUERY_CACHE.pop(oldest_key, None)
        _QUERY_CACHE[sql] = (time.time(), value)


class TideService:
    """Client for TIDE's /api/external/query endpoint."""

    def __init__(self):
        cfg = get_tide_config()
        self.url = (cfg.get("url") or "").rstrip("/")
        self.api_key = cfg.get("api_key") or ""
        self.enabled = cfg.get("enabled", False) and bool(self.url) and bool(self.api_key)
        self.verify = get_ssl_verify() if cfg.get("verify_ssl", True) else False
        self.space = cfg.get("space") or os.environ.get("ION_TIDE_SPACE", "default")

    async def query_async(self, sql: str, retries: int = 1) -> Optional[dict]:
        """Async wrapper around _query that doesn't block the event loop.

        Use this from any async FastAPI handler. Internally it just defers
        the sync httpx call to a thread pool worker, but it ensures the
        single-threaded asyncio event loop is never stalled by a slow TIDE.
        """
        return await asyncio.to_thread(self._query, sql, retries)

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        if not self.enabled:
            return None

        # 1. Cache hit short-circuits everything (including 504 storms).
        hit, cached = _cache_get(sql)
        if hit:
            return cached

        # 2. Circuit breaker — if TIDE is down, fail fast and serve None.
        if not tide_breaker.can_execute():
            logger.debug("TIDE circuit breaker OPEN — skipping query")
            return None

        # 3. Concurrency throttle. If too many TIDE queries are already in
        #    flight from this process, fail fast (cached negative) instead
        #    of pinning a worker thread. This is the difference between
        #    "the page shows partial data" and "the whole app falls over".
        if not _TIDE_SEMAPHORE.acquire(blocking=False):
            logger.info("TIDE concurrency limit reached — shedding query")
            _cache_put(sql, None)
            return None

        start_t = time.time()
        try:
            for attempt in range(retries + 1):
                # Hard total-budget guard — bail before another network call
                # if we've already burned the per-query budget on backoff.
                if time.time() - start_t > _TIDE_TOTAL_BUDGET_S:
                    logger.warning("TIDE total budget exceeded, giving up")
                    tide_breaker.record_failure()
                    _cache_put(sql, None)
                    return None

                try:
                    resp = httpx.post(
                        f"{self.url}/api/external/query",
                        json={"sql": sql},
                        headers={
                            "X-TIDE-API-KEY": self.api_key,
                            "Content-Type": "application/json",
                        },
                        verify=self.verify,
                        # Tight per-request timeout: 8s read, 3s connect.
                        # 1 retry max → worst-case ~16s + backoff, fits inside
                        # the 20s _TIDE_TOTAL_BUDGET_S above.
                        timeout=httpx.Timeout(8.0, connect=3.0),
                    )
                except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                    if attempt < retries:
                        backoff = 0.5 * (2 ** attempt)
                        logger.info(
                            "TIDE %s, retrying in %.1fs (%d/%d)",
                            type(e).__name__, backoff, attempt + 1, retries,
                        )
                        time.sleep(backoff)
                        continue
                    logger.warning("TIDE connection error after %d retries: %s", retries, type(e).__name__)
                    tide_breaker.record_failure()
                    _cache_put(sql, None)
                    return None
                except Exception as e:
                    logger.error("TIDE unexpected error: %s", type(e).__name__)
                    tide_breaker.record_failure()
                    _cache_put(sql, None)
                    return None

                if resp.status_code == 200:
                    tide_breaker.record_success()
                    try:
                        data = resp.json()
                    except Exception:
                        tide_breaker.record_failure()
                        _cache_put(sql, None)
                        return None
                    _cache_put(sql, data)
                    return data

                # Transient 5xx — retry once with short backoff
                if resp.status_code in _RETRY_STATUSES and attempt < retries:
                    backoff = 0.5 * (2 ** attempt)
                    logger.info(
                        "TIDE %d, retrying in %.1fs (%d/%d)",
                        resp.status_code, backoff, attempt + 1, retries,
                    )
                    time.sleep(backoff)
                    continue

                # Hard fail — 4xx or out of retries on 5xx.
                logger.warning("TIDE query failed: %s", resp.status_code)
                tide_breaker.record_failure()
                _cache_put(sql, None)
                return None

            return None
        finally:
            _TIDE_SEMAPHORE.release()

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
            JOIN detection_rules dr ON dr.rule_id = ad.detection_id AND dr.space = '{self.space}'
            WHERE ad.system_id = '{system_id}'
            ORDER BY dr.severity DESC, dr.name
        """)
        system["detections"] = det_result["rows"] if det_result else []

        # Get total rules count for coverage calculation
        total_result = self._query(
            f"SELECT count(DISTINCT rule_id) as total FROM detection_rules WHERE space = '{self.space}'"
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
            JOIN detection_rules dr ON dr.rule_id = ad.detection_id AND dr.space = '{self.space}',
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
        stats = self._query(f"""
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
            WHERE dr.space = '{self.space}'
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
        sys_cov = self._query(f"""
            SELECT
                t.technique_id,
                s.name as system_name,
                s.id as system_id
            FROM applied_detections ad
            JOIN detection_rules dr ON dr.rule_id = ad.detection_id AND dr.space = '{self.space}'
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
            f"SELECT count(DISTINCT rule_id) as total FROM detection_rules WHERE space = '{self.space}'"
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
        """Overall detection posture: totals, severity breakdown, quality, coverage.

        Consolidated into TWO SQL round-trips (was 7) to reduce DuckDB lock
        contention and 504 risk.
        """
        if not self.enabled:
            return None

        # Round-trip 1: everything from detection_rules + mitre coverage in ONE CTE query.
        result = self._query(f"""
            WITH
            rules AS (
                SELECT DISTINCT rule_id, severity, enabled, quality_score, mitre_ids
                FROM detection_rules WHERE space = '{self.space}'
            ),
            totals AS (
                SELECT
                    count(*) AS total_rules,
                    count(*) FILTER (WHERE enabled = 1) AS enabled_rules,
                    count(*) FILTER (WHERE enabled = 0) AS disabled_rules,
                    count(*) FILTER (WHERE mitre_ids IS NULL OR len(mitre_ids) = 0) AS unmapped_rules,
                    count(*) FILTER (WHERE quality_score >= 30) AS q_excellent,
                    count(*) FILTER (WHERE quality_score >= 20 AND quality_score < 30) AS q_good,
                    count(*) FILTER (WHERE quality_score >= 10 AND quality_score < 20) AS q_fair,
                    count(*) FILTER (WHERE quality_score < 10) AS q_poor,
                    round(avg(quality_score), 1) AS avg_quality,
                    min(quality_score) AS min_quality,
                    max(quality_score) AS max_quality
                FROM rules
            ),
            sev AS (
                SELECT severity,
                       count(*) AS cnt,
                       count(*) FILTER (WHERE enabled = 1) AS enabled,
                       count(*) FILTER (WHERE enabled = 0) AS disabled
                FROM rules
                GROUP BY severity
            ),
            coverage AS (
                SELECT count(DISTINCT t.technique_id) AS covered
                FROM rules r, LATERAL unnest(r.mitre_ids) AS t(technique_id)
                WHERE r.mitre_ids IS NOT NULL
            )
            SELECT
                t.*,
                c.covered AS covered_techniques,
                (SELECT json_group_array(json_object(
                    'severity', s.severity, 'count', s.cnt, 'enabled', s.enabled, 'disabled', s.disabled
                )) FROM sev s) AS severity_json
            FROM totals t, coverage c
        """)

        if not result or not result["rows"]:
            return None
        r = result["rows"][0]

        # Parse the severity JSON array (DuckDB json_group_array returns a string)
        severity = {}
        sev_raw = r.get("severity_json")
        if sev_raw:
            import json as _json
            try:
                sev_list = _json.loads(sev_raw) if isinstance(sev_raw, str) else sev_raw
                for s in sev_list:
                    severity[s["severity"]] = {
                        "total": s["count"], "enabled": s["enabled"], "disabled": s["disabled"]
                    }
            except Exception:
                pass

        # Round-trip 2: counts from mitre_techniques + systems (small, fast tables).
        counts = self._query(
            "SELECT (SELECT count(*) FROM mitre_techniques) AS total_techniques, "
            "(SELECT count(*) FROM systems) AS total_systems"
        )
        total_techniques = 0
        total_systems = 0
        if counts and counts["rows"]:
            total_techniques = counts["rows"][0].get("total_techniques", 0)
            total_systems = counts["rows"][0].get("total_systems", 0)

        return {
            "total_rules": r["total_rules"],
            "enabled_rules": r["enabled_rules"],
            "disabled_rules": r["disabled_rules"],
            "severity": severity,
            "quality": {
                "excellent": r["q_excellent"],
                "good": r["q_good"],
                "fair": r["q_fair"],
                "poor": r["q_poor"],
                "avg_quality": r["avg_quality"],
                "min_quality": r["min_quality"],
                "max_quality": r["max_quality"],
            },
            "unmapped_rules": r["unmapped_rules"],
            "covered_techniques": r["covered_techniques"],
            "total_techniques": total_techniques,
            "total_systems": total_systems,
        }

    def get_disabled_critical_high(self) -> list[dict]:
        """Return disabled rules with critical or high severity — quick wins to enable."""
        if not self.enabled:
            return []
        result = self._query(f"""
            SELECT DISTINCT rule_id, name, severity, quality_score, mitre_ids
            FROM detection_rules
            WHERE space = '{self.space}' AND enabled = 0
              AND severity IN ('critical', 'high')
            ORDER BY
                CASE severity WHEN 'critical' THEN 0 ELSE 1 END,
                quality_score DESC
        """)
        return result["rows"] if result else []

    def get_playbooks_with_kill_chains(self) -> list[dict]:
        """Return playbooks (baselines) with steps, techniques, detections, and system coverage.

        Uses the full TIDE baseline model:
        - playbooks → playbook_steps (with tactic)
        - step_techniques (many techniques per step)
        - step_detections (many detection rules per step)
        - system_baselines (which systems have this baseline applied)
        """
        if not self.enabled:
            return []
        pb = self._query("SELECT id, name, description FROM playbooks ORDER BY name")
        if not pb or not pb["rows"]:
            return []
        playbooks = pb["rows"]

        for p in playbooks:
            # Get steps
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
                    step_id = r["step_id"]

                    # Get multi-techniques from step_techniques junction table
                    st = self._query(f"SELECT technique_id FROM step_techniques WHERE step_id = '{step_id}'")
                    techniques = [row["technique_id"] for row in (st["rows"] if st else [])]
                    # Fallback to legacy single technique_id if junction table empty
                    if not techniques and r.get("technique_id"):
                        techniques = [r["technique_id"]]

                    # Get multi-detections from step_detections junction table
                    sd = self._query(f"SELECT rule_ref, note, source FROM step_detections WHERE step_id = '{step_id}'")
                    detections = [{"rule_ref": row["rule_ref"], "note": row.get("note", ""), "source": row.get("source", "")} for row in (sd["rows"] if sd else [])]
                    # Fallback to legacy single required_rule
                    if not detections and r.get("required_rule"):
                        detections = [{"rule_ref": r["required_rule"], "note": "", "source": "legacy"}]

                    step_list.append({
                        "step_id": step_id,
                        "order": r["step_number"],
                        "name": r["title"],
                        "description": r["description"],
                        "techniques": techniques,
                        "detections": detections,
                        "tactic": r.get("tactic"),
                    })
                    all_tids.update(techniques)
            p["steps"] = step_list

            # Get systems that have this baseline applied
            sys_result = self._query(f"""
                SELECT sb.system_id, s.name as system_name
                FROM system_baselines sb
                JOIN systems s ON s.id = sb.system_id
                WHERE sb.playbook_id = '{p["id"]}'
                ORDER BY s.name
            """)
            p["applied_systems"] = sys_result["rows"] if sys_result else []

            # For each technique in steps, get rule coverage
            if all_tids:
                tid_list = ",".join(f"'{t}'" for t in all_tids)
                cov = self._query(f"""
                    SELECT t.technique_id,
                           count(DISTINCT dr.rule_id) as rule_count,
                           count(DISTINCT dr.rule_id) FILTER (WHERE dr.enabled = 1) as enabled_rules
                    FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
                    WHERE dr.space = '{self.space}' AND t.technique_id IN ({tid_list})
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

        conditions = [f"space = '{self.space}'"]
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

        # Single round-trip: count(*) OVER() gives total alongside the page rows.
        rows_result = self._query(f"""
            SELECT DISTINCT rule_id, name, severity, enabled, quality_score, mitre_ids,
                   count(*) OVER() AS _total
            FROM detection_rules {where}
            ORDER BY name
            LIMIT {int(limit)} OFFSET {int(offset)}
        """)
        if not rows_result or not rows_result["rows"]:
            return {"rows": [], "total": 0}
        rows = rows_result["rows"]
        total = rows[0].get("_total", 0)
        # Strip the _total column from the output
        for r in rows:
            r.pop("_total", None)
        return {"rows": rows, "total": total}

    def get_gaps_analysis(self) -> Optional[dict]:
        """Blind spots by tactic, unmapped rules, quick-win suggestions.

        4 round-trips (was 5). The technique + covered queries are simple
        enough that DuckDB handles them quickly. The big posture query
        (7→2 consolidation) is where the real savings are.
        """
        if not self.enabled:
            return None

        # 1. All techniques
        all_tech = self._query(
            "SELECT id AS technique_id, name, tactic FROM mitre_techniques ORDER BY tactic, id"
        )
        if not all_tech:
            return None
        techniques = all_tech["rows"]

        # 2. Covered techniques
        covered = self._query(f"""
            SELECT DISTINCT t.technique_id
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE dr.space = '{self.space}' AND dr.mitre_ids IS NOT NULL
        """)
        covered_set: set[str] = set()
        if covered:
            for r in covered["rows"]:
                covered_set.add(r["technique_id"].split(".")[0])

        by_tactic: dict[str, list] = {}
        for t in techniques:
            tid = t["technique_id"]
            if tid not in covered_set:
                tac = t["tactic"] or "unknown"
                if tac not in by_tactic:
                    by_tactic[tac] = []
                by_tactic[tac].append({"id": tid, "name": t["name"]})

        # Remaining small queries — kept separate because DuckDB rejects
        # UNION ALL across CTEs with ORDER BY / LIMIT in sub-queries.
        # These are tiny reads (< 100 rows each) so the lock hold time is short.
        unmapped = self._query(f"""
            SELECT DISTINCT rule_id, name, severity, enabled, quality_score
            FROM detection_rules
            WHERE space = '{self.space}' AND (mitre_ids IS NULL OR len(mitre_ids) = 0)
            ORDER BY severity, name
            LIMIT 100
        """)
        unmapped_rules = unmapped["rows"] if unmapped else []

        quick = self._query(f"""
            SELECT DISTINCT rule_id, name, severity, quality_score, mitre_ids
            FROM detection_rules
            WHERE space = '{self.space}' AND enabled = 0
              AND quality_score >= 20 AND severity IN ('critical', 'high')
            ORDER BY quality_score DESC, severity
            LIMIT 20
        """)
        quick_wins = quick["rows"] if quick else []

        sys_cov = self._query("""
            SELECT s.id, s.name,
                   count(DISTINCT ad.detection_id) AS applied_rules
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

    def get_system_use_case_coverage(self, system_id: str) -> Optional[dict]:
        """Compute per-use-case detection coverage scoped to a single CyAB/TIDE system.

        For each TIDE playbook (use case), walks each step's MITRE techniques
        and asks: of the rules currently *applied to this system* via
        applied_detections, do any cover the technique? Returns a list of
        use cases with per-step coverage state and an overall % per use case.

        This is the per-system equivalent of get_playbooks_with_kill_chains
        (which is global / not scoped to one system).
        """
        if not self.enabled or not system_id:
            return None

        safe_id = system_id.replace("'", "''")

        # 1. Pull this system's applied rules and the MITRE techniques they
        #    cover. One round-trip via LATERAL unnest.
        applied = self._query(f"""
            SELECT DISTINCT t.technique_id
            FROM applied_detections ad
            JOIN detection_rules dr
              ON dr.rule_id = ad.detection_id AND dr.space = '{self.space}'
            JOIN systems s ON s.id = ad.system_id,
                 LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE ad.system_id = '{safe_id}'
              AND dr.mitre_ids IS NOT NULL
        """)
        if applied is None:
            return None

        # Build a set of covered technique IDs and a set of "parent" IDs so a
        # use case step listing T1003 is covered by an applied rule tagged
        # with T1003.001 (and vice-versa).
        covered_set: set[str] = set()
        for row in (applied.get("rows") or []):
            tid = (row.get("technique_id") or "").strip()
            if not tid:
                continue
            covered_set.add(tid)
            if "." in tid:
                covered_set.add(tid.split(".", 1)[0])

        def _is_covered(tid: str) -> bool:
            if not tid:
                return False
            tid = tid.strip()
            if tid in covered_set:
                return True
            # Sub-technique on the use case side, parent in the system's coverage
            if "." in tid and tid.split(".", 1)[0] in covered_set:
                return True
            # Parent on the use case side, any sub on the system's coverage
            prefix = tid + "."
            return any(c.startswith(prefix) for c in covered_set)

        # 2. Pull the playbooks (use cases) and walk steps + step_techniques.
        playbooks = self.get_playbooks_with_kill_chains() or []

        out_use_cases: list[dict] = []
        overall_total_steps = 0
        overall_covered_steps = 0
        overall_partial_steps = 0

        for pb in playbooks:
            steps = pb.get("steps") or []
            uc_total = len(steps)
            uc_covered = 0
            uc_partial = 0
            uc_steps_out: list[dict] = []
            for s in steps:
                techs = s.get("techniques") or []
                if not techs:
                    state = "unknown"
                else:
                    cov = sum(1 for t in techs if _is_covered(t))
                    if cov == 0:
                        state = "blind"
                    elif cov == len(techs):
                        state = "covered"
                    else:
                        state = "partial"
                uc_steps_out.append({
                    "order": s.get("order"),
                    "name": s.get("name"),
                    "tactic": s.get("tactic"),
                    "techniques": techs,
                    "state": state,
                    "covered_techniques": [t for t in techs if _is_covered(t)],
                    "gap_techniques": [t for t in techs if not _is_covered(t)],
                })
                if state == "covered":
                    uc_covered += 1
                elif state == "partial":
                    uc_partial += 1
            overall_total_steps += uc_total
            overall_covered_steps += uc_covered
            overall_partial_steps += uc_partial

            # Step-weighted score: covered = 1, partial = 0.5, blind/unknown = 0
            uc_score = (
                round(((uc_covered + uc_partial * 0.5) / uc_total) * 100)
                if uc_total else 0
            )
            if uc_score >= 80:
                uc_state = "covered"
            elif uc_score >= 30:
                uc_state = "partial"
            else:
                uc_state = "blind"

            out_use_cases.append({
                "id": pb.get("id"),
                "name": pb.get("name"),
                "description": pb.get("description"),
                "step_count": uc_total,
                "covered_steps": uc_covered,
                "partial_steps": uc_partial,
                "blind_steps": uc_total - uc_covered - uc_partial,
                "score": uc_score,
                "state": uc_state,
                "steps": uc_steps_out,
            })

        overall_score = (
            round(((overall_covered_steps + overall_partial_steps * 0.5) / overall_total_steps) * 100)
            if overall_total_steps else 0
        )

        return {
            "system_id": system_id,
            "use_cases": out_use_cases,
            "summary": {
                "use_case_count": len(out_use_cases),
                "fully_covered": sum(1 for uc in out_use_cases if uc["state"] == "covered"),
                "partial": sum(1 for uc in out_use_cases if uc["state"] == "partial"),
                "blind": sum(1 for uc in out_use_cases if uc["state"] == "blind"),
                "total_steps": overall_total_steps,
                "covered_steps": overall_covered_steps,
                "partial_steps": overall_partial_steps,
                "overall_score": overall_score,
            },
        }

    def test_connection(self) -> dict:
        if not self.enabled:
            return {"ok": False, "error": "TIDE integration not configured"}
        result = self._query(f"SELECT count(*) as rule_count FROM detection_rules WHERE space = '{self.space}'")
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
    # Drop the per-process query cache too — config may have changed.
    with _CACHE_LOCK:
        _QUERY_CACHE.clear()
