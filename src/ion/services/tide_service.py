"""TIDE integration service — queries TIDE's external SQL API for detection data."""

import asyncio
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal, Optional, Union

import httpx

from ion.core.circuit_breaker import tide_breaker
from ion.core.config import get_ssl_verify, get_tide_config
from ion.services import attack_catalogue

logger = logging.getLogger(__name__)


# TIDE queries are hand-built SQL strings shipped to TIDE's /api/external/query
# executor, so a destination's siem_id and space MUST be constrained to an
# identifier charset: they are interpolated into string literals with no other
# guard. `*` is a real value (a Wazuh rule deployed to every agent group).
_DESTINATION_PART_RE = re.compile(r"^[A-Za-z0-9_.\-* ]{1,64}$")

@dataclass(frozen=True)
class Destination:
    """Where TIDE deployed a rule: a space on one SIEM.

    On Elastic the space is a Kibana space; on Wazuh it is an agent group, or
    `*` for every group. TIDE's detection_rules key is (rule_id, siem_id,
    space), so the same rule_id at two destinations is two deployed rules.
    """

    space: str
    #: None means this space on any SIEM, which is what a space-only setting
    #: (Settings > TIDE, from before TIDE had SIEM ids) asks for.
    siem_id: Optional[str] = None

    def __post_init__(self):
        for part in (self.space, self.siem_id):
            if part is not None and not _DESTINATION_PART_RE.match(part):
                raise ValueError("Invalid TIDE destination")

    @property
    def key(self) -> str:
        return f"{self.siem_id or ''}|{self.space}"

    @classmethod
    def from_key(cls, key: str) -> "Destination":
        siem_id, sep, space = key.strip().partition("|")
        if not sep:
            return cls(space=siem_id)
        return cls(space=space, siem_id=siem_id or None)

    @property
    def label(self) -> str:
        return f"{self.siem_id or 'any SIEM'} / {self.space}"


#: Which rules a query reads: one destination, or None for every destination
#: in the tenant, which is how TIDE 7 itself counts a client's rules.
RuleScope = Optional[Destination]


def scope_label(scope: RuleScope) -> str:
    return scope.label if scope else "all destinations"


@dataclass(frozen=True)
class _RuleColumns:
    """Columns that older TIDE lacks: siem_id and rule_type on
    detection_rules, and the destination a step detection names."""

    siem_id: bool = True
    rule_type: bool = True
    step_siem_id: bool = True


FailureKind = Literal[
    "auth_rejected", "no_tenant", "tenant_forbidden", "tenant_missing",
    "bad_request", "unreachable", "server_error", "overloaded",
]

_FAILURE_ADVICE: dict[FailureKind, str] = {
    "auth_rejected": (
        "TIDE rejected the API key. From TIDE 7 a key works only while its "
        "owner is an active TIDE user: keys created while TIDE ran with "
        "AUTH_DISABLED belong to dev-user-001 and stop working. Create a key "
        "as a real TIDE user and save it in Settings > TIDE."
    ),
    "no_tenant": (
        "The API key's owner has no tenant in TIDE. Assign that user to the "
        "client in TIDE's user administration."
    ),
    "tenant_forbidden": (
        "The API key's owner cannot open the requested tenant. Check Client ID "
        "in Settings > TIDE, or the user's tenant assignments in TIDE."
    ),
    "tenant_missing": (
        "TIDE has no database for the requested tenant. Check Client ID in "
        "Settings > TIDE."
    ),
    "bad_request": "TIDE refused the query.",
    "unreachable": (
        "ION could not reach TIDE. Check the URL in Settings > TIDE and that "
        "TIDE is running."
    ),
    "server_error": "TIDE answered with a server error.",
    "overloaded": "TIDE is busy. Try again shortly.",
}


@dataclass(frozen=True)
class TideFailure:
    """Why a TIDE query returned nothing, with TIDE's own detail text."""

    kind: FailureKind
    detail: str = ""
    status: Optional[int] = None

    @property
    def message(self) -> str:
        return _FAILURE_ADVICE[self.kind]

    def as_dict(self) -> dict:
        return {"kind": self.kind, "status": self.status,
                "detail": self.detail, "message": self.message}


@dataclass(frozen=True)
class TableAbsent:
    """TIDE answered, but this tenant has no such table (or column): an older
    TIDE, or a TIDE 7 table not created until its feature first runs."""

    table: str


#: Rows (possibly none), the table missing from this TIDE, or a failed read.
TideRows = Union[list, TableAbsent, TideFailure]


def _classify(status: int, detail: str) -> FailureKind:
    if status == 401:
        return "auth_rejected"
    if status == 403:
        return "no_tenant" if "no tenant access" in detail.lower() else "tenant_forbidden"
    if status == 404:
        return "tenant_missing"
    if status == 429:
        return "overloaded"
    if status >= 500:
        return "server_error"
    return "bad_request"


def _response_detail(resp: httpx.Response) -> str:
    try:
        detail = (resp.json() or {}).get("detail", "")
    except Exception:
        detail = resp.text
    return str(detail)[:300]

#: TIDE refuses any statement longer than this. Documented in the upstream
#: README (github.com/sigeauk/tide) alongside the SELECT/WITH-only rule and
#: the keyword blocklist. Queries here are hand-built strings, so this is a
#: real ceiling: anything that interpolates a list of unknown length can
#: cross it, and the rejection comes back as a 4xx that _query turns into
#: None, which every caller reads as "no rows".
_MAX_SQL_CHARS = 4000


def _strip_sql_comments(sql: str) -> str:
    """Drop ``--`` comments, leaving quoted text alone.

    TIDE refuses a statement if a word like LOAD, SET or UPDATE appears
    anywhere in it, comments included, so an explanatory comment such as
    "load-bearing" took down the whole posture query.
    """
    out, i, n, quoted = [], 0, len(sql), False
    while i < n:
        ch = sql[i]
        if ch == "'":
            quoted = not quoted
        elif not quoted and sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end == -1 else end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _quoted_id_batches(ids, budget: int):
    """Split ids into quoted SQL list fragments, each at most `budget` chars.

    Measured 2026-10-12 against the technique-coverage query, whose body is
    439 characters: that leaves room for roughly 296 subtechnique ids or 445
    parent ids in one statement. A baseline playbook can list more, and the
    rejection used to surface as an empty coverage map, which the caller then
    rendered as every technique having no rules. A query too long to send was
    being drawn as a total absence of detection.

    Also escapes each id. The previous inline f-string did not, so a quote
    inside a technique id broke the statement.
    """
    batch: list[str] = []
    size = 0
    for raw in ids:
        token = "'" + str(raw).replace("'", "''") + "'"
        extra = len(token) + (1 if batch else 0)
        if batch and size + extra > budget:
            yield ",".join(batch)
            batch, size = [token], len(token)
        else:
            batch.append(token)
            size += extra
    if batch:
        yield ",".join(batch)


# Per-process micro-cache for identical SQL within a short window. Detection
# Engineering pages fan out 6+ parallel queries on load; without this, every
# concurrent fetch hits TIDE independently and a slow DuckDB amplifies into a
# storm of 504s.
_QUERY_CACHE: dict[str, tuple[float, Union[dict, TideFailure]]] = {}
_CACHE_TTL_SECONDS = 8.0
_CACHE_LOCK = threading.Lock()
_MAX_CACHE_ENTRIES = 256


# Shared persistent httpx client — avoids per-request connection overhead.
_tide_client: Optional[httpx.Client] = None


def _get_tide_client(verify_ssl) -> httpx.Client:
    """Return (and lazily create) the module-level shared sync client."""
    global _tide_client
    if _tide_client is None or _tide_client.is_closed:
        _tide_client = httpx.Client(
            verify=verify_ssl,
            timeout=httpx.Timeout(8.0, connect=3.0),
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=3),
        )
    return _tide_client


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


def _cache_get(sql: str) -> tuple[bool, Optional[Union[dict, TideFailure]]]:
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


def _cache_put(sql: str, value: Union[dict, TideFailure]) -> None:
    with _CACHE_LOCK:
        if len(_QUERY_CACHE) >= _MAX_CACHE_ENTRIES:
            # Drop the oldest entry to bound memory
            oldest_key = min(_QUERY_CACHE, key=lambda k: _QUERY_CACHE[k][0])
            _QUERY_CACHE.pop(oldest_key, None)
        _QUERY_CACHE[sql] = (time.time(), value)


#: The system an applied detection belongs to: the one it is pinned to, or
#: its host's system when it is pinned to a host (TIDE's
#: _applied_detection_ids reads both). Needs `hosts h` joined on ad.host_id.
_APPLIED_SYSTEM = "CASE WHEN ad.host_id IS NULL THEN ad.system_id ELSE h.system_id END"


class TideService:
    """Client for TIDE's /api/external/query endpoint."""

    # Learnt once from TIDE's schema; None until asked. Whether baselines are
    # copied per system (TIDE 6), whether rule scores are percentages
    # (TIDE 5.1+), and which multi-SIEM rule columns exist.
    _per_system_baselines: Optional[bool] = None
    _percent_scores: Optional[bool] = None
    _columns: Optional[_RuleColumns] = None

    #: Every destination unless a caller narrows it.
    scope: RuleScope = None
    configured_scope: RuleScope = None
    #: Why the most recent query on this service came back empty-handed;
    #: cleared by the next answered query.
    last_failure: Optional[TideFailure] = None

    def __init__(self):
        cfg = get_tide_config()
        self.url = (cfg.get("url") or "").rstrip("/")
        self.api_key = cfg.get("api_key") or ""
        self.enabled = cfg.get("enabled", False) and bool(self.url) and bool(self.api_key)
        self.verify = get_ssl_verify() if cfg.get("verify_ssl", True) else False
        self.configured_scope = self._scope_from_setting(cfg.get("space") or "")
        self.scope = self.configured_scope
        self.client_id = cfg.get("client_id") or ""
        self._resolved_client_id: Optional[str] = None

        # Startup diagnostic — log exactly what's configured so TIDE issues
        # are diagnosable from `docker logs ion` without guessing.
        if self.enabled:
            logger.info(
                "TIDE service initialized: url=%s scope=%s client_id=%s "
                "api_key=%s verify_ssl=%s",
                self.url, scope_label(self.scope),
                self.client_id[:8] if self.client_id else "(auto)",
                "(set)" if self.api_key else "(unset)",
                self.verify,
            )
        else:
            missing = []
            if not cfg.get("enabled", False):
                missing.append("ION_TIDE_ENABLED=false")
            if not self.url:
                missing.append("ION_TIDE_URL empty")
            if not self.api_key:
                missing.append("ION_TIDE_API_KEY empty")
            logger.warning("TIDE service DISABLED: %s", ", ".join(missing) or "unknown reason")

    @staticmethod
    def _scope_from_setting(space: str) -> RuleScope:
        space = space.strip()
        if not space:
            return None
        try:
            return Destination(space=space)
        except ValueError:
            # Widening to every destination beats taking TIDE pages down over
            # a setting nobody can see is wrong; the log says which.
            logger.error("TIDE space setting %r is not a valid space; reading all destinations", space)
            return None

    # -----------------------------------------------------------------------
    # Rule scope and identity. Every detection_rules query goes through these
    # rather than writing its own space filter.
    # -----------------------------------------------------------------------

    def _rule_columns(self) -> _RuleColumns:
        if self._columns is None:
            if self._query("SELECT count(*) AS n FROM detection_rules") is None:
                return _RuleColumns()
            self._columns = _RuleColumns(
                siem_id=self._query("SELECT siem_id FROM detection_rules LIMIT 0") is not None,
                rule_type=self._query("SELECT rule_type FROM detection_rules LIMIT 0") is not None,
                step_siem_id=self._query("SELECT siem_id FROM step_detections LIMIT 0") is not None,
            )
        return self._columns

    # Every rule query aliases detection_rules as `dr`.

    def _scope_sql(self) -> str:
        """The active scope as a predicate on detection_rules."""
        if self.scope is None:
            return "TRUE"
        clause = f"dr.space = '{self.scope.space}'"
        if self.scope.siem_id is not None and self._rule_columns().siem_id:
            clause = f"dr.siem_id = '{self.scope.siem_id}' AND {clause}"
        return clause

    def _rule_identity(self) -> str:
        """The expression that tells two deployed rules apart. rule_id alone
        is only unique inside one destination."""
        if self._rule_columns().siem_id:
            return "(dr.rule_id, dr.siem_id, dr.space)"
        return "(dr.rule_id, dr.space)"

    def _kind_sql(self) -> str:
        if self._rule_columns().rule_type:
            return "CASE WHEN dr.rule_type = 'wazuh' THEN 'wazuh' ELSE 'elastic' END"
        return "'elastic'"

    def _applied_rules_sql(self) -> str:
        """FROM-clause body joining applied_detections to the rules in scope.

        detection_id is a step_detections id (a CVE detection id on the
        vulnerability path), never a rule id: the step detection names the
        rule in rule_ref and the destination it runs at, as TIDE resolves it
        (inventory_engine._counted_scope_resolver). Joining detection_id to
        rule_id matched nothing, so every system read as having no rules.
        Rows with no siem_id are hand-made mappings that name a rule only.
        """
        dest = "TRUE"
        if self._rule_columns().siem_id and self._rule_columns().step_siem_id:
            dest = ("(coalesce(sd.siem_id, '') = '' OR (dr.siem_id = sd.siem_id "
                    "AND dr.space = coalesce(nullif(sd.space, ''), 'default')))")
        return ("applied_detections ad LEFT JOIN hosts h ON h.id = ad.host_id "
                "JOIN step_detections sd ON sd.id = ad.detection_id "
                f"JOIN detection_rules dr ON dr.rule_id = sd.rule_ref AND {dest} AND {self._scope_sql()}")

    def _destination_cols(self) -> str:
        """siem_id, space and kind for a rule listing, so the UI can say
        where a rule runs and whether it is Wazuh or Elastic."""
        siem = "dr.siem_id" if self._rule_columns().siem_id else "NULL"
        return f"{siem} AS siem_id, dr.space AS space, {self._kind_sql()} AS kind"

    async def query_async(self, sql: str, retries: int = 1) -> Optional[dict]:
        """Async wrapper around _query that doesn't block the event loop.

        Use this from any async FastAPI handler. Internally it just defers
        the sync httpx call to a thread pool worker, but it ensures the
        single-threaded asyncio event loop is never stalled by a slow TIDE.
        """
        return await asyncio.to_thread(self._query, sql, retries)

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        """Rows from TIDE, or None. The reason for a None is on last_failure."""
        if not self.enabled:
            return None
        outcome = self._run(sql, retries)
        return None if isinstance(outcome, TideFailure) else outcome

    def _run(self, sql: str, retries: int = 1) -> Union[dict, TideFailure]:
        outcome = self._execute(sql, retries)
        self.last_failure = outcome if isinstance(outcome, TideFailure) else None
        return outcome

    def _fail(self, sql: str, failure: TideFailure, *, trip: bool) -> TideFailure:
        # Only an unreachable or failing TIDE trips the breaker. A 401 or 403
        # is TIDE up and answering; opening the breaker on it replaced the
        # reason with "circuit open" and hid the fix from the operator.
        if trip:
            tide_breaker.record_failure()
        _cache_put(sql, failure)
        return failure

    def _execute(self, sql: str, retries: int = 1) -> Union[dict, TideFailure]:
        # 0. Length ceiling. TIDE refuses any statement over _MAX_SQL_CHARS,
        #    and refuses it as a 4xx that _query turns into None. Every
        #    caller reads None as "no rows", so an over-long query arrives as
        #    an absence of data rather than as an error. Catching it here
        #    names the offender in the log instead of leaving a page quietly
        #    reporting zero coverage. See _quoted_id_batches.
        sql = _strip_sql_comments(sql)
        if len(sql) > _MAX_SQL_CHARS:
            logger.error(
                "TIDE query is %d chars, over the %d limit, so it was not sent. "
                "Build it with _quoted_id_batches. sql=%s",
                len(sql), _MAX_SQL_CHARS, sql[:200],
            )
            return TideFailure("bad_request", f"query is {len(sql)} characters, over TIDE's {_MAX_SQL_CHARS}")

        # 1. Cache hit short-circuits everything (including 504 storms).
        hit, cached = _cache_get(sql)
        if hit:
            return cached

        # 2. Circuit breaker — if TIDE is down, fail fast.
        if not tide_breaker.can_execute():
            logger.debug("TIDE circuit breaker OPEN — skipping query")
            return TideFailure("unreachable", "ION paused TIDE queries after repeated failures")

        # 3. Concurrency throttle. If too many TIDE queries are already in
        #    flight from this process, fail fast (cached negative) instead
        #    of pinning a worker thread. This is the difference between
        #    "the page shows partial data" and "the whole app falls over".
        if not _TIDE_SEMAPHORE.acquire(blocking=False):
            logger.info("TIDE concurrency limit reached — shedding query")
            return self._fail(sql, TideFailure("overloaded", "too many TIDE queries in flight"), trip=False)

        start_t = time.time()
        try:
            for attempt in range(retries + 1):
                # Hard total-budget guard — bail before another network call
                # if we've already burned the per-query budget on backoff.
                if time.time() - start_t > _TIDE_TOTAL_BUDGET_S:
                    logger.warning("TIDE total budget exceeded, giving up")
                    return self._fail(sql, TideFailure("unreachable", "TIDE did not answer in time"), trip=True)

                # TIDE 4.x accepts an optional client_id on the POST body.
                # Prefer explicit config, else the auto-resolved single-tenant
                # id, else omit entirely (TIDE 3.x ignores unknown fields and
                # 4.x infers for single-tenant keys).
                payload: dict[str, Any] = {"sql": sql}
                tenant = self.client_id or self._resolved_client_id
                if tenant:
                    payload["client_id"] = tenant

                try:
                    client = _get_tide_client(self.verify)
                    resp = client.post(
                        f"{self.url}/api/external/query",
                        json=payload,
                        headers={
                            "X-TIDE-API-KEY": self.api_key,
                            "Content-Type": "application/json",
                        },
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
                    return self._fail(sql, TideFailure("unreachable", type(e).__name__), trip=True)
                except Exception as e:
                    logger.error("TIDE unexpected error: %s", type(e).__name__)
                    return self._fail(sql, TideFailure("unreachable", type(e).__name__), trip=True)

                if resp.status_code == 200:
                    tide_breaker.record_success()
                    try:
                        data = resp.json()
                    except Exception:
                        logger.error("TIDE 200 but response is not JSON: %s", resp.text[:200])
                        return self._fail(sql, TideFailure("server_error", "response was not JSON", 200), trip=True)
                    rows = data.get("rows", []) if isinstance(data, dict) else []
                    elapsed = round((time.time() - start_t) * 1000)
                    logger.debug(
                        "TIDE query OK: %d rows in %dms | %s",
                        len(rows), elapsed, sql[:80],
                    )
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

                detail = _response_detail(resp)

                # TIDE 4.x: 400 when a multi-tenant API key is missing
                # client_id. Try to auto-resolve once via /api/external/clients
                # and retry this same attempt if we get exactly one tenant.
                if (
                    resp.status_code == 400
                    and not tenant
                    and self._resolved_client_id is None
                    and "client_id" in detail.lower()
                ):
                    resolved = self._discover_single_tenant()
                    if resolved:
                        self._resolved_client_id = resolved
                        logger.info("TIDE auto-resolved client_id=%s", resolved[:8])
                        # Re-issue immediately without burning a retry slot
                        continue

                kind = _classify(resp.status_code, detail)
                log = logger.error if kind in ("auth_rejected", "no_tenant", "tenant_forbidden", "tenant_missing") else logger.warning
                log(
                    "TIDE %d (%s): %s | url=%s client_id=%s | sql=%s",
                    resp.status_code, kind, detail, self.url, tenant or "(none)", sql[:60],
                )
                # A 400 is TIDE refusing this one statement, and 401/403/404
                # are TIDE refusing the key or tenant: TIDE is up either way.
                return self._fail(
                    sql, TideFailure(kind, detail, resp.status_code),
                    trip=kind in ("server_error", "overloaded"),
                )

            return TideFailure("unreachable", "no attempt was made")
        finally:
            _TIDE_SEMAPHORE.release()

    # -----------------------------------------------------------------------
    # TIDE 4.x tenant discovery
    # -----------------------------------------------------------------------

    def discover_clients(self) -> list[dict[str, str]]:
        """Return [{id, name, slug}] for tenants this API key can access.

        TIDE 3.x does not expose this endpoint and will return 404 — that is
        handled as "empty list" so callers can treat it as "nothing to show".
        """
        if not self.enabled:
            return []
        try:
            client = _get_tide_client(self.verify)
            resp = client.get(
                f"{self.url}/api/external/clients",
                headers={"X-TIDE-API-KEY": self.api_key},
            )
        except Exception as e:
            logger.warning("TIDE discover_clients error: %s", type(e).__name__)
            return []
        if resp.status_code == 404:
            logger.info("TIDE discover_clients: 404 (TIDE 3.x or endpoint missing)")
            return []
        if resp.status_code == 401:
            logger.error(
                "TIDE discover_clients: 401 — API key rejected. Key may be "
                "from TIDE 3.x (no created_by_user_id). Create a new key in "
                "TIDE 4.x admin."
            )
            return []
        if resp.status_code != 200:
            try:
                detail = (resp.json() or {}).get("detail", resp.text[:200])
            except Exception:
                detail = resp.text[:200]
            logger.warning("TIDE discover_clients %d: %s", resp.status_code, detail)
            return []
        try:
            clients = (resp.json() or {}).get("clients", []) or []
            logger.info(
                "TIDE discover_clients: %d tenant(s) — %s",
                len(clients),
                ", ".join(c.get("name", "?") for c in clients[:5]),
            )
            return clients
        except Exception:
            return []

    def _discover_single_tenant(self) -> Optional[str]:
        """If the API key has exactly one tenant, return its id; else None."""
        clients = self.discover_clients()
        if len(clients) == 1:
            return clients[0].get("id")
        return None

    def get_systems(self) -> list[dict[str, Any]]:
        result = self._query(
            "SELECT id, name, classification, description FROM systems ORDER BY name"
        )
        return result["rows"] if result else []

    def get_system_detail(self, system_id: str) -> Optional[dict]:
        # system_id is a user-controlled path parameter; escape the single-quote
        # break-out before interpolation (matches get_system_use_case_coverage).
        safe_id = system_id.replace("'", "''")
        result = self._query(
            f"SELECT id, name, classification, description FROM systems WHERE id = '{safe_id}'"
        )
        if not result or not result["rows"]:
            return None
        system = result["rows"][0]

        # Get applied detections with rule details
        det_result = self._query(f"""
            SELECT DISTINCT dr.rule_id, dr.name, dr.severity, dr.enabled, dr.quality_score,
                   dr.mitre_ids, {self._destination_cols()}
            FROM {self._applied_rules_sql()}
            WHERE {_APPLIED_SYSTEM} = '{safe_id}'
            ORDER BY dr.severity DESC, dr.name
        """)
        system["detections"] = det_result["rows"] if det_result else []

        # Get total rules count for coverage calculation
        total_result = self._query(self._total_rules_sql())
        system["total_rules"] = total_result["rows"][0]["total"] if total_result and total_result["rows"] else 0

        return system

    def get_detection_rules(self, search: str = "", limit: int = 50) -> list[dict]:
        where = f"WHERE {self._scope_sql()}"
        if search:
            safe = search.replace("'", "''")
            where += f" AND (dr.name ILIKE '%{safe}%' OR array_to_string(dr.mitre_ids, ',') ILIKE '%{safe}%')"
        result = self._query(f"""
            SELECT DISTINCT dr.rule_id, dr.name, dr.severity, dr.enabled, dr.quality_score,
                   dr.mitre_ids, {self._destination_cols()}
            FROM detection_rules dr
            {where}
            ORDER BY dr.name
            LIMIT {int(limit)}
        """)
        return result["rows"] if result else []

    def get_mitre_coverage(self, system_id: str) -> dict:
        """Get MITRE technique coverage for a system."""
        # system_id is user-controlled; escape the single-quote break-out.
        safe_id = system_id.replace("'", "''")
        # Techniques covered by this system's detections
        # dr.enabled = 1: a rule applied to this system but switched off is
        # not covering anything on it. Applied and running are different
        # facts, and only the second one detects an intrusion.
        covered = self._query(f"""
            SELECT DISTINCT t.technique_id
            FROM {self._applied_rules_sql()},
            LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE {_APPLIED_SYSTEM} = '{safe_id}' AND dr.enabled = 1
        """)
        covered_ids = {r["technique_id"] for r in (covered["rows"] if covered else [])}

        # The catalogue is ION's own: TIDE 6 does not serve it (see attack_catalogue).
        techniques = [dict(t) for t in attack_catalogue.techniques()]

        return {
            "covered": list(covered_ids),
            "total_techniques": len(techniques),
            "techniques": techniques,
        }

    def get_global_mitre_coverage(self) -> Optional[dict]:
        """Get global MITRE technique coverage across all detection rules and systems."""
        if not self.enabled:
            return None

        # 1. All known MITRE techniques, from ION's catalogue (see attack_catalogue).
        techniques = [dict(t) for t in attack_catalogue.techniques()]
        tech_catalog = {t["technique_id"]: t for t in techniques}

        # 2. Per-technique rule stats (LATERAL unnest for DuckDB compatibility)
        rid = self._rule_identity()
        stats = self._query(f"""
            SELECT
                t.technique_id,
                count(DISTINCT {rid}) as rule_count,
                count(dr.quality_score) as scored_rules,
                round(avg(dr.quality_score), 1) as avg_quality,
                count(DISTINCT {rid}) FILTER (WHERE dr.severity = 'critical') as critical_rules,
                count(DISTINCT {rid}) FILTER (WHERE dr.severity = 'high') as high_rules,
                count(DISTINCT {rid}) FILTER (WHERE dr.severity = 'medium') as medium_rules,
                count(DISTINCT {rid}) FILTER (WHERE dr.severity = 'low') as low_rules,
                count(DISTINCT {rid}) FILTER (WHERE dr.enabled = 1) as enabled_rules
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE {self._scope_sql()}
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
                s["_quality_sum"] += (r["avg_quality"] or 0) * r["scored_rules"]
                s["_quality_n"] += r["scored_rules"]

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
            FROM {self._applied_rules_sql()}
            JOIN systems s ON s.id = {_APPLIED_SYSTEM},
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

        # 4. Build result.
        #
        # Three states, not two. A technique whose rules are all switched off
        # is neither covered nor untouched: someone wrote the detection and
        # nothing is running it. That is a different problem from having no
        # rule at all, and a cheaper one, because enabling beats authoring.
        # Collapsing it into either bucket destroys the only fact that tells
        # them apart.
        #
        # Measured on the live tenant 2026-10-12: 164 techniques had a rule
        # and 94 had an enabled one. The previous test counted a technique as
        # covered the moment any rule mentioned it, so 70 techniques were
        # reported as covered by rules nothing was running, and none of them
        # appeared as a gap anywhere.
        result_techs = {}
        covered_ids = set()
        inactive_ids = []
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
            if tid in sys_map:
                entry["systems"] = sys_map[tid]

            if (entry.get("enabled_rules") or 0) > 0:
                covered_ids.add(tid)
            elif (entry.get("rule_count") or 0) > 0:
                inactive_ids.append(tid)
            else:
                blind_spots.append(tid)
            result_techs[tid] = entry

        # Total rules
        total_result = self._query(self._total_rules_sql())
        total_rules = total_result["rows"][0]["total"] if total_result and total_result["rows"] else 0

        return {
            "techniques": result_techs,
            "total_techniques": len(tech_catalog),
            "covered_techniques": len(covered_ids),
            # Rules written, none switched on. Kept apart from blind_spots so
            # a reader can tell "nobody built this" from "nobody turned it on".
            "inactive_techniques": inactive_ids,
            "blind_spots": blind_spots,
            # Stated rather than left to be inferred from the name. "Covered"
            # here means something is actually running, not that a rule exists.
            "coverage_basis": "at least one enabled rule",
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

        excellent, good, fair = self._quality_bands()
        # Round-trip 1: everything from detection_rules + mitre coverage in ONE CTE query.
        result = self._query(f"""
            WITH
            rules AS (
                SELECT DISTINCT {self._rule_identity()} AS rid, {self._kind_sql()} AS kind,
                       dr.severity, dr.enabled, dr.quality_score, dr.mitre_ids
                FROM detection_rules dr WHERE {self._scope_sql()}
            ),
            totals AS (
                SELECT
                    count(*) AS total_rules,
                    count(*) FILTER (WHERE enabled = 1) AS enabled_rules,
                    count(*) FILTER (WHERE enabled = 0) AS disabled_rules,
                    count(*) FILTER (WHERE mitre_ids IS NULL OR len(mitre_ids) = 0) AS unmapped_rules,
                    count(*) FILTER (WHERE quality_score >= {excellent}) AS q_excellent,
                    count(*) FILTER (WHERE quality_score >= {good} AND quality_score < {excellent}) AS q_good,
                    count(*) FILTER (WHERE quality_score >= {fair} AND quality_score < {good}) AS q_fair,
                    count(*) FILTER (WHERE quality_score < {fair}) AS q_poor,
                    count(*) FILTER (WHERE quality_score IS NULL) AS q_unscored,
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
            kinds AS (
                SELECT kind, count(*) AS cnt, count(*) FILTER (WHERE enabled = 1) AS enabled
                FROM rules
                GROUP BY kind
            ),
            coverage AS (
                -- enabled = 1 is load-bearing. This figure reaches SOC
                -- Health as technique_coverage_pct and then the detection
                -- coverage grade; without it a technique counted as covered
                -- because a disabled rule mentioned it. Measured on the live
                -- tenant: 164 techniques had a rule, 94 had an enabled one.
                SELECT count(DISTINCT t.technique_id) AS covered
                FROM rules r, LATERAL unnest(r.mitre_ids) AS t(technique_id)
                WHERE r.mitre_ids IS NOT NULL AND r.enabled = 1
            )
            SELECT
                t.*,
                c.covered AS covered_techniques,
                (SELECT json_group_array(json_object(
                    'severity', s.severity, 'count', s.cnt, 'enabled', s.enabled, 'disabled', s.disabled
                )) FROM sev s) AS severity_json,
                (SELECT json_group_array(json_object(
                    'kind', k.kind, 'count', k.cnt, 'enabled', k.enabled
                )) FROM kinds k) AS kinds_json
            FROM totals t, coverage c
        """)

        if not result or not result["rows"]:
            return None
        r = result["rows"][0]

        severity = {
            s["severity"]: {"total": s["count"], "enabled": s["enabled"], "disabled": s["disabled"]}
            for s in _json_rows(r.get("severity_json"))
        }
        rules_by_kind = {
            k["kind"]: {"total": k["count"], "enabled": k["enabled"]}
            for k in _json_rows(r.get("kinds_json"))
        }

        # Round-trip 2: the systems count.
        counts = self._query(
            "SELECT (SELECT count(*) FROM systems) AS total_systems"
        )
        total_systems = 0
        if counts and counts["rows"]:
            total_systems = counts["rows"][0].get("total_systems", 0)

        # TIDE 6 moved the ATT&CK catalogue into a reference database its query
        # API refuses to read, so the total comes from ION's own catalogue.
        total_techniques = len(attack_catalogue.techniques())

        return {
            "total_rules": r["total_rules"],
            "enabled_rules": r["enabled_rules"],
            "disabled_rules": r["disabled_rules"],
            "rules_by_kind": rules_by_kind,
            "scope": self.scope.key if self.scope else None,
            "severity": severity,
            "quality": {
                "scale": "percent" if self._scores_are_percentages() else "points",
                "excellent": r["q_excellent"],
                "good": r["q_good"],
                "fair": r["q_fair"],
                "poor": r["q_poor"],
                # Mostly Wazuh rules, which TIDE leaves unscored. Counted
                # apart so they are neither poor nor missing from the total.
                "unscored": r["q_unscored"],
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
            SELECT DISTINCT dr.rule_id, dr.name, dr.severity, dr.quality_score, dr.mitre_ids,
                   {self._destination_cols()}
            FROM detection_rules dr
            WHERE {self._scope_sql()} AND dr.enabled = 0
              AND dr.severity IN ('critical', 'high')
            ORDER BY
                CASE dr.severity WHEN 'critical' THEN 0 ELSE 1 END,
                dr.quality_score DESC NULLS LAST
        """)
        return result["rows"] if result else []

    # Lower bounds of the excellent, good and fair quality bands. TIDE 5.1
    # moved rule scores from points (about 0-40) to a percentage; the
    # percentage bands follow TIDE's own colouring (green from 80, amber from 50).
    _POINT_BANDS = (30, 20, 10)
    _PERCENT_BANDS = (80, 50, 25)

    def _scores_are_percentages(self) -> bool:
        """True from TIDE 5.1. Scoring v2 arrived with checkedRule.rule_id,
        a tenant table every TIDE creates up front (rule_score_history, which
        carries scoring_version, only exists once rules have been synced).
        Assumed until TIDE can be asked, since current TIDE scores that way."""
        if self._percent_scores is None:
            if self._query("SELECT count(*) AS n FROM checkedRule") is None:
                return True
            self._percent_scores = (
                self._query("SELECT rule_id FROM checkedRule LIMIT 0") is not None
            )
        return self._percent_scores

    def _quality_bands(self) -> tuple[int, int, int]:
        return self._PERCENT_BANDS if self._scores_are_percentages() else self._POINT_BANDS

    def _baselines_are_per_system(self) -> Optional[bool]:
        """True on TIDE 6, where playbooks carry a system_id; None if TIDE
        could not be asked. The external query API refuses schema lookups,
        so the column itself is the probe: when the table answers and the
        column is refused, the column is absent."""
        if self._per_system_baselines is None:
            if self._query("SELECT count(*) AS n FROM playbooks") is None:
                return None
            self._per_system_baselines = (
                self._query("SELECT system_id FROM playbooks LIMIT 0") is not None
            )
        return self._per_system_baselines

    def _playbook_steps(self, playbook_id: str) -> tuple[list[dict], set[str]]:
        """A baseline's steps with their techniques and detections, and every
        technique the steps name."""
        # Escape ids before interpolation. These come from prior TIDE query
        # results (second-order), but a crafted id in the TIDE tenant data
        # could otherwise alter the follow-up query — same escaping as the
        # user-facing system_id path.
        safe_pid = str(playbook_id).replace("'", "''")
        # Get steps
        steps = self._query(f"""
            SELECT id as step_id, step_number, title, description,
                   technique_id, required_rule, tactic
            FROM playbook_steps
            WHERE playbook_id = '{safe_pid}'
            ORDER BY step_number
        """)
        step_list = []
        all_tids = set()
        if steps:
            for r in steps["rows"]:
                step_id = r["step_id"]
                safe_step = str(step_id).replace("'", "''")

                # Get multi-techniques from step_techniques junction table
                st = self._query(f"SELECT technique_id FROM step_techniques WHERE step_id = '{safe_step}'")
                techniques = [row["technique_id"] for row in (st["rows"] if st else [])]
                # Fallback to legacy single technique_id if junction table empty
                if not techniques and r.get("technique_id"):
                    techniques = [r["technique_id"]]

                # Get multi-detections from step_detections junction table
                sd = self._query(f"SELECT rule_ref, note, source FROM step_detections WHERE step_id = '{safe_step}'")
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
        return step_list, all_tids

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
        per_system = self._baselines_are_per_system()
        if per_system is None:
            return []
        # TIDE 6 gives every system its own copy of each baseline it applies,
        # in the same table. The catalogue is the templates, the rows with no
        # system; listing every row showed each baseline once per system.
        where = "WHERE system_id IS NULL " if per_system else ""
        pb = self._query(f"SELECT id, name, description FROM playbooks {where}ORDER BY name")
        if not pb or not pb["rows"]:
            return []
        playbooks = pb["rows"]

        for p in playbooks:
            safe_pid = str(p["id"]).replace("'", "''")
            step_list, all_tids = self._playbook_steps(p["id"])
            p["steps"] = step_list

            # Get systems that have this baseline applied
            if per_system:
                # A system's link points at its own copy, and TIDE 6 cleared
                # the copy's template_id, so the copy is found by name.
                safe_name = str(p["name"]).replace("'", "''")
                sys_result = self._query(f"""
                    SELECT DISTINCT pc.system_id, s.name as system_name
                    FROM playbooks pc
                    JOIN systems s ON s.id = pc.system_id
                    WHERE pc.system_id IS NOT NULL AND pc.name = '{safe_name}'
                    ORDER BY s.name
                """)
            else:
                sys_result = self._query(f"""
                    SELECT sb.system_id, s.name as system_name
                    FROM system_baselines sb
                    JOIN systems s ON s.id = sb.system_id
                    WHERE sb.playbook_id = '{safe_pid}'
                    ORDER BY s.name
                """)
            p["applied_systems"] = sys_result["rows"] if sys_result else []

            # For each technique in steps, get rule coverage
            if all_tids:
                # Built as prefix + ids + suffix so the budget is exact by
                # construction rather than a guessed headroom figure.
                rid = self._rule_identity()
                prefix = (
                    "SELECT t.technique_id, "
                    f"count(DISTINCT {rid}) as rule_count, "
                    f"count(DISTINCT {rid}) FILTER (WHERE dr.enabled = 1) "
                    "as enabled_rules "
                    "FROM detection_rules dr, "
                    "LATERAL unnest(dr.mitre_ids) AS t(technique_id) "
                    f"WHERE {self._scope_sql()} AND t.technique_id IN ("
                )
                suffix = ") GROUP BY t.technique_id"
                budget = _MAX_SQL_CHARS - len(prefix) - len(suffix)

                cov_map = {}
                measured = True
                for id_list in _quoted_id_batches(sorted(all_tids), budget):
                    cov = self._query(prefix + id_list + suffix)
                    if cov is None:
                        # One failed batch means the map is incomplete, and an
                        # incomplete map is indistinguishable from "these
                        # techniques have no rules". Say it is unmeasured
                        # rather than let a reader draw the wrong conclusion.
                        measured = False
                        continue
                    for r in cov["rows"]:
                        cov_map[r["technique_id"]] = {
                            "rule_count": r["rule_count"],
                            "enabled_rules": r["enabled_rules"],
                        }
                p["technique_coverage"] = cov_map
                p["technique_coverage_measured"] = measured
            else:
                p["technique_coverage"] = {}
                p["technique_coverage_measured"] = True

        return playbooks

    def get_rules_paginated(
        self, search: str = "", severity: str = "", enabled: str = "",
        offset: int = 0, limit: int = 50
    ) -> dict:
        """Paginated rule browser with filters."""
        if not self.enabled:
            return {"rows": [], "total": 0}

        conditions = [self._scope_sql()]
        if search:
            safe = search.replace("'", "''")
            conditions.append(
                f"(dr.name ILIKE '%{safe}%' OR array_to_string(dr.mitre_ids, ',') ILIKE '%{safe}%')"
            )
        if severity:
            safe_sev = severity.replace("'", "''")
            conditions.append(f"dr.severity = '{safe_sev}'")
        if enabled in ("1", "0"):
            conditions.append(f"dr.enabled = {enabled}")

        where = "WHERE " + " AND ".join(conditions)

        # Single round-trip: count(*) OVER() gives total alongside the page
        # rows. The window runs over the de-duplicated CTE; over the DISTINCT
        # select itself it counted the rows before they were de-duplicated.
        rows_result = self._query(f"""
            WITH r AS (
                SELECT DISTINCT dr.rule_id, dr.name, dr.severity, dr.enabled, dr.quality_score,
                       dr.mitre_ids, {self._destination_cols()}
                FROM detection_rules dr {where}
            )
            SELECT *, count(*) OVER() AS _total FROM r
            ORDER BY name, rule_id
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

        # 1. All techniques, from ION's catalogue (see attack_catalogue).
        techniques = sorted(
            (dict(t) for t in attack_catalogue.techniques()),
            key=lambda t: (t["tactic"] is None, t["tactic"] or "", t["technique_id"]),
        )

        # 2. Covered techniques. enabled = 1, so a gap analysis cannot clear a
        # tactic on the strength of rules nobody switched on. This function
        # reports total_blind_spots, which is exactly the number that must not
        # be flattered.
        covered = self._query(f"""
            SELECT DISTINCT t.technique_id
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE {self._scope_sql()} AND dr.mitre_ids IS NOT NULL
              AND dr.enabled = 1
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
            SELECT DISTINCT dr.rule_id, dr.name, dr.severity, dr.enabled, dr.quality_score,
                   {self._destination_cols()}
            FROM detection_rules dr
            WHERE {self._scope_sql()} AND (dr.mitre_ids IS NULL OR len(dr.mitre_ids) = 0)
            ORDER BY dr.severity, dr.name
            LIMIT 100
        """)
        unmapped_rules = unmapped["rows"] if unmapped else []

        _, good, _ = self._quality_bands()
        quick = self._query(f"""
            SELECT DISTINCT dr.rule_id, dr.name, dr.severity, dr.quality_score, dr.mitre_ids,
                   {self._destination_cols()}
            FROM detection_rules dr
            WHERE {self._scope_sql()} AND dr.enabled = 0
              AND dr.quality_score >= {good} AND dr.severity IN ('critical', 'high')
            ORDER BY dr.quality_score DESC, dr.severity
            LIMIT 20
        """)
        quick_wins = quick["rows"] if quick else []

        sys_cov = self._query(f"""
            WITH applied AS (
                SELECT {_APPLIED_SYSTEM} AS system_id, {self._rule_identity()} AS rid
                FROM {self._applied_rules_sql()}
            )
            SELECT s.id, s.name, count(DISTINCT a.rid) AS applied_rules
            FROM systems s
            LEFT JOIN applied a ON a.system_id = s.id
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
            FROM {self._applied_rules_sql()},
                 LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE {_APPLIED_SYSTEM} = '{safe_id}'
              AND dr.mitre_ids IS NOT NULL AND dr.enabled = 1
        """)
        if applied is None:
            return None

        # also pull the rule refs applied to this system so
        # we can decorate each playbook-step's detection with applied=True/False.
        # The baseline view shows TIDE's recommended rules per step; flagging
        # which are actually live here is what makes "why is this covered"
        # meaningful — and what makes blind steps actionable ("apply rule X").
        # Compared by rule_ref: on TIDE 6+ a system's step detections belong
        # to its own copy of the baseline, so their ids never match the
        # template's.
        applied_rules = self._query(f"""
            SELECT DISTINCT sd.rule_ref
            FROM applied_detections ad
            LEFT JOIN hosts h ON h.id = ad.host_id
            JOIN step_detections sd ON sd.id = ad.detection_id
            WHERE {_APPLIED_SYSTEM} = '{safe_id}'
        """)
        applied_rule_ids: set[str] = set()
        for row in ((applied_rules or {}).get("rows") or []):
            rid = (row.get("rule_ref") or "").strip()
            if rid:
                applied_rule_ids.add(rid)

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

        # 2. The use cases applied to this system, walked step by step. TIDE
        #    grades a system on its own baselines: on TIDE 6 the system's
        #    copies (some exist only as a copy), before that the shared
        #    baselines linked in system_baselines. Scoring every template put
        #    steps nobody applied here into the denominator.
        per_system = self._baselines_are_per_system()
        if per_system is None:
            return None
        own = self._query(
            f"SELECT id, name, description FROM playbooks WHERE system_id = '{safe_id}' ORDER BY name"
            if per_system else
            "SELECT p.id, p.name, p.description FROM system_baselines sb "
            f"JOIN playbooks p ON p.id = sb.playbook_id WHERE sb.system_id = '{safe_id}' ORDER BY p.name"
        )
        if own is None:
            return None
        playbooks = [dict(pb, steps=self._playbook_steps(pb["id"])[0]) for pb in own["rows"]]

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
                # surface the TIDE-recommended detections per step
                # plus the analyst note (the "why") and a flag for whether
                # the rule is actually applied to this system. The frontend
                # baseline view renders these instead of just the technique
                # heat-grid — analysts get rule-level traceability.
                step_detections = []
                for d in (s.get("detections") or []):
                    if not isinstance(d, dict):
                        continue
                    rid = (d.get("rule_ref") or "").strip()
                    step_detections.append({
                        "rule_ref": rid,
                        "note": d.get("note") or "",
                        "source": d.get("source") or "",
                        "applied": rid in applied_rule_ids if rid else False,
                    })
                uc_steps_out.append({
                    "order": s.get("order"),
                    "name": s.get("name"),
                    "tactic": s.get("tactic"),
                    "techniques": techs,
                    "state": state,
                    "covered_techniques": [t for t in techs if _is_covered(t)],
                    "gap_techniques": [t for t in techs if not _is_covered(t)],
                    "detections": step_detections,
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

    def get_destinations(self) -> Optional[list[dict]]:
        """Every destination holding rules in this tenant, busiest first, or
        None when TIDE could not be asked."""
        if not self.enabled:
            return []
        siem = "dr.siem_id" if self._rule_columns().siem_id else "NULL"
        result = self._query(
            f"SELECT {siem} AS siem_id, dr.space AS space, {self._kind_sql()} AS kind, "
            "count(*) AS rule_count FROM detection_rules dr "
            "GROUP BY 1, 2, 3 ORDER BY rule_count DESC, 1, 2"
        )
        if result is None:
            return None
        destinations = []
        for r in result["rows"]:
            try:
                dest = Destination(space=r["space"], siem_id=r["siem_id"])
            except (ValueError, TypeError):
                logger.warning("TIDE destination %r/%r cannot be filtered on; left out",
                               r.get("siem_id"), r.get("space"))
                continue
            destinations.append({"key": dest.key, "siem_id": dest.siem_id, "space": dest.space,
                                 "kind": r["kind"], "rule_count": r["rule_count"]})
        return destinations

    def set_scope(self, scope: RuleScope) -> None:
        """Narrow every later query to one destination, or widen to all.
        Queries carry the scope in their SQL, so a cached answer cannot leak
        across a switch."""
        self.scope = scope
        logger.info("TIDE scope switched to: %s", scope_label(scope))

    def get_enabled_rule_counts_by_technique(self) -> Optional[list[dict]]:
        """[{tid, n}]: enabled rules per technique id in scope, or None."""
        result = self._query(f"""
            SELECT t.technique_id AS tid, count(DISTINCT {self._rule_identity()}) AS n
            FROM detection_rules dr, LATERAL unnest(dr.mitre_ids) AS t(technique_id)
            WHERE dr.enabled = 1 AND {self._scope_sql()}
            GROUP BY t.technique_id
        """)
        return result["rows"] if result else None

    # -----------------------------------------------------------------------
    # TIDE 7 tenant tables. TIDE creates several of these only when the
    # feature that writes them first runs, and older TIDE has none of them,
    # so "Unknown table" is an answer (TableAbsent), not a failure.
    # -----------------------------------------------------------------------

    def _tenant_rows(self, table: str, sql: str) -> "TideRows":
        if not self.enabled:
            return TideFailure("unreachable", "TIDE is not configured")
        outcome = self._run(sql)
        if isinstance(outcome, TideFailure):
            if outcome.kind == "bad_request" and "unknown table" in outcome.detail.lower():
                return TableAbsent(table)
            return outcome
        return [r for r in outcome.get("rows") or [] if isinstance(r, dict)]

    def _dest_sql(self, alias: str) -> str:
        """The active scope on a TIDE 7 table that names siem_id and space."""
        if self.scope is None:
            return "TRUE"
        clause = f"{alias}.space = '{self.scope.space}'"
        if self.scope.siem_id is not None:
            clause = f"{alias}.siem_id = '{self.scope.siem_id}' AND {clause}"
        return clause

    def get_rule_inventory(self, limit: int = 5000) -> "TideRows":
        """Every rule in scope with its Kibana id, which rule_alert_counts
        keys alerts on (rule_uuid = raw_data.id)."""
        cols = self._rule_columns()
        siem = "dr.siem_id" if cols.siem_id else "NULL"
        return self._tenant_rows("detection_rules", f"""
            SELECT dr.rule_id, dr.name, dr.severity, dr.enabled, dr.quality_score, dr.mitre_ids,
                   {siem} AS siem_id, dr.space AS space, {self._kind_sql()} AS kind,
                   json_extract_string(dr.raw_data, '$.id') AS rule_uuid
            FROM detection_rules dr WHERE {self._scope_sql()}
            ORDER BY dr.name, dr.rule_id LIMIT {int(limit)}
        """)

    def get_rule_issues(self) -> "TideRows":
        """Rule Monitoring's open findings in scope, rule and destination level."""
        return self._tenant_rows("rule_issues", f"""
            SELECT ri.issue, ri.cause, ri.siem_id, ri.space, ri.rule_id, ri.severity, ri.detail,
                   ri.first_seen, ri.last_seen
            FROM rule_issues ri WHERE ri.resolved_at IS NULL AND {self._dest_sql('ri')}
        """)

    def get_rule_alert_days(self, days: int) -> "TideRows":
        """Alerts per rule per UTC day for the last `days` days, any status."""
        return self._tenant_rows("rule_alert_counts", f"""
            SELECT rac.siem_id, rac.space, rac.rule_uuid, rac.rule_id, CAST(rac.day AS VARCHAR) AS day,
                   sum(rac.alerts) AS alerts
            FROM rule_alert_counts rac
            WHERE rac.day > current_date - INTERVAL {int(days)} DAY AND {self._dest_sql('rac')}
            GROUP BY 1, 2, 3, 4, 5
        """)

    def get_gitlab_issues(self) -> "TideRows":
        """GitLab issues TIDE opened for rule problems and has not seen closed."""
        return self._tenant_rows("gitlab_issues", """
            SELECT gi.iid, gi.title, gi.web_url, gi.state, gi.causes, gi.rules
            FROM gitlab_issues gi WHERE coalesce(gi.state, '') <> 'closed'
            ORDER BY gi.iid DESC
        """)

    def get_elastic_checks(self) -> "TideRows":
        return self._tenant_rows("rule_elastic_checks", f"""
            SELECT rec.rule_id, rec.siem_id, rec.space, rec.checked_at, rec.problems
            FROM rule_elastic_checks rec WHERE {self._dest_sql('rec')}
        """)

    def get_system_platforms(self) -> "TideRows":
        """[{id, name, platforms}]; platforms is TIDE 7's, so older TIDE
        reads as absent."""
        outcome = self._tenant_rows("systems", "SELECT s.id, s.name, s.platforms FROM systems s ORDER BY s.name")
        if isinstance(outcome, TideFailure) and outcome.kind == "bad_request" and "platforms" in outcome.detail:
            return TableAbsent("systems.platforms")
        return outcome

    def get_hosts(self) -> "TideRows":
        return self._tenant_rows("hosts", """
            SELECT h.id, h.system_id, h.name, h.os, h.source FROM hosts h
        """)

    def get_host_agents(self) -> "TideRows":
        return self._tenant_rows("host_agents", """
            SELECT ha.host_id, ha.siem_id, ha.space, ha.agent_id, ha.status,
                   CAST(ha.last_seen AS VARCHAR) AS last_seen
            FROM host_agents ha
        """)

    def get_wazuh_agents(self) -> "TideRows":
        """Every agent of every Wazuh destination as of its last read."""
        return self._tenant_rows("wazuh_agents", """
            SELECT wa.siem_id, wa.space, wa.agent_id, wa.name, wa.status,
                   CAST(wa.last_seen AS VARCHAR) AS last_seen
            FROM wazuh_agents wa
        """)

    def get_system_wazuh_sources(self) -> "TideRows":
        return self._tenant_rows("system_wazuh_agents", """
            SELECT swa.system_id, swa.siem_id, swa.space, swa.name_pattern FROM system_wazuh_agents swa
        """)

    def get_system_vulnerabilities(self) -> "TideRows":
        """Open findings per system and CVE (current = not resolved)."""
        return self._tenant_rows("host_vulnerabilities", """
            SELECT h.system_id, hv.cve_id, max(hv.severity) AS severity, max(hv.cvss) AS cvss,
                   max(hv.description) AS description, max(hv.package) AS package,
                   string_agg(DISTINCT h.name, ', ') AS hosts
            FROM host_vulnerabilities hv JOIN hosts h ON h.id = hv.host_id
            WHERE hv.resolved_at IS NULL
            GROUP BY 1, 2
        """)

    def get_system_sca_scores(self) -> "TideRows":
        return self._tenant_rows("host_sca_policies", """
            SELECT h.system_id, p.policy_id, p.name, avg(p.score) AS score, count(*) AS hosts
            FROM host_sca_policies p JOIN hosts h ON h.id = p.host_id
            WHERE p.score IS NOT NULL GROUP BY 1, 2, 3
        """)

    def get_system_sca_history(self, days: int = 70) -> "TideRows":
        return self._tenant_rows("host_sca_history", f"""
            SELECT h.system_id, CAST(date_trunc('week', hs.recorded_at) AS VARCHAR) AS week,
                   avg(hs.score) AS score
            FROM host_sca_history hs JOIN hosts h ON h.id = hs.host_id
            WHERE hs.recorded_at > current_date - INTERVAL {int(days)} DAY AND hs.score IS NOT NULL
            GROUP BY 1, 2 ORDER BY 1, 2
        """)

    def get_system_failed_checks(self) -> "TideRows":
        return self._tenant_rows("host_sca_checks", """
            SELECT h.system_id, c.policy_id, c.check_id, c.title, array_to_string(c.cis_ids, ', ') AS cis,
                   string_agg(DISTINCT h.name, ', ') AS hosts, count(DISTINCT h.id) AS host_count
            FROM host_sca_checks c JOIN hosts h ON h.id = c.host_id
            WHERE c.result = 'failed'
            GROUP BY 1, 2, 3, 4, 5
        """)

    def get_blind_spots_due(self) -> "TideRows":
        """Accepted blind spots whose review date has passed."""
        outcome = self._tenant_rows("blind_spots", """
            SELECT bs.id, bs.entity_type, bs.system_id, bs.reason, bs.override_type,
                   CAST(bs.review_by AS VARCHAR) AS review_by, bs.created_by
            FROM blind_spots bs
            WHERE bs.review_by IS NOT NULL AND bs.review_by < current_date
            ORDER BY bs.review_by
        """)
        if isinstance(outcome, TideFailure) and outcome.kind == "bad_request" and "review_by" in outcome.detail:
            return TableAbsent("blind_spots.review_by")
        return outcome

    def _total_rules_sql(self) -> str:
        return (f"SELECT count(DISTINCT {self._rule_identity()}) AS total "
                f"FROM detection_rules dr WHERE {self._scope_sql()}")

    def test_connection(self) -> dict:
        if not self.enabled:
            return {"ok": False, "error": "TIDE integration not configured"}
        outcome = self._run(self._total_rules_sql())
        if isinstance(outcome, TideFailure):
            return {"ok": False, "error": outcome.message, "failure": outcome.as_dict()}
        rows = outcome.get("rows") or []
        if not rows:
            return {"ok": False, "error": "TIDE answered with no rows"}
        return {"ok": True, "rule_count": rows[0]["total"], "scope": scope_label(self.scope)}


def _json_rows(raw: object) -> list[dict]:
    """A DuckDB json_group_array value, which arrives as a string."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return []
    return [r for r in parsed if isinstance(r, dict)] if isinstance(parsed, list) else []


_tide_service: Optional[TideService] = None


def get_tide_service() -> TideService:
    global _tide_service
    if _tide_service is None:
        _tide_service = TideService()
    return _tide_service


def reset_tide_service():
    global _tide_service, _tide_client
    _tide_service = None
    if _tide_client is not None and not _tide_client.is_closed:
        try:
            _tide_client.close()
        except Exception:
            pass
    _tide_client = None
    # Drop the per-process query cache too — config may have changed.
    with _CACHE_LOCK:
        _QUERY_CACHE.clear()


def get_playbooks_with_kill_chains() -> list[dict]:
    """Module-level convenience wrapper around
    ``get_tide_service().get_playbooks_with_kill_chains()``.

    Lets callers (e.g. ``cyab_scoping_engine``) reach the playbook catalogue
    without having to construct a service instance themselves, and gives
    tests a single attribute to monkeypatch.
    """
    return get_tide_service().get_playbooks_with_kill_chains()
