"""Prometheus ``/metrics`` endpoint (opt-in) for SIEM / Elastic-Agent scraping.

Gated by ``ION_METRICS_ENABLED`` (default off) — when disabled the route returns
404 and does no work, so a closed endpoint isn't advertised (same posture as the
MCP endpoint). Optional ``ION_METRICS_TOKEN`` adds a bearer-token check for
defence-in-depth on top of network isolation.

Exposes:
  - ``ion_build_info{version}``
  - ``ion_http_requests_total{method,route,status}`` + ``ion_http_request_duration_seconds{method,route}``
    (route = the FastAPI path template, so cardinality is bounded by the route set)
  - ``ion_circuit_breaker_state{integration}`` (0=closed,1=half_open,2=open) + ``…_failures``
  - ``ion_db_pool_connections{state}`` (Postgres QueuePool only; SQLite dev pool has no counts)

Multi-worker note: ION runs N uvicorn workers. Set ``PROMETHEUS_MULTIPROC_DIR``
to a shared writable dir so counters/histograms aggregate across workers; without
it each worker reports only its own view (correct for a single worker / dev). The
runtime gauges are set at scrape time and, in multiproc mode, aggregate with
``max`` (so an open breaker on any worker surfaces).
"""

from __future__ import annotations

import logging
import os
import time

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)
router = APIRouter()

_TRUTHY = {"1", "true", "yes", "on"}


def metrics_enabled() -> bool:
    return os.environ.get("ION_METRICS_ENABLED", "").strip().lower() in _TRUTHY


# Lazy/guarded import — the feature is opt-in, so the app must boot even if the
# library is somehow absent.
try:
    import prometheus_client as _prom
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    _PROM_OK = True
except Exception as _imp_err:  # pragma: no cover - only if dep missing
    _PROM_OK = False
    logger.info("prometheus_client unavailable (%s); /metrics will 503 if enabled", _imp_err)


if _PROM_OK:
    _MULTIPROC = bool(os.environ.get("PROMETHEUS_MULTIPROC_DIR"))

    HTTP_REQUESTS = Counter(
        "ion_http_requests_total", "HTTP requests processed",
        ["method", "route", "status"],
    )
    HTTP_LATENCY = Histogram(
        "ion_http_request_duration_seconds", "HTTP request latency (s)",
        ["method", "route"],
    )
    BUILD_INFO = Gauge(
        "ion_build_info", "ION build info (always 1)", ["version"],
        multiprocess_mode="max",
    )
    CB_STATE = Gauge(
        "ion_circuit_breaker_state",
        "Integration circuit-breaker state (0=closed,1=half_open,2=open)",
        ["integration"], multiprocess_mode="max",
    )
    CB_FAILURES = Gauge(
        "ion_circuit_breaker_failures", "Circuit-breaker consecutive failures",
        ["integration"], multiprocess_mode="max",
    )
    DB_POOL = Gauge(
        "ion_db_pool_connections", "SQLAlchemy connection-pool counts",
        ["state"], multiprocess_mode="max",
    )

    _CB_STATE_VAL = {"closed": 0, "half_open": 1, "open": 2}


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Record request count + latency, labelled by the matched route template."""

    async def dispatch(self, request: Request, call_next):
        if not _PROM_OK:
            return await call_next(request)
        start = time.perf_counter()
        response = await call_next(request)
        try:
            route = request.scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            if template != "/metrics":  # don't self-instrument the scrape
                HTTP_REQUESTS.labels(request.method, template, str(response.status_code)).inc()
                HTTP_LATENCY.labels(request.method, template).observe(time.perf_counter() - start)
        except Exception:  # never let metrics break a request
            pass
        return response


def _refresh_runtime_gauges() -> None:
    """Set the pull-style gauges from current process state (called on scrape)."""
    try:
        import ion
        BUILD_INFO.labels(ion.__version__).set(1)
    except Exception:
        pass
    try:
        from ion.core.circuit_breaker import get_all_breaker_status
        for b in get_all_breaker_status():
            name = b.get("name", "unknown")
            CB_STATE.labels(name).set(_CB_STATE_VAL.get(b.get("state"), -1))
            CB_FAILURES.labels(name).set(b.get("failure_count", 0) or 0)
    except Exception:
        pass
    try:
        from ion.storage.database import get_engine
        pool = get_engine().pool
        # QueuePool (Postgres) exposes these; SQLite's pool does not — guard each.
        for attr in ("checkedin", "checkedout", "overflow"):
            fn = getattr(pool, attr, None)
            if callable(fn):
                try:
                    DB_POOL.labels(attr).set(fn())
                except Exception:
                    pass
    except Exception:
        pass


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    if not metrics_enabled():
        raise HTTPException(status_code=404, detail="Not found")
    if not _PROM_OK:
        raise HTTPException(status_code=503, detail="prometheus_client not installed")

    token = os.environ.get("ION_METRICS_TOKEN", "").strip()
    if token and request.headers.get("authorization", "") != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="metrics token required")

    _refresh_runtime_gauges()
    if _MULTIPROC:
        registry = CollectorRegistry()
        _prom.multiprocess.MultiProcessCollector(registry)
        payload = generate_latest(registry)
    else:
        payload = generate_latest()
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)
