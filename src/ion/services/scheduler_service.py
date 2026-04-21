"""Generic cron-style job scheduler service.

Separate from ``report_scheduler_service`` (which is fixed to daily/weekly/
monthly report generation). This module:

* Provides a module-level registry of async handler functions keyed by a
  short ``handler_key``. Other services register work by decorating a
  function with ``@register_handler("my_key")``.
* Parses 5-field crontab expressions via ``croniter``.
* Runs a single-worker background loop guarded by a Postgres advisory
  lock (``LOCK_SCHEDULER_BG``) — so uvicorn's N parallel workers don't
  fire the same job N times.
* Records every dispatch as a ``JobExecution`` row with duration + status.

All public-facing functions accept a SQLAlchemy ``Session`` so callers
(including web routers) can compose them in their own transactions.
"""

import asyncio
import inspect
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy.orm import Session

from ion.core.config import get_config
from ion.models.scheduler import ScheduledJob
from ion.storage.database import get_engine, get_session_factory, run_locked
from ion.storage.scheduler_repository import SchedulerRepository

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------
#
# Handlers are async callables with the signature:
#
#     async def handler(params: dict, db: Session) -> dict
#
# They return a JSON-serialisable dict that's stored in
# ``JobExecution.output_json``. Raising any exception marks the execution
# as "error" with the exception message captured in ``error_text``.
#
# The registry is a plain module-level dict — import-time side-effects
# from other ``ion.services.*`` modules populate it. Call
# ``list_handlers()`` to see everything currently registered.

HandlerFn = Callable[[dict, Session], Awaitable[Dict[str, Any]]]
_HANDLERS: Dict[str, HandlerFn] = {}


def register_handler(handler_key: str) -> Callable[[HandlerFn], HandlerFn]:
    """Decorator: register an async handler under ``handler_key``.

    Re-registering the same key overwrites the previous entry (useful
    during development hot-reload). Raises ``ValueError`` if the wrapped
    function is not an async callable so misconfigurations fail loudly.
    """

    def _decorator(fn: HandlerFn) -> HandlerFn:
        if not inspect.iscoroutinefunction(fn):
            raise ValueError(
                f"scheduler handler '{handler_key}' must be an async function"
            )
        _HANDLERS[handler_key] = fn
        logger.debug("Registered scheduler handler: %s", handler_key)
        return fn

    return _decorator


def list_handlers() -> list[str]:
    """Return a sorted list of registered handler keys."""
    return sorted(_HANDLERS.keys())


def get_handler(handler_key: str) -> Optional[HandlerFn]:
    return _HANDLERS.get(handler_key)


# ---------------------------------------------------------------------------
# Built-in handlers
# ---------------------------------------------------------------------------


@register_handler("noop")
async def _noop_handler(params: dict, db: Session) -> dict:
    """A do-nothing handler useful for smoke-testing the scheduler loop.

    Echoes back the ``params`` it was called with and the current UTC
    timestamp. Does not touch the database.
    """
    return {
        "handler": "noop",
        "params": params or {},
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Cron parsing
# ---------------------------------------------------------------------------


def compute_next_run(cron_expr: str, base: Optional[datetime] = None) -> datetime:
    """Compute the next firing time for ``cron_expr`` after ``base``.

    ``base`` defaults to ``datetime.now(timezone.utc)``. Returns a
    timezone-aware UTC datetime. Raises ``ValueError`` on an invalid cron
    string (propagated from croniter).
    """
    try:
        from croniter import croniter
    except ImportError as exc:  # pragma: no cover — import guard
        raise RuntimeError(
            "croniter is not installed. Add `croniter>=2.0.0` to pyproject "
            "dependencies."
        ) from exc

    if base is None:
        base = datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)

    itr = croniter(cron_expr, base)
    nxt = itr.get_next(datetime)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=timezone.utc)
    return nxt


def validate_cron_expr(cron_expr: str) -> bool:
    """Return True if ``cron_expr`` is a valid 5-field crontab string."""
    try:
        from croniter import croniter
        return croniter.is_valid(cron_expr)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Job CRUD wrappers (take a Session)
# ---------------------------------------------------------------------------


def _params_to_json(params: Any) -> Optional[str]:
    if params is None:
        return None
    if isinstance(params, str):
        return params
    try:
        return json.dumps(params)
    except (TypeError, ValueError):
        return None


def create_job(
    session: Session,
    *,
    name: str,
    cron_expr: str,
    handler_key: str,
    params: Optional[dict] = None,
    description: Optional[str] = None,
    enabled: bool = True,
    created_by_id: Optional[int] = None,
) -> dict:
    if not validate_cron_expr(cron_expr):
        raise ValueError(f"Invalid cron expression: {cron_expr!r}")
    if handler_key not in _HANDLERS:
        logger.warning(
            "Creating job %r with unregistered handler_key %r — dispatch will "
            "fail until the handler is registered.",
            name, handler_key,
        )

    repo = SchedulerRepository(session)
    next_run = compute_next_run(cron_expr)
    job = repo.create_job(
        name=name,
        cron_expr=cron_expr,
        handler_key=handler_key,
        next_run_at=next_run,
        description=description,
        params_json=_params_to_json(params),
        enabled=enabled,
        created_by_id=created_by_id,
    )
    session.commit()
    session.refresh(job)
    return job.to_dict()


def update_job(session: Session, job_id: int, **fields) -> Optional[dict]:
    repo = SchedulerRepository(session)
    # If cron_expr is being changed, re-compute next_run_at from the new one.
    if "cron_expr" in fields and fields["cron_expr"] is not None:
        if not validate_cron_expr(fields["cron_expr"]):
            raise ValueError(f"Invalid cron expression: {fields['cron_expr']!r}")
        fields.setdefault("next_run_at", compute_next_run(fields["cron_expr"]))
    if "params" in fields:
        fields["params_json"] = _params_to_json(fields.pop("params"))
    job = repo.update_job(job_id, **fields)
    if job is None:
        return None
    session.commit()
    session.refresh(job)
    return job.to_dict()


def delete_job(session: Session, job_id: int) -> bool:
    repo = SchedulerRepository(session)
    ok = repo.delete_job(job_id)
    if ok:
        session.commit()
    return ok


def list_jobs(session: Session) -> list[dict]:
    repo = SchedulerRepository(session)
    return [j.to_dict() for j in repo.list_jobs()]


def get_job(session: Session, job_id: int) -> Optional[dict]:
    repo = SchedulerRepository(session)
    job = repo.get_job(job_id)
    return job.to_dict() if job else None


def list_executions(session: Session, job_id: int, limit: int = 50) -> list[dict]:
    repo = SchedulerRepository(session)
    return [e.to_dict() for e in repo.list_executions_for_job(job_id, limit=limit)]


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


async def _dispatch_job(job_id: int) -> dict:
    """Fetch + dispatch + record a single job by id.

    Uses its own session so it can commit the execution row independently
    of whatever called us. Returns the execution dict.
    """
    factory = get_session_factory()
    session = factory()
    try:
        repo = SchedulerRepository(session)
        job = repo.get_job(job_id)
        if job is None:
            logger.warning("Dispatch requested for missing job id=%s", job_id)
            return {"status": "error", "error": "job not found"}

        handler = get_handler(job.handler_key)
        params = {}
        if job.params_json:
            try:
                params = json.loads(job.params_json)
            except (TypeError, ValueError):
                params = {}

        # Record start
        exe = repo.record_execution_start(job.id)
        execution_id = exe.id
        job.last_status = "running"
        session.commit()

        status = "success"
        error_text: Optional[str] = None
        output: Optional[dict] = None

        try:
            if handler is None:
                raise LookupError(
                    f"No handler registered for key={job.handler_key!r}"
                )
            result = await handler(params or {}, session)
            output = result if isinstance(result, dict) else {"result": result}
        except Exception as exc:
            logger.exception(
                "Scheduler job %s (%s) failed", job.id, job.name
            )
            status = "error"
            error_text = f"{type(exc).__name__}: {exc}"[:4000]

        output_json = None
        if output is not None:
            try:
                output_json = json.dumps(output, default=str)
            except (TypeError, ValueError):
                output_json = json.dumps({"result": str(output)})

        # Record end + advance job pointers
        repo.record_execution_end(
            execution_id,
            status=status,
            error_text=error_text,
            output_json=output_json,
        )
        # Re-read the row (a different session would have been fine too)
        job = repo.get_job(job_id)
        if job is not None:
            job.last_run_at = datetime.now(timezone.utc)
            job.last_status = status
            try:
                job.next_run_at = compute_next_run(job.cron_expr)
            except Exception as exc:
                logger.warning(
                    "Could not compute next_run for job %s (%s): %s",
                    job.id, job.cron_expr, exc,
                )
        session.commit()
        return {
            "job_id": job_id,
            "execution_id": execution_id,
            "status": status,
            "error": error_text,
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def trigger_now(job_id: int) -> dict:
    """Manual run — schedule an immediate dispatch of ``job_id``.

    Runs the dispatch on a fresh asyncio event loop in the current thread
    so callers (the web API) can get a synchronous success/failure reply.
    """
    try:
        return asyncio.run(_dispatch_job(job_id))
    except RuntimeError:
        # Already inside a running event loop — schedule and don't wait.
        loop = asyncio.get_event_loop()
        loop.create_task(_dispatch_job(job_id))
        return {"job_id": job_id, "status": "queued"}


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------

_stop_event = threading.Event()
_loop_thread: Optional[threading.Thread] = None


def _poll_and_dispatch() -> None:
    """One poll pass: find due jobs and dispatch them."""
    factory = get_session_factory()
    session = factory()
    try:
        repo = SchedulerRepository(session)
        now = datetime.now(timezone.utc)
        due = repo.list_due_jobs(now)
    finally:
        session.close()

    if not due:
        return

    for job in due:
        try:
            asyncio.run(_dispatch_job(job.id))
        except Exception as exc:
            logger.warning(
                "Scheduler dispatch crashed for job %s (%s): %s",
                job.id, job.name, exc,
            )


def run_scheduler_loop(interval_s: int = 30) -> None:
    """Spawn the background scheduler thread.

    Meant to be called from server.py startup **inside a run_locked()
    guard** on ``LOCK_SCHEDULER_BG`` so only one uvicorn worker per
    container runs the loop.

    The loop polls every ``interval_s`` seconds by default; callers can
    override this via the ``ION_SCHEDULER_INTERVAL_S`` env var or the
    ``scheduler_interval_s`` config field. Setting ``ION_SCHEDULER_ENABLED=
    false`` is a no-op safety valve.
    """
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("Scheduler background loop already running — skipping")
        return

    def _loop():
        logger.info(
            "Generic scheduler background loop started (interval: %ds)", interval_s
        )
        while not _stop_event.is_set():
            try:
                _poll_and_dispatch()
            except Exception as exc:
                logger.warning("Scheduler poll error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("Generic scheduler background loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-scheduler"
    )
    _loop_thread.start()


def stop_scheduler_loop() -> None:
    """Signal the background thread to exit at the next poll boundary."""
    _stop_event.set()


def start_scheduler_if_enabled(engine=None, lock_id: Optional[int] = None) -> bool:
    """Convenience wrapper: honour the ION_SCHEDULER_ENABLED flag and wrap
    the loop in a Postgres advisory lock so only one worker runs it.

    Returns True if this worker actually started the loop, False if
    disabled or another worker already holds the lock.
    """
    import os

    enabled_env = os.environ.get("ION_SCHEDULER_ENABLED", "").lower()
    if enabled_env in ("false", "0", "no"):
        logger.info("Scheduler disabled by ION_SCHEDULER_ENABLED=%s", enabled_env)
        return False

    try:
        interval_s = int(os.environ.get("ION_SCHEDULER_INTERVAL_S", "30"))
    except ValueError:
        interval_s = 30

    if engine is None:
        engine = get_engine(get_config().db_path)

    if lock_id is None:
        # Prefer a database.py-provided constant (unique across the codebase).
        # Fall back to 1015 (next unused slot in the 1000-1999 range) if
        # database.py has not yet been updated to export one. See the
        # Integration Checklist — the preferred wiring is to add
        # LOCK_SCHEDULER_BG = 1015 to database.py and import it from there.
        try:
            from ion.storage.database import LOCK_SCHEDULER_BG  # type: ignore
            lock_id = LOCK_SCHEDULER_BG
        except ImportError:
            lock_id = 1015

    def _start():
        run_scheduler_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "scheduler_bg_loop", _start, hold_until_close=True
    )


# ---------------------------------------------------------------------------
# Singleton accessor (kept for ION service naming convention)
# ---------------------------------------------------------------------------


class _SchedulerService:
    """Thin facade exposing the module-level API as methods.

    ION convention is ``get_<name>_service()`` returning an object; this
    class exists only to satisfy that pattern. All real work lives in
    module-level functions above.
    """

    def create_job(self, session: Session, **kwargs) -> dict:
        return create_job(session, **kwargs)

    def update_job(self, session: Session, job_id: int, **fields) -> Optional[dict]:
        return update_job(session, job_id, **fields)

    def delete_job(self, session: Session, job_id: int) -> bool:
        return delete_job(session, job_id)

    def list_jobs(self, session: Session) -> list[dict]:
        return list_jobs(session)

    def get_job(self, session: Session, job_id: int) -> Optional[dict]:
        return get_job(session, job_id)

    def list_executions(self, session: Session, job_id: int, limit: int = 50) -> list[dict]:
        return list_executions(session, job_id, limit=limit)

    def trigger_now(self, job_id: int) -> dict:
        return trigger_now(job_id)

    def list_handlers(self) -> list[str]:
        return list_handlers()

    def start(self, engine=None) -> bool:
        return start_scheduler_if_enabled(engine=engine)

    def stop(self) -> None:
        stop_scheduler_loop()


_scheduler_service: Optional[_SchedulerService] = None


def get_scheduler_service() -> _SchedulerService:
    """Return the singleton scheduler service facade."""
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = _SchedulerService()
    return _scheduler_service
