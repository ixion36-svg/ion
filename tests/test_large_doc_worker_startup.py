"""A dead analysis worker must not leave the job reading as running.

``_worker`` opened its database session on the line BEFORE its try block:

    session = get_session_factory(get_engine())()
    try:
        ...
    except Exception:
        _update(status="error", ...)

So any failure building the engine or the session killed the thread
before the handler existed. The row stayed ``status='running'``,
``done=0``, for ever -- a job that died looking exactly like a job still
working, with no error, no finish time and nothing to distinguish it
from one that is simply slow.

This is how the test_large_doc flake presented: under full-suite load
the worker thread was gone from threading.enumerate() while the row
still said running. The test was blamed for being timing-sensitive; the
timing only decided whether the window was hit.

A worker that cannot start says so.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services import large_doc_service as lds

DOC = b"This is a real document with content to analyse."


def _read(temp_db, job_id):
    s = sessionmaker(bind=temp_db)()
    try:
        return lds.get_job(s, job_id, 1)
    finally:
        s.close()


def _await_terminal(temp_db, job_id, timeout: float = 60.0):
    """Wait for the row to reach a terminal status, and return it.

    Not a thread join. An earlier version of this helper looked the
    worker up by ``large-doc-{job_id[:8]}`` -- but job_id opens with
    sixteen hex digits of microsecond timestamp, so that prefix is the
    top half of a clock that turns over about every 71 minutes. Every
    job inside one window shared a thread name, and under parallel load
    the helper joined a different test's finished thread and returned
    while the real worker was still going. The service now names threads
    from the uuid tail, and this waits on the row regardless.
    """
    deadline = time.monotonic() + timeout
    while True:
        job = _read(temp_db, job_id)
        if job is not None and job["status"] in ("done", "error"):
            return job
        if time.monotonic() >= deadline:
            return job
        time.sleep(0.05)


@pytest.fixture(autouse=True)
def _no_real_llm(monkeypatch):
    """No test in this file is about the model.

    Without this the worker that DOES get a session walks on into
    _map_reduce and calls a real Ollama that is not running here. In
    isolation that fails fast; under full-suite load it sat long enough
    to outlast the poll, and the job was found at phase 'map' still
    reading as running -- which looked exactly like the production bug
    these tests exist to catch.
    """
    import ion.services.ollama_service as oll

    class _Fake:
        async def chat(self, messages, system_prompt=None, temperature=0.2,
                       max_tokens=None, bypass_queue=False):
            return {"content": "- a point"}

    monkeypatch.setattr(oll, "get_ollama_service", lambda: _Fake())


@pytest.fixture(autouse=True)
def _isolate_session_factory():
    """Make the worker's session bind to THIS test's database.

    get_session_factory(engine) ignores its engine argument once the
    module-level _session_factory is set:

        if _session_factory is None:
            _session_factory = sessionmaker(bind=engine, ...)
        return _session_factory

    So the first caller in the process decides the engine for everyone
    afterwards. A worker thread here would then write the job's status
    into whichever database some earlier test bound, find no row, and
    skip in silence -- status left at 'running', error None, nothing
    logged. Outside pytest this reproduced 11 times in 12; the one that
    passed was the first, which is the only run that populates the
    cache. Under --dist loadfile the file-to-worker assignment moves
    between runs, which is what made it look like a timing flake.
    """
    import ion.storage.database as db

    engine, factory = db._engine, db._session_factory
    db._engine, db._session_factory = None, None
    yield
    db._engine, db._session_factory = engine, factory


def _flaky_engine(monkeypatch, temp_db):
    """Fail a worker thread's FIRST get_engine call, then work.

    Keyed on the calling thread rather than a global call counter. A
    counter is shared with every other caller in the process -- the
    fixtures, a previous test's worker still finishing -- so under load
    something else spent the one failure and the worker under test got a
    healthy engine, which is not the scenario being tested.

    One failure then success models the real cause, transient contention
    while the worker opens its session. A permanently dead engine cannot
    be reported in the database by definition; that case is covered in
    TestAWorkerWithNoDatabaseAtAll.
    """
    import ion.storage.database as db

    failed: set = set()

    def _maybe():
        name = threading.current_thread().name
        if name.startswith("large-doc-") and name not in failed:
            failed.add(name)
            raise RuntimeError("engine unavailable")
        return temp_db

    monkeypatch.setattr(db, "get_engine", _maybe)
    return failed


class TestAWorkerThatCannotStart:
    def test_the_job_does_not_stay_running(self, session, temp_db,
                                           monkeypatch):
        """The symptom that matters. Whatever went wrong, the row must
        not sit at 'running' once the thread is gone."""
        _flaky_engine(monkeypatch, temp_db)

        job_id = lds.start_analysis(
            session, 1, "notes.txt", DOC, "summary", None)
        job = _await_terminal(temp_db, job_id)
        assert job is not None
        assert job["status"] != "running", (
            "a worker that died before it started left the job reading "
            "as in progress: " + repr(job)
        )

    def test_it_is_recorded_as_an_error_with_a_reason(self, session,
                                                      temp_db, monkeypatch):
        _flaky_engine(monkeypatch, temp_db)

        job_id = lds.start_analysis(
            session, 1, "notes.txt", DOC, "summary", None)
        job = _await_terminal(temp_db, job_id)
        assert job["status"] == "error"
        assert "engine unavailable" in (job.get("error") or ""), job

    def test_it_is_given_a_finish_time(self, session, temp_db, monkeypatch):
        """Without one the job is undated as well as undone, and no
        sweep can tell how long it has been dead."""
        from ion.models.service_desk import DocAnalysisJob

        _flaky_engine(monkeypatch, temp_db)
        job_id = lds.start_analysis(
            session, 1, "notes.txt", DOC, "summary", None)
        _await_terminal(temp_db, job_id)

        s = sessionmaker(bind=temp_db)()
        try:
            assert s.get(DocAnalysisJob, job_id).finished_at is not None
        finally:
            s.close()


class TestAWorkerWithNoDatabaseAtAll:
    """The unreportable case, stated rather than pretended away.

    If the database cannot be reached at all, the worker cannot write
    'error' into it -- that is arithmetic, not a design choice. What it
    must still do is fail quietly and locally: no traceback escaping
    into a thread nobody owns.
    """

    def test_the_thread_does_not_escape_the_failure(self, session, temp_db,
                                                    monkeypatch):
        import ion.storage.database as db

        monkeypatch.setattr(db, "get_engine", lambda: (_ for _ in ()).throw(
            RuntimeError("database is gone")))

        seen: list = []
        monkeypatch.setattr(threading, "excepthook",
                            lambda args: seen.append(args))

        job_id = lds.start_analysis(
            session, 1, "notes.txt", DOC, "summary", None)
        # No terminal status is reachable here -- the database is gone,
        # which is the point. Wait for the thread to finish by name; the
        # service now names it from the uuid tail, so this is unique.
        worker = next((t for t in threading.enumerate()
                       if t.name == f"large-doc-{job_id[-8:]}"), None)
        if worker is not None:
            worker.join(timeout=30)
            assert not worker.is_alive()
        assert seen == [], f"worker raised out of the thread: {seen}"
