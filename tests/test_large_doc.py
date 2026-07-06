"""Tests for the large-document AI analysis (chunked map-reduce, toggle-gated).

The internal LLM is faked — these tests exercise chunking, the hierarchical
reduce, presets, the toggle, the single-job guard, and the background-job
lifecycle without needing a real Ollama.
"""

import asyncio
import time

from sqlalchemy.orm import sessionmaker

from ion.services import large_doc_service as lds


# ── toggle ───────────────────────────────────────────────────────────────────
def test_toggle_default_off(session, monkeypatch):
    monkeypatch.delenv("ION_AI_LARGE_PDF_ENABLED", raising=False)
    assert lds.is_enabled() is False
    assert lds.status(session)["enabled"] is False


def test_toggle_on(session, monkeypatch):
    monkeypatch.setenv("ION_AI_LARGE_PDF_ENABLED", "true")
    assert lds.is_enabled() is True
    s = lds.status(session)
    assert s["enabled"] and "checklist" in s["presets"]


# ── presets ──────────────────────────────────────────────────────────────────
def test_presets_and_custom():
    assert "must/shall/should" in lds._resolve_instructions("checklist", None)["map"]
    cust = lds._resolve_instructions("custom", "Find all dates")
    assert "Find all dates" in cust["map"] and "consolidate" in cust["reduce_instruction"].lower()


def test_batch_by_chars():
    items = ["x" * 100 for _ in range(5)]
    batches = lds._batch_by_chars(items, 250)
    assert all(sum(len(i) for i in b) <= 300 for b in batches)  # ~2 per batch
    assert sum(len(b) for b in batches) == 5


# ── map-reduce core ──────────────────────────────────────────────────────────
def _counting_chat():
    calls = {"map": 0, "reduce": 0}

    async def chat(messages, system_prompt=None, temperature=0.2, max_tokens=None, bypass_queue=False):
        u = messages[0]["content"]
        if u.startswith("DOCUMENT CHUNK"):
            calls["map"] += 1
            return {"content": f"- [ ] item {calls['map']}"}
        calls["reduce"] += 1
        return {"content": "CONSOLIDATED"}

    return chat, calls


def test_map_reduce_hierarchical():
    chat, calls = _counting_chat()
    text = ("A requirement paragraph. " * 30 + "\n\n") * 30
    res = asyncio.run(lds._map_reduce(
        text, "checklist", None, chat,
        chunk_chars=800, reduce_chars=400, max_chunks=250,
    ))
    assert res["map_hits"] == res["chunks"] > 1
    assert res["reduce_rounds"] >= 2  # combined partials overflowed → hierarchical
    assert calls["map"] == res["chunks"]
    assert res["result"]


def test_map_reduce_skips_failed_chunks():
    # A chunk that raises (e.g. a timeout) is skipped, not fatal — the rest still
    # produce a result, with a partial-coverage note.
    calls = {"n": 0}

    async def flaky_chat(messages, system_prompt=None, temperature=0.2, max_tokens=None, bypass_queue=False):
        u = messages[0]["content"]
        if u.startswith("DOCUMENT CHUNK"):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("model cold-loading")  # first chunk times out
            return {"content": "- [ ] item"}
        return {"content": "CONSOLIDATED"}

    text = ("A requirement paragraph. " * 20 + "\n\n") * 6
    res = asyncio.run(lds._map_reduce(text, "checklist", None, flaky_chat,
                                      chunk_chars=400, reduce_chars=100000, max_chunks=250))
    assert res["map_failures"] >= 1
    assert res["map_hits"] >= 1  # the surviving chunks still produced output
    assert "partial" in res["result"].lower()


def test_map_reduce_all_fail_raises():
    async def dead_chat(messages, **kw):
        raise TimeoutError("model unavailable")
    try:
        asyncio.run(lds._map_reduce("a\n\nb\n\nc", "summary", None, dead_chat,
                                    chunk_chars=1, reduce_chars=100, max_chunks=250))
        assert False, "expected RuntimeError when every chunk fails"
    except RuntimeError as e:
        assert "timed out" in str(e).lower() or "unavailable" in str(e).lower()


def test_reduce_call_falls_back_on_failure():
    async def reduce_dies(messages, **kw):
        raise TimeoutError("reduce timeout")
    out = asyncio.run(lds._reduce_call("PARTIAL-A\n\nPARTIAL-B", "consolidate", reduce_dies))
    assert "PARTIAL-A" in out and "PARTIAL-B" in out  # content preserved, not lost


def test_map_reduce_all_none_is_graceful():
    async def none_chat(messages, **kw):
        return {"content": "NONE"}
    res = asyncio.run(lds._map_reduce("a\n\nb", "checklist", None, none_chat,
                                      chunk_chars=800, reduce_chars=400, max_chunks=250))
    assert res["map_hits"] == 0 and res["reduce_rounds"] == 0
    assert "nothing" in res["result"].lower()


def test_map_reduce_truncates_at_max_chunks():
    chat, _ = _counting_chat()
    text = ("para. " * 20 + "\n\n") * 50
    res = asyncio.run(lds._map_reduce(text, "summary", None, chat,
                                      chunk_chars=200, reduce_chars=100000, max_chunks=5))
    assert res["truncated"] is True
    assert res["chunks"] == 5


# ── job lifecycle (DB-backed) ────────────────────────────────────────────────
def test_single_job_guard(session):
    from ion.models.service_desk import DocAnalysisJob
    session.add(DocAnalysisJob(id="running1", status="running", filename="x", task="summary"))
    session.commit()
    try:
        lds.start_analysis(session, 1, "x.txt", b"some text here", "summary", None)
        assert False, "expected ValueError (already running)"
    except ValueError as e:
        assert "already running" in str(e).lower()


def test_start_analysis_empty_text_raises(session):
    try:
        lds.start_analysis(session, 1, "empty.txt", b"   \n  ", "summary", None)
        assert False, "expected ValueError (no text)"
    except ValueError as e:
        assert "no extractable text" in str(e).lower()


def test_start_analysis_runs_to_completion(session, temp_db, monkeypatch):
    # The worker thread opens its own session from get_engine() — point that at
    # the test DB so the persisted job is observable from the poll.
    import ion.services.ollama_service as oll
    import ion.storage.database as db

    monkeypatch.setattr(db, "get_engine", lambda: temp_db)

    class _FakeSvc:
        async def chat(self, messages, system_prompt=None, temperature=0.2, max_tokens=None, bypass_queue=False):
            return {"content": "- key point"}

    monkeypatch.setattr(oll, "get_ollama_service", lambda: _FakeSvc())
    job_id = lds.start_analysis(
        session, 1, "notes.txt", b"This is a real document with content to analyse.", "summary", None
    )
    # poll from a fresh session each tick so we see the worker's commits
    Sess = sessionmaker(bind=temp_db)
    job = None
    for _ in range(80):
        s2 = Sess()
        job = lds.get_job(s2, job_id)
        s2.close()
        if job and job["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert job is not None and job["status"] == "done", job
    assert job["result"]["result"]
    assert job["result"]["map_hits"] >= 1


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-v"]))


# ── v0.49.3 code-review fixes ────────────────────────────────────────────────
def _mk_running_job(session, job_id="stuck1", minutes_ago=0):
    from datetime import datetime, timedelta, timezone

    import sqlalchemy as sa

    from ion.models.service_desk import DocAnalysisJob

    session.add(DocAnalysisJob(id=job_id, status="running", filename="x", task="summary"))
    session.commit()
    if minutes_ago:
        past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
        session.execute(
            sa.update(DocAnalysisJob)
            .where(DocAnalysisJob.id == job_id)
            .values(updated_at=past, created_at=past)
        )
        session.commit()


def test_stale_running_job_is_reaped_and_does_not_block(session):
    """A 'running' row orphaned by a worker restart must not brick the feature
    with 409s forever: rows with no heartbeat past the stale threshold are
    marked error and stop counting as running."""
    from ion.models.service_desk import DocAnalysisJob

    _mk_running_job(session, "stuck1", minutes_ago=120)  # orphaned 2h ago
    assert lds._running_exists(session) is False
    reaped = session.get(DocAnalysisJob, "stuck1")
    assert reaped.status == "error"
    assert "orphan" in (reaped.error or "").lower() or "stale" in (reaped.error or "").lower()


def test_fresh_running_job_still_blocks(session):
    """A live job (heartbeating via progress updates) must still 409."""
    _mk_running_job(session, "live1", minutes_ago=0)
    assert lds._running_exists(session) is True
    try:
        lds.start_analysis(session, 1, "d.txt", b"some text", "summary", None)
        assert False, "expected ValueError while a live job is running"
    except ValueError as e:
        assert "already running" in str(e).lower()


def test_reduce_no_progress_returns_unconsolidated_instead_of_spinning():
    """When every reduce call fails (LLM outage) the fallback returns its input
    verbatim; oversized singleton batches then never shrink. The loop must
    detect no-progress and bail out with the un-consolidated content instead
    of spinning forever hammering Ollama."""
    calls = {"map": 0, "reduce": 0}

    async def outage_chat(messages, system_prompt=None, temperature=0.2, max_tokens=None, bypass_queue=False):
        # Yield to the loop so wait_for's cancellation can land even while the
        # buggy reduce loop spins (a real Ollama call always awaits I/O).
        await asyncio.sleep(0)
        u = messages[0]["content"]
        if u.startswith("DOCUMENT CHUNK"):
            calls["map"] += 1
            return {"content": "ITEM-" + ("x" * 400)}  # big partials
        calls["reduce"] += 1
        raise TimeoutError("ollama down")  # every reduce fails

    text = ("A requirement paragraph. " * 20 + "\n\n") * 6

    async def _bounded():
        return await asyncio.wait_for(
            lds._map_reduce(text, "checklist", None, outage_chat,
                            chunk_chars=400, reduce_chars=300, max_chunks=250),
            timeout=10,
        )

    res = asyncio.run(_bounded())  # pre-fix: hangs -> TimeoutError
    assert "ITEM-" in res["result"]  # extracted content survives
    # bounded number of reduce attempts, not an unbounded spin
    assert calls["reduce"] <= 2 * res["chunks"] + 4


def test_start_analysis_second_racer_loses(session, monkeypatch):
    """Two workers passing the pre-check simultaneously must not both start a
    GPU job: the later claim loses deterministically."""
    from ion.models.service_desk import DocAnalysisJob

    # Simulate both racers passing the friendly pre-check.
    monkeypatch.setattr(lds, "_running_exists", lambda s: False)
    started = []
    monkeypatch.setattr(lds.threading, "Thread",
                        lambda *a, **k: type("T", (), {"start": lambda self: started.append(1)})())

    job1 = lds.start_analysis(session, 1, "a.txt", b"text one", "summary", None)
    try:
        lds.start_analysis(session, 1, "b.txt", b"text two", "summary", None)
        assert False, "expected the second concurrent claim to lose"
    except ValueError:
        pass
    running = session.query(DocAnalysisJob).filter(DocAnalysisJob.status == "running").all()
    assert [j.id for j in running] == [job1]
    assert len(started) == 1  # only the winner spawned a worker


def test_api_start_analysis_runs_off_event_loop(session, monkeypatch):
    """The upload handler must not run pypdf extraction on the event loop —
    lds.start_analysis has to execute where no loop is running (a thread)."""
    from io import BytesIO

    from starlette.datastructures import UploadFile

    from ion.web import large_doc_api as api

    monkeypatch.setattr(api.lds, "is_enabled", lambda: True)
    seen = {}

    def _probe(*a, **k):
        try:
            asyncio.get_running_loop()
            seen["on_loop"] = True
        except RuntimeError:
            seen["on_loop"] = False
        return "job-1"

    monkeypatch.setattr(api.lds, "start_analysis", _probe)

    class _U:
        id = 1

    upload = UploadFile(file=BytesIO(b"hello world"), filename="t.txt")

    async def _call():
        return await api.start_document_analysis(
            file=upload, task="summary", custom_prompt="",
            current_user=_U(), session=session,
        )

    out = asyncio.run(_call())
    assert out == {"job_id": "job-1"}
    assert seen["on_loop"] is False, "start_analysis ran ON the event loop (blocks the worker)"


def test_two_connections_cannot_both_hold_running(tmp_path, monkeypatch):
    """AUDIT-1: the single-winner guarantee must come from the DB (partial
    unique index on status='running'), not from claim-order heuristics — a
    later-id worker that commits first must not co-win with an earlier-id
    worker under READ COMMITTED. Two separate sessions = two workers."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ion.models.document import Base
    from ion.models.service_desk import DocAnalysisJob

    engine = create_engine(f"sqlite:///{tmp_path / 'race.db'}")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)
    s1, s2 = S(), S()

    monkeypatch.setattr(lds, "_running_exists", lambda s: False)  # both pass pre-check
    started = []
    monkeypatch.setattr(lds.threading, "Thread",
                        lambda *a, **k: type("T", (), {"start": lambda self: started.append(1)})())

    job1 = lds.start_analysis(s1, 1, "a.txt", b"text one", "summary", None)
    try:
        lds.start_analysis(s2, 1, "b.txt", b"text two", "summary", None)
        assert False, "second worker's insert must fail at the DB layer"
    except ValueError as e:
        assert "already running" in str(e).lower()

    running = s1.query(DocAnalysisJob).filter(DocAnalysisJob.status == "running").all()
    assert [j.id for j in running] == [job1]
    assert len(started) == 1
    s1.close()
    s2.close()


def test_done_jobs_do_not_block_new_running_row(tmp_path, monkeypatch):
    """The uniqueness must apply ONLY to status='running' — finished jobs
    accumulate and must not trip the partial index."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ion.models.document import Base
    from ion.models.service_desk import DocAnalysisJob

    engine = create_engine(f"sqlite:///{tmp_path / 'hist.db'}")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine)
    s = S()
    s.add(DocAnalysisJob(id="old1", status="done", filename="x", task="summary"))
    s.add(DocAnalysisJob(id="old2", status="error", filename="y", task="summary"))
    s.commit()

    monkeypatch.setattr(lds, "_running_exists", lambda sess: False)
    monkeypatch.setattr(lds.threading, "Thread",
                        lambda *a, **k: type("T", (), {"start": lambda self: None})())
    job = lds.start_analysis(s, 1, "c.txt", b"new text", "summary", None)
    assert s.get(DocAnalysisJob, job).status == "running"
    s.close()
