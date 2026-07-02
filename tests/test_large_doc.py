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
