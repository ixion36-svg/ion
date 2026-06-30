"""Large-document AI analysis — chunked map-reduce over the internal LLM (Bob).

A large PDF (e.g. a 600 KB+ standard) holds far more text than fits in one
prompt, and asking for the whole analysis in one response blows the generation
budget. This service map-reduces instead:

  1. **Extract** text locally (pypdf — nothing leaves the box).
  2. **Map**: split into context-sized chunks and ask Bob to pull the relevant
     items out of each chunk independently.
  3. **Reduce** (hierarchical): consolidate the per-chunk outputs, batching and
     re-reducing when the combined partials would themselves overflow context,
     until a single consolidated result remains.

So no single LLM call ever exceeds the window, regardless of document size.

OPT-IN: gated by ``ION_AI_LARGE_PDF_ENABLED`` (default off) — turn it on to run
a job, off again when finished. Work runs in a background thread; the page polls
an in-memory job registry. A single job runs at a time (protects the GPU).

Env:
* ``ION_AI_LARGE_PDF_ENABLED``       (default ``false``)
* ``ION_AI_LARGE_PDF_CHUNK_CHARS``   (default ``8000`` — per map call)
* ``ION_AI_LARGE_PDF_REDUCE_CHARS``  (default ``12000`` — reduce batch budget)
* ``ION_AI_LARGE_PDF_MAX_CHUNKS``    (default ``250`` — safety backstop)
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_ANALYSIS_SYSTEM = (
    "You are a meticulous document-analysis assistant running inside ION, an "
    "air-gapped security operations platform. You are shown one chunk of a "
    "larger document at a time and must follow the instruction exactly. Stay "
    "faithful to the source text — never invent requirements or facts that are "
    "not present. Output only what the instruction asks for, in Markdown."
)

# task → (map_instruction, reduce_system, reduce_instruction)
_PRESETS: Dict[str, Dict[str, str]] = {
    "checklist": {
        "map": (
            "Extract every discrete requirement, control, obligation, or "
            "'must/shall/should' statement in this chunk that belongs in a "
            "compliance checklist. Output each as a single concise, checkable "
            "bullet, preserving any section/clause reference in parentheses. "
            "If the chunk contains nothing checklist-relevant, output exactly 'NONE'."
        ),
        "reduce_instruction": (
            "Below are checklist items extracted from successive chunks of one "
            "document. Consolidate them into a single, de-duplicated compliance "
            "checklist. Group items under clear thematic headings, merge "
            "near-duplicates, preserve section references, and render every item "
            "as a Markdown checkbox ('- [ ] …'). Output only the checklist."
        ),
    },
    "summary": {
        "map": (
            "Summarise the key points of this chunk as 3–6 concise bullets. "
            "If the chunk is boilerplate with no substantive content, output 'NONE'."
        ),
        "reduce_instruction": (
            "Below are bullet summaries of successive chunks of one document. "
            "Merge them into a single coherent executive summary with short "
            "thematic sections. Remove repetition. Output only the summary."
        ),
    },
}


def _enabled() -> bool:
    return os.environ.get("ION_AI_LARGE_PDF_ENABLED", "false").strip().lower() in ("true", "1", "yes", "on")


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _chunk_chars() -> int:
    return _int_env("ION_AI_LARGE_PDF_CHUNK_CHARS", 8000)


def _reduce_chars() -> int:
    return _int_env("ION_AI_LARGE_PDF_REDUCE_CHARS", 12000)


def _max_chunks() -> int:
    return _int_env("ION_AI_LARGE_PDF_MAX_CHUNKS", 250)


def is_enabled() -> bool:
    return _enabled()


def status() -> Dict[str, Any]:
    return {
        "enabled": _enabled(),
        "chunk_chars": _chunk_chars(),
        "max_chunks": _max_chunks(),
        "presets": ["checklist", "summary", "custom"],
        "running": any(j["status"] == "running" for j in _JOBS.values()),
    }


# ── in-memory job registry ───────────────────────────────────────────────────
_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _JOBS_LOCK:
        j = _JOBS.get(job_id)
        return dict(j) if j else None


def _set(job_id: str, **kw) -> None:
    with _JOBS_LOCK:
        if job_id in _JOBS:
            _JOBS[job_id].update(kw)


def _resolve_instructions(task: str, custom_prompt: Optional[str]) -> Dict[str, str]:
    if task in _PRESETS:
        return _PRESETS[task]
    instr = (custom_prompt or "").strip() or "Extract and summarise the key information from this chunk."
    return {
        "map": f"{instr}\n\nApply this to the chunk below. If the chunk is irrelevant, output 'NONE'.",
        "reduce_instruction": (
            f"Below are per-chunk results for this instruction: \"{instr}\". "
            f"Consolidate them into a single, de-duplicated, well-structured "
            f"Markdown answer. Output only the consolidated result."
        ),
    }


# ── map-reduce core (LLM-agnostic; the chat fn is injected for testability) ───
async def _map_reduce(
    text: str,
    task: str,
    custom_prompt: Optional[str],
    chat_fn,
    *,
    chunk_chars: int,
    reduce_chars: int,
    max_chunks: int,
    progress=None,
) -> Dict[str, Any]:
    from ion.services.translation_service import chunk_text

    instr = _resolve_instructions(task, custom_prompt)
    chunks = chunk_text(text, max_chars=chunk_chars)
    truncated = False
    if len(chunks) > max_chunks:
        chunks = chunks[:max_chunks]
        truncated = True

    # ── map ──
    partials: List[str] = []
    total = len(chunks)
    for i, chunk in enumerate(chunks):
        out = await chat_fn(
            messages=[{"role": "user", "content": f"DOCUMENT CHUNK {i + 1} of {total}:\n\n{chunk}\n\n---\n{instr['map']}"}],
            system_prompt=_ANALYSIS_SYSTEM,
            temperature=0.2,
            max_tokens=1024,
        )
        body = (out or {}).get("content") or ""
        body = body.strip()
        if body and body.upper() != "NONE":
            partials.append(body)
        if progress:
            progress("map", i + 1, total)

    if not partials:
        return {"result": "_The model found nothing matching the requested task in this document._",
                "chunks": total, "map_hits": 0, "reduce_rounds": 0, "truncated": truncated}

    # ── reduce (hierarchical) ──
    reduce_rounds = 0
    level = partials
    while True:
        combined = "\n\n".join(level)
        if len(combined) <= reduce_chars or len(level) == 1:
            final = await _reduce_call(combined, instr["reduce_instruction"], chat_fn)
            reduce_rounds += 1
            return {"result": final.strip(), "chunks": total, "map_hits": len(partials),
                    "reduce_rounds": reduce_rounds, "truncated": truncated}
        # Batch the partials into groups that each fit the reduce budget, reduce
        # each group, then recurse on the (smaller) set of group results.
        reduce_rounds += 1
        batches = _batch_by_chars(level, reduce_chars)
        next_level: List[str] = []
        for b in batches:
            r = await _reduce_call("\n\n".join(b), instr["reduce_instruction"], chat_fn)
            next_level.append(r.strip())
            if progress:
                progress("reduce", len(next_level), len(batches))
        level = next_level


async def _reduce_call(combined: str, reduce_instruction: str, chat_fn) -> str:
    out = await chat_fn(
        messages=[{"role": "user", "content": f"{reduce_instruction}\n\n---\n{combined}"}],
        system_prompt=_ANALYSIS_SYSTEM,
        temperature=0.2,
        max_tokens=4096,
    )
    return (out or {}).get("content") or ""


def _batch_by_chars(items: List[str], budget: int) -> List[List[str]]:
    batches: List[List[str]] = []
    cur: List[str] = []
    cur_len = 0
    for it in items:
        if cur and cur_len + len(it) > budget:
            batches.append(cur)
            cur, cur_len = [], 0
        cur.append(it)
        cur_len += len(it) + 2
    if cur:
        batches.append(cur)
    return batches


# ── job orchestration ────────────────────────────────────────────────────────
def start_analysis(filename: str, content: bytes, task: str, custom_prompt: Optional[str]) -> str:
    """Extract text, then run the map-reduce in a background thread. Returns a
    job id. Raises ValueError on extraction problems / when a job is running."""
    from ion.services.translation_service import extract_text_from_upload

    with _JOBS_LOCK:
        if any(j["status"] == "running" for j in _JOBS.values()):
            raise ValueError("Another document analysis is already running — wait for it to finish.")

    text, kind = extract_text_from_upload(filename, content)
    if not text.strip():
        raise ValueError("No extractable text found in the document.")

    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "id": job_id, "status": "running", "phase": "map", "done": 0, "total": 0,
            "filename": filename, "kind": kind, "task": task, "chars": len(text),
            "result": None, "error": None, "created_at": _now_iso(), "finished_at": None,
        }

    def _progress(phase: str, done: int, total: int) -> None:
        _set(job_id, phase=phase, done=done, total=total)

    def _worker() -> None:
        import asyncio
        try:
            from ion.services.ollama_service import get_ollama_service
            svc = get_ollama_service()

            async def _chat(**kw):
                return await svc.chat(bypass_queue=True, **kw)

            result = asyncio.run(_map_reduce(
                text, task, custom_prompt, _chat,
                chunk_chars=_chunk_chars(), reduce_chars=_reduce_chars(),
                max_chunks=_max_chunks(), progress=_progress,
            ))
            _set(job_id, status="done", result=result, finished_at=_now_iso())
        except Exception as exc:  # noqa: BLE001
            logger.warning("large-doc analysis failed: %s", exc)
            _set(job_id, status="error", error=f"{type(exc).__name__}: {exc}"[:500], finished_at=_now_iso())

    threading.Thread(target=_worker, daemon=True, name=f"large-doc-{job_id[:8]}").start()
    return job_id
