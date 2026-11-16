"""Starting an investigation never blocks the event loop that started it.

Found by load test: with case creation starting a Bob case investigation as a
task on the request loop, the investigation's blocking call to Ollama's
embeddings endpoint (a sync httpx client) froze the worker. Ten concurrent case
creations took a median 38 s and /api/health waited a median 11 s.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from ion.services.investigation_service import InvestigationService

BLOCK_S = 0.6


def _blocking(record: dict):
    async def investigate(self, *a, **k):
        record["thread"] = threading.get_ident()
        time.sleep(BLOCK_S)
        record["done"] = True
    return investigate


def _start_case():
    from ion.services.case_grouper_service import enqueue_case_investigation
    enqueue_case_investigation(1)


def _start_alert():
    from ion.services.case_grouper_service import enqueue_investigation
    enqueue_investigation("a-1")


def _start_manual():
    from ion.web.investigation_api import _spawn_investigation
    _spawn_investigation("a-1", force=False, triggered_by="test")


@pytest.mark.parametrize("method,start", [
    ("investigate_case", _start_case),
    ("investigate_alert", _start_alert),
    ("investigate_alert", _start_manual),
], ids=["case creation", "case grouper per alert", "manual investigate"])
def test_the_calling_loop_keeps_serving(monkeypatch, method, start):
    record: dict = {}
    monkeypatch.setattr(InvestigationService, method, _blocking(record))

    async def caller() -> float:
        start()
        worst, last = 0.0, time.perf_counter()
        for _ in range(int(BLOCK_S / 0.02)):
            await asyncio.sleep(0.02)
            now = time.perf_counter()
            worst, last = max(worst, now - last), now
        return worst

    loop_thread = threading.get_ident()
    worst_gap = asyncio.run(caller())
    deadline = time.time() + 5
    while not record.get("done") and time.time() < deadline:
        time.sleep(0.02)

    assert record.get("done"), "the investigation never ran"
    assert record["thread"] != loop_thread
    assert worst_gap < BLOCK_S / 2, f"loop stalled for {worst_gap:.2f}s"
