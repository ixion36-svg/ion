"""An arriving alert is not sent to the AI. Bob runs when a case is created.

ION used to start a background sweep that sent every open alert to Bob every
15 minutes. It was meant as a fallback for when the case grouper does not
investigate, but it also ran when cases were created by hand, so alerts were
investigated on arrival and again with their case. The automatic sweep is
removed; the manual sweep in the investigation API stays.
"""

from __future__ import annotations

import asyncio

import ion.storage.database as database
from ion.services.investigation_service import InvestigationService


def test_startup_starts_nothing_that_investigates_alerts(monkeypatch, tmp_path):
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    started: list[str] = []
    monkeypatch.setattr(database, "run_locked",
                        lambda engine, lock_id, name, fn, **kw: started.append(name))

    swept: list[object] = []

    async def _sweep(self, *a, **k):
        swept.append(a)
        return {}

    async def _investigate(self, *a, **k):
        swept.append(a)

    monkeypatch.setattr(InvestigationService, "investigate_open_alerts_sweep", _sweep)
    monkeypatch.setattr(InvestigationService, "investigate_alert", _investigate)

    from ion.web import server
    asyncio.run(server._startup_event())

    assert "case_grouper_bg_loop" in started, started
    assert not any("investigat" in n for n in started), started
    assert swept == []


def test_the_manual_sweep_is_still_there():
    from ion.web import investigation_api
    paths = {r.path for r in investigation_api.router.routes}
    assert any("sweep" in p for p in paths), sorted(paths)
