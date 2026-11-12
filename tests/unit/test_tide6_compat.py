"""ION against TIDE 5 and TIDE 6: baselines listed once, scores banded right.

TIDE 6 copies every applied baseline into a per-system row of the same
playbooks table, and TIDE 5.1 moved rule scores to a percentage. The fakes
refuse a column the way TIDE's query API does (None from _query) when that
version lacks it.
"""
from __future__ import annotations

import re
from typing import Optional

from ion.services.tide_service import TideService

TEMPLATE = {"id": "tpl-1", "name": "Ransomware", "description": "d", "system_id": None}
COPIES = [
    {"id": "cp-1", "name": "Ransomware", "description": "d", "system_id": "sys-a"},
    {"id": "cp-2", "name": "Ransomware", "description": "d", "system_id": "sys-b"},
]


class _Tide(TideService):
    def __init__(self, version: int):
        self.enabled = True
        self.space = "default"
        self.version = version
        self.sent: list[str] = []

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        self.sent.append(sql)
        q = " ".join(sql.split())
        if self.version < 6 and "system_id FROM playbooks" in q:
            return None
        if self.version < 5 and "rule_id FROM checkedRule" in q:
            return None
        if q.startswith("SELECT count(*) AS n FROM"):
            return {"rows": [{"n": 1}]}
        if "LIMIT 0" in q:
            return {"rows": []}
        if q.startswith("SELECT id, name, description FROM playbooks"):
            rows = [TEMPLATE] + COPIES
            if "system_id IS NULL" in q:
                rows = [r for r in rows if r["system_id"] is None]
            return {"rows": [{k: r[k] for k in ("id", "name", "description")} for r in rows]}
        if "FROM playbooks pc" in q:
            return {"rows": [{"system_id": "sys-a", "system_name": "A"},
                             {"system_id": "sys-b", "system_name": "B"}]}
        if "FROM system_baselines" in q:
            return {"rows": [{"system_id": "sys-a", "system_name": "A"}]}
        if "q_excellent" in q:
            bands = [int(x) for x in re.findall(r"quality_score >= (\d+)\)", q)]
            return {"rows": [{"bands": bands, "total_rules": 0, "enabled_rules": 0,
                              "disabled_rules": 0, "unmapped_rules": 0, "q_excellent": 0,
                              "q_good": 0, "q_fair": 0, "q_poor": 0, "avg_quality": 0,
                              "min_quality": 0, "max_quality": 0, "covered_techniques": 0,
                              "severity_json": "[]"}]}
        return {"rows": []}


def test_tide6_lists_each_baseline_once_with_the_systems_using_it():
    books = _Tide(6).get_playbooks_with_kill_chains()
    assert [b["id"] for b in books] == ["tpl-1"]
    assert [s["system_id"] for s in books[0]["applied_systems"]] == ["sys-a", "sys-b"]


def test_tide5_still_reads_the_shared_baselines_and_their_links():
    svc = _Tide(5)
    books = svc.get_playbooks_with_kill_chains()
    assert len(books) == 3
    assert not [q for q in svc.sent if "system_id IS NULL" in q]
    assert books[0]["applied_systems"] == [{"system_id": "sys-a", "system_name": "A"}]


def test_an_unreachable_tide_lists_nothing_and_is_asked_again():
    svc = _Tide(6)
    svc._query = lambda sql, retries=1: None
    assert svc.get_playbooks_with_kill_chains() == []
    assert svc._per_system_baselines is None


def _quick_win_floor(svc) -> int:
    svc.get_gaps_analysis()
    q = next(" ".join(s.split()) for s in svc.sent if "enabled = 0" in s and "quality_score >=" in s)
    return int(re.search(r"quality_score >= (\d+)", q).group(1))


def test_percentage_scores_are_banded_on_the_percentage_scale():
    svc = _Tide(6)
    assert svc._quality_bands() == (80, 50, 25)
    assert svc.get_posture_stats()["quality"]["scale"] == "percent"
    assert _quick_win_floor(_Tide(6)) == 50


def test_point_scores_keep_the_old_bands():
    svc = _Tide(4)
    assert svc._quality_bands() == (30, 20, 10)
    assert svc.get_posture_stats()["quality"]["scale"] == "points"
    assert _quick_win_floor(_Tide(4)) == 20


def _http_tide(monkeypatch, status: int):
    """A real TideService whose HTTP calls get `status` back from a mock TIDE."""
    import httpx

    import ion.services.tide_service as ts
    from ion.core.circuit_breaker import CircuitState, tide_breaker

    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, json={"detail": "Forbidden SQL keyword: LOAD"})))
    monkeypatch.setattr(ts, "_get_tide_client", lambda verify: client)
    monkeypatch.setattr(ts, "_cache_get", lambda sql: (False, None))
    monkeypatch.setattr(ts, "_cache_put", lambda sql, value: None)
    monkeypatch.setattr(ts.time, "sleep", lambda s: None)
    tide_breaker._transition(CircuitState.CLOSED)
    svc = ts.TideService.__new__(ts.TideService)
    svc.url, svc.api_key, svc.client_id, svc.enabled = "http://tide.test", "k", "c", True
    svc.verify, svc.space, svc._resolved_client_id = False, "default", None
    return svc, tide_breaker


def test_refused_queries_leave_the_breaker_closed(monkeypatch):
    """TIDE answering "no" to one statement means TIDE is up. Three refusals
    used to open the breaker and cut off every other TIDE read."""
    svc, breaker = _http_tide(monkeypatch, 400)
    for i in range(5):
        assert svc._query(f"SELECT {i} AS n FROM systems") is None
    assert breaker.can_execute()


def test_a_failing_tide_still_opens_the_breaker(monkeypatch):
    svc, breaker = _http_tide(monkeypatch, 500)
    for i in range(3):
        svc._query(f"SELECT {i} AS n FROM systems", retries=0)
    assert not breaker.can_execute()
    from ion.core.circuit_breaker import CircuitState
    breaker._transition(CircuitState.CLOSED)


def test_the_execution_alert_total_is_counted_exactly(monkeypatch):
    """Elasticsearch stops counting at 10,000 unless asked, so a busy week
    read as exactly 10,000 firing alerts."""
    import asyncio

    from ion.web import de_tide_api

    sent = {}

    class _ES:
        is_configured = True
        alert_index = ".alerts-security.alerts-default"

        async def _request(self, method, path, json=None):
            sent.update(json or {})
            return {"hits": {"total": {"value": 25126, "relation": "eq"}}, "aggregations": {}}

    class _Tide:
        enabled = True
        space = "default"

        def _query(self, sql, retries=1):
            return {"rows": []}

        def get_rules_paginated(self, *a, **k):
            return {"rules": [], "total": 0}

    monkeypatch.setattr(de_tide_api, "ElasticsearchService", lambda: _ES())
    monkeypatch.setattr(de_tide_api, "get_tide_service", lambda: _Tide())
    asyncio.run(de_tide_api.tide_de_execution(168))
    assert sent.get("track_total_hits") is True
