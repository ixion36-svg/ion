"""The standup's seven-day metrics: the arithmetic and the reading of it.

Pins the definitions in services/standup_metrics.py: what a spike is, how
week-on-week change is worded, what MTTA/MTTR measure, what the FP rate
divides by, and that the per-analyst table credits the right person.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from ion.services import standup_metrics as sm
from ion.web.ui.daily_standup import _chg, _duration, _metrics_view


def _days(totals):
    start = date(2026, 11, 6)
    return [{"date": (start + timedelta(days=i)).isoformat(), "total": t} for i, t in enumerate(totals)]


def test_a_spike_is_twice_the_median_of_the_week_before():
    daily = _days([4, 5, 6, 5, 4, 5, 6] + [5, 6, 13, 5, 4, 9, 30])
    spikes = sm.find_spikes(daily)
    assert [s["date"] for s in spikes] == ["2026-11-15", "2026-11-19"]
    assert spikes[0]["baseline"] == 5


def test_a_quiet_day_is_never_a_spike_however_big_the_ratio():
    assert sm.find_spikes(_days([0] * 13 + [4])) == []


def test_change_reports_delta_and_percent():
    assert sm.change(30, 20) == {"this": 30, "last": 20, "delta": 10, "pct": 50.0}
    assert sm.change(5, 0)["pct"] is None
    assert sm.change(None, 3)["delta"] is None


def test_movers_rank_risers_and_name_new_rules():
    m = sm.movers({"a": 9, "b": 4, "c": 2}, {"a": 3, "b": 6})
    assert [r["name"] for r in m["rising"]] == ["a", "c"]
    assert m["new"] == ["c"]
    assert m["top"][0] == {"name": "a", "count": 9, "last": 3}


def test_response_time_stats_come_from_the_aggregation():
    agg = {"n": {"value": 12}, "mean": {"value": 31.26},
           "pct": {"values": {"50.0": 20.04, "90.0": 75.5}}}
    assert sm.rt_stats(agg) == {"n": 12, "mean": 31.3, "median": 20.0, "p90": 75.5}
    assert sm.rt_stats({"n": {"value": 0}}) == {"n": 0, "mean": None, "median": None, "p90": None}
    assert sm.rt_stats(None)["n"] == 0


def test_response_times_are_aggregated_in_elasticsearch_not_paged():
    """A page of hits capped the old read at 5,000 alerts."""
    import asyncio
    es = FakeES(datetime.now(timezone.utc))
    asyncio.run(sm.read_alert_metrics(es, now=es.now))
    rt = [b for b in es.bodies if "runtime_mappings" in b]
    assert len(rt) == 1 and rt[0]["size"] == 0
    assert all(b.get("size", 0) == 0 for b in es.bodies)


def test_daily_rows_zero_fill_fourteen_days():
    rows = sm.daily_rows([{"key_as_string": "2026-11-19", "doc_count": 3,
                           "sev": {"buckets": {"critical": {"doc_count": 1}}}}], date(2026, 11, 19))
    assert len(rows) == 14 and rows[-1]["total"] == 3 and rows[0]["total"] == 0
    assert rows[-1]["severity"]["critical"] == 1


def test_the_verdict_rates_divide_by_verdict_closures_only():
    mix = sm._verdict_mix(["false_positive", "true_positive", "true_positive", "duplicate", None])
    assert mix["verdicts"] == 3
    assert mix["fp_rate"] == pytest.approx(33.3)
    assert mix["tp_rate"] == pytest.approx(66.7)


def test_the_analyst_table_credits_the_closer_and_their_alert_verdicts(session):
    from ion.models.alert_triage import AlertCase, AlertCaseStatus, Note, NoteEntityType
    from ion.models.user import User

    User.metadata.create_all(session.get_bind())
    amy, ben = User(username="amy", email="a@x", password_hash="x"), User(username="ben", email="b@x", password_hash="x")
    session.add_all([amy, ben])
    session.commit()
    now = datetime.utcnow()
    session.add_all([
        AlertCase(case_number="C-1", title="t", status=AlertCaseStatus.CLOSED, created_by_id=ben.id,
                  assigned_to_id=ben.id, closed_by_id=amy.id, closure_reason="false_positive",
                  created_at=now - timedelta(hours=10), closed_at=now - timedelta(hours=4),
                  source_alert_ids=["x", "y"]),
        AlertCase(case_number="C-2", title="t", status=AlertCaseStatus.OPEN, created_by_id=ben.id,
                  assigned_to_id=ben.id, created_at=now - timedelta(days=2)),
    ])
    session.add(Note(entity_type=NoteEntityType.CASE, entity_id="1", user_id=ben.id,
                     content="**Alert closed as Escalated**\nAlert: `x`\nReason: N/A"))
    session.commit()

    out = sm.read_case_and_analyst_metrics(session, alerts_this_week=8, alerts_last_week=0,
                                           now=datetime.now(timezone.utc))
    rows = {r["name"]: r for r in out["analysts"]}
    assert rows["amy"]["cases_closed"] == 1 and rows["amy"]["fp_rate"] == 100.0
    assert rows["amy"]["mttr_hours"] == 6.0
    assert rows["ben"]["cases_opened"] == 2 and rows["ben"]["open_assigned"] == 1
    assert rows["ben"]["alerts_marked"] == 1 and rows["ben"]["tp_rate"] == 100.0
    assert out["closed"]["this"] == 1 and out["escalation_rate"]["this"] == 25.0
    assert out["fp_rate"]["this"] == 100.0


def test_the_view_words_change_by_whether_it_is_good_news():
    assert _chg({"this": 40, "last": 60, "delta": -20, "pct": -33.3}, "down") == {
        "text": "▼ 33%", "tone": "good", "title": "This week 40, last week 60"}
    assert _chg({"this": 40, "last": 60, "delta": -20, "pct": -33.3})["tone"] == "flat"
    assert _chg({"this": 3, "last": 0, "delta": 3, "pct": None})["text"] == "▲ new"
    assert _chg({"this": None, "last": 2})["text"] is None
    assert [_duration(m) for m in (42, 200, 4000, None)] == ["42m", "3.3h", "2.8d", None]


def test_a_failed_half_leaves_the_other_standing():
    view = _metrics_view({"alerts": None, "alerts_error": "Request to Elasticsearch timed out",
                          "cases": {"opened": sm.change(1, 0), "closed": sm.change(0, 0),
                                    "mttr_hours": {}, "outcomes": {}, "analysts": []}})
    assert view["alerts"]["failed"] is True
    assert "timed out" in view["alerts"]["error"]
    assert view["cases"]["failed"] is False and view["cases"]["opened"]["value"] == "1"


# ── the Elasticsearch reader, against a fake cluster ──────────────────────

def _sev(**n):
    return {"buckets": {s: {"doc_count": n.get(s, 0)} for s in sm.SEVERITIES}}


class FakeES:
    alert_index = ".alerts-*"

    def __init__(self, now):
        self.now = now
        self.bodies = []

    async def _request(self, method, path, json=None, timeout=None):
        self.bodies.append(json)
        if "aggs" in json and "daily" in json["aggs"]:
            days = [(self.now.date() - timedelta(days=b)).isoformat() for b in range(13, -1, -1)]
            counts = [3] * 7 + [3, 3, 3, 3, 3, 3, 12]
            return {"aggregations": {
                "daily": {"buckets": [{"key_as_string": d, "doc_count": c, "sev": _sev(high=c)}
                                      for d, c in zip(days, counts)]},
                "weeks": {"buckets": [
                    {"key": "last", "doc_count": 21, "sev": _sev(high=21),
                     "rule0": {"buckets": [{"key": "Brute force", "doc_count": 21}]},
                     "rule1": {"buckets": []}, "host": {"buckets": [{"key": "DC01", "doc_count": 21}]}},
                    {"key": "this", "doc_count": 30, "sev": _sev(high=26, critical=4),
                     "rule0": {"buckets": [{"key": "Brute force", "doc_count": 18}]},
                     "rule1": {"buckets": [{"key": "Beacon", "doc_count": 12}]},
                     "host": {"buckets": [{"key": "DC01", "doc_count": 30}]}},
                ]},
            }}
        if "aggs" in json and "age" in json["aggs"]:
            return {"aggregations": {"age": {"buckets": [
                {"key": "under_24h", "doc_count": 4}, {"key": "1_7d", "doc_count": 6},
                {"key": "over_7d", "doc_count": 9}]}}}
        def stats(n, median):
            return {"n": {"value": n}, "mean": {"value": median},
                    "pct": {"values": {"50.0": median, "90.0": median}}}
        return {"aggregations": {"weeks": {"buckets": [
            {"key": "last", "ack": stats(0, None), "closed": stats(0, None)},
            {"key": "this", "ack": stats(1, 20.0), "closed": stats(1, 20.0)}]}}}


def _read(now):
    import asyncio
    return asyncio.run(sm.read_alert_metrics(FakeES(now), now=now))


def test_the_es_reader_puts_the_weeks_side_by_side():
    now = datetime.now(timezone.utc)
    out = _read(now)
    assert out["total"] == {"this": 30, "last": 21, "delta": 9, "pct": 42.9}
    assert out["severity"]["critical"]["this"] == 4
    assert [s["date"] for s in out["spikes"]] == [now.date().isoformat()]
    assert out["rules"]["new"] == ["Beacon"]
    assert out["hosts"]["top"][0] == {"name": "DC01", "count": 30, "last": 21}
    assert out["backlog"] == {"total": 19, "under_24h": 4, "1_7d": 6, "over_7d": 9}
    assert out["mtta_minutes"]["median"]["this"] == 20.0
    assert out["mttr_minutes"]["median"]["this"] == 20.0
    assert len(out["daily"]) == 7


def test_the_view_draws_the_week_and_marks_the_spike():
    view = _metrics_view({"alerts": _read(datetime.now(timezone.utc)), "cases": None,
                          "cases_error": "db down"})
    a = view["alerts"]
    assert a["failed"] is False and a["total"]["value"] == "30"
    assert a["total"]["change"]["text"] == "▲ 43%"
    assert [b["spike"] for b in a["chart"]["bars"]].count(True) == 1
    assert a["mtta"]["median"]["value"] == "20m"
    assert a["new_rules"] == ["Beacon"]
    assert view["cases"] == {"failed": True, "error": "db down"}


# ── the standup check: retry, and an unconfigured cluster ─────────────────

def test_the_check_retries_once_on_a_timeout_and_says_when_es_is_absent(monkeypatch):
    import asyncio

    from ion.services import elasticsearch_service as ess
    from ion.web import daily_standup_api as api

    monkeypatch.setattr(sm, "read_case_and_analyst_metrics", lambda *a, **k: {"analysts": []})
    calls = []

    async def flaky(es):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("Request to Elasticsearch timed out: ")
        return {"_week_totals": {"this": 3, "last": 1}}

    monkeypatch.setattr(sm, "read_alert_metrics", flaky)
    monkeypatch.setattr(ess.ElasticsearchService, "is_configured", property(lambda self: True))
    out = asyncio.run(api._check_metrics_7d())
    assert len(calls) == 2 and out["alerts_error"] is None and out["cases"] == {"analysts": []}

    monkeypatch.setattr(ess.ElasticsearchService, "is_configured", property(lambda self: False))
    out = asyncio.run(api._check_metrics_7d())
    assert out["alerts"] is None and out["alerts_error"] == "Elasticsearch is not configured"
