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


def test_response_times_use_the_status_change_stamp():
    since = datetime(2026, 11, 12, tzinfo=timezone.utc)
    docs = [
        {"@timestamp": "2026-11-13T10:00:00Z", "kibana.alert.workflow_status": "acknowledged",
         "kibana.alert.workflow_status_updated_at": "2026-11-13T10:30:00Z"},
        {"@timestamp": "2026-11-13T10:00:00Z", "kibana.alert.workflow_status": "closed",
         "kibana.alert.workflow_status_updated_at": "2026-11-13T12:00:00Z"},
        {"@timestamp": "2026-11-13T10:00:00Z", "kibana.alert.workflow_status": "open",
         "kibana.alert.workflow_status_updated_at": "2026-11-13T10:01:00Z"},
        {"@timestamp": "2026-11-01T10:00:00Z", "kibana.alert.workflow_status": "closed",
         "kibana.alert.workflow_status_updated_at": "2026-11-13T10:00:00Z"},
    ]
    rt = sm.response_times(docs, since)
    assert rt["mtta"]["n"] == 2 and rt["mtta"]["median"] == 75.0
    assert rt["mttr"]["n"] == 1 and rt["mttr"]["median"] == 120.0


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
