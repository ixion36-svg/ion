"""Kibana sync: who wins a status change, and alerts added after create.

Status used to be decided by comparing ION's ``updated_at`` with Kibana's.
They come from two machines, and both move on unrelated writes (a grouper
tick, a comment), so the side that changed status could lose. A reopen in
Kibana was also re-closed every cycle, because ION treated closed as final.
Alerts added to an ION case after it reached Kibana never reached Kibana.
"""

from __future__ import annotations

import asyncio

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
import ion.services.kibana_sync_service as kss
from tests.test_kibana_case_sync_cost import INDEX, FakeKibana, _link_cases, db, kibana  # noqa: F401

PAST = "2020-01-01T00:00:00.000Z"
FUTURE = "2099-01-01T00:00:00.000Z"


class RecordingKibana(FakeKibana):
    """Applies status PATCHes and records attached alerts, like Kibana does."""

    fail_reads = False

    def __call__(self, request):
        import httpx
        if self.fail_reads and request.method == "GET" and "_find" not in request.url.path:
            self.requests.append((request.method, request.url.path, {}))
            return httpx.Response(503, json={})
        response = super().__call__(request)
        body = request.content and __import__("json").loads(request.content)
        if request.method == "PATCH" and request.url.path == "/api/cases":
            for c in body["cases"]:
                if "status" in c:
                    self.cases[c["id"]]["status"] = c["status"]
        path = request.url.path
        if (request.method == "POST" and path.endswith("/comments")
                and body.get("type") == "alert" and response.status_code == 200):
            case_id = path.split("/")[3]
            self.comments.setdefault(case_id, []).append(
                {"type": "alert", "alertId": body["alertId"], "index": body["index"]})
        return response


@pytest.fixture
def kb(kibana, monkeypatch):
    import httpx
    fake = kibana(cases=1)
    rec = RecordingKibana(0)
    rec.cases, rec.comments = fake.cases, fake.comments
    fake.service._client = httpx.Client(base_url="http://kibana.test", transport=httpx.MockTransport(rec))
    rec.service = fake.service
    return rec


def _case(db):
    s = db()
    return s, s.get(AlertCase, 1)


def _cycle(sync):
    asyncio.run(sync.run_sync_cycle())


def _status_patches(kb):
    return [c.get("status") for m, p, b in kb.requests if m == "PATCH" for c in b["cases"]]


def _ion_status(db):
    s, case = _case(db)
    status = case.status.value if hasattr(case.status, "value") else case.status
    s.close()
    return status


# ── status ────────────────────────────────────────────────────────────────


def test_a_kibana_status_change_wins_when_ion_wrote_something_else_since(kb, db):
    _link_cases(db, 1)
    sync = kss.KibanaSyncService()
    _cycle(sync)

    kb.cases["kb-1"].update(status="in-progress", updated_at=PAST)
    s, case = _case(db)
    case.title = "grouper touched the row"
    s.commit()
    s.close()
    kb.reset()
    _cycle(sync)

    assert _ion_status(db) == "acknowledged"
    assert _status_patches(kb) == []


def test_an_ion_status_change_wins_when_kibana_moved_for_another_reason(kb, db):
    _link_cases(db, 1)
    sync = kss.KibanaSyncService()
    _cycle(sync)

    s, case = _case(db)
    case.status = AlertCaseStatus.ACKNOWLEDGED
    s.commit()
    s.close()
    kb.cases["kb-1"]["updated_at"] = FUTURE  # someone commented in Kibana
    kb.reset()
    _cycle(sync)

    assert _ion_status(db) == "acknowledged"
    assert _status_patches(kb) == ["in-progress"]


def test_a_reopen_in_kibana_reaches_ion(kb, db):
    _link_cases(db, 1, status=AlertCaseStatus.CLOSED)
    kb.cases["kb-1"]["status"] = "closed"
    s, case = _case(db)
    case.closure_reason = "false_positive"
    s.commit()
    s.close()
    sync = kss.KibanaSyncService()
    _cycle(sync)

    kb.cases["kb-1"]["status"] = "open"
    kb.reset()
    _cycle(sync)

    s, case = _case(db)
    assert case.status == AlertCaseStatus.OPEN
    assert case.closure_reason is None and case.closed_at is None
    s.close()
    assert _status_patches(kb) == []


def test_a_reopen_in_ion_reaches_kibana(kb, db):
    _link_cases(db, 1, status=AlertCaseStatus.CLOSED)
    kb.cases["kb-1"]["status"] = "closed"
    sync = kss.KibanaSyncService()
    _cycle(sync)

    s, case = _case(db)
    case.status = AlertCaseStatus.OPEN
    s.commit()
    s.close()
    kb.reset()
    _cycle(sync)

    assert _ion_status(db) == "open"
    assert _status_patches(kb) == ["open"]


def test_a_close_in_ion_is_pushed_not_reverted(kb, db):
    _link_cases(db, 1, status=AlertCaseStatus.ACKNOWLEDGED)
    kb.cases["kb-1"]["status"] = "in-progress"
    sync = kss.KibanaSyncService()
    _cycle(sync)

    s, case = _case(db)
    case.status = AlertCaseStatus.CLOSED
    s.commit()
    s.close()
    kb.cases["kb-1"]["updated_at"] = FUTURE
    kb.reset()
    _cycle(sync)

    assert _ion_status(db) == "closed"
    assert _status_patches(kb) == ["closed"]


def test_a_case_with_no_agreed_status_still_takes_a_kibana_close(kb, db):
    _link_cases(db, 1)
    kb.cases["kb-1"].update(status="closed", updated_at=PAST)
    _cycle(kss.KibanaSyncService())

    s, case = _case(db)
    assert case.status == AlertCaseStatus.CLOSED
    assert case.kibana_synced_status == "closed"
    s.close()


def test_agreeing_cases_cost_no_requests(kb, db):
    _link_cases(db, 3)
    kb.cases.update({f"kb-{i}": {**kb.cases["kb-1"], "id": f"kb-{i}"} for i in (2, 3)})
    sync = kss.KibanaSyncService()
    _cycle(sync)
    kb.reset()
    _cycle(sync)
    assert [r for r in kb.requests if r[0] != "GET" or "_find" not in r[1]] == []


# ── alerts added after create ─────────────────────────────────────────────


def _add_alert(db, alert_id, **kw):
    s = db()
    s.add(AlertTriage(es_alert_id=alert_id, case_id=1, **kw))
    s.commit()
    s.close()


def _attached(kb):
    return [b["alertId"] for m, p, b in kb.requests if m == "POST" and b.get("type") == "alert"]


def test_an_alert_added_to_an_existing_case_is_attached_in_kibana(kb, db):
    _link_cases(db, 1)
    sync = kss.KibanaSyncService()
    _cycle(sync)

    _add_alert(db, "a-9")
    kb.reset()
    _cycle(sync)
    assert _attached(kb) == [["a-9"]]
    assert {b["index"][0] for m, p, b in kb.requests if m == "POST"} == {INDEX}

    kb.reset()
    _cycle(sync)
    assert _attached(kb) == []


def test_alerts_from_outside_elastic_are_not_attached(kb, db):
    _link_cases(db, 1)
    sync = kss.KibanaSyncService()
    _cycle(sync)

    _add_alert(db, "arkime:marker-1", source_system="arkime-rtmon")
    kb.reset()
    _cycle(sync)
    assert _attached(kb) == []


def test_an_alert_kibana_rejects_is_not_retried_every_cycle(kb, db):
    _link_cases(db, 1)
    sync = kss.KibanaSyncService()
    _cycle(sync)

    kb.reject_alert_ids = {"a-bad"}
    _add_alert(db, "a-bad")
    _cycle(sync)
    kb.reset()
    _cycle(sync)
    _cycle(sync)
    assert _attached(kb) == []


def test_a_failed_alert_read_neither_attaches_nor_gives_up(kb, db):
    _link_cases(db, 1)
    sync = kss.KibanaSyncService()
    _cycle(sync)

    _add_alert(db, "a-9")
    kb.fail_reads = True
    _cycle(sync)
    assert _attached(kb) == []

    kb.fail_reads = False
    kb.reset()
    _cycle(sync)
    assert _attached(kb) == [["a-9"]]
