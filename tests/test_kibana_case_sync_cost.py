"""Kibana case sync: request counts, and keeping blocking calls off the loop.

Measured before these changes, against a fake Kibana at 150 ms (create) and
30 ms (sync) per request:

* a 50-alert case create made 51 Kibana requests on the request path, one
  attach per alert, and took 7.75 s;
* one sync cycle over 150 linked cases made 452 requests (a GET per case
  for status, a second for the push, a comments read per case) and held the
  web worker's event loop for 14.2 s of every 15 s.

The properties pinned here are the request counts, which are deterministic,
and the thread every Kibana call runs on, which is the reason a slow Kibana
froze unrelated requests. Wall-clock budgets would be flaky.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, Note
from ion.models.base import Base
from ion.models.user import User
import ion.services.kibana_cases_service as kcs
import ion.services.kibana_sync_service as kss

INDEX = ".alerts-security.alerts-default"


class FakeKibana:
    """Just enough of the Cases API, recording every request and its thread."""

    def __init__(self, cases: int = 0):
        self.requests: list[tuple[str, str, dict]] = []
        self.threads: set[int] = set()
        self.reject_alert_ids: set[str] = set()
        self.fail_comments_for: set[str] = set()
        self.cases = {
            f"kb-{i}": {
                "id": f"kb-{i}", "title": f"[CASE-{i}] t", "tags": ["ion"],
                "status": "open", "version": "v1",
                "updated_at": "2026-01-01T00:00:00.000Z",
                "created_at": "2026-01-01T00:00:00.000Z", "totalComment": 0,
            }
            for i in range(1, cases + 1)
        }
        self.comments: dict[str, list[dict]] = {}
        self.on_patch = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.threads.add(threading.get_ident())
        body = json.loads(request.content) if request.content else {}
        path = request.url.path
        self.requests.append((request.method, path, body))

        if request.method == "PATCH" and path == "/api/cases":
            if self.on_patch:
                self.on_patch(body)
            return httpx.Response(200, json=[{"id": c["id"], "version": "v9"}
                                             for c in body.get("cases", [])])
        if request.method == "POST" and path == "/api/cases":
            return httpx.Response(200, json={"id": "kb-new", "version": "v1"})
        m = re.fullmatch(r"/api/cases/([^/]+)/comments", path)
        if request.method == "POST" and m and body.get("type") == "alert":
            ids, idx = body["alertId"], body["index"]
            if not isinstance(idx, list) or len(idx) != len(ids):
                return httpx.Response(400, json={"message": "alertId/index mismatch"})
            if self.reject_alert_ids & set(ids):
                return httpx.Response(400, json={"message": "unknown alert"})
            return httpx.Response(200, json={"id": m.group(1), "version": "v2"})
        if path == "/api/cases/_find":
            page = int(request.url.params.get("page", 1))
            per = int(request.url.params.get("perPage", 20))
            rows = list(self.cases.values())
            return httpx.Response(200, json={
                "cases": rows[(page - 1) * per: page * per], "total": len(rows),
                "page": page, "perPage": per,
            })
        m = re.fullmatch(r"/api/cases/([^/]+)/comments/_find", path)
        if m:
            if m.group(1) in self.fail_comments_for:
                return httpx.Response(500, json={})
            page = int(request.url.params.get("page", 1))
            per = int(request.url.params.get("perPage", 20))
            rows = self.comments.get(m.group(1), [])
            return httpx.Response(200, json={
                "comments": rows[(page - 1) * per: page * per], "total": len(rows),
                "page": page, "perPage": per,
            })
        m = re.fullmatch(r"/api/cases/([^/]+)", path)
        if request.method == "GET" and m:
            case = self.cases.get(m.group(1))
            return httpx.Response(200, json=case) if case else httpx.Response(404, json={})
        return httpx.Response(200, json={})

    def count(self, method: str, pattern: str) -> int:
        return sum(1 for m, p, _ in self.requests
                   if m == method and re.fullmatch(pattern, p))

    def reset(self) -> None:
        self.requests.clear()
        self.threads.clear()


@pytest.fixture
def kibana(monkeypatch):
    def make(cases: int = 0) -> FakeKibana:
        fake = FakeKibana(cases)
        svc = kcs.KibanaCasesService.__new__(kcs.KibanaCasesService)
        svc.config = {"enabled": True, "url": "http://kibana.test",
                      "space_id": "default", "case_owner": "securitySolution",
                      "username": "", "password": ""}
        svc._client = httpx.Client(base_url="http://kibana.test",
                                   transport=httpx.MockTransport(fake))
        monkeypatch.setattr(kcs, "_kibana_service", svc)
        fake.service = svc
        return fake
    return make


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'kb.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(kss, "get_engine", lambda *a, **k: engine)
    monkeypatch.setattr(kss, "get_session_factory", lambda *a, **k: factory)
    s = factory()
    s.add(User(id=1, username="admin", email="a@x", password_hash="x",
               is_active=True, elastic_uid="u_admin"))
    s.commit()
    yield factory
    s.close()


def _link_cases(factory, n: int, **overrides) -> None:
    s = factory()
    s.add_all([
        AlertCase(id=i, case_number=f"CASE-{i}", title="t", severity="low",
                  status=overrides.get("status", AlertCaseStatus.OPEN),
                  created_by_id=1, kibana_case_id=f"kb-{i}", kibana_case_version="v1")
        for i in range(1, n + 1)
    ])
    s.commit()
    s.close()


# ── attach ────────────────────────────────────────────────────────────────


class TestAttachIsBatched:
    def test_fifty_alerts_are_one_request_with_parallel_arrays(self, kibana):
        fake = kibana()
        ids = [f"a-{i}" for i in range(50)]
        assert fake.service.attach_alerts_to_case("kb-1", ids, INDEX)

        posts = [b for m, p, b in fake.requests if m == "POST"]
        assert len(posts) == 1
        assert posts[0]["alertId"] == ids
        assert posts[0]["index"] == [INDEX] * 50

    def test_large_sets_are_chunked_and_nothing_is_dropped(self, kibana):
        fake = kibana()
        ids = [f"a-{i}" for i in range(250)]
        fake.service.attach_alerts_to_case("kb-1", ids, INDEX)

        posts = [b for m, p, b in fake.requests if m == "POST"]
        assert len(posts) == 3
        assert [a for b in posts for a in b["alertId"]] == ids
        assert all(len(b["alertId"]) <= kcs.ATTACH_CHUNK_SIZE for b in posts)

    def test_a_rejected_chunk_retries_one_by_one_and_loses_only_the_bad_alert(self, kibana):
        fake = kibana()
        fake.reject_alert_ids = {"a-3"}
        ids = [f"a-{i}" for i in range(5)]
        fake.service.attach_alerts_to_case("kb-1", ids, INDEX)

        posts = [b["alertId"] for m, p, b in fake.requests if m == "POST"]
        assert posts[0] == ids
        assert posts[1:] == [[a] for a in ids]


# ── reads ─────────────────────────────────────────────────────────────────


class TestReadsAreComplete:
    def test_comments_past_the_first_hundred_are_read(self, kibana):
        fake = kibana()
        fake.comments["kb-1"] = [{"id": f"c{i}", "type": "user", "comment": str(i)}
                                 for i in range(250)]
        comments = fake.service.fetch_case_comments("kb-1")
        assert len(comments) == 250
        assert comments[-1]["comment"] == "249"

    def test_a_failed_comment_read_is_none_not_empty(self, kibana):
        fake = kibana()
        fake.fail_comments_for = {"kb-1"}
        assert fake.service.fetch_case_comments("kb-1") is None
        assert fake.service.get_case_comments("kb-1") == []

    def test_the_sweep_pages_through_every_case(self, kibana):
        fake = kibana(cases=230)
        cases = fake.service.find_all_cases()
        assert len(cases) == 230
        assert fake.count("GET", r"/api/cases/_find") == 3


# ── the sync cycle ────────────────────────────────────────────────────────


class TestSyncCycleCost:
    def test_unchanged_cases_cost_nothing_after_the_first_cycle(self, kibana, db):
        fake = kibana(cases=150)
        _link_cases(db, 150)
        sync = kss.KibanaSyncService()

        asyncio.run(sync.run_sync_cycle())
        assert fake.count("GET", r"/api/cases/kb-\d+") == 0, "status must come from the sweep"

        fake.reset()
        fake.cases["kb-7"]["version"] = "v2"
        asyncio.run(sync.run_sync_cycle())

        assert fake.count("GET", r"/api/cases/kb-\d+/comments/_find") == 1
        assert fake.count("GET", r"/api/cases/kb-\d+") == 0
        # the 2-page sweep, shared by import, status and comments
        assert len(fake.requests) == 3

    def test_kibana_calls_never_run_on_the_event_loop_thread(self, kibana, db):
        fake = kibana(cases=5)
        _link_cases(db, 5)
        sync = kss.KibanaSyncService()

        async def cycle():
            loop_thread = threading.get_ident()
            await sync.run_sync_cycle()
            return loop_thread

        loop_thread = asyncio.run(cycle())
        assert fake.requests
        assert loop_thread not in fake.threads

    def test_a_failed_comment_read_is_retried_next_cycle(self, kibana, db):
        fake = kibana(cases=1)
        _link_cases(db, 1)
        fake.fail_comments_for = {"kb-1"}
        sync = kss.KibanaSyncService()
        asyncio.run(sync.run_sync_cycle())

        fake.fail_comments_for = set()
        fake.comments["kb-1"] = [{"id": "c1", "type": "user", "comment": "from kibana",
                                  "created_by": {"username": "eve"}}]
        fake.reset()
        asyncio.run(sync.run_sync_cycle())

        assert fake.count("GET", r"/api/cases/kb-1/comments/_find") == 1
        s = db()
        assert [n.content for n in s.query(Note).all()] == ["[From Kibana - eve] from kibana"]
        s.close()

    def test_a_close_in_kibana_reaches_ion_from_the_sweep_alone(self, kibana, db):
        fake = kibana(cases=1)
        _link_cases(db, 1)
        fake.cases["kb-1"].update(status="closed", updated_at="2030-01-01T00:00:00.000Z")
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())

        s = db()
        assert s.get(AlertCase, 1).status == AlertCaseStatus.CLOSED
        s.close()
        assert fake.count("GET", r"/api/cases/kb-1") == 0

    def test_a_case_deleted_in_kibana_is_skipped_not_polled(self, kibana, db):
        fake = kibana(cases=0)
        _link_cases(db, 3)
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())
        assert fake.count("GET", r"/api/cases/kb-\d+(/comments/_find)?") == 0

    def test_a_failed_sweep_skips_status_and_comments(self, kibana, db, monkeypatch):
        fake = kibana(cases=3)
        _link_cases(db, 3)
        monkeypatch.setattr(fake.service, "find_all_cases", lambda: None)
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())
        assert fake.count("GET", r"/api/cases/kb-\d+(/comments/_find)?") == 0


# ── case create ───────────────────────────────────────────────────────────


class TestCaseCreate:
    def test_fifty_alert_create_makes_two_kibana_requests_off_the_loop(
        self, kibana, db, monkeypatch,
    ):
        import ion.web.case_lifecycle_api as api
        from ion.core.config import get_config

        fake = kibana()
        monkeypatch.setattr(get_config(), "case_grouper_auto_investigate", False)
        session = db()
        user = session.get(User, 1)
        ids = [f"alert-{i}" for i in range(50)]
        data = api.CaseCreate(title="t", severity="high", alert_ids=ids)

        async def create():
            return threading.get_ident(), await api.create_case(
                data=data, current_user=user, session=session)

        loop_thread, result = asyncio.run(create())
        session.close()

        assert result["linked_alerts"] == 50
        assert result["kibana_case_id"] == "kb-new"
        assert fake.count("POST", r"/api/cases") == 1
        assert fake.count("POST", r"/api/cases/kb-new/comments") == 1
        assert loop_thread not in fake.threads


# ── cases created in Kibana ───────────────────────────────────────────────


def _kibana_native(fake: FakeKibana, n: int) -> None:
    """Replace the fake's cases with n analyst-created ones (no ION marks)."""
    fake.cases = {
        f"kb-{i}": {
            "id": f"kb-{i}", "title": f"Phish {i}", "tags": [], "status": "open",
            "severity": "high", "version": "v1", "totalComment": 0,
            "updated_at": "2026-01-01T00:00:00.000Z",
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        for i in range(1, n + 1)
    }


class TestKibanaCreatedCases:
    def test_cases_beyond_the_newest_hundred_are_imported(self, kibana, db):
        fake = kibana()
        _kibana_native(fake, 150)
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())

        s = db()
        assert s.query(AlertCase).filter(AlertCase.kibana_case_id.isnot(None)).count() == 150
        s.close()

    def test_the_import_is_committed_before_kibana_is_renamed(self, kibana, db):
        """The "[CASE-" rename makes later cycles skip the case, so the ION
        row must already be durable when Kibana is renamed."""
        fake = kibana()
        _kibana_native(fake, 1)
        seen_at_rename = []

        def check(body):
            other = db()
            seen_at_rename.append(
                other.query(AlertCase).filter_by(kibana_case_id="kb-1").count())
            other.close()

        fake.on_patch = check
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())
        assert seen_at_rename == [1]

    def test_a_kibana_case_is_imported_once_and_then_synced_both_ways(self, kibana, db):
        fake = kibana()
        _kibana_native(fake, 1)
        sync = kss.KibanaSyncService()
        asyncio.run(sync.run_sync_cycle())
        asyncio.run(sync.run_sync_cycle())

        s = db()
        assert s.query(AlertCase).count() == 1
        s.close()

        fake.cases["kb-1"].update(status="closed", version="v3",
                                  updated_at="2030-01-01T00:00:00.000Z")
        asyncio.run(sync.run_sync_cycle())
        s = db()
        assert s.query(AlertCase).one().status == AlertCaseStatus.CLOSED
        s.close()


# ── alerts attached in Kibana ─────────────────────────────────────────────


def _alert_comment(*ids: str) -> dict:
    return {"id": "att-" + ids[0], "type": "alert", "alertId": list(ids),
            "index": [INDEX] * len(ids), "created_by": {"username": "eve"}}


class TestAlertsAttachedInKibana:
    def test_they_reach_the_ion_case(self, kibana, db):
        fake = kibana(cases=1)
        _link_cases(db, 1)
        fake.comments["kb-1"] = [_alert_comment("a-1", "a-2"), _alert_comment("a-3")]
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())

        s = db()
        assert sorted(t.es_alert_id for t in
                      s.query(AlertTriage).filter_by(case_id=1)) == ["a-1", "a-2", "a-3"]
        assert s.get(AlertCase, 1).source_alert_ids == ["a-1", "a-2", "a-3"]
        s.close()

    def test_an_alert_ion_files_under_another_case_stays_there(self, kibana, db):
        fake = kibana(cases=2)
        _link_cases(db, 2)
        s = db()
        s.add(AlertTriage(es_alert_id="a-1", status="acknowledged", case_id=2))
        s.commit()
        s.close()
        fake.comments["kb-1"] = [_alert_comment("a-1")]
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())

        s = db()
        assert s.query(AlertTriage).filter_by(es_alert_id="a-1").one().case_id == 2
        assert not s.get(AlertCase, 1).source_alert_ids
        s.close()

    def test_alerts_already_on_the_case_change_nothing(self, kibana, db):
        fake = kibana(cases=1)
        _link_cases(db, 1)
        s = db()
        s.add(AlertTriage(es_alert_id="a-1", status="acknowledged", case_id=1))
        s.get(AlertCase, 1).source_alert_ids = ["a-1"]
        s.commit()
        s.close()
        fake.comments["kb-1"] = [_alert_comment("a-1")]
        asyncio.run(kss.KibanaSyncService().run_sync_cycle())

        s = db()
        assert s.query(AlertTriage).count() == 1
        assert s.get(AlertCase, 1).source_alert_ids == ["a-1"]
        s.close()
