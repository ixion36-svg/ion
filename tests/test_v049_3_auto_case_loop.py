"""v0.49.3 code-review fix (v0.39.8 baseline F3): the Arkime auto-case loop
ran sync SQLAlchemy AND sync Kibana HTTP (create_case + attach — blocking
httpx.Client.post, 5s timeout, up to 2 round-trips per alert) directly on the
uvicorn event loop. N new alerts with a slow/unreachable Kibana froze every
HTTP request and SSE stream on that worker for up to ~10s x N per pass.
"""

from __future__ import annotations

import asyncio

from ion.services import arkime_auto_case_service as aac


def test_auto_case_run_pass_db_and_kibana_work_off_event_loop(monkeypatch):
    import ion.services.ai_user as ai_user
    import ion.services.connectors.elasticsearch_connector as conn_mod
    import ion.storage.database as database

    class _Alert:
        id = "es-1"
        network_community_id = "1:abc="
        arkime_node = "cap01"

    class _FakeES:
        is_configured = True

        async def get_alerts(self, **kw):
            return [_Alert()]

    on_loop: list = []

    def _probe(what: str) -> None:
        try:
            asyncio.get_running_loop()
            on_loop.append(what)  # ran ON the event loop — blocks the worker
        except RuntimeError:
            pass  # in a worker thread — good

    class _ProbeSession:
        def query(self, *a, **k):
            _probe("query")
            return self

        def filter(self, *a, **k):
            return self

        def all(self):
            return []

        def rollback(self):
            _probe("rollback")

        def close(self):
            _probe("close")

    created: list = []

    def _fake_create(session, alert, bob_id, enqueue_fn):
        # This is where the sync DB writes + blocking Kibana HTTP live.
        _probe("create_case")
        created.append(alert.id)

    def _fake_bob(session):
        _probe("get_bob_user_id")
        return 1

    monkeypatch.setattr(conn_mod, "get_elasticsearch_service", lambda: _FakeES())
    monkeypatch.setattr(ai_user, "get_bob_user_id", _fake_bob)
    monkeypatch.setattr(database, "get_session_factory", lambda engine: (lambda: _ProbeSession()))
    monkeypatch.setattr(aac, "_create_case_for_alert", _fake_create)

    asyncio.run(aac._run_pass(engine=None))

    assert created == ["es-1"]  # behaviour unchanged: the case is created
    assert on_loop == [], f"blocking work ran on the event loop: {on_loop}"
