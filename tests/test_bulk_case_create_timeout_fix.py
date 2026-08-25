"""Large multi-select case creation must not outlive proxy read timeouts.

A bulk create used to spend ~52s in per-alert query/flush loops plus an
unbounded stretch of sequential OpenCTI round-trips before responding.
Behind the deployed nginx (60s read timeout on /api/) the client received
an HTML 504 for a case that WAS created — response.json() on that body is
the "JSON error" toast, and the create dialog stayed open.

Pins the two server-side halves of the fix: the link-only fast path on
enrich_and_link_observables_for_case, and the deferred-enrichment
background job that finishes the work off the request thread.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace


def _stub_service():
    from ion.services.observable_service import ObservableService

    svc = ObservableService.__new__(ObservableService)
    svc.session = SimpleNamespace(flush=lambda: None)
    svc.get_or_create = lambda obs_type, value: (
        SimpleNamespace(id=1, threat_level=None), True,
    )
    svc.link_to_case = lambda oid, cid, context: None
    return svc


class TestLinkOnlyFastPath:
    def test_enrich_false_never_calls_opencti(self):
        svc = _stub_service()

        async def must_not_run(*a, **kw):
            raise AssertionError("enrich() must not be called with enrich=False")

        svc.enrich = must_not_run
        results = asyncio.run(svc.enrich_and_link_observables_for_case(
            1, [{"type": "source_ip", "value": "10.0.0.1"}], enrich=False,
        ))
        assert len(results) == 1
        assert results[0]["value"] == "10.0.0.1"
        assert results[0]["enrichment"] is None

    def test_default_still_enriches(self):
        svc = _stub_service()
        calls = []

        async def fake_enrich(oid, source="opencti"):
            calls.append(oid)
            return None

        svc.enrich = fake_enrich
        results = asyncio.run(svc.enrich_and_link_observables_for_case(
            1, [{"type": "source_ip", "value": "10.0.0.1"}],
        ))
        assert calls, "default path must still attempt enrichment"
        assert len(results) == 1


class TestDeferredEnrichmentJob:
    def test_deferred_job_persists_enriched_observables(self, monkeypatch):
        import ion.services.observable_service as osvc
        import ion.web.case_lifecycle_api as api

        enriched = [{"type": "source_ip", "value": "10.0.0.1",
                     "observable_id": 1, "threat_level": "benign",
                     "enrichment": {"source": "opencti", "is_malicious": False}}]
        case = SimpleNamespace(id=42, observables=None, kibana_case_id=None,
                               case_number="CASE-0042", notes=[])
        committed = []

        class FakeQuery:
            def filter_by(self, **kw):
                return self

            def first(self):
                return case

        fake_session = SimpleNamespace(
            query=lambda model: FakeQuery(),
            commit=lambda: committed.append(True),
            rollback=lambda: None,
            close=lambda: None,
        )
        monkeypatch.setattr(api, "_new_background_session", lambda: fake_session)

        class FakeSvc:
            async def enrich_and_link_observables_for_case(self, case_id, observables, enrich=True):
                assert enrich is True
                return enriched

        monkeypatch.setattr(osvc, "get_observable_service", lambda s: FakeSvc())

        async def no_note(*a, **kw):
            return None

        async def no_sync(case_id):
            return None

        monkeypatch.setattr(api, "post_enrichment_note", no_note)
        monkeypatch.setattr(api, "_background_case_sync", no_sync)
        monkeypatch.setattr(
            api, "get_kibana_cases_service",
            lambda: SimpleNamespace(enabled=False),
        )

        # Runs synchronously here — in the app it's queued on FastAPI
        # BackgroundTasks so it starts only after the response is sent.
        api._run_deferred_case_enrichment(
            42, 1, "admin", [{"type": "source_ip", "value": "10.0.0.1"}],
        )
        assert case.observables == enriched
        assert committed, "deferred job must commit its own session"

    def test_deferred_kibana_creates_attaches_and_mirrors(self, monkeypatch):
        """The worker's Kibana leg replaces the inline sync for large cases:
        create + set ids + mirror pre-existing notes (e.g. KFP auto-close)."""
        import ion.web.case_lifecycle_api as api

        note = SimpleNamespace(
            content="**Auto-closed as Known False Positive**",
            user=SimpleNamespace(username="admin"),
        )
        case = SimpleNamespace(
            id=7, case_number="CASE-0007", title="Big case", description=None,
            severity="high", affected_hosts=None, affected_users=None,
            evidence_summary=None, observables=[], source_alert_ids=["a1"],
            triggered_rules=None, assigned_to_id=None, kibana_case_id=None,
            kibana_case_version=None, notes=[note],
        )
        session = SimpleNamespace(commit=lambda: None)
        synced = {}
        mirrored = []

        monkeypatch.setattr(
            api, "get_kibana_cases_service",
            lambda: SimpleNamespace(enabled=True, config={}),
        )

        def fake_sync(**kw):
            synced.update(kw)
            return {"kibana_case_id": "kb-1", "kibana_case_version": "v1",
                    "kibana_url": "http://kb/1"}

        monkeypatch.setattr(api, "sync_new_case_to_kibana", fake_sync)
        monkeypatch.setattr(
            api, "sync_note_to_kibana",
            lambda cid, user, content: mirrored.append((cid, user, content)),
        )

        api._kibana_create_for_deferred_case(session, case)

        assert synced["alert_ids"] == ["a1"]
        assert case.kibana_case_id == "kb-1"
        assert mirrored and mirrored[0][0] == "kb-1"

    def test_deferred_kibana_attaches_when_export_loop_won(self, monkeypatch):
        """export_cases_to_kibana creates WITHOUT attaching alerts — if the
        15s loop beat the worker, the worker must still attach them."""
        import ion.web.case_lifecycle_api as api

        attached = {}
        kb = SimpleNamespace(
            enabled=True,
            config={"case_owner": "securitySolution", "space_id": "prod"},
            attach_alerts_to_case=lambda **kw: attached.update(kw),
        )
        monkeypatch.setattr(api, "get_kibana_cases_service", lambda: kb)

        case = SimpleNamespace(
            id=8, case_number="CASE-0008", kibana_case_id="kb-existing",
            source_alert_ids=["a1", "a2"], assigned_to_id=None,
        )
        api._kibana_create_for_deferred_case(SimpleNamespace(), case)

        assert attached["case_id"] == "kb-existing"
        assert attached["alert_ids"] == ["a1", "a2"]
        assert attached["alert_index"] == ".alerts-security.alerts-prod"

    def test_inline_threshold_is_sane(self):
        from ion.web.case_lifecycle_api import _ENRICH_INLINE_MAX
        # Small enough that inline enrichment stays well inside a 60s proxy
        # budget even at ~1s per OpenCTI round-trip; large enough that the
        # single-alert path keeps instant enrichment.
        assert 5 <= _ENRICH_INLINE_MAX <= 60
