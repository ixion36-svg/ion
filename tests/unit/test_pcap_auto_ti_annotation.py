"""Auto-PCAP case notes carry OpenCTI annotations + prior-case history.

The Arkime auto-case pipeline enriches the extracted observables via
OpenCTI and answers "have we seen this before?" from ION's own
observable→case links; both land in the markdown note, and known-bad TI
matches escalate the case severity exactly like the manual analyzer.
Also pins the Kibana sync-loop cadence (15s default, env-tunable).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from ion.services.pcap_analysis_service import (
    _render_pcap_markdown,
    _ti_and_history,
    pcap_case_severity,
)


def _result(**over):
    base = dict(
        packet_count=100, file_size=1000, capture_duration=1.0,
        time_start="", time_end="", protocols={"TCP": 100},
        top_src_ips=[], top_dst_ips=[], dns_queries=[], tls_handshakes=[],
        http_requests=[], findings=[], verdict={"label": "Likely Benign", "score": 0},
        tls_certificates=[], os_fingerprints=[], beacons=[], mitre_techniques=[],
    )
    base.update(over)
    return SimpleNamespace(**base)


def _md(**kw):
    return _render_pcap_markdown(
        community_id="1:abc=", sessions=[{"id": "s1"}], pcap_result=_result(),
        **kw,
    )


class TestThreatIntelSection:
    def test_flagged_observable_renders(self):
        ti = {
            "ips_checked": 3, "domains_checked": 2, "malicious_count": 1,
            "observables": [{
                "value": "185.56.137.138", "type": "ipv4",
                "enrichment": {"is_malicious": True, "score": 90,
                               "labels": ["c2"], "threat_actors": ["APT99"]},
            }],
        }
        md = _md(threat_intel=ti)
        assert "**Threat intel (OpenCTI):**" in md
        assert "`185.56.137.138` — **MALICIOUS** (score 90)" in md
        assert "labels: c2" in md and "actors: APT99" in md

    def test_clean_run_says_checked(self):
        ti = {"ips_checked": 4, "domains_checked": 7, "malicious_count": 0,
              "observables": [{"value": "8.8.8.8", "enrichment": None}]}
        md = _md(threat_intel=ti)
        assert "No matches — 4 IP(s) and 7 domain(s) checked." in md

    def test_omitted_when_opencti_unavailable(self):
        md = _md(threat_intel=None)
        assert "Threat intel" not in md


class TestSeenBeforeSection:
    def test_prior_cases_render(self):
        seen = [{"value": "evil.example", "type": "domain",
                 "prior_case_count": 3, "last_case_number": "CASE-0041",
                 "malicious": True}]
        md = _md(seen_before=seen)
        assert "**Seen before in ION:**" in md
        assert "`evil.example`" in md
        assert "3 prior case(s), most recent CASE-0041" in md

    def test_empty_history_is_an_explicit_no(self):
        md = _md(seen_before=[])
        assert "None of the extracted observables appear in an earlier case." in md

    def test_omitted_when_lookup_failed(self):
        md = _md(seen_before=None)
        assert "Seen before" not in md


class TestTiAndHistory:
    """_ti_and_history feeds both the note and the severity path."""

    def test_ti_match_escalates_case_severity(self, monkeypatch):
        import ion.services.opencti_service as ocs
        import ion.services.pcap_enrichment_service as pes

        enrichments = {
            "ips_checked": 1, "domains_checked": 0, "malicious_count": 1,
            "observables": [{
                "value": "185.56.137.138", "type": "ipv4", "observable_id": 7,
                "enrichment": {"source": "opencti", "is_malicious": True,
                               "score": 90, "labels": [], "threat_actors": [],
                               "reports": []},
            }],
        }

        async def fake_enrich(result, is_private_fn):
            return enrichments

        monkeypatch.setattr(pes, "enrich_pcap_observables", fake_enrich)
        monkeypatch.setattr(
            pes, "seen_before_for_case", lambda entries, case_id: []
        )
        monkeypatch.setattr(
            ocs, "get_opencti_service",
            lambda: SimpleNamespace(is_configured=True),
        )

        result = _result(findings=[{"severity": "low", "title": "x"}])
        ti, seen = asyncio.run(_ti_and_history(1, result))

        assert ti is enrichments
        assert seen == []
        assert any(f.get("category") == "Threat Intel Match" for f in result.findings)
        assert pcap_case_severity(result) == "critical"
        # verdict is recomputed over the combined findings — the note can't
        # show "Likely Benign" above a known-bad IOC
        assert result.verdict["label"] != "Likely Benign"
        assert result.verdict["score"] >= 50

    def test_opencti_down_still_reports_history(self, monkeypatch):
        import ion.services.opencti_service as ocs
        import ion.services.pcap_enrichment_service as pes

        async def fake_enrich(result, is_private_fn):
            return {"ips_checked": 1, "domains_checked": 0, "malicious_count": 0,
                    "observables": [{"value": "1.2.3.4", "observable_id": 9,
                                     "enrichment": None}]}

        monkeypatch.setattr(pes, "enrich_pcap_observables", fake_enrich)
        monkeypatch.setattr(
            pes, "seen_before_for_case",
            lambda entries, case_id: [{"value": "1.2.3.4", "type": "ipv4",
                                       "prior_case_count": 2,
                                       "last_case_number": "CASE-0007",
                                       "malicious": False}],
        )
        monkeypatch.setattr(
            ocs, "get_opencti_service",
            lambda: SimpleNamespace(is_configured=False),
        )

        result = _result()
        ti, seen = asyncio.run(_ti_and_history(1, result))
        assert ti is None  # unconfigured → no TI section, not a fake "clean"
        assert seen and seen[0]["prior_case_count"] == 2

    def test_never_raises(self, monkeypatch):
        import ion.services.pcap_enrichment_service as pes

        async def boom(result, is_private_fn):
            raise RuntimeError("db down")

        monkeypatch.setattr(pes, "enrich_pcap_observables", boom)
        ti, seen = asyncio.run(_ti_and_history(1, _result()))
        assert ti is None and seen is None


class TestSharedEnrichmentModule:
    def test_pcap_api_reexports_the_service_implementations(self):
        from ion.services.pcap_enrichment_service import (
            enrich_pcap_observables,
            ti_findings,
        )
        from ion.web.pcap_api import _enrich_pcap_observables, _ti_findings

        assert _enrich_pcap_observables is enrich_pcap_observables
        assert _ti_findings is ti_findings


class TestKibanaSyncCadence:
    def test_default_is_15s(self, monkeypatch):
        from ion.services.kibana_sync_service import kibana_sync_interval_seconds
        monkeypatch.delenv("ION_KIBANA_SYNC_INTERVAL_SECONDS", raising=False)
        assert kibana_sync_interval_seconds() == 15

    def test_env_override(self, monkeypatch):
        from ion.services.kibana_sync_service import kibana_sync_interval_seconds
        monkeypatch.setenv("ION_KIBANA_SYNC_INTERVAL_SECONDS", "30")
        assert kibana_sync_interval_seconds() == 30

    def test_floor_protects_kibana(self, monkeypatch):
        from ion.services.kibana_sync_service import kibana_sync_interval_seconds
        monkeypatch.setenv("ION_KIBANA_SYNC_INTERVAL_SECONDS", "1")
        assert kibana_sync_interval_seconds() == 5

    def test_garbage_falls_back(self, monkeypatch):
        from ion.services.kibana_sync_service import kibana_sync_interval_seconds
        monkeypatch.setenv("ION_KIBANA_SYNC_INTERVAL_SECONDS", "fast")
        assert kibana_sync_interval_seconds() == 15
