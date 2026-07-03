"""Tests for the reworked Arkime realtime monitor (content & behaviour detection).

The v0.45.0 monitor only matched live sessions against ION's IOC IP set. The
rework swaps that for a panel of intrinsic-signal detectors — cleartext
credentials, command/C2 channels, beacon-shape cadence, DNS tunneling — with
the legacy IOC matcher demoted to an opt-in toggle. These tests exercise the
pure detector functions, the confirm-first gating, and the pass orchestration
with the Arkime client + DB faked out (no live Arkime/Ollama needed).
"""

import asyncio

import pytest

from ion.services import arkime_realtime_monitor_service as rtmon


# ── helpers ──────────────────────────────────────────────────────────────────
def _sess(**kw):
    base = {"communityId": "1:abc=", "node": "cap01", "srcIp": "10.0.0.5", "dstIp": "10.0.0.9"}
    base.update(kw)
    return base


# ── severity mapping (regression — externally referenced) ────────────────────
def test_rtmon_severity_mapping():
    assert rtmon._severity_for("critical") == "critical"
    assert rtmon._severity_for("HIGH") == "high"
    assert rtmon._severity_for("medium") == "medium"
    assert rtmon._severity_for("") == "medium"
    assert rtmon._severity_for(None) == "medium"


# ── small helpers ────────────────────────────────────────────────────────────
def test_is_external():
    assert rtmon._is_external("8.8.8.8") is True
    assert rtmon._is_external("10.0.0.1") is False
    assert rtmon._is_external("192.168.1.1") is False
    assert rtmon._is_external("127.0.0.1") is False
    assert rtmon._is_external("not-an-ip") is False


def test_shannon_entropy_discriminates():
    low = rtmon._shannon_entropy("aaaaaaaa")
    high = rtmon._shannon_entropy("a9Fk2Lp8Qz3Xv7Bn")
    assert high > low
    assert rtmon._shannon_entropy("") == 0.0


# ── detector: cleartext credentials ──────────────────────────────────────────
def test_cleartext_user_field_flags():
    cands = rtmon._detect_cleartext_credentials([_sess(user="admin", protocol=["ftp"])])
    assert len(cands) == 1
    c = cands[0]
    assert c["detector"] == "cleartext_credentials"
    assert c["severity"] == "high"
    assert c["confirm_first"] is False
    assert c["marker"] == "rtmon:cleartext_credentials:cap01:1:abc="
    assert c["evidence"]["user"] == "admin"


def test_cleartext_protocol_only_flags():
    cands = rtmon._detect_cleartext_credentials([_sess(protocol=["telnet"])])
    assert len(cands) == 1
    assert cands[0]["evidence"]["cleartext_protocol"] == "telnet"


def test_cleartext_user_as_list():
    cands = rtmon._detect_cleartext_credentials([_sess(user=["", "bob"], protocol=["http"])])
    assert len(cands) == 1
    assert cands[0]["evidence"]["user"] == "bob"


def test_cleartext_clean_https_not_flagged():
    # No parsed user, only TLS — nothing to recover.
    assert rtmon._detect_cleartext_credentials([_sess(protocol=["tls", "http"])]) == []


def test_cleartext_requires_community_and_node():
    assert rtmon._detect_cleartext_credentials([_sess(communityId="", user="x", protocol=["ftp"])]) == []


# ── detector: command / C2 channel ───────────────────────────────────────────
def test_command_telnet_flags():
    cands = rtmon._detect_command_channel([_sess(protocol=["telnet"])])
    assert len(cands) == 1
    assert cands[0]["detector"] == "command_channel"
    assert cands[0]["severity"] == "high"


def test_command_external_shell_port_flags():
    cands = rtmon._detect_command_channel([_sess(dstIp="45.77.198.7", dstPort=4444)])
    assert len(cands) == 1
    assert cands[0]["dst_port"] == 4444


def test_command_internal_shell_port_suppressed():
    # Port-only signal to an internal dst is suppressed (service-traffic noise).
    assert rtmon._detect_command_channel([_sess(dstIp="10.0.0.9", dstPort=4444)]) == []


def test_command_rsh_port_external_flags():
    cands = rtmon._detect_command_channel([_sess(dstIp="185.220.101.4", dstPort=514)])
    assert len(cands) == 1
    assert "rsh" in cands[0]["summary"].lower()


# ── detector: C2 beacon shape ────────────────────────────────────────────────
def _beacon_sessions(n=10, interval_ms=60000, size=512, dst="45.77.198.50", port=443):
    out = []
    base = 1_700_000_000_000
    for i in range(n):
        out.append(_sess(
            communityId=f"1:beacon{i}=", srcIp="10.0.0.5", dstIp=dst, dstPort=port,
            firstPacket=base + i * interval_ms, totBytes=size,
        ))
    return out


def test_beacon_regular_egress_flags_and_dedups():
    cands = rtmon._detect_beacon_shape(_beacon_sessions(n=12))
    assert len(cands) == 1  # 12 sessions of one tuple collapse to one beacon candidate
    c = cands[0]
    assert c["detector"] == "c2_beacon_shape"
    assert c["confirm_first"] is True and c["confirmed"] is True  # score gate already passed
    assert c["marker"] == "rtmon:beacon:10.0.0.5:45.77.198.50:443"
    assert c["evidence"]["connections"] >= 6
    assert c["evidence"]["score"] >= 0.9


def test_beacon_internal_dst_excluded():
    assert rtmon._detect_beacon_shape(_beacon_sessions(dst="10.0.0.50")) == []


def test_beacon_benign_ntp_port_excluded():
    assert rtmon._detect_beacon_shape(_beacon_sessions(port=123)) == []


def test_beacon_irregular_cadence_not_flagged():
    # Jittered intervals + sizes → regularity score below the gate.
    out = []
    base = 1_700_000_000_000
    jitter = [0, 5000, 41000, 3000, 90000, 12000, 60000, 8000, 75000, 2000, 50000, 30000]
    sizes = [200, 1500, 340, 9000, 80, 4200, 120, 6000, 95, 3300, 70, 8800]
    t = base
    for i, (j, sz) in enumerate(zip(jitter, sizes)):
        t += j
        out.append(_sess(communityId=f"1:j{i}=", dstIp="45.77.198.50", dstPort=443,
                          firstPacket=t, totBytes=sz))
    assert rtmon._detect_beacon_shape(out) == []


def test_beacon_too_few_connections_not_flagged():
    assert rtmon._detect_beacon_shape(_beacon_sessions(n=4)) == []


# ── detector: DNS tunneling ──────────────────────────────────────────────────
def test_dns_long_query_flags_candidate_unconfirmed():
    long_name = "a8f0e1c2d3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c.tunnel.evil.example"
    cands = rtmon._detect_dns_tunneling([_sess(dstIp="198.51.100.9", **{"dns.host": [long_name]})])
    assert len(cands) == 1
    c = cands[0]
    assert c["detector"] == "dns_tunneling"
    assert c["confirm_first"] is True and c["confirmed"] is False  # must be verified vs PCAP
    assert c["evidence"]["query_len"] == len(long_name)


def test_dns_normal_query_not_flagged():
    assert rtmon._detect_dns_tunneling([_sess(**{"dns.host": ["www.google.com"]})]) == []


def test_dns_nested_host_shape():
    long_name = "ZmlsZXRyYW5zZmVyMDAxYmVhY29uZGF0YWV4Zmls.c2.example"
    cands = rtmon._detect_dns_tunneling([_sess(dns={"host": [long_name]})])
    assert len(cands) == 1


# ── confirm-first: DNS tunnel PCAP re-analysis ───────────────────────────────
def _fake_finding(category):
    # parse_pcap stores findings as plain dicts — mirror that exact shape so
    # the confirm path is tested against reality, not a convenient object.
    return {"category": category, "severity": "high", "title": category}


class _FakePcapResult:
    def __init__(self, findings):
        self.findings = findings


def test_confirm_dns_tunnel_true_when_pipeline_agrees(monkeypatch):
    import ion.services.pcap_analysis_service as pas

    async def fake_analyze_one(cid, **kw):
        return {"pcap_result": _FakePcapResult([_fake_finding("DNS Tunneling")])}

    monkeypatch.setattr(pas, "_analyze_one", fake_analyze_one)
    cand = {"community_id": "1:x=", "node": "cap01", "src": "10.0.0.5", "dst": "8.8.8.8"}
    assert asyncio.run(rtmon._confirm_dns_tunnel(cand)) is True


def test_confirm_dns_tunnel_false_when_pipeline_disagrees(monkeypatch):
    import ion.services.pcap_analysis_service as pas

    async def fake_analyze_one(cid, **kw):
        return {"pcap_result": _FakePcapResult([_fake_finding("Cleartext Protocol")])}

    monkeypatch.setattr(pas, "_analyze_one", fake_analyze_one)
    cand = {"community_id": "1:x=", "node": "cap01", "src": "10.0.0.5", "dst": "8.8.8.8"}
    assert asyncio.run(rtmon._confirm_dns_tunnel(cand)) is False


def test_confirm_dns_tunnel_false_when_pcap_missing(monkeypatch):
    import ion.services.pcap_analysis_service as pas

    async def fake_analyze_one(cid, **kw):
        return {"pcap_result": None, "pcap_error": "unreachable"}

    monkeypatch.setattr(pas, "_analyze_one", fake_analyze_one)
    cand = {"community_id": "1:x=", "node": "cap01", "src": "10.0.0.5", "dst": "8.8.8.8"}
    assert asyncio.run(rtmon._confirm_dns_tunnel(cand)) is False


# ── legacy IOC detector ──────────────────────────────────────────────────────
def test_ioc_detector_maps_severity():
    iocs = {"203.0.113.66": {"threat_level": "critical", "label": "IOC", "observable_id": 7}}
    cands = rtmon._detect_ioc_ip([_sess(dstIp="203.0.113.66")], iocs)
    assert len(cands) == 1
    assert cands[0]["detector"] == "ioc_ip"
    assert cands[0]["severity"] == "critical"


def test_ioc_detector_no_match():
    assert rtmon._detect_ioc_ip([_sess(dstIp="8.8.8.8")], {"1.2.3.4": {}}) == []


# ── _gather_candidates dispatch + toggles ────────────────────────────────────
class _FakeArkime:
    is_configured = True

    def __init__(self, by_expr):
        self.by_expr = by_expr
        self.calls = []

    async def find_recent_sessions_by_expression(self, expr, **kw):
        self.calls.append(expr)
        for needle, sessions in self.by_expr.items():
            if needle in expr:
                return sessions
        return []

    async def find_recent_sessions_for_ips(self, ips, **kw):
        return []


def test_gather_runs_enabled_detectors(monkeypatch):
    for k in ("CLEARTEXT", "COMMAND", "BEACON", "DNS"):
        monkeypatch.delenv(f"ION_ARKIME_RTMON_{k}_ENABLED", raising=False)
    svc = _FakeArkime({
        "user == EXISTS!": [_sess(user="root", protocol=["ftp"])],
        "protocols == telnet": [_sess(protocol=["telnet"])],
        "ip.dst != 10.0.0.0/8": _beacon_sessions(n=10),
        "protocols == dns": [_sess(**{"dns.host": ["x" * 60 + ".evil.example"]})],
    })
    cands = asyncio.run(rtmon._gather_candidates(svc))
    detectors = {c["detector"] for c in cands}
    assert detectors == {"cleartext_credentials", "command_channel", "c2_beacon_shape", "dns_tunneling"}


def test_gather_respects_detector_toggle(monkeypatch):
    monkeypatch.setenv("ION_ARKIME_RTMON_CLEARTEXT_ENABLED", "false")
    monkeypatch.setenv("ION_ARKIME_RTMON_COMMAND_ENABLED", "false")
    monkeypatch.setenv("ION_ARKIME_RTMON_BEACON_ENABLED", "false")
    monkeypatch.delenv("ION_ARKIME_RTMON_DNS_ENABLED", raising=False)
    svc = _FakeArkime({"protocols == dns": [_sess(**{"dns.host": ["y" * 60 + ".evil.example"]})]})
    cands = asyncio.run(rtmon._gather_candidates(svc))
    assert {c["detector"] for c in cands} == {"dns_tunneling"}
    # Disabled detectors must not even issue their Arkime sweep.
    assert not any("user == EXISTS" in e for e in svc.calls)


# ── _run_pass orchestration (Arkime + DB faked) ──────────────────────────────
class _FakeQuery:
    def __init__(self, first_val=None, rows=None):
        self._first = first_val
        self._rows = rows or []

    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def join(self, *a, **k):
        return self

    def first(self):
        return self._first

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, triage_first=None, actioned=()):
        self.added = []
        self.commits = 0
        self.triage_first = triage_first
        self._next_id = 1
        # markers already actioned in a prior pass — served to the batched
        # (es_alert_id IN (...)) dedup query as one-tuples, like SQLAlchemy.
        self.actioned = [(m,) for m in actioned]

    def query(self, model):
        name = str(getattr(model, "__name__", model))
        if "AlertTriage" in name:
            return _FakeQuery(first_val=self.triage_first, rows=list(self.actioned))
        return _FakeQuery(first_val=None)

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        # Model the DB assigning a primary key on flush (assign_case_number
        # derives CASE-NNNN from case.id).
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                try:
                    obj.id = self._next_id
                    self._next_id += 1
                except Exception:
                    pass

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass


def _wire_run_pass(monkeypatch, svc, session, enqueue_calls):
    import ion.services.ai_user as ai_user
    import ion.services.arkime_service as arkime_service
    import ion.services.pcap_analysis_service as pas
    import ion.storage.database as database

    monkeypatch.setattr(arkime_service, "get_arkime_service", lambda: svc)
    monkeypatch.setattr(ai_user, "get_bob_user_id", lambda s: 1)
    monkeypatch.setattr(database, "get_session_factory", lambda engine: (lambda: session))
    monkeypatch.setattr(pas, "enqueue_pcap_analysis_for_case",
                        lambda **kw: enqueue_calls.append(kw))


def _isolate_to(monkeypatch, *keep):
    for k in ("CLEARTEXT", "COMMAND", "BEACON", "DNS", "IOC"):
        monkeypatch.setenv(f"ION_ARKIME_RTMON_{k}_ENABLED", "true" if k in keep else "false")


def test_run_pass_opens_cleartext_case(monkeypatch):
    _isolate_to(monkeypatch, "CLEARTEXT")
    svc = _FakeArkime({"user == EXISTS!": [_sess(user="root", protocol=["ftp"])]})
    session = _FakeSession()
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))

    # case + triage marker + note added; PCAP enqueued for deep evidence.
    assert len(enqueue_calls) == 1
    assert enqueue_calls[0]["flows"][0]["community_id"] == "1:abc="
    assert session.commits >= 1
    assert len(session.added) == 3


def test_run_pass_dns_not_confirmed_opens_no_case(monkeypatch):
    _isolate_to(monkeypatch, "DNS")
    import ion.services.pcap_analysis_service as pas

    async def fake_analyze_one(cid, **kw):
        return {"pcap_result": _FakePcapResult([])}  # pipeline finds nothing

    monkeypatch.setattr(pas, "_analyze_one", fake_analyze_one)
    svc = _FakeArkime({"protocols == dns": [_sess(**{"dns.host": ["z" * 60 + ".evil.example"]})]})
    session = _FakeSession()
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))

    assert enqueue_calls == []
    assert session.added == []


def test_run_pass_dns_confirmed_opens_case(monkeypatch):
    _isolate_to(monkeypatch, "DNS")
    import ion.services.pcap_analysis_service as pas

    async def fake_analyze_one(cid, **kw):
        return {"pcap_result": _FakePcapResult([_fake_finding("DNS Tunneling")])}

    monkeypatch.setattr(pas, "_analyze_one", fake_analyze_one)
    svc = _FakeArkime({"protocols == dns": [_sess(**{"dns.host": ["q" * 60 + ".evil.example"]})]})
    session = _FakeSession()
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))

    assert len(enqueue_calls) == 1


def test_run_pass_dedups_already_actioned_marker(monkeypatch):
    _isolate_to(monkeypatch, "CLEARTEXT")
    svc = _FakeArkime({"user == EXISTS!": [_sess(user="root", protocol=["ftp"])]})
    # marker already actioned in a prior pass → the batched dedup skips it
    session = _FakeSession(actioned=["rtmon:cleartext_credentials:cap01:1:abc="])
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))

    assert enqueue_calls == []
    assert session.added == []


def test_run_pass_disabled_when_arkime_unconfigured(monkeypatch):
    _isolate_to(monkeypatch, "CLEARTEXT")

    class _Down:
        is_configured = False

    svc = _Down()
    session = _FakeSession()
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))
    assert enqueue_calls == []


# ── v0.49.3 code-review fixes ────────────────────────────────────────────────
def _ioc_db():
    """In-memory DB with just the Observable tables the IOC loader touches."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from ion.models import observable as obs_mod

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for cls_name in ("Observable", "ObservableEnrichment", "ObservableLink"):
        cls = getattr(obs_mod, cls_name, None)
        if cls is not None:
            cls.__table__.create(engine, checkfirst=True)
    return sessionmaker(bind=engine)()


def test_ioc_hit_severity_uses_enum_value_not_str():
    """str(ThreatLevel.CRITICAL) is 'ThreatLevel.CRITICAL', which _severity_for
    can never match — a known-critical IOC must file a *critical* case."""
    from ion.models.observable import Observable, ObservableType, ThreatLevel

    session = _ioc_db()
    session.add(Observable(type=ObservableType.IPV4, value="198.18.0.9",
                           normalized_value="198.18.0.9", is_ioc=True,
                           threat_level=ThreatLevel.CRITICAL))
    session.add(Observable(type=ObservableType.IPV4, value="198.18.0.10",
                           normalized_value="198.18.0.10", is_ioc=True,
                           threat_level=ThreatLevel.HIGH))
    session.commit()

    iocs = rtmon._load_ioc_ips(session)
    assert iocs["198.18.0.9"]["threat_level"] == "critical"
    assert iocs["198.18.0.10"]["threat_level"] == "high"

    sessions = [{"node": "n1", "communityId": "1:abc=",
                 "srcIp": "10.0.0.5", "dstIp": "198.18.0.9", "dstPort": 443}]
    cands = rtmon._detect_ioc_ip(sessions, iocs)
    assert len(cands) == 1
    assert cands[0]["severity"] == "critical"
    # the human-readable summary must show 'critical', not 'ThreatLevel.CRITICAL'
    assert "ThreatLevel." not in cands[0]["summary"]


def test_is_external_matches_arkime_service_semantics():
    """ArkimeService._is_private_ip is deliberately RFC-1918-only because
    documentation/test ranges show up in real pcap; the realtime monitor must
    not silently discard those flows as 'internal'."""
    # documentation ranges are routable-in-practice → external
    assert rtmon._is_external("203.0.113.5") is True
    assert rtmon._is_external("192.0.2.7") is True
    assert rtmon._is_external("198.51.100.23") is True
    # genuinely private/special ranges stay internal
    assert rtmon._is_external("10.1.2.3") is False
    assert rtmon._is_external("172.16.5.5") is False
    assert rtmon._is_external("192.168.1.1") is False
    assert rtmon._is_external("127.0.0.1") is False
    assert rtmon._is_external("169.254.1.1") is False
    assert rtmon._is_external("224.0.0.1") is False
    assert rtmon._is_external("8.8.8.8") is True
    assert rtmon._is_external("not-an-ip") is False


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


# ── v0.49.3: DB work must not block the event loop; dedup must be batched ────
class _LoopProbeSession(_FakeSession):
    """Records any DB touch that executes ON the event loop (each blocking
    query/commit stalls every HTTP request and SSE stream on the worker)."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.on_loop_calls = []
        self.triage_queries = 0

    def _probe(self, what):
        try:
            asyncio.get_running_loop()
            self.on_loop_calls.append(what)
        except RuntimeError:
            pass  # in a worker thread — good

    def query(self, model):
        name = str(getattr(model, "__name__", model))
        self._probe(f"query:{name}")
        if "AlertTriage" in name:
            self.triage_queries += 1
        return super().query(model)

    def commit(self):
        self._probe("commit")
        super().commit()

    def flush(self):
        self._probe("flush")
        super().flush()


def _three_cleartext_sessions():
    return [
        _sess(user="root", protocol=["ftp"], communityId="1:aaa="),
        _sess(user="admin", protocol=["telnet"], communityId="1:bbb="),
        _sess(user="svc", protocol=["ftp"], communityId="1:ccc="),
    ]


def test_run_pass_db_work_runs_off_event_loop(monkeypatch):
    _isolate_to(monkeypatch, "CLEARTEXT")
    svc = _FakeArkime({"user == EXISTS!": _three_cleartext_sessions()})
    session = _LoopProbeSession()
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))

    assert len(enqueue_calls) == 3  # behaviour unchanged: all cases open
    assert session.on_loop_calls == [], (
        f"blocking DB work ran on the event loop: {session.on_loop_calls}"
    )


def test_run_pass_dedup_lookup_is_batched(monkeypatch):
    """One IN-query for all candidate markers, not one SELECT per candidate."""
    _isolate_to(monkeypatch, "CLEARTEXT")
    svc = _FakeArkime({"user == EXISTS!": _three_cleartext_sessions()})
    session = _LoopProbeSession()
    enqueue_calls = []
    _wire_run_pass(monkeypatch, svc, session, enqueue_calls)

    asyncio.run(rtmon._run_pass(engine=None))

    assert len(enqueue_calls) == 3
    assert session.triage_queries == 1, (
        f"expected one batched dedup query, saw {session.triage_queries}"
    )
