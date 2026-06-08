"""Regression tests for the high-severity code-review fixes.

Two independent defects found by the full-sweep review and fixed here:

  1. SQL injection in TIDE ``system_id`` path parameter
     (``tide_service.get_system_detail`` / ``get_mitre_coverage``) — the
     user-controlled id was f-string-interpolated into SQL with no escaping,
     while the sibling ``get_system_use_case_coverage`` already escaped it.
     Fix: single-quote-double the id before interpolation (house pattern).

  2. ``investigate_case`` unpacked a 4-tuple from ``_call_llm`` which returns
     a 5-tuple, raising ``ValueError`` on every successful LLM call and
     leaving an orphaned "running" Investigation row. Fix: unpack 5 values.
     Guarded here with an AST contract test so the arity can't drift again.
"""

import ast
import inspect
import logging

import pytest

from ion.core import config as cfg_mod
from ion.core.config import Config, get_oidc_config, set_config
from ion.services import investigation_service
from ion.services.pcap_service import PcapResult, _build_network_graph
from ion.services.tide_service import TideService


# ---------------------------------------------------------------------------
# 1. TIDE SQL-injection escaping (behavioural)
# ---------------------------------------------------------------------------
# A classic break-out payload: a single quote closes the literal, the rest is
# attacker SQL. After escaping, the quote must appear doubled ('') and the
# raw break-out (`... = 'evil' OR ...`) must NOT survive into the query text.
_PAYLOAD = "evil' OR '1'='1' --"


def _service_capturing_sql():
    """A TideService whose _query records the SQL instead of hitting TIDE."""
    svc = TideService()
    svc.enabled = True          # bypass the config gate
    svc.space = "default"
    captured: list[str] = []

    def _fake_query(sql, retries=1):
        captured.append(sql)
        # Minimal shape the callers expect so they don't blow up post-query
        # (get_system_detail reads ["total"], get_mitre_coverage reads rows).
        return {"rows": [{"id": "x", "technique_id": "T1059", "total": 0}]}

    svc._query = _fake_query
    return svc, captured


def _assert_escaped(captured: list[str]):
    assert captured, "expected at least one query to be issued"
    joined = "\n".join(captured)
    # The break-out must not appear unescaped anywhere.
    assert "'evil' OR" not in joined, (
        f"unescaped single-quote break-out reached SQL:\n{joined}"
    )
    # The escaped form (doubled quotes) must be present, proving we escaped
    # rather than merely dropping the payload.
    assert "evil'' OR ''1''=''1" in joined, (
        f"payload was not single-quote-escaped:\n{joined}"
    )


def test_get_system_detail_escapes_system_id():
    svc, captured = _service_capturing_sql()
    svc.get_system_detail(_PAYLOAD)
    _assert_escaped(captured)


def test_get_mitre_coverage_escapes_system_id():
    svc, captured = _service_capturing_sql()
    svc.get_mitre_coverage(_PAYLOAD)
    _assert_escaped(captured)


# ---------------------------------------------------------------------------
# 2. _call_llm unpack-arity contract (static / AST)
# ---------------------------------------------------------------------------
# investigate_case crashed because it unpacked 4 values from _call_llm's
# 5-tuple. Rather than stand up the full cluster-investigation pipeline, we
# assert the contract directly: every `await self._call_llm(...)` assignment
# must unpack exactly as many names as _call_llm returns.

_EXPECTED_ARITY = 5


def _module_tree():
    src = inspect.getsource(investigation_service)
    return ast.parse(src)


def _call_llm_unpack_sites(tree):
    """Yield the target tuples of every `... = await self._call_llm(...)`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Await):
            continue
        call = value.value
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "_call_llm":
            yield node


def test_every_call_llm_caller_unpacks_full_arity():
    tree = _module_tree()
    sites = list(_call_llm_unpack_sites(tree))
    # investigate_alert + investigate_case both call it — guard against the
    # test silently passing if the calls were renamed away.
    assert len(sites) >= 2, (
        f"expected >=2 _call_llm call sites, found {len(sites)}"
    )
    for site in sites:
        target = site.targets[0]
        assert isinstance(target, ast.Tuple), (
            f"_call_llm result at line {site.lineno} is not tuple-unpacked"
        )
        assert len(target.elts) == _EXPECTED_ARITY, (
            f"_call_llm caller at line {site.lineno} unpacks "
            f"{len(target.elts)} values, expected {_EXPECTED_ARITY}"
        )


def test_call_llm_returns_full_arity():
    """The other half of the contract: _call_llm itself returns 5 values."""
    tree = _module_tree()
    func = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_call_llm"
    )
    returns = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
    ]
    assert returns, "_call_llm has no tuple return statements"
    for ret in returns:
        assert len(ret.value.elts) == _EXPECTED_ARITY, (
            f"_call_llm return at line {ret.lineno} yields "
            f"{len(ret.value.elts)} values, expected {_EXPECTED_ARITY}"
        )


# ---------------------------------------------------------------------------
# 3. OIDC TLS-verification-disabled startup warning (finding #1)
# ---------------------------------------------------------------------------
# The insecure default (verify off) is retained for air-gapped/self-signed
# deployments, but it must be loud, not silent — a once-only WARNING when OIDC
# is enabled with verification off.
@pytest.fixture
def _restore_config():
    """Snapshot/restore the global Config + warn-once flag around a test."""
    saved = cfg_mod._config
    saved_flag = cfg_mod._oidc_tls_warned
    try:
        yield
    finally:
        set_config(saved)
        cfg_mod._oidc_tls_warned = saved_flag


def _install_config(**overrides):
    c = Config()
    for k, v in overrides.items():
        setattr(c, k, v)
    set_config(c)
    cfg_mod._oidc_tls_warned = False  # reset warn-once for a clean assertion


_WARN_MARKER = "OIDC TLS verification is DISABLED"


def test_oidc_tls_disabled_logs_warning(_restore_config, caplog):
    _install_config(oidc_enabled=True, oidc_verify_ssl=False)
    with caplog.at_level(logging.WARNING, logger="ion.core.config"):
        get_oidc_config()
    assert any(_WARN_MARKER in r.message for r in caplog.records), (
        "expected a loud warning when OIDC is enabled with TLS verification off"
    )


def test_oidc_tls_disabled_warns_only_once(_restore_config, caplog):
    _install_config(oidc_enabled=True, oidc_verify_ssl=False)
    with caplog.at_level(logging.WARNING, logger="ion.core.config"):
        get_oidc_config()
        get_oidc_config()
        get_oidc_config()
    hits = [r for r in caplog.records if _WARN_MARKER in r.message]
    assert len(hits) == 1, f"warning should fire once, fired {len(hits)}x"


def test_oidc_tls_enabled_no_warning(_restore_config, caplog):
    _install_config(oidc_enabled=True, oidc_verify_ssl=True)
    with caplog.at_level(logging.WARNING, logger="ion.core.config"):
        get_oidc_config()
    assert not any(_WARN_MARKER in r.message for r in caplog.records), (
        "no warning expected when TLS verification is on"
    )


def test_oidc_disabled_no_warning(_restore_config, caplog):
    # OIDC off entirely: the insecure-TLS flag is irrelevant, stay quiet.
    _install_config(oidc_enabled=False, oidc_verify_ssl=False)
    with caplog.at_level(logging.WARNING, logger="ion.core.config"):
        get_oidc_config()
    assert not any(_WARN_MARKER in r.message for r in caplog.records), (
        "no warning expected when OIDC is disabled"
    )


# ---------------------------------------------------------------------------
# 4. PCAP network graph reads the real conversation shape (finding #6)
# ---------------------------------------------------------------------------
# parse_pcap emits conversations as {"pair": "<a> <-> <b>", "bytes": n}; the
# graph builder previously read non-existent src/dst keys and returned an
# always-empty graph for every capture.
def test_network_graph_populated_from_pair_conversations():
    result = PcapResult()
    result.conversations = [
        {"pair": "10.0.0.5 <-> 8.8.8.8", "bytes": 5 * 1024 * 1024},
        {"pair": "10.0.0.5 <-> 192.168.1.10", "bytes": 2048},
    ]
    graph = _build_network_graph(result)

    # Three distinct IPs -> three nodes; two conversations -> two edges.
    assert graph["stats"]["total_nodes"] == 3, graph["stats"]
    assert graph["stats"]["total_edges"] == 2, graph["stats"]
    node_ids = {n["id"] for n in graph["nodes"]}
    assert node_ids == {"10.0.0.5", "8.8.8.8", "192.168.1.10"}

    # Internal/external classification flows through to stats.
    assert graph["stats"]["internal_nodes"] == 2   # 10.x + 192.168.x
    assert graph["stats"]["external_nodes"] == 1    # 8.8.8.8

    # The MB-scale edge is labelled by volume, not left blank.
    big = next(e for e in graph["edges"] if e["to"] == "8.8.8.8" or e["from"] == "8.8.8.8")
    assert "MB" in big["label"]


def test_network_graph_empty_when_no_conversations():
    graph = _build_network_graph(PcapResult())
    assert graph["stats"]["total_nodes"] == 0
    assert graph["stats"]["total_edges"] == 0


def test_network_graph_skips_malformed_pair():
    result = PcapResult()
    result.conversations = [
        {"pair": "not-a-pair", "bytes": 10},     # no " <-> " separator
        {"bytes": 10},                            # missing pair entirely
        {"pair": "1.2.3.4 <-> 5.6.7.8", "bytes": 100},
    ]
    graph = _build_network_graph(result)
    assert graph["stats"]["total_edges"] == 1
    assert {n["id"] for n in graph["nodes"]} == {"1.2.3.4", "5.6.7.8"}


# ---------------------------------------------------------------------------
# 5. Wallboard AIFeedback dedup + pending exclusion (finding #5)
# ---------------------------------------------------------------------------
# The AIFeedback ledger is dual-written (pending fire-time row + case-close
# row). The wallboard reader must dedup by MAX(id) per (alert_id, template_id)
# and exclude the "pending" sentinel from agreement, or both feedback_7d_total
# and agreement_pct are wrong.
def _bob_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from ion.models.ai_feedback import AIFeedback
    from ion.models.investigation import Investigation

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Only the two tables _collect_bob touches; FK targets (users, cases) are
    # not enforced under SQLite so we don't need to materialise them.
    AIFeedback.__table__.create(engine)
    Investigation.__table__.create(engine)
    return sessionmaker(bind=engine)(), AIFeedback


def test_wallboard_bob_dedups_and_excludes_pending():
    from ion.services.wallboard_service import _collect_bob

    session, AIFeedback = _bob_db()
    # alert A / template 1: pending fire-time row THEN case-close row.
    # Dedup must keep only the close row (a true_positive match).
    session.add(AIFeedback(alert_id="A", alert_prompt_template_id=1,
                           bob_suggested_verdict="true_positive", human_verdict="pending"))
    session.add(AIFeedback(alert_id="A", alert_prompt_template_id=1,
                           bob_suggested_verdict="true_positive", human_verdict="true_positive"))
    # alert B / template 1: still pending (no close yet) — counts toward volume
    # but must be excluded from agreement.
    session.add(AIFeedback(alert_id="B", alert_prompt_template_id=1,
                           bob_suggested_verdict="false_positive", human_verdict="pending"))
    # alert C / template 2: resolved disagreement.
    session.add(AIFeedback(alert_id="C", alert_prompt_template_id=2,
                           bob_suggested_verdict="true_positive", human_verdict="false_positive"))
    session.commit()

    bob = _collect_bob(session)

    # 4 physical rows -> 3 logical after dedup (A's pending+close collapse).
    assert bob["feedback_7d_total"] == 3, bob
    # Agreement scored only over the 2 RESOLVED rows (A match, C mismatch).
    assert bob["agreement_total"] == 2, bob
    assert bob["agreement_count"] == 1, bob
    assert bob["agreement_pct"] == 50, bob  # pre-fix this was 25 over 4 raw rows


def test_wallboard_bob_no_feedback_is_safe():
    from ion.services.wallboard_service import _collect_bob

    session, _ = _bob_db()
    bob = _collect_bob(session)
    assert bob["feedback_7d_total"] == 0
    assert bob["agreement_total"] == 0
    assert bob["agreement_pct"] is None  # no divide-by-zero, no false 0%


# ---------------------------------------------------------------------------
# 6. OIDC identity matching: sub-first + rebind guard (finding #4, safe subset)
# ---------------------------------------------------------------------------
def _user_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from ion.models.user import User  # registers User/Role/Permission tables

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    User.metadata.create_all(engine)
    return sessionmaker(bind=engine)(), User


def _token(sub, email="", username=""):
    from ion.auth.oidc import OIDCTokenData
    return OIDCTokenData(sub=sub, email=email, preferred_username=username)


def _sync(session):
    from ion.auth.oidc import OIDCUserSync
    from ion.auth.oidc_config import OIDCConfig
    return OIDCUserSync(session, OIDCConfig(enabled=True, auto_create_users=True))


def test_get_by_keycloak_sub_matches_immutable_subject():
    session, User = _user_db()
    u = User(username="alice", email="alice@corp.test",
             password_hash="x", keycloak_sub="SUB-ALICE")
    session.add(u)
    session.commit()

    repo = _sync(session).user_repo
    assert repo.get_by_keycloak_sub("SUB-ALICE").username == "alice"
    assert repo.get_by_keycloak_sub("SUB-NOBODY") is None
    assert repo.get_by_keycloak_sub("") is None  # empty sub must not match


def test_guard_rebind_refuses_cross_subject_takeover():
    session, User = _user_db()
    # Victim already federated to subject VICTIM.
    victim = User(username="victim", email="victim@corp.test",
                  password_hash="x", keycloak_sub="SUB-VICTIM")
    session.add(victim)
    session.commit()

    sync = _sync(session)
    # Attacker token carries victim's email but a DIFFERENT subject.
    attacker_tok = _token("SUB-ATTACKER", email="victim@corp.test")
    # The email match returns the victim row; the guard must reject the rebind.
    assert sync._guard_rebind(victim, attacker_tok) is None


def test_guard_rebind_allows_unfederated_account():
    session, User = _user_db()
    # Pre-provisioned local account with no keycloak_sub yet — still bindable,
    # preserving today's behaviour for realms without verified email.
    local = User(username="bob", email="bob@corp.test",
                 password_hash="x", keycloak_sub=None)
    sync = _sync(session)
    tok = _token("SUB-BOB", email="bob@corp.test")
    assert sync._guard_rebind(local, tok) is local


def test_guard_rebind_allows_same_subject_and_handles_none():
    session, User = _user_db()
    sync = _sync(session)
    same = User(username="carol", email="carol@corp.test",
                password_hash="x", keycloak_sub="SUB-CAROL")
    tok = _token("SUB-CAROL", email="carol@corp.test")
    assert sync._guard_rebind(same, tok) is same      # same subject -> ok
    assert sync._guard_rebind(None, tok) is None       # no candidate -> None


# ---------------------------------------------------------------------------
# 7. Bob-eval serialisation locks are session-scoped on a dedicated conn (#7)
# ---------------------------------------------------------------------------
# The serialisation lock must survive the COMMITs inside _execute_eval, so it
# must use the session-scoped pg_try_advisory_lock (NOT pg_advisory_xact_lock,
# which releases on COMMIT) and be released explicitly. The Postgres path can't
# run under SQLite, so we unit-test the lock helpers against a fake connection.
class _FakeResult:
    def __init__(self, val):
        self._val = val

    def scalar(self):
        return self._val


class _FakeConn:
    def __init__(self, grant=True):
        self.calls = []
        self._grant = grant

    def execute(self, clause, params=None):
        self.calls.append((str(clause), params))
        return _FakeResult(self._grant)


def test_try_lock_uses_session_scoped_function():
    from ion.services.bob_eval_service import _try_lock_on

    conn = _FakeConn(grant=True)
    assert _try_lock_on(conn, 7, 42) is True
    sql, params = conn.calls[-1]
    # Session-scoped form — must NOT regress to the xact form that COMMIT drops.
    assert "pg_try_advisory_lock" in sql
    assert "xact" not in sql
    assert params == {"ns": 7, "key": 42}


def test_try_lock_reports_contention():
    from ion.services.bob_eval_service import _try_lock_on

    assert _try_lock_on(_FakeConn(grant=False), 7, 42) is False


def test_release_locks_unlocks_all():
    from ion.services.bob_eval_service import _release_locks_on

    conn = _FakeConn()
    _release_locks_on(conn)
    assert any("pg_advisory_unlock_all" in sql for sql, _ in conn.calls)


def test_eval_lock_namespaces_are_distinct():
    # Per-template and per-run locks must not alias onto the same (ns, key).
    from ion.services import bob_eval_service as b

    assert b._BPEH_NS != b._BPEH_RUN_NS


# ---------------------------------------------------------------------------
# 8. Assorted low-severity hardening (findings #2/#3/#5 lows)
# ---------------------------------------------------------------------------
class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeReq:
    def __init__(self, peer, headers=None):
        self.client = _FakeClient(peer) if peer is not None else None
        self.headers = headers or {}


def test_x_real_ip_malformed_falls_back_to_peer(monkeypatch):
    # A trusted proxy peer with a garbage X-Real-IP must NOT leak the garbage
    # into source_ip / rate-limit keys — fall back to the validated peer.
    import ipaddress

    from ion.core import client_ip as cip

    monkeypatch.setattr(cip, "_TRUSTED_PROXIES", [ipaddress.ip_network("10.0.0.0/8")])
    req = _FakeReq("10.0.0.5", {"X-Real-IP": "not-an-ip"})
    assert cip.get_client_ip(req) == "10.0.0.5"

    # And a well-formed X-Real-IP is still honoured (no regression).
    req_ok = _FakeReq("10.0.0.5", {"X-Real-IP": "198.51.100.42"})
    assert cip.get_client_ip(req_ok) == "198.51.100.42"


def test_reset_password_enforces_policy_when_enabled(_restore_config):
    from ion.auth.service import AuthService
    from ion.models.user import User

    session, _ = _user_db()
    _install_config(password_min_length=12)  # turn F6 policy ON
    svc = AuthService(session)
    user = User(username="target", email="t@corp.test", password_hash="x")

    # Weak password must be rejected at the reset path (was silently accepted).
    import pytest as _pytest
    with _pytest.raises(ValueError):
        svc.reset_password(user, "short", must_change=True)


def test_reset_password_policy_noop_when_disabled(_restore_config):
    # With the policy off (default), the reset path must not raise on a short
    # password (preserves pre-F6 behaviour). It will proceed to hashing.
    from ion.auth.service import AuthService
    from ion.models.user import User

    session, _ = _user_db()
    _install_config(password_min_length=0)
    svc = AuthService(session)
    svc.audit_repo.create = lambda **kw: None  # avoid needing the audit table
    user = User(username="target2", email="t2@corp.test", password_hash="x")
    session.add(user)
    session.commit()
    # Should not raise a ValueError from the policy gate.
    svc.reset_password(user, "short", must_change=True)
    assert user.must_change_password is True
