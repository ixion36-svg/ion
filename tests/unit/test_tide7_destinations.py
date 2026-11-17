"""ION against TIDE 7: rules at every destination, and refusals that say why.

TIDE 7 keeps Wazuh rules in detection_rules beside Elastic ones, with the
space column holding a Wazuh agent group or `*`, and counts a client's rules
across every destination. ION filtered on one Kibana space, so on a live
TIDE 7 tenant of 2 Elastic and 3 Wazuh rules its posture read 2 rules and 1
covered technique. TIDE 7 also refuses keys whose owner is not a real user,
and ION turned that 401 into an empty page.
"""
from __future__ import annotations

import re
from typing import Optional

import httpx
import pytest

import ion.services.tide_service as ts
from ion.core.circuit_breaker import CircuitState, tide_breaker
from ion.services.tide_service import Destination, TideService


class _Recording(TideService):
    """Answers every statement with `rows` and records it. `columns` is the
    set of multi-SIEM columns this TIDE has; a probe for any other is refused
    the way TIDE refuses an unknown column."""

    def __init__(self, *, scope=None, columns=("siem_id", "rule_type"), rows=None):
        self.enabled = True
        self.scope = scope
        self.columns = columns
        self.rows = rows if rows is not None else []
        self.sent: list[str] = []

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        q = " ".join(sql.split())
        self.sent.append(q)
        probe = re.fullmatch(r"SELECT (\w+) FROM detection_rules LIMIT 0", q)
        if probe:
            return {"rows": []} if probe.group(1) in self.columns else None
        return {"rows": list(self.rows)}


def _every_rule_read(svc: TideService) -> None:
    svc.get_detection_rules("power")
    svc.get_mitre_coverage("sys-1")
    svc.get_global_mitre_coverage()
    svc.get_posture_stats()
    svc.get_disabled_critical_high()
    svc.get_rules_paginated(search="x", severity="high", enabled="1")
    svc.get_gaps_analysis()
    svc.get_system_use_case_coverage("sys-1")
    svc.get_enabled_rule_counts_by_technique()


def _rule_reads(svc: _Recording) -> list[str]:
    return [q for q in svc.sent
            if "detection_rules dr" in q and "LIMIT 0" not in q]


@pytest.fixture(autouse=True)
def _catalogue(monkeypatch):
    from ion.services import attack_catalogue
    monkeypatch.setattr(attack_catalogue, "techniques", lambda: (
        {"technique_id": "T1110", "name": "Brute Force", "tactic": "credential-access"},))


# ---------------------------------------------------------------------------
# Destinations and scope
# ---------------------------------------------------------------------------


def test_a_destination_key_round_trips_including_the_wazuh_wildcard():
    dest = Destination(space="*", siem_id="siem-wazuh")
    assert Destination.from_key(dest.key) == dest
    assert Destination.from_key("|default") == Destination(space="default")
    assert Destination.from_key("default") == Destination(space="default")


@pytest.mark.parametrize("key", ["siem|x' OR '1'='1", "siem|", "a;b|c", "|" + "x" * 65])
def test_a_destination_that_could_break_out_of_its_literal_is_refused(key):
    with pytest.raises(ValueError):
        Destination.from_key(key)


def test_all_destinations_reads_rules_with_no_space_filter():
    svc = _Recording()
    _every_rule_read(svc)
    reads = _rule_reads(svc)
    assert len(reads) >= 12
    assert not [q for q in reads if re.search(r"dr\.space = '", q)]


def test_one_destination_narrows_every_rule_read():
    """The scope is rendered in one place; this pins that no query kept a
    hand-written filter or forgot the scope."""
    svc = _Recording(scope=Destination(space="linux-servers", siem_id="siem-wazuh"))
    _every_rule_read(svc)
    reads = _rule_reads(svc)
    missing = [q for q in reads
               if "dr.siem_id = 'siem-wazuh' AND dr.space = 'linux-servers'" not in q]
    assert reads and not missing


def test_a_space_only_setting_matches_that_space_on_every_siem():
    svc = _Recording(scope=Destination(space="default"))
    svc.get_posture_stats()
    posture = next(q for q in svc.sent if "q_excellent" in q)
    assert "dr.space = 'default'" in posture
    assert "siem_id =" not in posture


def test_rule_counts_tell_deployed_rules_apart_by_destination():
    """rule_id is unique only inside one destination; the same Wazuh rule id
    in two agent groups is two deployed rules."""
    svc = _Recording()
    svc.get_global_mitre_coverage()
    svc.get_posture_stats()
    counted = [q for q in svc.sent if "count(DISTINCT" in q]
    assert counted
    assert not [q for q in counted if "count(DISTINCT dr.rule_id)" in q]
    assert all("(dr.rule_id, dr.siem_id, dr.space)" in q for q in counted)


def test_a_tide_without_siem_ids_keeps_working_on_space_alone():
    svc = _Recording(columns=(), scope=Destination(space="default", siem_id="ignored"))
    svc.get_posture_stats()
    svc.get_rules_paginated()
    posture = next(q for q in svc.sent if "q_excellent" in q)
    listing = next(q for q in svc.sent if "OVER()" in q)
    assert "(dr.rule_id, dr.space)" in posture
    assert "siem_id" not in posture
    assert "NULL AS siem_id" in listing and "'elastic' AS kind" in listing


def test_the_paginated_total_counts_rules_after_de_duplication():
    """count(*) OVER() beside SELECT DISTINCT is evaluated before the
    DISTINCT, so the total counted duplicate rows the page then dropped."""
    svc = _Recording(rows=[{"rule_id": "r1", "_total": 1}])
    out = svc.get_rules_paginated()
    listing = next(q for q in svc.sent if "OVER()" in q)
    assert re.search(r"WITH r AS \( SELECT DISTINCT .*\) SELECT \*, count\(\*\) OVER\(\) AS _total FROM r", listing)
    assert out == {"rows": [{"rule_id": "r1"}], "total": 1}


def test_destinations_are_listed_and_unfilterable_ones_left_out():
    svc = _Recording(rows=[
        {"siem_id": "siem-elastic", "space": "default", "kind": "elastic", "rule_count": 2},
        {"siem_id": "siem-wazuh", "space": "*", "kind": "wazuh", "rule_count": 2},
        {"siem_id": "siem-wazuh", "space": "it's", "kind": "wazuh", "rule_count": 1},
    ])
    assert svc.get_destinations() == [
        {"key": "siem-elastic|default", "siem_id": "siem-elastic", "space": "default",
         "kind": "elastic", "rule_count": 2},
        {"key": "siem-wazuh|*", "siem_id": "siem-wazuh", "space": "*",
         "kind": "wazuh", "rule_count": 2},
    ]


def test_an_unreadable_destination_list_is_none_not_empty():
    svc = _Recording()
    svc._query = lambda sql, retries=1: None
    assert svc.get_destinations() is None


def test_posture_reports_rules_by_kind_and_leaves_unscored_out_of_poor():
    row = {"total_rules": 5, "enabled_rules": 4, "disabled_rules": 1, "unmapped_rules": 0,
           "q_excellent": 1, "q_good": 1, "q_fair": 0, "q_poor": 0, "q_unscored": 3,
           "avg_quality": 76.0, "min_quality": 72, "max_quality": 80, "covered_techniques": 4,
           "severity_json": '[{"severity":"high","count":2,"enabled":2,"disabled":0}]',
           "kinds_json": '[{"kind":"elastic","count":2,"enabled":1},{"kind":"wazuh","count":3,"enabled":3}]',
           "n": 1}
    svc = _Recording(rows=[row])
    p = svc.get_posture_stats()
    assert p["total_rules"] == 5 and p["covered_techniques"] == 4
    assert p["rules_by_kind"] == {"elastic": {"total": 2, "enabled": 1},
                                  "wazuh": {"total": 3, "enabled": 3}}
    assert p["quality"]["poor"] == 0 and p["quality"]["unscored"] == 3
    assert p["scope"] is None


@pytest.mark.parametrize("saved,scope", [("", None), ("  ", None),
                                         ("default", Destination(space="default")),
                                         ("x' OR 1=1", None)])
def test_the_saved_space_setting_becomes_the_configured_scope(monkeypatch, saved, scope):
    monkeypatch.setattr(ts, "get_tide_config", lambda: {
        "enabled": True, "url": "http://tide.test", "api_key": "k", "space": saved})
    monkeypatch.setattr(ts, "get_ssl_verify", lambda: False)
    svc = TideService()
    assert svc.scope == svc.configured_scope == scope


def test_a_fresh_config_reads_every_destination():
    from ion.core.config import Config
    assert Config().tide_space == ""


# ---------------------------------------------------------------------------
# Refusals, classified at the HTTP boundary
# ---------------------------------------------------------------------------


def _http_tide(monkeypatch, handler):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ts, "_get_tide_client", lambda verify: client)
    monkeypatch.setattr(ts.time, "sleep", lambda s: None)
    ts._QUERY_CACHE.clear()
    tide_breaker._transition(CircuitState.CLOSED)
    svc = TideService.__new__(TideService)
    svc.url, svc.api_key, svc.client_id, svc.enabled = "http://tide.test", "k", "c", True
    svc.verify, svc._resolved_client_id = False, None
    return svc


@pytest.fixture(autouse=True)
def _clean_cache():
    yield
    ts._QUERY_CACHE.clear()
    tide_breaker._transition(CircuitState.CLOSED)


@pytest.mark.parametrize("status,detail,kind", [
    (401, "Invalid or missing API key.", "auth_rejected"),
    (403, "API key owner has no tenant access. Assign the user to a client.", "no_tenant"),
    (403, "API key owner does not have access to the requested tenant", "tenant_forbidden"),
    (404, "Tenant database not found", "tenant_missing"),
    (400, "Query error: Binder Error", "bad_request"),
    (500, "boom", "server_error"),
])
def test_a_refusal_is_classified_and_callers_still_get_none(monkeypatch, status, detail, kind):
    svc = _http_tide(monkeypatch, lambda r: httpx.Response(status, json={"detail": detail}))
    assert svc._query("SELECT 1 AS n FROM systems", retries=0) is None
    assert svc.last_failure.kind == kind
    assert svc.last_failure.status == status
    assert svc.last_failure.detail == detail


def test_an_unreachable_tide_is_classified_as_unreachable(monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("refused", request=request)
    svc = _http_tide(monkeypatch, refuse)
    assert svc._query("SELECT 1 AS n FROM systems", retries=0) is None
    assert svc.last_failure.kind == "unreachable"


def test_a_rejected_key_says_how_to_fix_it(monkeypatch):
    svc = _http_tide(monkeypatch, lambda r: httpx.Response(
        401, json={"detail": "Invalid or missing API key."}))
    result = svc.test_connection()
    assert result["ok"] is False
    assert result["failure"]["kind"] == "auth_rejected"
    assert "active TIDE user" in result["error"] and "dev-user-001" in result["error"]


def test_rejected_keys_leave_the_breaker_closed_so_the_reason_survives(monkeypatch):
    """Opening the breaker on 401s replaced "key rejected" with "circuit
    open" on every later read."""
    svc = _http_tide(monkeypatch, lambda r: httpx.Response(
        401, json={"detail": "Invalid or missing API key."}))
    for i in range(6):
        svc._query(f"SELECT {i} AS n FROM systems", retries=0)
    assert tide_breaker.can_execute()
    assert svc.test_connection()["failure"]["kind"] == "auth_rejected"


def test_a_cached_refusal_replays_its_reason(monkeypatch):
    calls = []

    def answer(request):
        calls.append(1)
        return httpx.Response(403, json={"detail": "API key owner has no tenant access."})
    svc = _http_tide(monkeypatch, answer)
    svc._query("SELECT 1 AS n FROM systems")
    svc.last_failure = None
    assert svc._query("SELECT 1 AS n FROM systems") is None
    assert len(calls) == 1
    assert svc.last_failure.kind == "no_tenant"


def test_an_answer_clears_the_last_failure(monkeypatch):
    status = {"code": 401}
    svc = _http_tide(monkeypatch, lambda r: httpx.Response(
        status["code"], json={"detail": "nope"} if status["code"] != 200 else {"rows": [{"n": 1}]}))
    svc._query("SELECT 1 AS n FROM systems")
    status["code"] = 200
    assert svc._query("SELECT 2 AS n FROM systems") == {"rows": [{"n": 1}]}
    assert svc.last_failure is None


def test_a_sync_that_gets_nothing_records_why(monkeypatch):
    from ion.services import tide_sync_service as sync

    class _Refused:
        enabled = True
        last_failure = ts.TideFailure("auth_rejected", "Invalid or missing API key.", 401)

        def __getattr__(self, name):
            return lambda **kw: None

    stored = {}
    monkeypatch.setattr(ts, "TideService", _Refused)
    monkeypatch.setattr(sync, "_upsert_snapshot",
                        lambda s, key, data, ms, error=None: stored.__setitem__(key, error))
    monkeypatch.setattr(sync.time, "sleep", lambda s: None)
    sync.sync_all(session=None)
    assert stored["posture"] == "returned None: auth_rejected"


# ---------------------------------------------------------------------------
# Applied detections reach rules through step_detections
# ---------------------------------------------------------------------------
#
# applied_detections.detection_id is a step_detections id (or a CVE detection
# id), as TIDE writes it in every version from 4.0: add_step_detection, then
# apply_detection(det.id). ION joined it straight to detection_rules.rule_id,
# which matched nothing, so every system read as having no rules. The fake
# resolves whichever join the SQL names, so the old join gets the old answer.

_RULES = [
    {"rule_id": "r-lsass", "siem_id": "siem-e", "space": "default", "name": "LSASS access",
     "enabled": 1, "severity": "high", "quality_score": 80, "mitre_ids": ["T1003.001"], "kind": "elastic"},
    # The same rule in a second Kibana space. The step names default, so this
    # copy is not what the system runs.
    {"rule_id": "r-lsass", "siem_id": "siem-e", "space": "soc-staging", "name": "LSASS access (staging)",
     "enabled": 1, "severity": "high", "quality_score": 80, "mitre_ids": ["T1003.001"], "kind": "elastic"},
    {"rule_id": "5710", "siem_id": "siem-w", "space": "*", "name": "sshd brute force",
     "enabled": 1, "severity": "medium", "quality_score": None, "mitre_ids": ["T1110"], "kind": "wazuh"},
]
_STEP_DETECTIONS = [
    {"id": "sd-1", "rule_ref": "r-lsass", "siem_id": "siem-e", "space": "default"},
    {"id": "sd-2", "rule_ref": "5710", "siem_id": "siem-w", "space": "*"},
]
_APPLIED = [
    {"detection_id": "sd-1", "system_id": "sys-1", "host_id": None},
    # Pinned to one of the system's hosts, not to the system.
    {"detection_id": "sd-2", "system_id": None, "host_id": "h-1"},
    # A CVE detection: not a rule at all.
    {"detection_id": "vd-1", "system_id": "sys-1", "host_id": None},
    {"detection_id": "vd-2", "system_id": "sys-1", "host_id": None},
]
_HOSTS = {"h-1": "sys-1"}


class _Tenant(TideService):
    def __init__(self):
        self.enabled = True
        self.sent: list[str] = []

    def _applied_rules(self, q: str, system_id: str) -> list[dict]:
        out = []
        for ad in _APPLIED:
            owner = ad["system_id"] if ad["host_id"] is None else (
                _HOSTS.get(ad["host_id"]) if "h.system_id" in q else None)
            if owner != system_id:
                continue
            if "sd.id = ad.detection_id" in q and "dr.rule_id = sd.rule_ref" in q:
                sds = [sd for sd in _STEP_DETECTIONS if sd["id"] == ad["detection_id"]]
                out += [r for sd in sds for r in _RULES if r["rule_id"] == sd["rule_ref"]
                        and ("dr.siem_id = sd.siem_id" not in q
                             or (r["siem_id"], r["space"]) == (sd["siem_id"], sd["space"]))]
            elif "dr.rule_id = ad.detection_id" in q:
                out += [r for r in _RULES if r["rule_id"] == ad["detection_id"]]
        return out

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        q = " ".join(sql.split())
        self.sent.append(q)
        if "LIMIT 0" in q or q.startswith("SELECT count(*) AS n FROM"):
            return {"rows": [{"n": 1}]}
        if q.startswith("SELECT id, name, classification, description FROM systems WHERE id"):
            return {"rows": [{"id": "sys-1", "name": "Domain Controllers"}]}
        if "FROM systems s" in q and "applied_rules" in q:
            if "count(DISTINCT ad.detection_id)" in q:
                n = len([a for a in _APPLIED if a["system_id"] == "sys-1"])
            else:
                n = len({(r["rule_id"], r["siem_id"], r["space"]) for r in self._applied_rules(q, "sys-1")})
            return {"rows": [{"id": "sys-1", "name": "Domain Controllers", "applied_rules": n}]}
        if "applied_detections ad" in q:
            system_id = re.search(r"= '(sys-[^']+)'", q).group(1)
            rules = [r for r in self._applied_rules(q, system_id)
                     if "dr.enabled = 1" not in q or r["enabled"] == 1]
            if q.startswith("SELECT DISTINCT t.technique_id"):
                return {"rows": [{"technique_id": t} for t in sorted({t for r in rules for t in r["mitre_ids"]})]}
            if q.startswith("SELECT DISTINCT dr.rule_id") or q.startswith("SELECT dr.rule_id"):
                return {"rows": rules}
            return {"rows": []}
        if "AS total FROM detection_rules" in q:
            return {"rows": [{"total": len(_RULES)}]}
        return {"rows": []}


def test_a_systems_rules_are_the_ones_its_step_detections_name():
    detail = _Tenant().get_system_detail("sys-1")
    assert sorted((d["name"], d["space"]) for d in detail["detections"]) == [
        ("LSASS access", "default"), ("sshd brute force", "*")]


def test_a_systems_coverage_counts_rules_pinned_to_its_hosts():
    assert sorted(_Tenant().get_mitre_coverage("sys-1")["covered"]) == ["T1003.001", "T1110"]


def test_the_gap_analysis_counts_rules_not_applied_detection_rows():
    systems = _Tenant().get_gaps_analysis()["systems_coverage"]
    assert systems == [{"id": "sys-1", "name": "Domain Controllers", "applied_rules": 2}]


def test_a_systems_use_cases_are_its_own_baselines_scored_on_its_rules():
    """TIDE 6 gives each system its own copy of a baseline, and some exist
    only as a copy. Scoring every template put steps nobody applied to the
    system into the denominator; Microsoft 365 on a live TIDE 7 read 9%
    against TIDE's own 80%."""
    class _WithBaseline(_Tenant):
        def _query(self, sql, retries=1):
            q = " ".join(sql.split())
            if q.startswith("SELECT id, name, description FROM playbooks WHERE system_id = 'sys-1'"):
                self.sent.append(q)
                return {"rows": [{"id": "pb-copy", "name": "Cloud Identity Baseline", "description": ""}]}
            if "FROM playbook_steps WHERE playbook_id = 'pb-copy'" in q:
                return {"rows": [
                    {"step_id": "s1", "step_number": 1, "title": "Dump creds", "description": "", "technique_id": "T1003.001", "required_rule": None, "tactic": "credential-access"},
                    {"step_id": "s2", "step_number": 2, "title": "Exfil", "description": "", "technique_id": "T1048", "required_rule": None, "tactic": "exfiltration"},
                ]}
            if q.startswith("SELECT id, name, description FROM playbooks"):
                raise AssertionError("scored the template catalogue: " + q)
            return super()._query(sql, retries)

    summary = _WithBaseline().get_system_use_case_coverage("sys-1")
    assert [u["name"] for u in summary["use_cases"]] == ["Cloud Identity Baseline"]
    assert (summary["summary"]["covered_steps"], summary["summary"]["total_steps"]) == (1, 2)
