"""ION must ask OpenCTI about the entity it means.

Found against OpenCTI 6.4.4, 17 November 2026. The lookup filtered on a
value key alone and never named an entity type, so ``hostname`` could come
back as the Domain-Name of the same value. The type map knew fourteen
strings, none of them ION's own ``ObservableType`` values, so a stored
user account, MAC address, CVE or ``sha256`` was refused as unsupported
before any request was made. ``source_ip`` was IPv4 whatever the address.

The fake below answers the way the live instance does: it applies the filter
group it is given, and it rejects a filter key that no schema defines, which
6.4.4 does with "incorrect filter keys not existing in any schema
definition".
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.observable import ObservableType
from ion.services.opencti_service import OpenCTIError, OpenCTIService

#: Filter keys the live 6.4.4 schema accepted on 17 November 2026.
_LIVE_KEYS = {
    "entity_type", "value", "name", "account_login", "user_id",
    "hashes.MD5", "hashes.SHA-1", "hashes.SHA-256",
}

IPV6 = "2001:db8:85a3::8a2e:370:7334"
MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

#: Order matters: the Domain-Name precedes the Hostname of the same value,
#: and the Text precedes the IPv4-Addr, so an unconstrained ``first: 1``
#: returns the wrong entity.
SEEDED = [
    {"entity_type": "Text", "value": "185.220.101.34"},
    {"entity_type": "IPv4-Addr", "value": "185.220.101.34"},
    {"entity_type": "IPv6-Addr", "value": IPV6},
    {"entity_type": "Domain-Name", "value": "evil-login.example.com"},
    {"entity_type": "Hostname", "value": "evil-login.example.com"},
    {"entity_type": "Hostname", "value": "srv-staging-07"},
    {"entity_type": "Domain-Name", "value": "xkqpt7b2nf.evil.com"},
    {"entity_type": "Url", "value": "https://evil-login.example.com/api/callback"},
    {"entity_type": "Email-Addr", "value": "billing@evil-login.example.com"},
    {"entity_type": "Mac-Addr", "value": "00:1b:44:11:3a:b7"},
    {"entity_type": "User-Account", "account_login": "svc_backup_adm",
     "user_id": "S-1-5-21-1004336348-1177238915-682003330-1105"},
    {"entity_type": "StixFile", "name": "invoice_q4.exe",
     "hashes.MD5": MD5, "hashes.SHA-1": SHA1},
    {"entity_type": "StixFile", "hashes.SHA-256": SHA256},
    {"entity_type": "Vulnerability", "name": "CVE-2021-44228"},
]


class FakeOpenCTI(OpenCTIService):
    """An OpenCTI that holds ``SEEDED`` and records what it was asked."""

    def __init__(self, objects=SEEDED, indicators=()):
        super().__init__(url="http://opencti.test", token="t", verify_ssl=False)
        self.objects = list(objects)
        self.indicators = list(indicators)
        self.calls = []

    def _matches(self, obj, group):
        results = []
        for f in group.get("filters", []):
            if f["key"] not in _LIVE_KEYS:
                raise OpenCTIError(
                    "incorrect filter keys not existing in any schema definition")
            results.append(obj.get(f["key"]) in f["values"])
        results.extend(self._matches(obj, g) for g in group.get("filterGroups", []))
        if not results:
            return True
        return any(results) if group.get("mode") == "or" else all(results)

    async def _graphql(self, query, variables=None):
        variables = variables or {}
        self.calls.append((query, variables))
        if "stixCoreRelationships" in query:
            return {"stixCoreRelationships": {"edges": []}}
        if "indicators(search" in query:
            needle = variables["search"]
            hits = [i for i in self.indicators if needle in i["pattern"]]
            return {"indicators": {"edges": [{"node": i} for i in hits]}}
        root = "vulnerabilities" if "vulnerabilities(" in query else "stixCyberObservables"
        pool = [o for o in self.objects
                if (o["entity_type"] == "Vulnerability") == (root == "vulnerabilities")]
        hits = [o for o in pool if self._matches(o, variables.get("filters") or {})]
        first = variables.get("first") or int(re.search(r"first:\s*(\d+)", query).group(1))
        return {root: {"edges": [{"node": self._node(o)} for o in hits[:first]]}}

    @staticmethod
    def _node(obj):
        shown = obj.get("value") or obj.get("account_login") or obj.get("name") \
            or obj.get("hashes.SHA-256") or obj.get("hashes.MD5")
        return {"id": f"id-{obj['entity_type']}-{shown}", "entity_type": obj["entity_type"],
                "observable_value": shown, "name": obj.get("name")}

    def lookups(self):
        """(root, entity types asked for, value keys asked for) per lookup."""
        out = []
        for query, variables in self.calls:
            if "filters" not in variables or "stixCoreRelationships" in query:
                continue
            root = "vulnerabilities" if "vulnerabilities(" in query else "stixCyberObservables"
            types, keys = [], []

            def walk(group):
                for f in group.get("filters", []):
                    if f["key"] == "entity_type":
                        types.extend(f["values"])
                    else:
                        keys.append(f["key"])
                for g in group.get("filterGroups", []):
                    walk(g)

            walk(variables["filters"])
            out.append((root, types, keys))
        return out


def enrich(fake, obs_type, value):
    return asyncio.run(fake.enrich_observable(obs_type, value))


# -- The service ---------------------------------------------------------


class TestHostname:
    def test_a_hostname_is_found_as_a_hostname_not_the_domain_of_the_same_value(self):
        result = enrich(FakeOpenCTI(), "hostname", "evil-login.example.com")
        assert result["found"]
        assert result["observable"]["type"] == "Hostname"

    def test_a_bare_host_name_is_asked_for_as_a_hostname(self):
        fake = FakeOpenCTI()
        result = enrich(fake, "hostname", "srv-staging-07")
        assert result["observable"]["type"] == "Hostname"
        assert fake.lookups()[0][1][:1] == ["Hostname"]

    def test_a_dns_name_typed_hostname_is_still_found_as_a_domain(self):
        """``destination.domain`` is extracted as ``destination_hostname``,
        so a value of this kind is often a DNS name OpenCTI holds only as a
        Domain-Name. Losing that match would trade one wrong answer for
        another."""
        result = enrich(FakeOpenCTI(), "destination_hostname", "xkqpt7b2nf.evil.com")
        assert result["found"]
        assert result["observable"]["type"] == "Domain-Name"

    def test_a_domain_is_never_answered_with_a_hostname(self):
        objects = [{"entity_type": "Hostname", "value": "only-a-host.example"}]
        assert not enrich(FakeOpenCTI(objects), "domain", "only-a-host.example")["found"]


class TestIpFamily:
    @pytest.mark.parametrize("alias", [
        "ip", "source_ip", "destination_ip", "host_ip", "ipv4-addr", "ipv4", "ipv6",
    ])
    def test_an_ipv6_value_is_asked_for_as_ipv6_whatever_the_alias(self, alias):
        fake = FakeOpenCTI()
        result = enrich(fake, alias, IPV6)
        assert result["error"] is None
        assert result["observable"]["type"] == "IPv6-Addr"
        assert fake.lookups()[0] == ("stixCyberObservables", ["IPv6-Addr"], ["value"])

    def test_an_ipv6_indicator_verifies_for_an_ip_alias(self):
        """With no observable to find, the indicator fallback has to check
        the pattern against the family the value belongs to."""
        indicator = {"id": "i1", "name": "C2 over IPv6",
                     "pattern": f"[ipv6-addr:value = '{IPV6}']"}
        result = enrich(FakeOpenCTI(objects=[], indicators=[indicator]), "source_ip", IPV6)
        assert result["found"]
        assert [i["id"] for i in result["indicators"]] == ["i1"]

    def test_an_ipv4_lookup_does_not_return_another_type_holding_that_value(self):
        fake = FakeOpenCTI()
        result = enrich(fake, "source_ip", "185.220.101.34")
        assert result["observable"]["type"] == "IPv4-Addr"
        assert fake.lookups()[0] == ("stixCyberObservables", ["IPv4-Addr"], ["value"])


class TestIonsOwnKinds:
    @pytest.mark.parametrize("kind,value,entity,keys", [
        (ObservableType.DOMAIN, "xkqpt7b2nf.evil.com", "Domain-Name", ["value"]),
        (ObservableType.URL, "https://evil-login.example.com/api/callback", "Url", ["value"]),
        (ObservableType.EMAIL, "billing@evil-login.example.com", "Email-Addr", ["value"]),
        (ObservableType.MAC_ADDRESS, "00:1b:44:11:3a:b7", "Mac-Addr", ["value"]),
        (ObservableType.FILE_HASH_MD5, MD5, "StixFile", ["hashes.MD5"]),
        (ObservableType.FILE_HASH_SHA1, SHA1, "StixFile", ["hashes.SHA-1"]),
        (ObservableType.FILE_HASH_SHA256, SHA256, "StixFile", ["hashes.SHA-256"]),
        (ObservableType.FILE_NAME, "invoice_q4.exe", "StixFile", ["name"]),
    ])
    def test_each_stored_kind_reaches_its_entity_by_its_key(self, kind, value, entity, keys):
        fake = FakeOpenCTI()
        result = enrich(fake, kind.value, value)
        assert result["error"] is None
        assert result["observable"]["type"] == entity
        assert fake.lookups()[0] == ("stixCyberObservables", [entity], keys)

    @pytest.mark.parametrize("alias", ["user_account", "subject_user", "target_user", "user"])
    def test_a_user_account_is_looked_up_by_login(self, alias):
        fake = FakeOpenCTI()
        result = enrich(fake, alias, "svc_backup_adm")
        assert result["error"] is None
        assert result["observable"]["type"] == "User-Account"
        root, types, keys = fake.lookups()[0]
        assert types == ["User-Account"]
        assert "account_login" in keys

    def test_a_user_account_is_also_found_by_its_id(self):
        """ECS ``user.id`` is extracted as ``user_account`` and holds a SID."""
        result = enrich(
            FakeOpenCTI(), "user_account", "S-1-5-21-1004336348-1177238915-682003330-1105")
        assert result["error"] is None
        assert result["observable"]["type"] == "User-Account"

    def test_a_cve_is_a_vulnerability_looked_up_by_name(self):
        fake = FakeOpenCTI()
        result = enrich(fake, "cve", "cve-2021-44228")
        assert result["found"]
        assert result["observable"]["type"] == "Vulnerability"
        assert result["observable"]["value"] == "CVE-2021-44228"
        assert fake.lookups() == [("vulnerabilities", [], ["name"])]


class TestUnknownTypes:
    def test_an_unknown_type_is_skipped_and_says_so(self, caplog):
        fake = FakeOpenCTI()
        with caplog.at_level(logging.WARNING, logger="ion.services.opencti_service"):
            result = enrich(fake, "process_name", "powershell.exe")
        assert not result["found"]
        assert result["error"] == "Unsupported observable type: process_name"
        assert fake.calls == []
        assert "process_name" in caplog.text


# -- Each path that reaches the service ----------------------------------


class TestObservableServicePath:
    @pytest.mark.parametrize("kind,value,expected", [
        (ObservableType.USER_ACCOUNT, "svc_backup_adm", "User-Account"),
        (ObservableType.MAC_ADDRESS, "00:1b:44:11:3a:b7", "Mac-Addr"),
        (ObservableType.CVE, "CVE-2021-44228", "Vulnerability"),
        (ObservableType.HOSTNAME, "srv-staging-07", "Hostname"),
        (ObservableType.FILE_NAME, "invoice_q4.exe", "StixFile"),
        # A row stored before the family was decided by value.
        (ObservableType.IPV4, IPV6, "IPv6-Addr"),
    ])
    def test_a_stored_observable_is_enriched_as_its_kind(
        self, monkeypatch, kind, value, expected
    ):
        from ion.services import observable_service

        fake = FakeOpenCTI()
        monkeypatch.setattr(observable_service, "get_opencti_service", lambda: fake)
        service = observable_service.ObservableService(session=None)
        result = asyncio.run(
            service._fetch_opencti_result(SimpleNamespace(type=kind, value=value)))
        assert result["error"] is None
        assert result["observable"]["type"] == expected


class TestTriagePath:
    def test_every_extracted_type_is_enriched_as_its_kind(self, monkeypatch):
        from ion.services import opencti_service
        from ion.storage import database
        from ion.web import api

        fake = FakeOpenCTI()
        monkeypatch.setattr(opencti_service, "get_opencti_service", lambda: fake)

        def no_database(*args, **kwargs):
            raise RuntimeError("the persistence half is not under test")

        monkeypatch.setattr(database, "get_engine", no_database)
        asyncio.run(api._background_enrich_triage_observables(1, [
            {"type": "host_ip", "value": IPV6},
            {"type": "hostname", "value": "srv-staging-07"},
            {"type": "subject_user", "value": "svc_backup_adm"},
            {"type": "target_user", "value": "svc_backup_adm"},
            {"type": "sha256", "value": SHA256},
            {"type": "command_line", "value": "whoami /all"},
        ]))
        assert fake.lookups() == [
            ("stixCyberObservables", ["IPv6-Addr"], ["value"]),
            ("stixCyberObservables", ["Hostname", "Domain-Name"], ["value"]),
            ("stixCyberObservables", ["User-Account"], ["account_login", "user_id"]),
            ("stixCyberObservables", ["User-Account"], ["account_login", "user_id"]),
            ("stixCyberObservables", ["StixFile"], ["hashes.SHA-256"]),
        ]


class TestAlertsEnrichPath:
    def test_the_enrich_button_sends_every_enrichable_observable(self):
        """The page map had no entry for host_ip, the hashes or the role-typed
        users and sent those as themselves, and it dropped user_account."""
        from ion.web.ui.alerts import enrichable_observables

        sent = enrichable_observables([
            {"type": "host_ip", "value": "185.220.101.34"},
            {"type": "user_account", "value": "svc_backup_adm"},
            {"type": "subject_user", "value": "svc_backup_adm"},
            {"type": "md5", "value": MD5},
            {"type": "process_name", "value": "powershell.exe"},
        ])
        assert [s["original_type"] for s in sent] == [
            "host_ip", "user_account", "subject_user", "md5"]
        fake = FakeOpenCTI()
        results = asyncio.run(fake.enrich_batch(
            [{"type": s["type"], "value": s["value"]} for s in sent]))
        assert [(r["observable"] or {}).get("type") for r in results] == [
            "IPv4-Addr", "User-Account", "User-Account", "StixFile"]


class TestArkimePath:
    def test_an_ipv6_top_talker_is_enriched_as_ipv6(self, monkeypatch):
        """The PCAP summariser types every top talker ``ipv4-addr``."""
        from ion.services import shodan_service, virustotal_service
        from ion.web import arkime_api

        fake = FakeOpenCTI()
        monkeypatch.setattr(arkime_api, "get_opencti_service", lambda: fake)
        monkeypatch.setattr(virustotal_service, "get_virustotal_service", lambda: None)
        monkeypatch.setattr(shodan_service, "get_shodan_service", lambda: None)
        observable = arkime_api.EnrichedObservable(
            type="ipv4-addr", value=IPV6, source="top_dst_ips")
        asyncio.run(arkime_api._enrich_observables([observable]))
        assert observable.found
        assert fake.lookups()[0] == ("stixCyberObservables", ["IPv6-Addr"], ["value"])


class TestInvestigationPath:
    def test_domains_and_hashes_name_their_entity(self, monkeypatch):
        from ion.services import investigation_service as inv

        fake = FakeOpenCTI()
        for getter in ("_get_vt", "_get_shodan", "_get_abuseipdb"):
            monkeypatch.setattr(inv.InvestigationService, getter, lambda self: None)
        monkeypatch.setattr(inv.InvestigationService, "_get_opencti", lambda self: fake)
        monkeypatch.setattr(inv, "get_engine", lambda *a, **k: None)
        monkeypatch.setattr(
            inv, "get_session_factory",
            lambda engine: lambda: SimpleNamespace(
                commit=lambda: None, rollback=lambda: None, close=lambda: None))
        monkeypatch.setattr(inv.inv_repo, "upsert_ioc_sighting", lambda **kwargs: None)

        service = object.__new__(inv.InvestigationService)
        enrichment = asyncio.run(service._enrich_iocs(
            {"domains": ["xkqpt7b2nf.evil.com"], "sha256": [SHA256], "md5": [MD5]}, inv_id=1))
        assert fake.lookups() == [
            ("stixCyberObservables", ["Domain-Name"], ["value"]),
            ("stixCyberObservables", ["StixFile"], ["hashes.SHA-256"]),
            ("stixCyberObservables", ["StixFile"], ["hashes.MD5"]),
        ]
        assert enrichment["domain"]["xkqpt7b2nf.evil.com"]["opencti"]["found"]


class TestPastedValuePaths:
    """Tools and the command centre infer a type from the pasted value."""

    VALUES = [
        "185.220.101.34", IPV6, MD5, SHA1, SHA256,
        "https://evil-login.example.com/api/callback",
        "billing@evil-login.example.com", "xkqpt7b2nf.evil.com",
    ]
    FOUND_AS = [
        "IPv4-Addr", "IPv6-Addr", "StixFile", "StixFile", "StixFile",
        "Url", "Email-Addr", "Domain-Name",
    ]

    def test_tools_sends_a_type_the_service_resolves(self):
        from ion.web.ui.tools import ioc_type

        fake = FakeOpenCTI()
        found = [enrich(fake, ioc_type(v), v)["observable"]["type"] for v in self.VALUES]
        assert found == self.FOUND_AS

    def test_the_command_centre_sends_a_type_the_service_resolves(self):
        from ion.web.ui.analyst import _ioc_type

        fake = FakeOpenCTI()
        found = [enrich(fake, _ioc_type(v), v)["observable"]["type"] for v in self.VALUES]
        assert found == self.FOUND_AS
