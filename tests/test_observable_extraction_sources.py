"""Observables come from the event, in every shape ION holds an alert in.

v0.99.10 stopped the investigation walker reading a rule's own prose, but
matched the rule subtree from the document root. ``investigate_case`` hands
the walker ``ElasticsearchAlert.to_dict(include_raw=True)``, where the
document sits under ``raw_data``, so on that path nothing was excluded and
the guide, the description and the MITRE reference links all came back as
observables. Both paths also read the alert's own id, a 64-hex string, as a
SHA-256.

These tests drive the real pipeline, ``_alert_to_text_blob`` into
``extract_iocs``, over both shapes, and assert on the observables that come
out the other end.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services.elasticsearch_service import ElasticsearchService
from ion.services.investigation_service import (
    _alert_to_text_blob,
    _normalise_extracted_iocs,
)
from ion.services.ioc_text_extractor import extract_iocs
from ion.services.observable_extractor import (
    extract_observables_from_raw,
    to_contract_observables,
)

ALERT_ID = "256274b17e404e755892c813316521647da292726b4b34a0f7f7d0cc46913ea8"

GUIDE_IP = "45.77.12.90"
GUIDE_DOMAIN = "guide-example-c2.com"
GUIDE_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
DESC_IP = "91.92.240.17"
DESC_DOMAIN = "description-example.net"
DESC_HASH = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

EVENT_IP = "185.220.101.34"
EVENT_DOMAIN = "real-beacon-host.com"
EVENT_HASH = "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"

RULE = {
    "name": "Beaconing to a rare domain",
    "description": (
        f"Detects beaconing, for example to {DESC_IP} or {DESC_DOMAIN}, "
        f"loader hash {DESC_HASH}."
    ),
    "note": (
        "## Investigation guide\n"
        f"Check whether the host contacted {GUIDE_IP} or {GUIDE_DOMAIN}. "
        f"The known loader is {GUIDE_HASH}."
    ),
    "false_positives": ["Backups to 45.77.12.91"],
    "references": ["https://threat-blog-example.org/post/1"],
    "setup": "Point the agent at 45.77.12.92.",
    "author": ["soc@author-example.org"],
    "license": "Elastic License v2",
    "tags": ["Domain: Endpoint"],
    "threat": [{
        "framework": "MITRE ATT&CK",
        "tactic": {"id": "TA0011", "reference": "https://attack.mitre.org/tactics/TA0011/"},
        "technique": [{"id": "T1071", "reference": "https://attack.mitre.org/techniques/T1071/"}],
    }],
}

RULE_METADATA_VALUES = [
    ("ips", GUIDE_IP, "rule.note"),
    ("domains", GUIDE_DOMAIN, "rule.note"),
    ("sha256", GUIDE_HASH, "rule.note"),
    ("ips", DESC_IP, "rule.description"),
    ("domains", DESC_DOMAIN, "rule.description"),
    ("sha256", DESC_HASH, "rule.description"),
    ("ips", "45.77.12.91", "rule.false_positives"),
    ("domains", "threat-blog-example.org", "rule.references"),
    ("ips", "45.77.12.92", "rule.setup"),
    ("emails", "soc@author-example.org", "rule.author"),
    ("domains", "attack.mitre.org", "rule.threat.*.reference"),
    ("urls", "https://attack.mitre.org/techniques/T1071/", "rule.threat.technique.reference"),
]

EVIDENCE_VALUES = [
    ("ips", EVENT_IP, "source.ip"),
    ("domains", EVENT_DOMAIN, "destination.domain"),
    ("sha256", EVENT_HASH, "file.hash.sha256"),
    ("ips", "10.20.30.40", "host.ip"),
]


def source() -> dict:
    """A Kibana security alert ``_source``: the event, with the rule beside it."""
    rule = copy.deepcopy(RULE)
    rule["parameters"] = copy.deepcopy(RULE)
    return {
        "@timestamp": "2026-10-08T10:00:00.000Z",
        "host": {"name": "WKS-FINANCE07", "ip": ["10.20.30.40"]},
        "source": {"ip": EVENT_IP},
        "destination": {"domain": EVENT_DOMAIN},
        "file": {"hash": {"sha256": EVENT_HASH}},
        "kibana": {"alert": {
            "uuid": ALERT_ID,
            "reason": f"network event to {EVENT_DOMAIN} on WKS-FINANCE07",
            "rule": rule,
        }},
    }


def as_fetched(src: dict) -> dict:
    """What ``_fetch_alert`` returns: the ``_source`` with its id and index."""
    return dict(src, _id=ALERT_ID, _index=".internal.alerts-security.alerts-default-000002")


def as_parsed(src: dict) -> dict:
    """What ``investigate_case`` builds for every alert on the case."""
    parsed = ElasticsearchService.__new__(ElasticsearchService)._parse_alert(ALERT_ID, src)
    return parsed.to_dict(include_raw=True)


def as_flattened(src: dict) -> dict:
    """The same document with dotted keys, as some forwarders ship it."""
    flat: dict = {}

    def walk(node, prefix):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{prefix}.{k}" if prefix else k)
        else:
            flat[prefix] = node

    walk(src, "")
    return as_fetched(flat)


SHAPES = {"fetched _source": as_fetched, "parsed alert": as_parsed, "flattened": as_flattened}


def iocs_of(doc: dict) -> dict:
    return _normalise_extracted_iocs(extract_iocs(_alert_to_text_blob(doc)))


@pytest.fixture(params=SHAPES, ids=list(SHAPES))
def iocs(request):
    return iocs_of(SHAPES[request.param](source()))


class TestRuleMetadataYieldsNoObservables:
    @pytest.mark.parametrize("kind,value,where", RULE_METADATA_VALUES)
    def test_a_value_the_rule_author_wrote_is_not_an_observable(self, iocs, kind, value, where):
        assert value not in iocs[kind], f"{value} was written into {where} by the rule author"

    def test_only_the_file_hash_is_a_hash(self, iocs):
        assert iocs["sha256"] == [EVENT_HASH]


class TestEvidenceStillYieldsObservables:
    @pytest.mark.parametrize("kind,value,where", EVIDENCE_VALUES)
    def test_a_value_from_the_event_is_an_observable(self, iocs, kind, value, where):
        assert value in iocs[kind], f"{value} is in {where}"

    def test_the_same_value_in_a_guide_and_in_the_event_is_kept(self):
        src = source()
        src["source"]["ip"] = GUIDE_IP
        src["destination"]["domain"] = GUIDE_DOMAIN
        src["file"]["hash"]["sha256"] = GUIDE_HASH
        for build in SHAPES.values():
            found = iocs_of(build(src))
            assert GUIDE_IP in found["ips"]
            assert GUIDE_DOMAIN in found["domains"]
            assert GUIDE_HASH in found["sha256"]


class TestAlertBookkeepingYieldsNoObservables:
    def test_the_alert_id_is_not_a_file_hash(self, iocs):
        assert ALERT_ID not in iocs["sha256"]

    def test_the_rule_description_standing_in_for_a_message_is_not_evidence(self):
        """``_parse_alert`` falls back to the rule description when an alert
        has neither a message nor a reason."""
        src = source()
        del src["kibana"]["alert"]["reason"]
        found = iocs_of(as_parsed(src))
        assert DESC_IP not in found["ips"]
        assert DESC_DOMAIN not in found["domains"]

    def test_the_summary_ion_wrote_back_is_not_read_again(self):
        src = source()
        src["ion"] = {"summary": "Bob: likely benign, the guide mentions 45.77.12.99."}
        for build in SHAPES.values():
            assert "45.77.12.99" not in iocs_of(build(src))["ips"]

    def test_an_eql_sequence_group_id_is_not_a_file_hash(self):
        group = "0c7a8e8a5b6f4d3e9a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
        src = source()
        src["kibana"]["alert"]["group"] = {"id": group, "index": 0}
        src["kibana"]["alert"]["building_block_type"] = "default"
        for build in SHAPES.values():
            found = iocs_of(build(src))
            assert group not in found["sha256"]
            assert EVENT_IP in found["ips"]


class TestEvidenceUnderKibanaAlertSurvives:
    """``kibana.alert`` holds more than the rule. These are generated per
    alert from the matched events."""

    @pytest.mark.parametrize("field,kind,value", [
        ({"reason": "connection from 198.51.100.77 to WKS-FINANCE07"}, "ips", "198.51.100.77"),
        ({"threshold_result": {"count": 517, "terms": [
            {"field": "source.ip", "value": "198.51.100.78"}]}}, "ips", "198.51.100.78"),
        ({"new_terms": ["new-term-host.com"]}, "domains", "new-term-host.com"),
        ({"suppression": {"terms": [
            {"field": "destination.ip", "value": ["198.51.100.79"]}]}}, "ips", "198.51.100.79"),
    ], ids=["reason", "threshold_result", "new_terms", "suppression.terms"])
    def test_per_alert_fields_are_evidence(self, field, kind, value):
        src = source()
        src["kibana"]["alert"].update(field)
        for name, build in SHAPES.items():
            assert value in iocs_of(build(src))[kind], name

    def test_a_field_merely_named_like_rule_metadata_is_evidence(self):
        src = source()
        src["process"] = {"name": "rule.exe", "command_line": "note.exe --to 198.51.100.80"}
        src["user"] = {"name": "description"}
        for name, build in SHAPES.items():
            assert "198.51.100.80" in iocs_of(build(src))["ips"], name


class TestFieldMapExtractorReadsOnlyEvidence:
    """The alert-page and case-creation extractor names its fields, so it
    never read the rule. This holds it to the same contract."""

    def test_no_rule_metadata_or_bookkeeping_value_comes_out(self):
        values = {o["value"] for o in extract_observables_from_raw(as_fetched(source()))}
        junk = {v for _, v, _ in RULE_METADATA_VALUES} | {ALERT_ID}
        assert not values & junk

    def test_the_event_values_come_out(self):
        got = {(o["type"], o["value"]) for o in to_contract_observables(source())}
        assert {("ip", EVENT_IP), ("sha256", EVENT_HASH), ("host", "WKS-FINANCE07")} <= got
