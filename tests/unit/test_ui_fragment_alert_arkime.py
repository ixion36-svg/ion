"""The Arkime PCAP workspace as a server-rendered fragment.

alert_arkime.html used to POST the preview, then build the findings list,
the destination table, the protocol bars, the observable cards and the
attach result with string concatenation and innerHTML, behind a hand-rolled
escHtml(). Those are the cases below. Each one is a behaviour the
JavaScript got wrong, arranged so the wrong behaviour still fails.

The rows are fixtures. A live preview needs Elasticsearch and Arkime, and
an empty capture proves nothing about the cards, which is all that moved.
The routes are checked against arkime_preview and arkime_commit themselves,
patched at the module those routes import, because that is the only way to
know the fragment did not grow a second copy of the analysis.
"""
from __future__ import annotations

import enum
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from ion.web.templating import make_templates
from ion.web.ui.alert_arkime import PERMISSION, _view, router

FRAGMENT = "_fragments/alert_arkime.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alert_arkime.html"
FRAGMENT_PATH = ROOT / "src/ion/web/templates" / FRAGMENT
SERVER = ROOT / "src/ion/web/server.py"

DASH = "\u2014"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def html_of(data: dict, alert_id: str = "alert-1") -> str:
    return render(**_view(data, alert_id))


def payload(**over: Any) -> dict:
    data = {
        "arkime_node": "node-a",
        "arkime_session_id": "sess-1",
        "network_community_id": "1:cid",
        "session_metadata": {
            "srcIp": "10.0.0.1",
            "srcPort": 51514,
            "dstIp": "10.0.0.2",
            "dstPort": 443,
            "ipProtocol": 6,
            "packets": 3,
            "bytes": 128,
        },
        "pcap_size_bytes": 2048,
        "analysis": {
            "findings": [],
            "top_dst_ips": [],
            "protocols": {},
            "verdict": {"label": "Likely Benign", "confidence": 85},
        },
        "observables": [],
        "enrichment_enabled": False,
        "warnings": [],
        "arkime_web_url": "",
    }
    data.update(over)
    return data


def meta(**over: Any) -> dict:
    base = dict(payload()["session_metadata"])
    base.update(over)
    return base


def analysis(**over: Any) -> dict:
    base = {
        "findings": [],
        "top_dst_ips": [],
        "protocols": {},
        "verdict": {"label": "Measured", "score": 1},
    }
    base.update(over)
    return base


def element(html: str, element_id: str) -> str:
    """The inner HTML of one id, comments removed, tags balanced.

    A whole-file substring lies when a comment or a neighbouring card quotes
    the same words. The failure copy says "not zero"; the measured zero is
    the digit in its own cell.
    """
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    marker = re.search(rf'\bid="{re.escape(element_id)}"', html)
    assert marker, f"#{element_id} missing"
    start = html.rfind("<", 0, marker.start())
    tag_m = re.match(r"<([A-Za-z0-9]+)", html[start:])
    assert tag_m, html[start:start + 40]
    tag = tag_m.group(1)
    open_end = html.find(">", start)
    assert open_end != -1
    pos = open_end + 1
    depth = 1
    for token in re.finditer(rf"</?{tag}\b[^>]*>", html[pos:], flags=re.I):
        lexeme = token.group(0)
        if lexeme.startswith("</"):
            depth -= 1
        elif not lexeme.endswith("/>"):
            depth += 1
        if depth == 0:
            return html[pos:pos + token.start()]
    raise AssertionError(f"#{element_id} <{tag}> never closed")


def text_of(fragment: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", fragment)).strip()


def opening_tag(html: str, element_id: str) -> str:
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    match = re.search(rf'<[A-Za-z0-9]+\b[^>]*\bid="{re.escape(element_id)}"[^>]*>', html)
    assert match, f"#{element_id} tag missing"
    return match.group(0)


def hidden_size(html: str) -> str:
    tag = re.search(r'<input\b[^>]*name="pcap_size_bytes"[^>]*>', html)
    assert tag, "the attach form did not echo a capture size"
    value = re.search(r'value="([^"]*)"', tag.group(0))
    assert value
    return value.group(1)


def destination_cell(row: dict) -> str:
    html = html_of(payload(analysis=analysis(top_dst_ips=[row])))
    cells = re.findall(r"<td\b[^>]*>(.*?)</td>", element(html, "top-dst"), re.S)
    assert len(cells) >= 2, cells
    return text_of(cells[-1])


def time_attr(html: str, element_id: str) -> str:
    match = re.search(r'<time\b[^>]*\bdatetime="([^"]+)"', element(html, element_id))
    assert match, element(html, element_id)
    return match.group(1)


# ---------------------------------------------------------------------------
# What the cards have to show
# ---------------------------------------------------------------------------


def test_a_measured_empty_capture_renders_the_workspace():
    """The shape arkime_preview returns when the capture ran and found
    nothing. Zeros are that result. The failure copy is a different one."""
    html = html_of(payload())
    assert text_of(element(html, "sess-node")) == "node-a"
    assert text_of(element(html, "sess-id")) == "sess-1"
    assert text_of(element(html, "sess-cid")) == "1:cid"
    assert text_of(element(html, "sess-flow")) == "10.0.0.1:51514 → 10.0.0.2:443"
    assert text_of(element(html, "sess-proto")) == "6"
    assert text_of(element(html, "sess-packets")) == "3"
    assert text_of(element(html, "session-size")) == "2.0 KB · 128 raw"
    assert text_of(element(html, "stat-verdict")) == "Likely Benign"
    assert text_of(element(html, "stat-findings")) == "0"
    assert "No suspicious findings detected." in element(html, "findings-list")
    assert "could not be read" not in html
    assert 'id="arkime-commit-form"' in html


def test_a_missing_node_is_a_dash_not_a_blank():
    html = html_of(payload(arkime_node=None))
    assert text_of(element(html, "sess-node")) == DASH


def test_zero_packets_is_a_count():
    """`if (!packets)` treats a capture with no packets as a capture whose
    packet count was never read."""
    html = html_of(payload(session_metadata=meta(packets=0)))
    assert text_of(element(html, "sess-packets")) == "0"


def test_a_missing_packet_count_is_not_zero():
    fields = meta()
    del fields["packets"]
    html = html_of(payload(session_metadata=fields))
    assert text_of(element(html, "sess-packets")) == DASH


def test_a_source_port_of_zero_is_kept():
    """`port || '?'` renders a measured port 0 as unknown."""
    html = html_of(payload(session_metadata=meta(srcPort=0)))
    assert "10.0.0.1:0" in text_of(element(html, "sess-flow"))
    assert ":?" not in text_of(element(html, "sess-flow"))


def test_an_ip_protocol_of_zero_is_not_replaced_by_the_next_field():
    """`meta.ipProtocol || meta.protocol` drops a measured 0 and shows
    whatever string happens to sit in the other field."""
    html = html_of(payload(session_metadata=meta(ipProtocol=0, protocol="tcp")))
    assert text_of(element(html, "sess-proto")) == "0"


def test_a_missing_ip_protocol_falls_through_to_protocol():
    fields = meta()
    del fields["ipProtocol"]
    fields["protocol"] = "tcp"
    html = html_of(payload(session_metadata=fields))
    assert text_of(element(html, "sess-proto")) == "tcp"


class _Severity(enum.Enum):
    HIGH = "high"


def test_a_severity_enum_renders_its_value_not_the_repr():
    """Same failure as the quirks pill. A SQLEnum member reaches the
    template as the member. str() of it on 3.12 is the repr, so the badge
    would read Severity.HIGH and the colour lookup would miss."""
    html = html_of(payload(analysis=analysis(findings=[{
        "severity": _Severity.HIGH,
        "title": "Beacon",
        "detail": "every 60s",
    }])))
    block = element(html, "findings-list")
    assert "Severity" not in block
    assert ">high<" in block
    assert "badge-warning" in block


def test_a_finding_body_comes_from_detail_when_description_was_not_sent():
    """The analyser emits `detail`. The JavaScript read `description`, which
    this payload does not have, so every finding rendered with no body.
    When both are present, description is what the analyst wrote and wins."""
    html = html_of(payload(analysis=analysis(findings=[
        {"severity": "high", "title": "Beacon", "detail": "every 60s"},
        {
            "severity": "low",
            "title": "Note",
            "description": "from-description",
            "detail": "from-detail",
        },
    ])))
    block = element(html, "findings-list")
    assert "every 60s" in block
    assert "from-description" in block
    assert "from-detail" not in block


def test_an_unknown_severity_is_not_painted_as_info():
    """A severity the map does not know is not informational. Painting it
    badge-info makes an unrecognised finding look routine."""
    html = html_of(payload(analysis=analysis(findings=[{
        "title": "Something odd",
        "detail": "no severity field",
    }])))
    block = element(html, "findings-list")
    assert ">unknown<" in block
    assert "badge-ghost" in block
    assert "badge-info" not in block


def test_no_findings_is_an_empty_list_and_a_count_of_zero():
    html = html_of(payload(analysis=analysis(findings=[])))
    assert "No suspicious findings detected." in element(html, "findings-list")
    assert "could not be read" not in element(html, "findings-list")
    assert text_of(element(html, "stat-findings")) == "0"


def test_a_missing_findings_key_is_the_same_measured_empty():
    """The parser always emits the key. Absence on an analysis that ran is
    an empty section, not a read failure."""
    body = analysis()
    del body["findings"]
    html = html_of(payload(analysis=body))
    assert "No suspicious findings detected." in element(html, "findings-list")
    assert text_of(element(html, "stat-findings")) == "0"


def test_findings_that_are_not_a_list_are_not_zero_findings():
    """The string "no" is truthy and not a list. An empty-state render of it
    would say the capture is clean."""
    html = html_of(payload(analysis=analysis(findings="no")))
    block = element(html, "findings-list")
    assert "Findings could not be read" in block
    assert "not zero findings" in block
    assert "No suspicious findings detected." not in block
    assert text_of(element(html, "stat-findings")) == DASH


def test_a_findings_list_whose_entries_all_fail_to_parse_is_not_zero():
    html = html_of(payload(analysis=analysis(findings=["no", 1, None])))
    assert "could not be read" in element(html, "findings-list")
    assert text_of(element(html, "stat-findings")) == DASH
    assert "No suspicious findings detected." not in element(html, "findings-list")


def test_the_card_slices_findings_and_the_attach_payload_does_not():
    """Showing 25 of 26 is a display limit. Echoing the sliced list back to
    commit would drop the 26th finding on the way into the case."""
    findings = [
        {"title": f"finding-{i}", "severity": "low", "detail": "body"}
        for i in range(26)
    ]
    html = html_of(payload(analysis=analysis(findings=findings)))
    shown = element(html, "findings-list")
    form = element(html, "arkime-commit-form")
    assert "finding-0" in shown
    assert "finding-25" not in shown
    assert "Showing 25 of 26" in shown
    assert "finding-25" in form


def test_a_verdict_with_no_label_is_unknown_not_benign():
    """`verdict.label || 'benign'` turned a missing label into a clean
    verdict. Confidence without a label is still no judgement: the
    no-findings payload carries confidence 85 and, separately, a label."""
    html = html_of(payload(analysis=analysis(verdict={"confidence": 85})))
    assert text_of(element(html, "stat-verdict")) == "Unknown"
    assert "benign" not in text_of(element(html, "stat-verdict")).lower()
    assert "score" not in text_of(element(html, "stat-verdict-sub"))


def test_the_real_no_findings_verdict_keeps_its_label_and_invents_no_score():
    """That payload's verdict is {label: Likely Benign, confidence: 85} and
    has no score key. `score != null` was the JavaScript's one correct
    guard, and it has to survive: a missing score is not zero."""
    html = html_of(payload())
    assert text_of(element(html, "stat-verdict")) == "Likely Benign"
    assert text_of(element(html, "stat-verdict-sub")) == ""


def test_a_score_of_zero_is_shown():
    html = html_of(payload(analysis=analysis(
        verdict={"label": "Suspicious", "score": 0},
    )))
    assert text_of(element(html, "stat-verdict")) == "Suspicious"
    assert text_of(element(html, "stat-verdict-sub")) == "score 0"


@pytest.mark.parametrize("row,expect", [
    ({"ip": "1.1.1.1", "bytes": 0, "count": 4}, "0 B"),
    ({"ip": "1.1.1.1", "count": 4}, "4"),
    ({"ip": "1.1.1.1", "count": 0}, "0"),
    ({"ip": "1.1.1.1", "bytes": None, "count": 4}, "4"),
    ({"ip": "1.1.1.1"}, DASH),
    ({"ip": "1.1.1.1", "bytes": True, "count": 3}, "3"),
    ({"ip": "1.1.1.1", "bytes": -5, "count": 3}, "3"),
], ids=[
    "zero-bytes-is-a-size-and-wins",
    "missing-bytes-is-not-zero-bytes",
    "zero-flows-is-not-zero-bytes",
    "null-bytes-falls-through-to-count",
    "nothing-measured-is-a-dash",
    "a-bool-is-not-one-byte",
    "a-negative-is-not-a-size",
])
def test_a_destination_does_not_print_zero_bytes_for_a_missing_size(row, expect):
    """fmtBytes did `if (!n) return '0 B'`, and the column read `row.bytes`
    only. Real top_dst_ips rows are {ip, count}, so the column was blank,
    and a row that did carry bytes: 0 was indistinguishable from one that
    carried nothing."""
    assert destination_cell(row) == expect


def test_destinations_that_are_not_a_list_are_not_an_empty_capture():
    html = html_of(payload(analysis=analysis(top_dst_ips="no")))
    block = element(html, "top-dst")
    assert "could not be read" in block
    assert "No outbound traffic recorded." not in block


def test_a_missing_destination_key_is_measured_empty():
    body = analysis()
    del body["top_dst_ips"]
    html = html_of(payload(analysis=body))
    block = element(html, "top-dst")
    assert "No outbound traffic recorded." in block
    assert "could not be read" not in block


def test_protocol_percentages_are_a_share_of_the_rows_shown():
    """The JavaScript summed the sliced entries, not the whole map. Nine
    protocols at one flow each: eight are shown, each is 13% of those
    eight. 1/9 would be 11%, and that is the bug."""
    counts = {f"p{i}": 1 for i in range(9)}
    html = html_of(payload(analysis=analysis(protocols=counts)))
    block = element(html, "protocols")
    assert "p8" not in block
    assert "p0" in block
    assert "13%" in block
    assert "11%" not in block
    assert "Showing 8 of 9" in block


def test_a_half_percent_rounds_the_way_math_round_does():
    """1/8 is 12.5. Math.round gives 13. Python round() gives 12, because
    12 is even. The bar the JavaScript drew was 13."""
    html = html_of(payload(analysis=analysis(protocols={"small": 1, "big": 7})))
    block = element(html, "protocols")
    assert 'data-ion-style="width:13%"' in block
    assert "width:12%" not in block
    assert 'data-ion-style="width:88%"' in block
    assert ' style="' not in block


def test_a_protocol_total_of_zero_has_no_percentage():
    """`total || 1` avoids the division and then reports each protocol as
    0% of the traffic. A total of zero has no share."""
    html = html_of(payload(analysis=analysis(protocols={"a": 0, "b": 0})))
    block = element(html, "protocols")
    assert "%" not in block
    assert text_of(block).count("0") >= 2


def test_a_bool_protocol_count_is_unmeasured():
    """True is an int, so a truthiness or isinstance(int) check counts it
    as one flow and draws a full bar."""
    html = html_of(payload(analysis=analysis(protocols={"hop": True})))
    block = element(html, "protocols")
    assert "%" not in block
    assert "1" not in text_of(block)
    assert DASH in text_of(block)


def test_a_protocol_value_that_is_not_a_map_is_not_an_empty_mix():
    html = html_of(payload(analysis=analysis(protocols="no")))
    block = element(html, "protocols")
    assert "could not be read" in block
    assert "No protocols recorded." not in block


def test_a_missing_protocol_key_is_measured_empty():
    body = analysis()
    del body["protocols"]
    html = html_of(payload(analysis=body))
    block = element(html, "protocols")
    assert "No protocols recorded." in block
    assert "could not be read" not in block


@pytest.mark.parametrize("enabled,expect", [
    (True, "0"),
    (False, "Not checked"),
    (None, DASH),
    ("no", DASH),
])
def test_opencti_keeps_three_states(enabled, expect):
    """Off means enrichment never ran, so a hit count of 0 would claim
    OpenCTI looked and found nothing. None is the third state. The string
    "no" is the one a truthiness test gets wrong: it is truthy, so it takes
    the measured branch and prints 0."""
    html = html_of(payload(enrichment_enabled=enabled, observables=[]))
    assert text_of(element(html, "stat-hits")) == expect


def test_only_a_real_true_counts_as_an_opencti_hit():
    """`found` is a bool on the model. The string "no" is truthy and must
    not increment the hit count or draw the badge."""
    html = html_of(payload(
        enrichment_enabled=True,
        observables=[
            {"type": "ip", "value": "1.1.1.1", "found": "no"},
            {"type": "ip", "value": "2.2.2.2", "found": True},
            {"type": "ip", "value": "3.3.3.3", "found": False},
        ],
    ))
    assert text_of(element(html, "stat-hits")) == "1"
    assert element(html, "obs-list").count(">OpenCTI<") == 1


def test_zero_hits_after_a_real_check_is_shown():
    html = html_of(payload(
        enrichment_enabled=True,
        observables=[{"type": "ip", "value": "1.1.1.1", "found": False}],
    ))
    assert text_of(element(html, "stat-hits")) == "0"


def test_observables_that_are_not_a_list_are_not_an_empty_extraction():
    """And they are not attached. Echoing [] for a list we never received
    would write "nothing extracted" onto the case."""
    html = html_of(payload(observables="no"))
    assert "could not be read" in element(html, "obs-list")
    assert "No observables extracted." not in element(html, "obs-list")
    assert text_of(element(html, "stat-obs")) == DASH
    assert "arkime-commit-form" not in html


def test_a_missing_observable_list_is_not_attached_as_empty():
    data = payload()
    del data["observables"]
    html = html_of(data)
    assert "could not be read" in element(html, "obs-list")
    assert "arkime-commit-form" not in html


def test_an_empty_observable_list_is_a_measured_zero_and_can_be_attached():
    html = html_of(payload(observables=[]))
    assert "No observables extracted." in element(html, "obs-list")
    assert text_of(element(html, "stat-obs")) == "0"
    assert "arkime-commit-form" in html


def test_an_unreadable_analysis_is_not_a_clean_capture_and_not_attached():
    """analysis="no" is truthy. Treating it as present renders the empty
    verdict, which is the opposite of "we could not read this"."""
    html = html_of(payload(analysis="no", observables=[]))
    assert "The capture metadata arrived but the analysis could not be read" in html
    assert "stat-verdict" not in html
    assert "No suspicious findings detected." not in html
    assert "arkime-commit-form" not in html


def test_an_analysis_object_with_no_sections_is_measured_empty():
    html = html_of(payload(analysis={}, observables=[]))
    assert "could not be read" not in html
    assert text_of(element(html, "stat-verdict")) == "Unknown"
    assert text_of(element(html, "stat-findings")) == "0"
    assert text_of(element(html, "stat-obs")) == "0"
    assert "arkime-commit-form" in html


# ---------------------------------------------------------------------------
# Sizes and times, where zero and missing are different claims
# ---------------------------------------------------------------------------


def test_a_capture_of_zero_bytes_is_shown_and_echoed_into_the_form():
    """The hidden field is what commit receives. Omitting it when the size
    is zero (`if size`) makes the next request say the size was missing."""
    html = html_of(payload(
        pcap_size_bytes=0,
        session_metadata=meta(bytes=0),
    ))
    assert text_of(element(html, "session-size")) == f"0 B · 0 raw"
    assert hidden_size(html) == "0"


def test_a_missing_capture_size_is_not_zero_bytes():
    data = payload()
    del data["pcap_size_bytes"]
    fields = meta()
    del fields["bytes"]
    data["session_metadata"] = fields
    html = html_of(data)
    assert text_of(element(html, "session-size")) == f"{DASH} · {DASH} raw"
    assert "0 B" not in element(html, "session-size")
    assert hidden_size(html) == ""


@pytest.mark.parametrize("size", [True, -1, float("nan")])
def test_an_unreadable_capture_size_is_not_submitted(size):
    """A bool is an int, NaN is a float, and a negative is not a size. Any
    of them shown as unknown while the form still posts the number would
    attach a size the card said it could not read."""
    html = html_of(payload(pcap_size_bytes=size))
    assert "0 B" not in element(html, "session-size")
    assert text_of(element(html, "session-size")).startswith(DASH)
    assert hidden_size(html) == ""


def test_packet_times_use_the_services_millisecond_split():
    """firstPacket is milliseconds on current Arkime and seconds on older
    ones. ArkimeService._packet_epoch is that split. Copying the threshold
    shows one of the two clocks off by a thousand."""
    from ion.services.arkime_service import ArkimeService

    ms = 1_744_689_000_000
    sec = 1_744_689_000
    assert ArkimeService._packet_epoch(ms) == pytest.approx(
        ArkimeService._packet_epoch(sec)
    )
    html_ms = html_of(payload(session_metadata=meta(firstPacket=ms)))
    html_sec = html_of(payload(session_metadata=meta(firstPacket=sec)))
    assert time_attr(html_ms, "sess-first") == time_attr(html_sec, "sess-first")
    assert "1970" not in element(html_ms, "sess-first")


def test_a_packet_time_of_zero_is_not_the_epoch():
    """Zero is Arkime's empty sentinel. Rendering it is 1970, which is the
    failure the timestamp fallback exists to prevent."""
    html = html_of(payload(session_metadata=meta(firstPacket=0, lastPacket=0)))
    for element_id in ("sess-first", "sess-last"):
        block = element(html, element_id)
        assert "No packet time" in block
        assert "1970" not in block
        assert "<time" not in block


def test_a_missing_packet_time_is_not_the_epoch():
    html = html_of(payload())
    block = element(html, "sess-first")
    assert "No packet time" in block
    assert "1970" not in block
    assert "<time" not in block


def test_an_iso_packet_time_is_a_time_element_not_server_text():
    html = html_of(payload(session_metadata=meta(
        firstPacket="2026-04-15T12:34:56Z",
    )))
    block = element(html, "sess-first")
    assert "<time" in block
    assert "2026-04-15" in time_attr(html, "sess-first")
    assert "No packet time" not in block


def test_an_unparseable_packet_time_is_kept_rather_than_blanked():
    html = html_of(payload(session_metadata=meta(firstPacket="not-a-clock")))
    block = element(html, "sess-first")
    assert "not-a-clock" in block
    assert "No packet time" not in block
    assert "1970" not in block


def test_a_date_only_packet_time_does_not_become_midnight():
    """Parsing a date invents 00:00. That is a time nobody measured."""
    html = html_of(payload(session_metadata=meta(firstPacket="2026-04-15")))
    block = element(html, "sess-first")
    assert "2026-04-15" in block
    assert "00:00" not in block


# ---------------------------------------------------------------------------
# Escaping and stored URLs
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_escHtml_used_to():
    """escHtml() is gone. A title, a warning and an observable value are
    the strings the old helper existed to escape."""
    html = html_of(payload(
        arkime_node="<script>alert(1)</script>",
        warnings=["<script>warn</script>"],
        analysis=analysis(findings=[{
            "severity": "high",
            "title": "<img src=x onerror=1>",
            "detail": "body",
        }]),
        observables=[{
            "type": "domain",
            "value": "<svg onload=1>",
            "source": "dns",
            "found": True,
            "labels": ["<script>label</script>"],
            "threat_actors": ["APT-29"],
            "error": "<img src=x onerror=2>",
        }],
        enrichment_enabled=True,
    ))
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "<svg onload" not in html
    assert "&lt;script&gt;" in html
    assert "APT-29" in element(html, "obs-list")
    assert ">OpenCTI<" in element(html, "obs-list")


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "java\tscript:alert(1)",
    "//evil.example/pcap",
])
def test_a_stored_arkime_url_with_a_bad_scheme_is_not_a_link(url):
    """Jinja escapes characters, not schemes. The filter drops javascript:
    and protocol-relative URLs, including the tab a browser strips before
    reading the scheme."""
    html = html_of(payload(arkime_web_url=url))
    assert 'id="open-in-arkime"' not in html
    assert "javascript:" not in html
    assert "//evil.example" not in html


def test_an_https_arkime_url_is_a_link():
    html = html_of(payload(arkime_web_url="https://arkime.example/sessions?q=1"))
    assert 'href="https://arkime.example/sessions?q=1"' in opening_tag(
        html, "open-in-arkime"
    )


def test_a_script_scheme_case_url_is_not_a_link():
    html = render(
        kind="commit_ok",
        case_url="javascript:alert(1)",
        case_number="IR-9",
        observables_created=1,
    )
    assert "javascript:" not in html
    assert "href=" not in html
    assert "IR-9" in html


def test_an_alert_id_cannot_break_out_of_the_commit_url():
    html = html_of(payload(), alert_id='a b"><script>')
    tag = opening_tag(html, "arkime-commit-form")
    assert 'hx-post="/ui/alerts/a%20b%22%3E%3Cscript%3E/arkime/commit"' in tag
    assert "<script>" not in html


def test_the_attach_form_names_its_own_request():
    """The form is rendered inside the preview panel, which posts the
    preview. Without hx-disinherit the submit button inherits that verb
    and re-runs the preview into the panel, discarding the form. The form
    is inside this render because only a preview that ran has a payload;
    Refresh stays in the page shell and is the control that retries."""
    html = html_of(payload(), alert_id="alert-1")
    tag = opening_tag(html, "arkime-commit-form")
    assert 'hx-post="/ui/alerts/alert-1/arkime/commit"' in tag
    assert 'hx-target="#commit-result"' in tag
    assert 'hx-swap="innerHTML"' in tag
    assert 'hx-disinherit="hx-post hx-target hx-swap"' in tag
    assert 'hx-disabled-elt="find button"' in tag
    assert "hx-include" not in tag


# ---------------------------------------------------------------------------
# The gates
# ---------------------------------------------------------------------------


def _permissions(route) -> set[str]:
    found: set[str] = set()

    def walk(deps):
        for dep in deps:
            fn = dep.call
            if fn is not None:
                base = getattr(fn, "__qualname__", "").split(".")[0]
                if base in ("require_permission", "require_any_permission"):
                    cells = dict(zip(
                        fn.__code__.co_freevars,
                        (c.cell_contents for c in (fn.__closure__ or ())),
                    ))
                    one = cells.get("permission_name")
                    many = cells.get("permission_names")
                    if isinstance(one, str):
                        found.add(one)
                    if isinstance(many, (list, tuple, set)):
                        found.update(str(p) for p in many)
            walk(dep.dependencies)

    walk(route.dependant.dependencies)
    return found


def _names(route) -> list[str]:
    out: list[str] = []

    def walk(deps):
        for dep in deps:
            if dep.call is not None:
                out.append(getattr(dep.call, "__qualname__", ""))
            walk(dep.dependencies)

    walk(route.dependant.dependencies)
    return out


def _json_routes():
    from ion.web.arkime_api import router as arkime_router

    found = {}
    for route in arkime_router.routes:
        path = getattr(route, "path", "")
        if path.endswith("/arkime/preview"):
            found["preview"] = route
        elif path.endswith("/arkime/commit"):
            found["commit"] = route
    return found


def test_the_fragment_permission_is_the_json_routes_permission():
    """Read out of the live dependency, not retyped from memory. The commit
    docstring mentions case:create and the decorator does not. The closure
    is what a request meets. A fragment must not be a softer way in, and it
    must not invent a second permission the JSON route does not check."""
    json_routes = _json_routes()
    assert set(json_routes) == {"preview", "commit"}
    for route in json_routes.values():
        assert _permissions(route) == {"alert:read"}
    assert PERMISSION == "alert:read"
    assert len(router.routes) == 2
    for route in router.routes:
        assert _permissions(route) == {"alert:read"}
        assert route.response_class is HTMLResponse
        blob = " ".join(_names(route))
        assert "require_page_permission" not in blob
        assert "require_de_module" not in blob


def test_the_json_router_is_not_behind_the_detection_engineering_gate():
    """arkime_router is mounted with no module dependency. require_de_module
    belongs to de_router. This page is not a de_* module, which is the only
    set the registry gates. Copying that pair here would answer 404 on a
    deployment the page and the JSON both still serve, and that 404 tells
    the caller the workspace does not exist."""
    src = SERVER.read_text(encoding="utf-8")
    mount = re.search(r"include_router\(\s*arkime_router\b[^)]*\)", src)
    assert mount, "arkime_router mount not found"
    assert "require_de_module" not in mount.group(0)


def test_the_module_mounts_both_routes_under_ui():
    from ion.web import ui as ui_pkg

    paths = {getattr(route, "path", "") for route in ui_pkg.router.routes}
    assert "/ui/alerts/{alert_id}/arkime" in paths
    assert "/ui/alerts/{alert_id}/arkime/commit" in paths


class _User:
    id = 1
    username = "arkime-tester"

    def has_permission(self, _name):
        return True


@pytest.fixture
def app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: session
    yield application
    application.dependency_overrides.clear()


def _preview_model():
    from ion.web.arkime_api import ArkimePreviewResponse

    return ArkimePreviewResponse(
        alert_id="alert-1",
        arkime_node="node-a",
        network_community_id="1:cid",
        arkime_session_id="sess-1",
        session_metadata={
            "srcIp": "10.0.0.1",
            "srcPort": 443,
            "dstIp": "8.8.8.8",
            "dstPort": 53,
            "ipProtocol": 17,
            "firstPacket": 1_744_689_000_000,
            "packets": 0,
            "bytes": 0,
        },
        pcap_size_bytes=0,
        analysis={
            "findings": [{
                "severity": "high",
                "title": "Beacon",
                "detail": "every 60s",
            }],
            "top_dst_ips": [{"ip": "8.8.8.8", "count": 4}],
            "protocols": {"dns": 2},
            "verdict": {"label": "Suspicious", "score": 0},
        },
        observables=[],
        enrichment_enabled=True,
        warnings=["partial capture"],
        arkime_web_url="https://arkime.example/sessions?expression=1",
    )


def test_the_route_renders_the_preview_the_json_endpoint_returns(app, monkeypatch):
    """The fragment calls arkime_preview. A model, not a dict: that is what
    the JSON route returns, and model_dump is how its enums and observables
    become the same structure the old JavaScript parsed."""
    seen = {}

    async def fake(alert_id, user):
        seen["alert_id"] = alert_id
        seen["user"] = user
        return _preview_model()

    monkeypatch.setattr("ion.web.arkime_api.arkime_preview", fake)
    with TestClient(app) as client:
        resp = client.post("/ui/alerts/alert-1/arkime")
    assert resp.status_code == 200
    assert seen["alert_id"] == "alert-1"
    assert seen["user"].username == "arkime-tester"
    assert "every 60s" in resp.text
    assert "Beacon" in resp.text
    assert text_of(element(resp.text, "stat-verdict-sub")) == "score 0"
    assert text_of(element(resp.text, "sess-packets")) == "0"
    assert "0 B" in element(resp.text, "session-size")
    assert destination_text(resp.text) == "4"
    assert text_of(element(resp.text, "stat-hits")) == "0"
    assert "partial capture" in resp.text
    assert 'href="https://arkime.example/sessions?expression=1"' in resp.text
    assert hidden_size(resp.text) == "0"


def destination_text(html: str) -> str:
    cells = re.findall(r"<td\b[^>]*>(.*?)</td>", element(html, "top-dst"), re.S)
    return text_of(cells[-1])


def test_an_arkime_401_is_a_fragment_and_not_a_login_redirect(app, monkeypatch):
    """htmx-errors.js sends the browser to /login on a 401. Arkime's 401 is
    Arkime rejecting its own credentials, not the analyst's session. Letting
    it propagate logs the analyst out of a page they are still signed in to."""
    async def fake(*_a, **_k):
        raise HTTPException(status_code=401, detail="Arkime rejected the credentials")

    monkeypatch.setattr("ion.web.arkime_api.arkime_preview", fake)
    with TestClient(app) as client:
        resp = client.post("/ui/alerts/alert-1/arkime")
    assert resp.status_code == 200
    assert "Preview failed (HTTP 401)" in resp.text
    assert "Arkime rejected the credentials" in resp.text
    assert "No suspicious findings detected." not in resp.text
    assert 'id="stat-findings"' not in resp.text
    assert "arkime-commit-form" not in resp.text


def test_an_unconfigured_arkime_says_so_instead_of_leaving_the_spinner(app, monkeypatch):
    """htmx does not swap a 503, so the analyst would keep reading
    "Requesting PCAP from Arkime" forever."""
    async def fake(*_a, **_k):
        raise HTTPException(
            status_code=503,
            detail="Arkime is not configured — set ION_ARKIME_URL",
        )

    monkeypatch.setattr("ion.web.arkime_api.arkime_preview", fake)
    with TestClient(app) as client:
        resp = client.post("/ui/alerts/alert-1/arkime")
    assert resp.status_code == 200
    assert "Preview failed (HTTP 503)" in resp.text
    assert "Arkime is not configured" in resp.text
    assert "not an empty capture" in resp.text


def test_a_preview_error_detail_is_escaped(app, monkeypatch):
    async def fake(*_a, **_k):
        raise HTTPException(status_code=502, detail="<script>alert(1)</script>")

    monkeypatch.setattr("ion.web.arkime_api.arkime_preview", fake)
    with TestClient(app) as client:
        resp = client.post("/ui/alerts/alert-1/arkime")
    assert resp.status_code == 200
    assert "<script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_an_unexpected_preview_failure_does_not_leak_or_look_empty(app, monkeypatch):
    async def fake(*_a, **_k):
        raise RuntimeError("arkime-password-leak")

    monkeypatch.setattr("ion.web.arkime_api.arkime_preview", fake)
    with TestClient(app) as client:
        resp = client.post("/ui/alerts/alert-1/arkime")
    assert resp.status_code == 200
    assert "arkime-password-leak" not in resp.text
    assert "could not be read" in resp.text
    assert "unknown rather than zero" in resp.text
    assert "No suspicious findings detected." not in resp.text


@pytest.mark.parametrize("path", [
    "/ui/alerts/abc/arkime",
    "/ui/alerts/abc/arkime/commit",
])
def test_an_unauthenticated_request_is_401(path, session):
    """get_db_session is overridden because resolving the auth dependency
    opens one even when the cookie is missing. The user dependency is not
    overridden: that is the case under test. 403 is deliberately not
    requested. audit_refusal writes through the configured engine, which is
    not this test's database."""
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_db_session] = lambda: session
    try:
        with TestClient(application) as client:
            resp = client.post(path)
    finally:
        application.dependency_overrides.clear()
    assert resp.status_code == 401
    assert "No suspicious findings" not in resp.text


# ---------------------------------------------------------------------------
# Attach
# ---------------------------------------------------------------------------


def _stub_commit(monkeypatch, result=None, error=None):
    seen: dict = {}

    async def fake(alert_id, body, user, session):
        seen["alert_id"] = alert_id
        seen["body"] = body
        seen["user"] = user
        if error is not None:
            raise error
        return result

    monkeypatch.setattr("ion.web.arkime_api.arkime_commit", fake)
    return seen


def _post_commit(client, omit=(), **fields):
    data = {
        "commit_mode": "new",
        "case_title": "Mine",
        "case_severity": "medium",
        "analysis": '{"verdict": {"label": "Suspicious"}}',
        "observables": "[]",
        "pcap_size_bytes": "128",
    }
    data.update(fields)
    for key in omit:
        data.pop(key, None)
    return client.post("/ui/alerts/alert-1/arkime/commit", data=data)


def _ok_result(**over):
    from types import SimpleNamespace

    base = dict(case_id=9, case_number="IR-9", observables_created=0)
    base.update(over)
    return SimpleNamespace(**base)


def test_a_commit_of_zero_observables_says_zero(app, monkeypatch):
    """A successful attach that created nothing is not a failed attach.
    The failure copy says the count is unknown."""
    seen = _stub_commit(monkeypatch, result=_ok_result(observables_created=0))
    with TestClient(app) as client:
        resp = _post_commit(client, pcap_size_bytes="0")
    assert resp.status_code == 200
    assert seen["body"].pcap_size_bytes == 0
    assert seen["body"].create_new_case is True
    assert seen["alert_id"] == "alert-1"
    assert "0 observable(s) created." in resp.text
    assert "unknown, not zero" not in resp.text
    assert 'data-case-url="/cases?id=9"' in resp.text
    assert "IR-9" in resp.text
    assert 'hx-swap-oob="outerHTML"' in resp.text
    assert ">Attached<" in resp.text


def test_a_commit_whose_observable_count_is_missing_does_not_say_zero(app, monkeypatch):
    from types import SimpleNamespace

    _stub_commit(monkeypatch, result=SimpleNamespace(case_id=9, case_number="IR-9"))
    with TestClient(app) as client:
        resp = _post_commit(client)
    assert resp.status_code == 200
    assert "unknown, not zero" in resp.text
    assert "0 observable" not in resp.text


def test_an_unusable_case_id_does_not_become_a_link(app, monkeypatch):
    _stub_commit(monkeypatch, result=_ok_result(case_id="nope", case_number=None, observables_created=1))
    with TestClient(app) as client:
        resp = _post_commit(client)
    assert resp.status_code == 200
    assert "href=" not in resp.text
    assert "1 observable(s) created." in resp.text


def test_an_integral_float_size_is_a_byte_count(app, monkeypatch):
    """The form echoes a number. "1024.0" is 1024 bytes. int() of that
    string raises, and treating the raise as "unreadable" refuses a size
    the preview itself produced."""
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(client, pcap_size_bytes="1024.0")
    assert resp.status_code == 200
    assert seen["body"].pcap_size_bytes == 1024
    assert "0 observable(s) created." in resp.text


def test_a_fractional_size_is_refused_and_nothing_is_written(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(client, pcap_size_bytes="1.5")
    assert resp.status_code == 200
    assert "body" not in seen
    assert "could not be read" in resp.text
    assert "0 observable" not in resp.text


def test_a_blank_size_is_not_stored_as_zero_bytes(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(client, pcap_size_bytes="")
    assert resp.status_code == 200
    assert "body" not in seen
    assert "not zero bytes" in resp.text


def test_a_missing_size_field_is_not_stored_as_zero_bytes(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(client, omit=("pcap_size_bytes",))
    assert resp.status_code == 200
    assert "body" not in seen
    assert "not zero bytes" in resp.text


def test_a_commit_mode_outside_new_or_existing_writes_nothing(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(client, commit_mode="sideways")
    assert resp.status_code == 200
    assert "body" not in seen
    assert "Nothing was written." in resp.text


def test_an_existing_case_without_an_id_writes_nothing(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(client, commit_mode="existing", case_id="")
    assert resp.status_code == 200
    assert "body" not in seen
    assert "case id is required" in resp.text


def test_an_existing_case_keeps_the_id_and_drops_the_new_title(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        resp = _post_commit(
            client, commit_mode="existing", case_id="12", case_title="Ignored",
        )
    assert resp.status_code == 200
    body = seen["body"]
    assert body.case_id == 12
    assert body.create_new_case is False
    assert body.case_title is None
    assert body.analysis == {"verdict": {"label": "Suspicious"}}


def test_a_blank_severity_defaults_to_medium(app, monkeypatch):
    """ArkimeCommitRequest defaults the severity to medium. An empty select
    is that default, not the string "None" and not an omitted field."""
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        _post_commit(client, case_severity="")
    assert seen["body"].case_severity == "medium"
    assert seen["body"].case_title == "Mine"


def test_a_payload_that_does_not_parse_writes_nothing(app, monkeypatch):
    seen = _stub_commit(monkeypatch, result=_ok_result())
    with TestClient(app) as client:
        bad_json = _post_commit(client, analysis="{")
        not_object = _post_commit(client, analysis="[]")
        not_list = _post_commit(client, observables="{}")
    assert "body" not in seen
    assert bad_json.status_code == not_object.status_code == not_list.status_code == 200
    assert "could not be read back" in bad_json.text
    assert "not a result object" in not_object.text
    assert "unreadable" in not_list.text
    for resp in (bad_json, not_object, not_list):
        assert "0 observable" not in resp.text


def test_an_arkime_refusal_on_commit_stays_a_fragment(app, monkeypatch):
    _stub_commit(
        monkeypatch,
        error=HTTPException(status_code=401, detail="<img src=x onerror=1>"),
    )
    with TestClient(app) as client:
        resp = _post_commit(client)
    assert resp.status_code == 200
    assert "Attach failed (HTTP 401)" in resp.text
    assert "Nothing was written." in resp.text
    assert "<img" not in resp.text
    assert "&lt;img" in resp.text


def test_an_unexpected_commit_failure_does_not_look_like_zero_observables(app, monkeypatch):
    _stub_commit(monkeypatch, error=RuntimeError("case-db-password"))
    with TestClient(app) as client:
        resp = _post_commit(client)
    assert resp.status_code == 200
    assert "case-db-password" not in resp.text
    assert "write failed" in resp.text
    assert "0 observable" not in resp.text


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _source(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    return src


def test_the_page_builds_no_markup_in_javascript_and_the_script_parses():
    """The server column, measured the way tools/ui_redesign_status.py does.
    Comments are not stripped there, so the raw script body is what counts.
    hx-swap="innerHTML" is an attribute and is not in that body."""
    src = PAGE.read_text(encoding="utf-8")
    scripts = re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S)
    assert len(scripts) == 1
    js = scripts[0]
    assert js.strip()
    assert not re.findall(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js)
    fd, name = tempfile.mkstemp(suffix=".js")
    os.close(fd)
    try:
        Path(name).write_text(js, encoding="utf-8")
        proc = subprocess.run(
            ["node", "--check", name], capture_output=True, text=True,
        )
    finally:
        os.unlink(name)
    assert proc.returncode == 0, proc.stderr


def test_the_string_building_helper_is_gone():
    src = _source(PAGE)
    assert "escHtml" not in src
    assert "function render" not in src
    assert "fmtBytes" not in src


def test_refresh_sits_outside_the_swap_target_and_posts_the_fragment():
    """A control inside the fragment is removed by any render that omits it,
    and the failure render omits everything except the error."""
    src = PAGE.read_text(encoding="utf-8")
    assert src.index('id="arkime-refresh"') < src.index('id="arkime-content"')
    refresh = opening_tag(src, "arkime-refresh")
    slot = opening_tag(src, "arkime-content")
    assert 'hx-post="/ui/alerts/{{ alert_id | urlencode }}/arkime"' in refresh
    assert 'hx-target="#arkime-content"' in refresh
    assert "hx-trigger" not in refresh
    assert 'hx-trigger="load"' in slot
    assert 'hx-disinherit="hx-post hx-target hx-swap"' in slot
    assert src.count('hx-post="/ui/alerts/{{ alert_id | urlencode }}/arkime"') == 2
    assert "/api/alerts" not in src
    assert "arkime-commit-form" not in src


def test_neither_template_compiles_a_string_for_htmx_or_handles_errors():
    """CSP blocks hx-on, js: values and an event filter, and the feature
    silently does nothing. static/js/htmx-errors.js owns 401 and the rest."""
    for path in (PAGE, FRAGMENT_PATH):
        src = _source(path)
        assert "hx-on" not in src, path.name
        assert "js:" not in src, path.name
        assert "hx-vals" not in src, path.name
        assert "[key==" not in src, path.name
        assert "htmx:responseError" not in src, path.name
        assert "htmx:sendError" not in src, path.name
