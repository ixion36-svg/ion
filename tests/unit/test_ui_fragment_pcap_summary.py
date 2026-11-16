"""The pcap analyser's verdict banner, summary cards, overview and network.

A MISSING VERDICT TOOK THE WHOLE PAGE DOWN

renderResults opened with

    const label = d.verdict.label;

with no guard, and it is the first statement in the function that renders
every one of the page's twenty-eight panels. A stored result without a
verdict key threw there, so nothing rendered at all: no protocol
distribution, no DNS, no findings, no threat intel. The analysis had run
and the result was in the database.

THE SAME NaN DEFECT AS THE REST OF THE REDESIGN

    const max = Math.max(...top.map(i => i.count), 1);
    const pct = (i.count / max * 100).toFixed(1);

One count that is not a number makes `max` NaN, which makes every
percentage NaN, so every bar in both IP tables and both port tables
rendered `width:NaN%` and the column was empty. Seen first on the
analytics index breakdown; this is the same shape in four tables at once.

`convMax` is worse than a reduce: it is `d.conversations[0].bytes`, so it
trusts the list to be sorted and one missing `bytes` on the first entry
makes every conversation bar NaN.

EVERY TAB BADGE CARRIED ITS PALETTE IN A JAVASCRIPT STRING

    fb.style.cssText = 'display:inline;background:var(--sev-critical);...'

repeated at eighteen sites, one per tab. This is not a CSP problem:
server.py's note is explicit that the policy allows programmatic CSSOM,
and a `style.cssText` write is CSSOM rather than a style attribute parse.
It is the problem this project exists to fix. Eighteen copies of a
padding, a radius, a font size and a colour held in JavaScript, where no
sweep of the stylesheet reaches any of them.

Smaller ones: fmtBytes and fmtDuration both fall through every comparison
for a missing value and return "NaN GB" and "NaNh"; fmtNum's `(n || 0)`
reports a recorded zero and a missing count alike; `${i.port}` printed
"undefined"; and an empty protocols map rendered a summary card with a
blank value.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.pcap import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/pcap.html"
#: The page sheet was retired; these rules are nested under
#: body[data-page="pcap"] in the one build.
SHEET = ROOT / "frontend/ion-pages.css"

SUMMARY = "/ui/pcap/7/summary"
NETWORK = "/ui/pcap/7/network"


class _User:
    id = 1
    username = "pcap-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(url, user):
    with TestClient(_app(user)) as client:
        return client.get(url)


def _reader():
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def job(monkeypatch):
    def set(result=None, raises=None, payload=None):
        def handler(job_id, _user=None, session=None):
            if raises is not None:
                raise raises
            if payload is not None:
                return payload
            return {"id": job_id, "status": "complete", "result": result}

        monkeypatch.setattr("ion.web.pcap_api.get_pcap_job", handler)

    return set


def _result(**over):
    r = {
        "verdict": {"label": "Elevated", "confidence": 72, "score": 31,
                    "finding_count": 3,
                    "reasons": ["beaconing to one host"]},
        "file_name": "capture.pcapng",
        "file_size": 2048,
        "packet_count": 1200,
        "capture_duration": 65.4,
        "time_start": "2026-10-13T09:00:00",
        "protocols": {"TCP": 900, "UDP": 300},
        "top_src_ips": [{"ip": "10.0.0.1", "count": 500}],
        "top_dst_ips": [{"ip": "10.0.0.2", "count": 400}],
        "top_src_ports": [{"port": 443, "count": 300}],
        "top_dst_ports": [{"port": 53, "count": 200}],
        "dns_queries": [{"query": "example.test", "count": 4}],
        "conversations": [{"pair": "10.0.0.1 - 10.0.0.2", "bytes": 9000}],
        "findings": [{"title": "beaconing"}],
    }
    r.update(over)
    return r


def _oob(html: str, ident: str) -> str:
    match = re.search('id="' + ident + r'"(.*?)hx-swap-oob', html, re.S)
    if match is None:
        match = re.search('id="' + ident + r'"[^>]*>(.*?)</(?:div|span|ul)>',
                          html, re.S)
    assert match, (ident, html[:500])
    return match.group(0)


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_both_panels_need_the_pages_permission(job):
    job(result=_result())
    for url in (SUMMARY, NETWORK):
        assert _get(url, _User()).status_code == 403, url
        assert _get(url, _reader()).status_code == 200, url


# ---------------------------------------------------------------------------
# The crash
# ---------------------------------------------------------------------------


def test_a_result_with_no_verdict_still_renders_everything_else(job):
    """`const label = d.verdict.label` threw on the first line of the
    function that renders all twenty-eight panels."""
    job(result=_result(verdict=None))
    html = _get(SUMMARY, _reader()).text
    body = flat(html)
    # The verdict says it is missing, and the rest of the summary is
    # still there.
    assert "no verdict" in body.lower()
    assert "capture.pcapng" in body
    assert "1,200" in body
    assert "TCP" in body


def test_a_verdict_that_is_not_an_object_is_reported(job):
    job(result=_result(verdict="Elevated"))
    assert "no verdict" in flat(_get(SUMMARY, _reader()).text).lower()


@pytest.mark.parametrize("label,state", [
    ("Needs Investigation", "investigate"),
    ("Elevated", "elevated"),
    ("Benign", "benign"),
    ("something else", "benign"),
])
def test_the_verdict_state_class_is_unchanged(job, label, state):
    job(result=_result(verdict={"label": label, "confidence": 10,
                                "reasons": []}))
    assert "verdict-banner " + state in _get(SUMMARY, _reader()).text


def test_a_missing_confidence_is_not_rendered_as_undefined(job):
    job(result=_result(verdict={"label": "Elevated", "reasons": []}))
    html = _get(SUMMARY, _reader()).text
    assert "undefined" not in html
    assert "Confidence: %" not in flat(html)


def test_a_score_of_zero_is_shown_and_a_missing_score_is_not(job):
    """`d.verdict.score != null` was right for this; the test keeps it
    right."""
    job(result=_result(verdict={"label": "Benign", "confidence": 90,
                                "score": 0, "reasons": []}))
    assert "Score: 0" in flat(_get(SUMMARY, _reader()).text)
    job(result=_result(verdict={"label": "Benign", "confidence": 90,
                                "reasons": []}))
    assert "Score:" not in flat(_get(SUMMARY, _reader()).text)


def test_a_verdict_reason_is_escaped(job):
    job(result=_result(verdict={
        "label": "Elevated", "confidence": 1,
        "reasons": ["<img src=x onerror=alert(1)>"]}))
    html = _get(SUMMARY, _reader()).text
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_reasons_that_are_not_a_list_are_not_no_reasons(job):
    job(result=_result(verdict={"label": "Elevated", "confidence": 1,
                                "reasons": "lots"}))
    body = flat(_get(SUMMARY, _reader()).text)
    assert "not in a shape" in body or "could not" in body.lower()


# ---------------------------------------------------------------------------
# The findings badge
# ---------------------------------------------------------------------------


def test_the_findings_badge_is_styled_by_a_class_not_a_js_string(job):
    """`fb.style.cssText = ...` applied, but it held the colour, padding
    and radius in JavaScript, where no stylesheet reaches them."""
    job(result=_result(findings=[{"title": "a"}, {"title": "b"}]))
    html = _get(SUMMARY, _reader()).text
    assert "pcap-findings-badge" in html
    # A real style attribute, not the data-ion-style the CSP-safe
    # dynamic widths use.
    assert not re.search(r'(?<!-)\bstyle="', html)
    assert ">2<" in html.replace(" ", "").replace("\n", "")


def test_no_findings_hides_the_badge(job):
    job(result=_result(findings=[]))
    html = _get(SUMMARY, _reader()).text
    assert "pcap-findings-badge is-empty" in html or ">0<" not in html


def test_findings_that_are_not_a_list_do_not_report_a_count(job):
    job(result=_result(findings="three"))
    html = _get(SUMMARY, _reader()).text
    assert "undefined" not in html
    assert "NaN" not in html


# ---------------------------------------------------------------------------
# The summary cards
# ---------------------------------------------------------------------------


def test_the_file_size_and_duration_are_formatted(job):
    job(result=_result(file_size=2048, capture_duration=65.4))
    body = flat(_get(SUMMARY, _reader()).text)
    assert "2.0 KB" in body
    assert "1.1m" in body


@pytest.mark.parametrize("size,label", [
    (512, "512 B"), (2048, "2.0 KB"), (2097152, "2.0 MB"),
    (2147483648, "2.0 GB"),
])
def test_the_byte_thresholds_are_unchanged(job, size, label):
    job(result=_result(file_size=size))
    assert label in flat(_get(SUMMARY, _reader()).text)


@pytest.mark.parametrize("seconds,label", [
    (0.25, "0.250s"), (12.0, "12.0s"), (65.4, "1.1m"), (7200.0, "2.0h"),
])
def test_the_duration_thresholds_are_unchanged(job, seconds, label):
    job(result=_result(capture_duration=seconds))
    assert label in flat(_get(SUMMARY, _reader()).text)


def test_a_missing_size_or_duration_is_not_nan(job):
    """Both formatters fall through every comparison for a missing value
    and divide, so they returned "NaN GB" and "NaNh"."""
    job(result=_result(file_size=None, capture_duration=None))
    html = _get(SUMMARY, _reader()).text
    assert "NaN" not in html
    assert "an-absent" in html


def test_a_missing_packet_count_is_not_reported_as_zero_packets(job):
    """`fmtNum` is `(n || 0).toLocaleString()`, so a capture whose packet
    count was not recorded reported zero packets."""
    job(result=_result(packet_count=None))
    html = _get(SUMMARY, _reader()).text
    assert "an-absent" in html


def test_a_recorded_zero_packet_count_is_shown(job):
    job(result=_result(packet_count=0))
    assert "0" in flat(_get(SUMMARY, _reader()).text)


def test_an_empty_protocol_map_says_so_rather_than_leaving_a_blank(job):
    job(result=_result(protocols={}))
    body = flat(_get(SUMMARY, _reader()).text)
    assert "no protocols" in body.lower()


def test_a_file_name_is_escaped(job):
    job(result=_result(file_name="<script>alert(1)</script>.pcap"))
    html = _get(SUMMARY, _reader()).text
    assert "<script>alert(1)" not in html
    assert "alert(1)" in flat(html)


# ---------------------------------------------------------------------------
# The overview
# ---------------------------------------------------------------------------


def test_the_protocol_bars_are_drawn(job):
    job(result=_result(protocols={"TCP": 750, "UDP": 250}))
    html = _get(SUMMARY, _reader()).text
    assert "proto-bar-fill tcp" in html
    assert "proto-bar-fill udp" in html
    assert "75.0%" in flat(html)


def test_an_unlisted_protocol_takes_the_other_class(job):
    job(result=_result(protocols={"GRE": 10}))
    html = _get(SUMMARY, _reader()).text
    assert "proto-bar-fill other" in html
    assert "proto-bar-fill GRE" not in html


def test_one_unreadable_protocol_count_does_not_make_every_bar_nan(job):
    job(result=_result(protocols={"TCP": 10, "UDP": "lots"}))
    html = _get(SUMMARY, _reader()).text
    assert "NaN" not in html
    assert "proto-bar-fill tcp" in html


def test_the_conversation_bars_scale_to_the_largest_not_the_first(job):
    """`convMax = d.conversations[0].bytes` trusted the list to be
    sorted, so an unsorted list drew bars over 100%."""
    job(result=_result(conversations=[
        {"pair": "a - b", "bytes": 100},
        {"pair": "c - d", "bytes": 900}]))
    html = _get(SUMMARY, _reader()).text
    assert "width:100.0%" in html.replace(" ", "")
    for found in re.findall(r"width:\s*([\d.]+)%", html):
        assert float(found) <= 100.0, found


def test_a_conversation_with_no_byte_count_does_not_nan_the_rest(job):
    job(result=_result(conversations=[
        {"pair": "a - b"}, {"pair": "c - d", "bytes": 900}]))
    html = _get(SUMMARY, _reader()).text
    assert "NaN" not in html
    assert "c - d" in flat(html)


def test_at_most_ten_conversations_are_shown(job):
    job(result=_result(conversations=[
        {"pair": "p%d" % i, "bytes": 100 - i} for i in range(20)]))
    assert _get(SUMMARY, _reader()).text.count("conv-bar-fill") == 10


def test_no_conversations_says_so(job):
    job(result=_result(conversations=[]))
    assert "No conversations recorded" in flat(_get(SUMMARY, _reader()).text)


# ---------------------------------------------------------------------------
# The network tables
# ---------------------------------------------------------------------------


def test_the_four_tables_are_drawn(job):
    job(result=_result())
    body = flat(_get(NETWORK, _reader()).text)
    for heading in ("Top Source IPs", "Top Destination IPs",
                    "Top Source Ports", "Top Destination Ports"):
        assert heading in body, heading
    assert "10.0.0.1" in body
    assert "443" in body


def test_one_unreadable_count_does_not_make_every_bar_nan(job):
    """The defect these tables share with the analytics index
    breakdown."""
    job(result=_result(top_src_ips=[
        {"ip": "10.0.0.1", "count": 10},
        {"ip": "10.0.0.2", "count": "lots"}]))
    html = _get(NETWORK, _reader()).text
    assert "NaN" not in html
    assert "10.0.0.1" in flat(html)


def test_a_port_with_no_number_does_not_print_undefined(job):
    job(result=_result(top_src_ports=[{"count": 10}]))
    html = _get(NETWORK, _reader()).text
    assert "undefined" not in html


def test_an_ip_is_escaped(job):
    job(result=_result(top_src_ips=[
        {"ip": "<script>alert(1)</script>", "count": 1}]))
    html = _get(NETWORK, _reader()).text
    assert "<script>alert(1)" not in html


def test_at_most_fifteen_rows_per_table(job):
    job(result=_result(top_src_ips=[
        {"ip": "10.0.0.%d" % i, "count": 100 - i} for i in range(30)]))
    html = _get(NETWORK, _reader()).text
    first = html.index("Top Destination IPs")
    assert html[:first].count("<tr>") <= 16


def test_an_empty_table_says_no_data(job):
    job(result=_result(top_src_ips=[]))
    assert "No data" in flat(_get(NETWORK, _reader()).text)


def test_a_table_payload_that_is_not_a_list_is_not_no_data(job):
    job(result=_result(top_src_ips="broken"))
    body = flat(_get(NETWORK, _reader()).text)
    assert "not in a shape" in body


# ---------------------------------------------------------------------------
# Failures of the read itself
# ---------------------------------------------------------------------------


def test_a_missing_job_is_reported(job):
    job(raises=HTTPException(status_code=404, detail="Job 7 not found"))
    assert "Job 7 not found" in flat(_get(SUMMARY, _reader()).text)


def test_an_unexpected_exception_is_reported(job):
    job(raises=RuntimeError("the store went away"))
    assert "could not" in flat(_get(SUMMARY, _reader()).text).lower()


def test_a_job_with_no_result_is_not_an_empty_capture(job):
    job(result=None)
    body = flat(_get(SUMMARY, _reader()).text)
    assert "no stored result" in body.lower() or "could not" in body.lower()


def test_a_failed_job_reports_its_own_error(job):
    job(payload={"id": 7, "status": "failed",
                 "error": "tshark is not installed", "result": None})
    assert "tshark is not installed" in flat(_get(SUMMARY, _reader()).text)


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_these_panels():
    body = _scripts()
    # Word boundaries: renderNetworkGraph is a different function that
    # stays, and it contains renderNetwork as a substring.
    for name in ("renderOverview", "renderNetwork", "ipTable",
                 "portTable", "card"):
        assert not re.search(r"function " + name + r"\b", body), name


def test_no_badge_holds_its_palette_in_javascript_any_more():
    """Seventeen sites, one per tab, each with its own copy of a padding,
    a radius, a font size and a colour.

    The page's scripts now name no badge at all: each comes back inside
    its own tab button from a fragment. So this checks the palette is
    gone from the JavaScript and that the classes exist where the markup
    is, which the tone test below pins against the stylesheet.
    """
    body = _scripts()
    assert "style.cssText" not in body
    assert "badge.className" not in body
    assert "pcap-tab-badge" in SHEET.read_text(encoding="utf-8")


def test_every_badge_tone_anything_asks_for_exists_in_the_stylesheet():
    """A tone with no rule is a badge with no background.

    The tones are named in the fragments and in the registry now, not in
    the page's scripts, so this reads all three. The `assert asked` guard
    is load-bearing: when the tones moved out of the page it was an empty
    set, and the loop would otherwise have passed over nothing.
    """
    import re as _re

    page = SHEET.read_text(encoding="utf-8")
    sources = [_scripts(),
               (ROOT / "src/ion/web/ui/pcap.py").read_text(encoding="utf-8")]
    fragments = ROOT / "src/ion/web/templates/_fragments"
    for name in ("pcap_tables.html", "pcap_summary.html",
                 "pcap_detail.html"):
        sources.append((fragments / name).read_text(encoding="utf-8"))

    asked = set()
    for source in sources:
        asked |= set(_re.findall(r"tone-[a-z]+", source))
    assert len(asked) >= 2, asked
    for tone in asked:
        assert ".pcap-tab-badge." + tone + " " in page, tone


def test_the_page_no_longer_reads_the_verdict_unguarded():
    assert "d.verdict.label" not in _scripts()


def test_the_page_links_the_sheet_that_carries_those_rules():
    """A sheet nobody links is the mistake that left the forensics
    preview bare, and it is the one these rules now depend on."""
    page = PAGE.read_text(encoding="utf-8")
    assert "pcap-page.css" not in page
    assert "{% block page_id %}pcap{% endblock %}" in page
    assert "<style" not in PAGE.read_text(encoding="utf-8")
