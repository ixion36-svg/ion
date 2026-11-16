"""The fourteen uniform pcap table panels.

They were the same function written fourteen times, and they shared their
defects as well as their shape.

A HIDDEN TAB CLAIMED THE CAPTURE WAS CLEAN

    const fps = d.ja3_fingerprints || [];
    if (!fps.length) { tab.style.display = 'none'; return; }

A payload in the wrong shape became an empty list, which hid the tab. A
hidden tab is the strongest claim this page can make: it says the capture
contained no credentials, no malware JA3 match, no ARP anomalies and no
extracted files. It was being made on the strength of a read that failed.

NUMBERS STRAIGHT INTO MARKUP

`${b.port}`, `${b.score}`, `${b.connections}`, `${s.retransmits}` and
`fmtBytes(f.size)` each produced "undefined" or "NaN GB" for a row that
did not carry one.

ARP BUILT A CSS VARIABLE NAME OUT OF THE PAYLOAD

    data-ion-style="color:var(--sev-${a.severity})"

A severity the analyser did not emit resolves to an undefined custom
property, so the text kept its inherited colour and the row read as
ordinary. The severity picks from a fixed set of classes now.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.pcap import PERMISSION, TABLE_PANELS, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/pcap.html"

URL = "/ui/pcap/7/tables"


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


def _get(user):
    with TestClient(_app(user)) as client:
        return client.get(URL)


def _reader():
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def job(monkeypatch):
    def set(result=None, raises=None):
        def handler(job_id, _user=None, session=None):
            if raises is not None:
                raise raises
            return {"id": job_id, "status": "complete", "result": result}

        monkeypatch.setattr("ion.web.pcap_api.get_pcap_job", handler)

    return set


def _panel(html: str, panel_id: str) -> str:
    start = html.index('id="' + panel_id + '"')
    opened = html.rfind("<div", 0, start)
    end = html.find('hx-swap-oob="innerHTML:#', start)
    end = html.find("<div id=", end + 10)
    return html[opened:end if end != -1 else len(html)]


def _tab(html: str, tab_id: str) -> str:
    start = html.index('id="' + tab_id + '"')
    opened = html.rfind("<button", 0, start)
    return html[opened:html.find("</button>", start) + 9]


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panels_need_the_pages_permission(job):
    job(result={})
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


# ---------------------------------------------------------------------------
# The hidden tab
# ---------------------------------------------------------------------------


def test_an_unreadable_list_keeps_its_tab_and_says_so(job):
    """The defect these panels exist to fix. `|| []` hid the tab, which
    says the capture contained none."""
    job(result={"credential_captures": "broken"})
    html = _get(_reader()).text
    assert "hidden" not in _tab(html, "tab-creds")
    assert "not in a shape" in flat(_panel(html, "panel-creds"))


def test_an_empty_list_hides_its_tab_as_before(job):
    job(result={"credential_captures": []})
    assert "hidden" in _tab(_get(_reader()).text, "tab-creds")


def test_a_populated_list_shows_its_tab_and_count(job):
    job(result={"credential_captures": [
        {"protocol": "ftp", "username": "bob", "credential": "hunter2",
         "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "detail": "cleartext"},
        {"protocol": "http", "username": "eve", "credential": "x",
         "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "detail": "basic"}]})
    html = _get(_reader()).text
    tab = _tab(html, "tab-creds")
    assert "hidden" not in tab
    assert ">2<" in tab.replace(" ", "").replace("\n", "")
    body = flat(_panel(html, "panel-creds"))
    assert "bob" in body
    assert "cleartext" in body


def test_a_failed_read_does_not_hide_every_tab(job):
    """It is the same claim, made fourteen times at once."""
    job(raises=RuntimeError("the store went away"))
    body = flat(_get(_reader()).text).lower()
    assert "could not" in body


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------


def test_a_beacon_with_no_port_or_score_does_not_print_undefined(job):
    job(result={"beacons": [{"src": "10.0.0.1", "dst": "10.0.0.2"}]})
    html = _get(_reader()).text
    assert "undefined" not in html
    assert "an-absent" in _panel(html, "panel-beacons")


def test_a_beacon_renders_its_figures(job):
    job(result={"beacons": [{"src": "a", "dst": "b", "port": 443,
                             "score": 9, "connections": 1200,
                             "interval_s": 60}]})
    body = flat(_panel(_get(_reader()).text, "panel-beacons"))
    assert "443" in body
    assert "1,200" in body
    assert "~60s" in body


def test_a_file_with_no_size_is_not_nan(job):
    job(result={"extracted_files": [{"filename": "x.exe"}]})
    html = _get(_reader()).text
    assert "NaN" not in html
    assert "x.exe" in flat(html)


def test_a_zero_byte_file_reports_zero_bytes(job):
    job(result={"extracted_files": [{"filename": "x", "size": 0}]})
    assert "0 B" in flat(_panel(_get(_reader()).text, "panel-files"))


def test_a_dns_count_is_thousands_separated(job):
    job(result={"dns_queries": [{"query": "a.test", "count": 4200}]})
    assert "4,200" in flat(_panel(_get(_reader()).text, "panel-dns"))


def test_at_most_forty_dns_rows(job):
    job(result={"dns_queries": [
        {"query": "q%d.test" % i, "count": i} for i in range(80)]})
    panel = _panel(_get(_reader()).text, "panel-dns")
    assert panel.count("<tr>") <= 41
    # The heading still reports the true total, not the shown count.
    assert "80" in flat(panel)


# ---------------------------------------------------------------------------
# ARP severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity", [
    "critical", "high", "medium", "low", "info"])
def test_a_known_severity_takes_its_class(job, severity):
    job(result={"arp_anomalies": [
        {"mac": "aa:bb", "ips": ["1.1.1.1"], "severity": severity,
         "detail": "d"}]})
    assert "pcap-sev-" + severity in _get(_reader()).text


def test_an_unknown_severity_keeps_its_text_but_takes_no_class(job):
    """`var(--sev-${a.severity})` resolved to nothing and the row looked
    ordinary."""
    job(result={"arp_anomalies": [
        {"mac": "aa:bb", "ips": ["1.1.1.1"], "severity": "catastrophic",
         "detail": "d"}]})
    html = _get(_reader()).text
    assert "catastrophic" in flat(html)
    assert "pcap-sev-catastrophic" not in html


def test_a_missing_severity_says_so(job):
    job(result={"arp_anomalies": [
        {"mac": "aa:bb", "ips": ["1.1.1.1"], "detail": "d"}]})
    assert "an-absent" in _panel(_get(_reader()).text, "panel-arp")


def test_the_claimed_ips_are_joined(job):
    job(result={"arp_anomalies": [
        {"mac": "aa", "ips": ["1.1.1.1", "2.2.2.2"], "severity": "high",
         "detail": "d"}]})
    assert "1.1.1.1, 2.2.2.2" in flat(_get(_reader()).text)


def test_an_ips_field_that_is_not_a_list_says_so(job):
    job(result={"arp_anomalies": [
        {"mac": "aa", "ips": "lots", "severity": "high", "detail": "d"}]})
    html = _get(_reader()).text
    assert "an-absent" in _panel(html, "panel-arp")
    assert "lots" not in flat(html)


# ---------------------------------------------------------------------------
# Malware match and badge tone
# ---------------------------------------------------------------------------


def test_a_ja3_malware_match_is_marked_and_raises_the_tone(job):
    job(result={"ja3_fingerprints": [
        {"ja3_hash": "abc", "src_ip": "a", "dst_ip": "b", "dst_port": 443,
         "known_malware": "Cobalt Strike"}]})
    html = _get(_reader()).text
    assert "Cobalt Strike" in flat(html)
    assert "pcap-malware-hit" in html
    assert "tone-critical" in _tab(html, "tab-ja3")


def test_a_clean_ja3_set_takes_the_quieter_tone(job):
    job(result={"ja3_fingerprints": [
        {"ja3_hash": "abc", "src_ip": "a", "dst_ip": "b",
         "dst_port": 443}]})
    html = _get(_reader()).text
    assert "tone-primary" in _tab(html, "tab-ja3")
    assert "clean" in flat(_panel(html, "panel-ja3"))


def test_the_destination_endpoint_joins_host_and_port(job):
    job(result={"ja3_fingerprints": [
        {"ja3_hash": "abc", "src_ip": "a", "dst_ip": "10.0.0.9",
         "dst_port": 8443}]})
    assert "10.0.0.9:8443" in flat(_get(_reader()).text)


def test_an_endpoint_with_no_port_still_shows_the_host(job):
    job(result={"ja3_fingerprints": [
        {"ja3_hash": "abc", "src_ip": "a", "dst_ip": "10.0.0.9"}]})
    body = flat(_get(_reader()).text)
    assert "10.0.0.9" in body
    assert "10.0.0.9:" not in body


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key,field,panel", [
    ("extracted_files", "filename", "panel-files"),
    ("credential_captures", "username", "panel-creds"),
    ("smb_transfers", "detail", "panel-smb"),
])
def test_a_payload_value_cannot_inject_markup(job, key, field, panel):
    job(result={key: [{field: "<img src=x onerror=alert(1)>"}]})
    html = _get(_reader()).text
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


# ---------------------------------------------------------------------------
# The registry itself
# ---------------------------------------------------------------------------


def test_every_panel_in_the_registry_targets_a_container_on_the_page():
    """A panel whose container does not exist swaps into nothing and the
    tab opens an empty div."""
    page = PAGE.read_text(encoding="utf-8")
    for spec in TABLE_PANELS:
        assert 'id="' + spec["panel"] + '"' in page, spec["panel"]
        if spec.get("tab"):
            assert 'id="' + spec["tab"] + '"' in page, spec["tab"]
        if spec.get("badge"):
            assert 'id="' + spec["badge"] + '"' in page, spec["badge"]


def test_every_panel_declares_a_column_for_every_header():
    for spec in TABLE_PANELS:
        assert spec["columns"], spec["key"]
        for column in spec["columns"]:
            assert len(column) == 4, (spec["key"], column)
            assert column[0] and column[1], (spec["key"], column)


def test_a_tab_bearing_panel_declares_its_label_and_data_panel():
    """The tab button is replaced whole, so a missing label would blank
    it."""
    page = PAGE.read_text(encoding="utf-8")
    for spec in TABLE_PANELS:
        if not spec.get("tab"):
            continue
        assert spec.get("label"), spec["key"]
        assert spec.get("data_panel"), spec["key"]
        assert 'data-panel="' + spec["data_panel"] + '"' in page, spec["key"]


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_these_fourteen_panels():
    body = _scripts()
    for name in ("renderDns", "renderHttp", "renderTls",
                 "renderExtractedFiles", "renderJA3", "renderCredentials",
                 "renderJA3S", "renderHASSH", "renderSMB",
                 "renderKerberos", "renderHTTPFiles", "renderARP",
                 "renderBase64", "renderBeacons"):
        assert not re.search(r"function " + name + r"\b", body), name
