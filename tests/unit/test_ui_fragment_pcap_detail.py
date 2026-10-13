"""The pcap analyser's seven bespoke panels.

These are the ones the registry could not take, because each has real
logic rather than a list of columns.

THE EXFILTRATION FLAG COULD NOT FIRE ON THE CLEAREST EXFILTRATION SHAPE

    const exfil = i.received > 0 && i.sent / i.received > 3 && i.sent > 100000;

The guard is there for the division, and it means a host that sent a
great deal and received **nothing** never trips the flag. All-outbound,
no inbound is the shape the heuristic exists to catch. The ratio column
already prints an infinity sign for that case, so the page can see it; the
flag just cannot say so. A host with no recorded `received` at all fails
the same test for the same reason.

A MISSING IKE STATUS TOOK THE PANEL DOWN

    const statusClass = s => s.toLowerCase().replace(/\\s+/g, '-');
    ...
    <span class="ike-status ${statusClass(s.status)}">

`undefined.toLowerCase()` throws, and it throws inside the map that builds
every row. The status also went straight into a class attribute, so a
status outside the four the stylesheet knows took a class that styles
nothing. The four summary counts compare exact strings, so a session
whose status is none of them is counted nowhere and the counts quietly
sum to less than the total.

AND THE USUAL

`i.sent + i.received` with either missing is NaN, and
`Math.max(...top.map(i => i.sent + i.received), 1)` is then NaN, so every
direction bar rendered `width:NaN%`. `${s.sport}`, `${s.dport}`,
`${s.initiator_packets}`, `${s.retransmits}` and `${s.duration}` printed
"undefined". `fmtBytes` on a missing size returned "NaN GB".

`m.attachments || []` means an unreadable attachment list renders as no
attachments, on the one column that highlights dangerous extensions.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.pcap import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/pcap.html"

URL = "/ui/pcap/7/detail"


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
    """One panel's markup, up to the start of the next one.

    The out-of-band attribute sits on the same element as the id, so
    searching forward for it finds this panel's own and truncates to
    nothing. The next panel's opening tag is the boundary.
    """
    start = html.index('id="' + panel_id + '"')
    opened = html.rfind("<div", 0, start)
    nxt = html.find('<div id="panel-', start + 10)
    return html[opened:nxt if nxt != -1 else len(html)]


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panels_need_the_pages_permission(job):
    job(result={})
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


# ---------------------------------------------------------------------------
# Data transfer and the exfiltration flag
# ---------------------------------------------------------------------------


def test_a_host_that_only_sent_is_flagged(job):
    """The defect this panel exists to fix. `i.received > 0` made the
    clearest exfiltration shape the one case that could not trip."""
    job(result={"data_transfer": {"total_bytes": 500000, "by_ip": [
        {"ip": "10.0.0.5", "sent": 400000, "received": 0}]}})
    panel = _panel(_get(_reader()).text, "panel-data")
    assert "dt-exfil" in panel
    assert "10.0.0.5" in flat(panel)


def test_a_host_with_no_recorded_inbound_is_not_silently_cleared(job):
    """Same test, same consequence: `undefined > 0` is false."""
    job(result={"data_transfer": {"by_ip": [
        {"ip": "10.0.0.6", "sent": 400000}]}})
    panel = _panel(_get(_reader()).text, "panel-data")
    assert "an-absent" in panel
    assert "0 B" not in flat(panel)


def test_the_original_ratio_threshold_still_flags(job):
    job(result={"data_transfer": {"by_ip": [
        {"ip": "a", "sent": 400000, "received": 1000}]}})
    assert "dt-exfil" in _panel(_get(_reader()).text, "panel-data")


def test_a_balanced_host_is_not_flagged(job):
    job(result={"data_transfer": {"by_ip": [
        {"ip": "a", "sent": 400000, "received": 400000}]}})
    assert "dt-exfil" not in _panel(_get(_reader()).text, "panel-data")


def test_a_small_outbound_host_is_not_flagged(job):
    """The 100 KB floor is the page's and stays."""
    job(result={"data_transfer": {"by_ip": [
        {"ip": "a", "sent": 4000, "received": 10}]}})
    assert "dt-exfil" not in _panel(_get(_reader()).text, "panel-data")


def test_one_unreadable_row_does_not_make_every_bar_nan(job):
    job(result={"data_transfer": {"by_ip": [
        {"ip": "good", "sent": 100, "received": 100},
        {"ip": "bad", "sent": "lots", "received": 5}]}})
    html = _get(_reader()).text
    assert "NaN" not in html
    assert "good" in flat(html)


def test_a_missing_total_is_not_reported_as_zero_bytes(job):
    job(result={"data_transfer": {"by_ip": [
        {"ip": "a", "sent": 1, "received": 1}]}})
    panel = _panel(_get(_reader()).text, "panel-data")
    assert "Total: 0 B" not in flat(panel)
    assert "an-absent" in panel


def test_no_data_transfer_says_so(job):
    job(result={"data_transfer": {"by_ip": []}})
    assert "No data transfer" in flat(_get(_reader()).text)


def test_a_by_ip_that_is_not_a_list_is_not_no_data(job):
    job(result={"data_transfer": {"by_ip": "broken"}})
    body = flat(_panel(_get(_reader()).text, "panel-data"))
    assert "not in a shape" in body


def test_at_most_twenty_data_rows(job):
    job(result={"data_transfer": {"by_ip": [
        {"ip": "10.0.0.%d" % i, "sent": 100 - i, "received": 1}
        for i in range(40)]}})
    assert _panel(_get(_reader()).text, "panel-data").count("dt-row") == 20


# ---------------------------------------------------------------------------
# ISAKMP
# ---------------------------------------------------------------------------


def test_a_session_with_no_status_does_not_take_the_panel_down(job):
    """`undefined.toLowerCase()` threw inside the row map."""
    job(result={"isakmp_sessions": [{"initiator": "10.0.0.1"}]})
    panel = _panel(_get(_reader()).text, "panel-isakmp")
    assert "10.0.0.1" in flat(panel)
    assert "an-absent" in panel


@pytest.mark.parametrize("status,css", [
    ("Established", "established"), ("Failed", "failed"),
    ("No Response", "no-response"), ("Incomplete", "incomplete"),
])
def test_a_known_status_keeps_its_class(job, status, css):
    job(result={"isakmp_sessions": [{"status": status}]})
    assert "ike-status " + css in _get(_reader()).text


def test_an_unknown_status_keeps_its_text_but_takes_no_class(job):
    """`ike-status ${statusClass(s.status)}` put a payload value into the
    class attribute, where only four values style anything."""
    job(result={"isakmp_sessions": [{"status": "Renegotiating"}]})
    html = _get(_reader()).text
    assert "Renegotiating" in flat(html)
    assert "ike-status renegotiating" not in html


def test_a_status_outside_the_four_is_still_counted(job):
    """The four counts compared exact strings, so a fifth status was
    counted nowhere and the summary summed to less than the total."""
    job(result={"isakmp_sessions": [
        {"status": "Established"}, {"status": "Renegotiating"}]})
    body = flat(_panel(_get(_reader()).text, "panel-isakmp"))
    assert "2 session(s)" in body
    assert "1 not categorised" in body or "Renegotiating 1" in body


def test_session_packet_counts_do_not_print_undefined(job):
    job(result={"isakmp_sessions": [{"status": "Failed"}]})
    html = _get(_reader()).text
    assert "undefined" not in html


def test_session_figures_render_when_present(job):
    job(result={"isakmp_sessions": [{
        "status": "Established", "initiator_packets": 4,
        "responder_packets": 3, "retransmits": 1, "duration": 12,
        "ike_version": "2", "exchanges": ["SA_INIT", "AUTH"]}]})
    body = flat(_panel(_get(_reader()).text, "panel-isakmp"))
    assert "4i / 3r" in body
    assert "SA_INIT, AUTH" in body
    assert "12s" in body


def test_session_errors_are_escaped_and_shown(job):
    job(result={"isakmp_sessions": [{
        "status": "Failed", "errors": ["<b>NO_PROPOSAL_CHOSEN</b>"]}]})
    html = _get(_reader()).text
    assert "<b>NO_PROPOSAL" not in html
    assert "NO_PROPOSAL_CHOSEN" in flat(html)


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


def test_a_self_signed_certificate_is_marked(job):
    job(result={"tls_certificates": [
        {"server_ip": "a", "subject": "s", "self_signed": True}]})
    body = flat(_panel(_get(_reader()).text, "panel-certs"))
    assert "yes" in body


def test_a_certificate_validity_is_rendered_in_years(job):
    job(result={"tls_certificates": [
        {"server_ip": "a", "validity_days": 730}]})
    assert "2y" in flat(_panel(_get(_reader()).text, "panel-certs"))


def test_a_certificate_with_no_validity_is_not_zero_years(job):
    job(result={"tls_certificates": [{"server_ip": "a"}]})
    panel = _panel(_get(_reader()).text, "panel-certs")
    assert "0y" not in flat(panel)
    assert "an-absent" in panel


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


def test_a_host_profile_renders_its_figures(job):
    job(result={"host_profiles": [{
        "ip": "10.0.0.1", "os": "Windows", "os_evidence": "ttl=128",
        "role": ["client", "dns"], "sent": 2048, "received": 1024,
        "snis": ["a.test", "b.test"], "beacons": 2, "findings": 1}]})
    body = flat(_panel(_get(_reader()).text, "panel-hosts"))
    assert "10.0.0.1" in body
    assert "ttl=128" in body
    assert "client, dns" in body
    assert "2.0 KB" in body


def test_a_host_with_no_beacon_count_is_not_reported_as_zero(job):
    """`h.beacons || 0` reported a host whose beacon count was never
    recorded as having none."""
    job(result={"host_profiles": [{"ip": "10.0.0.1"}]})
    panel = _panel(_get(_reader()).text, "panel-hosts")
    assert "an-absent" in panel


def test_a_recorded_zero_beacon_count_is_shown(job):
    job(result={"host_profiles": [{"ip": "a", "beacons": 0,
                                   "findings": 0}]})
    assert "0" in flat(_panel(_get(_reader()).text, "panel-hosts"))


def test_at_most_four_snis_per_host(job):
    job(result={"host_profiles": [{
        "ip": "a", "snis": ["s%d.test" % i for i in range(9)]}]})
    body = flat(_panel(_get(_reader()).text, "panel-hosts"))
    assert "s0.test" in body
    assert "s8.test" not in body


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------


def test_a_stream_renders_its_endpoints_and_preview(job):
    job(result={"tcp_streams": [{
        "src": "10.0.0.1", "sport": 1234, "dst": "10.0.0.2",
        "dport": 80, "size": 2048, "preview": "GET / HTTP/1.1"}]})
    body = flat(_panel(_get(_reader()).text, "panel-streams"))
    assert "10.0.0.1:1234" in body
    assert "10.0.0.2:80" in body
    assert "2.0 KB" in body
    assert "GET / HTTP/1.1" in body


def test_a_stream_with_no_ports_does_not_print_undefined(job):
    job(result={"tcp_streams": [{"src": "a", "dst": "b"}]})
    html = _get(_reader()).text
    assert "undefined" not in html
    assert "NaN" not in html


def test_a_truncated_stream_says_so(job):
    job(result={"tcp_streams": [{
        "src": "a", "sport": 1, "dst": "b", "dport": 2, "size": 10,
        "truncated": True}]})
    assert "truncated" in flat(_panel(_get(_reader()).text,
                                      "panel-streams"))


def test_a_stream_preview_is_escaped(job):
    job(result={"tcp_streams": [{
        "src": "a", "sport": 1, "dst": "b", "dport": 2,
        "preview": "<script>alert(1)</script>"}]})
    html = _get(_reader()).text
    assert "<script>alert(1)" not in html


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "invoice.exe", "report.docm", "payload.ps1", "thing.iso",
    "setup.msi", "a.lnk",
])
def test_a_dangerous_attachment_is_marked(job, name):
    job(result={"email_messages": [{"attachments": [name]}]})
    assert "attach-bad" in _get(_reader()).text


def test_a_harmless_attachment_is_not_marked(job):
    job(result={"email_messages": [{"attachments": ["notes.txt"]}]})
    html = _get(_reader()).text
    assert "notes.txt" in flat(html)
    assert "attach-bad" not in html


def test_an_unreadable_attachment_list_is_not_no_attachments(job):
    """`m.attachments || []` rendered an empty cell, on the one column
    that marks a dangerous extension."""
    job(result={"email_messages": [{"mail_from": "a@test",
                                    "attachments": "invoice.exe"}]})
    panel = _panel(_get(_reader()).text, "panel-email")
    assert "an-absent" in panel


def test_a_message_with_no_subject_says_so(job):
    job(result={"email_messages": [{"mail_from": "a@test"}]})
    panel = _panel(_get(_reader()).text, "panel-email")
    assert "an-absent" in panel


def test_an_attachment_name_is_escaped(job):
    job(result={"email_messages": [{
        "attachments": ["<img src=x onerror=alert(1)>.exe"]}]})
    html = _get(_reader()).text
    assert "<img src=x" not in html


def test_recipients_are_joined(job):
    job(result={"email_messages": [{
        "rcpt_to": ["a@test", "b@test"]}]})
    assert "a@test, b@test" in flat(_get(_reader()).text)


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


def test_an_unexpected_exception_is_reported(job):
    job(raises=RuntimeError("the store went away"))
    assert "could not" in flat(_get(_reader()).text).lower()


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_these_seven_panels():
    body = _scripts()
    for name in ("renderData", "renderIsakmp", "renderJA4", "renderCerts",
                 "renderHosts", "renderStreams", "renderEmail"):
        assert not re.search(r"function " + name + r"\b", body), name


def test_the_page_no_longer_carries_the_dangerous_extension_list():
    """It is a detection list. It belongs where it can be tested."""
    body = _scripts()
    assert "docm" not in body
    from ion.web.ui.pcap import DANGEROUS_ATTACHMENTS

    assert DANGEROUS_ATTACHMENTS.search("a.docm")
    assert not DANGEROUS_ATTACHMENTS.search("a.txt")
