"""The pcap findings panel, threat intel, history and the case picker.

AN UNREADABLE FINDINGS PAYLOAD SHOWED A SHIELD AND "NO SUSPICIOUS FINDINGS"

    const items = (d.findings || []).map(...)
    if (!items.length) {
        panel.innerHTML = '... <i class="icon-shield-check"></i>
                           <p>No suspicious findings detected</p>';

On a tool whose job is to tell an analyst whether a capture is clean, a
findings list that could not be read rendered the clean verdict, with a
tick. That is the worst available way to be wrong, and it is one `|| []`.

THE SEVERITY CHIPS COULD SUM TO LESS THAN THE TOTAL

    items.forEach(f => { if (counts[f.severity] != null) counts[f.severity]++; });

with `counts` seeded for four severities and the total chip reading
`items.length`. A finding whose severity is outside those four is counted
in no chip, so the four chips and the total disagree and nothing says why.
The card's class came from the same value, so such a finding also rendered
with no severity colour.

THE THREAT INTEL LABEL CHIPS HAD INVALID BACKGROUNDS

    const color = threatColors[level] || '#8b949e';
    ... 'background:' + color + '20;color:' + color

The `20` is an alpha suffix for an eight-digit hex. Every colour in
`threatColors` is a `var(--sev-*)` reference, so the expression produces
`background:var(--sev-low)20`, which is not a colour and is discarded. It
worked only for the one case the map misses and the hex fallback catches.

A missing threat-intel payload and a failed enrichment were one message
that blamed configuration: "No threat intelligence data — OpenCTI may not
be configured."

And the case picker reported no open cases when the read failed:
`_pcapCases = r.ok ? ... : []`, with the same `[]` in its catch, so an
analyst with findings to attach was told there was nothing to attach them
to.
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

FINDINGS = "/ui/pcap/7/findings"
HISTORY = "/ui/pcap/history"
CASES = "/ui/pcap/case-options"


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
    return _User(PERMISSION, "case:read")


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


@pytest.fixture
def history(monkeypatch):
    def set(payload=None, raises=None):
        def handler(case_id=None, limit=50, _user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr("ion.web.pcap_api.list_pcap_jobs", handler)

    return set


@pytest.fixture
def cases(monkeypatch):
    def set(payload=None, raises=None):
        async def handler(**kwargs):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.case_lifecycle_api.list_cases", handler)

    return set


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_every_panel_needs_the_pages_permission(job, history, cases):
    job(result={})
    history(payload={"jobs": []})
    cases(payload={"cases": []})
    for url in (FINDINGS, HISTORY, CASES):
        assert _get(url, _User()).status_code == 403, url
        assert _get(url, _reader()).status_code == 200, url


# ---------------------------------------------------------------------------
# The false clean verdict
# ---------------------------------------------------------------------------


def test_an_unreadable_findings_list_is_not_a_clean_verdict(job):
    """The defect this panel exists to fix."""
    job(result={"findings": "three things"})
    body = flat(_get(FINDINGS, _reader()).text)
    assert "No suspicious findings detected" not in body
    assert "not in a shape" in body


def test_a_genuinely_empty_findings_list_is_still_the_clean_verdict(job):
    job(result={"findings": []})
    assert "No suspicious findings detected" in flat(
        _get(FINDINGS, _reader()).text)


def test_a_failed_read_is_not_a_clean_verdict(job):
    job(raises=RuntimeError("the store went away"))
    body = flat(_get(FINDINGS, _reader()).text)
    assert "No suspicious findings detected" not in body
    assert "could not" in body.lower()


# ---------------------------------------------------------------------------
# Findings cards and chips
# ---------------------------------------------------------------------------


def _finding(**over):
    f = {"severity": "high", "category": "beaconing",
         "title": "Periodic callout", "detail": "every 60s", "mitre": []}
    f.update(over)
    return f


def test_findings_sort_by_severity_with_unknown_last(job):
    job(result={"findings": [
        _finding(severity="weird", title="W"),
        _finding(severity="critical", title="C"),
        _finding(severity="low", title="L")]})
    html = _get(FINDINGS, _reader()).text
    assert html.index("C") < html.index("L") < html.index("W")


def test_a_severity_outside_the_four_takes_no_card_class(job):
    job(result={"findings": [_finding(severity="catastrophic")]})
    html = _get(FINDINGS, _reader()).text
    assert "catastrophic" in flat(html)
    assert "finding-card catastrophic" not in html


def test_a_finding_outside_the_four_is_still_accounted_for(job):
    """The four chips and the total disagreed with nothing to say why."""
    job(result={"findings": [
        _finding(severity="high"), _finding(severity="catastrophic")]})
    body = flat(_get(FINDINGS, _reader()).text)
    assert "1 not categorised" in body or "uncategorised" in body.lower()


def test_the_chips_carry_their_counts(job):
    job(result={"findings": [
        _finding(severity="critical"), _finding(severity="critical"),
        _finding(severity="low")]})
    html = _get(FINDINGS, _reader()).text
    assert 'data-sev="critical"' in html
    assert 'data-sev="total"' in html


def test_a_zero_chip_is_disabled_as_before(job):
    job(result={"findings": [_finding(severity="high")]})
    html = _get(FINDINGS, _reader()).text
    match = re.search(r'data-sev="critical"[^>]*', html)
    assert match, html[:400]
    assert "zero" in match.group(0) or "disabled" in html


def test_a_finding_keeps_its_index_in_the_stored_result(job):
    """The cards sort by severity, so the checkbox has to carry the
    stored index. Attaching by display position would pin the wrong
    finding, which is what the page's own comment warns about."""
    job(result={"findings": [
        _finding(severity="low", title="first"),
        _finding(severity="critical", title="second")]})
    html = _get(FINDINGS, _User(PERMISSION, "case:read", "case:update")).text
    first = html.index("second")
    chunk = html[max(0, first - 900):first]
    assert 'data-finding-index="1"' in chunk, chunk[-300:]


def test_a_finding_with_no_title_or_detail_says_so(job):
    job(result={"findings": [{"severity": "high"}]})
    html = _get(FINDINGS, _reader()).text
    assert "undefined" not in html
    assert "an-absent" in html


def test_a_finding_title_is_escaped(job):
    job(result={"findings": [
        _finding(title="<img src=x onerror=alert(1)>")]})
    html = _get(FINDINGS, _reader()).text
    assert "<img src=x" not in html


def test_mitre_techniques_roll_up(job):
    job(result={"findings": [_finding(mitre=["T1071"])],
                "mitre_techniques": [{"id": "T1071", "name": "App Layer"}]})
    body = flat(_get(FINDINGS, _reader()).text)
    assert "T1071" in body
    assert "App Layer" in body


def test_an_unreadable_technique_rollup_is_not_silence(job):
    job(result={"findings": [_finding()],
                "mitre_techniques": "T1071"})
    assert "an-absent" in _get(FINDINGS, _reader()).text


# ---------------------------------------------------------------------------
# Threat intel
# ---------------------------------------------------------------------------


def test_a_missing_payload_and_a_failed_enrichment_differ(job):
    job(result={"findings": []})
    absent = flat(_get(FINDINGS, _reader()).text)
    job(result={"findings": [],
                "threat_intel": {"error": "OpenCTI refused the query"}})
    failed = flat(_get(FINDINGS, _reader()).text)
    assert "OpenCTI refused the query" in failed
    assert "OpenCTI refused the query" not in absent


def test_the_label_chip_background_is_a_class_not_a_composed_colour(job):
    """`'background:' + color + '20'` with color = var(--sev-low) is
    `var(--sev-low)20`, which is not a colour."""
    job(result={"findings": [], "threat_intel": {
        "total": 1, "ips_checked": 1, "domains_checked": 0,
        "malicious_count": 1,
        "observables": [{"type": "ipv4", "value": "1.2.3.4",
                         "threat_level": "high",
                         "enrichment": {"score": 80, "is_malicious": True,
                                        "labels": ["apt"],
                                        "threat_actors": ["Actor"]}}]}})
    html = _get(FINDINGS, _reader()).text
    assert ")20" not in html
    assert "ti-level-high" in html
    assert "apt" in flat(html)


def test_the_chip_and_link_styling_survives_under_its_own_name(job):
    """These were _ion-s-7554583028 and _ion-s-b17605f04d, hashed names
    from the v0.31.21 inline-style migration.

    After this conversion no template referenced either and no other page
    used them: only a constant in ui/pcap.py did, which is a reference
    the rewrite audit cannot see and a reader cannot place. So both have
    real names in pcap-page.css carrying the same declarations, and
    tools/hashed_class_map.json claims them, which the audit checks.

    What this test is for is unchanged: the styling must not be dropped.
    """
    job(result={"findings": [], "threat_intel": {
        "total": 1, "ips_checked": 1, "domains_checked": 0,
        "malicious_count": 0,
        "observables": [{"type": "ipv4", "value": "1.2.3.4",
                         "threat_level": "low",
                         "enrichment": {"labels": ["x"]}}]}})
    html = _get(FINDINGS, _reader()).text
    assert "pcap-ti-chip" in html
    assert "pcap-ti-link" in html

    sheet = (ROOT / "src/ion/web/static/css/pcap-page.css").read_text(
        encoding="utf-8")
    # The declarations, not just the selectors: a renamed class with an
    # empty body is the same loss under a nicer name.
    assert ".pcap-ti-chip" in sheet
    assert "border-radius: 3px" in sheet
    assert ".pcap-ti-link" in sheet
    assert "underline dotted" in sheet


def test_the_claims_for_those_two_names_are_recorded(job):
    """The audit checks a replaced_by claim against the sheets, so an
    unbacked claim cannot silence a real loss. This checks the claim
    exists at all, which is the part the audit cannot tell me."""
    import json

    data = json.loads(
        (ROOT / "tools/hashed_class_map.json").read_text(encoding="utf-8"))
    assert data["_ion-s-b17605f04d"]["replaced_by"] == [".pcap-ti-link"]
    assert data["_ion-s-7554583028"]["replaced_by"] == [".pcap-ti-chip"]


def test_a_missing_checked_count_does_not_print_undefined(job):
    job(result={"findings": [], "threat_intel": {
        "observables": [{"type": "ipv4", "value": "1.2.3.4"}]}})
    html = _get(FINDINGS, _reader()).text
    assert "undefined" not in html


def test_no_observables_says_so(job):
    job(result={"findings": [],
                "threat_intel": {"observables": [], "total": 0}})
    assert "No external IPs or domains" in flat(
        _get(FINDINGS, _reader()).text)


def test_an_observable_value_is_linked_and_escaped(job):
    job(result={"findings": [], "threat_intel": {
        "observables": [{"type": "domain", "value": "bad<x>.test"}]}})
    html = _get(FINDINGS, _reader()).text
    assert "bad<x>" not in html
    assert "/observables?q=" in html


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def test_a_history_row_renders_its_fields(history):
    history(payload={"jobs": [{
        "id": 4, "status": "completed", "filename": "c.pcap",
        "content_sha256": "abcdef0123456789", "file_size": 2048,
        "verdict": {"label": "Elevated"}, "finding_count": 3,
        "parser_version": "1.2", "requested_by": "lyndon"}]})
    body = flat(_get(HISTORY, _reader()).text)
    assert "c.pcap" in body
    assert "abcdef012345" in body
    assert "2.0 KB" in body
    assert "Elevated" in body
    assert "3 findings" in body


def test_one_finding_is_singular(history):
    history(payload={"jobs": [{
        "id": 1, "status": "completed", "filename": "c.pcap",
        "finding_count": 1}]})
    assert "1 finding" in flat(_get(HISTORY, _reader()).text)


def test_a_history_row_with_no_finding_count_is_not_reported_as_clean(
        history):
    """`(j.finding_count || 0) + ' findings'` said a capture whose count
    was never recorded had none."""
    history(payload={"jobs": [{
        "id": 1, "status": "completed", "filename": "c.pcap"}]})
    html = _get(HISTORY, _reader()).text
    assert "0 findings" not in flat(html)
    assert "an-absent" in html


def test_a_history_row_with_no_size_is_not_zero_bytes(history):
    history(payload={"jobs": [{
        "id": 1, "status": "completed", "filename": "c.pcap",
        "finding_count": 0}]})
    assert "0 B" not in flat(_get(HISTORY, _reader()).text)


def test_only_a_completed_job_offers_reopen(history):
    history(payload={"jobs": [
        {"id": 1, "status": "completed", "filename": "a"},
        {"id": 2, "status": "failed", "filename": "b"}]})
    html = _get(HISTORY, _reader()).text
    assert html.count("pcap-reopen") == 1
    assert 'data-job-id="1"' in html


def test_no_history_says_so(history):
    history(payload={"jobs": []})
    assert "No captures analysed yet" in flat(_get(HISTORY, _reader()).text)


def test_a_failed_history_read_says_so(history):
    history(raises=RuntimeError("gone"))
    body = flat(_get(HISTORY, _reader()).text)
    assert "could not" in body.lower()
    assert "No captures analysed yet" not in body


# ---------------------------------------------------------------------------
# The case picker
# ---------------------------------------------------------------------------


def test_the_picker_lists_open_cases(cases):
    cases(payload={"cases": [
        {"id": 3, "case_number": "CASE-3", "title": "Phish"}]})
    html = _get(CASES, _reader()).text
    assert 'value="3"' in html
    assert "CASE-3 - Phish" in flat(html)


def test_a_case_with_no_title_falls_back_to_its_id(cases):
    cases(payload={"cases": [{"id": 9}]})
    assert "Case 9" in flat(_get(CASES, _reader()).text)


def test_no_open_cases_says_so(cases):
    cases(payload={"cases": []})
    assert "No open cases" in flat(_get(CASES, _reader()).text)


def test_a_failed_case_read_is_not_no_open_cases(cases):
    """An analyst with findings to attach was told there was nothing to
    attach them to."""
    cases(raises=RuntimeError("gone"))
    body = flat(_get(CASES, _reader()).text)
    assert "No open cases" not in body
    assert "could not" in body.lower()


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
    for name in ("renderFindings", "renderThreatIntel"):
        assert not re.search(r"function " + name + r"\b", body), name
    assert "No suspicious findings detected" not in body
    assert "threatColors" not in body


def test_the_page_has_no_runtime_dom_writes_left():
    """The measured column. pcap.html has no streaming excuse."""
    body = _scripts()
    assert not re.search(r"innerHTML\s*\+?=", body)
    assert "insertAdjacentHTML" not in body
    assert not re.search(r"outerHTML\s*\+?=", body)
