"""Contracts for wiring defects first reproduced in Chromium."""

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.storage.database import get_db_session
from ion.web.ui import pcap

ROOT = Path(__file__).resolve().parents[2]


def client(permissions):
    app = FastAPI()
    app.include_router(pcap.router, prefix="/ui")
    user = SimpleNamespace(id=1, has_permission=lambda permission: permission in permissions)
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app)


@pytest.mark.parametrize("endpoint", ["tables", "detail"])
def test_oob_only_responses_do_not_overwrite_their_main_panel(endpoint):
    source = (ROOT / "src/ion/web/templates/pcap.html").read_text(encoding="utf-8")
    pattern = re.compile(r"'/" + re.escape(endpoint) + r"'\s*,\s*\{(.*?)\}\)", re.S)
    assert pattern.search("'/" + endpoint + "', {swap: 'none'})")
    assert not pattern.search("'/different', {swap: 'none'})")
    call = pattern.search(source)
    assert call is not None
    assert "swap: 'none'" in call.group(1)


def test_populated_detail_panels_have_reachable_replacement_tabs(monkeypatch):
    monkeypatch.setattr(
        "ion.web.pcap_api.get_pcap_job",
        lambda *args, **kwargs: {
            "result": {"host_profiles": [{"ip": "192.0.2.1"}], "ja4_fingerprints": [{"ja4": "known"}], "tcp_streams": [], "isakmp_sessions": [], "tls_certificates": [], "email_messages": []}
        },
    )
    response = client({"alert:read"}).get("/ui/pcap/7/detail")
    soup = BeautifulSoup(response.text, "html.parser")
    for panel in ["hosts", "ja4"]:
        tab = soup.select_one("#tab-" + panel)
        assert tab is not None
        assert tab["hx-swap-oob"] == "outerHTML:#tab-" + panel
        assert "hidden" not in tab.get("class", [])
    assert "hidden" in soup.select_one("#tab-streams").get("class", [])


def test_case_picker_does_not_query_cases_without_case_read(monkeypatch):
    async def forbidden(**kwargs):
        pytest.fail("case source queried without case:read")

    monkeypatch.setattr("ion.web.case_lifecycle_api.list_cases", forbidden)
    response = client({"alert:read"}).get("/ui/pcap/case-options")
    assert response.status_code == 200
    assert "withheld" in response.text.lower()


def test_case_picker_passes_a_concrete_offset_to_direct_api_call(monkeypatch):
    async def read(**kwargs):
        assert kwargs["offset"] == 0
        return {"cases": [{"id": 9, "title": "Case nine"}]}

    monkeypatch.setattr("ion.web.case_lifecycle_api.list_cases", read)
    response = client({"alert:read", "case:read"}).get("/ui/pcap/case-options")
    assert 'value="9"' in response.text


def test_chat_attachment_is_an_action_with_json_arguments():
    template = (ROOT / "src/ion/web/templates/_fragments/chat_files.html").read_text(encoding="utf-8")
    assert 'data-click-action="showFileModal"' in template
    assert "data-args='{{ [f.id]|tojson }}'" in template


@pytest.mark.parametrize("name", ["search", "mappings", "field_stats", "ioc_hunt", "ioc_bulk"])
def test_discover_table_rows_precede_non_table_oob_metadata(name):
    from ion.web.ui._shared import templates

    html = templates.get_template("_fragments/discover_" + name + ".html").render(
        state="failed",
        detail="Read failed",
        total=None,
        took_ms=None,
        fields=[],
        rows=[],
        hits=[],
        indices=[],
        found=None,
        searched=None,
        not_found=None,
        unique=None,
        docs=None,
        index=None,
        field=None,
    )
    # A leading span makes the native template parser discard later tr tags.
    # The browser regression checks both real rows and OOB metadata after swap.
    assert BeautifulSoup(html, "html.parser").find().name == "tr"


@pytest.mark.parametrize(
    "permissions,visible", [({"alert:read"}, False), ({"alert:read", "case:read"}, False), ({"alert:read", "case:update"}, False), ({"alert:read", "case:read", "case:update"}, True)]
)
def test_findings_attachment_controls_require_read_and_update(monkeypatch, permissions, visible):
    monkeypatch.setattr("ion.web.pcap_api.get_pcap_job", lambda *args, **kwargs: {"result": {"findings": [{"severity": "high", "title": "Known finding"}]}})
    soup = BeautifulSoup(client(permissions).get("/ui/pcap/7/findings").text, "html.parser")
    assert bool(soup.select_one("#pcap-attach-case")) is visible
    assert bool(soup.select_one(".pcap-finding-pick")) is visible
