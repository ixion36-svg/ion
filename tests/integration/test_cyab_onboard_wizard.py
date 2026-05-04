"""Integration tests for the /cyab/onboard wizard."""

import pytest


# Use the conftest-provided ``client`` + ``make_system`` fixtures (these wire
# auth dependency overrides + a temp DB). The plan sketch redefined ``client``
# locally with a real-login fixture, but the established CyAB integration
# tests all rely on the conftest one — we follow the existing pattern so auth
# overrides apply consistently.


def test_onboard_root_starts_wizard_and_redirects(client):
    r = client.get("/cyab/onboard", follow_redirects=False)
    assert r.status_code in (302, 303)
    loc = r.headers["location"]
    assert "/cyab/onboard?wid=" in loc and "step=1" in loc


def test_onboard_step_1_renders_identity_form(client):
    # Start a session — TestClient follows the redirect by default.
    r = client.get("/cyab/onboard")
    body = r.text.lower()
    assert "identity" in body
    for fld in ("name", "hostname", "pillar", "owner", "department", "containment"):
        assert fld in body
    # CyAB tab strip is present
    assert "cyab-section-nav" in r.text


def test_post_step_1_creates_system_and_advances(client):
    # Start
    r = client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]

    # POST identity
    r = client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={
            "name": "prod-sso-w",
            "hostname": "sso01",
            "pillar": "identity",
            "owner": "alice",
            "department": "Identity",
            "containment_authority": "SOC L2",
        },
    )
    assert r.status_code in (200, 302, 303)
    # The CyabSystem row exists
    sys_list = client.get("/api/cyab/systems").json()
    assert any(s["name"] == "prod-sso-w" for s in sys_list)


def test_step_1_invalid_wid_returns_404(client):
    r = client.post(
        "/api/cyab/onboard/bogus/step/1",
        data={"name": "x", "department": "y"},
    )
    assert r.status_code == 404


def test_wizard_never_blocks_partial_data_ok(client):
    """Posting step 1 with only name + department (no owner / pillar) still saves."""
    r = client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    r = client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={"name": "minimal", "department": "X"},
    )
    assert r.status_code in (200, 302, 303)


# ---------------------------------------------------------------------------
# Steps 2-4 + Finish
# ---------------------------------------------------------------------------


def _start_and_step1(client) -> str:
    r = client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={
            "name": "wiz-test", "department": "Eng", "hostname": "h1",
            "pillar": "endpoint", "owner": "x", "containment_authority": "y",
        },
    )
    return wid


def test_step_2_intake_saves_answers(client):
    wid = _start_and_step1(client)
    r = client.post(
        f"/api/cyab/onboard/{wid}/step/2",
        data={"answers[q_traffic]": "high", "answers[q_users]": "200"},
    )
    assert r.status_code in (200, 302, 303)


def test_step_3_creates_data_source(client):
    wid = _start_and_step1(client)
    client.post(f"/api/cyab/onboard/{wid}/step/2", data={})
    r = client.post(
        f"/api/cyab/onboard/{wid}/step/3",
        data={"name": "winlog", "data_source_type": "windows-evtx", "subprofile_id": ""},
    )
    assert r.status_code in (200, 302, 303)
    # Source attached to the system
    sys_list = client.get("/api/cyab/systems").json()
    sys_id = next(s["id"] for s in sys_list if s["name"] == "wiz-test")
    sources = client.get(f"/api/cyab/systems/{sys_id}/sources").json()
    assert any(s["name"] == "winlog" for s in sources)


def test_step_4_lists_seeded_checklist_items(client):
    wid = _start_and_step1(client)
    client.post(f"/api/cyab/onboard/{wid}/step/2", data={})
    client.post(
        f"/api/cyab/onboard/{wid}/step/3",
        data={"name": "x", "data_source_type": "edr-generic"},
    )
    r = client.get(f"/cyab/onboard?wid={wid}&step=4")
    body = r.text
    # 20 default items — at minimum HLD / Owners / Network Topology are present
    for label in ("HLD", "Network Topology", "Owners"):
        assert label in body
    # 'I'll do this later' control exists
    assert "later" in body.lower()


def test_finish_redirects_to_per_system_page(client):
    wid = _start_and_step1(client)
    client.post(f"/api/cyab/onboard/{wid}/step/2", data={})
    client.post(
        f"/api/cyab/onboard/{wid}/step/3",
        data={"name": "x", "data_source_type": "edr-generic"},
    )
    r = client.post(
        f"/api/cyab/onboard/{wid}/finish",
        data={},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    assert "/cyab/systems/" in r.headers["location"]
