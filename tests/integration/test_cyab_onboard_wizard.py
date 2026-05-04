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
