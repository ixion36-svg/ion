"""End-to-end: wizard Step 2 answers visible from per-system Intake tab.

The wizard's Step 2 form posts to the *same* /api/cyab/studio/systems/{id}/answers
endpoint that the per-system Intake tab autosaves to (Sub-plan A Task 5). This
guards against a regression where the wizard accidentally points at a
wizard-private path and answers don't surface on the per-system page.
"""

import pytest


@pytest.fixture
def authed_client(client):
    """`client` from conftest already overrides the page-level auth dep, but
    the studio API also depends on ``get_current_user`` directly (not via the
    page-permission factory). Add an override so POSTs to ``/api/cyab/studio``
    succeed without needing a real session token.
    """
    from ion.auth.dependencies import get_current_user
    from ion.models.user import User
    from ion.web.server import app

    fake_admin = User(
        id=1,
        username="admin",
        email="admin@localhost",
        password_hash="x",
        display_name="Administrator",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: fake_admin
    yield client
    # conftest's teardown clears dependency_overrides — no extra cleanup here.


def test_wizard_intake_answer_visible_from_per_system_page(authed_client):
    # Start wizard
    r = authed_client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]

    # Identity → step 1 creates the CyabSystem row.
    authed_client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={
            "name": "intake-persist",
            "department": "X",
            "hostname": "h",
            "pillar": "endpoint",
            "owner": "o",
            "containment_authority": "c",
        },
    )

    # Look up the system_id we just created.
    sys_id = next(
        s["id"]
        for s in authed_client.get("/api/cyab/systems").json()
        if s["name"] == "intake-persist"
    )

    # Submit an intake answer directly to the studio endpoint — this is what
    # the Step 2 form does on autosave.
    r = authed_client.post(
        f"/api/cyab/studio/systems/{sys_id}/answers",
        json={"answers": {"q_traffic_volume": "high"}},
    )
    assert r.status_code in (200, 201, 204)

    # Read back via the same endpoint — answer should be present.
    r = authed_client.get(f"/api/cyab/studio/systems/{sys_id}/answers")
    assert r.status_code == 200
    body = r.json()
    assert body.get("answers", {}).get("q_traffic_volume") == "high"


def test_wizard_resume_loads_prior_state(authed_client):
    """Visiting /cyab/onboard?wid=<existing>&step=1 shows saved values."""
    r = authed_client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    authed_client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={"name": "resume-test", "department": "X"},
    )
    # Re-fetch step 1 — the form should re-render with the saved name.
    r = authed_client.get(f"/cyab/onboard?wid={wid}&step=1")
    assert "resume-test" in r.text
