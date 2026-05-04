"""End-to-end smoke: wizard Finish lands user on per-system page;
new system appears on /cyab Overview and /cyab/systems portfolio list.

Catches any cross-page wiring breaks before release.
"""

# Uses the conftest-provided ``client`` fixture, which wires the temp DB and
# overrides page-level auth dependencies with a fake admin user. The plan
# sketch defined a separate ``admin_session`` fixture that posted to
# /api/auth/login, but the established CyAB integration tests all rely on the
# conftest pattern — we follow that for consistency with the rest of the
# suite.


def test_full_wizard_to_landing_smoke(client):
    # 1. Start wizard
    r = client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]

    # 2. Identity
    client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={
            "name": "smoke-finished",
            "department": "Smoke",
            "hostname": "smk01",
            "pillar": "endpoint",
            "owner": "smoker",
            "containment_authority": "SOC L1",
        },
    )

    # 3. Intake (skip — wizard never blocks)
    client.post(f"/api/cyab/onboard/{wid}/step/2", data={})

    # 4. Source
    client.post(
        f"/api/cyab/onboard/{wid}/step/3",
        data={"name": "smk-source", "data_source_type": "edr-generic"},
    )

    # 5. Finish
    r = client.post(
        f"/api/cyab/onboard/{wid}/finish",
        data={},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    target = r.headers["location"]
    assert target.startswith("/cyab/systems/")
    sys_id = int(target.rsplit("/", 1)[-1])
    assert sys_id > 0

    # 6. Per-system page renders the new system (Sub-plan A page)
    r = client.get(target)
    assert r.status_code == 200
    assert "smoke-finished" in r.text

    # 7. Overview "in progress" feed includes the new name
    r = client.get("/cyab")
    assert r.status_code == 200
    assert "smoke-finished" in r.text

    # 8. Portfolio list table includes the new name
    r = client.get("/cyab/systems/_table")
    assert r.status_code == 200
    assert "smoke-finished" in r.text


def test_overview_kpi_strip_reflects_new_system_count(client):
    before = client.get("/api/cyab/dashboard").json()["total_systems"]

    r = client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    client.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={"name": "kpi-bump", "department": "X"},
    )

    after = client.get("/api/cyab/dashboard").json()["total_systems"]
    assert after == before + 1
