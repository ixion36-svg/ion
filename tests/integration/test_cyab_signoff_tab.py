"""Integration tests for the Sign-off tab — governance + Onboarding Pack
PDF link + signoff history.

The plan literal references ``admin_session`` + ``system_id`` fixtures.
We use the project-wide ``client`` + ``make_system`` from conftest (the
client fixture already injects an admin user via dependency overrides,
so no login is needed). ``make_system`` accepts arbitrary CyabSystem
kwargs incl. ``containment_authority``.
"""


def test_signoff_tab_renders(client, make_system):
    sys_id = make_system(name="signoff-test", containment_authority="SOC Lead")
    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    assert r.status_code == 200
    body = r.text.lower()
    assert "sign-off" in body or "sign off" in body


def test_signoff_tab_includes_containment_authority(client, make_system):
    sys_id = make_system(name="signoff-ca", containment_authority="SOC Lead")
    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    assert "SOC Lead" in r.text


def test_signoff_tab_links_onboarding_pack_pdf(client, make_system):
    sys_id = make_system(name="signoff-pdf", containment_authority="SOC Lead")
    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    assert f"/api/cyab/systems/{sys_id}/onboarding-pack" in r.text


def test_signoff_tab_includes_governance_section(client, make_system):
    sys_id = make_system(name="signoff-gov", containment_authority="SOC Lead")
    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    body = r.text.lower()
    assert "governance" in body
    assert "containment" in body


def test_signoff_tab_has_sign_form(client, make_system):
    sys_id = make_system(name="signoff-form", containment_authority="SOC Lead")
    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    assert f"/api/cyab/systems/{sys_id}/onboarding-pack/sign" in r.text


def test_signoff_tab_empty_history(client, make_system):
    sys_id = make_system(name="signoff-empty", containment_authority="SOC Lead")
    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    body = r.text.lower()
    assert "no sign-offs yet" in body or "no signoffs yet" in body


def test_signoff_tab_shows_prior_signoffs(client, make_system, temp_db):
    """Prior sign-offs are read from CyabSystem.sign_dept_* / sign_soc_*
    fields (the actual sign-off persistence used by the
    POST /api/cyab/systems/{id}/onboarding-pack/sign endpoint).

    The plan note about CyabSnapshot rows tagged 'signoff' doesn't match
    the actual model — CyabSnapshot has no ``kind`` or ``signed_by``
    columns. The de-duped sign-off history therefore comes from the
    canonical sign-off fields on CyabSystem itself.
    """
    from datetime import date
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem

    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(
        name="signoff-prior",
        department="TestDept",
        containment_authority="SOC Lead",
        sign_dept_name="Alice Dept",
        sign_dept_date=date(2026, 1, 15),
        sign_soc_name="Bob SOC",
        sign_soc_date=date(2026, 1, 16),
    )
    s.add(sys)
    s.commit()
    sys_id = sys.id
    s.close()

    r = client.get(f"/cyab/systems/{sys_id}/tab/signoff")
    assert r.status_code == 200
    assert "Alice Dept" in r.text
    assert "Bob SOC" in r.text
