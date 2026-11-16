"""The condensed Threat Intel page: five tabs, a KPI Overview, a paged KEV.

What these pin, beyond what test_ui_fragment_threat_intel.py already does:

  * Every old panel id still reaches its view. Other pages and older links
    call tiSwitchTab('watchlist') or open ?tab=kev, so the eight ids are a
    contract even though the strip now has five tabs.
  * The KEV tab pages through the whole catalog with its filters, and a
    page turn keeps the filter. It used to render the newest 50 and stop.
  * The Overview's KEV figures come from real local sources and say "not
    measured" rather than zero when they have none: no vulnerability
    register, or a snapshot older than the window.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui._shared import templates as make_templates
from ion.web.ui.threat_intel import (
    KEV_LIMIT,
    PERMISSION,
    STORIES_PERMISSION,
    kev_page,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/threat_intel.html"
CSS = ROOT / "src/ion/web/static/css/threat-intel.css"
KEV = "_fragments/threat_intel_kev.html"
KEV_RECENT = "_fragments/threat_intel_kev_recent.html"


def flat(html: str) -> str:
    return " ".join(html.split())


def render(name: str, **ctx) -> str:
    return make_templates.env.get_template(name).render(**ctx)


class _User:
    id = 1
    username = "ti-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _client(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return app


def _seed_kev(session, n=120, start=date(2026, 1, 1), ransomware_every=10):
    from ion.models.kev import KevEntry

    session.query(KevEntry).delete()
    for i in range(n):
        session.add(KevEntry(
            cve_id=f"CVE-2026-{1000 + i}",
            vendor_project="Fortinet" if i % 3 == 0 else "Acme",
            product="FortiOS" if i % 3 == 0 else "Widget",
            vulnerability_name=f"Bug {i}",
            date_added=start + timedelta(days=i),
            due_date=start + timedelta(days=i + 21),
            known_ransomware=(i % ransomware_every == 0),
            known_ransomware_raw="Known" if i % ransomware_every == 0 else "Unknown",
            catalog_version="2026.05.01",
            source="bundled",
        ))
    session.commit()


# ---------------------------------------------------------------------------
# The tab strip
# ---------------------------------------------------------------------------

def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _script() -> str:
    page = _page()
    body = page[page.index('<script nonce="{{ csp_nonce }}">') + 32:]
    return body[:body.index("</script>")]


def test_the_strip_has_five_tabs():
    tabs = re.findall(r'class="ti-tab[^"]*"[^>]*data-tab="([a-z]+)"', _page())
    assert tabs == ["overview", "adversaries", "indicators", "reports", "kev"]


@pytest.mark.parametrize("old,group", [
    ("overview", "overview"), ("actors", "adversaries"),
    ("campaigns", "adversaries"), ("ioc", "indicators"),
    ("watchlist", "indicators"), ("reports", "reports"),
    ("stories", "reports"), ("kev", "kev"),
])
def test_every_old_panel_id_maps_to_its_tab_and_still_exists(old, group):
    """tiSwitchTab and ?tab= take the eight ids the old strip used."""
    page = _page()
    assert f"{old}: ['{group}', '{old}']" in _script()
    # The panel is inside its tab's group, so tiShow's containment check
    # accepts it.
    g = page.index(f'id="group-{group}"')
    nxt = page.find('class="ti-group', g + 10)
    block = page[g:nxt if nxt != -1 else len(page)]
    assert f'id="panel-{old}"' in block


def test_the_view_switches_go_through_delegation():
    """script-src-attr is 'none': no onclick, so data-click-action."""
    page = _page()
    for view in ("actors", "campaigns", "ioc", "watchlist", "reports", "stories"):
        assert (f'data-click-action="tiSwitchTab" data-args=\'["{view}"]\' '
                f'data-panel="{view}"') in page, view
    assert "onclick=" not in page
    assert not re.search(r'\sstyle="', page)


def test_the_unread_badge_rides_on_the_indicators_tab():
    page = _page()
    tab = page[page.index('data-tab="indicators"'):]
    tab = tab[:tab.index("</button>")]
    assert 'id="ti-unread-badge"' in tab


def test_the_view_classes_the_script_toggles_have_rules():
    css = CSS.read_text(encoding="utf-8")
    for rule in (".ti-group.active", ".ti-panel.active", ".ti-sub.active",
                 ".ti-tab.active"):
        assert rule in css, rule


def test_the_page_honours_tab_and_drill_arguments():
    """navigateToTechnique in base.html sends /threat-intel?drill=T…, which
    the page never read before."""
    script = _script()
    assert "params.get('tab')" in script
    assert "params.get('drill')" in script


def test_the_new_kev_regions_need_their_page_actions():
    script = _script()
    for name in ("tiKevReset", "tiKevFind", "tiSearchFor", "tiCloseBrief"):
        assert f"window.{name} = function" in script, name


# ---------------------------------------------------------------------------
# KEV paging
# ---------------------------------------------------------------------------

def test_kev_page_cuts_pages_of_fifty_newest_first(session):
    _seed_kev(session, 120)
    first = kev_page(session)
    assert first["total"] == 120 and first["pages"] == 3 and first["page"] == 1
    assert len(first["results"]) == KEV_LIMIT == 50
    assert first["results"][0]["cve_id"] == "CVE-2026-1119"
    third = kev_page(session, page=3)
    assert len(third["results"]) == 20
    assert third["results"][-1]["cve_id"] == "CVE-2026-1000"


def test_kev_page_past_the_end_lands_on_the_last_page(session):
    _seed_kev(session, 120)
    out = kev_page(session, page=40)
    assert out["page"] == 3 and len(out["results"]) == 20


def test_kev_page_filters_compose(session):
    _seed_kev(session, 120)
    out = kev_page(session, q="fortinet", ransomware_only=True,
                   added_from=date(2026, 1, 31), added_to=date(2026, 3, 31))
    ids = {r["cve_id"] for r in out["results"]}
    # i % 3 == 0 and i % 10 == 0 -> i % 30 == 0; day 30..89 -> i in {30, 60}
    assert ids == {"CVE-2026-1030", "CVE-2026-1060"}
    assert out["total"] == 2


def test_kev_page_matches_the_terms_the_api_matches(session):
    """The same five columns kev_service.search reads."""
    from ion.services import kev_service

    _seed_kev(session, 30)
    for term in ("CVE-2026-1003", "acme", "widget", "bug 7"):
        api = {e.cve_id for e in kev_service.search(session, q=term, limit=200)}
        tab = {r["cve_id"] for r in kev_page(session, q=term, per_page=200)["results"]}
        assert api == tab, term


def test_the_kev_route_pages_and_keeps_the_filter_on_the_pager(session):
    _seed_kev(session, 120)
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = flat(client.get("/ui/threat-intel/kev?page=2").text)
    assert "<b>51&ndash;100</b> of <b>120</b>" in body
    assert "page 2 of 3" in body
    assert 'hx-get="/ui/threat-intel/kev?page=3" hx-include="#kev-form"' in body
    assert "CVE-2026-1069" in body and "CVE-2026-1119" not in body


def test_an_empty_date_input_is_not_a_422(session):
    """An empty date input sends `added_from=`. A `date` parameter would
    refuse it and take the whole table away."""
    _seed_kev(session, 5)
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        r = client.get("/ui/threat-intel/kev?q=&added_from=&added_to=")
    assert r.status_code == 200
    assert "CVE-2026-1004" in r.text


def test_an_unreadable_date_is_dropped_and_said(session):
    _seed_kev(session, 5)
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = flat(client.get("/ui/threat-intel/kev?added_from=2026-13-45").text)
    assert "An unreadable from date was ignored" in body
    assert "CVE-2026-1004" in body


def test_the_page_number_is_bounded(session):
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/kev?page=0").status_code == 422


def test_a_single_page_shows_no_page_buttons():
    html = render(KEV, q="", ransomware_only=False, failed=False,
                  results=[{"cve_id": "CVE-1"}], status={"loaded": True},
                  total=1, page=1, pages=1, per_page=50)
    assert "ti-pbtn" not in html
    assert "of <b>1</b>" in flat(html)


def test_an_empty_filtered_result_names_the_dates():
    html = flat(render(KEV, q="", ransomware_only=False, failed=False,
                       results=[], status={"loaded": True, "catalog_version": "v1"},
                       added_from=date(2026, 1, 1), added_to=None,
                       total=0, page=1, pages=1, per_page=50))
    assert "No entries in catalog v1, added from 2026-01-01." in html


def test_a_tracked_cve_is_marked_and_an_unread_register_says_so(session):
    from ion.models.vulnerability import Vulnerability

    _seed_kev(session, 3)
    session.add(Vulnerability(cve_id="CVE-2026-1001", title="x", status="open"))
    session.commit()
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev").text
    row = body[body.index("CVE-2026-1001"):]
    row = row[:row.index("</tr>")]
    assert ">tracked<" in row

    unread = render(KEV, q="", ransomware_only=False, failed=False,
                    results=[{"cve_id": "CVE-2026-1001"}], status={"loaded": True},
                    total=1, page=1, pages=1, tracked=None)
    assert ">tracked<" not in unread
    assert "not the same as none being in your estate" in flat(unread)


def test_the_kev_form_sends_every_filter():
    page = _page()
    form = page[page.index('<form id="kev-form"'):]
    form = form[:form.index("</form>")]
    for name in ('name="q"', 'name="ransomware_only" value="false"',
                 'name="ransomware_only" value="true"', 'name="added_from"',
                 'name="added_to"'):
        assert name in form, name
    results = page[page.index('id="kev-results"'):]
    assert 'hx-include="#kev-form"' in results[:400]


# ---------------------------------------------------------------------------
# The Overview's KEV sources
# ---------------------------------------------------------------------------

def test_the_stats_route_counts_open_tracked_cves_in_kev(session):
    from ion.models.vulnerability import Vulnerability

    _seed_kev(session, 10)
    session.add_all([
        Vulnerability(cve_id="cve-2026-1002", title="a", status="open"),
        Vulnerability(cve_id="CVE-2026-1003", title="b", status="in_progress"),
        Vulnerability(cve_id="CVE-2026-1004", title="c", status="patched"),
        Vulnerability(cve_id="CVE-1999-0001", title="d", status="open"),
    ])
    session.commit()
    app = _client(session, _User(PERMISSION, STORIES_PERMISSION))
    with TestClient(app) as client:
        body = flat(client.get("/ui/threat-intel/overview-stats").text)
    tile = body[body.index("KEV in your estate"):]
    tile = tile[:400]
    assert re.search(r'ti-kpi-v is-warn">\s*2\s*<', tile), tile
    assert "of 4 tracked" in tile


def test_the_stats_route_dashes_the_estate_with_no_register(session):
    from ion.models.vulnerability import Vulnerability

    _seed_kev(session, 10)
    session.query(Vulnerability).delete()
    session.commit()
    app = _client(session, _User(PERMISSION, STORIES_PERMISSION))
    with TestClient(app) as client:
        body = flat(client.get("/ui/threat-intel/overview-stats").text)
    assert "no vulnerabilities tracked in ION" in body


def test_the_stats_route_reads_no_kev_without_alert_read(session, monkeypatch):
    import ion.web.ui.threat_intel as ui

    def boom(_session):
        raise AssertionError("KEV read for a viewer without alert:read")

    monkeypatch.setattr(ui, "_kev_overview", boom)
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        r = client.get("/ui/threat-intel/overview-stats")
    assert r.status_code == 200
    assert "needs alert:read" in r.text
    assert 'id="ti-kev-count"' not in r.text


def test_a_failed_kev_read_leaves_the_watch_tiles_standing(session, monkeypatch):
    import ion.web.ui.threat_intel as ui

    def boom(_session):
        raise RuntimeError("kev table gone")

    monkeypatch.setattr(ui, "_kev_overview", boom)
    app = _client(session, _User(PERMISSION, STORIES_PERMISSION))
    with TestClient(app) as client:
        body = flat(client.get("/ui/threat-intel/overview-stats").text)
    assert "the KEV read failed" in body
    assert "kev table gone" not in body
    assert "The threat intel overview could not be read" not in body


def test_kev_recent_needs_alert_read(session):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/kev-recent").status_code == 403


def test_kev_recent_lists_the_newest_and_marks_ransomware(session):
    _seed_kev(session, 20, ransomware_every=19)
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev-recent").text
    assert "CVE-2026-1019" in body and "CVE-2026-1013" not in body
    row = body[body.index("CVE-2026-1019"):]
    assert ">ransomware<" in row[:row.index("</tr>")]
    assert 'id="ti-kev-recent-n"' in body and 'hx-swap-oob="outerHTML"' in body


def test_kev_recent_failure_is_not_an_empty_catalog():
    html = render(KEV_RECENT, failed=True, rows=None, status=None,
                  snapshot=None, tracked=None, window_days=7)
    assert 'role="alert"' in html
    assert "not an empty catalog" in flat(html)
