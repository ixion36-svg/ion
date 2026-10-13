"""The cases page's stat tiles and Management Analytics panel as a fragment.

Every test that asserts on a figure goes through TestClient and the route,
with the service monkeypatched where the real one cannot fail on demand. The
template is not rendered with a hand-built context anywhere in this file.
Across eight mutation rounds on this project every first-pass survivor was
a template tested with a hand-built context while the module function that
computed the context went undriven, so this file is written the other way
round from the start.

Measured on the page before the change, by reading cases.html:

  * renderAnalyticsPanel returned early when teamMetricsCache was null, which
    is what loadTeamMetrics set it to on a failed read. A failed read left
    every analytics card as the empty div the shell ships with.
  * renderSummaryStrip wrote `strip.replaceChildren() + '<div ...'`, a
    discarded string. The four chips it describes have never rendered.
  * Every count was derived from the loaded array, capped at 2,000 rows.
  * ageLabel parsed `isoformat()` of a naive UTC column with `new Date`,
    which reads a zoneless string in the viewer's zone.
  * getCaseAgeColor(NaN) fell through to `sla-red`, so a case with no
    created_at was painted as the oldest band.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.web.ui.cases import (
    CLOSURES_SHOWN,
    METRICS_PERMISSION,
    OLDEST_SHOWN,
    PERMISSION,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"
FRAGMENT = ROOT / "src/ion/web/templates/_fragments/cases_summary.html"

URL = "/ui/cases/summary"


@pytest.fixture(scope="module")
def _engine(tmp_path_factory):
    """One schema build for the file.

    conftest's `temp_db` runs create_all over ION's whole schema per test,
    measured at 5 seconds of setup for each of these tests, which makes a
    thirty-mutation pass an afternoon. These tests write one table, so the
    per-test `session` below empties that table instead.
    """
    from sqlalchemy import create_engine

    from ion.models.document import Base

    db_path = tmp_path_factory.mktemp("cases-fragment") / "cases.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(_engine):
    from sqlalchemy.orm import sessionmaker

    db = sessionmaker(bind=_engine)()
    try:
        yield db
    finally:
        db.rollback()
        db.query(AlertCase).delete()
        db.commit()
        db.close()


def flat(html: str) -> str:
    """Rendered HTML as its visible text: tags removed, entities decoded,
    whitespace collapsed, so a sentence that wraps in the template is one
    string here and an en dash is an en dash rather than `&ndash;`."""
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


class _User:
    id = 1
    username = "cases-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: session
    return application


def _get(session, *permissions):
    with TestClient(_app(session, _User(*permissions))) as client:
        return client.get(URL)


def _both(session):
    return _get(session, PERMISSION, METRICS_PERMISSION)


NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def _case(session, number, status=AlertCaseStatus.OPEN, severity="medium",
          age=timedelta(hours=1), assigned=None, closed_ago=None,
          reason=None, created_at="set", title=None):
    """One case row. `created_at="set"` means age ago; None means NULL."""
    row = AlertCase(
        case_number=number,
        title=title or f"title {number}",
        status=status,
        severity=severity,
        created_by_id=1,
        assigned_to_id=assigned,
        closure_reason=reason,
        closed_at=None if closed_ago is None else NOW - closed_ago,
    )
    if created_at == "set":
        row.created_at = NOW - age
    else:
        row.created_at = created_at
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_the_fragment_refuses_a_caller_without_case_read(session):
    assert _get(session).status_code == 403
    assert _get(session, METRICS_PERMISSION).status_code == 403


def test_case_read_alone_opens_the_fragment(session):
    assert _get(session, PERMISSION).status_code == 200


def test_the_gate_is_the_one_the_json_endpoints_carry():
    """GET /api/cases and /api/cases/facets name case:read; team-metrics
    names alert:read. Spelled once in the module; pinned here so a later edit
    cannot soften the fragment below the endpoints it mirrors."""
    assert PERMISSION == "case:read"
    assert METRICS_PERMISSION == "alert:read"


# ---------------------------------------------------------------------------
# The eight tiles: zero, none, failed, and withheld are four renders
# ---------------------------------------------------------------------------


def test_an_empty_estate_counts_zero_and_does_not_say_the_read_failed(session):
    text = flat(_both(session).text)
    assert "Open Cases 0 Acknowledged 0 Critical Active 0" in text
    assert "Unassigned 0" in text
    assert "read failed" not in text


def test_the_tiles_count_the_table_not_a_loaded_page(session):
    _case(session, "T-1", severity="critical")
    _case(session, "T-2", status=AlertCaseStatus.ACKNOWLEDGED, assigned=1)
    _case(session, "T-3", status=AlertCaseStatus.ACKNOWLEDGED, severity="critical")
    _case(session, "T-4", status=AlertCaseStatus.CLOSED, severity="critical",
          closed_ago=timedelta(hours=1))
    session.commit()
    text = flat(_both(session).text)
    assert "Open Cases 1" in text
    assert "Acknowledged 2" in text
    # Critical active: T-1 and T-3, not the closed T-4.
    assert "Critical Active 2" in text
    # Unassigned active: T-1 and T-3; T-2 is assigned, T-4 is closed.
    assert re.search(r"Unassigned 2 Critical/High", text)


def test_a_failed_facets_read_marks_open_and_acknowledged_not_zero(session, monkeypatch):
    """The JavaScript's catch set allCases = [] and carried on, so a failed
    list read rendered 0 in every tile."""
    import ion.services.case_query_service as cq

    def boom(_session):
        raise RuntimeError("facets down")

    monkeypatch.setattr(cq, "case_facets", boom)
    _case(session, "F-1")
    session.commit()
    text = flat(_both(session).text)
    assert "Open Cases – read failed, not counted" in text
    assert "Acknowledged – read failed, not counted" in text
    assert "Open Cases 0" not in text
    # The other sources still render: the active rows are a separate read.
    assert "Critical Active 0" in text
    assert "Status counts could not be read" in text


def test_a_failed_active_read_marks_its_tiles_and_cards_only(session, monkeypatch):
    import ion.web.ui.cases as mod

    def boom(_session):
        raise RuntimeError("active down")

    monkeypatch.setattr(mod, "active_cases", boom)
    _case(session, "A-1")
    session.commit()
    text = flat(_both(session).text)
    assert "Critical Active – read failed, not counted" in text
    assert "Unassigned – read failed, not counted" in text
    assert "Active cases could not be read" in text
    assert "No active cases" not in text
    # Facets are a separate read and still count.
    assert "Open Cases 1" in text


def test_a_failed_closure_read_is_not_an_estate_with_no_closed_cases(session, monkeypatch):
    import ion.services.case_metrics as cm

    def boom(_session, since, until=None):
        raise RuntimeError("metrics down")

    monkeypatch.setattr(cm, "case_metrics", boom)
    text = flat(_both(session).text)
    assert "Avg Resolution – read failed, not measured" in text
    assert "Closure reasons could not be read" in text
    assert "No closed cases" not in text
    assert "no case has closed yet" not in text
    # Closed today sits on the same read and must not print 0.
    assert re.search(r"Closed Today \(UTC\) –", text)


def test_no_closed_case_is_worded_as_that_not_as_a_dash(session):
    text = flat(_both(session).text)
    assert "Avg Resolution – no case has closed yet" in text


def test_average_resolution_is_all_closed_cases_in_hours_then_days(session):
    _case(session, "R-1", status=AlertCaseStatus.CLOSED, age=timedelta(hours=6),
          closed_ago=timedelta(hours=2))
    session.commit()
    assert "Avg Resolution 4h" in flat(_both(session).text)

    _case(session, "R-2", status=AlertCaseStatus.CLOSED, age=timedelta(days=10),
          closed_ago=timedelta(hours=0))
    session.commit()
    # (4h + 240h) / 2 = 122h, which is 5.08 days.
    assert "Avg Resolution 5d" in flat(_both(session).text)


def test_the_team_metrics_tiles_are_withheld_without_alert_read(session):
    """Every built-in role with case:read also has alert:read, measured in
    ion/auth/service.py, but a custom role need not, and the fragment must
    not be a softer way into /api/dashboard/team-metrics than that endpoint
    is. Withheld is a fourth render, distinct from failed and from None."""
    _case(session, "W-1", status=AlertCaseStatus.CLOSED, age=timedelta(hours=2),
          closed_ago=timedelta(hours=1))
    session.commit()
    text = flat(_get(session, PERMISSION).text)
    assert "MTTR · 30d – needs alert:read, not shown" in text
    assert "Closure rate · 7d – needs alert:read, not shown" in text
    assert "Created / Closed · 7d – needs alert:read, not shown" in text
    assert text.count("This account cannot read team metrics") == 3
    assert "read failed" not in text
    # The case:read figures are not hidden behind the stricter permission.
    assert "Avg Resolution 1h" in text
    assert "Closure Reasons 1 closed" in text


def test_a_failed_team_metrics_read_is_not_withheld_and_not_zero(session, monkeypatch):
    import ion.web.api as api

    def boom(_session):
        raise RuntimeError("team metrics down")

    monkeypatch.setattr(api, "team_metrics_payload", boom)
    text = flat(_both(session).text)
    assert "MTTR · 30d – read failed, not measured" in text
    assert "Created / Closed · 7d – read failed, not measured" in text
    assert "needs alert:read" not in text
    assert "Severity counts could not be read" in text
    assert "Workload could not be read" in text
    assert "Recent closures could not be read" in text
    assert "0 / 0" not in text


def test_team_metrics_none_figures_are_worded_not_zeroed(session):
    """mttr_hours is None when nothing closed in 30 days and closure_rate_7d
    is None when nothing opened in 7, per team_metrics_payload. Neither is a
    zero and the JavaScript printed "-" for both, the loading glyph."""
    text = flat(_both(session).text)
    assert "MTTR · 30d – no closures in 30d" in text
    assert "Closure rate · 7d – nothing opened in 7d, nothing to divide by" in text
    assert "Created / Closed · 7d 0 / 0" in text


def test_team_metrics_figures_render_with_their_units(session):
    _case(session, "M-1", status=AlertCaseStatus.CLOSED, age=timedelta(hours=3),
          closed_ago=timedelta(hours=1))
    _case(session, "M-2")
    session.commit()
    text = flat(_both(session).text)
    # One closure two hours after creation: mttr 2.0h, shown as 2h.
    assert "MTTR · 30d 2h" in text
    # Two created, one closed in the window.
    assert "Closure rate · 7d 50%" in text
    assert "Created / Closed · 7d 2 / 1" in text


# ---------------------------------------------------------------------------
# The summary strip, which never rendered before
# ---------------------------------------------------------------------------


def test_the_summary_strip_renders_its_four_chips(session):
    _case(session, "S-1", severity="high", age=timedelta(days=5))
    _case(session, "S-2", severity="critical", age=timedelta(days=1), assigned=1)
    _case(session, "S-3", severity="low")
    _case(session, "S-4", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(minutes=5))
    _case(session, "S-5", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(days=3))
    session.commit()
    text = flat(_both(session).text)
    assert "Critical/High Active 2" in text
    assert "Unassigned 2 Oldest Active 5d" in text
    assert "Closed Today (UTC) 1" in text


def test_the_oldest_active_chip_says_none_with_no_active_cases(session):
    """The reduce started at 0 and printed "0d" for an empty estate."""
    text = flat(_both(session).text)
    assert "Oldest Active none" in text
    assert "Oldest Active 0d" not in text


def test_the_oldest_chip_dot_follows_the_three_day_and_seven_day_bands(session):
    _case(session, "O-1", age=timedelta(days=8))
    session.commit()
    html = _both(session).text
    assert re.search(r'summary-chip-dot sla-red"></span>\s*<span class="summary-chip-label">Oldest', html)

    session.query(AlertCase).delete()
    # Seven days and a bit floors to 7, and the page's `> 7` is strict: a
    # week-old case is the warning band, not the danger one.
    _case(session, "O-2", age=timedelta(days=7, hours=2))
    session.commit()
    html = _both(session).text
    assert re.search(r'summary-chip-dot sla-yellow"></span>\s*<span class="summary-chip-label">Oldest', html)

    session.query(AlertCase).delete()
    _case(session, "O-3", age=timedelta(days=3, hours=2))
    session.commit()
    html = _both(session).text
    assert re.search(r'summary-chip-dot sla-green"></span>\s*<span class="summary-chip-label">Oldest', html)


def test_a_resolution_of_exactly_a_day_is_a_day_not_24h(session):
    """renderStats tested `avgHrs < 24`, so 24 rolled over to days."""
    _case(session, "X-1", status=AlertCaseStatus.CLOSED, age=timedelta(hours=25),
          closed_ago=timedelta(hours=1))
    session.commit()
    assert "Avg Resolution 1d" in flat(_both(session).text)


def test_an_age_of_exactly_a_day_is_the_second_band(session):
    """getCaseAgeColor tested `hours < 24`, so a case exactly a day old is
    1-3d. The bands are half-open on the same side here."""
    _case(session, "Y-1", age=timedelta(hours=24, seconds=1))
    session.commit()
    text = flat(_both(session).text)
    assert "<24h: 0 1-3d: 1 3-7d: 0 >7d: 0" in text


# ---------------------------------------------------------------------------
# Donuts
# ---------------------------------------------------------------------------


def test_the_status_donut_counts_every_status_from_the_facets(session):
    _case(session, "D-1")
    _case(session, "D-2", status=AlertCaseStatus.ACKNOWLEDGED)
    _case(session, "D-3", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(hours=1))
    _case(session, "D-4", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(hours=1))
    session.commit()
    text = flat(_both(session).text)
    assert "Status Breakdown 4 total Open 1 25% Acknowledged 1 25% Closed 2 50%" in text


def test_the_severity_donut_is_active_cases_only(session):
    _case(session, "V-1", severity="critical")
    _case(session, "V-2", severity="critical", status=AlertCaseStatus.CLOSED,
          closed_ago=timedelta(hours=1))
    _case(session, "V-3", severity="low")
    session.commit()
    text = flat(_both(session).text)
    assert "Severity Distribution 2 cases Critical 1 50% Low 1 50%" in text


def test_a_closure_with_no_reason_is_a_segment_not_a_dropped_row(session):
    """`if (c.closure_reason)` skipped it, so a case closed without saying
    why was missing from the donut and from its total."""
    _case(session, "C-1", status=AlertCaseStatus.CLOSED, reason="false_positive",
          closed_ago=timedelta(hours=1))
    _case(session, "C-2", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(hours=1))
    session.commit()
    text = flat(_both(session).text)
    assert "Closure Reasons 2 closed" in text
    assert "No reason recorded 1 50%" in text
    assert "False Positive 1 50%" in text


def test_a_donut_draws_one_arc_per_non_zero_segment(session):
    _case(session, "G-1")
    _case(session, "G-2", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(hours=1))
    session.commit()
    html = _both(session).text
    status_svg = html.split("Status Breakdown", 1)[1].split("</svg>", 1)[0]
    arcs = re.findall(r'class="donut-arc"', status_svg)
    assert len(arcs) == 2, "open and closed drawn, acknowledged (zero) skipped"
    # Two equal halves of the circumference 2*pi*45 = 282.74.
    assert 'stroke-dasharray="141.37 141.37"' in status_svg
    assert 'stroke-dashoffset="-141.37"' in status_svg
    assert 'stroke="#3b82f6"' in status_svg
    assert 'stroke="#6b7280"' in status_svg


def test_a_legend_dot_colour_travels_as_data_ion_style_not_an_inline_style(session):
    """style-src-attr 'none' blocks a style attribute; the page used
    data-ion-style for exactly this and ion-dynamic-styles.js applies it."""
    _case(session, "L-1")
    session.commit()
    html = _both(session).text
    assert 'data-ion-style="background:#3b82f6"' in html
    assert ' style="' not in html


# ---------------------------------------------------------------------------
# Workload
# ---------------------------------------------------------------------------


def test_workload_bars_are_shares_of_the_busiest_assignee(session, monkeypatch):
    import ion.web.api as api

    def payload(_session):
        return {
            "mttr_hours": None, "closure_rate_7d": None,
            "created_7d": 0, "closed_7d": 0,
            "cases_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "cases_by_assignee": [
                {"username": "a", "display_name": "Ann", "open_count": 4, "closed_7d": 0},
                {"username": "b", "display_name": "Bob", "open_count": 1, "closed_7d": 0},
            ],
            "recent_closures": [],
        }

    monkeypatch.setattr(api, "team_metrics_payload", payload)
    html = _both(session).text
    assert 'title="Ann"' in html
    assert 'data-ion-style="width:100.0%;background:#3b82f6"' in html
    assert 'data-ion-style="width:25.0%;background:#8b5cf6"' in html
    assert "hbar-value\">4<" in html.replace(" ", "").replace('hbar-value">', 'hbar-value">')


def test_no_assignee_rows_is_worded_as_nothing_open(session):
    text = flat(_both(session).text)
    assert "Analyst Workload No open cases to share out." in text


# ---------------------------------------------------------------------------
# Open case ages
# ---------------------------------------------------------------------------


def test_age_buckets_count_every_active_case_and_list_the_oldest(session):
    for i in range(OLDEST_SHOWN + 2):
        _case(session, f"AG-{i}", age=timedelta(days=10 + i))
    _case(session, "AG-fresh", age=timedelta(hours=3))
    _case(session, "AG-mid", age=timedelta(hours=50))
    _case(session, "AG-week", age=timedelta(hours=100))
    _case(session, "AG-closed", status=AlertCaseStatus.CLOSED, age=timedelta(days=30),
          closed_ago=timedelta(hours=1))
    session.commit()
    html = _both(session).text
    text = flat(html)
    assert "<24h: 1 1-3d: 1 3-7d: 1 >7d: 10" in text
    assert f"Oldest {OLDEST_SHOWN} of 13 active." in text
    # The oldest first: AG-9 (19 days) leads and AG-fresh is not among the eight.
    rows = re.findall(r'class="sla-case-num">([^<]+)<', html)
    assert rows[0] == "AG-9"
    assert len(rows) == OLDEST_SHOWN
    assert "AG-fresh" not in rows
    # Closed, so not an open-case age; it belongs in Recent Closures instead.
    assert "AG-closed" not in rows
    age_card = html.split("Open Case Age", 1)[1].split("Recent Closures", 1)[0]
    assert "AG-closed" not in age_card


def test_a_case_with_no_creation_time_is_age_unknown_not_oldest(session, monkeypatch):
    """getCaseAgeColor(NaN) fell through every `<` to sla-red.

    The row comes from a stubbed `active_cases` rather than the table,
    because TimestampMixin fills created_at on insert, so the ORM cannot
    write the NULL this branch exists for; a migration or a raw import can.
    """
    import ion.web.ui.cases as mod

    rows = [
        {"id": 1, "case_number": "N-1", "title": "no clock", "severity": "high",
         "status": "open", "assigned_to_id": None, "created_at": None},
        {"id": 2, "case_number": "N-2", "title": "fresh", "severity": "low",
         "status": "open", "assigned_to_id": None,
         "created_at": NOW - timedelta(hours=1)},
    ]
    monkeypatch.setattr(mod, "active_cases", lambda _session: rows)
    html = _both(session).text
    text = flat(html)
    assert "age unknown: 1" in text
    assert ">7d: 0" in text
    rows = re.findall(r'class="sla-case-num">([^<]+)<', html)
    assert rows == ["N-2"]


def test_each_oldest_row_opens_its_case_through_the_delegated_action(session):
    row = _case(session, "K-1")
    session.commit()
    html = _both(session).text
    assert f'data-click-action="openCaseDetail" data-args="[{row.id}]"' in html


def test_age_bar_segments_carry_their_weight_as_data_ion_style(session):
    _case(session, "B-1", age=timedelta(hours=1))
    _case(session, "B-2", age=timedelta(hours=2))
    _case(session, "B-3", age=timedelta(days=9))
    session.commit()
    html = _both(session).text
    assert 'class="age-bar-seg sla-green" data-ion-style="flex:2"' in html
    assert 'class="age-bar-seg sla-red" data-ion-style="flex:1"' in html
    assert "age-bar-seg sla-yellow" not in html, "a zero bucket draws no segment"


def test_an_age_is_read_as_utc_not_as_the_viewer_clock(session):
    """ageLabel used `new Date(iso)` on a zoneless string, which JavaScript
    parses as local time. Two hours is two hours whoever is looking."""
    _case(session, "Z-1", age=timedelta(hours=2, minutes=5))
    session.commit()
    html = _both(session).text
    assert re.search(r'class="sla-age">2h<', html)


# ---------------------------------------------------------------------------
# Recent closures
# ---------------------------------------------------------------------------


def test_recent_closures_show_the_newest_five_with_short_reasons(session):
    for i in range(CLOSURES_SHOWN + 2):
        _case(session, f"RC-{i}", status=AlertCaseStatus.CLOSED, severity="high",
              reason="true_positive", closed_ago=timedelta(hours=i + 1))
    session.commit()
    html = _both(session).text
    rows = re.findall(r'class="rclosure-num">([^<]+)<', html)
    assert rows == [f"RC-{i}" for i in range(CLOSURES_SHOWN)]
    assert html.count('class="rclosure-reason cw-closure reason-true_positive"') == CLOSURES_SHOWN
    assert ">TP<" in html
    assert "1h ago" in html


def test_a_closure_with_no_reason_renders_a_dash_not_none(session):
    _case(session, "RN-1", status=AlertCaseStatus.CLOSED, closed_ago=timedelta(hours=1))
    session.commit()
    html = _both(session).text
    assert 'title="No closure reason recorded">-<' in html
    assert "None" not in flat(html)


def test_no_closures_is_worded_as_that(session):
    assert "Recent Closures No recent closures." in flat(_both(session).text)


# ---------------------------------------------------------------------------
# The retry control and the out-of-band targets
# ---------------------------------------------------------------------------


def test_a_clean_render_offers_no_retry_and_a_failed_one_offers_exactly_one(session, monkeypatch):
    html = _both(session).text
    assert 'id="cases-summary-retry" hx-swap-oob="true"' in html
    assert html.count('hx-get="/ui/cases/summary"') == 0

    import ion.services.case_query_service as cq
    monkeypatch.setattr(cq, "case_facets", lambda _s: (_ for _ in ()).throw(RuntimeError()))
    failed = _both(session).text
    assert failed.count('hx-get="/ui/cases/summary"') == 1
    assert 'hx-target="#cases-stats"' in failed
    assert "could not be read" in flat(failed)


def test_the_panel_body_lands_out_of_band_by_inner_html(session):
    """So the collapsed class on #analytics-panel-body, which the page
    toggles client-side, survives a refresh."""
    html = _both(session).text
    assert 'hx-swap-oob="innerHTML:#analytics-panel-body"' in html


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def test_the_page_pulls_the_fragment_and_refreshes_on_cases_changed():
    page = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/cases/summary"' in page
    assert 'hx-trigger="load, cases-changed from:body"' in page
    assert 'id="cases-summary-retry"' in page
    assert 'id="analytics-panel-body"' in page
    assert "new CustomEvent('cases-changed')" in page


def test_the_shell_keeps_a_retry_for_when_the_request_itself_fails():
    """Measured in the browser: on a 500, htmx-errors.js worded the tiles
    target, but the panel body and the Retry travel out of band in that
    same response and never arrived, so the panel sat at its loading text
    for ever with nothing to click. The shell's own hidden Retry sits in the
    slot outside both targets and the listener reveals it."""
    page = PAGE.read_text(encoding="utf-8")
    slot = page.split('id="cases-summary-retry"', 1)[1].split("<!-- Case widget board", 1)[0]
    assert 'data-summary-retry' in slot
    assert slot.count('hx-get="/ui/cases/summary"') == 1
    assert 'hx-target="#cases-stats"' in slot
    assert "addEventListener('htmx:responseError', summaryRequestFailed)" in page
    assert "addEventListener('htmx:sendError', summaryRequestFailed)" in page
    assert "panel.textContent = " in page
    # Words it as not measured, never as empty.
    assert "nothing here has been measured" in page


def test_the_page_no_longer_draws_the_region_in_javascript():
    page = PAGE.read_text(encoding="utf-8")
    for name in ("renderDonutChart", "renderWorkloadBars", "renderOpenCaseAges",
                 "renderRecentClosures", "renderSummaryStrip", "renderStats",
                 "renderRow2Stats", "renderAnalyticsPanel", "loadTeamMetrics",
                 "teamMetricsCache", "closureReasonColors"):
        assert name not in page, name
    # The ids the fragment writes into are no longer written by script.
    for stat in ("stat-open", "stat-mttr", "stat-unassigned", "analytics-sla",
                 "analytics-workload", "analytics-recent"):
        assert f"getElementById('{stat}')" not in page, stat


def test_the_shell_placeholders_do_not_read_as_measured_zero():
    """The tiles shipped with "0" before the script ran, which is the same
    glyph as a measured zero. A placeholder has to look like one."""
    page = PAGE.read_text(encoding="utf-8")
    stats = page.split('id="cases-stats"', 1)[1].split("</div>\n", 1)[0]
    assert 'ion-metric-value">0<' not in stats


def test_the_classes_the_fragment_emits_have_rules_in_the_page_stylesheet():
    """A class with no rule is invisible, not wrong."""
    page = PAGE.read_text(encoding="utf-8")
    for cls in (".age-bar-seg", ".cases-stat-sub", ".cases-card-failed",
                ".sla-row", ".hbar-track", ".rclosure-row", ".summary-chip",
                ".donut-legend-list", ".donut-center-text"):
        assert cls + " {" in page or cls + "{" in page, cls


def test_the_fragment_carries_no_inline_style_and_no_script():
    fragment = FRAGMENT.read_text(encoding="utf-8")
    assert "<script" not in fragment
    assert ' style="' not in fragment
    assert "hx-on" not in fragment


# ---------------------------------------------------------------------------
# Closing the survivors of this stage's first mutation pass.
#
# The pass ran 20 mutations and 9 survived. Three of those nine are
# equivalent mutants rather than coverage gaps, and are recorded here so
# nobody writes a test that cannot fail:
#
#   * `{% if d is none %}` to `{% if not d %}` on a donut, and the same on
#     `ages`. Both helpers return either None or a dict that always carries
#     its keys, and a non-empty dict is always truthy, so the two spellings
#     cannot diverge for any value the module can produce.
#   * swapping the two arms of `metrics_reason`. `metrics_withheld` and
#     `failed.metrics` are mutually exclusive by construction: the metrics
#     read is skipped rather than attempted when the viewer lacks
#     alert:read, so `failed["metrics"]` stays False in exactly the case
#     where `metrics_withheld` is True.
#
# The six below are real.
# ---------------------------------------------------------------------------


def test_a_flag_where_a_count_belongs_does_not_render_as_one(session, monkeypatch):
    """`_count` excludes bool on purpose, because True is an int in Python.
    Driven through the route as well as asserted directly, since the guard's
    whole job is to survive a service that starts emitting the wrong type."""
    from ion.web.ui.cases import _count, _number

    assert _count(True) is None
    assert _count(False) is None
    assert _count(3) == 3
    assert _number(True) is None
    assert _number(False) is None

    import ion.services.case_query_service as cq

    monkeypatch.setattr(cq, "case_facets",
                        lambda _s: {"by_status": {"open": True,
                                                  "acknowledged": 2}})
    text = flat(_both(session).text)
    assert "Open Cases 1" not in text, "a flag rendered as a count of one"
    assert "Acknowledged 2" in text, "the sibling count still renders"


def test_an_average_resolution_that_is_a_flag_is_not_an_hour(session, monkeypatch):
    """The same bool rule reached through `_number`, which resolution_text
    uses. True would otherwise print as "1h"."""
    import ion.services.case_metrics as cm

    monkeypatch.setattr(cm, "case_metrics",
                        lambda _s, since=None: {"avg_resolution_hours": True,
                                                "closed": 1, "by_reason": {}})
    text = flat(_both(session).text)
    assert "1h" not in text, "a flag printed as an average of one hour"
    assert "no case has closed yet" in text


def test_a_team_metrics_payload_that_is_not_a_mapping_is_a_failed_read(
        session, monkeypatch):
    """The isinstance check in summary_context. Without it a list reaches the
    donut and workload helpers, which would report no data rather than a
    read that answered the wrong shape."""
    import ion.web.api as api

    monkeypatch.setattr(api, "team_metrics_payload", lambda _s: ["not", "a",
                                                                 "mapping"])
    text = flat(_both(session).text)
    assert "read failed, not measured" in text
    assert "needs alert:read, not shown" not in text, (
        "the viewer holds alert:read; this is a failure, not a withholding")


def test_closed_today_is_counted_from_naive_utc_midnight(session, monkeypatch):
    """closed_at is a naive column holding UTC, so the boundary handed to
    case_metrics must be naive UTC midnight. An aware boundary, or one in the
    viewer's zone, moves "today" with whoever is looking, which is the defect
    this conversion fixed."""
    import ion.services.case_metrics as cm

    seen = []

    def record(_session, since=None):
        seen.append(since)
        return {"closed": 3, "by_reason": {}}

    monkeypatch.setattr(cm, "case_metrics", record)
    assert _both(session).status_code == 200

    assert len(seen) == 2, "one read for all time, one for today"
    day_start = seen[1]
    assert day_start.tzinfo is None, (
        "an aware boundary compared against a naive column is the bug")
    assert (day_start.hour, day_start.minute, day_start.second,
            day_start.microsecond) == (0, 0, 0, 0)
    assert day_start == datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0, tzinfo=None)


def test_a_metrics_read_with_no_closed_count_is_not_zero_closed_today(
        session, monkeypatch):
    """The existing dash test covers case_metrics raising. This covers it
    answering without the key, which is the only state where `_count` and a
    plain `or 0` differ: "the read did not report it" against "nothing
    closed today"."""
    import ion.services.case_metrics as cm

    monkeypatch.setattr(cm, "case_metrics", lambda _s, since=None: {"by_reason": {}})
    text = flat(_both(session).text)
    assert re.search(r"Closed Today \(UTC\) –", text), (
        "an unreported count rendered as a measured zero")
    assert "Closed Today (UTC) 0" not in text


def test_the_age_bands_exclude_their_upper_bound():
    """Asserted on the pure function rather than through a render, because
    the boundary is the point: a case aged exactly 24 hours belongs to 1-3d,
    and driving it through the route would compare against a clock that has
    moved on by the time the row is read, so the exact bound would never be
    the value under test."""
    from ion.web.ui.cases import AGE_BANDS, age_band

    assert age_band(23.999)[1] == "<24h"
    assert age_band(24.0)[1] == "1-3d", "the bound belongs to the band above"
    assert age_band(71.999)[1] == "1-3d"
    assert age_band(72.0)[1] == "3-7d"
    assert age_band(168.0)[1] == ">7d"
    assert age_band(10_000.0)[1] == AGE_BANDS[-1][2], "no upper bound"


def test_the_none_checks_in_the_fragment_cannot_be_softened_to_truthiness():
    """Pins the equivalence that makes three mutations harmless.

    The fragment asks `if d is none` and `if ages is none`. A mutation to
    `if not d` survives the suite, and the reason is not missing coverage:
    both helpers return either None or a dict that always carries its keys,
    and a non-empty dict is always truthy, so no input can tell the two
    spellings apart.

    That is a property of the helpers, not of the template, and nothing in
    the module enforced it. If either helper is later changed to return an
    empty dict for an empty result, the `is none` spelling becomes
    load-bearing and this fails, which is the point of writing it down as a
    test rather than as a comment.
    """
    from ion.web.ui.cases import ages_view, donut

    assert donut(None) is None
    assert ages_view(None, datetime.now(timezone.utc)) is None

    empty_donut = donut([])
    assert empty_donut is not None and empty_donut, (
        "an empty donut must stay truthy, or `is none` starts meaning "
        "something the template does not say")
    assert empty_donut["total"] == 0

    all_zero = donut([("open", 0, "a"), ("closed", 0, "b")])
    assert all_zero and all_zero["total"] == 0, "a measured zero, not a refusal"

    empty_ages = ages_view([], datetime.now(timezone.utc))
    assert empty_ages is not None and empty_ages
    assert empty_ages["total"] == 0 and empty_ages["oldest_days"] is None


def test_a_withheld_metric_is_never_also_a_failed_one(session, monkeypatch):
    """The other equivalence. Swapping the two arms of `metrics_reason`
    survives because the arms are mutually exclusive: summary_context skips
    the team-metrics read when the viewer lacks alert:read rather than
    attempting it and swallowing the failure, so `failed["metrics"]` cannot
    be true in the case where `metrics_withheld` is.

    Pinned by driving both viewers past a service that would fail if called.
    """
    import ion.web.api as api

    called = []

    def boom(_session):
        called.append(True)
        raise RuntimeError("team metrics down")

    monkeypatch.setattr(api, "team_metrics_payload", boom)

    withheld = flat(_get(session, PERMISSION).text)
    assert not called, "the read must be skipped, not attempted and swallowed"
    assert "needs alert:read, not shown" in withheld
    assert "read failed, not measured" not in withheld

    allowed = flat(_get(session, PERMISSION, METRICS_PERMISSION).text)
    assert called, "with the permission the read is attempted"
    assert "read failed, not measured" in allowed
    assert "needs alert:read, not shown" not in allowed
