"""Server-side case pagination (8 Oct 2026 review, §2, stage 5).

    "Add server pagination, compact list summaries and concurrent-edit
    conflict detection."

Stage 5's exit condition is "proven behaviour at the target workload".
``GET /api/cases`` did this::

    cases = query.order_by(AlertCase.created_at.desc()).all()

Every case, with three relationships eager-loaded each, serialised in full,
every time the page loaded. The page then filtered and sorted the whole set
in the browser. That is fine at fifty cases and a page that never loads at
fifty thousand, and the failure mode is the worst kind: it degrades
gradually with use until the product stops working for the SOCs that have
used it most.

Three things the tests pin beyond "a limit exists":

* **``total`` counts the matching rows, not the page.** Otherwise "showing
  50 of 50" is what a truncated list reports, and nobody can tell there are
  another twelve hundred behind it.
* **Severity does not sort alphabetically.** ``critical, high, low, medium``
  is what a plain string sort gives, which puts ``low`` above ``medium`` and
  is wrong in a way nobody notices until they are triaging by it.
* **An unknown sort field is refused, not ignored.** Quietly falling back to
  a different order means the caller believes it asked for something it did
  not get.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.base import Base
from ion.models.user import User
from ion.services import case_query_service as cq
from ion.services.case_query_service import CaseQueryError


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'case_pagination.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    for uid, name in ((1, "alice"), (2, "bob")):
        s.add(User(id=uid, username=name, email=f"{name}@x", password_hash="x",
                   display_name=name, is_active=True))
    s.commit()
    yield s
    s.close()


_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _case(db, n, *, status=AlertCaseStatus.OPEN, severity="medium",
          assigned_to_id=None, title=None, commit=True):
    c = AlertCase(
        case_number=f"CASE-{n:04d}",
        title=title or f"Case {n}",
        status=status,
        severity=severity,
        created_by_id=1,
        assigned_to_id=assigned_to_id,
        created_at=(_T0 + timedelta(hours=n)).replace(tzinfo=None),
    )
    db.add(c)
    if commit:
        db.commit()
        db.refresh(c)
    return c


def _many(db, count, **kw):
    for n in range(1, count + 1):
        _case(db, n, commit=False, **kw)
    db.commit()


# ── The envelope ─────────────────────────────────────────────────────────


class TestEnvelope:
    def test_an_empty_database_returns_an_empty_page(self, db):
        page = cq.list_cases_page(db)
        assert page["cases"] == []
        assert page["total"] == 0
        assert page["has_more"] is False

    def test_the_default_limit_is_finite(self, db):
        """Unbounded is the defect; a generous default is still bounded."""
        assert cq.DEFAULT_LIMIT > 0
        _many(db, cq.DEFAULT_LIMIT + 5)
        assert len(cq.list_cases_page(db)["cases"]) == cq.DEFAULT_LIMIT

    def test_the_total_counts_matching_rows_not_the_page(self, db):
        """"showing 50 of 50" is what a truncated list would otherwise say."""
        _many(db, 120)
        page = cq.list_cases_page(db, limit=25)
        assert len(page["cases"]) == 25
        assert page["total"] == 120

    def test_has_more_is_true_while_rows_remain(self, db):
        _many(db, 30)
        assert cq.list_cases_page(db, limit=10, offset=0)["has_more"] is True
        assert cq.list_cases_page(db, limit=10, offset=20)["has_more"] is False

    def test_the_envelope_echoes_the_window(self, db):
        _many(db, 30)
        page = cq.list_cases_page(db, limit=10, offset=10)
        assert page["limit"] == 10
        assert page["offset"] == 10
        assert page["returned"] == 10

    def test_an_offset_past_the_end_is_an_empty_page_not_an_error(self, db):
        _many(db, 5)
        page = cq.list_cases_page(db, offset=500)
        assert page["cases"] == []
        assert page["total"] == 5
        assert page["has_more"] is False

    def test_the_limit_is_capped(self, db):
        page = cq.list_cases_page(db, limit=10_000)
        assert page["limit"] == cq.MAX_LIMIT

    def test_a_non_positive_limit_is_refused(self, db):
        for bad in (0, -1):
            with pytest.raises(CaseQueryError):
                cq.list_cases_page(db, limit=bad)

    def test_a_negative_offset_is_refused(self, db):
        with pytest.raises(CaseQueryError):
            cq.list_cases_page(db, offset=-1)

    def test_pages_do_not_overlap_or_skip(self, db):
        """The property that makes paging usable at all."""
        _many(db, 25)
        seen = []
        for offset in range(0, 25, 10):
            seen += [c["id"] for c in
                     cq.list_cases_page(db, limit=10, offset=offset)["cases"]]
        assert len(seen) == 25
        assert len(set(seen)) == 25


# ── Filters apply server side ────────────────────────────────────────────


class TestFilters:
    def test_status_filters(self, db):
        _case(db, 1, status=AlertCaseStatus.OPEN)
        _case(db, 2, status=AlertCaseStatus.CLOSED)
        page = cq.list_cases_page(db, status="OPEN")
        assert page["total"] == 1
        assert page["cases"][0]["case_number"] == "CASE-0001"

    def test_status_is_case_insensitive(self, db):
        _case(db, 1, status=AlertCaseStatus.OPEN)
        assert cq.list_cases_page(db, status="open")["total"] == 1

    def test_an_unknown_status_is_refused(self, db):
        """Returning everything for a typo'd filter is the wrong answer."""
        with pytest.raises(CaseQueryError):
            cq.list_cases_page(db, status="OPNE")

    def test_severity_filters(self, db):
        _case(db, 1, severity="critical")
        _case(db, 2, severity="low")
        page = cq.list_cases_page(db, severity="critical")
        assert page["total"] == 1

    def test_assignee_filters(self, db):
        _case(db, 1, assigned_to_id=1)
        _case(db, 2, assigned_to_id=2)
        assert cq.list_cases_page(db, assigned_to_id=2)["total"] == 1

    def test_unassigned_filters(self, db):
        """The handover report counts these, so the list has to find them."""
        _case(db, 1, assigned_to_id=1)
        _case(db, 2, assigned_to_id=None)
        page = cq.list_cases_page(db, unassigned=True)
        assert page["total"] == 1
        assert page["cases"][0]["case_number"] == "CASE-0002"

    def test_unassigned_and_an_assignee_together_are_refused(self, db):
        """They cannot both hold; silently preferring one hides the mistake."""
        with pytest.raises(CaseQueryError):
            cq.list_cases_page(db, unassigned=True, assigned_to_id=1)

    def test_search_matches_the_title(self, db):
        _case(db, 1, title="Beaconing from finance VLAN")
        _case(db, 2, title="Phishing report")
        assert cq.list_cases_page(db, q="beacon")["total"] == 1

    def test_search_matches_the_case_number(self, db):
        _case(db, 7)
        assert cq.list_cases_page(db, q="CASE-0007")["total"] == 1

    def test_search_is_case_insensitive(self, db):
        _case(db, 1, title="Beaconing")
        assert cq.list_cases_page(db, q="BEACONING")["total"] == 1

    def test_a_search_wildcard_is_treated_literally(self, db):
        """A bare % in the query must not match everything."""
        _case(db, 1, title="Beaconing")
        _case(db, 2, title="Phishing")
        assert cq.list_cases_page(db, q="%")["total"] == 0

    def test_an_underscore_is_treated_literally(self, db):
        _case(db, 1, title="svc_backup logon")
        _case(db, 2, title="svcXbackup logon")
        assert cq.list_cases_page(db, q="svc_backup")["total"] == 1

    def test_filters_combine(self, db):
        _case(db, 1, status=AlertCaseStatus.OPEN, severity="critical")
        _case(db, 2, status=AlertCaseStatus.OPEN, severity="low")
        _case(db, 3, status=AlertCaseStatus.CLOSED, severity="critical")
        page = cq.list_cases_page(db, status="OPEN", severity="critical")
        assert page["total"] == 1

    def test_the_total_respects_the_filters(self, db):
        """A total over all rows would make the filtered page look truncated."""
        _many(db, 40, status=AlertCaseStatus.OPEN)
        _case(db, 99, status=AlertCaseStatus.CLOSED)
        page = cq.list_cases_page(db, status="CLOSED", limit=10)
        assert page["total"] == 1


# ── Sorting ──────────────────────────────────────────────────────────────


class TestSorting:
    def test_the_default_is_newest_first(self, db):
        _case(db, 1)
        _case(db, 2)
        numbers = [c["case_number"]
                   for c in cq.list_cases_page(db)["cases"]]
        assert numbers == ["CASE-0002", "CASE-0001"]

    def test_the_order_can_be_reversed(self, db):
        _case(db, 1)
        _case(db, 2)
        numbers = [c["case_number"]
                   for c in cq.list_cases_page(db, order="asc")["cases"]]
        assert numbers == ["CASE-0001", "CASE-0002"]

    def test_severity_sorts_by_rank_not_alphabetically(self, db):
        """Alphabetically: critical, high, low, medium. `low` above `medium`
        is wrong in a way nobody notices until they triage by it."""
        for n, sev in enumerate(("low", "critical", "medium", "high"), start=1):
            _case(db, n, severity=sev)
        severities = [c["severity"] for c in
                      cq.list_cases_page(db, sort="severity", order="desc")["cases"]]
        assert severities == ["critical", "high", "medium", "low"]

    def test_severity_ascending_is_the_exact_reverse(self, db):
        for n, sev in enumerate(("low", "critical", "medium", "high"), start=1):
            _case(db, n, severity=sev)
        severities = [c["severity"] for c in
                      cq.list_cases_page(db, sort="severity", order="asc")["cases"]]
        assert severities == ["low", "medium", "high", "critical"]

    def test_an_unranked_severity_sorts_last_not_first(self, db):
        """An unrecognised value must not outrank critical."""
        _case(db, 1, severity="critical")
        _case(db, 2, severity="banana")
        severities = [c["severity"] for c in
                      cq.list_cases_page(db, sort="severity", order="desc")["cases"]]
        assert severities[0] == "critical"

    def test_a_null_severity_sorts_last(self, db):
        _case(db, 1, severity="low")
        _case(db, 2, severity=None)
        severities = [c["severity"] for c in
                      cq.list_cases_page(db, sort="severity", order="desc")["cases"]]
        assert severities[-1] is None

    def test_an_unknown_sort_field_is_refused(self, db):
        """Quietly falling back means the caller believes it got what it asked
        for. It is also how an ORDER BY injection would arrive."""
        with pytest.raises(CaseQueryError):
            cq.list_cases_page(db, sort="created_at; DROP TABLE alert_cases")

    def test_an_unknown_order_is_refused(self, db):
        with pytest.raises(CaseQueryError):
            cq.list_cases_page(db, order="sideways")

    def test_every_allowed_sort_actually_works(self, db):
        """A whitelist entry with no mapping would 500 rather than 400."""
        _many(db, 3)
        for field in cq.SORTABLE_FIELDS:
            page = cq.list_cases_page(db, sort=field)
            assert len(page["cases"]) == 3, field

    def test_the_sort_is_deterministic_under_ties(self, db):
        """Equal sort keys with no tiebreak means pages can repeat or skip
        rows -- the paging property above would fail intermittently."""
        _many(db, 6, severity="high")
        first = [c["id"] for c in cq.list_cases_page(
            db, sort="severity", limit=3, offset=0)["cases"]]
        second = [c["id"] for c in cq.list_cases_page(
            db, sort="severity", limit=3, offset=3)["cases"]]
        assert not set(first) & set(second)


# ── The compact summary ──────────────────────────────────────────────────


class TestSummaryShape:
    def test_the_row_carries_what_a_list_renders(self, db):
        _case(db, 1, assigned_to_id=2)
        row = cq.list_cases_page(db)["cases"][0]
        for key in ("id", "case_number", "title", "status", "severity",
                    "created_at", "assigned_to", "alert_count"):
            assert key in row, key

    def test_the_row_omits_the_bulky_fields(self, db):
        """"compact list summaries": a list of 500 cases must not ship every
        description and evidence summary."""
        _case(db, 1)
        row = cq.list_cases_page(db)["cases"][0]
        assert "description" not in row
        assert "evidence_summary" not in row

    def test_the_assignee_is_resolved_to_a_username(self, db):
        _case(db, 1, assigned_to_id=2)
        assert cq.list_cases_page(db)["cases"][0]["assigned_to"] == "bob"

    def test_an_unassigned_case_reports_none_not_empty_string(self, db):
        _case(db, 1, assigned_to_id=None)
        row = cq.list_cases_page(db)["cases"][0]
        assert row["assigned_to"] is None
        assert row["assigned_to_id"] is None

    def test_the_status_is_a_plain_string(self, db):
        """The enum's own value, lower case, as the existing UI reads it."""
        _case(db, 1, status=AlertCaseStatus.OPEN)
        assert cq.list_cases_page(db)["cases"][0]["status"] ==             AlertCaseStatus.OPEN.value == "open"


# ── Facet counts for the filter bar ──────────────────────────────────────


class TestFacets:
    def test_counts_by_status_are_available_without_fetching_rows(self, db):
        _case(db, 1, status=AlertCaseStatus.OPEN)
        _case(db, 2, status=AlertCaseStatus.OPEN)
        _case(db, 3, status=AlertCaseStatus.CLOSED)
        facets = cq.case_facets(db)
        assert facets["by_status"][AlertCaseStatus.OPEN.value] == 2
        assert facets["by_status"][AlertCaseStatus.CLOSED.value] == 1

    def test_counts_by_severity_are_available(self, db):
        _case(db, 1, severity="critical")
        _case(db, 2, severity="critical")
        assert cq.case_facets(db)["by_severity"]["critical"] == 2

    def test_the_unassigned_count_is_available(self, db):
        _case(db, 1, assigned_to_id=None)
        _case(db, 2, assigned_to_id=1)
        assert cq.case_facets(db)["unassigned"] == 1

    def test_the_total_is_available(self, db):
        _many(db, 7)
        assert cq.case_facets(db)["total"] == 7

    def test_facets_on_an_empty_database_are_zero(self, db):
        facets = cq.case_facets(db)
        assert facets["total"] == 0
        assert facets["unassigned"] == 0


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "case_lifecycle_api.py"
                ).read_text(encoding="utf-8")

    def test_the_list_endpoint_takes_a_limit(self):
        src = self._api()
        block = src.split('@router.get("/elasticsearch/alerts/cases")')[1][:900]
        assert "limit" in block
        assert "offset" in block

    def test_the_unbounded_query_is_gone(self):
        """The literal defect: order_by(...).all() with no limit."""
        src = self._api()
        block = src.split('@router.get("/elasticsearch/alerts/cases")')[1][:2000]
        assert "AlertCase.created_at.desc()).all()" not in block

    def test_the_facets_endpoint_exists(self):
        assert "/elasticsearch/alerts/cases/facets" in self._api()

    def test_the_facets_route_is_declared_before_the_detail_route(self):
        """Otherwise "facets" is parsed as a case id and the request 422s."""
        src = self._api()
        facets = '@router.get("/elasticsearch/alerts/cases/facets")'
        detail = '@router.get("/elasticsearch/alerts/cases/{case_id}")'
        assert facets in src and detail in src
        assert src.index(facets) < src.index(detail)

    @staticmethod
    def _page():
        return (_SRC / "ion" / "web" / "templates" / "cases.html"
                ).read_text(encoding="utf-8")

    def test_the_page_requests_a_window(self):
        """The bare /api/cases fetch is gone.

        Asserted on the fetch itself, not on the strings "limit=" and
        "offset=" anywhere in the file -- they appear in unrelated calls, so
        that version of this test passed before the page was changed at all.
        """
        page = self._page()
        assert "fetch('/api/cases')" not in page
        assert "'/api/cases?limit=' + CASES_PAGE_SIZE" in page

    def test_the_page_follows_has_more(self):
        """A single page would show the first N and call it the board."""
        assert "data.has_more" in self._page()

    def test_the_page_stops_at_a_ceiling(self):
        """Following has_more without a bound just restores the old
        unbounded load, one request at a time."""
        page = self._page()
        assert "CASES_LOAD_CEILING" in page
        assert "casesTruncated = true" in page

    def test_a_capped_load_is_visible_to_the_analyst(self):
        """A board silently showing a third of the cases is worse than one
        that admits it."""
        page = self._page()
        assert "cases-load-notice" in page
        assert "renderCaseLoadNotice" in page

    def test_the_page_reads_the_servers_counts(self):
        """Client-side counts over a capped array understate the backlog."""
        assert "/api/cases/facets" in self._page()


# ── No page relies on the old unbounded default ──────────────────────────


class TestNoUnboundedCallers:
    """Found in the browser: /cases had been converted, but the alerts page
    still did a bare `fetch('/api/cases')`.

    With the endpoint's default limit that call silently returns the first
    page, and the panel's badge -- a count of *active* cases taken from the
    array -- would undercount on any SOC with more cases than the page size.
    The list being short is a display choice; the count being wrong is not.
    """

    @staticmethod
    def _templates():
        return sorted(
            (_SRC / "ion" / "web" / "templates").rglob("*.html")
        )

    def test_the_glob_finds_templates(self):
        assert len(self._templates()) > 30

    def test_no_template_reads_the_case_list_without_a_window(self):
        import re

        # A GET with no query string. POSTs to the same path create a case
        # and are unaffected, so the pattern requires the closing paren.
        bare = re.compile(r"""fetch\(\s*['"`]/api/cases['"`]\s*\)""")
        offenders = []
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            for match in bare.finditer(text):
                offenders.append(f"{path.name}:{text[:match.start()].count(chr(10)) + 1}")
        assert not offenders, (
            "these read the case list with no limit, so they silently get "
            f"only the first page: {offenders}"
        )

    def test_the_alerts_summary_counts_from_the_server(self):
        page = (_SRC / "ion" / "web" / "templates" / "alerts.html"
                ).read_text(encoding="utf-8")
        assert "/api/cases/facets" in page
        assert "casesActiveTotal" in page
