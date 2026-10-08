"""The case list at workload (8 Oct 2026 review, stage 5).

Stage 5's exit condition: *"Proven behaviour at the target workload and
deployment boundary."* The review also asks to *"validate complete journeys
with realistic datasets"* rather than inspecting source.

The pagination commit claims the list no longer degrades with the size of
the table. That is a claim about cost, and the previous tests do not test
it: they all run against a handful of rows, where the unbounded version
would have passed too.

**Query count, not wall clock.** The defect was structural — an unbounded
``.all()`` plus per-case relationship loads — so the measurement is the
number of SQL statements, which is deterministic. A wall-clock budget would
be flaky on a loaded machine and would pass on a fast one even if the N+1
came back.

The property that matters: **statement count is flat in the size of the
table.** 50 cases and 5,000 cases must cost the same number of queries for
the same page. If someone reintroduces a relationship access inside the
serialisation loop, the count becomes proportional to the page size and
these fail.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
from ion.models.base import Base
from ion.models.user import User
from ion.services import case_query_service as cq

#: Enough rows that an unbounded query is unmistakably different from a
#: bounded one, while keeping the fixture build to a couple of seconds.
SMALL = 50
LARGE = 5_000

#: Alerts attached to the first few cases, so alert_count has real work to do
#: rather than always counting zero.
ALERTS_PER_CASE = 4
CASES_WITH_ALERTS = 40


class _Counter:
    """Counts SQL statements executed on an engine."""

    def __init__(self, engine):
        self.engine = engine
        self.statements: list[str] = []

    def __enter__(self):
        event.listen(self.engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc):
        event.remove(self.engine, "before_cursor_execute", self._record)
        return False

    def _record(self, conn, cursor, statement, params, context, executemany):
        self.statements.append(statement)

    @property
    def count(self) -> int:
        return len(self.statements)


def _build(tmp_path, name, case_count):
    engine = create_engine(f"sqlite:///{tmp_path / name}")
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    session = maker()

    session.add_all([
        User(id=1, username="alice", email="a@x", password_hash="x",
             display_name="Alice", is_active=True),
        User(id=2, username="bob", email="b@x", password_hash="x",
             display_name="Bob", is_active=True),
    ])
    session.commit()

    base = datetime(2026, 1, 1, tzinfo=timezone.utc).replace(tzinfo=None)
    severities = ("critical", "high", "medium", "low")
    statuses = (AlertCaseStatus.OPEN, AlertCaseStatus.CLOSED)

    session.bulk_save_objects([
        AlertCase(
            id=n,
            case_number=f"CASE-{n:06d}",
            title=f"Case {n} beaconing from host-{n % 250}",
            status=statuses[n % 2],
            severity=severities[n % 4],
            created_by_id=1,
            # Half assigned, half not, so the unassigned filter has to work.
            assigned_to_id=(2 if n % 2 else None),
            created_at=base + timedelta(minutes=n),
        )
        for n in range(1, case_count + 1)
    ])
    session.commit()

    session.bulk_save_objects([
        AlertTriage(
            es_alert_id=f"alert-{case_id}-{i}",
            case_id=case_id,
            status="open",
        )
        for case_id in range(1, min(CASES_WITH_ALERTS, case_count) + 1)
        for i in range(ALERTS_PER_CASE)
    ])
    session.commit()
    return engine, session


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    engine, session = _build(tmp_path_factory.mktemp("small"), "small.db", SMALL)
    yield engine, session
    session.close()
    engine.dispose()


@pytest.fixture(scope="module")
def large(tmp_path_factory):
    engine, session = _build(tmp_path_factory.mktemp("large"), "large.db", LARGE)
    yield engine, session
    session.close()
    engine.dispose()


def _queries_for(engine, session, **kw):
    with _Counter(engine) as counter:
        page = cq.list_cases_page(session, **kw)
    return page, counter


# ── The dataset is what the test claims it is ────────────────────────────


class TestFixture:
    def test_the_large_dataset_is_large(self, large):
        _, session = large
        assert cq.case_facets(session)["total"] == LARGE

    def test_the_small_dataset_is_small(self, small):
        _, session = small
        assert cq.case_facets(session)["total"] == SMALL

    def test_alerts_are_attached_so_alert_count_has_work(self, large):
        _, session = large
        page = cq.list_cases_page(session, sort="created_at", order="asc", limit=5)
        assert page["cases"][0]["alert_count"] == ALERTS_PER_CASE


# ── Cost is flat in the size of the table ────────────────────────────────


class TestQueryCost:
    def test_one_page_costs_the_same_at_any_table_size(self, small, large):
        """The whole claim of the pagination work, in one assertion."""
        s_engine, s_session = small
        l_engine, l_session = large

        _, small_counter = _queries_for(s_engine, s_session, limit=50)
        _, large_counter = _queries_for(l_engine, l_session, limit=50)

        assert small_counter.count == large_counter.count, (
            "query count changed with table size: "
            f"{small_counter.count} at {SMALL} rows vs "
            f"{large_counter.count} at {LARGE} rows"
        )

    def test_a_page_is_a_handful_of_queries_not_one_per_row(self, large):
        """A relationship access inside the serialisation loop would make
        this proportional to the page size."""
        engine, session = large
        page, counter = _queries_for(engine, session, limit=100)
        assert page["returned"] == 100
        assert counter.count <= 5, (
            f"{counter.count} queries for one page of 100: "
            + "; ".join(s.split("\n")[0][:80] for s in counter.statements[:8])
        )

    def test_doubling_the_page_size_does_not_change_the_query_count(self, large):
        engine, session = large
        _, c50 = _queries_for(engine, session, limit=50)
        _, c200 = _queries_for(engine, session, limit=200)
        assert c50.count == c200.count

    def test_the_facet_counts_are_aggregates_not_a_scan(self, large):
        engine, session = large
        with _Counter(engine) as counter:
            facets = cq.case_facets(session)
        assert facets["total"] == LARGE
        assert counter.count <= 6

    def test_filtering_does_not_add_a_query_per_row(self, large):
        engine, session = large
        _, counter = _queries_for(engine, session, status="open", limit=50)
        assert counter.count <= 5

    def test_searching_does_not_add_a_query_per_row(self, large):
        engine, session = large
        _, counter = _queries_for(engine, session, q="host-42", limit=50)
        assert counter.count <= 5

    def test_sorting_by_severity_does_not_add_queries(self, large):
        """The CASE expression must sort in the database, not in Python."""
        engine, session = large
        _, counter = _queries_for(engine, session, sort="severity", limit=50)
        assert counter.count <= 5


# ── Correctness survives the workload ───────────────────────────────────


class TestCorrectnessAtScale:
    def test_the_total_is_the_table_not_the_page(self, large):
        _, session = large
        page = cq.list_cases_page(session, limit=10)
        assert page["total"] == LARGE
        assert page["returned"] == 10
        assert page["has_more"] is True

    def test_the_filtered_total_is_the_filtered_count(self, large):
        _, session = large
        page = cq.list_cases_page(session, status="open", limit=10)
        # Half the rows, by construction.
        assert page["total"] == LARGE // 2

    def test_the_unassigned_filter_finds_its_half(self, large):
        _, session = large
        assert cq.list_cases_page(session, unassigned=True)["total"] == LARGE // 2

    def test_walking_every_page_sees_every_row_exactly_once(self, large):
        """The property that makes paging usable, at a size where an unstable
        sort would actually have ties to get wrong."""
        _, session = large
        seen: set[int] = set()
        offset = 0
        pages = 0
        while True:
            page = cq.list_cases_page(session, limit=cq.MAX_LIMIT, offset=offset)
            ids = [c["id"] for c in page["cases"]]
            assert not (seen & set(ids)), "a row appeared on two pages"
            seen.update(ids)
            pages += 1
            if not page["has_more"]:
                break
            offset += len(ids)
            assert pages < 100, "paging did not terminate"
        assert len(seen) == LARGE

    def test_walking_pages_sorted_by_severity_also_covers_everything(self, large):
        """Severity has only four distinct values over 5,000 rows, so every
        page boundary lands inside a block of ties. Without the id tiebreak
        this loses and repeats rows."""
        _, session = large
        seen: set[int] = set()
        offset = 0
        while True:
            page = cq.list_cases_page(
                session, sort="severity", order="desc",
                limit=cq.MAX_LIMIT, offset=offset,
            )
            ids = [c["id"] for c in page["cases"]]
            assert not (seen & set(ids)), "a tied row appeared on two pages"
            seen.update(ids)
            if not page["has_more"]:
                break
            offset += len(ids)
        assert len(seen) == LARGE

    def test_severity_order_holds_across_the_whole_table(self, large):
        _, session = large
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        previous = 5
        offset = 0
        while True:
            page = cq.list_cases_page(
                session, sort="severity", order="desc",
                limit=cq.MAX_LIMIT, offset=offset,
            )
            for row in page["cases"]:
                current = rank[row["severity"]]
                assert current <= previous, "severity order broke across pages"
                previous = current
            if not page["has_more"]:
                break
            offset += page["returned"]

    def test_the_last_page_is_not_short_of_rows_that_exist(self, large):
        _, session = large
        offset = LARGE - 10
        page = cq.list_cases_page(session, limit=cq.MAX_LIMIT, offset=offset)
        assert page["returned"] == 10
        assert page["has_more"] is False


# ── A coarse wall-clock sanity check ────────────────────────────────────


class TestResponsiveness:
    """Deliberately generous. This is a smoke test against an accidental
    full-table materialisation, not a performance budget — a tight bound
    would be flaky on a loaded machine and would prove little on a fast
    one. The query-count tests above are the real guard."""

    BUDGET_SECONDS = 2.0

    def test_a_page_of_the_large_table_returns_promptly(self, large):
        _, session = large
        started = time.perf_counter()
        page = cq.list_cases_page(session, limit=100)
        elapsed = time.perf_counter() - started
        assert page["returned"] == 100
        assert elapsed < self.BUDGET_SECONDS, f"took {elapsed:.2f}s"

    def test_the_deepest_page_returns_promptly(self, large):
        """OFFSET gets slower with depth; this checks it is not pathological
        at a realistic depth."""
        _, session = large
        started = time.perf_counter()
        cq.list_cases_page(session, limit=100, offset=LARGE - 100)
        elapsed = time.perf_counter() - started
        assert elapsed < self.BUDGET_SECONDS, f"took {elapsed:.2f}s"

    def test_the_facets_return_promptly(self, large):
        _, session = large
        started = time.perf_counter()
        cq.case_facets(session)
        elapsed = time.perf_counter() - started
        assert elapsed < self.BUDGET_SECONDS, f"took {elapsed:.2f}s"
