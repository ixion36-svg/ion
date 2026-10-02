"""v0.79.4 — the lab-fixture lookup stops sequential-scanning alert_triage.

`_fixture_alert_dicts` (web/elasticsearch_api.py) runs on EVERY return path of
the alerts-list endpoint — ION's hottest read — and filters
`es_alert_id LIKE 'lab-fixture-%'`. A prefix LIKE cannot use the plain btree on
`es_alert_id` under a non-C collation (the database is en_US.utf8); that needs
`text_pattern_ops`. So it planned as a Seq Scan over a table that grows one row
per triaged alert, forever, purely to surface a handful of lab-training
fixtures that a production deployment never uses.

Measured at 200k rows: Parallel Seq Scan 73.1 ms -> Index Scan 0.197 ms.
Production APM on v0.78.0 put ~50% of response time in repeated alert_triage
selects (6 executions, 807 ms) — ~135 ms each, the right order for this scan.

The fix is a PARTIAL index holding only the fixture rows (16 kB, against 7 MB
for a text_pattern_ops index over every row).

**What makes this fragile, and why these tests exist.** Postgres uses the
partial index only because it can prove the query predicate implies the index
predicate — which here rests on the two LIKE expressions being IDENTICAL. Change
the prefix in either place and the planner silently falls back to the Seq Scan:
no error, no wrong answer, no failing test. Just the slowness back, and nothing
to attribute it to. So:

  * `test_the_two_predicates_are_identical` pins the literal in both files.
  * `test_the_planner_actually_uses_the_index` executes the migration's OWN DDL
    text (extracted from source, never retyped here) against Postgres at a size
    where the planner has a real choice, and asserts the plan.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

DB = Path("src/ion/storage/database.py")
ES_API = Path("src/ion/web/elasticsearch_api.py")

INDEX_NAME = "ix_alert_triage_lab_fixture"
FIXTURE_PREFIX = "lab-fixture-%"


def _strip_comments(src: str) -> str:
    """These files DESCRIBE the predicate in prose above the code. Matching my
    own comment instead of the statement has been a false positive repeatedly
    in this codebase — strip them before asserting anything.
    """
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    return re.sub(r"^\s*#.*$", "", src, flags=re.M)


@pytest.fixture(scope="module")
def db_src() -> str:
    return _strip_comments(DB.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def api_src() -> str:
    return _strip_comments(ES_API.read_text(encoding="utf-8"))


def _extract_index_ddl(db_source: str) -> str:
    """Rebuild the CREATE INDEX statement from the migration's own source.

    The DDL lives as adjacent string literals inside a conn.execute(text(...)).
    Extracting it (rather than restating it) is the point: a test that retypes
    the DDL would pass while the shipped migration said something else.
    """
    anchor = db_source.index(f"CREATE INDEX IF NOT EXISTS {INDEX_NAME}")
    tail = db_source[anchor - 200:anchor + 400]
    parts = re.findall(r'"([^"]*)"', tail)
    ddl = "".join(p for p in parts if "CREATE INDEX" in p or "ON alert_triage" in p)
    assert ddl.startswith("CREATE INDEX"), f"could not rebuild DDL, got: {ddl!r}"
    return ddl


# ── the coupling ─────────────────────────────────────────────────────────


def test_the_migration_creates_the_partial_index(db_src):
    ddl = _extract_index_ddl(db_src)
    assert INDEX_NAME in ddl
    assert "ON alert_triage" in ddl
    assert "WHERE" in ddl, "not a PARTIAL index — it would cover every row"
    assert FIXTURE_PREFIX in ddl


def test_it_is_created_idempotently(db_src):
    """Every ION boot runs the migrations; a bare CREATE INDEX would raise on
    the second start."""
    assert f"CREATE INDEX IF NOT EXISTS {INDEX_NAME}" in _extract_index_ddl(db_src)


def test_the_two_predicates_are_identical(db_src, api_src):
    """The whole optimisation rests on this. If these ever disagree the index is
    dead weight and the scan is back, silently."""
    assert f'.like("{FIXTURE_PREFIX}")' in api_src, (
        "the query's LIKE predicate changed — the partial index in "
        "storage/database.py no longer applies and alert_triage will Seq Scan"
    )
    assert FIXTURE_PREFIX in _extract_index_ddl(db_src)


def test_index_failure_is_not_fatal(db_src):
    """Without the index the lookup is slow, not wrong. A deployment must still
    boot if the DDL fails (e.g. an engine without partial-index support)."""
    block = db_src[db_src.index(f"CREATE INDEX IF NOT EXISTS {INDEX_NAME}") - 400:]
    block = block[:block.index("doc_analysis_jobs")]
    assert "except Exception" in block
    assert "logger.warning" in block


def test_the_query_site_warns_about_the_coupling():
    """The comment is the only thing standing between a future edit and a silent
    370x regression, so its presence is worth asserting. Read UNSTRIPPED."""
    raw = ES_API.read_text(encoding="utf-8")
    site = raw[:raw.index('.like("lab-fixture-%")')]
    tail = site[-1400:]
    assert INDEX_NAME in tail, "query site does not name the index it depends on"
    assert "Seq Scan" in tail, "query site does not say what breaks"


# ── the plan itself ──────────────────────────────────────────────────────


def _pg_url() -> str | None:
    url = os.environ.get("ION_TEST_DATABASE_URL") or os.environ.get("ION_DATABASE_URL")
    if url and url.startswith("postgresql"):
        return url
    return None


@pytest.mark.skipif(_pg_url() is None, reason="needs a reachable Postgres")
def test_the_planner_actually_uses_the_index(db_src):
    """Prove the predicate implication holds — at a size where it matters.

    On a small table the planner correctly prefers a Seq Scan no matter what, so
    asserting the plan against an empty test database would prove nothing. This
    inserts enough rows for the choice to be real, then rolls the whole thing
    back so the target database is untouched.
    """
    import sqlalchemy as sa

    engine = sa.create_engine(_pg_url())
    ddl = _extract_index_ddl(db_src)

    with engine.connect() as conn:
        trans = conn.begin()
        try:
            conn.execute(sa.text(
                "INSERT INTO alert_triage (es_alert_id, status, created_at, updated_at) "
                "SELECT 'planprobe-' || g, 'OPEN', now(), now() "
                "FROM generate_series(1, 60000) g"
            ))
            conn.execute(sa.text(ddl))
            conn.execute(sa.text("ANALYZE alert_triage"))
            plan = "\n".join(
                r[0] for r in conn.execute(sa.text(
                    "EXPLAIN SELECT * FROM alert_triage "
                    "WHERE es_alert_id LIKE 'lab-fixture-%'"
                ))
            )
        finally:
            trans.rollback()

    assert "Seq Scan" not in plan, (
        "alert_triage is being sequentially scanned for lab fixtures on every "
        f"alerts-list request. Plan was:\n{plan}"
    )
    assert INDEX_NAME in plan, f"a different index was chosen:\n{plan}"
