"""v0.30.0 — lab fixture system end-to-end repair (Bugs 1+2+3+4).

These tests guard the four compounding bugs that kept graded labs broken
end-to-end from v0.21.0 through v0.29.1. Each test maps to one bug:

- Bug 1: labs_api decorators missing `/api/` prefix → endpoint 404
- Bug 2: seed_lab_fixtures.py not COPY'd into the Docker image
       + not invoked by the seed_all orchestrator → fixtures never seeded
- Bug 3: SELECT in seed_lab_fixtures used lowercase `l.lesson_type = 'lab'`
       against an enum stored as the NAME ('LAB') → silently inserts zero
- Bug 4: `/api/elasticsearch/alerts` returned ES alerts only; fixture
       triage rows were invisible → analyst couldn't open them

Run: `pytest tests/test_v030_lab_fixture_repair.py -v`
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401  — register all tables on Base.metadata
from ion.models.alert_triage import AlertTriage
from ion.models.base import Base
from ion.models.course import (
    Course,
    CourseLevel,
    CourseModule,
    Lesson,
    LessonType,
)
from ion.storage.database import _run_migrations


# ── Shared engine ────────────────────────────────────────────────────────


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "v030_repair.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    _run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def db(engine) -> Session:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    yield session
    session.rollback()
    session.close()


# ── Bug 1: labs_api routes carry `/api/` prefix ──────────────────────────


def test_labs_api_routes_use_api_prefix():
    """Decorators must include `/api/` — the router is mounted with prefix=''.

    Pre-fix the decorators were `@router.post("/courses/.../lab/launch")` and
    served `/courses/.../lab/launch`, while the frontend hit `/api/courses/...`
    → 404 since v0.21.0. This test inspects the FastAPI router directly so
    it doesn't import the full server (which spawns background loops).
    """
    from ion.web.labs_api import router

    paths = {r.path for r in router.routes}
    assert "/api/courses/{slug}/lessons/{lesson_id}/lab/launch" in paths, (
        f"lab/launch route missing or misprefixed; routes={paths}"
    )
    assert "/api/courses/{slug}/lessons/{lesson_id}/lab/complete" in paths, (
        f"lab/complete route missing or misprefixed; routes={paths}"
    )
    assert "/api/courses/{slug}/lessons/{lesson_id}/lab-sessions" in paths, (
        f"lab-sessions route missing or misprefixed; routes={paths}"
    )
    # And the un-prefixed forms must NOT be served — that was the bug shape.
    for p in paths:
        assert not p.startswith("/courses/"), (
            f"un-prefixed lab route present: {p} — Bug 1 regression"
        )


# ── Bug 3: enum-case SELECT matches stored uppercase 'LAB' ───────────────


def test_seed_lab_fixtures_select_matches_uppercase_lab(db: Session):
    """SQLEnum(native_enum=False) stores the enum NAME ('LAB'), not value.

    The pre-fix SELECT `l.lesson_type = 'lab'` (lowercase) returned no rows
    against an enum-stored lesson, so the seeder silently inserted zero
    fixtures. The fix uses UPPER(l.lesson_type) = 'LAB'. This test replays
    the exact fixed query.
    """
    # Build the minimal course/module/lesson chain the seed script joins on.
    c = Course(
        title="L1 Foundation",
        slug="l1-foundation",
        level=CourseLevel.L1,
        published=True,
        author_id=None,
    )
    db.add(c)
    db.flush()
    m = CourseModule(course_id=c.id, order=2, title="Module 2")
    db.add(m)
    db.flush()
    lesson = Lesson(
        module_id=m.id,
        order=9,
        title="LAB — Read your first alert in /alerts",
        lesson_type=LessonType.LAB,
        lab_target_url="/alerts",
    )
    db.add(lesson)
    db.flush()
    db.commit()

    # Pre-fix query (lowercase) returns nothing — sanity-check the original bug shape:
    pre_fix = db.execute(text("""
        SELECT l.id FROM lessons l
        JOIN course_modules m ON m.id = l.module_id
        JOIN courses c ON c.id = m.course_id
        WHERE c.level = 'L1'
          AND l.lesson_type = 'lab'
          AND l.title LIKE '%Read your first alert%'
        LIMIT 1
    """)).fetchone()
    assert pre_fix is None, (
        "Pre-fix lowercase query unexpectedly matched — enum storage may have "
        "changed; revisit the seed script's UPPER() wrap if so."
    )

    # Post-fix query (UPPER) returns the lesson.
    post_fix = db.execute(text("""
        SELECT l.id FROM lessons l
        JOIN course_modules m ON m.id = l.module_id
        JOIN courses c ON c.id = m.course_id
        WHERE c.level = 'L1'
          AND UPPER(l.lesson_type) = 'LAB'
          AND l.title LIKE '%Read your first alert%'
        LIMIT 1
    """)).fetchone()
    assert post_fix is not None, "Post-fix UPPER query failed to find LAB lesson"
    assert post_fix[0] == lesson.id


# ── Bug 2: seed_lab_fixtures shipped in image + orchestrator wires it ────


def test_seed_lab_fixtures_in_dockerfile_copy_block():
    """The Dockerfile Stage-2 COPY block must include seed_lab_fixtures.py
    or the script can't run inside the deployed container."""
    repo_root = Path(__file__).resolve().parent.parent
    dockerfile = (repo_root / "Dockerfile").read_text(encoding="utf-8")
    assert "seed_lab_fixtures.py" in dockerfile, (
        "Dockerfile missing seed_lab_fixtures.py in COPY block — Bug 2 regression"
    )


def test_seed_all_orchestrator_invokes_lab_fixtures():
    """seed_all.py must include seed_lab_fixtures in its SEEDS list,
    AFTER seed_courses (lab fixtures depend on lesson rows)."""
    repo_root = Path(__file__).resolve().parent.parent
    seed_all = (repo_root / "seed_all.py").read_text(encoding="utf-8")
    assert "seed_lab_fixtures.py" in seed_all, (
        "seed_all.py does not invoke seed_lab_fixtures — fixtures would never "
        "be seeded in deployed containers"
    )
    # Must come AFTER seed_courses (the JOIN target).
    pos_courses = seed_all.find("seed_courses.py")
    pos_lab = seed_all.find("seed_lab_fixtures.py")
    assert pos_courses != -1 and pos_lab != -1
    assert pos_lab > pos_courses, (
        "seed_lab_fixtures.py must run after seed_courses.py (lessons JOIN target)"
    )


# ── Bug 4: alerts list endpoint surfaces lab-fixture rows ────────────────


def test_alerts_list_includes_lab_fixture_triage_rows(db: Session):
    """The merge block in get_es_alerts must surface AlertTriage rows whose
    es_alert_id starts with 'lab-fixture-'. We replay the merge logic
    directly against SQLite — same query, same shape — to keep this test
    independent of the live Elasticsearch path.
    """
    # Seed two fixture rows + one non-fixture row (should NOT appear in
    # the fixture branch — represents a real ES-backed triage entry).
    t1 = AlertTriage(
        es_alert_id="lab-fixture-mimikatz-001",
        status="open",
        priority="high",
        rule_name="Credential Dumping via LSASS Memory (Lab fixture)",
        source_system="elastic",
        mitre_techniques=["T1003.001"],
    )
    t2 = AlertTriage(
        es_alert_id="lab-fixture-powershell-encoded-001",
        status="open",
        priority="medium",
        rule_name="Suspicious Base64-Encoded PowerShell (Lab fixture)",
        source_system="elastic",
    )
    t3 = AlertTriage(
        es_alert_id="real-elastic-alert-xyz",
        status="open",
        priority="low",
        rule_name="Some Real Alert",
        source_system="elastic",
    )
    db.add_all([t1, t2, t3])
    db.commit()

    # Replay the fixture-branch query from api.py:get_es_alerts.
    fixtures = (
        db.query(AlertTriage)
        .filter(AlertTriage.es_alert_id.like("lab-fixture-%"))
        .filter(AlertTriage.status != "closed")
        .all()
    )
    ids = {t.es_alert_id for t in fixtures}
    assert "lab-fixture-mimikatz-001" in ids
    assert "lab-fixture-powershell-encoded-001" in ids
    assert "real-elastic-alert-xyz" not in ids


def test_alerts_list_severity_filter_maps_to_priority(db: Session):
    """`severity` query param must filter fixture rows by AlertTriage.priority
    (AlertTriage has no `severity` column; priority is the seed-payload
    field that semantically aligns with the ES-alert severity)."""
    db.add_all([
        AlertTriage(
            es_alert_id="lab-fixture-high-001",
            status="open",
            priority="high",
            rule_name="High Lab Fixture",
        ),
        AlertTriage(
            es_alert_id="lab-fixture-medium-001",
            status="open",
            priority="medium",
            rule_name="Medium Lab Fixture",
        ),
    ])
    db.commit()

    high_only = (
        db.query(AlertTriage)
        .filter(AlertTriage.es_alert_id.like("lab-fixture-%"))
        .filter(AlertTriage.priority == "high")
        .all()
    )
    assert len(high_only) == 1
    assert high_only[0].es_alert_id == "lab-fixture-high-001"


def test_fixture_alert_dicts_does_not_touch_elasticsearch(db: Session):
    """The `_fixture_alert_dicts` helper must work without any
    Elasticsearch service or configuration involvement — fixtures have
    to surface in air-gapped dev environments where ES isn't running.

    Earlier v0.30.0 implementations put the fixture merge inside the
    ES-success path, so fixtures disappeared when ES was disabled,
    unconfigured, or unreachable. This test guards the regression by
    importing the helper directly and confirming it produces the
    correct dict shape from AlertTriage rows alone.
    """
    from ion.web.api import _fixture_alert_dicts

    db.add_all([
        AlertTriage(
            es_alert_id="lab-fixture-no-es-001",
            status="open",
            priority="high",
            rule_name="Air-Gapped Lab Fixture",
            source_system="elastic",
            mitre_techniques=["T1059.001"],
        ),
        AlertTriage(
            es_alert_id="lab-fixture-no-es-002",
            status="closed",
            priority="low",
            rule_name="Already-Closed Fixture",
        ),
        AlertTriage(
            es_alert_id="real-elastic-alert-999",
            status="open",
            priority="high",
            rule_name="Real Alert (Not A Fixture)",
        ),
    ])
    db.commit()

    # Default: open + acknowledged fixtures surface; closed is filtered
    # out unless include_closed=True. Real ES-backed AlertTriage rows
    # never appear (they have a backing ES doc).
    dicts = _fixture_alert_dicts(db)
    ids = {d["id"] for d in dicts}
    assert "lab-fixture-no-es-001" in ids
    assert "lab-fixture-no-es-002" not in ids  # closed → filtered
    assert "real-elastic-alert-999" not in ids  # not a fixture

    # is_lab_fixture flag is set on every returned dict — drives the UI
    # badge.
    assert all(d["is_lab_fixture"] is True for d in dicts)

    # Dict shape mirrors the ES alert dict the frontend expects.
    open_fixture = next(d for d in dicts if d["id"] == "lab-fixture-no-es-001")
    assert open_fixture["severity"] == "high"
    assert open_fixture["title"] == "Air-Gapped Lab Fixture"
    assert open_fixture["mitre_technique_id"] == "T1059.001"
    assert open_fixture["timestamp"] is not None  # overridden to "now"

    # include_closed=True surfaces both.
    dicts_with_closed = _fixture_alert_dicts(db, include_closed=True)
    ids_with_closed = {d["id"] for d in dicts_with_closed}
    assert "lab-fixture-no-es-002" in ids_with_closed

    # Explicit status=closed filters to closed fixtures only.
    closed_only = _fixture_alert_dicts(db, status="closed")
    assert {d["id"] for d in closed_only} == {"lab-fixture-no-es-002"}
