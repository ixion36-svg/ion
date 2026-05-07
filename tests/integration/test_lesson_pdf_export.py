"""Smoke tests for the lesson-level PDF export route.

Route: GET /api/courses/{slug}/lessons/{lesson_id}/export.pdf

Happy-path: seeded course → lesson → route returns 200 + application/pdf
(or text/html fallback when WeasyPrint is absent) with a non-empty body
that starts with the PDF magic bytes when WeasyPrint is available.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def seeded_client(temp_db, monkeypatch):
    """TestClient with a seeded course/module/lesson and auth bypassed."""
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from ion.storage.database import reset_engine
    reset_engine()

    from ion.models.base import Base
    from ion.models.course import Course, CourseModule, Lesson
    from ion.models.user import User

    Base.metadata.create_all(temp_db)

    Session = sessionmaker(bind=temp_db)
    s = Session()

    course = Course(
        title="L1 Alert Triage", slug="l1-alert-triage", level="L1",
        description_md="Intro course.", estimated_hours=2,
        pass_threshold=70, published=True,
    )
    s.add(course)
    s.flush()

    module = CourseModule(
        course_id=course.id, order=1, title="Module 1: Foundations",
        description_md="", estimated_minutes=45,
    )
    s.add(module)
    s.flush()

    lesson = Lesson(
        module_id=module.id, order=1, title="What is an Alert",
        lesson_type="reading",
        content_md="## Overview\n\nAn alert is a detection event.\n\n```python\nprint('hello')\n```",
        duration_min=15,
    )
    s.add(lesson)
    s.commit()

    lesson_id = lesson.id
    course_slug = course.slug
    s.close()

    fake_admin = User(
        id=1, username="admin", email="admin@localhost",
        password_hash="x", display_name="Admin", is_active=True,
    )

    from ion.auth.dependencies import get_current_user
    from ion.web.server import app

    app.dependency_overrides[get_current_user] = lambda: fake_admin

    client = TestClient(app)
    yield client, course_slug, lesson_id

    app.dependency_overrides.clear()
    reset_engine()


def test_lesson_pdf_happy_path(seeded_client):
    """Route returns 200 with application/pdf or html fallback; non-empty body."""
    client, slug, lesson_id = seeded_client
    r = client.get(f"/api/courses/{slug}/lessons/{lesson_id}/export.pdf")

    assert r.status_code == 200
    ct = r.headers["content-type"]
    assert ct.startswith("application/pdf") or ct.startswith("text/html")
    assert len(r.content) > 0


def test_lesson_pdf_is_valid_pdf_when_weasyprint_available(seeded_client):
    """When WeasyPrint renders successfully the body must be a valid PDF."""
    client, slug, lesson_id = seeded_client
    r = client.get(f"/api/courses/{slug}/lessons/{lesson_id}/export.pdf")

    if r.headers["content-type"].startswith("application/pdf"):
        assert r.content[:4] == b"%PDF"


def test_lesson_pdf_attachment_header(seeded_client):
    """PDF response carries Content-Disposition: attachment."""
    client, slug, lesson_id = seeded_client
    r = client.get(f"/api/courses/{slug}/lessons/{lesson_id}/export.pdf")

    if r.headers["content-type"].startswith("application/pdf"):
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert slug in cd


def test_lesson_pdf_404_bad_course(seeded_client):
    """Unknown course slug returns 404."""
    client, _slug, lesson_id = seeded_client
    r = client.get(f"/api/courses/no-such-course/lessons/{lesson_id}/export.pdf")
    assert r.status_code == 404


def test_lesson_pdf_404_bad_lesson(seeded_client):
    """Unknown lesson id returns 404."""
    client, slug, _lesson_id = seeded_client
    r = client.get(f"/api/courses/{slug}/lessons/99999/export.pdf")
    assert r.status_code == 404


def test_lesson_pdf_404_lesson_wrong_course(seeded_client, temp_db):
    """Lesson belonging to a different course returns 404 on this slug."""
    client, slug, lesson_id = seeded_client

    from sqlalchemy.orm import sessionmaker as _SM
    from ion.models.course import Course, CourseModule, Lesson

    Session = _SM(bind=temp_db)
    s = Session()
    other_course = Course(
        title="Other Course", slug="other-course", level="L2",
        description_md="", estimated_hours=1, pass_threshold=70, published=True,
    )
    s.add(other_course)
    s.flush()
    other_mod = CourseModule(course_id=other_course.id, order=0, title="M1", estimated_minutes=30)
    s.add(other_mod)
    s.flush()
    other_lesson = Lesson(
        module_id=other_mod.id, order=0, title="Other Lesson",
        lesson_type="reading", content_md="content", duration_min=5,
    )
    s.add(other_lesson)
    s.commit()
    other_lesson_id = other_lesson.id
    s.close()

    r = client.get(f"/api/courses/{slug}/lessons/{other_lesson_id}/export.pdf")
    assert r.status_code == 404
