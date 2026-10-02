"""Lesson PDF export — archived with the courseware subsystem.

Extracted from ``src/ion/services/pdf_export_service.py``, which the
courseware archive left behind. Its only caller is
``archive/courseware/web/course_api.py``, and the ``Lesson``/``Course``
models it reads live in ``archive/courseware/models/course.py`` — so it was
unreachable from the live tree, and 78 lines of it sat at 0% coverage with
no way to raise that honestly.

``generate_pdf`` and ``_content_to_html`` are still live; this module imports
them rather than copying them.
"""

from ion.services.pdf_export_service import _content_to_html, generate_pdf


def render_lesson_pdf(lesson, course) -> bytes:
    """Render a lesson (with its parent course) as a PDF.

    Converts ``lesson.content_md`` to HTML via the markdown library (same
    extensions as ``_content_to_html``).  Mermaid fenced blocks are replaced
    with a static notice because WeasyPrint runs no JavaScript.  Quiz
    questions are appended without correct answers so the PDF is safe to
    share as study material.

    Args:
        lesson: ORM ``Lesson`` instance (with ``.module.course`` loaded).
        course: ORM ``Course`` instance that owns the lesson.

    Returns:
        PDF bytes.
    """
    import re as _re

    module = lesson.module
    content_md = lesson.content_md or ""

    # Replace ```mermaid … ``` blocks — WeasyPrint has no JS renderer.
    content_md = _re.sub(
        r"```mermaid\b.*?```",
        "*[Diagram — available in the interactive lesson view]*",
        content_md,
        flags=_re.DOTALL,
    )

    body_html = _content_to_html(content_md, "markdown")

    questions = lesson.questions or []
    if questions:
        import html as _html_mod
        q_rows = ""
        for i, q in enumerate(questions, 1):
            import json as _json
            options_html = ""
            if q.options_json:
                try:
                    opts = _json.loads(q.options_json)
                    items = "".join(
                        f"<li>{_html_mod.escape(str(o.get('label') or o.get('value', '')))}</li>"
                        for o in opts
                    )
                    options_html = f"<ol type='A'>{items}</ol>"
                except (TypeError, ValueError):
                    pass
            q_rows += (
                f"<div style='margin:14px 0;padding:10px 14px;"
                f"background:#f7f8fa;border:1px solid #d0d7de;border-radius:4px;'>"
                f"<p style='margin:0 0 6px;font-weight:600;'>{i}. "
                f"{_html_mod.escape(q.stem_md or '')}</p>"
                f"{options_html}</div>"
            )
        body_html += (
            "<h2>Knowledge Check</h2>"
            "<p style='font-size:9.5pt;color:#555;margin-bottom:12px;'>"
            "Questions only — submit answers in the interactive lesson view.</p>"
            + q_rows
        )

    course_slug = course.slug or ""
    module_title = module.title if module else ""
    title = lesson.title or "Lesson"

    metadata = {
        "Course": course.title,
        "Level": course.level,
        "Module": module_title,
        "Type": (lesson.lesson_type or "").title(),
        "Duration": f"{lesson.duration_min} min" if lesson.duration_min else None,
    }

    return generate_pdf(body_html, title=title, metadata=metadata)
