"""base.html carries the token and loads the attaching script.

Source-level assertions rather than behavioural ones: ION has no JavaScript test
runner (no package.json, no jest/vitest), so these are the strongest checks
available without introducing a build step. They guard the wiring — that the
token is rendered, that the script is loaded with a nonce, and that the script's
security-relevant branches are present — not the script's runtime behaviour.
"""

from pathlib import Path

BASE_HTML = Path("src/ion/web/templates/base.html")
CSRF_JS = Path("src/ion/web/static/js/csrf.js")


def test_csrf_script_file_exists():
    assert CSRF_JS.is_file()


def test_base_html_renders_the_meta_tag_guarded_by_the_token():
    html = BASE_HTML.read_text(encoding="utf-8")
    assert '{% if csrf_token %}' in html
    assert 'name="csrf-token"' in html
    assert '{{ csrf_token }}' in html


def test_base_html_loads_the_script_with_a_nonce():
    html = BASE_HTML.read_text(encoding="utf-8")
    assert '/static/js/csrf.js' in html
    for line in html.splitlines():
        if '/static/js/csrf.js' in line:
            assert 'nonce="{{ csp_nonce }}"' in line
            return
    raise AssertionError("csrf.js script tag not found")


def test_script_attaches_only_to_unsafe_same_origin_requests():
    js = CSRF_JS.read_text(encoding="utf-8")
    assert "X-CSRF-Token" in js
    assert "htmx:configRequest" in js
    # Cross-origin requests must be left alone so the token never leaks outbound.
    assert "sameOrigin" in js


def test_script_redirects_to_login_on_csrf_invalid():
    # Spec, Failure handling: a stale token means the session is gone, so the
    # only sane recovery is re-login. Matches app.js's existing redirect shape.
    js = CSRF_JS.read_text(encoding="utf-8")
    assert "csrf_invalid" in js
    assert "/login?redirect=" in js


def test_script_is_es5_safe():
    js = CSRF_JS.read_text(encoding="utf-8")
    for banned in ("=>", "const ", "let ", "`"):
        assert banned not in js, f"{banned!r} is not ES5-safe"


def test_middleware_renders_the_token_into_a_page_end_to_end():
    """The whole chain: cookie -> middleware -> ContextVar -> Jinja global -> tag.

    The other tests in this file only assert on source text. This one proves the
    wiring actually works, which is what the meta tag depends on. It renders the
    same guard expression base.html uses rather than base.html itself, since
    that template needs a large route context this test has no business building.
    """
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    from fastapi.testclient import TestClient

    from ion.core.csrf import derive_token
    from ion.web.csrf_middleware import CSRFMiddleware
    from ion.web.templating import make_templates

    tpl = make_templates().env.from_string(
        '{% if csrf_token %}<meta name="csrf-token" content="{{ csrf_token }}">{% endif %}'
    )

    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.get("/page")
    async def page():
        return HTMLResponse(tpl.render())

    client = TestClient(app, base_url="http://ion.test")

    # Anonymous: the guard suppresses the tag entirely.
    assert client.get("/page").text == ""

    # Authenticated: the tag carries exactly the derived token.
    client.cookies.set("ion_session", "sess-123")
    assert derive_token("sess-123") in client.get("/page").text
