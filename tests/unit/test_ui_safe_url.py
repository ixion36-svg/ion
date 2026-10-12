"""The `safe_url` filter, which is how a stored URL reaches an href.

Jinja escapes characters, not schemes. `href="{{ row.url }}"` with
`javascript:alert(1)` in that column renders a link that executes on click.
The hand-rolled `esc()` helpers the fragments replaced had the same hole, so
this is not a regression the conversion introduced, but moving these links
into shared templates is the moment to close it once.

Two fragments render a GitLab issue URL straight out of the database.
"""
from __future__ import annotations

import pytest

from ion.web.templating import _safe_url, make_templates


def render(value):
    env = make_templates().env
    return env.from_string('<a href="{{ v|safe_url }}">x</a>').render(v=value)


@pytest.mark.parametrize("url", [
    "https://gitlab.example/g/p/-/issues/4",
    "http://localhost:8010/x",
    "mailto:soc@example.com",
    "/cases/7",
    "docs/runbook",
])
def test_an_ordinary_link_passes_through(url):
    assert _safe_url(url) == url


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
])
def test_a_scheme_that_does_something_other_than_navigate_is_dropped(url):
    assert _safe_url(url) == ""


@pytest.mark.parametrize("url", [
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "\njavascript:alert(1)",
    "  javascript:alert(1)",
    "jav\x00ascript:alert(1)",
])
def test_whitespace_tricks_do_not_get_past_the_scheme_check(url):
    """A browser strips ASCII whitespace and control characters before
    reading the scheme, so a naive startswith check passes something the
    browser then executes."""
    assert _safe_url(url) == ""


def test_a_protocol_relative_url_is_dropped():
    """It is a valid URL, but it changes origin, which a stored link has no
    business doing. It also slipped through the first version of this
    filter: "//evil/x".split("/")[0] is the empty string, which contains no
    colon and so looked like an ordinary relative path."""
    assert _safe_url("//evil.example/x") == ""
    assert _safe_url("\t//evil.example/x") == ""


@pytest.mark.parametrize("empty", [None, "", 0])
def test_an_absent_url_gives_the_fallback(empty):
    assert _safe_url(empty) == ""
    assert _safe_url(empty, "-") == "-"


def test_the_filter_is_registered_and_still_escapes():
    """Dropping the scheme must not cost the escaping: both guards apply."""
    html = render('javascript:alert("x")')
    assert 'href=""' in html
    assert "alert" not in html


def test_a_passing_url_is_still_attribute_escaped():
    html = render('https://e.com/?a=1&b="2"')
    assert "&amp;" in html
    assert '&#34;' in html or "&quot;" in html
