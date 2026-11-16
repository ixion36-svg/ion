import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"
WRITE = re.compile(r"\binnerHTML\s*=")
STYLE = re.compile(r"^<style\b[^>]*>.*?</style>", re.S | re.M)


def test_write_pattern_has_positive_and_negative_controls():
    assert WRITE.search("board.innerHTML = '<div></div>'")
    assert not WRITE.search("board.textContent = 'Unavailable'")
    assert "\x08" not in WRITE.pattern
    assert STYLE.search('<style nonce="example">body {}</style>')
    assert not STYLE.search("{# The inline <style> block stays here. #}")


def test_board_uses_server_filters_without_prefetch_loop():
    source = PAGE.read_text(encoding="utf-8")
    assert "'/ui/cases/board'" in source
    assert "function filterCases(" not in source
    assert "function sortCases(" not in source
    assert "CASES_LOAD_CEILING" not in source
    assert "function renderCaseWidget(" not in source
    assert "let allCases = [];" in source
    assert "async function loadAllCases()" in source


def test_the_styles_and_the_date_formatters_have_gone():
    """This asserted the opposite, as that tranche's scope marker: the
    board conversion deliberately left the inline <style> block and the
    two client date formatters alone, and pinning them proved the tranche
    had not reached them.

    All three have since moved, and this test failing is how that was
    noticed. The page's 1,926 lines of CSS are in
    static/css/cases-page.css, and ageLabel and fmtDate went with their
    last callers, which render server-side now. Each read a naive UTC
    column through `new Date(iso)`, which the browser resolves in the
    viewer's zone.

    It pins the finished position instead, which is the stronger
    direction: a style block or a client date formatter coming back is a
    regression, where before either one merely marked work not yet done.
    """
    source = PAGE.read_text(encoding="utf-8")
    assert '<style nonce="{{ csp_nonce }}">' not in source
    assert not STYLE.search(source)
    assert "function ageLabel" not in source
    assert "fmtDate" not in source


def test_the_page_still_escapes_and_reads_back_quoted_attributes():
    """Not part of that move. `esc` is the page's attribute escaper and
    the `.innerHTML.replace` is a read rather than a write, so both are
    untouched by the CSS and formatter changes above."""
    source = PAGE.read_text(encoding="utf-8")
    assert "function esc(s)" in source
    assert '.innerHTML.replace(/"/g' in source
