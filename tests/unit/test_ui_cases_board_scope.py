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


def test_styles_and_later_formatters_stay_in_place():
    source = PAGE.read_text(encoding="utf-8")
    assert '<style nonce="{{ csp_nonce }}">' in source
    assert "function esc(s)" in source
    assert "function ageLabel(dateStr)" in source
    assert "function fmtDate(dateStr)" in source
    assert '.innerHTML.replace(/"/g' in source
