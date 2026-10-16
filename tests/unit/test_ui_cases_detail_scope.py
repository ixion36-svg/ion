"""The converted lazy loaders delegate markup to protected fragments."""

import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "src/ion/web/templates/cases.html"
WRITE = re.compile(r"\binnerHTML\s*=")
NAMES = [
    "loadProcessTreeInto",
    "loadKibanaComments",
    "loadRuleGuideInto",
    "loadResponseActionLog",
    "loadAnnotations",
    "loadCaseSyncStatus",
    "loadResponseActions",
    "renderAnnotations",
    "translateCaseNote",
]


def function_pattern(name):
    return re.compile(r"^(?:async )?function " + re.escape(name) + r"\b[^\n]*\{(.*?)(?=^(?:async )?function |\Z)", re.S | re.M)


def test_patterns_have_positive_and_negative_controls():
    assert WRITE.search("node.innerHTML = markup;")
    assert not WRITE.search("node.textContent = 'Unavailable';")
    assert "\x08" not in WRITE.pattern
    pattern = function_pattern("loadPanel")
    assert pattern.search("function loadPanel() {node.textContent='ok';}\nfunction next() {}")
    assert not pattern.search("function otherPanel() {node.innerHTML='';}")


@pytest.mark.parametrize("name", NAMES)
def test_lazy_loader_no_longer_writes_markup(name):
    source = PAGE.read_text(encoding="utf-8")
    match = function_pattern(name).search(source)
    if match is None:
        assert name == "renderAnnotations"
        assert "renderAnnotations(" not in source
        return
    assert not WRITE.search(match.group(1)), name
