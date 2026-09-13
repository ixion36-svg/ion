"""Regressions for tools/dead_css.py's reference scanner.

Every test here is a case where the scanner failed to SEE a class that markup
genuinely carries. That direction is the dangerous one: a class the scanner
misses is reported dead, and `--write` deletes its rule. There is no error and
no failing test when that happens -- the styling simply goes, on whichever page
nobody opened that week.

All three were found the same way, by checking the tool's own output against a
plain boundary-grep of the source rather than trusting it.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.dead_css import literal_tokens  # noqa: E402


def test_sees_a_class_beside_a_template_literal_interpolation():
    """`class="a b${x}"` was skipped whole: the value pattern banned braces.

    alerts-queue.js builds nearly every cell this way, so aq-caseref, aq-ghead,
    aq-kev and aq-sev-pill all read as dead at once.
    """
    src = """h += `<span class="aq-tag aq-kev${ransom ? ' is-ransomware' : ''}"`"""
    assert "aq-tag" in literal_tokens(src)
    assert "aq-kev" in literal_tokens(src)


def test_sees_a_class_written_inside_the_interpolation():
    """The conditional half of a ternary is a real class on a real element.

    Cutting `${...}` out before splitting loses `aq-closed`, which appears
    nowhere else in the app.
    """
    src = """`<div class="aq-ghead sev-${esc(g.sev || '')}${shut ? ' aq-closed' : ''}">`"""
    toks = literal_tokens(src)
    assert "aq-ghead" in toks
    assert "aq-closed" in toks


def test_an_empty_string_does_not_put_the_quote_scan_out_of_phase():
    """`''` must consume both its quotes or every later quote pairs wrongly.

    Requiring at least one character meant the scan resumed from the first of
    the two, pairing `', cls: '` as a string and dropping `aq-act` into the gap
    between two matches.
    """
    src = "{ k: 'act', label: '', cls: 'aq-act', on: true, fixed: true }"
    assert "aq-act" in literal_tokens(src)


def test_sees_a_class_beside_a_jinja_expression():
    """Templates interpolate into class attributes as routinely as JS does."""
    src = '<div class="card bg-base-200 sr-role sr-c-{{ r.color }}">'
    toks = literal_tokens(src)
    assert "card" in toks
    assert "sr-role" in toks


def test_a_nested_brace_in_an_interpolation_fails_towards_live():
    """The one case still not parsed must skip the attribute, not mis-split it.

    Skipping means the classes are not collected from THIS attribute, so the
    tool can only under-report liveness elsewhere -- never invent a token that
    makes something look reachable when it is not.
    """
    src = '<div class="wrap ${xs.map(x => `${x}`)} tail">'
    toks = literal_tokens(src)
    # Whatever it does, it must not emit a fragment of expression code as a
    # class name that could shadow a real one.
    assert not any(re.search(r"[(){}$`]", t) for t in toks)
