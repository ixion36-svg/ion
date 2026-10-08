"""An element lookup inside an event handler must not query a fragment.

Demonstrated live, 8 October 2026. A joiner opened their own onboarding,
filled in the evidence reference for the first mandatory item, pressed
"Mark complete" and nothing happened. The console said::

    Uncaught TypeError: Cannot set properties of null (setting 'disabled')
        at HTMLButtonElement.<anonymous> (/workforce:965)

``reqRow`` builds each row from a ``<template>``::

    const node = document.getElementById('wf-req-row').content.cloneNode(true);
    const f = function (n) { return node.querySelector('[data-f="' + n + '"]'); };

``node`` is a DocumentFragment. Appending it MOVES its children into the
list and leaves the fragment empty, so ``f`` works while the row is being
built and returns ``null`` from that moment on. Every deferred handler
that called ``f`` was therefore dead:

    f('submit').addEventListener('click', function () {
        f('submit').disabled = true;        <- null by now
        api('POST', ... , {
          completed_on: f('date').value,    <- null
          evidence_ref: f('evidence').value <- null
        })

The listener was attached to the real element, so the click arrived; the
first line of the handler threw before the request was sent. Nothing was
submitted, no error was shown, and the row stayed "To do".

That is the whole self-service onboarding dead at the first action, and it
is invisible: no failed request in the network tab, no message on screen,
just a button that does nothing.

The fix is to capture the elements in variables while the fragment is
still populated, and close over those. The test is structural because
there is no JavaScript runner in this repo -- it enforces the rule that
caused the bug rather than the symptom.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_TEMPLATES = (
    Path(__file__).resolve().parent.parent
    / "src" / "ion" / "web" / "templates"
)
_JOURNEY = _TEMPLATES / "workforce_journey.html"


def _handler_bodies(source: str):
    """Every addEventListener callback body, roughly.

    Brace-matched from the callback's opening brace so a nested block does
    not end the body early.
    """
    out = []
    for m in re.finditer(r"addEventListener\([^,]+,\s*function\s*\([^)]*\)\s*\{",
                         source):
        i = m.end() - 1
        depth = 0
        for j in range(i, len(source)):
            if source[j] == "{":
                depth += 1
            elif source[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.start(), source[i:j + 1]))
                    break
    return out


class TestTheFragmentLookupBug:
    def test_no_handler_queries_the_cloned_fragment(self):
        """`f(...)` resolves against the DocumentFragment, which is empty
        once the row has been appended."""
        source = _JOURNEY.read_text(encoding="utf-8")
        offenders = []
        for start, body in _handler_bodies(source):
            if re.search(r"\bf\(\s*['\"]", body):
                line = source[:start].count("\n") + 1
                offenders.append(f"line {line}: {body.strip()[:90]}")
        assert not offenders, (
            "These handlers call f(...) after the fragment has been "
            "appended, so the lookup returns null and the handler throws "
            "on its first line:\n  " + "\n  ".join(offenders)
        )

    def test_the_rows_are_still_built_from_a_template(self):
        """The fix is to capture elements, not to abandon templates."""
        source = _JOURNEY.read_text(encoding="utf-8")
        assert "wf-req-row" in source
        assert "cloneNode(true)" in source

    def test_the_submit_handler_still_sends_the_evidence(self):
        """Capturing the elements must not quietly drop the fields the
        joiner filled in -- an empty evidence reference would verify as a
        blank record."""
        source = _JOURNEY.read_text(encoding="utf-8")
        block = source.split("/submit'")[1][:400]
        assert "completed_on" in block
        assert "evidence_ref" in block


class TestTheCheckItself:
    """A guard that cannot detect the bug it guards is worse than none."""

    def test_it_spots_a_handler_that_calls_f(self):
        bad = "x.addEventListener('click', function () { f('submit').disabled = true; });"
        assert any(re.search(r"\bf\(\s*['\"]", b) for _, b in _handler_bodies(bad))

    def test_it_ignores_a_handler_that_uses_a_captured_variable(self):
        good = "x.addEventListener('click', function () { submitBtn.disabled = true; });"
        assert not any(re.search(r"\bf\(\s*['\"]", b) for _, b in _handler_bodies(good))

    def test_it_does_not_end_the_body_at_a_nested_brace(self):
        nested = (
            "x.addEventListener('click', function () { "
            "if (a) { b(); } f('late'); });"
        )
        bodies = _handler_bodies(nested)
        assert bodies and re.search(r"\bf\(\s*['\"]", bodies[0][1])


class TestOtherTemplates:
    """The pattern is only in this one file today; keep it that way."""

    @pytest.mark.parametrize(
        "path",
        [p for p in sorted(_TEMPLATES.glob("*.html"))
         if "cloneNode" in p.read_text(encoding="utf-8")],
        ids=lambda p: p.name,
    )
    def test_no_template_defers_a_fragment_lookup(self, path):
        source = path.read_text(encoding="utf-8")
        if "content.cloneNode" not in source:
            pytest.skip("not a <template> clone")
        offenders = [
            body.strip()[:80] for _, body in _handler_bodies(source)
            if re.search(r"\bf\(\s*['\"]", body)
        ]
        assert not offenders, (
            f"{path.name} defers a fragment lookup into a handler: "
            f"{offenders}"
        )
