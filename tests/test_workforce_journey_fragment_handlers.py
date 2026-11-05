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

The fix was to capture the elements in variables while the fragment is
still populated, and close over those. The test is structural because
there is no JavaScript runner in this repo -- it enforces the rule that
caused the bug rather than the symptom.

Superseded by a stronger fix. /workforce is now served by
ion.web.ui.workforce_journey: the rows are rendered by Jinja and the forms
post to /ui/workforce/requirements/<id>/{submit,withdraw}, so the page has
no `<template>`, no cloneNode and no handlers. A deferred lookup into an
emptied fragment is not merely absent, it has nothing left to be deferred
into.

The two tests that pinned the old mechanism are rewritten rather than
deleted, because the GUARANTEES they bought still matter and only their
mechanism changed:

  * rows are not assembled in JavaScript here at all (was: they are built
    from a <template>, carefully)
  * the joiner's date and evidence reference still reach the server (was:
    the captured elements are still read in the submit handler)

The detector and the sweep over other templates are untouched, and still
guard any page that does clone a <template>.
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
_FRAGMENTS = _TEMPLATES / "_fragments"


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

    def test_the_page_builds_no_rows_in_javascript(self):
        """The bug needed a cloned fragment and a deferred handler. The
        page now has neither: the rows are rendered server-side.

        Asserted as an absence so the page cannot drift back. Returning to
        client-side row building would reopen the whole class, not just the
        one occurrence that was fixed.
        """
        source = _JOURNEY.read_text(encoding="utf-8")
        for mechanism in ("<template", "cloneNode", "addEventListener"):
            assert mechanism not in source, (
                f"workforce_journey.html has reintroduced {mechanism!r}. "
                "The rows are served by ion.web.ui.workforce_journey; "
                "building them in JavaScript here brings back the deferred "
                "fragment lookup this file exists to prevent."
            )

    def test_the_submitted_form_still_carries_date_and_evidence(self):
        """Whatever renders the form, it must still send both fields.

        This is the guarantee the old handler test bought, and it outlives
        the handler: an evidence reference dropped on the way to the server
        is verified by a lead as a blank record, which is the same bad
        outcome by a different route.
        """
        row = _FRAGMENTS / "_workforce_requirement.html"
        source = row.read_text(encoding="utf-8")
        assert "/submit" in source, "the row no longer posts a submission"
        assert 'name="completed_on"' in source
        assert 'name="evidence_ref"' in source


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
