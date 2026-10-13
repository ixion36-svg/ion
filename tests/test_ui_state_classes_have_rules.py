"""A state class the code applies that no stylesheet paints.

Twice in the UI redesign a control was wired correctly and did nothing
visible, because the class the JS toggled had no rule anywhere:
`.aq-facet.is-on` on the alerts queue, and a bare `.active` on
threat_intel. Neither is catchable by the obvious test. Asserting that the
class is applied passes: it *is* applied. The element simply looks the same
before and after, so the reader cannot tell which facet is on or which tab
they are reading.

This check reads the two halves and compares them:

  applied   every class name passed to classList.add or classList.toggle
            as a string literal, in ION's own JS and templates
  painted   every class name appearing in any selector, across
            static/css/*.css and the inline <style> blocks the templates
            still carry

A class in the first set and not the second is applied and paints nothing.

MARKERS ARE EXEMPT, AND HAVE TO BE

Not every class is for painting. chat.html does

    if (!row || row.classList.contains('submitted')) return;
    row.classList.add('submitted');

which is a guard against double submission, read back by the code that set
it. A class the code reads back through contains(), querySelector(),
closest() or getElementsByClassName() is state, not style, and wanting a
CSS rule for it would be wrong. Those are exempt, which is also why the
exemption is narrow: it is the read-back that earns it, not a naming
convention.

WHAT IT FOUND WHEN IT WAS WRITTEN

Three classes, of which two were defects:

  .im-tab-active   investigation_memory.html toggled it on DaisyUI .tab
                   buttons, whose stylesheet paints .tab-active. The
                   selected tab looked exactly like the other three.
  .mobile-open     app.js toggled it, with .open, inside toggleNavMenu.
                   No template defines #nav-links or #nav-hamburger and
                   nothing called the function. Dead.
  .submitted       the guard above, correctly unstyled.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src/ion/web/static"
TEMPLATES = ROOT / "src/ion/web/templates"

#: Any class name inside a selector. Deliberately loose: a class mentioned
#: anywhere in any selector counts as painted, because `.a .b`, `.a.b` and
#: `.a > .b` all style .b in some context and this check is not trying to
#: prove a rule applies, only that one exists.
CLASS_IN_CSS = re.compile(r"\.(-?[_a-zA-Z][\w-]*)")
STYLE_BLOCK = re.compile(r"<style[^>]*>(.*?)</style>", re.S | re.I)
APPLIED = re.compile(r"""classList\.(?:add|toggle)\(\s*['"]([^'"]+)['"]""")

#: Read back by the code that set it, so it is state rather than style.
READ_BACK = re.compile(
    r"""classList\.contains\(\s*['"]([^'"]+)['"]"""
    r"""|(?:querySelector|querySelectorAll|closest)\(\s*['"][^'"]*?\.([\w-]+)"""
    r"""|getElementsByClassName\(\s*['"]([^'"]+)['"]"""
)

#: Third-party bundles style themselves from CSS that does not live in
#: static/css, so their classes cannot be checked here.
VENDOR = re.compile(r"\.min\.js$|quill|vis-network|jsvectormap|topojson|htmx|chart",
                    re.I)


def own_sources() -> list[Path]:
    js = [f for f in sorted(STATIC.glob("js/*.js")) if not VENDOR.search(f.name)]
    return js + sorted(TEMPLATES.rglob("*.html"))


def painted() -> set[str]:
    names: set[str] = set()
    for f in sorted(STATIC.glob("css/*.css")):
        names |= set(CLASS_IN_CSS.findall(f.read_text(encoding="utf-8", errors="replace")))
    for f in sorted(TEMPLATES.rglob("*.html")):
        for block in STYLE_BLOCK.findall(f.read_text(encoding="utf-8", errors="replace")):
            names |= set(CLASS_IN_CSS.findall(block))
    return names


def applied_and_markers() -> tuple[dict[str, set[str]], set[str]]:
    where: dict[str, set[str]] = defaultdict(set)
    markers: set[str] = set()
    for f in own_sources():
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in APPLIED.finditer(text):
            for name in m.group(1).split():
                # 'sev-' + severity builds a name; the literal is a prefix
                if name.endswith("-") or "$" in name or "{" in name:
                    continue
                where[name].add(f.relative_to(ROOT).as_posix())
        for m in READ_BACK.finditer(text):
            markers |= {g for g in m.groups() if g}
    return where, markers


def test_the_stylesheets_are_readable_and_not_empty():
    """The comparison below is vacuous if either half comes back empty, and
    an empty `painted` set would report every class in the app as a defect
    rather than silently passing. Pin both ends."""
    names = painted()
    assert len(names) > 1000, f"only {len(names)} classes found in selectors"
    where, _ = applied_and_markers()
    assert len(where) > 20, f"only {len(where)} classes applied by classList"


def test_every_applied_state_class_has_a_rule_somewhere():
    where, markers = applied_and_markers()
    names = painted()
    missing = {c: sorted(fs) for c, fs in where.items()
               if c not in names and c not in markers}
    assert missing == {}, (
        "applied by classList and painted by nothing:\n"
        + "\n".join(f"  .{c}  in {', '.join(fs)}" for c, fs in sorted(missing.items()))
    )


def test_a_class_read_back_by_the_code_is_treated_as_a_marker():
    """The exemption is load-bearing, so it is pinned rather than assumed.
    chat.html's `submitted` guard is applied, read back with contains(), and
    rightly has no CSS rule."""
    _, markers = applied_and_markers()
    assert "submitted" in markers
    assert "submitted" not in painted()


def test_the_two_classes_this_check_was_written_for_are_painted_now():
    """`.aq-facet.is-on` and threat_intel's `.active` were each applied by
    correct code and styled by nothing. Both were fixed during the redesign,
    and this is the control that says the check would have seen them."""
    names = painted()
    assert "is-on" in names
    assert "active" in names
