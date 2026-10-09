"""Arbitrary Tailwind utilities in the slide deck must exist in the build.

ION serves a prebuilt ion.css. Tailwind arbitrary values like
``pt-[14vh]`` only work if that exact class was compiled into it; a new
one resolves to nothing at all.

It fails silently, which is the problem. Changing ``pt-[14vh]`` to
``pt-[12vh]`` on the slide shell did not shift the padding slightly --
it set it to zero, dropping the slide title behind the ION header on
the one screen a room full of people is reading. Nothing errored,
nothing logged, and the class name still looked right in the template.

So: every arbitrary utility this deck uses has to be present in the
compiled stylesheet, and anything load-bearing for layout belongs in
the template's own <style> block instead, where it always applies.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE = (_ROOT / "src" / "ion" / "web" / "templates"
             / "daily_standup_slides.html")
_CSS = _ROOT / "src" / "ion" / "web" / "static" / "css" / "ion.css"

#: class="..." / className strings only -- not CSS inside <style>.
_CLASS_ATTR = re.compile(r'class="([^"]*)"')
#: Tailwind arbitrary utility: prefix-[value], e.g. pt-[14vh].
_ARBITRARY = re.compile(r'(?<![\w:-])((?:[a-z]+-)+\[[^\]\s"]+\])')


def _arbitrary_classes_used() -> set[str]:
    html = _TEMPLATE.read_text(encoding="utf-8")
    # Drop the <style> block: real CSS in there is not a Tailwind class.
    html = re.sub(r"<style.*?</style>", "", html, flags=re.S)
    found: set[str] = set()
    for attr in _CLASS_ATTR.findall(html):
        for token in attr.split():
            if _ARBITRARY.fullmatch(token):
                found.add(token)
    return found


def _css_text() -> str:
    return _CSS.read_text(encoding="utf-8", errors="replace")


def _css_unescaped() -> str:
    r"""The stylesheet with CSS escapes removed.

    Tailwind escapes every character a selector cannot hold literally,
    so ``bg-[rgba(148,163,184,0.12)]`` compiles to
    ``.bg-\[rgba\(148\,163\,184\,0\.12\)\]``. Stripping backslashes
    turns that back into the class name as written in the template,
    which makes a plain substring test correct for all of them --
    escaping them by hand only covered the brackets and reported two
    dozen working classes as missing.
    """
    return _css_text().replace("\\", "")


def test_the_stylesheet_is_where_we_think_it_is():
    """If the build moves, this suite would pass by finding nothing."""
    assert _CSS.exists(), _CSS
    assert "14vh" in _css_text(), \
        "ion.css does not contain the deck's known-good utilities"


def test_every_arbitrary_utility_is_in_the_compiled_css():
    css = _css_unescaped()
    used = _arbitrary_classes_used()
    assert used, "parser found no arbitrary utilities - it has broken"

    missing = sorted(cls for cls in used if cls not in css)
    assert missing == [], (
        "These arbitrary Tailwind classes are not in the compiled "
        "ion.css, so they do nothing at all: "
        f"{missing}. Either reuse a value already in the build, or put "
        "the rule in the template's own <style> block."
    )


def test_layout_critical_geometry_is_not_a_tailwind_arbitrary_value():
    """The slide box's own padding and flex sizing must be real CSS.

    These are the rules that, when they silently vanish, put the title
    under the header or a table under the footer controls.
    """
    html = _TEMPLATE.read_text(encoding="utf-8")
    style = "\n".join(re.findall(r"<style.*?>(.*?)</style>", html, flags=re.S))
    for rule in (".deck-slide", ".deck-body", ".deck-tablebox"):
        assert rule in style, f"{rule} must be defined in the <style> block"
    assert "padding" in style.split(".deck-slide")[1][:400], \
        ".deck-slide must set its own padding, not borrow pt-[..] from the build"
