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
    """If the build moves, this suite would pass by finding nothing.

    The canary was the literal string "14vh", which turned out to be alive by
    accident. `pt-[14vh]` appeared only inside a COMMENT in the deck's CSS;
    Tailwind's @source scan reads templates as plain text, so it emitted that
    utility because a comment mentioned it, and nothing ever used the class.
    When the CSS moved to frontend/ion-pages.css, an @import rather than a
    scanned source, the utility stopped being emitted and this control failed
    -- correctly, and for entirely the wrong reason.

    It now checks what has to hold for the test below to mean anything: the
    file exists, it is a real stylesheet rather than a stub or a failed
    build, and the deck does use arbitrary utilities worth checking.
    """
    assert _CSS.exists(), _CSS
    text = _css_text()
    assert len(text) > 100_000, (
        f"ion.css is only {len(text)} bytes, which is a stub or a failed "
        "build; every assertion below would pass by finding nothing"
    )
    assert "tailwindcss" in text[:200].lower(), \
        "ion.css does not look like a Tailwind build"
    assert _arbitrary_classes_used(), \
        "the deck uses no arbitrary utilities, so the next test is vacuous"


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
    # Was asserted against the template's own <style> block. The redesign's
    # `styled` column removed that block, so these rules live in
    # frontend/ion-pages.css now, scoped to this page. The requirement has not
    # changed: the geometry must be real CSS that always applies, never an
    # arbitrary utility that resolves to nothing when its value is absent
    # from the prebuilt sheet.
    page_css = (_ROOT / "frontend" / "ion-pages.css").read_text(encoding="utf-8")
    marker = "/* ── daily_standup_slides.html"
    assert marker in page_css, "the deck's chunk is missing from ion-pages.css"
    chunk = page_css.split(marker, 1)[1].split("/* ── ", 1)[0]

    for rule in (".deck-slide", ".deck-body", ".deck-tablebox"):
        assert rule in chunk, f"{rule} must be defined in the deck's page CSS"
    assert 'body[data-page="daily_standup_slides"]' in chunk, (
        "the deck's rules must be scoped to the page, or they reach every "
        "other page that happens to share a selector with it"
    )
    assert "padding" in chunk.split(".deck-slide")[1][:400], \
        ".deck-slide must set its own padding, not borrow pt-[..] from the build"
