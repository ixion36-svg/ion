"""The rewrite's stylesheet input must not silently drop light-mode support.

tailwind.input.css is 13KB of which only the first ~30 lines are tokens. The
rest is accumulated light-mode machinery: the ink-ramp flip, shell tokens, and
13 explicit patch selectors for utilities Tailwind bakes literally
(text-white, bg-white/5, border-white/5) which no CSS-variable override can
reach.

A clean-slate rewrite input that carries only the tokens regresses light mode
across the entire app, and does so silently — the page still renders, it is
just unreadable. A proof build on 2026-09-13 rendered accent text at roughly
1.6:1 contrast on white. This test is the guard.
"""

import re
from pathlib import Path

CURRENT = Path("frontend/tailwind.input.css")
REWRITE = Path("frontend/tailwind-daisy.input.css")
# The daisyUI slot mapping and collision fixes live here; the rewrite input
# @imports it. A test that reads only the input file misses everything in it.
THEME = Path("frontend/ion-daisy-theme.css")
BUILT = Path("src/ion/web/static/css/ion.css")


def _strip_comments(css: str) -> str:
    """Remove /* ... */ blocks.

    Both files discuss [data-mode="light"] in prose. Without this, the selector
    regex below matches inside a comment and runs on to the next real `{`,
    inventing a selector that was never dropped. That produced a false failure
    on the first run of this test.
    """
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _light_selectors(css: str) -> set[str]:
    """Every selector carrying a [data-mode="light"] qualifier."""
    return {
        m.group(0).strip()
        for m in re.finditer(r'\[data-mode="light"\][^{;}]*(?={)', _strip_comments(css))
    }


def test_rewrite_input_exists():
    assert REWRITE.is_file()


def test_rewrite_carries_a_light_mode_block():
    assert '[data-mode="light"]' in REWRITE.read_text(encoding="utf-8")


def test_rewrite_flips_the_ink_ramp_for_light_mode():
    """bg-ink-* utilities cascade off --color-ink-*; if those do not flip,
    every dark surface stays dark on a white page."""
    css = REWRITE.read_text(encoding="utf-8")
    light = css.split('[data-mode="light"]', 1)[1]
    for token in ("--color-ink-950", "--color-ink-900", "--color-ink-800",
                  "--color-ink-700", "--color-ink-600"):
        assert token in light, f"{token} is not flipped for light mode"


def test_rewrite_patches_every_literally_baked_utility_the_current_build_does():
    """Tailwind compiles text-white / bg-white/5 to literal values, so the
    variable flip cannot reach them. Each one the current build patches must
    still be patched, or it renders white-on-white."""
    current = _light_selectors(CURRENT.read_text(encoding="utf-8"))
    rewrite = _light_selectors(REWRITE.read_text(encoding="utf-8"))
    missing = current - rewrite
    assert not missing, f"light-mode patches dropped by the rewrite: {sorted(missing)}"


def test_rewrite_flips_the_ion_accent_ramp_for_light_mode():
    """A fix-forward, NOT a parity check — tailwind.input.css does not do this.

    The original left --color-ion-* at their dark-mode values in light mode, so
    text-ion-cyan rendered #6de4ff on a white page: measured 1.38:1, against
    WCAG AA's 4.5:1. ion-lime measured 1.31:1, ion-amber 1.70:1. `text-ion-*`
    appears 370 times across 70 of the 114 templates, so this was widespread
    rather than a corner case. After the flip the same three measured 4.50,
    5.03 and 4.13.

    Deliberately asserted only against the rewrite stylesheet. Applying it to
    tailwind.input.css would change every page in the current build, which is
    not this plan's scope.
    """
    css = REWRITE.read_text(encoding="utf-8")
    light = css.split('[data-mode="light"]', 1)[1]
    for token in ("--color-ion-cyan", "--color-ion-amber", "--color-ion-coral",
                  "--color-ion-lime", "--color-ion-iris"):
        assert token in light, (
            f"{token} is not flipped for light mode; text-{token[8:]} will render "
            "at roughly 1.3-1.7:1 contrast on a light surface"
        )


def test_rewrite_overrides_the_hardcoded_body_background():
    """style.css hardcodes body to #07080c. Without this override everything
    outside .ion-tw-page reads as dark on a light page."""
    css = REWRITE.read_text(encoding="utf-8")
    assert re.search(r'\[data-mode="light"\]\s+body', css)


def test_daisyui_loading_spinner_does_not_hijack_ion_loading_text():
    """daisyUI's `.loading` is a masked spinner; ION's is a text element.

    ION has used `class="loading"` as plain text since long before daisyUI —
    `<p class="loading">Loading...</p>` in 211 places across 54 templates.
    daisyUI 5 defines `.loading` as display:inline-block, width 1.5rem,
    aspect-ratio 1, background-color:currentColor and a spinner mask-image.

    Cascade layers do not save it: daisyUI's rule is in @layer daisyui and ION's
    is unlayered in style.css, so ION wins only for the four properties it
    declares (color, text-align, padding, font-size). The mask and the fill
    still apply. Measured before the fix: the element rendered 32px wide, grey
    filled, spinner-masked, with its text invisible — on all 114 pages, from the
    moment ion.css was added to base.html and regardless of any restyle.

    The :not([class*="loading-"]) guard keeps real spinners
    (`loading loading-spinner`) working.
    """
    css = THEME.read_text(encoding="utf-8")
    assert '.loading:not([class*="loading-"])' in css, (
        "the .loading reset is gone; 211 'Loading...' text elements across 54 "
        "templates will render as a masked spinner glyph with no visible text"
    )
    reset = css.split('.loading:not([class*="loading-"])', 1)[1].split("}", 1)[0]
    for prop in ("mask-image", "background-color", "width", "aspect-ratio"):
        assert prop in reset, f"the reset no longer neutralises {prop}"

    # And confirm it survived into the BUILT stylesheet. Having the rule in
    # source but not in ion.css would be the same bug with extra steps.
    if BUILT.is_file():
        built = BUILT.read_text(encoding="utf-8")
        assert 'loading:not([class*=loading-])' in built.replace('"', ''), (
            "the reset is in the source but missing from the built ion.css"
        )


def test_daisyui_border_width_token_does_not_collide_with_ions_border_colour():
    """daisyUI's `--border` is a WIDTH; ION's was a COLOUR. Same name.

    daisyUI 5 uses `--border` as its border-width token (`1px`). ION's
    style.css had used `--border` as a colour since long before, and 598
    declarations across seven stylesheets and 21 templates read it that way,
    as `border: 1px solid var(--border)`.

    Both are declared on an unlayered `:root`, and base.html loads ion.css
    (line 23) after style.css (line 9), so daisyUI won. `1px solid var(--border)`
    then resolved to `1px solid 1px`, which is not a valid shorthand, so the
    browser discarded the whole declaration. Measured: border-width computed to
    0px and border-style to none. The borders did not change colour, they
    disappeared -- on every page, from the moment ion.css entered base.html,
    with no error anywhere.

    Fixed by renaming ION's colour token to `--ion-border` and leaving
    daisyUI's width token alone. This guards the rename.
    """
    legacy = [
        Path("src/ion/web/static/css") / f
        for f in ("style.css", "design-system.css", "ai-chat.css",
                  "alert-detail.css", "ion-workspace.css", "ion-migrated-styles.css")
    ]
    templates = sorted(Path("src/ion/web/templates").rglob("*.html"))
    # --border exactly, not --border-bright or --border-color.
    bare = re.compile(r"(?<![-\w])--border(?![-\w])")
    offenders = [
        p.as_posix() for p in legacy + templates
        if p.is_file() and bare.search(p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert not offenders, (
        "these still use the bare --border token, which daisyUI defines as a "
        f"1px width; their borders will vanish: {offenders}"
    )
