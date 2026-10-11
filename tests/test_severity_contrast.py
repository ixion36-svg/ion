"""Every severity badge must be readable, in both modes, by measurement.

ION states severity in colour, so a severity nobody can read is a product
defect rather than a styling preference. Nothing checked it, and on
2026-10-12 all five badges failed in light mode:

    level      dark   light
    critical   4.49    2.63
    high       5.48    2.12
    medium     5.46    2.13
    low        5.42    2.12
    info       5.42    2.13

Cause: `frontend/ion-legacy.css` has a `[data-mode="light"]` block with
144 overrides in the file and not one of them touched `--sev-*`, so the
dark ramp was carried onto a white page. Critical also missed in dark
mode, by 0.01.

This recomputes from the stylesheet on every run. It does not read the
comments next to those values, and it does not trust a number recorded in
a commit message. Change a token and this says whether the change is
readable.

Geometry, which is what makes the naive check wrong: a badge is
`background: var(--sev-X-dim); color: var(--sev-X)`, and the dim token is
the same hue at low alpha. The text therefore sits on a tint of itself
over the page, not on the page. Measuring against bare white or bare
#0d1114 overstates contrast in dark mode and understates it in light.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = Path(__file__).resolve().parent.parent / "frontend" / "ion-legacy.css"

LEVELS = ("critical", "high", "medium", "low", "info")

# The page the badge sits on in each mode. Dark from the root block,
# light from the --bg-primary the light block sets.
SURFACE = {"dark": "#0d1114", "light": "#ffffff"}

TEXT_MIN = 4.5   # WCAG AA, normal-size text
SOLID_MIN = 3.0  # WCAG AA, non-text such as a stripe or bar


def _lin(c: float) -> float:
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _lum(rgb: tuple[float, float, float]) -> float:
    r, g, b = (_lin(c / 255) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _ratio(a: tuple, b: tuple) -> float:
    la, lb = _lum(a), _lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _over(fg: tuple, alpha: float, bg: tuple) -> tuple:
    return tuple(fg[i] * alpha + bg[i] * (1 - alpha) for i in range(3))


def _hex(h: str) -> tuple[int, int, int]:
    h = h.strip().lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _rgba(v: str) -> tuple[tuple[int, int, int], float]:
    m = re.match(r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)", v.strip())
    assert m, f"not an rgba() value: {v!r}"
    return (int(m[1]), int(m[2]), int(m[3])), float(m[4])


def _block(css: str, mode: str) -> str:
    """The declarations of the root block (dark) or the light-mode block.

    The dark selector is a multi-line list, `:root,\\n[data-theme="cyan"]
    {`, so the opening brace is not adjacent to `:root`. A single-line
    pattern misses it and reports no block at all, which is how the first
    version of this test failed. Matching to the next brace also records
    the real structure: the base tokens are on `:root`, so selecting a
    non-cyan theme does not lose them.
    """
    anchor = '[data-mode="light"]' if mode == "light" else ":root"
    i = css.index(anchor)
    start = css.index("{", i) + 1
    return css[start:css.index("\n}", start)]


def _tokens(mode: str) -> dict[str, str]:
    block = _block(CSS.read_text(encoding="utf-8"), mode)
    return {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"--(sev-[\w-]+)\s*:\s*([^;]+);", block)
    }


@pytest.fixture(scope="module")
def ramp() -> dict[str, dict[str, str]]:
    return {mode: _tokens(mode) for mode in SURFACE}


def test_both_modes_define_the_whole_ramp(ramp):
    """A level missing from light mode silently inherits the dark value,
    which is exactly how this defect arrived."""
    for mode, toks in ramp.items():
        missing = [
            f"--sev-{lvl}{suffix}"
            for lvl in LEVELS
            for suffix in ("", "-dim")
            if f"sev-{lvl}{suffix}" not in toks
        ]
        assert not missing, f"{mode} mode does not define: {missing}"


@pytest.mark.parametrize("mode", sorted(SURFACE))
@pytest.mark.parametrize("level", LEVELS)
def test_badge_text_is_readable_on_its_own_tint(ramp, mode, level):
    toks = ramp[mode]
    fg = _hex(toks[f"sev-{level}"])
    tint_rgb, alpha = _rgba(toks[f"sev-{level}-dim"])
    bg = _over(tint_rgb, alpha, _hex(SURFACE[mode]))
    got = _ratio(fg, bg)
    assert got >= TEXT_MIN, (
        f"{mode} mode: .sev-{level} text {toks[f'sev-{level}']} on its own "
        f"{alpha} tint over {SURFACE[mode]} is {got:.2f}:1, under {TEXT_MIN}. "
        f"Darken the colour in light mode, or weaken the tint alpha."
    )


@pytest.mark.parametrize("mode", sorted(SURFACE))
@pytest.mark.parametrize("level", LEVELS)
def test_solid_colour_works_as_a_stripe(ramp, mode, level):
    """`.sev-stripe-*::before` paints the solid colour against the page."""
    toks = ramp[mode]
    got = _ratio(_hex(toks[f"sev-{level}"]), _hex(SURFACE[mode]))
    assert got >= SOLID_MIN, (
        f"{mode} mode: solid .sev-stripe-{level} {toks[f'sev-{level}']} on "
        f"{SURFACE[mode]} is {got:.2f}:1, under {SOLID_MIN}"
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect, recorded rather than fixed here. high #f0883e, medium "
        "#d29922 and info #bc8cff sit within 0.002 relative luminance of each "
        "other, so orange, yellow and purple are the same lightness and differ "
        "by hue alone. Separating them means changing brand colours, which is a "
        "design decision and not part of a contrast fix. strict=True so this "
        "fails loudly the day someone does fix it, forcing the marker off."
    ),
)
@pytest.mark.parametrize("mode", sorted(SURFACE))
def test_levels_are_distinguishable_from_each_other(ramp, mode):
    """Severity is ordered, so two levels that look alike lose the order.

    Not a WCAG rule. A colour-blind analyst reading a queue needs adjacent
    levels to differ in lightness, not only in hue.
    """
    toks = ramp[mode]
    lums = {lvl: _lum(_hex(toks[f"sev-{lvl}"])) for lvl in LEVELS}
    too_close = [
        (a, b, round(abs(lums[a] - lums[b]), 4))
        for i, a in enumerate(LEVELS)
        for b in LEVELS[i + 1:]
        if abs(lums[a] - lums[b]) < 0.01
    ]
    assert not too_close, (
        f"{mode} mode: these severity pairs are within 0.01 relative "
        f"luminance, so they differ by hue alone: {too_close}"
    )
