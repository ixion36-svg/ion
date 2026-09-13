"""Guards for the daisyUI responsive trim.

frontend/daisyui.css is vendored whole, and ~790KB of its 1.12MB is five
@media blocks holding every component again under an sm:/md:/lg:/xl:/2xl:
prefix -- 2,725 variants. tools/trim_daisyui.py rewrites those blocks to hold
only the ones ION uses, and the build imports the trimmed copy.

The failure this protects against is silent: add `md:card` to a template,
forget to regenerate, and the class simply does nothing at that breakpoint.
There is no error and no visual clue until someone resizes a window.
"""

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.trim_daisyui import OUT, SRC, wanted  # noqa: E402

BREAKPOINTS = ("sm", "md", "lg", "xl", "2xl")


def _generated(css: str) -> set[str]:
    out = set()
    for m in re.finditer(r"\.((?:\\32 )?[a-z0-9]{1,3})\\:([a-z0-9-]+)", css):
        out.add(m.group(1).replace("\\32 ", "2") + ":" + m.group(2))
    return {g for g in out if g.split(":")[0] in BREAKPOINTS}


def test_the_trimmed_dist_exists_and_is_smaller():
    assert OUT.is_file(), "run tools/trim_daisyui.py --write"
    assert OUT.stat().st_size < SRC.stat().st_size


def test_every_responsive_variant_the_app_uses_survived_the_trim():
    """The one invariant that matters. Everything else is bytes."""
    trimmed = OUT.read_text(encoding="utf-8")
    needed = wanted() & _generated(SRC.read_text(encoding="utf-8"))
    assert needed, "expected ION to use at least one responsive daisyUI variant"
    missing = sorted(n for n in needed if n not in _generated(trimmed))
    assert not missing, (
        f"{missing} used in markup but trimmed out of daisyui.trimmed.css; "
        "re-run tools/trim_daisyui.py --write"
    )


def test_the_build_imports_the_trimmed_copy_not_the_raw_dist():
    css = Path("frontend/tailwind-daisy.input.css").read_text(encoding="utf-8")
    assert '@import "./daisyui.trimmed.css";' in css
    assert '@import "./daisyui.css";' not in css


def test_the_trim_is_reproducible_from_the_vendored_dist():
    """Regenerating must be a no-op, or the committed copy is stale.

    Keeps the pristine dist as the single source of truth, so a daisyUI
    upgrade is a file swap plus a re-run rather than a merge.
    """
    before = OUT.read_bytes()
    subprocess.run([sys.executable, "tools/trim_daisyui.py", "--write"],
                   check=True, capture_output=True)
    assert OUT.read_bytes() == before, (
        "daisyui.trimmed.css is not what tools/trim_daisyui.py produces from "
        "daisyui.css -- it was hand-edited, or the source changed without a "
        "re-run"
    )


def test_the_untouched_utility_blocks_are_still_there():
    """The trim must not have reached daisyUI's responsive COLOUR utilities.

    Those live under `@media (width>=40rem)` rather than `...640px`, which is
    the only thing separating them from the component variants. If the px/rem
    distinction ever stops holding, sm:bg-base-100 and friends vanish.
    """
    trimmed = OUT.read_text(encoding="utf-8")
    for unit in ("40rem", "48rem", "64rem", "80rem", "96rem"):
        assert f"@media (width>={unit})" in trimmed, (
            f"the {unit} utility block was removed; the trim is only meant to "
            "touch px-based component-variant blocks"
        )
