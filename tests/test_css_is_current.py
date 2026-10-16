"""Guard that ion.css is current with the inputs it is built from.

tests/test_tailwind_build_pin.py already guards WHICH binary produced
ion.css. Nothing guarded WHEN. Those are different failures, and the
second one is silent.

ion.css is compiled with `@source` over the templates, the static JS and
the Python, so Tailwind emits a rule only for a class it can see written
somewhere. Add a class to a template without rebuilding and the class
does nothing. The markup reads correctly, the rule never existed, and no
error is raised anywhere. Delete the last use of a class without
rebuilding and its rule is shipped to every visitor for ever.

Measured on 2026-10-12, before this guard existed: the committed ion.css
was 2,766 bytes larger than a fresh build from the same inputs. It
carried 55 rules for classes nothing writes any more, and was missing 21
that templates write today. 13 of 16 sampled were confirmed used but
absent, so they silently did nothing, concentrated on the workforce
pages: `lg:grid-cols-[1fr_300px]` and `min-w-fit` on the ORBAT layout,
`h-0.5` and `h-2.5` on the journey progress bars, `cursor-not-allowed`
on its disabled controls, `pt-[12vh]` on the standup slides.

The build is deterministic. Two runs from identical inputs are
byte-identical, so equality is the right assertion and the fix for a
failure is always the same: rebuild and commit the result.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "frontend" / "tailwindcss.exe"
INPUT = ROOT / "frontend" / "tailwind-daisy.input.css"
BUILT = ROOT / "src" / "ion" / "web" / "static" / "css" / "ion.css"

REBUILD_HINT = (
    "cd frontend && ./tailwindcss.exe -i ./tailwind-daisy.input.css "
    "-o ../src/ion/web/static/css/ion.css --minify"
)


def _selectors(css: str) -> set[str]:
    out: set[str] = set()
    for m in re.finditer(r"([^{}]+)\{", css):
        for sel in m.group(1).split(","):
            sel = sel.strip()
            if sel and not sel.startswith("@"):
                out.add(sel)
    return out


@pytest.fixture(scope="module")
def rebuilt() -> str:
    """A fresh build from the committed inputs.

    Skips rather than fails when the gitignored toolchain is absent, the
    same way test_tailwind_build_pin.py does, so a clone without the
    binary is not reported as a stale stylesheet.
    """
    if not BINARY.exists():
        pytest.skip(f"{BINARY.name} is gitignored and absent; cannot rebuild to compare")
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "rebuilt.css"
        proc = subprocess.run(
            [str(BINARY), "-i", str(INPUT), "-o", str(out), "--minify"],
            capture_output=True,
            text=True,
            cwd=str(ROOT / "frontend"),
        )
        assert proc.returncode == 0, f"tailwind build failed:\n{proc.stdout}\n{proc.stderr}"
        return out.read_text(encoding="utf-8")


def test_committed_css_matches_a_fresh_build(rebuilt: str):
    """The whole invariant. Everything below only explains a failure here."""
    committed = BUILT.read_text(encoding="utf-8")
    if committed == rebuilt:
        return

    have, want = _selectors(committed), _selectors(rebuilt)
    missing = sorted(want - have)
    stale = sorted(have - want)

    detail = [
        f"ion.css is {len(committed) - len(rebuilt):+d} bytes against a fresh build.",
        f"  {len(missing)} selector(s) the inputs need but ion.css lacks "
        f"(these classes currently do NOTHING):",
    ]
    detail += [f"      {s}" for s in missing[:12]]
    if len(missing) > 12:
        detail.append(f"      ... and {len(missing) - 12} more")
    detail.append(f"  {len(stale)} selector(s) ion.css ships that nothing writes any more:")
    detail += [f"      {s}" for s in stale[:8]]
    if len(stale) > 8:
        detail.append(f"      ... and {len(stale) - 8} more")
    detail.append(f"  fix: {REBUILD_HINT}")

    pytest.fail("\n".join(detail))


def test_no_class_the_templates_write_is_missing_from_the_css(rebuilt: str):
    """The half of the failure that is a live bug, asserted on its own.

    A stale rule is waste. A missing rule is a defect, because the author
    wrote a class and got nothing. Separated so a failure says which of
    the two happened without reading a diff.
    """
    missing = sorted(_selectors(rebuilt) - _selectors(BUILT.read_text(encoding="utf-8")))
    assert not missing, (
        f"{len(missing)} class(es) are written in the source but absent from ion.css, "
        f"so they render nothing: {missing[:12]}"
        + (f" ... and {len(missing) - 12} more" if len(missing) > 12 else "")
        + f"\nfix: {REBUILD_HINT}"
    )
