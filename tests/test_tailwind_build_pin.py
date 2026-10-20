"""Guard that ion.css was built by the pinned Tailwind release.

Tailwind's minor releases change utility codegen: v4.2.2 emits
`calc(var(--spacing) * 0)` where v4.3.3 emits `0`, drops `.start`/`.end`,
and ships a different preflight font stack. A build from the wrong version
therefore rewrites most of the stylesheet while looking like an ordinary
diff, and nothing downstream notices.

frontend/TAILWIND_VERSION is the pin. The banner Tailwind writes into its
own output is what proves which toolchain produced the shipped file.

The toolchain is frontend/package.json plus its lockfile. It used to be a
gitignored frontend/tailwindcss.exe, which meant the two build tests below
skipped everywhere the binary was absent -- CI included, so they never ran
there at all. `npm ci` puts the CLI in node_modules/.bin, so they do now.
The binary is still accepted when a checkout has one.
"""

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = ROOT / "frontend" / "TAILWIND_VERSION"
BUILT = ROOT / "src" / "ion" / "web" / "static" / "css" / "ion.css"
NODE_BIN = ROOT / "frontend" / "node_modules" / ".bin"


def _toolchain() -> list[str] | None:
    """The pinned CLI, however this checkout has it. None when absent."""
    for name in ("tailwindcss.cmd", "tailwindcss"):
        candidate = NODE_BIN / name
        if candidate.exists():
            return [str(candidate)]
    legacy = ROOT / "frontend" / "tailwindcss.exe"
    if legacy.exists():
        return [str(legacy)]
    found = shutil.which("tailwindcss")
    return [found] if found else None


BINARY = _toolchain()

BANNER = re.compile(r"tailwindcss v(\d+\.\d+\.\d+)")
ANSI = re.compile(r"\[[0-9;]*m")


def _pinned() -> str:
    return PIN.read_text(encoding="utf-8").strip()


def test_pin_is_a_concrete_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+", _pinned())


def test_shipped_css_was_built_by_the_pinned_version():
    banner = BANNER.search(BUILT.read_text(encoding="utf-8")[:200])
    assert banner, "ion.css has no Tailwind banner -- was it hand-edited?"
    assert banner.group(1) == _pinned(), (
        f"ion.css was built by Tailwind {banner.group(1)} but the pin is {_pinned()}. Rebuild with the pinned binary, or move the pin deliberately and re-verify the cascade."
    )


def test_local_binary_matches_the_pin_when_present():
    """Skipped only where no toolchain is installed at all."""
    if BINARY is None:
        return
    out = subprocess.run(BINARY + ["--help"], capture_output=True, text=True, timeout=60).stdout
    found = BANNER.search(ANSI.sub("", out))
    assert found, "could not read a version from the local Tailwind CLI"
    assert found.group(1) == _pinned(), f"the installed Tailwind CLI is {found.group(1)}, pin is {_pinned()}. Building with it would rewrite ion.css."


def _selectors(css: str) -> set[str]:
    """Every class selector a sheet defines.

    Compared as a set rather than byte for byte, because Tailwind orders some
    output by first-seen and a reordering is not a missing rule.
    """
    return {m.group(1).replace("\\", "")
            for m in re.finditer(r"\.((?:\\.|[A-Za-z0-9_\-])+)", css)}


def test_shipped_css_is_up_to_date_with_the_templates():
    """A utility a template names but the sheet never defines does nothing.

    The pin above proves which binary built the sheet and says nothing about
    whether it was built since the templates last changed. It was not, and
    three utilities had no rule at all while templates were already using
    them: `whitespace-pre-line`, which `maturity_result`, `stories_editor`
    and `threat_intel_actor` rely on to preserve newlines in prose after
    those conversions stopped injecting `<br>`, plus `space-y-4` on
    `shift_handover_detail` and `m-10` on `daily_standup_slides`.

    Nothing caught it. Each of those conversions asserts the class is in its
    markup, which was true, and no test asked whether the class meant
    anything. It is the inverse of the premise the whole fragment conversion
    rests on: moving markup to the server does make it reachable from the
    stylesheet, but only once the stylesheet is rebuilt.

    Skipped only where no toolchain is installed, like the test above.
    """
    if BINARY is None:
        return
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "fresh.css"
        proc = subprocess.run(
            BINARY + ["-i", str(ROOT / "frontend" / "tailwind-daisy.input.css"),
                      "-o", str(fresh), "--minify"],
            capture_output=True, text=True, timeout=300, cwd=ROOT,
        )
        assert proc.returncode == 0, f"Tailwind build failed: {proc.stderr[-400:]}"
        missing = _selectors(fresh.read_text(encoding="utf-8")) - _selectors(
            BUILT.read_text(encoding="utf-8"))

    assert not missing, (
        "ion.css is missing rules a fresh build emits, so these utilities are "
        "named in a template or a scanned module and do nothing on the page: "
        f"{sorted(missing)[:20]}. Rebuild with: "
        "cd frontend && npm ci && npm run build:css"
    )
