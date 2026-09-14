"""Guard that ion.css was built by the pinned Tailwind release.

frontend/tailwindcss.exe is gitignored, so a clone has no toolchain and
whoever rebuilds uses whatever binary is on their box. Tailwind's minor
releases change utility codegen: v4.2.2 emits `calc(var(--spacing) * 0)`
where v4.3.3 emits `0`, drops `.start`/`.end`, and ships a different
preflight font stack. A build from the wrong binary therefore rewrites
most of the stylesheet while looking like an ordinary diff, and nothing
downstream notices.

frontend/TAILWIND_VERSION is the pin. The banner Tailwind writes into its
own output is what proves which binary produced the shipped file.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = ROOT / "frontend" / "TAILWIND_VERSION"
BUILT = ROOT / "src" / "ion" / "web" / "static" / "css" / "ion.css"
BINARY = ROOT / "frontend" / "tailwindcss.exe"

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
    """Skipped in CI, where the gitignored binary is absent."""
    if not BINARY.exists():
        return
    out = subprocess.run([str(BINARY), "--help"], capture_output=True, text=True, timeout=60).stdout
    found = BANNER.search(ANSI.sub("", out))
    assert found, "could not read a version from the local Tailwind binary"
    assert found.group(1) == _pinned(), f"frontend/tailwindcss.exe is {found.group(1)}, pin is {_pinned()}. Building with it would rewrite ion.css."
