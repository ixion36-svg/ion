"""Glass surfaces: dark mode only, switchable, and safe for sticky headers.

The glass sheet makes panel tokens translucent. A sticky header that takes
its background from one of those tokens then shows the rows scrolling
under it, which is what the alerts table did before it was listed. These
tests keep the list complete as page sheets gain sticky headers.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "src" / "ion" / "web"
CSS = WEB / "static" / "css"
GLASS = (CSS / "ion-glass.css").read_text(encoding="utf-8")
GATE = 'html[data-glass="on"][data-mode="dark"]'
TOKEN_BG = re.compile(r"background(?:-color)?\s*:\s*var\(--(bg-|ion-surface|color-base-)")


def _rules(text: str):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    depth, start, sel = 0, 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                sel = text[start:i].strip()
                body_start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                yield sel, text[body_start:i]
                start = i + 1


def test_every_glass_rule_is_gated_on_dark_mode_and_the_switch():
    """Light mode and the Solid setting must render exactly as before."""
    for selector, body in _rules(GLASS):
        if selector.startswith("@media"):
            inner = [s for s, _ in _rules(body)]
            assert all(s.startswith(GATE) for s in inner), inner
            continue
        if selector.startswith(".glass-btn"):
            continue
        for part in selector.split(",\n"):
            assert part.strip().startswith(GATE), part


def test_every_token_backed_sticky_header_is_frosted():
    frosted = GLASS[GLASS.index("Sticky headers"):]
    frosted = frosted[:frosted.index("}")]
    missing = []
    for sheet in sorted(CSS.glob("*.css")):
        if sheet.name in {"ion.css", "ion-glass.css"}:
            continue
        for selector, body in _rules(sheet.read_text(encoding="utf-8", errors="ignore")):
            if not re.search(r"position\s*:\s*sticky", body) or not TOKEN_BG.search(body):
                continue
            for part in selector.split(","):
                tokens = part.split()
                # A bare element (`th`) is named by its parent (`table.aq th`).
                key = tokens[-1] if any(c in tokens[-1] for c in ".#") else " ".join(tokens[-2:])
                if not re.search(r"(^|[\s,(])" + re.escape(key) + r"(?=[\s,)])", frosted):
                    missing.append(f"{sheet.name}: {part.strip()}")
    assert not missing, "add these sticky headers to ion-glass.css: " + "; ".join(missing)


def test_the_page_loads_the_glass_sheet_after_every_page_sheet():
    base = (WEB / "templates" / "base.html").read_text(encoding="utf-8")
    assert base.index("ion-glass.css") > base.index("ion-shell.css") > base.index("{% block head_css %}")


def test_glass_is_on_unless_switched_off():
    init = (WEB / "static" / "js" / "theme-init.js").read_text(encoding="utf-8")
    assert "localStorage.getItem('ion-glass') || 'on'" in init
    assert "setAttribute('data-glass', glass)" in init
    profile = (WEB / "templates" / "profile.html").read_text(encoding="utf-8")
    assert 'data-click-action="setGlass" data-args=\'["off"]\'' in profile
    assert "function setGlass(value)" in profile
