"""The shell's light colours stay paired after the inline blocks move.

tools/ui_redesign_status.py only reads a template's own <style>. Moving
base.html's blocks into a sheet makes `light` pass for free, which is how
a white-on-white rule would ship. The classifier is run against the sheet.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "src/ion/web/templates"
CSS = ROOT / "src/ion/web/static/css"


def _status():
    spec = importlib.util.spec_from_file_location(
        "ui_redesign_status_shell", ROOT / "tools" / "ui_redesign_status.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rule(css: str, selector: str) -> str:
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for match in re.finditer(r"([^{}]+)\{([^}]*)\}", body):
        sels = [re.sub(r"\s+", " ", part.strip()) for part in match.group(1).split(",")]
        if selector in sels:
            return re.sub(r"\s+", "", match.group(2))
    raise AssertionError(selector)


def test_the_notepad_whites_carry_a_fill_and_light_mode_clears_it():
    """`.np-note-title` and `.np-title-input` are `color:#fff` with no fill.
    The panel behind them turns into `--bg-card` in light mode, so the white
    is the invisible case. A fill on the dark rule without a light-mode
    clear would leave a dark chip on that light panel.
    """
    css = (CSS / "ion-shell.css").read_text(encoding="utf-8")
    bad = _status()._invisible_light_rules(css)
    assert not any("np-note-title" in s or "np-title-input" in s for s in bad), bad

    title = _rule(css, ".np-note-title")
    field = _rule(css, ".np-title-input")
    assert "color:#fff" in title
    assert "color:#fff" in field
    assert "background:rgba(10,12,18,.95)" in title
    assert "background:rgba(10,12,18,.95)" in field
    # The search field is a different control and already has its own fill.
    # Repainting it is not this fix.
    assert "background:rgba(10,12,18,.95)" not in _rule(css, ".np-search")

    light = _rule(css, '[data-mode="light"] .np-note-title')
    assert "background:transparent" in light
    assert "#fff" not in light


def test_base_links_the_shell_and_no_longer_carries_a_style_block():
    page = (TPL / "base.html").read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="/static/css/ion-shell.css?v={{ ion_version }}">' in page
    # A comment names the tag HTMX must not inject. A block is the pair.
    assert not re.search(r"<style[^>]*>.*?</style>", page, re.S)
    # The link stays after ion-workspace, which is the last sheet the
    # inline blocks used to follow. Putting it in head_css would lose
    # ties to ion-workspace.
    assert page.index("ion-workspace.css") < page.index("ion-shell.css")


def test_login_moves_its_rules_and_still_overrides_the_page_min_height():
    page = (TPL / "login.html").read_text(encoding="utf-8")
    assert not re.search(r"<style[^>]*>.*?</style>", page, re.S)
    assert page.index("ion.css") < page.index("login-page.css")
    css = (CSS / "login-page.css").read_text(encoding="utf-8")
    assert "min-height:100vh" in _rule(css, ".ion-tw-page")
    assert "display:none" in _rule(css, "#error-message")
    shown = _rule(css, "#error-message.show")
    assert "display:flex" in shown
    assert "display:none" not in shown
