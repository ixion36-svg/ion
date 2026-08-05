"""Dead-CSS sweep — the v0.31.21 inline-style migration.

That migration hashed inline styles into static CSS classes. Where the style was
a JS template literal (`style="width:${pct}%"`) it emitted a STATIC rule holding
the literal `${pct}`:

    ._ion-s-95aea49e0e { width:${pct}%; }

which is invalid CSS. Browsers drop the bad declaration, so the dynamic part
silently never applied — progress bars had no width, severity text no colour,
collapsible panels no display toggle. 125 rules across 29 templates, unnoticed
for roughly 40 releases.

The fix returns the dynamic declarations to the element as `data-ion-style`
(where `${...}` interpolates normally again) and applies them at runtime via
`el.style.setProperty` — CSP-safe, since that is a DOM write rather than an
inline `style=` attribute.

These tests stop it coming back.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = Path("src/ion/web/static/css/ion-migrated-styles.css")
APPLIER = Path("src/ion/web/static/js/ion-dynamic-styles.js")
TPL = Path("src/ion/web/templates")
STATIC = Path("src/ion/web/static")


def _frontend_files():
    for d in (TPL, STATIC):
        for f in d.rglob("*"):
            if f.suffix.lower() in (".html", ".js"):
                yield f


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


# ── the defect itself ────────────────────────────────────────────────────


def test_no_template_literals_survive_in_the_stylesheet():
    """A `${...}` in a CSS declaration is invalid — the browser drops it, so the
    style silently never applies. Comments may still mention the old classes."""
    body = _strip_comments(CSS.read_text(encoding="utf-8"))
    offenders = [ln.strip() for ln in body.splitlines() if "${" in ln]
    assert not offenders, (
        f"{len(offenders)} dead migrated rule(s) reintroduced — move the dynamic "
        f"declaration to data-ion-style instead: {offenders[:3]}"
    )


def test_static_declarations_were_preserved_not_deleted():
    """Rules that mixed static and dynamic declarations had to keep the static
    part — those DO apply today, and dropping them would be a visual regression."""
    css = CSS.read_text(encoding="utf-8")
    # a known mixed rule: the alerts outcome badge kept padding/border/font
    assert "_ion-s-e78d4016b2" in css
    m = re.search(r"\._ion-s-e78d4016b2\s*\{([^}]*)\}", css)
    assert m, "the mixed rule should still exist for its static declarations"
    body = m.group(1)
    for prop in ("padding", "border-radius", "font-size", "font-weight"):
        assert prop in body, f"static {prop} was lost in the sweep"
    assert "${" not in body


# ── the runtime applier ──────────────────────────────────────────────────


def test_applier_exists_and_is_csp_safe():
    raw = APPLIER.read_text(encoding="utf-8")
    # Assert against CODE, not prose — the file's header comment discusses
    # innerHTML and cssText when explaining why neither is used.
    code = re.sub(r"/\*.*?\*/", "", raw, flags=re.S)
    code = re.sub(r"//[^\n]*", "", code)

    # setProperty is a DOM write — no inline style attribute, so no unsafe-inline
    assert "setProperty(" in code
    assert "cssText" not in code, "cssText assignment would be a blunt injection sink"
    assert "innerHTML" not in code
    # must cover dynamically rendered markup, not just first paint
    assert "MutationObserver" in code


def test_applier_is_loaded_where_it_is_needed():
    base = (TPL / "base.html").read_text(encoding="utf-8")
    assert "ion-dynamic-styles.js" in base
    # wallboard is standalone — it does not extend base.html
    wall = (TPL / "wallboard.html").read_text(encoding="utf-8")
    assert "{% extends" not in wall.split("\n")[0], "assumption: wallboard is standalone"
    assert "ion-dynamic-styles.js" in wall, "standalone pages need it loaded directly"


# ── the call sites ───────────────────────────────────────────────────────


def test_call_sites_were_actually_rewritten():
    total = sum(
        f.read_text(encoding="utf-8", errors="replace").count("data-ion-style")
        for f in _frontend_files()
    )
    assert total >= 100, f"expected the sweep to rewrite ~144 call sites, found {total}"


def test_no_quote_nesting_broke_an_attribute():
    """The dynamic value goes inside an HTML attribute; the same quote character
    appearing inside it would terminate the attribute early."""
    bad = []
    for f in _frontend_files():
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in re.finditer(r'data-ion-style=(["\'])(.*?)\1', line):
                if m.group(1) in m.group(2):
                    bad.append(f"{f.name}:{i}")
    assert not bad, f"quote nesting would truncate the attribute at: {bad[:5]}"


def test_every_referenced_migrated_class_still_exists():
    """A class kept at a call site must still be defined, or its static styling
    is gone too."""
    css = CSS.read_text(encoding="utf-8")
    defined = set(re.findall(r"\.(_ion-s-[a-f0-9]{6,})", css))
    referenced = set()
    for f in _frontend_files():
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'class\s*=\s*(["\'])(.*?)\1', text, re.S):
            referenced |= {
                c for c in m.group(2).split() if re.fullmatch(r"_ion-s-[a-f0-9]{6,}", c)
            }
    dangling = sorted(referenced - defined)
    assert not dangling, f"class kept at a call site but no longer defined: {dangling}"


@pytest.mark.parametrize("tpl", ["analytics.html", "alerts.html", "training.html",
                                 "detection_engineering.html", "integrations.html"])
def test_heaviest_templates_have_no_dead_class_left(tpl):
    """The five templates that carried the most dead rules.

    v0.74.0: topology.html was merged into integrations.html (route audit
    phase 7e) — its markup, CSS and JS moved wholesale, so the assertion
    follows the content to its new home rather than being dropped.
    """
    text = (TPL / tpl).read_text(encoding="utf-8")
    css_body = _strip_comments(CSS.read_text(encoding="utf-8"))
    dead_classes = set(re.findall(r"\.(_ion-s-[a-f0-9]{6,})\s*\{[^}]*\$\{", css_body))
    used_dead = [c for c in dead_classes if c in text]
    assert not used_dead, f"{tpl} still uses dead rule(s): {used_dead}"
