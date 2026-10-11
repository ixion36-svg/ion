"""Render ION's header, and reduce it to comparable data.

Before the nav registry, a test checked the nav by reading base.html and
grepping for an href. That stopped working: the template now loops over
`nav_items` from `ion.web.nav`, so its source holds no destinations at
all. Seven test modules need the rendered header instead, which is why
this is a declared helper in the test package rather than a function
inside a script under tools/.

Every licence gate is open by default, so the full nav renders. A test
that wants a gate shut passes its own `nav_visible`:

    render(nav_visible=lambda item: item.gate != "workforce")

The globals mirror `ion.web.templating.make_templates()` without
importing it, on purpose. A pin that went through the app's template
factory would also depend on its config, its licence state and every
router it imports, and would then fail for reasons that have nothing to
do with the navigation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
_SRC = str(ROOT / "src")
if _SRC not in sys.path:
    # Needed when this is imported by a script rather than under pytest,
    # which supplies it via pythonpath = ["src"].
    sys.path.insert(0, _SRC)

TEMPLATE = "base.html"
TEMPLATES_DIR = ROOT / "src" / "ion" / "web" / "templates"


class _StubURL:
    def __init__(self, path: str) -> None:
        self.path = path


class StubRequest:
    """base.html reads only `request.url.path`, via `{% set p = ... %}`."""

    def __init__(self, path: str) -> None:
        self.url = _StubURL(path)


def env():
    """A Jinja environment holding exactly what base.html references."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    from ion.web import nav

    e = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        auto_reload=False,
    )
    e.globals.update(
        ion_version="0.0.0-pin",
        csp_nonce="PINNONCE",
        csrf_token="PINCSRF",
        nav_items=nav.NAV,
        nav_mobile_items=nav.mobile_items,
        nav_shortcuts=nav.shortcuts,
        nav_visible=lambda item: True,
    )
    return e


def render(path: str = "/", **globals_: Any) -> str:
    """base.html rendered for `path`, with any global overridden by keyword."""
    e = env()
    e.globals.update(globals_)
    return e.get_template(TEMPLATE).render(request=StubRequest(path))


# --------------------------------------------------------------------
# The pin. tools/nav_snapshot.py is a CLI over snapshot(); the logic
# lives here because tests/test_nav_parity.py is what depends on it.
# --------------------------------------------------------------------

# Paths to render. Every nav destination, plus sub-paths that exercise the
# prefix matching, plus the two routes reachable only by keyboard, plus a
# path that matches nothing so "no active item" is pinned too.
EXTRA_PATHS = [
    "/alerts/a1b2c3",
    "/alerts/a1b2c3/arkime",
    "/cases/CASE-2026-0001",
    "/audit-logs",
    "/shift-handover",
    "/threat-landscape",
    "/nothing-matches-this",
    # Exercises the only negative guard the old nav had,
    # `p.startswith('/alerts') and '/audit' not in p`. No registered route
    # satisfies both halves, so the guard was unreachable and dropping it
    # changed nothing the first version of this pin could see. Pinned
    # explicitly so its behaviour is recorded either way.
    "/alerts/audit",
]

def _slice(html: str, start: str, end: str) -> str:
    i = html.index(start)
    j = html.index(end, i)
    return html[i:j]


def _structure(html: str) -> dict[str, Any]:
    """The nav's shape, independent of whitespace and of which item is active."""
    nav = _slice(html, '<nav id="tw-nav"', "</nav>")
    items: list[dict[str, Any]] = []

    # Walk the nav in document order so ordering is pinned, not just membership.
    for m in re.finditer(
        r'<a href="(?P<href>/[^"]*)"[^>]*class="[^"]*tw-nav-link[^"]*"[^>]*>(?P<label>[^<]*)'
        r'|<button[^>]*tw-drop-btn[^>]*>(?P<group>[^<]*)',
        nav,
    ):
        if m.group("group") is not None:
            items.append({"kind": "group", "label": m.group("group").strip(), "items": []})
        else:
            entry = {"kind": "link", "href": m.group("href"), "label": m.group("label").strip()}
            items.append(entry)

    # Group children, in order, attached to the group that precedes them.
    for gm in re.finditer(r'<button[^>]*tw-drop-btn[^>]*>([^<]*).*?<div class="tw-drop-menu">(.*?)</div>', nav, re.S):
        label = gm.group(1).strip()
        kids = [
            {"href": h, "label": lab.strip()}
            for h, lab in re.findall(r'<a href="(/[^"]*)"[^>]*tw-drop-item[^>]*>([^<]*)', gm.group(2))
        ]
        for it in items:
            if it["kind"] == "group" and it["label"] == label and not it["items"]:
                it["items"] = kids
                break

    mobile_block = html[html.index('id="tw-mobile-panel"') :][:4000]
    mobile = [
        {"href": h, "label": lab.strip()}
        for h, lab in re.findall(r'<a href="(/[^"]*)"[^>]*>([^<]*)', mobile_block)
    ]

    routes = re.search(r"var routes = \{(.*?)\};", html)
    gkeys = dict(re.findall(r"(\w+):'(/[^']*)'", routes.group(1))) if routes else {}

    return {"top_level": items, "mobile": mobile, "gkeys": gkeys}


def _active(html: str) -> list[str]:
    """Every href whose element carries is-active, plus group labels that do."""
    nav = _slice(html, '<nav id="tw-nav"', "</nav>")
    out = []
    for m in re.finditer(r'<a href="(/[^"]*)"[^>]*class="([^"]*)"', nav):
        if "is-active" in m.group(2):
            out.append(m.group(1))
    for m in re.finditer(r'<button[^>]*class="([^"]*)"[^>]*>([^<]*)', nav):
        if "is-active" in m.group(1):
            out.append("group:" + m.group(2).strip())
    return sorted(set(out))


def snapshot() -> dict[str, Any]:
    first = render("/")
    structure = _structure(first)

    hrefs = [
        it["href"] for it in structure["top_level"] if it["kind"] == "link"
    ] + [k["href"] for it in structure["top_level"] if it["kind"] == "group" for k in it["items"]]

    paths = sorted(set(hrefs) | set(EXTRA_PATHS))
    active = {p: _active(render(p)) for p in paths}

    return {
        "note": "generated by tools/nav_snapshot.py; the nav registry must not change this",
        "structure": structure,
        "active_by_path": active,
    }
