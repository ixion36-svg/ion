"""/security-dashboard is the first page off its own stylesheet.

`security-dashboard-page.css` is deleted. Its severity and status badges now
resolve through `[data-sev]` / `[data-status]` in ion-value-scales.css, and
the geometry and the modal bridge moved to ion-pages.css under
`body[data-page="security_dashboard"]`. Both are compiled into ion.css, so
the page links no sheet of its own.

This re-asserts what `tests/test_ui_page_stylesheets_moved.py` guaranteed
while the sheet existed, plus the new failure the move introduces.

**A value the server emits with no row in the scale is invisible.** The old
stylesheet enumerated `.severity-critical`, `.status-new` and the rest beside
the markup that used them; the scale is now shared and somewhere else, so a
sixth status added to the enum would render an uncoloured chip and nothing
would say so. The enum is the source of truth and is asserted against the
sheet here, which is the check the old arrangement never had.

**The modal bridge changed how it wins.** It used to beat daisyUI by source
order, loading from head_css after ion.css. Inside ion.css it wins on
specificity instead: `body[data-page=...] .modal.active` is 0,3,1 against
daisyUI's 0,1,0. Drop the body prefix and the modal opens invisible, which is
the worst bug this project has had.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.security import (  # noqa: E402
    SecurityEventSeverity,
    SecurityEventStatus,
)

PAGE = ROOT / "src/ion/web/templates/security_dashboard.html"
FRAGMENT = ROOT / "src/ion/web/templates/_fragments/security_dashboard.html"
SCALES = ROOT / "frontend/ion-value-scales.css"
PAGES_CSS = ROOT / "frontend/ion-pages.css"
BUILT = ROOT / "src/ion/web/static/css/ion.css"
SCOPE = 'body[data-page="security_dashboard"]'


def _text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _without_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


# ------------------------------------------------------------ the sheet is gone

def test_the_page_stylesheet_is_deleted():
    assert not (ROOT / "src/ion/web/static/css/security-dashboard-page.css").exists()


def test_the_page_links_no_stylesheet_of_its_own():
    assert "security-dashboard-page.css" not in _text(PAGE)
    assert "{% block head_css %}" not in _text(PAGE), (
        "the page has no sheet to link; an empty head_css block is misleading"
    )


def test_the_page_declares_the_scope_its_rules_need():
    """Without page_id the body carries data-page="" and every rule moved to
    ion-pages.css matches nothing -- silently, because the page still renders."""
    assert "{% block page_id %}security_dashboard{% endblock %}" in _text(PAGE)


# --------------------------------------------- every emitted value has a colour

@pytest.mark.parametrize("member", list(SecurityEventSeverity))
def test_every_severity_the_enum_can_emit_has_a_row_in_the_scale(member):
    assert f'[data-sev="{member.value}"]' in _without_comments(_text(SCALES)), (
        f"SecurityEventSeverity.{member.name} renders an uncoloured chip"
    )


@pytest.mark.parametrize("member", list(SecurityEventStatus))
def test_every_status_the_enum_can_emit_has_a_row_in_the_scale(member):
    assert f'[data-status="{member.value}"]' in _without_comments(_text(SCALES)), (
        f"SecurityEventStatus.{member.name} renders an uncoloured chip"
    )


def test_every_threat_level_the_banner_can_set_has_a_row():
    """_LEVELS is the banner's own set and includes `normal`, which is not a
    SecurityEventSeverity member."""
    from ion.web.ui.security_dashboard import _LEVELS

    scales = _without_comments(_text(SCALES))
    missing = [lvl for lvl in sorted(_LEVELS)
               if f'[data-sev="{lvl}"]' not in scales]
    assert not missing, f"threat levels with no colour: {missing}"


def test_the_status_value_reaches_the_markup_with_its_underscore():
    """The old _badge() rewrote `false_positive` to `false-positive` to match a
    selector. The data attribute carries the enum value, so that rewrite is
    gone and must not come back."""
    assert 'data-status="{{ event.status or \'\' }}"' in _text(FRAGMENT)
    assert "status-false-positive" not in _text(FRAGMENT)


def test_the_view_model_no_longer_builds_badge_classes():
    source = (ROOT / "src/ion/web/ui/security_dashboard.py").read_text(encoding="utf-8")
    for gone in ("severity_class", "status_class", "def _badge("):
        assert gone not in source, f"{gone} survived the move to the scales"


# ------------------------------------------------------------ the chip's tiers

def test_the_chip_takes_its_density_from_the_region():
    """Comfortable by default, compact inside .ion-dense. A modifier class
    would have to be remembered at every call site; the region already knows."""
    css = _without_comments(_text(SCALES))
    assert re.search(r"\.v-chip\s*\{[^}]*font-size:\s*12px", css), (
        "the default chip is not the comfortable size"
    )
    assert re.search(r"\.ion-dense\s+\.v-chip\s*\{[^}]*font-size:\s*10\.5px", css), (
        "a chip inside a dense region does not compact, so a 500-row queue "
        "pays comfortable padding on every row"
    )


def test_severity_still_reads_as_a_rank_in_caps():
    """.severity-badge set text-transform:uppercase, so the page has always
    shown CRITICAL. The markup emits the lowercase enum value, so losing this
    rule quietly lowercases every severity on the page."""
    css = _without_comments(_text(SCALES))
    assert re.search(r"\.v-chip\[data-sev\]\s*\{[^}]*text-transform:\s*uppercase", css)
    assert "text-transform" not in re.search(
        r"\.v-chip\s*\{([^}]*)\}", css).group(1), (
        "a status is a phrase and is title-cased by the view model; "
        "uppercasing every chip would shout it too"
    )


# ------------------------------------------------- the rules that stayed, moved

@pytest.mark.parametrize("selector", [
    ".modal.active",
    ".modal.active > .modal-box",
    "#events-table th",
    ".matched-content",
    ".matched-content code",
])
def test_the_page_only_rules_moved_to_ion_pages_under_its_scope(selector):
    css = _without_comments(_text(PAGES_CSS))
    assert f"{SCOPE} {selector}" in css, (
        f"{selector} is not scoped to this page in ion-pages.css"
    )


def test_the_modal_bridge_still_outranks_daisyui():
    """It used to win by source order. Inside ion.css it wins on specificity,
    and only while it keeps the body[data-page] prefix."""
    css = _without_comments(_text(PAGES_CSS))
    bridge = re.search(r"([^\s{};]*\s*)\.modal\.active\s*\{", css)
    assert bridge, "the modal bridge is gone"
    assert SCOPE in bridge.group(0), (
        "the bridge lost its body[data-page] prefix, so at 0,1,1 it no longer "
        "beats daisyUI and the modal opens laid out but invisible"
    )


# ------------------------------------------------------- and it reaches the app

@pytest.mark.parametrize("needle", [
    '[data-sev="critical"]',
    '[data-status="false_positive"]',
    'body[data-page=security_dashboard] .modal.active',
])
def test_the_rules_are_in_the_shipped_stylesheet(needle):
    """ion.css is committed, so a source change that was never rebuilt ships
    nothing. The minifier drops the quotes from attribute selectors."""
    built = _text(BUILT)
    unquoted = needle.replace('"', "")
    assert needle in built or unquoted in built, (
        f"{needle} is not in the built ion.css -- rebuild with: "
        "cd frontend && npm run build:css"
    )
