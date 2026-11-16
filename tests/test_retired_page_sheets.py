"""Pages that no longer link a stylesheet of their own.

`tests/test_ui_page_stylesheets_moved.py` guards the pages that still have
one. As each is retired its entry leaves that registry and arrives here, so
the two together always account for every page: a page in neither is a page
nobody is checking.

The failure this file exists for is specific to the destination. A rule in
`frontend/ion-pages.css` is scoped `body[data-page="<id>"]`, and the scope
comes from `{% block page_id %}` in the template. Those two are written in
different files, nothing links them, and if they disagree the selector
matches nothing -- the page still renders, just unstyled in that one
respect, which is the quietest way this project has broken itself before.

The rules are asserted against the authored source rather than the shipped
`ion.css`, because the build minifies the selectors; `test_tailwind_build_pin`
is what proves the shipped sheet was built from this source.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "src/ion/web/templates"
CSS = ROOT / "src/ion/web/static/css"
PAGES_CSS = ROOT / "frontend/ion-pages.css"

#: page_id -> (template stem, the sheet it used to link, load-bearing
#: selectors carried over verbatim from that sheet's registry entry)
RETIRED = {
    "security_dashboard": (
        "security_dashboard",
        "security-dashboard-page.css",
        (
            ".modal.active",                       # modal bridge: JS toggles .active
            "#events-table th",
            ".matched-content code",
        ),
    ),
    "maturity": (
        "maturity",
        "maturity-page.css",
        (".mat-title",),                           # beats daisyUI .input on specificity
    ),
    "data_flow": (
        "data_flow",
        "data-flow-page.css",
        (".df-winlog-row .df-event-id",),          # ties with .val, wins on order
    ),
    "scheduler": (
        "scheduler",
        "scheduler-page.css",
        (
            "#sch-modal-bg.show",                  # modal bridge: JS toggles .show
            "#sch-exec-bg.show",
            ".sch-card.ok",
            ".sch-grid",                           # auto-fit grid, no daisyUI token
        ),
    ),
    "alert_arkime": (
        "alert_arkime",
        "alert-arkime-page.css",
        (
            ".arkime-commit .mode-new",            # the radio that drives the switch
            ".arkime-commit .mode-bar label",
            ".arkime-commit .mode-new:checked ~ .commit-fields .commit-existing",
        ),
    ),
    "templates": (
        "templates",
        "templates-page.css",
        (
            "#folders-modal.modal",                # modal bridge: JS sets display:flex
            ".folder-item.active",
            "#templates-list > .card",
            "#templates-list .tag",
        ),
    ),
    "template_view": (
        "template_view",
        "template-view-page.css",
        (
            ".tabs-border > .tab.content-tab-btn.active",  # .active, not .tab-active
            "#version-modal.modal",
            ".sv-card",
            ".checkpoint-badge",
            ".diff-view .diff-add",
        ),
    ),
    "documents": (
        "documents",
        "documents-page.css",
        (
            ".doc-row",
            ".doc-row-archived",
            ".doc-unmeasured",                     # a figure the payload lacked
            ".doc-filter-notice",                  # a filter that could not be honoured
        ),
    ),
    "gitlab": (
        "gitlab",
        "gitlab-page.css",
        (
            '#create-issue-modal[style*="flex"]',  # modal bridge: JS sets display:flex
            ".connection-status.connected",        # banner state from the fragment
            "#issues-list .loading",               # the word, not daisyUI's spinner
            ".issue-state.opened",
            "#issue-labels",                       # native multi-select, not .select
        ),
    ),
    "network_topology": (
        "network_topology",
        "network-topology-page.css",
        (
            "#nt-unconfigured.hidden",             # state the fragment sets
            "#nt-range-tabs .nt-seg-btn.active",   # .active, not daisyUI .tab-active
            "#nt-canvas",
        ),
    ),
    "arkime_traffic": (
        "arkime_traffic",
        "arkime-traffic.css",
        (
            ".atf-busy",
            "#atf-talkers .ip-cell",
            ".atf-hunt-done",                      # run state, server-rendered
        ),
    ),
    "pcap": (
        "pcap",
        "pcap-page.css",
        (
            ".pcap-tab.active",                    # .active, not daisyUI .tab-active
            ".pcap-panel.active",
            ".triage-chip.selected",
            ".finding-card.hidden",                # a filter state, not a utility
        ),
    ),
    "discover": (
        "discover",
        "discover-page.css",
        (
            ".modal-dialog",                       # the page's own overlay, not daisyUI
            ".modal-close",
            ".health-green",                       # connection state from the server
        ),
    ),
    "forensics": (
        "forensics",
        "forensics-page.css",
        (
            ".fr-tab.active",                      # .active, not daisyUI .tab-active
            ".ioc-chip.selected",
            ".modal-body",
        ),
    ),
    "alerts": (
        "alerts",
        "alerts-queue.css",
        (
            "table.aq tbody tr.aq-cur td",         # keyboard cursor row
            "table.aq tbody tr.aq-picked td",      # multi-select state
            "tr.sv-critical td",                   # severity row tint
        ),
    ),
    "daily_standup": (
        "daily_standup",
        "ds-standup.css",
        (
            ".ds-sev-critical",                    # severity, server-rendered
            ".ds-sev-high",
        ),
    ),
    "playbooks": (
        "playbooks",
        "playbooks-page.css",
        (
            ".exec-status.completed",              # run state from the fragment
            ".exec-status.failed",
            ".exec-step-item.done",
        ),
    ),
    "threat_intel": (
        "threat_intel",
        "threat-intel.css",
        (
            ".ti-empty",                           # the no-results sentence
            ".ti-table",
            ".ti-btn-watch",                       # watchlist state
            ".ti-spinner",
        ),
    ),
    "threat_intel_actor": (
        "threat_intel_actor",
        "threat-intel.css",
        (
            ".ti-detail-row",                      # the actor results table
            ".ti-name-cell",
        ),
    ),
    "observables": ("observables", "observables-page.css",
                    (".co-occur-badge", ".context-badge")),
    "analytics": ("analytics", "analytics-page.css",
                  (".an-absent", ".an-breakdown-title")),
    "integrations": ("integrations", "integrations-page.css",
                     (".cluster-status", ".copy-field")),
    "settings": ("settings", "settings-page.css",
                 (".backup-item", ".backup-meta")),
    "chat": ("chat", "chat-page.css",
             (".ai-brand-icon", ".ai-grounding")),
    "cases": ("cases", "cases-page.css",
              (".age-bar-seg", ".analytics-card")),
    "login": ("login", "login-page.css", ()),
    "wallboard": ("wallboard", "wallboard-page.css",
                  (".wb-att-critical", ".wb-panel-critical")),
}


#: Pages that retired one sheet but still link another. The moved rules are
#: pinned like any other; only the "links nothing of its own" claim is held
#: back until the page's last sheet goes.
PARTIAL = {"alerts"}

#: threat_intel_actor never linked a sheet. It is registered because
#: the scope now reaches it: /ui/threat-intel/actors renders ti-* markup
#: into that page, and nothing painted it before.
NEVER_LINKED = {"threat_intel_actor"}

#: Standalone pages. They do not extend base.html, so they have no
#: page_id block; the scope is a data-page attribute on <body>.
STANDALONE = {"login", "wallboard"}


def _page(stem: str) -> str:
    return (TPL / f"{stem}.html").read_text(encoding="utf-8")


def _pages_css() -> str:
    return re.sub(r"/\*.*?\*/", "", PAGES_CSS.read_text(encoding="utf-8"), flags=re.S)


def _scope_block(css: str, page_id: str) -> str:
    """The body of a `body[data-page="x"] { ... }` wrapper, or "".

    A sheet moved verbatim is nested inside one of these and the build
    flattens it; a sheet moved rule by rule is prefixed instead. Both forms
    are in this file, so the selector check has to know about both.
    """
    opener = f'body[data-page="{page_id}"] {{'
    start = css.find(opener)
    if start == -1:
        # A sheet shared by two pages opens with a grouped selector:
        #   body[data-page="a"],
        #   body[data-page="b"] {
        # The build compiles that to :is(a, b) <selector>, which reaches
        # both; find the brace that closes the group's selector list.
        m = re.search(r'body\[data-page="' + re.escape(page_id) + r'"\]\s*(?:,[^{]*)?\{', css)
        if not m:
            return ""
        start, opener = m.start(), m.group(0)
    i = start + len(opener)
    depth = 1
    while i < len(css) and depth:
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
        i += 1
    return css[start + len(opener):i - 1]


@pytest.mark.parametrize("page_id", sorted(RETIRED))
def test_the_old_sheet_is_gone(page_id):
    _, sheet, _ = RETIRED[page_id]
    assert not (CSS / sheet).exists(), f"{sheet} is back"


@pytest.mark.parametrize("page_id", sorted(RETIRED))
def test_the_page_links_no_stylesheet_of_its_own(page_id):
    stem, sheet, _ = RETIRED[page_id]
    page = _page(stem)
    if page_id in PARTIAL:
        assert sheet not in page, f"{sheet} is retired but still linked"
        return
    assert sheet not in page
    assert "{% block head_css %}" not in page, (
        "an empty head_css block says the page has a sheet when it does not"
    )


@pytest.mark.parametrize("page_id", sorted(RETIRED))
def test_the_template_declares_the_scope_its_rules_are_written_against(page_id):
    """The scope and the selector live in different files. If they disagree
    the rules match nothing and the page renders unstyled without an error."""
    stem = RETIRED[page_id][0]
    if page_id in STANDALONE:
        assert f'data-page="{page_id}"' in _page(stem), (
            f"{stem}.html is standalone; its <body> must carry the scope"
        )
        return
    assert f"{{% block page_id %}}{page_id}{{% endblock %}}" in _page(stem), (
        f"{stem}.html does not declare page_id {page_id!r}, so every "
        f'body[data-page="{page_id}"] rule in ion-pages.css is dead'
    )


@pytest.mark.parametrize("page_id,selector", [
    (pid, sel) for pid, (_, _, sels) in sorted(RETIRED.items()) for sel in sels
])
def test_each_load_bearing_rule_survived_the_move(page_id, selector):
    css = _pages_css()
    prefixed = f'body[data-page="{page_id}"] {selector}' in css
    nested = selector in _scope_block(css, page_id)
    assert prefixed or nested, (
        f"{selector} is not scoped to {page_id} in ion-pages.css, in either "
        "the prefixed or the nested form. It was pinned because only the "
        "server emits it, so no state-class or dead-CSS check would notice "
        "it going missing."
    )


def test_a_retired_sheet_never_reappears_in_the_other_registry():
    """The two registries are disjoint by construction. A page in both would
    be asserted to link a sheet and to have none, and whichever test ran
    second would be the one believed.

    This does not claim every page sheet on disk is registered: that registry
    covers only the seven whose inline <style> block moved out in October,
    and fourteen older sheets predate it.
    """
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_ui_page_stylesheets_moved import PAGES as STILL_LINKED

    overlap = set(RETIRED) & set(STILL_LINKED)
    assert not overlap, f"registered as both linked and retired: {sorted(overlap)}"

    for page_id, (_, sheet, _) in RETIRED.items():
        assert sheet not in {s for s, _ in STILL_LINKED.values()}, (
            f"{sheet} is retired but still listed as linked"
        )


def test_every_scope_with_rules_is_declared_by_some_template():
    """The whole-file invariant, not just the retired pages.

    A rule in ion-pages.css is addressed to body[data-page="x"]. If no
    template ever sets that x, the rule matches nothing and the page still
    renders -- unstyled in that one respect, with no error anywhere. This
    is the cheapest guard against that, and it covers pages that were never
    retired as well as the ones that were.
    """
    pages_css = PAGES_CSS.read_text(encoding="utf-8")
    scopes = sorted(set(re.findall(r'body\[data-page="([a-z_]+)"\]', pages_css)))
    assert scopes, "no scoped rules found at all -- has the file moved?"

    declared = set()
    for p in TPL.glob("*.html"):
        t = p.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"\{%\s*block page_id\s*%\}([a-z_]+)\{%\s*endblock\s*%\}", t):
            declared.add(m.group(1))
        for m in re.finditer(r'<body[^>]*data-page="([a-z_]+)"', t):
            declared.add(m.group(1))

    orphans = sorted(set(scopes) - declared)
    assert not orphans, (
        f"rules are scoped to pages nothing declares: {orphans}. Either the "
        "page_id block is missing, or it disagrees with the scope the rules "
        "were written against."
    )


#: Selectors a page scope shares with a global sheet that base.html links
#: AFTER ion.css. Each is safe only because the body[data-page] prefix adds
#: 0,1,1 and so outranks the unprefixed rule that now loads later. Before
#: the flattening these pages won on source order instead, from head_css.
KNOWN_LATE_SHEET_CLASHES = {
    "alert-detail.css": {"cases": {".caf-key", ".caf-val"}},
}

#: Linked by base.html after ion.css, so their rules now come second.
LOADS_AFTER_ION = ("ion-migrated-styles.css", "alert-detail.css",
                   "ion-workspace.css", "ion-shell.css")


def _selectors(text: str) -> set[str]:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    out, depth, head = set(), 0, ""
    for ch in text:
        if ch == "{":
            if depth == 0:
                for s in head.split(","):
                    s = " ".join(s.split())
                    if s and not s.startswith("@") and not s.endswith("%"):
                        out.add(s)
                head = ""
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            head += ch
    return out


def test_no_new_clash_with_a_sheet_that_now_loads_after_the_build():
    """A page sheet used to load from head_css, after ion-migrated-styles
    and alert-detail. Its rules are inside ion.css now, which base.html
    links BEFORE both, so a shared selector has swapped from winning on
    order to depending on the scope prefix for its specificity.

    That holds today for the one clash there is, checked in a browser. The
    point of this test is the next one: a new shared selector should be a
    decision, not a silent restyle.
    """
    src = PAGES_CSS.read_text(encoding="utf-8")
    scopes = sorted(set(re.findall(r'body\[data-page="([a-z_]+)"\]', src)))

    found: dict[str, dict[str, set[str]]] = {}
    for name in LOADS_AFTER_ION:
        theirs = _selectors((CSS / name).read_text(encoding="utf-8", errors="replace"))
        for scope in scopes:
            m = re.search(r'body\[data-page="' + scope + r'"\]\s*(?:,[^{]*)?\{', src)
            if not m:
                continue
            i, depth = m.end(), 1
            while depth:
                if src[i] == "{":
                    depth += 1
                elif src[i] == "}":
                    depth -= 1
                i += 1
            shared = _selectors(src[m.end():i - 1]) & theirs
            if shared:
                found.setdefault(name, {})[scope] = shared

    assert found == KNOWN_LATE_SHEET_CLASHES, (
        "the set of selectors a page shares with a later-loading global sheet "
        f"changed.\n  expected: {KNOWN_LATE_SHEET_CLASHES}\n  found:    {found}\n"
        "Each one only still wins because of its body[data-page] prefix. "
        "Check the new one in a browser before adding it here."
    )


def test_a_hoisted_keyframe_never_shadows_a_different_one():
    """@keyframes cannot be nested, so every page's animations were hoisted
    out of its scope and are global. A later block with the same name
    replaces an earlier one outright, whatever the specificity and whatever
    page it came from.

    Two names are declared twice -- slideIn by observables and alerts, spin
    by integrations and settings -- and both pairs are identical, so which
    one wins does not matter. The moment they differ, one page's animation
    silently becomes the other's.

    This also covers the global sheets base.html links, where the same
    collision already happened once: chat-page.css declared typingBounce at
    opacity 0.4 and ai-chat.css declares it at 0.5, so hoisting chat's copy
    changed the widget on every page. It is chatTypingBounce now.
    """
    def blocks(text: str) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for m in re.finditer(r"@keyframes\s+([A-Za-z0-9_-]+)\s*\{", text):
            i, depth = m.end(), 1
            while depth:
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                i += 1
            found.setdefault(m.group(1), []).append(
                " ".join(text[m.end():i - 1].split()))
        return found

    ours = blocks(PAGES_CSS.read_text(encoding="utf-8"))
    diverged = {n: v for n, v in ours.items() if len(set(v)) > 1}
    assert not diverged, (
        f"the same keyframe name is declared differently by two pages: "
        f"{sorted(diverged)}. One page's animation is silently the other's."
    )

    for name in ("ai-chat.css", "alert-detail.css", "ion-workspace.css",
                 "ion-shell.css", "ion-migrated-styles.css"):
        theirs = blocks((CSS / name).read_text(encoding="utf-8", errors="replace"))
        clash = sorted(
            n for n in set(ours) & set(theirs)
            if set(ours[n]) != set(theirs[n])
        )
        assert not clash, (
            f"{name} declares {clash} differently, and base.html links it on "
            "every page. A hoisted copy replaces it everywhere -- rename the "
            "page's keyframes instead."
        )
