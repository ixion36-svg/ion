"""No ION-authored markup may carry an inline event handler.

Found on the running estate, 8 October 2026. Opening Settings -> Integration
Wizard and pressing "Get Started" did nothing at all. The console said::

    Executing inline event handler violates the following Content Security
    Policy directive 'script-src-attr 'none''.

ION sets ``script-src-attr 'none'`` itself, in
``SecurityHeadersMiddleware`` (src/ion/web/server.py). Every ``onclick=``
the browser finds is therefore refused. The wizard renders perfectly and
every one of its 27 buttons is inert: close, get started, select, skip,
test connection, save all. ``ai-chat.js`` was in the same state, so the
assistant panel could not be opened, cleared, or sent to.

Nothing errors on page load, which is why this survived. The markup is
valid, the functions exist, the network tab is clean. The feature is simply
dead on click, and the only evidence is a console line nobody reads unless
they already suspect something.

The migration to ``data-click-action`` delegation (static/js/event-
delegation.js) did almost all of this: of ION's own JavaScript and
templates, only these two files were missed. A guard is worth more than the
fix, because the next inline handler someone adds will fail exactly as
quietly.

Scope: ION-authored JavaScript and templates. Vendored bundles are excluded
-- ION does not control their source, and a library writing handlers into
its own DOM is that library's problem, not a regression anyone here can
introduce.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_WEB = Path(__file__).resolve().parent.parent / "src" / "ion" / "web"
_JS = _WEB / "static" / "js"
_TEMPLATES = _WEB / "templates"

#: Third-party bundles. ION neither wrote nor can fix their internals, and
#: they do not emit ION's markup.
_VENDOR = {
    "plotly.min.js", "vis-network.min.js", "html2pdf.bundle.min.js",
    "htmx.min.js", "marked.min.js", "purify.min.js", "mermaid.min.js",
    "quill.js", "chart.min.js", "lucide.min.js",
    # Vendored but not minified, so the `.min.js` shorthand misses them.
    # jsvectormap-world.js is the library's world geodata, not code ION
    # maintains.
    "jsvectormap-world.js", "topojson-client.min.js",
}

#: The dispatcher itself documents the very pattern it replaces, in prose
#: and in example markup. Exempt by name rather than by cleverness, so the
#: exemption is visible.
_DISPATCHER = "event-delegation.js"

#: An inline handler *attribute*, not a JavaScript property assignment.
#:
#: `sel.onchange = function () {...}` is a DOM property set from script and
#: CSP has no opinion about it -- only `script-src-attr` applies, and that
#: governs attributes in markup. So the lookbehind rejects anything reached
#: through a dot or sitting inside a longer identifier, and the value must
#: open with a quote immediately, which is how an attribute is written and
#: how an assignment to a function or an arrow is not.
_HANDLER = re.compile(
    r"(?<![.\w$-])on(?:click|change|input|submit|keydown|keyup|keypress|"
    r"blur|focus|mouseover|mouseout|mouseenter|mouseleave|dblclick|"
    r"contextmenu|dragstart|dragend|dragover|dragenter|dragleave|drop|"
    r"error|load)"
    r"\s*=\s*[\"']",
    re.IGNORECASE,
)

_LINE_COMMENT = re.compile(r"(?<![:'\"])//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _strip_comments(text: str, *, html: bool) -> str:
    """Blank out comments, preserving line numbering.

    Comments are where the migration *describes* the pattern it removed --
    "replaces inline onclick=..." -- and flagging those would train people
    to delete the explanation rather than keep the fix.
    """
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))

    if html:
        text = _HTML_COMMENT.sub(blank, text)
        text = _JINJA_COMMENT.sub(blank, text)
    text = _BLOCK_COMMENT.sub(blank, text)
    text = _LINE_COMMENT.sub(blank, text)
    return text


def _offenders(path: Path, *, html: bool):
    stripped = _strip_comments(path.read_text(encoding="utf-8"), html=html)
    hits = []
    for n, line in enumerate(stripped.splitlines(), 1):
        if _HANDLER.search(line):
            hits.append((n, line.strip()[:110]))
    return hits


def _ion_js():
    return [
        p for p in sorted(_JS.glob("*.js"))
        if p.name not in _VENDOR and p.name != _DISPATCHER
    ]


def _ion_templates():
    return sorted(_TEMPLATES.glob("*.html"))


# -- The files that were found broken -------------------------------------


class TestTheFilesThatWereFound:
    def test_the_integration_wizard_has_no_inline_handlers(self):
        """Settings -> Integration Wizard: every button was inert."""
        hits = _offenders(_JS / "integration-wizard.js", html=False)
        assert not hits, (
            "integration-wizard.js still has inline handlers, which CSP "
            "blocks:\n"
            + "\n".join(f"  line {n}: {t}" for n, t in hits)
        )

    def test_the_ai_chat_panel_has_no_inline_handlers(self):
        hits = _offenders(_JS / "ai-chat.js", html=False)
        assert not hits, (
            "ai-chat.js still has inline handlers, which CSP blocks:\n"
            + "\n".join(f"  line {n}: {t}" for n, t in hits)
        )


# -- The guard that stops the next one ------------------------------------


class TestNoInlineHandlersAnywhere:
    @pytest.mark.parametrize(
        "path", _ion_js(), ids=lambda p: p.name)
    def test_ion_javascript_is_clean(self, path):
        hits = _offenders(path, html=False)
        assert not hits, (
            f"{path.name} emits markup with inline event handlers. ION sets "
            f"script-src-attr 'none', so these never fire. Use "
            f"data-click-action (see static/js/event-delegation.js):\n"
            + "\n".join(f"  line {n}: {t}" for n, t in hits)
        )

    @pytest.mark.parametrize(
        "path", _ion_templates(), ids=lambda p: p.name)
    def test_ion_templates_are_clean(self, path):
        hits = _offenders(path, html=True)
        assert not hits, (
            f"{path.name} has inline event handlers, which CSP blocks:\n"
            + "\n".join(f"  line {n}: {t}" for n, t in hits)
        )


# -- The CSP that makes this matter ---------------------------------------


class TestTheDirectiveIsStillSet:
    def test_script_src_attr_is_none(self):
        """If this is ever relaxed, the guard above is arguing for nothing
        and the reasoning in it needs revisiting rather than deleting."""
        server = (_WEB / "server.py").read_text(encoding="utf-8")
        assert "script-src-attr 'none'" in server

    def test_the_delegation_helper_still_exists(self):
        """The guard tells people to migrate to it, so it has to be there."""
        helper = _JS / _DISPATCHER
        assert helper.exists()
        assert "data-click-action" in helper.read_text(encoding="utf-8")


# -- A fixed handler nobody receives is not fixed --------------------------


_SCRIPT_SRC = re.compile(r'src="/static/js/([A-Za-z0-9._-]+\.js)(\?[^"]*)?"')


class TestIonScriptsAreCacheBusted:
    """ION's own JavaScript must carry ``?v={{ ion_version }}``.

    Found while verifying the handler migration above: the browser kept
    serving the old ``integration-wizard.js`` after the file changed on
    disk, because that one tag was the only ION-authored script included
    without the version query every other one has. ``theme-init.js`` was in
    the same state.

    On a developer's machine that costs a confusing minute. On an upgraded
    deployment it means every browser that ever loaded the page keeps
    running the previous release's code, with no error and no sign that
    anything is stale -- so a fix like the one above would ship and appear
    not to work.

    Vendored bundles are exempt: their filenames are the version, and they
    do not change between ION releases.
    """

    @pytest.mark.parametrize(
        "path", _ion_templates(), ids=lambda p: p.name)
    def test_ion_authored_scripts_carry_a_version(self, path):
        text = path.read_text(encoding="utf-8")
        bare = [
            name for name, query in _SCRIPT_SRC.findall(text)
            if not query and name not in _VENDOR and not name.endswith(".min.js")
        ]
        assert not bare, (
            f"{path.name} includes ION scripts with no cache-busting query, "
            f"so browsers keep the previous release's copy: {sorted(set(bare))}. "
            f'Add ?v={{{{ ion_version }}}} as the other tags do.'
        )


# -- Every delegated action must resolve ----------------------------------


_ACTION_ATTR = re.compile(
    r"data-(?:click|change|input|submit|keydown|keyup|blur|focus)-action="
    r"[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']"
)


class TestDelegatedActionsResolve:
    """A migrated handler that names a function nobody defines is just as
    dead as the inline one it replaced, and fails just as quietly."""

    @pytest.mark.parametrize(
        "path", [_JS / "integration-wizard.js", _JS / "ai-chat.js"],
        ids=lambda p: p.name)
    def test_actions_name_functions_defined_in_the_file(self, path):
        src = path.read_text(encoding="utf-8")
        named = set(_ACTION_ATTR.findall(src))
        if not named:
            pytest.skip(f"{path.name} declares no delegated actions yet")
        defined = set(re.findall(
            r"(?:function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|"
            r"window\.([A-Za-z_][A-Za-z0-9_]*)\s*=)", src))
        flat = {a or b for a, b in defined}
        missing = sorted(n for n in named if n not in flat)
        assert not missing, (
            f"{path.name} delegates to functions it does not define: "
            f"{missing}"
        )
