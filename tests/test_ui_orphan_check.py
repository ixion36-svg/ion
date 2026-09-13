"""The orphaned-ancestor checker must catch the real case and stay quiet on the
false ones, because the false ones outnumber the real ones roughly 70 to 1.

When the sweep that motivated this tool ran across nine restyled pages it found
69 orphaned rules, of which exactly one was a genuine regression. A checker that
reports all 69 is worse than no checker: it trains you to skim the output.

These exercise the discrimination directly rather than through the CLI.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.ui_orphan_check import (  # noqa: E402
    Descendants,
    blank_blocks,
    orphaned_rules,
    still_unstyled,
)

STYLES = """
.form-group        { margin-bottom: 1.25rem; }
.form-group label  { display: block; font-weight: 600; }
.panel h3          { margin: 0; }
.card h4           { font-size: 0.9rem; color: #888; }
.btn:hover         { opacity: .8; }
"""


def test_detects_a_rule_orphaned_by_a_dropped_ancestor():
    old = '<div class="form-group"><label>Name</label></div>'
    new = '<div class="mb-5"><label>Name</label></div>'
    rules = orphaned_rules(old, new, STYLES)
    assert ("form-group", "label", ".form-group label", "display: block; font-weight: 600;") in rules


def test_ignores_the_ancestors_own_rule_which_is_merely_inert():
    """`.form-group { margin-bottom }` matching nothing is expected and fine --
    only rules that styled OTHER elements are a problem."""
    old = '<div class="form-group"><label>Name</label></div>'
    new = '<div class="mb-5"><label>Name</label></div>'
    selectors = {sel for _, _, sel, _ in orphaned_rules(old, new, STYLES)}
    assert ".form-group" not in selectors


def test_ignores_margin_only_heading_rules():
    """The reset already zeroes heading margins -- browser-verified -- so
    `.panel h3 { margin: 0 }` was inert before the restyle as well."""
    old = '<div class="panel"><h3>Title</h3></div>'
    new = '<div class="p-4"><h3>Title</h3></div>'
    assert orphaned_rules(old, new, STYLES) == []


def test_ignores_same_element_state_rules():
    """`.btn:hover` is not a descendant rule; dropping .btn loses the hover, but
    that is the element's own styling, reported elsewhere, not orphaning."""
    old = '<button class="btn">Go</button>'
    new = '<button class="px-4">Go</button>'
    assert orphaned_rules(old, new, STYLES) == []


def test_reports_an_element_that_is_now_classless():
    hit = {"id": None, "text": "Name"}
    bad, ident = still_unstyled('<div class="mb-5"><label>Name</label></div>', "label", hit)
    assert bad, "a classless label that lost its ancestor rule is a real regression"
    assert "Name" in ident


def test_stays_quiet_when_the_styling_was_re_homed_onto_the_descendant():
    """The common, correct outcome: the restyle moved the declarations onto the
    element itself. The rule is orphaned but nothing is unstyled."""
    hit = {"id": None, "text": "Name"}
    new = '<div class="mb-5"><label class="block font-semibold">Name</label></div>'
    bad, _ = still_unstyled(new, "label", hit)
    assert not bad


def test_matches_by_id_in_preference_to_text():
    hit = {"id": "field-name", "text": "anything at all"}
    new = '<label id="field-name">Renamed</label>'
    bad, ident = still_unstyled(new, "label", hit)
    assert bad and ident == "id=field-name"


def test_descendant_walker_respects_nesting_rather_than_document_order():
    """A bare <h4> AFTER the .card closes must not be attributed to .card --
    that conflation is what made the first version of this tool useless."""
    html = ('<div class="card"><h4>Inside</h4></div>'
            '<div class="other"><h4>Outside</h4></div>')
    p = Descendants("card", "h4")
    p.feed(html)
    assert [" ".join(h["text"].split()) for h in p.hits] == ["Inside"]


def test_void_elements_do_not_corrupt_the_ancestor_stack():
    """<input> and <br> have no closing tag. Pushing them would leave the stack
    unbalanced and make every later element look nested inside them."""
    html = '<div class="form-group"><input type="text"><label>After</label></div>'
    p = Descendants("form-group", "label")
    p.feed(html)
    assert len(p.hits) == 1


def test_script_and_style_content_is_blanked_but_offsets_survive():
    """Class names inside a <script> template literal are not markup. Blanking
    must preserve length so line numbers stay usable."""
    src = '<div class="a"></div><script>var x = \'<div class="b"></div>\';</script>'
    out = blank_blocks(src)
    assert len(out) == len(src)
    assert 'class="a"' in out
    assert 'class="b"' not in out
