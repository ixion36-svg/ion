"""The alerts page's client-state renders, stages 9 to 14.

These six stages hold no server-side answer, so unlike the earlier stages
there is no fragment and no module to test. The queue's alerts, the drawer's
charts and the detail modal all came from the server and became fragments.
A toast's text is whatever the caller passed, the saved views live in
localStorage, the detected patterns are computed in the browser from the
loaded alerts, the tag chips are being typed, the globe tooltip follows the
pointer and the column choice is the reader's. None of them has a server to
ask, so the markup moved into <template> elements and the script fills
textContent, which is the pattern stage 4 established for the queue's side
lists.

What that leaves to test is the structure the technique depends on. Four
things break it silently:

  A <template> inside a <script> is inert text, so cloneTemplate finds no
  content and returns null, and the caller's `if (!x) return` makes the
  control vanish rather than fail.

  A cloneTemplate id with no matching element does the same.

  A duplicate template id resolves to whichever comes first in the
  document, so one caller silently gets the other's markup.

  A data-args built by string interpolation rather than JSON.stringify
  parses as invalid JSON in event-delegation.js, which logs and returns.
  The control looks live and does nothing. That was ten separate sites on
  this page before these stages.

Every assertion here is against the rendered-template source, because that
is the artifact: there is no Python to drive.
"""
from __future__ import annotations

import json
import pathlib
import re

PAGE = pathlib.Path(__file__).resolve().parents[2] / (
    "src/ion/web/templates/alerts.html")

SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)
TEMPLATE_ID = re.compile(r"<template\s+id=\"([^\"]+)\"")
CLONE = re.compile(r"cloneTemplate\(\s*'([^']+)'\s*\)")
WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


def _blank(m: re.Match) -> str:
    """Replace a region with as many newlines as it held, so a reported
    line number still points at the real file."""
    return "\n" * m.group(0).count("\n")


def page() -> str:
    """The page with its Jinja comments blanked.

    The comment at the top of the file explains why the queue's permissions
    arrive on a data attribute "rather than Jinja inside the <script>".
    That sentence holds the file's first <script>, so a plain regex pairs it
    with the real </script> 500 lines later and blanks the whole shell,
    the markup these stages moved into it included. Three tests here passed
    against an empty string before this.
    """
    text = PAGE.read_text(encoding="utf-8").replace("\r\n", "\n")
    return JINJA_COMMENT.sub(_blank, text)


def markup() -> str:
    """The page with every script body blanked, so only real elements match.

    Without it a template id named in a JS comment reads as a defined
    template: there are 32 and the naive count is 41.
    """
    return SCRIPT.sub(lambda m: "<script>" + "\n" * m.group(1).count("\n")
                      + "</script>", page())


def scripts() -> str:
    return "\n".join(SCRIPT.findall(page()))


def on_comment_line(text: str, pos: int) -> bool:
    """Whether the offset sits on a JS comment line."""
    line = text[text.rfind("\n", 0, pos) + 1:pos].lstrip()
    return line.startswith("//") or line.startswith("*")


def fn(name: str) -> str:
    """One function's body, by brace depth from its declaration."""
    text = page()
    m = re.search(r"^[ \t]*(?:async\s+)?function\s+" + re.escape(name)
                  + r"\s*\(", text, re.M)
    assert m, f"no function {name}"
    depth = 0
    for i in range(m.start(), len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():i + 1]
    raise AssertionError(f"unbalanced braces in {name}")


def tpl(tid: str) -> str:
    """One <template> element's inner markup."""
    text = markup()
    start = text.index(f'<template id="{tid}"')
    return text[start:text.index("</template>", start)]


# ---------------------------------------------------------------------------
# The measure, and the four ways the technique fails without a sound.
#
# Every test in this file was run against the page as it stood before stage
# 9, and 26 of the 30 fail there. The four that pass are the invariants
# below rather than claims about these stages: nine templates and nine
# clone sites already agreed, no id was doubled, and the shell's literal
# data-args were already JSON. Each was then driven against a page carrying
# exactly its defect, a doubled id, a clone of an id nothing defines, an
# orphan template, a data-args of `[critical, 2]`, a dropped denominator
# guard, and a template smuggled inside the script, and all six were
# caught. They are kept as pins, not as evidence of the conversion.
# ---------------------------------------------------------------------------


def test_the_page_makes_no_runtime_dom_write_anywhere():
    """The point of the fourteen stages. Counted over the whole file rather
    than per function, so a new writer anywhere trips it."""
    found = WRITES.findall(page())
    assert found == [], found


def test_every_template_lives_outside_the_script_blocks():
    """A <template> inside a <script> is text, not an element.
    document.getElementById finds nothing, cloneTemplate returns null, and
    every control built from it quietly does not appear."""
    for body in SCRIPT.findall(page()):
        for m in TEMPLATE_ID.finditer(body):
            # These stages' comments name the template each render clones,
            # so the question is whether a match is an element or prose.
            assert on_comment_line(body, m.start()), m.group(1)
    assert len(TEMPLATE_ID.findall(markup())) == 32


def test_every_cloned_id_is_a_template_the_page_defines():
    defined = set(TEMPLATE_ID.findall(markup()))
    used = set(CLONE.findall(scripts()))
    assert used - defined == set()
    assert defined - used == set(), "a template nothing clones is dead markup"


def test_no_template_id_is_defined_twice():
    """Two elements with one id resolve to whichever is first in document
    order, so the second caller silently renders the first's markup."""
    ids = TEMPLATE_ID.findall(markup())
    assert {i for i in ids if ids.count(i) > 1} == set()


def test_no_data_args_is_built_by_string_interpolation():
    """The dispatcher parses data-args with JSON.parse and on a throw it
    logs and returns. escapeHtml turns a double quote into &quot;, the
    browser decodes it to a bare quote inside the JSON string, and the
    control becomes a button that does nothing. Ten sites on this page did
    this; every one now goes through JSON.stringify."""
    for body in SCRIPT.findall(page()):
        assert not re.search(r"data-args=[\"'][^\"']*\$\{", body)
    for m in re.finditer(r"\.dataset\.args\s*=\s*(.+)", scripts()):
        assert m.group(1).lstrip().startswith("JSON.stringify"), m.group(1)


def test_every_literal_data_args_in_the_markup_is_valid_json():
    """The shell's own data-args are hand-written, so they are parsed rather
    than assumed."""
    found = re.findall(r"data-args='([^']*)'", markup())
    assert found, "no literal data-args found; the anchor has moved"
    for raw in found:
        assert isinstance(json.loads(raw), list), raw


# ---------------------------------------------------------------------------
# Stage 9: the toast, the threat banner, the saved-views dropdown
# ---------------------------------------------------------------------------


def test_the_toast_is_a_clone_whose_message_is_text_not_markup():
    body = fn("showNotification")
    assert "cloneTemplate('notification-toast-template')" in body
    assert not WRITES.search(body)
    assert 'class="notification-text"' in tpl("notification-toast-template")
    assert "slot.textContent" in body


def test_a_null_message_renders_as_empty_rather_than_the_word_null():
    """String(null) is "null", which is a toast reading null. The caller
    passes whatever it has, so the guard is here."""
    assert "message == null ? '' : String(message)" in fn("showNotification")


def test_the_threat_banner_labels_are_in_the_shell_and_only_numbers_fill():
    shell = markup()
    for stat, label in (("total", "Total"), ("critical", "Critical"),
                        ("high", "High"), ("open", "Open")):
        assert f'id="threat-stat-{stat}"' in shell
        assert f">{label}</div>" in shell
    body = fn("renderThreatBanner")
    assert not WRITES.search(body)
    for stat in ("total", "critical", "high", "open"):
        assert f"'threat-stat-{stat}'" in body


def test_the_saved_views_dropdown_is_built_from_option_elements():
    body = fn("populateSavedFiltersDropdown")
    assert not WRITES.search(body)
    assert "select.replaceChildren()" in body
    assert body.count("createElement('option')") == 2
    assert "placeholder.textContent = 'Saved Views...'" in body
    assert "opt.textContent = f.name" in body


# ---------------------------------------------------------------------------
# Stage 10: tag chips, the globe tooltip, the column chooser
# ---------------------------------------------------------------------------


def test_a_typed_tag_is_chip_text_not_assembled_markup():
    chip = tpl("tag-chip-template")
    assert "tag-chip-text" in chip
    assert 'data-click-action="__tagChipRemove"' in chip
    body = fn("_initTagInput")
    assert not WRITES.search(body)
    assert "cloneTemplate('tag-chip-template')" in body
    assert "cloneTemplate('tag-input-template')" in body
    assert "slot.textContent = t" in body


def test_the_chip_remove_button_carries_its_index():
    """The dispatcher reads which chip to drop off the button. Without
    data-idx every cross removes the first tag."""
    assert "remove.dataset.idx = i" in fn("_initTagInput")


def test_the_globe_tooltip_colours_by_attribute_not_inline_style():
    """style-src-attr is 'none', so an inline style= paints nothing. The
    severity colour goes through data-ion-style and the shared script."""
    body = fn("handleMapHover")
    assert not WRITES.search(body)
    assert "cloneTemplate('globe-tooltip-template')" in body
    assert "setAttribute('data-ion-style'" in body


def test_the_column_chooser_rows_come_from_a_template():
    row = tpl("aq-colrow-template")
    assert "aq-colrow-label" in row
    assert 'type="checkbox"' in row
    assert "box.dataset.aqCol = c.k" in page()


# ---------------------------------------------------------------------------
# Stage 11: the attention chips, the queue views, the saved-views dialog
# ---------------------------------------------------------------------------


def test_the_three_attention_chips_are_fixed_markup_in_the_shell():
    shell = markup()
    for name in ("critical", "high", "unassigned"):
        assert f'id="attn-chip-{name}"' in shell
    chip = shell[shell.index('id="attn-chip-critical"'):]
    chip = chip[:chip.index("</button>")]
    assert "hidden" in chip
    assert """data-args='["critical", 2]'""" in chip
    assert "chip-count" in chip


def test_a_chip_with_no_count_is_hidden_rather_than_showing_zero():
    """Three chips, two things each: the number and whether it shows. A
    chip reading "0 Critical Stale" is noise, so n === 0 hides it."""
    body = fn("computeAlertAttention")
    assert not WRITES.search(body)
    assert "chip.hidden = n === 0" in body
    assert "slot.textContent = n" in body


def test_the_queue_view_buttons_carry_their_key_and_count():
    body = fn("renderQueueViews")
    assert not WRITES.search(body)
    for tid in ("aq-view-template", "aq-view-saved-template",
                "aq-view-add-template"):
        assert f"cloneTemplate('{tid}')" in body
    assert "btn.dataset.aqView = v.k" in body
    assert "btn.dataset.aqView = f.id" in body


def test_a_saved_views_name_is_text_and_its_id_goes_through_stringify():
    body = fn("manageSavedFilters")
    assert not WRITES.search(body)
    assert "name.textContent = f.name" in body
    assert "load.dataset.args = JSON.stringify([f.id])" in body
    assert "del.dataset.args = JSON.stringify([f.id])" in body


# ---------------------------------------------------------------------------
# Stage 12: the two closure dialogs
# ---------------------------------------------------------------------------


def test_the_alert_closure_dialog_varies_three_things_and_no_more():
    body = fn("showAlertClosureModal")
    assert not WRITES.search(body)
    assert "cloneTemplate('alert-closure-template')" in body
    assert "heading.textContent = `Close Alert as ${label}`" in body
    assert "kfp.hidden = !isFP" in body
    assert "setAttribute('data-ion-style', `color:${color}`)" in body


def test_the_alert_closure_confirm_passes_both_arguments_as_json():
    assert ("confirm.dataset.args = JSON.stringify([alertId, closureType])"
            in fn("showAlertClosureModal"))


def test_the_case_closure_reasons_are_static_options_not_a_rebuilt_array():
    """Seven options, fixed, rebuilt from a JS array on every open. They are
    markup now, so only the two data-args vary."""
    body = tpl("case-closure-reason-template")
    for value in ("true_positive", "false_positive", "benign_true_positive",
                  "duplicate", "insufficient_data", "not_applicable"):
        assert f'value="{value}"' in body
    assert body.count("<option") == 7
    fill = fn("showClosureReasonModal")
    assert "const reasonOptions" not in fill
    assert "confirm.dataset.args = JSON.stringify([caseId, newStatus])" in fill


# ---------------------------------------------------------------------------
# Stage 13: the pattern cards and the related-alerts timeline
# ---------------------------------------------------------------------------


def test_a_pattern_group_key_reaches_the_dispatcher_as_json():
    """The group key is a hostname or a username out of alert data. One
    holding a double quote broke Show Alerts, silently."""
    body = fn("renderPatternCards")
    assert not WRITES.search(body)
    assert ("show.dataset.args = JSON.stringify([p.group_by, p.group_key])"
            in body)
    assert "set('.pc-group-key', p.group_key)" in body


def test_an_absent_execution_hides_the_button_rather_than_linking_to_nothing():
    body = fn("renderPatternCards")
    assert "viewExec.hidden = !hasExec" in body
    assert "if (hasExec) viewExec.dataset.args" in body


def test_the_timeline_keeps_the_name_and_signature_alert_detail_probes_for():
    """alert-detail.js feature-detects this page's renderTimeline and calls
    it as host(container, alerts), falling back to its own markup with no
    CURRENT badge when it is absent. Renaming it hands the render to that
    fallback with no error anywhere."""
    assert re.search(r"function renderTimeline\(container,\s*alerts\)", page())
    body = fn("renderTimeline")
    assert not WRITES.search(body)
    assert "cloneTemplate('timeline-item-template')" in body
    assert "current.hidden = !a._isCurrent" in body
    assert "tl-current" in tpl("timeline-item-template")


# ---------------------------------------------------------------------------
# Stage 14: the MITRE heatmap
#
# A clone rather than a server fragment on purpose. The grid merges the
# page's own allAlerts with the client-held _tideMitreCoverage, so a server
# grid would need a second definition of both and of the four-state sort.
# That is the two-paths-disagree failure this page's own comments warn about.
# ---------------------------------------------------------------------------


def _cell_branch() -> str:
    """The count branch after the cell exists.

    Two branches test the same count. The first picks the heat level, and
    slicing to the first match tested that one instead.
    """
    body = fn("renderMitreHeatmap")
    block = body[body.index("cloneTemplate('mitre-cell-template')"):]
    block = block[block.index("if (tech.count > 0) {"):]
    return block[:block.index("\n                }")]


def test_the_heatmap_cell_passes_its_technique_id_as_json():
    body = fn("renderMitreHeatmap")
    assert not WRITES.search(body)
    assert "cell.dataset.args = JSON.stringify([tech.id])" in body
    assert "idSlot.textContent = tech.id" in body


def test_an_uncovered_cell_gets_no_click_action_at_all():
    """A cell with no alerts filters to nothing. Both the action and its
    argument sit inside the count check, so a dead cell is not a
    live-looking control."""
    block = _cell_branch()
    assert "cell.dataset.clickAction = 'filterByMitreTechnique'" in block
    assert "cell.dataset.args = JSON.stringify([tech.id])" in block


def test_the_cell_title_is_set_as_a_property_because_it_holds_newlines():
    r"""titleParts.join('\n') inside an attribute string gives a literal
    backslash-n in the tooltip."""
    assert r"cell.title = titleParts.join('\n')" in fn("renderMitreHeatmap")


def test_the_legend_swatches_are_fixed_markup_and_only_four_figures_fill():
    legend = tpl("mitre-legend-template")
    for cls in ("ml-covered", "ml-total", "ml-inactive", "ml-blind",
                "ml-rules"):
        assert cls in legend
    assert legend.count("mitre-legend-swatch") == 4
    body = fn("renderMitreHeatmap")
    for cls in ("ml-covered", "ml-inactive", "ml-blind", "ml-rules"):
        assert f"put('.{cls}'" in body


def test_an_unknown_technique_total_leaves_the_denominator_off():
    """A cov.total_techniques of 0 or None rendered "/0", which reads as a
    measured total of nothing rather than an unmeasured one."""
    assert ("cov.total_techniques != null && cov.total_techniques > 0"
            in fn("renderMitreHeatmap"))


def test_an_empty_heatmap_hides_the_legend_rather_than_showing_blank_figures():
    body = fn("renderMitreHeatmap")
    block = body[body.index("if (Object.keys(techCounts).length === 0"):]
    block = block[:block.index("\n    }")]
    assert "cloneTemplate('mitre-empty-template')" in block
    assert "legendEl.style.display = 'none'" in block
