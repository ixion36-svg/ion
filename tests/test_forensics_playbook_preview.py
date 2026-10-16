"""The playbook step preview keeps its container and what it told you.

The conversion replaced `_ion-s-5eaab7cb30` with a `<template>` clone whose
classes had no rule in any stylesheet, so the preview rows rendered as bare
text with nothing separating one step from the next. It also dropped the
REQUIRED marker and the field count, which are what an analyst picks a
playbook on, leaving a preview that looked complete while saying less.

Neither was visible to a test. `tests/test_ui_state_classes_have_rules.py`
reads classes the JavaScript adds with classList.add; a class sitting in a
`<template>` in the shell is added by cloning, so it does not see them. And
`tests/test_ui_rewrite_harness.py` did flag the lost hashed class, but it
was already failing on three older templates, so a fourth entry appearing
in its output changed nothing about its result.

A general version of the first check is worth having and is not here: the
classes in these templates include Tailwind arbitrary values, whose
selectors are escaped in the compiled sheet, and JS hook classes that
correctly have no rules. Both need handling before such a check is anything
but noise.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "src/ion/web/templates/forensics.html"
SHEETS = ROOT / "src/ion/web/static/css"

#: The classes the preview row is built from. Each carries layout or colour,
#: so each needs a rule. `pb-preview-title` is deliberately absent: it is a
#: <strong> inside pb-preview-head and takes its type from there.
STYLED = (
    "pb-preview-step",
    "pb-preview-head",
    "pb-preview-req",
    "pb-preview-fields",
    "pb-preview-desc",
)


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _template() -> str:
    block = re.search(
        r'<template id="forensic-playbook-preview"[^>]*>(.*?)</template>',
        _page(), re.S)
    assert block, "the preview template is in the shell"
    return block.group(1)


def _all_css() -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in sorted(SHEETS.glob("*.css")))


@pytest.mark.parametrize("cls", STYLED)
def test_every_preview_class_has_a_rule(cls):
    assert f".{cls}" in _all_css(), (
        f"{cls} is in the preview template and no stylesheet paints it, so "
        "the row renders unstyled and no route test can see it")


@pytest.mark.parametrize("cls", STYLED)
def test_the_template_actually_uses_each_class(cls):
    """The other half. Rules for classes nothing uses would satisfy the test
    above while the preview stayed bare."""
    assert cls in _template(), cls


def test_the_container_carries_the_padding_and_the_tint_it_lost():
    """_ion-s-5eaab7cb30's whole job was separating one step from the next:
    padding, a tinted background and rounded corners."""
    rule = re.search(
        r"\.pb-preview-step\s*\{([^}]*)\}", _all_css())
    assert rule, "the container rule"
    body = rule.group(1)
    assert "padding" in body
    assert "background" in body
    assert "border-radius" in body


def test_the_preview_still_marks_a_required_step():
    assert "pb-preview-req" in _template()
    assert "REQUIRED" in _page()


def test_the_preview_still_reports_the_field_count():
    assert "pb-preview-fields" in _template()
    assert "fields" in _page()


def test_a_step_whose_fields_are_unreadable_says_so_rather_than_nothing():
    """`(s.fields||[]).length` showed nothing for a step with no fields and
    nothing for a payload that carried no list. Those are different."""
    assert "fields unknown" in _page()


def test_the_required_marker_tests_for_true_not_truthiness():
    """is_required is a boolean column. A string would be truthy."""
    assert "step.is_required===true" in re.sub(r"\s+", "", _page())
