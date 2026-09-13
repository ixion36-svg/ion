"""Guards on the hashed-class lookup table that pass 2 applies mechanically.

The table is applied to 1,370 usages without a human reading each one, so a
wrong entry is a silent visual change on a page nobody opens. Two failure modes
have already occurred and both are covered here.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.hashed_class_map import convert, escape_arbitrary  # noqa: E402

MAP = Path("tools/hashed_class_map.json")


def _rules() -> dict:
    d = json.loads(MAP.read_text(encoding="utf-8"))
    return d.get("rules", d)


def test_no_arbitrary_value_contains_an_unescaped_space():
    """`border-radius:0 4px 4px 0` naively becomes `rounded-[0 4px 4px 0]`, and
    the browser splits that class attribute on whitespace into four tokens that
    Tailwind never generated. The radius silently does not apply.

    Two of these shipped in the committed map before anyone noticed."""
    broken = []
    for name, rule in _rules().items():
        for m in re.finditer(r"[\w:./-]*\[[^\]]*\]", rule.get("tailwind") or ""):
            if " " in m.group(0):
                broken.append(f"{name}: {m.group(0)}")
    assert not broken, f"arbitrary values split by whitespace: {broken}"


def test_escape_arbitrary_underscores_only_inside_brackets():
    assert escape_arbitrary("rounded-[0 4px 4px 0]") == "rounded-[0_4px_4px_0]"
    assert escape_arbitrary("flex-[0 0 auto]") == "flex-[0_0_auto]"
    # Utilities separated by spaces must stay separate utilities.
    assert escape_arbitrary("grid grid-cols-2 gap-5") == "grid grid-cols-2 gap-5"
    assert escape_arbitrary("border-l-[2px] border-l-[#334155]") == \
        "border-l-[2px] border-l-[#334155]"


def test_manual_rules_never_publish_an_actionable_string():
    """A manual rule has some declarations that map and some that do not.
    Publishing the partial string invites an agent to apply it and silently drop
    the rest -- `display:grid;grid-template-columns:...` would become `grid`
    with the columns quietly gone."""
    for name, rule in _rules().items():
        if rule.get("kind") == "manual":
            assert not rule.get("tailwind"), \
                f"{name} is manual but publishes a tailwind string"


def test_the_only_unmappable_rules_left_are_the_ones_that_are_not_css():
    """Widening the mapper cut manual from 117 to 36. What remains should be
    dominated by JS-concatenated values, which are not CSS and cannot become a
    class -- if this count climbs, a real property stopped mapping."""
    manual = [r for r in _rules().values() if r.get("kind") == "manual"]
    assert len(manual) <= 40, f"{len(manual)} manual rules; the mapper regressed"


def test_properties_tailwind_covers_directly_are_not_deferred_to_a_human():
    """Each of these sat in the manual bucket purely because the table did not
    know the property, so 81 rules were withheld from conversion for nothing."""
    cases = [
        ("overflow-y", "auto", "overflow-y-auto"),
        ("text-overflow", "ellipsis", "text-ellipsis"),
        ("font-style", "italic", "italic"),
        ("box-sizing", "border-box", "box-border"),
        ("flex-shrink", "0", "shrink-0"),
        ("vertical-align", "middle", "align-middle"),
        ("list-style", "none", "list-none"),
        ("grid-template-columns", "1fr 1fr", "grid-cols-2"),
        ("grid-template-columns", "repeat(3, minmax(0, 1fr))", "grid-cols-3"),
        ("grid-column", "1 / -1", "col-span-full"),
    ]
    for prop, value, expected in cases:
        util, kind = convert(prop, value)
        assert util == expected, f"{prop}:{value} -> {util}, expected {expected}"
        assert kind != "manual"


def test_border_shorthand_splits_into_width_and_colour():
    """Tailwind has no single per-side border shorthand, so one CSS declaration
    becomes two utilities."""
    util, kind = convert("border-left", "3px solid #6366f1")
    assert util == "border-l-[3px] border-l-[#6366f1]"
    assert kind == "arbitrary"


def test_dashed_and_dotted_borders_are_left_to_a_human():
    """Tailwind's border-style utility is not per-side, so applying it would
    change all four edges. Better to report than to quietly over-apply."""
    util, _ = convert("border-left", "2px dashed #888")
    assert util is None


def test_a_gradient_background_is_not_folded_into_a_colour_utility():
    assert convert("background", "linear-gradient(90deg, #000, #fff)")[0] is None
    assert convert("background", "#112233")[0] == "bg-[#112233]"
