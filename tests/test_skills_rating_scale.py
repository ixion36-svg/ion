"""The self-assessment scale says what each value takes to demonstrate.

Before this, the scale was five labels: "Never heard of it", "Aware of
it", "Can do it supervised", "Confident & independent", "Could teach it".
A label is not a criterion. "Can do it supervised" and "Confident &
independent" are the same claim at different volumes, so where somebody
lands depends on how boldly they read themselves rather than on what they
have done -- which is how two people with identical experience rate
themselves two apart, and how a skills matrix becomes an opinion survey
that coverage figures are then computed from.

Each level now names something a reader could point at. That is also what
makes the number checkable afterwards: a lead recording an equivalence,
or asking why cover is thin on a pillar, has something specific to ask
for.

The per-question `guidance` strings are a different thing and stay. They
anchor the top of the scale for one question ("Level 5: diagnoses
unassigned shards from the allocation API"); this answers what 1 to 4
look like anywhere.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services.role_skills_service import (  # noqa: E402
    RATING_SCALE,
    get_role_definitions,
)

_TEMPLATES = _SRC / "ion" / "web" / "templates"
_CLIENT = _TEMPLATES / "_fragments" / "training_assessment_client.html"
_TRAINING = _TEMPLATES / "training.html"
_CSS = _ROOT / "frontend" / "ion-training.css"


class TestTheScaleItself:
    def test_it_covers_one_to_five_in_order(self):
        """SkillAssessment.rating is 1-5 and the questionnaire renders
        buttons for 1..5. A scale that disagreed with either would offer a
        value that cannot be saved, or omit one that can."""
        assert [r["value"] for r in RATING_SCALE] == [1, 2, 3, 4, 5]

    def test_every_level_says_what_demonstrates_it(self):
        missing = [r["value"] for r in RATING_SCALE
                   if not (r.get("demonstrates") or "").strip()]
        assert not missing, (
            f"levels {missing} have no demonstration text, which puts them "
            "back to being a label somebody reads at their own volume"
        )

    def test_the_demonstrations_are_not_the_same_sentence(self):
        """Five levels that describe the same evidence do not separate
        anybody. Caught by distinctness rather than by eye, because the
        copy-paste version of this list looks fine at a glance."""
        texts = [r["demonstrates"].strip().lower() for r in RATING_SCALE]
        assert len(set(texts)) == len(texts)

    def test_the_upper_levels_ask_for_something_pointed_at(self):
        """3, 4 and 5 are the levels a coverage figure is built on, so each
        has to name evidence rather than a feeling."""
        for level in (3, 4, 5):
            text = next(r["demonstrates"] for r in RATING_SCALE
                        if r["value"] == level).lower()
            assert "point to" in text, (
                f"level {level} does not ask the reader to point at "
                f"anything: {text!r}"
            )

    def test_the_api_payload_carries_it(self):
        """The questionnaire reads the scale from get_role_definitions, so
        a scale that is right in the module and absent from the payload
        changes nothing on screen."""
        scale = get_role_definitions()["rating_scale"]
        assert scale == RATING_SCALE
        assert all("demonstrates" in r for r in scale)


class TestTheQuestionnaireShowsIt:
    """Reference data nothing renders is reference data nobody reads."""

    def test_the_legend_template_has_a_slot_for_it(self):
        markup = _CLIENT.read_text(encoding="utf-8")
        for hook in ("rm-rating-value", "rm-rating-label", "rm-rating-demo"):
            assert hook in markup, f"{hook} missing from the legend template"

    def test_the_renderer_fills_that_slot(self):
        source = _TRAINING.read_text(encoding="utf-8")
        assert "rating.demonstrates" in source, (
            "the legend renderer never reads demonstrates, so the template "
            "slot stays empty"
        )

    def test_the_pill_rule_that_would_box_the_text_is_gone(self):
        """`.rm-rating-legend span` styled every span as a chip. The label
        and the demonstration text are both spans now, so leaving it would
        put a sentence in a bordered pill."""
        css = _CSS.read_text(encoding="utf-8")
        assert not re.search(r"\.rm-rating-legend\s+span\s*\{", css)

    def test_the_new_classes_are_styled(self):
        css = _CSS.read_text(encoding="utf-8")
        for cls in ("rm-rating-row", "rm-rating-value", "rm-rating-label",
                    "rm-rating-demo", "rm-rating-caption"):
            assert f".{cls}" in css, f"{cls} has no rule, so it renders unstyled"
