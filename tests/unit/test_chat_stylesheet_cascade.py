"""chat-page.css only works because of where base.html loads it.

The chat page's 1,157 lines of CSS moved out of an in-body <style> block
into a stylesheet linked from head_css. That lowers their precedence, and
twelve of its selectors are also declared in ai-chat.css with different
values:

    .ai-cursor        colour primary here, accent there
    .ai-grounding     px spacing here, rem spacing there
    .ai-messages      20px/16px padding and gap here, 1rem there
    .ai-welcome       a flex column here, centred text there
    .ai-welcome p     its own size and margins here, a margin there

plus the blink and pulse keyframes, which matter more than the rest: a
later @keyframes block with the same name replaces an earlier one
outright, whatever the specificity.

The page's values keep winning because ai-chat.css is linked before
head_css. That ordering is the whole reason this move was safe, so it is
pinned here rather than left as a thing someone has to notice.
"""
from __future__ import annotations

import re
from pathlib import Path

from page_css import hoisted_keyframes, page_css

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "src/ion/web/templates/base.html"
PAGE = ROOT / "src/ion/web/templates/chat.html"
#: The page sheet was retired into the one build; this is the
#: body[data-page="chat"] block, and only that block.
SHEET_TEXT = page_css("chat")


def test_ai_chat_css_is_linked_before_head_css():
    """If these ever swap, every overlapping rule changes winner."""
    base = BASE.read_text(encoding="utf-8")
    ai_chat = base.index("ai-chat.css")
    head_css = base.index("{% block head_css %}")
    assert ai_chat < head_css


def test_the_page_declares_the_scope_that_reaches_its_rules():
    """The sheet is retired into the one build. ion.css is still linked
    after ai-chat.css, so the overlapping rules still come second; the
    page_id block is what addresses them to this page."""
    page = PAGE.read_text(encoding="utf-8")
    assert "chat-page.css" not in page, "the retired sheet is linked again"
    assert "{% block page_id %}chat{% endblock %}" in page


def test_the_page_carries_no_style_block_of_its_own():
    assert "<style" not in PAGE.read_text(encoding="utf-8")


def test_the_sheet_still_declares_what_it_has_to_outrank():
    """The overlapping selectors have to be present to win. A move that
    silently dropped one would leave ai-chat.css's value in place, which
    is a different page rather than a broken one, and so easy to miss."""
    sheet = SHEET_TEXT
    for selector in (".ai-cursor", ".ai-grounding", ".ai-messages",
                     ".ai-welcome", ".ai-welcome p", ".ai-grounding ul",
                     ".ai-grounding-foot"):
        assert selector + " " in sheet or selector + "," in sheet \
            or selector + "{" in sheet, selector


def test_the_chat_keyframes_no_longer_collide_with_ai_chat():
    """This used to assert the opposite: chat-page.css had to redeclare the
    names ai-chat.css uses, because it loaded later and a same-named
    @keyframes replaces an earlier one outright.

    Retiring the sheet inverted the problem. @keyframes cannot be nested,
    so chat's were hoisted out of its scope and became global -- and
    typingBounce differs between the two files, opacity 0.4 against 0.5, so
    chat's copy started replacing ai-chat's on every page the widget
    appears on rather than just this one. chat's is chatTypingBounce now.
    blink was identical in both, so the duplicate was dropped instead.
    """
    ours = set(re.findall(r"@keyframes\s+([\w-]+)", hoisted_keyframes()))
    ai_chat = set(re.findall(
        r"@keyframes\s+([\w-]+)",
        (ROOT / "src/ion/web/static/css/ai-chat.css").read_text(encoding="utf-8")))
    assert not (ours & ai_chat), (
        f"{sorted(ours & ai_chat)} is declared in both. base.html links "
        "ai-chat.css on every page, so a hoisted copy replaces it everywhere."
    )
    assert "chatTypingBounce" in ours, "chat lost its renamed typing animation"
    assert "chatTypingBounce" in SHEET_TEXT, "nothing on the page uses it"
