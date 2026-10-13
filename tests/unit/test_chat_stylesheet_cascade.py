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

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "src/ion/web/templates/base.html"
PAGE = ROOT / "src/ion/web/templates/chat.html"
SHEET = ROOT / "src/ion/web/static/css/chat-page.css"


def test_ai_chat_css_is_linked_before_head_css():
    """If these ever swap, every overlapping rule changes winner."""
    base = BASE.read_text(encoding="utf-8")
    ai_chat = base.index("ai-chat.css")
    head_css = base.index("{% block head_css %}")
    assert ai_chat < head_css


def test_the_page_links_its_sheet_from_head_css():
    page = PAGE.read_text(encoding="utf-8")
    block = re.search(r"\{% block head_css %\}(.*?)\{% endblock %\}", page,
                      re.S)
    assert block, "head_css"
    assert "chat-page.css" in block.group(1)


def test_the_page_carries_no_style_block_of_its_own():
    assert "<style" not in PAGE.read_text(encoding="utf-8")


def test_the_sheet_still_declares_what_it_has_to_outrank():
    """The overlapping selectors have to be present to win. A move that
    silently dropped one would leave ai-chat.css's value in place, which
    is a different page rather than a broken one, and so easy to miss."""
    sheet = SHEET.read_text(encoding="utf-8")
    for selector in (".ai-cursor", ".ai-grounding", ".ai-messages",
                     ".ai-welcome", ".ai-welcome p", ".ai-grounding ul",
                     ".ai-grounding-foot"):
        assert selector + " " in sheet or selector + "," in sheet \
            or selector + "{" in sheet, selector


def test_the_sheet_still_declares_the_keyframes_it_has_to_replace():
    sheet = SHEET.read_text(encoding="utf-8")
    ai_chat = (ROOT / "src/ion/web/static/css/ai-chat.css").read_text(
        encoding="utf-8")
    shared = (set(re.findall(r"@keyframes\s+([\w-]+)", sheet))
              & set(re.findall(r"@keyframes\s+([\w-]+)", ai_chat)))
    assert shared, "no keyframes are shared, so this test proves nothing"
    for name in shared:
        assert re.search(r"@keyframes\s+" + name + r"\b", sheet), name
