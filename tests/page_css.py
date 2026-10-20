"""Read one page's rules out of the single build.

Every page stylesheet was retired into `frontend/ion-pages.css`, nested
under `body[data-page="<id>"]`. A test that used to read
`static/css/<page>-page.css` wants that block and nothing else: the file
carries all 58 pages, so handing back the whole thing silently widens every
assertion made against it from one page to all of them. That has already
caught two tests out -- discover's overlap check started failing on "0%" and
"50%", which are keyframe stops belonging to another page.

A page can hold more than one block. /alerts has two, because
alerts-queue.css and alerts-page.css were separate sheets retired
separately, so every block is returned, joined.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES_CSS = ROOT / "frontend" / "ion-pages.css"


def page_css(scope: str) -> str:
    """Every rule scoped to `scope`, with the wrapper stripped."""
    whole = PAGES_CSS.read_text(encoding="utf-8")
    opener = f'body[data-page="{scope}"] {{'
    blocks: list[str] = []
    at = 0
    while (found := whole.find(opener, at)) != -1:
        start = found + len(opener)
        depth, i = 1, start
        while depth:
            if whole[i] == "{":
                depth += 1
            elif whole[i] == "}":
                depth -= 1
            i += 1
        blocks.append(whole[start:i - 1])
        at = i
    if not blocks:
        raise AssertionError(
            f'no body[data-page="{scope}"] block in ion-pages.css. Either the '
            "page was never retired into the build, or its scope was renamed."
        )
    return "\n".join(blocks)


def hoisted_keyframes() -> str:
    """The @keyframes that sit outside every scope.

    A keyframe name is global and @keyframes is not a style rule, so each
    page's animations were lifted out of its wrapper. A test looking for a
    page's keyframes will not find them with page_css().
    """
    whole = PAGES_CSS.read_text(encoding="utf-8")
    out, depth, i = [], 0, 0
    while i < len(whole):
        if depth == 0 and whole.startswith("@keyframes", i):
            start = i
            while whole[i] != "{":
                i += 1
            d = 1
            i += 1
            while d:
                if whole[i] == "{":
                    d += 1
                elif whole[i] == "}":
                    d -= 1
                i += 1
            out.append(whole[start:i])
            continue
        if whole[i] == "{":
            depth += 1
        elif whole[i] == "}":
            depth -= 1
        i += 1
    return "\n".join(out)
