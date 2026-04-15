"""
Bulk-port every Jinja template under src/ion/web/templates/ to wear the
Tailwind chrome.

Transformations applied to each template that `extends "base.html"`:

1. Wrap the content block body in the `.ion-tw` container (bg, font, grain,
   max-width, responsive padding) — only if not already wrapped.
2. Restyle every page-level `<h1>TITLE</h1>` (no class or with `page-header`
   class wrappers) into the Tailwind Geist heading.

Pages already ported manually (already contain the wrapper) are skipped.
Non-content templates and login are also skipped.
"""

from pathlib import Path
import re

TEMPLATES_DIR = Path(r"C:\Users\Tomo\ixion\src\ion\web\templates")

SKIP_NAMES = {
    "base.html",
    "_components.html",
    "_icons.html",
    "login.html",          # different auth layout
    "dashboard_v2.html",   # already in Tailwind
    "alerts.html",         # already ported
    "cases.html",          # already ported
    "observables.html",    # already ported
    "index.html",          # legacy dashboard — kept as rollback
}

WRAP_OPEN = (
    '<div class="ion-tw ion-tw-page text-slate-200 overflow-x-hidden">\n'
    '<div class="relative z-10 mx-auto max-w-[1920px] w-full '
    'px-4 sm:px-6 lg:px-10 xl:px-14 py-10 md:py-14">\n'
)
WRAP_CLOSE = (
    '</div><!-- /ion-tw inner -->\n'
    '</div><!-- /ion-tw -->\n'
)

# Upgraded H1 classes (applied to raw `<h1>` tags without an existing class)
H1_CLASS = (
    'font-sans font-semibold text-[36px] md:text-[44px] xl:text-[52px] '
    'leading-[1.05] text-white tracking-[-0.02em] mb-6'
)


def find_block_bounds(content: str, block_name: str):
    """Return (start_idx, end_idx_exclusive) of the named block's body,
    i.e. the span between `{% block X %}` and its matching `{% endblock %}`.

    Handles pages where scripts follow content: we pick the FIRST `{% endblock %}`
    that appears after the `{% block X %}`.
    """
    start_tag = re.search(r"\{%\s*block\s+" + re.escape(block_name) + r"\s*%\}",
                          content)
    if not start_tag:
        return None
    body_start = start_tag.end()
    # Find the matching endblock — first `{% endblock %}` after body_start
    end_tag = re.search(r"\{%\s*endblock\s*%\}", content[body_start:])
    if not end_tag:
        return None
    body_end = body_start + end_tag.start()
    return body_start, body_end


def process(path: Path) -> str:
    """Return updated content for path, or None if unchanged."""
    src = path.read_text(encoding="utf-8")

    # Must extend base.html
    if 'extends "base.html"' not in src and "extends 'base.html'" not in src:
        return None

    # Skip if already wrapped
    if "ion-tw-page" in src:
        return None

    bounds = find_block_bounds(src, "content")
    if not bounds:
        return None
    body_start, body_end = bounds
    body = src[body_start:body_end]

    # Restyle raw <h1> tags — only those with NO class attribute.
    # Pattern: <h1>Title</h1>  →  <h1 class="...">Title</h1>
    def h1_repl(m):
        return f'<h1 class="{H1_CLASS}">{m.group(1)}</h1>'
    body = re.sub(r"<h1>([^<]+)</h1>", h1_repl, body)

    # Wrap
    new_body = "\n" + WRAP_OPEN + body.lstrip("\n") + "\n" + WRAP_CLOSE
    # Strip trailing whitespace duplication from the original
    if not new_body.endswith("\n"):
        new_body += "\n"

    new_src = src[:body_start] + new_body + src[body_end:]
    return new_src


def main():
    touched = 0
    skipped = 0
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        if path.name in SKIP_NAMES:
            skipped += 1
            continue
        result = process(path)
        if result is None:
            skipped += 1
            continue
        path.write_text(result, encoding="utf-8")
        touched += 1
        print(f"  ported: {path.name}")
    print(f"\n{touched} touched, {skipped} skipped")


if __name__ == "__main__":
    main()
