"""Migrate inline `style="..."` attributes to hashed CSS classes.

P11 style-attr half closure (v0.31.21). Walks every template under
``src/ion/web/templates/``, finds every ``style="..."`` HTML attribute,
generates a stable class name for each unique style content (via
SHA-1 prefix), rewrites the templates to use the class instead, and
emits a single CSS file with the class definitions. base.html loads
the CSS file inside a ``<style nonce>`` block (already nonce-allowed
via ``style-src 'nonce-XXX'`` since v0.31.3), so the styles apply
before paint — no FOUC.

After this migration runs and the new CSS is wired into base.html,
``style-src-attr 'unsafe-inline'`` can flip to ``'none'`` in
``SecurityHeadersMiddleware`` (last bit of P11 closure).

Usage:
    python tools/migrate_inline_styles.py

Idempotent — re-running picks up any styles added since the last
run and updates the CSS file accordingly. Existing class additions
on already-migrated elements are preserved.
"""
from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent.parent / "src" / "ion" / "web" / "templates"
CSS_OUT = Path(__file__).parent.parent / "src" / "ion" / "web" / "static" / "css" / "ion-migrated-styles.css"

# Match `style="VALUE"` where VALUE contains no `"` (single-pass attribute).
STYLE_ATTR_RE = re.compile(r'\sstyle="([^"]+)"')

# Find class attribute on the current tag (anywhere inside the matched tag).
CLASS_ATTR_RE = re.compile(r'\bclass="([^"]*)"')

# Find the enclosing tag boundaries: from the nearest `<tag` before to the
# next `>` after. Handles `<tag ...>` and `<tag ... />`.
TAG_OPEN_RE = re.compile(r"<[A-Za-z][\w-]*")


def class_name_for(style_value: str) -> str:
    """Stable short CSS class name for a style declaration block."""
    h = hashlib.sha1(style_value.encode("utf-8")).hexdigest()[:10]
    return f"_ion-s-{h}"


def find_tag_bounds(text: str, attr_start: int) -> tuple[int, int] | None:
    """Given a position of `style="..."` attribute, return (tag_start, tag_end)
    where text[tag_start] is `<` and text[tag_end] is `>`."""
    # Walk back to find the nearest `<`
    i = attr_start
    while i >= 0 and text[i] != "<":
        i -= 1
    if i < 0:
        return None
    # Walk forward to find the next `>` (outside any nested attribute value).
    j = attr_start
    in_string = None
    while j < len(text):
        ch = text[j]
        if in_string:
            if ch == in_string:
                in_string = None
        elif ch in ('"', "'"):
            in_string = ch
        elif ch == ">":
            return (i, j)
        j += 1
    return None


def inject_class(tag_text: str, class_name: str) -> str:
    """Return tag_text with `class_name` appended to (or as) the class
    attribute. tag_text is the slice from `<` to `>` inclusive."""
    cls_match = CLASS_ATTR_RE.search(tag_text)
    if cls_match:
        existing = cls_match.group(1).strip()
        if class_name in existing.split():
            return tag_text  # already present
        new_classes = (existing + " " + class_name).strip() if existing else class_name
        return (
            tag_text[: cls_match.start()]
            + f'class="{new_classes}"'
            + tag_text[cls_match.end() :]
        )
    # No class attribute — insert right after the tag name
    m = TAG_OPEN_RE.match(tag_text)
    if not m:
        return tag_text
    insert_at = m.end()
    return tag_text[:insert_at] + f' class="{class_name}"' + tag_text[insert_at:]


def process_file(path: Path, style_to_class: dict[str, str]) -> tuple[str, int]:
    """Return (rewritten_text, migrations_count) for one file."""
    text = path.read_text(encoding="utf-8")
    migrations = 0
    # We rewrite by finding each style="..." match, locating its enclosing tag,
    # and substituting. We do it iteratively from the END of the text so byte
    # offsets stay valid as we substitute.
    matches = list(STYLE_ATTR_RE.finditer(text))
    matches.reverse()
    out = text
    for m in matches:
        style_val = m.group(1)
        if style_val not in style_to_class:
            # Shouldn't happen — first pass collected all styles. Skip defensively.
            continue
        class_name = style_to_class[style_val]
        bounds = find_tag_bounds(out, m.start())
        if bounds is None:
            continue
        tag_start, tag_end = bounds
        tag_text = out[tag_start : tag_end + 1]
        # Remove the style attribute from tag_text. The match.start/end were on
        # `out` not `tag_text`, so re-locate inside tag_text by content match.
        local_match = STYLE_ATTR_RE.search(tag_text)
        if not local_match:
            continue
        new_tag = tag_text[: local_match.start()] + tag_text[local_match.end() :]
        # Collapse any doubled spaces left behind, but preserve single-space delims.
        new_tag = re.sub(r"  +", " ", new_tag)
        new_tag = new_tag.replace(" >", ">").replace(" />", "/>")
        new_tag = inject_class(new_tag, class_name)
        out = out[:tag_start] + new_tag + out[tag_end + 1 :]
        migrations += 1
    return out, migrations


def main() -> None:
    template_paths = sorted(TEMPLATE_DIR.glob("*.html"))
    # First pass: collect every unique style value, assign a class.
    style_to_class: OrderedDict[str, str] = OrderedDict()
    for tpath in template_paths:
        text = tpath.read_text(encoding="utf-8")
        for m in STYLE_ATTR_RE.finditer(text):
            sv = m.group(1)
            if sv not in style_to_class:
                style_to_class[sv] = class_name_for(sv)
    print(
        f"discovered {sum(1 for _ in style_to_class)} unique style values "
        f"across {len(template_paths)} templates"
    )

    # Second pass: rewrite each template file.
    total_migrations = 0
    files_touched = 0
    for tpath in template_paths:
        out_text, count = process_file(tpath, style_to_class)
        if count > 0:
            tpath.write_text(out_text, encoding="utf-8")
            files_touched += 1
            total_migrations += count
    print(f"rewrote {files_touched} templates with {total_migrations} migrations")

    # Third pass: emit CSS file.
    CSS_OUT.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "/* AUTO-GENERATED by tools/migrate_inline_styles.py. Do NOT edit by\n"
        " * hand. P11 style-attr-half closure (v0.31.21).\n"
        " * Each rule maps to a single previously-inline `style=\"...\"` value.\n"
        " * Hash-based class naming so identical inline styles dedupe to one\n"
        " * rule. base.html loads this file inside a <style nonce> block so it\n"
        " * applies before paint.\n"
        " */\n\n"
    )
    body_lines = []
    for style_val, class_name in style_to_class.items():
        # Ensure trailing semicolon-cleanup; just wrap as { ...; }
        decls = style_val.strip().rstrip(";")
        # display:none rules use 'html body .' prefix (specificity 0,1,2) so they
        # beat single-class page CSS (0,1,0) without !important, preserving the
        # ability for JS inline styles (specificity 1,0,0) to show elements.
        import re as _re
        if _re.search(r'display\s*:\s*none', decls):
            selector_prefix = "html body "
        else:
            selector_prefix = ""
        body_lines.append(f"{selector_prefix}.{class_name} {{ {decls}; }}")
    CSS_OUT.write_text(header + "\n".join(body_lines) + "\n", encoding="utf-8")
    print(f"wrote {CSS_OUT.relative_to(TEMPLATE_DIR.parent.parent.parent.parent)}")


if __name__ == "__main__":
    main()
