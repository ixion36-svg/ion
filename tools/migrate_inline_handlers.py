"""Migrate inline `on${event}="..."` handlers to data-${event}-action delegation.

Used in v0.31.4+ Secure-by-Design P11 work to retire inline event handlers
template-by-template so CSP `script-src-attr 'unsafe-inline'` can eventually
flip to `'none'`. The companion delegated dispatcher lives at
`src/ion/web/static/js/event-delegation.js`.

This script handles the common patterns mechanically:

  onclick="fn()"
    → data-click-action="fn"

  onclick="fn(${expr}, 'literal')"
    → data-click-action="fn" data-args='[${expr}, "literal"]'

  onchange="fn(this.value)"
    → data-change-action="fn" data-args='["$value"]'

  onclick="event.stopPropagation()"
    → data-stop-propagation

  onclick="event.stopPropagation(); fn(...)"
    → data-click-action="fn" data-stop-propagation [+ data-args]

  onclick="if(event.target===this)fn()"
    → data-click-action="fn" data-only-self-click

  onclick="if(event.target===this)this.remove()"
    → data-remove-self-on-self-click

  onclick="document.getElementById('foo').remove()"
    → data-remove-target="foo"

  onclick="fn(); return false"
    → data-click-action="fn" data-prevent-default

Edge cases the script can't handle (chained user-function calls, runtime
DOM lookups passed as args) are LISTED, not migrated. Hand-fix those.

Usage:
    python tools/migrate_inline_handlers.py <template-path> [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional


# Events the helper handles. Order matters — we look for these in source.
EVENTS = [
    "click", "change", "input", "submit",
    "keydown", "keyup", "blur", "focus",
    "dragstart", "dragend", "dragover", "dragenter", "dragleave", "drop",
]

# Match an inline handler attribute. The value is single-pass — no nested
# quotes that would defeat the regex.
ATTR_RE = re.compile(
    r'\bon('
    + '|'.join(EVENTS)
    + r')="([^"]+)"'
)


class Unmigratable(Exception):
    """Raised when the script doesn't know how to translate a handler value."""


def _split_arg_list(s: str) -> list[str]:
    """Split a comma-separated argument list, respecting nested () and quotes.

    The input is the body between an outer `(` and `)`. JS-string contents
    may contain commas that aren't separators (`'hello, world'`); ${...}
    expressions may contain commas inside their own function calls
    (`escapeHtml(a, b)`). Naive `s.split(',')` would break both.
    """
    args: list[str] = []
    depth = 0
    in_single = False
    in_double = False
    cur: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        # Handle template-literal placeholder ${...} as opaque
        if c == '$' and i + 1 < len(s) and s[i + 1] == '{' and not in_single and not in_double:
            # Find matching close brace, allowing nesting.
            j = i + 2
            nest = 1
            while j < len(s) and nest:
                if s[j] == '{':
                    nest += 1
                elif s[j] == '}':
                    nest -= 1
                j += 1
            cur.append(s[i:j])
            i = j
            continue
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            elif c == ',' and depth == 0:
                args.append(''.join(cur).strip())
                cur = []
                i += 1
                continue
        cur.append(c)
        i += 1
    if cur:
        args.append(''.join(cur).strip())
    return [a for a in args if a]  # drop empty for fn() case


def _arg_to_json(arg: str) -> str:
    """Convert a single JS-argument string into a JSON-fragment string usable
    inside a `data-args='[...]'` attribute.

    Rules:
      'literal'             → "literal"
      'pre-${expr}-suf'     → "pre-${expr}-suf"  (single→double quotes)
      ${expr}               → ${expr}            (numeric/passthrough)
      this.value            → "$value"
      this.checked          → "$checked"
      this                  → "$target"
      event                 → "$event"
      123                   → 123
      otherwise             → unchanged (e.g. variable identifiers)
    """
    s = arg.strip()
    if s == "this.value":
        return '"$value"'
    if s == "this.checked":
        return '"$checked"'
    if s == "this":
        return '"$target"'
    if s == "event":
        return '"$event"'
    # Numeric literal
    if re.fullmatch(r"-?\d+(?:\.\d+)?", s):
        return s
    # JS-quoted string literal — may contain ${...} interpolations. Swap the
    # outer single quotes for JSON double quotes; assume inner ${} produces
    # an HTML-attribute-escaped value (the templates use escapeHtml(...) for
    # this).
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return '"' + s[1:-1] + '"'
    # Already a ${expr} or some identifier — assume it stringifies to a
    # number or already-JSON-quoted value. Numbers are common (ids); for
    # bare ${expr} the helper's substituteRuntimeArgs ignores
    # non-string-sentinels and JSON.parse handles numbers.
    return s


def _translate_handler(value: str) -> Optional[dict[str, Optional[str]]]:
    """Translate an inline handler body into delegated data-attributes.

    Returns a dict of { attribute_name: value } to emit, or None if the
    pattern is unmigratable (caller should leave it alone and flag).
    """
    # JS-source-escape pattern: when an onclick attribute lives INSIDE a
    # JS single-quoted string (e.g. `html += '<button onclick="fn(\'x\')">'`),
    # the captured value contains `\'` escape sequences. The regex matched
    # across an actual quote boundary in the JS source. Naively converting
    # would produce a broken JS literal. Flag for manual handling — these
    # spots need the data-args attribute to be JS-string-aware (escape the
    # `'` that delimits the HTML attribute as `\'` so the outer JS string
    # parser doesn't terminate early).
    if "\\'" in value or '\\"' in value:
        return None

    s = value.strip().rstrip(';').strip()
    flags: dict[str, Optional[str]] = {}

    # if(event.target===this)X — only-self-click gate
    m = re.fullmatch(
        r"if\(event\.target===this\)\s*(.+)", s, flags=re.DOTALL
    )
    if m:
        flags["data-only-self-click"] = ""
        s = m.group(1).strip().rstrip(';').strip()

    # this.remove() — used for the modal-backdrop self-remove pattern
    if s == "this.remove()":
        if "data-only-self-click" in flags:
            flags.pop("data-only-self-click")
            flags["data-remove-self-on-self-click"] = ""
            return flags
        # Bare this.remove() without the self-click gate would remove on any
        # bubbled click; that's unusual — leave it for manual review.
        return None

    # Trailing "; return false" → data-prevent-default
    rf = re.search(r";\s*return\s+false\s*$", s)
    if rf:
        flags["data-prevent-default"] = ""
        s = s[: rf.start()].strip().rstrip(';').strip()

    # Leading event.stopPropagation(); → data-stop-propagation
    sp = re.match(r"event\.stopPropagation\(\)\s*;?", s)
    if sp:
        flags["data-stop-propagation"] = ""
        s = s[sp.end():].strip()

    if not s:
        # Only had stopPropagation / preventDefault / etc — no further call
        return flags or None

    # document.getElementById('FOO').remove()
    m = re.fullmatch(
        r"document\.getElementById\(\s*['\"]([^'\"]+)['\"]\s*\)\.remove\(\)",
        s,
    )
    if m:
        flags["data-remove-target"] = m.group(1)
        return flags

    # this.parentElement.remove() — used for tag/badge dismissal patterns
    if s == "this.parentElement.remove()":
        flags["data-remove-parent"] = ""
        return flags

    # this.closest('SELECTOR').remove() — used for row/card dismissal patterns
    m = re.fullmatch(
        r"this\.closest\(\s*['\"]([^'\"]+)['\"]\s*\)\.remove\(\)",
        s,
    )
    if m:
        flags["data-remove-closest"] = m.group(1)
        return flags

    # Chained user-function calls: fn1(...); fn2(...);
    # Can't represent as a single data-action; flag for manual.
    if ";" in s and re.search(r"\)\s*;\s*\w+\s*\(", s):
        return None

    # Plain function call: fn() or fn(args)
    m = re.fullmatch(r"(\w+)\((.*)\)", s, flags=re.DOTALL)
    if not m:
        return None
    fn_name, args_body = m.group(1), m.group(2).strip()

    # Reject if args contain runtime DOM lookups we can't substitute
    if "document.querySelector" in args_body or "document.getElementById" in args_body:
        return None

    flags["__fn_name"] = fn_name
    if args_body:
        arg_list = _split_arg_list(args_body)
        try:
            json_args = [_arg_to_json(a) for a in arg_list]
        except Exception:
            return None
        flags["data-args"] = "[" + ", ".join(json_args) + "]"
    return flags


def _emit_attributes(event_name: str, translated: dict[str, Optional[str]]) -> str:
    """Build the replacement attribute string for the migrated element."""
    parts: list[str] = []
    fn_name = translated.pop("__fn_name", None)
    if fn_name:
        parts.append(f'data-{event_name}-action="{fn_name}"')
    for attr, val in translated.items():
        if val is None or val == "":
            parts.append(attr)
        elif attr == "data-args":
            # The args attribute uses single-quote wrapping so its JSON
            # double-quotes don't collide.
            parts.append(f"data-args='{val}'")
        else:
            parts.append(f'{attr}="{val}"')
    return " ".join(parts)


def migrate(path: Path, dry_run: bool) -> tuple[int, int, list[tuple[int, str]]]:
    """Migrate one template. Returns (translated, skipped, [(line, value), ...])."""
    text = path.read_text(encoding="utf-8")
    translated_count = 0
    skipped: list[tuple[int, str]] = []

    def replace(match: re.Match) -> str:
        nonlocal translated_count
        event = match.group(1)
        value = match.group(2)
        result = _translate_handler(value)
        if result is None:
            line = text.count("\n", 0, match.start()) + 1
            skipped.append((line, match.group(0)))
            return match.group(0)
        translated_count += 1
        return _emit_attributes(event, result)

    new_text = ATTR_RE.sub(replace, text)
    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return translated_count, len(skipped), skipped


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("template")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    path = Path(args.template)
    if not path.exists():
        print(f"ERROR: not found: {path}")
        return 2

    translated, n_skipped, skipped = migrate(path, dry_run=args.dry_run)
    action = "would migrate" if args.dry_run else "migrated"
    print(f"{action} {translated} handlers; skipped {n_skipped} unmigratable.")
    if skipped:
        print("\nSkipped (need manual handling):")
        for line, val in skipped[:30]:
            print(f"  {path}:{line}  {val}")
        if len(skipped) > 30:
            print(f"  ... and {len(skipped) - 30} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
