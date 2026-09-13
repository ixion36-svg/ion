"""Map every `_ion-s-*` hashed class to its Tailwind v4 equivalent.

Why a generated lookup rather than letting an agent improvise per rule: there
are 905 rules and 1,696 usages. An agent deciding "what's the Tailwind for
margin-bottom:0.5rem?" 905 times will be right most of the time, and the times
it is wrong are invisible — a slightly different margin looks fine and nobody
notices. A table is checkable once and applied mechanically.

What these classes actually are, measured 2026-09-13: 894 of 905 rules are
plain static styling (color, font-size, display, padding, margin), 1,687 of
1,696 usages sit in static `class="..."` markup, and ZERO templates construct
them in JavaScript. They are the residue of the v0.31.21 migration that hashed
existing static inline styles into classes to satisfy `style-src-attr 'none'`.
They are not, as `concepts/reskin-scope.md` states and as this repo's plan
previously repeated, carriers for JS-computed values.

Output classifies each rule:
  exact      - every declaration maps to a Tailwind utility; safe to swap
  arbitrary  - maps using Tailwind's arbitrary-value syntax, e.g. mb-[0.6rem]
  manual     - needs a human; reported rather than guessed

Usage:
    python tools/hashed_class_map.py             # write tools/hashed_class_map.json
    python tools/hashed_class_map.py --summary   # print coverage only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src/ion/web/static/css/ion-migrated-styles.css"
OUT = REPO / "tools/hashed_class_map.json"

# Tailwind's default spacing scale: rem value -> suffix.
SPACING = {
    0: "0", 0.125: "0.5", 0.25: "1", 0.375: "1.5", 0.5: "2", 0.625: "2.5",
    0.75: "3", 0.875: "3.5", 1: "4", 1.25: "5", 1.5: "6", 1.75: "7", 2: "8",
    2.25: "9", 2.5: "10", 3: "12", 3.5: "14", 4: "16",
}
FONT_SIZE = {
    0.75: "text-xs", 0.875: "text-sm", 1: "text-base", 1.125: "text-lg",
    1.25: "text-xl", 1.5: "text-2xl", 1.875: "text-3xl", 2.25: "text-4xl",
}
SIDE = {"margin": "m", "padding": "p"}
AXIS = {"top": "t", "right": "r", "bottom": "b", "left": "l"}

DISPLAY = {
    "none": "hidden", "block": "block", "flex": "flex", "grid": "grid",
    "inline": "inline", "inline-block": "inline-block", "inline-flex": "inline-flex",
}
SIMPLE = {
    "text-align": {"left": "text-left", "center": "text-center", "right": "text-right"},
    "font-weight": {"400": "font-normal", "500": "font-medium", "600": "font-semibold",
                    "700": "font-bold", "bold": "font-bold", "normal": "font-normal"},
    "text-transform": {"uppercase": "uppercase", "lowercase": "lowercase",
                       "capitalize": "capitalize", "none": "normal-case"},
    "align-items": {"center": "items-center", "flex-start": "items-start",
                    "flex-end": "items-end", "stretch": "items-stretch",
                    "baseline": "items-baseline"},
    "justify-content": {"center": "justify-center", "flex-start": "justify-start",
                        "flex-end": "justify-end", "space-between": "justify-between",
                        "space-around": "justify-around"},
    "flex-direction": {"column": "flex-col", "row": "flex-row",
                       "column-reverse": "flex-col-reverse", "row-reverse": "flex-row-reverse"},
    "flex-wrap": {"wrap": "flex-wrap", "nowrap": "flex-nowrap"},
    "overflow": {"hidden": "overflow-hidden", "auto": "overflow-auto",
                 "scroll": "overflow-scroll", "visible": "overflow-visible"},
    "position": {"relative": "relative", "absolute": "absolute", "fixed": "fixed",
                 "sticky": "sticky", "static": "static"},
    "cursor": {"pointer": "cursor-pointer", "default": "cursor-default",
               "not-allowed": "cursor-not-allowed"},
    "white-space": {"nowrap": "whitespace-nowrap", "pre-wrap": "whitespace-pre-wrap"},
    # Added after the first pass left 117 rules in the manual bucket. Auditing
    # why, only 26 were genuinely unmappable (JS-concatenated values); the rest
    # were properties Tailwind covers directly that this table simply did not
    # know about, so they were being deferred to a human for no reason.
    "overflow-y": {"auto": "overflow-y-auto", "hidden": "overflow-y-hidden",
                   "scroll": "overflow-y-scroll", "visible": "overflow-y-visible"},
    "overflow-x": {"auto": "overflow-x-auto", "hidden": "overflow-x-hidden",
                   "scroll": "overflow-x-scroll", "visible": "overflow-x-visible"},
    "text-overflow": {"ellipsis": "text-ellipsis", "clip": "text-clip"},
    "font-style": {"italic": "italic", "normal": "not-italic"},
    "vertical-align": {"middle": "align-middle", "top": "align-top",
                       "bottom": "align-bottom", "baseline": "align-baseline",
                       "text-top": "align-text-top", "text-bottom": "align-text-bottom"},
    "box-sizing": {"border-box": "box-border", "content-box": "box-content"},
    "flex-shrink": {"0": "shrink-0", "1": "shrink"},
    "flex-grow": {"0": "grow-0", "1": "grow"},
    "list-style": {"none": "list-none"},
    "list-style-type": {"none": "list-none", "disc": "list-disc", "decimal": "list-decimal"},
    "text-decoration": {"none": "no-underline", "underline": "underline",
                        "line-through": "line-through"},
    "text-decoration-line": {"none": "no-underline", "underline": "underline",
                             "line-through": "line-through"},
    "resize": {"none": "resize-none", "vertical": "resize-y",
               "horizontal": "resize-x", "both": "resize"},
    "user-select": {"none": "select-none", "all": "select-all", "text": "select-text"},
}

# grid-template-columns values with a numbered Tailwind utility. Spelled out
# rather than parsed because `repeat(3, 1fr)` and `1fr 1fr 1fr` describe the
# same grid and both spellings appear in the source.
GRID_COLS: dict[str, str] = {}
for _n in range(1, 13):
    for _spelling in (" ".join(["1fr"] * _n), f"repeat({_n},1fr)",
                      f"repeat({_n}, 1fr)", f"repeat({_n},minmax(0,1fr))",
                      f"repeat({_n}, minmax(0, 1fr))"):
        GRID_COLS[_spelling] = f"grid-cols-{_n}"

BORDER_SIDE = {"border-top": "t", "border-right": "r",
               "border-bottom": "b", "border-left": "l"}


def _border_shorthand(side: str, value: str) -> tuple[str | None, str]:
    """`3px solid #f00` -> `border-l-[3px] border-l-[#f00]`.

    Colour and width are separate utilities in Tailwind, so a one-line CSS
    shorthand becomes two. Anything that is not <width> <style> <colour> is
    handed back for a human rather than guessed at.
    """
    parts = value.split()
    if not parts:
        return None, "manual"
    width = parts[0]
    colour = " ".join(parts[2:]) if len(parts) > 2 else ""
    style = parts[1].lower() if len(parts) > 1 else "solid"
    if style not in ("solid", "none", "dashed", "dotted"):
        return None, "manual"
    if style == "none" or width in ("0", "0px"):
        return f"border-{side}-0", "exact"
    out = [f"border-{side}-[{width}]"]
    if colour:
        out.append(f"border-{side}-[{colour.replace(' ', '_')}]")
    if style in ("dashed", "dotted"):
        # Tailwind's border-style utility is not per-side; flag rather than
        # silently apply it to all four edges.
        return None, "manual"
    return " ".join(out), "arbitrary"


def escape_arbitrary(util: str) -> str:
    """Underscore the spaces inside a Tailwind arbitrary value.

    `border-radius:0 4px 4px 0` naively becomes `rounded-[0 4px 4px 0]`, and in
    a class attribute the browser splits that on whitespace into four tokens --
    `rounded-[0`, `4px`, `4px`, `0]` -- none of which is a class Tailwind
    generated. The radius silently does not apply.

    Two of these were already in the committed map (`rounded-[10px 10px 0 0]`
    and `flex-[0 0 auto]`); widening the mapper surfaced five more that had been
    hidden inside blanked manual rules. Escaping centrally here rather than at
    each call site, so a new handler cannot reintroduce it.
    """
    out, i = [], 0
    while i < len(util):
        j = util.find("[", i)
        if j == -1:
            out.append(util[i:])
            break
        k = util.find("]", j)
        if k == -1:
            out.append(util[i:])
            break
        out.append(util[i:j + 1])
        out.append(util[j + 1:k].replace(" ", "_"))
        out.append("]")
        i = k + 1
    return "".join(out)


def _rem(value: str) -> float | None:
    m = re.fullmatch(r"([\d.]+)rem", value)
    if m:
        return float(m.group(1))
    m = re.fullmatch(r"([\d.]+)px", value)
    if m:  # Tailwind's scale is rem-based at 16px root
        return float(m.group(1)) / 16
    if value == "0":
        return 0.0
    return None


def _spacing_util(prefix: str, value: str) -> tuple[str, str]:
    """Return (utility, kind)."""
    rem = _rem(value)
    if rem is not None and rem in SPACING:
        return f"{prefix}-{SPACING[rem]}", "exact"
    return f"{prefix}-[{value}]", "arbitrary"


def convert(prop: str, value: str) -> tuple[str | None, str]:
    prop, value = prop.strip().lower(), value.strip()

    if prop == "display":
        return (DISPLAY.get(value), "exact") if value in DISPLAY else (None, "manual")

    if prop in SIMPLE:
        return (SIMPLE[prop].get(value), "exact") if value in SIMPLE[prop] else (None, "manual")

    if prop == "font-size":
        rem = _rem(value)
        if rem is not None and rem in FONT_SIZE:
            return FONT_SIZE[rem], "exact"
        return f"text-[{value}]", "arbitrary"

    if prop in ("margin", "padding"):
        parts = value.split()
        p = SIDE[prop]
        if len(parts) == 1:
            return _spacing_util(p, parts[0])
        if len(parts) == 2:
            v, kind = _spacing_util(f"{p}y", parts[0])
            h, kind2 = _spacing_util(f"{p}x", parts[1])
            return f"{v} {h}", "exact" if kind == kind2 == "exact" else "arbitrary"
        if len(parts) in (3, 4):
            # CSS order is top right bottom left (3-value: top, x, bottom).
            top, right, bottom = parts[0], parts[1], parts[2]
            left = parts[3] if len(parts) == 4 else right
            outs, kinds = [], []
            for side, val in (("t", top), ("r", right), ("b", bottom), ("l", left)):
                u, k = _spacing_util(f"{p}{side}", val)
                outs.append(u)
                kinds.append(k)
            return " ".join(outs), "exact" if all(k == "exact" for k in kinds) else "arbitrary"
        return None, "manual"

    m = re.fullmatch(r"(margin|padding)-(top|right|bottom|left)", prop)
    if m:
        return _spacing_util(f"{SIDE[m.group(1)]}{AXIS[m.group(2)]}", value)

    if prop == "gap":
        return _spacing_util("gap", value)

    if prop == "color":
        return f"text-[{value}]", "arbitrary"
    if prop in ("background", "background-color"):
        if value in ("none", "transparent"):
            return "bg-transparent", "exact"
        # var(--x), hex and rgb all work as Tailwind arbitrary values.
        if re.fullmatch(r"#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|var\(--[\w-]+\)", value):
            return f"bg-[{value}]", "arbitrary"
        return None, "manual"          # gradients and images need a human
    if prop == "border-radius":
        return f"rounded-[{value}]", "arbitrary"
    if prop == "width":
        return ("w-full", "exact") if value == "100%" else (f"w-[{value}]", "arbitrary")
    if prop == "height":
        return ("h-full", "exact") if value == "100%" else (f"h-[{value}]", "arbitrary")
    if prop in ("min-width", "max-width", "min-height", "max-height"):
        short = {"min-width": "min-w", "max-width": "max-w",
                 "min-height": "min-h", "max-height": "max-h"}[prop]
        return f"{short}-[{value}]", "arbitrary"
    if prop == "flex":
        return ("flex-1", "exact") if value == "1" else (f"flex-[{value}]", "arbitrary")

    # --- position offsets -------------------------------------------------
    if prop in ("top", "right", "bottom", "left"):
        if value == "0":
            return f"{prop}-0", "exact"
        if value == "50%":
            return f"{prop}-1/2", "exact"
        return f"{prop}-[{value}]", "arbitrary"
    if prop == "inset":
        return ("inset-0", "exact") if value == "0" else (f"inset-[{value}]", "arbitrary")
    if prop == "z-index":
        return f"z-[{value}]", "arbitrary"

    # The single most common transform in this codebase: centring a modal.
    if prop == "transform":
        if re.fullmatch(r"translate\(\s*-50%\s*,\s*-50%\s*\)", value):
            return "-translate-x-1/2 -translate-y-1/2", "exact"
        return f"[transform:{value.replace(' ', '_')}]", "arbitrary"

    if prop == "border":
        if value == "none":
            return "border-0", "exact"
        m = re.fullmatch(r"(\S+)\s+solid\s+(.+)", value)
        if m:
            w, colour = m.group(1), m.group(2).strip()
            wu = "border" if w in ("1px", "0.0625rem") else f"border-[{w}]"
            return f"{wu} border-[{colour}]", "arbitrary"
        return None, "manual"
    m = re.fullmatch(r"border-(top|right|bottom|left)", prop)
    if m and value == "none":
        return f"border-{AXIS[m.group(1)]}-0", "exact"
    if prop == "border-color":
        return f"border-[{value}]", "arbitrary"

    if prop == "align-self":
        return {"center": "self-center", "flex-start": "self-start",
                "flex-end": "self-end", "stretch": "self-stretch"}.get(value), \
               ("exact" if value in ("center", "flex-start", "flex-end", "stretch") else "manual")
    if prop == "grid-column" and value in ("1/-1", "1 / -1"):
        return "col-span-full", "exact"
    if prop == "resize":
        return {"vertical": "resize-y", "horizontal": "resize-x",
                "none": "resize-none", "both": "resize"}.get(value), \
               ("exact" if value in ("vertical", "horizontal", "none", "both") else "manual")
    if prop == "opacity":
        try:
            return f"opacity-{int(float(value) * 100)}", "exact"
        except ValueError:
            return None, "manual"
    if prop == "line-height":
        return f"leading-[{value}]", "arbitrary"
    if prop == "letter-spacing":
        return f"tracking-[{value}]", "arbitrary"
    if prop == "box-shadow":
        return ("shadow-none", "exact") if value == "none" else \
               (f"shadow-[{value.replace(' ', '_')}]", "arbitrary")
    if prop == "text-decoration":
        return {"none": "no-underline", "underline": "underline",
                "line-through": "line-through"}.get(value), \
               ("exact" if value in ("none", "underline", "line-through") else "manual")
    if prop == "font-family":
        if "mono" in value.lower():
            return "font-mono", "exact"
        return f"[font-family:{value.replace(' ', '_')}]", "arbitrary"
    if prop == "object-fit":
        return {"cover": "object-cover", "contain": "object-contain"}.get(value), \
               ("exact" if value in ("cover", "contain") else "manual")
    if prop == "pointer-events":
        return {"none": "pointer-events-none", "auto": "pointer-events-auto"}.get(value), \
               ("exact" if value in ("none", "auto") else "manual")
    if prop == "word-break":
        return {"break-all": "break-all", "break-word": "break-words"}.get(value), \
               ("exact" if value in ("break-all", "break-word") else "manual")
    if prop == "backdrop-filter":
        return f"[backdrop-filter:{value.replace(' ', '_')}]", "arbitrary"

    if prop == "grid-template-columns":
        key = " ".join(value.split())
        if key in GRID_COLS:
            return GRID_COLS[key], "exact"
        return f"grid-cols-[{key.replace(' ', '_')}]", "arbitrary"

    if prop == "grid-column":
        v = " ".join(value.split())
        if v in ("1 / -1", "1/-1"):
            return "col-span-full", "exact"
        m = re.fullmatch(r"span (\d+)(?: / span \d+)?", v)
        if m:
            return f"col-span-{m.group(1)}", "exact"
        return f"col-[{v.replace(' ', '_')}]", "arbitrary"

    if prop in BORDER_SIDE:
        return _border_shorthand(BORDER_SIDE[prop], value)

    if prop == "border":
        parts = value.split()
        if value.strip() in ("0", "none", "0px"):
            return "border-0", "exact"
        if len(parts) >= 2 and parts[1].lower() == "solid":
            colour = " ".join(parts[2:])
            out = [f"border-[{parts[0]}]"]
            if colour:
                out.append(f"border-[{colour.replace(' ', '_')}]")
            return " ".join(out), "arbitrary"
        return None, "manual"

    if prop == "background":
        # Only a plain colour is safe to fold into bg-[...]; a gradient or a
        # multi-part shorthand needs a person.
        v = value.strip()
        if re.fullmatch(r"(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|hsla?\([^)]*\)"
                        r"|transparent|currentColor|var\(--[\w-]+\))", v):
            return f"bg-[{v.replace(' ', '_')}]", "arbitrary"
        return None, "manual"

    if prop == "fill":
        return f"fill-[{value.replace(' ', '_')}]", "arbitrary"

    if prop == "transition":
        return f"[transition:{value.replace(' ', '_')}]", "arbitrary"

    return None, "manual"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    css = SRC.read_text(encoding="utf-8")
    rules = re.findall(r"\.(_?ion-s-[a-z0-9]+)\s*\{([^}]*)\}", css)

    # Some rules are not CSS at all. The v0.31.21 migration hashed inline styles
    # that were built by JavaScript string concatenation, producing rules like
    #   .ion-s-5245a21b9b { top:' + (cy - r2 - 55) + 'px; }
    # A naive converter turns that into `top-[' + (cy - r2 - 55) + 'px]`, which
    # is meaningless. These can only be fixed by rewriting the JS that emits
    # them, so they are forced unmappable.
    JS_ARTIFACT = re.compile(r"\+\s*'|'\s*\+|\$\{")

    mapping, counts = {}, {"exact": 0, "arbitrary": 0, "manual": 0}
    for name, body in rules:
        utils, kinds, unmapped = [], [], []
        for decl in body.split(";"):
            if ":" not in decl:
                continue
            prop, value = decl.split(":", 1)
            util, kind = convert(prop, value)
            if util is None:
                unmapped.append(decl.strip())
                kinds.append("manual")
            else:
                utils.append(escape_arbitrary(util))
                kinds.append(kind)
        kind = "manual" if "manual" in kinds else ("arbitrary" if "arbitrary" in kinds else "exact")
        if JS_ARTIFACT.search(body):
            kind = "manual"
            unmapped.append("JS-concatenated value — not real CSS")
        counts[kind] += 1
        # Key on the class name EXACTLY as it appears in templates, underscore
        # included. Stripping it produced a map with zero overlap against the
        # baseline, so Grok looked up `_ion-s-X`, found nothing, and converted
        # nothing — while the verifier flagged every class as unknown and rolled
        # the page back. Silent on both sides until the keys were compared.
        # A "manual" rule has SOME declarations that map and some that do not.
        # Publishing the partial string invites an agent to apply it and
        # silently lose the rest — e.g. `display:grid;grid-template-columns:...`
        # would become `grid gap-3` with the columns quietly dropped. Blank the
        # actionable field so the only valid move is to leave the class alone.
        mapping[name] = {
            "css": body.strip(),
            # Order-preserving dedupe. One source rule declares display:none
            # twice (.ion-s-47c5a3e01b), which produced "hidden flex-1 hidden
            # flex-col". Semantically fine, but duplicate classes in the markup
            # are noise a reader will stop to puzzle over.
            "tailwind": "" if kind == "manual" else " ".join(dict.fromkeys(utils)),
            "kind": kind,
            "unmapped": unmapped,
            **({"partial_do_not_apply": " ".join(utils)} if kind == "manual" and utils else {}),
        }

    total = len(rules)
    print(f"rules: {total}")
    for k in ("exact", "arbitrary", "manual"):
        print(f"  {k:9s}: {counts[k]:4d}  ({counts[k]*100//max(total,1)}%)")

    if not args.summary:
        OUT.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwritten: {OUT}")
        manual = [n for n, v in mapping.items() if v["kind"] == "manual"]
        if manual:
            print(f"\n{len(manual)} rule(s) need a human; first 10:")
            for n in manual[:10]:
                print(f"  .{n} {{ {mapping[n]['css'][:80]} }}")
                if mapping[n]["unmapped"]:
                    print(f"      unmapped: {mapping[n]['unmapped'][:3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
