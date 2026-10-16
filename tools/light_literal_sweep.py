"""Replace bright dark-mode colour literals with tokens that flip per mode.

After the shared components were fixed, every contrast failure left in the
app was a one-page singleton: each page's own component prefix (`sr-` on
/soc-roles, `tt-` on /training, `fr-` on /forensics) hardcodes a Tailwind
400-level brand colour as text. Those read fine on the dark page and fail on
the white one, and no token flip can reach a literal.

They share a shape, so they can be swept rather than hand-edited. The
mapping is declared below, each entry measured: a literal goes to the ION
token whose dark value it already matches, so dark mode is unchanged by
construction and light mode gains the flip it never had.

    python tools/light_literal_sweep.py            # report only
    python tools/light_literal_sweep.py --apply    # rewrite

A literal is only touched when it is the value of `color` and its own rule
sets no background, which is the same test tools/ui_redesign_status.py uses
and for the same reason: `color:#fff` on a coloured fill is correct, and
rewriting it would break a working badge. Verified by re-crawling after.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "src" / "ion" / "web" / "templates"

#: literal -> (token, why). The token's DARK value equals the literal, or is
#: close enough that the dark page does not change perceptibly; its LIGHT
#: value is the darkened one from ion-legacy.css's light ramp.
MAPPING = {
    "#4ade80": ("var(--mitre-covered)", "green-400, 1.74:1 as text on white"),
    "#34d3ee": ("var(--color-ion-cyan)", "cyan, 1.66:1 on white"),
    "#fbbf24": ("var(--warning)", "amber-400, 1.52:1 on white"),
    "#bc8cff": ("var(--sev-info)", "purple, 2.10:1 on white"),
    "#f8b33a": ("var(--warning)", "ion amber, 1.77:1 on white"),
    "#6de4ff": ("var(--color-ion-cyan)", "ion cyan, 1.44:1 on white"),
    "#86f0a0": ("var(--success)", "ion lime, 1.48:1 on white"),
    "#ff6c6c": ("var(--danger)", "ion coral, 2.55:1 on white"),
    "#cbd5e1": ("var(--text-primary)", "slate-300, 1.52:1 on white"),
    "#94a3b8": ("var(--text-secondary)", "slate-400, 2.56:1 on white"),
    "#f5a524": ("var(--warning)", "amber-ish, 1.95:1 on white"),
    "#a78bfa": ("var(--sev-info)", "violet-400, 2.50:1 on white"),
    "#fb923c": ("var(--neon-orange)", "orange-400, 2.17:1 on white"),
    "#a3e635": ("var(--neon-lime)", "lime-400, 1.51:1 on white"),
    "#93c5fd": ("var(--neon-sky)", "blue-300, 1.80:1 on white"),
    "#2dd4bf": ("var(--neon-teal)", "teal-400, 1.86:1 on white"),
    "#a5b4cb": ("var(--text-secondary)", "slate-ish, 2.10:1 on white"),
    "#f472b6": ("var(--neon-pink)", "pink-400, 2.65:1 on white"),
    "#fb7185": ("var(--neon-rose)", "rose-400, 2.69:1 on a card"),
}

RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
# `color:` only, never background-color or border-color.
COLOR_DECL = re.compile(r"(?<![-\w])color\s*:\s*(#[0-9a-fA-F]{6})\b")
OWN_BG = re.compile(
    r"(?<![-\w])background(?:-color|-image)?\s*:\s*"
    r"(?!\s*(?:transparent|none|inherit|initial|unset)\s*[;}])",
    re.I,
)


#: A page-local accent token holding a mapped literal, e.g.
#: `.sr-c-cyan { --sr-ac: #34d3ee; --sr-tint: color-mix(... #34d3ee 8% ...) }`.
#: /soc-roles and /training define their palettes this way, so the literal is
#: never the value of `color` and the rule above cannot see it.
#:
#: Rewriting the definition fixes every consumer at once, including the tints
#: derived with color-mix. Checked before enabling: on /soc-roles the token is
#: read by 5 `color`, 2 `border-color` and exactly one `background`, and that
#: background is a 7px round dot with no text in it, so a darker light-mode
#: value makes it more visible rather than less. Opt-in per template, because
#: a page whose accent token fills something that carries text would need its
#: foreground moved in the same edit.
CUSTOM_PROP = re.compile(r"(--[\w-]+\s*:\s*)(#[0-9a-fA-F]{6})\b")


def sweep_custom_props(css: str) -> tuple[str, list[tuple[str, str, str]]]:
    changes: list[tuple[str, str, str]] = []

    def repl(m):
        lit = m.group(2).lower()
        if lit not in MAPPING:
            return m.group(0)
        token = MAPPING[lit][0]
        changes.append((m.group(1).strip().rstrip(":"), lit, token))
        return m.group(1) + token

    # color-mix(... #hex N% ...) occurrences too, so a tint follows its accent.
    out = CUSTOM_PROP.sub(repl, css)

    def mix_repl(m):
        lit = m.group(1).lower()
        if lit not in MAPPING:
            return m.group(0)
        changes.append(("color-mix tint", lit, MAPPING[lit][0]))
        return m.group(0).replace(m.group(1), MAPPING[lit][0])

    out = re.sub(r"(?<=color-mix\(in oklab, )(#[0-9a-fA-F]{6})", mix_repl, out)
    out = re.sub(r"(?<=color-mix\(in srgb, )(#[0-9a-fA-F]{6})", mix_repl, out)
    return out, changes


def sweep_text(css: str) -> tuple[str, list[tuple[str, str, str]]]:
    """Return the rewritten CSS and the (selector, literal, token) changes."""
    changes: list[tuple[str, str, str]] = []
    out, last = [], 0
    for m in RULE.finditer(css):
        out.append(css[last:m.start()])
        sel, body = m.group(1), m.group(2)
        if OWN_BG.search(body):
            out.append(m.group(0))
            last = m.end()
            continue

        def repl(d):
            lit = d.group(1).lower()
            if lit not in MAPPING:
                return d.group(0)
            token = MAPPING[lit][0]
            changes.append((" ".join(sel.split())[:44], lit, token))
            return d.group(0).replace(d.group(1), token)

        out.append(m.group(0).replace(body, COLOR_DECL.sub(repl, body)))
        last = m.end()
    out.append(css[last:])
    return "".join(out), changes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--only", nargs="*", help="limit to these template names")
    ap.add_argument(
        "--custom-props", nargs="*", default=[],
        help="templates whose page-local accent tokens may also be rewritten; "
             "check first that none of them fills an element carrying text",
    )
    args = ap.parse_args()

    total = 0
    for path in sorted(TEMPLATES.glob("*.html")):
        if args.only and path.name not in args.only:
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        new_src, all_changes = src, []
        # Only inside <style> blocks; markup is left alone.
        do_props = path.name in args.custom_props
        for sm in list(re.finditer(r"<style[^>]*>(.*?)</style>", src, re.S))[::-1]:
            swept, changes = sweep_text(sm.group(1))
            if do_props:
                swept, prop_changes = sweep_custom_props(swept)
                changes = changes + prop_changes
            if changes:
                all_changes = changes + all_changes
                new_src = new_src[: sm.start(1)] + swept + new_src[sm.end(1):]
        if not all_changes:
            continue
        total += len(all_changes)
        print(f"\n{path.name}: {len(all_changes)} literal(s)")
        for sel, lit, token in all_changes[:8]:
            print(f"    {sel:46} {lit} -> {token}")
        if len(all_changes) > 8:
            print(f"    ... and {len(all_changes) - 8} more")
        if args.apply:
            path.write_text(new_src, encoding="utf-8")

    print(f"\n{total} literal(s) {'rewritten' if args.apply else 'would be rewritten'}")
    if not args.apply and total:
        print("re-run with --apply, then rebuild ion.css and re-crawl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
