"""Fingerprint every element's computed style, so a CSS move can be proved inert.

The redesign's `styled` column is passed by deleting a template's inline
`<style>` and putting those rules in the compiled sheet. That is a cascade
change, not a copy: an inline `<style>` sits after every linked stylesheet,
so rules that used to beat a Tailwind utility can quietly lose once they move
into an imported file. The failure is silent, which is the whole problem with
this kind of edit.

So: snapshot before, move, snapshot after, diff. An empty diff is the proof.
A non-empty one names the element and the property that changed.

    python tools/style_snapshot.py --out before.json --pages /guide /notes
    ... make the change, rebuild, restart ...
    python tools/style_snapshot.py --out after.json --pages /guide /notes
    python tools/style_snapshot.py --diff before.json after.json

Elements are keyed by a structural path rather than by index, so a page whose
content shifts by one node does not report every element as changed.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

#: Properties a restyle would plausibly change. Deliberately not the whole
#: computed set, which includes dozens of values that differ run to run
#: (resolved widths, scroll offsets) and would bury a real difference.
PROPS = [
    "color", "background-color", "border-top-color", "border-bottom-color",
    "border-left-color", "border-right-color", "border-top-width",
    "border-bottom-width", "border-radius", "font-size", "font-weight",
    "font-family", "line-height", "letter-spacing", "text-transform",
    "text-align", "display", "flex-direction", "justify-content",
    "align-items", "gap", "padding-top", "padding-right", "padding-bottom",
    "padding-left", "margin-top", "margin-bottom", "opacity", "visibility",
    "text-decoration-line",
    # box-shadow and background-image are excluded: ION animates a
    # pulsing glow, so two captures differ by an animation frame
    # (0.02 vs 0.016 alpha) and bury real differences in noise.
]

PROBE = """
(props) => {
  const path = el => {
    const parts = [];
    for (let n = el; n && n !== document.body; n = n.parentElement) {
      const sibs = [...(n.parentElement ? n.parentElement.children : [])];
      const same = sibs.filter(s => s.tagName === n.tagName);
      const idx = same.indexOf(n);
      const cls = (typeof n.className === 'string' ? n.className : '')
        .trim().split(/\\s+/).slice(0, 3).join('.');
      parts.unshift(n.tagName.toLowerCase() + (cls ? '.' + cls : '')
        + (same.length > 1 ? `[${idx}]` : ''));
    }
    return parts.join('>');
  };
  const out = {};
  // Non-rendering nodes are skipped. A <style> block in the content area is
  // itself an element, so deleting one (which is the point of the `styled`
  // column) would otherwise show up as a diff on every page.
  const SKIP = new Set(['STYLE', 'SCRIPT', 'LINK', 'META', 'TEMPLATE', 'TITLE']);
  for (const el of document.querySelectorAll('body *')) {
    if (SKIP.has(el.tagName)) continue;
    const cs = getComputedStyle(el);
    const rec = {};
    for (const p of props) rec[p] = cs.getPropertyValue(p);
    const k = path(el);
    // A repeated structural path (a list built at runtime) gets a suffix so
    // entries never overwrite each other.
    let key = k, n = 1;
    while (key in out) key = `${k}#${++n}`;
    out[key] = rec;
  }
  return out;
}
"""


def capture(base: str, cookies: str, paths: list[str], modes: list[str]) -> dict:
    from playwright.sync_api import sync_playwright

    jar = http.cookiejar.MozillaCookieJar(cookies)
    jar.load(ignore_discard=True, ignore_expires=True)
    cks = [
        {"name": c.name, "value": c.value, "domain": "127.0.0.1", "path": "/"}
        for c in jar
    ]
    snap: dict = {}
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(viewport={"width": 1500, "height": 1100})
        ctx.add_cookies(cks)
        pg = ctx.new_page()
        for path in paths:
            for mode in modes:
                try:
                    r = pg.goto(base + path, wait_until="domcontentloaded", timeout=30000)
                except Exception as exc:  # noqa: BLE001
                    print(f"  {path} {mode}: load failed {str(exc)[:50]}")
                    continue
                if r is None or r.status >= 400:
                    print(f"  {path} {mode}: HTTP {r.status if r else '?'}")
                    continue
                pg.evaluate(f"document.documentElement.setAttribute('data-mode','{mode}')")
                pg.wait_for_timeout(1000)
                snap[f"{path}|{mode}"] = pg.evaluate(PROBE, PROPS)
                print(f"  {path:24} {mode:6} {len(snap[f'{path}|{mode}'])} elements")
        b.close()
    return snap


def diff(a_path: Path, b_path: Path) -> int:
    a = json.loads(a_path.read_text(encoding="utf-8"))
    b = json.loads(b_path.read_text(encoding="utf-8"))
    changed = 0
    for scope in sorted(set(a) | set(b)):
        ea, eb = a.get(scope, {}), b.get(scope, {})
        only_a = set(ea) - set(eb)
        only_b = set(eb) - set(ea)
        rows = []
        for key in sorted(set(ea) & set(eb)):
            for prop, va in ea[key].items():
                vb = eb[key].get(prop)
                if va != vb:
                    rows.append((key, prop, va, vb))
        if not rows and not only_a and not only_b:
            print(f"  {scope:34} identical ({len(ea)} elements)")
            continue
        changed += len(rows) + len(only_a) + len(only_b)
        print(f"\n  {scope}: {len(rows)} property change(s), "
              f"{len(only_a)} gone, {len(only_b)} new")
        for key, prop, va, vb in rows[:14]:
            print(f"      {key[-58:]:58} {prop}")
            print(f"          before {va[:52]!r}")
            print(f"          after  {vb[:52]!r}")
        if len(rows) > 14:
            print(f"      ... and {len(rows) - 14} more")
        for key in sorted(only_a)[:5]:
            print(f"      GONE {key[-62:]}")
        for key in sorted(only_b)[:5]:
            print(f"      NEW  {key[-62:]}")
    print(f"\n{changed} difference(s)")
    return 0 if changed == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8010")
    ap.add_argument("--cookies")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--pages", nargs="*")
    ap.add_argument("--modes", nargs="*", default=["light", "dark"])
    ap.add_argument("--diff", nargs=2, type=Path)
    args = ap.parse_args()

    if args.diff:
        return diff(*args.diff)

    if not (args.out and args.cookies):
        ap.error("--out and --cookies are required unless --diff is used")
    paths = args.pages
    if not paths:
        from ion.web.nav import destinations
        paths = list(destinations())
    snap = capture(args.base, args.cookies, paths, args.modes)
    args.out.write_text(json.dumps(snap, indent=0, sort_keys=True), encoding="utf-8")
    total = sum(len(v) for v in snap.values())
    print(f"\nwrote {args.out} ({total} elements across {len(snap)} page-modes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
