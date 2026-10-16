"""Find every unreadable element on every page, in both modes, by rendering.

Grepping the stylesheets for light-on-dark literals finds 133 candidates
across 24 templates, but it cannot tell `.case-badge{color:white}` sitting
on a coloured fill (fine) from `.np-note-title{color:#fff}` on the page
(invisible in light mode). Rewriting both the same way breaks the first.

So this measures the composited result in a real browser instead. For
every element that paints text, it walks up for the first non-transparent
background, composites any alpha, and computes the WCAG ratio. What comes
back is the work list, not a suspicion list.

Needs a running ION and a session cookie jar:

    python tools/contrast_crawl.py --base http://127.0.0.1:8010 \\
        --cookies <path to a Mozilla cookie jar> --out contrast.json
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# WCAG AA. 3.0 is the large-text and non-text floor; 4.5 is body text.
AA_TEXT = 4.5
AA_LARGE = 3.0

# Collected in the page, because only the browser knows the real cascade.
PROBE = r"""
() => {
  const lin = c => c <= 0.03928 ? c/12.92 : Math.pow((c+0.055)/1.055, 2.4);
  const lum = ([r,g,b]) => 0.2126*lin(r/255) + 0.7152*lin(g/255) + 0.0722*lin(b/255);

  // Tailwind v4 emits oklab and oklch, so getComputedStyle returns strings
  // like "oklab(0.93 -0.0008 -0.0087 / 0.6)". Pulling the first three
  // numbers out of that treats lightness and two signed axes as RGB bytes
  // and reports almost any such colour as near-black. An earlier version
  // of this file did exactly that and claimed 1383 unreadable elements in
  // dark mode on pages that are plainly fine.
  // A canvas resolves any CSS colour string to sRGB bytes, whatever the
  // colour space, so the renderer does the conversion rather than a regex.
  const _cv = document.createElement('canvas');
  _cv.width = _cv.height = 1;
  const _cx = _cv.getContext('2d', { willReadFrequently: true });
  const _memo = new Map();
  const parse = s => {
    if (!s) return null;
    if (_memo.has(s)) return _memo.get(s);
    let out = null;
    try {
      _cx.clearRect(0, 0, 1, 1);
      _cx.fillStyle = '#000';
      _cx.fillStyle = s;               // invalid strings leave it at #000
      if (_cx.fillStyle !== '#000000' || /^#0{3,8}$|black|rgba?\(0, ?0, ?0/i.test(s.trim())) {
        _cx.clearRect(0, 0, 1, 1);
        _cx.fillRect(0, 0, 1, 1);
        const d = _cx.getImageData(0, 0, 1, 1).data;
        out = [d[0], d[1], d[2], d[3] / 255];
      }
    } catch (e) { out = null; }
    _memo.set(s, out);
    return out;
  };
  const over = (f, b) => [0,1,2].map(i => f[i]*f[3] + b[i]*(1-f[3]));
  const ratio = (a, b) => {
    const [x, y] = [lum(a), lum(b)].sort((p,q) => q-p);
    return (x + 0.05) / (y + 0.05);
  };

  // The page's own backdrop. ION paints this on <body> (style.css hardcodes
  // it) and leaves <html> transparent, so walking only to documentElement
  // finds nothing and a naive white fallback reports every light-on-dark
  // element as unreadable. That produced 1383 dark-mode "failures" on pages
  // a screenshot shows are fine.
  const backdrop = (() => {
    for (const n of [document.body, document.documentElement]) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c[3] === 1) return [c[0], c[1], c[2]];
    }
    // last resort: ask the renderer what the canvas is, via a probe element
    const probe = document.createElement('div');
    document.body.appendChild(probe);
    const c = parse(getComputedStyle(probe).backgroundColor);
    probe.remove();
    return (c && c[3] === 1) ? [c[0], c[1], c[2]] : [255, 255, 255];
  })();

  // The first painted background behind an element, composited down.
  // Returns null when something in the chain paints a gradient or an
  // image, because backgroundColor reports transparent for those and the
  // real backdrop cannot be derived from the cascade. The ION logo is the
  // case that matters: dark text on `bg-gradient-to-br from-ion-cyan`,
  // which this reported at 1.00:1 on every page while being perfectly
  // legible. An unprovable element is counted apart, never failed.
  const bgOf = el => {
    let stack = [], n = el;
    while (n) {
      const cs = getComputedStyle(n);
      if (cs.backgroundImage && cs.backgroundImage !== 'none') return null;
      const c = parse(cs.backgroundColor);
      if (c && c[3] > 0) { stack.push(c); if (c[3] === 1) break; }
      n = n.parentElement;
    }
    let base = backdrop.slice();
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return base;
  };

  const out = [];
  const seen = new Set();
  let undeterminable = 0;
  let decorative = 0;

  // WCAG 1.4.3 governs text that conveys information. Text hidden from
  // assistive technology does not, and nor does a logotype. ION's
  // integration tiles are both: `<div class="integration-icon elasticsearch"
  // aria-hidden="true">E</div>` is the first letter of a name printed in full
  // beside it, on the vendor's own brand colour. White on Elasticsearch teal
  // measures 2.31:1 and no recolouring is available, because the colour IS
  // the brand. Counting those as failures would steer the work toward
  // repainting other companies' marks, so an aria-hidden subtree is counted
  // apart and never failed, the same treatment a gradient backdrop gets.
  const hiddenFromAT = el => {
    for (let n = el; n && n !== document.body; n = n.parentElement) {
      if (n.getAttribute('aria-hidden') === 'true') return true;
      const role = (n.getAttribute('role') || '').toLowerCase();
      if (role === 'presentation' || role === 'none') return true;
      // 1.4.3 Incidental: "text or images of text that are part of an
      // inactive user interface component" has no contrast requirement.
      // /audit-logs' Previous button is `disabled` on the first page and
      // daisyUI greys it to 0.2 alpha, which measured 1.55:1. Dimming a
      // control to show it is unavailable is the intended design, so this
      // is counted apart rather than failed.
      if (n.disabled === true) return true;
      if (n.getAttribute('aria-disabled') === 'true') return true;
    }
    return false;
  };

  for (const el of document.querySelectorAll('body *')) {
    // only elements that paint their own visible text
    const txt = [...el.childNodes]
      .filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(' ').trim();
    if (!txt) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity === 0) continue;
    if (hiddenFromAT(el)) { decorative++; continue; }
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) continue;

    const fg = parse(cs.color);
    if (!fg) continue;
    const bg = bgOf(el);
    if (bg === null) { undeterminable++; continue; }
    const fgc = fg[3] < 1 ? over(fg, bg) : [fg[0], fg[1], fg[2]];
    const got = ratio(fgc, bg);

    const px = parseFloat(cs.fontSize) || 16;
    const bold = (parseInt(cs.fontWeight, 10) || 400) >= 700;
    const large = px >= 24 || (bold && px >= 18.66);
    const need = large ? 3.0 : 4.5;
    if (got >= need) continue;

    const key = el.className + '|' + txt.slice(0, 24);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      cls: (typeof el.className === 'string' ? el.className : '').slice(0, 70),
      tag: el.tagName.toLowerCase(),
      text: txt.slice(0, 44),
      color: cs.color, size: px, bold, need,
      ratio: Math.round(got * 100) / 100,
    });
  }
  return { bad: out.sort((a, b) => a.ratio - b.ratio), undeterminable, decorative };
}
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8010")
    ap.add_argument("--cookies", required=True)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--pages", nargs="*", help="paths to visit; default is the nav registry")
    ap.add_argument("--modes", nargs="*", default=["light", "dark"])
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    if args.pages:
        paths = args.pages
    else:
        from ion.web.nav import destinations
        paths = list(destinations())

    jar = http.cookiejar.MozillaCookieJar(args.cookies)
    jar.load(ignore_discard=True, ignore_expires=True)
    cookies = [
        {"name": c.name, "value": c.value, "domain": "127.0.0.1", "path": "/"} for c in jar
    ]

    report: dict[str, dict[str, list]] = {}
    skipped: dict[str, int] = {}
    decor: dict[str, int] = {}
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(viewport={"width": 1500, "height": 1100})
        ctx.add_cookies(cookies)
        pg = ctx.new_page()

        print(f"{'path':28}{'mode':7}{'fails':>7}{'worst':>8}  worst offender")
        print("-" * 82)
        for path in paths:
            for mode in args.modes:
                try:
                    r = pg.goto(args.base + path, wait_until="domcontentloaded", timeout=25000)
                except Exception as exc:  # noqa: BLE001
                    print(f"{path:28}{mode:7}{'':>7}{'':>8}  load failed: {str(exc)[:30]}")
                    continue
                if r is None or r.status >= 400:
                    continue
                pg.evaluate(f"document.documentElement.setAttribute('data-mode','{mode}')")
                pg.wait_for_timeout(1200)
                res = pg.evaluate(PROBE)
                bad, undet = res["bad"], res["undeterminable"]
                decor[mode] = decor.get(mode, 0) + res.get("decorative", 0)
                report.setdefault(path, {})[mode] = bad
                skipped[mode] = skipped.get(mode, 0) + undet
                if bad:
                    w = bad[0]
                    print(f"{path:28}{mode:7}{len(bad):>7}{w['ratio']:>8.2f}  "
                          f"{w['tag']}.{w['cls'][:26]} {w['text'][:22]!r}")
        b.close()

    total = sum(len(v) for m in report.values() for v in m.values())
    pages_with = sum(1 for m in report.values() if any(m.values()))
    print()
    print(f"{total} unreadable elements across {pages_with} of {len(report)} pages")
    for mode in args.modes:
        n = sum(len(m.get(mode, [])) for m in report.values())
        print(f"  {mode:6} {n} unreadable, {skipped.get(mode, 0)} undeterminable "
              f"(gradient or image backdrop), {decor.get(mode, 0)} decorative "
              f"(aria-hidden, out of WCAG 1.4.3 scope)")

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
