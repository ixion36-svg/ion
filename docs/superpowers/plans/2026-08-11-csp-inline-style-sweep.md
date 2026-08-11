# v0.80.0 — finish the CSP inline-style migration

**Status:** COMPLETE (2026-08-11). Swept to zero in one sitting.
**Superseded:** the first version of this plan, written the same day, scoped six
phases against a count of 163. That number was wrong. See §2 — the error is kept
here deliberately, because the way it happened is more instructive than the fix.

---

## 1. The claim that was false

`src/ion/web/server.py` sets `style-src-attr 'none'` and the comment above it
asserted:

> v0.31.21: … retired every inline `style=""` attribute … **P11 is now fully closed.**

It was not closed. **22 inline `style=` attributes survived across 11 first-party
templates and scripts**, every one refused at render time.

Excluded and correct: **84** in `templates/emails/*` and `*_pdf.html`. Those are
not served under ION's CSP and HTML email requires inline styles.

## 2. The counting error, and why it is worth recording

The first sweep reported **163 violations across 36 files** and produced a
six-phase plan: a 77-site colour phase, a 53-site size phase, and so on. All of
that was fiction. The counting regex was:

```python
re.findall(r"""style\s*=\s*["'][^"']*["']""", body)
```

which also matches the tail of **`data-ion-style="..."`** — the *sanctioned
replacement*. So 141 already-migrated sites were counted as violations, and the
plan proposed migrating code that was already migrated.

The corrected pattern carries a lookbehind:

```python
re.compile(r"""(?<![-\w])style\s*=\s*["'][^"']*["']""")
```

Two lessons, both cheap to state and expensive to relearn:

- **A measurement that drives a plan needs verifying before the plan does.** The
  error surfaced only because P1 removed 14 sites and the total dropped by 12 —
  an arithmetic mismatch, not a review.
- **The v0.31.21 migration worked far better than the bad number implied.** It is
  worth saying plainly: `data-ion-style` adoption was already broad. The debt was
  a short tail, not a systemic failure.

## 3. What was actually done

**P0 — guard first.** `tests/test_v080_csp_inline_styles.py` lands the ban with a
per-file allowlist of current counts, so new violations fail immediately while
the sweep is in flight. Proven non-vacuous by injecting a violation: caught by
both the per-file assertion and the total.

**P1 — 14 static / display / custom-property sites.** New utilities in
`ion-ui.css` (`.ion-u-hidden`, `.ion-u-mt-*`, `.ion-u-mr-*`, `.ion-u-inline-row`,
`.ti-badge-ransomware`). The three `display:none` sites are all toggled later
with `el.style.display = …`, a CSSOM write that overrides the class — so the
toggles keep working untouched.

**P2 — the remaining 10 dynamic sites** → `data-ion-style`, in `pcap.html` (4),
`notes-page.js` (2) and three CyAB partials (4, Jinja `{{ pct }}`).

**P3 — guard tightened to an absolute ban.** `KNOWN_REMAINING` is now empty and
kept as an empty dict rather than deleted, so a future temporary exemption has a
documented home instead of weakening the ban.

**P4 — the false comment corrected** in `server.py`, with the reason and the
route for future dynamic styles.

## 4. Verification

Static counting cannot prove a style *applied* — which is exactly how this
survived. A harness rendered every shape through `ion-dynamic-styles.js`,
injected via `innerHTML` after load so the `MutationObserver` path was the one
under test:

| Declaration | Computed | |
|---|---|---|
| `width:62%` | 186px of 300 | ✅ |
| `width: 41%` (Jinja spacing) | 123px | ✅ |
| `background:#f87171` | `rgb(248,113,113)` | ✅ |
| `--role-color:#22c55e` | border resolves | ✅ |
| two declarations, second wins | dashed / `rgb(22,27,34)` | ✅ |

**Not verified:** the affected pages under real data and login — `/pcap`,
`/notes`, the CyAB tabs, `/threat-intel`, the DE pages. The mechanism is proven;
the individual sites are not. Worth a look when next on those pages: bars should
have width, the ransomware badge should be red.

## 5. Not in scope

The `style-src-attr` directive is unchanged. Nothing here weakens the CSP — the
policy has been correct throughout.
