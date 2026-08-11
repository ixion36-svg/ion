r"""v0.80.0 P0 — the guard for the CSP inline-style sweep.

`server.py` sets `style-src-attr 'none'` and asserts, in a comment, that
"P11 is now fully closed" after the v0.31.21 migration retired 1,820 inline
styles. That claim is wrong — but only by **22**, not by the 163 first reported.

**The counting trap, recorded because it nearly set the whole release off in the
wrong direction.** A naive `style\s*=` pattern also matches the tail of
`data-ion-style="..."`, which is the SANCTIONED replacement. So the first sweep
counted 163 by flagging 141 already-migrated sites as violations, and produced a
six-phase plan for work that was already done. The regex below has a
`(?<![-\w])` guard so `data-ion-style=` cannot match. Any future tooling that
counts these must carry the same guard.

True figures: **22 in-app violations before P1, 10 after.** The v0.31.21
migration substantially worked; what remains is a short tail.

A refused inline style produces no error, no log line and no failed request —
only an unstyled element. That is why 22 sat unnoticed, and why the case-rail
severity stripe rendered colourless for three releases before v0.79.5.

**Why an allowlist rather than a plain ban.** A test that only tightens at the
END would leave the sweep unguarded while in flight — which is how one crept
back into /documents at v0.79.0, on a surface already cleaned. So the ban lands
FIRST, with the current count recorded per file:

  * a NEW violation in any file fails immediately;
  * a file not listed here must be at zero;
  * the recorded number is a CEILING — it may only go down;
  * a file that has been fixed must be REMOVED from the list, so the allowlist
    cannot quietly outlive the debt it records.

Deliberately excluded: `templates/emails/*` and `*_pdf.html` (84 sites). Those
are not served under ION's CSP, and HTML email genuinely requires inline styles.
Excluding them is correct, not a concession.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOTS = (Path("src/ion/web/templates"), Path("src/ion/web/static/js"))
BASE = Path("src/ion/web")

# Third-party bundles — not ours to rewrite.
VENDOR = ("min.js", "quill.js", "marked", "purify", "mermaid", "htmx", "topojson", "lucide")

# (?<![-\w]) is load-bearing: without it this matches inside `data-ion-style=`,
# the sanctioned replacement, and every migrated site reads as a violation.
INLINE_STYLE = re.compile(r"""(?<![-\w])style\s*=\s*["'][^"']*["']""")

# Counted 2026-08-11. CEILINGS, not targets. Delete an entry when its file is
# clean; never raise a number.
# EMPTY. The sweep completed in one sitting once the true count was known —
# 22, not the 163 the flawed regex reported. Keep this dict here rather than
# deleting it: if a future change genuinely needs a temporary exemption, it goes
# here with a count and gets removed again, instead of the ban being weakened.
KNOWN_REMAINING: dict[str, int] = {}

TOTAL_AT_P0 = 0   # 22 before the sweep


def _strip(src: str) -> str:
    """Comments describe the ban using the very syntax under test — cases.html
    carries a CSS comment containing `style=""`. Strip before counting."""
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)     # HTML
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)      # CSS + JS block
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)     # JS line


def _first_party_files():
    for root in ROOTS:
        for f in sorted(root.rglob("*")):
            if not f.is_file() or f.suffix not in (".html", ".js"):
                continue
            if any(v in f.name for v in VENDOR):
                continue
            if "emails" in f.parts or "_pdf" in f.name:
                continue
            yield f


def _count(f: Path) -> int:
    body = _strip(f.read_text(encoding="utf-8", errors="replace"))
    return len(INLINE_STYLE.findall(body))


def _key(f: Path) -> str:
    return f.relative_to(BASE).as_posix()


ALL_FILES = list(_first_party_files())


@pytest.mark.parametrize("f", ALL_FILES, ids=_key)
def test_no_new_inline_styles(f):
    """Every file is at or below its recorded ceiling; unlisted files are at 0."""
    n = _count(f)
    allowed = KNOWN_REMAINING.get(_key(f), 0)
    assert n <= allowed, (
        f"{_key(f)} has {n} inline style attributes, allowed {allowed}.\n"
        "CSP sets style-src-attr 'none', so each one is REFUSED at render time — "
        "the element simply renders unstyled, with no error and no log line.\n"
        "Use data-ion-style=\"...\" instead; static/js/ion-dynamic-styles.js "
        "applies it via el.style.setProperty, which is CSP-legal."
    )


def test_the_allowlist_does_not_outlive_the_debt():
    """A fixed file must be removed from the list. Otherwise the allowlist
    silently becomes permission rather than a record of work outstanding."""
    stale = []
    for key, allowed in KNOWN_REMAINING.items():
        f = BASE / key
        if not f.exists():
            stale.append(f"{key} (file no longer exists)")
            continue
        n = _count(f)
        if n < allowed:
            stale.append(f"{key}: allowlist says {allowed}, actual {n} — lower it or delete the entry")
    assert not stale, "allowlist is stale:\n  " + "\n  ".join(stale)


def test_no_inline_styles_remain_anywhere():
    """The absolute ban. Was an allowlist during the sweep; now zero."""
    total = sum(_count(f) for f in ALL_FILES)
    assert total <= TOTAL_AT_P0, (
        f"{total} inline styles, up from {TOTAL_AT_P0} — the sweep is going backwards"
    )


def test_email_and_pdf_templates_are_deliberately_exempt():
    """They are not served under ION's CSP and email requires inline styles.
    Asserted so a future reader does not 'helpfully' extend the ban to them."""
    emails = list(Path("src/ion/web/templates/emails").glob("*.html"))
    assert emails, "email templates moved — revisit the exemption in this test"
    assert any(_count(f) > 0 for f in emails), (
        "email templates now have no inline styles, which would be surprising — "
        "confirm they still render correctly in mail clients"
    )


def test_the_sanctioned_alternative_is_wired():
    """The remedy has to be reachable or the ban is just an obstacle."""
    js = Path("src/ion/web/static/js/ion-dynamic-styles.js")
    assert js.exists()
    body = js.read_text(encoding="utf-8")
    assert "setProperty" in body
    assert "data-ion-style" in body
    assert "MutationObserver" in body, "innerHTML render paths would not be covered"
    base = Path("src/ion/web/templates/base.html").read_text(encoding="utf-8")
    assert "ion-dynamic-styles.js" in base, "the fixer is not loaded on any page"
