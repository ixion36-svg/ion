"""The KEV catalogue page shows what the catalogue actually carries (v0.81.2).

Five columns rendered CVE, vendor/product, vulnerability name and two dates.
Every one of the 1,662 entries also carries a description, a required action and
references, and 1,491 carry CWEs — all of it already in the API response, all of
it discarded by the row renderer.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TI = ROOT / "src" / "ion" / "web" / "templates" / "threat_intel.html"
MODEL = ROOT / "src" / "ion" / "models" / "kev.py"
SERVICE = ROOT / "src" / "ion" / "services" / "kev_service.py"

# The catalogue rows were built in the page by kevDetail() and
# kevRansomware(), and the tests below sliced threat_intel.html between those
# two function names. Both are gone: the rows are server-rendered here, from
# ui/threat_intel.py. Every behaviour they pinned survived the move and is
# asserted against the fragment instead, including the escaping, which is
# Jinja autoescaping now rather than a hand-rolled escapeHtml call.
FRAGMENT = (ROOT / "src" / "ion" / "web" / "templates" / "_fragments"
            / "threat_intel_kev.html")


# ── the payload carries everything ──────────────────────────────────────────

def test_to_dict_exposes_every_catalogue_field():
    """cwes and synced_at were on the model but absent from the API payload, so
    no client could render them however it tried."""
    from ion.models.kev import KevEntry
    e = KevEntry(cve_id="CVE-2026-8037")
    d = e.to_dict()
    for field in ("short_description", "required_action", "notes", "cwes",
                  "known_ransomware_raw", "catalog_version", "source", "synced_at"):
        assert field in d, f"to_dict() drops {field}"


@pytest.mark.parametrize("stored,expected", [
    ('["CWE-77"]', ["CWE-77"]),
    ('["CWE-77", "CWE-78"]', ["CWE-77", "CWE-78"]),
    ("[]", []),
    (None, []),
    ("", []),
    ("not json", []),          # malformed must not break a catalogue page
    ('{"a": 1}', []),          # valid JSON, wrong shape
    ("[1, 2]", ["1", "2"]),    # coerced to strings
])
def test_cwe_list_survives_whatever_is_in_the_column(stored, expected):
    from ion.models.kev import KevEntry
    assert KevEntry(cve_id="X", cwes=stored).cwe_list() == expected


# ── "Unknown" is not "no" ───────────────────────────────────────────────────

def test_ransomware_unknown_is_rendered_distinctly_from_known():
    """CISA publishes "Known" / "Unknown", never "No". Unknown means NOT
    ESTABLISHED. 1,324 of 1,662 entries are Unknown, so showing them exactly
    like a definitive negative — which a bare missing badge does — asserts
    something the catalogue does not, on the majority of rows.
    """
    fragment = FRAGMENT.read_text(encoding="utf-8")
    assert "known_ransomware_raw" in fragment, \
        "the raw Known/Unknown value must reach the UI"
    assert "ti-badge-unknown" in fragment, \
        "Unknown needs its own badge, not the absence of one"
    assert "ti-badge-ransomware" in fragment, \
        "and Known needs a different one, or the two read alike"
    assert "not the same as ruling it out" in fragment, \
        "the Unknown badge must say what Unknown means"


# ── the detail is rendered ──────────────────────────────────────────────────

@pytest.mark.parametrize("field", [
    "short_description", "required_action", "cwes", "notes",
    "catalog_version", "source",
])
def test_the_detail_panel_renders_the_field(field):
    fragment = FRAGMENT.read_text(encoding="utf-8")
    assert field in fragment, f"the KEV fragment never reads {field}"


def test_rows_are_expandable_and_collapsed_by_default():
    """1,662 entries expanded at once is not a page."""
    # The attribute is on the server-rendered row and the handler stayed in
    # the page, because expanding a row is a client interaction. Asserting
    # both is what catches the pair being split by a later move: an
    # attribute with no handler, or a handler nothing triggers.
    assert 'data-click-action="kevToggle"' in FRAGMENT.read_text(
        encoding="utf-8")
    src = TI.read_text(encoding="utf-8")
    assert "function kevToggle(" in src
    assert "window.kevToggle" in src, "the delegated dispatcher resolves via window[name]"
    # The .ti-kev-* rules moved out of the retired ion-ui.css and into
    # frontend/ion-daisy-theme.css, which is compiled into ion.css.
    css = (ROOT / "frontend/ion-daisy-theme.css").read_text(encoding="utf-8")
    assert re.search(r"\.ti-kev-detail\s*\{[^}]*display:\s*none", css), \
        "detail rows must start collapsed"
    built = (ROOT / "src/ion/web/static/css/ion.css").read_text(encoding="utf-8")
    assert "ti-kev-detail" in built, \
        "the rule is in the source but was not compiled into ion.css"


def test_references_are_text_not_links():
    """ION ships to air-gapped sites; an external anchor is a dead end that
    looks broken. The reference is still worth having to hand."""
    fragment = FRAGMENT.read_text(encoding="utf-8")
    assert "<a " not in fragment and "href" not in fragment, \
        "references must render as selectable text, not anchors"
    assert "ti-kev-notes" in fragment


def test_detail_escapes_every_catalogue_value():
    """The catalogue is external data reaching the DOM.

    It used to reach it through innerHTML, so this walked every `${...}`
    interpolation in kevDetail() and required escapeHtml around any that
    touched `e.<field>`. The rows are a Jinja fragment now, so the escaping
    is autoescaping and the thing to look for is the one way out of it.

    `|safe` on a catalogue value would be the same hole the old version
    guarded, and it is how a stored XSS reached the case panel's alert rail
    earlier in this redesign. There is one `|safe` in this fragment and it
    is on a literal, `'&mdash;'`, which is fine because Jinja binds a
    filter tighter than `or`: the catalogue value in that expression is
    still autoescaped.
    """
    fragment = FRAGMENT.read_text(encoding="utf-8")
    unsafe = [
        match for match in re.findall(r"\{\{[^}]*\|\s*safe[^}]*\}\}", fragment)
        if not re.search(r"'[^']*'\s*\|\s*safe", match)
    ]
    assert not unsafe, (
        "a catalogue value leaves autoescaping: " + str(unsafe))
    assert "|safe" not in fragment.replace("'&mdash;'|safe", ""), \
        "a second |safe appeared; check what it is applied to"


def test_the_escaping_check_would_notice_a_value_marked_safe():
    """A control, because the test above passes on a fragment with no
    `|safe` at all and would therefore also pass if it were looking in the
    wrong file."""
    hostile = "<span>{{ e.short_description|safe }}</span>"
    unsafe = [
        match for match in re.findall(r"\{\{[^}]*\|\s*safe[^}]*\}\}", hostile)
        if not re.search(r"'[^']*'\s*\|\s*safe", match)
    ]
    assert unsafe, "the pattern no longer catches a value marked safe"

    literal = "<b>{{ status.get('catalog_version') or '&mdash;'|safe }}</b>"
    allowed = [
        match for match in re.findall(r"\{\{[^}]*\|\s*safe[^}]*\}\}", literal)
        if not re.search(r"'[^']*'\s*\|\s*safe", match)
    ]
    assert not allowed, "the literal case must not be reported"


# ── search covers the description ───────────────────────────────────────────

def test_search_also_matches_the_description():
    src = SERVICE.read_text(encoding="utf-8")
    fn = src[src.index("def search("):]
    fn = fn[:fn.index("\ndef ") if "\ndef " in fn else len(fn)]
    assert "short_description.ilike" in fn


def test_search_widening_claim_is_stated_accurately():
    """The first version of this comment claimed those terms matched nothing
    before. They matched 109 and 54 — the technique is usually already in
    vulnerability_name. A comment that overstates a win is a comment that will
    mislead whoever reads it next."""
    src = SERVICE.read_text(encoding="utf-8")
    fn = src[src.index("def search("):]
    fn = fn[:fn.index("\ndef ") if "\ndef " in fn else len(fn)]
    assert "matches nothing" not in fn
    assert "widens the match modestly" in fn
