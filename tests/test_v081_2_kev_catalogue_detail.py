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
    src = TI.read_text(encoding="utf-8")
    fn = src[src.index("function kevRansomware("):]
    fn = fn[:fn.index("\n    function ")]
    assert "known_ransomware_raw" in fn, "the raw Known/Unknown value must reach the UI"
    assert "ti-badge-unknown" in fn, "Unknown needs its own badge, not the absence of one"
    assert "not the same as ruling it out" in fn, \
        "the Unknown badge must say what Unknown means"


# ── the detail is rendered ──────────────────────────────────────────────────

@pytest.mark.parametrize("field", [
    "short_description", "required_action", "cwes", "notes",
    "catalog_version", "source",
])
def test_the_detail_panel_renders_the_field(field):
    src = TI.read_text(encoding="utf-8")
    body = src[src.index("function kevDetail("):]
    body = body[:body.index("\n    function ")]
    assert f"e.{field}" in body, f"kevDetail() never reads {field}"


def test_rows_are_expandable_and_collapsed_by_default():
    """1,662 entries expanded at once is not a page."""
    src = TI.read_text(encoding="utf-8")
    assert 'data-click-action="kevToggle"' in src
    assert "window.kevToggle" in src, "the delegated dispatcher resolves via window[name]"
    css = (ROOT / "src/ion/web/static/css/ion-ui.css").read_text(encoding="utf-8")
    assert re.search(r"\.ti-kev-detail\s*\{[^}]*display:\s*none", css), \
        "detail rows must start collapsed"


def test_references_are_text_not_links():
    """ION ships to air-gapped sites; an external anchor is a dead end that
    looks broken. The reference is still worth having to hand."""
    src = TI.read_text(encoding="utf-8")
    body = src[src.index("function kevDetail("):]
    body = body[:body.index("\n    function ")]
    assert "<a " not in body and "href" not in body, \
        "references must render as selectable text, not anchors"
    assert "ti-kev-notes" in body


def test_detail_escapes_every_catalogue_value():
    """The catalogue is external data reaching the DOM through innerHTML."""
    src = TI.read_text(encoding="utf-8")
    body = src[src.index("function kevDetail("):]
    body = body[:body.index("\n    function ")]
    # every interpolation of a catalogue value goes through escapeHtml
    raw = re.findall(r"\$\{(?!escapeHtml)(?!cwes\.map)([^}]*e\.[a-z_]+[^}]*)\}", body)
    unescaped = [r for r in raw if "escapeHtml" not in r and "===" not in r]
    assert not unescaped, f"unescaped catalogue values reach innerHTML: {unescaped}"


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
