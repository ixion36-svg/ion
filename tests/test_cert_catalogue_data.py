"""The certification catalogue is the same on both sides.

It was a JavaScript literal in training.html and nothing on the server
could read it -- the position skills_matrix was in before it moved, and
worse here, because these 85 entries are the only prices in ION. A
training plan item's cost is whatever somebody copied off that screen,
and the forecast then puts the total in front of a budget conversation.

The template keeps its copy for the browser-side catalogue UI. Two
copies of reference data drift, and nobody notices because each screen
looks right on its own: the catalogue page keeps quoting the old price
while a plan built from the Python copy quotes the new one, and the two
disagree about what the same certificate costs.

These tests parse the template's literal and compare it, so the drift
fails here rather than in an argument about which figure is right.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.data import cert_catalogue as cc  # noqa: E402

_TEMPLATE = _SRC / "ion" / "web" / "templates" / "training.html"

_QUOTED = re.compile(r"'((?:[^'\\]|\\.)*)'")
_KEY = re.compile(r"(\{|,)\s*([A-Za-z_][\w-]*)\s*:")
_TRAILING = re.compile(r",(\s*[}\]])")
_LINE_COMMENT = re.compile(r"^\s*//.*$", re.M)


def _parse_js_array(src: str, name: str) -> list:
    """The named array literal out of the template, as Python.

    Narrow on purpose, like the parser in test_skills_matrix_data.py: it
    handles the literals this file checks and nothing else. A general
    JavaScript parser here would be a second thing to maintain.
    """
    block = src[src.index("const " + name + " = ["):]
    block = block[block.index("["):]
    depth = 0
    for i, ch in enumerate(block):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                block = block[: i + 1]
                break
    # Comments go first, or their text is quoted as data.
    block = _LINE_COMMENT.sub("", block)
    js = _QUOTED.sub(lambda m: json.dumps(m.group(1).replace("\\'", "'")), block)
    js = _KEY.sub(lambda m: m.group(1) + '"' + m.group(2) + '":', js)
    js = _TRAILING.sub(r"\1", js)
    return json.loads(js)


def _template() -> str:
    return _TEMPLATE.read_text(encoding="utf-8")


class TestTheTwoCopiesAgree:
    def test_the_certifications_match_the_template(self):
        template = _parse_js_array(_template(), "CR_CERTS")
        assert template == json.loads(json.dumps(cc.CERTIFICATIONS)), (
            "training.html and ion.data.cert_catalogue disagree. Edit one "
            "and copy to the other, or the catalogue page and anything "
            "costing a training plan will quote different prices."
        )

    def test_the_domains_match_the_template(self):
        template = _parse_js_array(_template(), "CR_DOMAINS")
        assert template == json.loads(json.dumps(cc.CERT_DOMAINS))

    def test_the_levels_match_the_template(self):
        template = _parse_js_array(_template(), "CR_LEVELS")
        assert tuple(template) == cc.LEVELS


class TestTheCheckItself:
    """A guard that cannot detect the drift it guards is worse than none."""

    def test_the_parser_reads_a_price(self):
        certs = _parse_js_array(_template(), "CR_CERTS")
        assert any(c.get("cost") for c in certs), (
            "the parser returned no costs, so a price change would not be "
            "compared and this file would pass whatever happened"
        )

    def test_the_parser_keeps_apostrophes(self):
        """A description with an escaped apostrophe must survive, or the
        comparison fails for a reason that has nothing to do with drift."""
        sample = "const X = [{ desc:'it\\'s fine' }];"
        assert _parse_js_array(sample, "X") == [{"desc": "it's fine"}]

    def test_the_parser_drops_comments(self):
        sample = "const X = [\n    // ─── A section ───\n    { id:'a' },\n];"
        assert _parse_js_array(sample, "X") == [{"id": "a"}]


class TestTheCatalogueIsCoherent:
    def test_every_cert_has_an_id_and_a_name(self):
        for cert in cc.CERTIFICATIONS:
            assert cert.get("id") and cert.get("name"), cert

    def test_ids_are_unique(self):
        ids = [c["id"] for c in cc.CERTIFICATIONS]
        assert len(ids) == len(set(ids))

    def test_every_cert_names_a_domain_that_exists(self):
        known = {d["id"] for d in cc.CERT_DOMAINS}
        for cert in cc.CERTIFICATIONS:
            assert cert["domain"] in known, (cert["id"], cert["domain"])

    def test_every_cert_names_a_level_that_exists(self):
        for cert in cc.CERTIFICATIONS:
            assert cert["level"] in cc.LEVELS, (cert["id"], cert["level"])

    def test_every_prereq_names_a_cert_that_exists(self):
        """A prereq pointing at nothing is a broken pathway on screen."""
        known = {c["id"] for c in cc.CERTIFICATIONS}
        for cert in cc.CERTIFICATIONS:
            for prereq in cert.get("prereqs") or []:
                assert prereq in known, (cert["id"], prereq)

    def test_every_price_states_its_currency(self):
        """The whole point of the currency work: a bare number is the bug."""
        for cert in cc.CERTIFICATIONS:
            assert cert.get("currency"), cert["id"]


class TestPriceProvenance:
    def test_provenance_keys_name_real_certs(self):
        known = {c["id"] for c in cc.CERTIFICATIONS}
        for cert_id in cc.PRICE_PROVENANCE:
            assert cert_id in known, cert_id

    def test_every_checked_price_says_where_and_when(self):
        """A provenance entry with no source or no date records nothing."""
        for cert_id, entry in cc.PRICE_PROVENANCE.items():
            assert entry.get("source"), cert_id
            assert entry.get("checked_on"), cert_id

    def test_unverified_prices_are_reported_not_hidden(self):
        """Unchecked is the honest default, and has to be visible. Every
        cert is either in PRICE_PROVENANCE or named by this."""
        unverified = set(cc.unverified_prices())
        checked = set(cc.PRICE_PROVENANCE)
        assert unverified | checked == {c["id"] for c in cc.CERTIFICATIONS}
        assert not (unverified & checked)


class TestKnownIssues:
    """Lifting the data out of the browser made it readable; these are
    what reading it found."""

    def test_they_name_real_certs(self):
        known = {c["id"] for c in cc.CERTIFICATIONS}
        for cert_id in cc.KNOWN_ISSUES:
            assert cert_id in known, (
                f"{cert_id} is recorded as a data issue but is not in the "
                "catalogue; the note has outlived the entry"
            )

    def test_each_one_says_what_is_wrong(self):
        for cert_id, note in cc.KNOWN_ISSUES.items():
            assert len(note.strip()) > 40, cert_id

    def test_a_flagged_entry_is_not_also_price_checked(self):
        """crtp's price is the SANS flat rate applied to an entry that is
        probably not a SANS certification. Recording it as checked would
        assert the figure is right for it."""
        for cert_id in cc.KNOWN_ISSUES:
            assert cert_id not in cc.PRICE_PROVENANCE, cert_id


class TestThePriceCheckIsHonest:
    def test_every_checked_sans_id_is_a_sans_entry(self):
        """The shared SANS check is one check applied to the entries that
        genuinely share its pricing structure, not a blanket."""
        for cert_id in cc._SANS_GIAC_IDS:
            cert = cc.get_cert(cert_id)
            assert cert is not None, cert_id
            assert cert["provider"] == "SANS/GIAC", cert_id

    def test_a_vendor_price_states_its_own_currency(self):
        """The vendor figure is in the vendor's currency and is not
        converted into cost. Without the currency it is just a number
        next to a different number."""
        for cert_id, entry in cc.PRICE_PROVENANCE.items():
            if "vendor_price" in entry:
                assert entry.get("vendor_currency"), cert_id

    def test_a_checked_price_is_the_vendor_figure_verbatim(self):
        """Adopted, never converted.

        A checked entry carries the vendor's own number in the vendor's
        own currency. That is exact for ever and anybody can re-derive
        it from the source. A converted figure would be precise to the
        pound and wrong by hundreds -- no GBP/USD rate could be verified
        for the day these were checked and the candidates spread
        1.28-1.35 -- and nothing downstream could tell which rate made
        it.
        """
        for cert_id, entry in cc.PRICE_PROVENANCE.items():
            if "vendor_price" not in entry:
                continue
            cert = cc.get_cert(cert_id)
            assert cert is not None, cert_id
            assert cert["cost"] == entry["vendor_price"], (
                f"{cert_id}: catalogue says {cert['cost']}, vendor says "
                f"{entry['vendor_price']}. Adopt the vendor figure or "
                f"drop the provenance; a half-updated entry claims to be "
                f"checked and is not."
            )
            assert cert["currency"] == entry["vendor_currency"], (
                f"{cert_id}: carrying {cert['currency']} against a "
                f"{entry['vendor_currency']} vendor figure means somebody "
                f"converted it without recording a rate."
            )

    def test_the_catalogue_reports_being_multi_currency(self):
        """Checked entries are in the vendor's currency and the rest are
        the template's original GBP, so this genuinely holds both.
        Anything summing across it has to convert deliberately."""
        assert set(cc.currencies()) == {"GBP", "USD"}

    def test_components_add_up_to_the_adopted_figure(self):
        """A price recorded as parts must equal the sum of its parts, or
        the breakdown is decoration rather than a record of what was
        bought."""
        for cert_id, entry in cc.PRICE_PROVENANCE.items():
            components = entry.get("components")
            if not components:
                continue
            assert sum(components.values()) == entry["vendor_price"], (
                f"{cert_id}: {components} does not sum to "
                f"{entry['vendor_price']}"
            )
