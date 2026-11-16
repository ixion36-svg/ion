"""The threat actor profile fragment.

This page is intelligence about an adversary, so an absence it asserts is a
finding. The JavaScript it replaces said "No TTPs surfaced by OpenCTI for
this actor" and "No campaigns linked to this actor in OpenCTI" from the
same failed lookup it had already reported in the description. One failure
reported itself once and claimed an absence twice, and the second claim is
the one an analyst would act on.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ion.web.templating import make_templates
from ion.web.ui.threat_intel_actor import (
    KNOWN_SEVERITIES,
    TTP_LIMIT,
    alias_list,
    case_rows,
    ttp_chips,
)

FRAGMENT = "_fragments/threat_intel_actor.html"


def render(**ctx) -> str:
    ctx.setdefault("failed", False)
    ctx.setdefault("entity_id", "G0007")
    ctx.setdefault("actor", {"name": "APT28"})
    ctx.setdefault("actor_error", None)
    ctx.setdefault("cases_error", None)
    ctx.setdefault("cases", [])
    ctx.setdefault("aliases", [])
    ctx.setdefault("ttps", [])
    ctx.setdefault("ttps_hidden", 0)
    ctx.setdefault("campaigns", [])
    return make_templates().env.get_template(FRAGMENT).render(**ctx)


def flat(html: str) -> str:
    """Rendered text with runs of whitespace collapsed.

    A prose assertion has to go through this. The template wraps its
    sentences to fit the file, so "not a finding that the actor is absent"
    arrives with a newline and six spaces inside it, and a contiguous
    substring check fails against correct output. Two of these tests failed
    that way before this existed.
    """
    return " ".join(html.split())


# ---------------------------------------------------------------------------
# A failed OpenCTI lookup is not an actor with nothing known about it
# ---------------------------------------------------------------------------


def test_a_failed_lookup_does_not_claim_the_actor_has_no_techniques():
    """The defect this conversion exists to fix.

    `actor_error` set means the lookup failed, so `ttps` is empty for a
    reason that has nothing to do with the actor. The page rendered "No
    TTPs surfaced by OpenCTI for this actor" from exactly that state.
    """
    html = render(actor=None, actor_error="OpenCTI not configured", ttps=[])
    assert "No techniques recorded" not in html
    assert "not an actor with no" in flat(html)


def test_a_failed_lookup_does_not_claim_the_actor_has_no_campaigns():
    html = render(actor=None, actor_error="connection refused", campaigns=[])
    assert "No campaigns linked" not in html


def test_a_successful_lookup_with_no_techniques_does_say_so():
    """The other direction. If the lookup worked and found nothing, that is
    a real finding and the page must still report it."""
    html = render(actor={"name": "APT28"}, actor_error=None, ttps=[])
    assert "No techniques recorded" in html
    assert "not an actor with no" not in flat(html)


def test_the_lookup_failure_is_named_once_in_the_description():
    html = render(actor=None, actor_error="OpenCTI not configured")
    assert "OpenCTI lookup failed" in html
    assert "OpenCTI not configured" in html
    assert "No description available" not in html


# ---------------------------------------------------------------------------
# A failed local search is not an actor absent from your environment
# ---------------------------------------------------------------------------


def test_a_failed_case_search_is_not_a_count_of_zero():
    """The local-case query used to swallow its exception and leave the list
    empty, and the tile printed `(recent_cases || []).length`. Zero on that
    tile reads as "this actor has not been seen here", which is the
    opposite of "we could not look"."""
    html = render(cases=[], cases_error="database is locked")
    assert "Unknown" in html
    assert "not a finding that the actor is absent" in flat(html)


def test_a_successful_empty_case_search_says_no_matches():
    html = render(cases=[], cases_error=None)
    assert "No matching cases in the last 180 days" in flat(html)
    assert "not a finding that the actor is absent" not in flat(html)


def test_a_zero_case_count_is_rendered_when_the_search_ran():
    html = render(cases=[], cases_error=None)
    assert ">0<" in html.replace("\n", "").replace(" ", "")


def test_a_total_failure_renders_no_section_at_all():
    """Distinct from either half failing. Nothing was read, so the fragment
    must not render an actor, a case list, or an empty state for either."""
    html = render(failed=True, actor=None)
    assert "could not be read" in html
    assert "No matching cases" not in html
    assert "No techniques recorded" not in html
    assert "stat-value" not in html


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------


def test_a_confidence_of_zero_is_a_measurement():
    """OpenCTI reporting zero confidence in an attribution is the opposite
    of not having reported one."""
    html = render(actor={"name": "A", "confidence": 0})
    assert "0%" in html


def test_a_missing_confidence_is_a_dash():
    html = render(actor={"name": "A", "confidence": None})
    assert "0%" not in html
    assert "&mdash;" in html


def test_a_missing_first_seen_says_not_reported_rather_than_the_epoch():
    html = render(actor={"name": "A", "first_seen": None})
    assert "Not reported" in html
    assert "1970" not in html


def test_a_timestamp_goes_through_the_time_macro():
    html = render(actor={"name": "A",
                         "first_seen": datetime(2026, 3, 4, tzinfo=timezone.utc)})
    assert "<time datetime=" in html
    assert "data-ts-format" in html


# ---------------------------------------------------------------------------
# The helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    (["a", "b"], ["a", "b"]),
    ("solo", ["solo"]),
    ([], []),
    (None, []),
    ("", []),
    ({"not": "a list"}, []),
])
def test_alias_list_accepts_what_opencti_actually_returns(raw, expected):
    """The JavaScript took a list or a bare string and treated anything else
    as none, which is right: guessing would put a dict's repr on the page."""
    assert alias_list(raw) == expected


def test_no_aliases_renders_no_label():
    """An "Also known as:" label with nothing after it reads as aliases that
    failed to load."""
    assert "Also known as" not in render(aliases=[])
    assert "Also known as" in render(aliases=["Fancy Bear"])


def test_an_unknown_severity_gets_a_class_the_stylesheet_has():
    """The JavaScript built `sev-${c.severity}` straight from the column, so
    a value outside the known set produced a class with no rule and an
    unstyled chip, silently."""
    rows = case_rows([{"id": 1, "severity": "catastrophic"}])
    assert rows[0]["severity_class"] == "sev-info"
    assert rows[0]["severity_known"] is False
    assert rows[0]["severity"] == "catastrophic", "the word itself is kept"


@pytest.mark.parametrize("severity", KNOWN_SEVERITIES)
def test_a_known_severity_keeps_its_own_class(severity):
    rows = case_rows([{"id": 1, "severity": severity}])
    assert rows[0]["severity_class"] == f"sev-{severity}"
    assert rows[0]["severity_known"] is True


def test_the_technique_list_reports_how_many_it_cut():
    """The page sliced at 30 and said nothing, so a reader could not tell a
    complete list from a clipped one."""
    chips, hidden = ttp_chips({"ttps": [{"mitre_id": f"T{i}"} for i in range(42)]})
    assert len(chips) == TTP_LIMIT
    assert hidden == 42 - TTP_LIMIT
    html = render(ttps=chips, ttps_hidden=hidden)
    assert f"Showing {TTP_LIMIT} of 42 techniques" in flat(html)


def test_a_short_technique_list_says_nothing_about_truncation():
    chips, hidden = ttp_chips({"ttps": [{"mitre_id": "T1"}]})
    assert hidden == 0
    assert "Showing" not in flat(render(ttps=chips, ttps_hidden=0))


def test_a_non_dict_technique_is_skipped_rather_than_rendered():
    chips, _ = ttp_chips({"ttps": ["T1059", {"mitre_id": "T1055"}]})
    assert [c["id"] for c in chips] == ["T1055"]


# ---------------------------------------------------------------------------
# Escaping, and the javascript: href that was in the markup
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    html = render(actor={"name": '<script>alert(1)</script>'})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_the_description_is_not_assembled_with_injected_tags():
    """The JavaScript escaped the description and then replaced newlines
    with <br>, which works but handles the field most likely to carry
    attacker-supplied prose by concatenating tags into it. CSS renders the
    newlines instead."""
    html = render(actor={"name": "A", "description": "line one\nline two"})
    assert "whitespace-pre-line" in html
    assert "<br>" not in html


def test_a_technique_is_a_button_not_a_javascript_url():
    """`href="javascript:void(0)"` was a javascript: URL sitting in the
    markup, which is the shape safe_url exists to reject elsewhere. A link
    that does not navigate is a button."""
    html = render(ttps=[{"id": "T1059", "name": "Command interpreter"}])
    assert "javascript:" not in html
    assert "<button" in html
    assert 'data-technique="T1059"' in html


def test_a_case_link_goes_through_safe_url():
    html = render(cases=case_rows([{"id": 7, "case_number": "C-7",
                                    "severity": "high"}]))
    assert 'href="/cases?selected=7"' in html
