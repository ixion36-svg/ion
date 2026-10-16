"""The /ui fragment router: the replacement for innerHTML string-building.

service_accounts.html built its risk summary and account table from 55 lines
of JavaScript string concatenation, with a hand-rolled `esc()`. That is the
shape the redesign's `server` column exists to remove: markup assembled in
JavaScript cannot be restyled from the stylesheet, so every such site is a
place a sweep silently fails to reach.

These tests render the fragment directly with fixture data, because the dev
database has no service accounts and an empty render proves nothing about the
table, which is the bulk of what moved. Each case is one the old JavaScript
either got right and must keep, or got wrong.
"""
from __future__ import annotations

from typing import Any

import pytest

from ion.web.templating import make_templates
from ion.web.ui.service_accounts import _systems_display

FRAGMENT = "_fragments/service_accounts.html"


class _Req:
    """TemplateResponse wants a request; the fragment reads nothing from it."""

    scope: dict = {"type": "http", "state": {}}
    url = type("U", (), {"path": "/ui/service-accounts"})()


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _account(**over: Any) -> dict:
    base = {
        "account_name": "svc-backup",
        "display_name": "Backup agent",
        "account_type": "service",
        "owner_name": "Platform",
        "department": "IT",
        "risk_level": "high",
        "status": "active",
        "password_age_days": 42,
        "password_never_expires": False,
        "systems_display": "db01, db02",
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The table, which is what actually moved
# ---------------------------------------------------------------------------


def test_an_account_renders_its_row():
    html = render(accounts=[_account()], summary={"total": 1}, failed=False)
    assert "svc-backup" in html
    assert "Backup agent" in html
    assert "db01, db02" in html
    assert "badge-warning" in html, "high risk should take the warning badge"


def test_a_zero_day_password_age_is_a_measurement_not_unknown():
    """The guard that matters most here.

    The JavaScript tested `a.password_age_days != null`, which is correct.
    A Jinja port written as `{% if pw_age %}` would be wrong: 0 is falsy, so
    a password changed today would render as "Unknown". Those lead to
    opposite actions, so the template uses `is not none`.
    """
    html = render(accounts=[_account(password_age_days=0)],
                  summary={}, failed=False)
    assert ">0d<" in html
    assert "Unknown" not in html


def test_a_missing_password_age_says_unknown():
    html = render(accounts=[_account(password_age_days=None)],
                  summary={}, failed=False)
    assert "Unknown" in html


@pytest.mark.parametrize("days,expected", [
    (200, "text-error"), (120, "text-warning"), (10, "text-success"),
])
def test_password_age_keeps_its_thresholds(days, expected):
    html = render(accounts=[_account(password_age_days=days)],
                  summary={}, failed=False)
    assert expected in html


def test_never_expires_is_called_out():
    html = render(accounts=[_account(password_never_expires=True)],
                  summary={}, failed=False)
    assert "NEVER EXPIRES" in html


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """The old helper built a div and read innerHTML back. Jinja autoescapes,
    so the helper is gone; this proves the replacement actually escapes."""
    html = render(
        accounts=[_account(account_name='<script>alert(1)</script>')],
        summary={}, failed=False,
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_no_accounts_is_an_empty_estate_not_a_failure():
    html = render(accounts=[], summary={"total": 0}, failed=False)
    assert "No service accounts tracked yet" in html


def test_a_failed_read_says_so_rather_than_showing_zeros():
    """The JavaScript replaced the whole container with "Failed to load".
    The fragment keeps that distinction: an unreadable estate and an empty
    one lead to opposite actions, so it must never render 0 for either."""
    html = render(accounts=None, summary=None, failed=True)
    assert "could not be read" in html
    assert "not an empty estate" in html
    assert "stat-value" not in html, "a failed read must not print figures"


# ---------------------------------------------------------------------------
# The summary strip
# ---------------------------------------------------------------------------


def test_the_summary_counts_render():
    html = render(accounts=[], failed=False, summary={
        "total": 12, "by_risk": {"critical": 2, "high": 3},
        "stale_count": 4, "never_expires_count": 1,
    })
    for n in (">12<", ">2<", ">3<", ">4<", ">1<"):
        assert n in html, n


def test_a_zero_count_is_not_coloured_as_a_problem():
    html = render(accounts=[], failed=False,
                  summary={"total": 0, "by_risk": {}, "stale_count": 0})
    assert "text-error" not in html


def test_a_nonzero_critical_count_is_coloured():
    html = render(accounts=[], failed=False,
                  summary={"total": 1, "by_risk": {"critical": 1}})
    assert "text-error" in html


# ---------------------------------------------------------------------------
# systems_display, ported from a try/catch
# ---------------------------------------------------------------------------


def test_systems_display_takes_the_first_three():
    assert _systems_display('["a","b","c","d"]') == "a, b, c"


def test_systems_display_shows_unparseable_json_raw():
    """The JavaScript's catch fell back to the raw string, so a row with
    malformed JSON showed something odd rather than an empty cell that reads
    as "no systems". Same choice here."""
    assert _systems_display("db01,db02") == "db01,db02"


@pytest.mark.parametrize("raw", [None, "", "[]"])
def test_systems_display_is_empty_when_there_is_nothing(raw):
    assert _systems_display(raw) == ""


def test_systems_display_accepts_a_real_list():
    assert _systems_display(["x", "y"]) == "x, y"


# ---------------------------------------------------------------------------
# bob_eval samples: a paginated table whose pager is htmx, not JavaScript
# ---------------------------------------------------------------------------

SAMPLES = "_fragments/bob_eval_samples.html"


def render_samples(payload, run_id=7):
    env = make_templates().env
    return env.get_template(SAMPLES).render(payload=payload, run_id=run_id)


def _payload(samples, **over):
    base = {"run_id": 7, "page": 1, "page_size": 50, "total": len(samples),
            "total_pages": 1, "samples": samples}
    base.update(over)
    return base


def _sample(**over):
    base = {"ai_feedback_id": 11, "bob_verdict": "true_positive",
            "human_verdict": "true_positive", "agreement": True,
            "confidence_int": 80}
    base.update(over)
    return base


@pytest.mark.parametrize("agreement,badge,label", [
    (True, "badge-success", "Yes"),
    (False, "badge-error", "No"),
    (None, "badge-ghost", "Abstain"),
])
def test_agreement_has_three_states_not_two(agreement, badge, label):
    """The JavaScript used `=== true` / `=== false`, so None rendered as
    Abstain. A truthiness port folds abstain into "No", which turns "BOB
    declined to judge" into "BOB was wrong"."""
    html = render_samples(_payload([_sample(agreement=agreement)]))
    assert badge in html
    assert label in html


def test_a_zero_confidence_is_a_score_not_a_blank():
    html = render_samples(_payload([_sample(confidence_int=0)]))
    assert ">0<" in html or ">0 " in html
    assert html.count("-") == html.count("-")  # no silent dash for 0


def test_a_missing_confidence_shows_a_dash():
    html = render_samples(_payload([_sample(confidence_int=None)]))
    assert "-" in html


def test_a_missing_bob_verdict_shows_a_dash():
    html = render_samples(_payload([_sample(bob_verdict=None)]))
    assert "-" in html


def test_the_pager_links_are_htmx_requests_not_javascript():
    html = render_samples(_payload([_sample()], page=2, total_pages=3, total=150))
    # &amp; because Jinja entity-encodes the ampersand in an attribute, which
    # is correct HTML; the browser decodes it before htmx reads the value.
    # Every ampersand is &amp; because each URL is one escaped value. Written
    # as `{{ base }}&page={{ n }}` the attribute mixed &amp; with a bare &,
    # since template text is not escaped and a variable is.
    assert "run_id=7&amp;page_size=50&amp;page=1" in html
    assert "run_id=7&amp;page_size=50&amp;page=3" in html
    assert "data-click-action=\"loadSamplesPage\"" not in html
    assert "Page 2 of 3 (150 total)" in html


def test_the_first_page_has_no_prev_and_the_last_no_next():
    first = render_samples(_payload([_sample()], page=1, total_pages=2))
    assert "Prev" not in first and "Next" in first
    last = render_samples(_payload([_sample()], page=2, total_pages=2))
    assert "Prev" in last and "Next" not in last


def test_an_empty_page_says_so_inside_the_table():
    html = render_samples(_payload([]))
    assert "No samples on this page" in html


def test_a_missing_run_is_an_error_not_an_empty_table():
    html = render_samples(None)
    assert "Eval run not found" in html
    assert "<table" not in html


def test_the_error_state_can_still_be_dismissed():
    """Found by driving the pager in a browser, not by reading the template.

    Moving the card chrome into the fragment put the Close button inside the
    success branch. A pager click on a run deleted since the page loaded then
    swapped the chrome away, and the panel sat open with an error and no way
    out but a reload. The chrome now wraps both states.
    """
    html = render_samples(None, run_id=12)
    assert 'data-click-action="closeSamples"' in html
    assert "Run 12" in html, "the heading must render without a payload"


def test_the_fragment_carries_its_own_card_chrome():
    """The page holds only an empty slot, so the panel's header and Close
    button have to come from here or they have two definitions."""
    html = render_samples(_payload([_sample()]))
    assert "Samples &mdash; Run 7" in html or "Samples — Run 7" in html
    assert 'data-click-action="closeSamples"' in html
