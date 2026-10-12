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
from ion.web.ui import _systems_display

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
