"""The change-request (CAB) table as a server-rendered fragment.

change_requests.html built nine columns, a risk pill, a status pill, the
GitLab cell and the per-status action buttons out of a template literal, and
wrote the result into `#crs-body` with innerHTML at three sites. Those are
the cases below: each one is something the JavaScript either got right and
must keep, or got wrong and must stop doing.

The rows are fixtures rather than live data: the dev database has no change
requests, and an empty render proves nothing about the table, which is all
that moved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from ion.models.service_desk import ChangeRequestStatus, ChangeRiskLevel
from ion.web.templating import make_templates
from ion.web.ui.change_requests import (
    _created_display,
    _next_actions,
    _row_view,
    router,
)

FRAGMENT = "_fragments/change_requests.html"
PAGE = Path(__file__).resolve().parents[2] / "src/ion/web/templates/change_requests.html"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _cr(**over: Any) -> dict:
    base = {
        "id": 7,
        "reference": "CR-0007",
        "title": "Upgrade ION to 0.49.0",
        "change_type": "ION version upgrade",
        "current_version": "0.48.3",
        "target_version": "0.49.0",
        "risk_level": "medium",
        "status": "submitted",
        "requested_by_username": "admin",
        "gitlab_issue_iid": 412,
        "gitlab_issue_url": "https://gitlab.example.com/ion/-/issues/412",
        "gitlab_error": None,
        "created_at": "2026-10-12T08:30:11.123456",
    }
    base.update(over)
    return base


def rows(*crs: dict) -> list[dict]:
    return [_row_view(c) for c in crs]


# ---------------------------------------------------------------------------
# The row, which is what actually moved
# ---------------------------------------------------------------------------


def test_a_change_request_renders_its_row():
    html = render(rows=rows(_cr()), status="all", failed=False)
    assert "CR-0007" in html
    assert "Upgrade ION to 0.49.0" in html
    assert "0.48.3" in html and "0.49.0" in html
    assert "admin" in html
    assert "/api/change-requests/7/export" in html


def test_the_status_pill_reads_the_value_not_the_enum_repr():
    """The guard that the port would silently fail without.

    `ChangeRequest.status` is a SQLEnum column, so `to_dict()` hands back a
    `ChangeRequestStatus` member, not a string. The JavaScript never saw one:
    FastAPI serialised it to "submitted" on the way out. Jinja renders it with
    str(), and on Python 3.12 that is "ChangeRequestStatus.SUBMITTED", so the
    pill would read the repr and `stColor[...]` would never match.
    """
    html = render(
        rows=rows(_cr(status=ChangeRequestStatus.SUBMITTED,
                      risk_level=ChangeRiskLevel.HIGH)),
        status="all", failed=False,
    )
    assert "ChangeRequestStatus" not in html
    assert "ChangeRiskLevel" not in html
    assert ">submitted<" in html
    assert ">high<" in html


@pytest.mark.parametrize("risk,cls", [
    ("low", "ion-c-green"), ("medium", "ion-c-amber"), ("high", "ion-c-red"),
])
def test_risk_keeps_its_colour(risk, cls):
    html = render(rows=rows(_cr(risk_level=risk)), status="all", failed=False)
    assert cls in html


def test_an_unknown_risk_falls_back_to_muted_rather_than_no_class():
    html = render(rows=rows(_cr(risk_level="catastrophic")), status="all",
                  failed=False)
    assert "ion-c-muted" in html


@pytest.mark.parametrize("status,cls", [
    ("draft", "ion-c-muted"), ("submitted", "ion-c-cyan"),
    ("approved", "ion-c-green"), ("rejected", "ion-c-red"),
])
def test_status_keeps_its_colour(status, cls):
    html = render(rows=rows(_cr(status=status)), status="all", failed=False)
    assert cls in html


def test_a_row_with_no_target_version_omits_the_arrow():
    html = render(rows=rows(_cr(target_version=None)), status="all",
                  failed=False)
    assert "→" not in html


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """esc() is gone. This is what replaces it."""
    html = render(
        rows=rows(_cr(title="<script>alert(1)</script>",
                      reference="<img src=x onerror=1>")),
        status="all", failed=False,
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html


# ---------------------------------------------------------------------------
# The GitLab cell
# ---------------------------------------------------------------------------


def test_a_linked_gitlab_issue_renders_as_a_link():
    html = render(rows=rows(_cr()), status="all", failed=False)
    assert "https://gitlab.example.com/ion/-/issues/412" in html
    assert "#412" in html


def test_a_gitlab_failure_is_shown_rather_than_hidden():
    html = render(
        rows=rows(_cr(gitlab_issue_url=None, gitlab_issue_iid=None,
                      gitlab_error="GitLab not configured")),
        status="all", failed=False,
    )
    assert "GitLab not configured" in html


def test_issue_zero_is_an_issue_number_not_a_blank():
    """`is not none`, not truthiness. iid 0 is a number GitLab could hand
    back, and `{% if iid %}` would print the fallback for it."""
    html = render(
        rows=rows(_cr(gitlab_issue_iid=0,
                      gitlab_issue_url="https://gitlab.example.com/i/0")),
        status="all", failed=False,
    )
    assert "#0" in html
    assert "#?" not in html


# ---------------------------------------------------------------------------
# The action buttons, which were a second copy of the workflow
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status,expected", [
    ("draft", ["submit", "cancel"]),
    ("submitted", ["approve", "reject", "cancel"]),
    ("approved", ["schedule", "implement", "cancel"]),
    ("scheduled", ["implement", "cancel"]),
    ("implemented", ["close"]),
    ("closed", []),
    ("rejected", []),
    ("cancelled", []),
])
def test_next_actions_match_the_services_transition_table(status, expected):
    """The JavaScript carried its own NEXT_ACTIONS map, which is a second
    definition of the state machine in service_desk_service. It happened to
    agree; the fragment derives the list from that table instead, so it
    cannot stop agreeing."""
    assert [a["action"] for a in _next_actions(status)] == expected


def test_next_actions_accepts_an_enum_status():
    assert [a["action"] for a in _next_actions(ChangeRequestStatus.DRAFT)] == [
        "submit", "cancel",
    ]


def test_the_action_buttons_carry_parseable_args():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which would leave buttons that look live and do nothing."""
    html = render(rows=rows(_cr(status="submitted")), status="all",
                  failed=False)
    args = re.findall(r"data-args='([^']*)'", html)
    assert args, "no action buttons rendered"
    for raw in args:
        assert json.loads(raw.replace("&#34;", '"')) [0] == 7


def test_a_closed_request_offers_export_but_no_transition():
    html = render(rows=rows(_cr(status="closed")), status="all", failed=False)
    assert 'data-click-action="transition"' not in html
    assert "/api/change-requests/7/export" in html


# ---------------------------------------------------------------------------
# Empty is not failed
# ---------------------------------------------------------------------------


def test_no_change_requests_says_so_inside_the_table():
    html = render(rows=[], status="all", failed=False)
    assert "No change requests" in html
    assert "<table" in html, "the column headings survive an empty list"


def test_a_failed_read_says_so_rather_than_showing_an_empty_table():
    """"Nothing there" and "we could not look" lead to opposite actions. The
    JavaScript distinguished them ("Failed to load: 500") and so must this."""
    html = render(rows=None, status="all", failed=True)
    assert "could not be read" in html
    assert "not an empty list" in html
    assert "No change requests" not in html


def test_the_failed_state_keeps_the_table_chrome():
    """The filter select that re-requests this fragment lives in the page, so
    an error swap cannot remove the way out. The headings stay too, so the
    error lands in the table rather than replacing it."""
    html = render(rows=None, status="all", failed=True)
    assert "<table" in html
    assert "<th>Ref</th>" in html


# ---------------------------------------------------------------------------
# created_at, ported from fmtDate
# ---------------------------------------------------------------------------


def test_created_display_is_date_and_minutes():
    assert _created_display("2026-10-12T08:30:11.123456") == "2026-10-12 08:30"


@pytest.mark.parametrize("raw", [None, ""])
def test_created_display_is_empty_when_there_is_no_timestamp(raw):
    assert _created_display(raw) == ""


def test_created_display_does_not_shift_the_clock():
    """fmtDate did `new Date(iso).toISOString()`, which reads a naive UTC
    stamp as local time and then converts it, so the column was off by the
    browser's offset. The server renders the stored value."""
    assert _created_display("2026-10-12T23:59:00") == "2026-10-12 23:59"


# ---------------------------------------------------------------------------
# The route and the page
# ---------------------------------------------------------------------------


def _permission_of(route) -> str | None:
    for dep in route.dependant.dependencies:
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            return cells.get("permission_name")
    return None


def test_the_fragment_permission_matches_the_json_endpoint():
    """A fragment must not be a softer way in than the API it mirrors. The
    page is gated on the same permission as every /api/change-requests route,
    and the sibling bug-reports page needs none, which is the mistake this
    asserts against."""
    from ion.web.change_request_api import _PERM

    assert _PERM == "system:settings"
    perms = [_permission_of(r) for r in router.routes]
    assert perms == [_PERM]


def test_the_json_endpoint_and_the_fragment_share_one_query():
    from ion.web import change_request_api

    assert hasattr(change_request_api, "change_requests_payload")


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py does.

    Scoped to the inline script bodies on purpose: `hx-swap="innerHTML"` is an
    attribute telling htmx where to put server-rendered markup, which is the
    opposite of the thing being removed.
    """
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/change-requests"' in src
    assert 'hx-trigger="load"' in src
    assert "NEXT_ACTIONS" not in src, "the state machine lives on the server"
    assert "function esc(" not in src, "Jinja autoescapes"
