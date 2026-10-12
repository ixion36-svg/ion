"""The audit log fragment.

This page is the journal of who did what, so the usual honesty rules bite
harder than elsewhere: an unreadable journal must never render as an empty
one, a system action must not read as a lost actor, and a redacted field
must not be indistinguishable from a field that was never there.

The secret filter moved from the browser to the server. It used to run in
`formatDetails`, which means the values had already been sent to the page
and the filter only kept them out of the table.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ion.web.templating import make_templates
from ion.web.ui.audit_logs import ACTION_BADGE, format_action, visible_details

FRAGMENT = "_fragments/audit_logs.html"


def render(**ctx) -> str:
    ctx.setdefault("failed", False)
    ctx.setdefault("offset", 0)
    ctx.setdefault("page_size", 50)
    ctx.setdefault("has_next", False)
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _log(**over) -> dict:
    base = {
        "username": "alice",
        "action": "login",
        "action_label": "Login",
        "badge": "badge-success",
        "resource_type": "user",
        "resource_id": 3,
        "details": [("ip", "10.0.0.1")],
        "ip_address": "10.0.0.1",
        "timestamp": datetime(2026, 10, 12, 9, 41, 7, tzinfo=timezone.utc),
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The secret filter, now server-side
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", [
    "password", "new_password", "password_hash", "token", "access_token",
    "PASSWORD", "api_key", "client_secret", "Hash",
])
def test_a_key_named_like_a_secret_never_reaches_the_page(key):
    out = visible_details({key: "s3cret", "username": "alice"})
    assert [label for label, _ in out] == ["username"]
    assert "s3cret" not in str(out)


def test_an_ordinary_key_survives_and_is_humanised():
    assert visible_details({"resource_name": "Case 7"}) == [
        ("resource name", "Case 7")
    ]


def test_a_nested_value_is_serialised_rather_than_dropped():
    assert visible_details({"changed": {"role": "admin"}}) == [
        ("changed", '{"role": "admin"}')
    ]


def test_a_legacy_bare_string_is_kept_as_itself():
    """Some historical producers stored a bare string rather than an object,
    and json.loads on those used to 500 the whole page."""
    assert visible_details("203.0.113.0/24") == "203.0.113.0/24"


@pytest.mark.parametrize("empty", [None, "", {}, []])
def test_absent_details_are_none_not_an_empty_render(empty):
    assert visible_details(empty) is None


def test_the_filter_reads_keys_and_not_values():
    """A redactor that guesses from values hides real audit content and
    still misses a secret stored under an innocent name."""
    assert visible_details({"note": "the password policy changed"}) == [
        ("note", "the password policy changed")
    ]


# ---------------------------------------------------------------------------
# Row rendering
# ---------------------------------------------------------------------------


def test_a_row_renders_its_fields():
    html = render(logs=[_log()])
    assert "alice" in html
    assert "badge-success" in html
    assert "user #3" in html
    assert "10.0.0.1" in html


def test_the_timestamp_goes_through_the_time_macro():
    """A server-formatted timestamp would show every viewer outside the
    server's timezone the wrong time on every row."""
    html = render(logs=[_log()])
    assert 'datetime="2026-10-12T09:41:07+00:00"' in html
    assert "data-ts-format" in html


def test_a_null_username_is_the_system_not_a_lost_actor():
    html = render(logs=[_log(username=None)])
    assert "System" in html


def test_a_resource_id_of_zero_is_still_an_id():
    """`{% if log.resource_id %}` would drop it. Row 0 exists."""
    assert "user #0" in render(logs=[_log(resource_id=0)])


def test_a_row_with_no_resource_shows_a_dash():
    html = render(logs=[_log(resource_type=None, resource_id=None)])
    assert ">-<" in html or "-\n" in html


def test_an_unmapped_action_takes_the_neutral_badge():
    """A new action type must not inherit the colour of a security event it
    has nothing to do with."""
    assert ACTION_BADGE.get("some_new_action", "badge-ghost") == "badge-ghost"


@pytest.mark.parametrize("action,expected", [
    ("login_failed", "Login Failed"),
    ("user_roles_updated", "User Roles Updated"),
    (None, "-"),
])
def test_format_action(action, expected):
    assert format_action(action) == expected


def test_jinja_escapes_details_content():
    html = render(logs=[_log(details=[("note", "<script>alert(1)</script>")])])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# The two empty states, which are not the same state
# ---------------------------------------------------------------------------


def test_no_matching_entries_says_so():
    html = render(logs=[])
    assert "No audit entries match these filters" in html


def test_an_unreadable_journal_is_not_an_empty_one():
    """The single most misleading thing this page could say is "no audit
    logs" when the truth is that it could not look."""
    html = render(logs=None, failed=True)
    assert "could not be read" in html
    assert "not an empty journal" in html
    assert "No audit entries" not in html


def test_a_failed_read_hides_the_pager():
    """A pager on an unreadable table invites paging through nothing."""
    html = render(logs=None, failed=True)
    assert "Next" not in html


# ---------------------------------------------------------------------------
# The pager
# ---------------------------------------------------------------------------


def test_the_first_page_cannot_go_back():
    html = render(logs=[_log()], offset=0, has_next=True)
    assert "Previous" in html
    prev = html.split("Previous")[0]
    assert prev.rstrip().endswith("disabled") or "disabled>Previous" in html


def test_the_last_page_cannot_go_forward():
    html = render(logs=[_log()], offset=50, has_next=False)
    assert "disabled>Next" in html.replace("\n", "").replace("          ", "")


def test_previous_never_offsets_below_zero():
    """A page size larger than the offset would produce a negative offset,
    which the route rejects with a 422 and htmx shows as nothing at all."""
    html = render(logs=[_log()], offset=10, page_size=50)
    assert '"offset": 0' in html


def test_the_page_number_counts_from_one():
    assert "Page 3" in render(logs=[_log()], offset=100, page_size=50)


def test_the_pager_carries_the_filters():
    """Paging that drops the filters silently widens what the user is
    looking at, which on an audit view means showing them rows they had
    deliberately excluded."""
    html = render(logs=[_log()], has_next=True)
    assert html.count('hx-include="#filter-action, #filter-resource"') == 2
