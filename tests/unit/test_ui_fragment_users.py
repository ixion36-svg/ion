"""The user and role administration page as server-rendered fragments.

users.html built the whole table out of template literals and wrote it into
`#users-tbody` at five innerHTML sites, and wrote the role picker into both
modals at a sixth, across 301 lines of inline JavaScript. The cases below
are what that JavaScript either got right and must keep, or got wrong and
must stop doing.

What it got wrong, which is the substance of this file:

  * `new Date(user.last_login).toLocaleString()` over a value from a naive
    DateTime column. JavaScript parses a zoneless ISO date-time as local
    time, so every Last Login on the page was out by the viewer's offset
    while looking authoritative.
  * `loadRoles()` called `renderRoleCheckboxes()` only inside
    `if (response.ok)` and its catch reached no further than
    `console.error`, so a role list that could not be read left both
    pickers as empty containers. "This deployment defines no roles" and "we
    could not read the roles" are opposite instructions to an administrator
    creating an account, and the page said neither.
  * `(role.permissions || []).length` printed "0 permissions" for a role
    whose permission list never arrived.
  * Edit, Reset Password and Delete rendered on every row for every viewer,
    although they need `user:update` and `user:delete` and the page is
    behind `user:read`; and Delete rendered on the viewer's own row, which
    `DELETE /api/users/{user_id}` refuses outright.
  * the role names in the Roles column went into innerHTML unescaped, and
    so did a role's `description` in the picker, while the username beside
    them went through escapeHtml. A sink next to a guarded one is the kind
    that survives review.

Rows are fixtures rather than live data. The dev database holds a handful of
accounts and none of the states worth checking, and an empty render proves
nothing about the row, which is all that moved.
"""
from __future__ import annotations

import inspect
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request

from ion.web.templating import make_templates
from ion.web.ui import users as page
from ion.web.ui.users import (
    _CREATE_PERM,
    _DELETE_PERM,
    _READ_PERM,
    _UPDATE_PERM,
    ROLE_GROUPS,
    _role_view,
    _row_view,
)

FRAGMENT = "_fragments/users.html"
ROLES = "_fragments/users_role_options.html"
TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "src/ion/web/templates"
PAGE = TEMPLATE_DIR / "users.html"

#: The viewer every helper below renders for unless a test says otherwise.
VIEWER_ID = 9


def flat(html: str) -> str:
    """Whitespace collapsed, because the templates wrap their sentences.

    Every prose assertion here goes through it. The failure wording runs to
    three lines in the template, so a raw substring match fails on the line
    break Jinja kept, and the obvious fix is to shorten the sentence until
    the test passes, which is the test dictating the wording.
    """
    return re.sub(r"\s+", " ", html)


def _entry(**over: Any) -> dict:
    """One row shaped like users_list_payload() emits it.

    A dict rather than a User, because that is what the function the JSON
    endpoint calls hands over, with `last_login` already an ISO string.
    """
    base = {
        "id": 41,
        "username": "jdoe",
        "email": "jdoe@example.com",
        "display_name": "Jane Doe",
        "is_active": True,
        "last_login": "2026-10-11T22:14:03",
        "roles": ["analyst"],
        "employment_type": "cs",
        "elastic_username": "jdoe",
        "elastic_uid": "u-7f3a",
        "keycloak_sub": None,
        "gitlab_username": None,
        "created_at": "2026-01-04T09:00:00",
    }
    base.update(over)
    return base


def render(name: str, **ctx: Any) -> str:
    return make_templates().env.get_template(name).render(**ctx)


def table(
    *entries: dict,
    can_update: bool = True,
    can_delete: bool = True,
    can_create: bool = True,
    include_inactive: bool = False,
    viewer_id: object = VIEWER_ID,
) -> str:
    rows = [
        _row_view(e, viewer_id=viewer_id, can_update=can_update,
                  can_delete=can_delete)
        for e in entries
    ]
    return render(
        FRAGMENT, rows=rows, failed=False, can_update=can_update,
        can_delete=can_delete, can_create=can_create,
        include_inactive=include_inactive,
    )


def failed_table(**chrome: Any) -> str:
    ctx = {
        "rows": None, "failed": True, "can_update": True, "can_delete": True,
        "can_create": True, "include_inactive": False,
    }
    ctx.update(chrome)
    return render(FRAGMENT, **ctx)


def _role(**over: Any) -> dict:
    base = {
        "id": 3,
        "name": "senior_analyst",
        "description": "Case closure",
        "is_system": True,
        "permissions": ["alert:read", "alert:triage", "case:read"],
    }
    base.update(over)
    return base


def picker(*entries: dict, group: str = "new") -> str:
    return render(
        ROLES,
        roles=[_role_view(e) for e in entries],
        failed=False,
        field_name=ROLE_GROUPS[group],
    )


def failed_picker(group: str = "new") -> str:
    return render(
        ROLES, roles=None, failed=True, field_name=ROLE_GROUPS[group]
    )


def cells(html: str) -> list[str]:
    """Each cell including its opening tag.

    The tag matters: two of the nine columns carry their colour in a
    `data-ion-style` attribute on the `<td>` itself, so a capture of the
    inner text alone would make every assertion about that colour pass
    whatever the attribute said.
    """
    return re.findall(r"(<td[^>]*>.*?</td>)", html, re.S)


def actions_cell(html: str) -> str:
    """The last cell of the row, which is where the three buttons live.

    Extracted rather than matched against the whole render, because this
    file carries a lot of explanatory comment and a whole-file substring
    assertion passes on a comment that names the thing it is checking for.
    Three conversions in this project were caught that way.
    """
    found = cells(html)
    assert found, "no cells rendered, so this proves nothing"
    return found[-1]


# ---------------------------------------------------------------------------
# The row
# ---------------------------------------------------------------------------


def test_a_user_renders_its_row():
    html = table(_entry())
    assert "jdoe" in html
    assert "jdoe@example.com" in html
    assert "Jane Doe" in html
    assert "analyst" in html


def test_every_user_in_the_list_gets_its_own_row():
    html = table(_entry(id=1, username="alice"), _entry(id=2, username="bob"))
    assert html.count("<tr") == 3  # the header plus two
    assert "alice" in html and "bob" in html


def test_the_table_keeps_the_ids_and_columns_the_page_had():
    """The page's own markup is the baseline the style snapshot compares
    against, so the table arrives with the hooks it was styled through and
    the same nine columns in the same order."""
    html = table(_entry())
    assert 'id="users-table"' in html
    assert 'id="users-tbody"' in html
    headers = re.findall(r"<th>(.*?)</th>", html)
    assert headers == [
        "Username", "Email", "Display Name", "Roles", "Elastic UID",
        "Keycloak Sub", "Status", "Last Login", "Actions",
    ]


# ---------------------------------------------------------------------------
# Roles: unknown, none, and some
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("roles,expected", [
    (None, "Roles unknown"),
    ([], "No roles assigned"),
])
def test_an_absent_role_list_is_not_an_empty_one(roles, expected):
    """Three states, not two. A payload with no roles key is a role list that
    did not arrive; an empty list is an account that holds no role and can
    therefore do nothing. On an identity page those lead to opposite
    actions."""
    html = flat(table(_entry(roles=roles)))
    assert expected in html


def test_a_user_with_roles_renders_each_as_its_own_badge():
    """The third arm, and the one that makes the two above non-vacuous: the
    branch has to be reachable in all three directions."""
    html = table(_entry(roles=["analyst", "lead"]))
    assert html.count("badge-ghost") >= 2
    assert "analyst" in html and "lead" in html
    assert "Roles unknown" not in html
    assert "No roles assigned" not in html


# ---------------------------------------------------------------------------
# is_active, which is two-state and stays two
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", [True, 1])
def test_an_active_account_is_badged_active_and_not_dimmed(flag):
    """Parametrised over a non-boolean on purpose. `is_active` is a
    non-nullable Boolean column, so the guard is deliberately truthiness
    rather than `is true`, and a raw row or a round trip through JSON hands
    back 1. `{% if x is true %}` would call such a row disabled."""
    html = table(_entry(is_active=flag))
    assert "badge-success" in html
    assert ">Active<" in html
    assert "opacity-50" not in html


@pytest.mark.parametrize("flag", [False, 0])
def test_a_disabled_account_is_badged_inactive_and_dimmed(flag):
    html = table(_entry(is_active=flag))
    assert ">Inactive<" in html
    assert "badge-success" not in html
    assert "opacity-50" in html


def test_the_payload_always_states_whether_an_account_is_active():
    """What keeps the two-state render above honest.

    A third "unknown" branch would be dead markup and a vacuous test, since
    None behaves identically under truthiness, `is true` and `is not none`.
    The real guard is that the key is never missing, which is a property of
    the function both callers share rather than of the template.
    """
    source = inspect.getsource(page.users_list_payload)
    assert '"is_active": u.is_active' in source


# ---------------------------------------------------------------------------
# The optional identifier columns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field,header_index", [
    ("elastic_uid", 4),
    ("keycloak_sub", 5),
])
@pytest.mark.parametrize("missing", [None, ""])
def test_an_unset_identifier_says_not_set_and_is_coloured_as_unset(
    field, header_index, missing
):
    """`""` is parametrised because the parked draft tested `is none` alone.
    `update_user` normalises a blank identifier to NULL with `value or None`,
    so "" and NULL are one state in the column, and a cell that told them
    apart would colour an empty box as though a UID had been resolved.
    """
    html = table(_entry(**{field: missing}))
    cell = cells(html)[header_index]
    assert "Not set" in cell
    assert "var(--text-muted)" in cell


@pytest.mark.parametrize("field,header_index", [
    ("elastic_uid", 4),
    ("keycloak_sub", 5),
])
def test_a_set_identifier_is_shown_and_coloured_as_set(field, header_index):
    html = table(_entry(**{field: "abc-123"}))
    cell = cells(html)[header_index]
    assert "abc-123" in cell
    assert "var(--primary)" in cell
    assert "Not set" not in cell


def test_the_elastic_cell_carries_the_username_under_the_uid():
    html = table(_entry(elastic_uid="u-1", elastic_username="jdoe"))
    cell = cells(html)[4]
    assert "u-1" in cell
    assert "jdoe" in cell


def test_a_user_with_no_display_name_says_not_set():
    assert "Not set" in table(_entry(display_name=None))


# ---------------------------------------------------------------------------
# last_login, which is where the JavaScript was wrong rather than untidy
# ---------------------------------------------------------------------------


def test_last_login_is_a_time_element_rather_than_a_server_format():
    html = table(_entry(last_login="2026-10-11T22:14:03"))
    assert "<time datetime=" in html
    assert "2026-10-11" in html


def test_a_zoneless_last_login_is_not_offered_up_for_localising():
    """The defect, stated as a guard.

    `last_login` is a naive DateTime column, so the value carries no zone.
    `new Date("2026-10-11T22:14:03")` is parsed as the viewer's local time,
    so `toLocaleString()` converted out of a zone the value was never in and
    printed a time wrong by the viewer's offset on every row. The macro
    marks such a value `data-ts-local="no"`, and that attribute is what
    keeps static/js/local-time.js off it.
    """
    html = table(_entry(last_login="2026-10-11T22:14:03"))
    assert 'data-ts-local="no"' in html
    assert 'data-ts-local="yes"' not in html


def test_a_zoned_last_login_is_localised():
    """The positive control. Without it the test above passes for a macro
    that never localises anything."""
    html = table(_entry(last_login="2026-10-11T22:14:03+00:00"))
    assert 'data-ts-local="yes"' in html


def test_a_user_who_has_never_signed_in_says_never():
    html = table(_entry(last_login=None))
    assert "Never" in html
    assert "1970" not in html


# ---------------------------------------------------------------------------
# Escaping, which retires escapeHtml and closes the two sinks it skipped
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_escapehtml_was_asked_to():
    html = table(_entry(username="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_jinja_escapes_the_role_names_escapehtml_was_never_asked_to():
    """`user.roles.map(r => '<span ...>' + r + '</span>')`. The username one
    line above went through escapeHtml and these did not."""
    html = table(_entry(roles=["<img src=x onerror=alert(1)>"]))
    assert "<img src=x" not in html
    assert "&lt;img" in html


@pytest.mark.parametrize("field", [
    "display_name", "email", "elastic_uid", "elastic_username",
    "keycloak_sub",
])
def test_every_text_column_escapes_a_script_tag(field):
    html = table(_entry(**{field: "<script>alert(1)</script>"}))
    assert "<script>alert(1)</script>" not in html


def test_an_identifier_is_escaped_in_its_title_attribute_too():
    """The cell puts the full value in `title` as well as in the text, so
    there are two sinks per identifier and only one of them is visible."""
    html = table(_entry(elastic_uid='" onmouseover="alert(1)'))
    assert 'onmouseover="alert(1)"' not in html
    assert "&#34;" in html or "&quot;" in html


def test_the_page_carries_no_hand_rolled_escaper():
    """Jinja autoescapes. A second escaper is a second decision about what
    counts as safe, and the one this page had was applied to four values and
    skipped two."""
    assert "escapeHtml" not in page_code()


# ---------------------------------------------------------------------------
# The buttons, which are claims about what this viewer may do
# ---------------------------------------------------------------------------


def test_a_viewer_who_can_write_is_offered_all_three_row_controls():
    """The positive control. Without it every withholding test below passes
    for a fragment that renders no buttons at all."""
    cell = actions_cell(table(_entry(id=41)))
    assert "showEditUserModal" in cell
    assert "showResetPasswordModal" in cell
    assert "deleteUser" in cell


def test_a_read_only_viewer_is_offered_no_row_controls_and_told_why():
    """The page is behind user:read and rendered all three buttons for
    everyone. Edit and Reset Password need user:update, Delete needs
    user:delete, so a read-only analyst's only way to learn that was to make
    the change and read the 403."""
    html = flat(table(_entry(), can_update=False, can_delete=False))
    assert "showEditUserModal" not in html
    assert "showResetPasswordModal" not in html
    assert "deleteUser" not in html
    assert "read user accounts but not change them" in html
    assert "<th>Actions</th>" not in html


def test_update_without_delete_keeps_edit_and_reset_and_drops_delete():
    cell = actions_cell(table(_entry(), can_update=True, can_delete=False))
    assert "showEditUserModal" in cell
    assert "showResetPasswordModal" in cell
    assert "deleteUser" not in cell


def test_delete_without_update_keeps_only_delete():
    cell = actions_cell(table(_entry(), can_update=False, can_delete=True))
    assert "showEditUserModal" not in cell
    assert "showResetPasswordModal" not in cell
    assert "deleteUser" in cell


def test_delete_is_withheld_on_the_viewers_own_row_and_the_reason_given():
    """DELETE /api/users/{user_id} refuses this outright, and the page used
    to render the button and let the 400 explain."""
    cell = flat(actions_cell(table(_entry(id=VIEWER_ID))))
    assert "deleteUser" not in cell
    assert "Cannot delete your own account" in cell


def test_delete_is_offered_on_every_other_row():
    cell = actions_cell(table(_entry(id=VIEWER_ID + 1)))
    assert "deleteUser" in cell
    assert "Cannot delete your own account" not in cell


def test_the_refusal_is_the_predicate_the_delete_route_itself_calls():
    """Derived, not restated. A second copy of the rule keeps offering the
    button after the route stops accepting it, and nothing in a diff shows
    that the two have parted."""
    from ion.web import api

    assert page.user_delete_refusal is api.user_delete_refusal
    assert page.user_delete_refusal(7, 7) == "Cannot delete your own account"
    assert page.user_delete_refusal(7, 8) is None
    source = inspect.getsource(api.delete_user)
    assert "user_delete_refusal" in source
    assert "user_id == current_user.id" not in source, (
        "the comparison is back alongside the predicate, which is two "
        "definitions of the rule rather than one"
    )


@pytest.mark.parametrize("target,actor", [(None, 7), (7, None), (None, None)])
def test_an_unknown_id_is_not_a_refusal(target, actor):
    """`is not None` on both ids rather than a bare equality, or a row with
    no id and a viewer with no id would compare equal and the button would
    be withheld for a reason that does not exist."""
    assert page.user_delete_refusal(target, actor) is None


def test_a_row_with_no_id_is_offered_no_controls():
    """None of the three endpoints can address it, so every button for it
    would be dead."""
    cell = actions_cell(table(_entry(id=None)))
    assert "showEditUserModal" not in cell
    assert "deleteUser" not in cell


def test_user_zero_is_still_a_user():
    """`is not None`, not truthiness. Row 0 should not exist on an
    autoincrement key, but `{% if row.id %}` is how its controls would
    vanish if one did."""
    cell = actions_cell(table(_entry(id=0)))
    assert "showEditUserModal" in cell
    assert '[0]' in cell


def test_a_button_carries_its_arguments_as_parseable_json():
    """event-delegation.js JSON.parses data-args and logs and gives up on a
    value it cannot read, so a quote in a username is a dead button rather
    than a visible fault. The page built this attribute by interpolating
    escapeHtml(username) into single quotes."""
    cell = actions_cell(table(_entry(id=41, username="o'brien \"x\"")))
    args = re.findall(r"data-args='([^']*)'", cell)
    assert args, cell
    for raw in args:
        parsed = json.loads(raw.replace("&#34;", '"').replace("&amp;", "&")
                            .replace("&#39;", "'").replace("&lt;", "<")
                            .replace("&gt;", ">").replace("\\u0027", "'"))
        assert isinstance(parsed, list)
        assert parsed[0] == 41


# ---------------------------------------------------------------------------
# New User, which is a permission the shell cannot see
# ---------------------------------------------------------------------------


def test_the_create_button_arrives_out_of_band_for_a_viewer_who_may_create():
    html = table(_entry())
    assert 'id="users-create-slot" hx-swap-oob="true"' in html
    assert "showCreateUserModal" in html


def test_the_create_button_is_withheld_from_a_viewer_who_may_not():
    """POST /api/users needs user:create. The page rendered the button for
    everyone, so a viewer holding only user:read filled in the whole dialog
    before learning the answer."""
    html = table(_entry(), can_create=False)
    assert 'id="users-create-slot"' in html
    assert "showCreateUserModal" not in html


def test_a_failed_read_leaves_the_create_button_as_it_was():
    """The slot is rendered from the permission alone and sits outside the
    state branch, so an unreadable user list does not also take away the
    only way to add an account."""
    html = failed_table(can_create=True)
    assert "showCreateUserModal" in html


# ---------------------------------------------------------------------------
# Three states for the table: rows, nothing, and could not look
# ---------------------------------------------------------------------------


def test_an_empty_estate_says_so_and_names_the_filter():
    html = flat(table(include_inactive=False))
    assert "No active users found" in html
    assert "Show inactive users" in html
    assert "could not be read" not in html


def test_an_empty_estate_with_the_filter_on_does_not_suggest_the_filter():
    html = flat(table(include_inactive=True))
    assert "No users found." in html
    assert "Show inactive users" not in html


def test_a_failed_read_is_not_an_empty_directory():
    """On an identity page "no users" reads as an account database that has
    been emptied, which is an incident, and "we could not look" is a
    retry."""
    html = flat(failed_table())
    assert "could not be read" in html
    assert "not an empty directory" in html
    assert "unknown rather than zero" in html
    assert "No users found" not in html
    assert "No active users found" not in html


def test_a_failed_read_prints_no_table_and_no_count():
    html = failed_table()
    assert "<table" not in html
    assert 'id="users-tbody"' not in html


# ---------------------------------------------------------------------------
# The role picker, the sixth innerHTML site
# ---------------------------------------------------------------------------


def test_the_picker_renders_a_widget_per_role():
    html = picker(_role(name="admin"), _role(name="analyst"))
    assert html.count("role-widget-card") == 2
    assert "role-widgets" in html


def test_the_picker_keeps_the_class_names_the_stylesheet_targets():
    """ion-pages.css styles the picker through .role-widgets, .role-widget,
    .role-widget-input, .role-widget-card and six more under
    body[data-page="users"], and the per-role accent comes from a
    --role-color custom property. The point of the conversion is that a
    restyle reaches the markup."""
    html = picker(_role())
    for cls in ("role-widgets", "role-widget", "role-widget-input",
                "role-widget-card", "role-widget-header", "role-widget-icon",
                "role-widget-tier", "role-widget-check", "role-widget-name",
                "role-widget-desc", "role-widget-caps", "role-cap-pill",
                "role-widget-perms"):
        assert cls in html, cls
    assert "--role-color:" in html


def test_the_accent_colour_goes_through_the_csp_safe_attribute():
    """ION serves no unsafe-inline, so a `style=` attribute would be
    dropped. ion-dynamic-styles.js applies data-ion-style with
    el.style.setProperty, on a MutationObserver that reaches markup which
    arrived in an htmx swap."""
    html = picker(_role(name="admin"))
    assert 'data-ion-style="--role-color:#f87171"' in html
    # The lookbehind is load-bearing: `data-ion-style="` ends in the same
    # eight characters as a real `style="`, so a bare substring check here
    # would fail on the attribute it is meant to allow.
    assert not re.search(r'(?<![-\w])style="', html)


def test_the_checkbox_value_is_the_name_the_roles_endpoint_matches_on():
    """The label is the name with its underscores replaced, and the value is
    not: PUT /api/users/{id}/roles matches the stored name."""
    html = picker(_role(name="senior_analyst"))
    assert 'value="senior_analyst"' in html
    assert "senior analyst" in html


@pytest.mark.parametrize("group,field", sorted(ROLE_GROUPS.items()))
def test_each_picker_carries_its_own_field_name(group, field):
    assert f'name="{field}"' in picker(_role(), group=group)


def test_a_role_the_metadata_table_knows_shows_its_tier_and_capabilities():
    html = picker(_role(name="forensic",
                        permissions=["forensic:read", "case:read",
                                     "ai:chat"]))
    assert "DFIR" in html
    assert "Forensics" in html
    assert "Cases" in html
    assert "AI" in html


def test_a_role_the_metadata_table_does_not_know_falls_back_to_its_own_text():
    html = picker(_role(name="tenant_auditor", description="Reads one tenant",
                        permissions=[]))
    assert "Reads one tenant" in html
    assert "tenant auditor" in html


def test_the_description_of_an_unknown_role_is_escaped():
    """`meta.short` for an unknown role is the role's own `description`
    column: stored text, settable through the role API, and interpolated
    into innerHTML unescaped."""
    html = picker(_role(name="tenant_auditor",
                        description="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_the_role_name_is_escaped_in_the_checkbox_value():
    html = picker(_role(name='x" onfocus="alert(1)'))
    assert 'onfocus="alert(1)"' not in html


@pytest.mark.parametrize("permissions,expected", [
    (["a:read", "b:read", "c:read"], "3 permissions"),
    ([], "0 permissions"),
    (None, "permissions unknown"),
])
def test_the_permission_count_tells_a_measured_zero_from_a_missing_list(
    permissions, expected
):
    """`is not none`, never truthiness, and never `|| []`. A role that
    grants nothing is a measurement worth reading before you assign it; a
    role whose permission list did not arrive is a different claim. The
    JavaScript's `(role.permissions || []).length` printed 0 for both, on
    the one widget where the figure decides what access somebody gets.

    All three arms arranged, because the None case alone behaves identically
    under every variant of the guard.
    """
    html = flat(picker(_role(permissions=permissions)))
    assert expected in html


def test_a_role_with_no_permissions_is_not_described_as_unknown():
    html = flat(picker(_role(permissions=[])))
    assert "permissions unknown" not in html


def test_a_picker_that_could_not_be_read_says_so_rather_than_rendering_empty():
    """loadRoles() rendered nothing at all on a failed read, so the Roles
    fieldset was an empty box. That reads as "this deployment defines no
    roles", which is the opposite instruction."""
    html = flat(failed_picker())
    assert "could not be read" in html
    assert "It is unknown" in html
    assert "role-widget" not in html


def test_a_deployment_with_no_roles_is_a_different_claim():
    html = flat(picker())
    assert "nothing to assign" in html
    assert "came back empty" in html
    assert "could not be read" not in html


def test_a_failed_picker_is_marked_for_the_form_handlers():
    """The attribute rather than the wording, because the two save handlers
    check it. A picker whose read failed holds no checked boxes, and
    `roles: []` on PUT /api/users/{id}/roles strips every role the account
    holds rather than leaving them alone."""
    assert "data-roles-unreadable" in failed_picker()
    assert "data-roles-unreadable" not in picker(_role())
    assert "data-roles-unreadable" not in picker()


def test_the_save_handlers_refuse_to_submit_an_unreadable_picker():
    js = page_code()
    assert "data-roles-unreadable" in js
    assert js.count("rolesUnreadable(") == 3, (
        "expected one definition and one check in each of the two save "
        "handlers"
    )


# ---------------------------------------------------------------------------
# The routes, which are what select a state
# ---------------------------------------------------------------------------


class _Viewer:
    def __init__(self, *permissions: str, user_id: object = VIEWER_ID):
        self.id = user_id
        self._permissions = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self._permissions


def _request(path: str = "/ui/users") -> Request:
    return Request({
        "type": "http", "method": "GET", "path": path,
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("testserver", 80), "root_path": "",
    })


def _call_table(monkeypatch, payload, *, viewer: _Viewer | None = None,
                include_inactive: bool = False):
    monkeypatch.setattr(page, "users_list_payload", payload)
    return page.users_fragment(
        request=_request(),
        include_inactive=include_inactive,
        user=viewer or _Viewer(_READ_PERM, _UPDATE_PERM, _DELETE_PERM,
                               _CREATE_PERM),
        session=object(),
    )


def _call_picker(monkeypatch, payload, *, group: str = "new"):
    monkeypatch.setattr(page, "roles_list_payload", payload)
    return page.users_role_options_fragment(
        request=_request("/ui/users/role-options"),
        group=group,
        user=_Viewer(_READ_PERM),
        session=object(),
    )


def test_the_route_renders_the_table_when_the_read_succeeds(monkeypatch):
    """The positive control. Without it the failure tests below pass for a
    route that only ever renders a failure."""
    html = flat(_call_table(
        monkeypatch, lambda session, include_inactive=False: [_entry()]
    ).body.decode("utf-8"))
    assert "jdoe@example.com" in html
    assert "could not be read" not in html


def test_the_route_renders_the_failure_state_when_the_read_raises(monkeypatch):
    """Rendering the template directly with failed=True proves the markup and
    says nothing about whether the route ever selects it. An except handler
    that returned `[]` with failed=False would be exactly the JavaScript's
    defect and would leave every template test above green."""
    def boom(session, include_inactive=False):
        raise RuntimeError("the users query failed")

    html = flat(_call_table(monkeypatch, boom).body.decode("utf-8"))
    assert "not an empty directory" in html
    assert "No active users found" not in html


def test_the_failing_route_still_answers_200_so_htmx_swaps_the_wording(
    monkeypatch
):
    """htmx does not swap a non-2xx body, so a route that let the exception
    out would leave the spinner under htmx-errors.js's generic alert and the
    wording, which is the point of the branch, would never reach the page."""
    def boom(session, include_inactive=False):
        raise RuntimeError("the users query failed")

    assert _call_table(monkeypatch, boom).status_code == 200


def test_a_failed_read_is_logged_with_its_traceback(monkeypatch, caplog):
    """The fragment answers 200 with honest wording, so the exception is the
    only record that anything broke."""
    def boom(session, include_inactive=False):
        raise RuntimeError("the users query failed")

    with caplog.at_level(logging.ERROR, logger="ion.web.ui.users"):
        _call_table(monkeypatch, boom)
    records = [r for r in caplog.records if r.name == "ion.web.ui.users"]
    assert records, "the failure was swallowed"
    assert all(r.exc_info for r in records), "logged without a traceback"


def test_the_route_passes_the_filter_through_to_the_shared_payload(
    monkeypatch
):
    """The checkbox's value has to reach `list_all`'s only filter, or Show
    inactive users is a control that does nothing."""
    seen = {}

    def payload(session, include_inactive=False):
        seen["include_inactive"] = include_inactive
        return []

    _call_table(monkeypatch, payload, include_inactive=True)
    assert seen == {"include_inactive": True}


def test_the_route_asks_the_viewer_rather_than_assuming_the_write_rights(
    monkeypatch
):
    """can_update, can_delete and can_create come off the authenticated user,
    so a read-only analyst is offered none of the four controls the server
    would refuse."""
    html = flat(_call_table(
        monkeypatch,
        lambda session, include_inactive=False: [_entry()],
        viewer=_Viewer(_READ_PERM),
    ).body.decode("utf-8"))
    assert "showEditUserModal" not in html
    assert "showResetPasswordModal" not in html
    assert "deleteUser" not in html
    assert "showCreateUserModal" not in html
    assert "read user accounts but not change them" in html


def test_the_route_withholds_delete_on_the_viewers_own_row(monkeypatch):
    """The self-delete rule read through the route rather than through
    _row_view, because the route is what supplies the viewer's id."""
    html = flat(_call_table(
        monkeypatch,
        lambda session, include_inactive=False: [
            _entry(id=VIEWER_ID, username="me"),
            _entry(id=VIEWER_ID + 1, username="them"),
        ],
    ).body.decode("utf-8"))
    assert "Cannot delete your own account" in html
    assert html.count("deleteUser") == 1


def test_the_picker_route_renders_the_widgets_when_the_read_succeeds(
    monkeypatch
):
    html = _call_picker(
        monkeypatch, lambda session: [_role(name="admin")]
    ).body.decode("utf-8")
    assert "role-widget-card" in html
    assert 'value="admin"' in html


def test_the_picker_route_renders_the_failure_state_when_the_read_raises(
    monkeypatch
):
    def boom(session):
        raise RuntimeError("the roles query failed")

    response = _call_picker(monkeypatch, boom)
    html = flat(response.body.decode("utf-8"))
    assert response.status_code == 200
    assert "could not be read" in html
    assert "data-roles-unreadable" in html
    assert "nothing to assign" not in html


@pytest.mark.parametrize("group,field", sorted(ROLE_GROUPS.items()))
def test_the_picker_route_names_the_field_from_the_literal_mapping(
    monkeypatch, group, field
):
    """The field name is looked up in ROLE_GROUPS rather than interpolated
    from the query value, so the fragment cannot be asked to emit an
    attribute of the caller's choosing."""
    html = _call_picker(
        monkeypatch, lambda session: [_role()], group=group
    ).body.decode("utf-8")
    assert f'name="{field}"' in html


def test_the_picker_route_takes_no_group_outside_that_mapping():
    """The annotation is what rejects one, before the lookup can raise a
    KeyError into a 500.

    Evaluated rather than read off the signature: the module declares
    `from __future__ import annotations`, so the raw annotation is the
    string "Literal[...]" and `__args__` on a string is empty, which would
    make this assertion pass for any annotation at all.
    """
    annotation = inspect.get_annotations(
        page.users_role_options_fragment, eval_str=True
    )["group"]
    assert set(annotation.__args__) == set(ROLE_GROUPS)


# ---------------------------------------------------------------------------
# Permission, and the payload both callers share
# ---------------------------------------------------------------------------


def _ui_route(path: str):
    import ion.web.ui as ui

    for r in ui.router.routes:
        if r.path == path:
            return r
    raise AssertionError(f"{path} is not mounted")


def _api_route(path: str, method: str = "GET"):
    from ion.web.api import router as api_router

    for r in api_router.routes:
        if r.path == path and method in r.methods:
            return r
    raise AssertionError(f"{method} {path} is not an API route")


def _dependency_calls(route) -> list:
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _required_permissions(route) -> set[str]:
    """Every permission the route's dependency tree really demands.

    Read out of the closure cell rather than off the decorator, and from
    both factories: `require_permission` keeps one name in
    `permission_name` and `require_any_permission` keeps a list in
    `permission_names`. A fragment that reached for the second where its
    endpoint uses the first would read as a gate while being a softer way
    in, and nothing in a diff would show it.
    """
    found = set()
    for fn in _dependency_calls(route):
        base = getattr(fn, "__qualname__", "").split(".")[0]
        if base not in ("require_permission", "require_any_permission"):
            continue
        cells_ = dict(zip(fn.__code__.co_freevars,
                          (c.cell_contents for c in (fn.__closure__ or ()))))
        one = cells_.get("permission_name")
        many = cells_.get("permission_names")
        if isinstance(one, str):
            found.add(one)
        if isinstance(many, (list, tuple, set)):
            found.update(many)
    return found


MIRRORED = {
    "/ui/users": "/users",
    "/ui/users/role-options": "/roles",
}


@pytest.mark.parametrize("ui_path,api_path", sorted(MIRRORED.items()))
def test_each_fragment_permission_matches_the_endpoint_it_mirrors(ui_path,
                                                                 api_path):
    """A fragment must never be a softer way in than the API it mirrors, nor
    a harder one. Read off the live /api route rather than restated here, so
    tightening that endpoint fails here instead of quietly leaving the
    fragment behind. This is an administrative page, and /api/roles returns
    the whole role-to-permission map."""
    api_perms = _required_permissions(_api_route(api_path))
    assert api_perms == {_READ_PERM}, api_perms
    assert _required_permissions(_ui_route(ui_path)) == api_perms


@pytest.mark.parametrize("perm,path,method", [
    ("user:update", "/users/{user_id}", "PUT"),
    ("user:update", "/users/{user_id}/roles", "PUT"),
    ("user:update", "/users/{user_id}/reset-password", "POST"),
    ("user:delete", "/users/{user_id}", "DELETE"),
    ("user:create", "/users", "POST"),
])
def test_the_withheld_controls_are_withheld_on_the_real_permissions(
    perm, path, method
):
    """The three constants the fragment branches on, checked against the
    routes the buttons actually call rather than against a guess. A button
    withheld on the wrong permission is as wrong as one offered on none."""
    assert _required_permissions(_api_route(path, method)) == {perm}


def test_the_write_permissions_are_not_the_read_one():
    """What makes the test above load-bearing: if every one of these were
    user:read, withholding a control would be unreachable and every test
    above it would pass for a fragment that always shows everything."""
    assert _READ_PERM not in {_UPDATE_PERM, _DELETE_PERM, _CREATE_PERM}
    assert len({_UPDATE_PERM, _DELETE_PERM, _CREATE_PERM}) == 3


@pytest.mark.parametrize("ui_path", sorted(MIRRORED))
def test_no_fragment_uses_a_redirecting_page_dependency(ui_path):
    """require_page_permission answers an unauthorised request with a
    redirect to the login form, which htmx would swap into the middle of the
    page as a password box."""
    for call in _dependency_calls(_ui_route(ui_path)):
        name = getattr(call, "__qualname__", "")
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name


#: The keys GET /api/users answered with before the payload was extracted.
#: Frozen here because the fragment now shares that function: a field added
#: for the fragment's benefit would change what the JSON endpoint returns.
ENDPOINT_KEYS = {
    "id", "username", "email", "display_name", "is_active", "last_login",
    "roles", "employment_type", "elastic_username", "elastic_uid",
    "keycloak_sub", "gitlab_username", "created_at",
}


def test_the_shared_payload_still_returns_exactly_what_the_endpoint_did():
    """The extraction is a move, not a change. The fragment reads this
    function, so the temptation is to add a column it wants, and that column
    would appear in the JSON endpoint's response without anyone asking."""
    source = inspect.getsource(page.users_list_payload)
    emitted = set(re.findall(r'^\s*"([a-z_]+)":', source, re.M))
    assert emitted == ENDPOINT_KEYS, emitted ^ ENDPOINT_KEYS


def test_the_json_endpoint_calls_the_function_the_fragment_calls():
    """Not a second copy of the row shape or of list_all's inactive filter.
    The endpoint's body is the call and nothing else, so the two cannot
    drift."""
    from ion.web import api

    source = inspect.getsource(api.list_users)
    assert "users_list_payload" in source
    assert "UserRepository" not in source
    assert "elastic_uid" not in source


def test_the_roles_endpoint_calls_the_function_the_picker_calls():
    from ion.web import api

    source = inspect.getsource(api.list_roles)
    assert "roles_list_payload" in source
    assert "RoleRepository" not in source


def test_the_role_payload_always_states_a_permission_list():
    """What keeps "0 permissions" honest. The absent case is still rendered
    as unknown, but the function both callers share does not produce it."""
    from ion.web import api

    source = inspect.getsource(api.roles_list_payload)
    assert '"permissions": [p.name for p in r.permissions]' in source


def test_the_user_list_has_no_per_caller_scope_to_reimplement():
    """Checked rather than assumed. UserRepository.list_all filters on
    is_active and nothing else, so every viewer holding user:read sees every
    account, and a scope invented in the fragment would hide rows the API
    returns. If one is ever added this fails, which is the point."""
    source = inspect.getsource(page.users_list_payload)
    assert "viewer" not in source
    assert "current_user" not in source
    assert list(
        inspect.signature(page.users_list_payload).parameters
    ) == ["session", "include_inactive"]


# ---------------------------------------------------------------------------
# The page that is left
# ---------------------------------------------------------------------------


def page_scripts() -> str:
    src = PAGE.read_text(encoding="utf-8")
    return "".join(
        re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S)
    )


def page_code() -> str:
    """The script bodies with their // comments removed.

    The comments name the helpers that were deleted and the fetch that no
    longer happens, which is the point of them, so a test for those names
    has to read the code rather than the prose about it. A whole-file
    substring assertion over a conversion's own comments is how three
    earlier pages shipped a guard that could not fail.
    """
    return re.sub(r"(?m)^\s*//.*$", "", page_scripts())


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does. Scoped to the inline script bodies: hx-swap="innerHTML" is an
    attribute telling htmx where to put server-rendered markup, which is the
    opposite of the thing being removed."""
    js = page_scripts()
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_table_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/users"' in src
    assert 'hx-trigger="load' in src
    assert 'id="users-content"' in src


def test_the_page_requests_a_picker_for_each_modal():
    src = PAGE.read_text(encoding="utf-8")
    for group in ROLE_GROUPS:
        assert f'hx-get="/ui/users/role-options?group={group}"' in src


def test_the_page_holds_the_slot_the_fragment_swaps_out_of_band():
    """htmx drops an out-of-band element whose id is not in the document and
    says so only in the console, so the New User button would simply never
    appear."""
    src = PAGE.read_text(encoding="utf-8")
    assert 'id="users-create-slot"' in src


def test_the_page_carries_no_second_copy_of_the_servers_table():
    js = page_code()
    assert "function loadUsers" not in js
    assert "function loadRoles" not in js
    assert "renderRoleCheckboxes" not in js
    assert "ROLE_META" not in js, "the metadata table lives in the module"
    assert "permissionCapabilities" not in js
    assert "toLocaleString" not in js, "the ts macro is the viewer's clock"
    assert "No users found" not in js, "the empty state is the server's"
    assert "users-tbody" not in js, "the rows are the server's"


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what an expired session means. The
    page used to redirect to /login itself on a 401 from /api/users."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src
    assert "htmx:afterRequest" not in src
    assert "/login?redirect=" not in src


def test_the_controls_sit_outside_the_swap_target():
    """A render that says the read failed must not remove the control that
    retries it, or a page reload is the only way back. Measured by position:
    both controls are in the card header, which closes before the swap
    target opens."""
    src = PAGE.read_text(encoding="utf-8")
    target = src.index('id="users-content"')
    for control in ('id="include-inactive"', ">Refresh<"):
        assert control in src, control
        assert src.index(control) < target, control


def test_the_filter_reaches_the_fragment_on_every_request_that_renders_it():
    """hx-include on the container as well as on the two controls. Firefox
    restores a checkbox's state across a reload, so a first paint that sent
    nothing would show the active users under a ticked box."""
    src = PAGE.read_text(encoding="utf-8")
    assert src.count('hx-include="#include-inactive"') == 3
    assert 'name="include_inactive"' in src


def test_the_filter_sends_a_value_the_route_parses_unambiguously():
    """A checkbox with no value sends the browser's "on". Spelling it means
    the wire format and the route's bool are the same decision in one
    place."""
    src = PAGE.read_text(encoding="utf-8")
    assert 'name="include_inactive" value="true"' in src


def test_every_mutation_re_requests_the_table():
    """Each one used to call loadUsers(), which rebuilt the tbody from
    strings. They are still mutations; what changed is the aftermath.

    Counted rather than searched per function: one definition plus one call
    from each of create, update and delete. Reset Password changes no row the
    table shows, so it is not among them. A handler that patched the DOM
    itself instead would leave the count short.
    """
    js = page_code()
    assert "loadUsers" not in js
    for handler in ("createUser", "updateUser", "deleteUser"):
        assert "function " + handler in js, handler
    assert js.count("refreshUsers") == 4, (
        "expected one definition, one call from each of the three mutations"
    )


def test_the_page_binds_every_handler_the_fragment_names():
    """event-delegation.js resolves a data-click-action through window[], so
    a fragment naming a handler the page never exposes renders a button that
    does nothing when clicked. Four of these names are rendered by the
    fragment rather than written in the page."""
    js = page_code()
    fragment = (TEMPLATE_DIR / FRAGMENT).read_text(encoding="utf-8")
    named = set(re.findall(r'data-click-action="([^"]+)"', fragment))
    assert named, "the fragment names no handler, so this proves nothing"
    for name in named:
        assert f"window.{name} =" in js, name


@pytest.mark.parametrize("name", [
    "users.html",
    "_fragments/users.html",
    "_fragments/users_role_options.html",
])
def test_no_htmx_feature_that_compiles_a_string(name):
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing: the markup
    reads right, the fragment the server returns is right, and the control
    is dead. That rules out an hx-trigger event filter such as
    `keyup[key=='Enter']`, the `js:` form of hx-vals and hx-headers, and
    hx-on. One converted page shipped a dead Enter key this way, and only a
    browser console showed it.
    """
    src = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    assert "hx-on" not in src
    assert "hx-vals" not in src
    assert "hx-headers" not in src
    assert not re.search(r'hx-trigger="[^"]*\[', src)
