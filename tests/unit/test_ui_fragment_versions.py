"""The template version history as server-rendered fragments.

versions.html built the version list out of string concatenation and wrote
it into `#versions-list` at three sites, and built the detail modal's meta
bar at two more. The cases below are what that JavaScript either got right
and must keep, or got wrong and must stop doing:

  * `v.message || 'No message'` folded an empty message into "no message".
    Those are not the same claim about who wrote the version.
  * the message went in through innerHTML without escapeHtml, so a template
    updated with `{"message": "<img src=x onerror=...>"}` executed on this
    page. The checkpoint name beside it was escaped, which is what makes the
    omission easy to miss.
  * a checkpoint with no name rendered `escapeHtml(null)` into its badge.
  * `formatDate` is `toLocaleDateString` over a naive stamp, so the column
    showed the stored digits as though they were the viewer's clock and
    labelled them as nobody's.
  * a template that does not exist and a database that will not answer both
    rendered "Failed to load versions".
  * the Diff button's version pair, which is the only arithmetic on the page.

The rows are built as unflushed TemplateVersion objects rather than dicts:
an attribute that was never set is None, where `row.message` on a dict
missing the key is Undefined, and `Undefined is not none` is true. That
would make every "no message" case below pass for the wrong reason.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request

from ion.core.exceptions import TemplateNotFoundError, VersionNotFoundError
from ion.models.version import TemplateVersion
from ion.web.templating import make_templates
from ion.web.ui import versions as page

LIST = "_fragments/versions_list.html"
DETAIL = "_fragments/versions_detail.html"
META = "_fragments/versions_meta.html"
TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "src/ion/web/templates"
PAGE = TEMPLATE_DIR / "versions.html"


def flat(html: str) -> str:
    """Whitespace collapsed, because the templates wrap their sentences.

    A prose assertion against the raw render fails on whatever line break
    Jinja kept, and the obvious fix is to shorten the sentence in the
    template until the test passes, which is the test dictating the wording.
    """
    return re.sub(r"\s+", " ", html)


def render(name: str, **ctx: Any) -> str:
    return make_templates().env.get_template(name).render(**ctx)


def _v(**over: Any) -> TemplateVersion:
    base: dict[str, Any] = {
        "version_number": 3,
        "content": "line one\nline two\n",
        "is_checkpoint": False,
        "checkpoint_name": None,
        "message": "second revision",
        "author": "admin",
        "created_at": "2026-10-12T10:30:10",
    }
    base.update(over)
    return TemplateVersion(**base)


def rows(*vs: TemplateVersion) -> str:
    return render(LIST, rows=list(vs), state="ok", template_id=23)


def detail(**over: Any) -> str:
    ctx: dict[str, Any] = {
        "kind": "version", "state": "ok", "version": _v(),
        "version_number": 3, "rollback_to": 3, "template_id": 23,
    }
    ctx.update(over)
    return render(DETAIL, **ctx)


def diff_modal(**over: Any) -> str:
    ctx: dict[str, Any] = {
        "kind": "diff", "state": "ok", "diff": "--- old\n+++ new\n+line three\n",
        "from_version": 2, "to_version": 3, "version_number": None,
        "rollback_to": 3, "template_id": 23,
    }
    ctx.update(over)
    return render(DETAIL, **ctx)


def hx_gets(html: str) -> list[str]:
    return re.findall(r'hx-get="([^"]*)"', html)


# ---------------------------------------------------------------------------
# The row, which is what actually moved
# ---------------------------------------------------------------------------


def test_a_version_renders_its_row():
    html = rows(_v(version_number=2, message="second revision"))
    assert "v2" in html
    assert "second revision" in html
    assert ">View<" in html


def test_the_row_keeps_the_class_names_the_stylesheet_targets():
    """ion-pages.css styles this page through .version-item, .version-header,
    .version-number, .version-meta and .version-actions under
    body[data-page="versions"]. The point of the conversion is that a restyle
    reaches the markup, so the markup keeps the hooks it is restyled through.
    """
    html = rows(_v())
    for cls in ("version-item", "version-header", "version-number",
                "version-meta", "version-actions", "ion-btn"):
        assert cls in html, cls


def test_a_checkpoint_row_is_marked_and_badged():
    html = rows(_v(is_checkpoint=True, checkpoint_name="v1.0"))
    assert "version-item checkpoint" in html
    assert "checkpoint-badge" in html
    assert "v1.0" in html


def test_a_plain_version_has_neither_the_class_nor_the_badge():
    html = rows(_v(is_checkpoint=False))
    assert "version-item checkpoint" not in html
    assert "checkpoint-badge" not in html


@pytest.mark.parametrize("flag", [True, 1])
def test_a_truthy_checkpoint_flag_badges_the_row(flag):
    """Parametrised over a non-boolean on purpose.

    `is_checkpoint` is a non-nullable Boolean column, so it is two-state and
    the guard is deliberately truthiness rather than `is true`. A raw row, or
    a payload that has been through JSON, hands back 1 rather than True, and
    `{% if x is true %}` would drop the badge for it while every True-valued
    case above still passed.
    """
    assert "checkpoint-badge" in rows(_v(is_checkpoint=flag,
                                         checkpoint_name="v1.0"))


@pytest.mark.parametrize("flag", [False, 0, None])
def test_a_falsy_checkpoint_flag_does_not_badge_the_row(flag):
    assert "checkpoint-badge" not in rows(_v(is_checkpoint=flag,
                                             checkpoint_name="v1.0"))


def test_a_checkpoint_with_no_name_does_not_render_the_word_none():
    """The JavaScript put escapeHtml(v.checkpoint_name) in the badge under
    `if (v.is_checkpoint)` alone, so a checkpoint whose name is missing
    rendered a badge reading "null". A badge naming nothing is still a true
    claim that this version is a checkpoint; one reading "null" is not."""
    html = rows(_v(is_checkpoint=True, checkpoint_name=None))
    assert "checkpoint-badge" in html
    assert "None" not in html
    assert "null" not in html


# ---------------------------------------------------------------------------
# message: absent is not empty
# ---------------------------------------------------------------------------


def test_a_version_with_no_message_says_so():
    assert "No message" in rows(_v(message=None))


def test_an_empty_message_is_not_the_same_claim_as_no_message():
    """`v.message || 'No message'` could not tell them apart. A version saved
    with an empty message had one and it was empty; a version with none never
    carried one, which is the case worth labelling."""
    assert "No message" not in rows(_v(message=""))


def test_a_message_is_rendered_verbatim():
    """"0" is the case worth naming: a message is a Text column, so an empty
    string is the only falsy value it can hold, and a guard written
    `{% if v.message is not none and v.message %}` would read as careful
    while dropping anything else a reader assumes is falsy."""
    html = rows(_v(message="0"))
    assert "No message" not in html
    assert ">0<" in html


def test_jinja_escapes_what_escapehtml_was_never_asked_to():
    """The checkpoint name went through escapeHtml and the message did not,
    so the message was a stored-XSS sink reachable from
    PUT /api/templates/{id} with a crafted `message`. Jinja escapes both."""
    html = rows(_v(is_checkpoint=True,
                   checkpoint_name="<script>alert(1)</script>",
                   message="<img src=x onerror=alert(2)>"))
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# created_at, ported off formatDate
# ---------------------------------------------------------------------------


def test_the_timestamp_is_a_time_element_rather_than_a_server_format():
    """formatDate called toLocaleDateString, which is the viewer's clock. A
    server knows only its own, so the macro emits the stored value in a
    <time> and static/js/local-time.js rewrites it after the swap."""
    html = rows(_v(created_at="2026-10-12T10:30:10"))
    assert "<time datetime=" in html
    assert "2026-10-12" in html


def test_a_zoneless_stamp_is_not_offered_up_for_localising():
    """The defect formatDate shipped, stated as a guard rather than left to
    the macro's own tests.

    `created_at` is a naive DateTime column, so the value carries no zone.
    JavaScript parses a zoneless ISO date-time as local time, so localising
    it converts out of a zone the value was never in and is wrong by the
    viewer's offset while looking authoritative. The macro marks such a
    value `data-ts-local="no"`, and that attribute is what keeps
    local-time.js off it.
    """
    html = rows(_v(created_at="2026-10-12T10:30:10"))
    assert 'data-ts-local="no"' in html
    assert 'data-ts-local="yes"' not in html


def test_a_zoned_stamp_is_localised():
    """The positive control for the test above, which would otherwise pass
    for a macro that never localises anything."""
    html = rows(_v(created_at="2026-10-12T10:30:10+00:00"))
    assert 'data-ts-local="yes"' in html


def test_a_version_with_no_timestamp_does_not_render_the_epoch():
    assert "1970" not in rows(_v(created_at=None))


# ---------------------------------------------------------------------------
# The Diff pair, which is the only arithmetic on the page
# ---------------------------------------------------------------------------


def test_version_one_offers_no_diff():
    """There is nothing before version 1 to compare it against, and the
    JavaScript's `v.version_number > 1` said so."""
    html = rows(_v(version_number=1))
    assert ">Diff<" not in html
    assert hx_gets(html) == ["/ui/templates/23/versions/1"]


@pytest.mark.parametrize("n", [2, 3, 7, 42])
def test_a_diff_compares_the_previous_version_with_this_one(n):
    """The pair is (n - 1, n), in that order. Either half shifted by one
    renders a button that diffs the wrong two versions and says nothing about
    it, which is the failure this arithmetic invites."""
    assert hx_gets(rows(_v(version_number=n))) == [
        f"/ui/templates/23/versions/{n}",
        f"/ui/templates/23/versions/diff/{n - 1}/{n}",
    ]


def test_version_zero_offers_view_but_no_diff():
    """Version 0 should not exist. If one does, `{% if n %}` would drop its
    View button as though the row were not there, and `> 1` is what keeps the
    Diff button off it. Both halves are cheap to pin."""
    html = rows(_v(version_number=0))
    assert "v0" in html
    assert hx_gets(html) == ["/ui/templates/23/versions/0"]


def test_a_row_with_no_version_number_offers_no_actions():
    """`is not none`, not truthiness: a row with no number has nothing for
    View or Diff to address, and the button would hx-get
    /ui/templates/23/versions/None."""
    html = rows(_v(version_number=None))
    assert hx_gets(html) == []
    assert "vNone" not in html


def test_the_action_buttons_target_the_modal_host_in_the_page():
    """The host is in the page shell, not in this fragment, so a list that
    re-renders does not take the open modal with it."""
    html = rows(_v())
    assert html.count('hx-target="#version-modal-host"') == 2


def test_every_version_in_the_list_gets_its_own_row():
    html = rows(_v(version_number=3), _v(version_number=2), _v(version_number=1))
    assert html.count("version-item") == 3
    assert hx_gets(html)[0] == "/ui/templates/23/versions/3"
    assert hx_gets(html)[-1] == "/ui/templates/23/versions/1"


def test_every_url_the_row_emits_is_a_route_this_module_mounts():
    """The buttons' only correctness check that reaches past their own string.

    A prefix typed one way in the template and another in the decorator
    renders a button that 404s on click, and every assertion above would
    still pass because they compare the attribute against the same wrong
    string. Matched against the mounted paths instead.
    """
    import ion.web.ui as ui

    mounted = [
        re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", r.path) + "$")
        for r in ui.router.routes
    ]
    emitted = hx_gets(rows(_v(version_number=3)))
    assert emitted, "no URL was emitted, so this proves nothing"
    for url in emitted:
        assert any(p.match(url) for p in mounted), url


# ---------------------------------------------------------------------------
# Three states: rows, nothing, and could not look
# ---------------------------------------------------------------------------


def test_no_version_history_says_so():
    html = flat(render(LIST, rows=[], state="ok", template_id=23))
    assert "No versions found" in html
    assert "could not be read" not in html


def test_a_failed_read_says_so_rather_than_showing_an_empty_list():
    """"Nothing there" and "we could not look" lead to opposite actions. The
    JavaScript distinguished them ("Failed to load versions") and so must
    this."""
    html = flat(render(LIST, rows=None, state="failed", template_id=23))
    assert "could not be read" in html
    assert "not an empty history" in html
    assert "Use Refresh to try again" in html, (
        "the branch has to name the control that retries it, since the "
        "operator's alternative is to read the wording as a dead end"
    )
    assert "No versions found" not in html


def test_a_missing_template_is_a_different_claim_than_a_failed_read():
    """The JSON endpoint answers 404 for a template that does not exist and
    500 for a database that will not answer. One wording for both sends an
    analyst looking for an outage that is a mistyped id."""
    html = flat(render(LIST, rows=None, state="missing", template_id=4242))
    assert "No template 4242" in html
    assert "could not be read" not in html
    assert "No versions found" not in html


@pytest.mark.parametrize("state", ["failed", "missing"])
def test_the_list_failure_states_keep_the_class_the_stylesheet_targets(state):
    """ion-pages.css styles `#versions-list > .error`, a direct-child
    selector, so the error has to arrive as a direct child of the swap
    target. Wrapping this fragment in a card would leave both failure states
    unstyled and nothing would look broken enough to notice."""
    html = render(LIST, rows=None, state=state, template_id=23).strip()
    assert html.startswith('<p class="error"')


def test_the_empty_state_keeps_the_class_the_stylesheet_targets():
    html = render(LIST, rows=[], state="ok", template_id=23).strip()
    assert html.startswith('<p class="empty-state"')


# ---------------------------------------------------------------------------
# The detail modal
# ---------------------------------------------------------------------------


def test_the_detail_modal_shows_the_version_and_its_content():
    html = detail(version=_v(version_number=3, content="line one\nline two\n"))
    assert "Version 3" in html
    assert "line one" in html
    assert "<pre" in html


def test_the_detail_modal_renders_the_same_metadata_as_the_row():
    """One macro, so the modal cannot disagree with the row it was opened
    from. viewVersion() and loadVersions() each had their own copy and the
    copies had already drifted on escaping."""
    v = _v(is_checkpoint=True, checkpoint_name="v1.0", message=None)
    html = detail(version=v)
    assert "checkpoint-badge" in html
    assert "v1.0" in html
    assert "No message" in html
    assert "<time datetime=" in html


def test_the_detail_modal_escapes_the_version_content():
    html = detail(version=_v(content="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_the_diff_modal_escapes_the_diff():
    """A diff is two versions' content spliced together, so it carries
    whatever either of them carried. The <pre> is not a safe harbour: it
    renders a tag like any other element."""
    html = diff_modal(diff="+<script>alert(1)</script>\n")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_the_modal_opens_itself_rather_than_waiting_for_a_style_write():
    """The modal used to be a hidden element in the page that JavaScript
    revealed with showModal()'s classList.add('show'). It arrives open, so
    "what does an open modal look like" has one definition and no second
    place to disagree.

    `show`, not daisyUI's `modal-open`: the compiled ion.css has two modal
    systems and the legacy unlayered `.modal{display:none}` beats daisyUI's
    layered `.modal{display:grid}`, so `modal modal-open` computes to
    display:none on this page. That was measured in a browser, which is the
    only way it shows: the class name reads correct either way.
    """
    html = detail()
    assert 'class="modal show"' in html
    assert "modal-open" not in html


def test_the_diff_modal_names_the_pair_in_order():
    html = diff_modal(from_version=2, to_version=3)
    assert "Version 2 &rarr; 3" in html
    assert "Comparing versions" in html


def test_the_diff_modal_shows_the_diff():
    html = diff_modal(diff="--- old\n+++ new\n+line three\n")
    assert "+line three" in html
    assert "No changes" not in html


@pytest.mark.parametrize("empty", ["", None])
def test_an_empty_diff_is_no_changes(empty):
    """diff_versions returns a str, so empty is the only falsy value it can
    hand back and it means the two versions have identical content."""
    html = diff_modal(diff=empty)
    assert "No changes" in html


@pytest.mark.parametrize("kind,state", [
    ("version", "ok"), ("version", "missing"), ("version", "failed"),
    ("diff", "ok"), ("diff", "missing"), ("diff", "failed"),
])
def test_every_modal_state_keeps_a_way_out(kind, state):
    """bob_eval learned this in a browser rather than in a test: an error swap
    that returned a bare alert left the panel open with no Close button, so
    the only way out was a reload. The chrome wraps both branches."""
    html = (diff_modal if kind == "diff" else detail)(
        state=state, rollback_to=None if state != "ok" else 3,
    )
    assert "data-remove-closest" in html
    assert ">Close<" in html
    assert "data-remove-self-on-self-click" in html


@pytest.mark.parametrize("kind,state", [
    ("version", "missing"), ("version", "failed"),
    ("diff", "missing"), ("diff", "failed"),
])
def test_every_modal_state_keeps_a_heading_that_names_what_was_asked_for(
    kind, state
):
    """The other half of the chrome rule. A heading reading "Version" with
    nothing after it leaves the operator unable to say which version the
    modal failed on, so the number is passed from the route rather than read
    off a payload the failing branches do not have."""
    html = (diff_modal if kind == "diff" else detail)(
        state=state, version=None, diff=None, rollback_to=None,
    )
    assert ("Version 2 &rarr; 3" if kind == "diff" else "Version 3") in html


def test_a_modal_that_could_not_read_the_version_says_so():
    html = flat(detail(state="failed", version=None, rollback_to=None))
    assert "could not be read" in html
    assert "not an empty version" in html
    assert "Content" not in html


def test_a_modal_for_a_version_that_is_gone_is_a_different_claim():
    html = flat(detail(state="missing", version=None, rollback_to=None))
    assert "no longer exists" in html
    assert "could not be read" not in html


@pytest.mark.parametrize("state", ["failed", "missing"])
def test_a_modal_that_read_nothing_offers_no_rollback(state):
    """A button labelled "Rollback to This Version" in a modal that could not
    read the version is a button that lies about what it would act on."""
    html = detail(state=state, version=None, rollback_to=None)
    assert "Rollback" not in html


def test_the_rollback_button_carries_the_version_it_would_roll_back_to():
    """It used to read a `currentVersionNum` global that two functions wrote,
    so a modal that failed to open could leave the previous value behind for
    Rollback to act on."""
    assert "data-args='[3]'" in detail(rollback_to=3)


def test_rollback_to_version_zero_is_still_offered():
    """`is not none`, not truthiness. Version 0 should not exist, but if one
    does then `{% if rollback_to %}` is how the only way back off it
    disappears. The handler in the page shell makes the same call with
    `=== null || === undefined` rather than `!versionNum`."""
    html = detail(version=_v(version_number=0), version_number=0,
                  rollback_to=0)
    assert "data-args='[0]'" in html
    assert "Rollback" in html


def test_the_diff_modal_rolls_back_to_the_later_of_the_pair():
    """showDiff() set currentVersionNum = toVersion. Rolling a comparison
    back to the version on its left would undo the change being read."""
    assert "data-args='[3]'" in diff_modal(from_version=2, to_version=3)


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


def _request(path: str = "/ui/templates/23/versions") -> Request:
    return Request({
        "type": "http", "method": "GET", "path": path,
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("testserver", 80), "root_path": "",
    })


class _Stub:
    """Stands in for VersionService. `calls` is what proves reuse."""

    def __init__(self, result: Any = None, raises: BaseException | None = None):
        self.result, self.raises, self.calls = result, raises, []

    def __call__(self, session: Any) -> "_Stub":
        self.session = session
        return self

    def _record(self, name: str, *a: Any, **kw: Any) -> Any:
        self.calls.append((name, a, kw))
        if self.raises is not None:
            raise self.raises
        return self.result

    def list_versions(self, *a: Any, **kw: Any) -> Any:
        return self._record("list_versions", *a, **kw)

    def get_version(self, *a: Any, **kw: Any) -> Any:
        return self._record("get_version", *a, **kw)

    def diff_versions(self, *a: Any, **kw: Any) -> Any:
        return self._record("diff_versions", *a, **kw)


def _list_body(**kw: Any) -> str:
    return page.versions_list_fragment(
        _request(), template_id=23, **kw).body.decode("utf-8")


def _detail_body(**kw: Any) -> str:
    return page.version_detail_fragment(
        _request(), template_id=23, version_number=3, **kw
    ).body.decode("utf-8")


def _diff_body(**kw: Any) -> str:
    return page.version_diff_fragment(
        _request(), template_id=23, from_version=2, to_version=3, **kw
    ).body.decode("utf-8")


def test_the_list_route_calls_the_service_the_json_endpoint_calls(monkeypatch):
    """Not a second query. /api/templates/{id}/versions goes through
    VersionService.list_versions, which is also where the template's
    existence is checked, so a fragment with its own query would answer for
    a template the API reports as 404."""
    stub = _Stub(result=[_v(version_number=1)])
    monkeypatch.setattr(page, "VersionService", stub)
    body = _list_body(session=object())
    assert stub.calls == [("list_versions", (23,), {})]
    assert "v1" in body


def test_the_detail_route_calls_get_version(monkeypatch):
    stub = _Stub(result=_v(version_number=3))
    monkeypatch.setattr(page, "VersionService", stub)
    body = _detail_body(session=object())
    assert stub.calls == [("get_version", (23, 3), {})]
    assert "Version 3" in body


def test_the_diff_route_calls_diff_versions_with_the_pair_in_order(monkeypatch):
    stub = _Stub(result="--- old\n+++ new\n")
    monkeypatch.setattr(page, "VersionService", stub)
    body = _diff_body(session=object())
    assert stub.calls == [("diff_versions", (23, 2, 3), {})]
    assert "Version 2 &rarr; 3" in body


# Each not-found read against the wording its route has to reach. Stated as
# the wording rather than as the absence of the failure wording: a route
# whose handler fell through to the empty state, or to any other branch,
# would satisfy "could not be read is absent" and prove nothing.
_NOT_FOUND = [
    ("_list_body", TemplateNotFoundError(23), "No template 23"),
    ("_detail_body", VersionNotFoundError(23, 3), "no longer exists"),
    ("_detail_body", TemplateNotFoundError(23), "no longer exists"),
    ("_diff_body", VersionNotFoundError(23, 3), "no longer exists"),
    ("_diff_body", TemplateNotFoundError(23), "no longer exists"),
]


@pytest.mark.parametrize("call,exc,wording", _NOT_FOUND)
def test_a_not_found_read_renders_the_missing_branch(monkeypatch, call, exc,
                                                     wording):
    monkeypatch.setattr(page, "VersionService", _Stub(raises=exc))
    body = flat(globals()[call](session=object()))
    assert wording in body
    assert "could not be read" not in body
    assert "No versions found" not in body


@pytest.mark.parametrize("call", ["_list_body", "_detail_body", "_diff_body"])
def test_a_raising_read_renders_the_failure_branch(monkeypatch, call):
    monkeypatch.setattr(page, "VersionService",
                        _Stub(raises=RuntimeError("database gone")))
    body = flat(globals()[call](session=object()))
    assert "could not be read" in body
    assert "No versions found" not in body
    assert "No template 23" not in body
    assert "no longer exists" not in body


@pytest.mark.parametrize("call", ["_list_body", "_detail_body", "_diff_body"])
def test_every_route_answers_200_so_htmx_swaps_the_wording(monkeypatch, call):
    """htmx does not swap a non-2xx body. A route that let the exception out
    would leave the spinner in place under htmx-errors.js's generic alert,
    and the wording above, which is the point of the branch, would never
    reach the page."""
    monkeypatch.setattr(page, "VersionService",
                        _Stub(raises=RuntimeError("database gone")))
    response = getattr(page, {
        "_list_body": "versions_list_fragment",
        "_detail_body": "version_detail_fragment",
        "_diff_body": "version_diff_fragment",
    }[call])(**({"request": _request(), "template_id": 23, "session": object()}
                | ({"version_number": 3} if call == "_detail_body" else {})
                | ({"from_version": 2, "to_version": 3}
                   if call == "_diff_body" else {})))
    assert response.status_code == 200


@pytest.mark.parametrize("call", ["_list_body", "_detail_body", "_diff_body"])
def test_a_failed_read_is_logged_with_its_traceback(monkeypatch, caplog, call):
    """Each fragment answers 200 with honest wording, so the exception is the
    only record that anything broke. Logged with `logger.exception`, or a
    database that has stopped answering looks to the operator like a page
    saying "could not be read" for no reason anyone can find."""
    monkeypatch.setattr(page, "VersionService",
                        _Stub(raises=RuntimeError("database gone")))
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.versions"):
        globals()[call](session=object())
    records = [r for r in caplog.records if r.name == "ion.web.ui.versions"]
    assert records, "the failure was swallowed"
    assert all(r.exc_info for r in records), "logged without a traceback"


@pytest.mark.parametrize("call,exc", [
    ("_list_body", TemplateNotFoundError(23)),
    ("_detail_body", VersionNotFoundError(23, 3)),
    ("_diff_body", VersionNotFoundError(23, 3)),
])
def test_a_not_found_read_is_not_logged_as_a_failure(monkeypatch, caplog,
                                                     call, exc):
    """A mistyped id is not an outage. Logging it at error level is how a log
    stops being worth reading."""
    monkeypatch.setattr(page, "VersionService", _Stub(raises=exc))
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.versions"):
        globals()[call](session=object())
    assert not [r for r in caplog.records if r.name == "ion.web.ui.versions"]


# ---------------------------------------------------------------------------
# Registration and permission
# ---------------------------------------------------------------------------


# Each fragment path against the /api path it mirrors.
MIRRORED = {
    "/ui/templates/{template_id}/versions":
        "/templates/{template_id}/versions",
    "/ui/templates/{template_id}/versions/{version_number}":
        "/templates/{template_id}/versions/{version_number}",
    "/ui/templates/{template_id}/versions/diff/{from_version}/{to_version}":
        "/templates/{template_id}/diff/{from_version}/{to_version}",
}


def _route(path: str):
    import ion.web.ui as ui

    for r in ui.router.routes:
        if r.path == path:
            return r
    raise AssertionError(f"{path} is not mounted")


def _api_route(path: str):
    from ion.web.api import router as api_router

    for r in api_router.routes:
        if r.path == path and "GET" in r.methods:
            return r
    raise AssertionError(f"GET {path} is not an API route")


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
    `permission_name`, `require_any_permission` keeps a list in
    `permission_names`, and a fragment that reached for the second where its
    endpoint uses the first would be a softer way in while reading as a
    gate.
    """
    found = set()
    for fn in _dependency_calls(route):
        base = getattr(fn, "__qualname__", "").split(".")[0]
        if base not in ("require_permission", "require_any_permission"):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        one = cells.get("permission_name")
        many = cells.get("permission_names")
        if isinstance(one, str):
            found.add(one)
        if isinstance(many, (list, tuple, set)):
            found.update(many)
    return found


@pytest.mark.parametrize("ui_path", sorted(MIRRORED))
def test_the_module_mounts_every_fragment_route(ui_path):
    assert _route(ui_path) is not None


@pytest.mark.parametrize("ui_path,api_path", sorted(MIRRORED.items()))
def test_each_fragment_permission_matches_the_endpoint_it_mirrors(ui_path,
                                                                 api_path):
    """A fragment must never be a softer way in than the API it mirrors, nor
    a harder one. Read off the /api route rather than restated, so
    tightening that endpoint fails here instead of quietly leaving the
    fragment behind.

    There is nothing else to match. The template id is an object reference,
    but a Template carries no owner, no tenant and no collection ACL, and the
    service functions check only that the row exists, so `template:read` plus
    that existence check is the whole of the API's answer and has to be the
    whole of the fragment's.
    """
    api_perms = _required_permissions(_api_route(api_path))
    assert api_perms == {"template:read"}, api_perms
    assert _required_permissions(_route(ui_path)) == api_perms


@pytest.mark.parametrize("ui_path", sorted(MIRRORED))
def test_no_fragment_uses_a_redirecting_page_dependency(ui_path):
    """require_page_permission answers an unauthorised request with a
    redirect to the login form, which htmx would swap into the page as a
    password box in the middle of the version list."""
    for call in _dependency_calls(_route(ui_path)):
        name = getattr(call, "__qualname__", "")
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name


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

    The comments name what was deleted, which is the whole point of them and
    would make the assertions below pass or fail on prose."""
    return re.sub(r"(?m)^\s*//.*$", "", page_scripts())


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does. Scoped to the inline script bodies because hx-swap="innerHTML" is
    an attribute telling htmx where to put server-rendered markup, which is
    the opposite of the thing being removed."""
    js = page_scripts()
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_list_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/templates/{{ template_id }}/versions"' in src
    assert 'hx-trigger="load' in src


def test_the_page_holds_the_modal_host_the_fragments_target():
    src = PAGE.read_text(encoding="utf-8")
    assert 'id="version-modal-host"' in src
    assert "modal-box" not in src, "the modal has one definition, in Jinja"


def test_the_page_no_longer_names_the_row_markup_or_its_helpers():
    js = page_code()
    assert "version-item" not in js, "the row has one definition, in Jinja"
    assert "checkpoint-badge" not in js
    assert "escapeHtml" not in js, "Jinja autoescapes"
    assert "formatDate" not in js, "the ts macro and local-time.js own this"
    assert "currentVersionNum" not in js, "Rollback reads its own data-args"


def test_the_page_binds_the_handler_the_fragment_names():
    """event-delegation.js resolves a data-click-action through window[], and
    its ACTION_NAME_RE and denylist both let this name through. A fragment
    naming a handler the page never exposes renders a Rollback button that
    does nothing when clicked and logs nothing either."""
    js = page_code()
    assert "window.rollbackToVersion" in js
    assert "data-click-action=\"rollbackToVersion\"" in (
        TEMPLATE_DIR / "_fragments/versions_detail.html"
    ).read_text(encoding="utf-8")


def test_the_page_keeps_the_controls_outside_the_swap_target():
    """A control inside the swap target is removed by any render that does
    not include it, so a failed read would take away the button that retries
    it. Measured by position rather than by parsing: all three controls are
    in the header section, which closes before the swap target opens.
    """
    src = PAGE.read_text(encoding="utf-8")
    target = src.index('<div id="versions-list"')
    for control in ('id="versions-refresh"', 'id="checkpoint-btn"',
                    "Back to Template"):
        assert control in src, control
        assert src.index(control) < target, control
    assert "click from:#versions-refresh" in src


@pytest.mark.parametrize("name", [
    "versions.html",
    "_fragments/versions_list.html",
    "_fragments/versions_detail.html",
    "_fragments/versions_meta.html",
])
def test_no_htmx_feature_that_compiles_a_string(name):
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing: the markup
    reads right, the fragment the server returns is right, and the control
    is dead. That rules out an hx-trigger event filter such as
    `keyup[key=='Enter']`, the `js:` form of hx-vals and hx-headers, and
    hx-on. One converted page shipped a dead Enter key this way.
    """
    src = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    assert "hx-on" not in src
    assert "hx-vals" not in src
    assert "hx-headers" not in src
    assert not re.search(r'hx-trigger="[^"]*\[', src)


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed swap
    means. A per-page listener is one copy per page of the decision about an
    expired session."""
    js = page_code()
    assert "htmx:responseError" not in js
    assert "htmx:afterRequest" not in js
    assert "htmx:sendError" not in js
