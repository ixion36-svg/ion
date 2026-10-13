"""The Job Scheduler cards, history, handler form and cron preview.

scheduler.html built five pieces of markup with innerHTML: the job cards,
one job's execution history, the handler ``<option>`` list, the typed
settings inputs, and the cron preview line. ``schEsc()`` escaped them.
Each test below is one of those, and is a case the JavaScript either got
right and must keep or got wrong and must stop doing.

The page is not part of the detection-engineering module. Every JSON read
it mirrors is ``require_permission("system:settings")`` and nothing else,
and the scheduler router is mounted with no licence gate. Copying
``require_de_module`` off a sibling conversion would 404 this fragment on
a deployment that is not licensed for that module, while ``/scheduler``
and ``/api/scheduler`` kept answering.
"""
from __future__ import annotations

import enum
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.models.scheduler import JobExecution
from ion.services.scheduler_service import create_job
from ion.web.ui.scheduler import PERMISSION, _utc_clock, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/scheduler.html"
FRAGMENT = ROOT / "src/ion/web/templates/_fragments/scheduler.html"
SERVER = ROOT / "src/ion/web/server.py"

# The same expression tools/ui_redesign_status.py and the tranche verifier
# measure with. hx-swap="innerHTML" and swap: 'innerHTML' do not match:
# those name the slot the server's markup lands in, which is the opposite
# of a string the browser assembles.
WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")

# What the page's JavaScript fetches, paired with the JSON route that
# already serves it. /params has no JSON route of its own: it is the
# catalogue half of GET /handlers, rendered as inputs instead of options.
_PAIRS = (
    ("/scheduler", "/api/scheduler/jobs"),
    ("/scheduler/handlers", "/api/scheduler/handlers"),
    ("/scheduler/params", "/api/scheduler/handlers"),
    ("/scheduler/preview", "/api/scheduler/preview-schedule"),
    (
        "/scheduler/jobs/{job_id}/executions",
        "/api/scheduler/jobs/{job_id}/executions",
    ),
)


class _User:
    id = 1
    username = "scheduler-tester"

    def has_permission(self, _name):
        return True


class _LastStatus(enum.Enum):
    """A plain enum, not a str mixin. ``str(member)`` on 3.12 is the repr."""

    ERROR = "error"


class _ExecStatus(enum.Enum):
    ERROR = "error"


def _calls(route) -> list:
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _permission_of(route) -> str | None:
    for fn in _calls(route):
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(
                fn.__code__.co_freevars,
                (c.cell_contents for c in (fn.__closure__ or ())),
            ))
            return cells.get("permission_name")
    return None


def _fragment(path: str):
    for route in router.routes:
        if getattr(route, "path", None) == path:
            return route
    raise AssertionError(f"fragment route {path} not found")


def _json(path: str):
    from ion.web.scheduler_api import router as api

    for route in api.routes:
        if getattr(route, "path", None) == path and "GET" in route.methods:
            return route
    raise AssertionError(f"GET {path} not found on the scheduler API")


def _visible(src: str) -> str:
    """Drop comments, so a note that quotes a rule cannot satisfy it."""
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    return src


def _opening_tag(src: str, element_id: str) -> str:
    match = re.search(
        rf"<[a-zA-Z][^>]*\bid=\"{re.escape(element_id)}\"[^>]*>",
        _visible(src),
    )
    assert match, f"no element with id {element_id}"
    return match.group(0)


def _inline_js(src: str) -> str:
    return "\n".join(
        m.group(1)
        for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S
        )
    )


def _strip_js_comments(js: str) -> str:
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", js)


@pytest.fixture
def app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: session
    yield application
    application.dependency_overrides.clear()


def get(app, path: str, **params):
    with TestClient(app) as client:
        return client.get(path, params=params)


def _job_row(**over) -> dict:
    base = {
        "id": 4,
        "name": "Nightly sync",
        "cron_expr": "0 3 * * *",
        "handler_key": "noop",
        "description": "",
        "params_json": "",
        "enabled": True,
        "last_status": None,
        "next_run_at": None,
        "last_run_at": None,
    }
    base.update(over)
    return base


def _serve_jobs(monkeypatch, *rows: dict) -> None:
    monkeypatch.setattr(
        "ion.services.scheduler_service.list_jobs",
        lambda _session: list(rows),
    )


def _execution_row(**over) -> dict:
    base = {
        "id": 1,
        "job_id": 4,
        "started_at": "2026-10-12T08:00:00+00:00",
        "completed_at": None,
        "status": "success",
        "error_text": None,
        "duration_ms": None,
    }
    base.update(over)
    return base


def _serve_history(monkeypatch, job_name: str, *rows: dict) -> None:
    monkeypatch.setattr(
        "ion.services.scheduler_service.get_job",
        lambda _session, _job_id: {"id": 4, "name": job_name},
    )
    monkeypatch.setattr(
        "ion.services.scheduler_service.list_executions",
        lambda _session, _job_id, limit=50: list(rows),
    )


def _catalogue(*params: dict):
    return [{
        "key": "probe",
        "label": "Probe",
        "description": "A probe handler",
        "parameters": list(params),
    }]


def _serve_catalogue(monkeypatch, parameters: list[dict]) -> None:
    monkeypatch.setattr(
        "ion.services.scheduler_service.describe_handlers",
        lambda: _catalogue(*parameters),
    )


def _integer(name: str = "n", **over) -> dict:
    base = {
        "name": name,
        "label": "Count",
        "type": "integer",
        "default": 7,
        "minimum": 1,
        "maximum": 10,
        "help": "",
    }
    base.update(over)
    return base


def _flag(**over) -> dict:
    base = {
        "name": "flag",
        "label": "Flag",
        "type": "boolean",
        "default": True,
        "help": "",
    }
    base.update(over)
    return base


def _data_job(html: str) -> dict:
    match = re.search(r"data-job='([^']*)'", html)
    assert match, "edit button carries no data-job payload"
    return json.loads(match.group(1))


def _flat(html: str) -> str:
    """The sentence a browser shows. A phrase wrapped across lines in the
    template is still one sentence, and a test for the sentence that
    demands it on one source line fails the honest copy."""
    return re.sub(r"\s+", " ", html)


def _logged_failure(caplog) -> None:
    assert any(
        record.exc_info and record.exc_info[0] is RuntimeError
        for record in caplog.records
    ), "a failed read must be logged with its traceback, not only a sentence"


# ---------------------------------------------------------------------------
# Gates. This page is not detection engineering.
# ---------------------------------------------------------------------------


def test_every_fragment_permission_matches_its_json_read():
    """Read out of the JSON route's closure, not restated here.

    A fragment that is a softer way in than the API it mirrors does not
    look different in the template. ``/params`` has no JSON route of its
    own and takes the catalogue read's permission, which is the same one.
    """
    assert PERMISSION == "system:settings"
    fragment_paths = {route.path for route in router.routes}
    assert fragment_paths == {path for path, _json_path in _PAIRS}
    for fragment_path, json_path in _PAIRS:
        assert _permission_of(_fragment(fragment_path)) == PERMISSION
        assert _permission_of(_json(json_path)) == PERMISSION


def test_no_fragment_route_carries_the_detection_engineering_gate():
    """``require_de_module`` first would be right for a ``de_*`` page and
    wrong for this one. The scheduler API does not have it, so a fragment
    that does is the stricter of the two: an unlicensed deployment would
    be told this feature does not exist, while ``/api/scheduler`` still
    returned the jobs.
    """
    for route in router.routes:
        names = [getattr(fn, "__qualname__", "") for fn in _calls(route)]
        assert not any("require_de_module" in name for name in names), route.path
        assert not any("require_page_permission" in name for name in names), route.path
        assert not any("require_page_auth" in name for name in names), route.path


def test_the_scheduler_router_is_mounted_without_that_gate():
    """The claim the test above is matching. If the API ever grows the
    module gate, the fragment has to grow it too, in the same order, and
    this fails until somebody does that on purpose."""
    src = SERVER.read_text(encoding="utf-8")
    mount = re.search(r"include_router\(\s*scheduler_router[^)]*\)", src)
    assert mount, "scheduler_router is no longer included from server.py"
    assert "require_de_module" not in mount.group(0)


def test_the_module_mounts_its_routes_under_ui():
    from ion.web import ui as ui_pkg

    mounted = {route.path for route in ui_pkg.router.routes}
    for route in router.routes:
        assert "/ui" + route.path in mounted, route.path


# ---------------------------------------------------------------------------
# Job cards
# ---------------------------------------------------------------------------


def test_a_real_job_is_rendered_from_list_jobs_and_escaped(app, session):
    """The cards come from ``scheduler_service.list_jobs``, the same call
    GET /api/scheduler/jobs makes. The name is hostile on purpose: ``schEsc``
    is gone, and the edit payload is JSON rather than a hand-built argument
    list, which is what broke when a name contained a quote.
    """
    name = "O'Brien <script>alert(1)</script>"
    created = create_job(
        session,
        name=name,
        cron_expr="*/15 * * * *",
        handler_key="noop",
        description="<img src=x onerror=1>",
        enabled=True,
    )
    resp = get(app, "/ui/scheduler")
    assert resp.status_code == 200
    html = resp.text
    assert name not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "&lt;img" in html
    assert ">pending<" in html
    assert "sch-card ok" in html
    assert "<time" in html
    payload = _data_job(html)
    assert payload["name"] == name
    assert payload["id"] == created["id"]
    assert payload["enabled"] is True
    history = re.search(r"<button\b[^>]*>History</button>", html)
    assert history, "a saved job offers no history"
    tag = history.group(0)
    assert f'/ui/scheduler/jobs/{created["id"]}/executions' in tag
    assert "?" not in tag
    assert 'hx-target="#sch-exec-body"' in tag
    assert 'hx-trigger="click"' in tag
    assert "data-args" not in tag
    args = re.search(r"data-args='([^']*)'", html)
    assert args and json.loads(args.group(1)) == [created["id"]]


def test_no_jobs_says_there_are_none_rather_than_that_the_read_failed(app):
    resp = get(app, "/ui/scheduler")
    assert resp.status_code == 200
    assert "No scheduled jobs yet" in resp.text
    assert "could not be read" not in resp.text


def test_a_failed_job_read_says_so_and_is_not_an_empty_list(app, monkeypatch, caplog):
    """"Nothing scheduled" and "we could not look" are opposite claims.
    htmx does not swap a 500, so this has to be a 200 that says the read
    failed, and the traceback has to be logged or the next person only has
    the sentence.
    """
    def boom(_session):
        raise RuntimeError("scheduler store unreachable")

    monkeypatch.setattr("ion.services.scheduler_service.list_jobs", boom)
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "not an empty list" in resp.text
    assert "No scheduled jobs yet" not in resp.text
    _logged_failure(caplog)


@pytest.mark.parametrize("status,card,badge,label", [
    ("error", "sch-card err", "badge-error", "error"),
    ("running", "sch-card run", "badge-warning", "running"),
    ("success", "sch-card ok", "badge-success", "success"),
    (None, "sch-card ok", "badge-success", "pending"),
    ("   ", "sch-card ok", "badge-success", "pending"),
])
def test_an_enabled_jobs_status_keeps_its_meaning(
    app, monkeypatch, status, card, badge, label
):
    """A blank status is not a status, and a job that has never run is
    pending. Calling that unknown would say we could not tell whether it
    is enabled, which we could."""
    _serve_jobs(monkeypatch, _job_row(last_status=status))
    html = get(app, "/ui/scheduler").text
    assert card in html
    assert badge in html
    assert f">{label}<" in html


def test_the_status_pill_reads_the_enum_value_not_its_repr(app, monkeypatch):
    """``last_status`` is a string column today. ``plain`` is applied
    anyway, because a template does not serialise an enum the way FastAPI
    did for the script: ``str(member)`` on 3.12 is ``_LastStatus.ERROR``,
    which matches no colour and is what the pill would show.
    """
    _serve_jobs(monkeypatch, _job_row(last_status=_LastStatus.ERROR))
    html = get(app, "/ui/scheduler").text
    assert "_LastStatus" not in html
    assert ">error<" in html
    assert "badge-error" in html
    assert "badge-success" not in html


def test_a_disabled_job_stays_disabled_when_its_last_run_errored(app, monkeypatch):
    """The stripe says whether the job will fire, not how the previous
    fire went. Colouring it as an error says a disabled job is failing."""
    _serve_jobs(monkeypatch, _job_row(enabled=False, last_status="error"))
    html = get(app, "/ui/scheduler").text
    assert "sch-card off" in html
    assert ">disabled<" in html
    assert "badge-ghost" in html
    assert "badge-error" not in html
    assert _data_job(html)["enabled"] is False


@pytest.mark.parametrize("enabled", [None, "yes"])
def test_an_enabled_flag_that_is_not_a_boolean_is_unknown(app, monkeypatch, enabled):
    """Three states stay three, and the guard is ``is True`` / ``is False``.

    Truthiness reads the string ``"yes"`` as enabled and reads None as
    disabled. Dropping the ``is False`` branch reads a real False as
    unknown, which is the test next to this one. Either one shows the
    opposite of whether the job will fire. None alone cannot catch the
    string, and the string alone cannot catch a missing false branch.
    """
    _serve_jobs(monkeypatch, _job_row(enabled=enabled, last_status="error"))
    html = get(app, "/ui/scheduler").text
    assert ">unknown<" in html
    assert "sch-card off" not in html
    assert "sch-card ok" not in html
    assert "sch-card err" not in html
    assert ">disabled<" not in html
    assert ">error<" not in html
    assert _data_job(html)["enabled"] is None


def test_a_job_with_no_id_offers_no_actions(app, monkeypatch):
    """An action needs an id to name the job. Rendering Delete for a row
    that has none posts it at the collection and deletes nothing useful."""
    _serve_jobs(monkeypatch, _job_row(id=None, name="Unsaved"))
    html = get(app, "/ui/scheduler").text
    assert "Unsaved" in html
    assert "Delete" not in html
    assert "History" not in html
    assert "Run now" not in html
    assert "data-job" not in html


def test_a_job_id_of_zero_is_a_real_id(app, monkeypatch):
    """``if job_id`` treats 0 as absent. Zero is a value, and the buttons
    have to carry it as JSON ``[0]``, not drop it."""
    _serve_jobs(monkeypatch, _job_row(id=0))
    html = get(app, "/ui/scheduler").text
    assert "Delete" in html
    assert "/ui/scheduler/jobs/0/executions" in html
    args = [json.loads(raw) for raw in re.findall(r"data-args='([^']*)'", html)]
    assert args
    assert all(item == [0] for item in args)
    assert _data_job(html)["id"] == 0


# ---------------------------------------------------------------------------
# Execution history
# ---------------------------------------------------------------------------


def test_a_duration_of_zero_is_printed(app, session):
    """``is not none``, not truthiness. A run that finished in 0ms was
    measured. Dropping it on ``{% if duration_ms %}`` or ``or None`` reads
    the same as a run whose duration was never written.
    """
    created = create_job(
        session, name="instant", cron_expr="0 3 * * *",
        handler_key="noop", enabled=True,
    )
    session.add(JobExecution(
        job_id=created["id"],
        started_at=datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc),
        status="success",
        duration_ms=0,
    ))
    session.commit()
    html = get(app, f"/ui/scheduler/jobs/{created['id']}/executions").text
    assert "0ms" in html
    assert "<time" in html
    assert 'data-ts-local="' in html


def test_a_missing_duration_is_not_printed_as_zero(app, monkeypatch):
    _serve_history(monkeypatch, "Nightly", _execution_row(duration_ms=None))
    html = get(app, "/ui/scheduler/jobs/4/executions").text
    assert "0ms" not in html
    assert ">success<" in html


def test_an_execution_status_reads_the_enum_value(app, monkeypatch):
    """Same repr trap as the job pill, on the other string column. Without
    ``plain`` the word becomes ``_ExecStatus.ERROR`` and the stripe falls
    through to the warning colour, because only the value ``error`` is red.
    """
    _serve_history(
        monkeypatch, "Nightly", _execution_row(status=_ExecStatus.ERROR)
    )
    html = get(app, "/ui/scheduler/jobs/4/executions").text
    assert "_ExecStatus" not in html
    assert ">error<" in html
    assert "badge-error" in html
    assert "badge-warning" not in html


@pytest.mark.parametrize("status,card,badge,label", [
    ("success", "sch-exec-row ok", "badge-success", "success"),
    ("error", "sch-exec-row err", "badge-error", "error"),
    ("queued", "sch-exec-row run", "badge-warning", "queued"),
])
def test_a_recorded_execution_status_keeps_its_word(
    app, monkeypatch, status, card, badge, label
):
    """``queued`` is not a synonym of running. The word that was stored is
    the word the row shows; only success and error have their own stripe."""
    _serve_history(monkeypatch, "Nightly", _execution_row(status=status))
    html = get(app, "/ui/scheduler/jobs/4/executions").text
    assert card in html
    assert badge in html
    assert f">{label}<" in html


def test_a_missing_execution_status_is_unknown_not_running(app, monkeypatch):
    """The column's own default is ``running``. A row whose status was not
    read is not a job that is in progress, and painting it warning says it
    is."""
    _serve_history(monkeypatch, "Nightly", _execution_row(status=None))
    html = get(app, "/ui/scheduler/jobs/4/executions").text
    assert ">unknown<" in html
    assert "badge-ghost" in html
    assert ">running<" not in html
    assert "badge-warning" not in html
    assert "sch-exec-row run" not in html


def test_execution_error_text_is_escaped(app, monkeypatch):
    _serve_history(
        monkeypatch, "Nightly",
        _execution_row(status="error", error_text="<script>alert(1)</script>"),
    )
    html = get(app, "/ui/scheduler/jobs/4/executions").text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_no_executions_says_the_job_has_not_run(app, session):
    created = create_job(
        session, name="idle", cron_expr="0 3 * * *",
        handler_key="noop", enabled=True,
    )
    html = get(app, f"/ui/scheduler/jobs/{created['id']}/executions").text
    assert "No executions yet" in html
    assert "idle" in html
    assert "could not be read" not in html


def test_a_missing_job_is_a_404_not_an_empty_history(app, session):
    """Empty history and a deleted job are different claims. The row is
    inserted first so "the name is absent" is not true of every 404 body.
    """
    create_job(
        session, name="still-here", cron_expr="0 3 * * *",
        handler_key="noop", enabled=True,
    )
    resp = get(app, "/ui/scheduler/jobs/99999/executions")
    assert resp.status_code == 404
    assert "No executions yet" not in resp.text
    assert "still-here" not in resp.text
    assert "could not be read" not in resp.text


def test_a_non_numeric_job_id_is_a_bad_request_not_a_failed_read(app):
    resp = get(app, "/ui/scheduler/jobs/nope/executions")
    assert resp.status_code == 422
    assert "could not be read" not in resp.text
    assert "No executions yet" not in resp.text


def test_a_failed_job_lookup_names_no_job_it_did_not_read(
    app, monkeypatch, caplog
):
    def boom(_session, _job_id):
        raise RuntimeError("job row unreadable")

    monkeypatch.setattr("ion.services.scheduler_service.get_job", boom)
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler/jobs/4/executions")
    assert resp.status_code == 200
    text = _flat(resp.text)
    assert "could not be read" in text
    assert "not an empty history" in text
    assert "No executions yet" not in text
    _logged_failure(caplog)


def test_a_failed_history_read_still_names_the_job(app, monkeypatch, caplog):
    """The job loaded and the runs did not. The failure can say which job
    it was; it still must not say the job has never run."""
    monkeypatch.setattr(
        "ion.services.scheduler_service.get_job",
        lambda _session, _job_id: {"id": 4, "name": "Nightly <sync>"},
    )

    def boom(_session, _job_id, limit=50):
        raise RuntimeError("history unreadable")

    monkeypatch.setattr(
        "ion.services.scheduler_service.list_executions", boom
    )
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler/jobs/4/executions")
    assert resp.status_code == 200
    html = resp.text
    text = _flat(html)
    assert "could not be read" in text
    assert "Nightly &lt;sync&gt;" in text
    assert "Nightly <sync>" not in html
    assert "No executions yet" not in text
    _logged_failure(caplog)


def test_history_passes_the_pages_limit_through_to_the_service(
    app, session, monkeypatch
):
    """The spy's own default is None, so a route that forgets the argument
    and leans on ``list_executions``'s default of 50 still fails. The page
    asked for 50 and the JSON endpoint defaults to 50; both have to be the
    call this fragment makes.
    """
    created = create_job(
        session, name="limited", cron_expr="0 3 * * *",
        handler_key="noop", enabled=True,
    )
    seen: dict = {}

    def spy(_session, job_id, limit=None):
        seen["job_id"] = job_id
        seen["limit"] = limit
        return []

    monkeypatch.setattr(
        "ion.services.scheduler_service.list_executions", spy
    )
    resp = get(app, f"/ui/scheduler/jobs/{created['id']}/executions")
    assert resp.status_code == 200
    assert seen["job_id"] == created["id"]
    assert seen["limit"] == 50


# ---------------------------------------------------------------------------
# Handler options and typed settings
# ---------------------------------------------------------------------------


def test_handler_options_come_from_describe_handlers(app, monkeypatch):
    """The options and the typed form both call ``describe_handlers``,
    which is the catalogue half of GET /api/scheduler/handlers. A probe
    key appended there shows up only if that function is the one called.
    """
    from ion.services.scheduler_service import describe_handlers

    def wrapped():
        return describe_handlers() + _catalogue()

    monkeypatch.setattr(
        "ion.services.scheduler_service.describe_handlers", wrapped
    )
    html = get(app, "/ui/scheduler/handlers").text
    assert 'value="probe"' in html
    assert "Probe" in html
    assert 'value="noop"' in html


def test_a_handler_option_is_escaped(app, monkeypatch):
    monkeypatch.setattr(
        "ion.services.scheduler_service.describe_handlers",
        lambda: [{
            "key": "<script>",
            "label": "<script>x</script>",
            "description": '"><img',
            "parameters": [],
        }],
    )
    html = get(app, "/ui/scheduler/handlers").text
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html


def test_no_handlers_says_none_are_registered(app, monkeypatch):
    monkeypatch.setattr(
        "ion.services.scheduler_service.describe_handlers", lambda: []
    )
    html = get(app, "/ui/scheduler/handlers").text
    assert "No handlers are registered" in html
    assert "could not be read" not in html


def test_a_failed_catalogue_read_says_so(app, monkeypatch, caplog):
    def boom():
        raise RuntimeError("catalogue unreachable")

    monkeypatch.setattr(
        "ion.services.scheduler_service.describe_handlers", boom
    )
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler/handlers")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "No handlers are registered" not in resp.text
    _logged_failure(caplog)


def test_a_real_handler_renders_its_declared_bounds_and_default(app):
    """executive_report's period defaults to 7 and is bounded 1..365. Those
    numbers are the catalogue's, not a copy of them in the template."""
    html = get(
        app, "/ui/scheduler/params", handler_key="executive_report"
    ).text
    assert 'data-sch-params="typed"' in html
    assert 'value="7"' in html
    assert 'min="1"' in html
    assert 'max="365"' in html
    assert "could not be parsed" not in html


def test_a_bound_of_zero_and_a_default_of_zero_are_rendered(app, monkeypatch):
    """No registered parameter has a minimum of 0, so the real catalogue
    cannot catch this. ``{% if minimum %}`` and ``or None`` both drop a
    bound of zero, and the input then has no floor."""
    _serve_catalogue(monkeypatch, [
        _integer(default=0, minimum=0, maximum=0),
    ])
    html = get(app, "/ui/scheduler/params", handler_key="probe").text
    assert 'min="0"' in html
    assert 'max="0"' in html
    assert 'value="0"' in html


def test_a_missing_bound_is_not_rendered_as_zero(app, monkeypatch):
    _serve_catalogue(monkeypatch, [
        _integer(default=4, minimum=None, maximum=None),
    ])
    html = get(app, "/ui/scheduler/params", handler_key="probe").text
    assert "min=" not in html
    assert "max=" not in html
    assert 'value="4"' in html


def test_a_stored_zero_beats_the_default(app, monkeypatch):
    """``existing.get(name) or default`` turns a recorded 0 into 7. The
    key being present is the test, and 0 is a value that was saved."""
    _serve_catalogue(monkeypatch, [_integer(default=7, minimum=1)])
    html = get(
        app, "/ui/scheduler/params",
        handler_key="probe", params='{"n": 0}',
    ).text
    assert 'value="0"' in html
    assert 'value="7"' not in html


def test_a_stored_null_is_not_replaced_by_the_default(app, monkeypatch):
    """None stored under the key means saved as empty, not never saved."""
    _serve_catalogue(monkeypatch, [_integer(default=7)])
    html = get(
        app, "/ui/scheduler/params",
        handler_key="probe", params='{"n": null}',
    ).text
    assert 'value=""' in html
    assert 'value="7"' not in html


@pytest.mark.parametrize("stored,checked", [
    (True, True),
    (False, False),
    ("false", False),
    ("yes", False),
    (None, False),
])
def test_a_checkbox_is_ticked_only_for_a_real_true(
    app, monkeypatch, stored, checked
):
    """The default here is True, so every other arrangement has to win.

    ``{% if value %}`` ticks the box for the strings ``"false"`` and
    ``"yes"``. ``{% if value is not none %}`` ticks it for a stored False.
    ``stored or default`` ticks it for a stored False and for a stored
    None, because the default is True. A test that only arranges None
    passes the first two defects.
    """
    _serve_catalogue(monkeypatch, [_flag(default=True)])
    html = get(
        app, "/ui/scheduler/params",
        handler_key="probe", params=json.dumps({"flag": stored}),
    ).text
    assert 'data-sch-type="boolean"' in html
    assert ("checked" in html) is checked


def test_unreadable_stored_settings_warn_and_show_the_defaults(app):
    """A present value that is not a JSON object is not "no settings".
    Showing the defaults without saying so lets Save overwrite a real
    configuration with them."""
    html = get(
        app, "/ui/scheduler/params",
        handler_key="executive_report", params="{",
    ).text
    text = _flat(html)
    assert 'data-sch-params="typed"' in html
    assert "could not be parsed" in text
    assert "replaces the stored value" in text
    assert 'value="7"' in html
    assert "could not be read" not in text


def test_a_json_array_is_not_a_settings_object(app):
    html = get(
        app, "/ui/scheduler/params",
        handler_key="executive_report", params="[]",
    ).text
    assert "could not be parsed" in html
    assert 'value="7"' in html
    assert 'data-sch-params="raw"' not in html


def test_an_unknown_handler_is_raw_json_not_a_failed_read(app):
    """A job can name a handler this process has not loaded. That is not
    a catalogue outage, and the JSON field is the only view of what was
    stored."""
    html = get(
        app, "/ui/scheduler/params", handler_key="not-a-handler"
    ).text
    assert 'data-sch-params="raw"' in html
    assert "could not be read" not in html
    assert "No job type is selected" not in html


def test_no_selected_handler_is_not_the_raw_field_and_not_a_failure(app):
    html = get(app, "/ui/scheduler/params", handler_key="  ").text
    assert "No job type is selected" in html
    assert 'data-sch-params="failed"' in html
    assert 'data-sch-params="raw"' not in html
    assert "could not be read" not in html


def test_a_failed_parameter_read_is_not_an_empty_form(app, monkeypatch, caplog):
    def boom():
        raise RuntimeError("catalogue unreachable")

    monkeypatch.setattr(
        "ion.services.scheduler_service.describe_handlers", boom
    )
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler/params", handler_key="noop")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert 'data-sch-params="failed"' in resp.text
    assert 'data-sch-params="raw"' not in resp.text
    assert "No handlers" not in resp.text
    _logged_failure(caplog)


def test_a_handler_with_no_parameters_selects_raw_json(app):
    """noop declares an empty parameter list. That is the raw field, not
    an empty typed form and not a failure."""
    html = get(app, "/ui/scheduler/params", handler_key="noop").text
    assert 'data-sch-params="raw"' in html
    assert "could not be read" not in html
    assert "could not be parsed" not in html


# ---------------------------------------------------------------------------
# Cron preview. UTC wall clock, not the viewer's, and not ts().
# ---------------------------------------------------------------------------


def test_an_offset_instant_is_printed_as_a_utc_clock(app, monkeypatch):
    """08:00+01:00 is 07:00 UTC. Formatting the offset's own digits, or
    sending the instant through ``ts``, both show the wrong clock next to
    a label that still says UTC: ``ts`` sets ``data-ts-local``, and
    local-time.js then rewrites the digits onto the viewer's zone.
    """
    monkeypatch.setattr(
        "ion.services.scheduler_service.preview_schedule",
        lambda _expr, count=5: {
            "valid": True,
            "description": "Quarter-hourly",
            "timezone": "UTC",
            "next_runs": ["2026-10-12T08:00:00+01:00"],
            "error": None,
        },
    )
    html = get(
        app, "/ui/scheduler/preview",
        cron_expr="*/15 * * * *", count=3,
    ).text
    assert "2026-10-12 07:00" in html
    assert "08:00" not in html
    assert "data-ts-local" not in html
    assert "Quarter-hourly" in html
    assert "(UTC)" in html


def test_a_naive_preview_instant_is_not_labelled_as_utc(app, monkeypatch):
    """No zone was stated. Inventing UTC is the same move as printing 0
    for a figure nobody measured, and ``ts`` on a naive value still prints
    the digits."""
    monkeypatch.setattr(
        "ion.services.scheduler_service.preview_schedule",
        lambda _expr, count=5: {
            "valid": True,
            "description": "No zone",
            "timezone": "UTC",
            "next_runs": ["2026-10-12T08:00:00"],
            "error": None,
        },
    )
    html = get(
        app, "/ui/scheduler/preview", cron_expr="0 8 * * *"
    ).text
    assert "No zone" in html
    assert "08:00" not in html
    assert "data-ts-local" not in html


def test_utc_clock_converts_and_refuses_a_naive_value():
    assert _utc_clock("2026-10-12T08:00:00+01:00") == "2026-10-12 07:00"
    assert _utc_clock("2026-10-12T08:00:00Z") == "2026-10-12 08:00"
    assert _utc_clock("2026-10-12T08:00:00") is None
    assert _utc_clock(None) is None
    assert _utc_clock("not a time") is None


def test_a_valid_expression_uses_the_services_preview(app):
    html = get(
        app, "/ui/scheduler/preview",
        cron_expr="*/15 * * * *", count=3,
    ).text
    assert "Every 15 minutes" in html
    assert "(UTC)" in html
    assert "data-ts-local" not in html
    assert "text-error" not in html


@pytest.mark.parametrize("verdict", ["yes", None, 1])
def test_a_valid_flag_that_is_not_a_boolean_says_the_check_did_not_run(
    app, monkeypatch, caplog, verdict
):
    """``{% if preview.valid %}`` is truthiness, and silence is not a verdict.

    Truthiness shows a description for a preview the service did not call
    valid, which is the string case. Rendering nothing instead is the other
    defect and the one that survived longer: an empty preview line beside a
    filled-in expression is what a blank field looks like, so "the service
    answered something we cannot read" arrives as "no objection". ``1`` is
    here because ``is true`` and ``== True`` disagree about it.
    """
    monkeypatch.setattr(
        "ion.services.scheduler_service.preview_schedule",
        lambda _expr, count=5: {
            "valid": verdict,
            "description": "MUST-NOT-SHOW",
            "timezone": "UTC",
            "next_runs": ["2026-10-12T08:00:00+00:00"],
            "error": None,
        },
    )
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler/preview", cron_expr="*/15 * * * *")
    assert resp.status_code == 200
    html = resp.text
    assert "MUST-NOT-SHOW" not in html
    assert "2026-10-12" not in html
    assert "data-ts-local" not in html
    assert "could not be read" in html
    assert "not an invalid expression" in html
    assert any(
        "no readable verdict" in record.getMessage()
        for record in caplog.records
    ), "an unreadable payload must reach the log, not only the user"


def test_an_invalid_expression_shows_the_services_error(app):
    """``preview_schedule`` reports an invalid expression as data, not as
    an exception. This must not take the "the check did not run" branch."""
    html = get(app, "/ui/scheduler/preview", cron_expr="nope").text
    assert "text-error" in html
    assert "CroniterBadCronError" in html or "Exactly 5" in html
    assert "could not be read" not in html
    assert "Every 15 minutes" not in html


def test_a_failed_preview_says_the_check_did_not_run(app, monkeypatch, caplog):
    def boom(_expr, count=5):
        raise RuntimeError("croniter missing")

    monkeypatch.setattr(
        "ion.services.scheduler_service.preview_schedule", boom
    )
    with caplog.at_level(logging.ERROR):
        resp = get(app, "/ui/scheduler/preview", cron_expr="*/15 * * * *")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "not an invalid expression" in resp.text
    assert "Every 15 minutes" not in resp.text
    _logged_failure(caplog)


def test_a_blank_expression_renders_nothing(app):
    resp = get(app, "/ui/scheduler/preview", cron_expr="   ")
    assert resp.status_code == 200
    assert resp.text.strip() == ""
    assert "text-error" not in resp.text


def test_a_bad_preview_count_is_a_bad_request_not_a_failed_read(app):
    resp = get(
        app, "/ui/scheduler/preview", cron_expr="*/15 * * * *", count="nope"
    )
    assert resp.status_code == 422
    assert "could not be read" not in resp.text


def test_a_count_of_zero_is_passed_to_the_service_unmodified(app, monkeypatch):
    """The service clamps ``count or 5`` itself. Copying that clamp into
    the route, or dropping a falsy count before the call, is a second
    implementation of the same rule and it will drift. The spy defaults to
    5, which is the service's default, so forgetting the argument fails too.
    """
    seen: dict = {}

    def spy(_expr, count=5):
        seen["count"] = count
        return {
            "valid": True, "description": "ok", "timezone": "UTC",
            "next_runs": [], "error": None,
        }

    monkeypatch.setattr(
        "ion.services.scheduler_service.preview_schedule", spy
    )
    resp = get(
        app, "/ui/scheduler/preview", cron_expr="*/5 * * * *", count=0
    )
    assert resp.status_code == 200
    assert seen["count"] == 0


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """The ``server`` column, measured the way the verifier measures it.

    Both copies: ``ui_redesign_status`` counts the script as it is, and
    the tranche strips comments first. A comment that says
    ``container.innerHTML =`` fails the first, which is why it is not an
    acceptable way to explain the removal.
    """
    js = _inline_js(PAGE.read_text(encoding="utf-8"))
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not WRITES.findall(js)
    assert not WRITES.findall(_strip_js_comments(js))


def test_the_string_building_helpers_are_gone():
    js = _strip_js_comments(_inline_js(PAGE.read_text(encoding="utf-8")))
    for name in (
        "schEsc", "schRender", "schRenderParams", "schFmtTime",
        "schBootstrap", "schCache", "schCatalogue",
    ):
        assert f"function {name}" not in js
        assert f"function {name}(" not in js


def test_the_cards_load_from_the_fragment_and_the_retry_stays_outside():
    """A control inside ``#sch-content`` is removed by any render that
    omits it, including the one that says the read failed."""
    src = _visible(PAGE.read_text(encoding="utf-8"))
    content = _opening_tag(src, "sch-content")
    assert 'hx-get="/ui/scheduler"' in content
    assert 'hx-trigger="load"' in content
    assert "hx-include" not in content
    assert "hx-target" not in content
    refresh = _opening_tag(src, "sch-refresh")
    assert 'hx-get="/ui/scheduler"' in refresh
    assert 'hx-target="#sch-content"' in refresh
    assert src.index('id="sch-refresh"') < src.index('id="sch-content"')
    assert src.index("+ New Job") < src.index('id="sch-content"')


def test_the_form_controls_are_outside_the_regions_they_refill():
    src = _visible(PAGE.read_text(encoding="utf-8"))
    cron = _opening_tag(src, "sch-cron")
    assert 'name="cron_expr"' in cron
    assert 'hx-get="/ui/scheduler/preview?count=3"' in cron
    assert "cron_expr=" not in cron
    assert 'hx-trigger="input changed delay:300ms"' in cron
    assert 'hx-target="#sch-cron-preview"' in cron
    assert "[" not in cron
    assert src.index('id="sch-cron"') < src.index('id="sch-cron-preview"')

    handler = _opening_tag(src, "sch-handler")
    assert 'hx-get="/ui/scheduler/handlers"' in handler
    assert 'hx-trigger="load"' in handler

    # The textarea is the raw control. It has to be a sibling of the slot
    # the typed fragment replaces, not a child of it.
    assert re.search(
        r'<div id="sch-params-typed"[^>]*>\s*</div>', src
    )
    assert src.index('id="sch-params-typed"') < src.index('id="sch-params"')
    assert src.index('data-click-action="schCloseExec"') < src.index(
        'id="sch-exec-body"'
    )


def test_the_page_compiles_no_htmx_expression_and_handles_no_errors_itself():
    page = _visible(PAGE.read_text(encoding="utf-8"))
    fragment = _visible(FRAGMENT.read_text(encoding="utf-8"))
    for src in (page, fragment):
        assert "hx-on" not in src
        assert not re.search(r"hx-(?:vals|headers)=\"\s*js:", src)
        assert not re.search(r'hx-trigger="[^"]*\[[^\]]*\]', src)
    assert "htmx:responseError" not in page
    assert "htmx:sendError" not in page
    assert "<script" not in fragment


def test_click_actions_are_real_function_declarations():
    """``data-click-action`` looks the name up as a window property.
    ``function schSubmit`` is one; ``const schSubmit =`` is not, and the
    click then does nothing.

    ``schSubmit`` has to cancel the native submit itself. The
    validating-submit hook calls ``preventDefault`` only when the action
    returns something falsy, and ``schSubmit`` is ``async``, so what it
    hands back is a Promise and always truthy. Its own
    ``ev.preventDefault()`` is therefore the only thing stopping the form
    from navigating away mid-save, and the trailing ``return false`` is
    decorative. Both are asserted, the first because it is load-bearing.
    """
    page = PAGE.read_text(encoding="utf-8")
    fragment = FRAGMENT.read_text(encoding="utf-8")
    js = _strip_js_comments(_inline_js(page))
    names = set(re.findall(
        r'data-(?:click|change|validating-submit)-action="([^"]+)"',
        page + fragment,
    ))
    assert names, "no actions found, so this proves nothing"
    for name in names:
        assert re.search(rf"\bfunction {name}\s*\(", js), name
        assert not re.search(rf"\b(?:const|let|var) {name}\s*=", js), name

    match = re.search(r"function schSubmit\s*\(", js)
    assert match
    brace = js.find("{", match.end())
    depth = 0
    end = None
    for index in range(brace, len(js)):
        if js[index] == "{":
            depth += 1
        elif js[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    assert re.search(r"\basync function schSubmit\s*\(", js), (
        "schSubmit is no longer async, so the hook's falsy-return contract "
        "applies again and this test should assert that instead"
    )
    body = js[brace + 1:end]
    stripped = [line.strip() for line in body.splitlines() if line.strip()]
    assert stripped[0] == "ev.preventDefault();"
    assert stripped[-1] == "return false;"


# ---------------------------------------------------------------------------
# The four survivors of this conversion's mutation pass.
#
# Two were real and are closed below. Two are equivalent mutants and the
# third test pins the property that makes them equivalent, so nobody writes
# a test that cannot fail and nobody later removes the invariant without
# anything noticing:
#
#   * `{% elif preview and preview.valid is false %}` to `not preview.valid`
#   * `{% elif preview and preview.valid is true %}`  to `{% elif preview %}`
#
# Both are unreachable. scheduler_preview_fragment normalises every payload
# whose verdict is neither True nor False into `preview=None, failed=True`
# before the template is reached, so when `preview` is not None its `valid`
# is exactly True or False, and in that domain each mutated spelling agrees
# with the original on every input. The strictness in the template is
# correct defensive depth; the invariant is enforced in the route, which is
# where the third test asserts it.
# ---------------------------------------------------------------------------


def test_a_completed_time_is_a_time_element_and_an_absent_one_is_not_the_word_none(
    app, monkeypatch
):
    """Closes a survivor. Every other history test leaves completed_at at its
    default of None, so dropping the ts macro from it rendered the literal
    string "None" after the label and no test failed. The start time is
    covered and this is its sibling: both timestamps in a row must go
    through the macro, or one localises to the viewer's clock and the other
    does not, in the same row.
    """
    _serve_history(monkeypatch, "Nightly", _execution_row(
        completed_at="2026-10-12T08:05:00+00:00",
    ))
    html = get(app, "/ui/scheduler/jobs/4/executions").text
    assert re.search(r"completed:\s*<time", html), (
        "the completed time must be a <time> element, like the start time")
    assert len(re.findall(r"<time", html)) >= 2, "started and completed"

    _serve_history(monkeypatch, "Nightly", _execution_row(completed_at=None))
    absent = get(app, "/ui/scheduler/jobs/4/executions").text
    assert "None" not in absent, (
        "a missing timestamp rendered as Python's None, which is not a claim "
        "about anything")
    assert "—" in absent, "the macro's fallback, not an empty space"


def test_an_unknown_parameter_type_is_normalised_before_it_reaches_the_form(
    app, monkeypatch
):
    """Closes a survivor. A declared type outside integer, boolean and
    string is normalised to string, and the mutation that drops the
    normalisation is invisible in behaviour today: the save handler's final
    branch treats anything it does not recognise as a string anyway.

    It is pinned because that silence is the hazard. A handler declaring
    `integer64` would be saved as a string with nothing said, and the one
    place that decides what the three permitted types are is this
    normalisation. The attribute is the observable form of that decision.
    """
    _serve_catalogue(monkeypatch, [_integer(type="integer64")])
    html = get(app, "/ui/scheduler/params", handler_key="probe").text
    assert 'data-sch-type="string"' in html
    assert "integer64" not in html, (
        "an un-normalised type reached the markup the save handler reads")
    assert 'type="text"' in html
    assert 'type="number"' not in html


def test_the_preview_route_never_hands_the_template_an_unreadable_verdict(
    app, monkeypatch, caplog
):
    """Pins the invariant behind the two equivalent mutants above.

    The template guards with `is false` and `is true` rather than
    truthiness. Those are strictly correct and also currently redundant,
    because this route converts any payload without a boolean verdict into
    the failed render and passes `preview=None`. Asserted on the context the
    route actually builds, so if the normalisation is ever removed this
    fails here rather than silently making the template's two guards
    load-bearing with no test behind them.
    """
    import ion.web.ui.scheduler as mod

    seen = []
    real = mod._render

    def capture(request, **context):
        seen.append(context)
        return real(request, **context)

    monkeypatch.setattr(mod, "_render", capture)

    for verdict in (None, "yes", "false", 1, 0, [], {}, 1.0):
        monkeypatch.setattr(
            "ion.services.scheduler_service.preview_schedule",
            lambda _expr, count=3, _v=verdict: {
                "valid": _v, "description": "MUST-NOT-SHOW",
                "timezone": "UTC", "next_runs": [], "error": None,
            },
        )
        with caplog.at_level(logging.ERROR):
            resp = get(app, "/ui/scheduler/preview", cron_expr="*/15 * * * *")
        assert resp.status_code == 200
        assert "MUST-NOT-SHOW" not in resp.text, verdict

    assert seen, "the route must have rendered"
    for context in seen:
        preview = context.get("preview")
        assert preview is None or preview.get("valid") in (True, False), (
            "a preview reached the template with a verdict the template's "
            f"two branches cannot read: {preview!r}")
