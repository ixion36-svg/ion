"""The security dashboard as server-rendered fragments.

security_dashboard.html built the threat banner, the 24-hour cards, the
events table, the top-IP list, the threat-type list, the blocked-IP list
and the event-detail modal out of string concatenation, and wrote them
with innerHTML. Those are the cases below.

Two of them matter more than the rest on a posture page. A severity pill
that reads the enum repr is unreadable, and a failed read rendered as zero
says the estate is quiet when the truth is that we could not look.

Rows in the render tests are fixtures. The route tests drive the real
service on a real session, because that is the only way to know the
fragment and the JSON endpoint answer the same question.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_args, get_type_hints

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.models.security import (
    BlockedIP,
    SecurityEvent,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityEventType,
)
from ion.web.templating import make_templates
from ion.web.ui.security_dashboard import (
    MANAGE_PERMISSION,
    PERMISSION,
    STATUSES,
    _blocked_addresses,
    _count,
    blocked_view,
    event_view,
    matched_preview,
    payload_sections,
    router,
    security_dashboard_fragment,
    stats_view,
    summary_view,
)

FRAGMENT = "_fragments/security_dashboard.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/security_dashboard.html"
SERVER = ROOT / "src/ion/web/server.py"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _text(html: str, element_id: str) -> str | None:
    """The text of the element with this id, or None if it was not rendered.

    Scoped to the element so a zero somewhere else on the page cannot make
    a missing figure look measured.
    """
    match = re.search(rf'id="{element_id}"[^>]*>(.*?)</', html, re.S)
    if match is None:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()


def _summary(**over: Any) -> dict:
    base = {
        "threat_level": "normal",
        "level_class": "normal",
        "active_blocks": 0,
        "last_hour_total": 0,
        "top_threats": [],
        "top_attackers": [],
    }
    base.update(over)
    return base


def _stats(**over: Any) -> dict:
    base = {"total": 0, "critical": 0, "high": 0, "blocked": 0}
    base.update(over)
    return base


def dashboard(**over: Any) -> str:
    ctx: dict[str, Any] = {
        "panel": "dashboard",
        "hours": 24,
        "severity": "",
        "summary": _summary(),
        "summary_failed": False,
        "stats": _stats(),
        "stats_failed": False,
        "events": [],
        "events_failed": False,
        "blocked": [],
        "blocked_failed": False,
        # The block list was read and held nothing, so no address is
        # blocked. None would mean the list could not be read, which the
        # three-state tests below arrange on purpose.
        "blocked_addresses": set(),
        # A viewer who can act, so the tests that are about a control's
        # markup see the control. The permission tests set it both ways.
        "can_manage": True,
        "statuses": STATUSES,
    }
    ctx.update(over)
    return render(**ctx)


def _namespace(**over: Any) -> SimpleNamespace:
    now = datetime(2026, 10, 12, 15, 4, 0)
    base = dict(
        id=7,
        title="SQLi against the login form",
        description="UNION SELECT in the username field",
        source_ip="203.0.113.10",
        severity="high",
        status="new",
        event_type="sql_injection",
        created_at=now,
        first_seen=now,
        last_seen=now,
        event_count=3,
        confidence_score=80,
        username="alice",
        request_path="/login",
        request_method="POST",
        user_agent="sqlmap/1.7",
        raw_data={"matched_content": "' OR 1=1"},
        matched_patterns=["union select"],
    )
    base.update(over)
    return SimpleNamespace(**base)


def one(**over: Any) -> str:
    return dashboard(events=[event_view(_namespace(**over))])


def detail(**over: Any) -> str:
    failed = over.pop("failed", False)
    can_manage = over.pop("can_manage", True)
    event = None if failed else event_view(_namespace(**over))
    return render(
        panel="event", failed=failed, event=event,
        can_manage=can_manage, statuses=STATUSES,
    )


def _flat(html: str) -> str:
    """One space between words, so a prose assertion can span template lines.

    The failure wording is indented across three lines in the template. A
    substring of the sentence matches the source only by accident of where
    the author happened to wrap it.
    """
    return re.sub(r"\s+", " ", html)


# ---------------------------------------------------------------------------
# Counts, where zero is a measurement
# ---------------------------------------------------------------------------


def test_a_boolean_is_not_a_count_and_zero_is():
    """``bool`` is an ``int``. A type check that forgets that publishes a
    flag as the count 1, and a truthiness check publishes a measured 0 as
    unknown."""
    assert _count(0) == 0
    assert _count(4) == 4
    assert _count(True) is None
    assert _count(False) is None
    assert _count(None) is None


def test_a_severity_the_aggregation_did_not_group_is_zero():
    """get_statistics omits a severity with no rows. That is a count of
    zero, not a severity nobody asked about."""
    assert stats_view({
        "total_events": 4, "by_severity": {"high": 4}, "blocked_count": 0,
    })["critical"] == 0
    assert stats_view({
        "total_events": 0, "by_severity": {}, "blocked_count": 0,
    })["high"] == 0


def test_a_missing_severity_map_is_not_zero():
    """No map means the count was not made. Zero would say the estate had
    no critical events, which is a different finding."""
    view = stats_view({"total_events": 4, "blocked_count": 0})
    assert view["critical"] is None
    assert view["high"] is None


@pytest.mark.parametrize("value", [None, True, "0"])
def test_a_severity_value_that_is_not_a_number_is_not_zero(value):
    view = stats_view({
        "total_events": 1, "by_severity": {"critical": value}, "blocked_count": 0,
    })
    assert view["critical"] is None


def test_measured_zeros_are_printed_rather_than_hidden():
    """``is not none``, not truthiness. ``{% if stats.critical %}`` renders
    a measured zero the same as a figure nobody computed."""
    html = dashboard()
    for element_id in (
        "stat-total", "stat-critical", "stat-high", "stat-blocked",
        "stat-last-hour", "stat-blocks",
    ):
        assert _text(html, element_id) == "0", element_id


def test_an_unmeasured_figure_is_a_dash_and_not_zero():
    html = dashboard(
        stats=_stats(total=None, critical=None, high=None, blocked=None),
        summary=_summary(active_blocks=None, last_hour_total=None),
    )
    for element_id in (
        "stat-total", "stat-critical", "stat-high", "stat-blocked",
        "stat-last-hour", "stat-blocks",
    ):
        assert _text(html, element_id) == "—", element_id


def test_a_threat_count_of_zero_is_shown():
    """The badge is the count. Hiding a zero reads as 'not counted'."""
    html = dashboard(summary=_summary(top_threats=[
        {"label": "sql_injection", "text": "Sql Injection", "count": 0},
    ]))
    section = html.split('id="threat-types-list"', 1)[1].split('id="blocked-ips-list"', 1)[0]
    assert ">0<" in section
    assert "Sql Injection" in section


def test_an_unmeasured_threat_count_is_not_shown_as_zero():
    html = dashboard(summary=_summary(top_threats=[
        {"label": "sql_injection", "text": "Sql Injection", "count": None},
    ]))
    section = html.split('id="threat-types-list"', 1)[1].split('id="blocked-ips-list"', 1)[0]
    assert ">0<" not in section
    assert "—" in section


def test_a_missing_summary_list_is_not_an_empty_one():
    """``[]`` means the summary looked and found nothing. A missing key
    means this fragment does not know, and 'No threats detected' is the
    wrong sentence for that."""
    assert summary_view({
        "threat_level": "low", "last_hour": {}, "active_blocks": 0,
    })["top_threats"] is None
    html = dashboard(summary=_summary(top_threats=None, top_attackers=None))
    assert "could not be read" in html
    assert "No threats detected" not in html
    assert "No source IPs" not in html


def test_an_event_count_of_zero_is_printed():
    html = one(event_count=0)
    counts = re.findall(r'class="event-count">(.*?)<', html)
    assert counts == ["0"]


def test_a_missing_event_count_is_not_zero():
    html = one(event_count=None)
    counts = re.findall(r'class="event-count">(.*?)<', html)
    assert counts == ["—"]


def test_a_confidence_of_zero_is_zero_percent():
    """0% is a score. The JavaScript interpolated it. A truthiness check
    renders it as unknown, which reads as 'not scored'."""
    assert _text(detail(confidence_score=0), "detail-confidence") == "0%"


def test_a_missing_confidence_is_not_zero_percent():
    assert _text(detail(confidence_score=None), "detail-confidence") == "—"


# ---------------------------------------------------------------------------
# The row, which is what the enum and the escaping moved for
# ---------------------------------------------------------------------------


def test_the_severity_pill_reads_the_value_not_the_enum_repr():
    """SecurityEvent.severity is a SQLEnum. The JSON endpoint handed the
    script the value, because FastAPI serialises a str-mixin enum that way.
    Jinja stringifies the member, and on Python 3.12 that is
    ``SecurityEventSeverity.CRITICAL``, so the pill would read the repr and
    the colour class would be ``severity-SecurityEventSeverity.CRITICAL``."""
    html = one(severity=SecurityEventSeverity.CRITICAL)
    assert "SecurityEventSeverity" not in html
    assert ">critical<" in html
    assert 'data-sev="critical"' in html


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_each_severity_keeps_its_colour(severity):
    """The colour comes from [data-sev] in ion-value-scales.css now, not a
    severity-<level> class. tests/test_security_dashboard_scales.py asserts
    every enum member has a row there; this asserts the markup carries the
    value that selects it."""
    html = one(severity=severity)
    assert f'data-sev="{severity}"' in html
    assert "severity-badge" not in html


def test_the_status_pill_reads_the_value_not_the_enum_repr():
    """The attribute carries the enum value, so the underscore stays an
    underscore. The old class form rewrote it to a hyphen to match a
    selector; `[data-status="false_positive"]` needs no rewrite, and the
    rewrite coming back would leave the pill uncoloured."""
    html = one(status=SecurityEventStatus.FALSE_POSITIVE)
    assert "SecurityEventStatus" not in html
    assert ">False Positive<" in html
    assert 'data-status="false_positive"' in html
    assert "status-false-positive" not in html


def test_the_type_is_words_not_the_enum_repr():
    html = one(event_type=SecurityEventType.SQL_INJECTION)
    assert "SecurityEventType" not in html
    assert "Sql Injection" in html


def test_jinja_escapes_what_escapehtml_used_to():
    """escapeHtml() is gone. A title, an IP and a matched payload that
    contain markup must not become markup."""
    html = one(
        title="<script>alert(1)</script>",
        source_ip="<svg onload=1>",
        raw_data={"matched_content": "<img src=x onerror=1>"},
        matched_patterns=["<script>p</script>"],
    )
    assert "<script>alert(1)</script>" not in html
    assert "<script>p</script>" not in html
    assert "<svg onload=1>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_the_block_button_args_parse_back_to_the_ip():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which leaves a button that looks live and does nothing. An IP
    with a quote or markup used to be interpolated into the attribute."""
    html = one(source_ip="10.0.0.1'")
    args = re.findall(r"data-args='([^']*)'", html)
    parsed = [json.loads(raw) for raw in args]
    assert ["10.0.0.1'"] in parsed
    assert any(item == [7] for item in parsed)


def test_a_row_with_no_source_ip_offers_no_block_button():
    html = one(source_ip=None)
    assert "quickBlockIP" not in html


# ---------------------------------------------------------------------------
# Matched content, where 0 is a payload and not a reason to skip
# ---------------------------------------------------------------------------


def test_numeric_zero_matched_content_is_not_the_next_field():
    """The JavaScript used truthiness, so a matched_content of 0 fell
    through to the query string. That shows the analyst a different
    payload from the one that matched."""
    got = matched_preview({"matched_content": 0, "query_string": "secret"})
    assert got["text"] == "0"
    assert got["title"] == "0"


def test_an_empty_matched_content_does_not_fall_through_either():
    got = matched_preview({"matched_content": "", "query_string": "secret"})
    assert got == {"text": "", "title": ""}


def test_a_query_string_keeps_plus_and_decodes_percent_escapes():
    """``unquote_plus`` would turn ``+`` into a space. decodeURIComponent
    does not, and ``+`` in a query is part of the payload."""
    got = matched_preview({"query_string": "a+b%20c"})
    assert got["text"] == "a+b c"


def test_a_broken_percent_escape_stays_raw():
    """decodeURIComponent throws on a trailing %. The cell showed the raw
    string, not an exception and not a half-decoded one."""
    assert matched_preview({"query_string": "100%"})["text"] == "100%"


@pytest.mark.parametrize("payload", ["%C0%80", "%E0%80%AF", "%FF", "%ED%A0%80"])
def test_invalid_utf8_payload_bytes_survive_as_written(payload):
    """The other half of what decodeURIComponent refuses.

    These escapes are well formed, so the malformed-percent pattern passes
    them, and `unquote` with its default `errors="replace"` turns each into
    U+FFFD. They are the overlong and surrogate sequences a WAF bypass is
    built out of, so a replacement glyph throws away the evidence the cell
    exists to show, and does it silently: U+FFFD from a decode failure and
    U+FFFD the attacker really sent look identical. The JavaScript threw
    here and kept the raw string.
    """
    got = matched_preview({"query_string": payload})
    assert got["text"] == payload
    assert "�" not in got["text"]
    assert got["title"] == payload


def test_valid_multibyte_payloads_still_decode():
    """The guard above must not stop decoding what is valid. Without this,
    returning the raw string unconditionally would pass every assertion in
    the test above."""
    assert matched_preview({"query_string": "%E2%9C%93"})["text"] == "✓"
    assert matched_preview({"query_string": "caf%C3%A9"})["text"] == "café"


def test_a_query_string_is_clipped_only_past_100_characters():
    exact = "q" * 100
    assert matched_preview({"query_string": exact})["text"] == exact
    longer = "q" * 101
    got = matched_preview({"query_string": longer})
    assert got["text"] == ("q" * 100) + "..."
    assert got["title"] == longer


def test_a_body_always_grows_an_ellipsis_and_the_title_does_not():
    """``substring(0, 100) + '...'`` appends the ellipsis even when the
    body is shorter. The title kept the full text."""
    got = matched_preview({"body": "hi"})
    assert got["text"] == "hi..."
    assert got["title"] == "hi"


def test_matched_content_is_not_clipped():
    text = "m" * 150
    assert matched_preview({"matched_content": text})["text"] == text


def test_a_non_dict_payload_is_a_dash_not_a_crash():
    assert matched_preview("nope") == {"text": "-", "title": "-"}
    assert payload_sections(["nope"]) == []


def test_the_modal_payload_is_unclipped_and_ordered():
    sections = payload_sections({"body": "x" * 150, "path": "/admin"})
    assert [s["label"] for s in sections] == ["Request Body:", "Request Path:"]
    assert sections[0]["text"] == "x" * 150


def test_a_decoded_query_string_is_escaped_in_the_cell():
    html = one(raw_data={"query_string": "%3Cscript%3Ealert(1)%3C/script%3E"})
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_the_created_at_is_a_machine_readable_instant():
    """Never formatted into a locale string on the server. The column is
    naive, so the macro marks it local=no and leaves the digits as stored.
    Localising them would invent a zone."""
    html = one()
    assert '<time datetime="2026-10-12T15:04:00"' in html
    assert 'data-ts-format="datetime"' in html
    assert 'data-ts-local="no"' in html
    assert "2026-10-12 15:04" in html
    assert "1970" not in html


def test_a_missing_timestamp_is_a_dash_and_not_the_epoch():
    """The table's Time cell and the modal's First/Last Seen. A missing
    value is the macro's hyphen, never the epoch and never the word None."""
    table = one(created_at=None)
    assert "1970" not in table
    assert '<span class="opacity-60">-</span>' in table
    modal = detail(first_seen=None, last_seen=None)
    assert "1970" not in modal
    assert modal.count('<span class="opacity-60">-</span>') >= 2


# ---------------------------------------------------------------------------
# Permanent is three states
# ---------------------------------------------------------------------------


def _blocked(**over: Any) -> str:
    row = {"ip_address": "203.0.113.8", "permanent": False, "blocked_until": None}
    row.update(over)
    return dashboard(blocked=[row])


def test_a_permanent_block_says_permanent_even_with_an_expiry():
    html = _blocked(permanent=True, blocked_until=datetime(2026, 11, 1))
    assert "Permanent" in html
    assert "Until" not in html
    assert "Indefinite" not in html


def test_a_timed_block_names_the_instant():
    html = _blocked(permanent=False, blocked_until=datetime(2026, 11, 1, 0, 0))
    assert "Until" in html
    assert '<time datetime="2026-11-01T00:00:00"' in html
    assert "Permanent" not in html
    assert "Indefinite" not in html


def test_a_non_permanent_block_with_no_expiry_is_indefinite():
    html = _blocked(permanent=False, blocked_until=None)
    assert "Indefinite" in html
    assert "Permanent" not in html
    assert "Duration unknown" not in html


@pytest.mark.parametrize("permanent", [None, "no"])
def test_an_unmeasured_permanent_flag_is_neither_permanent_nor_indefinite(permanent):
    """Three states stay three.

    ``None`` and the string ``"no"`` are not a boolean. Truthiness reads
    ``"no"`` as permanent. ``is true`` with no middle branch reads both as
    indefinite. Either tells an analyst the block will or will not expire
    when the flag was never read. ``"no"`` is the case a weakened first
    condition gets wrong; ``None`` alone cannot catch that, because it is
    falsy either way.
    """
    html = _blocked(permanent=permanent, blocked_until=None)
    assert "Duration unknown" in html
    assert "Permanent" not in html
    assert "Indefinite" not in html


def test_blocked_view_does_not_coerce_a_non_boolean():
    row = blocked_view(SimpleNamespace(
        ip_address="203.0.113.8", permanent="no", blocked_until=None,
    ))
    assert row["permanent"] is None
    assert blocked_view(SimpleNamespace(
        ip_address="203.0.113.8", permanent=False, blocked_until=None,
    ))["permanent"] is False


# ---------------------------------------------------------------------------
# Empty is not failed, and one failure does not zero the rest
# ---------------------------------------------------------------------------


def test_a_quiet_window_says_the_window_and_not_that_the_read_failed():
    html = dashboard(events=[], severity="", hours=24)
    assert "No security events in this 24-hour window." in html
    assert "could not be read" not in html
    assert "Other severities" not in html


def test_an_empty_severity_filter_does_not_claim_the_window_has_nothing():
    html = dashboard(events=[], severity="high", hours=1)
    assert "No high events in this 1-hour window" in html
    assert "No security events in this" not in html
    assert "could not be read" not in html


def test_a_failed_event_read_is_not_an_empty_table():
    html = dashboard(events=None, events_failed=True)
    assert "could not be read" in html
    assert "not an empty list" in html
    assert "No security events in this" not in html
    assert 'id="events-empty"' not in html
    # The card stays, so the error lands in the panel.
    assert 'id="events-table"' in html


def test_a_failed_summary_does_not_announce_normal_or_zero():
    html = dashboard(summary=None, summary_failed=True)
    assert "could not be read" in html
    assert "not an all-clear" in html
    assert "Threat Level:" not in html
    assert _text(html, "stat-last-hour") is None
    assert _text(html, "stat-blocks") is None
    assert "No threats detected" not in html
    assert "No source IPs" not in html


def test_a_failed_statistics_read_prints_no_zero_cards():
    html = dashboard(stats=None, stats_failed=True, events=[event_view(_namespace())])
    assert "24-hour counts are unknown rather than zero" in html
    assert _text(html, "stat-total") is None
    assert _text(html, "stat-critical") is None
    assert "SQLi against the login form" in html


def test_a_failed_block_list_is_not_an_empty_one_and_keeps_the_button():
    """The Block IP button is inside the swap because the card is. It has
    to survive the failure branch or the failed read removes the control."""
    html = dashboard(blocked=None, blocked_failed=True)
    assert "could not be read" in html
    assert "unknown rather than zero" in html
    assert "No blocked IPs" not in html
    assert 'data-click-action="showBlockIPModal"' in html


def test_no_blocks_says_so():
    html = dashboard(blocked=[])
    assert "No blocked IPs" in html
    assert "could not be read" not in html


def test_the_dashboard_fragment_renders_no_nested_request():
    """#sd-content carries hx-include for the two selects. A nested hx-get
    inside it would send hours and severity again, and FastAPI would keep
    the inherited copy. The fragment has no request of its own."""
    html = dashboard(events=[event_view(_namespace())])
    assert "hx-get" not in html
    assert "hx-include" not in html
    assert "hx-on" not in html


# ---------------------------------------------------------------------------
# The event detail
# ---------------------------------------------------------------------------


def test_the_detail_renders_the_event_and_marks_its_status():
    html = detail(status="mitigated", description="<b>owned</b>")
    assert "Sql Injection" in html
    assert "&lt;b&gt;owned&lt;/b&gt;" in html
    assert "<b>owned</b>" not in html
    assert re.search(r'<option value="mitigated"[^>]*selected', html)
    assert not re.search(r'<option value="new"[^>]*selected', html)


def test_the_status_select_offers_every_status_the_enum_has():
    html = detail()
    for status in SecurityEventStatus:
        assert f'value="{status.value}"' in html
    assert {value for value, _label in STATUSES} == {s.value for s in SecurityEventStatus}


def test_a_failed_detail_says_so_and_has_no_status_select():
    """There is no status to change when the event was not read. Close
    lives in the page shell, so the failure branch does not need one."""
    html = detail(failed=True)
    assert "could not be read" in html
    assert "not an empty record" in html
    assert 'id="event-status-select"' not in html
    assert "0%" not in html


def test_a_missing_username_is_a_dash_and_not_the_word_none():
    html = detail(username=None, request_path=None, user_agent=None)
    assert "None" not in html
    assert ">-</div>" in html or ">-</" in html


def test_a_username_of_zero_is_kept():
    """The string ``0`` is a username. A truthiness check on the field
    renders the dash instead."""
    html = detail(username="0")
    assert ">0<" in html


# ---------------------------------------------------------------------------
# The gates
# ---------------------------------------------------------------------------


def _dependency_names(route) -> list[str]:
    return [getattr(dep.call, "__qualname__", "") for dep in route.dependant.dependencies]


def _permission_of(route) -> str | None:
    for dep in route.dependant.dependencies:
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(
                fn.__code__.co_freevars,
                (c.cell_contents for c in (fn.__closure__ or ())),
            ))
            return cells.get("permission_name")
    return None


def _fragment_routes() -> dict:
    return {route.path: route for route in router.routes}


def _json_routes() -> dict:
    from ion.web.security_api import router as security_router

    found = {}
    for route in security_router.routes:
        if "GET" not in getattr(route, "methods", set()):
            continue
        found.setdefault(route.path, route)
    return found


_GETS = (
    "/threat-summary",
    "/statistics",
    "/events",
    "/events/{event_id}",
    "/blocked-ips",
)


def test_the_fragment_permission_matches_every_get_it_mirrors():
    """Read out of each JSON route, not restated. fragment_plan reports
    require_permission('security:read') for all five. security:manage is
    the gate on block, unblock and status, and using it here would lock
    the dashboard behind a write."""
    assert PERMISSION == "security:read"
    pages = _fragment_routes()
    assert set(pages) == {
        "/security-dashboard",
        "/security-dashboard/events/{event_id}",
    }
    gets = _json_routes()
    for path in _GETS:
        assert _permission_of(gets[path]) == PERMISSION, path
        assert "require_de_module" not in _dependency_names(gets[path])
    for route in pages.values():
        assert _permission_of(route) == PERMISSION
        names = _dependency_names(route)
        assert "require_de_module" not in names
        assert "require_page_permission" not in names
        assert "security:manage" not in ( _permission_of(route) or "")


def test_the_security_router_is_not_mounted_behind_the_de_licence():
    """The claim the test above is matching. server.py mounts this router
    with a prefix and no dependencies. Adding require_de_module there, or
    on the fragment, would 404 the dashboard on a deployment that is not
    licensed for detection engineering, which is a page the API still
    serves. If the mount ever grows the gate, this fails instead of
    letting the fragment drift from it."""
    src = SERVER.read_text(encoding="utf-8")
    assert re.search(
        r'include_router\(\s*security_router,\s*prefix="/api/security"\s*\)',
        src,
    )


def test_the_severity_filter_is_the_enum_plus_the_all_sentinel():
    hints = get_type_hints(security_dashboard_fragment)
    allowed = set(get_args(hints["severity"]))
    assert allowed == {""} | {s.value for s in SecurityEventSeverity}


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------


class _User:
    """A viewer holding exactly the permissions it was given.

    Not a blanket True. `security:read` and `security:manage` are two
    different answers on this page, and a user that grants everything
    cannot tell the two apart.
    """

    id = 1
    username = "sec-tester"

    def __init__(self, *permissions: str):
        self._permissions = set(permissions) or {PERMISSION, MANAGE_PERMISSION}

    def has_permission(self, name):
        return name in self._permissions


def _app(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: session
    return application


@pytest.fixture
def app(session):
    application = _app(session, _User())
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def read_only_app(session):
    """A viewer who may read the dashboard and may not act on it."""
    application = _app(session, _User(PERMISSION))
    yield application
    application.dependency_overrides.clear()


def _event(session, **over: Any) -> SecurityEvent:
    now = datetime.utcnow().replace(microsecond=0)
    fields = dict(
        event_type=SecurityEventType.SQL_INJECTION,
        severity=SecurityEventSeverity.HIGH,
        status=SecurityEventStatus.NEW,
        title="probe",
        description="a probe event",
        source_ip="203.0.113.10",
        detection_rule="sqli",
        confidence_score=50,
        event_count=1,
        blocked=False,
        created_at=now,
        first_seen=now,
        last_seen=now,
    )
    fields.update(over)
    row = SecurityEvent(**fields)
    session.add(row)
    session.commit()
    return row


def test_a_quiet_estate_renders_measured_zeros(app):
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert resp.status_code == 200
    assert _text(resp.text, "stat-total") == "0"
    assert _text(resp.text, "stat-critical") == "0"
    assert _text(resp.text, "stat-high") == "0"
    assert _text(resp.text, "stat-blocked") == "0"
    assert _text(resp.text, "stat-last-hour") == "0"
    assert _text(resp.text, "stat-blocks") == "0"
    assert "Threat Level: NORMAL" in resp.text
    assert "No threats detected" in resp.text
    assert "No source IPs" in resp.text
    assert "No blocked IPs" in resp.text
    assert "No security events in this 24-hour window." in resp.text
    assert "could not be read" not in resp.text


def test_the_banner_level_is_the_json_endpoints(app, session):
    """get_threat_summary owns the thresholds. A second copy here would
    keep saying normal after those moved.

    The event was pinned to datetime(2026, 10, 12, 15, 4, 0), and
    get_threat_summary derives the level from a rolling 24-hour window.
    That date was inside the window in the week this was written and has
    since aged out of it, after which the level read normal and this
    failed as though the thresholds had broken. It is two hours before now
    instead, and the rendered timestamp is derived from the same value
    rather than written out a second time, so the test stays deterministic
    without depending on the calendar.
    """
    occurred = datetime.utcnow().replace(microsecond=0) - timedelta(hours=2)
    _event(session, severity=SecurityEventSeverity.CRITICAL, title="crit-probe",
           created_at=occurred)
    from ion.web.security_api import get_threat_summary

    level = get_threat_summary(session=session, current_user=None)["threat_level"]
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert resp.status_code == 200
    assert level == "critical"
    assert "Threat Level: CRITICAL" in resp.text
    assert 'class="threat-level v-text flex items-center gap-4" data-sev="critical"' in resp.text
    assert "crit-probe" in resp.text
    assert "SecurityEventSeverity" not in resp.text
    assert f'<time datetime="{occurred.isoformat()}"' in resp.text


def test_the_cards_are_the_24h_statistics_not_the_table_window(app, session):
    """The table follows the window select. The cards do not: the script
    always asked statistics for 24 hours. An old event drops out of a
    one-hour table and stays in the 24-hour total."""
    _event(session, title="old-probe",
           created_at=datetime.utcnow().replace(microsecond=0) - timedelta(hours=3))
    _event(session, title="new-probe")
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard", params={"hours": 1})
    assert resp.status_code == 200
    assert "new-probe" in resp.text
    assert "old-probe" not in resp.text
    assert _text(resp.text, "stat-total") == "2"
    assert "No security events in this 1-hour window" not in resp.text


def test_the_severity_filter_is_applied_by_the_service(app, session):
    _event(session, severity=SecurityEventSeverity.CRITICAL, title="crit-row")
    _event(session, severity=SecurityEventSeverity.LOW, title="low-row")
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard", params={"severity": "low"})
    assert resp.status_code == 200
    assert "low-row" in resp.text
    assert "crit-row" not in resp.text


def test_the_table_asks_for_the_same_limit_the_page_sent(app, monkeypatch):
    seen: dict = {}

    def fake(self, hours=24, severity=None, limit=100, **_k):
        seen["hours"] = hours
        seen["severity"] = severity
        seen["limit"] = limit
        return []

    monkeypatch.setattr(
        "ion.services.security_service.SecurityDetectionService.get_recent_events",
        fake,
    )
    with TestClient(app) as client:
        resp = client.get(
            "/ui/security-dashboard", params={"hours": 72, "severity": "high"},
        )
    assert resp.status_code == 200
    assert seen == {
        "hours": 72,
        "severity": SecurityEventSeverity.HIGH,
        "limit": 100,
    }


def test_blocked_events_and_blocked_addresses_are_different_counts(app, session):
    """The Blocked card is events flagged blocked. The banner's Active
    Blocks is the block list. They are different queries and the
    JavaScript showed both. Using one number for the other hides a block
    that caught nothing, or an event that was blocked without an address
    landing on the list."""
    _event(session, blocked=True, title="blocked-one")
    _event(session, blocked=True, title="blocked-two")
    session.add(BlockedIP(
        ip_address="203.0.113.50", reason="manual", permanent=True,
    ))
    session.commit()
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert _text(resp.text, "stat-blocked") == "2"
    assert _text(resp.text, "stat-blocks") == "1"
    assert "203.0.113.50" in resp.text
    assert "Permanent" in resp.text


def test_an_expired_block_is_not_listed(app, session):
    """get_blocked_ips returns the active list. An expired row is not an
    active block, and rendering it would say an address is blocked when
    the service would let it through."""
    session.add(BlockedIP(
        ip_address="198.51.100.9", reason="old", permanent=False,
        blocked_until=datetime.utcnow() - timedelta(hours=1),
    ))
    session.commit()
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert resp.status_code == 200
    assert "198.51.100.9" not in resp.text
    assert "No blocked IPs" in resp.text


def test_an_unparseable_filter_is_a_bad_request_not_a_failed_read(app):
    with TestClient(app) as client:
        bogus = client.get("/ui/security-dashboard", params={"severity": "bogus"})
        huge = client.get("/ui/security-dashboard", params={"hours": 720})
        zero = client.get("/ui/security-dashboard", params={"hours": 0})
        ok = client.get("/ui/security-dashboard", params={"hours": 168, "severity": ""})
    assert bogus.status_code == 422
    assert huge.status_code == 422
    assert zero.status_code == 422
    assert ok.status_code == 200
    for resp in (bogus, huge, zero):
        assert "could not be read" not in resp.text


def test_an_events_failure_does_not_zero_the_figures_that_were_read(app, session, monkeypatch):
    _event(session, title="still-counted")

    def boom(self, *args, **kwargs):
        raise RuntimeError("event store unreachable")

    monkeypatch.setattr(
        "ion.services.security_service.SecurityDetectionService.get_recent_events",
        boom,
    )
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert "not an empty list" in resp.text
    assert "still-counted" not in resp.text
    assert "No security events in this" not in resp.text
    # The statistics read did happen, and it counted the row.
    assert _text(resp.text, "stat-total") == "1"
    assert "No blocked IPs" in resp.text


def test_a_statistics_failure_does_not_drop_the_events_or_print_zero(app, session, monkeypatch):
    _event(session, title="still-listed")

    def boom(self, hours=24):
        raise RuntimeError("stats down")

    monkeypatch.setattr(
        "ion.services.security_service.SecurityDetectionService.get_statistics",
        boom,
    )
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert resp.status_code == 200
    assert "still-listed" in resp.text
    assert "24-hour counts are unknown rather than zero" in resp.text
    assert _text(resp.text, "stat-critical") is None
    assert _text(resp.text, "stat-total") is None
    # The summary is built from the same statistics call, so it fails too,
    # and it must not fall back to a normal banner.
    assert "Threat Level:" not in resp.text
    assert "No blocked IPs" in resp.text


def test_the_detail_route_renders_the_row_the_repository_returns(app, session):
    """The modal body is what showEventDetail wrote. That script never
    printed the title there (the table does), so the description, the
    payload and the pattern are the proof this is the stored row."""
    row = _event(
        session, title="detail-probe", description="payload <x>",
        status=SecurityEventStatus.INVESTIGATING,
        raw_data={"matched_content": "UNION SELECT"},
        matched_patterns=["union"],
    )
    with TestClient(app) as client:
        resp = client.get(f"/ui/security-dashboard/events/{row.id}")
    assert resp.status_code == 200
    assert "UNION SELECT" in resp.text
    assert "union" in resp.text
    assert "&lt;x&gt;" in resp.text
    assert "<x>" not in resp.text
    assert "SecurityEventStatus" not in resp.text
    assert re.search(r'<option value="investigating"[^>]*selected', resp.text)


def test_a_missing_event_is_a_404_not_a_failed_read(app, session):
    _event(session, title="present-probe")
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard/events/999999")
    assert resp.status_code == 404
    assert "present-probe" not in resp.text
    assert "could not be read" not in resp.text


def test_a_detail_read_failure_renders_the_failure_fragment(app, monkeypatch):
    def boom(self, event_id):
        raise RuntimeError("event store unreachable")

    monkeypatch.setattr(
        "ion.storage.security_repository.SecurityEventRepository.get_by_id",
        boom,
    )
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard/events/7")
    assert resp.status_code == 200
    assert "could not be read" in resp.text
    assert 'id="event-status-select"' not in resp.text


def test_an_event_id_that_is_not_an_integer_is_a_bad_request(app):
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard/events/nope")
    assert resp.status_code == 422
    assert "could not be read" not in resp.text


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _script(src: str) -> str:
    return "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))


def _tag(src: str, element_id: str) -> str:
    match = re.search(rf'<[^>]*id="{element_id}"[^>]*>', src)
    assert match, element_id
    return match.group(0)


def test_the_status_select_carries_the_event_it_belongs_to():
    """The write target comes off the control, not off a variable the
    opener set. htmx leaves the previous event's body on screen while the
    detail request is in flight, so a module-level current-event id would
    already be the new event while the select is still the old one, and a
    change in that window would patch one event with another's status."""
    html = detail(status="mitigated")
    tag = re.search(r'<select[^>]*id="event-status-select"[^>]*>', html).group(0)
    assert 'data-event-id="7"' in tag
    assert 'data-change-action="updateEventStatus"' in tag

    js = _script(PAGE.read_text(encoding="utf-8"))
    assert "select.dataset.eventId" in js
    # The global is gone, not merely unused: a surviving one is what the
    # handler would fall back to.
    assert "currentEventId" not in js


def test_an_event_with_no_id_gets_no_status_select():
    """PATCH /events/{id}/status cannot address a missing id, so a select
    for it would be a control whose only outcome is a 422."""
    html = detail(id=None)
    assert 'id="event-status-select"' not in html
    # The record is still rendered; only the control is withheld.
    assert "Sql Injection" in html


def test_the_duration_hint_does_not_promise_what_the_form_refuses():
    """The old hint read "Set to 0 for permanent block". The field carries
    min="1", so the browser rejects 0 before submit, and blockIP's
    `parseInt(...) || 60` would read a 0 that got through as sixty minutes.
    An analyst following that hint asked for permanent and got an hour."""
    src = PAGE.read_text(encoding="utf-8")
    markup = _markup(src)
    assert "Set to 0 for permanent block" not in markup
    assert 'min="1"' in _tag(src, "block-duration")
    assert "Permanent Block" in markup


def test_the_page_builds_no_markup_in_javascript():
    src = PAGE.read_text(encoding="utf-8")
    js = _script(src)
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_string_building_helpers_are_gone():
    """Each of these was defined in this page's own script at HEAD, so each
    assertion names a function this conversion really deleted.

    `function escapeHtml(` is deliberately not among them. The old page
    never defined one: it called the shared helper in static/js/app.js,
    which nine other templates still use. Asserting the definition is
    absent would pass on a page that had never had it, which is this page,
    so it would catch nothing. What this page really stopped doing is
    calling it, which the next assertion checks, and the escaping that
    replaced it has its own test feeding `<script>`.
    """
    js = _script(PAGE.read_text(encoding="utf-8"))
    assert "escapeHtml(" not in js
    assert "function formatDateTime(" not in js
    assert "function formatEventType(" not in js
    assert "function formatStatus(" not in js
    assert "function loadEvents(" not in js
    assert "function loadThreatSummary(" not in js
    assert "function loadStatistics(" not in js
    assert "function loadBlockedIPs(" not in js
    assert "toLocaleString" not in js
    assert "/login?redirect=/security" not in js


def test_the_page_requests_the_fragment_on_load_and_includes_the_filters():
    """Asserted on the element, not the file. A comment that names the
    attribute would keep a whole-file search green after the attribute
    was removed."""
    src = PAGE.read_text(encoding="utf-8")
    slot = _tag(src, "sd-content")
    assert 'hx-get="/ui/security-dashboard"' in slot
    assert 'hx-trigger="load"' in slot
    assert 'hx-include="#sd-severity,#sd-hours"' in slot
    assert 'hx-swap="innerHTML"' in slot
    assert 'name="severity"' in _tag(src, "sd-severity")
    assert 'hx-include="#sd-hours"' in _tag(src, "sd-severity")
    assert 'name="hours"' in _tag(src, "sd-hours")
    assert 'hx-include="#sd-severity"' in _tag(src, "sd-hours")
    refresh = _tag(src, "sd-refresh")
    assert 'hx-get="/ui/security-dashboard"' in refresh
    assert 'hx-include="#sd-severity,#sd-hours"' in refresh


def test_the_filters_and_refresh_sit_outside_the_swap_target():
    src = PAGE.read_text(encoding="utf-8")
    content = src.index('id="sd-content"')
    assert src.index('id="sd-severity"') < content
    assert src.index('id="sd-hours"') < content
    assert src.index('id="sd-refresh"') < content


def test_the_event_modal_keeps_close_outside_the_detail_swap():
    src = PAGE.read_text(encoding="utf-8")
    modal = src.split('id="event-modal"', 1)[1].split('id="block-ip-modal"', 1)[0]
    assert 'id="event-detail-content"' in modal
    assert 'id="event-status-select"' not in modal
    assert modal.index("Close") > modal.index('id="event-detail-content"')


def test_the_page_writes_no_failure_handler_of_its_own():
    """htmx-errors.js is the one definition of what a 401 means. The old
    page had its own: loadThreatSummary redirected to /login?redirect=
    /security on a 401, which is one copy per page of that decision."""
    js = _script(PAGE.read_text(encoding="utf-8"))
    assert "htmx:responseError" not in js
    assert "htmx:sendError" not in js
    assert "htmx:afterRequest" not in js


def _markup(src: str) -> str:
    """The page with its scripts, styles and comments removed.

    An htmx attribute lives in markup, so searching the inline script for
    one can never fail: the three assertions this replaces were looking for
    `hx-on:`, `hx-vals` and `[key==` inside <script>, which is a region
    those attributes cannot occupy. Comments go too, because this page
    explains the attributes it does and does not use by name.
    """
    without_blocks = re.sub(
        r"<(script|style)\b[^>]*>.*?</\1>", "", src, flags=re.S,
    )
    return re.sub(r"<!--.*?-->|\{#.*?#\}", "", without_blocks, flags=re.S)


# ---------------------------------------------------------------------------
# Reads at security:read, writes at security:manage
# ---------------------------------------------------------------------------


_ACTIONS = (
    "quickBlockIP",
    "showBlockIPModal",
    "unblockIP",
)


def _rows(**over: Any) -> dict:
    """A dashboard with every card populated, so every control has a site."""
    ctx = dict(
        events=[event_view(_namespace())],
        blocked=[{
            "ip_address": "203.0.113.8", "permanent": True,
            "blocked_until": None,
        }],
        blocked_addresses={"203.0.113.8"},
        summary=_summary(top_attackers=[
            {"label": "198.51.100.4", "text": "198.51.100.4", "count": 9},
        ]),
    )
    ctx.update(over)
    return ctx


def test_a_viewer_who_can_manage_gets_every_action_control():
    """The other half of the gate. Without this, hiding the controls
    unconditionally would pass the test below."""
    html = dashboard(**_rows())
    for action in _ACTIONS:
        assert f'data-click-action="{action}"' in html, action
    assert "<th>Actions</th>" in html


def test_a_read_only_viewer_is_offered_no_action_control():
    """POST, DELETE and PATCH are all security:manage. A Block or Unblock
    button for a viewer holding only security:read has one possible answer
    and it is 403, so the old page made clicking the way to learn the
    rule."""
    html = dashboard(**_rows(can_manage=False))
    for action in _ACTIONS:
        assert action not in html, action
    assert "<th>Actions</th>" not in html
    # The records themselves are still there: this withholds the controls,
    # not the posture.
    assert "203.0.113.8" in html
    assert "198.51.100.4" in html
    assert "SQLi against the login form" in html
    assert "Permanent" in html


def test_a_read_only_viewer_gets_no_status_select_on_the_detail():
    html = detail(can_manage=False)
    assert 'id="event-status-select"' not in html
    assert "updateEventStatus" not in html
    # The status it has is still reported, just not as a control.
    assert "Sql Injection" in html


def test_the_empty_and_failed_rows_span_the_columns_that_exist():
    """A hard colspan leaves the error row wider than the head once the
    Actions column is gated away, which pushes the table sideways."""
    assert 'colspan="9"' in dashboard(events=[], can_manage=True)
    assert 'colspan="8"' in dashboard(events=[], can_manage=False)
    assert 'colspan="9"' in dashboard(events=None, events_failed=True)
    assert 'colspan="8"' in dashboard(
        events=None, events_failed=True, can_manage=False,
    )


def test_both_routes_hand_the_template_the_write_permission(app, read_only_app, session):
    """The context key, not just the template. Jinja renders a missing
    name as undefined, which is falsy, so a route that forgot to pass
    can_manage would withhold every control from an administrator and no
    template test would notice."""
    row = _event(session, source_ip="203.0.113.77")
    with TestClient(app) as client:
        board = client.get("/ui/security-dashboard")
        event = client.get(f"/ui/security-dashboard/events/{row.id}")
    assert 'data-click-action="quickBlockIP"' in board.text
    assert 'data-click-action="showBlockIPModal"' in board.text
    assert 'id="event-status-select"' in event.text

    with TestClient(read_only_app) as client:
        board = client.get("/ui/security-dashboard")
        event = client.get(f"/ui/security-dashboard/events/{row.id}")
    assert board.status_code == 200
    assert event.status_code == 200
    assert "quickBlockIP" not in board.text
    assert "showBlockIPModal" not in board.text
    assert "unblockIP" not in board.text
    assert 'id="event-status-select"' not in event.text
    # Reading is still allowed, and the row is still rendered.
    assert "203.0.113.77" in board.text


def test_the_fragment_itself_is_not_gated_on_the_write_permission(session):
    """The gate belongs on the control. Requiring security:manage to
    render would lock the read behind the write, which is the mirror of
    the defect above."""
    user = _User(PERMISSION)
    assert not user.has_permission(MANAGE_PERMISSION)
    with TestClient(_app(session, user)) as client:
        assert client.get("/ui/security-dashboard").status_code == 200
    with TestClient(_app(session, _User("something:else"))) as client:
        assert client.get("/ui/security-dashboard").status_code == 403


# ---------------------------------------------------------------------------
# Record state: a quick block of an address already blocked
# ---------------------------------------------------------------------------


def test_an_already_blocked_address_says_what_blocking_it_again_would_do():
    """BlockedIPRepository.block upserts. quickBlockIP posts 60 minutes
    and permanent=false, so on an address already blocked permanently the
    button marked Block IP shortens the block to an hour. The server
    accepts it, so the control is not withheld, but it must not read as a
    fresh block."""
    html = dashboard(**_rows(
        events=[event_view(_namespace(source_ip="203.0.113.8"))],
        summary=_summary(top_attackers=[
            {"label": "203.0.113.8", "text": "203.0.113.8", "count": 9},
        ]),
    ))
    assert "Already blocked" in html
    assert "replaces that block with 60 minutes" in html
    # Both sites, the table row and the top-IP list, read the same set.
    assert "Block IP for 60 minutes" not in html
    assert html.count("Already blocked") == 2


def test_an_unblocked_address_is_offered_a_plain_block():
    html = dashboard(**_rows(
        events=[event_view(_namespace(source_ip="203.0.113.10"))],
        blocked_addresses={"198.51.100.200"},
    ))
    assert "Block IP for 60 minutes" in html
    assert "Already blocked" not in html


def test_an_unreadable_block_list_does_not_claim_an_address_is_unblocked():
    """Three states. None is 'we could not look', and the quick block is
    still offered, because the server would accept the click. Rendering it
    as 'Block IP for 60 minutes' would be a claim nobody measured."""
    html = dashboard(
        events=[event_view(_namespace(source_ip="203.0.113.8"))],
        blocked=None, blocked_failed=True, blocked_addresses=None,
    )
    assert 'data-click-action="quickBlockIP"' in html
    assert "Already blocked" not in html


def test_the_address_set_keeps_an_unread_list_distinct_from_an_empty_one():
    assert _blocked_addresses(None) is None
    assert _blocked_addresses([]) == set()
    assert _blocked_addresses([
        {"ip_address": "203.0.113.8"}, {"ip_address": None},
    ]) == {"203.0.113.8"}


def test_the_route_derives_the_block_state_from_the_list_it_rendered(app, session):
    """Measured through the route rather than handed in, so the set cannot
    drift from the list on screen."""
    session.add(BlockedIP(
        ip_address="203.0.113.99", reason="manual", permanent=True,
    ))
    session.commit()
    _event(session, source_ip="203.0.113.99", title="repeat-offender")
    _event(session, source_ip="203.0.113.12", title="first-offence")
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert resp.status_code == 200
    flat = _flat(resp.text)
    assert "Already blocked" in flat
    assert "Block IP for 60 minutes" in flat


def test_the_unblock_control_is_not_withheld_for_a_state_that_never_refuses(app, session):
    """BlockedIPRepository.unblock matches any row by address, and every
    row the list renders is a row. A control withheld for a rule the
    server does not have is the same defect as one offered where it
    refuses, so this asserts the absence of that invention."""
    session.add(BlockedIP(
        ip_address="198.51.100.77", reason="manual", permanent=False,
        blocked_until=datetime.utcnow() + timedelta(hours=2),
    ))
    session.commit()
    with TestClient(app) as client:
        resp = client.get("/ui/security-dashboard")
    assert "198.51.100.77" in resp.text
    assert 'data-click-action="unblockIP"' in resp.text


def test_the_page_declares_no_htmx_feature_that_compiles_a_string():
    """ION serves no `unsafe-eval`, so anything htmx hands to Function()
    throws and the control silently does nothing. Asserted on the markup
    with the comments stripped: the page names `hx-on` in a comment."""
    markup = _markup(PAGE.read_text(encoding="utf-8"))
    assert "hx-get" in markup, "no htmx markup found, so this proves nothing"
    assert "hx-on" not in markup
    assert "hx-vals" not in markup
    assert "hx-headers" not in markup
    assert not re.search(r"hx-trigger=\"[^\"]*\[", markup)
