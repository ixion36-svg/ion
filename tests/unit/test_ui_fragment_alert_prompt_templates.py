"""Guards for the alert prompt fragment's measured, missing and failed states."""
from enum import Enum
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from ion.auth.dependencies import get_current_user
from ion.web.templating import make_templates
from ion.web.ui import alert_prompt_templates as page


def item(**overrides):
    return dict({"id": 7, "name": "Prompt seven", "description": "Guide", "rule_ids": ["1100"],
                 "rule_groups": ["sysmon"], "rule_id_pattern": "^11", "priority": 0,
                 "severity_hint": "high", "enabled": True, "mitre_techniques": ["T1059"],
                 "mitre_tactics": ["execution"]}, **overrides)


def card(**overrides):
    return dict({"sample_size": 10, "evaluated": 2, "agreement_pct": 0,
                 "tp_rate": 0, "fp_rate": None, "btp_rate": 25,
                 "tuning_needed": True}, **overrides)


def render(rows=None, cards=None, **overrides):
    cards = {7: card()} if cards is None else cards
    context = dict(items=[item()] if rows is None else rows,
                   scorecards=cards, summary=page.scorecard_summary(cards),
                   failed=False, scores_failed=False)
    context.update(overrides)
    return make_templates().env.get_template("_fragments/alert_prompt_templates.html").render(**context)


def route(monkeypatch, rows=None, cards=None, list_error=False, score_error=False):
    listing = Mock(return_value={"templates": [item()] if rows is None else rows})
    scoring = Mock(return_value={"scorecards": {7: card()} if cards is None else cards})
    if list_error:
        listing.side_effect = RuntimeError("list offline")
    if score_error:
        scoring.side_effect = RuntimeError("scores offline")
    monkeypatch.setattr(page, "list_alert_prompts", listing)
    monkeypatch.setattr(page, "get_all_scorecards", scoring)
    session = object()
    request = Request({"type": "http", "path": "/ui/alert-prompts", "headers": []})
    response = page.alert_prompt_templates_fragment(request, enabled_only=True, session=session)
    return response.body.decode(), listing, scoring, session


def test_shared_readers_receive_filter_and_session(monkeypatch):
    html, listing, scoring, session = route(monkeypatch)
    listing.assert_called_once_with(enabled_only=True, session=session)
    scoring.assert_called_once_with(window_days=30, session=session)
    for value in ("Prompt seven", "1100", "sysmon", "^11", "T1059", "execution", "badge-warning"):
        assert value in html


def test_zero_measurements_survive_and_missing_rates_are_unknown():
    html = " ".join(render().split())
    assert "<td>0</td>" in html
    assert "<strong>0%</strong>" in html
    assert "TP 0%" in html
    assert "FP Unknown" in html
    assert "BTP 25%" in html


def test_missing_sample_and_priority_do_not_become_zero():
    row = item()
    row["priority"] = None
    html = " ".join(render([row], {7: card(sample_size=None)}).split())
    assert "<td>Unknown</td>" in html
    assert "n=Unknown" in html
    assert 'id="sc-kpi-samples" class="stat-value">Unknown<' in html


def test_zero_sample_count_is_a_measurement():
    html = " ".join(render(cards={7: card(sample_size=0, evaluated=0, agreement_pct=None)}).split())
    assert "n=0" in html
    assert "<strong>Unknown</strong>" in html


@pytest.mark.parametrize("value,label", [(True, "Enabled"), (False, "Disabled"), (None, "Unknown"), (1, "Unknown")])
def test_enabled_is_three_state_not_truthiness(value, label):
    row = item()
    row["enabled"] = value
    html = render([row])
    assert f">{label}</span>" in html


@pytest.mark.parametrize("value,expected", [(True, "tune</span>"), (False, None), (None, "Tuning unknown"), (1, "Tuning unknown")])
def test_tuning_is_three_state_not_truthiness(value, expected):
    html = render(cards={7: card(tuning_needed=value)})
    if expected:
        assert expected in html
    else:
        assert "tune</span>" not in html and "Tuning unknown" not in html


def test_jinja_escapes_script_in_names_chips_and_action_arguments():
    row = item()
    attack = "<script>alert(1)</script>"
    row.update(name=attack, rule_ids=[attack], description=attack, rule_id_pattern=attack)
    html = render([row])
    assert attack not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "\\u003cscript\\u003e" in html


def test_absent_scorecard_is_no_data_not_zero():
    html = render(cards={})
    assert "no data" in html
    assert "n=0" not in html


def test_summary_uses_evaluated_denominator_and_preserves_missing_values():
    cards = {7: card(sample_size=100, evaluated=2, agreement_pct=50),
             8: card(sample_size=10, evaluated=8, agreement_pct=100, tuning_needed=False)}
    assert page.scorecard_summary(cards) == dict(templates=2, samples=110, agreement=90, tuning=1)
    assert page.scorecard_summary({}) == dict(templates=0, samples=0, agreement=None, tuning=0)
    for field in ("sample_size", "evaluated", "agreement_pct", "tuning_needed"):
        broken = card(**{field: None})
        result = page.scorecard_summary({7: broken})
        assert result[{"sample_size": "samples", "evaluated": "agreement", "agreement_pct": "agreement", "tuning_needed": "tuning"}[field]] is None


def test_list_failure_is_selected_by_route_and_logged(monkeypatch, caplog):
    html, *_ = route(monkeypatch, list_error=True)
    html = " ".join(html.split())
    assert "Prompt templates could not be read" in html
    assert "not an empty list" in html
    assert "No templates match" not in html
    assert any(r.exc_info for r in caplog.records)


def test_score_failure_is_selected_by_route_not_empty_or_zero(monkeypatch, caplog):
    html, *_ = route(monkeypatch, score_error=True)
    assert "AI scorecards could not be read" in html
    assert "Prompt seven" in html
    assert "no data" not in html
    assert "stat-value" not in html
    assert any(r.exc_info for r in caplog.records)


def test_empty_list_is_distinct_from_read_failure():
    html = render(rows=[], cards={})
    assert "No templates match this filter" in html
    assert "could not be read" not in html


def test_enum_severity_is_unwrapped_by_route(monkeypatch):
    class Severity(str, Enum):
        HIGH = "high"
    row = item()
    row["severity_hint"] = Severity.HIGH
    html, *_ = route(monkeypatch, rows=[row])
    assert ">high</span>" in html
    assert "Severity.HIGH" not in html


def test_fragment_requires_read_permission_not_write_permission(monkeypatch):
    app = FastAPI()
    app.include_router(page.router, prefix="/ui")
    client = TestClient(app)
    assert client.get("/ui/alert-prompts").status_code == 401
    app.dependency_overrides[get_current_user] = lambda: type("User", (), {"has_any_permission": lambda self, names: "playbook:update" in names})()
    assert client.get("/ui/alert-prompts").status_code == 403
    app.dependency_overrides[get_current_user] = lambda: type("User", (), {"has_any_permission": lambda self, names: "playbook:read" in names})()
    app.dependency_overrides[page.get_db_session] = lambda: object()
    monkeypatch.setattr(page, "list_alert_prompts", lambda **kw: {"templates": []})
    monkeypatch.setattr(page, "get_all_scorecards", lambda **kw: {"scorecards": {}})
    response = client.get("/ui/alert-prompts")
    assert response.status_code == 200
    assert "No templates match" in response.text


def test_controls_survive_swaps_and_mutations_request_fragment():
    shell = (Path(__file__).parents[2] / "src/ion/web/templates/alert_prompt_templates.html").read_text(encoding="utf-8")
    before, target = shell.split('<div id="prompts-content"', 1)
    assert 'id="filter-enabled-only"' in before
    assert '>Refresh</button>' in before
    assert 'hx-trigger="load, promptsChanged"' in target
    assert 'hx-include="#filter-enabled-only"' in target
    assert "htmx.trigger(document.getElementById('prompts-content'), 'promptsChanged')" in shell
    assert shell.count("    loadPrompts();") == 2
    for banned in (".innerHTML", "insertAdjacentHTML", ".outerHTML", "function esc(", "_cache", "hx-on=", "js:"):
        assert banned not in shell
