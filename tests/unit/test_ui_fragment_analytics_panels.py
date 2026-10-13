"""The three uniform analytics list panels.

Rule noise, repeat offenders and entity risk share the job-state
foundation in test_ui_fragment_analytics.py, and share one more defect
between two of them: a missing figure falls through a chain of comparisons
to the most reassuring end of the scale.

  * `r.fp_ratio > 0.5 ? 'fp-high' : r.fp_ratio > 0.2 ? 'fp-med' :
    'fp-low'`. Both comparisons are false for undefined, so a rule whose
    false-positive ratio the job did not record was painted as a low-FP
    rule: the one colour that says leave this one alone.
  * `e.risk_score >= 100 ? 'critical' : ... : 'low'`, the same shape, so
    an entity with no risk score was drawn as low risk.

And two that affect a whole chart rather than one row:

  * `Math.max(...rules.map(r => r.alert_count), 1)` is NaN if any single
    count is not a number, so every bar width became the string "NaN%".
  * `entities[0]?.risk_score || 1` took the scale from the first row, so a
    first row without a score rescaled every bar.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.analytics import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/analytics.html"

NOISE = "/ui/analytics/rule-noise"
OFFENDERS = "/ui/analytics/repeat-offenders"
RISK = "/ui/analytics/entity-risk"


class _User:
    id = 1
    username = "analytics-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(user, url):
    with TestClient(_app(user)) as client:
        return client.get(url)


def _reader():
    return _User(PERMISSION)


@pytest.fixture
def job(monkeypatch):
    def set(result):
        def handler(job_type, current_user=None, session=None):
            return {"job_type": job_type, "display_name": "X",
                    "last_run_at": "2026-09-01T10:30:00",
                    "last_error": None, "result": result}

        monkeypatch.setattr(
            "ion.web.analytics_api.get_analytics_job", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


# ---------------------------------------------------------------------------
# The job types themselves
# ---------------------------------------------------------------------------


def test_the_job_types_come_from_the_enum_not_a_literal():
    """I first wrote "entity_risk" where the registered type is
    "entity_risk_score", which would have rendered every visit to that
    panel as "this job is not registered". AnalyticsJobType is the source.
    """
    module = (ROOT / "src/ion/web/ui/analytics.py").read_text(
        encoding="utf-8")
    for member in ("ENTITY_RISK_SCORE", "RULE_NOISE", "REPEAT_OFFENDERS",
                   "STALE_INVESTIGATIONS"):
        assert "AnalyticsJobType." + member + ".value" in module, member
    assert '"entity_risk"' not in module


# ---------------------------------------------------------------------------
# Rule noise
# ---------------------------------------------------------------------------


def test_a_rule_with_no_fp_ratio_is_not_painted_as_low_fp(job):
    job(result={"rules": [{"rule_name": "unmeasured", "alert_count": 10}]})
    html = _get(_reader(), NOISE).text
    assert "fp-unmeasured" in html
    assert "noise-bar-fill fp-low" not in html


@pytest.mark.parametrize("ratio,band", [
    (0.9, "fp-high"), (0.3, "fp-med"), (0.1, "fp-low"),
])
def test_a_measured_ratio_keeps_its_band(job, ratio, band):
    job(result={"rules": [
        {"rule_name": "r", "alert_count": 5, "fp_ratio": ratio}]})
    assert "noise-bar-fill " + band in _get(_reader(), NOISE).text


def test_one_unreadable_alert_count_does_not_erase_the_chart(job):
    job(result={"rules": [
        {"rule_name": "good", "alert_count": 10, "fp_ratio": 0.1},
        {"rule_name": "bad", "alert_count": "lots", "fp_ratio": 0.1}]})
    html = _get(_reader(), NOISE).text
    assert "NaN" not in html
    assert "width: 100.0%" in html or "width: 100%" in html
    assert "good" in flat(html)
    assert "bad" in flat(html)


def test_the_noise_legend_carries_no_hard_coded_colour(job):
    job(result={"rules": [
        {"rule_name": "r", "alert_count": 1, "fp_ratio": 0.1}]})
    html = _get(_reader(), NOISE).text
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "fp-low-text" in html


# ---------------------------------------------------------------------------
# Repeat offenders
# ---------------------------------------------------------------------------


def test_an_entity_type_cannot_escape_its_class_attribute(job):
    """The page wrote the value straight into a class attribute."""
    hostile = 'a" onload="alert(1)'
    job(result={"offenders": [
        {"entity": "web-01", "type": hostile, "count_7d": 1,
         "count_30d": 2, "rules": []}]})
    html = _get(_reader(), OFFENDERS).text
    assert 'onload="alert(1)"' not in html
    assert "entity-type-badge unknown" in html
    # The real text is still shown to the reader, as text.
    assert "onload=" in flat(html)


def test_a_sane_entity_type_keeps_its_own_class(job):
    job(result={"offenders": [
        {"entity": "web-01", "type": "host", "count_7d": 1,
         "count_30d": 2, "rules": []}]})
    assert "entity-type-badge host" in _get(_reader(), OFFENDERS).text


def test_a_missing_rule_list_is_not_reported_as_zero_rules(job):
    """`(o.rules || []).length` counted a list we were not given."""
    job(result={"offenders": [
        {"entity": "web-01", "type": "host", "count_7d": 1,
         "count_30d": 2}]})
    html = _get(_reader(), OFFENDERS).text
    assert "0 rules" not in flat(html)
    assert "an-absent" in html


def test_an_empty_rule_list_does_say_zero_rules(job):
    job(result={"offenders": [
        {"entity": "web-01", "type": "host", "count_7d": 1,
         "count_30d": 2, "rules": []}]})
    assert "0 rules" in flat(_get(_reader(), OFFENDERS).text)


@pytest.mark.parametrize("field", ["count_7d", "count_30d"])
def test_a_missing_count_is_not_printed_as_undefined(job, field):
    row = {"entity": "web-01", "type": "host", "count_7d": 1,
           "count_30d": 2, "rules": []}
    row.pop(field)
    job(result={"offenders": [row]})
    html = _get(_reader(), OFFENDERS).text
    assert "undefined" not in html
    assert "an-absent" in html


# ---------------------------------------------------------------------------
# Entity risk
# ---------------------------------------------------------------------------


def test_an_entity_with_no_risk_score_is_not_drawn_as_low_risk(job):
    job(result={"entities": [{"entity": "web-01", "type": "host"}]})
    html = _get(_reader(), RISK).text
    assert "risk-bar low" not in html
    assert "an-absent" in html


@pytest.mark.parametrize("score,band", [
    (150, "critical"), (60, "high"), (25, "medium"), (5, "low"),
])
def test_a_measured_score_keeps_its_band(job, score, band):
    job(result={"entities": [
        {"entity": "e", "type": "host", "risk_score": score}]})
    assert "risk-bar " + band in _get(_reader(), RISK).text


def test_the_scale_is_the_largest_score_not_the_first_row(job):
    """`entities[0]?.risk_score || 1` took the scale from the first row."""
    job(result={"entities": [
        {"entity": "nofigure", "type": "host"},
        {"entity": "big", "type": "host", "risk_score": 200},
        {"entity": "small", "type": "host", "risk_score": 100}]})
    html = _get(_reader(), RISK).text
    assert "width: 100.0%" in html or "width: 100%" in html
    assert "width: 50.0%" in html or "width: 50%" in html


def test_bar_widths_use_the_hook_that_survives_a_swap(job):
    """The page set them from data-pct with an applyBarWidths() pass over
    the whole document. data-ion-style is applied on a MutationObserver,
    so it lands after an htmx swap without the fragment asking."""
    job(result={"entities": [
        {"entity": "e", "type": "host", "risk_score": 10}]})
    html = _get(_reader(), RISK).text
    assert "data-ion-style" in html
    assert "data-pct" not in html


# ---------------------------------------------------------------------------
# What all three share
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,key", [
    (NOISE, "rules"), (OFFENDERS, "offenders"), (RISK, "entities"),
])
def test_every_panel_tells_an_unreadable_list_from_an_empty_one(
        job, url, key):
    job(result={key: "broken"})
    assert "not in a shape" in flat(_get(_reader(), url).text), url
    job(result={key: []})
    assert "not in a shape" not in flat(_get(_reader(), url).text), url


@pytest.mark.parametrize("url", [NOISE, OFFENDERS, RISK])
def test_every_panel_needs_the_pages_permission(job, url):
    job(result={"rules": [], "offenders": [], "entities": []})
    assert _get(_User(), url).status_code == 403
    assert _get(_reader(), url).status_code == 200


@pytest.mark.parametrize("url", [NOISE, OFFENDERS, RISK])
def test_every_panel_separates_never_run_from_unreadable(job, url):
    job(result=None)
    assert "Run All Jobs" in flat(_get(_reader(), url).text), url
    job(result="oops")
    assert "cannot read" in flat(_get(_reader(), url).text), url


@pytest.mark.parametrize("url", [NOISE, OFFENDERS, RISK])
def test_no_panel_ships_a_colour_or_an_inline_style(job, url):
    job(result={"rules": [{"rule_name": "r", "alert_count": 1,
                           "fp_ratio": 0.1}],
                "offenders": [{"entity": "e", "type": "host",
                               "count_7d": 1, "count_30d": 1,
                               "rules": []}],
                "entities": [{"entity": "e", "type": "host",
                              "risk_score": 10}]})
    html = _get(_reader(), url).text
    assert not re.search(r'\sstyle="', html), url
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html), url


def test_the_page_builds_none_of_the_three_panels():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    for name in ("renderRuleNoise", "renderRepeatOffenders",
                 "renderEntityRisk"):
        block = re.search(r"\bfunction " + name + r"\(.*?\n\}", body, re.S)
        assert block, name
        assert not re.search(r"\.innerHTML\s*=", block.group(0)), name
        assert "htmx.ajax" in block.group(0), name
