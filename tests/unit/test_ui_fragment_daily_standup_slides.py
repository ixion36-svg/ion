"""Presentation checks preserve unknown measurements and section failures."""
import asyncio
import json
import re
from enum import Enum
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from ion.web import daily_standup_api as api
from ion.web.templating import make_templates
from ion.web.ui import daily_standup_slides as page


def payload():
    return {"timestamp": "2026-10-12T12:00:00+00:00", "cluster_health": {"status": "green", "indices_count": 0},
            "critical_alerts": {"critical_count": 0, "alerts": []}, "stale_cases": {"count": 0, "cases": []},
            "open_alerts_30d": {"total": 0, "open": None}, "case_status_counts": {"open": 0},
            "dc_log_health": {"hosts_with_gaps": 0, "host_count": None},
            "wef_log_health": {"hosts_with_gaps": None, "host_count": 0}, "rule_failures": {"count": 0, "rules": []}}


def render(data):
    return make_templates().env.get_template('_fragments/daily_standup_slides.html').render(data=data)


def section(html, key):
    return html.split('data-slide="'+key+'"', 1)[1].split('data-slide=', 1)[0]


def request():
    return Request({"type": "http", "path": "/ui/daily-standup/slides", "headers": []})


def test_all_eleven_slides_and_progress_dots_are_server_markup():
    html = render(payload())
    assert html.count('data-slide="') == 11
    assert html.count('class="deck-progress-dot"') == 11
    assert 'data-name="Critical Alerts"' in html


def test_zero_and_unmeasured_figures_are_distinct():
    html = section(render(payload()), 'backlog')
    assert '>0</div>' in html
    assert '>Unknown</div>' in html
    assert 'Unknown% of' not in html
    assert 'Unknown of 30-day total' in html


@pytest.mark.parametrize('key,slide', [('cluster_health','cluster'), ('critical_alerts','criticals'),
    ('stale_cases','stale-cases'), ('open_alerts_30d','backlog'), ('case_status_counts','case-status'),
    ('rule_failures','rule-failures')])
def test_failed_sections_never_claim_zero_or_success(key, slide):
    data = payload()
    data[key] = {'error': 'offline'}
    html = section(render(data), slide)
    assert 'could not be read' in html and 'offline' in html
    assert 'stat-value' not in html and 'alert-success' not in html


def test_log_sources_fail_independently():
    data = payload()
    data['dc_log_health'] = {'error': 'DC offline'}
    html = section(render(data), 'log-health')
    assert 'Domain Controllers could not be read' in html
    assert 'Windows Event Forwarding could not be read' not in html
    assert '>0</div>' in html and '>Unknown</div>' in html


def test_missing_section_is_unknown_not_empty_success():
    data = payload()
    del data['stale_cases']
    html = section(render(data), 'stale-cases')
    assert 'could not be read' in html
    assert 'No stale cases' not in html


def test_alert_cap_discloses_omitted_rows_and_escapes_names():
    data = payload()
    data['critical_alerts'] = {'critical_count': 10, 'alerts': [
        {'rule_name': '<script>alert(1)</script>', 'timestamp': '2026-10-12T12:00:00Z', 'severity': 'high'} for _ in range(10)]}
    html = section(render(data), 'criticals')
    assert '+ 2 more alerts not shown' in html
    assert html.count('&lt;script&gt;alert(1)&lt;/script&gt;') == 8
    assert '<script>alert(1)</script>' not in html
    assert 'data-ts-local="yes"' in html


def test_stale_cases_are_not_silently_capped_and_zero_hours_survive():
    data = payload()
    data['stale_cases'] = {'count': 20, 'cases': [{'case_number': str(n), 'hours_open': 0} for n in range(20)]}
    html = section(render(data), 'stale-cases')
    assert html.count('<td>0h</td>') == 20


def test_failure_route_selects_failure_state_and_logs(monkeypatch, caplog):
    monkeypatch.setattr(page, 'daily_checks_payload', AsyncMock(side_effect=RuntimeError('offline')))
    response = asyncio.run(page.slides(request()))
    html = response.body.decode()
    assert 'Standup checks could not be read' in html
    assert 'stat-value' not in html
    assert any(r.exc_info for r in caplog.records)


def test_json_and_fragment_use_the_extracted_payload(monkeypatch):
    assert page.daily_checks_payload is api.daily_checks_payload
    reader = AsyncMock(return_value=payload())
    monkeypatch.setattr(api, 'daily_checks_payload', reader)
    response = asyncio.run(api.get_daily_checks(current_user=object()))
    assert json.loads(response.body)['critical_alerts']['critical_count'] == 0
    assert 'no-store' in response.headers['cache-control']
    reader.assert_awaited_once_with()
    reader.reset_mock()
    monkeypatch.setattr(page, 'daily_checks_payload', reader)
    response = asyncio.run(page.slides(request()))
    assert response.status_code == 200 and 'no-store' in response.headers['cache-control']
    reader.assert_awaited_once_with()


def test_enum_severity_is_unwrapped(monkeypatch):
    class Severity(str, Enum):
        HIGH = 'high'
    data = payload()
    data['critical_alerts']['alerts'] = [{'severity': Severity.HIGH, 'rule_name': 'Rule'}]
    monkeypatch.setattr(page, 'daily_checks_payload', AsyncMock(return_value=data))
    html = asyncio.run(page.slides(request())).body.decode()
    assert '>high</span>' in html and 'Severity.HIGH' not in html


def test_retry_is_outside_swapped_region_and_drafts_use_text_content():
    source = (Path(__file__).parents[2] / 'src/ion/web/templates/daily_standup_slides.html').read_text(encoding='utf-8')
    source = re.sub(r'<!--.*?-->|\{#.*?#\}|//[^\n]*', '', source, flags=re.S)
    button = re.search(r'<button[^>]*id="deck-refresh"[^>]*>', source).group()
    assert 'hx-get="/ui/daily-standup/slides"' in button and 'hx-target="#deck-content"' in button
    assert "if (text) el.textContent = text" in source
    assert '.innerHTML' not in source and 'const esc =' not in source
    html = render(payload())
    assert html.count('Browser draft from the live standup page') == 2
