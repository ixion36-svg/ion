"""Permission, state and read-failure behavior for shift transfers."""
import asyncio
import re
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from starlette.requests import Request

from ion.services import shift_handover_record_service as service
from ion.web.templating import make_templates
from ion.web.ui import shift_handover as page


def request():
    return Request({"type": "http", "path": "/ui/shift-handover", "headers": []})


def user(actor=1, write=True):
    return SimpleNamespace(id=actor, username="Analyst", has_permission=lambda permission: write)


def handover(status="draft", incoming=2):
    return {"id": 7, "status": status, "outgoing_lead_id": 1, "incoming_lead_id": incoming,
            "outgoing_lead": "Night", "incoming_lead": "Day", "summary": "<script>alert(1)</script>",
            "shift_hours": 0, "snapshot_taken_at": "2026-10-12T12:00:00Z", "actions": [],
            "open_action_count": 0, "overdue_action_count": None, "unowned_action_count": 0,
            "changes_since_previous": {"baseline": None}, "snapshot": {}}


def render(fragment, **context):
    return make_templates().env.get_template('_fragments/shift_handover_'+fragment+'.html').render(**context)


def detail(monkeypatch, data, actor=1, write=True):
    reader = Mock(return_value=data)
    monkeypatch.setattr(page.handovers, 'get_handover', reader)
    monkeypatch.setattr(page, 'list_assignable_users', AsyncMock(return_value={"users": [
        {"id": 1, "username": "Night"}, {"id": 2, "username": "Day"}]}))
    response = asyncio.run(page.detail(request(), 7, user(actor, write), Mock()))
    reader.assert_called_once_with(reader.call_args.args[0], 7)
    return response.body.decode()


@pytest.mark.parametrize('status,actor,incoming,allowed', [
    ('draft',1,2,{'shSubmit','shSetIncoming','shAddAction'}),
    ('draft',1,None,{'shSetIncoming','shAddAction'}),
    ('draft',2,2,{'shAddAction'}),
    ('submitted',1,2,{'shAddAction'}),
    ('submitted',2,2,{'shAccept','shReject','shAddAction'}),
    ('submitted',3,2,{'shAccept','shReject','shAddAction'}),
    ('rejected',1,2,{'shSubmit','shAddAction'}),
    ('accepted',2,2,set()), ('unexpected',1,2,set())])
def test_buttons_match_service_state_and_actor(monkeypatch, status, actor, incoming, allowed):
    html = detail(monkeypatch, handover(status, incoming), actor)
    controls = set(re.findall(r'data-click-action="([^"]+)"', html))
    assert controls == allowed


@pytest.mark.parametrize('status', ['draft','submitted','accepted','rejected'])
def test_readers_get_no_write_controls(monkeypatch, status):
    data = handover(status)
    data['actions'] = [{'id': 9, 'status': 'open', 'description': 'Work', 'carry_count': 0}]
    html = detail(monkeypatch, data, actor=2, write=False)
    assert 'data-click-action=' not in html and '<input' not in html and '<select' not in html


@pytest.mark.parametrize('status,allowed', [('open',True),('done',False),('cancelled',False),('other',False)])
def test_only_open_actions_can_be_resolved_even_after_acceptance(monkeypatch, status, allowed):
    data = handover('accepted')
    data['actions'] = [{'id': 9, 'status': status, 'description': 'Work', 'carry_count': 0, 'overdue': False}]
    html = detail(monkeypatch, data, actor=2)
    assert ('shCompleteAction' in html) is allowed
    assert ('shCancelAction' in html) is allowed
    assert 'shAddAction' not in html
    assert 'carried ×0' in html


def test_detail_numbers_escaping_and_timestamp(monkeypatch):
    html = detail(monkeypatch, handover())
    assert '0 open · Unknown overdue · 0 unowned' in html and '0h' in html
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html and '<script>alert(1)</script>' not in html
    assert 'data-ts-local="yes"' in html


@pytest.mark.parametrize('flag,wording', [(True,'Accepted by the named'),(False,'who was not the named'),
                                       (None,'acceptor was the named incoming lead is unknown'),
                                       ('false','acceptor was the named incoming lead is unknown')])
def test_acceptance_is_three_state(monkeypatch, flag, wording):
    data = handover('accepted')
    data['accepted_by_designated_lead'] = flag
    assert wording in detail(monkeypatch, data)


@pytest.mark.parametrize('flag,wording', [(True,'>Overdue<'),(False,'Not overdue'),
                                       (None,'Deadline status unknown'),('false','Deadline status unknown')])
def test_overdue_is_three_state(monkeypatch, flag, wording):
    data = handover()
    data['actions'] = [{'id': 9, 'status': 'done', 'overdue': flag}]
    assert wording in detail(monkeypatch, data)


def test_report_zero_and_unmeasured_are_distinct():
    html = render('report', data={'alerts': {'total_triaged': 0}, 'cases': {}, 'pending': {}, 'watches': {}})
    assert '>0</div>' in html and '>Unknown</div>' in html
    assert 'Case list unknown' in html and 'No cases recorded' not in html


def test_transfers_zero_empty_missing_and_unreadable_are_distinct():
    html = render('transfers', rows=[], metrics={'unaccepted_count':0})
    assert '>0</div>' in html and '>Unknown</div>' in html and 'No handover has been raised' in html
    html = render('transfers', rows=None, metrics=None)
    assert 'Transfers could not be read' in html and 'Transfer metrics could not be read' in html
    assert 'stat-value' not in html and 'No handover has been raised' not in html


def test_report_failure_uses_real_route_and_logs(monkeypatch, caplog):
    monkeypatch.setattr(page, 'get_shift_report', Mock(side_effect=RuntimeError('offline')))
    html = page.report(request(), 8, user(), Mock()).body.decode()
    assert 'Shift report could not be read' in html and 'stat-value' not in html
    assert any(r.exc_info for r in caplog.records)


def test_detail_failure_is_not_empty_and_logs(monkeypatch, caplog):
    monkeypatch.setattr(page.handovers, 'get_handover', Mock(side_effect=RuntimeError('offline')))
    html = asyncio.run(page.detail(request(),7,user(),Mock())).body.decode()
    assert 'Handover could not be read' in html
    assert 'Nothing recorded' not in html and 'data-click-action' not in html
    assert any(r.exc_info for r in caplog.records)


def test_transfer_list_and_metrics_fail_independently(monkeypatch, caplog):
    monkeypatch.setattr(page.handovers,'list_handovers',Mock(side_effect=RuntimeError('offline')))
    monkeypatch.setattr(page.handovers,'handover_metrics',Mock(return_value={'unaccepted_count':0}))
    session = Mock()
    html = page.transfers(request(),session).body.decode()
    assert 'Transfers could not be read' in html and '>0</div>' in html
    session.rollback.assert_called_once_with()
    monkeypatch.setattr(page.handovers,'list_handovers',Mock(return_value=[]))
    monkeypatch.setattr(page.handovers,'handover_metrics',Mock(side_effect=RuntimeError('offline')))
    html = page.transfers(request(),session).body.decode()
    assert 'Transfer metrics could not be read' in html and 'No handover has been raised' in html
    assert len([r for r in caplog.records if r.exc_info]) == 2


def test_assignment_failure_is_visible_not_no_people(monkeypatch, caplog):
    monkeypatch.setattr(page,'list_assignable_users',AsyncMock(side_effect=RuntimeError('offline')))
    html = asyncio.run(page.leads(request(),user(),Mock())).body.decode()
    assert 'Incoming leads could not be read' in html and '<select' not in html
    monkeypatch.setattr(page.handovers,'get_handover',Mock(return_value=handover()))
    html = asyncio.run(page.detail(request(),7,user(),Mock())).body.decode()
    assert 'Assignment choices could not be read' in html and 'shSetIncoming' not in html
    assert any(r.exc_info for r in caplog.records)


def test_assignment_picker_excludes_self_and_requires_write(monkeypatch):
    monkeypatch.setattr(page,'list_assignable_users',AsyncMock(return_value={'users':[
        {'id':1,'username':'SELF'}, {'id':2,'username':'Other'}]}))
    html = asyncio.run(page.leads(request(),user(),Mock())).body.decode()
    assert 'SELF' not in html and 'Other' in html
    assert '<select' not in asyncio.run(page.leads(request(),user(write=False),Mock())).body.decode()


def test_shared_report_reader_receives_hours_user_and_session(monkeypatch):
    reader = Mock(return_value={})
    monkeypatch.setattr(page,'get_shift_report',reader)
    actor,session = user(),Mock()
    page.report(request(),12,actor,session)
    reader.assert_called_once_with(hours=12,session=session,current_user=actor)


def test_enum_fields_and_keys_are_unwrapped():
    class Status(str,Enum):
        OPEN='open'
    normalized = page.normalize({Status.OPEN:[{'status':Status.OPEN,'count':0}]})
    assert normalized == {'open':[{'status':'open','count':0}]}
    assert type(next(iter(normalized))) is str
    assert type(normalized['open'][0]['status']) is str


def test_every_read_uses_the_exact_api_permission_factory():
    from ion.auth.dependencies import require_permission
    expected = require_permission('alert:read')
    assert len(page.router.routes) == 5
    for route in page.router.routes:
        guards = [d.call for d in route.dependant.dependencies
                  if getattr(d.call, '__code__', None) is expected.__code__]
        assert len(guards) == 1, route.path
        assert [c.cell_contents for c in guards[0].__closure__] == ['alert:read']


def test_zero_delta_and_absent_baseline_are_distinct(monkeypatch):
    data = handover()
    data['changes_since_previous'] = {'baseline':0,'metrics':[
        {'label':'Open','current':0,'delta':0,'direction':'flat'},
        {'label':'Other','current':None,'delta':None,'direction':'unknown'}]}
    html = detail(monkeypatch,data)
    assert 'Open: 0 · flat 0' in html and 'Other: Unknown · no baseline' in html
    assert 'Against #0' in html


def test_shell_controls_survive_swaps_and_mutations_refresh():
    source = (Path(__file__).parents[2]/'src/ion/web/templates/shift_handover.html').read_text(encoding='utf-8')
    source = re.sub(r'<!--.*?-->|\{#.*?#\}|//[^\n]*','',source,flags=re.S)
    refresh = re.search(r'<button[^>]*id="sh-refresh"[^>]*>',source).group()
    target = re.search(r'<div[^>]*id="sh-content"[^>]*>',source).group()
    assert 'hx-get="/ui/shift-handover/report"' in refresh and 'hx-include="#sh-hours"' in refresh
    assert 'hx-include="#sh-hours"' in target and 'hx-disinherit="hx-include"' in target
    assert source.index('id="sh-detail-close"') < source.index('id="sh-detail"')
    assert 'await shLoadTransfers();' in source and "'/incoming-lead'" in source
    assert '.innerHTML' not in source and 'function esc(' not in source
    writer = page.controls(request(), user()).body.decode()
    assert writer.index('id="sh-leads-refresh"') < writer.index('id="sh-leads"')
    assert 'shOpenRaiseModal' in writer
    assert 'shOpenRaiseModal' not in page.controls(request(), user(write=False)).body.decode()
    dialog = re.search(r'<dialog[^>]*id="sh-raise-modal"[^>]*>', writer).group()
    assert 'class="modal"' not in dialog
    assert "$('sh-raise-modal').showModal()" in source and "$('sh-raise-modal').close()" in source
