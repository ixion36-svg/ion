"""Memory rendering, live gates, shared reads and independent failures."""
import inspect
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from starlette.requests import Request
from ion.auth.dependencies import require_permission
from ion.web.ui import investigation_memory as page


def render(region,data):
    return page.templates.env.get_template('_fragments/investigation_memory_'+region+'.html').render(data=data,plain=page.plain)


def test_exact_live_permission_factory():
    factory=require_permission('probe').__code__
    assert len(page.router.routes)==5
    for route in page.router.routes:
        guard=next(d.call for d in route.dependant.dependencies if getattr(d.call,'__code__',None) is factory)
        assert inspect.getclosurevars(guard).nonlocals['permission_name']=='alert:read'
    for route in page.api.router.routes:
        if route.path.startswith('/api/'):
            guard=next(d.call for d in route.dependant.dependencies if getattr(d.call,'__code__',None) is factory)
            assert inspect.getclosurevars(guard).nonlocals['permission_name']=='alert:read'


@pytest.mark.parametrize('region,endpoint,kwargs',[
 ('investigations','list_investigations_endpoint',{}),('iocs','list_iocs_endpoint',{}),
 ('fps','list_fps_endpoint',{}),('review','knowledge_review_endpoint',{}),
 ('detail','get_investigation_endpoint',{'inv_id':3})])
def test_failure_is_logged_and_not_empty(monkeypatch,caplog,region,endpoint,kwargs):
    monkeypatch.setattr(page.api,endpoint,Mock(side_effect=RuntimeError('unavailable')))
    result=getattr(page,region)(Request({'type':'http','headers':[]}),db=object(),user=object(),**kwargs)
    html=result.body.decode()
    assert 'Could not read' in html
    assert 'Retry the read' in html
    assert 'No FP signatures yet' not in html and 'Nothing needs review' not in html
    assert any(r.exc_info for r in caplog.records)


def test_filters_reuse_api_and_preserve_false(monkeypatch):
    spy=Mock(return_value={'iocs':[]}); monkeypatch.setattr(page.api,'list_iocs_endpoint',spy)
    page.iocs(Request({'type':'http','headers':[]}),ioc_type='url',is_known_bad=False,db='db',user='actor')
    assert spy.call_args.kwargs==dict(ioc_type='url',is_known_bad=False,limit=100,offset=0,db='db',user='actor')
    spy=Mock(return_value={'investigations':[]}); monkeypatch.setattr(page.api,'list_investigations_endpoint',spy)
    page.investigations(Request({'type':'http','headers':[]}),alert_signature=' x ',host=' h ',verdict='benign',status='completed',from_date='2026-01-01',to_date='2026-02-01',db='db',user='actor')
    assert spy.call_args.kwargs==dict(alert_signature='x',host='h',verdict='benign',status='completed',from_date='2026-01-01',to_date='2026-02-01',limit=50,offset=0,db='db',user='actor')


def test_fps_zero_missing_and_escape():
    row=dict(id=1,enabled=True,rule_name='<script>x</script>',rule_id=None,alert_signature=None,host_pattern=None,user_pattern=None,confidence=0,hit_count=0,last_matched_at='2026-10-12T12:00:00Z',reason='<b>why</b>')
    html=render('fps',{'fps':[row]})
    assert '<td>0%</td><td>0</td>' in html
    assert '&lt;script&gt;x&lt;/script&gt;' in html and '<script>' not in html
    assert '&lt;b&gt;why&lt;/b&gt;' in html and '<b>why</b>' not in html
    assert 'datetime="2026-10-12T12:00:00+00:00"' in html
    row.update(confidence=None,hit_count=None)
    assert '<td>-</td><td>-</td>' in render('fps',{'fps':[row]})


def test_detail_zero_observation_and_tokens():
    row=dict(alert_id_ref='a',alert_signature='sig',host=None,user_name=None,llm_model_used=None,status='completed',verdict=None,severity_assessment=None,tokens_used=0,duration_ms=0,created_at=None,completed_at=None,summary_text=None,key_observations=[dict(field='count',value=0,significance='<bad>')],recommended_actions=None,ioc_snapshot=None)
    html=render('detail',row)
    assert 'Tokens: 0' in html and 'Duration: 0 ms' in html and '</code>: 0' in html
    assert '&lt;bad&gt;' in html


def test_ioc_unknown_false_zero_and_slashes():
    row=dict(ioc_type='url',ioc_value='https://host/a/b',seen_count=0,first_seen_at=None,last_seen_at=None,is_known_bad=None,is_known_good=False,last_investigation_id=0)
    html=render('iocs',{'iocs':[row]})
    assert 'https://host/a/b' in html and '<td>0</td>' in html and '#0' in html
    assert 'bad: unknown' in html and 'good: unknown' not in html


def test_enum_values():
    class Status(str,Enum): COMPLETED='completed'
    row=dict(id=1,created_at=None,alert_signature='sig',host=None,user_name=None,status=Status.COMPLETED,verdict=None,severity_assessment=None,duration_ms=None)
    html=render('investigations',{'investigations':[row]})
    assert 'Status.COMPLETED' not in html and '>completed<' in html


def review_item(**over):
    return dict(dict(kind='repeated_uncertainty',title='<tag>',owner=None,why='why',action='act',link='javascript:alert(1)',evidence=dict(abstentions=0,sample_size=0,abstention_rate=0,window_days=0,min_sample_size=0,threshold_rate=0)),**over)


def test_review_safety_denominators_zero_and_unknown():
    item=review_item(); payload=dict(items=[item],total=0,by_kind={},window_days=0)
    html=render('review',payload)
    assert 'Abstentions: 0 of 0 (0%)' in html and '0 closures and 0%' in html
    assert 'javascript:' not in html and '&lt;tag&gt;' in html
    item['evidence'].update(abstention_rate=None,threshold_rate=None)
    html=render('review',payload)
    assert 'unknown rate' in html and 'unknown threshold' in html
    item['link']='/investigation-memory'; assert 'href="/investigation-memory"' in render('review',payload)


@pytest.mark.parametrize('kind,evidence,expected',[
 ('expired_quirk',dict(days_lapsed=0,review_date='2026-10-12T00:00:00Z',annotation='note'),'Lapsed for 0 day(s)'),
 ('stale_fp_signature',dict(governance_state='expired',hit_count=0,last_matched_at=None,review_date=None,reason='why'),'Suppressed: 0 alert(s)'),
 ('contradictory_outcome',dict(verdicts=['benign','false_positive'],closures=[dict(human_verdict='benign',closed_by=None,closed_by_id=0,closed_at=None)]),'user 0')])
def test_review_evidence_kinds(kind,evidence,expected):
    html=render('review',dict(items=[review_item(kind=kind,evidence=evidence)],total=1,by_kind={},window_days=30))
    assert expected in html


def test_shell_mutations_retry_and_no_markup_writes():
    shell=Path('src/ion/web/templates/investigation_memory.html').read_text(encoding='utf-8')
    assert 'innerHTML =' not in shell and '.innerHTML' not in shell and 'imEscape' not in shell
    assert 'parseInt(payload.confidence, 10) ||' not in shell
    assert 'parseInt(payload.confidence, 10)' in shell
    assert 'review:imLoadReviewInbox' in shell
    assert '.showModal()' in shell and '.close()' in shell and '.style.display' not in shell
    from bs4 import BeautifulSoup
    soup=BeautifulSoup(shell,'html.parser')
    for key in ['inv','iocs','fps','review','detail']:
        retry=soup.find(id='im-retry-'+key)
        assert retry is not None
        assert not retry.find_parent(attrs={'hx-get':True})
    assert soup.find(id='im-inv-modal-body').find_parent('dialog') is not None
    assert len(soup.select('[hx-get]'))==4


def test_fps_review_and_detail_reuse_endpoints(monkeypatch):
    req=Request({'type':'http','headers':[]})
    fp=Mock(return_value={'fps':[]}); monkeypatch.setattr(page.api,'list_fps_endpoint',fp)
    page.fps(req,db='db',user='actor')
    assert fp.call_args.kwargs==dict(limit=100,offset=0,db='db',user='actor')
    review=Mock(return_value=dict(items=[],total=0,by_kind={},window_days=30)); monkeypatch.setattr(page.api,'knowledge_review_endpoint',review)
    page.review(req,db='db',user='actor')
    assert review.call_args.kwargs==dict(kind=None,window_days=page.api.knowledge_review.DEFAULT_WINDOW_DAYS,limit=200,db='db',user='actor')
    detail=Mock(return_value=SimpleNamespace(model_dump=lambda:None)); monkeypatch.setattr(page.api,'get_investigation_endpoint',detail)
    page.detail(req,inv_id=4,db='db',user='actor')
    assert detail.call_args.kwargs==dict(inv_id=4,db='db',user='actor')
