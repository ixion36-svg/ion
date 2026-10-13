import importlib
from types import SimpleNamespace
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from ion.storage.database import get_db_session
from ion.web import forensics_api, forensic_workbench_api

@pytest.fixture
def client():
    try:
        ui = importlib.import_module('ion.web.ui._forensics_detail')
    except ModuleNotFoundError as error:
        if error.name != 'ion.web.ui._forensics_detail': raise
        ui = SimpleNamespace(router=APIRouter())
    app=FastAPI(); app.include_router(ui.router,prefix='/ui')
    for route in ui.router.routes:
        for dep in route.dependant.dependencies:
            if dep.call is not get_db_session:
                app.dependency_overrides[dep.call]=lambda:SimpleNamespace(has_permission=lambda p:True)
    app.dependency_overrides[get_db_session]=lambda:None
    return TestClient(app)

@pytest.mark.parametrize('path,service,module,key',[
 ('cases/1/sections','get_case_steps',forensics_api,None),
 ('cases/1/timeline','get_timeline',forensics_api,None),
 ('cases/1/evidence','list_evidence',forensics_api,None),
 ('cases/1/annotations','list_annotations_endpoint',forensic_workbench_api,'annotations'),
 ('evidence/1/custody','get_custody_log',forensics_api,None),
 ('playbooks','list_playbooks',forensics_api,None),
 ('reference-docs','get_reference_docs',forensics_api,None),
])
@pytest.mark.parametrize('payload,state',[ (None,'failed'), ({},'failed'), ([], 'empty'), ([{'id':1,'title':'<attack>','name':'Example','content':'Text'}],'data') ])
def test_collection_outcomes(client,monkeypatch,path,service,module,key,payload,state):
    result={key:payload} if key else payload
    monkeypatch.setattr(module,service,lambda **kw:result)
    response=client.get('/ui/forensics/'+path,headers={'Accept':'application/json'})
    assert response.status_code==200
    assert response.json()['state']==state
    html=client.get('/ui/forensics/'+path)
    assert html.status_code==200
    assert '<attack>' not in html.text
    if state=='failed': assert 'unavailable' in html.text.lower()

@pytest.mark.parametrize('field',['id','title','description','content','fields','fields_data','step_order','is_completed','is_required','completed_by_username','completed_at'])
@pytest.mark.parametrize('value',[None,0,'',[]])
def test_sections_missing_and_zero(client,monkeypatch,field,value):
    row={'id':2,'title':'Step','fields':[],'fields_data':{},field:value}
    monkeypatch.setattr(forensics_api,'get_case_steps',lambda **kw:[row])
    response=client.get('/ui/forensics/cases/1/sections')
    assert response.status_code==200
    assert 'undefined' not in response.text

@pytest.mark.parametrize('field',['custody_entries','step_count'])
@pytest.mark.parametrize('value',[None,0,4])
def test_figures_keep_unknown(client,monkeypatch,field,value):
    service='list_evidence' if field=='custody_entries' else 'list_playbooks'
    path='cases/1/evidence' if field=='custody_entries' else 'playbooks'
    monkeypatch.setattr(forensics_api,service,lambda **kw:[{'id':1,'name':'N',field:value}])
    html=client.get('/ui/forensics/'+path).text
    assert ('Unknown' if value is None else str(value)) in html

@pytest.mark.parametrize('path,service,module',[
 ('cases/1/sections','get_case_steps',forensics_api),('cases/1/timeline','get_timeline',forensics_api),
 ('cases/1/evidence','list_evidence',forensics_api),('evidence/1/custody','get_custody_log',forensics_api),
 ('playbooks','list_playbooks',forensics_api),('reference-docs','get_reference_docs',forensics_api),
 ('cases/1/annotations','list_annotations_endpoint',forensic_workbench_api)])
def test_refusal_never_looks_empty(client,monkeypatch,path,service,module):
    def refused(**kwargs): raise RuntimeError('private backend detail')
    monkeypatch.setattr(module,service,refused)
    response=client.get('/ui/forensics/'+path)
    assert response.status_code==200
    assert 'unavailable' in response.text.lower()
    assert 'private backend detail' not in response.text

@pytest.mark.parametrize('kind,value',[
 ('text',0),('text','<script>'),('textarea','"quoted"'),('list',['a','<img>']),
 ('table',[{'Col':'<img>'}]),('select','Option'),('checkbox',True),('checkbox',False)])
def test_structured_section_fields(client,monkeypatch,kind,value):
    from bs4 import BeautifulSoup
    field={'key':'field','type':kind,'label':'Field','placeholder':'"input"','columns':['Col'],'options':['Option']}
    monkeypatch.setattr(forensics_api,'get_case_steps',lambda **kw:[{'id':2,'title':'Step','fields':[field],'fields_data':{'field':value}}])
    response=client.get('/ui/forensics/cases/1/sections');assert response.status_code==200
    soup=BeautifulSoup(response.text,'html.parser');el=soup.select_one('#sf-2-field');assert el is not None
    assert soup.find('script') is None and soup.find('img') is None
    if kind=='text': assert el['value']==str(value)
    elif kind=='textarea': assert el.text==value
    elif kind=='checkbox': assert el.has_attr('checked')==value
    elif kind=='select': assert el.select_one('option[selected]')['value']==value
    elif kind=='list': assert [x['value'] for x in el.select('input')]==value
    elif kind=='table': assert el.select_one('input')['value']==value[0]['Col']

@pytest.mark.parametrize('steps,expected',[(None,None),([],0),([{'is_completed':False}],0),([{'is_completed':True}],100)])
def test_summary_zero_unknown(client,monkeypatch,steps,expected):
    monkeypatch.setattr(forensics_api,'get_case',lambda **kw:{'id':1,'case_steps':steps})
    response=client.get('/ui/forensics/cases/1/summary',headers={'Accept':'application/json'})
    assert response.status_code==200
    assert response.json()['progress']==expected
    html=client.get('/ui/forensics/cases/1/summary').text
    assert ('Section progress unavailable' if expected is None else str(expected)+'%') in html

@pytest.mark.parametrize('payload',[None,{},[]])
def test_missing_summary_fields_are_unavailable(client,monkeypatch,payload):
    monkeypatch.setattr(forensics_api,'get_case',lambda **kw:payload)
    html=client.get('/ui/forensics/cases/1/summary').text
    assert 'unavailable' in html
    assert '0%' not in html

@pytest.mark.parametrize('path,service,payload',[
 ('cases/1/sections','get_case_steps',[{'id':1,'title':'Readonly','fields':[],'fields_data':{}}]),
 ('cases/1/evidence','list_evidence',[{'id':1,'name':'Readonly'}]),
 ('playbooks','list_playbooks',[{'id':1,'name':'Readonly'}])])
def test_readonly_view_withholds_write_controls(monkeypatch,path,service,payload):
    ui=importlib.import_module('ion.web.ui._forensics_detail')
    from ion.auth.dependencies import get_current_user
    app=FastAPI();app.include_router(ui.router,prefix='/ui')
    app.dependency_overrides[get_current_user]=lambda:SimpleNamespace(has_permission=lambda p:p=='forensic:read')
    app.dependency_overrides[get_db_session]=lambda:None
    monkeypatch.setattr(forensics_api,service,lambda **kw:payload)
    response=TestClient(app).get('/ui/forensics/'+path)
    assert response.status_code==200
    for action in ['saveSection','completeSection','deleteSection','showCustodyModal','editPlaybook','deletePlaybook']:
        assert 'data-click-action="'+action+'"' not in response.text

def test_fragment_read_permission_is_enforced(monkeypatch):
    ui=importlib.import_module('ion.web.ui._forensics_detail')
    from ion.auth.dependencies import get_current_user
    app=FastAPI();app.include_router(ui.router,prefix='/ui')
    app.dependency_overrides[get_current_user]=lambda:SimpleNamespace(has_permission=lambda p:False)
    app.dependency_overrides[get_db_session]=lambda:None
    calls=[];monkeypatch.setattr(forensics_api,'get_case_steps',lambda **kw:calls.append(1))
    response=TestClient(app).get('/ui/forensics/cases/1/sections')
    assert response.status_code==403 and calls==[]

def test_reference_formatting_escapes_raw_html_and_link_schemes(client,monkeypatch):
    from bs4 import BeautifulSoup
    monkeypatch.setattr(forensics_api,'get_reference_docs',lambda **kw:[{'id':'a','title':'Reference','content':'# Heading\n\n**Bold** and `code`\n\n<img src=x onerror=evil()>\n\n[Bad](javascript:evil)'}])
    response=client.get('/ui/forensics/reference-docs/a'); assert response.status_code==200
    soup=BeautifulSoup(response.text,'html.parser')
    assert soup.h1.text=='Heading'; assert soup.strong.text=='Bold';assert soup.code.text=='code'
    assert soup.img is None and soup.a is None

@pytest.mark.parametrize('payload',[[None],[4],['bad']])
@pytest.mark.parametrize('path,service', [('cases/1/sections','get_case_steps'),('cases/1/timeline','get_timeline'),('cases/1/evidence','list_evidence'),('evidence/1/custody','get_custody_log'),('playbooks','list_playbooks'),('reference-docs','get_reference_docs')])
def test_malformed_record_lists_are_failed_reads(client,monkeypatch,payload,path,service):
    monkeypatch.setattr(forensics_api,service,lambda **kw:payload)
    response=client.get('/ui/forensics/'+path,headers={'Accept':'application/json'})
    assert response.status_code==200
    assert response.json()['state']=='failed'

@pytest.mark.parametrize('field',['evidence_number','name','evidence_type','status','hash_sha256','hash_md5','storage_location','collected_by_username','source'])
@pytest.mark.parametrize('value',[None,0,'','<img src=x>'])
def test_evidence_fields_are_safe_in_both_presentations(client,monkeypatch,field,value):
    from bs4 import BeautifulSoup
    row={'id':1,'name':'Evidence',field:value}
    monkeypatch.setattr(forensics_api,'list_evidence',lambda **kw:[row])
    for suffix in ['', '?table=true']:
        response=client.get('/ui/forensics/cases/1/evidence'+suffix)
        assert response.status_code==200
        assert BeautifulSoup(response.text,'html.parser').find('img') is None
        if value=='<img src=x>' and not (field=='source' and suffix or field=='collected_by_username' and not suffix): assert '&lt;img src=x&gt;' in response.text.lower()

@pytest.mark.parametrize('field',['title','category','content'])
@pytest.mark.parametrize('value',[None,0,'','<img src=x>'])
def test_reference_preview_missing_fields_are_safe(client,monkeypatch,field,value):
    from bs4 import BeautifulSoup
    monkeypatch.setattr(forensics_api,'get_reference_docs',lambda **kw:[{'id':'ref','title':'Reference',field:value}])
    response=client.get('/ui/forensics/reference-docs')
    assert response.status_code==200
    assert BeautifulSoup(response.text,'html.parser').find('img') is None
    if field=='content' and value is None: assert 'Preview unavailable' in response.text


def test_section_missing_fields_does_not_offer_save(client,monkeypatch):
    monkeypatch.setattr(forensics_api,'get_case_steps',lambda **kw:[{'id':1,'title':'Section'}])
    response=client.get('/ui/forensics/cases/1/sections')
    assert response.status_code==200
    assert 'Structured fields unavailable' in response.text
    assert 'data-click-action="saveSection"' not in response.text

@pytest.mark.parametrize('step',[{}, {'is_completed':None}, {'is_completed':0}, {'is_completed':''}])
def test_summary_unmeasured_completion_is_unknown(client,monkeypatch,step):
    monkeypatch.setattr(forensics_api,'get_case',lambda **kw:{'id':1,'case_steps':[step]})
    response=client.get('/ui/forensics/cases/1/summary',headers={'Accept':'application/json'})
    assert response.json()['done'] is None
    assert response.json()['progress'] is None
    assert response.json()['total']==1
    html=client.get('/ui/forensics/cases/1/summary').text
    assert 'Section progress unavailable' in html and '0%' not in html
