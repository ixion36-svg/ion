"""Template catalogue permissions, finite recursion and independent read failures."""
import asyncio
import inspect
import re
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from starlette.requests import Request

from ion.auth.dependencies import require_permission
from ion.web import api
from ion.web.ui import templates_page as page


def request():
    return Request({'type':'http','path':'/ui/templates-page/list','headers':[]})


def user(*permissions):
    return SimpleNamespace(has_permission=lambda p:p in permissions)


def folders():
    return [{'id':1,'parent_id':None,'name':'Root','template_count':0,'document_count':None},
            {'id':2,'parent_id':1,'name':'Child','template_count':0,'document_count':0},
            {'id':3,'parent_id':2,'name':'Leaf','template_count':1,'document_count':0}]


def template(**over):
    return dict({'id':4,'name':'<script>alert(1)</script>','description':'Alpha','format':'markdown',
                 'document_type':'SOP','current_version':0,'collection_id':3,'collection_name':'Leaf',
                 'updated_at':'2026-10-12T12:00:00Z','tags':['<b>tag</b>']},**over)


def render(name, **context):
    return page.templates.env.get_template('_fragments/templates_page_'+name+'.html').render(**context)


def test_recursive_macro_preserves_root_and_two_nested_levels():
    tree,_ = page.forest(folders())
    html = render('folders',tree=tree,selected='3')
    assert html.count('class="folder-children"') == 2
    assert '<div data-folder-depth="0">' in html
    assert 'data-folder-depth="1"' in html and 'data-folder-depth="2"' in html
    assert 'folder-item w-full active" data-folder="3"' in html
    assert '(0)' in html


@pytest.mark.parametrize('rows', [[{'id':1,'parent_id':1}],
                                [{'id':1,'parent_id':2},{'id':2,'parent_id':1}]])
def test_self_parent_and_cycle_fail_before_recursive_render(rows):
    with pytest.raises(ValueError,match='cycle'):
        page.forest(rows)


def test_orphan_is_visible_as_root():
    tree,_ = page.forest([{'id':4,'parent_id':999,'name':'Orphan'}])
    assert tree[0]['name']=='Orphan'


@pytest.mark.parametrize('permission', ['template:read','template:create','template:update','template:delete'])
def test_each_action_uses_its_live_route_permission(permission):
    actor = user(permission)
    actual = page.permissions(actor)
    from ion.web.server import app
    factory = require_permission('__probe__').__code__
    for action,(method,path) in page.ACTIONS.items():
        route = next(r for r in app.routes if r.path == '/api'+path and method in r.methods)
        guard = next(d.call for d in route.dependant.dependencies if getattr(d.call,'__code__',None) is factory)
        gate = inspect.getclosurevars(guard).nonlocals['permission_name']
        assert actual[action] is (gate == permission)


def test_permission_reader_tracks_the_route_not_a_second_literal(monkeypatch):
    route = next(r for r in api.router.routes if r.path=='/collections' and 'POST' in r.methods)
    dep = next(d for d in route.dependant.dependencies if d.call.__closure__)
    monkeypatch.setattr(dep,'call',require_permission('test:changed'))
    assert page.permissions(user('test:changed'))['create_collection'] is True
    assert page.permissions(user('template:create'))['create_collection'] is False


def test_all_fragment_reads_match_live_read_factory():
    factory = require_permission('__probe__').__code__
    expected = page.route_permission('GET','/templates')
    assert len(page.router.routes)==6
    for route in page.router.routes:
        guard = next(d.call for d in route.dependant.dependencies if getattr(d.call,'__code__',None) is factory)
        assert inspect.getclosurevars(guard).nonlocals['permission_name']==expected


@pytest.mark.parametrize('permission,shown,hidden', [
    ('template:create','data-click-action="createFolder"','data-click-action="renameFolder"'),
    ('template:update','data-click-action="renameFolder"','data-click-action="createFolder"'),
    ('template:delete','data-click-action="deleteFolder"','data-click-action="renameFolder"'),
    ('template:read','Existing Folders','data-click-action=')])
def test_management_buttons_are_independently_gated(permission,shown,hidden):
    tree,_ = page.forest(folders())
    html = render('manage',tree=tree,can=page.permissions(user(permission)))
    assert shown in html and hidden not in html


def test_catalogue_buttons_and_empty_create_link_require_own_permissions():
    can = page.permissions(user('template:read'))
    html = render('list',rows=[template()],path=[],folder='',can=can)
    assert '/render' in html and '/edit' not in html and 'data-click-action=' not in html
    html = render('list',rows=[],path=[],folder='',can=can)
    assert '/templates/new' not in html
    html = render('list',rows=[template()],path=[],folder='',can=page.permissions(user('template:update')))
    assert '/edit' in html and 'showMoveModal' in html and 'deleteTemplate' not in html


def test_numeric_zero_unknown_timestamp_and_autoescape():
    html = render('list',rows=[template(),template(current_version=None)],path=[],folder='',can={})
    assert 'Version: 0' in html and 'Version: Unknown' in html
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html and '<script>alert(1)</script>' not in html
    assert '&lt;b&gt;tag&lt;/b&gt;' in html and 'data-ts-local="yes"' in html
    tree,_=page.forest(folders())
    html = render('manage',tree=tree,can={})
    assert '0 templates, Unknown docs' in html


def test_parent_and_move_options_include_nested_names():
    tree,_ = page.forest(folders())
    html = render('manage',tree=tree,can=page.permissions(user('template:create')))
    assert '<option value="3">› › Leaf</option>' in html
    html = render('move',tree=tree,selected='3',can=page.permissions(user('template:update')))
    assert '<option value="3" selected>› › Leaf</option>' in html
    assert '<option value="">No Folder (Root)</option>' in html
    assert '<select' not in render('move',tree=tree,selected='',can={})


def test_filtering_and_breadcrumbs_include_descendants(monkeypatch):
    monkeypatch.setattr(page,'templates_payload',Mock(return_value=[template(),template(id=5,collection_id=None)]))
    monkeypatch.setattr(api,'list_collections',AsyncMock(return_value=folders()))
    html=asyncio.run(page.catalogue(request(),search='alpha',format='markdown',document_type='SOP',folder='1',user=user(),services=Mock())).body.decode()
    assert html.count('class="card bg-base-200 shadow"')==1
    assert 'data-folder="1">Root' in html
    html=asyncio.run(page.catalogue(request(),folder='uncategorized',user=user(),services=Mock())).body.decode()
    assert '/templates/5"' in html and '/templates/4"' not in html


def test_enum_labels_are_rendered_as_values(monkeypatch):
    class Format(str,Enum):
        MARKDOWN='markdown'
    monkeypatch.setattr(page,'templates_payload',Mock(return_value=[template(format=Format.MARKDOWN)]))
    html=asyncio.run(page.catalogue(request(),user=user(),services=Mock())).body.decode()
    assert '>markdown</span>' in html and 'Format.MARKDOWN' not in html


@pytest.mark.parametrize('endpoint,text', [('folders','Folders could not be read'),
    ('manage','Folder management could not be read'),('move','Move destinations could not be read')])
def test_folder_region_failures_are_explicit_and_logged(monkeypatch,caplog,endpoint,text):
    monkeypatch.setattr(api,'list_collections',AsyncMock(side_effect=RuntimeError('offline')))
    html=asyncio.run(getattr(page,endpoint)(request(),user=user(),services=Mock())).body.decode()
    assert text in html and 'No folders yet' not in html and '<option' not in html
    assert any(r.exc_info for r in caplog.records)


def test_list_failure_does_not_claim_empty(monkeypatch,caplog):
    monkeypatch.setattr(page,'templates_payload',Mock(side_effect=RuntimeError('offline')))
    html=asyncio.run(page.catalogue(request(),user=user(),services=Mock())).body.decode()
    assert 'Template catalogue could not be read' in html and 'No templates match' not in html
    assert any(r.exc_info for r in caplog.records)


def test_types_failure_and_selected_type(monkeypatch,caplog):
    monkeypatch.setattr(api,'list_document_types',AsyncMock(side_effect=RuntimeError('offline')))
    html=asyncio.run(page.types(request(),user=user())).body.decode()
    assert 'Document types could not be read' in html and '<select' not in html
    assert any(r.exc_info for r in caplog.records)
    monkeypatch.setattr(api,'list_document_types',AsyncMock(return_value={'types':{'SOP':'Procedure'}}))
    html=asyncio.run(page.types(request(),document_type='SOP',user=user())).body.decode()
    assert 'value="SOP" selected' in html


def test_json_list_uses_same_payload(monkeypatch):
    assert page.templates_payload is api.templates_payload
    reader=Mock(return_value=[{'id':0}]); monkeypatch.setattr(api,'templates_payload',reader)
    services=Mock()
    assert asyncio.run(api.list_templates(format=None,tag=None,search=None,collection_id=None,document_type=None,services=services))==[{'id':0}]
    reader.assert_called_once_with(services,format=None,tag=None,search=None,collection_id=None,document_type=None)


def test_shell_retry_controls_are_outside_targets_and_unfile_uses_delete():
    source=(Path(__file__).parents[2]/'src/ion/web/templates/templates.html').read_text(encoding='utf-8')
    source=re.sub(r'<!--.*?-->|\{#.*?#\}|/\*.*?\*/|//[^\n]*','',source,flags=re.S)
    for button,target in [('folders-refresh','folder-list'),('manage-refresh','folders-tree-manage'),('move-refresh','move-options'),('types-refresh','doctype-host')]:
        assert source.index('id="'+button+'"') < source.index('id="'+target+'"')
    form=re.search(r'<form[^>]*id="template-filters"[^>]*>',source).group()
    assert 'hx-get="/ui/templates-page/list"' in form
    types_host=re.search(r'<span[^>]*id="doctype-host"[^>]*>',source).group()
    assert 'hx-target="this"' in types_host
    assert "api.delete('/api/templates/' + moveTemplateId + '/collection')" in source
    assert '.innerHTML' not in source and 'escapeHtml' not in source and 'style=' not in source
