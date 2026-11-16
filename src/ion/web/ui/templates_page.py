"""Template catalogue, recursive folder navigation and permission-specific controls."""
import inspect
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.web import api
from ion.web.api import Services, get_services, templates_payload
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)
router = APIRouter()


def route_permission(method, path):
    route = next(r for r in api.router.routes if r.path == path and method in r.methods)
    factory = require_permission('__probe__').__code__
    guards = [d.call for d in route.dependant.dependencies if getattr(d.call, '__code__', None) is factory]
    if len(guards) != 1:
        raise ValueError(f'Expected one named permission on {method} {path}')
    return inspect.getclosurevars(guards[0]).nonlocals['permission_name']


READ = route_permission('GET', '/templates')
ACTIONS = {
    'create_collection': ('POST', '/collections'),
    'rename_collection': ('PUT', '/collections/{collection_id}'),
    'delete_collection': ('DELETE', '/collections/{collection_id}'),
    'move_template': ('POST', '/collections/{collection_id}/templates/{template_id}'),
    'unfile_template': ('DELETE', '/templates/{template_id}/collection'),
    'create_template': ('POST', '/templates'),
    'edit_template': ('PUT', '/templates/{template_id}'),
    'delete_template': ('DELETE', '/templates/{template_id}'),
}


def permissions(user):
    return {key: user.has_permission(route_permission(*route)) for key, route in ACTIONS.items()}


def forest(rows):
    """Reject corrupt parent cycles before recursive Jinja or ancestor filtering."""
    by_id = {r['id']: dict(r, children=[]) for r in rows}
    roots = []
    for node in by_id.values():
        seen = set()
        current = node
        while current is not None:
            if current['id'] in seen:
                raise ValueError('Folder parent cycle; hierarchy cannot be read safely')
            seen.add(current['id'])
            current = by_id.get(current.get('parent_id'))
        parent = by_id.get(node.get('parent_id'))
        if parent is None:
            roots.append(node)
        else:
            parent['children'].append(node)
    return roots, by_id


def folder_path(by_id, folder):
    parts = []
    current = by_id.get(folder)
    while current is not None:
        parts.append(current)
        current = by_id.get(current.get('parent_id'))
    return list(reversed(parts))


async def read_folders(services):
    rows = await api.list_collections(parent_id=None, flat=True, services=services)
    return forest(rows)


@router.get('/templates-page/controls', response_class=HTMLResponse)
def controls(request: Request, user: User = Depends(require_permission(READ))):
    return templates.TemplateResponse(request=request, name='_fragments/templates_page_controls.html',
                                      context={'can': permissions(user)})


@router.get('/templates-page/types', response_class=HTMLResponse)
async def types(request: Request, document_type: str = '', user: User = Depends(require_permission(READ))):
    data = None
    try:
        data = (await api.list_document_types())['types']
    except Exception:
        logger.exception('Template document types could not be read')
    return templates.TemplateResponse(request=request, name='_fragments/templates_page_types.html',
                                      context={'types': data, 'selected': document_type})


@router.get('/templates-page/folders', response_class=HTMLResponse)
async def folders(request: Request, folder: str = '', user: User = Depends(require_permission(READ)),
                  services: Services = Depends(get_services)):
    tree = None
    try:
        tree, _ = await read_folders(services)
    except Exception:
        logger.exception('Template folders could not be read')
    return templates.TemplateResponse(request=request, name='_fragments/templates_page_folders.html',
                                      context={'tree': tree, 'selected': folder})


@router.get('/templates-page/manage', response_class=HTMLResponse)
async def manage(request: Request, user: User = Depends(require_permission(READ)),
                 services: Services = Depends(get_services)):
    tree = None
    try:
        tree, _ = await read_folders(services)
    except Exception:
        logger.exception('Folder management could not be read')
    return templates.TemplateResponse(request=request, name='_fragments/templates_page_manage.html',
                                      context={'tree': tree, 'can': permissions(user)})


@router.get('/templates-page/move', response_class=HTMLResponse)
async def move(request: Request, selected: str = '', user: User = Depends(require_permission(READ)),
               services: Services = Depends(get_services)):
    tree = None
    try:
        tree, _ = await read_folders(services)
    except Exception:
        logger.exception('Move destinations could not be read')
    return templates.TemplateResponse(request=request, name='_fragments/templates_page_move.html',
                                      context={'tree': tree, 'selected': selected, 'can': permissions(user)})


@router.get('/templates-page/list', response_class=HTMLResponse)
async def catalogue(request: Request, search: str = '', format: str = '', document_type: str = '', folder: str = '',
                    user: User = Depends(require_permission(READ)), services: Services = Depends(get_services)):
    rows = None
    path = []
    try:
        rows = templates_payload(services)
        by_id = {}
        target = None
        if folder and folder != 'uncategorized':
            target = int(folder)
            _, by_id = await read_folders(services)
            if target not in by_id:
                raise ValueError('Selected folder no longer exists')
            path = folder_path(by_id, target)
        filtered = []
        for original in rows:
            row = dict(original)
            row['format'] = plain(row.get('format'))
            row['document_type'] = plain(row.get('document_type'))
            if search.lower() not in (row['name'] + ' ' + (row.get('description') or '')).lower():
                continue
            if format and row['format'] != format:
                continue
            if document_type and row['document_type'] != document_type:
                continue
            if folder == 'uncategorized' and row.get('collection_id') is not None:
                continue
            if target is not None and target not in [n['id'] for n in folder_path(by_id, row.get('collection_id'))]:
                continue
            filtered.append(row)
        rows = filtered
    except Exception:
        logger.exception('Template catalogue could not be read')
        rows = None
    return templates.TemplateResponse(request=request, name='_fragments/templates_page_list.html',
                                      context={'rows': rows, 'path': path, 'folder': folder, 'can': permissions(user)},
                                      headers={'Cache-Control': 'no-store'})
