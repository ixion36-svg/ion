"""Independent memory reads, reusing the JSON endpoints' payload builders."""
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.models.user import User
from ion.web import investigation_memory_api as api
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)
router = APIRouter()


def render(request, region, payload):
    return templates.TemplateResponse(request=request,
        name=f'_fragments/investigation_memory_{region}.html',
        context={'data': payload, 'plain': plain})


@router.get('/investigation-memory/investigations', response_class=HTMLResponse)
def investigations(request: Request, verdict: str = '', status: str = '',
                   alert_signature: str = '', host: str = '', from_date: str = '', to_date: str = '',
                   db: Session = Depends(get_db_session), user: User = Depends(require_permission('alert:read'))):
    try:
        data = api.list_investigations_endpoint(verdict=verdict or None, status=status or None,
            alert_signature=alert_signature.strip() or None, host=host.strip() or None,
            from_date=from_date or None, to_date=to_date or None, limit=50, offset=0, db=db, user=user)
    except Exception:
        logger.exception('Could not read investigations')
        data = None
    return render(request, 'investigations', data)


@router.get('/investigation-memory/detail/{inv_id}', response_class=HTMLResponse)
def detail(request: Request, inv_id: int, db: Session = Depends(get_db_session),
           user: User = Depends(require_permission('alert:read'))):
    try:
        data = api.get_investigation_endpoint(inv_id=inv_id, db=db, user=user).model_dump()
    except Exception:
        logger.exception('Could not read investigation detail %s', inv_id)
        data = None
    return render(request, 'detail', data)


@router.get('/investigation-memory/iocs', response_class=HTMLResponse)
def iocs(request: Request, ioc_type: str = '', is_known_bad: bool | None = None,
         db: Session = Depends(get_db_session), user: User = Depends(require_permission('alert:read'))):
    try:
        data = api.list_iocs_endpoint(ioc_type=ioc_type or None, is_known_bad=is_known_bad,
                                     limit=100, offset=0, db=db, user=user)
    except Exception:
        logger.exception('Could not read IOC sightings')
        data = None
    return render(request, 'iocs', data)


@router.get('/investigation-memory/fps', response_class=HTMLResponse)
def fps(request: Request, db: Session = Depends(get_db_session),
        user: User = Depends(require_permission('alert:read'))):
    try:
        data = api.list_fps_endpoint(limit=100, offset=0, db=db, user=user)
    except Exception:
        logger.exception('Could not read FP signatures')
        data = None
    return render(request, 'fps', data)


@router.get('/investigation-memory/review', response_class=HTMLResponse)
def review(request: Request, db: Session = Depends(get_db_session),
           user: User = Depends(require_permission('alert:read'))):
    try:
        data = api.knowledge_review_endpoint(kind=None, window_days=api.knowledge_review.DEFAULT_WINDOW_DAYS,
                                            limit=200, db=db, user=user)
    except Exception:
        logger.exception('Could not read knowledge review inbox')
        data = None
    return render(request, 'review', data)
