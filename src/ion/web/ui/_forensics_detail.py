"""Forensic read panels; each read retains the JSON endpoint's permission."""
from __future__ import annotations

import logging
from html import escape
from html.parser import HTMLParser
from typing import Any, Literal, TypedDict

import markdown
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import forensic_workbench_api, forensics_api
from ion.web.ui._shared import render_view, rows

logger=logging.getLogger(__name__)
read_user=require_permission('forensic:read')
router=APIRouter()

class CollectionPanel(TypedDict):
    state: Literal['failed','empty','data']
    items: list[dict[str,Any]] | None
    can_update: bool
    can_manage: bool
    case_id: int | None
    table: bool

class SummaryPanel(TypedDict):
    state: Literal['failed','data']
    case: dict[str,Any] | None
    milestones: list[dict[str,Any]] | None
    progress: int | None
    done: int | None
    total: int | None

class ReferencePanel(TypedDict):
    state: Literal['failed','data']
    document: dict[str,Any] | None
    content_html: str | None


def _collection(payload: object, user: Any, *, case_id: int | None=None, table: bool=False) -> CollectionPanel:
    found=rows({'items':payload},'items')
    if found is not None and not all(isinstance(item,dict) for item in found): found=None
    return {'state':'failed' if found is None else 'data' if found else 'empty','items':found,
            'can_update':user.has_permission('forensic:update'),'can_manage':user.has_permission('forensic:manage_playbooks'),
            'case_id':case_id,'table':table}


def _read(fn, **kwargs):
    try: return fn(**kwargs)
    except Exception:
        logger.exception('Forensic panel read failed')
        return None

@router.get('/forensics/cases/{case_id}/summary',response_class=HTMLResponse)
def summary(request:Request,case_id:int,user=Depends(read_user),session:Session=Depends(get_db_session)):
    payload=_read(forensics_api.get_case,case_id=case_id,user=user,session=session)
    case=payload if isinstance(payload,dict) else None
    steps=rows(case,'case_steps')
    if steps is not None and not all(isinstance(s,dict) for s in steps): steps=None
    done=sum(s['is_completed'] for s in steps) if steps is not None and all(isinstance(s.get('is_completed'),bool) for s in steps) else None
    total=len(steps) if steps is not None else None
    sla=case.get('sla_status') if case else None
    milestones=rows(sla,'milestones')
    if milestones is not None and not all(isinstance(m,dict) for m in milestones): milestones=None
    view:SummaryPanel={'state':'data' if case is not None else 'failed','case':case,'milestones':milestones,
                       'progress':round(done/total*100) if total and done is not None else 0 if total==0 else None,'done':done,'total':total}
    return render_view(request,'_fragments/forensics_summary.html',view)

@router.get('/forensics/cases/{case_id}/sections',response_class=HTMLResponse)
def sections(request:Request,case_id:int,user=Depends(read_user),session:Session=Depends(get_db_session)):
    view:CollectionPanel=_collection(_read(forensics_api.get_case_steps,case_id=case_id,user=user,session=session),user,case_id=case_id)
    return render_view(request,'_fragments/forensics_sections.html',view)

@router.get('/forensics/cases/{case_id}/timeline',response_class=HTMLResponse)
def timeline(request:Request,case_id:int,user=Depends(read_user),session:Session=Depends(get_db_session)):
    view:CollectionPanel=_collection(_read(forensics_api.get_timeline,case_id=case_id,user=user,session=session),user,case_id=case_id)
    return render_view(request,'_fragments/forensics_timeline.html',view)

@router.get('/forensics/cases/{case_id}/evidence',response_class=HTMLResponse)
def evidence(request:Request,case_id:int,table:bool=False,user=Depends(read_user),session:Session=Depends(get_db_session)):
    view:CollectionPanel=_collection(_read(forensics_api.list_evidence,case_id=case_id,user=user,session=session),user,case_id=case_id,table=table)
    return render_view(request,'_fragments/forensics_evidence.html',view)

@router.get('/forensics/cases/{case_id}/annotations',response_class=HTMLResponse)
def annotations(request:Request,case_id:int,user=Depends(read_user),session:Session=Depends(get_db_session)):
    payload=_read(forensic_workbench_api.list_annotations_endpoint,case_id=case_id,user=user,session=session)
    view:CollectionPanel=_collection(rows(payload,'annotations'),user,case_id=case_id)
    return render_view(request,'_fragments/forensics_annotations.html',view)

@router.get('/forensics/evidence/{evidence_id}/custody',response_class=HTMLResponse)
def custody(request:Request,evidence_id:int,user=Depends(read_user),session:Session=Depends(get_db_session)):
    view:CollectionPanel=_collection(_read(forensics_api.get_custody_log,evidence_id=evidence_id,user=user,session=session),user)
    return render_view(request,'_fragments/forensics_custody.html',view)

@router.get('/forensics/playbooks',response_class=HTMLResponse)
def playbooks(request:Request,investigation_type:str|None=None,user=Depends(read_user),session:Session=Depends(get_db_session)):
    view:CollectionPanel=_collection(_read(forensics_api.list_playbooks,investigation_type=investigation_type,active_only=False,user=user,session=session),user)
    return render_view(request,'_fragments/forensics_playbooks.html',view)

@router.get('/forensics/reference-docs',response_class=HTMLResponse)
def references(request:Request,user=Depends(read_user)):
    view:CollectionPanel=_collection(_read(forensics_api.get_reference_docs,user=user),user)
    return render_view(request,'_fragments/forensics_references.html',view)

class _ReferenceHTML(HTMLParser):
    """Keep document typography, stripping links and all HTML attributes."""
    allowed={'h1','h2','h3','h4','p','br','strong','em','code','pre','ul','ol','li','table','thead','tbody','th','td','tr','hr','blockquote'}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts=[]
    def handle_starttag(self,tag,attrs):
        if tag in self.allowed: self.parts.append('<'+tag+'>')
    def handle_endtag(self,tag):
        if tag in self.allowed: self.parts.append('</'+tag+'>')
    def handle_data(self,data):
        self.parts.append(escape(data))


def _reference_html(content: object) -> str | None:
    if not isinstance(content,str): return None
    parser=_ReferenceHTML()
    parser.feed(markdown.markdown(escape(content),extensions=['tables','fenced_code']))
    return ''.join(parser.parts)


@router.get('/forensics/reference-docs/{document_id}',response_class=HTMLResponse)
def reference(request:Request,document_id:str,user=Depends(read_user)):
    payload=_read(forensics_api.get_reference_docs,user=user)
    items=rows({'items':payload},'items')
    document=next((d for d in items if isinstance(d,dict) and str(d.get('id'))==document_id),None) if items is not None else None
    view:ReferencePanel={'state':'data' if document is not None else 'failed','document':document,
                        'content_html':_reference_html(document.get('content')) if document else None}
    return render_view(request,'_fragments/forensics_reference.html',view)
