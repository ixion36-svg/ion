"""Forensic Investigation API endpoints."""

from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission, get_current_user, get_db_session
from ion.models.user import User
from ion.models.forensics import (
    ForensicCaseStatus,
    ForensicCasePriority,
    InvestigationType,
    EvidenceType,
    EvidenceStatus,
    CustodyAction,
)
from ion.storage.forensic_repository import ForensicRepository, DEFAULT_SLA_PROFILES

router = APIRouter(tags=["forensics"])


# =============================================================================
# Request Models
# =============================================================================

class CaseCreate(BaseModel):
    title: str
    investigation_type: str
    description: Optional[str] = None
    priority: str = ForensicCasePriority.MEDIUM.value
    lead_investigator_id: Optional[int] = None
    alert_case_id: Optional[int] = None
    classification: Optional[str] = None
    sla_profile: Optional[dict] = None
    playbook_id: Optional[int] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    lead_investigator_id: Optional[int] = None
    classification: Optional[str] = None


class CaseClose(BaseModel):
    summary: Optional[str] = None
    findings: Optional[str] = None
    recommendations: Optional[str] = None


class EvidenceCreate(BaseModel):
    name: str
    evidence_type: str
    description: Optional[str] = None
    source: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    storage_location: Optional[str] = None
    metadata: Optional[dict] = None


class EvidenceUpdate(BaseModel):
    status: Optional[str] = None
    description: Optional[str] = None
    storage_location: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None


class CustodyCreate(BaseModel):
    action: str
    received_by_id: Optional[int] = None
    location: Optional[str] = None
    notes: Optional[str] = None


class TimelineCreate(BaseModel):
    content: str
    metadata: Optional[dict] = None


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    investigation_type: Optional[str] = None
    is_active: bool = True
    steps: Optional[list[dict]] = None


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    investigation_type: Optional[str] = None
    is_active: Optional[bool] = None
    steps: Optional[list[dict]] = None


# =============================================================================
# Case Endpoints
# =============================================================================

@router.get("/cases")
def list_cases(
    status: Optional[str] = None,
    investigation_type: Optional[str] = None,
    priority: Optional[str] = None,
    lead_investigator_id: Optional[int] = None,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """List forensic investigations with optional filters."""
    repo = ForensicRepository(session)
    cases = repo.list_cases(
        status=status,
        investigation_type=investigation_type,
        priority=priority,
        lead_investigator_id=lead_investigator_id,
    )
    return [c.to_dict() for c in cases]


@router.post("/cases")
def create_case(
    payload: CaseCreate,
    user: User = Depends(require_permission("forensic:create")),
    session: Session = Depends(get_db_session),
):
    """Create a new forensic investigation."""
    repo = ForensicRepository(session)
    case = repo.create_case(
        title=payload.title,
        investigation_type=payload.investigation_type,
        created_by_id=user.id,
        description=payload.description,
        priority=payload.priority,
        lead_investigator_id=payload.lead_investigator_id,
        alert_case_id=payload.alert_case_id,
        classification=payload.classification,
        sla_profile=payload.sla_profile,
        playbook_id=payload.playbook_id,
    )
    session.commit()
    return case.to_dict()


@router.get("/cases/overdue")
def get_overdue_cases(
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Get cases with breached SLAs."""
    repo = ForensicRepository(session)
    cases = repo.get_overdue_cases()
    result = []
    for c in cases:
        d = c.to_dict()
        d["sla_status"] = repo.get_sla_status(c)
        result.append(d)
    return result


@router.get("/cases/{case_id}")
def get_case(
    case_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Get a forensic investigation by ID."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    result = case.to_dict(include_evidence=True, include_timeline=True)
    result["sla_status"] = repo.get_sla_status(case)
    return result


@router.patch("/cases/{case_id}")
def update_case(
    case_id: int,
    payload: CaseUpdate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Update a forensic investigation."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    # Enforce lock: only the locker or lead can modify a locked case
    if case.is_locked and case.locked_by_id != user.id and case.lead_investigator_id != user.id:
        if not user.has_permission("forensic:close"):
            raise HTTPException(423, "Investigation is locked. Only the lock holder or lead investigator can modify it.")
    case = repo.update_case(
        case, user.id,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        priority=payload.priority,
        lead_investigator_id=payload.lead_investigator_id,
        classification=payload.classification,
    )
    session.commit()
    result = case.to_dict()
    result["sla_status"] = repo.get_sla_status(case)
    return result


@router.post("/cases/{case_id}/close")
def close_case(
    case_id: int,
    payload: CaseClose,
    user: User = Depends(require_permission("forensic:close")),
    session: Session = Depends(get_db_session),
):
    """Close a forensic investigation with summary/findings/recommendations."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    if case.status == ForensicCaseStatus.CLOSED.value:
        raise HTTPException(400, "Investigation is already closed")
    case = repo.close_case(
        case, user.id,
        summary=payload.summary,
        findings=payload.findings,
        recommendations=payload.recommendations,
    )
    # Auto-generate report document in the Document Library
    doc = repo.generate_report_document(case, user.username)
    session.commit()
    result = case.to_dict()
    result["report_document_id"] = doc.id
    result["report_document_name"] = doc.name
    return result


@router.get("/cases/{case_id}/report")
def get_case_report(
    case_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Generate structured outcome report for a case."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    return repo.generate_report(case)


# =============================================================================
# Timeline Endpoints
# =============================================================================

@router.get("/cases/{case_id}/timeline")
def get_timeline(
    case_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Get timeline entries for a case."""
    repo = ForensicRepository(session)
    entries = repo.get_timeline(case_id)
    return [e.to_dict() for e in entries]


@router.post("/cases/{case_id}/timeline")
def add_timeline_note(
    case_id: int,
    payload: TimelineCreate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Add a timeline note to a case."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    entry = repo.add_timeline_note(case_id, user.id, payload.content, payload.metadata)
    session.commit()
    return entry.to_dict()


# =============================================================================
# Case Step Endpoints (Fillable Sections)
# =============================================================================

class StepUpdate(BaseModel):
    content: Optional[str] = None
    is_completed: Optional[bool] = None
    title: Optional[str] = None
    description: Optional[str] = None
    fields_data: Optional[dict] = None


class StepCreate(BaseModel):
    title: str
    description: Optional[str] = None
    is_required: bool = False


@router.get("/cases/{case_id}/steps")
def get_case_steps(
    case_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Get all investigation sections/steps for a case."""
    repo = ForensicRepository(session)
    steps = repo.get_case_steps(case_id)
    return [s.to_dict() for s in steps]


@router.patch("/cases/{case_id}/steps/{step_id}")
def update_case_step(
    case_id: int,
    step_id: int,
    payload: StepUpdate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Update a case step — fill in content, mark complete, etc."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    # Lock check
    if case.is_locked and case.locked_by_id != user.id and case.lead_investigator_id != user.id:
        if not user.has_permission("forensic:close"):
            raise HTTPException(423, "Investigation is locked.")
    step = None
    for s in (case.case_steps or []):
        if s.id == step_id:
            step = s
            break
    if not step:
        raise HTTPException(404, "Step not found")
    step = repo.update_case_step(
        step, user.id,
        content=payload.content,
        is_completed=payload.is_completed,
        title=payload.title,
        description=payload.description,
        fields_data=payload.fields_data,
    )
    session.commit()
    return step.to_dict()


@router.post("/cases/{case_id}/steps")
def add_case_step(
    case_id: int,
    payload: StepCreate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Add an ad-hoc section/step to a case."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    step = repo.add_case_step(
        case_id, user.id,
        title=payload.title,
        description=payload.description,
        is_required=payload.is_required,
    )
    session.commit()
    return step.to_dict()


@router.delete("/cases/{case_id}/steps/{step_id}")
def delete_case_step(
    case_id: int,
    step_id: int,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Delete an ad-hoc step from a case."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    step = None
    for s in (case.case_steps or []):
        if s.id == step_id:
            step = s
            break
    if not step:
        raise HTTPException(404, "Step not found")
    if step.playbook_step_id:
        raise HTTPException(400, "Cannot delete a playbook-sourced section")
    repo.delete_case_step(step, user.id)
    session.commit()
    return {"status": "ok"}


# =============================================================================
# Evidence Endpoints
# =============================================================================

@router.post("/cases/{case_id}/evidence")
def add_evidence(
    case_id: int,
    payload: EvidenceCreate,
    user: User = Depends(require_permission("forensic:create")),
    session: Session = Depends(get_db_session),
):
    """Add evidence to a forensic case."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    evidence = repo.add_evidence(
        case, payload.name, payload.evidence_type, user.id,
        description=payload.description,
        source=payload.source,
        hash_md5=payload.hash_md5,
        hash_sha256=payload.hash_sha256,
        storage_location=payload.storage_location,
        metadata=payload.metadata,
    )
    session.commit()
    return evidence.to_dict()


@router.get("/cases/{case_id}/evidence")
def list_evidence(
    case_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """List evidence items for a case."""
    repo = ForensicRepository(session)
    items = repo.list_evidence_for_case(case_id)
    return [e.to_dict(include_custody=True) for e in items]


@router.patch("/evidence/{evidence_id}")
def update_evidence(
    evidence_id: int,
    payload: EvidenceUpdate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Update an evidence item."""
    repo = ForensicRepository(session)
    evidence = repo.get_evidence_by_id(evidence_id)
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    evidence = repo.update_evidence(
        evidence,
        status=payload.status,
        description=payload.description,
        storage_location=payload.storage_location,
        hash_md5=payload.hash_md5,
        hash_sha256=payload.hash_sha256,
    )
    session.commit()
    return evidence.to_dict()


# =============================================================================
# Custody Endpoints
# =============================================================================

@router.get("/evidence/{evidence_id}/custody")
def get_custody_log(
    evidence_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Get custody log for an evidence item."""
    repo = ForensicRepository(session)
    entries = repo.get_custody_log(evidence_id)
    return [e.to_dict() for e in entries]


@router.post("/evidence/{evidence_id}/custody")
def add_custody_entry(
    evidence_id: int,
    payload: CustodyCreate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Add a custody log entry for an evidence item."""
    repo = ForensicRepository(session)
    evidence = repo.get_evidence_by_id(evidence_id)
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    entry = repo.add_custody_entry(
        evidence, payload.action, user.id,
        received_by_id=payload.received_by_id,
        location=payload.location,
        notes=payload.notes,
    )
    session.commit()
    return entry.to_dict()


# =============================================================================
# Playbook Endpoints
# =============================================================================

@router.get("/playbooks")
def list_playbooks(
    investigation_type: Optional[str] = None,
    active_only: bool = False,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """List forensic playbooks."""
    repo = ForensicRepository(session)
    playbooks = repo.list_playbooks(investigation_type=investigation_type, active_only=active_only)
    return [p.to_dict() for p in playbooks]


@router.post("/playbooks")
def create_playbook(
    payload: PlaybookCreate,
    user: User = Depends(require_permission("forensic:manage_playbooks")),
    session: Session = Depends(get_db_session),
):
    """Create a forensic playbook."""
    repo = ForensicRepository(session)
    pb = repo.create_playbook(
        name=payload.name,
        created_by_id=user.id,
        description=payload.description,
        investigation_type=payload.investigation_type,
        is_active=payload.is_active,
        steps=payload.steps,
    )
    session.commit()
    return pb.to_dict()


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    """Get a forensic playbook by ID."""
    repo = ForensicRepository(session)
    pb = repo.get_playbook_by_id(playbook_id)
    if not pb:
        raise HTTPException(404, "Playbook not found")
    return pb.to_dict()


@router.put("/playbooks/{playbook_id}")
def update_playbook(
    playbook_id: int,
    payload: PlaybookUpdate,
    user: User = Depends(require_permission("forensic:manage_playbooks")),
    session: Session = Depends(get_db_session),
):
    """Update a forensic playbook."""
    repo = ForensicRepository(session)
    pb = repo.get_playbook_by_id(playbook_id)
    if not pb:
        raise HTTPException(404, "Playbook not found")
    pb = repo.update_playbook(
        pb,
        name=payload.name,
        description=payload.description,
        investigation_type=payload.investigation_type,
        is_active=payload.is_active,
        steps=payload.steps,
    )
    session.commit()
    return pb.to_dict()


@router.delete("/playbooks/{playbook_id}")
def delete_playbook(
    playbook_id: int,
    user: User = Depends(require_permission("forensic:manage_playbooks")),
    session: Session = Depends(get_db_session),
):
    """Delete a forensic playbook."""
    repo = ForensicRepository(session)
    pb = repo.get_playbook_by_id(playbook_id)
    if not pb:
        raise HTTPException(404, "Playbook not found")
    repo.delete_playbook(pb)
    session.commit()
    return {"status": "ok"}


# =============================================================================
# SLA Profiles
# =============================================================================

@router.get("/sla-profiles")
def get_sla_profiles(
    user: User = Depends(require_permission("forensic:read")),
):
    """Get default SLA profiles per investigation type."""
    return DEFAULT_SLA_PROFILES


# =============================================================================
# Enum Values (for UI dropdowns)
# =============================================================================

@router.get("/enums")
def get_enums(
    user: User = Depends(require_permission("forensic:read")),
):
    """Get all enum values for forensics UI."""
    return {
        "case_statuses": [s.value for s in ForensicCaseStatus],
        "case_priorities": [p.value for p in ForensicCasePriority],
        "investigation_types": [t.value for t in InvestigationType],
        "evidence_types": [t.value for t in EvidenceType],
        "evidence_statuses": [s.value for s in EvidenceStatus],
        "custody_actions": [a.value for a in CustodyAction],
    }


# =============================================================================
# Lock / Unlock
# =============================================================================

@router.post("/cases/{case_id}/lock")
def lock_case(
    case_id: int,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Lock a forensic investigation to prevent unauthorized edits."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    if case.is_locked:
        raise HTTPException(400, f"Already locked by {case.locked_by.username if case.locked_by else 'unknown'}")
    case = repo.lock_case(case, user.id)
    session.commit()
    return case.to_dict()


@router.post("/cases/{case_id}/unlock")
def unlock_case(
    case_id: int,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    """Unlock a forensic investigation."""
    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Investigation not found")
    if not case.is_locked:
        raise HTTPException(400, "Investigation is not locked")
    # Only the locker, lead, or someone with close permission can unlock
    if case.locked_by_id != user.id and case.lead_investigator_id != user.id:
        if not user.has_permission("forensic:close"):
            raise HTTPException(403, "Only the lock holder, lead investigator, or a lead/admin can unlock")
    case = repo.unlock_case(case, user.id)
    session.commit()
    return case.to_dict()


# =============================================================================
# IOC Extraction
# =============================================================================

MAX_IOC_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_IOC_EXTENSIONS = {".csv", ".txt", ".log", ".json", ".md", ".tsv", ".ioc"}


@router.post("/extract-iocs")
async def extract_iocs_endpoint(
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None),
    user: User = Depends(require_permission("forensic:read")),
):
    """Extract IOCs from uploaded file or pasted text.

    Accepts CSV, TXT, LOG, JSON, MD, TSV, or IOC files (max 10 MB),
    or freeform text via the 'text' form field.

    Returns categorized IOCs: ipv4, ipv6, md5, sha1, sha256, domains,
    urls, emails, cves, mac_addresses, hostnames.
    """
    from ion.services.ioc_text_extractor import extract_iocs, extract_from_file

    if file and file.filename:
        ext = ("." + file.filename.rsplit(".", 1)[-1].lower()) if "." in file.filename else ""
        if ext not in ALLOWED_IOC_EXTENSIONS:
            raise HTTPException(
                400,
                f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_IOC_EXTENSIONS))}",
            )
        content = await file.read()
        if len(content) > MAX_IOC_FILE_SIZE:
            raise HTTPException(400, f"File too large. Maximum size is {MAX_IOC_FILE_SIZE // (1024*1024)} MB.")
        if not content:
            raise HTTPException(400, "File is empty.")
        return extract_from_file(content, file.filename)
    elif text and text.strip():
        return extract_iocs(text.strip())
    else:
        raise HTTPException(400, "Provide either a file upload or text to extract IOCs from.")


# =============================================================================
# Reference Documents
# =============================================================================

FORENSIC_REFERENCE_DOCS = [
    {
        "id": "evidence-handling",
        "title": "Evidence Handling & Preservation",
        "category": "Procedures",
        "content": """## Evidence Handling & Preservation Guide

### Purpose
Ensure all digital and physical evidence is collected, preserved, and documented in a forensically sound manner that maintains its integrity and admissibility.

### Before You Begin
- Photograph the scene and all devices in situ before touching anything
- Document date, time, location, and all personnel present
- Wear anti-static wrist straps when handling storage media

### Digital Evidence Collection
1. **Volatile data first** - Capture RAM, running processes, network connections before powering down
2. **Create forensic image** - Use write-blockers; never work on original media
3. **Hash everything** - Generate MD5 and SHA-256 hashes immediately after imaging
4. **Document the chain** - Log every transfer, every person who touches evidence

### Storage Requirements
- Store in tamper-evident bags with unique evidence labels
- Maintain temperature-controlled environment (15-25C, <80% humidity)
- Digital copies stored on encrypted, access-controlled media
- Minimum two independent copies of all forensic images

### Common Mistakes to Avoid
- Powering on a suspect device without a write-blocker
- Forgetting to document the hash before and after analysis
- Allowing evidence to leave secure storage without logging custody
- Using the original evidence instead of a forensic copy"""
    },
    {
        "id": "chain-of-custody",
        "title": "Chain of Custody Procedures",
        "category": "Procedures",
        "content": """## Chain of Custody Procedures

### Why Chain of Custody Matters
An unbroken chain of custody proves that evidence has not been tampered with. Any gap can render evidence inadmissible and compromise the entire investigation.

### Required Information for Every Transfer
- Full name and role of person releasing evidence
- Full name and role of person receiving evidence
- Date and time (use 24-hour format, include timezone)
- Reason for transfer (analysis, storage, return, etc.)
- Physical location of transfer
- Condition of evidence at time of transfer
- Signature of both parties (or digital acknowledgement in ION)

### Custody Log Best Practices
1. **Never leave evidence unattended** - If you step away, check it back in
2. **Log immediately** - Don't rely on memory; log the action as it happens
3. **Use tamper-evident seals** - If a seal is broken, document it and re-seal with a new unique ID
4. **Limit access** - Only personnel with a documented need should handle evidence
5. **Secure transport** - Use locked containers for physical transport

### Digital Chain of Custody
- Log all access to forensic images and analysis workstations
- Use hash verification before and after every analysis session
- Maintain access logs for shared storage locations
- Document any tools used and their versions"""
    },
    {
        "id": "disk-imaging",
        "title": "Forensic Disk Imaging Guide",
        "category": "Technical",
        "content": """## Forensic Disk Imaging Guide

### Tools
- **dd / dcfldd** - Linux command-line, widely accepted in court
- **FTK Imager** - GUI-based, creates E01/AFF formats
- **Guymager** - Open-source GUI imager for Linux

### Step-by-Step Process

#### 1. Preparation
- Verify your destination drive is larger than the source
- Connect source drive through a **hardware write-blocker**
- Document the source drive (make, model, serial number, capacity)

#### 2. Create the Image
```
# Using dcfldd (preferred for forensics)
dcfldd if=/dev/sdX of=/mnt/evidence/case001.dd hash=sha256 hashlog=/mnt/evidence/case001.hash bs=4096

# Using dd
dd if=/dev/sdX of=/mnt/evidence/case001.dd bs=4096 status=progress
sha256sum /dev/sdX > /mnt/evidence/source.sha256
sha256sum /mnt/evidence/case001.dd > /mnt/evidence/image.sha256
```

#### 3. Verify Integrity
- Compare source hash to image hash - they **must** match
- Document both hashes in the evidence log
- Store hash values separately from the image

#### 4. Create Working Copy
- Never analyze the master forensic image
- Create a second copy for analysis
- Verify the working copy hash matches the master

### Image Formats
| Format | Extension | Notes |
|--------|-----------|-------|
| Raw/dd | .dd, .raw | Universal, simple, large |
| E01 | .E01 | EnCase format, supports compression |
| AFF4 | .aff4 | Open format, supports compression and metadata |"""
    },
    {
        "id": "memory-forensics",
        "title": "Memory Forensics Acquisition",
        "category": "Technical",
        "content": """## Memory Forensics Acquisition

### Why Capture Memory?
RAM contains evidence that disappears when a system is powered off: running processes, network connections, encryption keys, malware in memory, user credentials, clipboard contents.

### Acquisition Tools
- **WinPmem** - Windows physical memory acquisition
- **LiME** - Linux Memory Extractor (kernel module)
- **AVML** - Microsoft's Acquire Volatile Memory for Linux
- **Magnet RAM Capture** - Windows GUI tool

### Windows Memory Capture
```
# Using WinPmem (run as Administrator)
winpmem_mini_x64.exe output.raw

# Verify hash immediately
certutil -hashfile output.raw SHA256
```

### Linux Memory Capture
```
# Using LiME
insmod lime-$(uname -r).ko "path=/mnt/evidence/memory.lime format=lime"

# Using AVML
./avml /mnt/evidence/memory.lime
sha256sum /mnt/evidence/memory.lime
```

### Analysis with Volatility 3
```
# Identify the OS profile
vol -f memory.lime windows.info
vol -f memory.lime linux.bash

# List processes
vol -f memory.lime windows.pslist
vol -f memory.lime windows.pstree

# Network connections
vol -f memory.lime windows.netscan

# Check for injected code
vol -f memory.lime windows.malfind
```

### Best Practices
- Capture memory **before** disk imaging (volatile data first)
- Note the exact time of capture
- Document system uptime at time of acquisition
- Hash the memory dump immediately"""
    },
    {
        "id": "network-forensics",
        "title": "Network Forensics & Packet Capture",
        "category": "Technical",
        "content": """## Network Forensics & Packet Capture

### Capture Methods

#### Full Packet Capture
```
# tcpdump - capture all traffic on an interface
tcpdump -i eth0 -w /evidence/capture.pcap -C 1000 -Z root

# With BPF filter for specific host
tcpdump -i eth0 host 10.0.0.50 -w /evidence/suspect_traffic.pcap
```

#### NetFlow / Metadata Only
- Lower storage requirements, sufficient for many investigations
- Captures: src/dst IP, ports, protocol, byte counts, timestamps
- Tools: nfdump, SiLK, Elastic Beats

### Analysis Workflow
1. **Identify timeframe** - When did the incident occur?
2. **Filter relevant traffic** - Focus on suspect IPs, unusual ports, high volumes
3. **Look for indicators**:
   - DNS queries to known-bad domains
   - Connections to C2 infrastructure
   - Large outbound transfers (exfiltration)
   - Unusual protocols or ports
   - Beaconing patterns (regular interval connections)
4. **Extract artifacts** - Files, credentials, commands from packet payloads
5. **Correlate** - Match network activity to host-based evidence

### ION PCAP Analyzer
Use ION's built-in PCAP analyzer at `/pcap` for automated detection of:
- Beaconing patterns
- DNS tunneling
- Domain Generation Algorithms (DGA)
- Port scanning
- Data exfiltration indicators
- Suspicious user agents
- Cleartext credentials

### Legal Considerations
- Ensure you have authorization to capture network traffic
- Document the legal basis for the capture
- Capture only what is necessary and proportionate
- Protect captured data as evidence"""
    },
    {
        "id": "malware-analysis",
        "title": "Malware Analysis Procedures",
        "category": "Technical",
        "content": """## Malware Analysis Procedures

### Safety First
- **Never analyze malware on a production system**
- Use isolated VMs with no network access (or controlled network)
- Take VM snapshots before analysis for easy rollback
- Disable shared folders between host and analysis VM

### Static Analysis
1. **File identification**
   - `file malware.exe` - identify file type
   - `sha256sum malware.exe` - get hash for lookup
   - Check hash against VirusTotal, MalwareBazaar
2. **String extraction**
   - `strings -a malware.exe | less` - readable strings
   - Look for: URLs, IPs, registry keys, file paths, error messages
3. **PE analysis** (Windows executables)
   - Check imports/exports (suspicious: WinExec, URLDownloadToFile, VirtualAlloc)
   - Examine sections (.text, .data, unusual section names)
   - Check for packers (UPX, Themida, custom)

### Dynamic Analysis
1. **Set up monitoring** before execution:
   - Process Monitor (ProcMon) - file/registry/network activity
   - Wireshark/tcpdump - network capture
   - RegShot - registry diff before/after
2. **Execute in sandbox** and observe:
   - Files created/modified/deleted
   - Registry changes
   - Network connections attempted
   - Processes spawned
   - Persistence mechanisms installed
3. **Document everything** with timestamps

### Reporting
- IOC extraction: hashes, domains, IPs, file paths, registry keys
- MITRE ATT&CK technique mapping
- Recommended detection rules (YARA, Sigma)
- Remediation steps"""
    },
    {
        "id": "incident-timeline",
        "title": "Building an Investigation Timeline",
        "category": "Methodology",
        "content": """## Building an Investigation Timeline

### Purpose
A well-constructed timeline is the backbone of any forensic investigation. It establishes the sequence of events and helps identify the full scope of an incident.

### Data Sources for Timeline Events
- **System logs**: Windows Event Logs, syslog, journal
- **Application logs**: web server, database, authentication
- **File system**: creation, modification, access timestamps (MAC times)
- **Registry**: last write timestamps on keys
- **Network logs**: firewall, proxy, DNS, NetFlow
- **SIEM alerts**: correlated events with timestamps
- **Email headers**: sent/received timestamps
- **Cloud audit logs**: AWS CloudTrail, Azure Activity Log, GCP Audit

### Timeline Construction Process
1. **Define scope** - What is the timeframe of interest?
2. **Collect timestamps** from all available sources
3. **Normalize timezones** - Convert everything to UTC
4. **Merge and sort** chronologically
5. **Identify key events**: initial compromise, lateral movement, data access, exfiltration
6. **Fill gaps** - What happened between known events?
7. **Validate** - Do the events make logical sense in sequence?

### Tools
- **Plaso/log2timeline** - Automated super-timeline creation from disk images
- **TimeSketch** - Collaborative timeline analysis
- **Excel/Sheets** - Simple but effective for smaller investigations

### ION Timeline
Use the investigation timeline in ION to document events as you discover them. Tag entries by type (status_change, evidence_added, custody_change, note) to keep the timeline organized.

### Common Pitfalls
- Assuming system clocks are accurate (check NTP configuration)
- Mixing timezones without converting to a common standard
- Focusing only on the incident window (look before and after)
- Not documenting the absence of expected log entries"""
    },
    {
        "id": "report-writing",
        "title": "Writing Forensic Investigation Reports",
        "category": "Methodology",
        "content": """## Writing Forensic Investigation Reports

### Report Structure
1. **Executive Summary** - 1-2 paragraphs for non-technical stakeholders
2. **Scope & Objectives** - What was investigated and why
3. **Methodology** - Tools and techniques used
4. **Findings** - Detailed technical findings with evidence
5. **Timeline** - Chronological sequence of events
6. **Evidence Summary** - List of all evidence with hashes and custody chain
7. **Conclusions** - What happened, who was involved, what was affected
8. **Recommendations** - Remediation and prevention measures

### Writing Guidelines
- **Be objective** - State facts, not opinions
- **Be precise** - Include timestamps, hashes, exact file paths
- **Be reproducible** - Another examiner should reach the same conclusions
- **Separate facts from analysis** - Clearly distinguish observations from interpretations
- **Use screenshots** - Visual evidence supports your narrative
- **Reference evidence** - Cite specific evidence items for every claim

### Common Report Mistakes
- Using jargon without explanation
- Making claims without supporting evidence
- Omitting methodology details
- Failing to document negative findings (what you looked for but didn't find)
- Not having the report peer-reviewed before submission

### ION Auto-Reports
When you close an investigation in ION, a report is automatically generated and saved to the Document Library under "Forensic Reports". This includes:
- Case metadata and SLA compliance
- Evidence inventory with chain of custody
- Full investigation timeline
- Your summary, findings, and recommendations

You can then amend the document in the Document Library to add additional detail."""
    },
    {
        "id": "legal-considerations",
        "title": "Legal & Compliance Considerations",
        "category": "Methodology",
        "content": """## Legal & Compliance Considerations

### Before Starting Any Investigation
1. **Authorization** - Ensure you have written authorization to investigate
2. **Scope** - Clearly define what you are and are not authorized to examine
3. **Legal counsel** - Involve legal early for incidents that may lead to prosecution
4. **Data protection** - Understand GDPR, CCPA, or relevant privacy regulations
5. **Employment law** - Insider threat investigations require HR and legal involvement

### Evidence Admissibility Requirements
- **Authenticity** - Can you prove the evidence is what you claim it is?
- **Integrity** - Can you prove it hasn't been altered? (hash verification)
- **Chain of custody** - Can you account for every moment the evidence was handled?
- **Proportionality** - Did you collect only what was necessary?
- **Legality** - Was the evidence collected lawfully?

### Documentation Requirements
- Every action taken during the investigation must be documented
- Include tools used and their versions
- Record who performed each action and when
- Note any anomalies or deviations from standard procedures
- Keep contemporaneous notes (write it down as it happens, not later)

### Data Handling
- Classify all evidence according to your organization's data classification scheme
- Apply appropriate access controls (need-to-know basis)
- Securely dispose of evidence copies when no longer needed
- Maintain evidence for the required retention period

### Cross-Border Considerations
- Data sovereignty laws may restrict where evidence can be stored/processed
- Mutual Legal Assistance Treaties (MLATs) for international cases
- Different jurisdictions have different rules for digital evidence"""
    },
]


@router.get("/reference-docs")
def get_reference_docs(
    user: User = Depends(require_permission("forensic:read")),
):
    """Get forensic reference/how-to documents."""
    return FORENSIC_REFERENCE_DOCS
