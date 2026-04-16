"""Repository for Forensic Investigation operations."""

import json
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy import select, func
from sqlalchemy.orm import Session, joinedload, selectinload

from ion.models.forensics import (
    ForensicCase,
    ForensicCaseStatus,
    ForensicCasePriority,
    EvidenceItem,
    EvidenceStatus,
    CustodyLogEntry,
    CustodyAction,
    ForensicPlaybook,
    ForensicPlaybookStep,
    ForensicCaseStep,
    ForensicTimelineEntry,
)


# Default SLA profiles per investigation type (hours for each milestone)
DEFAULT_SLA_PROFILES = {
    "malware_analysis": {
        "initial_response": 4,
        "evidence_collection": 24,
        "analysis": 72,
        "reporting": 120,
    },
    "insider_threat": {
        "initial_response": 2,
        "evidence_collection": 12,
        "analysis": 48,
        "reporting": 96,
    },
    "data_breach": {
        "initial_response": 1,
        "evidence_collection": 8,
        "analysis": 48,
        "reporting": 72,
    },
    "unauthorized_access": {
        "initial_response": 2,
        "evidence_collection": 16,
        "analysis": 48,
        "reporting": 96,
    },
    "network_intrusion": {
        "initial_response": 1,
        "evidence_collection": 8,
        "analysis": 48,
        "reporting": 72,
    },
    "fraud": {
        "initial_response": 4,
        "evidence_collection": 48,
        "analysis": 120,
        "reporting": 168,
    },
    "policy_violation": {
        "initial_response": 8,
        "evidence_collection": 48,
        "analysis": 120,
        "reporting": 168,
    },
    "other": {
        "initial_response": 4,
        "evidence_collection": 24,
        "analysis": 72,
        "reporting": 120,
    },
}

# Status transition map: from_status -> to_status triggers SLA met field
SLA_TRANSITION_MAP = {
    ForensicCaseStatus.EVIDENCE_COLLECTION.value: "sla_initial_response_met",
    ForensicCaseStatus.ANALYSIS.value: "sla_evidence_collection_met",
    ForensicCaseStatus.REPORTING.value: "sla_analysis_met",
    ForensicCaseStatus.REVIEW.value: "sla_reporting_met",
    ForensicCaseStatus.CLOSED.value: "sla_reporting_met",
}


class ForensicRepository:
    """Repository for Forensic Investigation CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    # =========================================================================
    # Case Number Generation
    # =========================================================================

    def _next_case_number(self) -> str:
        """Generate next FOR-NNNN case number."""
        stmt = select(func.max(ForensicCase.id))
        max_id = self.session.execute(stmt).scalar() or 0
        return f"FOR-{max_id + 1:04d}"

    def _next_evidence_number(self, case_number: str) -> str:
        """Generate next evidence number like FOR-NNNN-E001."""
        stmt = (
            select(func.count(EvidenceItem.id))
            .join(ForensicCase)
            .where(ForensicCase.case_number == case_number)
        )
        count = self.session.execute(stmt).scalar() or 0
        return f"{case_number}-E{count + 1:03d}"

    # =========================================================================
    # SLA Helpers
    # =========================================================================

    def _apply_sla_profile(self, case: ForensicCase) -> None:
        """Set SLA due dates based on profile and creation time."""
        profile = case.sla_profile or DEFAULT_SLA_PROFILES.get(
            case.investigation_type, DEFAULT_SLA_PROFILES["other"]
        )
        base_time = case.created_at or datetime.utcnow()
        case.sla_initial_response_due = base_time + timedelta(hours=profile.get("initial_response", 4))
        case.sla_evidence_collection_due = base_time + timedelta(hours=profile.get("evidence_collection", 24))
        case.sla_analysis_due = base_time + timedelta(hours=profile.get("analysis", 72))
        case.sla_reporting_due = base_time + timedelta(hours=profile.get("reporting", 120))

    def _mark_sla_met(self, case: ForensicCase, new_status: str) -> None:
        """Set SLA met timestamp on status transition."""
        field = SLA_TRANSITION_MAP.get(new_status)
        if field and getattr(case, field) is None:
            setattr(case, field, datetime.utcnow())

    def get_sla_status(self, case: ForensicCase) -> dict:
        """Return SLA compliance data for a case."""
        now = datetime.utcnow()
        milestones = []
        for name in ("initial_response", "evidence_collection", "analysis", "reporting"):
            due = getattr(case, f"sla_{name}_due")
            met = getattr(case, f"sla_{name}_met")
            if due is None:
                milestones.append({"name": name, "status": "not_set"})
                continue
            if met:
                milestones.append({
                    "name": name,
                    "status": "met" if met <= due else "breached_met",
                    "due": due.isoformat(),
                    "met": met.isoformat(),
                })
            elif now > due:
                milestones.append({
                    "name": name,
                    "status": "breached",
                    "due": due.isoformat(),
                })
            else:
                remaining = (due - now).total_seconds()
                total = (due - (case.created_at or now)).total_seconds() or 1
                pct_remaining = remaining / total
                milestones.append({
                    "name": name,
                    "status": "at_risk" if pct_remaining < 0.25 else "on_track",
                    "due": due.isoformat(),
                    "pct_remaining": round(pct_remaining * 100, 1),
                })
        return {"milestones": milestones}

    # =========================================================================
    # Timeline Helper
    # =========================================================================

    def _add_timeline_entry(
        self,
        case_id: int,
        user_id: int,
        content: str,
        entry_type: str = "note",
        metadata: dict | None = None,
    ) -> ForensicTimelineEntry:
        entry = ForensicTimelineEntry(
            forensic_case_id=case_id,
            user_id=user_id,
            content=content,
            entry_type=entry_type,
            timestamp=datetime.utcnow(),
            metadata_json=metadata,
        )
        self.session.add(entry)
        return entry

    # =========================================================================
    # Case CRUD
    # =========================================================================

    def create_case(
        self,
        title: str,
        investigation_type: str,
        created_by_id: int,
        description: str | None = None,
        priority: str = ForensicCasePriority.MEDIUM.value,
        lead_investigator_id: int | None = None,
        alert_case_id: int | None = None,
        classification: str | None = None,
        sla_profile: dict | None = None,
        playbook_id: int | None = None,
    ) -> ForensicCase:
        case = ForensicCase(
            case_number=self._next_case_number(),
            title=title,
            description=description,
            status=ForensicCaseStatus.INTAKE.value,
            priority=priority,
            investigation_type=investigation_type,
            classification=classification,
            lead_investigator_id=lead_investigator_id,
            alert_case_id=alert_case_id,
            playbook_id=playbook_id,
            sla_profile=sla_profile or DEFAULT_SLA_PROFILES.get(investigation_type),
        )
        self.session.add(case)
        self.session.flush()
        self._apply_sla_profile(case)

        # Copy playbook steps as case steps
        if playbook_id:
            pb = self.get_playbook_by_id(playbook_id)
            if pb and pb.steps:
                for step in pb.steps:
                    cs = ForensicCaseStep(
                        forensic_case_id=case.id,
                        playbook_step_id=step.id,
                        step_order=step.step_order,
                        title=step.title,
                        description=step.description,
                        is_required=step.is_required,
                        fields_json=step.fields_json,
                    )
                    self.session.add(cs)

        self._add_timeline_entry(
            case.id, created_by_id,
            f"Investigation created: {title}" + (f" (playbook: {pb.name})" if playbook_id and pb else ""),
            entry_type="status_change",
            metadata={"new_status": ForensicCaseStatus.INTAKE.value, "playbook_id": playbook_id},
        )
        self.session.flush()
        return case

    def get_case_by_id(self, case_id: int) -> Optional[ForensicCase]:
        # v0.9.81: selectinload for every *-to-many collection — previous
        # chained joinedload produced a 6-dimensional cartesian
        # (case_steps × evidence_items × custody_log × timeline_entries × …).
        stmt = (
            select(ForensicCase)
            .options(
                joinedload(ForensicCase.lead_investigator),
                joinedload(ForensicCase.playbook).selectinload(ForensicPlaybook.steps),
                selectinload(ForensicCase.case_steps).joinedload(ForensicCaseStep.completed_by),
                selectinload(ForensicCase.evidence_items).joinedload(EvidenceItem.collected_by),
                selectinload(ForensicCase.evidence_items).selectinload(EvidenceItem.custody_log),
                selectinload(ForensicCase.timeline_entries).joinedload(ForensicTimelineEntry.user),
            )
            .where(ForensicCase.id == case_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_cases(
        self,
        status: str | None = None,
        investigation_type: str | None = None,
        priority: str | None = None,
        lead_investigator_id: int | None = None,
    ) -> List[ForensicCase]:
        stmt = (
            select(ForensicCase)
            .options(
                joinedload(ForensicCase.lead_investigator),
                joinedload(ForensicCase.playbook),
                selectinload(ForensicCase.case_steps),
                selectinload(ForensicCase.evidence_items),
            )
        )
        if status:
            stmt = stmt.where(ForensicCase.status == status)
        if investigation_type:
            stmt = stmt.where(ForensicCase.investigation_type == investigation_type)
        if priority:
            stmt = stmt.where(ForensicCase.priority == priority)
        if lead_investigator_id:
            stmt = stmt.where(ForensicCase.lead_investigator_id == lead_investigator_id)
        stmt = stmt.order_by(ForensicCase.created_at.desc())
        return list(self.session.execute(stmt).scalars().all())

    def update_case(
        self,
        case: ForensicCase,
        user_id: int,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        priority: str | None = None,
        lead_investigator_id: int | None = None,
        classification: str | None = None,
    ) -> ForensicCase:
        if title is not None:
            case.title = title
        if description is not None:
            case.description = description
        if priority is not None:
            case.priority = priority
        if lead_investigator_id is not None:
            case.lead_investigator_id = lead_investigator_id
        if classification is not None:
            case.classification = classification
        if status is not None and status != case.status:
            old_status = case.status
            case.status = status
            self._mark_sla_met(case, status)
            self._add_timeline_entry(
                case.id, user_id,
                f"Status changed from {old_status} to {status}",
                entry_type="status_change",
                metadata={"old_status": old_status, "new_status": status},
            )
        self.session.flush()
        return case

    def close_case(
        self,
        case: ForensicCase,
        closed_by_id: int,
        summary: str | None = None,
        findings: str | None = None,
        recommendations: str | None = None,
    ) -> ForensicCase:
        old_status = case.status
        case.status = ForensicCaseStatus.CLOSED.value
        case.closed_at = datetime.utcnow()
        case.closed_by_id = closed_by_id
        if summary is not None:
            case.summary = summary
        if findings is not None:
            case.findings = findings
        if recommendations is not None:
            case.recommendations = recommendations
        self._mark_sla_met(case, ForensicCaseStatus.CLOSED.value)
        self._add_timeline_entry(
            case.id, closed_by_id,
            f"Investigation closed (was {old_status})",
            entry_type="status_change",
            metadata={"old_status": old_status, "new_status": ForensicCaseStatus.CLOSED.value},
        )
        self.session.flush()
        return case

    # =========================================================================
    # Lock / Unlock
    # =========================================================================

    def lock_case(self, case: ForensicCase, user_id: int) -> ForensicCase:
        """Lock investigation — only lead investigator or the locker can modify."""
        case.is_locked = True
        case.locked_by_id = user_id
        case.locked_at = datetime.utcnow()
        self._add_timeline_entry(
            case.id, user_id,
            "Investigation locked",
            entry_type="status_change",
            metadata={"action": "locked"},
        )
        self.session.flush()
        return case

    def unlock_case(self, case: ForensicCase, user_id: int) -> ForensicCase:
        """Unlock an investigation."""
        case.is_locked = False
        case.locked_by_id = None
        case.locked_at = None
        self._add_timeline_entry(
            case.id, user_id,
            "Investigation unlocked",
            entry_type="status_change",
            metadata={"action": "unlocked"},
        )
        self.session.flush()
        return case

    # =========================================================================
    # Case Steps (Fillable Sections)
    # =========================================================================

    def get_case_steps(self, case_id: int) -> List[ForensicCaseStep]:
        stmt = (
            select(ForensicCaseStep)
            .options(joinedload(ForensicCaseStep.completed_by))
            .where(ForensicCaseStep.forensic_case_id == case_id)
            .order_by(ForensicCaseStep.step_order)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def update_case_step(
        self,
        step: ForensicCaseStep,
        user_id: int,
        content: str | None = None,
        is_completed: bool | None = None,
        title: str | None = None,
        description: str | None = None,
        fields_data: dict | None = None,
    ) -> ForensicCaseStep:
        if title is not None:
            step.title = title
        if description is not None:
            step.description = description
        if content is not None:
            step.content = content
        if fields_data is not None:
            step.fields_data = json.dumps(fields_data)
        if is_completed is not None and is_completed != step.is_completed:
            step.is_completed = is_completed
            if is_completed:
                step.completed_by_id = user_id
                step.completed_at = datetime.utcnow()
                self._add_timeline_entry(
                    step.forensic_case_id, user_id,
                    f"Section completed: {step.title}",
                    entry_type="status_change",
                    metadata={"step_id": step.id, "action": "step_completed"},
                )
            else:
                step.completed_by_id = None
                step.completed_at = None
        self.session.flush()
        return step

    def add_case_step(
        self,
        case_id: int,
        user_id: int,
        title: str,
        description: str | None = None,
        is_required: bool = False,
    ) -> ForensicCaseStep:
        """Add an ad-hoc step to a case (not from a playbook)."""
        max_order = self.session.execute(
            select(func.max(ForensicCaseStep.step_order))
            .where(ForensicCaseStep.forensic_case_id == case_id)
        ).scalar() or 0
        step = ForensicCaseStep(
            forensic_case_id=case_id,
            step_order=max_order + 1,
            title=title,
            description=description,
            is_required=is_required,
        )
        self.session.add(step)
        self._add_timeline_entry(
            case_id, user_id,
            f"Section added: {title}",
            entry_type="status_change",
            metadata={"action": "step_added"},
        )
        self.session.flush()
        return step

    def delete_case_step(self, step: ForensicCaseStep, user_id: int) -> None:
        self._add_timeline_entry(
            step.forensic_case_id, user_id,
            f"Section removed: {step.title}",
            entry_type="status_change",
            metadata={"action": "step_removed"},
        )
        self.session.delete(step)
        self.session.flush()

    # =========================================================================
    # Report → Document Library
    # =========================================================================

    def generate_report_document(self, case: ForensicCase, created_by_username: str) -> "Document":
        """Generate a markdown report and save it as a Document in the library."""
        from ion.models.document import Document, DocumentVersion
        from ion.models.template import Collection, Tag

        report = self.generate_report(case)
        md = self._render_report_markdown(report)

        # Find or create "Forensic Reports" collection
        collection = self.session.execute(
            select(Collection).where(Collection.name == "Forensic Reports")
        ).scalar_one_or_none()
        if not collection:
            collection = Collection(name="Forensic Reports", description="Auto-generated forensic investigation reports", icon="shield")
            self.session.add(collection)
            self.session.flush()

        doc_name = f"Forensic Report - {case.case_number} - {case.title}"
        doc = Document(
            name=doc_name,
            rendered_content=md,
            output_format="markdown",
            collection_id=collection.id,
            current_version=1,
            status="active",
        )
        self.session.add(doc)
        self.session.flush()

        version = DocumentVersion(
            document_id=doc.id,
            version_number=1,
            rendered_content=md,
            amendment_reason="Auto-generated from forensic investigation closure",
            amended_by=created_by_username,
        )
        self.session.add(version)

        # Auto-tag
        tag_names = ["forensic-report", case.investigation_type, case.priority]
        if case.classification:
            tag_names.append(case.classification.lower().replace(":", "-"))
        tags = []
        for tn in tag_names:
            tn = tn.strip()
            if not tn:
                continue
            tag = self.session.execute(
                select(Tag).where(Tag.name == tn)
            ).scalar_one_or_none()
            if not tag:
                tag = Tag(name=tn)
                self.session.add(tag)
            tags.append(tag)
        doc.tags = tags

        case.report_document_id = doc.id
        self.session.flush()
        return doc

    def _render_report_markdown(self, report: dict) -> str:
        """Render report dict as a formatted markdown document."""
        lines = []
        lines.append(f"# Forensic Investigation Report: {report['case_number']}")
        lines.append("")
        lines.append(f"**Title:** {report['title']}")
        lines.append(f"**Type:** {report['investigation_type'].replace('_', ' ').title()}")
        lines.append(f"**Priority:** {report['priority'].upper()}")
        lines.append(f"**Classification:** {report.get('classification') or 'N/A'}")
        lines.append(f"**Lead Investigator:** {report.get('lead_investigator') or 'Unassigned'}")
        lines.append(f"**Created:** {report.get('created_at', 'N/A')}")
        lines.append(f"**Closed:** {report.get('closed_at', 'N/A')}")
        lines.append(f"**Status:** {report['status'].replace('_', ' ').title()}")
        lines.append("")

        # SLA Compliance
        lines.append("## SLA Compliance")
        lines.append("")
        lines.append("| Milestone | Status | Due | Met |")
        lines.append("|-----------|--------|-----|-----|")
        for m in report.get("sla_compliance", {}).get("milestones", []):
            lines.append(f"| {m['name'].replace('_', ' ').title()} | {m['status'].replace('_', ' ').title()} | {m.get('due', 'N/A')} | {m.get('met', '-')} |")
        lines.append("")

        # Description
        if report.get("description"):
            lines.append("## Description")
            lines.append("")
            lines.append(report["description"])
            lines.append("")

        # Summary
        if report.get("summary"):
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(report["summary"])
            lines.append("")

        # Findings
        if report.get("findings"):
            lines.append("## Findings")
            lines.append("")
            lines.append(report["findings"])
            lines.append("")

        # Recommendations
        if report.get("recommendations"):
            lines.append("## Recommendations")
            lines.append("")
            lines.append(report["recommendations"])
            lines.append("")

        # Investigation Sections (from playbook steps)
        case_steps = report.get("case_steps", [])
        if case_steps:
            lines.append("## Investigation Sections")
            lines.append("")
            for step in case_steps:
                status_icon = "COMPLETE" if step.get("is_completed") else "PENDING"
                lines.append(f"### {step['step_order']}. {step['title']} [{status_icon}]")
                if step.get("description"):
                    lines.append(f"*{step['description']}*")
                    lines.append("")
                # Render structured field data if present
                fd = step.get("fields_data", {})
                fields_def = step.get("fields", [])
                if fd and fields_def:
                    for fdef in fields_def:
                        key = fdef.get("key", "")
                        label = fdef.get("label", key)
                        ftype = fdef.get("type", "text")
                        val = fd.get(key)
                        if val is None or val == "" or val == []:
                            continue
                        if ftype == "list" and isinstance(val, list):
                            lines.append(f"**{label}:**")
                            for item in val:
                                lines.append(f"- `{item}`")
                        elif ftype == "table" and isinstance(val, list):
                            cols = fdef.get("columns", [])
                            if cols and val:
                                lines.append(f"**{label}:**")
                                lines.append("| " + " | ".join(cols) + " |")
                                lines.append("| " + " | ".join(["---"] * len(cols)) + " |")
                                for row in val:
                                    lines.append("| " + " | ".join(str(row.get(c, "")) for c in cols) + " |")
                        elif ftype == "checkbox":
                            lines.append(f"**{label}:** {'Yes' if val else 'No'}")
                        else:
                            lines.append(f"**{label}:** {val}")
                    lines.append("")
                if step.get("content"):
                    lines.append(step["content"])
                elif not fd:
                    lines.append("*No content provided.*")
                lines.append("")

        # Evidence Items
        evidence = report.get("evidence_items", [])
        if evidence:
            lines.append("## Evidence Items")
            lines.append("")
            lines.append("| # | Name | Type | Status | SHA-256 | Storage |")
            lines.append("|---|------|------|--------|---------|---------|")
            for e in evidence:
                sha = e.get("hash_sha256", "-") or "-"
                if len(sha) > 16:
                    sha = sha[:16] + "..."
                lines.append(f"| {e['evidence_number']} | {e['name']} | {e.get('evidence_type', '-').replace('_', ' ').title()} | {e.get('status', '-').replace('_', ' ').title()} | `{sha}` | {e.get('storage_location') or '-'} |")
            lines.append("")

            # Chain of custody per evidence
            for e in evidence:
                custody = e.get("custody_log", [])
                if custody:
                    lines.append(f"### Chain of Custody: {e['evidence_number']}")
                    lines.append("")
                    lines.append("| Timestamp | Action | Performed By | Received By | Location | Notes |")
                    lines.append("|-----------|--------|--------------|-------------|----------|-------|")
                    for c in custody:
                        lines.append(f"| {c.get('timestamp', '-')} | {c.get('action', '-').replace('_', ' ').title()} | {c.get('performed_by_username', '-')} | {c.get('received_by_username', '-') or '-'} | {c.get('location') or '-'} | {c.get('notes') or '-'} |")
                    lines.append("")

        # Timeline
        timeline = report.get("timeline", [])
        if timeline:
            lines.append("## Investigation Timeline")
            lines.append("")
            for t in timeline:
                lines.append(f"- **{t.get('timestamp', '')}** [{t.get('entry_type', 'note')}] ({t.get('username', 'System')}): {t['content']}")
            lines.append("")

        lines.append("---")
        lines.append("*Report auto-generated by ION Forensic Investigation Module*")
        return "\n".join(lines)

    def get_overdue_cases(self) -> List[ForensicCase]:
        """Get cases with breached SLAs (open cases past due dates)."""
        now = datetime.utcnow()
        stmt = (
            select(ForensicCase)
            .options(joinedload(ForensicCase.lead_investigator))
            .where(
                ForensicCase.status != ForensicCaseStatus.CLOSED.value,
            )
        )
        cases = list(self.session.execute(stmt).unique().scalars().all())
        overdue = []
        for case in cases:
            for name in ("initial_response", "evidence_collection", "analysis", "reporting"):
                due = getattr(case, f"sla_{name}_due")
                met = getattr(case, f"sla_{name}_met")
                if due and not met and now > due:
                    overdue.append(case)
                    break
        return overdue

    def generate_report(self, case: ForensicCase) -> dict:
        """Generate a structured outcome report."""
        sla = self.get_sla_status(case)
        evidence = [e.to_dict(include_custody=True) for e in (case.evidence_items or [])]
        timeline = [
            t.to_dict() for t in sorted(
                case.timeline_entries or [], key=lambda x: x.timestamp
            )
        ]
        case_steps = [s.to_dict() for s in (case.case_steps or [])]
        return {
            "case_number": case.case_number,
            "title": case.title,
            "investigation_type": case.investigation_type,
            "priority": case.priority,
            "classification": case.classification,
            "status": case.status,
            "lead_investigator": case.lead_investigator.username if case.lead_investigator else None,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "description": case.description,
            "summary": case.summary,
            "findings": case.findings,
            "recommendations": case.recommendations,
            "sla_compliance": sla,
            "case_steps": case_steps,
            "evidence_items": evidence,
            "timeline": timeline,
        }

    # =========================================================================
    # Evidence CRUD
    # =========================================================================

    def add_evidence(
        self,
        case: ForensicCase,
        name: str,
        evidence_type: str,
        collected_by_id: int,
        description: str | None = None,
        source: str | None = None,
        hash_md5: str | None = None,
        hash_sha256: str | None = None,
        storage_location: str | None = None,
        metadata: dict | None = None,
    ) -> EvidenceItem:
        evidence = EvidenceItem(
            forensic_case_id=case.id,
            evidence_number=self._next_evidence_number(case.case_number),
            name=name,
            evidence_type=evidence_type,
            status=EvidenceStatus.COLLECTED.value,
            description=description,
            source=source,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            storage_location=storage_location,
            collected_by_id=collected_by_id,
            collected_at=datetime.utcnow(),
            metadata_json=metadata,
        )
        self.session.add(evidence)
        self.session.flush()

        # Auto-create initial custody entry
        custody = CustodyLogEntry(
            evidence_item_id=evidence.id,
            action=CustodyAction.COLLECTED.value,
            performed_by_id=collected_by_id,
            timestamp=datetime.utcnow(),
            location=storage_location,
            notes=f"Evidence collected: {name}",
        )
        self.session.add(custody)

        # Timeline entry
        self._add_timeline_entry(
            case.id, collected_by_id,
            f"Evidence added: {evidence.evidence_number} - {name}",
            entry_type="evidence_added",
            metadata={"evidence_id": evidence.id, "evidence_type": evidence_type},
        )
        self.session.flush()
        return evidence

    def get_evidence_by_id(self, evidence_id: int) -> Optional[EvidenceItem]:
        stmt = (
            select(EvidenceItem)
            .options(
                joinedload(EvidenceItem.collected_by),
                selectinload(EvidenceItem.custody_log).joinedload(CustodyLogEntry.performed_by),
                selectinload(EvidenceItem.custody_log).joinedload(CustodyLogEntry.received_by),
            )
            .where(EvidenceItem.id == evidence_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_evidence_for_case(self, case_id: int) -> List[EvidenceItem]:
        stmt = (
            select(EvidenceItem)
            .options(
                joinedload(EvidenceItem.collected_by),
                selectinload(EvidenceItem.custody_log),
            )
            .where(EvidenceItem.forensic_case_id == case_id)
            .order_by(EvidenceItem.created_at)
        )
        return list(self.session.execute(stmt).scalars().all())

    def update_evidence(
        self,
        evidence: EvidenceItem,
        status: str | None = None,
        description: str | None = None,
        storage_location: str | None = None,
        hash_md5: str | None = None,
        hash_sha256: str | None = None,
    ) -> EvidenceItem:
        if status is not None:
            evidence.status = status
        if description is not None:
            evidence.description = description
        if storage_location is not None:
            evidence.storage_location = storage_location
        if hash_md5 is not None:
            evidence.hash_md5 = hash_md5
        if hash_sha256 is not None:
            evidence.hash_sha256 = hash_sha256
        self.session.flush()
        return evidence

    # =========================================================================
    # Custody Log
    # =========================================================================

    def add_custody_entry(
        self,
        evidence: EvidenceItem,
        action: str,
        performed_by_id: int,
        received_by_id: int | None = None,
        location: str | None = None,
        notes: str | None = None,
    ) -> CustodyLogEntry:
        entry = CustodyLogEntry(
            evidence_item_id=evidence.id,
            action=action,
            performed_by_id=performed_by_id,
            received_by_id=received_by_id,
            timestamp=datetime.utcnow(),
            location=location,
            notes=notes,
        )
        self.session.add(entry)

        # Timeline entry on the parent case
        self._add_timeline_entry(
            evidence.forensic_case_id, performed_by_id,
            f"Custody action '{action}' on {evidence.evidence_number}",
            entry_type="custody_change",
            metadata={"evidence_id": evidence.id, "action": action},
        )
        self.session.flush()
        return entry

    def get_custody_log(self, evidence_id: int) -> List[CustodyLogEntry]:
        stmt = (
            select(CustodyLogEntry)
            .options(
                joinedload(CustodyLogEntry.performed_by),
                joinedload(CustodyLogEntry.received_by),
            )
            .where(CustodyLogEntry.evidence_item_id == evidence_id)
            .order_by(CustodyLogEntry.timestamp.desc())
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    # =========================================================================
    # Timeline
    # =========================================================================

    def get_timeline(self, case_id: int) -> List[ForensicTimelineEntry]:
        stmt = (
            select(ForensicTimelineEntry)
            .options(joinedload(ForensicTimelineEntry.user))
            .where(ForensicTimelineEntry.forensic_case_id == case_id)
            .order_by(ForensicTimelineEntry.timestamp.desc())
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def add_timeline_note(
        self,
        case_id: int,
        user_id: int,
        content: str,
        metadata: dict | None = None,
    ) -> ForensicTimelineEntry:
        entry = self._add_timeline_entry(case_id, user_id, content, "note", metadata)
        self.session.flush()
        return entry

    # =========================================================================
    # Forensic Playbooks
    # =========================================================================

    def create_playbook(
        self,
        name: str,
        created_by_id: int,
        description: str | None = None,
        investigation_type: str | None = None,
        is_active: bool = True,
        steps: list[dict] | None = None,
    ) -> ForensicPlaybook:
        pb = ForensicPlaybook(
            name=name,
            description=description,
            investigation_type=investigation_type,
            is_active=is_active,
            created_by_id=created_by_id,
        )
        self.session.add(pb)
        self.session.flush()

        if steps:
            for order, step_data in enumerate(steps, start=1):
                fj = step_data.get("fields")
                step = ForensicPlaybookStep(
                    playbook_id=pb.id,
                    step_order=order,
                    title=step_data.get("title", ""),
                    description=step_data.get("description"),
                    is_required=step_data.get("is_required", False),
                    expected_duration_hours=step_data.get("expected_duration_hours"),
                    fields_json=json.dumps(fj) if fj else None,
                )
                self.session.add(step)
            self.session.flush()

        return pb

    def get_playbook_by_id(self, playbook_id: int) -> Optional[ForensicPlaybook]:
        stmt = (
            select(ForensicPlaybook)
            .options(
                joinedload(ForensicPlaybook.created_by),
                selectinload(ForensicPlaybook.steps),
            )
            .where(ForensicPlaybook.id == playbook_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_playbooks(
        self,
        investigation_type: str | None = None,
        active_only: bool = False,
    ) -> List[ForensicPlaybook]:
        stmt = (
            select(ForensicPlaybook)
            .options(
                joinedload(ForensicPlaybook.created_by),
                selectinload(ForensicPlaybook.steps),
            )
        )
        if investigation_type:
            stmt = stmt.where(ForensicPlaybook.investigation_type == investigation_type)
        if active_only:
            stmt = stmt.where(ForensicPlaybook.is_active == True)
        stmt = stmt.order_by(ForensicPlaybook.name)
        return list(self.session.execute(stmt).scalars().all())

    def update_playbook(
        self,
        pb: ForensicPlaybook,
        name: str | None = None,
        description: str | None = None,
        investigation_type: str | None = None,
        is_active: bool | None = None,
        steps: list[dict] | None = None,
    ) -> ForensicPlaybook:
        if name is not None:
            pb.name = name
        if description is not None:
            pb.description = description
        if investigation_type is not None:
            pb.investigation_type = investigation_type
        if is_active is not None:
            pb.is_active = is_active

        if steps is not None:
            # Replace all steps
            for s in pb.steps[:]:
                self.session.delete(s)
            self.session.flush()
            for order, step_data in enumerate(steps, start=1):
                fj = step_data.get("fields")
                step = ForensicPlaybookStep(
                    playbook_id=pb.id,
                    step_order=order,
                    title=step_data.get("title", ""),
                    description=step_data.get("description"),
                    is_required=step_data.get("is_required", False),
                    expected_duration_hours=step_data.get("expected_duration_hours"),
                    fields_json=json.dumps(fj) if fj else None,
                )
                self.session.add(step)

        self.session.flush()
        return pb

    def delete_playbook(self, pb: ForensicPlaybook) -> None:
        self.session.delete(pb)
        self.session.flush()
