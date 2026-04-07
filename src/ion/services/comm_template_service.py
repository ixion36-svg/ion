"""Communication template management — pre-seeded incident notification templates."""

import logging
import re
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ion.models.oncall import CommTemplate

logger = logging.getLogger(__name__)

DEFAULT_TEMPLATES = [
    {
        "name": "Security Incident Initial Notification",
        "category": "status_update",
        "audience": "internal",
        "subject_template": "[ION-{{case_number}}] Security Incident \u2014 Initial Notification",
        "body_template": (
            "SECURITY INCIDENT NOTIFICATION\n"
            "==============================\n\n"
            "Case Reference: ION-{{case_number}}\n"
            "Severity: {{severity}}\n"
            "Date/Time: {{timestamp}}\n"
            "Investigating Analyst: {{analyst_name}}\n\n"
            "INCIDENT SUMMARY\n"
            "----------------\n"
            "Title: {{title}}\n\n"
            "{{summary}}\n\n"
            "AFFECTED SYSTEMS\n"
            "----------------\n"
            "{{affected_systems}}\n\n"
            "CURRENT STATUS\n"
            "--------------\n"
            "The SOC is actively investigating this incident. Containment measures "
            "are being evaluated and will be applied as appropriate. Further updates "
            "will be provided as the investigation progresses.\n\n"
            "REQUIRED ACTIONS\n"
            "----------------\n"
            "- Do not attempt to remediate affected systems independently\n"
            "- Preserve any relevant logs or evidence\n"
            "- Report any additional suspicious activity to the SOC immediately\n\n"
            "Next update expected within 2 hours unless the situation changes.\n\n"
            "SOC Contact: soc@internal | Ext. 4400\n"
            "Analyst: {{analyst_name}}"
        ),
    },
    {
        "name": "Ransomware Stakeholder Update",
        "category": "ransomware",
        "audience": "executive",
        "subject_template": "URGENT: Ransomware Incident Update \u2014 {{timestamp}}",
        "body_template": (
            "RANSOMWARE INCIDENT \u2014 STAKEHOLDER UPDATE\n"
            "==========================================\n\n"
            "Classification: CONFIDENTIAL\n"
            "Date/Time: {{timestamp}}\n"
            "Severity: {{severity}}\n\n"
            "SITUATION OVERVIEW\n"
            "------------------\n"
            "{{summary}}\n\n"
            "AFFECTED SCOPE\n"
            "--------------\n"
            "Systems Impacted: {{affected_systems}}\n"
            "Estimated Affected Users: {{affected_user_count}}\n"
            "Business Functions at Risk: {{business_impact}}\n\n"
            "CONTAINMENT ACTIONS TAKEN\n"
            "-------------------------\n"
            "- Network segmentation applied to affected VLANs\n"
            "- Compromised accounts disabled pending credential reset\n"
            "- Endpoint isolation initiated on confirmed infected hosts\n"
            "- Backup integrity verification in progress\n\n"
            "RECOVERY TIMELINE (ESTIMATED)\n"
            "-----------------------------\n"
            "- Containment: {{containment_eta}}\n"
            "- Eradication: {{eradication_eta}}\n"
            "- Partial service restoration: {{partial_restore_eta}}\n\n"
            "DECISIONS REQUIRED\n"
            "------------------\n"
            "1. Authorise external incident response engagement (if escalation needed)\n"
            "2. Approve communications to affected third parties\n"
            "3. Confirm business continuity plan activation scope\n\n"
            "Next briefing scheduled: {{next_update}}\n"
            "Incident Commander: {{analyst_name}}"
        ),
    },
    {
        "name": "Phishing Campaign All-Hands",
        "category": "phishing",
        "audience": "all_staff",
        "subject_template": "ACTION REQUIRED: Phishing Campaign Targeting {{department}}",
        "body_template": (
            "PHISHING ALERT \u2014 ACTION REQUIRED\n"
            "=================================\n\n"
            "The Security Operations Centre has identified an active phishing "
            "campaign targeting {{department}} staff.\n\n"
            "WHAT WE KNOW\n"
            "------------\n"
            "{{summary}}\n\n"
            "HOW TO IDENTIFY THE PHISHING EMAIL\n"
            "----------------------------------\n"
            "- Subject lines may reference: {{phishing_subjects}}\n"
            "- Sender addresses may spoof: {{spoofed_senders}}\n"
            "- Emails contain links to credential-harvesting pages\n\n"
            "WHAT YOU SHOULD DO\n"
            "------------------\n"
            "1. Do NOT click any links in suspicious emails\n"
            "2. Do NOT enter credentials on unfamiliar login pages\n"
            "3. Report the email using the 'Report Phishing' button in Outlook\n"
            "4. If you have already clicked a link or entered credentials:\n"
            "   - Change your password immediately at https://password.internal\n"
            "   - Contact the SOC at soc@internal or Ext. 4400\n\n"
            "Our mail filtering rules have been updated to block known indicators. "
            "If you receive a suspicious email that was not caught, please forward "
            "it to phishing@internal as an attachment.\n\n"
            "Thank you for your vigilance.\n"
            "Security Operations Centre"
        ),
    },
    {
        "name": "Data Breach Legal Notification",
        "category": "breach_notification",
        "audience": "legal",
        "subject_template": "CONFIDENTIAL: Potential Data Breach \u2014 Legal Review Required",
        "body_template": (
            "PRIVILEGED AND CONFIDENTIAL \u2014 ATTORNEY-CLIENT\n"
            "===============================================\n\n"
            "Date: {{timestamp}}\n"
            "Case Reference: ION-{{case_number}}\n"
            "Severity: {{severity}}\n"
            "Prepared by: {{analyst_name}}\n\n"
            "INCIDENT OVERVIEW\n"
            "-----------------\n"
            "{{summary}}\n\n"
            "DATA EXPOSURE ASSESSMENT\n"
            "------------------------\n"
            "Data Categories Potentially Affected:\n"
            "{{data_categories}}\n\n"
            "Estimated Records Affected: {{record_count}}\n"
            "Geographic Scope: {{geographic_scope}}\n"
            "Affected Systems: {{affected_systems}}\n\n"
            "REGULATORY CONSIDERATIONS\n"
            "-------------------------\n"
            "Based on the initial assessment, the following notification "
            "obligations may apply:\n"
            "- GDPR Article 33: 72-hour supervisory authority notification\n"
            "- GDPR Article 34: Individual notification (if high risk)\n"
            "- NIS2 Directive: Significant incident reporting\n"
            "- Sector-specific requirements: {{sector_requirements}}\n\n"
            "TIMELINE\n"
            "--------\n"
            "- Breach discovered: {{discovery_time}}\n"
            "- Containment initiated: {{containment_time}}\n"
            "- 72-hour deadline: {{notification_deadline}}\n\n"
            "REQUESTED LEGAL ACTIONS\n"
            "-----------------------\n"
            "1. Review breach notification obligation triggers\n"
            "2. Advise on supervisory authority notification timeline\n"
            "3. Draft data subject notification (if required)\n"
            "4. Assess third-party processor notification requirements\n\n"
            "Please treat this communication as privileged. Do not forward "
            "outside the legal and security incident response teams."
        ),
    },
    {
        "name": "Executive Incident Brief",
        "category": "executive_brief",
        "audience": "executive",
        "subject_template": "Security Incident Brief \u2014 {{severity}} \u2014 {{title}}",
        "body_template": (
            "EXECUTIVE INCIDENT BRIEF\n"
            "========================\n\n"
            "Case: ION-{{case_number}}\n"
            "Severity: {{severity}}\n"
            "Status: {{status}}\n"
            "Date: {{timestamp}}\n\n"
            "BOTTOM LINE UP FRONT\n"
            "--------------------\n"
            "{{summary}}\n\n"
            "IMPACT\n"
            "------\n"
            "- Affected Systems: {{affected_systems}}\n"
            "- Business Impact: {{business_impact}}\n"
            "- Data at Risk: {{data_at_risk}}\n"
            "- Operational Disruption: {{disruption_level}}\n\n"
            "RESPONSE ACTIONS\n"
            "----------------\n"
            "{{response_actions}}\n\n"
            "CURRENT RISK POSTURE\n"
            "--------------------\n"
            "Threat Contained: {{contained}}\n"
            "Root Cause Identified: {{root_cause_identified}}\n"
            "Recurrence Prevention: {{prevention_status}}\n\n"
            "RESOURCE REQUIREMENTS\n"
            "---------------------\n"
            "{{resource_needs}}\n\n"
            "Next update: {{next_update}}\n"
            "Incident Lead: {{analyst_name}}"
        ),
    },
    {
        "name": "Incident Resolved Notification",
        "category": "status_update",
        "audience": "internal",
        "subject_template": "[ION-{{case_number}}] Incident Resolved \u2014 {{title}}",
        "body_template": (
            "INCIDENT RESOLVED\n"
            "=================\n\n"
            "Case Reference: ION-{{case_number}}\n"
            "Title: {{title}}\n"
            "Original Severity: {{severity}}\n"
            "Resolved: {{timestamp}}\n"
            "Resolved by: {{analyst_name}}\n\n"
            "RESOLUTION SUMMARY\n"
            "------------------\n"
            "{{summary}}\n\n"
            "ROOT CAUSE\n"
            "----------\n"
            "{{root_cause}}\n\n"
            "ACTIONS TAKEN\n"
            "-------------\n"
            "{{actions_taken}}\n\n"
            "AFFECTED SYSTEMS\n"
            "----------------\n"
            "{{affected_systems}}\n\n"
            "All affected systems have been verified as operational. Monitoring "
            "has been enhanced for the indicators associated with this incident "
            "and will remain elevated for the next 72 hours.\n\n"
            "FOLLOW-UP ITEMS\n"
            "---------------\n"
            "- Post-incident review scheduled within 5 business days\n"
            "- Detection rule tuning recommendations to follow\n"
            "- Lessons learned document will be circulated to stakeholders\n\n"
            "If you observe any recurrence of the activity described above, "
            "contact the SOC immediately at soc@internal | Ext. 4400."
        ),
    },
]


def get_templates(session: Session, category: Optional[str] = None) -> list[dict]:
    query = select(CommTemplate).order_by(CommTemplate.name)
    if category:
        query = query.where(CommTemplate.category == category)
    templates = session.execute(query).scalars().all()
    return [_template_to_dict(t) for t in templates]


def get_template(session: Session, template_id: int) -> dict:
    tmpl = session.get(CommTemplate, template_id)
    if not tmpl:
        return {}
    return _template_to_dict(tmpl)


def create_template(session: Session, **kwargs) -> dict:
    tmpl = CommTemplate(**kwargs)
    session.add(tmpl)
    session.flush()
    session.refresh(tmpl)
    return _template_to_dict(tmpl)


def update_template(session: Session, template_id: int, **kwargs) -> dict:
    tmpl = session.get(CommTemplate, template_id)
    if not tmpl:
        return {}
    for key, value in kwargs.items():
        if hasattr(tmpl, key):
            setattr(tmpl, key, value)
    session.flush()
    session.refresh(tmpl)
    return _template_to_dict(tmpl)


def render_template(session: Session, template_id: int, variables: dict) -> dict:
    tmpl = session.get(CommTemplate, template_id)
    if not tmpl:
        return {"error": "Template not found"}

    def _replace(text: str, vars_: dict) -> str:
        def replacer(match):
            key = match.group(1).strip()
            return str(vars_.get(key, match.group(0)))
        return re.sub(r"\{\{(\s*\w+\s*)\}\}", replacer, text)

    rendered_subject = _replace(tmpl.subject_template, variables)
    rendered_body = _replace(tmpl.body_template, variables)

    return {
        "template_id": tmpl.id,
        "name": tmpl.name,
        "subject": rendered_subject,
        "body": rendered_body,
        "audience": tmpl.audience,
        "category": tmpl.category,
    }


def seed_default_templates(session: Session):
    existing_count = session.execute(
        select(func.count(CommTemplate.id))
    ).scalar() or 0

    if existing_count > 0:
        logger.info("Communication templates already seeded (%d exist), skipping", existing_count)
        return

    for tmpl_data in DEFAULT_TEMPLATES:
        tmpl = CommTemplate(
            name=tmpl_data["name"],
            category=tmpl_data["category"],
            audience=tmpl_data["audience"],
            subject_template=tmpl_data["subject_template"],
            body_template=tmpl_data["body_template"],
            is_default=True,
        )
        session.add(tmpl)

    session.flush()
    logger.info("Seeded %d default communication templates", len(DEFAULT_TEMPLATES))


def _template_to_dict(tmpl: CommTemplate) -> dict:
    return {
        "id": tmpl.id,
        "name": tmpl.name,
        "category": tmpl.category,
        "subject_template": tmpl.subject_template,
        "body_template": tmpl.body_template,
        "audience": tmpl.audience,
        "created_by_id": tmpl.created_by_id,
        "is_default": tmpl.is_default,
        "created_at": tmpl.created_at.isoformat() if tmpl.created_at else None,
        "updated_at": tmpl.updated_at.isoformat() if tmpl.updated_at else None,
    }
