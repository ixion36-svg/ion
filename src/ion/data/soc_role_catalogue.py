"""A catalogue of roles a SOC might have, for a lead to pick from.

Reference data, not configuration. Nothing here is created until somebody
adopts it: a SOC chooses which of these it actually has, and adopting one
builds a role profile it can then edit. The catalogue's job is to stop a
lead starting from an empty page, not to tell them what their SOC is.

Three things this deliberately does NOT claim.

**The certificates are typical, not required.** They are what job adverts
and SANS/CompTIA/GIAC pathways for the role usually list, which is a
different thing from what somebody needs to do the work. A SOC adopting a
role decides which of them it actually requires, and any requirement can
be met by assessed proficiency instead -- see ``record_equivalence``.
Listing a certificate here is not an opinion that people without it
cannot do the job.

**Common vs specialist is about prevalence, not importance.** A role
marked specialist is one many SOCs do not staff separately, usually
because it is covered by somebody wearing two hats or bought in. It says
nothing about whether the function matters.

**The headcounts are a starting point.** ``typical_establishment`` is a
rough shape for a mid-sized 24/7 SOC, offered so the ORBAT is not empty
on day one. Every SOC's numbers come from its own cover model, hours and
risk appetite, and a number here that somebody accepts without thinking
is worse than no number at all -- so the UI should present it as a
suggestion to overwrite rather than a default to accept.

``skills_role_id`` links to role_skills_service where a questionnaire
exists. Most of these have none, and that is honest: ION has five
questionnaires, not twenty.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Categories, in the order a SOC org chart usually reads.
CATEGORIES = (
    "operations",
    "detection_engineering",
    "incident_response",
    "threat_intelligence",
    "governance",
    "specialist",
)

#: tier is the seniority band used to match training scenarios and to sort
#: the ORBAT; it mirrors role_skills_service's T1-T4 where they overlap.
#:
#: ``leads`` names the category this role heads, or ``"soc"`` for a role
#: that heads the whole thing. A role with it is placed above that unit's
#: members rather than beside them, because a flat list of posts does not
#: say who answers for the function.
#:
#: Incident response, threat intelligence and governance have no lead
#: role on purpose. At one or two people each, a lead post per function
#: would put permanent vacancies on the ORBAT that a SOC this size never
#: intends to fill; they answer to the SOC Lead directly. A SOC big
#: enough to want one adds it -- the catalogue is a starting point.
SOC_ROLE_CATALOGUE: List[Dict[str, Any]] = [
    # ---------------------------------------------------------------- ops
    {
        "id": "l1_soc_analyst",
        "name": "SOC Analyst (L1)",
        "category": "operations",
        "tier": "T1",
        "common": True,
        "typical_establishment": 6,
        "description": (
            "Front line of the queue. Triages alerts, gathers context, "
            "closes the obvious and escalates the rest."
        ),
        "skills_role_id": "l1_soc_analyst",
        "typical_certifications": [
            "CompTIA Security+", "CompTIA CySA+", "Blue Team Level 1 (BTL1)",
            "Microsoft SC-200",
        ],
        "core_skills": [
            "Alert triage and prioritisation",
            "Reading SIEM search results",
            "Phishing analysis",
            "Escalation and handover discipline",
            "Writing what you did, so the next person can follow it",
        ],
    },
    {
        "id": "l2_soc_analyst",
        "name": "SOC Analyst (L2)",
        "category": "operations",
        "tier": "T2",
        "common": True,
        "typical_establishment": 4,
        "description": (
            "Owns investigations end to end. Takes escalations, runs the "
            "case, decides what is real."
        ),
        "skills_role_id": "l2_soc_analyst",
        "typical_certifications": [
            "CompTIA CySA+", "GIAC GCIA", "Blue Team Level 2 (BTL2)",
            "Microsoft SC-200",
        ],
        "core_skills": [
            "Case ownership and investigation planning",
            "Intermediate query writing (KQL, EQL)",
            "Host and network artefact analysis",
            "Rule tuning and false-positive reduction",
            "IOC enrichment and threat intel pivoting",
        ],
    },
    {
        "id": "l3_soc_analyst",
        "name": "Senior SOC Analyst (L3)",
        "category": "operations",
        "tier": "T3",
        "common": True,
        "typical_establishment": 2,
        "description": (
            "The person the L2s escalate to. Reconstructs attack chains, "
            "writes the detections the queue was missing."
        ),
        "skills_role_id": "l3_soc_analyst",
        "typical_certifications": [
            "GIAC GCIA", "GIAC GCFA", "GIAC GCIH", "Offensive Security OSCP",
        ],
        "core_skills": [
            "Attack chain reconstruction",
            "Custom detection authoring",
            "Root cause analysis",
            "Mentoring and quality review of L1/L2 work",
        ],
    },
    {
        "id": "soc_shift_lead",
        "name": "SOC Shift Lead",
        "category": "operations",
        "tier": "T3",
        "common": True,
        "typical_establishment": 4,
        "description": (
            "Runs the shift. Owns the queue, the handover and the decision "
            "to wake somebody up."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCIH", "GIAC GSOM", "CompTIA CySA+",
        ],
        "core_skills": [
            "Shift handover and continuity",
            "Incident declaration and escalation authority",
            "Workload balancing across the shift",
            "Stakeholder communication under pressure",
        ],
    },
    {
        "id": "lead_analyst",
        "name": "Lead Analyst",
        "category": "operations",
        "tier": "T4",
        "common": True,
        "leads": "operations",
        "typical_establishment": 1,
        "description": (
            "Heads the analysis function. Owns the quality of what the "
            "queue produces and develops the analysts who produce it."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCIA", "GIAC GCIH", "GIAC GSOM",
        ],
        "core_skills": [
            "Setting and holding the analytical standard",
            "Quality review of investigations and verdicts",
            "Developing analysts across the tiers",
            "Deciding what the queue stops doing",
        ],
    },
    {
        "id": "operations_analyst",
        "name": "Operations Analyst",
        "category": "operations",
        "tier": "T3",
        "common": True,
        "typical_establishment": 1,
        "description": (
            "Runs the SOC as a service rather than as a queue. Owns the "
            "process, the metrics and the reporting, and carries the "
            "work that falls between the other roles -- which is most of "
            "the reason a SOC either improves or just keeps up."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GSOM", "CompTIA CySA+", "ITIL Foundation",
            "ISACA CISM",
        ],
        "core_skills": [
            "Writing process people actually follow, and retiring the "
            "parts they do not",
            "Metrics that change a decision, not metrics that fill a slide",
            "Shift patterns, cover and leave planned against real demand",
            "Running the standup, the handover and the weekly rhythm",
            "Owning the audit trail: what was agreed, by whom, and when",
            "Chasing the work that belongs to nobody until somebody "
            "names it",
        ],
    },
    {
        "id": "technical_analyst",
        "name": "Technical Analyst",
        "category": "operations",
        "tier": "T3",
        "common": True,
        "typical_establishment": 1,
        "description": (
            "The deep technical hand on the floor. Takes the "
            "investigation the tiers cannot close, makes the tooling "
            "work, and answers the question that has no runbook and "
            "needs an answer today."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCIA", "GIAC GCFA", "GIAC GCIH",
            "Offensive Security OSCP",
        ],
        "core_skills": [
            "Host and network analysis past the point the runbook stops",
            "Scripting to answer a one-off question faster than arguing "
            "about it",
            "Reading a system nobody has documented and explaining it back",
            "Taking the escalation the tiers cannot close, and saying so "
            "when it is not a security problem",
            "Turning a one-off investigation into a detection or a "
            "runbook so it is not one-off twice",
            "Being the person who says the tool is wrong, with evidence",
        ],
    },
    {
        "id": "soc_lead",
        "name": "SOC Lead",
        "category": "operations",
        "tier": "T4",
        "common": True,
        "leads": "soc",
        "typical_establishment": 1,
        "description": (
            "Runs the SOC day to day. The functional leads answer to them, "
            "and so do the functions too small to have a lead of their own."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GSOM", "GIAC GCIH", "ISACA CISM",
        ],
        "core_skills": [
            "Holding the shape of the day: cover, handover, escalation",
            "Deciding what gets dropped when the queue beats the team",
            "Running the standup and the weekly duty rota",
            "Fronting the SOC in an incident nobody has seen before",
            "Knowing which function is one person deep",
        ],
    },
    {
        "id": "soc_manager",
        "name": "SOC Manager",
        "category": "operations",
        "tier": "T4",
        "common": True,
        "leads": "soc",
        "typical_establishment": 1,
        "description": (
            "Accountable for the service: cover, capability, metrics and "
            "the people."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GSOM", "ISACA CISM", "(ISC)2 CISSP",
        ],
        "core_skills": [
            "Capability and coverage planning",
            "Metrics that mean something to the business",
            "Budget and tooling decisions",
            "Developing and retaining analysts",
        ],
    },
    # --------------------------------------------- detection engineering
    {
        "id": "detection_engineer",
        "name": "Detection Engineer",
        "category": "detection_engineering",
        "tier": "T3",
        "common": True,
        "typical_establishment": 2,
        "description": (
            "Builds and maintains the detections. Owns coverage against "
            "ATT&CK and the false-positive rate."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCDA", "GIAC GMON", "GIAC GCIA",
        ],
        "core_skills": [
            "Detection-as-code and version control",
            "Sigma and vendor rule languages",
            "ATT&CK coverage mapping and gap analysis",
            "Testing a detection before it reaches the queue",
            "Tuning without blinding the detection",
        ],
    },
    {
        "id": "lead_engineer",
        "name": "Lead Engineer",
        "category": "detection_engineering",
        "tier": "T4",
        "common": True,
        "leads": "detection_engineering",
        "typical_establishment": 1,
        "description": (
            "Heads the engineering function. Owns the platform's health "
            "and the detection estate built on it."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCDA", "Elastic Certified Engineer", "GIAC GSOM",
        ],
        "core_skills": [
            "Detection and platform roadmap",
            "Change control over the detection estate",
            "Capacity, retention and cost decisions",
            "Developing engineers and detection authors",
        ],
    },
    {
        "id": "soc_engineer",
        "name": "SOC Platform Engineer",
        "category": "detection_engineering",
        "tier": "T3",
        "common": True,
        "typical_establishment": 2,
        "description": (
            "Keeps the platform standing: ingest, parsing, retention, "
            "integrations and the agents."
        ),
        "skills_role_id": "soc_engineer",
        "typical_certifications": [
            "Elastic Certified Engineer", "GIAC GCIA",
            "Vendor SIEM administration certifications",
        ],
        "core_skills": [
            "SIEM administration and sizing",
            "Ingest pipelines, parsing and normalisation",
            "Agent and collector deployment",
            "Log source onboarding and validation",
            "Knowing when a gap is missing data, not a missing rule",
        ],
    },
    {
        "id": "automation_engineer",
        "name": "SOAR / Automation Engineer",
        "category": "detection_engineering",
        "tier": "T3",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Automates the repetitive parts of triage and response, and "
            "owns the playbooks that execute."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "Vendor SOAR certifications", "GIAC GPYC",
        ],
        "core_skills": [
            "Playbook design with a human in the loop",
            "API integration across the tool estate",
            "Scripting (Python, PowerShell)",
            "Failure handling: what the automation does when it is wrong",
        ],
    },
    # --------------------------------------------------- incident response
    {
        "id": "incident_responder",
        "name": "Incident Responder",
        "category": "incident_response",
        "tier": "T3",
        "common": True,
        "typical_establishment": 2,
        "description": (
            "Takes the confirmed incident: containment, eradication, "
            "recovery and the write-up."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCIH", "GIAC GCFA", "EC-Council ECIH",
        ],
        "core_skills": [
            "Containment decisions under time pressure",
            "Evidence preservation while responding",
            "Incident command and comms",
            "Lessons learned that change something",
        ],
    },
    {
        "id": "dfir_analyst",
        "name": "DFIR / Forensic Analyst",
        "category": "incident_response",
        "tier": "T3",
        "common": True,
        "typical_establishment": 1,
        "description": (
            "Deep host and network forensics. Produces findings that hold "
            "up when somebody disputes them."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCFA", "GIAC GCFE", "GIAC GNFA", "EnCase EnCE",
        ],
        "core_skills": [
            "Disk and memory acquisition and analysis",
            "Timeline reconstruction",
            "Chain of custody and evidential integrity",
            "Reporting to a standard that survives challenge",
        ],
    },
    {
        "id": "malware_analyst",
        "name": "Malware Analyst / Reverse Engineer",
        "category": "incident_response",
        "tier": "T4",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Works out what a sample actually does, and what to detect it "
            "by."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GREM", "Offensive Security OSCE",
        ],
        "core_skills": [
            "Static and dynamic analysis",
            "Safe detonation and sandbox discipline",
            "Unpacking and deobfuscation",
            "Turning analysis into durable detection logic",
        ],
    },
    # ------------------------------------------------- threat intelligence
    {
        "id": "cti_analyst",
        "name": "Threat Intelligence Analyst",
        "category": "threat_intelligence",
        "tier": "T3",
        "common": True,
        "typical_establishment": 1,
        "description": (
            "Turns intelligence into something the SOC can act on: who is "
            "likely to come at us, how, and what we would see."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GCTI", "EC-Council CTIA", "CREST CPTIA",
        ],
        "core_skills": [
            "Intelligence requirements and collection planning",
            "Actor and campaign tracking",
            "Structured analytic techniques",
            "Writing for the person who has to decide something",
            "Separating reporting from assessment",
        ],
    },
    {
        "id": "threat_hunter",
        "name": "Threat Hunter",
        "category": "threat_intelligence",
        "tier": "T4",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Looks for what the detections did not catch, from a hypothesis "
            "rather than an alert."
        ),
        "skills_role_id": "threat_hunter",
        "typical_certifications": [
            "GIAC GCTI", "GIAC GCFA", "SANS FOR508",
        ],
        "core_skills": [
            "Hypothesis-driven hunt methodology",
            "Advanced query and data pivoting",
            "Baselining and anomaly reasoning",
            "Feeding findings back as detections",
        ],
    },
    # -------------------------------------------------------- governance
    {
        "id": "grc_analyst",
        "name": "GRC / Compliance Analyst",
        "category": "governance",
        "tier": "T3",
        "common": True,
        "typical_establishment": 1,
        "description": (
            "Owns the evidence: control mapping, audit readiness, and "
            "whether the SOC can show what it claims."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "ISACA CISA", "ISACA CISM", "ISO 27001 Lead Auditor",
            "ISACA CRISC",
        ],
        "core_skills": [
            "Control frameworks and mapping",
            "Evidence collection and audit preparation",
            "Risk articulation to non-technical stakeholders",
            "Verifying onboarding and clearance records",
        ],
    },
    {
        "id": "vuln_analyst",
        "name": "Vulnerability Management Analyst",
        "category": "governance",
        "tier": "T2",
        "common": True,
        "typical_establishment": 1,
        "description": (
            "Runs the scanning, triages findings by real exposure, and "
            "chases remediation."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "CompTIA PenTest+", "GIAC GWAPT", "Qualys/Tenable vendor certs",
        ],
        "core_skills": [
            "Scan configuration and coverage assurance",
            "Prioritisation by exploitability, not CVSS alone",
            "Tracking remediation to closure",
            "Exception and risk-acceptance handling",
        ],
    },
    # -------------------------------------------------------- specialist
    {
        "id": "cloud_security_analyst",
        "name": "Cloud Security Analyst",
        "category": "specialist",
        "tier": "T3",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Detection and response for cloud estates, where the control "
            "plane is the attack surface."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "AWS Certified Security - Specialty", "Microsoft AZ-500",
            "GIAC GCLD", "Cloud Security Alliance CCSK",
        ],
        "core_skills": [
            "Cloud audit log analysis (CloudTrail, Entra, GCP audit)",
            "Identity and entitlement abuse detection",
            "Container and workload telemetry",
            "Infrastructure-as-code review",
        ],
    },
    {
        "id": "ot_security_analyst",
        "name": "OT / ICS Security Analyst",
        "category": "specialist",
        "tier": "T3",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Monitoring for industrial environments, where availability "
            "outranks confidentiality and you cannot patch on a whim."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "GIAC GICSP", "GIAC GRID", "ISA/IEC 62443",
        ],
        "core_skills": [
            "Industrial protocols (Modbus, DNP3, S7)",
            "Purdue model and segmentation",
            "Passive monitoring where active scanning is unsafe",
            "Safety-aware response decisions",
        ],
    },
    {
        "id": "purple_team",
        "name": "Purple Team / Adversary Emulation",
        "category": "specialist",
        "tier": "T4",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Runs the attack against your own detections, and proves "
            "whether coverage is real."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "Offensive Security OSCP", "Zero-Point CRTO", "GIAC GCPN",
        ],
        "core_skills": [
            "Adversary emulation planning against ATT&CK",
            "Detection validation and evidence of coverage",
            "Safe execution in production",
            "Closing the loop with detection engineering",
        ],
    },
    {
        "id": "insider_threat_analyst",
        "name": "Insider Threat Analyst",
        "category": "specialist",
        "tier": "T3",
        "common": False,
        "typical_establishment": 1,
        "description": (
            "Behavioural monitoring of trusted access, worked jointly with "
            "HR and Legal rather than alone."
        ),
        "skills_role_id": None,
        "typical_certifications": [
            "Carnegie Mellon Insider Threat Program Manager",
            "ISACA CISM",
        ],
        "core_skills": [
            "Behavioural baselining and deviation analysis",
            "Data loss and exfiltration detection",
            "Working inside HR and legal constraints",
            "Proportionality: the cost of being wrong about a colleague",
        ],
    },
]

_BY_ID = {r["id"]: r for r in SOC_ROLE_CATALOGUE}


def catalogue() -> List[Dict[str, Any]]:
    """Every role in the catalogue."""
    return list(SOC_ROLE_CATALOGUE)


def get_role(role_id: str) -> Dict[str, Any] | None:
    return _BY_ID.get(role_id)


def by_category() -> Dict[str, List[Dict[str, Any]]]:
    """Grouped for display, in the order an org chart usually reads."""
    out: Dict[str, List[Dict[str, Any]]] = {c: [] for c in CATEGORIES}
    for role in SOC_ROLE_CATALOGUE:
        out.setdefault(role["category"], []).append(role)
    return {k: v for k, v in out.items() if v}
