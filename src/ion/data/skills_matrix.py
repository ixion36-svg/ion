"""The skills matrix: what each pillar is made of, and who owns it.

This was JavaScript in training.html and nothing else could read it,
which is why coverage of the day-to-day pillars could be drawn as a
heatmap but never compared against who is actually in post. It lives
here now, and ``tests/test_skills_matrix_data.py`` fails if the
template's copy drifts from it.

Three things worth knowing before using it.

**The targets are a reference, not a bar to clear.** A level against a
role is the proficiency that role usually needs, taken from vendor and
GIAC pathways. Somebody below it is not failing; they are somebody whose
development has somewhere to go.

**Ownership is derived, not declared.** A role owns a pillar when the
targets say that is its day job -- see ``owners_of``. Deriving it keeps
ownership and targets from drifting apart, and it means a role the
targets under-specify shows up in ``roles_without_a_pillar`` instead of
being quietly credited with a pillar nobody chose for it.

**A rating here is self-assessed.** The matrix defines what to rate. It
says nothing about whether a rating was measured, and anything built on
it has to carry that caveat forward rather than present a self-rating as
a verified fact.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

#: 0 is not a rating. It is "this role does not need this skill", which
#: is why it has to be told apart from an unrated skill everywhere.
PROFICIENCY_LABELS: Tuple[str, ...] = (
    "N/A", "Awareness", "Basic", "Intermediate", "Advanced", "Expert",
)

#: Pillar -> {skill key: {"name": str, "targets": {role id: level}}}.
#: Transcribed from the template literal; do not hand-edit one copy.
SKILLS_MATRIX: Dict[str, Dict[str, dict]] = {
    "SIEM & Logging": {
        "siem-operations": {
            "name": "SIEM Operations",
            "targets": {"l1-analyst": 2, "l2-analyst": 3, "l3-analyst": 4, "soc-lead": 4, "detection-engineer": 5, "threat-hunter": 4, "security-engineer": 3, "cloud-security": 2, "security-architect": 3, "grc": 1},
        },
        "log-analysis": {
            "name": "Log Analysis",
            "targets": {"l1-analyst": 2, "l2-analyst": 3, "l3-analyst": 4, "incident-responder": 3, "threat-hunter": 4, "detection-engineer": 4, "digital-forensics": 3, "security-engineer": 2},
        },
        "kql-spl": {
            "name": "KQL / SPL Queries",
            "targets": {"l1-analyst": 1, "l2-analyst": 3, "l3-analyst": 4, "threat-hunter": 5, "detection-engineer": 5, "soc-lead": 3},
        },
        "log-parsing": {
            "name": "Log Parsing & Enrichment",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "detection-engineer": 5, "security-engineer": 3, "threat-hunter": 3},
        },
        "siem-admin": {
            "name": "SIEM Administration",
            "targets": {"l3-analyst": 3, "soc-lead": 4, "detection-engineer": 4, "security-engineer": 3},
        },
    },
    "Incident Response": {
        "alert-triage": {
            "name": "Alert Triage",
            "targets": {"l1-analyst": 3, "l2-analyst": 4, "l3-analyst": 5, "soc-lead": 4, "incident-responder": 4},
        },
        "forensic-collection": {
            "name": "Forensic Collection",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "incident-responder": 4, "digital-forensics": 5, "malware-analyst": 3},
        },
        "memory-analysis": {
            "name": "Memory Analysis",
            "targets": {"l3-analyst": 2, "incident-responder": 4, "digital-forensics": 5, "malware-analyst": 4},
        },
        "timeline-analysis": {
            "name": "Timeline Analysis",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "incident-responder": 4, "digital-forensics": 5},
        },
        "ir-frameworks": {
            "name": "IR Frameworks (NIST/SANS)",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "incident-responder": 4, "soc-lead": 3, "security-architect": 3, "grc": 3},
        },
    },
    "Threat Intelligence": {
        "osint": {
            "name": "OSINT",
            "targets": {"l2-analyst": 2, "threat-intel": 5, "threat-hunter": 3, "pen-tester": 3},
        },
        "stix-taxii": {
            "name": "STIX/TAXII",
            "targets": {"threat-intel": 5, "threat-hunter": 3, "l3-analyst": 2, "detection-engineer": 2},
        },
        "mitre-attack": {
            "name": "MITRE ATT&CK",
            "targets": {"l2-analyst": 2, "l3-analyst": 4, "threat-hunter": 5, "threat-intel": 4, "detection-engineer": 4, "soc-lead": 3, "security-architect": 2},
        },
        "ioc-enrichment": {
            "name": "IOC Enrichment",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "threat-intel": 4, "threat-hunter": 3, "detection-engineer": 3},
        },
        "intel-reporting": {
            "name": "Intelligence Reporting",
            "targets": {"threat-intel": 5, "threat-hunter": 3, "soc-lead": 3, "grc": 2},
        },
    },
    "Detection Engineering": {
        "sigma-rules": {
            "name": "Sigma Rules",
            "targets": {"l3-analyst": 2, "detection-engineer": 5, "threat-hunter": 4, "security-engineer": 2},
        },
        "yara-rules": {
            "name": "YARA Rules",
            "targets": {"detection-engineer": 4, "malware-analyst": 5, "threat-hunter": 3, "incident-responder": 2},
        },
        "detection-tuning": {
            "name": "Detection Tuning",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "detection-engineer": 5, "soc-lead": 3},
        },
        "cicd-detections": {
            "name": "CI/CD for Detections",
            "targets": {"detection-engineer": 4, "security-engineer": 4},
        },
        "detection-coverage": {
            "name": "Detection Coverage Mapping",
            "targets": {"detection-engineer": 4, "threat-hunter": 3, "soc-lead": 3},
        },
    },
    "Scripting & Automation": {
        "python": {
            "name": "Python",
            "targets": {"l2-analyst": 2, "l3-analyst": 3, "detection-engineer": 4, "security-engineer": 4, "threat-hunter": 3, "malware-analyst": 4, "pen-tester": 3, "cloud-security": 3},
        },
        "powershell": {
            "name": "PowerShell",
            "targets": {"l1-analyst": 1, "l2-analyst": 2, "l3-analyst": 3, "incident-responder": 3, "security-engineer": 3, "pen-tester": 3, "digital-forensics": 2},
        },
        "bash-shell": {
            "name": "Bash / Shell",
            "targets": {"l2-analyst": 2, "security-engineer": 3, "pen-tester": 3, "cloud-security": 3, "detection-engineer": 2},
        },
        "git-version-control": {
            "name": "Git / Version Control",
            "targets": {"l3-analyst": 2, "detection-engineer": 4, "security-engineer": 4, "cloud-security": 3, "pen-tester": 2},
        },
    },
    "Network & Infrastructure": {
        "tcp-ip-dns": {
            "name": "TCP/IP & DNS",
            "targets": {"l1-analyst": 2, "l2-analyst": 3, "l3-analyst": 3, "security-engineer": 4, "pen-tester": 4, "cloud-security": 3, "security-architect": 4},
        },
        "packet-analysis": {
            "name": "Packet Analysis (Wireshark)",
            "targets": {"l2-analyst": 3, "l3-analyst": 4, "incident-responder": 3, "threat-hunter": 3, "pen-tester": 3},
        },
        "firewall-waf": {
            "name": "Firewalls & WAF",
            "targets": {"security-engineer": 4, "cloud-security": 4, "security-architect": 4, "l3-analyst": 2, "soc-lead": 2},
        },
        "cloud-platforms": {
            "name": "Cloud Platforms (AWS/Azure/GCP)",
            "targets": {"security-engineer": 4, "cloud-security": 5, "security-architect": 4, "l3-analyst": 2},
        },
        "container-security": {
            "name": "Container / K8s Security",
            "targets": {"security-engineer": 4, "cloud-security": 4, "security-architect": 3},
        },
    },
    "Forensics & Malware": {
        "disk-imaging": {
            "name": "Disk Imaging",
            "targets": {"incident-responder": 3, "digital-forensics": 5},
        },
        "reverse-engineering": {
            "name": "Reverse Engineering",
            "targets": {"malware-analyst": 5, "digital-forensics": 2},
        },
        "sandbox-analysis": {
            "name": "Sandbox Analysis",
            "targets": {"malware-analyst": 4, "incident-responder": 2, "l3-analyst": 2, "threat-intel": 2},
        },
        "mobile-forensics": {
            "name": "Mobile Forensics",
            "targets": {"digital-forensics": 4},
        },
        "registry-artifact": {
            "name": "Registry & Artifact Analysis",
            "targets": {"digital-forensics": 5, "incident-responder": 3, "l3-analyst": 2},
        },
    },
    "Offensive Security": {
        "pentest-tools": {
            "name": "Pen Testing Tools (Burp/Metasploit)",
            "targets": {"pen-tester": 5, "security-engineer": 2, "threat-hunter": 2},
        },
        "webapp-testing": {
            "name": "Web App Testing",
            "targets": {"pen-tester": 5, "security-engineer": 3},
        },
        "ad-attacks": {
            "name": "Active Directory Attacks",
            "targets": {"pen-tester": 4, "incident-responder": 2, "threat-hunter": 2},
        },
        "social-engineering": {
            "name": "Social Engineering",
            "targets": {"pen-tester": 3},
        },
    },
    "Governance & Leadership": {
        "team-leadership": {
            "name": "Team Leadership",
            "targets": {"soc-lead": 5, "security-architect": 4, "grc": 3},
        },
        "stakeholder-comms": {
            "name": "Stakeholder Communications",
            "targets": {"soc-lead": 5, "security-architect": 4, "grc": 4, "threat-intel": 3},
        },
        "risk-management": {
            "name": "Risk Management",
            "targets": {"soc-lead": 3, "security-architect": 4, "grc": 5},
        },
        "policy-writing": {
            "name": "Policy Writing",
            "targets": {"grc": 5, "security-architect": 3, "soc-lead": 2},
        },
        "audit-management": {
            "name": "Audit Management",
            "targets": {"grc": 5},
        },
    },
    "Architecture & Design": {
        "threat-modeling": {
            "name": "Threat Modeling",
            "targets": {"security-architect": 5, "security-engineer": 3, "cloud-security": 3, "soc-lead": 2},
        },
        "zero-trust": {
            "name": "Zero Trust Architecture",
            "targets": {"security-architect": 5, "cloud-security": 4, "security-engineer": 3},
        },
        "security-frameworks": {
            "name": "Security Frameworks (ISO/NIST)",
            "targets": {"security-architect": 4, "grc": 5, "soc-lead": 3, "cloud-security": 2},
        },
        "vendor-evaluation": {
            "name": "Vendor & Tool Evaluation",
            "targets": {"security-architect": 4, "soc-lead": 3, "grc": 3},
        },
    },
}

#: The day-to-day pillars as the wallboard and the schedule name them,
#: each fed by one matrix category. The names differ from the category
#: names in two places and that is deliberate -- the pillar is what the
#: SOC delivers, the category is how the skills are grouped.
PILLARS: Dict[str, str] = {
    "Incident Response": "Incident Response",
    "Threat Intelligence": "Threat Intelligence",
    "Detection Engineering": "Detection Engineering",
    "Digital Forensics": "Forensics & Malware",
    "SIEM & Log Analysis": "SIEM & Logging",
    "Network Defense": "Network & Infrastructure",
    "Scripting & Automation": "Scripting & Automation",
    "Offensive Security": "Offensive Security",
    "Governance & Leadership": "Governance & Leadership",
    "Security Architecture": "Architecture & Design",
}

# --- reading the matrix -----------------------------------------------------


def pillars() -> Tuple[str, ...]:
    return tuple(PILLARS)


def skills_in(pillar: str) -> Dict[str, dict]:
    """The skills feeding a pillar, keyed as the assessments store them."""
    return SKILLS_MATRIX.get(PILLARS.get(pillar, pillar), {})


def skill_keys(pillar: str) -> Tuple[str, ...]:
    return tuple(skills_in(pillar))


def pillar_of_skill(skill_key: str) -> Optional[str]:
    for pillar, category in PILLARS.items():
        if skill_key in SKILLS_MATRIX.get(category, {}):
            return pillar
    return None


def target(skill_key: str, role_id: str) -> int:
    """The level ``role_id`` is expected to reach in a skill, 0 if none.

    0 means the role does not need the skill, which is a statement and not
    a missing value -- an L1 with no target for memory forensics is not a
    gap.
    """
    for skills in SKILLS_MATRIX.values():
        skill = skills.get(skill_key)
        if skill is not None:
            return int(skill["targets"].get(role_id, 0))
    return 0


def role_ids() -> Tuple[str, ...]:
    """Every role the targets mention."""
    seen = set()
    for skills in SKILLS_MATRIX.values():
        for skill in skills.values():
            seen.update(skill["targets"])
    return tuple(sorted(seen))


def mean_target(role_id: str, pillar: str) -> float:
    """``role_id``'s average target across a pillar, over ALL its skills.

    Averaging over every skill in the pillar rather than only the ones the
    role has a target for is the whole point: a role expected to be expert
    at two of five skills and absent from the other three does not own the
    pillar, and an average over its two best skills would say it does.
    """
    skills = skills_in(pillar)
    if not skills:
        return 0.0
    total = sum(int(s["targets"].get(role_id, 0)) for s in skills.values())
    return total / len(skills)


#: A role owns a pillar when its mean target reaches this.
OWNER_MEAN = 3.0
#: ...or when the pillar is the role's own strongest and clears this floor.
#: The second clause exists for specialists whose pillar nobody else comes
#: near; the floor stops it crediting a junior role with the pillar it
#: happens to score highest in. An L1 analyst's best pillar is SIEM at a
#: mean of 1.0, and "the L1s own SIEM" is exactly the wrong conclusion.
OWNER_TOP_FLOOR = 2.5


def owners_of(pillar: str) -> Tuple[str, ...]:
    """The roles whose day job this pillar is.

    Derived from the targets rather than listed, so the two cannot drift.
    """
    means = {r: mean_target(r, pillar) for r in role_ids()}
    if not means:
        return ()
    best = max(means.values())
    return tuple(sorted(
        r for r, m in means.items()
        if m >= OWNER_MEAN or (m == best and m >= OWNER_TOP_FLOOR)
    ))


def pillars_owned_by(role_id: str) -> Tuple[str, ...]:
    return tuple(p for p in PILLARS if role_id in owners_of(p))


def roles_without_a_pillar() -> Tuple[str, ...]:
    """Roles the targets never make accountable for anything.

    Not a bug in the rule. For junior roles it is correct -- an L1 is
    working towards pillars, not answerable for one. For a specialist it
    means the targets under-specify the role, and coverage will understate
    what seating one actually buys. Surfaced rather than patched over,
    because the fix is to fill in that role's targets and that is a
    decision for whoever owns the matrix.
    """
    return tuple(r for r in role_ids() if not pillars_owned_by(r))


# --- certificates -----------------------------------------------------------

#: Certificate -> the pillars holding it is evidence for.
#:
#: Evidence of having been examined on a pillar, which is not the same as
#: doing it here: a GCIH from 2019 says somebody once knew incident
#: response, not that they are on the rota. Anything consuming this has to
#: weigh it below somebody whose job it is, and has to check the expiry.
#:
#: An empty tuple is a deliberate answer, not a hole: foundation and
#: vendor-breadth certificates are real qualifications that do not make
#: anybody the cover for a particular pillar.
CERT_PILLARS: Dict[str, Tuple[str, ...]] = {
    # foundation -- known, deliberately credited to no pillar
    "SECURITY+": (),
    "ITIL FOUNDATION": (),
    "QUALYS/TENABLE VENDOR CERTS": (),
    # monitoring and detection
    "CYSA+": ("SIEM & Log Analysis", "Incident Response"),
    "BTL1": ("SIEM & Log Analysis", "Incident Response"),
    "BTL2": ("Incident Response", "Digital Forensics"),
    "SC-200": ("SIEM & Log Analysis", "Detection Engineering"),
    "GCIA": ("SIEM & Log Analysis", "Network Defense"),
    "GMON": ("SIEM & Log Analysis", "Detection Engineering"),
    "GCDA": ("Detection Engineering", "SIEM & Log Analysis"),
    "ELASTIC CERTIFIED ENGINEER": ("SIEM & Log Analysis",),
    "VENDOR SIEM ADMINISTRATION CERTIFICATIONS": ("SIEM & Log Analysis",),
    # incident response
    "GCIH": ("Incident Response",),
    "ECIH": ("Incident Response",),
    # forensics and malware
    "GCFA": ("Digital Forensics", "Incident Response"),
    "GCFE": ("Digital Forensics",),
    "FOR508": ("Digital Forensics", "Incident Response"),
    "GNFA": ("Digital Forensics", "Network Defense"),
    "GREM": ("Digital Forensics",),
    "ENCE": ("Digital Forensics",),
    # threat intelligence
    "GCTI": ("Threat Intelligence",),
    "CTIA": ("Threat Intelligence",),
    "CPTIA": ("Threat Intelligence",),
    # automation
    "GPYC": ("Scripting & Automation",),
    "VENDOR SOAR CERTIFICATIONS": ("Scripting & Automation",),
    # offensive
    "OSCP": ("Offensive Security",),
    "OSCE": ("Offensive Security",),
    "PENTEST+": ("Offensive Security",),
    "GWAPT": ("Offensive Security",),
    "GCPN": ("Offensive Security",),
    "CRTO": ("Offensive Security",),
    # cloud, network and OT
    "GCLD": ("Network Defense", "Security Architecture"),
    "AZ-500": ("Network Defense", "Security Architecture"),
    "AWS CERTIFIED SECURITY - SPECIALTY": ("Network Defense",
                                           "Security Architecture"),
    "CCSK": ("Network Defense", "Security Architecture"),
    "GICSP": ("Network Defense",),
    "GRID": ("Network Defense", "Incident Response"),
    "ISA/IEC 62443": ("Network Defense",),
    # governance and architecture
    "CISSP": ("Security Architecture", "Governance & Leadership"),
    "CISM": ("Governance & Leadership",),
    "CISA": ("Governance & Leadership",),
    "CRISC": ("Governance & Leadership",),
    "ISO 27001 LEAD AUDITOR": ("Governance & Leadership",),
    "GSOM": ("Governance & Leadership",),
    "CARNEGIE MELLON INSIDER THREAT PROGRAM MANAGER":
        ("Governance & Leadership",),
}


def pillars_for_cert(cert_name: str) -> Optional[Tuple[str, ...]]:
    """The pillars a certificate is evidence for.

    ``None`` for one this does not recognise, and an empty tuple for one it
    recognises as not pillar-specific. A caller must tell those apart: the
    first means "nobody has mapped this yet, go and look", the second
    means "mapped, and the answer is no pillar". Collapsing them both to
    zero would hide every certificate ION has not been taught.

    Matching ignores the issuing body, because the same certificate gets
    recorded as "GCIH", "GIAC GCIH" and "SANS GCIH".
    """
    text = (cert_name or "").upper().strip()
    if not text:
        return None
    if text in CERT_PILLARS:
        return CERT_PILLARS[text]
    # Longest key first, so a short code that happens to appear inside a
    # longer certificate's name cannot shadow the longer one.
    for key in sorted(CERT_PILLARS, key=len, reverse=True):
        if key in text:
            return CERT_PILLARS[key]
    return None


# --- the bridge to the role catalogue ---------------------------------------

#: Catalogue role id -> the matrix role whose targets apply to it.
#:
#: Two vocabularies, because they were written for different jobs: the
#: catalogue describes posts a SOC establishes, the matrix describes
#: profiles skills are rated against. They do not map one to one, and
#: pretending otherwise is how a Technical Analyst ends up held to an L1's
#: targets.
#:
#: ``None`` is a real entry. A role with no matrix equivalent contributes
#: nothing to primary coverage, which is better than borrowing another
#: role's targets -- a vulnerability analyst is not a penetration tester.
#: test_skills_matrix_data.py fails if a catalogue role is missing from
#: here, so a new one cannot be added and silently counted as nothing.
CATALOGUE_TO_SKILLS_ROLE: Dict[str, Optional[str]] = {
    "l1_soc_analyst": "l1-analyst",
    "l2_soc_analyst": "l2-analyst",
    "l3_soc_analyst": "l3-analyst",
    # A shift lead and a lead analyst are senior analysts who also lead.
    # Mapping them to soc-lead made their day job governance, which put
    # the Lead Analyst's cover against Governance & Leadership and left
    # the queue they actually run reading as one person short.
    "soc_shift_lead": "l3-analyst",
    "lead_analyst": "l3-analyst",
    "operations_analyst": "l3-analyst",
    "technical_analyst": "l3-analyst",
    "soc_lead": "soc-lead",
    "soc_manager": "soc-lead",
    "detection_engineer": "detection-engineer",
    "lead_engineer": "detection-engineer",
    "soc_engineer": "security-engineer",
    "automation_engineer": "security-engineer",
    "incident_responder": "incident-responder",
    "dfir_analyst": "digital-forensics",
    "malware_analyst": "malware-analyst",
    "cti_analyst": "threat-intel",
    "threat_hunter": "threat-hunter",
    "grc_analyst": "grc",
    "vuln_analyst": None,          # the matrix has no vulnerability role
    "cloud_security_analyst": "cloud-security",
    "ot_security_analyst": None,   # nor an OT one
    "purple_team": "pen-tester",
    "insider_threat_analyst": None,
}


def skills_role_for(catalogue_id: str) -> Optional[str]:
    return CATALOGUE_TO_SKILLS_ROLE.get(catalogue_id)


def unmapped_catalogue_roles() -> List[str]:
    """Catalogue roles the matrix cannot speak about."""
    return sorted(k for k, v in CATALOGUE_TO_SKILLS_ROLE.items() if v is None)
