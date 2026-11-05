"""The certification catalogue: what each one costs, and what it covers.

This was a JavaScript literal in training.html and nothing on the server
could read it -- the same position skills_matrix was in before it moved.
It matters more here than for most reference data, because these 85
entries are the only prices in ION: a training plan item's cost is
whatever somebody copied off this screen, and the forecast then adds
them up and puts them in front of a budget conversation.

The template keeps its copy for the browser-side catalogue UI, and
tests/test_cert_catalogue_data.py fails if the two drift. Two copies of
reference data drift silently, because each screen looks right on its
own.

**Prices are GBP, and the converted ones say so and how.** The 20
entries checked against their vendors hold the vendor's published
figure converted at a rate recorded beside it, so the arithmetic is
reproducible: multiply `vendor_price` by `rate` and you get `cost`
back, and a test asserts it. The remaining 65 are the template's
original undated GBP, which nobody has checked against anything.

A converted price is only true on the day of its rate. `rate_date` says
which day, and a figure whose rate is months old should be treated as
an estimate -- that is how the previous numbers went wrong. The old
flat SANS figure of GBP 6,800 implies about 1.29 USD/GBP against
tuition alone, so it was a fair conversion of the wrong amount at an
older rate, and OSCP's GBP 1,300 converts to within a pound of today's
figure. Neither was careless; both were stale.

PRICE_PROVENANCE says which figures have been checked and against what;
`unverified_prices()` names the rest, so "nobody has confirmed this" is
visible rather than implied.

**The costs are not all the same kind of thing.** Some are an exam fee
(Security+), some are a training course with the exam bundled (the
SANS/GIAC entries, which is why they are thousands rather than
hundreds). Anything summing them has to know which it is quoting.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

#: Catalogue domains, in the order the picker shows them.
CERT_DOMAINS: List[Dict[str, Any]] = [
    {
        "id": "secops",
        "name": "Security Operations",
        "icon": "icon-shield-check",
        "color": "#06b6d4"
    },
    {
        "id": "ir",
        "name": "IR & Forensics",
        "icon": "icon-search",
        "color": "#ef4444"
    },
    {
        "id": "threat",
        "name": "Threat Intel",
        "icon": "icon-brain",
        "color": "#a855f7"
    },
    {
        "id": "cloud",
        "name": "Cloud Security",
        "icon": "icon-cloud",
        "color": "#3b82f6"
    },
    {
        "id": "pentest",
        "name": "Pen Testing & Red Team",
        "icon": "icon-swords",
        "color": "#f97316"
    },
    {
        "id": "grc",
        "name": "GRC & Management",
        "icon": "icon-clipboard-list",
        "color": "#eab308"
    },
    {
        "id": "arch",
        "name": "Security Architecture",
        "icon": "icon-network",
        "color": "#6366f1"
    },
    {
        "id": "devsec",
        "name": "DevSecOps & AppSec",
        "icon": "icon-terminal",
        "color": "#10b981"
    }
]

#: Levels, hardest first -- the order the catalogue UI sorts by.
LEVELS: Tuple[str, ...] = ('expert', 'advanced', 'intermediate', 'foundation')

#: The catalogue itself. Mirrors CR_CERTS in training.html exactly;
#: tests/test_cert_catalogue_data.py fails if they differ.
CERTIFICATIONS: List[Dict[str, Any]] = [
    {
        "id": "secplus",
        "name": "Security+",
        "abbr": "Sec+",
        "provider": "CompTIA",
        "domain": "secops",
        "level": "foundation",
        "cost": 295,
        "currency": "GBP",
        "desc": "Foundational cybersecurity certification covering threat analysis, risk management, and network security. The industry standard entry-level cert.",
        "duration": "90 min",
        "questions": "90 MCQ + PBQ",
        "passing": "750/900",
        "renewal": "3 years / 50 CEUs",
        "prereqs": [],
        "topics": [
            "Threats & Vulnerabilities",
            "Architecture & Design",
            "Implementation",
            "Operations & IR",
            "Governance"
        ]
    },
    {
        "id": "cysa",
        "name": "CySA+",
        "abbr": "CySA+",
        "provider": "CompTIA",
        "domain": "secops",
        "level": "intermediate",
        "cost": 310,
        "currency": "GBP",
        "desc": "Validates behavioral analytics skills to detect and respond to cybersecurity threats through continuous security monitoring.",
        "duration": "165 min",
        "questions": "85 MCQ + PBQ",
        "passing": "750/900",
        "renewal": "3 years / 60 CEUs",
        "prereqs": [
            "secplus"
        ],
        "topics": [
            "Threat Management",
            "Vulnerability Management",
            "Incident Response",
            "Security Architecture"
        ]
    },
    {
        "id": "casp",
        "name": "CASP+",
        "abbr": "CASP+",
        "provider": "CompTIA",
        "domain": "secops",
        "level": "advanced",
        "cost": 380,
        "currency": "GBP",
        "desc": "Advanced-level practitioner certification for security architects and senior security engineers. Performance-based, no multiple choice.",
        "duration": "165 min",
        "questions": "90 PBQ",
        "passing": "Pass/Fail",
        "renewal": "3 years / 75 CEUs",
        "prereqs": [
            "cysa"
        ],
        "topics": [
            "Security Architecture",
            "Security Operations",
            "Governance",
            "Risk & Compliance",
            "Enterprise Security"
        ]
    },
    {
        "id": "cdsa",
        "name": "GIAC GCIA",
        "abbr": "GCIA",
        "provider": "SANS/GIAC",
        "domain": "secops",
        "level": "advanced",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Intrusion analyst certification. Deep-dive into traffic analysis, protocol dissection, and IDS/IPS management. One of the most respected blue team certs.",
        "duration": "Open book, 4h",
        "questions": "106",
        "passing": "70%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "TCP/IP",
            "IDS",
            "Signature Analysis",
            "Traffic Analysis",
            "Incident Handling"
        ]
    },
    {
        "id": "gsom",
        "name": "GIAC GSOM",
        "abbr": "GSOM",
        "provider": "SANS/GIAC",
        "domain": "secops",
        "level": "expert",
        "cost": 7266,
        "currency": "GBP",
        "desc": "SOC management certification covering building and running a security operations center. Strategy, staffing, metrics, and tool optimization.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "71%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "SOC Strategy",
            "Analyst Development",
            "Detection Engineering",
            "Metrics & Reporting",
            "Tool Optimization"
        ]
    },
    {
        "id": "splunkcore",
        "name": "Splunk Core Certified User",
        "abbr": "Splunk Core",
        "provider": "Splunk",
        "domain": "secops",
        "level": "foundation",
        "cost": 100,
        "currency": "GBP",
        "desc": "Validates foundational Splunk searching, reporting, and dashboard skills. Essential for SOC analysts using Splunk SIEM.",
        "duration": "60 min",
        "questions": "65",
        "passing": "70%",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "Searching",
            "Fields",
            "Reports",
            "Dashboards",
            "Lookups"
        ]
    },
    {
        "id": "ecsa",
        "name": "Elastic Certified Analyst",
        "abbr": "ECA",
        "provider": "Elastic",
        "domain": "secops",
        "level": "intermediate",
        "cost": 320,
        "currency": "GBP",
        "desc": "Validates skills in using Elastic Security for threat hunting, detection rules, and alert triage in Elasticsearch environments.",
        "duration": "120 min",
        "questions": "40 hands-on",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "KQL",
            "Detection Rules",
            "Alert Triage",
            "Dashboards",
            "Timeline Investigation"
        ]
    },
    {
        "id": "csa",
        "name": "CrowdStrike CCFA",
        "abbr": "CCFA",
        "provider": "CrowdStrike",
        "domain": "secops",
        "level": "intermediate",
        "cost": 160,
        "currency": "GBP",
        "desc": "CrowdStrike Certified Falcon Administrator. Validates skills in managing and operating the Falcon platform for endpoint detection and response.",
        "duration": "90 min",
        "questions": "60",
        "passing": "70%",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "Falcon Console",
            "Host Management",
            "Detection Policies",
            "IOA/IOC",
            "Response Actions"
        ]
    },
    {
        "id": "sscp",
        "name": "SSCP",
        "abbr": "SSCP",
        "provider": "ISC2",
        "domain": "secops",
        "level": "intermediate",
        "cost": 200,
        "currency": "GBP",
        "desc": "Systems Security Certified Practitioner. Validates hands-on security operations skills \u2014 access controls, IR, cryptography, network security.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "700/1000",
        "renewal": "3 years / 60 CPEs",
        "prereqs": [],
        "topics": [
            "Access Controls",
            "Security Operations",
            "Risk Identification",
            "IR & Recovery",
            "Cryptography",
            "Network Security"
        ]
    },
    {
        "id": "ecih",
        "name": "EC-Council ECIH",
        "abbr": "ECIH",
        "provider": "EC-Council",
        "domain": "ir",
        "level": "foundation",
        "cost": 595,
        "currency": "GBP",
        "desc": "EC-Council Certified Incident Handler. Covers the full IR lifecycle \u2014 preparation, identification, containment, eradication, and recovery.",
        "duration": "3 hours",
        "questions": "100",
        "passing": "70%",
        "renewal": "3 years / 120 ECE",
        "prereqs": [],
        "topics": [
            "IR Process",
            "Forensic Readiness",
            "Malware Incidents",
            "Email/Web/Insider Threats",
            "Cloud IR"
        ]
    },
    {
        "id": "gcih",
        "name": "GIAC GCIH",
        "abbr": "GCIH",
        "provider": "SANS/GIAC",
        "domain": "ir",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Certified Incident Handler. The gold standard for incident response skills \u2014 detection, response, and handling security incidents.",
        "duration": "Open book, 4h",
        "questions": "106",
        "passing": "70%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Incident Handling",
            "Hacker Techniques",
            "Tools",
            "Attack Detection",
            "Packet Analysis"
        ]
    },
    {
        "id": "gcfe",
        "name": "GIAC GCFE",
        "abbr": "GCFE",
        "provider": "SANS/GIAC",
        "domain": "ir",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Certified Forensic Examiner. Windows forensics, browser forensics, email analysis, and evidence preservation for DFIR practitioners.",
        "duration": "Open book, 4h",
        "questions": "115",
        "passing": "71%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Windows Forensics",
            "Browser Analysis",
            "Email Forensics",
            "Evidence Handling",
            "Registry Analysis"
        ]
    },
    {
        "id": "gnfa",
        "name": "GIAC GNFA",
        "abbr": "GNFA",
        "provider": "SANS/GIAC",
        "domain": "ir",
        "level": "advanced",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Network Forensic Analyst. Advanced network forensics including protocol analysis, encrypted traffic, and network-level indicators of compromise.",
        "duration": "Open book, 4h",
        "questions": "115",
        "passing": "70%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "gcih"
        ],
        "topics": [
            "Network Forensics",
            "Protocol Analysis",
            "Encrypted Traffic",
            "NetFlow",
            "Wireless Forensics"
        ]
    },
    {
        "id": "grem",
        "name": "GIAC GREM",
        "abbr": "GREM",
        "provider": "SANS/GIAC",
        "domain": "ir",
        "level": "advanced",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Reverse Engineering Malware. Deep malware analysis skills \u2014 static/dynamic analysis, code-level reverse engineering, and behavioral analysis.",
        "duration": "Open book, 4h",
        "questions": "75",
        "passing": "70%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "gcih"
        ],
        "topics": [
            "Static Analysis",
            "Dynamic Analysis",
            "Disassembly",
            "Document Malware",
            "Shellcode Analysis"
        ]
    },
    {
        "id": "cfce",
        "name": "IACIS CFCE",
        "abbr": "CFCE",
        "provider": "IACIS",
        "domain": "ir",
        "level": "advanced",
        "cost": 595,
        "currency": "GBP",
        "desc": "Certified Forensic Computer Examiner. Comprehensive digital forensics certification covering evidence acquisition, analysis, and courtroom presentation.",
        "duration": "Practical + written",
        "questions": "Peer review + exam",
        "passing": "80%",
        "renewal": "3 years / 40 hours training",
        "prereqs": [],
        "topics": [
            "Evidence Acquisition",
            "File System Analysis",
            "Email Forensics",
            "Internet Artifacts",
            "Report Writing"
        ]
    },
    {
        "id": "chfi",
        "name": "EC-Council CHFI",
        "abbr": "CHFI",
        "provider": "EC-Council",
        "domain": "ir",
        "level": "intermediate",
        "cost": 950,
        "currency": "GBP",
        "desc": "Computer Hacking Forensic Investigator. Digital forensics investigation skills including evidence collection, data recovery, and analysis.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "70%",
        "renewal": "3 years / 120 ECE",
        "prereqs": [],
        "topics": [
            "Forensic Science",
            "Hard Disk Forensics",
            "OS Forensics",
            "Network Forensics",
            "Mobile Forensics"
        ]
    },
    {
        "id": "gfa",
        "name": "GIAC GX-FA",
        "abbr": "GX-FA",
        "provider": "SANS/GIAC",
        "domain": "ir",
        "level": "expert",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Advanced Forensics & Incident Response. Expert-level forensics for lead investigators and DFIR team leads handling complex, multi-vector incidents.",
        "duration": "Open book, 3h",
        "questions": "82",
        "passing": "64%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "gnfa"
        ],
        "topics": [
            "Advanced Memory Forensics",
            "APT Tracking",
            "Multi-platform IR",
            "DFIR Automation",
            "Expert Witness"
        ]
    },
    {
        "id": "gosi",
        "name": "GIAC GOSI",
        "abbr": "GOSI",
        "provider": "SANS/GIAC",
        "domain": "threat",
        "level": "foundation",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Open Source Intelligence. OSINT collection, analysis, and operational security for intelligence gathering and investigations.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "66%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "OSINT Tools",
            "Social Media Intel",
            "Dark Web",
            "Sock Puppets",
            "Operational Security"
        ]
    },
    {
        "id": "gcti",
        "name": "GIAC GCTI",
        "abbr": "GCTI",
        "provider": "SANS/GIAC",
        "domain": "threat",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Cyber Threat Intelligence. Strategic and operational threat intelligence \u2014 APT profiling, intelligence cycle, and analytical frameworks.",
        "duration": "Open book, 4h",
        "questions": "75",
        "passing": "70%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Intelligence Cycle",
            "APT Analysis",
            "Diamond Model",
            "MITRE ATT&CK",
            "Strategic Intel",
            "Kill Chain"
        ]
    },
    {
        "id": "ctia",
        "name": "EC-Council CTIA",
        "abbr": "CTIA",
        "provider": "EC-Council",
        "domain": "threat",
        "level": "intermediate",
        "cost": 595,
        "currency": "GBP",
        "desc": "Certified Threat Intelligence Analyst. Covers threat data collection, processing, analysis, and dissemination in structured and unstructured formats.",
        "duration": "3 hours",
        "questions": "100",
        "passing": "70%",
        "renewal": "3 years / 120 ECE",
        "prereqs": [],
        "topics": [
            "Data Collection",
            "Analysis Frameworks",
            "APT Groups",
            "Intelligence Sharing",
            "TLP/STIX/TAXII"
        ]
    },
    {
        "id": "gti_mgmt",
        "name": "GIAC GSTRT",
        "abbr": "GSTRT",
        "provider": "SANS/GIAC",
        "domain": "threat",
        "level": "advanced",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Strategic Threat Intelligence. Building and managing CTI programs \u2014 team structure, collection planning, stakeholder communication, and intelligence-driven defense.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "67%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "gcti"
        ],
        "topics": [
            "Intel Program Design",
            "Collection Management",
            "Stakeholder Briefs",
            "Attribution",
            "Strategic Analysis"
        ]
    },
    {
        "id": "crtp",
        "name": "CRTL",
        "abbr": "CRTL",
        "provider": "SANS/GIAC",
        "domain": "threat",
        "level": "expert",
        "cost": 6800,
        "currency": "GBP",
        "desc": "Threat Intelligence Lead. Expert-level threat intel leadership \u2014 managing teams, developing collection strategies, driving intelligence-led operations.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "66%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "gti_mgmt"
        ],
        "topics": [
            "Intel Team Leadership",
            "Collection Strategy",
            "Purple Teaming",
            "Campaign Tracking",
            "Executive Reporting"
        ]
    },
    {
        "id": "ccsk",
        "name": "CSA CCSK",
        "abbr": "CCSK",
        "provider": "ISC2",
        "domain": "cloud",
        "level": "foundation",
        "cost": 315,
        "currency": "GBP",
        "desc": "Certificate of Cloud Security Knowledge. Foundational cloud security covering shared responsibility, data security, and cloud governance.",
        "duration": "90 min",
        "questions": "60",
        "passing": "80%",
        "renewal": "None (lifetime)",
        "prereqs": [],
        "topics": [
            "Cloud Architecture",
            "Data Security",
            "IAM",
            "Compliance",
            "Incident Response"
        ]
    },
    {
        "id": "awssaa",
        "name": "AWS SA Associate",
        "abbr": "AWS SAA",
        "provider": "AWS",
        "domain": "cloud",
        "level": "foundation",
        "cost": 120,
        "currency": "GBP",
        "desc": "AWS Solutions Architect Associate. Designing distributed systems on AWS \u2014 VPC, IAM, S3, EC2, Lambda. Foundation for cloud security understanding.",
        "duration": "130 min",
        "questions": "65",
        "passing": "720/1000",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "Compute",
            "Storage",
            "Networking",
            "Security",
            "Databases",
            "Monitoring"
        ]
    },
    {
        "id": "awsscs",
        "name": "AWS Security Specialty",
        "abbr": "AWS Sec",
        "provider": "AWS",
        "domain": "cloud",
        "level": "intermediate",
        "cost": 240,
        "currency": "GBP",
        "desc": "AWS Certified Security Specialty. Deep dive into AWS security services \u2014 GuardDuty, Security Hub, KMS, WAF, and incident response in cloud environments.",
        "duration": "170 min",
        "questions": "65",
        "passing": "750/1000",
        "renewal": "3 years",
        "prereqs": [
            "awssaa"
        ],
        "topics": [
            "IR",
            "Logging & Monitoring",
            "IAM",
            "Data Protection",
            "Infrastructure Security"
        ]
    },
    {
        "id": "az500",
        "name": "AZ-500",
        "abbr": "AZ-500",
        "provider": "Microsoft",
        "domain": "cloud",
        "level": "intermediate",
        "cost": 130,
        "currency": "GBP",
        "desc": "Microsoft Azure Security Technologies. Managing identity and access, platform protection, security operations, and data security in Azure.",
        "duration": "150 min",
        "questions": "40-60",
        "passing": "700/1000",
        "renewal": "Annual renewal",
        "prereqs": [],
        "topics": [
            "Identity & Access",
            "Platform Protection",
            "Security Operations",
            "Data & App Security"
        ]
    },
    {
        "id": "gcsec",
        "name": "Google PCA",
        "abbr": "GPCA",
        "provider": "Google",
        "domain": "cloud",
        "level": "intermediate",
        "cost": 160,
        "currency": "GBP",
        "desc": "Google Professional Cloud Architect. Designing secure, scalable cloud solutions on GCP \u2014 IAM, VPC, encryption, and compliance.",
        "duration": "120 min",
        "questions": "50-60",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "Cloud Architecture",
            "Security Design",
            "Compliance",
            "Reliability",
            "Migration"
        ]
    },
    {
        "id": "ccsp",
        "name": "CCSP",
        "abbr": "CCSP",
        "provider": "ISC2",
        "domain": "cloud",
        "level": "advanced",
        "cost": 475,
        "currency": "GBP",
        "desc": "Certified Cloud Security Professional. Advanced cloud security across all major platforms \u2014 architecture, data security, operations, compliance, and legal.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "700/1000",
        "renewal": "3 years / 90 CPEs",
        "prereqs": [
            "ccsk"
        ],
        "topics": [
            "Cloud Architecture",
            "Data Security",
            "Platform Security",
            "Application Security",
            "Operations",
            "Legal & Compliance"
        ]
    },
    {
        "id": "awssap",
        "name": "AWS SA Professional",
        "abbr": "AWS SAP",
        "provider": "AWS",
        "domain": "cloud",
        "level": "advanced",
        "cost": 240,
        "currency": "GBP",
        "desc": "AWS Solutions Architect Professional. Expert-level multi-account architecture, cost optimization, and complex migration strategies.",
        "duration": "180 min",
        "questions": "75",
        "passing": "750/1000",
        "renewal": "3 years",
        "prereqs": [
            "awssaa"
        ],
        "topics": [
            "Complex Architectures",
            "Cost Optimization",
            "Migration",
            "Multi-Account",
            "Hybrid Cloud"
        ]
    },
    {
        "id": "penplus",
        "name": "PenTest+",
        "abbr": "Pen+",
        "provider": "CompTIA",
        "domain": "pentest",
        "level": "foundation",
        "cost": 310,
        "currency": "GBP",
        "desc": "Intermediate pen testing cert covering planning, scoping, vulnerability assessment, and hands-on exploitation techniques.",
        "duration": "165 min",
        "questions": "85 MCQ + PBQ",
        "passing": "750/900",
        "renewal": "3 years / 60 CEUs",
        "prereqs": [
            "secplus"
        ],
        "topics": [
            "Planning & Scoping",
            "Information Gathering",
            "Vulnerability Assessment",
            "Attacks & Exploits",
            "Reporting"
        ]
    },
    {
        "id": "ejpt",
        "name": "eJPT",
        "abbr": "eJPT",
        "provider": "eLearnSecurity",
        "domain": "pentest",
        "level": "foundation",
        "cost": 200,
        "currency": "GBP",
        "desc": "eLearnSecurity Junior Penetration Tester. Practical, hands-on entry-level pen test cert. Lab-based exam testing real exploitation skills.",
        "duration": "48 hours (lab)",
        "questions": "20 practical",
        "passing": "70%",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "Networking",
            "Web App Testing",
            "Host Exploitation",
            "Scripting",
            "Reporting"
        ]
    },
    {
        "id": "pnpt",
        "name": "PNPT",
        "abbr": "PNPT",
        "provider": "TCM Security",
        "domain": "pentest",
        "level": "intermediate",
        "cost": 315,
        "currency": "GBP",
        "desc": "Practical Network Penetration Tester. Full external and internal pen test in a realistic lab. Includes OSINT, AD attacks, and report writing.",
        "duration": "5 days (lab)",
        "questions": "Practical report",
        "passing": "Report graded",
        "renewal": "Lifetime",
        "prereqs": [],
        "topics": [
            "OSINT",
            "External Pentest",
            "Active Directory",
            "Post-Exploitation",
            "Report Writing"
        ]
    },
    {
        "id": "ceh",
        "name": "CEH",
        "abbr": "CEH",
        "provider": "EC-Council",
        "domain": "pentest",
        "level": "intermediate",
        "cost": 950,
        "currency": "GBP",
        "desc": "Certified Ethical Hacker. Covers hacking techniques and tools across multiple domains. Widely recognized but knowledge-based rather than practical.",
        "duration": "4 hours",
        "questions": "125",
        "passing": "60-85%",
        "renewal": "3 years / 120 ECE",
        "prereqs": [],
        "topics": [
            "Footprinting",
            "Scanning",
            "Enumeration",
            "Exploitation",
            "Web Hacking",
            "Social Engineering"
        ]
    },
    {
        "id": "oscp",
        "name": "OSCP",
        "abbr": "OSCP",
        "provider": "Offensive Security",
        "domain": "pentest",
        "level": "advanced",
        "cost": 1299,
        "currency": "GBP",
        "desc": "Offensive Security Certified Professional. The gold standard practical pen testing cert. 24-hour hands-on exam exploiting multiple machines in a network.",
        "duration": "24 hours + report",
        "questions": "Practical",
        "passing": "70 points",
        "renewal": "None (lifetime)",
        "prereqs": [],
        "topics": [
            "Linux/Windows Exploitation",
            "Privilege Escalation",
            "Web Apps",
            "Active Directory",
            "Tunneling",
            "Report Writing"
        ]
    },
    {
        "id": "crto",
        "name": "CRTO",
        "abbr": "CRTO",
        "provider": "Zero Point Security",
        "domain": "pentest",
        "level": "advanced",
        "cost": 450,
        "currency": "GBP",
        "desc": "Certified Red Team Operator. Cobalt Strike-focused red team operations \u2014 C2, evasion, lateral movement, and domain dominance in simulated enterprise.",
        "duration": "48 hours (lab)",
        "questions": "6/8 flags",
        "passing": "6 flags",
        "renewal": "Lifetime",
        "prereqs": [],
        "topics": [
            "Cobalt Strike",
            "OPSEC",
            "Lateral Movement",
            "Privilege Escalation",
            "Domain Dominance",
            "Evasion"
        ]
    },
    {
        "id": "gxpn",
        "name": "GIAC GXPN",
        "abbr": "GXPN",
        "provider": "SANS/GIAC",
        "domain": "pentest",
        "level": "expert",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Expert Penetration Tester. SANS' most advanced pen test cert \u2014 custom exploit development, advanced network attacks, and cryptographic attacks.",
        "duration": "Open book, 3h",
        "questions": "60",
        "passing": "67%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "oscp"
        ],
        "topics": [
            "Exploit Development",
            "Network Attacks",
            "Crypto Attacks",
            "Fuzzing",
            "Shellcode",
            "Bypasses"
        ]
    },
    {
        "id": "osce3",
        "name": "OSCE3",
        "abbr": "OSCE3",
        "provider": "Offensive Security",
        "domain": "pentest",
        "level": "expert",
        "cost": 4350,
        "currency": "GBP",
        "desc": "Offensive Security Certified Expert 3. Requires OSWE + OSEP + OSED \u2014 web expert, evasion expert, and exploit developer. The ultimate OffSec achievement.",
        "duration": "3 x 48h exams",
        "questions": "Practical",
        "passing": "All 3 certs",
        "renewal": "None (lifetime)",
        "prereqs": [
            "oscp"
        ],
        "topics": [
            "Web Exploitation",
            "AV Evasion",
            "Exploit Development",
            "Shellcoding",
            "Active Directory",
            "Advanced Attacks"
        ]
    },
    {
        "id": "crt",
        "name": "CREST CRT",
        "abbr": "CRT",
        "provider": "CREST",
        "domain": "pentest",
        "level": "intermediate",
        "cost": 500,
        "currency": "GBP",
        "desc": "CREST Registered Penetration Tester. UK industry-standard pen test qualification. Required for CHECK/CREST-accredited testing.",
        "duration": "MCQ + Practical",
        "questions": "Mixed",
        "passing": "Pass/Fail",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "IP/Networking",
            "Web Technologies",
            "OS Security",
            "Cryptography",
            "Databases"
        ]
    },
    {
        "id": "cissp",
        "name": "CISSP",
        "abbr": "CISSP",
        "provider": "ISC2",
        "domain": "grc",
        "level": "advanced",
        "cost": 749,
        "currency": "GBP",
        "desc": "The most recognized information security management certification globally. Covers 8 domains spanning the full breadth of security practice. Requires 5 years experience.",
        "duration": "6 hours (CAT)",
        "questions": "125-175",
        "passing": "700/1000",
        "renewal": "3 years / 120 CPEs",
        "prereqs": [
            "sscp"
        ],
        "topics": [
            "Security & Risk Mgmt",
            "Asset Security",
            "Security Architecture",
            "Comms & Network",
            "IAM",
            "Assessment & Testing",
            "Security Operations",
            "Software Dev Security"
        ]
    },
    {
        "id": "cism",
        "name": "CISM",
        "abbr": "CISM",
        "provider": "ISACA",
        "domain": "grc",
        "level": "advanced",
        "cost": 455,
        "currency": "GBP",
        "desc": "Certified Information Security Manager. For security managers focusing on governance, risk management, program development, and incident management.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "450/800",
        "renewal": "3 years / 120 CPEs",
        "prereqs": [],
        "topics": [
            "Info Security Governance",
            "Risk Management",
            "Security Program",
            "Incident Management"
        ]
    },
    {
        "id": "cisa",
        "name": "CISA",
        "abbr": "CISA",
        "provider": "ISACA",
        "domain": "grc",
        "level": "intermediate",
        "cost": 455,
        "currency": "GBP",
        "desc": "Certified Information Systems Auditor. IT audit, control, and assurance. Widely recognized for governance and compliance roles.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "450/800",
        "renewal": "3 years / 120 CPEs",
        "prereqs": [],
        "topics": [
            "IS Audit Process",
            "IT Governance",
            "IS Acquisition & Development",
            "IS Operations",
            "Protection of IS Assets"
        ]
    },
    {
        "id": "crisc",
        "name": "CRISC",
        "abbr": "CRISC",
        "provider": "ISACA",
        "domain": "grc",
        "level": "advanced",
        "cost": 455,
        "currency": "GBP",
        "desc": "Certified in Risk and Information Systems Control. Enterprise IT risk management \u2014 identification, assessment, response, and monitoring.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "450/800",
        "renewal": "3 years / 120 CPEs",
        "prereqs": [
            "cisa"
        ],
        "topics": [
            "IT Risk Identification",
            "IT Risk Assessment",
            "Risk Response",
            "Control Monitoring"
        ]
    },
    {
        "id": "cgeit",
        "name": "CGEIT",
        "abbr": "CGEIT",
        "provider": "ISACA",
        "domain": "grc",
        "level": "expert",
        "cost": 455,
        "currency": "GBP",
        "desc": "Certified in Governance of Enterprise IT. For senior executives responsible for IT governance frameworks, strategic alignment, and value delivery.",
        "duration": "4 hours",
        "questions": "150",
        "passing": "450/800",
        "renewal": "3 years / 120 CPEs",
        "prereqs": [
            "cism"
        ],
        "topics": [
            "IT Governance Framework",
            "Strategic Alignment",
            "Value Delivery",
            "Risk Optimization",
            "Resource Optimization"
        ]
    },
    {
        "id": "itilf",
        "name": "ITIL 4 Foundation",
        "abbr": "ITIL4",
        "provider": "APMG",
        "domain": "grc",
        "level": "foundation",
        "cost": 315,
        "currency": "GBP",
        "desc": "IT Service Management foundation. Covers ITIL 4 practices including incident management, change control, and service desk operations.",
        "duration": "60 min",
        "questions": "40",
        "passing": "65%",
        "renewal": "None (lifetime)",
        "prereqs": [],
        "topics": [
            "Service Value System",
            "Guiding Principles",
            "Service Value Chain",
            "ITIL Practices",
            "Governance"
        ]
    },
    {
        "id": "iso27001",
        "name": "ISO 27001 LA",
        "abbr": "27001 LA",
        "provider": "APMG",
        "domain": "grc",
        "level": "intermediate",
        "cost": 1500,
        "currency": "GBP",
        "desc": "ISO 27001 Lead Auditor. Conduct ISMS audits against the international information security standard. Essential for compliance and audit roles.",
        "duration": "5-day course + exam",
        "questions": "MCQ",
        "passing": "70%",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "ISMS",
            "Risk Assessment",
            "Controls (Annex A)",
            "Audit Planning",
            "Non-conformities",
            "Certification Process"
        ]
    },
    {
        "id": "togaf",
        "name": "TOGAF 9",
        "abbr": "TOGAF",
        "provider": "APMG",
        "domain": "arch",
        "level": "intermediate",
        "cost": 550,
        "currency": "GBP",
        "desc": "The Open Group Architecture Framework. Enterprise architecture methodology for designing and governing technology architecture at scale.",
        "duration": "60 min L1 / 90 min L2",
        "questions": "40 / 8 scenario",
        "passing": "60% / 60%",
        "renewal": "None",
        "prereqs": [],
        "topics": [
            "ADM Cycle",
            "Architecture Governance",
            "Enterprise Continuum",
            "Capability Framework",
            "Content Framework"
        ]
    },
    {
        "id": "sabsa",
        "name": "SABSA Foundation",
        "abbr": "SABSA",
        "provider": "APMG",
        "domain": "arch",
        "level": "intermediate",
        "cost": 595,
        "currency": "GBP",
        "desc": "Sherwood Applied Business Security Architecture. Security architecture framework linking business requirements to security controls. Risk-driven design.",
        "duration": "90 min",
        "questions": "40",
        "passing": "65%",
        "renewal": "None",
        "prereqs": [],
        "topics": [
            "Business Requirements",
            "Security Services",
            "Logical Architecture",
            "Physical Architecture",
            "Lifecycle Management"
        ]
    },
    {
        "id": "cisaarch",
        "name": "CSSA",
        "abbr": "CSSA",
        "provider": "ISC2",
        "domain": "arch",
        "level": "advanced",
        "cost": 475,
        "currency": "GBP",
        "desc": "Certified Secure Software Architect (ISSAP concentration). Advanced architecture design \u2014 access control, security assessment, network security architecture.",
        "duration": "3 hours",
        "questions": "125",
        "passing": "700/1000",
        "renewal": "3 years / 20 CPEs",
        "prereqs": [
            "cissp"
        ],
        "topics": [
            "Architecture Methodology",
            "Access Control",
            "Telecom Security",
            "Security Assessment",
            "Tech-Related BCP/DRP"
        ]
    },
    {
        "id": "awssap_arch",
        "name": "AWS Sec Architect",
        "abbr": "AWS SecArch",
        "provider": "AWS",
        "domain": "arch",
        "level": "advanced",
        "cost": 240,
        "currency": "GBP",
        "desc": "AWS Solutions Architect Professional with security specialization. Multi-account, multi-region secure architecture at enterprise scale.",
        "duration": "180 min",
        "questions": "75",
        "passing": "750/1000",
        "renewal": "3 years",
        "prereqs": [
            "awssaa"
        ],
        "topics": [
            "Multi-Account Strategy",
            "Network Design",
            "Data Protection",
            "Identity Federation",
            "Disaster Recovery"
        ]
    },
    {
        "id": "cztp",
        "name": "Fortinet NSE7",
        "abbr": "NSE7",
        "provider": "Fortinet",
        "domain": "arch",
        "level": "advanced",
        "cost": 320,
        "currency": "GBP",
        "desc": "Fortinet Network Security Expert 7. Advanced firewall architecture, SD-WAN, zero trust, and multi-cloud security design with Fortinet products.",
        "duration": "60 min",
        "questions": "35",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "FortiGate Advanced",
            "SD-WAN",
            "Zero Trust",
            "Multi-Cloud",
            "FortiManager"
        ]
    },
    {
        "id": "pcnsa",
        "name": "Palo Alto PCNSA",
        "abbr": "PCNSA",
        "provider": "Palo Alto",
        "domain": "arch",
        "level": "foundation",
        "cost": 140,
        "currency": "GBP",
        "desc": "Palo Alto Certified Network Security Administrator. Firewall configuration, App-ID, Content-ID, and security policy management on PAN-OS.",
        "duration": "80 min",
        "questions": "75",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "PAN-OS",
            "Security Policies",
            "App-ID",
            "Content-ID",
            "Decryption",
            "Networking"
        ]
    },
    {
        "id": "ccna",
        "name": "CCNA",
        "abbr": "CCNA",
        "provider": "Cisco",
        "domain": "arch",
        "level": "foundation",
        "cost": 260,
        "currency": "GBP",
        "desc": "Cisco Certified Network Associate. Foundational networking cert covering routing, switching, IP services, and security fundamentals.",
        "duration": "120 min",
        "questions": "100",
        "passing": "825/1000",
        "renewal": "3 years / 30 CE",
        "prereqs": [],
        "topics": [
            "Network Fundamentals",
            "Network Access",
            "IP Connectivity",
            "IP Services",
            "Security",
            "Automation"
        ]
    },
    {
        "id": "csslp",
        "name": "CSSLP",
        "abbr": "CSSLP",
        "provider": "ISC2",
        "domain": "devsec",
        "level": "advanced",
        "cost": 475,
        "currency": "GBP",
        "desc": "Certified Secure Software Lifecycle Professional. Secure SDLC from requirements through deployment \u2014 threat modeling, secure coding, and testing.",
        "duration": "4 hours",
        "questions": "175",
        "passing": "700/1000",
        "renewal": "3 years / 90 CPEs",
        "prereqs": [],
        "topics": [
            "Secure Design",
            "Supply Chain",
            "Secure Coding",
            "Deployment",
            "Maintenance",
            "Testing"
        ]
    },
    {
        "id": "gweb",
        "name": "GIAC GWEB",
        "abbr": "GWEB",
        "provider": "SANS/GIAC",
        "domain": "devsec",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Web Application Penetration Tester. Finding and exploiting web app vulnerabilities \u2014 injection, XSS, auth flaws, and business logic bugs.",
        "duration": "Open book, 4h",
        "questions": "82",
        "passing": "71%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "OWASP Top 10",
            "Injection",
            "Auth/Session",
            "XSS",
            "CSRF",
            "API Security"
        ]
    },
    {
        "id": "oswe",
        "name": "OSWE",
        "abbr": "OSWE",
        "provider": "Offensive Security",
        "domain": "devsec",
        "level": "expert",
        "cost": 1300,
        "currency": "GBP",
        "desc": "Offensive Security Web Expert. White-box web app pen testing \u2014 source code review, auth bypass, and custom exploit development against real applications.",
        "duration": "48 hours + report",
        "questions": "Practical",
        "passing": "Pass/Fail",
        "renewal": "None (lifetime)",
        "prereqs": [
            "oscp"
        ],
        "topics": [
            "Source Code Review",
            "Auth Bypass",
            "Persistent XSS",
            "SQL Injection",
            "Deserialization",
            "Type Juggling"
        ]
    },
    {
        "id": "cde",
        "name": "CDE",
        "abbr": "CDE",
        "provider": "Cybrary",
        "domain": "devsec",
        "level": "foundation",
        "cost": 0,
        "currency": "GBP",
        "desc": "Cybrary Certified Detection Engineer (free). Introduction to detection engineering \u2014 writing rules, testing logic, and tuning for SIEM/EDR platforms.",
        "duration": "Self-paced",
        "questions": "Assessment",
        "passing": "Pass/Fail",
        "renewal": "None",
        "prereqs": [],
        "topics": [
            "SIGMA Rules",
            "YARA",
            "Detection Logic",
            "False Positive Tuning",
            "Data Sources"
        ]
    },
    {
        "id": "dsoe",
        "name": "GIAC GDAT",
        "abbr": "GDAT",
        "provider": "SANS/GIAC",
        "domain": "devsec",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Defending Advanced Threats. Purple team operations \u2014 building detections for advanced adversary techniques, validating controls, and improving defenses.",
        "duration": "Open book, 4h",
        "questions": "75",
        "passing": "69%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "APT Emulation",
            "Detection Engineering",
            "Endpoint Detection",
            "Network Detection",
            "Purple Teaming"
        ]
    },
    {
        "id": "ece",
        "name": "Elastic Certified Engineer",
        "abbr": "ECE",
        "provider": "Elastic",
        "domain": "secops",
        "level": "advanced",
        "cost": 320,
        "currency": "GBP",
        "desc": "Validates advanced skills in deploying, managing, and troubleshooting Elasticsearch clusters. Covers indexing, mappings, aggregations, cluster management, and performance tuning.",
        "duration": "120 min",
        "questions": "40 hands-on",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [
            "ecsa"
        ],
        "topics": [
            "Cluster Management",
            "Index Design",
            "Mappings & Analyzers",
            "Aggregations",
            "Cross-Cluster",
            "Performance Tuning"
        ]
    },
    {
        "id": "ecoe",
        "name": "Elastic Certified Observability Engineer",
        "abbr": "ECOE",
        "provider": "Elastic",
        "domain": "devsec",
        "level": "intermediate",
        "cost": 320,
        "currency": "GBP",
        "desc": "Demonstrates proficiency in using Elastic Observability for monitoring infrastructure, applications, and services \u2014 logs, metrics, APM, and uptime.",
        "duration": "120 min",
        "questions": "40 hands-on",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "Elastic Agent",
            "Fleet",
            "APM",
            "Logs & Metrics",
            "Uptime Monitoring",
            "SLOs",
            "Alerting"
        ]
    },
    {
        "id": "ecsiem",
        "name": "Elastic SIEM Specialist",
        "abbr": "ESIEM",
        "provider": "Elastic",
        "domain": "secops",
        "level": "intermediate",
        "cost": 320,
        "currency": "GBP",
        "desc": "Specialist certification for Elastic Security SIEM capabilities \u2014 detection rules, timeline investigation, case management, and threat hunting using EQL/ES|QL.",
        "duration": "120 min",
        "questions": "35 hands-on",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [
            "ecsa"
        ],
        "topics": [
            "Detection Rules",
            "EQL",
            "ES|QL",
            "Timeline",
            "Cases",
            "Threat Hunting",
            "Indicators"
        ]
    },
    {
        "id": "eced",
        "name": "Elastic Endpoint Security",
        "abbr": "ECED",
        "provider": "Elastic",
        "domain": "secops",
        "level": "advanced",
        "cost": 320,
        "currency": "GBP",
        "desc": "Covers Elastic Defend endpoint protection \u2014 malware prevention, ransomware protection, memory threat protection, and endpoint response actions.",
        "duration": "120 min",
        "questions": "35 hands-on",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [
            "ecsa"
        ],
        "topics": [
            "Elastic Defend",
            "Malware Prevention",
            "Ransomware Protection",
            "Memory Threats",
            "Response Actions",
            "Policy Management"
        ]
    },
    {
        "id": "gsec",
        "name": "GIAC GSEC",
        "abbr": "GSEC",
        "provider": "SANS/GIAC",
        "domain": "secops",
        "level": "foundation",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Security Essentials. Broad foundational cert validating hands-on security skills beyond theory \u2014 networking, defense, cryptography, and incident handling fundamentals.",
        "duration": "Open book, 5h",
        "questions": "106-180",
        "passing": "73%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Networking",
            "Defense in Depth",
            "Cryptography",
            "Linux/Windows Security",
            "Cloud Fundamentals",
            "Incident Handling"
        ]
    },
    {
        "id": "gcld",
        "name": "GIAC GCLD",
        "abbr": "GCLD",
        "provider": "SANS/GIAC",
        "domain": "cloud",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Cloud Security Automation. Building and securing cloud infrastructure using IaC, CI/CD pipelines, and cloud-native security tooling across AWS, Azure, and GCP.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "68%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Cloud Architecture",
            "IaC Security",
            "CI/CD Pipelines",
            "Container Security",
            "Cloud Monitoring",
            "Multi-Cloud"
        ]
    },
    {
        "id": "gpen",
        "name": "GIAC GPEN",
        "abbr": "GPEN",
        "provider": "SANS/GIAC",
        "domain": "pentest",
        "level": "intermediate",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Penetration Tester. SANS-level pen test cert covering advanced reconnaissance, exploitation, password attacks, and post-exploitation in enterprise environments.",
        "duration": "Open book, 3h",
        "questions": "82",
        "passing": "74%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Reconnaissance",
            "Scanning",
            "Exploitation",
            "Password Attacks",
            "Privilege Escalation",
            "Pivoting"
        ]
    },
    {
        "id": "gdsa",
        "name": "GIAC GDSA",
        "abbr": "GDSA",
        "provider": "SANS/GIAC",
        "domain": "arch",
        "level": "advanced",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Defensible Security Architecture. Designing and building resilient network architectures \u2014 zero trust, segmentation, cloud architecture, and detection-oriented design.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "69%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "Zero Trust",
            "Network Segmentation",
            "Cloud Architecture",
            "Detection Design",
            "Resilient Infrastructure",
            "Logging Architecture"
        ]
    },
    {
        "id": "sc200",
        "name": "SC-200",
        "abbr": "SC-200",
        "provider": "Microsoft",
        "domain": "secops",
        "level": "intermediate",
        "cost": 130,
        "currency": "GBP",
        "desc": "Microsoft Security Operations Analyst. Covers Microsoft Sentinel (SIEM), Defender XDR, threat hunting with KQL, and incident management in the Microsoft security stack.",
        "duration": "150 min",
        "questions": "40-60",
        "passing": "700/1000",
        "renewal": "Annual renewal",
        "prereqs": [],
        "topics": [
            "Microsoft Sentinel",
            "Defender XDR",
            "KQL Hunting",
            "Incident Response",
            "Threat Intelligence",
            "Workbooks"
        ]
    },
    {
        "id": "sc100",
        "name": "SC-100",
        "abbr": "SC-100",
        "provider": "Microsoft",
        "domain": "arch",
        "level": "advanced",
        "cost": 130,
        "currency": "GBP",
        "desc": "Microsoft Cybersecurity Architect Expert. Designing zero trust architecture, governance strategies, security operations architecture, and data/application security strategy across Microsoft platforms.",
        "duration": "150 min",
        "questions": "40-60",
        "passing": "700/1000",
        "renewal": "Annual renewal",
        "prereqs": [
            "az500"
        ],
        "topics": [
            "Zero Trust Strategy",
            "GRC Architecture",
            "Security Operations Design",
            "Identity Architecture",
            "Application Security",
            "Data Security"
        ]
    },
    {
        "id": "sc300",
        "name": "SC-300",
        "abbr": "SC-300",
        "provider": "Microsoft",
        "domain": "cloud",
        "level": "intermediate",
        "cost": 130,
        "currency": "GBP",
        "desc": "Identity and Access Administrator. Managing Azure AD/Entra ID \u2014 conditional access, MFA, identity governance, PIM, and external identities in hybrid environments.",
        "duration": "150 min",
        "questions": "40-60",
        "passing": "700/1000",
        "renewal": "Annual renewal",
        "prereqs": [],
        "topics": [
            "Entra ID",
            "Conditional Access",
            "MFA",
            "Identity Governance",
            "PIM",
            "External Identities",
            "Hybrid Identity"
        ]
    },
    {
        "id": "splunkadmin",
        "name": "Splunk Enterprise Admin",
        "abbr": "Splunk Admin",
        "provider": "Splunk",
        "domain": "secops",
        "level": "intermediate",
        "cost": 100,
        "currency": "GBP",
        "desc": "Validates Splunk administration skills \u2014 installation, configuration, user management, indexing, clustering, and performance monitoring in enterprise deployments.",
        "duration": "60 min",
        "questions": "65",
        "passing": "70%",
        "renewal": "3 years",
        "prereqs": [
            "splunkcore"
        ],
        "topics": [
            "Installation",
            "Configuration",
            "Index Management",
            "Clustering",
            "User Management",
            "Monitoring"
        ]
    },
    {
        "id": "splunkes",
        "name": "Splunk ES Admin",
        "abbr": "Splunk ES",
        "provider": "Splunk",
        "domain": "secops",
        "level": "advanced",
        "cost": 100,
        "currency": "GBP",
        "desc": "Splunk Enterprise Security Certified Admin. Configuring and managing Splunk ES for security operations \u2014 notable events, risk-based alerting, investigations, and threat intelligence.",
        "duration": "60 min",
        "questions": "64",
        "passing": "70%",
        "renewal": "3 years",
        "prereqs": [
            "splunkadmin"
        ],
        "topics": [
            "Notable Events",
            "Risk Framework",
            "Threat Intelligence",
            "Investigations",
            "Glass Tables",
            "Custom Dashboards"
        ]
    },
    {
        "id": "splunksoar",
        "name": "Splunk SOAR",
        "abbr": "SOAR",
        "provider": "Splunk",
        "domain": "secops",
        "level": "advanced",
        "cost": 100,
        "currency": "GBP",
        "desc": "Splunk SOAR Certified Automation Developer. Building playbooks and automations in Splunk SOAR for security orchestration, automated response, and case management.",
        "duration": "75 min",
        "questions": "66",
        "passing": "70%",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "Playbook Design",
            "Custom Actions",
            "REST API",
            "Case Management",
            "Automation Workflows",
            "Integrations"
        ]
    },
    {
        "id": "ccfr",
        "name": "CrowdStrike CCFR",
        "abbr": "CCFR",
        "provider": "CrowdStrike",
        "domain": "ir",
        "level": "intermediate",
        "cost": 160,
        "currency": "GBP",
        "desc": "CrowdStrike Certified Falcon Responder. Incident response and threat hunting using the Falcon platform \u2014 real-time response, host containment, and IOC sweeping.",
        "duration": "90 min",
        "questions": "60",
        "passing": "70%",
        "renewal": "2 years",
        "prereqs": [
            "csa"
        ],
        "topics": [
            "Real-Time Response",
            "Host Containment",
            "IOC Sweeping",
            "Event Search",
            "Spotlight Vulns",
            "Incident Workflow"
        ]
    },
    {
        "id": "ccht",
        "name": "CrowdStrike CCHT",
        "abbr": "CCHT",
        "provider": "CrowdStrike",
        "domain": "threat",
        "level": "intermediate",
        "cost": 160,
        "currency": "GBP",
        "desc": "CrowdStrike Certified Threat Hunter. Proactive threat hunting using Falcon \u2014 adversary tradecraft, behavioral IOAs, custom detections, and Falcon Overwatch methodology.",
        "duration": "90 min",
        "questions": "60",
        "passing": "70%",
        "renewal": "2 years",
        "prereqs": [
            "csa"
        ],
        "topics": [
            "Falcon Overwatch",
            "Behavioral IOAs",
            "Custom Detections",
            "Event Search",
            "CQL",
            "Adversary Tradecraft"
        ]
    },
    {
        "id": "netplus",
        "name": "Network+",
        "abbr": "Net+",
        "provider": "CompTIA",
        "domain": "arch",
        "level": "foundation",
        "cost": 285,
        "currency": "GBP",
        "desc": "Foundational networking certification covering network architecture, troubleshooting, security, and operations. Essential baseline for security engineers.",
        "duration": "90 min",
        "questions": "90 MCQ + PBQ",
        "passing": "720/900",
        "renewal": "3 years / 30 CEUs",
        "prereqs": [],
        "topics": [
            "Networking Concepts",
            "Infrastructure",
            "Network Operations",
            "Network Security",
            "Troubleshooting"
        ]
    },
    {
        "id": "linuxplus",
        "name": "Linux+",
        "abbr": "Linux+",
        "provider": "CompTIA",
        "domain": "devsec",
        "level": "foundation",
        "cost": 285,
        "currency": "GBP",
        "desc": "Validates Linux system administration skills \u2014 shell scripting, user management, networking, security hardening, and troubleshooting in enterprise environments.",
        "duration": "90 min",
        "questions": "90 MCQ + PBQ",
        "passing": "720/900",
        "renewal": "3 years / 30 CEUs",
        "prereqs": [],
        "topics": [
            "System Management",
            "Security",
            "Scripting",
            "Containers",
            "Troubleshooting",
            "Automation"
        ]
    },
    {
        "id": "cka",
        "name": "CKA",
        "abbr": "CKA",
        "provider": "CNCF",
        "domain": "devsec",
        "level": "intermediate",
        "cost": 315,
        "currency": "GBP",
        "desc": "Certified Kubernetes Administrator. Hands-on exam covering cluster architecture, workload scheduling, networking, storage, security, and troubleshooting in Kubernetes.",
        "duration": "2 hours",
        "questions": "15-20 practical",
        "passing": "66%",
        "renewal": "3 years",
        "prereqs": [],
        "topics": [
            "Cluster Architecture",
            "Workloads",
            "Services & Networking",
            "Storage",
            "Security",
            "Troubleshooting"
        ]
    },
    {
        "id": "cks",
        "name": "CKS",
        "abbr": "CKS",
        "provider": "CNCF",
        "domain": "devsec",
        "level": "advanced",
        "cost": 315,
        "currency": "GBP",
        "desc": "Certified Kubernetes Security Specialist. Securing Kubernetes clusters \u2014 supply chain security, runtime security, network policies, secrets management, and compliance.",
        "duration": "2 hours",
        "questions": "15-20 practical",
        "passing": "67%",
        "renewal": "3 years",
        "prereqs": [
            "cka"
        ],
        "topics": [
            "Cluster Setup",
            "System Hardening",
            "Supply Chain",
            "Runtime Security",
            "Network Policies",
            "Secrets Management"
        ]
    },
    {
        "id": "tf",
        "name": "Terraform Associate",
        "abbr": "TF Assoc",
        "provider": "HashiCorp",
        "domain": "devsec",
        "level": "foundation",
        "cost": 55,
        "currency": "GBP",
        "desc": "Validates understanding of Infrastructure as Code concepts using Terraform \u2014 HCL, state management, modules, and cloud provisioning workflows.",
        "duration": "60 min",
        "questions": "57",
        "passing": "70%",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "IaC Concepts",
            "HCL Syntax",
            "State Management",
            "Modules",
            "Providers",
            "Workspaces"
        ]
    },
    {
        "id": "vault",
        "name": "Vault Associate",
        "abbr": "Vault",
        "provider": "HashiCorp",
        "domain": "devsec",
        "level": "intermediate",
        "cost": 55,
        "currency": "GBP",
        "desc": "HashiCorp Vault secrets management \u2014 dynamic secrets, encryption as a service, identity-based access, and PKI certificate management.",
        "duration": "60 min",
        "questions": "57",
        "passing": "70%",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "Secrets Engines",
            "Auth Methods",
            "Policies",
            "Dynamic Secrets",
            "Encryption",
            "PKI",
            "Tokens"
        ]
    },
    {
        "id": "gcpse",
        "name": "Google Cloud Security Engineer",
        "abbr": "GCSE",
        "provider": "Google",
        "domain": "cloud",
        "level": "advanced",
        "cost": 160,
        "currency": "GBP",
        "desc": "Professional Cloud Security Engineer. Configuring access, network security, data protection, and compliance monitoring across Google Cloud Platform.",
        "duration": "120 min",
        "questions": "50-60",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [
            "gcsec"
        ],
        "topics": [
            "Identity & Access",
            "Network Security",
            "Data Protection",
            "Security Operations",
            "Compliance",
            "Org Policies"
        ]
    },
    {
        "id": "nse4",
        "name": "Fortinet NSE4",
        "abbr": "NSE4",
        "provider": "Fortinet",
        "domain": "arch",
        "level": "intermediate",
        "cost": 320,
        "currency": "GBP",
        "desc": "Fortinet Network Security Expert 4. FortiGate firewall administration \u2014 security policies, NAT, VPN, authentication, logging, and web filtering.",
        "duration": "105 min",
        "questions": "60",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [],
        "topics": [
            "Security Policies",
            "NAT",
            "IPsec VPN",
            "SSL VPN",
            "Authentication",
            "Web Filtering",
            "Logging"
        ]
    },
    {
        "id": "pcnse",
        "name": "Palo Alto PCNSE",
        "abbr": "PCNSE",
        "provider": "Palo Alto",
        "domain": "arch",
        "level": "advanced",
        "cost": 140,
        "currency": "GBP",
        "desc": "Palo Alto Certified Network Security Engineer. Expert-level PAN-OS skills \u2014 advanced firewall design, Panorama management, GlobalProtect, and WildFire configuration.",
        "duration": "80 min",
        "questions": "75",
        "passing": "Pass/Fail",
        "renewal": "2 years",
        "prereqs": [
            "pcnsa"
        ],
        "topics": [
            "Advanced Policies",
            "Panorama",
            "GlobalProtect",
            "WildFire",
            "HA Configuration",
            "Troubleshooting"
        ]
    },
    {
        "id": "gicsp",
        "name": "GIAC GICSP",
        "abbr": "GICSP",
        "provider": "SANS/GIAC",
        "domain": "arch",
        "level": "advanced",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Global Industrial Cyber Security Professional. Securing ICS/SCADA/OT environments \u2014 Purdue model, industrial protocols, safety systems, and OT incident response.",
        "duration": "Open book, 3h",
        "questions": "82",
        "passing": "71%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [],
        "topics": [
            "ICS Architecture",
            "SCADA Security",
            "Industrial Protocols",
            "Safety Systems",
            "OT Incident Response",
            "Purdue Model"
        ]
    },
    {
        "id": "grid",
        "name": "GIAC GRID",
        "abbr": "GRID",
        "provider": "SANS/GIAC",
        "domain": "ir",
        "level": "expert",
        "cost": 7266,
        "currency": "GBP",
        "desc": "Response and Industrial Defense. Advanced incident response in industrial and OT environments \u2014 forensics on PLCs, RTUs, and industrial network protocols.",
        "duration": "Open book, 3h",
        "questions": "75",
        "passing": "65%",
        "renewal": "4 years / 36 CPEs",
        "prereqs": [
            "gicsp"
        ],
        "topics": [
            "OT Forensics",
            "PLC Analysis",
            "Industrial Protocol Forensics",
            "Safety System IR",
            "OT Network Analysis",
            "ICS Threat Hunting"
        ]
    },
    {
        "id": "ccnpsec",
        "name": "CCNP Security",
        "abbr": "CCNP Sec",
        "provider": "Cisco",
        "domain": "arch",
        "level": "advanced",
        "cost": 320,
        "currency": "GBP",
        "desc": "Cisco Certified Network Professional Security. Advanced network security \u2014 firewalls, VPNs, IPS, identity services, and content security across Cisco platforms.",
        "duration": "120 min core + concentration",
        "questions": "90-110",
        "passing": "Pass/Fail",
        "renewal": "3 years / 120 CE",
        "prereqs": [
            "ccna"
        ],
        "topics": [
            "Firepower",
            "ISE",
            "VPN",
            "Secure Email",
            "Umbrella",
            "Endpoint Security",
            "Automation"
        ]
    }
]


#: Where a price was checked, and when. Keyed by cert id; absent means
#: nobody has confirmed that figure against a source.
#:
#: Deliberately separate from CERTIFICATIONS rather than extra fields on
#: each entry: the template holds the same list and the drift test
#: compares the two, so provenance the browser has no use for would make
#: them permanently unequal.
#:
#: `checked_on` is the date the source was read, not a publication date.
#: A price is only as good as that date.
#:
#: Hand-maintained. Nothing regenerates this, and a check recorded here
#: is a claim that somebody actually opened that page on that date.
#:
#: `vendor_price` and `vendor_currency` are what the vendor publishes.
#: `rate`, `rate_source` and `rate_date` are what turned that into the
#: `cost` the catalogue carries, so the conversion can be checked rather
#: than taken on trust: vendor_price * rate rounds to cost, and
#: test_cert_catalogue_data.py asserts it for every converted entry.
#:
#: Recording the rate is the whole point. The figures this replaced were
#: conversions too, at a rate nobody wrote down, which is why nobody
#: could tell they had gone stale.

#: Every SANS/GIAC entry in the catalogue carries the same flat £6,800,
#: which is a placeholder rather than a researched per-course figure.
#:
#: What the vendors actually publish, read 2026-11-05: SANS lists most
#: six-day courses at USD 8,780 (five-day ones nearer 8,260-8,375, ICS
#: courses nearer 9,230, and prices vary by event and region), and GIAC
#: lists the certification attempt separately at USD 999 whether bought
#: with training or standalone.
#:
#: So the catalogue figure looks like course tuition with the exam
#: attempt left out, and a plan built from it under-states each GIAC
#: certification by roughly the attempt fee. Flagged rather than fixed:
#: see the note above about inventing rates.
_SANS_GIAC_CHECK: Dict[str, Any] = {
    "source": "https://www.sans.org/cyber-security-courses/ and https://www.giac.org/pricing",
    "checked_on": "2026-11-05",
    #: Course plus attempt. Recorded as one adopted figure with its parts
    #: spelled out, because the two are bought separately and an estate
    #: whose alumni sit the exam alone pays only the second.
    "vendor_price": 8780 + 999,
    "vendor_currency": "USD",
    "components": {"sans_course": 8780, "giac_attempt": 999},
    "rate": 0.74299,
    "rate_source": "European Central Bank reference rate via api.frankfurter.dev",
    "rate_date": "2026-11-05",
    "note": (
        "USD 8,780 typical six-day SANS course tuition plus the USD 999 "
        "GIAC attempt, which is what it costs to hold the certification "
        "rather than to sit the course. Replaces a flat GBP 6,800 that "
        "every SANS entry carried and that appears to have been tuition "
        "only. Course prices vary by course, event and region, so this "
        "is the common figure rather than a quote for this specific "
        "certification -- and it is the vendor's own number, not a "
        "conversion."
    ),
}

_SANS_GIAC_IDS: Tuple[str, ...] = (
    "cdsa", "gsom", "gcih", "gcfe", "gnfa", "grem", "gfa", "gosi", "gcti",
    "gti_mgmt", "gxpn", "gweb", "dsoe", "gsec", "gcld", "gpen", "gdsa",
    "gicsp", "grid",
)

PRICE_PROVENANCE: Dict[str, Dict[str, Any]] = {
    cert_id: dict(_SANS_GIAC_CHECK) for cert_id in _SANS_GIAC_IDS
}

PRICE_PROVENANCE["oscp"] = {
    "source": "https://www.offsec.com/products/pen-200/",
    "checked_on": "2026-11-05",
    "vendor_price": 1749,
    "vendor_currency": "USD",
    "rate": 0.74299,
    "rate_source": "European Central Bank reference rate via api.frankfurter.dev",
    "rate_date": "2026-11-05",
    "note": (
        "Course and certification bundle, one exam attempt included. "
        "The standalone OSCP+ exam without the course is USD 1,699. "
        "The GBP 1,300 this replaces converts to within a pound of the "
        "same figure, so that one was right and had simply never been "
        "shown to be."
    ),
}


#: Entries whose own fields disagree with each other, found when this
#: data was lifted out of the template and could finally be read by
#: something other than a browser.
#:
#: Recorded rather than corrected. Each one needs somebody who knows
#: which field is the right one to keep, and guessing would replace a
#: visible inconsistency with an invisible wrong answer. A test asserts
#: these name real entries, so the list cannot rot once they are fixed.
KNOWN_ISSUES: Dict[str, str] = {
    "crtp": (
        "Four fields, four different certifications. The id is CRTP "
        "(Certified Red Team Professional, Altered Security), the name "
        "and abbr are CRTL (Certified Red Team Lead, Zero Point "
        "Security), the provider is SANS/GIAC, and the description is "
        "for a threat intelligence leadership course. CRTO is already "
        "in the catalogue separately and correctly under Zero Point "
        "Security, and GIAC's threat-intel management certification is "
        "already here as gti_mgmt. Its GBP 6,800 is the SANS flat rate, "
        "which is wrong for any of the three readings, so it is left out "
        "of the SANS price check above."
    ),
}


def all_certs() -> List[Dict[str, Any]]:
    """Every certification, in catalogue order."""
    return list(CERTIFICATIONS)


def get_cert(cert_id: str) -> Optional[Dict[str, Any]]:
    """One certification by id, or None."""
    for cert in CERTIFICATIONS:
        if cert["id"] == cert_id:
            return cert
    return None


def by_domain(domain_id: str) -> List[Dict[str, Any]]:
    """Every certification in one domain."""
    return [c for c in CERTIFICATIONS if c.get("domain") == domain_id]


def providers() -> Tuple[str, ...]:
    """Every issuing body named in the catalogue, sorted."""
    return tuple(sorted({c["provider"] for c in CERTIFICATIONS}))


def unverified_prices() -> List[str]:
    """Certifications whose price nobody has checked against a source.

    The honest default. A price with no provenance is a number somebody
    typed once, and a budget built on it should be able to say so.
    """
    return sorted(
        c["id"] for c in CERTIFICATIONS if c["id"] not in PRICE_PROVENANCE
    )


def currencies() -> Tuple[str, ...]:
    """Every currency the catalogue quotes in.

    More than one means nothing may sum these without converting, which
    needs a rate and a date this module does not have.
    """
    return tuple(sorted({c["currency"] for c in CERTIFICATIONS}))
