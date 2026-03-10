"""Built-in KB data: Security Fundamentals Articles."""

CORE_SECURITY = [
    {
        "title": "The CIA Triad — Confidentiality, Integrity, Availability",
        "tags": ["fundamentals", "cia-triad", "security-101"],
        "content": """# The CIA Triad

The CIA triad is the foundational model for information security. Every security control, policy, and incident can be framed in terms of these three pillars.

## Confidentiality
Ensuring information is accessible only to authorized individuals.

**Controls:** Encryption (AES-256, TLS), access control lists (ACLs), role-based access control (RBAC), data classification labels, need-to-know policies.

**Threats:** Eavesdropping, data breaches, insider threats, shoulder surfing, social engineering.

**SOC relevance:** Alerts for unauthorized access attempts, data exfiltration detection, DLP violations.

## Integrity
Ensuring information has not been altered in an unauthorized manner.

**Controls:** Hashing (SHA-256), digital signatures, version control, checksums, write-once storage, database constraints.

**Threats:** Man-in-the-middle attacks, SQL injection, file tampering, supply chain compromise.

**SOC relevance:** File integrity monitoring (FIM) alerts, unexpected configuration changes, code signing failures.

## Availability
Ensuring systems and data are accessible when needed.

**Controls:** Redundancy, load balancing, backups, disaster recovery plans, SLAs, auto-scaling, DDoS mitigation.

**Threats:** DDoS attacks, ransomware, hardware failure, natural disasters, misconfigurations.

**SOC relevance:** Service health monitoring, uptime alerts, capacity threshold breaches.

## The Triad in Practice
| Scenario | C | I | A |
|---|---|---|---|
| Ransomware encrypts files | - | - | Violated |
| Attacker modifies log files | - | Violated | - |
| Data exfiltrated to pastebin | Violated | - | - |
| DDoS takes down web app | - | - | Violated |
| SQL injection alters records | - | Violated | - |

## Extended Models
- **DAD Triad** (attacker's view): Disclosure, Alteration, Destruction
- **Parkerian Hexad**: Adds Possession, Authenticity, Utility
- **STRIDE**: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
""",
    },
    {
        "title": "Defense in Depth — Layered Security Strategy",
        "tags": ["fundamentals", "defense-in-depth", "security-101"],
        "content": """# Defense in Depth

Defense in depth is a strategy that employs multiple layers of security controls so that if one fails, others still protect the asset.

## The Layers (Outside → Inside)

### 1. Physical Security
Fences, guards, badges, CCTV, mantraps, locked server rooms, environmental controls (HVAC, fire suppression).

### 2. Perimeter Security
Firewalls (next-gen, WAF), IDS/IPS, DMZ architecture, email gateways, web proxies, DDoS scrubbing.

### 3. Network Security
Network segmentation (VLANs, microsegmentation), 802.1X NAC, VPN, network monitoring, DNS filtering.

### 4. Host Security
Endpoint Detection & Response (EDR), host firewalls, patch management, hardened OS images, application whitelisting.

### 5. Application Security
Secure coding practices, input validation, authentication/authorization, WAF rules, API security, SAST/DAST scanning.

### 6. Data Security
Encryption at rest and in transit, DLP, data classification, tokenization, database activity monitoring, backup encryption.

### 7. User Security
Security awareness training, phishing simulations, strong password policies, MFA, privileged access management.

## Why It Matters for SOC
- No single layer is perfect — assume breach
- Alerts from different layers provide correlation opportunities
- Attackers must bypass multiple controls, increasing detection chances
- SOC analysts see alerts from every layer — understanding the model helps prioritize and contextualize

## Common Anti-Patterns
- Over-relying on perimeter ("hard shell, soft center")
- Ignoring physical security in cloud-first environments
- No monitoring between internal network segments
""",
    },
    {
        "title": "Least Privilege Principle",
        "tags": ["fundamentals", "least-privilege", "access-control"],
        "content": """# Principle of Least Privilege (PoLP)

Every user, program, and process should have only the minimum privileges necessary to perform their function — no more, no less.

## Core Concepts

- **Need-to-know**: Access information only when required for the task
- **Just-in-time (JIT) access**: Elevated privileges granted temporarily, then revoked
- **Separation of duties**: No single person controls an entire critical process
- **Privilege creep**: Accumulation of unnecessary permissions over time (common when employees change roles)

## Implementation Approaches
1. **RBAC** — Role-based access control: permissions tied to job roles
2. **ABAC** — Attribute-based: policies based on user/resource/environment attributes
3. **Zero Trust** — Never trust, always verify; micro-segmentation + continuous auth
4. **PAM** — Privileged Access Management: vaulted credentials, session recording, JIT elevation

## SOC Detection Opportunities
- Users accessing resources outside their normal pattern
- Service accounts with interactive logins
- Privilege escalation attempts (e.g., `sudo`, `runas`, token manipulation)
- Dormant admin accounts being activated
- Unusual group membership changes in Active Directory

## Common Violations
| Violation | Risk |
|---|---|
| Shared admin accounts | No accountability, no audit trail |
| Developers with prod DB access | Accidental or malicious data changes |
| Service accounts with Domain Admin | Lateral movement jackpot for attackers |
| "Everyone" permissions on file shares | Data exposure |
""",
    },
    {
        "title": "Security Classification and Data Handling",
        "tags": ["fundamentals", "data-classification", "security-101"],
        "content": """# Security Classification & Data Handling

Data classification is the process of categorizing data based on sensitivity and the impact of unauthorized disclosure.

## Common Classification Levels

### Government/Military
| Level | Description |
|---|---|
| **Top Secret** | Exceptionally grave damage to national security |
| **Secret** | Serious damage to national security |
| **Confidential** | Damage to national security |
| **Unclassified** | No damage (but may still be controlled — CUI/FOUO) |

### Corporate/Private Sector
| Level | Description | Examples |
|---|---|---|
| **Restricted** | Highest sensitivity | Trade secrets, M&A plans, PII databases |
| **Confidential** | Internal sensitive | Financial reports, HR records, source code |
| **Internal** | Not for public | Internal memos, org charts, policies |
| **Public** | Freely shareable | Marketing materials, public website content |

## Data Handling Requirements
- **Labeling**: Documents, emails, and files must carry classification markings
- **Storage**: Encrypted at rest for Confidential+; access-controlled shares
- **Transmission**: Encrypted in transit (TLS 1.2+); no sensitive data over unencrypted email
- **Disposal**: Secure deletion (NIST 800-88), physical destruction for media
- **Retention**: Follow legal/regulatory retention schedules

## SOC Relevance
- DLP alerts tied to classification labels
- Misclassified data = unprotected sensitive data
- Incident severity partly determined by classification of affected data
- Regulatory reporting obligations depend on data type (PII, PHI, PCI)
""",
    },
    {
        "title": "Threat Landscape — Threat Actors and Motivations",
        "tags": ["fundamentals", "threat-actors", "threat-landscape"],
        "content": """# Threat Landscape: Actors & Motivations

Understanding who attacks, why, and how is foundational to threat assessment and alert prioritization.

## Threat Actor Categories

### Nation-State / APT
- **Motivation**: Espionage, sabotage, geopolitical advantage
- **Capabilities**: Highly funded, zero-days, custom tooling, long dwell times
- **Examples**: APT28 (Russia), APT41 (China), Lazarus Group (DPRK)
- **Targets**: Government, defense, critical infrastructure, think tanks

### Cybercriminals
- **Motivation**: Financial gain
- **Capabilities**: Ransomware-as-a-Service, exploit kits, phishing campaigns
- **Examples**: LockBit, ALPHV/BlackCat, Cl0p, FIN7
- **Targets**: Anyone with money or valuable data

### Hacktivists
- **Motivation**: Political/social causes, publicity
- **Capabilities**: DDoS, defacement, data leaks
- **Examples**: Anonymous, IT Army of Ukraine
- **Targets**: Organizations opposing their cause

### Insider Threats
- **Motivation**: Revenge, financial gain, ideology, negligence
- **Capabilities**: Legitimate access, knowledge of systems
- **Types**: Malicious insider, negligent insider, compromised insider

### Script Kiddies
- **Motivation**: Notoriety, curiosity, thrill
- **Capabilities**: Pre-built tools, limited understanding
- **Targets**: Low-hanging fruit, unpatched systems

## The Cyber Kill Chain (Lockheed Martin)
1. Reconnaissance → 2. Weaponization → 3. Delivery → 4. Exploitation → 5. Installation → 6. Command & Control → 7. Actions on Objectives

## Diamond Model of Intrusion Analysis
Four vertices: **Adversary** ↔ **Capability** ↔ **Infrastructure** ↔ **Victim**

Used to structure threat intelligence and correlate indicators across incidents.
""",
    },
    {
        "title": "Security Incident vs Event — Definitions and Workflow",
        "tags": ["fundamentals", "incident-management", "security-101"],
        "content": """# Security Event vs Incident

Understanding the difference is fundamental to SOC operations.

## Definitions

| Term | Definition |
|---|---|
| **Event** | Any observable occurrence in a system or network (login, file access, packet sent) |
| **Alert** | An event flagged by a detection rule as potentially suspicious |
| **Incident** | A confirmed violation of security policy or an imminent threat |

## The Triage Funnel
```
Events (millions/day) → Alerts (hundreds/day) → Incidents (few/week)
```

Most events are benign. The SOC's job is to efficiently filter noise and identify real incidents.

## Incident Severity Classification
| Severity | Description | Example | Response Time |
|---|---|---|---|
| **Critical (P1)** | Active breach, data exfiltration | Ransomware deployment | Immediate |
| **High (P2)** | Likely compromise, needs urgent investigation | C2 beaconing detected | < 1 hour |
| **Medium (P3)** | Suspicious activity, could be benign | Multiple failed logins | < 4 hours |
| **Low (P4)** | Informational, minor policy violation | Unauthorized USB device | < 24 hours |

## NIST Incident Response Lifecycle (SP 800-61)
1. **Preparation** — Policies, tools, training, playbooks
2. **Detection & Analysis** — Monitoring, triage, investigation
3. **Containment, Eradication, Recovery** — Stop the bleeding, remove the threat, restore
4. **Post-Incident Activity** — Lessons learned, report writing, process improvement

## Key Metrics
- **MTTD** — Mean Time to Detect
- **MTTR** — Mean Time to Respond
- **MTTC** — Mean Time to Contain
- **False Positive Rate** — % of alerts that are not real incidents
""",
    },
    {
        "title": "Common Attack Types — Phishing, Malware, DDoS, MitM",
        "tags": ["fundamentals", "attacks", "security-101"],
        "content": """# Common Attack Types

## Phishing
Social engineering via email/SMS/voice to trick users into revealing credentials or executing malware.

**Variants:**
- **Spear phishing** — Targeted at specific individuals
- **Whaling** — Targeting executives
- **Vishing** — Voice phishing (phone calls)
- **Smishing** — SMS phishing
- **BEC** — Business Email Compromise (impersonating executives for wire transfers)

**Detection:** Email gateway analysis, URL reputation, sender authentication (SPF/DKIM/DMARC), user reporting.

## Malware Categories
| Type | Behavior |
|---|---|
| **Virus** | Self-replicating, attaches to files |
| **Worm** | Self-propagating across networks |
| **Trojan** | Disguised as legitimate software |
| **Ransomware** | Encrypts data, demands payment |
| **Spyware** | Silently collects information |
| **Rootkit** | Hides deep in the OS, very hard to detect |
| **RAT** | Remote Access Trojan — gives attacker remote control |
| **Cryptominer** | Uses victim's CPU/GPU to mine cryptocurrency |

## Denial of Service (DoS/DDoS)
Overwhelming a target with traffic or requests to make it unavailable.

**Types:** Volumetric (UDP flood), Protocol (SYN flood), Application-layer (HTTP flood, Slowloris).

**Mitigation:** Rate limiting, CDN/scrubbing services, SYN cookies, geo-blocking.

## Man-in-the-Middle (MitM)
Attacker intercepts communication between two parties.

**Techniques:** ARP spoofing, DNS hijacking, SSL stripping, rogue Wi-Fi access points.

**Prevention:** TLS everywhere, certificate pinning, HSTS, network segmentation.

## Other Common Attacks
- **SQL Injection** — Injecting SQL via user input to manipulate databases
- **XSS (Cross-Site Scripting)** — Injecting scripts into web pages viewed by other users
- **Credential Stuffing** — Using breached credential lists to attempt logins
- **Pass-the-Hash** — Using stolen NTLM hashes to authenticate without knowing the password
- **Privilege Escalation** — Gaining higher-level permissions than authorized
""",
    },
    {
        "title": "Vulnerability Management Lifecycle",
        "tags": ["fundamentals", "vulnerability-management", "security-101"],
        "content": """# Vulnerability Management Lifecycle

A systematic process for identifying, evaluating, remediating, and reporting on security vulnerabilities.

## The Lifecycle

### 1. Discovery / Asset Inventory
You can't secure what you don't know about. Maintain a complete inventory of:
- Hardware (servers, endpoints, IoT, network devices)
- Software (OS, applications, libraries, containers)
- Cloud resources (VMs, serverless, storage buckets, APIs)

### 2. Vulnerability Scanning
- **Authenticated scans** — Agents or credentials for deeper inspection
- **Unauthenticated scans** — External perspective, like an attacker would see
- **Tools**: Nessus, Qualys, Rapid7 InsightVM, OpenVAS

### 3. Assessment & Prioritization
Not all vulnerabilities are equal. Use:
- **CVSS Score** (0-10): Base severity metric
- **EPSS** (Exploit Prediction Scoring): Probability of exploitation in the wild
- **Asset criticality**: Is this a domain controller or a test VM?
- **Exploitability**: Is there a public exploit? Is it being actively exploited (KEV catalog)?

### 4. Remediation
| Strategy | When to Use |
|---|---|
| **Patch** | Vendor fix available — preferred approach |
| **Mitigate** | No patch yet — apply compensating controls (WAF rule, network isolation) |
| **Accept** | Risk is within tolerance — document the decision |
| **Transfer** | Shift risk via insurance or outsourcing |

### 5. Verification
Re-scan to confirm the fix worked. Close the ticket only after verification.

### 6. Reporting
Track metrics: time-to-patch, vulnerability density, risk trends, SLA compliance.

## SOC Relevance
- Exploit attempts against known vulnerabilities generate alerts
- Unpatched CVEs inform alert prioritization (higher severity if target is vulnerable)
- Threat intel feeds reference CVEs — correlate with your asset inventory
""",
    },
    {
        "title": "Encryption Fundamentals — Symmetric, Asymmetric, Hashing",
        "tags": ["fundamentals", "encryption", "cryptography"],
        "content": """# Encryption Fundamentals

## Symmetric Encryption
Same key encrypts and decrypts. Fast, efficient for bulk data.

| Algorithm | Key Size | Status |
|---|---|---|
| **AES-256** | 256-bit | Gold standard, used everywhere |
| **AES-128** | 128-bit | Still secure, slightly faster |
| **ChaCha20** | 256-bit | Alternative to AES, great on mobile |
| **3DES** | 168-bit | Deprecated, avoid |
| **DES** | 56-bit | Broken, never use |

**Modes**: ECB (insecure), CBC (ok with IV), GCM (preferred — authenticated encryption), CTR.

## Asymmetric Encryption
Key pair: public key encrypts, private key decrypts. Slower, used for key exchange and signatures.

| Algorithm | Use Case | Status |
|---|---|---|
| **RSA** | Encryption, signatures | 2048+ bit keys required |
| **ECDSA/ECDH** | Signatures, key exchange | Smaller keys, same security |
| **Ed25519** | Signatures | Modern, fast, secure |

## Hashing
One-way function: input → fixed-size digest. Not encryption (cannot be reversed).

| Algorithm | Output | Status |
|---|---|---|
| **SHA-256** | 256-bit | Standard for integrity verification |
| **SHA-3** | Variable | Latest NIST standard |
| **MD5** | 128-bit | Broken — collision attacks trivial |
| **SHA-1** | 160-bit | Deprecated — collision attacks demonstrated |
| **bcrypt/scrypt/Argon2** | Variable | Password hashing (intentionally slow) |

## Where You See These in SOC Work
- **TLS certificates**: RSA/ECDSA signatures, AES for session encryption
- **File hashes**: SHA-256 for malware IOCs, integrity monitoring
- **Password storage**: bcrypt/Argon2 in databases (never plaintext!)
- **VPN tunnels**: IKE (asymmetric) for key exchange, AES (symmetric) for data
- **Digital signatures**: Code signing, email signing (S/MIME, PGP)
""",
    },
    {
        "title": "Zero Trust Architecture",
        "tags": ["fundamentals", "zero-trust", "architecture"],
        "content": """# Zero Trust Architecture

"Never trust, always verify." Zero Trust eliminates implicit trust based on network location.

## Core Principles (NIST SP 800-207)

1. **All data sources and computing services are resources**
2. **All communication is secured regardless of network location**
3. **Access to resources is granted per-session**
4. **Access is determined by dynamic policy** (identity, device health, behavior, context)
5. **All assets are monitored and measured**
6. **Authentication and authorization are strictly enforced before access**
7. **Collect information to improve security posture**

## Key Components

### Identity-Centric Access
- Strong MFA for all users (phishing-resistant: FIDO2/WebAuthn preferred)
- Continuous authentication (not just at login)
- Device trust verification (MDM compliance, health attestation)

### Microsegmentation
- Fine-grained network policies (workload-to-workload)
- No flat networks — even internal traffic is filtered
- Software-defined perimeter (SDP)

### Least Privilege Access
- Just-in-time (JIT) and just-enough-access (JEA)
- Conditional access policies (location, device, risk score)
- No standing privileges for admin accounts

### Continuous Monitoring
- Log everything: network flows, authentication events, resource access
- Behavioral analytics (UEBA) to detect anomalies
- Automated response to policy violations

## SOC Implications
- Significantly more telemetry to analyze (every access decision is logged)
- Better visibility into lateral movement attempts
- Alerts are more contextual (identity + device + behavior + resource)
- False positive reduction through richer context
""",
    },
    {
        "title": "Security Frameworks Overview — NIST, ISO 27001, CIS",
        "tags": ["fundamentals", "frameworks", "compliance"],
        "content": """# Security Frameworks Overview

Frameworks provide structured approaches to building and measuring security programs.

## NIST Cybersecurity Framework (CSF) 2.0
Five core functions:

| Function | Purpose | Examples |
|---|---|---|
| **Govern** | Establish strategy and oversight | Policies, risk management, roles |
| **Identify** | Know your assets and risks | Asset inventory, risk assessment |
| **Protect** | Implement safeguards | Access control, encryption, training |
| **Detect** | Find threats and anomalies | SIEM, IDS, monitoring, SOC |
| **Respond** | Take action on incidents | IR plans, communication, containment |
| **Recover** | Restore capabilities | Backup restoration, DR, lessons learned |

## ISO 27001
International standard for Information Security Management Systems (ISMS).
- **Annex A**: 93 controls across 4 themes (Organizational, People, Physical, Technological)
- Requires formal risk assessment and treatment plan
- Certification through external audit

## CIS Controls (v8)
18 prioritized security controls, ordered by effectiveness:
1. Inventory of Enterprise Assets
2. Inventory of Software Assets
3. Data Protection
4. Secure Configuration
5. Account Management
6. Access Control Management
7. Continuous Vulnerability Management
8. Audit Log Management
... through 18. Penetration Testing

## MITRE ATT&CK
Not a compliance framework — it's a **knowledge base of adversary tactics and techniques** based on real-world observations.
- **14 Tactics** (the "why"): Reconnaissance through Impact
- **200+ Techniques** (the "how"): Specific methods attackers use
- Used for: Detection engineering, threat intel, red team planning, gap analysis

## SOC Relevance
- Detection rules often map to CIS Controls and MITRE ATT&CK
- Compliance audits drive logging requirements (what the SOC must monitor)
- NIST CSF "Detect" function = the SOC's primary mission
""",
    },
    {
        "title": "Log Management Fundamentals — What to Log, How to Store",
        "tags": ["fundamentals", "logging", "siem"],
        "content": """# Log Management Fundamentals

Logs are the foundation of security monitoring. Without good logs, the SOC is blind.

## What to Log (Minimum)

### Authentication Events
- Successful and failed logins (who, when, from where)
- Account lockouts, password changes, MFA challenges
- Privileged account usage (sudo, runas, admin logins)

### Network Activity
- Firewall allow/deny logs
- DNS queries and responses
- Proxy/web gateway logs (URLs visited)
- VPN connections
- NetFlow/IPFIX data

### Endpoint Activity
- Process creation (with command line arguments!)
- File creation/modification/deletion in sensitive paths
- Registry changes (Windows)
- USB device connections
- Scheduled task/cron job creation

### Application Logs
- Web server access logs (HTTP method, URL, status code, user agent)
- Database query logs (especially privileged operations)
- Email gateway logs (sender, recipient, subject, attachments, verdict)

## Log Formats
| Format | Description |
|---|---|
| **Syslog** (RFC 5424) | Standard Unix logging protocol |
| **Windows Event Log** (EVTX) | Windows native format |
| **CEF** (Common Event Format) | ArcSight standard |
| **LEEF** (Log Event Extended Format) | QRadar standard |
| **JSON / ECS** | Elastic Common Schema — modern, structured |

## Retention Guidelines
| Data Type | Minimum Retention | Regulation |
|---|---|---|
| Security events | 1 year | SOC best practice |
| Authentication logs | 1-3 years | PCI DSS, HIPAA |
| Network flows | 90 days | SOC operational |
| Full packet capture | 3-7 days | Storage-limited |

## Key Principles
- **Centralize**: Ship all logs to SIEM — distributed logs are useless for correlation
- **Normalize**: Use consistent field names (ECS, CIM) for cross-source queries
- **Timestamp**: NTP sync all sources; use UTC
- **Protect**: Logs are forensic evidence — immutable storage, access controls
- **Alert**: Raw logs are useless without detection rules analyzing them
""",
    },
    {
        "title": "Indicators of Compromise (IOCs) — Types and Usage",
        "tags": ["fundamentals", "iocs", "threat-intel"],
        "content": """# Indicators of Compromise (IOCs)

IOCs are forensic artifacts that indicate a security breach has occurred or is in progress.

## IOC Types

### Network-Based
| Type | Example | Use |
|---|---|---|
| **IP Address** | 185.220.101.42 | Blocklist, correlation |
| **Domain** | evil-login.example.com | DNS filtering, hunting |
| **URL** | https://malware.site/payload.exe | Web proxy blocking |
| **JA3/JA3S Hash** | a0e9f5d64349fb13... | TLS fingerprinting |
| **User Agent** | Mozilla/5.0 (compatible; MSIE 6.0) | Anomaly detection |

### Host-Based
| Type | Example | Use |
|---|---|---|
| **File Hash (SHA-256)** | a1b2c3d4e5... | Malware identification |
| **File Path** | C:\\Users\\Public\\svchost.exe | Suspicious locations |
| **Registry Key** | HKCU\\...\\Run\\malware | Persistence detection |
| **Mutex** | Global\\DCRatMutex | Malware family identification |
| **Process Name** | mimikatz.exe | Known tool detection |

### Email-Based
| Type | Example | Use |
|---|---|---|
| **Sender Address** | admin@g00gle.com | Phishing detection |
| **Subject Line** | "Urgent: Verify your account" | Pattern matching |
| **Attachment Hash** | SHA-256 of malicious PDF | Email gateway rules |

## Pyramid of Pain (David Bianco)
How much pain each IOC type causes the attacker when you detect and block it:

```
        Tough (most pain)
       /  TTPs
      /  Tools
     /  Network/Host Artifacts
    /  Domain Names
   /  IP Addresses
  /  Hash Values
 /   Easy (least pain)
```

Blocking hash values is trivial for attackers to evade (recompile). Detecting TTPs forces them to change their entire approach.

## IOC Lifecycle
1. **Collection** — Threat intel feeds, incident investigation, OSINT
2. **Validation** — Confirm relevance, check for false positives
3. **Enrichment** — Add context (threat actor, campaign, confidence level)
4. **Distribution** — Push to SIEM rules, firewall blocklists, EDR
5. **Expiration** — IOCs go stale; review and retire old indicators

## SOC Usage
- Correlate IOCs against live telemetry (SIEM watchlists, EDR scans)
- Retroactive hunting: search historical logs for newly discovered IOCs
- Share IOCs via STIX/TAXII with trusted partners
""",
    },
    {
        "title": "Network Segmentation and Zones",
        "tags": ["fundamentals", "network-segmentation", "architecture"],
        "content": """# Network Segmentation & Security Zones

Dividing a network into isolated segments limits the blast radius of a breach and controls traffic flow.

## Common Security Zones

### Internet (Untrusted)
Public internet — fully untrusted. All inbound traffic is filtered.

### DMZ (Demilitarized Zone)
Semi-trusted zone between internet and internal network.
- Hosts public-facing services: web servers, email gateways, reverse proxies
- Can communicate with internet (outbound) and limited internal services
- Cannot freely access the internal network

### Internal Network (Trusted)
Corporate LAN — user workstations, internal applications.
- Should still be segmented (see below)
- Not blindly trusted in Zero Trust architecture

### Management Network
Isolated network for infrastructure management:
- Switch/router management interfaces (out-of-band management)
- IPMI/iLO/iDRAC (BMC interfaces)
- Jump boxes / bastion hosts for admin access

### Server / Data Center Zone
Databases, application servers, file servers.
- Strict access controls (only necessary ports from specific sources)
- Monitoring for lateral movement

## Segmentation Technologies
| Technology | Use Case |
|---|---|
| **VLANs** | Layer 2 segmentation within a site |
| **Firewall rules** | Layer 3/4 segmentation between zones |
| **Microsegmentation** | Host-level policies (VMware NSX, Illumio) |
| **ACLs on routers** | Basic traffic filtering |
| **SDN** | Software-defined networking for dynamic policies |

## SOC Relevance
- Cross-zone traffic that violates policy = high-priority alert
- Lateral movement detection relies on understanding normal zone-to-zone flows
- Segmentation failures (e.g., VLAN hopping) are critical findings
- Network maps and zone diagrams should be part of SOC documentation
""",
    },
    {
        "title": "Authentication Factors and Multi-Factor Authentication",
        "tags": ["fundamentals", "authentication", "mfa"],
        "content": """# Authentication Factors & MFA

Authentication verifies "you are who you claim to be."

## The Three Factors

| Factor | Category | Examples |
|---|---|---|
| **Something you know** | Knowledge | Password, PIN, security question |
| **Something you have** | Possession | Hardware token, phone, smart card |
| **Something you are** | Inherence | Fingerprint, face scan, iris scan |

**Multi-Factor Authentication (MFA)** = combining two or more different factors.
- Password + SMS code = MFA (knowledge + possession)
- Password + security question = NOT MFA (both are knowledge)

## MFA Methods Ranked by Security

| Method | Security | Phishing Resistant? |
|---|---|---|
| **FIDO2 / WebAuthn** (hardware key) | Excellent | Yes |
| **FIDO2 / Passkeys** (device-bound) | Excellent | Yes |
| **TOTP app** (Google Auth, Authy) | Good | No (but better than SMS) |
| **Push notification** (with number matching) | Good | Mostly |
| **Push notification** (simple approve) | Fair | No (MFA fatigue attacks) |
| **SMS code** | Fair | No (SIM swap, SS7 attacks) |
| **Email code** | Poor | No (if email is compromised) |
| **Security questions** | Poor | Not a real second factor |

## Attacks Against Authentication
- **Brute force**: Try all possible passwords
- **Credential stuffing**: Use breached password lists
- **Password spraying**: Try common passwords across many accounts
- **Phishing**: Trick user into entering credentials on fake site
- **MFA fatigue / push bombing**: Send repeated MFA prompts until user approves
- **SIM swapping**: Social engineer carrier to transfer phone number
- **Adversary-in-the-middle (AiTM)**: Proxy that captures session tokens post-MFA

## SOC Detection
- Multiple failed logins from one IP → brute force
- Multiple failed logins across accounts from one IP → password spray
- Successful login from impossible travel locations
- MFA challenge followed by immediate approval (no user interaction) → potential MFA bypass
- Login from a new device/location → contextual alert
""",
    },
    {
        "title": "The OSI Model — 7 Layers Explained for Security",
        "tags": ["fundamentals", "osi-model", "networking"],
        "content": """# The OSI Model — 7 Layers

The Open Systems Interconnection model is a conceptual framework for understanding network communication.

## Layer Summary

| Layer | Name | Function | Protocols | Security Concerns |
|---|---|---|---|---|
| 7 | **Application** | End-user services | HTTP, DNS, SMTP, SSH | XSS, SQLi, RCE, API abuse |
| 6 | **Presentation** | Data formatting, encryption | TLS/SSL, JPEG, ASCII | Weak ciphers, cert issues |
| 5 | **Session** | Session management | NetBIOS, RPC, SOCKS | Session hijacking |
| 4 | **Transport** | Reliable delivery | TCP, UDP | SYN floods, port scanning |
| 3 | **Network** | Routing & addressing | IP, ICMP, IPsec | IP spoofing, routing attacks |
| 2 | **Data Link** | Local network frames | Ethernet, Wi-Fi, ARP | ARP spoofing, MAC flooding |
| 1 | **Physical** | Bits on the wire | Cables, wireless signals | Wiretapping, jamming |

## How SOC Analysts Use the OSI Model

### Layer 3-4 Analysis (Network/Transport)
- Firewall logs operate at layers 3-4 (IPs, ports, protocols)
- NetFlow data shows layer 3-4 connections
- IDS/IPS inspects layers 3-7

### Layer 7 Analysis (Application)
- Web proxy logs show HTTP requests (URLs, methods, user agents)
- DNS logs show domain resolutions
- Email gateway logs show SMTP transactions

### Cross-Layer Correlation
Example: Detecting C2 communication
1. **Layer 7**: DNS query for suspicious domain
2. **Layer 3**: Connection to known-bad IP
3. **Layer 4**: Unusual port (e.g., TCP 8443)
4. **Layer 7**: Encrypted traffic with unusual JA3 fingerprint

## OSI vs TCP/IP Model
| OSI | TCP/IP |
|---|---|
| Application (7) | Application |
| Presentation (6) | Application |
| Session (5) | Application |
| Transport (4) | Transport |
| Network (3) | Internet |
| Data Link (2) | Network Access |
| Physical (1) | Network Access |

The TCP/IP model is what's actually implemented. The OSI model is used for conceptual understanding and discussion.
""",
    },
]


NETWORK_PROTOCOLS = [
    {
        "title": "TCP/IP Fundamentals — The Protocol Stack",
        "tags": ["fundamentals", "tcp-ip", "networking"],
        "content": """# TCP/IP Fundamentals

The TCP/IP stack is the actual protocol suite that powers the internet.

## The 4 Layers

### Application Layer
Protocols that applications use to communicate:
- **HTTP/HTTPS** (80/443) — Web traffic
- **DNS** (53) — Name resolution
- **SMTP** (25/587) — Email sending
- **SSH** (22) — Secure remote access
- **FTP** (20-21) — File transfer (avoid — use SFTP)
- **DHCP** (67-68) — Dynamic IP assignment
- **SNMP** (161-162) — Network management

### Transport Layer
Manages end-to-end communication:

**TCP (Transmission Control Protocol)**
- Connection-oriented (3-way handshake: SYN → SYN-ACK → ACK)
- Reliable, ordered delivery
- Flow control and congestion management
- Used for: HTTP, SSH, SMTP, databases

**UDP (User Datagram Protocol)**
- Connectionless — fire and forget
- No guaranteed delivery or ordering
- Lower overhead, faster
- Used for: DNS queries, VoIP, video streaming, gaming, NTP

### Internet Layer
Addressing and routing:
- **IPv4**: 32-bit addresses (e.g., 192.168.1.100)
- **IPv6**: 128-bit addresses (e.g., 2001:db8::1)
- **ICMP**: Error messages and diagnostics (ping, traceroute)
- **IPsec**: Encryption and authentication at the network layer

### Network Access Layer
Physical and data link combined:
- Ethernet (wired LAN)
- Wi-Fi (802.11)
- ARP (address resolution — IP to MAC)

## Important Port Numbers for SOC Analysts
| Port | Protocol | Notes |
|---|---|---|
| 20-21 | FTP | Cleartext — detect in sensitive zones |
| 22 | SSH | Watch for brute force |
| 23 | Telnet | Cleartext — should never be used |
| 25 | SMTP | Email relay — spam/phishing source |
| 53 | DNS | Tunneling risk, exfiltration channel |
| 80/443 | HTTP/S | Most traffic; C2 often hides here |
| 88 | Kerberos | AD authentication — Kerberoasting |
| 135/445 | RPC/SMB | Lateral movement (PsExec, WMI) |
| 389/636 | LDAP/S | AD queries — enumeration |
| 1433 | MSSQL | Database access |
| 3306 | MySQL | Database access |
| 3389 | RDP | Remote desktop — brute force target |
| 5985-5986 | WinRM | PowerShell remoting |
| 8080/8443 | Alt HTTP/S | Common for web apps, proxies, C2 |
""",
    },
    {
        "title": "DNS — How It Works and Security Implications",
        "tags": ["fundamentals", "dns", "networking"],
        "content": """# DNS Fundamentals & Security

DNS translates human-readable domain names to IP addresses. It's critical infrastructure — and a common attack vector.

## How DNS Resolution Works
1. User types `www.example.com` in browser
2. **Stub resolver** (OS) checks local cache
3. If not cached → queries **recursive resolver** (ISP or 8.8.8.8)
4. Recursive resolver queries root servers → TLD servers (.com) → authoritative server for example.com
5. Authoritative server returns the IP address
6. Result cached at each level (TTL-based)

## DNS Record Types
| Type | Purpose | Example |
|---|---|---|
| **A** | IPv4 address | example.com → 93.184.216.34 |
| **AAAA** | IPv6 address | example.com → 2606:2800:220:1:... |
| **CNAME** | Alias | www.example.com → example.com |
| **MX** | Mail server | example.com → mail.example.com |
| **TXT** | Text data | SPF records, DKIM, DMARC, domain verification |
| **NS** | Name servers | example.com → ns1.example.com |
| **SOA** | Start of Authority | Zone metadata |
| **PTR** | Reverse lookup | IP → domain name |
| **SRV** | Service location | _ldap._tcp.domain.com |

## DNS Security Threats

### DNS Tunneling
Encoding data in DNS queries to bypass firewalls. Signs:
- Unusually long subdomain labels (encoded data)
- High volume of queries to a single domain
- TXT record queries to unusual domains

### DNS Hijacking
Redirecting DNS responses to attacker-controlled servers:
- Router DNS setting modification
- Rogue DHCP server
- Compromised DNS server

### DNS Cache Poisoning
Injecting false records into DNS cache to redirect traffic.

### Typosquatting / Lookalike Domains
Registering domains similar to legitimate ones: `g00gle.com`, `microsoft-login.com`.

## DNS Security Controls
- **DNSSEC**: Cryptographic signatures on DNS responses (integrity)
- **DoH/DoT**: DNS over HTTPS/TLS (confidentiality)
- **RPZ (Response Policy Zones)**: DNS-level blocking of malicious domains
- **Sinkholing**: Redirecting malicious domains to controlled servers
- **Monitoring**: Log all DNS queries for threat hunting
""",
    },
    {
        "title": "IP Addressing — Subnets, CIDR, Private Ranges",
        "tags": ["fundamentals", "ip-addressing", "networking"],
        "content": """# IP Addressing Fundamentals

## IPv4 Addressing
32-bit address divided into 4 octets: `192.168.1.100`

### Private Address Ranges (RFC 1918)
| Range | CIDR | Class | # Addresses |
|---|---|---|---|
| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | A | 16.7 million |
| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | B | 1 million |
| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | C | 65,536 |

### Special Addresses
| Address | Purpose |
|---|---|
| 127.0.0.0/8 | Loopback (localhost) |
| 169.254.0.0/16 | Link-local (APIPA — no DHCP) |
| 0.0.0.0 | Default route / unspecified |
| 255.255.255.255 | Broadcast |

## CIDR Notation
`/24` = 256 IPs (254 usable), subnet mask 255.255.255.0
`/16` = 65,536 IPs, subnet mask 255.255.0.0
`/32` = single host
`/0` = all IPs (default route)

### Quick CIDR Reference
| CIDR | Hosts | Mask |
|---|---|---|
| /32 | 1 | 255.255.255.255 |
| /30 | 4 (2 usable) | 255.255.255.252 |
| /28 | 16 (14 usable) | 255.255.255.240 |
| /24 | 256 (254 usable) | 255.255.255.0 |
| /22 | 1,024 | 255.255.252.0 |
| /16 | 65,536 | 255.255.0.0 |
| /8 | 16.7 million | 255.0.0.0 |

## SOC Relevance
- Internal vs external IP identification (RFC 1918 vs public)
- GeoIP lookups on public IPs for threat context
- CIDR ranges in firewall rules and SIEM queries
- NAT can hide internal source IPs — check for NAT translation logs
- Bogon detection: traffic from unallocated/reserved ranges = suspicious
""",
    },
    {
        "title": "HTTP/HTTPS — Web Traffic Fundamentals",
        "tags": ["fundamentals", "http", "web-security"],
        "content": """# HTTP/HTTPS Fundamentals

## HTTP Methods
| Method | Purpose | Safe? |
|---|---|---|
| **GET** | Retrieve resource | Yes (read-only) |
| **POST** | Submit data / create resource | No |
| **PUT** | Replace resource | No |
| **PATCH** | Partial update | No |
| **DELETE** | Remove resource | No |
| **HEAD** | Like GET but headers only | Yes |
| **OPTIONS** | Discover allowed methods (CORS preflight) | Yes |

## HTTP Status Codes
| Range | Meaning | Key Codes |
|---|---|---|
| 1xx | Informational | 100 Continue |
| 2xx | Success | 200 OK, 201 Created, 204 No Content |
| 3xx | Redirection | 301 Moved, 302 Found, 304 Not Modified |
| 4xx | Client error | 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found |
| 5xx | Server error | 500 Internal Error, 502 Bad Gateway, 503 Service Unavailable |

## HTTPS (TLS)
HTTPS = HTTP over TLS. The TLS handshake:
1. Client Hello (supported cipher suites, TLS version)
2. Server Hello (chosen cipher, server certificate)
3. Certificate verification (chain of trust → root CA)
4. Key exchange (ECDHE preferred for forward secrecy)
5. Encrypted session established

## Security Headers
| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Force HTTPS (HSTS) |
| `Content-Security-Policy` | XSS prevention |
| `X-Frame-Options` | Clickjacking prevention |
| `X-Content-Type-Options` | MIME type sniffing prevention |
| `Referrer-Policy` | Control referrer information |

## SOC Relevance
- Web proxy logs: method, URL, status code, user agent, bytes transferred
- Unusual user agents = potential C2 or automated tools
- POST to login pages from unusual IPs = credential stuffing
- 4xx/5xx spikes = scanning or attack activity
- TLS certificate anomalies = potential MitM or phishing
- JA3 fingerprinting identifies TLS client implementations
""",
    },
    {
        "title": "Email Protocols — SMTP, SPF, DKIM, DMARC",
        "tags": ["fundamentals", "email-security", "protocols"],
        "content": """# Email Security Fundamentals

## Email Flow
1. Sender's email client → Sender's mail server (SMTP, port 587)
2. Sender's mail server → Recipient's mail server (SMTP, port 25)
3. Recipient's mail server → Recipient's email client (IMAP 993 or POP3 995)

## Email Authentication (Anti-Spoofing)

### SPF (Sender Policy Framework)
DNS TXT record listing authorized mail servers for a domain.
```
v=spf1 include:_spf.google.com -all
```
- `+all` = pass all (useless)
- `~all` = soft fail (tag but deliver)
- `-all` = hard fail (reject unauthorized senders)

### DKIM (DomainKeys Identified Mail)
Cryptographic signature in email headers proving the email hasn't been tampered with and was sent by an authorized server.
- Signing server adds `DKIM-Signature` header
- Receiving server verifies using public key published in DNS

### DMARC (Domain-based Message Authentication, Reporting & Conformance)
Policy that tells receiving servers what to do when SPF/DKIM fail:
```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```
- `p=none` — monitor only (report but deliver)
- `p=quarantine` — send to spam
- `p=reject` — block delivery

## Common Email Attacks
| Attack | Description | Detection |
|---|---|---|
| **Phishing** | Fake emails with malicious links/attachments | Email gateway, URL analysis |
| **BEC** | Impersonation of executives for wire fraud | Display name vs actual sender mismatch |
| **Spoofing** | Forging sender address | SPF/DKIM/DMARC failures |
| **Malicious attachments** | Macro-enabled docs, executables | Sandboxing, file type analysis |
| **Account takeover** | Compromised email account used for internal phishing | Impossible travel, unusual send patterns |

## SOC Relevance
- Check SPF/DKIM/DMARC results in email headers for suspicious emails
- Monitor for emails with executable attachments or macro-enabled documents
- Track email forwarding rules (attackers add auto-forward to exfil data)
- Alert on bulk email sends from a single user (compromised account)
""",
    },
    {
        "title": "Active Directory Fundamentals for SOC Analysts",
        "tags": ["fundamentals", "active-directory", "windows"],
        "content": """# Active Directory Fundamentals

Active Directory (AD) is Microsoft's directory service — the backbone of most enterprise networks. Understanding AD is critical for SOC analysts.

## Core Concepts

### Domain
A logical grouping of objects (users, computers, groups) sharing a common directory database and security policies. Example: `corp.example.com`

### Domain Controller (DC)
Server that hosts AD DS (Active Directory Domain Services). Handles authentication, authorization, and replication. **High-value target for attackers.**

### Organizational Unit (OU)
Container within a domain for organizing objects and applying Group Policy Objects (GPOs).

### Forest & Trust
- **Forest**: Top-level container of one or more domains sharing a common schema
- **Trust**: Relationship allowing users in one domain to access resources in another

## Key AD Objects
| Object | Description |
|---|---|
| **User** | Account with credentials (samAccountName, UPN) |
| **Computer** | Machine account (joined to domain) |
| **Group** | Collection of users/computers for permission management |
| **GPO** | Policy applied to OUs (password policy, software deployment) |
| **Service Account** | Account used by applications/services |

## AD Authentication Protocols

### Kerberos (default)
Ticket-based authentication:
1. User authenticates → gets **TGT** (Ticket Granting Ticket) from KDC
2. TGT used to request **Service Tickets** for specific resources
3. Service ticket presented to resource server

### NTLM (legacy)
Challenge-response protocol. Weaker than Kerberos. Still used for:
- Workgroup environments
- IP-based access (not hostname)
- Legacy application compatibility

## Critical AD Attacks SOC Must Detect
| Attack | What Happens | Detection |
|---|---|---|
| **Kerberoasting** | Request service tickets, crack offline | Event 4769 with RC4 encryption |
| **AS-REP Roasting** | Request TGTs for accounts without pre-auth | Event 4768 with RC4 |
| **DCSync** | Mimic DC to replicate password data | Event 4662 with replication GUIDs |
| **Golden Ticket** | Forged TGT using krbtgt hash | Tickets with impossible lifetimes |
| **Pass-the-Hash** | Authenticate with NTLM hash directly | Event 4624 Type 3 with NTLM |
| **Password Spraying** | Try common passwords across accounts | Multiple 4625 events, same password |

## Key Event IDs
- **4624**: Successful logon
- **4625**: Failed logon
- **4648**: Explicit credential logon (runas)
- **4672**: Special privileges assigned (admin logon)
- **4720/4726**: User created/deleted
- **4728/4732/4756**: User added to security group
""",
    },
    {
        "title": "Firewall Types and Rule Design",
        "tags": ["fundamentals", "firewalls", "network-security"],
        "content": """# Firewall Fundamentals

## Firewall Types

### Packet Filtering (Stateless)
- Examines individual packets (source/dest IP, port, protocol)
- No connection tracking — each packet evaluated independently
- Fast but limited (can't detect multi-packet attacks)

### Stateful Inspection
- Tracks connection state (TCP handshake, established sessions)
- Allows return traffic for established connections automatically
- Standard for most modern firewalls

### Next-Generation Firewall (NGFW)
Everything above, plus:
- **Application awareness** — identify apps regardless of port (e.g., detect Skype on port 443)
- **Intrusion prevention** (IPS) — signature + anomaly-based detection
- **SSL/TLS inspection** — decrypt and inspect encrypted traffic
- **URL filtering** — block web categories
- **Threat intelligence** — IP/domain reputation feeds
- **User identity integration** — rules based on AD user/group, not just IP

### Web Application Firewall (WAF)
Layer 7 firewall specifically for web applications:
- Protects against OWASP Top 10 (SQLi, XSS, CSRF)
- Virtual patching for known CVEs
- Bot detection and rate limiting

## Rule Design Best Practices
1. **Default deny** — block everything not explicitly allowed
2. **Most specific first** — order matters (first match wins)
3. **Log denied traffic** — essential for SOC visibility
4. **Review regularly** — remove unused/stale rules
5. **Use groups/objects** — named objects instead of raw IPs for readability
6. **Comment every rule** — document the business justification
7. **Separate inbound/outbound** — different risk profiles
8. **Time-limited rules** — temporary exceptions must expire

## Example Rule Structure
```
# Action  Source          Dest            Port    Proto  Log  Comment
ALLOW     10.10.0.0/16    10.20.1.100    443     TCP    Yes  "Web app access"
ALLOW     10.10.0.0/16    10.20.1.200    3306    TCP    Yes  "DB access (app servers only)"
DENY      ANY             ANY            ANY     ANY    Yes  "Default deny"
```

## SOC Relevance
- Firewall deny logs = reconnaissance detection, policy violation detection
- Allowed traffic that shouldn't be = misconfiguration or compromise
- Rule change alerts = detect unauthorized modifications
- Bypass detection = traffic that should hit the firewall but doesn't (routing issue or tunnel)
""",
    },
    {
        "title": "SIEM Fundamentals — What It Is and How It Works",
        "tags": ["fundamentals", "siem", "soc"],
        "content": """# SIEM Fundamentals

Security Information and Event Management (SIEM) is the SOC's central nervous system.

## What SIEM Does

### Log Collection & Aggregation
- Ingests logs from every security-relevant source
- Normalizes disparate formats into a common schema
- Stores for real-time analysis and historical search

### Correlation & Detection
- Applies detection rules (correlation rules) across multiple log sources
- Example: "Failed login from IP A" + "Successful login from IP A" + "Data download from IP A" = potential compromise
- Threshold-based: "More than 10 failed logins in 5 minutes"
- Statistical: "Login from a country the user has never accessed from"

### Alerting & Notification
- Generates alerts when rules match
- Severity-based routing (P1 → PagerDuty, P3 → ticket)
- Integration with SOAR for automated response

### Dashboards & Reporting
- Real-time visibility into security posture
- Compliance reporting (PCI, HIPAA, SOX audit evidence)
- KPI tracking (MTTD, MTTR, alert volume, false positive rate)

## Common SIEM Platforms
| Platform | Type |
|---|---|
| **Elastic Security (ELK)** | Open source / commercial |
| **Splunk** | Commercial (dominant market share) |
| **Microsoft Sentinel** | Cloud-native (Azure) |
| **IBM QRadar** | Commercial (enterprise) |
| **Google Chronicle/SecOps** | Cloud-native |
| **CrowdStrike LogScale** | Cloud-native |

## Key SIEM Concepts
- **Normalization**: Mapping diverse log formats to common field names (e.g., ECS)
- **Enrichment**: Adding context to events (GeoIP, threat intel, asset info)
- **Correlation**: Combining events from multiple sources to detect complex attacks
- **Use case**: A documented detection scenario with rule logic, response playbook, and tuning notes
- **Parsing**: Extracting structured fields from raw log messages

## SOC Analyst SIEM Workflow
1. Alert fires → review in SIEM dashboard
2. Pivot on key fields (source IP, user, hostname)
3. Search related events across time window
4. Correlate with threat intel and asset inventory
5. Determine: true positive, false positive, or needs escalation
6. Document findings and take action
""",
    },
]


AUTH_ACCESS = [
    {
        "title": "Access Control Models — DAC, MAC, RBAC, ABAC",
        "tags": ["fundamentals", "access-control", "authorization"],
        "content": """# Access Control Models

## Discretionary Access Control (DAC)
- **Owner decides** who gets access
- Common in: Windows NTFS permissions, Unix file permissions
- Weakness: Owners can grant access inappropriately; no centralized policy

## Mandatory Access Control (MAC)
- **System enforces** access based on labels/classifications
- Users cannot change permissions — set by administrators
- Common in: Military systems, SELinux, AppArmor
- Labels: Unclassified < Confidential < Secret < Top Secret
- Rule: "No read up, no write down" (Bell-LaPadula for confidentiality)

## Role-Based Access Control (RBAC)
- Access based on **job role**, not individual identity
- Users are assigned roles; roles have permissions
- Example: "SOC Analyst" role → can read alerts, update triage, cannot delete rules
- Most common in enterprise applications and cloud platforms

## Attribute-Based Access Control (ABAC)
- Access decisions based on **attributes** of user, resource, environment
- Example: "Allow access if user.department == 'Finance' AND resource.classification == 'Internal' AND time.hour BETWEEN 8 AND 18"
- Most flexible and granular — but most complex to implement
- Used in: AWS IAM policies, Azure Conditional Access

## Rule-Based Access Control
- Access determined by **rules** (often combined with other models)
- Example: Firewall rules, time-based access restrictions
- Often confused with RBAC but is a distinct concept

## Comparison
| Model | Who Decides | Granularity | Complexity | Example |
|---|---|---|---|---|
| DAC | Owner | Low | Low | File permissions |
| MAC | System | High | High | SELinux labels |
| RBAC | Admin (roles) | Medium | Medium | ION roles |
| ABAC | Policy engine | Very high | High | AWS IAM |
""",
    },
    {
        "title": "Password Security — Policies, Storage, and Attacks",
        "tags": ["fundamentals", "passwords", "authentication"],
        "content": """# Password Security

## Modern Password Policy (NIST SP 800-63B)
| Recommendation | Details |
|---|---|
| **Minimum length** | 8 characters (15+ preferred) |
| **Maximum length** | At least 64 characters allowed |
| **Complexity rules** | NOT recommended (uppercase/lowercase/symbol requirements) |
| **Passphrases** | Encouraged (e.g., "correct horse battery staple") |
| **Rotation** | NOT recommended unless compromise is suspected |
| **Breach checking** | Check against known breached password lists (HIBP) |
| **MFA** | Required for privileged and sensitive accounts |

## Password Storage
**Never store plaintext passwords.**

| Method | Security |
|---|---|
| **Argon2id** | Best — memory-hard, GPU-resistant |
| **bcrypt** | Good — time-tested, widely supported |
| **scrypt** | Good — memory-hard |
| **PBKDF2** | Acceptable — NIST approved, but GPU-vulnerable |
| **SHA-256 (unsalted)** | Bad — trivially crackable with rainbow tables |
| **MD5** | Terrible — never use |
| **Plaintext** | Catastrophic |

Proper hashing: `hash = Argon2id(password + unique_salt, iterations, memory)`

## Password Attacks
| Attack | Method | Defense |
|---|---|---|
| **Brute force** | Try all combinations | Account lockout, rate limiting |
| **Dictionary** | Try common words | Long passphrases |
| **Rainbow tables** | Precomputed hash lookup | Salting |
| **Credential stuffing** | Reuse breached passwords | Unique passwords per site |
| **Password spraying** | Few passwords, many accounts | Monitor failed login patterns |
| **Keylogging** | Capture keystrokes | EDR, MFA |
| **Phishing** | Trick user into entering password | Security training, phishing-resistant MFA |

## SOC Detection
- Multiple failed logins (4625) → brute force / password spray
- Login from breached credential source IP ranges
- Password changes outside normal patterns
- Cleartext password transmission alerts (FTP, Telnet, HTTP Basic)
""",
    },
    {
        "title": "PKI and Digital Certificates",
        "tags": ["fundamentals", "pki", "certificates"],
        "content": """# Public Key Infrastructure (PKI) & Digital Certificates

## What PKI Does
PKI provides the trust framework for verifying identities online using asymmetric cryptography.

## Certificate Components
A digital certificate (X.509) contains:
- **Subject**: Who the cert belongs to (CN, O, OU)
- **Issuer**: CA that signed the certificate
- **Public Key**: Subject's public key
- **Serial Number**: Unique identifier
- **Validity Period**: Not Before / Not After dates
- **Signature**: CA's digital signature (proof of authenticity)
- **Extensions**: Key usage, SAN (Subject Alternative Names), CRL distribution points

## Chain of Trust
```
Root CA (self-signed, stored in OS/browser trust store)
  └─ Intermediate CA (signed by Root)
       └─ Server Certificate (signed by Intermediate)
```

Browsers verify the chain: server cert → intermediate → root. If any link is broken or untrusted, the connection fails.

## Certificate Types
| Type | Validation | Use |
|---|---|---|
| **DV** (Domain Validation) | Prove domain ownership | Basic HTTPS |
| **OV** (Organization Validation) | Verify organization identity | Business sites |
| **EV** (Extended Validation) | Thorough vetting | Financial/government (less common now) |
| **Wildcard** | *.example.com | Multiple subdomains |
| **SAN** | Multiple specific domains | Multi-domain |
| **Code Signing** | Verify software publisher | Application trust |
| **Client** | Authenticate users/devices | Mutual TLS |

## Certificate Revocation
- **CRL** (Certificate Revocation List): Periodically published list of revoked certs
- **OCSP** (Online Certificate Status Protocol): Real-time revocation checking
- **OCSP Stapling**: Server includes OCSP response in TLS handshake (more efficient)

## SOC Relevance
- Expired or self-signed certificates = phishing or misconfiguration
- Certificate transparency (CT) logs — detect rogue certs for your domains
- TLS inspection (SSL decryption) requires internal CA certificates
- Code signing certificate theft = supply chain attack risk
""",
    },
    {
        "title": "OAuth 2.0 and SSO — How Modern Auth Works",
        "tags": ["fundamentals", "oauth", "sso", "authentication"],
        "content": """# OAuth 2.0 & Single Sign-On (SSO)

## OAuth 2.0
OAuth 2.0 is an **authorization** framework (not authentication). It allows applications to access resources on behalf of users without sharing passwords.

### Key Roles
| Role | Description |
|---|---|
| **Resource Owner** | The user who owns the data |
| **Client** | The app requesting access |
| **Authorization Server** | Issues tokens (e.g., Okta, Azure AD) |
| **Resource Server** | Hosts the protected data (e.g., API) |

### Token Types
- **Access Token**: Short-lived, grants API access (bearer token)
- **Refresh Token**: Long-lived, used to get new access tokens
- **ID Token** (OIDC): Contains user identity claims (JWT format)

### Common Flows
| Flow | Use Case |
|---|---|
| **Authorization Code** | Web apps (most secure for server-side) |
| **Authorization Code + PKCE** | Mobile/SPA apps (public clients) |
| **Client Credentials** | Server-to-server (no user involved) |
| **Device Code** | Smart TVs, CLI tools |

## OpenID Connect (OIDC)
Authentication layer built on top of OAuth 2.0. Adds the **ID Token** (JWT) containing user identity.

## SAML 2.0
XML-based SSO protocol. Common in enterprise environments.
- **IdP** (Identity Provider): Authenticates users (e.g., Okta, ADFS)
- **SP** (Service Provider): The application relying on authentication
- SAML Assertion: XML document containing authentication/authorization claims

## SSO Benefits & Risks
**Benefits**: One login for all apps, reduced password fatigue, centralized access control.

**Risks**: Single point of failure — compromise the IdP, compromise everything. Session token theft grants access to all SSO-connected apps.

## SOC Detection
- Unusual OAuth token grants (scope escalation, suspicious client IDs)
- Refresh token reuse from different IPs
- SAML response manipulation (golden SAML attack)
- Consent grant attacks (malicious app requesting broad permissions)
- Session token theft via cookie stealing or AiTM proxy
""",
    },
    {
        "title": "VPN Technologies — IPsec, SSL VPN, WireGuard",
        "tags": ["fundamentals", "vpn", "networking"],
        "content": """# VPN Technologies

Virtual Private Networks create encrypted tunnels over public networks.

## VPN Types

### Site-to-Site VPN
Connects two networks (e.g., branch office to HQ). Always-on tunnel between firewalls/routers.

### Remote Access VPN
Individual users connect to the corporate network from anywhere. Client software on the endpoint.

### Split Tunnel vs Full Tunnel
- **Full tunnel**: All traffic goes through VPN (more secure, more bandwidth)
- **Split tunnel**: Only corporate traffic goes through VPN (better performance, less visibility)
- SOC preference: Full tunnel (see all user traffic) or at minimum DNS through VPN

## Protocol Comparison
| Protocol | Layer | Speed | Security | Use Case |
|---|---|---|---|---|
| **IPsec (IKEv2)** | L3 | Fast | Strong | Site-to-site, remote access |
| **SSL/TLS VPN** | L4-7 | Good | Strong | Browser-based, clientless |
| **WireGuard** | L3 | Very fast | Strong | Modern remote access |
| **OpenVPN** | L3/L4 | Good | Strong | Cross-platform remote access |
| **PPTP** | L2 | Fast | Broken | Never use |
| **L2TP/IPsec** | L2/L3 | Moderate | Good | Legacy compatibility |

## SOC Relevance
- VPN authentication logs: who connected, when, from where
- Split tunnel = blind spot for SOC (user internet traffic bypasses monitoring)
- VPN brute force detection (multiple failed auth attempts)
- Impossible travel: VPN login from NYC, then physical badge swipe in London 30 min later
- Compromised VPN credentials = full network access (critical alert)
- Always-on VPN reduces risk of unmonitored endpoint activity
""",
    },
]


RISK_COMPLIANCE = [
    {
        "title": "Risk Management Fundamentals — Threat, Vulnerability, Risk",
        "tags": ["fundamentals", "risk-management", "governance"],
        "content": """# Risk Management Fundamentals

## Core Definitions

| Term | Definition |
|---|---|
| **Asset** | Anything of value (data, systems, people, reputation) |
| **Threat** | Potential cause of an unwanted incident (attacker, natural disaster) |
| **Vulnerability** | Weakness that can be exploited by a threat |
| **Risk** | Probability of a threat exploiting a vulnerability × impact |
| **Control** | Measure that reduces risk (technical, administrative, physical) |

## The Risk Equation
```
Risk = Threat × Vulnerability × Impact
```
Reduce any factor → reduce risk.

## Risk Assessment Process
1. **Identify assets** and their value/criticality
2. **Identify threats** (what could go wrong?)
3. **Identify vulnerabilities** (what weaknesses exist?)
4. **Assess likelihood** (how probable is exploitation?)
5. **Assess impact** (what's the damage if it happens?)
6. **Calculate risk level** (likelihood × impact matrix)
7. **Prioritize** and select risk treatment

## Risk Treatment Options
| Option | Description | Example |
|---|---|---|
| **Mitigate** | Reduce likelihood or impact | Apply patches, add MFA |
| **Transfer** | Shift risk to another party | Cyber insurance, outsourcing |
| **Accept** | Acknowledge and monitor | Low risk, cost of control > risk |
| **Avoid** | Eliminate the risky activity | Stop using vulnerable software |

## Risk Matrix (Likelihood × Impact)
|  | Low Impact | Medium Impact | High Impact |
|---|---|---|---|
| **High Likelihood** | Medium | High | Critical |
| **Medium Likelihood** | Low | Medium | High |
| **Low Likelihood** | Low | Low | Medium |

## SOC Relevance
- Alert severity should factor in asset risk (critical server vs test VM)
- Risk acceptance decisions affect what the SOC monitors
- Threat intel updates the "likelihood" side of the equation
- Incident impact assessment maps to the "impact" side
""",
    },
    {
        "title": "Regulatory Compliance — PCI DSS, HIPAA, GDPR Essentials",
        "tags": ["fundamentals", "compliance", "regulations"],
        "content": """# Regulatory Compliance Essentials

## PCI DSS (Payment Card Industry Data Security Standard)
Applies to: Any organization that stores, processes, or transmits cardholder data.

**12 Requirements (grouped):**
1-2. Secure network (firewalls, change defaults)
3-4. Protect cardholder data (encryption, secure transmission)
5-6. Vulnerability management (anti-malware, secure development)
7-9. Access control (need-to-know, unique IDs, physical security)
10-11. Monitoring and testing (logging, regular testing)
12. Security policies

**SOC Impact**: Must log and monitor all access to cardholder data environment (CDE). 90-day log retention minimum, daily log reviews.

## HIPAA (Health Insurance Portability and Accountability Act)
Applies to: Healthcare providers, health plans, clearinghouses, and business associates.

**Key Rules:**
- **Privacy Rule**: Who can access PHI (Protected Health Information)
- **Security Rule**: Administrative, physical, and technical safeguards for ePHI
- **Breach Notification Rule**: Report breaches within 60 days

**SOC Impact**: Audit trails for all ePHI access, encryption requirements, incident response with breach notification procedures.

## GDPR (General Data Protection Regulation)
Applies to: Any organization processing personal data of EU residents.

**Key Principles:**
- Lawful basis for processing (consent, legitimate interest, contract, etc.)
- Data minimization — collect only what's necessary
- Right to erasure ("right to be forgotten")
- 72-hour breach notification requirement
- Data Protection Impact Assessments (DPIA) for high-risk processing
- Fines: Up to 4% of global annual revenue or 20M EUR

## SOX (Sarbanes-Oxley Act)
Applies to: Public companies (US).
Focus: Financial reporting integrity, internal controls.
**SOC Impact**: Audit trails for financial systems, change management controls, access reviews.

## Common Compliance Requirements for SOC
| Requirement | PCI | HIPAA | GDPR | SOX |
|---|---|---|---|---|
| Access logging | Yes | Yes | Yes | Yes |
| Encryption at rest | Yes | Yes | Recommended | — |
| Encryption in transit | Yes | Yes | Recommended | — |
| Breach notification | Yes (card brands) | 60 days | 72 hours | — |
| Log retention | 1 year | 6 years | Varies | 7 years |
| Vulnerability scanning | Quarterly | Required | Implied | Implied |
""",
    },
    {
        "title": "Business Continuity and Disaster Recovery (BC/DR)",
        "tags": ["fundamentals", "disaster-recovery", "business-continuity"],
        "content": """# Business Continuity & Disaster Recovery

## Key Definitions

| Term | Definition |
|---|---|
| **BCP** (Business Continuity Plan) | Strategy to maintain operations during disruption |
| **DRP** (Disaster Recovery Plan) | Technical plan to restore IT systems after disaster |
| **BIA** (Business Impact Analysis) | Identifies critical processes and acceptable downtime |
| **RPO** (Recovery Point Objective) | Max acceptable data loss (time) — how far back you restore |
| **RTO** (Recovery Time Objective) | Max acceptable downtime — how fast you must recover |

## RPO vs RTO Examples
| System | RPO | RTO | Backup Strategy |
|---|---|---|---|
| Financial DB | 0 (no data loss) | 15 minutes | Synchronous replication |
| Email server | 1 hour | 4 hours | Hourly snapshots |
| Dev environment | 24 hours | 48 hours | Daily backups |
| Archived data | 1 week | 1 week | Weekly backups |

## Backup Strategies
| Type | Description | Pros | Cons |
|---|---|---|---|
| **Full** | Copy everything | Fast restore | Slow backup, high storage |
| **Incremental** | Changes since last backup | Fast, low storage | Slower restore (chain) |
| **Differential** | Changes since last full | Faster restore than incremental | Grows over time |

### 3-2-1 Backup Rule
- **3** copies of data
- **2** different media types
- **1** offsite (or cloud)

## Disaster Recovery Sites
| Type | RTO | Cost | Description |
|---|---|---|---|
| **Hot site** | Minutes | $$$$ | Fully operational, real-time replication |
| **Warm site** | Hours | $$$ | Hardware ready, data may be hours old |
| **Cold site** | Days | $ | Empty facility, equipment must be deployed |
| **Cloud DR** | Minutes-hours | $$ | On-demand cloud infrastructure |

## SOC Relevance
- Ransomware response depends on backup availability and RPO
- SOC must test restore procedures as part of IR exercises
- DR site activation = increased monitoring needs
- Backup integrity monitoring: ensure backups aren't corrupted or encrypted by ransomware
""",
    },
    {
        "title": "Security Operations Center (SOC) — Tiers and Responsibilities",
        "tags": ["fundamentals", "soc", "operations"],
        "content": """# SOC Tiers & Responsibilities

## SOC Tier Model

### Tier 1 — Alert Analyst (Triage)
**Responsibilities:**
- Monitor SIEM dashboards and alerts
- Initial triage: true positive, false positive, or needs investigation
- Follow playbooks for common alert types
- Escalate to Tier 2 when playbook doesn't cover the scenario
- Document findings in ticketing system

**Skills:** Log reading, basic network analysis, following procedures, pattern recognition.

### Tier 2 — Incident Handler (Investigation)
**Responsibilities:**
- Deep investigation of escalated alerts
- Correlate data across multiple sources
- Determine scope and impact of incidents
- Contain active threats (isolate hosts, block IPs)
- Create and refine detection rules
- Mentor Tier 1 analysts

**Skills:** Advanced log analysis, forensics basics, threat intel, scripting, MITRE ATT&CK.

### Tier 3 — Threat Hunter / Senior Analyst
**Responsibilities:**
- Proactive threat hunting (hypothesis-driven)
- Advanced malware analysis and reverse engineering
- Develop new detection logic and analytics
- Incident commander for major incidents
- Red/purple team coordination
- Threat intelligence analysis and production

**Skills:** Deep forensics, malware RE, scripting/automation, threat modeling, strategic thinking.

### SOC Manager / Lead
- Team management, hiring, training
- KPI tracking and reporting to leadership
- Process improvement and playbook development
- Vendor/tool evaluation
- Liaison with other teams (IT, legal, management)

## Key SOC Metrics
| Metric | Description | Target |
|---|---|---|
| **MTTD** | Mean Time to Detect | < 24 hours |
| **MTTR** | Mean Time to Respond | < 4 hours |
| **MTTC** | Mean Time to Contain | < 1 hour |
| **Alert Volume** | Alerts per analyst per day | < 50 (manageable) |
| **False Positive Rate** | % of alerts that are FP | < 30% |
| **Escalation Rate** | T1 → T2 escalations | 10-20% |
| **Coverage** | % of MITRE techniques detected | Track and improve |

## SOC Tools Ecosystem
- **SIEM**: Central log analysis (Elastic, Splunk, Sentinel)
- **SOAR**: Automated response orchestration (Phantom, XSOAR, Shuffle)
- **EDR**: Endpoint visibility and response (CrowdStrike, Defender, SentinelOne)
- **NDR**: Network detection and response (Zeek, Darktrace, Vectra)
- **TIP**: Threat intelligence platform (MISP, OpenCTI, Anomali)
- **Ticketing**: Case management (ServiceNow, Jira, TheHive)
""",
    },
    {
        "title": "Incident Response Playbook Structure",
        "tags": ["fundamentals", "incident-response", "playbooks"],
        "content": """# Incident Response Playbook Structure

A playbook is a documented, repeatable procedure for handling a specific type of security incident.

## Why Playbooks Matter
- Ensure consistent response regardless of which analyst is on shift
- Reduce decision fatigue during high-stress incidents
- Capture institutional knowledge
- Enable metrics (did we follow the process?)
- Basis for automation (SOAR)

## Standard Playbook Sections

### 1. Overview
- Playbook name and ID
- Description of the incident type
- Severity classification criteria
- MITRE ATT&CK mapping
- Last reviewed/updated date

### 2. Detection
- What alerts/indicators trigger this playbook
- Detection rule references (SIEM rule IDs)
- Data sources required (which logs?)

### 3. Triage
- Initial assessment questions
  - Is this a true positive?
  - What is the scope (one host or many)?
  - Is the activity ongoing or historical?
- Automated enrichment steps (IP reputation, hash lookup, user context)

### 4. Investigation
- Data collection steps (specific queries, log sources)
- Pivot points (what to search next based on findings)
- Timeline reconstruction guidance
- Evidence preservation requirements

### 5. Containment
- Immediate containment actions (network isolation, account disable)
- Short-term vs long-term containment
- Communication requirements (who to notify)

### 6. Eradication & Recovery
- Remove threat artifacts (malware, persistence mechanisms)
- Patch vulnerabilities exploited
- Restore from clean backups if needed
- Verify clean state before returning to production

### 7. Post-Incident
- Lessons learned meeting
- Playbook updates based on findings
- Detection rule improvements
- Metrics collection

## Example: Phishing Playbook (Simplified)
```
TRIGGER: Email gateway alert — malicious URL/attachment detected

TRIAGE:
  1. Pull email headers (sender, return-path, IPs)
  2. Check SPF/DKIM/DMARC results
  3. Analyze URL in sandbox (URLscan.io, VirusTotal)
  4. Check if any user clicked the link (proxy logs)

INVESTIGATE:
  5. Search for other recipients of same campaign (email gateway)
  6. If clicked: check endpoint for IOCs (EDR)
  7. If credentials entered: check for unauthorized logins (AD logs)

CONTAIN:
  8. Block sender domain/IP at email gateway
  9. Block malicious URL at web proxy
  10. If compromised: reset user password + revoke sessions

RECOVER:
  11. Remove phishing email from all mailboxes
  12. Notify affected users
  13. If credentials compromised: monitor for abuse (30 days)
```
""",
    },
]



COLLECTIONS = [
    (
        "Core Security Concepts",
        "Foundational security principles - CIA triad, defense in depth, threat landscape, frameworks",
        CORE_SECURITY,
    ),
    (
        "Network Models & Protocols",
        "OSI model, TCP/IP, DNS, HTTP, email protocols, VPN technologies",
        NETWORK_PROTOCOLS,
    ),
    (
        "Authentication & Access",
        "Access control models, MFA, PKI, OAuth/SSO, Active Directory, password security",
        AUTH_ACCESS,
    ),
    (
        "Risk, Compliance & Operations",
        "Risk management, regulatory compliance, BC/DR, SOC operations, playbook design",
        RISK_COMPLIANCE,
    ),
]
