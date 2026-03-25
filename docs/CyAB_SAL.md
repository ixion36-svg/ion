# CyAB — Cyber Assurance Base
## Security Assurance Levels (SAL)

> **Document ID:** CyAB-SAL-001
> **Version:** 1.0
> **Classification:** OFFICIAL
> **Date:** 2026-03-24
> **Review Date:** 2026-09-24
> **Owner:** Cyber Assurance Manager
> **Approver:** Head of Cyber Security / CISO

---

## 1. Purpose

This document defines the **Security Assurance Levels (SAL)** framework for the Cyber Assurance Base (CyAB). SALs provide a structured, risk-proportionate approach to determining the depth and rigour of security controls, verification activities, and evidence requirements applied to systems, services, and data assets.

Each assurance level prescribes a baseline of security controls, testing activities, documentation, and ongoing monitoring proportionate to the risk profile of the asset. This ensures that critical and high-risk systems receive greater scrutiny, while lower-risk assets are not burdened with disproportionate overhead.

---

## 2. Scope

This framework applies to:

- All information systems, applications, and services operated or managed under CyAB oversight
- Third-party and cloud-hosted services processing organisational data
- Operational technology (OT) and IoT devices within the security perimeter
- Development and staging environments where they process or replicate production data
- New systems during design, build, and pre-production assurance gates

---

## 3. Security Assurance Levels — Overview

| Level | Name | Risk Profile | Typical Assets |
|---|---|---|---|
| **SAL 1** | Foundation | Low risk, low business impact | Internal wikis, development sandboxes, non-sensitive file shares, printer infrastructure |
| **SAL 2** | Standard | Moderate risk, limited business impact | Corporate email, HR systems (non-payroll), project management tools, internal web apps |
| **SAL 3** | Enhanced | High risk, significant business impact | Customer-facing services, financial systems, authentication infrastructure, SIEM/SOC tooling |
| **SAL 4** | Critical | Very high risk, severe business/regulatory impact | Payment processing, PII/PHI data stores, domain controllers, PKI infrastructure, backup & recovery |
| **SAL 5** | Maximum | Existential risk, national security or safety-of-life | CNI control systems, classified networks, safety-critical OT, cryptographic key management |

---

## 4. SAL Classification Criteria

Systems are assigned an SAL based on the **highest applicable score** across the following dimensions:

### 4.1 Impact Assessment Matrix

| Dimension | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Confidentiality** | Public or internal-only data | Internal data, limited sensitivity | Confidential business data | PII, financial, legal privilege | Classified, TOP SECRET, safety-critical |
| **Integrity** | Corruption inconvenient | Corruption causes rework | Corruption causes financial loss or compliance breach | Corruption causes significant regulatory/legal action | Corruption causes safety failure or national security harm |
| **Availability** | Downtime tolerable (days) | Downtime tolerable (24h) | Downtime causes revenue loss (≤4h RTO) | Downtime causes major operational failure (≤1h RTO) | Zero-downtime required, life-safety dependency |
| **Regulatory** | No specific regulation | GDPR basics, internal policy | GDPR Art. 32, PCI DSS (low volume), Cyber Essentials Plus | PCI DSS (high volume), FCA, NIS2 essential | CNI (NIS Regulations), Official Secrets Act, DORA critical |
| **Data Subjects** | None / internal staff only | ≤ 1,000 individuals | 1,000–100,000 individuals | 100,000–1M individuals | > 1M individuals or vulnerable groups |
| **Supply Chain** | No external dependencies | Standard SaaS (low privilege) | SaaS with data processing, API integrations | Outsourced critical function, managed SOC | Sovereign infrastructure, cleared contractors |

### 4.2 Override Rules

- Any system processing **payment card data** → minimum SAL 4
- Any system processing **special category data** (Art. 9 GDPR) → minimum SAL 4
- Any system designated as **Critical National Infrastructure** → SAL 5
- Any system with **internet-facing authentication** → minimum SAL 3
- Any system acting as a **trust anchor** (CA, IdP, DNS root) → minimum SAL 4

---

## 5. Security Controls by SAL

### 5.1 Identity and Access Management

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Unique user accounts | Required | Required | Required | Required | Required |
| Password policy (complexity + rotation) | Basic (12 char) | Standard (14 char, 365d) | Strong (16 char, 180d) | Strong (16 char, 90d) | Passphrase (20+ char, 90d) |
| Multi-factor authentication | Recommended | Required (SSO) | Required (hardware token accepted) | Required (hardware token / FIDO2) | Required (FIDO2 hardware only) |
| Privileged access management | Shared admin acceptable | Named admin accounts | PAM solution, session recording | PAM with JIT access, break-glass only | PAM with dual-auth, continuous recording, time-bound |
| Access review cycle | Annual | 6-monthly | Quarterly | Monthly | Continuous (automated) |
| Joiners/movers/leavers process | Manual | Semi-automated | Automated with approval workflow | Automated with manager + security approval | Automated with DV/SC clearance validation |
| Service account management | Documented | Documented + rotated annually | Managed secrets vault | Managed vault + auto-rotation | HSM-backed, short-lived certificates |

### 5.2 Network Security

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Network segmentation | Flat network acceptable | VLAN separation | Micro-segmentation / zero-trust zones | Dedicated security zone, no lateral trust | Air-gapped or hardware-enforced boundary |
| Firewall rules | Default deny outbound recommended | Default deny outbound | Default deny both directions, reviewed quarterly | Allowlist-only, reviewed monthly | Allowlist-only, reviewed weekly, IDS/IPS inline |
| Encryption in transit | HTTPS for external | TLS 1.2+ for all external | TLS 1.2+ internal and external | TLS 1.3, mutual TLS for service-to-service | TLS 1.3, mTLS, CNSA-approved ciphers |
| DNS security | Standard DNS | Filtered DNS (malware/phishing) | DNSSEC validation, DNS logging | DNSSEC + DNS-over-HTTPS, full query logging | Dedicated resolvers, DNS sinkholing, anomaly detection |
| Remote access | VPN optional | VPN required | VPN + MFA, split-tunnel prohibited | Always-on VPN, device compliance check | Dedicated secure terminal, no BYOD |
| DDoS protection | None | Basic (ISP-level) | Cloud-based WAF/DDoS | Dedicated DDoS mitigation, auto-scaling | Multi-provider, sovereign DDoS mitigation |

### 5.3 Endpoint Security

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Anti-malware | Signature-based AV | Next-gen AV | EDR with 24/7 monitoring | EDR + application allowlisting | EDR + allowlisting + host-based IDS |
| Patch management | Monthly | Fortnightly (14 day critical) | Weekly (72h critical, 14d high) | 48h critical, 7d high | 24h critical, 48h high, zero-day same-day |
| Device encryption | Recommended | Required (FDE) | Required (FDE + removable media) | Required (FDE + TPM-backed, USB disabled) | Required (FIPS 140-3 validated encryption) |
| Configuration hardening | Default install | CIS Level 1 | CIS Level 2 / DISA STIG | CIS Level 2 + custom hardening baseline | Bespoke hardened image, integrity monitoring |
| Logging | Local logs | Centralised (SIEM) | Centralised, tamper-evident | Centralised, tamper-evident, 12-month retention | Centralised, cryptographically signed, 7-year retention |

### 5.4 Application Security

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Secure development lifecycle | Awareness training | OWASP Top 10 training + linting | SAST + DAST in CI/CD pipeline | SAST + DAST + SCA + manual code review | Formal methods, SAST/DAST/IAST, independent code audit |
| Dependency management | Manual updates | SCA scanning (quarterly) | SCA in CI/CD, auto-PR for critical | SCA + SBOM generation, licence compliance | SBOM + provenance attestation, signed dependencies |
| Input validation | Basic sanitisation | OWASP-compliant validation | WAF + server-side validation | WAF + CSP + server-side + parameterised queries | WAF + CSP + runtime application self-protection (RASP) |
| API security | API keys | API keys + rate limiting | OAuth 2.0 / OIDC + rate limiting | OAuth 2.0 + mTLS + request signing | mTLS + signed tokens + anomaly detection |
| Secrets management | Config files (gitignored) | Environment variables | Secrets vault (HashiCorp/AWS SM) | Secrets vault + auto-rotation + audit | HSM-backed vault, dual-control, break-glass |

### 5.5 Data Protection

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Data classification | Not required | Labelled (internal/public) | Labelled (4-tier), handling rules enforced | Automated classification + DLP | Automated classification + DLP + egress monitoring |
| Encryption at rest | Recommended | Required (platform default) | Required (AES-256, managed keys) | Required (AES-256, customer-managed keys) | Required (FIPS 140-3, HSM-managed keys) |
| Backup & recovery | Ad-hoc | Scheduled (daily) | Scheduled (daily), tested quarterly | Scheduled (hourly), tested monthly, offsite | Real-time replication, tested weekly, immutable, geographically separated |
| Data retention | Undefined | Policy-defined | Policy-enforced, automated deletion | Policy-enforced, crypto-shredding capable | Policy-enforced, crypto-shredding, verified destruction |
| Data loss prevention | None | Email DLP (basic) | Endpoint + email DLP | Endpoint + email + cloud + USB DLP | Full-spectrum DLP + UEBA |

### 5.6 Monitoring and Detection

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Log collection | Local only | Centralised SIEM (key sources) | Centralised SIEM (all sources), 90d retention | Full telemetry (SIEM + NDR + EDR), 12m retention | Full telemetry + UEBA + deception, 7yr retention |
| Alert monitoring | Business hours | Business hours, P1 on-call | 24/7 automated + analyst triage | 24/7 SOC with dedicated analyst coverage | 24/7 SOC + red team + continuous threat hunt |
| Detection rules | Vendor defaults | Vendor + basic custom rules | MITRE ATT&CK-mapped rules (≥40% coverage) | ATT&CK-mapped (≥60%), behavioural analytics | ATT&CK-mapped (≥80%), ML-based anomaly detection |
| Threat hunting | None | Reactive (post-incident) | Scheduled (monthly) | Scheduled (fortnightly) + ad-hoc | Continuous, dedicated hunt team |
| Incident response | Ad-hoc | Documented IRP | Documented IRP, tabletop annually | IRP + playbooks, tabletop quarterly, retainer | IRP + playbooks + automated SOAR, live exercise bi-annually |

---

## 6. Log Quality & Telemetry Standards

Log telemetry is a foundational security control. The depth, quality, and integrity of logging must be proportionate to the system's SAL. Full details are maintained in the dedicated SOC template **SOP-LOG-001 — Log Quality & Telemetry Standards**. The summary below captures the key requirements per tier.

### 6.1 Telemetry Coverage

| Requirement | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Systems forwarding logs** | ≥ 70% of in-scope | ≥ 85% | ≥ 95% | ≥ 99% | 100% |
| **Required event types collected** | Best effort | ≥ 80% | ≥ 90% | ≥ 98% | 100% |
| **Log source health monitoring** | None | Quarterly manual | Automated heartbeat | Real-time dashboard + alerts | Real-time + independent audit |

### 6.2 Log Quality Dimensions

| Dimension | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Schema conformance** (mandatory fields present) | ≥ 80% | ≥ 90% | ≥ 95% | ≥ 98% | 100% |
| **Ingestion latency** | ≤ 60 min | ≤ 15 min | ≤ 5 min | ≤ 2 min | ≤ 30 sec |
| **Clock sync (max skew)** | ≤ 5 min | ≤ 2 min | ≤ 1 min | ≤ 500ms | ≤ 100ms |
| **Unparsed / raw-only events** | ≤ 50% | ≤ 20% | ≤ 5% | 0% | 0% |
| **Enrichment** (geo, threat intel, asset context) | None | None | Required | Required + user/vuln context | Required + behavioural baseline |

### 6.3 Log Integrity

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Centralised (off-source) storage | — | Required | Required | Required | Required |
| Encrypted transport (TLS) | — | Required | Required | Required | Required |
| Source authentication (mTLS / API key) | — | — | Required | Required | Required |
| Append-only / write-once storage | — | — | — | Required | Required |
| Cryptographic signing | — | — | — | — | Required |
| Tamper detection alerting | — | — | Required | Required | Required |

### 6.4 Retention

| SAL | Hot (searchable) | Warm (queryable) | Cold / Archive | Total Minimum |
|---|---|---|---|---|
| SAL 1 | 7 days | 23 days | — | **30 days** |
| SAL 2 | 30 days | 60 days | — | **90 days** |
| SAL 3 | 30 days | 60 days | 275 days | **1 year** |
| SAL 4 | 90 days | 275 days | 2 years | **3 years** |
| SAL 5 | 90 days | 275 days | 6+ years | **7 years** |

### 6.5 Log Quality Review Cadence

| Activity | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Log source inventory review | Annual | 6-monthly | Quarterly | Monthly | Continuous |
| Schema compliance audit | — | Annual | Quarterly | Monthly | Continuous |
| Coverage gap assessment | — | Annual | Quarterly | Monthly | Weekly |
| Ingestion latency review | — | — | Monthly | Weekly | Daily |

> **Reference:** For the full specification including required event types per SAL, schema field requirements, enrichment standards, onboarding SLAs, and the log quality scorecard methodology, see the **Log Quality & Telemetry Standards** template (SOP-LOG-001) in the SOC Document Library.

---

## 7. Assurance Activities by SAL

### 7.1 Verification and Testing

| Activity | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Vulnerability scanning** | Quarterly (external) | Monthly (external + internal) | Fortnightly (authenticated) | Weekly (authenticated + credentialed) | Continuous (agent-based) |
| **Penetration testing** | None | Annual (external) | Annual (external + internal) | Bi-annual (external + internal + social eng.) | Quarterly + continuous red team |
| **Configuration audit** | Annual self-assessment | Annual (automated CIS scan) | Quarterly (automated + spot check) | Monthly (automated + manual review) | Continuous compliance monitoring |
| **Code review** | Peer review (optional) | Peer review (required) | Peer review + SAST | Peer review + SAST + independent review | Formal security audit per release |
| **Architecture review** | None | At major change | At every significant change | Quarterly review + change-triggered | Continuous architecture oversight board |
| **Disaster recovery test** | None | Annual (documented) | Annual (live test) | Bi-annual (live test, failover validated) | Quarterly (live test, measured RTO/RPO) |
| **Business continuity test** | None | Annual (tabletop) | Annual (simulation) | Bi-annual (simulation + live) | Quarterly (live exercise, unannounced) |

### 7.2 Third-Party Assurance

| Activity | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Supplier risk assessment** | Self-certification | Security questionnaire | Questionnaire + evidence review | On-site audit or SOC 2 Type II | On-site audit + continuous monitoring + right-to-audit |
| **Contract security clauses** | Standard T&Cs | Data processing agreement | DPA + security schedule + breach notification | DPA + security schedule + pen test right + SLA | Bespoke security contract, sovereign hosting, escrow |
| **Ongoing monitoring** | None | Annual review | Annual review + incident notification | Quarterly review + automated risk scoring | Continuous monitoring + threat intel sharing |

---

## 8. Documentation and Evidence Requirements

### 8.1 Required Artefacts per SAL

| Artefact | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| System description / asset register entry | Required | Required | Required | Required | Required |
| Data flow diagram | — | Recommended | Required | Required (detailed) | Required (verified, classified) |
| Risk assessment | — | Lightweight | Full (ISO 27005 / NIST 800-30) | Full + threat modelling (STRIDE/PASTA) | Full + threat modelling + residual risk sign-off |
| Security architecture document | — | — | Required | Required (reviewed) | Required (independently assured) |
| Hardening guide / build standard | — | — | CIS benchmark reference | Custom hardening baseline | Formal hardening spec, deviation register |
| Incident response playbook | — | Generic IRP reference | System-specific playbook | System-specific + tested playbook | Tested + automated playbook |
| Pen test report | — | Annual summary | Full report + remediation tracker | Full report + retest evidence | Full report + retest + continuous findings |
| Compliance evidence pack | — | — | Annual evidence bundle | Quarterly evidence bundle | Continuous compliance dashboard |
| Business impact assessment | — | — | Required | Required (signed by business owner) | Required (signed by board-level sponsor) |
| Decommissioning plan | — | — | — | Required | Required (data destruction certified) |

### 8.2 Evidence Retention

| SAL | Minimum Retention | Storage |
|---|---|---|
| SAL 1 | 1 year | Standard file share |
| SAL 2 | 2 years | Standard file share (access-controlled) |
| SAL 3 | 3 years | Secured repository, tamper-evident |
| SAL 4 | 5 years | Secured repository, cryptographically signed |
| SAL 5 | 7 years (or regulatory minimum) | Immutable storage, dual-control access |

---

## 9. Assurance Lifecycle

### 9.1 Assurance Gates

All systems must pass through assurance gates at key lifecycle stages:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   DESIGN    │───▶│    BUILD    │───▶│   PRE-PROD  │───▶│  LIVE /     │───▶│  DECOMMIS-  │
│   GATE      │    │   GATE      │    │   GATE      │    │  OPERATE    │    │  SION GATE  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

| Gate | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Design Gate** | Self-assessment | Peer review | Security architecture review | Security architecture review + threat model | Independent architecture assurance |
| **Build Gate** | N/A | SAST pass | SAST + DAST pass, dependency scan clean | SAST + DAST + code review + hardening verified | Independent code audit + hardening audit |
| **Pre-prod Gate** | Basic smoke test | Vuln scan (clean critical/high) | Vuln scan + pen test (clean critical) | Pen test + config audit + DR test | Full assurance pack review + sign-off board |
| **Operate** | Monitoring enabled | Monitoring + quarterly review | 24/7 monitoring + monthly review | 24/7 SOC + fortnightly review + threat hunt | 24/7 SOC + continuous hunt + red team |
| **Decommission Gate** | Asset register updated | Data migration verified | Data securely deleted, access revoked | Crypto-shredding + audit trail | Certified destruction + regulatory notification |

### 9.2 Review Cadence

| SAL | Full Assurance Review | Control Spot-check | SAL Re-classification |
|---|---|---|---|
| SAL 1 | Every 2 years | Annual | On significant change |
| SAL 2 | Annually | 6-monthly | On significant change |
| SAL 3 | Annually | Quarterly | Annually or on change |
| SAL 4 | Bi-annually | Monthly | Annually or on change |
| SAL 5 | Quarterly | Continuous | Quarterly |

---

## 10. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| **System Owner** | Ensures system meets its assigned SAL requirements. Provides resources for assurance activities. Accepts residual risk. |
| **Cyber Assurance Manager** | Maintains the SAL framework. Conducts or commissions assurance reviews. Escalates non-compliance. |
| **CyAB Analysts (L1–L3)** | Execute monitoring and detection at the depth prescribed by the system's SAL. Conduct threat hunts on SAL 3+ systems. |
| **SOC Lead** | Ensures operational coverage aligns with SAL requirements. Manages escalation and reporting cadence. |
| **Detection Engineer** | Builds and maintains detection rules at the coverage level required by each SAL tier. |
| **IT Operations / Platform Team** | Implements and maintains technical controls (patching, hardening, logging) to the standard required by the SAL. |
| **CISO / Head of Cyber Security** | Approves SAL 4/5 risk acceptances. Sponsors the framework. Reports assurance posture to board. |
| **Internal Audit** | Independently verifies SAL compliance for SAL 4/5 systems on an annual basis. |

---

## 11. SAL Assignment Process

### 11.1 Workflow

```
1. System Owner completes Impact Assessment (Section 4.1)
     │
     ▼
2. CyAB reviews assessment, applies override rules (Section 4.2)
     │
     ▼
3. Proposed SAL agreed between System Owner and Cyber Assurance Manager
     │
     ▼
4. SAL 4/5: Requires CISO sign-off
     │
     ▼
5. SAL recorded in asset register, controls baseline generated
     │
     ▼
6. Gap analysis: current controls vs. required SAL baseline
     │
     ▼
7. Remediation plan agreed (owner + timelines)
     │
     ▼
8. Assurance gate reviews commence per lifecycle stage
```

### 11.2 SAL Change Triggers

A system's SAL must be re-evaluated when:

- Significant change to data processed (volume, sensitivity, or classification)
- Change of hosting environment (on-prem ↔ cloud, change of provider)
- Regulatory change affecting the system or its data
- Merger, acquisition, or organisational restructure
- Security incident involving the system
- Major architectural change (new integrations, API exposure, public access)
- Scheduled re-classification review (per Section 9.2)

---

## 12. Non-Compliance and Risk Acceptance

### 12.1 Non-Compliance Handling

| Scenario | Action |
|---|---|
| **Control gap identified** (SAL 1–2) | Logged in risk register, remediation plan within 30 days |
| **Control gap identified** (SAL 3) | Escalated to Cyber Assurance Manager, remediation plan within 14 days |
| **Control gap identified** (SAL 4–5) | Escalated to CISO, remediation plan within 7 days, interim compensating controls required |
| **Systemic non-compliance** (multiple systems) | Triggered as a security incident, reported to senior leadership |

### 12.2 Risk Acceptance

Where a control cannot be implemented within the prescribed timeframe:

- **SAL 1–2:** System Owner may accept risk with documented justification (annual review)
- **SAL 3:** Cyber Assurance Manager must co-sign risk acceptance (6-month review)
- **SAL 4:** CISO must approve risk acceptance (quarterly review, compensating control required)
- **SAL 5:** Board-level sponsor must approve (monthly review, compensating control mandatory, time-limited ≤90 days)

---

## 13. Framework Alignment

| Framework | SAL Mapping |
|---|---|
| **NCSC CAF** | CAF Indicator A–D profiles map to SAL 2–5 |
| **ISO 27001:2022** | SAL 3+ aligns with Annex A control applicability |
| **Cyber Essentials / CE+** | SAL 2 baseline ≈ Cyber Essentials; SAL 3 baseline ≈ CE+ |
| **NIST CSF 2.0** | SAL tiers map to CSF implementation tiers (Partial → Adaptive) |
| **PCI DSS 4.0** | SAL 4 controls meet PCI DSS requirements for CDE systems |
| **NIS2 Directive** | Essential entities → SAL 4 minimum; Important entities → SAL 3 minimum |
| **DORA** | Critical ICT services → SAL 4/5 |
| **Common Criteria** | SAL 1≈EAL1, SAL 2≈EAL2, SAL 3≈EAL3, SAL 4≈EAL4, SAL 5≈EAL5+ |

---

## 14. Glossary

| Term | Definition |
|---|---|
| **SAL** | Security Assurance Level — a risk-proportionate tier of security controls and verification |
| **CyAB** | Cyber Assurance Base — the centralised cyber security assurance function |
| **CAF** | Cyber Assessment Framework (NCSC) |
| **CNI** | Critical National Infrastructure |
| **DLP** | Data Loss Prevention |
| **FDE** | Full Disk Encryption |
| **FIDO2** | Fast Identity Online 2 — hardware-based authentication standard |
| **HSM** | Hardware Security Module |
| **JIT** | Just-In-Time (access provisioning) |
| **mTLS** | Mutual Transport Layer Security |
| **PAM** | Privileged Access Management |
| **RASP** | Runtime Application Self-Protection |
| **SAST** | Static Application Security Testing |
| **DAST** | Dynamic Application Security Testing |
| **SCA** | Software Composition Analysis |
| **SBOM** | Software Bill of Materials |
| **SOAR** | Security Orchestration, Automation, and Response |
| **UEBA** | User and Entity Behaviour Analytics |
| **RTO** | Recovery Time Objective |
| **RPO** | Recovery Point Objective |

---

## 15. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-24 | CyAB | Initial release |

---

## 16. Signatories

| Role | Name | Signature | Date |
|---|---|---|---|
| **Cyber Assurance Manager** | | | |
| **Head of Cyber Security / CISO** | | | |
| **Head of IT Operations** | | | |
| **Internal Audit Representative** | | | |

---

*This document is subject to annual review. Next scheduled review: March 2027.*
