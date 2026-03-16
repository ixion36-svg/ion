"""Built-in KB data: Offensive Security — Access & Escalation."""

# ============================================================
# COLLECTION 1: INITIAL ACCESS & SOCIAL ENGINEERING
# ============================================================

INITIAL_ACCESS = [
    {
        "title": "Phishing Anatomy and Detection Strategies",
        "tags": ["phishing", "initial-access", "email-security", "T1566", "detection"],
        "content": r"""# Phishing Anatomy and Detection Strategies

## Overview

Phishing is the most prevalent initial access vector across all threat landscapes. Understanding each phase of a phishing attack equips SOC analysts to build layered detections that catch campaigns at reconnaissance, delivery, and exploitation stages rather than relying solely on endpoint alerts after payload execution.

## Attack Lifecycle

**Reconnaissance**: Attackers harvest employee names, email formats, and organizational structure from LinkedIn, corporate websites, and data breach dumps. They identify high-value targets such as finance, HR, and IT staff who regularly handle attachments or wire transfers.

**Infrastructure Staging**: Lookalike domains are registered days to weeks before the campaign. Common techniques include typosquatting (targetcorp vs targetc0rp), homoglyph substitution (using Cyrillic characters), and subdomain abuse (targetcorp.attacker.com). Let's Encrypt certificates are obtained to display the padlock icon.

**Delivery**: Emails are crafted with urgency-inducing pretexts — invoice disputes, package deliveries, password expiration notices, or shared documents. Payloads arrive as macro-laden Office documents, HTML smuggling pages, ISO/IMG disk images, or password-protected ZIP archives.

**Exploitation**: Once the user interacts, payloads execute via macros, DLL sideloading from mounted disk images, or credential harvesting on cloned login pages. Callbacks establish C2 connectivity within seconds.

## Detection Indicators

**Email Header Analysis:**
- `Reply-To` address differs from `From` address
- `Received` headers show mismatched originating domains
- SPF soft-fail or DKIM alignment failures
- Recently registered sending domains (< 30 days via WHOIS)
- X-Originating-IP from VPS/cloud hosting providers

**Content Indicators:**
- Urgency language combined with external links or attachments
- Shortened URLs (bit.ly, tinyurl) or base64-encoded redirect chains
- HTML email with embedded forms or JavaScript
- Password-protected attachments with password in the email body
- Display name spoofing (e.g., CEO name with external email)

**Network Indicators:**
- DNS queries to newly registered domains within minutes of email delivery
- HTTPS connections to domains with certificates issued < 7 days prior
- HTTP POST requests to non-corporate domains shortly after email open
- Data URI or blob URL navigations from email client processes

## Detection Engineering

**SIEM Correlation Rules:**
- Correlate email gateway logs with proxy/DNS logs: flag when a user clicks a link in an email and the destination domain was registered within 30 days
- Alert on email attachments with double extensions (.pdf.exe, .docx.js)
- Flag emails where the sender domain's MX record age is less than 14 days

**Endpoint Telemetry:**
- Monitor Office applications spawning PowerShell, cmd, or wscript
- Detect macro-enabled documents opened from Temp/Downloads directories
- Watch for ISO/IMG mount events followed by executable launches

## Analyst Response Checklist

1. Extract and defang all URLs and attachment hashes
2. Query email gateway for other recipients of the same campaign
3. Check proxy logs for users who clicked through
4. Submit URLs to sandbox and check against threat intel feeds
5. If credentials were harvested, force password resets and revoke active sessions
6. Block sender domain/IP and lookalike variations at the email gateway
""",
    },
    {
        "title": "Spearphishing Indicators and Targeted Attack Detection",
        "tags": ["spearphishing", "initial-access", "T1566.001", "T1566.002", "targeted-attack", "detection"],
        "content": r"""# Spearphishing Indicators and Targeted Attack Detection

## Overview

Spearphishing differs from commodity phishing in its precision targeting and customization. Attackers invest significant effort researching specific individuals or roles, crafting emails that reference real projects, colleagues, or events. Because these messages bypass generic phishing filters, detection requires behavioral analysis and contextual awareness beyond simple signature matching.

## Distinguishing Spearphishing from Commodity Phishing

| Characteristic | Commodity Phishing | Spearphishing |
|---|---|---|
| Targeting | Mass distribution | Specific individuals or small groups |
| Customization | Generic templates | References real names, projects, events |
| Sender identity | Random or bulk domains | Impersonates known contacts or partners |
| Payload | Common malware droppers | Custom implants or zero-day exploits |
| Volume | Thousands of emails | Single digits to low dozens |
| Infrastructure | Shared phishing kits | Dedicated C2 and domains |

## Key Detection Indicators

**Behavioral Anomalies:**
- Email received outside normal communication patterns for the sender relationship
- First-time communication from an external address mimicking an internal contact
- Attachment types unusual for the purported sender's role (e.g., a vendor sending .hta files)
- Requests that bypass normal business processes (e.g., wire transfers without PO references)

**Technical Indicators:**
- Email headers show the message was sent via a different mail infrastructure than the spoofed organization normally uses
- Embedded tracking pixels or unique per-recipient URLs (1x1 images with query string identifiers)
- Attachments with metadata showing different author names than the purported sender
- Macro code that calls WinHTTP, XMLHTTP, or PowerShell download cradles
- Template injection in Office documents (remote template loading via DOTM URLs)

**Contextual Red Flags:**
- References to internal projects that are also mentioned on public LinkedIn posts or press releases
- Timing aligns with known events (board meetings, earnings reports, audits)
- Sender claims to be a new employee, contractor, or recently changed email address
- Email thread hijacking — reply to a real conversation chain obtained from a compromised mailbox

## Detection Engineering Approach

**Email Gateway Rules:**
- Flag first-time external senders whose display names match internal directory entries
- Detect external replies to internal-only threads (In-Reply-To header analysis)
- Alert on Office documents with remote template references in XML relationships

**SIEM Analytics:**
- Correlate HR onboarding data with email sender claims of being new hires
- Track email open events followed by unusual DNS queries or process creation within a 5-minute window
- Alert on emails to executives or finance staff from domains registered < 30 days ago

**User Awareness Integration:**
- Deploy phishing report buttons and track report rates by department
- Correlate reported phishing attempts with SOC-identified campaigns to measure detection gap
- Brief high-risk users (executives, finance, HR) on current spearphishing themes quarterly

## Triage Workflow

1. Analyze email headers to identify true sending infrastructure
2. Check attachment hashes and URLs against threat intelligence platforms
3. Examine document metadata (author, creation date, last modified)
4. Search mailbox for other messages from same sender or infrastructure
5. If payload was executed, pivot to endpoint investigation immediately
6. Document campaign TTPs and update detection rules for future variants
""",
    },
    {
        "title": "Watering Hole Attack Detection and Response",
        "tags": ["watering-hole", "initial-access", "T1189", "strategic-web-compromise", "detection"],
        "content": r"""# Watering Hole Attack Detection and Response

## Overview

Watering hole attacks compromise websites frequently visited by the target population rather than attacking victims directly. By injecting malicious code into a trusted site, attackers exploit the implicit trust users place in familiar resources. These attacks are particularly dangerous because they bypass email security controls entirely and can compromise multiple targets simultaneously.

## MITRE ATT&CK Reference

- **T1189** — Drive-by Compromise
- **T1190** — Exploit Public-Facing Application (to compromise the watering hole site)
- **T1059** — Command and Scripting Interpreter (post-exploitation)

## Attack Mechanics

**Target Profiling**: Adversaries identify websites commonly visited by the target organization or industry — industry forums, professional associations, niche software update portals, regional news sites, or government contractor portals.

**Site Compromise**: The watering hole site is compromised via SQL injection, CMS vulnerabilities, or stolen webmaster credentials. Attackers inject JavaScript that performs visitor profiling before delivering exploits.

**Selective Targeting**: Injected scripts fingerprint visitors by IP range, browser version, installed plugins, or language settings. Only visitors matching the target profile receive the exploit; others see the normal site, making detection significantly harder.

**Exploitation**: Browser exploits or social engineering prompts (fake update dialogs, plugin installation requests) deliver the payload. Modern attacks frequently use browser-in-the-browser techniques or exploit vulnerabilities in PDF renderers and Java applets.

## Detection Strategies

**Network Monitoring:**
- Monitor for known-good websites suddenly generating unusual outbound connections or loading resources from unfamiliar domains
- Detect iframe injections or script includes from third-party domains not historically associated with the site
- Alert on users visiting a site that simultaneously triggers connections to unrelated IP ranges
- Track TLS certificate changes on frequently visited external sites

**Proxy and DNS Analysis:**
- Baseline normal browsing patterns for the organization and flag anomalous redirect chains
- Alert on HTTP responses from trusted sites that contain obfuscated JavaScript not previously observed
- Monitor for DNS queries to new domains immediately following visits to baselined sites

**Endpoint Detection:**
- Watch for browser processes spawning unexpected child processes after visiting external sites
- Detect browser exploit indicators: heap spray patterns, ROP chain artifacts, shellcode execution
- Monitor for file writes to Temp directories by browser processes, especially executables or DLLs
- Track browser plugin installations or updates that occur without user initiation

**Threat Intelligence Integration:**
- Subscribe to industry-specific threat feeds that track compromised websites
- Monitor Certificate Transparency logs for target industry domains
- Cross-reference newly compromised site reports with internal proxy logs

## Response Procedures

1. Identify all users who visited the compromised site during the attack window using proxy logs
2. Check endpoint telemetry for each visitor — process creation, file writes, network connections
3. Isolate endpoints showing post-exploitation indicators
4. Block the compromised site and associated IOCs at proxy and DNS layers
5. Notify the compromised site operator if appropriate
6. Sweep for lateral movement from any compromised endpoints
""",
    },
    {
        "title": "Supply Chain Attack Risk and Detection",
        "tags": ["supply-chain", "initial-access", "T1195", "third-party", "software-supply-chain", "detection"],
        "content": r"""# Supply Chain Attack Risk and Detection

## Overview

Supply chain attacks compromise trusted software vendors, open-source libraries, or managed service providers to gain access to downstream targets. These attacks are exceptionally difficult to detect because the malicious code arrives through trusted update channels with valid signatures. Major incidents like SolarWinds, Kaseya, Codecov, and 3CX demonstrate the devastating scope of this vector.

## MITRE ATT&CK Reference

- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1199** — Trusted Relationship

## Attack Categories

**Software Update Poisoning**: Adversaries compromise the build pipeline or update servers of a legitimate vendor. Trojanized updates are signed with valid certificates and distributed through normal channels.

**Open-Source Dependency Attacks**: Malicious packages published to npm, PyPI, or NuGet with names similar to popular packages (typosquatting) or injected into legitimate packages via compromised maintainer accounts.

**MSP/Cloud Provider Compromise**: Attackers target managed service providers who have privileged access to customer environments, using a single compromise to pivot into hundreds of downstream organizations.

**Hardware Supply Chain**: Pre-installed backdoors in firmware, network appliances, or peripheral devices. Less common but extremely difficult to detect.

## Detection Indicators

**Software Update Anomalies:**
- Vendor software making unexpected network connections to non-vendor infrastructure post-update
- Increased process spawning or new child processes from previously stable applications
- File integrity monitoring alerts on vendor binaries that change outside announced update windows
- DLL or shared library modifications in vendor application directories
- New scheduled tasks or services registered by vendor software update processes

**Dependency Analysis:**
- New transitive dependencies appearing in build manifests without developer action
- Dependency packages with creation dates that do not match their claimed version history
- Packages requesting permissions or making network calls unusual for their stated purpose
- Build output hash mismatches between CI/CD pipeline and developer workstations

**Network Indicators:**
- DNS queries or HTTPS connections from vendor software to domains unrelated to the vendor
- Beaconing patterns from applications that previously had no outbound connectivity
- Data exfiltration from vendor tools — unusual upload volume or connections to cloud storage APIs
- TLS connections where the server certificate does not match the expected vendor domain

## Detection Engineering

**SIEM Rules:**
- Alert on vendor application processes making outbound connections to non-vendor domains
- Correlate software deployment events with subsequent anomalous behavior on updated hosts
- Monitor for new service installations or scheduled tasks within 24 hours of software updates

**Endpoint Controls:**
- Maintain application whitelisting and behavioral baselines for vendor software
- Deploy file integrity monitoring on critical vendor application directories
- Log all DLL loads by vendor applications and alert on unsigned or unexpected modules

**Supply Chain Governance:**
- Inventory all third-party software and dependencies with a Software Bill of Materials (SBOM)
- Stagger update rollouts — deploy to canary systems first and monitor for 24-48 hours
- Verify update hashes against vendor-published checksums via out-of-band channels
- Monitor vendor security advisories and threat intelligence for supply chain compromises

## Analyst Response

1. Identify the scope of the compromised component across the environment
2. Determine which version introduced the malicious code
3. Isolate affected systems and block associated C2 infrastructure
4. Roll back to last known-good version if available
5. Audit actions performed by the compromised software (data access, credential use, lateral movement)
6. Engage vendor and share IOCs with industry ISACs
""",
    },
    {
        "title": "Credential Stuffing and Password Spray Detection",
        "tags": ["credential-stuffing", "password-spray", "T1110.003", "T1110.004", "brute-force", "detection"],
        "content": r"""# Credential Stuffing and Password Spray Detection

## Overview

Credential stuffing uses stolen username-password pairs from data breaches to authenticate against target services, exploiting password reuse. Password spraying tries a small number of commonly used passwords against many accounts simultaneously, staying below lockout thresholds. Both attacks target identity systems and can lead to full environment compromise when they succeed against privileged accounts.

## MITRE ATT&CK Reference

- **T1110.003** — Brute Force: Password Spraying
- **T1110.004** — Brute Force: Credential Stuffing
- **T1078** — Valid Accounts (post-compromise)

## Attack Characteristics

**Credential Stuffing:**
- Automated tools test thousands to millions of credential pairs from breach dumps
- Targets externally facing services: VPN, OWA, Office 365, SSO portals, VDI
- Uses residential proxies and rotating IPs to evade IP-based rate limiting
- Success rates typically 0.1-2%, but even low rates yield valuable footholds
- Tools: SentryMBA, OpenBullet, custom Python scripts with headless browsers

**Password Spraying:**
- Targets all or most accounts in a domain with 1-3 passwords per attempt cycle
- Common passwords tried: Season+Year (Winter2026!), Company+123, Welcome1, P@ssw0rd
- Cycles are spaced 30-60 minutes apart to avoid lockout policies
- Targets: ADFS, Azure AD, OWA, LDAP, Kerberos pre-authentication
- Tools: Spray, Ruler, MailSniper, custom scripts

## Detection Strategies

**Authentication Log Analysis:**
- **Credential Stuffing**: High volume of failed logins across many different usernames from single or clustered IPs. Success rate is low but non-zero — look for a burst of failures followed by one or two successes.
- **Password Spraying**: Many accounts experiencing exactly one failure within the same time window. No single account triggers lockout, but aggregate failure count across the directory is abnormal.

**Key Log Sources:**
- Azure AD Sign-in Logs (ResultType 50126 = invalid password)
- Windows Security Event ID 4625 (failed logon), sub-status 0xC000006A (bad password)
- ADFS Event ID 411 (token request failed)
- VPN concentrator authentication logs
- Web application firewall (WAF) logs for login endpoints

**Detection Rules:**

*Credential Stuffing:*
- More than 50 unique usernames with failed authentication from the same IP within 10 minutes
- A single IP authenticating successfully to more than 3 distinct accounts within 1 hour
- Authentication attempts from IPs flagged as known residential proxies or VPN exit nodes

*Password Spraying:*
- More than 20 accounts experiencing exactly one failed login within a 30-minute window
- Failed authentication events using identical User-Agent strings across many accounts
- Authentication failures distributed evenly across accounts rather than concentrated on one

**Behavioral Analytics:**
- Track per-user authentication velocity baselines and alert on statistical deviations
- Monitor for successful logins from geographically improbable locations
- Detect impossible travel — authentication from two distant locations within minutes
- Flag logins from Tor exit nodes or known anonymizing infrastructure

## Response Procedures

1. Correlate failed and successful authentication attempts to identify compromised accounts
2. Force password resets for all accounts that successfully authenticated during the attack window
3. Check compromised accounts for mailbox rule changes, MFA registration modifications, or OAuth app grants
4. Block attacking IP ranges and associated User-Agent patterns
5. Verify MFA is enforced on all external-facing authentication endpoints
6. Query Have I Been Pwned API for organizational email addresses to assess breach exposure
""",
    },
    {
        "title": "Business Email Compromise Indicators and Detection",
        "tags": ["BEC", "initial-access", "T1534", "T1566.002", "wire-fraud", "email-compromise", "detection"],
        "content": r"""# Business Email Compromise Indicators and Detection

## Overview

Business Email Compromise (BEC) causes more financial damage than any other cybercrime category, with the FBI reporting billions in annual losses. Unlike malware-based attacks, BEC relies on social engineering and account takeover to trick employees into transferring funds, redirecting payments, or disclosing sensitive information. Detection requires a combination of email analysis, authentication monitoring, and business process awareness.

## MITRE ATT&CK Reference

- **T1534** — Internal Spearphishing
- **T1566.002** — Phishing: Spearphishing Link (for credential harvesting leading to ATO)
- **T1078** — Valid Accounts (compromised mailbox used for BEC)
- **T1114** — Email Collection

## BEC Variants

**CEO Fraud**: Impersonates an executive and requests urgent wire transfer to a "new vendor" or "confidential acquisition." Targets accounts payable or finance staff.

**Vendor Impersonation**: Compromises or spoofs a real vendor's email to send fraudulent invoices with updated payment details. Often follows reconnaissance of the billing cycle.

**Account Takeover (ATO) BEC**: Attacker compromises a legitimate mailbox via credential phishing, then uses it to send internal requests. Passes all email authentication checks because the sending domain is genuine.

**Payroll Diversion**: Impersonates an employee and requests HR or payroll to change direct deposit bank information.

**Data Theft**: Targets HR for W-2/tax records, PII, or employee directories to enable further social engineering or identity fraud.

## Detection Indicators

**Email-Level Indicators:**
- Urgent financial requests sent near end of business day or on Friday afternoons
- Executive impersonation with external reply-to addresses
- Display name matches internal executive but email domain is external
- Email thread starters that mimic forwarded chains ("FW: RE: RE:") to create false legitimacy
- Requests to bypass standard approval or verification processes
- Language patterns: "keep this confidential," "handle this personally," "time-sensitive"

**Account Takeover Indicators:**
- New inbox rules created (auto-delete, auto-forward to external addresses)
- Mail forwarding configured to external addresses
- OAuth application consent grants for mail-reading permissions
- Login from unusual location followed by mailbox rule changes
- Sent items or deleted items folder manipulation to hide sent BEC emails
- MFA method changes (new phone number registered)

**Network and Log Indicators:**
- Successful authentication from IP addresses associated with VPN services or hosting providers
- Concurrent sessions from geographically distant locations
- Exchange/O365 audit logs showing MailItemsAccessed or Send-As operations from new IPs
- Bulk email reads via IMAP/POP3 or Graph API from unfamiliar clients

## Detection Engineering

**Email Gateway Rules:**
- Flag external emails where the display name matches a C-suite executive
- Alert on emails containing wire transfer keywords (ABA, SWIFT, routing number, beneficiary) from first-time external senders
- Detect emails with reply-to domains that differ from the sender domain

**SIEM Correlation:**
- Alert when new inbox rules (forwarding or auto-delete) are created after a login from a new IP
- Correlate password reset or MFA change events with subsequent unusual email activity
- Monitor for OAuth consent grants to third-party mail applications

**Business Process Controls:**
- Require out-of-band verification (phone call to known number) for payment changes > threshold
- Implement dual-approval for wire transfers and vendor banking detail changes
- Maintain a verified vendor contact database independent of email communications

## Triage and Response

1. Determine whether the BEC email originated from an impersonated external address or a compromised internal mailbox
2. If internal mailbox compromise: revoke sessions, reset password, remove malicious inbox rules and forwarding, audit sent messages
3. Search for additional recipients of BEC messages from the same sender or infrastructure
4. If funds were transferred: immediately contact the receiving bank to request a hold or recall
5. File an IC3 complaint and notify legal and compliance teams
6. Update email filtering rules to catch identified BEC patterns and sender infrastructure
""",
    },
]

# ============================================================
# COLLECTION 2: PRIVILEGE ESCALATION DETECTION
# ============================================================

PRIVESC = [
    {
        "title": "Windows Privilege Escalation Indicators — Event IDs and Log Analysis",
        "tags": ["windows", "privilege-escalation", "T1068", "event-log", "detection", "sysmon"],
        "content": r"""# Windows Privilege Escalation Indicators — Event IDs and Log Analysis

## Overview

Privilege escalation on Windows systems leaves traces across Security, System, Sysmon, and PowerShell logs. Knowing which event IDs correspond to escalation techniques enables SOC analysts to build targeted detections and rapidly triage alerts. This article maps common Windows privilege escalation methods to their observable log artifacts.

## Critical Event IDs for Privilege Escalation Detection

**Security Log:**
- **4672** — Special privileges assigned to new logon. Fires when an account receives sensitive privileges (SeDebugPrivilege, SeTcbPrivilege, SeAssignPrimaryTokenPrivilege). Alert when non-admin accounts receive these privileges.
- **4688** — Process creation. With command-line logging enabled, reveals suspicious process chains such as services spawning cmd.exe or PowerShell. Look for `TokenElevationType` of `%%1937` (full token) from unexpected parent processes.
- **4697** — A service was installed in the system. New service creation is a common persistence and escalation path.
- **4624** — Successful logon. Type 2 (interactive) or Type 10 (RemoteInteractive) from service accounts is anomalous.

**Sysmon:**
- **Event ID 1** — Process creation with full command line, parent process, and integrity level. Detect escalation by monitoring for processes running at High/System integrity spawned by Medium-integrity parents.
- **Event ID 8** — CreateRemoteThread. Detects process injection used for privilege escalation (injecting into SYSTEM processes).
- **Event ID 10** — ProcessAccess. Alerts on processes requesting PROCESS_ALL_ACCESS to lsass.exe or other privileged processes.
- **Event ID 13** — Registry value set. Monitors modifications to service image paths (for service binary hijacking) and IFEO (Image File Execution Options) entries.
- **Event ID 25** — Process tampering. Detects process hollowing and herpaderping techniques.

**PowerShell Logging:**
- **4104** — Script block logging captures the full text of executed PowerShell scripts, revealing privilege escalation commands.
- **4103** — Module logging captures pipeline execution details.

## Common Escalation Technique Detection

**Service Binary Hijacking:**
- Sysmon Event 13: Registry modification to `HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath`
- Security 4697: New service installed pointing to writable directory
- Process creation from `C:\ProgramData`, `C:\Temp`, or user-writable `Program Files` subdirectories

**Token Manipulation:**
- Security 4672 for unexpected accounts receiving SeImpersonatePrivilege
- Sysmon Event 1 showing processes like `JuicyPotato`, `PrintSpoofer`, `GodPotato`, or `RoguePotato` patterns in command lines
- Named pipe creation and impersonation events

**Unquoted Service Paths:**
- Service paths without quotes and containing spaces allow DLL planting
- Sysmon Event 11 (file creation) in directories like `C:\Program.exe` or `C:\Program Files\Vulnerable\` where unexpected executables appear

**Scheduled Task Abuse:**
- Security 4698: A scheduled task was created (watch for tasks running as SYSTEM)
- Sysmon Event 1: `schtasks.exe` with `/ru SYSTEM` parameter
- Task XML files written to `C:\Windows\System32\Tasks\` by non-administrative processes

## Detection Engineering Tips

- Enable command-line process creation auditing via GPO (Administrative Templates > System > Audit Process Creation)
- Deploy Sysmon with a well-tuned configuration (SwiftOnSecurity or Olaf Hartong configs as baselines)
- Baseline which accounts normally receive Event 4672 and alert on new entries
- Monitor for processes with SYSTEM integrity spawned by user-level parent processes
- Track service installations (4697) and correlate with change management tickets
""",
    },
    {
        "title": "Linux Privilege Escalation Paths and Detection",
        "tags": ["linux", "privilege-escalation", "T1548", "suid", "sudo", "detection", "auditd"],
        "content": r"""# Linux Privilege Escalation Paths and Detection

## Overview

Linux privilege escalation exploits misconfigurations in file permissions, SUID binaries, sudo rules, kernel vulnerabilities, and service configurations to elevate from standard user to root. Effective detection relies on auditd logging, file integrity monitoring, and behavioral baselines for privileged operations.

## Common Escalation Vectors and Their Indicators

**SUID/SGID Binary Abuse:**

SUID binaries execute with the file owner's privileges (typically root). Attackers search for exploitable SUID binaries using `find / -perm -4000`.

Detection:
- Audit SUID binary execution via auditd rules: monitor execve syscalls for known-abusable SUID binaries
- File integrity monitoring: alert on new SUID/SGID bits set on files (especially in non-standard locations)
- Baseline expected SUID binaries and alert on additions. GTFOBins documents exploitable binaries
- Key auditd rule: `-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k privesc`

**Sudo Misconfigurations:**

Overly permissive sudo rules (NOPASSWD on editors, interpreters, or package managers) allow trivial escalation.

Detection:
- Monitor `/var/log/auth.log` or `/var/log/secure` for sudo commands by unexpected users
- Alert on sudo rule modifications (`/etc/sudoers`, `/etc/sudoers.d/`)
- Detect `sudo -l` enumeration as a reconnaissance indicator
- Watch for sudo invocations of editors (vim, nano, less), interpreters (python, perl, ruby), or file managers

**Kernel Exploits:**

Unpatched kernels are vulnerable to local privilege escalation (DirtyPipe, DirtyCow, Polkit, etc.).

Detection:
- Monitor for compilation activity by non-developer users: `gcc`, `cc`, `make` invocations
- Detect file creation in `/tmp` or `/dev/shm` followed by immediate execution
- Watch for processes that transition from user to root UID without sudo/su involvement
- Track `dmesg` or kernel log entries indicating exploitation attempts (segfaults in privileged processes)

**Cron Job Exploitation:**

Writable scripts referenced by root cron jobs allow code execution as root.

Detection:
- File integrity monitoring on all scripts referenced in `/etc/crontab`, `/etc/cron.d/`, and root's crontab
- Alert on modifications to cron-referenced scripts by non-root users
- Monitor `/var/log/cron` for unusual job execution patterns

**Capabilities Abuse:**

Linux capabilities grant specific root-like powers to binaries without full SUID.

Detection:
- Audit `cap_set` syscalls to detect capability assignment
- Baseline binaries with capabilities via `getcap -r /` and alert on changes
- Monitor execution of binaries with dangerous capabilities: `cap_setuid`, `cap_dac_override`, `cap_sys_admin`

**Writable /etc/passwd or /etc/shadow:**

Misconfigured permissions allow direct password modification or user addition.

Detection:
- File integrity monitoring on `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Auditd watch rules: `-w /etc/passwd -p wa -k identity`
- Alert on `useradd`, `usermod`, or direct file edits by non-administrative processes

## Auditd Configuration for Escalation Detection

Key audit rules to deploy:
- Monitor privilege-related syscalls: `setuid`, `setgid`, `setreuid`, `setresuid`
- Watch identity files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/group`
- Track privileged command execution: `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/pkexec`
- Log all process creation by root where audit UID indicates a non-root origin user

## Analyst Workflow

1. Identify the escalation method from log indicators
2. Determine the initial access point (how did the attacker get user-level access)
3. Check for persistence mechanisms installed after escalation (SSH keys, cron jobs, new users)
4. Audit the misconfiguration that enabled escalation and remediate
5. Scan environment for identical misconfigurations on other hosts
""",
    },
    {
        "title": "Kerberoasting Detection and Response",
        "tags": ["kerberoasting", "T1558.003", "active-directory", "credential-access", "detection"],
        "content": r"""# Kerberoasting Detection and Response

## Overview

Kerberoasting is an Active Directory attack that extracts service account Kerberos ticket-granting service (TGS) tickets, which can be cracked offline to recover plaintext passwords. Any authenticated domain user can request TGS tickets for service accounts with Service Principal Names (SPNs), making this attack trivially easy to execute and difficult to prevent without architectural changes.

## MITRE ATT&CK Reference

- **T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting

## Attack Mechanics

1. Attacker enumerates accounts with SPNs registered in Active Directory (any domain user can perform this LDAP query)
2. TGS tickets are requested for target SPNs using normal Kerberos protocol operations
3. Tickets are encrypted with the service account's NTLM hash
4. Attacker extracts tickets and performs offline brute-force/dictionary attacks
5. Cracked passwords provide access to the service account's privileges, which often include domain admin or database access

## Detection Strategies

**Windows Security Event Log:**
- **Event ID 4769** — Kerberos Service Ticket Operations. Key fields:
  - `Ticket Encryption Type`: 0x17 (RC4-HMAC) is a strong indicator when environment uses AES
  - `Service Name`: target SPN being requested
  - `Client Address`: source of the request
  - `Ticket Options`: 0x40810000 is common in Kerberoasting tools

**Detection Logic:**
- Alert when a single user account requests TGS tickets for multiple SPNs in a short timeframe (> 5 unique SPNs in 10 minutes)
- Flag any TGS request using RC4 encryption (0x17) when the environment enforces AES (0x12)
- Detect known Kerberoasting tools by process name or command-line patterns in Sysmon logs: `Rubeus.exe kerberoast`, `Invoke-Kerberoast`, `GetUserSPNs.py`
- Correlate Event 4769 with process creation events to identify the requesting process

**Honeypot SPNs:**
- Create decoy service accounts with SPNs that no legitimate service uses
- Set strong passwords (>30 chars) so they cannot be cracked
- Any TGS request for honeypot SPNs is a guaranteed indicator of Kerberoasting
- Configure real-time alerting for Event 4769 targeting these accounts

**Network Detection:**
- Monitor for high-volume Kerberos TGS-REQ traffic from a single workstation
- Detect ldap queries filtering on `servicePrincipalName` attribute from non-administrative hosts

## Mitigation and Hardening

- Use Group Managed Service Accounts (gMSA) with 120-character auto-rotated passwords
- Enforce AES-only encryption for service accounts (disable RC4 support)
- Set service account passwords to 25+ character random strings
- Regularly audit accounts with SPNs and remove unnecessary ones
- Implement a PAM solution for service account password rotation

## Response Workflow

1. Identify which accounts had TGS tickets requested during the Kerberoasting event
2. Determine if any targeted accounts have weak or old passwords
3. Immediately rotate passwords for all targeted service accounts
4. Investigate the source account and workstation for additional compromise indicators
5. Check for lateral movement using any potentially compromised service accounts
6. Review and reduce SPN assignments to minimize the Kerberoasting attack surface
""",
    },
    {
        "title": "Pass-the-Hash Detection Indicators",
        "tags": ["pass-the-hash", "T1550.002", "credential-access", "lateral-movement", "NTLM", "detection"],
        "content": r"""# Pass-the-Hash Detection Indicators

## Overview

Pass-the-Hash (PtH) allows attackers to authenticate to remote systems using stolen NTLM password hashes without knowing the plaintext password. This technique bypasses the need for password cracking and is a cornerstone of Active Directory lateral movement. Detection focuses on identifying anomalous NTLM authentication patterns and correlating them with credential theft indicators.

## MITRE ATT&CK Reference

- **T1550.002** — Use Alternate Authentication Material: Pass the Hash

## How Pass-the-Hash Works

1. Attacker obtains NTLM hashes from memory (lsass.exe), SAM database, or NTDS.dit
2. Hash is injected into a new logon session using tools that create a process with the stolen credentials
3. The process authenticates to remote resources using NTLM challenge-response with the stolen hash
4. No plaintext password or password cracking is required

## Detection Indicators

**Windows Security Event Logs:**
- **Event 4624 (Logon)**: Logon Type 9 (NewCredentials) with the `Logon Process` field showing "seclogo" — this pattern is characteristic of PtH via common tooling
- **Event 4624**: Network logon (Type 3) where the source account is a local administrator and the `Authentication Package` is NTLM (not Kerberos)
- **Event 4776**: NTLM credential validation. Watch for NTLM authentications from accounts that typically use Kerberos
- **Event 4625**: Failed logon with NTLM from accounts that should be using Kerberos indicates PtH attempts

**Behavioral Indicators:**
- Local administrator accounts authenticating to remote systems via NTLM (these accounts should rarely do so)
- NTLM authentication from workstations where Kerberos should be available and preferred
- Logon events where the account name and source workstation indicate a mismatch (user from Workstation A, authenticating as user typically on Workstation B)
- Authentication to multiple systems in rapid succession from a single source using NTLM

**Endpoint Indicators (credential theft precursor):**
- Sysmon Event 10: Process accessing lsass.exe with `PROCESS_VM_READ` permission
- Security Event 4656/4663: Access attempts to lsass.exe memory
- Sysmon Event 1: Process creation of known credential dumping tools (by hash or command-line patterns)
- Sysmon Event 7: Unsigned DLLs loaded into lsass.exe (SSP injection)

**Network Indicators:**
- NTLM authentication traffic where Kerberos is expected (environment should prefer Kerberos)
- SMB sessions using NTLM to systems that the source account does not normally access
- High volume of NTLM authentications from a single source to multiple destinations in a short time

## Detection Engineering

**SIEM Rules:**
- Correlate Event 4624 Type 9 + seclogo with Event 10 (lsass access) within a time window on the same host
- Flag NTLM network logons from accounts that have authenticated exclusively via Kerberos for the past 30 days
- Alert on NTLM authentication from Domain Admin accounts to workstations (should use Kerberos to servers)
- Track unique destination count for NTLM network logons per source account per hour

**Baseline and Anomaly:**
- Profile normal NTLM usage patterns per account and host
- Many environments have legitimate NTLM usage — detection requires baselining to reduce false positives
- Focus high-fidelity alerting on admin accounts, domain controllers, and sensitive servers

## Mitigation

- Enable Credential Guard on Windows 10/11 and Server 2016+ to protect lsass
- Enforce LSA protection (RunAsPPL) to prevent credential dumping from lsass
- Restrict NTLM authentication via GPO where possible (audit first, then restrict)
- Deploy Local Administrator Password Solution (LAPS) to prevent shared local admin hashes
- Implement network segmentation to limit the reach of compromised credentials
""",
    },
    {
        "title": "Credential Theft and Dumping Detection",
        "tags": ["credential-dumping", "T1003", "lsass", "mimikatz", "SAM", "NTDS", "detection"],
        "content": r"""# Credential Theft and Dumping Detection

## Overview

Credential dumping extracts authentication material — passwords, hashes, Kerberos tickets, and tokens — from operating system memory, files, and directories. It is a pivotal post-exploitation step that enables lateral movement and privilege escalation. Detecting credential theft early is critical because it precedes nearly all subsequent attack phases.

## MITRE ATT&CK Reference

- **T1003.001** — OS Credential Dumping: LSASS Memory
- **T1003.002** — OS Credential Dumping: Security Account Manager (SAM)
- **T1003.003** — OS Credential Dumping: NTDS
- **T1003.004** — OS Credential Dumping: LSA Secrets
- **T1003.006** — OS Credential Dumping: DCSync

## Credential Theft Methods and Detection

**LSASS Memory Dumping:**
The most common credential theft technique targets the lsass.exe process, which holds plaintext passwords, NTLM hashes, and Kerberos tickets in memory.

Detection:
- Sysmon Event 10 (ProcessAccess): Any process accessing lsass.exe with `GrantedAccess` values of 0x1010, 0x1FFFFF, or 0x1410 — especially from unsigned or unexpected binaries
- Sysmon Event 1: Processes like `procdump.exe`, `comsvcs.dll` (via rundll32 MiniDump), `sqldumper.exe`, or `createdump.exe` targeting lsass
- Windows Security Event 4656: SAM or SECURITY hive access
- Sysmon Event 7: Unknown or unsigned DLLs loaded into lsass.exe address space (SSP loading)
- Sysmon Event 11: Dump files written to disk with lsass in the filename

**SAM Database Extraction:**
The SAM database stores local account hashes. Extracting it requires SYSTEM privilege.

Detection:
- Registry access to `HKLM\SAM` or `HKLM\SECURITY` by non-SYSTEM processes
- `reg.exe save HKLM\SAM` or `reg save HKLM\SECURITY` command-line patterns
- Volume Shadow Copy creation (`vssadmin create shadow`) followed by file access to SAM/SYSTEM hives
- Sysmon Event 11: Files written with names matching SAM, SYSTEM, or SECURITY in temp directories

**NTDS.dit Extraction:**
The NTDS.dit file on domain controllers contains all domain account hashes.

Detection:
- `ntdsutil` or `vssadmin` execution on domain controllers outside maintenance windows
- Sysmon Event 1: `ntdsutil.exe` with `activate instance ntds` or `ifm` in command line
- Volume Shadow Copy creation on DCs followed by file copy operations
- Network transfer of large files (>10MB) from domain controllers to workstations
- Event 4662: Object access in AD for replication operations from non-DC sources (DCSync indicator)

**DCSync Attack:**
Simulates domain controller replication to extract password hashes remotely.

Detection:
- Security Event 4662: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights exercised by non-domain-controller accounts
- Network detection: DRSUAPI RPC calls from workstations to domain controllers
- Alert when any account other than legitimate DCs performs directory replication

## High-Fidelity Detection Rules

1. Any non-standard process accessing lsass.exe memory (exclude known AV/EDR by hash)
2. `comsvcs.dll` loaded via rundll32 with MiniDump export — almost always credential theft
3. Volume Shadow Copy creation on domain controllers outside change windows
4. DS-Replication requests from non-DC machine accounts
5. Registry save commands targeting SAM or SECURITY hives

## Response Procedures

1. Immediately isolate the affected host to prevent lateral movement with stolen credentials
2. Identify which credential theft method was used and scope the compromised material
3. If domain admin hashes were compromised: initiate full domain password reset (krbtgt twice, all admin accounts)
4. If NTDS.dit was extracted: assume all domain passwords compromised — enterprise-wide reset required
5. Review access logs for any use of compromised credentials prior to detection
6. Deploy additional monitoring: Credential Guard, LSA protection, and enhanced lsass access auditing
""",
    },
    {
        "title": "DLL Hijacking and Search Order Exploitation Detection",
        "tags": ["DLL-hijacking", "T1574.001", "persistence", "privilege-escalation", "detection"],
        "content": r"""# DLL Hijacking and Search Order Exploitation Detection

## Overview

DLL hijacking exploits the Windows DLL search order to trick legitimate applications into loading malicious dynamic link libraries. When a program does not specify a full path for a DLL it needs, Windows searches a predictable sequence of directories. Attackers place a malicious DLL earlier in the search path so it loads instead of the legitimate one, achieving code execution in the context of the vulnerable application — often with elevated privileges.

## MITRE ATT&CK Reference

- **T1574.001** — Hijack Execution Flow: DLL Search Order Hijacking
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading

## DLL Search Order

When an application loads a DLL without specifying a full path, Windows searches in this order:
1. The directory from which the application was loaded
2. The system directory (C:\Windows\System32)
3. The 16-bit system directory (C:\Windows\System)
4. The Windows directory (C:\Windows)
5. The current working directory
6. Directories listed in PATH environment variable

If an attacker can write to any directory searched before the legitimate DLL location, they can hijack the load.

## Attack Variants

**Search Order Hijacking**: Placing a malicious DLL in the application directory when the legitimate DLL resides in System32. The application directory is searched first, so the malicious DLL loads before the legitimate one.

**DLL Side-Loading**: Exploiting a legitimate signed application to load a malicious DLL. The signed application provides cover — it passes application whitelisting and appears legitimate in process listings.

**Phantom DLL Hijacking**: Targeting DLLs that applications try to load but that do not exist on the system. No legitimate DLL is replaced, making detection based on file modification ineffective.

**PATH Directory Hijacking**: Placing malicious DLLs in directories listed in the system PATH that are searched before the legitimate DLL's location, particularly writable directories early in PATH.

## Detection Strategies

**File System Monitoring:**
- Sysmon Event 11 (FileCreate): DLL files created in application directories, especially for high-privilege applications (services, system utilities)
- Alert on DLL files appearing in directories that normally contain only executables (e.g., `C:\Program Files\<app>\` gaining unexpected DLLs)
- File integrity monitoring on system directories: new or modified DLLs in System32, SysWOW64, or Windows directories

**DLL Load Monitoring:**
- Sysmon Event 7 (ImageLoaded): DLL loaded from an unexpected path — e.g., a system DLL loading from an application directory instead of System32
- Alert on unsigned DLLs loaded by signed applications
- Detect DLL loads from user-writable directories (Temp, Downloads, AppData) by system services
- Compare loaded DLL paths against a known-good baseline

**Process Behavior:**
- Applications suddenly making network connections they historically have not (DLL injected network functionality)
- Signed applications spawning unexpected child processes (the hijacked DLL executing commands)
- Increased CPU or memory usage in previously stable applications

**Proactive Hunting:**
- Enumerate writable directories in system PATH and check for DLL files that share names with system DLLs
- Audit application directories for DLLs that duplicate names found in System32
- Check for applications loading DLLs without full path specification (compile a list of vulnerable applications)
- Compare DLL file versions and signatures against known-good copies

## Response and Remediation

1. Identify the malicious DLL and the application loading it
2. Determine if the application runs with elevated privileges (impacts severity assessment)
3. Check if the DLL has established persistence (will reload on reboot)
4. Remove the malicious DLL and verify the legitimate DLL is intact
5. Audit file system permissions on application directories and PATH directories
6. Apply vendor patches that add full-path DLL loading or implement DLL manifest files
""",
    },
    {
        "title": "UAC Bypass Detection Strategies",
        "tags": ["UAC-bypass", "T1548.002", "privilege-escalation", "windows", "detection"],
        "content": r"""# UAC Bypass Detection Strategies

## Overview

User Account Control (UAC) is a Windows security mechanism that prompts for consent or credentials when actions requiring administrator privileges are attempted. UAC bypass techniques allow attackers to escalate from a medium-integrity process to a high-integrity (administrator) process without triggering the UAC prompt. Dozens of bypass methods exist, exploiting auto-elevating binaries, COM objects, and environment variable manipulation.

## MITRE ATT&CK Reference

- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control

## Common UAC Bypass Categories

**Auto-Elevating Binary Abuse:**
Certain Microsoft-signed binaries are configured to auto-elevate without a UAC prompt. Attackers manipulate the execution context of these binaries to run arbitrary code at high integrity.

Common targets:
- `fodhelper.exe` — manipulates HKCU registry to hijack the ms-settings protocol handler
- `computerdefaults.exe` — similar registry-based hijack
- `sdclt.exe` — backup utility that reads registry keys controllable by the user
- `eventvwr.exe` — Event Viewer mmc snap-in with registry-based bypass
- `cmstp.exe` — Connection Manager with INF file abuse

**COM Object Hijacking:**
- Modifying HKCU COM registration to redirect auto-elevated COM objects
- `ICMLuaUtil` interface abuse for elevation
- DLL path hijacking in COM server paths

**Environment Variable Manipulation:**
- Setting `windir` or `systemroot` environment variables in HKCU to redirect auto-elevated processes to attacker-controlled directories
- `Disk Cleanup` (cleanmgr.exe) environment variable abuse
- Mock trusted directory creation (trailing spaces: `C:\Windows \System32\`)

## Detection Strategies

**Registry Monitoring:**
- Sysmon Event 13 (RegistrySetValue): Modifications to `HKCU\Software\Classes\ms-settings\shell\open\command`
- Registry changes to `HKCU\Software\Classes\mscfile\shell\open\command`
- HKCU COM object registrations that override HKLM entries for auto-elevating CLSIDs
- `HKCU\Environment` modifications to `windir` or `systemroot` variables
- Any `HKCU\Software\Classes\CLSID\` entry creation that matches known auto-elevated COM objects

**Process Monitoring:**
- Sysmon Event 1: Auto-elevating binaries (`fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`, `eventvwr.exe`, `cmstp.exe`) spawning unexpected child processes
- Medium-integrity process spawning a high-integrity child without a corresponding UAC prompt (Event 4688 with `TokenElevationType`)
- `cmstp.exe` executing with `/au` flag or loading a user-supplied INF file
- `mshta.exe` or `wscript.exe` spawned by auto-elevating binaries
- Processes creating directories with trailing spaces mimicking trusted paths

**Integrity Level Transitions:**
- Monitor for processes that transition from medium to high integrity without 4688 events showing the consent UI (`consent.exe`)
- Track high-integrity process creation where the parent process is at medium integrity
- Alert on high-integrity processes whose parent is not `consent.exe` or `svchost.exe` (AppInfo service)

**Known Tool Signatures:**
- Command-line patterns associated with UACME or other bypass frameworks
- PowerShell scripts containing known bypass function names
- Registry modifications in the patterns documented by the UACME project

## Detection Engineering Tips

- Focus on the gap: a process transitions to high integrity without `consent.exe` being the parent
- Registry monitoring is the highest-fidelity signal — most UAC bypasses require HKCU modifications
- Combine registry event + auto-elevating binary execution + child process creation in a three-event correlation rule
- Auto-elevating binaries launching cmd, powershell, mshta, wscript, or cscript are almost always malicious

## Response Procedures

1. Identify the specific UAC bypass technique from registry and process telemetry
2. Determine what the attacker executed at high integrity after the bypass
3. Check for persistence mechanisms installed with elevated privileges
4. Review the initial access method that placed the attacker on the endpoint
5. Assess whether Credential Guard, LSA protection, or other post-escalation protections were bypassed
6. Consider enforcing UAC "Always Notify" level and restricting auto-elevation via Group Policy
""",
    },
]

# ============================================================
# COLLECTION 3: LATERAL MOVEMENT & PERSISTENCE
# ============================================================

LATERAL_MOVEMENT = [
    {
        "title": "SMB Lateral Movement Detection",
        "tags": ["SMB", "lateral-movement", "T1021.002", "T1570", "PsExec", "detection"],
        "content": r"""# SMB Lateral Movement Detection

## Overview

Server Message Block (SMB) is the primary file sharing protocol in Windows environments and the most frequently abused protocol for lateral movement. Attackers use SMB to copy payloads to remote systems, execute commands via named pipes, and access administrative shares. Detecting malicious SMB activity requires distinguishing attacker patterns from legitimate administrative operations.

## MITRE ATT&CK Reference

- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1570** — Lateral Tool Transfer
- **T1080** — Taint Shared Content

## Common SMB Lateral Movement Techniques

**PsExec and Variants:**
The original PsExec copies an executable to the target's ADMIN$ share, creates a service to run it, and communicates over named pipes. Impacket's `psexec.py`, `smbexec.py`, and Metasploit's PsExec module follow similar patterns with variations.

**SMB File Copy + Remote Execution:**
Attackers copy tools to C$ or ADMIN$ shares, then trigger execution via WMI, scheduled tasks, or service creation.

**Pass-the-Hash over SMB:**
NTLM hashes are used to authenticate to SMB shares without plaintext passwords, enabling file access and remote execution.

## Detection Indicators

**Network Indicators:**
- SMB connections to ADMIN$ or C$ shares from workstations (workstation-to-workstation SMB is unusual in most environments)
- SMB connections from a single source to multiple destinations in rapid succession
- Named pipe creation: `\pipe\svcctl` (service control), `\pipe\atsvc` (scheduled tasks), `\pipe\PSEXESVC` (PsExec)
- Large file transfers over SMB to administrative shares from non-admin workstations

**Windows Event Log Indicators:**
- **Security Event 5140/5145**: Share access to ADMIN$ or C$ — track which accounts access admin shares and from where
- **Security Event 4697**: Service installation — PsExec creates a service named PSEXESVC (default) or a random name
- **Security Event 7045** (System log): New service installed with a binary path pointing to ADMIN$ or a temp directory
- **Security Event 4624**: Network logon (Type 3) from workstations to other workstations, especially using admin credentials
- **Security Event 4648**: Explicit credential logon — indicates `runas` or alternate credential usage

**Sysmon Indicators:**
- Event 18 (PipeConnected): Connection to named pipes associated with remote execution
- Event 1: Process creation from paths like `C:\Windows\PSEXESVC.exe` or random names in `C:\Windows\`
- Event 11: File creation on ADMIN$ share path (`C:\Windows\`) by SMB connections
- Event 3: Network connection from newly created services to external C2 infrastructure

## Detection Engineering

**High-Fidelity Rules:**
- Workstation-to-workstation SMB connections to ADMIN$ (rare in normal operations)
- New service installation where the binary path is in a temporary directory or admin share
- Event 5145 showing write access to ADMIN$ from a non-administrative workstation
- Named pipe `PSEXESVC` creation (default PsExec, though attackers often rename it)

**Behavioral Baselines:**
- Map normal admin share access patterns: which accounts, from which sources, to which destinations
- Alert on accounts accessing admin shares on systems they have never accessed before
- Track the ratio of read vs. write operations on admin shares per account

**Network Segmentation Monitoring:**
- Detect SMB traffic crossing network segments that should not communicate via SMB
- Alert on SMB connections from user VLANs to server VLANs outside approved management tools
- Monitor for SMB traffic to domain controllers from non-administrative workstations

## Response Actions

1. Identify the source account and workstation initiating the SMB lateral movement
2. Determine if the source credentials were compromised (check for prior credential theft indicators)
3. Catalog all systems accessed via SMB by the compromised account during the incident window
4. Check each accessed system for dropped payloads, new services, and persistence mechanisms
5. Contain by disabling the compromised account and isolating affected endpoints
6. Review and restrict admin share access via GPO (disable remote admin shares where not needed)
""",
    },
    {
        "title": "WMI and WinRM Lateral Movement Detection",
        "tags": ["WMI", "WinRM", "lateral-movement", "T1021.006", "T1047", "detection"],
        "content": r"""# WMI and WinRM Lateral Movement Detection

## Overview

Windows Management Instrumentation (WMI) and Windows Remote Management (WinRM) are legitimate administration protocols that attackers abuse for lateral movement because they leave fewer artifacts than SMB-based techniques. WMI enables remote process creation and command execution, while WinRM provides remote shell access similar to SSH. Both are enabled by default in many enterprise environments.

## MITRE ATT&CK Reference

- **T1047** — Windows Management Instrumentation
- **T1021.006** — Remote Services: Windows Remote Management

## WMI-Based Lateral Movement

**How It Works:**
Attackers use WMI to create processes on remote systems by calling the `Win32_Process.Create` method via DCOM (TCP 135 + dynamic ports). No files need to be copied to the target — commands execute directly.

**Detection Indicators:**

*Source Host:*
- Sysmon Event 1: `wmic.exe` with `/node:` parameter in command line
- PowerShell `Invoke-WmiMethod` or `Invoke-CimMethod` cmdlets with `-ComputerName` parameter
- Sysmon Event 3: Outbound connections to remote hosts on TCP 135 followed by dynamic high ports from `wmiprvse.exe` or `svchost.exe`

*Target Host:*
- Sysmon Event 1: Process creation with parent process `WmiPrvSE.exe` — this is the hallmark indicator. WmiPrvSE should not spawn cmd.exe, powershell.exe, or other interactive shells during normal operations
- Security Event 4688: Process creation under `WmiPrvSE.exe` parent
- Security Event 4624: Network logon (Type 3) followed immediately by WmiPrvSE child process creation
- WMI Event ID 5861 (Microsoft-Windows-WMI-Activity/Operational): WMI event consumer registration

**High-Fidelity WMI Detection:**
- `WmiPrvSE.exe` spawning any of: `cmd.exe`, `powershell.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `rundll32.exe`
- WMI permanent event subscriptions (Event 5861) created outside of management tools — used for persistence

## WinRM-Based Lateral Movement

**How It Works:**
WinRM uses HTTP (TCP 5985) or HTTPS (TCP 5986) to provide remote PowerShell sessions and command execution. PowerShell remoting and `Enter-PSSession`/`Invoke-Command` use WinRM as the transport.

**Detection Indicators:**

*Source Host:*
- Sysmon Event 1: PowerShell with `Enter-PSSession`, `Invoke-Command`, or `New-PSSession` with `-ComputerName`
- Sysmon Event 3: Outbound connections to TCP 5985 or 5986
- PowerShell Script Block Logging (Event 4104): Captured remoting commands

*Target Host:*
- Sysmon Event 1: Process creation with parent `wsmprovhost.exe` — this is the WinRM host process that spawns commands on the remote side
- Security Event 4624: Network logon (Type 3) associated with WinRM service
- Event 91 (Microsoft-Windows-WinRM/Operational): WinRM session creation
- Sysmon Event 3: `wsmprovhost.exe` making outbound network connections (indicates the attacker is pivoting further)

**High-Fidelity WinRM Detection:**
- `wsmprovhost.exe` spawning cmd.exe, powershell.exe, or any process that makes outbound network connections
- WinRM session initiation from workstations to other workstations (typically only admin tools use WinRM)
- Multiple WinRM sessions opened from a single source to many targets in a short time

## Combined Detection Strategy

**Behavioral Baselines:**
- Inventory which accounts and systems legitimately use WMI and WinRM for administration
- Alert on WMI or WinRM usage from accounts or hosts not in the baseline
- Track unique destination count per source for WMI/WinRM connections per hour

**Network Monitoring:**
- TCP 135 + dynamic ports (WMI/DCOM) from workstations to workstations
- TCP 5985/5986 (WinRM) from non-management hosts
- High fan-out patterns — one source connecting to many destinations

## Response Workflow

1. Identify the parent process (WmiPrvSE.exe or wsmprovhost.exe) and its child processes
2. Extract command-line arguments to understand what was executed remotely
3. Trace the authentication event to identify the source account and IP
4. Check the source system for compromise indicators
5. Audit all systems targeted by the same account via WMI/WinRM
6. Consider restricting WinRM and WMI access via Windows Firewall or GPO to authorized management hosts only
""",
    },
    {
        "title": "RDP Pivoting and Abuse Detection",
        "tags": ["RDP", "lateral-movement", "T1021.001", "remote-desktop", "detection"],
        "content": r"""# RDP Pivoting and Abuse Detection

## Overview

Remote Desktop Protocol (RDP) is one of the most commonly abused protocols for lateral movement because it provides full interactive GUI access and is enabled on many Windows servers and workstations. Attackers use compromised credentials to RDP between systems, often chaining multiple hops to reach high-value targets. Detecting malicious RDP usage requires distinguishing attacker patterns from legitimate remote administration.

## MITRE ATT&CK Reference

- **T1021.001** — Remote Services: Remote Desktop Protocol

## Attack Patterns

**Credential-Based RDP:**
Attackers use stolen passwords or hashes to authenticate via RDP. RDP supports NLA (Network Level Authentication) which requires valid credentials before session establishment.

**RDP Tunneling:**
Attackers tunnel RDP through SSH, Chisel, plink, or other tunneling tools to bypass firewall rules. Internal RDP traffic appears to originate from the initial foothold rather than the external attacker.

**RDP Session Hijacking:**
On older Windows versions, attackers can hijack disconnected RDP sessions using `tscon.exe` running as SYSTEM, gaining access to another user's active session without authentication.

**Restricted Admin / Remote Credential Guard:**
Attackers may abuse RemoteCredentialGuard or RestrictedAdmin modes to perform lateral movement without exposing credentials to the target system (ironically, security features repurposed for attacks).

## Detection Indicators

**Windows Event Logs:**
- **Security Event 4624**: Type 10 (RemoteInteractive) or Type 7 (Unlock) logon events. Track which accounts use RDP and from which source IPs.
- **Security Event 4778/4779**: Session reconnected/disconnected. Frequent reconnections from different IPs suggest credential sharing or attacker pivoting.
- **TerminalServices-LocalSessionManager Event 21**: RDP session logon — captures source IP and username
- **TerminalServices-LocalSessionManager Event 25**: Session reconnection — attacker reconnecting to an existing session
- **TerminalServices-RdpCoreTS Event 131**: Connection attempt with source IP (logged even when NLA fails)

**Network Indicators:**
- RDP connections (TCP 3389) between workstations (should be rare in most environments)
- RDP traffic on non-standard ports (attackers may change the listening port)
- RDP connections from recently compromised hosts to sensitive systems (domain controllers, file servers, databases)
- Tunneled RDP: detect SSH or other tunnel establishment followed by RDP connection from localhost

**Behavioral Anomalies:**
- RDP sessions at unusual hours (off-business hours, weekends, holidays)
- RDP from accounts that do not normally use remote desktop
- RDP session chaining — user RDPs to System A, then from System A opens RDP to System B (visible as nested Type 10 logons)
- Rapid RDP connections to multiple systems from a single source

**Session Hijacking Indicators:**
- `tscon.exe` execution with a session ID parameter, especially when running as SYSTEM
- Service creation that immediately runs `tscon.exe` (a common hijacking technique)
- Event 4778 (session reconnect) without a corresponding Event 4624 (new logon)

## Detection Engineering

**SIEM Correlation Rules:**
- Alert on RDP logon (Type 10) from source IPs not in the organization's known jump-box or admin workstation list
- Flag accounts using RDP that have not done so in the past 30 days
- Detect multi-hop RDP: Event 4624 Type 10 on System B where the source is System A, and System A itself has an active Type 10 session
- Correlate RDP session times with working hours; alert on off-hours sessions from non-exempt accounts

**Network Monitoring:**
- Baseline and alert on RDP connections crossing network segments (user VLAN to server VLAN, DMZ to internal)
- Detect RDP over non-standard ports using traffic analysis (TLS fingerprinting or protocol detection)
- Monitor for tunneling indicators: SSH connections followed by loopback RDP

## Response Procedures

1. Identify the compromised account used for RDP lateral movement
2. Map the full RDP chain — every system accessed via RDP during the incident
3. Check each system in the chain for dropped tools, persistence, and data staging
4. Determine if credentials were cached on any intermediate systems (creates additional compromise risk)
5. Force session logoff and password reset for the compromised account
6. Implement network-level access controls restricting RDP to designated jump boxes
""",
    },
    {
        "title": "Scheduled Task Persistence Detection",
        "tags": ["scheduled-tasks", "persistence", "T1053.005", "detection", "windows"],
        "content": r"""# Scheduled Task Persistence Detection

## Overview

Scheduled tasks are one of the most versatile persistence mechanisms available to attackers on Windows systems. They allow execution of arbitrary commands at specified times, intervals, or system events, surviving reboots and user logoffs. Attackers use scheduled tasks for persistence, privilege escalation (when tasks run as SYSTEM), and lateral movement (remote task creation).

## MITRE ATT&CK Reference

- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Attack Techniques

**Local Task Creation:**
Attackers create tasks on compromised hosts to maintain access. Tasks can be configured to run at startup, logon, on a recurring schedule, or triggered by specific events.

**Remote Task Creation:**
Using `schtasks.exe /create /s <remote_host>` or the Task Scheduler COM API, attackers create tasks on remote systems for lateral movement without needing to copy files first.

**Task Modification:**
Existing tasks are modified to include malicious actions, hiding within tasks that already run and are expected in the environment. Harder to detect than new task creation.

**XML Task Files:**
Tasks defined in XML files can be registered using `schtasks /create /xml`, allowing complex configurations including multi-action tasks and custom triggers.

## Detection Indicators

**Windows Event Logs:**
- **Security Event 4698**: A scheduled task was created. Contains the task name, XML definition, and the account that created it. This is the primary detection event.
- **Security Event 4702**: A scheduled task was updated. Detects task modification.
- **Security Event 4699**: A scheduled task was deleted. Attackers may delete tasks after execution to remove traces.
- **Task Scheduler Operational Event 106**: Task registered (supplementary to 4698)
- **Task Scheduler Operational Event 200/201**: Task executed / completed

**Sysmon Indicators:**
- Event 1: `schtasks.exe` process creation with `/create` command-line argument. Key fields to examine: `/sc` (schedule), `/ru` (run as user), `/tr` (task to run), `/tn` (task name)
- Event 1: `schtasks.exe` with `/s` parameter indicating remote task creation
- Event 11: XML files created in `C:\Windows\System32\Tasks\` directory

**High-Fidelity Detection Patterns:**

*Task properties that indicate malicious intent:*
- Task running as SYSTEM or a service account but created by a standard user
- Task action executing from unusual paths: `%TEMP%`, `%APPDATA%`, `C:\ProgramData`, user profile directories
- Task action using living-off-the-land binaries: `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`
- Task with execution triggers set to very frequent intervals (every 1-5 minutes) suggesting C2 callback
- Task names mimicking legitimate system tasks but with slight variations
- Hidden tasks (tasks with `<Hidden>true</Hidden>` in XML definition)

*Remote task creation:*
- `schtasks.exe /create /s` from workstations to other workstations
- Event 4698 on target where the creator is a network logon (Type 3) from a non-admin host
- Remote task creation from accounts not in the authorized administration group

## Detection Engineering

**SIEM Rules:**
- Alert on Event 4698 where the task action contains PowerShell, cmd, or LOLBIN execution
- Flag tasks running as SYSTEM created by non-administrative accounts
- Correlate task creation (4698) with file creation events to identify dropped payloads
- Detect remote task creation by joining Event 4698 (task created) with Event 4624 Type 3 (network logon) on the target system

**Baseline and Anomaly:**
- Inventory all scheduled tasks in the environment and baseline expected tasks
- Alert on new tasks that do not match naming conventions or do not appear in the approved task list
- Monitor for tasks created outside change management windows

## Response Procedures

1. Extract the full task XML definition to understand the action, trigger, and run-as context
2. Identify the payload or command the task executes and analyze it
3. Determine if the task was created locally or remotely, and identify the source
4. Delete the malicious task and remove any associated payloads from disk
5. Check for additional persistence mechanisms (attackers rarely use just one)
6. If the task ran as SYSTEM, treat the host as fully compromised and investigate for further lateral movement
""",
    },
    {
        "title": "Registry Run Key Persistence Detection",
        "tags": ["registry", "persistence", "T1547.001", "run-keys", "detection", "windows"],
        "content": r"""# Registry Run Key Persistence Detection

## Overview

Registry Run keys are among the oldest and most common persistence mechanisms in Windows. Programs listed in Run/RunOnce registry keys execute automatically when a user logs in or the system starts. Despite being well-known, attackers continue to use these keys because they are simple, reliable, and offer multiple variations that defenders must monitor comprehensively.

## MITRE ATT&CK Reference

- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

## Registry Locations

**User-Level Persistence (HKCU) — runs as the user:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`

**Machine-Level Persistence (HKLM) — runs as SYSTEM or at startup:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>\StubPath`

**Wow6432Node variants**: On 64-bit systems, 32-bit applications use mirrored keys under `Wow6432Node` — attackers may target these less-monitored paths.

## Detection Strategies

**Sysmon Event 13 (RegistrySetValue):**
This is the primary detection event. Monitor all registry modifications to the keys listed above.

Key fields:
- `TargetObject`: The full registry path being modified
- `Details`: The value being set (the command or executable path)
- `Image`: The process making the modification
- `User`: The account context

**High-Fidelity Detection Patterns:**

*Suspicious values:*
- Executable paths pointing to `%TEMP%`, `%APPDATA%`, `C:\ProgramData`, `C:\Users\Public`, or other user-writable directories
- Values containing `cmd.exe /c`, `powershell.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, or `wscript.exe`
- Encoded commands (base64 strings) in the value data
- Values referencing files with double extensions or unusual extensions (.scr, .pif, .hta)
- Values pointing to recently created executables (correlate with Sysmon Event 11)

*Suspicious modification sources:*
- Run key modifications by processes that should not be configuring autostart: `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `cscript.exe`
- Modifications by processes running from temporary directories
- `reg.exe add` command-line entries targeting Run keys
- Modifications immediately following process creation from email attachments or browser downloads

**Windows Security Events:**
- Event 4657: Registry value modification audit (requires Object Access auditing enabled on registry keys)
- Configure SACLs on Run key registry paths to generate events for all write operations

**Startup Folder Monitoring:**
The Startup folder is functionally equivalent to Run keys:
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (per-user)
- `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` (all users)
- Monitor file creation events (Sysmon Event 11) in these directories
- Alert on shortcuts (.lnk) or scripts placed in startup folders by non-installer processes

## Baseline and Anomaly Detection

- Capture a baseline of all Run key values across the environment using periodic registry snapshots
- Alert on any net-new entries that do not match approved software
- Monitor for value modifications to existing entries (attackers may change a legitimate entry's path)
- Track the frequency of Run key changes — most systems rarely modify these keys outside software installation

## Response Procedures

1. Identify the malicious registry value and the executable or command it references
2. Determine which process created the entry (Sysmon Event 13 source)
3. Analyze the referenced payload in a sandbox
4. Remove the malicious registry value and associated payload from disk
5. Check for additional persistence mechanisms — Run keys are often one of several
6. Hunt for the same registry value or payload hash across the enterprise
""",
    },
    {
        "title": "Kerberos Ticket Attack Detection — Golden and Silver Tickets",
        "tags": ["golden-ticket", "silver-ticket", "T1558.001", "T1558.002", "kerberos", "persistence", "detection"],
        "content": r"""# Kerberos Ticket Attack Detection — Golden and Silver Tickets

## Overview

Golden Ticket and Silver Ticket attacks forge Kerberos authentication tickets using stolen encryption keys, enabling attackers to impersonate any user (including non-existent ones) and access any resource in the domain. Golden Tickets forge Ticket Granting Tickets (TGTs) using the krbtgt account hash, while Silver Tickets forge service tickets using individual service account hashes. Both are extremely dangerous because they bypass normal authentication and are difficult to detect without specific monitoring.

## MITRE ATT&CK Reference

- **T1558.001** — Steal or Forge Kerberos Tickets: Golden Ticket
- **T1558.002** — Steal or Forge Kerberos Tickets: Silver Ticket

## Golden Ticket

**What It Is:** A forged TGT encrypted with the krbtgt account's NTLM hash. With this ticket, the attacker can request service tickets for any resource in the domain as any user, including Domain Admin.

**Prerequisites:** The attacker must obtain the krbtgt NTLM hash (via DCSync, NTDS.dit extraction, or domain controller compromise).

**Detection Indicators:**

*Event Log Anomalies:*
- Security Event 4769 (TGS request): The ticket encryption type is RC4 (0x17) when the domain uses AES, or vice versa
- Event 4769 where the account name does not exist in Active Directory (forged tickets can specify any SID)
- TGT tickets with abnormally long lifetimes (default is 10 hours; attackers often set 10 years)
- Security Event 4624: Logon events where the account SID does not match any real domain account
- Event 4672: Privileged logon for accounts that should not have admin rights

*Metadata Mismatches:*
- Domain field in the ticket does not match the actual domain name (case-sensitivity or typo)
- Group membership in the PAC (Privileged Attribute Certificate) includes Domain Admins for non-admin accounts
- Ticket creation time is significantly earlier than the logon event timestamp

**Network Detection:**
- Kerberos TGS-REQ directly to a service without a preceding AS-REQ to the KDC (the golden ticket was created offline)
- TGT presented to the KDC was issued at a time when no corresponding AS-REP was logged

## Silver Ticket

**What It Is:** A forged service ticket (TGS) encrypted with a specific service account's NTLM hash. It grants access only to that service but never contacts the domain controller, making it harder to detect via DC logs.

**Prerequisites:** The attacker must obtain the NTLM hash of the target service account.

**Detection Indicators:**

*Key Difference: Silver Tickets bypass the KDC entirely. There will be no Event 4769 on the domain controller.*
- Service access events on the target server without corresponding TGS-REQ events on the DC
- Security Event 4624 (Type 3) on the target server for an account with suspicious or impossible group membership
- PAC validation failures if PAC validation is enforced (Event 4769 with failure code)
- Encrypted ticket fields that do not match expected SPN formatting

*Behavioral Indicators:*
- Access to sensitive services (SQL, file shares, web apps) from accounts that typically do not access them
- Service access at unusual hours from accounts that were not actively logged in

## Advanced Detection Approaches

**PAC Validation:**
- Enable PAC validation on all service accounts where possible. Silver Tickets fail PAC validation because the KDC never issued the ticket.
- Event 4769 with KDC_ERR_TGT_REVOKED or KDC_ERR_TGT_NOT_YET_VALID

**Domain Controller Correlation:**
- For every network logon (Event 4624 Type 3) on a target server, verify there is a corresponding TGS-REQ (Event 4769) on the domain controller within a reasonable time window. Missing DC events suggest a Silver Ticket.

**Krbtgt Password Age Monitoring:**
- Monitor the krbtgt account's `pwdLastSet` attribute. If the krbtgt password has not been changed in over 180 days, Golden Ticket risk is elevated.
- Detect unauthorized krbtgt password resets (which might indicate an attacker resetting it to a known value).

**Honey Tokens:**
- Create decoy domain admin accounts that should never authenticate
- Any Kerberos ticket activity for these accounts indicates forged ticket usage

## Response Procedures

1. If a Golden Ticket is suspected: reset the krbtgt password TWICE (to invalidate both the current and previous key). This must be done carefully to avoid service disruptions.
2. If a Silver Ticket is suspected: reset the password of the targeted service account.
3. Identify the original compromise that allowed the attacker to obtain the hash (DCSync, NTDS.dit, etc.)
4. Review all authentication activity by the compromised identity during the attack window
5. Check for additional persistence mechanisms deployed using the forged credentials
6. Implement regular krbtgt password rotation (every 180 days minimum) and service account password rotation
""",
    },
    {
        "title": "DCOM Lateral Movement Indicators",
        "tags": ["DCOM", "lateral-movement", "T1021.003", "COM-objects", "detection"],
        "content": r"""# DCOM Lateral Movement Indicators

## Overview

Distributed Component Object Model (DCOM) enables inter-process communication across network boundaries, allowing attackers to instantiate COM objects on remote systems and execute methods that spawn processes. DCOM lateral movement is stealthier than PsExec or WMI because it uses less commonly monitored protocols and COM interfaces that appear as legitimate system operations.

## MITRE ATT&CK Reference

- **T1021.003** — Remote Services: Distributed Component Object Model

## Common DCOM Abuse Techniques

**MMC20.Application (MMC snap-in):**
The `MMC20.Application` COM object exposes an `ExecuteShellCommand` method that can run arbitrary commands on the remote system. This is one of the most commonly abused DCOM objects.

CLSID: `{49B2791A-B1AE-4C90-9B8E-E860BA07F889}`

Detection focus: `mmc.exe` spawning unexpected child processes on the target system.

**ShellBrowserWindow / ShellWindows:**
These COM objects provide access to the Windows Explorer shell and can execute commands via the `Document.Application.ShellExecute` method.

CLSIDs: `{C08AFD90-F2A1-11D1-8455-00A0C91F3880}` (ShellBrowserWindow), `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` (ShellWindows)

Detection focus: `explorer.exe` spawning processes that it normally would not, especially PowerShell or cmd.

**Excel.Application / Outlook.Application:**
Office application COM objects can be instantiated remotely to execute macros or scripts.

Detection focus: Office processes (excel.exe, outlook.exe) spawning on systems where the user has not interactively opened those applications.

**Visio.InvisibleApp:**
Allows command execution through Visio automation.

## Detection Indicators

**Network Indicators:**
- DCOM uses TCP 135 for initial endpoint mapping, then negotiates dynamic high ports (49152-65535) for the actual RPC communication
- RPC traffic from workstations to other workstations (should be rare outside of admin tools)
- Detect DCOM activation requests on TCP 135 from unusual source hosts

**Endpoint Detection — Target Host:**
- **Sysmon Event 1**: Key parent-child process relationships that indicate DCOM abuse:
  - `mmc.exe` spawning `cmd.exe`, `powershell.exe`, or other command interpreters
  - `explorer.exe` spawning unexpected processes (not initiated by user desktop interaction)
  - `excel.exe` or `outlook.exe` starting without user interaction on the console
  - Any COM server process spawning command-line interpreters
- **Security Event 4624**: Network logon (Type 3) followed immediately by COM server process activity
- **Sysmon Event 3**: Network connections from COM server processes to external IPs (indicates the attacker is using DCOM as a pivot point)

**Endpoint Detection — Source Host:**
- Sysmon Event 1: PowerShell with COM object instantiation patterns (`[activator]::CreateInstance`, `[System.Runtime.InteropServices.Marshal]`, `New-Object -ComObject` with remote parameters)
- Sysmon Event 3: Outbound RPC connections on TCP 135 followed by high-port connections to the same destination

**Windows Event Logs:**
- **System Event 10016** (DistributedCOM): DCOM activation errors or permission warnings — may indicate failed attempts
- **Security Event 4674**: Privileged operation on a COM object. Track which COM objects are being activated remotely.

## Detection Engineering

**High-Fidelity Rules:**
- `mmc.exe` process creation on a system where the user is not interactively logged in (no Type 10 or Type 2 logon), followed by `mmc.exe` spawning command interpreters
- COM server processes (`mmc.exe`, `excel.exe`, `explorer.exe`) with network connections from remote hosts and child process creation within 30 seconds
- RPC endpoint mapper traffic (TCP 135) from workstations to workstations outside approved management tools

**Process Tree Analysis:**
- Build expected process trees for COM server applications and alert on deviations
- `mmc.exe` should have child processes related to management console snap-ins, not command shells
- `explorer.exe` child process creation should correlate with user desktop interaction, not remote network logons

**Behavioral Baselines:**
- Inventory which systems legitimately use DCOM for remote management
- Track COM object activation patterns per host and alert on anomalies
- Monitor for COM objects being activated that have known abuse potential (the CLSIDs listed above)

## Response Procedures

1. Identify the COM object used for lateral movement from process creation and parent-child relationships
2. Determine the source host and account that initiated the DCOM connection
3. Examine the commands executed via the COM object on the target
4. Check for persistence mechanisms deployed after the DCOM-based execution
5. Investigate the source host for prior compromise indicators
6. Consider restricting remote DCOM activation via DCOMCNFG or Group Policy where not operationally required
""",
    },
]

# ============================================================
# COLLECTIONS EXPORT
# ============================================================

COLLECTIONS = [
    (
        "Initial Access & Social Engineering",
        "Phishing anatomy, spearphishing indicators, watering hole detection, supply chain risk, credential stuffing detection, and BEC indicators for SOC analysts.",
        INITIAL_ACCESS,
    ),
    (
        "Privilege Escalation Detection",
        "Windows and Linux privilege escalation indicators, Kerberoasting, pass-the-hash, credential theft, DLL hijacking, and UAC bypass detection strategies.",
        PRIVESC,
    ),
    (
        "Lateral Movement & Persistence",
        "SMB lateral movement, WMI/WinRM detection, RDP pivoting, scheduled task persistence, registry run keys, Kerberos ticket attacks, and DCOM indicators.",
        LATERAL_MOVEMENT,
    ),
]
