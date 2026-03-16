"""Built-in KB data: Networking — Defense & Traffic Analysis."""

FIREWALL_IDS = [
    {
        "title": "Stateful vs Stateless Firewalls",
        "tags": ["firewall", "stateful", "stateless", "network-security", "packet-filtering"],
        "content": r"""# Stateful vs Stateless Firewalls

## Overview

Firewalls are the foundational gatekeepers of network security. Understanding the difference between stateful and stateless inspection is critical for SOC analysts evaluating firewall logs and tuning rulesets.

## Stateless (Packet-Filtering) Firewalls

Stateless firewalls evaluate each packet in isolation against a static rule table. They inspect header fields — source/destination IP, port, and protocol — without tracking the broader conversation.

**Characteristics:**

- Decisions based solely on individual packet headers
- No memory of previous packets or connection state
- Fast processing with minimal resource usage
- Cannot distinguish between a new connection and a reply
- Vulnerable to fragmentation attacks and spoofed ACK packets

**Example rule (iptables syntax):**

```bash
# Allow inbound HTTP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
# Allow established replies — manual workaround for statelessness
iptables -A INPUT -p tcp --sport 80 ! --syn -j ACCEPT
```

The manual `! --syn` rule is an imperfect attempt to allow return traffic without true state tracking.

## Stateful Firewalls

Stateful firewalls maintain a **connection table** (also called a state table) that tracks each session through its lifecycle: `NEW`, `ESTABLISHED`, `RELATED`, `INVALID`.

**Characteristics:**

- Tracks full TCP handshake (SYN, SYN-ACK, ACK) and teardown (FIN/RST)
- Allows return traffic automatically once a session is established
- Detects out-of-state packets (e.g., ACK without a preceding SYN)
- Tracks UDP "connections" via timeout-based pseudo-state
- Higher memory and CPU usage due to table maintenance

**Connection table example:**

| Source | Destination | Protocol | State | Timeout |
|---|---|---|---|---|
| 10.0.1.50:49312 | 93.184.216.34:443 | TCP | ESTABLISHED | 3600s |
| 10.0.1.50:52891 | 8.8.8.8:53 | UDP | ESTABLISHED | 30s |

## SOC Relevance

When analyzing firewall logs, stateful firewalls produce richer telemetry. Look for:

- **INVALID state drops** — may indicate scanning, spoofing, or evasion attempts
- **Connection table exhaustion** — a symptom of DDoS or resource abuse
- **Asymmetric routing issues** — stateful firewalls on only one path see half-open sessions

## When to Use Each

| Use Case | Recommended |
|---|---|
| High-speed backbone filtering | Stateless (hardware ACL) |
| Perimeter defense | Stateful |
| Cloud security groups | Stateful (AWS SG) or stateless (NACL) |
| IoT/embedded devices | Stateless (resource constraints) |
| East-west datacenter traffic | Stateful or micro-segmentation |

Modern environments almost universally deploy stateful inspection at the perimeter, often supplemented by stateless ACLs at the network edge for volumetric DDoS mitigation before traffic reaches the stateful engine.
""",
    },
    {
        "title": "Next-Generation Firewall (NGFW) Features",
        "tags": ["ngfw", "firewall", "deep-packet-inspection", "application-control", "network-security"],
        "content": r"""# Next-Generation Firewall (NGFW) Features

## Overview

Next-Generation Firewalls extend traditional stateful inspection with application awareness, integrated intrusion prevention, and threat intelligence feeds. Major vendors include Palo Alto Networks, Fortinet FortiGate, Cisco Firepower, and Check Point.

## Core NGFW Capabilities

### Application Identification (App-ID)

NGFWs classify traffic by application rather than just port number. A connection on TCP/443 might be identified as Slack, Dropbox, or a custom web app. This defeats the common evasion technique of tunnelling malicious traffic over standard ports.

**How it works:**

1. Initial packet matching against known signatures
2. SSL decryption (if configured) to inspect the inner protocol
3. Heuristic and behavioral analysis for unknown applications
4. Continuous reclassification as more packets arrive

### User Identification (User-ID)

NGFWs integrate with directory services (Active Directory, LDAP) to associate traffic with specific users rather than just IP addresses. This enables policies like "allow analysts to reach threat intel feeds" regardless of which workstation they use.

**Integration methods:** AD agent polling, RADIUS accounting, captive portal, Syslog parsing, SAML.

### Integrated Intrusion Prevention (IPS)

Built-in IPS engines inspect packet payloads against signature databases and anomaly profiles. Unlike standalone IPS appliances, NGFW IPS shares context with the firewall policy engine.

### Threat Intelligence Integration

NGFWs consume real-time feeds of malicious IPs, domains, and file hashes. Traffic matching these indicators is blocked or flagged automatically.

### URL Filtering

Categorized URL databases allow policy enforcement by website category — blocking known phishing, malware distribution, and command-and-control domains.

### Sandboxing / File Analysis

Suspicious files traversing the firewall are sent to cloud or on-premises sandboxes (e.g., Palo Alto WildFire, Fortinet FortiSandbox) for dynamic analysis before delivery.

## NGFW Log Fields for SOC Analysis

When investigating NGFW alerts, focus on:

| Field | Significance |
|---|---|
| `app` | Identified application (may differ from port) |
| `action` | allow, deny, drop, reset |
| `threat_id` / `signature` | IPS or threat match identifier |
| `url_category` | Site classification |
| `file_verdict` | Sandbox result (benign, malicious, grayware) |
| `user` | Authenticated user associated with session |
| `rule_name` | Which policy matched |

## Deployment Best Practices

- Enable SSL decryption for outbound traffic (with privacy policy compliance)
- Create application-based rules instead of port-based where possible
- Tune IPS profiles to reduce false positives — start in alert mode before blocking
- Feed NGFW logs into your SIEM for correlation with endpoint telemetry
- Regularly update App-ID and threat signature databases
- Use zone-based segmentation (trust, untrust, DMZ, internal zones)
""",
    },
    {
        "title": "Suricata Rule Writing for SOC Analysts",
        "tags": ["suricata", "ids", "ips", "rule-writing", "signatures", "network-security"],
        "content": r"""# Suricata Rule Writing for SOC Analysts

## Overview

Suricata is an open-source IDS/IPS engine capable of real-time intrusion detection, inline prevention, network security monitoring, and offline PCAP processing. Writing effective rules is a core skill for SOC analysts performing threat detection engineering.

## Rule Structure

Every Suricata rule follows this format:

```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```

**Example:**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Cobalt Strike Beacon"; content:"GET"; http_method; content:"/updates"; http_uri; pcre:"/\/__utm[a-z]\?utmac=/U"; sid:2028362; rev:3;)
```

### Actions

| Action | Description |
|---|---|
| `alert` | Generate an alert |
| `pass` | Stop further inspection (whitelist) |
| `drop` | Block packet and alert (IPS mode) |
| `reject` | Block and send RST/ICMP unreachable |

### Protocol Keywords

Suricata supports: `tcp`, `udp`, `icmp`, `ip`, `http`, `tls`, `dns`, `smb`, `ssh`, `ftp`, `smtp`, `dhcp`, `krb5`.

## Key Detection Options

### Content Matching

```
content:"malicious_string";    # Case-sensitive match
content:"MaLiCiOuS"; nocase;  # Case-insensitive
content:"|de ad be ef|";       # Hex byte match
```

### Positional Modifiers

```
content:"POST"; offset:0; depth:4;    # Match in first 4 bytes
content:"cmd.exe"; distance:0; within:20;  # Relative to previous match
```

### Protocol-Specific Buffers

```
content:"login.php"; http_uri;           # Match only in URI
content:"evil.com"; http_host;           # Match in Host header
content:"powershell"; http_user_agent;   # Match in User-Agent
content:"|89 50 4e 47|"; file_data;      # Match in file content
```

### Flow Control

```
flow:established,to_server;    # Client-to-server on established conn
flow:established,to_client;    # Server-to-client response
```

### Threshold and Rate Limiting

```
threshold:type both, track by_src, count 10, seconds 60;
# Alert once per 60s after 10 matches from same source
```

## Practical Examples

### Detect Base64-Encoded PowerShell

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible encoded PowerShell download"; flow:established,to_server; content:"GET"; http_method; content:".ps1"; http_uri; content:"powershell"; http_user_agent; nocase; sid:1000001; rev:1;)
```

### Detect DNS Tunneling (Long Queries)

```
alert dns $HOME_NET any -> any 53 (msg:"Possible DNS tunneling - long query"; dns.query; content:"."; pcre:"/^.{60,}/"; threshold:type both, track by_src, count 5, seconds 60; sid:1000002; rev:1;)
```

## Testing Rules

```bash
# Test rule syntax
suricata -T -S custom.rules -c /etc/suricata/suricata.yaml

# Run against a PCAP
suricata -r capture.pcap -S custom.rules -l /tmp/output/

# Check results
cat /tmp/output/fast.log
jq . /tmp/output/eve.json | head -50
```

## SOC Workflow

1. Identify the threat behavior to detect (from CTI or incident findings)
2. Write the rule targeting specific protocol buffers
3. Test against known-good and known-bad PCAPs
4. Deploy in alert-only mode and monitor for false positives
5. Tune thresholds and content matches to reduce noise
6. Promote to blocking mode (IPS) when confidence is high
""",
    },
    {
        "title": "IDS/IPS Placement and Architecture",
        "tags": ["ids", "ips", "network-architecture", "sensor-placement", "network-security"],
        "content": r"""# IDS/IPS Placement and Architecture

## Overview

Where you place IDS/IPS sensors dramatically affects detection coverage and operational overhead. Poor placement creates blind spots; excessive placement creates alert fatigue. This article covers strategic placement for maximum visibility with manageable noise.

## IDS vs IPS Mode

| Aspect | IDS (Detection) | IPS (Prevention) |
|---|---|---|
| Deployment | Passive (SPAN/TAP) | Inline (traffic passes through) |
| Latency impact | None | Slight increase |
| Failure mode | Invisible to network | Can block legitimate traffic |
| Risk | Missed detections only | False positives cause outages |
| Best for | Monitoring, tuning phase | Perimeter, high-confidence rules |

## Sensor Placement Points

### 1. Internet Perimeter (North-South)

Place a sensor between the edge router and the perimeter firewall or just inside the firewall.

**Visibility:** All inbound and outbound traffic before NAT (outside placement) or after NAT (inside placement). Detects external scanning, inbound exploits, C2 callbacks, and data exfiltration.

**Recommendation:** IPS mode for high-confidence signatures; IDS mode with a TAP for full visibility.

### 2. DMZ Segment

Monitor traffic between the DMZ and both the internet and internal network.

**Visibility:** Attacks targeting public-facing services (web, email, DNS). Pivoting attempts from compromised DMZ hosts into the internal network.

**Recommendation:** IPS inline for internet-to-DMZ. IDS via TAP for DMZ-to-internal (to detect lateral movement without risking service disruption).

### 3. Internal Core (East-West)

Deploy sensors on trunk links between VLANs or at aggregation switches.

**Visibility:** Lateral movement, internal reconnaissance, credential theft, and policy violations. This is where most dwell-time activity occurs.

**Recommendation:** IDS mode initially — east-west traffic volumes are high and false-positive tolerance is lower.

### 4. Datacenter / Server Farm

Inline or passive sensors on traffic entering sensitive server segments.

**Visibility:** Unauthorized access to databases, file servers, and application backends. Detects SQL injection, application-layer attacks, and privilege escalation.

### 5. Cloud Workloads

Cloud-native IDS (AWS GuardDuty, Azure Network Watcher, GCP Packet Mirroring with Suricata) provides VPC flow log, DNS, and API anomaly monitoring.

## Traffic Acquisition Methods

| Method | Description | Pros | Cons |
|---|---|---|---|
| SPAN/Mirror Port | Switch copies traffic to sensor | Easy setup | Can drop packets under load |
| Network TAP | Hardware device copies all traffic | Lossless, full-duplex | Additional hardware cost |
| Inline (bump-in-wire) | Sensor sits in traffic path | Can block attacks | Adds latency, failure risk |
| Virtual TAP | Hypervisor-level traffic copy | Sees VM-to-VM traffic | Performance overhead |
| Packet Broker | Aggregates, filters, and distributes | Scales to multiple sensors | Complex and expensive |

## Tuning for Placement

**Perimeter:** exploit and malware signatures. **Internal:** lateral movement, credential abuse. **DMZ:** web app attacks, server exploits. **Cloud:** API abuse, metadata service access.

**Capacity planning:** Size sensors based on peak Gbps, packet rate (small packets stress CPU), active rule count, and logging volume (full PCAP vs metadata).
""",
    },
    {
        "title": "Web Application Firewall (WAF) Concepts",
        "tags": ["waf", "web-security", "owasp", "application-security", "network-security"],
        "content": r"""# Web Application Firewall (WAF) Concepts

## Overview

A Web Application Firewall operates at Layer 7 to protect HTTP/HTTPS applications from attacks that network firewalls cannot detect. WAFs inspect request and response bodies, headers, cookies, and URL parameters to block injection, cross-site scripting, and other OWASP Top 10 threats.

## How WAFs Work

### Deployment Models

| Model | Description | Examples |
|---|---|---|
| Reverse Proxy | WAF sits between client and server, terminates TLS | ModSecurity + Nginx, F5 ASM |
| Cloud-Based | DNS points to WAF provider, traffic proxied to origin | Cloudflare, AWS WAF, Akamai |
| Embedded/Agent | WAF module inside the web server or app runtime | ModSecurity (Apache module), RASP |
| Out-of-Band | Analyzes mirrored traffic, no inline blocking | Some API security products |

### Detection Methods

**Negative Security Model (Signature-Based):**

Rules define known-bad patterns. If a request matches a malicious signature, it is blocked. Fast and effective for known attacks but blind to novel techniques.

```
# ModSecurity example: block SQL injection in parameters
SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,msg:'SQL Injection Detected'"
```

**Positive Security Model (Allowlist-Based):**

Rules define known-good patterns. Only requests matching expected formats (parameter types, lengths, character sets) are allowed. Effective against zero-days but requires significant profiling and tuning per application.

**Anomaly Scoring:**

Each rule violation adds points to a per-request anomaly score. The request is blocked only when the cumulative score exceeds a threshold (e.g., 5 or more rule hits). Reduces false positives from single-rule matches.

## OWASP Core Rule Set (CRS)

The CRS is the standard open-source ruleset for ModSecurity-compatible WAFs. It provides detection for:

- SQL injection (SQLi) — union-based, blind, time-based, error-based
- Cross-site scripting (XSS) — reflected, stored, DOM-based patterns
- Remote code execution (RCE) — OS command injection, code injection
- Local/Remote file inclusion (LFI/RFI)
- Server-side request forgery (SSRF)
- Protocol violations and anomalies

**Paranoia levels** (PL1–PL4) control rule strictness: PL1 is low noise, PL4 catches the most but generates more false positives.

## SOC Analyst Workflow

When triaging WAF alerts:

1. **Check the rule ID and category** — is it SQLi, XSS, RCE, or a protocol anomaly?
2. **Examine the matched payload** — look at the specific parameter and value that triggered the rule
3. **Assess intent** — is this automated scanning (high volume, sequential payloads) or targeted exploitation?
4. **Check the source** — known scanner IPs, TOR exit nodes, cloud hosting providers
5. **Correlate with backend logs** — did the attack reach the application? Check application and database logs
6. **Determine impact** — was the request blocked (403) or only logged? Did subsequent requests indicate success?

## Bypass Techniques (Know Your Enemy)

Attackers evade WAFs using: encoding tricks (double URL-encoding, Unicode), case variation, comment insertion in SQL (`SEL/**/ECT`), HTTP parameter pollution, chunked transfer encoding abuse, and protocol-level smuggling.

Understanding these helps analysts identify evasion in logs and write better custom rules.
""",
    },
    {
        "title": "Network ACL Design and Best Practices",
        "tags": ["acl", "access-control", "firewall-rules", "network-security", "segmentation"],
        "content": r"""# Network ACL Design and Best Practices

## Overview

Access Control Lists (ACLs) are ordered sets of permit/deny rules applied to router interfaces, switch ports, or cloud network boundaries. Properly designed ACLs enforce the principle of least privilege at the network layer.

## ACL Types

### Standard ACLs

Filter based on source IP address only. Limited granularity but useful for simple access restrictions.

```
access-list 10 permit 10.1.1.0 0.0.0.255
access-list 10 deny any
```

### Extended ACLs

Filter on source IP, destination IP, protocol, and port. Provide the granularity needed for security policies.

```
access-list 100 permit tcp 10.1.1.0 0.0.0.255 host 10.2.1.50 eq 443
access-list 100 permit tcp 10.1.1.0 0.0.0.255 host 10.2.1.50 eq 22
access-list 100 deny ip any any log
```

### Named ACLs

Use descriptive names instead of numbers for readability and easier management.

```
ip access-list extended ANALYST-TO-SIEM
 permit tcp 10.10.5.0 0.0.0.255 host 10.20.1.100 eq 9200
 permit tcp 10.10.5.0 0.0.0.255 host 10.20.1.100 eq 5601
 deny ip any any log
```

## Design Principles

### 1. Default Deny

Always end an ACL with an explicit deny-all rule. Most platforms have an implicit deny, but making it explicit with logging helps troubleshooting.

### 2. Most Specific First

ACLs are evaluated top-down, first match wins. Place the most specific rules at the top and broader rules below.

### 3. Deny Known-Bad Early

Block RFC 1918 addresses on external interfaces, known bogon ranges, and threat intelligence blocklists near the top to drop unwanted traffic before processing more complex rules.

### 4. Group by Function

Organize rules by business function: management access, application traffic, monitoring, backup. Use comments to document each group.

### 5. Minimize Any/Any Rules

Every `permit any any` rule is a security gap. Document and justify each broad permit with a business requirement and review date.

## Cloud ACLs

### AWS Network ACLs vs Security Groups

| Feature | NACL | Security Group |
|---|---|---|
| Statefulness | Stateless | Stateful |
| Applied to | Subnet | ENI (instance) |
| Rule evaluation | Ordered (numbered) | All rules evaluated |
| Default | Allow all (default NACL) | Deny all inbound |
| Return traffic | Must explicitly allow | Automatic |

**Best practice:** Use Security Groups as the primary control (stateful, easier to manage). Use NACLs as a secondary layer for subnet-wide deny rules (e.g., blocking known-bad IP ranges).

## ACL Auditing for SOC

Regularly audit ACLs for:

- **Shadowed rules:** A rule that can never match because a broader rule above it already handles the traffic
- **Overly permissive rules:** `permit any any` or wide port ranges without justification
- **Stale rules:** Temporary exceptions that were never removed
- **Missing logging:** Deny rules without `log` keywords reduce visibility
- **Inconsistency:** Similar segments with different rule sets for no documented reason

Automated tools like Tufin, AlgoSec, or FireMon can analyze rulesets for these issues at scale.
""",
    },
    {
        "title": "NetFlow and sFlow Analysis for Security Monitoring",
        "tags": ["netflow", "sflow", "traffic-analysis", "network-monitoring", "flow-data"],
        "content": r"""# NetFlow and sFlow Analysis for Security Monitoring

## Overview

Flow data provides a metadata-level view of all network conversations without the storage cost of full packet capture. NetFlow (Cisco), IPFIX (IETF standard), and sFlow (sampling-based) are the primary protocols. For SOC teams, flow data fills the gap between firewall logs and full PCAP.

## Flow Record Fields

A typical flow record contains:

| Field | Description | Security Use |
|---|---|---|
| Source/Dest IP | Conversation endpoints | Identify C2, lateral movement |
| Source/Dest Port | Transport layer ports | Detect service abuse, tunneling |
| Protocol | TCP, UDP, ICMP, etc. | Anomalous protocol usage |
| Bytes/Packets | Volume counters | Exfiltration, DDoS detection |
| TCP Flags | SYN, ACK, FIN, RST summary | Scan detection, evasion |
| Start/End Time | Flow timing | Duration anomalies, beaconing |
| ToS/DSCP | Quality of service marking | Traffic classification abuse |
| Interface | Ingress/egress port index | Routing path verification |

## NetFlow vs sFlow

| Aspect | NetFlow/IPFIX | sFlow |
|---|---|---|
| Method | Tracks every flow, exports on completion or timeout | Samples 1-in-N packets |
| Accuracy | Complete flow records | Statistical sampling |
| Overhead | Higher (stateful flow cache) | Lower (no state) |
| Payload | Metadata only (v5/v9) | Can include packet header samples |
| Best for | Detailed flow analysis | High-speed networks, capacity planning |

## Security Use Cases

### Exfiltration Detection

Monitor for hosts sending unusually large volumes to external IPs. Create baselines per host/subnet and alert on deviations exceeding thresholds.

### Lateral Movement

Look for internal hosts communicating with other internal hosts on unusual ports or with hosts they have never contacted before.

**Indicators:**

- SMB (445) from workstations to other workstations (not servers)
- RDP (3389) between hosts that lack an admin relationship
- WMI (135) or WinRM (5985/5986) from unexpected sources
- SSH from hosts that are not jump boxes

### Scan Detection

Port scans appear as many short-lived flows from one source to one target (vertical scan) or one source to many targets on a single port (horizontal scan).

**Vertical scan pattern:** Single `src_ip`, single `dst_ip`, many `dst_port` values, most flows with SYN-only flag.

**Horizontal scan pattern:** Single `src_ip`, many `dst_ip` values, single `dst_port`, short flow durations.

### Beaconing

Regular intervals between flow start times from one internal host to one external destination suggest C2 beaconing. Calculate inter-flow intervals and measure coefficient of variation — low CV (< 0.15) indicates automated, regular callbacks.

### DDoS Detection

Massive inbound flow counts to a single destination, often with spoofed source IPs (SYN flood) or amplified UDP responses (DNS/NTP amplification).

## Collection and Enrichment

**Popular collectors:** Elastic (Filebeat NetFlow module), ntopng, SiLK, nfdump, Plixer Scrutinizer. Retain raw flows 30-90 days; aggregated summaries 1+ year. Flow data is typically 0.1-0.5% the size of full PCAP.

Enrich flow data with DNS logs, threat intel feeds, asset inventory, GeoIP databases, and WHOIS data for full context.
""",
    },
    {
        "title": "TLS Inspection Architecture and Considerations",
        "tags": ["tls", "ssl", "inspection", "decryption", "proxy", "network-security"],
        "content": r"""# TLS Inspection Architecture and Considerations

## Overview

With over 95% of web traffic now encrypted, TLS inspection (also called SSL decryption or break-and-inspect) is essential for network security monitoring. Without it, IDS/IPS, DLP, and malware sandboxes are blind to payload content. However, TLS inspection introduces architectural complexity, performance overhead, and privacy concerns.

## How TLS Inspection Works

### Forward Proxy (Outbound)

1. Client initiates TLS connection to `external-server.com`
2. The inspection proxy intercepts and terminates the client's TLS session
3. Proxy initiates a new TLS session to the actual destination server
4. Proxy decrypts traffic from the client, inspects it, re-encrypts, and forwards to the server
5. Response follows the reverse path

The proxy presents a dynamically generated certificate signed by an internal CA. Client devices must trust this CA in their certificate store — deployed via GPO, MDM, or configuration management.

### Reverse Proxy (Inbound)

1. External client connects to the organization's public IP
2. A load balancer or reverse proxy terminates TLS using the server's real certificate
3. Decrypted traffic is inspected and forwarded (re-encrypted or plaintext) to the backend

## Architecture Components

```
[Client] --TLS--> [Inspection Proxy] --TLS--> [Destination]
                        |
                   [IDS/IPS]
                   [DLP Engine]
                   [Sandbox]
                   [SIEM Logging]
```

### Key Components

- **Internal Certificate Authority:** Generates per-session certificates. Must be carefully protected — compromise enables man-in-the-middle attacks on all inspected traffic.
- **Policy Engine:** Determines what to inspect, bypass, or block. Not all traffic should be decrypted.
- **Inspection Tools:** IDS (Suricata), DLP, antimalware, URL filtering all operate on the decrypted stream.
- **Logging:** Decrypted sessions can be logged for forensic purposes (with appropriate authorization and data handling controls).

## What to Bypass (Do Not Decrypt)

Certain categories must bypass TLS inspection for legal, compliance, or technical reasons:

| Category | Reason |
|---|---|
| Banking / Financial | Regulatory compliance, certificate pinning |
| Healthcare portals | HIPAA, patient privacy |
| Government services | Legal requirements |
| Certificate-pinned apps | Will break (mobile apps, some desktop agents) |
| Personal email / HR sites | Employee privacy laws (jurisdiction-dependent) |
| EDR/AV update channels | Agent certificate pinning, tampering concerns |

## Performance Impact

TLS inspection is CPU-intensive due to cryptographic operations. Plan for:

- **2x-5x reduction** in throughput compared to pass-through mode
- Higher latency (additional TLS handshakes)
- Hardware acceleration (dedicated SSL offload cards) on high-throughput appliances
- Certificate caching to avoid regenerating certificates for frequently visited domains

## SOC Considerations

- Monitor for TLS inspection bypass rule changes — an attacker modifying bypass lists creates a blind spot
- Alert on certificate validation failures at the proxy (upstream cert expired, untrusted CA, hostname mismatch)
- Track decryption error rates — sudden spikes may indicate TLS 1.3 incompatibility or certificate pinning issues
- Ensure inspection logs include both the original client connection and the proxy-to-server connection for full forensic context
- Verify the proxy enforces minimum TLS 1.2, disables weak ciphers (RC4, 3DES, export-grade), and supports TLS 1.3
""",
    },
]

WIRELESS_CLOUD = [
    {
        "title": "802.11 WiFi Security — WPA2 and WPA3",
        "tags": ["wifi", "wireless", "wpa2", "wpa3", "802.11", "network-security"],
        "content": r"""# 802.11 WiFi Security — WPA2 and WPA3

## Overview

Wireless networks are inherently exposed — any device within radio range can observe or interact with the signal. Understanding WiFi security protocols is essential for SOC analysts monitoring wireless intrusion detection systems and investigating rogue access points.

## Evolution of WiFi Security

| Protocol | Year | Encryption | Status |
|---|---|---|---|
| WEP | 1997 | RC4 (24-bit IV) | Broken — crackable in minutes |
| WPA | 2003 | TKIP (RC4 wrapper) | Deprecated — vulnerable |
| WPA2 | 2004 | AES-CCMP (128-bit) | Current standard |
| WPA3 | 2018 | AES-GCMP (128/192-bit) | Next-generation |

## WPA2 Architecture

### WPA2-Personal (PSK)

All devices share a Pre-Shared Key. The 4-way handshake derives a unique Pairwise Transient Key (PTK) per session.

**Vulnerability:** The PSK-based handshake is vulnerable to offline brute-force attacks. An attacker who captures the 4-way handshake can run dictionary attacks offline using tools like hashcat or aircrack-ng.

**Mitigation:** Use long, complex passphrases (20+ characters). Consider WPA2-Enterprise for sensitive environments.

### WPA2-Enterprise (802.1X)

Each user authenticates individually via RADIUS, typically using EAP methods:

- **EAP-TLS:** Mutual certificate authentication (most secure, complex to deploy)
- **PEAP (MSCHAPv2):** Username/password protected by TLS tunnel (most common)
- **EAP-TTLS:** Similar to PEAP, broader EAP method support

**Advantage:** Individual credentials, per-user encryption keys, centralized access control, credential revocation.

## WPA3 Improvements

### Simultaneous Authentication of Equals (SAE)

WPA3-Personal replaces the PSK 4-way handshake with SAE (Dragonfly key exchange). This provides:

- **Forward secrecy:** Compromising the passphrase does not decrypt previously captured traffic
- **Offline brute-force resistance:** Each authentication attempt requires real-time interaction with the AP
- **Protection against dictionary attacks:** Even weak passwords are significantly harder to crack

### WPA3-Enterprise (192-bit)

Uses CNSA (Commercial National Security Algorithm) suite: AES-256-GCMP, SHA-384, ECDSA with P-384 curves. Designed for government and high-security environments.

### Other WPA3 Features

- **Protected Management Frames (PMF):** Mandatory in WPA3 — prevents deauthentication attacks
- **Enhanced Open (OWE):** Opportunistic Wireless Encryption for open networks — encrypts traffic without requiring a password
- **Wi-Fi Easy Connect (DPP):** QR code based provisioning for IoT devices

## Wireless Threats for SOC Monitoring

| Threat | Description | Detection |
|---|---|---|
| Rogue AP | Unauthorized AP on corporate network | WIDS, MAC/BSSID monitoring |
| Evil Twin | Fake AP mimicking legitimate SSID | Signal strength anomalies, certificate mismatches |
| KRACK | Key Reinstallation Attack on WPA2 | Patch verification, anomalous handshake retries |
| Deauth Attack | Flood deauth frames to disconnect clients | PMF enforcement, deauth frame counters |
| WPS Brute Force | Attack WPS PIN for network access | Disable WPS, monitor for WPS attempts |
| Karma/MANA | Respond to client probe requests | Monitor for APs answering all probe requests |

## SOC Best Practices

Deploy Wireless IDS/IPS (Kismet, Cisco ISE), monitor for unauthorized SSIDs/BSSIDs, enforce WPA2-Enterprise minimum with WPA3 migration planned, disable WPS, enable PMF (802.11w), and audit AP configurations regularly.
""",
    },
    {
        "title": "Cloud VPC Networking Fundamentals",
        "tags": ["cloud", "vpc", "aws", "azure", "gcp", "network-architecture"],
        "content": r"""# Cloud VPC Networking Fundamentals

## Overview

A Virtual Private Cloud (VPC) is a logically isolated network within a cloud provider's infrastructure. Understanding VPC architecture is critical for SOC analysts investigating cloud-based incidents, configuring security controls, and reviewing infrastructure-as-code for misconfigurations.

## Core VPC Components

### Subnets

Subnets partition the VPC CIDR range into segments. Each subnet exists in a single Availability Zone.

- **Public subnet:** Has a route to an Internet Gateway (IGW). Resources receive public IPs.
- **Private subnet:** No direct internet route. Resources access the internet via NAT Gateway only for outbound traffic.

### Route Tables

Each subnet is associated with a route table that determines where traffic is directed.

```
Destination       Target
10.0.0.0/16       local           # Intra-VPC routing
0.0.0.0/0         igw-abc123      # Internet (public subnet)
0.0.0.0/0         nat-def456      # NAT Gateway (private subnet)
10.1.0.0/16       pcx-ghi789      # VPC peering connection
```

### Internet Gateway (IGW)

Enables communication between VPC resources and the internet. Only one IGW per VPC. Performs NAT for instances with public IPs.

### NAT Gateway / NAT Instance

Allows private subnet resources to initiate outbound connections (e.g., software updates) without being directly reachable from the internet.

### VPC Peering

Direct network link between two VPCs. Traffic stays on the cloud provider's backbone (no internet transit). Non-transitive — if VPC-A peers with VPC-B and VPC-B peers with VPC-C, VPC-A cannot reach VPC-C through VPC-B.

### Transit Gateway

Hub-and-spoke connectivity for multiple VPCs and on-premises networks. Eliminates the mesh complexity of many peering connections.

## Cross-Cloud Comparison

| Concept | AWS | Azure | GCP |
|---|---|---|---|
| Virtual Network | VPC | VNet | VPC |
| Subnet Scope | Per-AZ | Per-Region | Per-Region |
| Internet Gateway | IGW | Implicit | Implicit |
| NAT | NAT Gateway | NAT Gateway | Cloud NAT |
| Peering | VPC Peering | VNet Peering | VPC Peering |
| Hub-Spoke | Transit Gateway | Virtual WAN / Hub | NCC |

## Security-Relevant VPC Features

### Flow Logs

All major providers offer flow logs that capture metadata about network connections. Essential for security monitoring.

- **AWS:** VPC Flow Logs (S3, CloudWatch, or Kinesis)
- **Azure:** NSG Flow Logs (Storage Account, Log Analytics)
- **GCP:** VPC Flow Logs (Cloud Logging)

## Common Misconfigurations

| Issue | Risk | Detection |
|---|---|---|
| Public subnet with no NACL restrictions | Unrestricted inbound access | Infrastructure audit |
| S3/Blob with public access | Data exposure | Cloud security posture management |
| Default security group allows all outbound | Exfiltration path | Security group review |
| Overly permissive peering routes | Lateral movement between VPCs | Route table audit |
| Missing flow logs | No visibility into network activity | Compliance check |

## SOC Priorities

Enable VPC flow logs and DNS logs everywhere. Alert on new peering connections, route changes, public IP assignments in private subnets, and security group modifications allowing 0.0.0.0/0. Integrate flow logs with SIEM for cross-correlation.
""",
    },
    {
        "title": "Security Groups vs NACLs — Cloud Network Controls",
        "tags": ["security-groups", "nacl", "cloud", "aws", "network-security", "access-control"],
        "content": r"""# Security Groups vs NACLs — Cloud Network Controls

## Overview

Cloud environments provide two primary network access control mechanisms: Security Groups (instance-level, stateful) and Network Access Control Lists (subnet-level, stateless). Using them together creates defense-in-depth at the network layer. This article focuses on AWS but the concepts map to Azure NSGs and GCP firewall rules.

## Security Groups (Stateful)

Security Groups act as virtual firewalls attached to individual network interfaces (ENIs). They are stateful — if inbound traffic is allowed, the response is automatically permitted without an explicit outbound rule.

### Key Characteristics

- Applied at the instance/ENI level
- **Allow-only rules** — you cannot create deny rules
- All rules are evaluated before deciding (not ordered)
- Default: deny all inbound, allow all outbound
- Supports referencing other security groups as sources (e.g., "allow traffic from the web-tier SG")

### Example Security Group Rules

**Web Server SG:**

| Direction | Protocol | Port | Source | Description |
|---|---|---|---|---|
| Inbound | TCP | 443 | 0.0.0.0/0 | HTTPS from internet |
| Inbound | TCP | 22 | sg-bastion | SSH from bastion only |
| Outbound | TCP | 5432 | sg-database | PostgreSQL to DB tier |
| Outbound | TCP | 443 | 0.0.0.0/0 | HTTPS for updates |

## Network ACLs (Stateless)

NACLs operate at the subnet boundary. They are stateless — you must explicitly allow both inbound and outbound traffic, including ephemeral return ports.

### Key Characteristics

- Applied at the subnet level
- Support both allow and deny rules
- Rules are evaluated in numerical order (lowest number first, first match wins)
- Default NACL allows all traffic; custom NACLs deny all by default
- Must account for ephemeral ports (1024-65535) for return traffic

NACL rules must explicitly handle ephemeral return ports (1024-65535) since they are stateless. Rules are numbered, and custom NACLs deny all by default.

## When to Use Each

| Scenario | Recommended Control |
|---|---|
| Per-instance access control | Security Group |
| Subnet-wide IP block (threat response) | NACL |
| Allow traffic between tiers | Security Group (SG references) |
| Emergency block of compromised IP | NACL (immediate, broad) |
| Microsegmentation | Security Group |
| Compliance audit boundary | NACL (clear subnet perimeter) |

## Defense-in-Depth Strategy

Use both together:

1. **NACLs** as a coarse outer boundary — block known-bad ranges, enforce subnet isolation
2. **Security Groups** as fine-grained inner controls — restrict per-instance to only required flows

## SOC Incident Response

During an incident, NACLs are the fastest isolation tool — add a low-numbered deny rule to immediately block a compromised IP across the entire subnet without touching individual security groups.
""",
    },
    {
        "title": "VPN Technologies — IPSec and WireGuard",
        "tags": ["vpn", "ipsec", "wireguard", "encryption", "remote-access", "network-security"],
        "content": r"""# VPN Technologies — IPSec and WireGuard

## Overview

Virtual Private Networks create encrypted tunnels over untrusted networks. SOC analysts encounter VPN traffic in logs daily — understanding the underlying protocols helps distinguish legitimate tunnels from unauthorized VPN usage by attackers or policy violators.

## IPSec VPN

IPSec is a protocol suite operating at Layer 3, providing authentication, integrity, and confidentiality for IP traffic.

### IPSec Phases

**Phase 1 (IKE SA):** Establishes a secure channel between peers for negotiation.

- IKEv1: Main Mode (6 messages, identity protected) or Aggressive Mode (3 messages, faster but exposes identity)
- IKEv2: Simplified to 4 messages (IKE_SA_INIT + IKE_AUTH), supports EAP, MOBIKE for roaming

**Phase 2 (IPSec SA):** Negotiates the actual data encryption parameters.

- Quick Mode (IKEv1) or CREATE_CHILD_SA (IKEv2)
- Defines transform sets: encryption algorithm, hash, PFS group

### IPSec Modes

| Mode | Description | Use Case |
|---|---|---|
| Tunnel | Entire IP packet encrypted + new IP header | Site-to-site VPN |
| Transport | Only payload encrypted, original IP header preserved | Host-to-host, L2TP/IPSec |

### IPSec Protocols

| Protocol | IP Protocol | Function |
|---|---|---|
| AH (Authentication Header) | 51 | Integrity + authentication, no encryption |
| ESP (Encapsulating Security Payload) | 50 | Encryption + integrity + authentication |
| IKE (Internet Key Exchange) | UDP 500 | Key negotiation |
| NAT-T (NAT Traversal) | UDP 4500 | IPSec through NAT devices |

**Site-to-site** connects two network perimeters with automatic encryption. **Remote access** connects individual clients to a concentrator, often using IKEv2 + EAP.

## WireGuard

WireGuard is a modern VPN protocol designed for simplicity and performance. It uses a fixed set of cryptographic primitives — no negotiation.

### Cryptographic Choices (Non-Negotiable)

- **Key Exchange:** Curve25519 (ECDH)
- **Encryption:** ChaCha20
- **MAC:** Poly1305
- **Hash:** BLAKE2s

### Key Characteristics

- ~4,000 lines of code (vs ~100,000+ for OpenVPN/IPSec)
- Kernel-space implementation for high performance
- UDP-only (single port, configurable, default 51820)
- Cryptokey routing: each peer has a public key and allowed IP ranges
- Silent to unauthenticated packets (stealth — no response to probes)
- Built-in roaming support (seamless IP changes)

Configuration is minimal: an interface section (private key, address, DNS) and peer sections (public key, endpoint, allowed IPs).

## SOC Monitoring Considerations

### Legitimate vs Unauthorized VPN

| Indicator | Legitimate | Suspicious |
|---|---|---|
| Destination | Corporate VPN gateway | Unknown external IP |
| Port | Standard (500, 4500, 1194, 51820) | Non-standard or dynamic |
| Duration | Business hours, reasonable | 24/7 persistent |
| User | Known employee | Service account, no associated user |
| Certificate | Corporate CA | Self-signed or unknown CA |

### Detection Strategies

- Monitor for ISAKMP (UDP 500) and ESP (IP protocol 50) traffic to non-corporate destinations
- Alert on WireGuard handshakes to unknown endpoints
- Track OpenVPN signatures on non-standard ports
- Correlate VPN usage with AD authentication — VPN without login is suspicious
- Baseline VPN traffic patterns and alert on volume anomalies
""",
    },
    {
        "title": "SD-WAN Concepts and Security Implications",
        "tags": ["sd-wan", "wan", "networking", "cloud", "security-architecture"],
        "content": r"""# SD-WAN Concepts and Security Implications

## Overview

Software-Defined Wide Area Networking (SD-WAN) decouples the network control plane from the data plane, enabling centralized management of WAN connections across multiple transport types (MPLS, broadband, LTE/5G). For SOC teams, SD-WAN changes traffic patterns, introduces new management surfaces, and can both improve and complicate security monitoring.

## Traditional WAN vs SD-WAN

| Aspect | Traditional WAN | SD-WAN |
|---|---|---|
| Transport | Dedicated MPLS circuits | Multiple (MPLS + broadband + cellular) |
| Routing | Per-device CLI configuration | Centralized orchestrator |
| Path Selection | Static routing / OSPF/BGP | Application-aware dynamic routing |
| Cloud Access | Backhaul through HQ datacenter | Direct internet breakout at branch |
| Cost | High (MPLS premium) | Lower (commodity broadband) |
| Deployment | Weeks/months | Hours/days (zero-touch provisioning) |

## SD-WAN Architecture

```
[Central Orchestrator / Controller]
         |
    [SD-WAN Fabric]
    /      |       \
[Branch]  [Branch]  [Branch]
  |          |         |
[MPLS]   [Broadband] [LTE]
```

### Key Components

- **Orchestrator:** Central management console for policy, configuration, and monitoring
- **Controller:** Distributes routing and security policies to edge devices
- **Edge Device (CPE):** Branch appliance that enforces policies, encrypts tunnels, selects paths
- **Overlay Tunnels:** IPSec or proprietary encrypted tunnels between sites over any underlay transport

## Security Benefits

### Encrypted Overlay

All inter-site traffic is encrypted by default, regardless of the underlying transport. Even traffic over commodity broadband is protected.

### Microsegmentation

SD-WAN can segment traffic by application, user, or device type across the WAN — isolating IoT devices from corporate systems, for example.

### Centralized Policy

Security policies are defined once in the orchestrator and pushed to all edges. This reduces configuration drift and ensures consistent enforcement.

### Zero-Touch Provisioning

New branch devices authenticate to the controller and receive their configuration automatically. Reduces manual errors but requires strong device authentication.

## Security Risks and SOC Concerns

### Direct Internet Access (DIA)

The biggest security shift: SD-WAN often enables branches to access cloud and internet directly rather than backhauling through a central security stack.

**Risk:** Branch traffic bypasses centralized IDS/IPS, proxy, and DLP. Each branch becomes an internet perimeter.

**Mitigation:** Deploy cloud-delivered security (SASE/SSE), integrate NGFW functionality into SD-WAN edge devices, or chain traffic through cloud security proxies.

### Management Plane Exposure

The central orchestrator is a high-value target. Compromise grants control over all WAN routing and policy.

**Mitigation:** Strong MFA, IP allowlisting, audit logging, network segmentation for management traffic.

### Visibility Gaps

Encrypted overlay tunnels can obscure traffic from network taps and IDS sensors placed on the underlay network.

**Mitigation:** Deploy inspection at the SD-WAN edge (many support integrated IDS/IPS), use orchestrator analytics, and export flow/log data to the SIEM.

## Monitoring Recommendations

- Ingest SD-WAN orchestrator logs and alerts into the SIEM
- Monitor for policy changes, new device registrations, and tunnel state changes
- Alert on unexpected DIA traffic patterns from branches
- Verify encryption status of all overlay tunnels
- Track application path selection for anomalies (e.g., sensitive data routed over untrusted transport)
""",
    },
    {
        "title": "SASE Architecture and Security Service Edge",
        "tags": ["sase", "sse", "zero-trust", "cloud-security", "network-architecture"],
        "content": r"""# SASE Architecture and Security Service Edge

## Overview

Secure Access Service Edge (SASE, pronounced "sassy") converges networking (SD-WAN) and security (SSE) into a cloud-delivered service. Coined by Gartner in 2019, SASE addresses the reality that users, applications, and data are no longer confined to the corporate perimeter.

## The Problem SASE Solves

Traditional architecture routes all traffic through a central datacenter for security inspection. This creates:

- **Latency:** Cloud-bound traffic hairpins through HQ, adding round-trip time
- **Bottlenecks:** Central firewalls and proxies become chokepoints
- **Blind spots:** Remote users on VPN split-tunnel bypass security controls
- **Complexity:** Separate products for firewall, proxy, CASB, ZTNA, and SD-WAN

## SASE Components

### Networking Side (SD-WAN)

- Application-aware routing over multiple transports
- WAN optimization (deduplication, compression, TCP optimization)
- Quality of Service (QoS) enforcement
- Dynamic path selection based on latency, jitter, and loss metrics

### Security Side (SSE — Security Service Edge)

| Service | Function |
|---|---|
| SWG (Secure Web Gateway) | URL filtering, malware scanning, DLP for web traffic |
| CASB (Cloud Access Security Broker) | Visibility and control over SaaS usage |
| ZTNA (Zero Trust Network Access) | Identity-based access to applications (replaces VPN) |
| FWaaS (Firewall as a Service) | Cloud-hosted firewall for non-web traffic |
| RBI (Remote Browser Isolation) | Renders web content in cloud, streams pixels to user |
| DLP (Data Loss Prevention) | Inspect and block sensitive data in transit |

## Zero Trust Network Access (ZTNA)

ZTNA is the component that most directly replaces traditional VPN:

- **Identity-centric:** Access decisions based on user identity, device posture, and context — not network location
- **Application-specific:** Users access only authorized applications, not the entire network
- **Continuous verification:** Posture and context re-evaluated throughout the session
- **Invisible to attackers:** Applications are not exposed to the internet; the ZTNA broker mediates all connections

### VPN vs ZTNA Comparison

| Aspect | Traditional VPN | ZTNA |
|---|---|---|
| Access scope | Full network access | Per-application access |
| Authentication | Once at connection | Continuous |
| Network visibility | User on the network | Application only |
| Lateral movement | Possible | Prevented by design |
| Scalability | Concentrator bottleneck | Cloud-native, elastic |
| User experience | Client software, split-tunnel complexity | Transparent or lightweight agent |

## SASE Deployment Models

**Single-vendor** (Palo Alto Prisma, Fortinet FortiSASE, Cisco Secure Connect, Cato Networks) simplifies management but may lack best-of-breed in every category. **Dual-vendor** combines existing SD-WAN with separate SSE (e.g., Viptela + Zscaler) for incremental adoption.

## SOC Monitoring in a SASE Environment

**Data sources:** SASE platform logs, ZTNA connection logs, CASB events, SWG logs.

**Key alerts:** Failed ZTNA access attempts, device posture failures, DLP violations, anomalous SaaS usage, and new shadow IT detection. Cross-correlate with endpoint detection for full attack chain visibility.
""",
    },
    {
        "title": "Container Networking — CNI and Service Mesh",
        "tags": ["containers", "kubernetes", "cni", "service-mesh", "istio", "network-security"],
        "content": r"""# Container Networking — CNI and Service Mesh

## Overview

Container networking introduces a dynamic, ephemeral network layer that traditional monitoring tools struggle to observe. SOC analysts working in Kubernetes environments need to understand Container Network Interface (CNI) plugins, network policies, and service mesh architectures to effectively monitor and investigate incidents.

## Container Networking Basics

Each container (pod in Kubernetes) receives its own IP address. Containers within a pod share a network namespace (communicate over localhost). Pods communicate across nodes via an overlay or routed network managed by a CNI plugin.

### Kubernetes Networking Model

Kubernetes mandates:

1. Every pod gets a unique IP address
2. Pods can communicate with all other pods without NAT
3. Nodes can communicate with all pods without NAT
4. The IP a pod sees for itself is the same IP others see

## CNI Plugins

The Container Network Interface is a specification for configuring network interfaces in Linux containers. The CNI plugin is responsible for IP allocation, routing, and network policy enforcement.

| CNI Plugin | Type | Key Features |
|---|---|---|
| Calico | Routed (BGP) or overlay (VXLAN) | Network policy, eBPF datapath, high performance |
| Cilium | eBPF-native | L3-L7 policy, transparent encryption, deep observability |
| Flannel | Overlay (VXLAN) | Simple, limited policy support |
| Weave Net | Overlay (VXLAN) | Encryption, multicast support |
| AWS VPC CNI | Native VPC | Pods get VPC IPs, integrates with security groups |
| Azure CNI | Native VNet | Pods on VNet subnet, integrates with NSGs |

### Security-Relevant CNI Choice

**Calico** and **Cilium** are the primary choices for security-conscious deployments because they support Kubernetes Network Policies and extend them with more granular controls.

## Kubernetes Network Policies

Network Policies are Kubernetes-native firewall rules for pods. Without them, all pod-to-pod traffic is allowed by default. Policies use label selectors to match pods and define allowed ingress/egress. **Best practice:** Start with a default-deny policy per namespace, then explicitly allow required traffic.

## Service Mesh

A service mesh adds a sidecar proxy (typically Envoy) alongside each pod to handle inter-service communication. This provides security features transparent to the application.

### Key Security Features

| Feature | Description |
|---|---|
| Mutual TLS (mTLS) | Automatic encryption and authentication between services |
| Authorization Policies | L7 access control (HTTP method, path, headers) |
| Observability | Detailed metrics, traces, and access logs for every request |
| Rate Limiting | Prevent resource abuse and DoS between services |
| Circuit Breaking | Isolate failing services to prevent cascade failures |

**Major implementations:** Istio (feature-rich, Envoy-based), Linkerd (lightweight, Rust-based), Cilium (eBPF, sidecar-free), Consul Connect (HashiCorp ecosystem).

## SOC Monitoring for Container Networks

**Data sources:** CNI flow logs (Cilium Hubble, Calico), service mesh access logs, Kubernetes audit logs, CoreDNS query logs.

**Key indicators:** Pods communicating with unexpected namespaces or external IPs, network policy changes (defense evasion), mTLS certificate errors, unusual egress from restricted pods, DNS queries for external domains from internal-only services, high-volume inter-pod traffic suggesting lateral movement.
""",
    },
]

TRAFFIC_ANALYSIS = [
    {
        "title": "Establishing Baseline Traffic Patterns",
        "tags": ["baseline", "traffic-analysis", "anomaly-detection", "network-monitoring", "soc"],
        "content": r"""# Establishing Baseline Traffic Patterns

## Overview

Effective anomaly detection requires knowing what "normal" looks like. A network traffic baseline captures typical patterns — volume, protocols, endpoints, timing — so that deviations can trigger investigation. Without a baseline, analysts drown in noise or miss subtle indicators.

## What to Baseline

### Volume Metrics

| Metric | Granularity | Purpose |
|---|---|---|
| Total bandwidth (Gbps) | Per link, per hour | Detect DDoS, exfiltration |
| Packets per second | Per interface | Identify flood attacks |
| Flow count | Per subnet | Spot scanning or worm propagation |
| DNS queries per second | Per resolver | DNS amplification, tunneling |

### Connection Patterns

- **Top talkers:** Which hosts generate the most traffic (by bytes and by connections)
- **Top destinations:** External IPs/domains that receive the most traffic
- **Protocol distribution:** TCP vs UDP vs ICMP ratios per subnet
- **Port usage:** Which ports carry traffic, and what percentage of total

### Temporal Patterns

- **Business hours vs off-hours:** Traffic volume should drop significantly outside working hours
- **Day of week:** Monday spikes from update downloads, Friday drops from early departures
- **Monthly cycles:** Backup windows, patch deployments, end-of-month batch processing

### Directional Patterns

- **Inbound/outbound ratio:** Most organizations send more data inbound (downloads) than outbound
- **East-west vs north-south:** Internal traffic typically exceeds internet-bound traffic in enterprise networks

## Baselining Methodology

### 1. Data Collection (2-4 Weeks Minimum)

Collect NetFlow/sFlow, firewall logs, DNS logs, and proxy logs for at least two full business weeks. Four weeks is better to capture monthly cycles.

### 2. Filter Out Known Anomalies

Remove known events from the baseline period — planned maintenance windows, DDoS incidents, or infrastructure migrations that would skew the baseline.

### 3. Statistical Profiling

For each metric, calculate:

- **Mean and median** (central tendency)
- **Standard deviation** (spread)
- **95th and 99th percentiles** (peak thresholds)
- **Time-of-day profiles** (hourly averages for each day of week)

### 4. Segment and Update

Create separate baselines per network segment, application, and user group. Recalculate weekly or monthly to adapt to legitimate changes.

## Anomaly Detection Thresholds

| Alert Level | Threshold | Example |
|---|---|---|
| Warning | > 2 standard deviations from mean | Unusual but could be legitimate |
| Alert | > 3 standard deviations from mean | Likely abnormal, investigate |
| Critical | > 99th percentile or new pattern | Never seen before, immediate triage |

## Practical Examples

- **Exfiltration:** Workstation uploading 5GB overnight vs 50MB/day baseline — 100x deviation
- **Lateral movement:** Server contacting 200 internal IPs on port 445 vs normal 15
- **C2:** New persistent connection to geography with zero historical traffic

**Tools:** SIEM statistical aggregations (Elastic, Splunk), ML-based monitoring (Darktrace, ExtraHop, Vectra), flow analysis (ntopng, SiLK), custom Python/Pandas scripts.
""",
    },
    {
        "title": "Beaconing Detection Methods",
        "tags": ["beaconing", "c2", "detection", "traffic-analysis", "threat-hunting"],
        "content": r"""# Beaconing Detection Methods

## Overview

Beaconing is the periodic callback an implant makes to its command-and-control (C2) server. Because attackers need reliable communication with their implants, beacons create regular patterns that defenders can detect through statistical analysis, even when the traffic is encrypted.

## Why Beaconing Is Detectable

C2 frameworks (Cobalt Strike, Metasploit, Sliver, Mythic) use configurable beacon intervals with optional jitter. Even with jitter, the underlying regularity produces statistical signatures that differentiate beaconing from human-generated web browsing.

## Detection Approach 1 — Interval Analysis

### Method

1. Extract all connection timestamps from one source IP to one destination IP
2. Calculate inter-arrival times (delta between consecutive connections)
3. Compute the coefficient of variation (CV): `CV = standard_deviation / mean`

### Interpretation

| CV Value | Interpretation |
|---|---|
| < 0.05 | Almost certainly automated (very regular) |
| 0.05 - 0.15 | Likely beaconing with low jitter |
| 0.15 - 0.30 | Possible beaconing with moderate jitter |
| > 0.30 | Likely human-driven or high-jitter C2 |

### Example Calculation

```python
import numpy as np

timestamps = [0, 60, 121, 179, 241, 299, 362, 420]  # seconds
deltas = np.diff(timestamps)  # [60, 61, 58, 62, 58, 63, 58]
cv = np.std(deltas) / np.mean(deltas)  # ~0.035 — strong beacon signal
```

### Challenges

- **High jitter:** Advanced C2 configurations use 50%+ jitter to increase CV
- **Working hours only:** Some beacons sleep during off-hours, creating gaps
- **Multiplexed connections:** Multiple beacons to the same server from different implants

## Detection Approach 2 — Frequency Domain Analysis (FFT)

Convert time-series connection data into the frequency domain using FFT. Beacons produce a strong spectral peak at the beacon frequency. Works well for long observation windows (24+ hours) and can identify multiple beacon intervals from the same host. Requires at least 50-100 events and is computationally expensive at scale.

## Detection Approach 3 — Session Size Consistency

Beacons often exchange similar amounts of data per callback (check-in request and response are templated). Look for:

- Consistent request sizes (e.g., always ~200 bytes)
- Consistent response sizes when no commands are issued (e.g., always ~100 bytes)
- Occasional response size spikes (command delivery)

Combine size consistency with timing regularity for higher confidence detection.

## Detection Approach 4 — RITA / AC-Hunter

**RITA (Real Intelligence Threat Analytics)** is an open-source tool specifically designed for beacon detection in Zeek logs.

RITA analyzes:

- Connection frequency and regularity
- Data size consistency
- Duration consistency
- Combines scores into a beacon probability

```bash
# Import Zeek logs
rita import /opt/zeek/logs/2024-01-15/ dataset_name

# Analyze for beacons
rita show-beacons dataset_name
# Output: Score | Source | Destination | Connections | Avg Bytes | ...
```

## Evasion and Counter-Evasion

**Attacker evasion:** High jitter (50-90%), domain fronting, traffic blending, work-hours-only beaconing, long intervals.

**Analyst counters:** Lower CV thresholds with multi-indicator correlation, longer observation windows, destination reputation and JA3/JA3S fingerprint analysis, detecting beacon clusters (multiple hosts to same destination).
""",
    },
    {
        "title": "Lateral Movement Traffic Signatures",
        "tags": ["lateral-movement", "traffic-analysis", "detection", "threat-hunting", "active-directory"],
        "content": r"""# Lateral Movement Traffic Signatures

## Overview

Lateral movement is the post-compromise phase where attackers traverse the internal network to reach high-value targets. Because this traffic occurs entirely within the network perimeter, it often bypasses perimeter-focused defenses. SOC analysts must understand the network signatures of common lateral movement techniques.

## SMB-Based Lateral Movement

### PsExec / Remote Service Creation

**Network signature:** SMB (TCP 445) connection from attacker-controlled host to target, followed by service creation via SVCCTL named pipe.

| Phase | Protocol | Indicator |
|---|---|---|
| Authentication | SMB | NTLM or Kerberos auth to IPC$ share |
| Binary Upload | SMB | Write to ADMIN$ or C$ share |
| Service Creation | SMB (SVCCTL) | Named pipe `\pipe\svcctl` |
| Execution | SMB | Service start command |
| Cleanup | SMB | Service deletion, binary removal |

**Detection:** Alert on SMB writes to ADMIN$ from workstations (not admin jump boxes). Monitor for rapid SMB connections to multiple hosts.

## WMI-Based Movement

**Network signature:** DCOM/WMI uses TCP 135 (RPC endpoint mapper) followed by a high ephemeral port for the actual WMI connection.

```
Step 1: TCP 135 → Endpoint mapper returns ephemeral port
Step 2: TCP 49152-65535 → WMI command execution
```

**Detection:** Alert on TCP 135 from workstations to other workstations (WMI is typically server-admin only). Look for `wmic.exe` or `wmiprvse.exe` in process logs correlated with network connections.

## WinRM / PowerShell Remoting

**Network signature:** HTTP/HTTPS on ports 5985 (HTTP) or 5986 (HTTPS).

**Detection:** Monitor for connections on 5985/5986 between hosts that lack an administrative relationship. PowerShell remoting between workstations is almost always suspicious.

## RDP Lateral Movement

**Network signature:** TCP 3389. **Detection:** RDP between workstations (unusual), off-hours RDP from unexpected hosts, multiple rapid RDP sessions (credential testing), RDP tunneled over SSH.

## Pass-the-Hash / Pass-the-Ticket

### Pass-the-Hash (PtH)

Attacker uses stolen NTLM hash without knowing the password. **Detection:** Look for NTLM auth from hosts that normally use Kerberos — indicates NTLM downgrade forced by hash-based authentication.

### Pass-the-Ticket (PtT)

Attacker uses stolen or forged Kerberos tickets. **Indicators:** Encryption type anomalies (RC4 when environment uses AES), abnormally long TGT lifetimes (golden ticket), service tickets without prior TGT request (silver ticket).

## DCSync

Attacker replicates AD data using MS-DRSR protocol (mimics DC replication). **Detection:** Alert on DRS replication traffic (RPC 135 + ephemeral port) from IPs that are not domain controllers.

## Detection Summary

| Technique | Port | Key Indicator |
|---|---|---|
| PsExec | 445 | SMB write to ADMIN$ + SVCCTL pipe |
| WMI | 135 + ephemeral | RPC from non-admin source |
| WinRM | 5985/5986 | HTTP/S between workstations |
| RDP | 3389 | Workstation-to-workstation |
| DCSync | 135 + ephemeral | DRS from non-DC |

## Mitigations

Microsegmentation restricting workstation-to-workstation traffic, SMB (445) blocking between workstation subnets, WinRM restricted to admin jump boxes, east-west IDS sensors, and honeypots on lateral movement paths.
""",
    },
    {
        "title": "Data Exfiltration Detection Techniques",
        "tags": ["exfiltration", "dlp", "detection", "traffic-analysis", "data-loss"],
        "content": r"""# Data Exfiltration Detection Techniques

## Overview

Data exfiltration is the unauthorized transfer of data from the organization. It is often the final objective of an intrusion, whether the goal is intellectual property theft, espionage, or ransomware double-extortion. Detecting exfiltration requires monitoring multiple channels and understanding attacker techniques.

## Exfiltration Channels

### Network-Based Channels

| Channel | Protocol | Detection Difficulty |
|---|---|---|
| HTTPS to cloud storage | TCP 443 | Medium (encrypted, blends with normal) |
| DNS tunneling | UDP 53 | Medium (volume/entropy analysis) |
| ICMP tunneling | ICMP | Low (unusual data in ICMP payloads) |
| FTP/SFTP | TCP 20-21/22 | Low (uncommon in modern environments) |
| Email attachments | TCP 25/587/993 | Medium (DLP can inspect) |
| Custom C2 protocol | Various | High (encrypted, custom encoding) |
| Steganography | Any | Very High (data hidden in images/files) |

## Detection Technique 1 — Volume Anomaly

Compare current upload volume against the host's historical baseline. Alert when outbound data exceeds 3 standard deviations from the mean, single sessions exceed 500MB, or daily uploads exceed the 99th percentile.

**Ratio analysis:** Most workstations download far more than they upload (10:1 to 50:1). A ratio below 2:1 or inverted is suspicious.

## Detection Technique 2 — Destination Analysis

### Uncommon Destinations

Flag outbound connections to:

- IPs/domains never previously contacted by this host or subnet
- Recently registered domains (< 30 days old)
- Dynamic DNS providers (duckdns.org, no-ip.com, etc.)
- Cloud storage personal instances (personal OneDrive vs corporate)
- Hosting providers commonly used for C2 (DigitalOcean, Linode, Vultr VPS ranges)
- Geographies unusual for the organization's business

### Domain Generation Algorithms (DGA)

Automated exfiltration may use DGA domains. Detect via high Shannon entropy in domain names (> 3.5 bits per character) and high NXDomain response rates.

## Detection Technique 3 — Protocol Anomaly

**DNS tunneling:** Query length > 50 chars, high volume to single domain, unusual record types (TXT, NULL), high entropy in subdomains.

**ICMP tunneling:** Large payloads (> 64 bytes), high packet rate between two hosts, non-standard type/code values.

## Detection Technique 4 — Content Inspection (DLP)

Deploy DLP at network egress to inspect for credit card numbers, SSNs, source code signatures, classification labels, and custom patterns. Limitation: DLP requires TLS inspection for encrypted traffic.

## Detection Technique 5 — Timing Analysis

Sophisticated attackers trickle data slowly to stay below thresholds. Monitor cumulative volume over days/weeks — 100MB/day for 30 days is 3GB. Large transfers during off-hours when the user is inactive are especially suspicious.

## Response Actions

1. **Confirm** the host, user, destination, and volume
2. **Preserve evidence** — PCAP capture, flow data snapshot
3. **Identify data** — DLP logs, accessed files, clipboard activity
4. **Contain** — block destination at firewall, isolate host
5. **Investigate scope** — check other hosts contacting the same destination
""",
    },
    {
        "title": "Encrypted Traffic Analysis — JA3, JA3S, and JARM",
        "tags": ["ja3", "jarm", "tls", "encrypted-traffic", "fingerprinting", "threat-hunting"],
        "content": r"""# Encrypted Traffic Analysis — JA3, JA3S, and JARM

## Overview

With most traffic encrypted, payload inspection is often impossible without TLS decryption. TLS fingerprinting techniques — JA3, JA3S, and JARM — extract identifying information from the TLS handshake itself, which occurs in plaintext before encryption begins. These fingerprints identify client applications, server configurations, and C2 frameworks without decrypting traffic.

The ClientHello and ServerHello messages are sent in plaintext before encryption begins, providing rich metadata for fingerprinting.

## JA3 — Client Fingerprint

JA3 creates an MD5 hash from specific ClientHello fields:

```
JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
```

### Example

```
TLSVersion: 771 (TLS 1.2)
Ciphers: 49195,49199,49196,49200,52393,52392,49171,49172
Extensions: 0,23,65281,10,11,35,16,5,13,28
EllipticCurves: 29,23,24,25
ECPointFormats: 0

JA3 String: 771,49195-49199-49196-49200-52393-52392-49171-49172,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0
JA3 Hash: e7d705a3286e19ea42f587b344ee6865
```

### Security Applications

| Use Case | How |
|---|---|
| Identify C2 frameworks | Cobalt Strike, Metasploit, Sliver have known JA3 hashes |
| Detect malware families | Many malware families use distinctive TLS libraries |
| Identify unauthorized software | Custom apps or tunneling tools have unique fingerprints |
| Track threat actors | Consistent tooling produces consistent JA3 values |

### Known C2 JA3 Hashes (Examples)

```
Cobalt Strike (default):  72a589da586844d7f0818ce684948eea
Metasploit (Meterpreter):  5d65ea3fb1d4aa7d826733d2f2cbbb1d
Trickbot:                  6734f37431670b3ab4292b8f60f29984
```

**Important:** Attackers can modify JA3 by changing TLS library settings. Treat JA3 matches as indicators, not proof.

## JA3S — Server Fingerprint

JA3S fingerprints the ServerHello response:

```
JA3S = MD5(TLSVersion,Cipher,Extensions)
```

The server's response is influenced by the client's offer, so the same server may produce different JA3S hashes for different clients. The **JA3 + JA3S pair** is more specific than either alone.

### Application

- Identify C2 servers by their consistent ServerHello responses
- Detect malleable C2 profiles (Cobalt Strike) that produce characteristic server fingerprints
- Profile servers without active scanning

## JARM — Active Server Fingerprint

JARM actively probes a server with 10 specially crafted ClientHello messages and fingerprints the responses.

```
JARM = concatenated hash of 10 ServerHello responses
```

### How JARM Works

1. Send 10 different ClientHellos (varying TLS versions, cipher suites, extensions)
2. Record each ServerHello response (cipher chosen, TLS version, extensions)
3. Hash the combined responses into a single 62-character fingerprint

JARM is active (probes the server) unlike passive JA3S, making it consistent per server configuration regardless of client. Use it to identify C2 infrastructure (Cobalt Strike default JARM: `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`), scan IP ranges for C2 servers, and cluster unknown infrastructure.

## Deployment and Integration

### Zeek Integration

Zeek has native JA3 support:

```
# In Zeek logs (ssl.log):
# ja3: e7d705a3286e19ea42f587b344ee6865
# ja3s: ec74a5c51106f0419184d0dd08fb05bc
```

### SIEM Correlation

Enrich TLS metadata with JA3/JA3S lookups:

1. Extract JA3 hashes from Zeek/Suricata logs
2. Match against threat intelligence JA3 databases
3. Alert on known-bad hashes
4. Investigate unknown hashes with high connection frequency (potential new C2)

### Limitations

- JA3 is not unique per application — different software may share JA3 values
- Attackers can customize TLS settings to mimic legitimate browsers
- TLS 1.3 reduces ClientHello variability (fewer extensions visible)
- GREASE (RFC 8701) randomizes some extension values, adding noise
""",
    },
    {
        "title": "Zeek Log Analysis for Security Operations",
        "tags": ["zeek", "bro", "network-monitoring", "log-analysis", "traffic-analysis", "ndr"],
        "content": r"""# Zeek Log Analysis for Security Operations

## Overview

Zeek (formerly Bro) is an open-source network security monitor that produces rich, structured logs from network traffic. Unlike IDS systems that generate alerts based on signatures, Zeek creates a detailed transaction log of everything it observes — connections, DNS queries, HTTP requests, TLS handshakes, file transfers, and more. This makes it invaluable for threat hunting and forensic investigation.

## Core Zeek Log Files

| Log File | Contents | Key Fields |
|---|---|---|
| `conn.log` | Every TCP/UDP/ICMP connection | uid, src/dst IP/port, proto, duration, bytes, conn_state |
| `dns.log` | DNS queries and responses | query, qtype, answers, rcode, TTL |
| `http.log` | HTTP requests and responses | method, host, uri, user_agent, status_code, resp_body_len |
| `ssl.log` | TLS handshake details | server_name (SNI), ja3, ja3s, issuer, subject, validation |
| `files.log` | File transfers observed on wire | filename, mime_type, md5, sha1, sha256, total_bytes, source |
| `x509.log` | X.509 certificate details | subject, issuer, serial, not_valid_before/after |
| `smtp.log` | Email metadata | from, to, subject, mailfrom, rcptto |
| `smb_mapping.log` | SMB share access | path, share_type, native_file_system |
| `kerberos.log` | Kerberos authentication | client, service, cipher, success, error_msg |
| `notice.log` | Zeek-generated alerts | note, msg, src, dst, sub |

## Essential Hunt Queries

### Hunt 1 — Long Connections (C2 Persistence)

```bash
# Find connections lasting more than 8 hours
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 > 28800' | sort -t$'\t' -k4 -rn | head -20
```

Long-duration connections to external hosts suggest persistent C2 channels, especially if combined with regular data exchange patterns.

### Hunt 2 — Rare User Agents

```bash
# Find uncommon user agents
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -20
```

Rare or unusual user agents may indicate custom malware, C2 frameworks (Cobalt Strike uses configurable UAs), or unauthorized tools.

### Hunt 3 — Self-Signed Certificates

```bash
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name validation_status | \
  grep -v "^#" | grep -v "ok" | sort | uniq -c | sort -rn
```

Self-signed certificates on external hosts are common for C2 infrastructure.

### Hunt 4 — SMB Lateral Movement

```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | \
  awk '$3 == 445' | sort | uniq -c | sort -rn
```

Cross-reference IPs against your asset inventory to identify workstation-to-workstation SMB traffic.

## Zeek + SIEM Integration

Ship Zeek logs to Elasticsearch using Filebeat's Zeek module, which supports conn, dns, http, ssl, and files log types natively.

### UID Correlation

Zeek's `uid` field links records across log files — a single UID appears in conn.log, http.log, ssl.log, and files.log, enabling full session reconstruction.

**Operational tips:** Deploy on dedicated sensors with TAP/SPAN, rotate logs via `zeekctl`, enable file extraction for executables, and use `zkg` for community detection packages.
""",
    },
    {
        "title": "PCAP Reconstruction and Forensic Analysis",
        "tags": ["pcap", "forensics", "wireshark", "packet-capture", "traffic-analysis", "incident-response"],
        "content": r"""# PCAP Reconstruction and Forensic Analysis

## Overview

Full packet capture (PCAP) provides the most detailed record of network activity — every byte of every packet. During incident response, PCAP reconstruction can reveal the exact data stolen, commands executed, exploits used, and tools deployed. This article covers practical PCAP forensic techniques.

## Capture Strategies

### Full Packet Capture

Record every packet on monitored links.

| Parameter | Recommendation |
|---|---|
| Interface | SPAN port or TAP (not production interface) |
| Snap length | Full packet (65535 bytes) for forensics |
| Storage | 1 Gbps sustained ≈ 10 TB/day (uncompressed) |
| Retention | 3-7 days for hot storage, longer for cold/compressed |
| Format | pcapng (supports metadata, multiple interfaces) |

### Triggered Capture

Record only when specific conditions are met (IDS alert, flow anomaly). Reduces storage but may miss pre-trigger activity.

### Rolling Buffer

Continuous capture with automatic rotation — oldest files are deleted when storage fills. Tools: `tcpdump`, `dumpcap`, Stenographer, Moloch/Arkime.

## Essential Wireshark Techniques

### Display Filters for Investigation

```
# Follow a specific conversation
ip.addr == 10.0.1.50 && ip.addr == 198.51.100.1

# HTTP traffic only
http

# DNS queries for suspicious domain
dns.qry.name contains "evil.com"

# TLS handshakes (ClientHello)
tls.handshake.type == 1

# SMB file operations
smb2.cmd == 5  # Create/Open

# TCP SYN packets only (scanning)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Packets with specific content
frame contains "password"

# Specific connection by stream index
tcp.stream eq 42
```

### Stream Reconstruction and File Extraction

Use "Follow TCP/UDP/TLS Stream" to reconstruct full conversations (HTTP exchanges, FTP transfers, SMTP emails). Use File > Export Objects > HTTP/SMB to extract transferred files for malware analysis or evidence recovery. The Statistics menu provides conversation summaries, endpoint listings, protocol hierarchy, and I/O graphs for spotting traffic spikes.

## Command-Line PCAP Analysis

### Command-Line Tools

```bash
# Extract HTTP URIs
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# Extract TLS server names (SNI)
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e ip.src -e tls.handshake.extensions_server_name

# Process PCAP through Zeek for offline analysis
zeek -r suspicious.pcap local
```

## Forensic Reconstruction Workflow

1. **Scope the timeframe** from alerts, EDR data, or SIEM events
2. **Identify key hosts** — compromised hosts, C2 IPs, lateral movement targets
3. **Extract conversations** — filter and follow TCP streams for application data
4. **Timeline the activity** — map exploit, C2 setup, recon, lateral movement, exfiltration
5. **Extract artifacts** — export files, credentials, C2 patterns for IOC creation
6. **Document and hash** — MD5/SHA256 all artifacts, record IPs, domains, ports, timing

## Legal Considerations

PCAP contains sensitive data (passwords, PII) — encrypt at rest, document chain of custody for legal proceedings, and ensure retention policies comply with GDPR/HIPAA requirements.
""",
    },
    {
        "title": "DNS Log Threat Hunting",
        "tags": ["dns", "threat-hunting", "dns-tunneling", "dga", "traffic-analysis", "detection"],
        "content": r"""# DNS Log Threat Hunting

## Overview

DNS is involved in nearly every network connection, making DNS logs one of the richest data sources for threat hunting. Attackers rely on DNS for C2 communication, data exfiltration, domain generation algorithms, and reconnaissance. Because DNS is often loosely monitored and rarely blocked, it is a favored channel for adversary operations.

**Key sources:** Internal DNS resolver query logs, passive DNS sensors (Zeek, Suricata), cloud DNS logs (Route 53, Cloud DNS), EDR/Sysmon Event ID 22, DNS firewalls/RPZ.

## Hunt 1 — DNS Tunneling

Attackers encode data in DNS queries and responses, using the DNS protocol as a covert data channel. Tools: iodine, dnscat2, dns2tcp, Cobalt Strike DNS beacon.

### Indicators

| Indicator | Threshold | Rationale |
|---|---|---|
| Query length | > 50 characters | Normal queries rarely exceed 30 characters |
| Subdomain label count | > 4 labels | Deep subdomain nesting encodes data |
| Query volume to single domain | > 100/hour | Tunneling requires many queries |
| TXT record queries | High volume | TXT records carry larger payloads |
| Shannon entropy of subdomain | > 3.5 bits/char | Encoded/encrypted data has high entropy |
| Unique subdomain diversity | > 50 unique/hour | Each query carries different encoded data |

## Hunt 2 — Domain Generation Algorithms (DGA)

Malware uses algorithms to generate pseudo-random domain names for C2 rendezvous. Only the malware and the operator know which domains will be generated, making pre-registration blocking difficult.

### Characteristics of DGA Domains

- High character entropy (random-looking strings)
- Common TLDs (.com, .net, .org, .info, .top)
- No meaningful words or brand names
- Short registration history (often registered same day)
- Many NXDomain responses (most generated domains are not registered)

**Detection:** Calculate Shannon entropy of domain strings — DGA domains typically exceed 3.5 bits/char vs < 3.0 for legitimate domains. Also alert on hosts generating > 50 NXDomain responses per hour (most DGA domains are unregistered).

## Hunt 3 — Fast Flux and Newly Observed Domains

**Fast flux:** Domain resolving to > 10 unique IPs within 24 hours with TTL < 300 seconds across multiple ASNs.

**Newly observed domains:** Alert when hosts query domains never seen in your environment, registered within 30 days, or lacking passive DNS history.

## Hunt 5 — Exfiltration and Suspicious TXT Queries

Attackers encode data directly in DNS subdomains (e.g., `aGVsbG8gd29ybGQ.exfil.attacker.com`). Monitor for base64-like patterns in subdomains with lengths > 20 characters. Also watch for high-volume TXT record queries to a single domain — TXT records carry larger payloads and are commonly abused for tunneling.

## Operational Recommendations

- Log all DNS queries at the resolver level, not just firewall permit/deny
- Deploy DNS RPZ to block known-bad domains; sinkhole DGA/C2 domains to honeypots
- Enrich with WHOIS age, VirusTotal reputation, passive DNS history, and CT logs
- Monitor DNS-over-HTTPS (DoH) — attackers use it to evade DNS logging
- Correlate DNS logs with Sysmon Event 22 to identify the querying process
""",
    },
]

COLLECTIONS = [
    ("Firewalls, IDS/IPS & Network Security", "Firewall technologies, intrusion detection and prevention systems, WAF concepts, ACL design, flow analysis, and TLS inspection architecture for network defense.", FIREWALL_IDS),
    ("Wireless & Cloud Networking", "WiFi security protocols, cloud VPC architecture, security groups, VPN technologies, SD-WAN, SASE, and container networking for modern hybrid environments.", WIRELESS_CLOUD),
    ("Network Traffic Analysis & Threat Hunting", "Baseline traffic profiling, beaconing detection, lateral movement signatures, exfiltration detection, encrypted traffic fingerprinting, Zeek analysis, PCAP forensics, and DNS threat hunting.", TRAFFIC_ANALYSIS),
]
