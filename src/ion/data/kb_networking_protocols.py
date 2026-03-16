"""Built-in KB data: Networking — Protocols & Infrastructure."""

PACKET_ANALYSIS = [
    {
        "title": "TCP Three-Way Handshake Deep Dive",
        "tags": ["tcp", "handshake", "packet-analysis", "networking"],
        "content": r"""# TCP Three-Way Handshake Deep Dive

The TCP three-way handshake establishes a reliable, full-duplex connection between two hosts. Understanding each step is essential for diagnosing connectivity issues and detecting SYN-based attacks.

## The Three Steps

**Step 1 — SYN:** The client sends a TCP segment with the SYN flag set and a randomly chosen Initial Sequence Number (ISN). The source port is typically ephemeral (49152-65535), and the destination port identifies the service (e.g., 443 for HTTPS).

**Step 2 — SYN-ACK:** The server responds with both SYN and ACK flags set. It acknowledges the client's ISN by setting the ACK number to client_ISN + 1 and provides its own ISN. The server allocates resources for the half-open connection at this stage.

**Step 3 — ACK:** The client acknowledges the server's ISN by sending an ACK with acknowledgment number set to server_ISN + 1. The connection is now ESTABLISHED on both sides.

## Sequence Number Mechanics

Each side independently tracks sequence numbers. The ISN should be unpredictable — weak ISN generation (e.g., incremental) enables TCP session hijacking. Modern operating systems use RFC 6528 algorithms combining a secret key with connection tuple hashing.

## SYN Flood Attacks

Attackers send high volumes of SYN packets with spoofed source addresses. The server allocates resources for each half-open connection in the SYN backlog queue. When the queue fills, legitimate connections are refused.

**Defenses:** SYN cookies (encode state in the ISN, no backlog entry needed), SYN proxy (firewall completes handshake on behalf of server), rate limiting, and increased backlog size.

## What to Look For in Captures

- **Retransmissions of SYN:** Indicate packet loss or firewall drops. Default retries vary by OS (Linux: 6 retries, Windows: 2).
- **SYN without SYN-ACK:** Firewall blocking or service down. Look for ICMP unreachable responses.
- **RST after SYN:** Port is closed, or a firewall is actively rejecting.
- **Abnormal ISN patterns:** Predictable sequences suggest vulnerable or embedded systems.
- **Window size = 0 in SYN:** Unusual and may indicate a crafted packet.

## Wireshark Filter

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

This isolates initial SYN packets — useful for counting new connection attempts and spotting SYN floods.
""",
    },
    {
        "title": "TCP Flags & the TCP State Machine",
        "tags": ["tcp", "flags", "state-machine", "packet-analysis"],
        "content": r"""# TCP Flags & the TCP State Machine

TCP uses control flags in the header to manage connection state. Mastering these flags is critical for packet analysis, firewall rule writing, and detecting reconnaissance or evasion techniques.

## The Eight TCP Flags

| Flag | Bit | Purpose |
|------|-----|---------|
| **CWR** | 128 | Congestion Window Reduced — sender is reducing rate |
| **ECE** | 64 | ECN-Echo — congestion notification |
| **URG** | 32 | Urgent pointer field is significant |
| **ACK** | 16 | Acknowledgment field is significant |
| **PSH** | 8 | Push data to application layer immediately |
| **RST** | 4 | Reset the connection |
| **SYN** | 2 | Synchronize sequence numbers (connection setup) |
| **FIN** | 1 | No more data from sender (connection teardown) |

## The TCP State Machine

A TCP connection transitions through 11 states:

**Connection setup:** CLOSED → SYN_SENT → ESTABLISHED (client side). CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED (server side).

**Connection teardown (normal):** ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED (initiator). ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED (responder).

**TIME_WAIT** lasts 2x MSL (Maximum Segment Lifetime, typically 60 seconds on Linux). This prevents delayed segments from a previous connection being misinterpreted in a new connection on the same port pair.

## Abnormal Flag Combinations in Security

- **SYN+FIN:** Invalid combination — used in OS fingerprinting and IDS evasion. No legitimate stack produces this.
- **No flags set (NULL scan):** Nmap NULL scan — closed ports respond with RST, open ports may be silent.
- **All flags set (Xmas scan):** FIN+PSH+URG — similar response behavior, used for firewall evasion.
- **ACK only (no established session):** Nmap ACK scan — used to map firewall rulesets. Stateful firewalls drop these; stateless ones pass them.
- **RST flood:** Used in connection disruption attacks and TCP reset attacks (as described in RFC 3360 concerns).

## SOC Detection Use Cases

Monitor for unusual flag combinations in IDS/IPS signatures. Alert on high volumes of RST or FIN packets from a single source. Track TIME_WAIT accumulation which may indicate resource exhaustion attacks.

## Wireshark Filters

```
tcp.flags.syn == 1 && tcp.flags.fin == 1    # SYN+FIN (scan)
tcp.flags == 0x000                            # NULL scan
tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1  # Xmas
```
""",
    },
    {
        "title": "TLS Handshake Analysis",
        "tags": ["tls", "ssl", "encryption", "packet-analysis", "handshake"],
        "content": r"""# TLS Handshake Analysis

The TLS handshake establishes an encrypted channel between client and server. Analyzing TLS traffic is a core SOC skill — even without decryption, metadata from the handshake reveals valuable intelligence.

## TLS 1.2 Handshake (Full)

1. **ClientHello:** Client sends supported TLS versions, cipher suites (ordered by preference), a random value, session ID, SNI (Server Name Indication), and extensions.
2. **ServerHello:** Server selects the TLS version and cipher suite. Returns its random value and session ID.
3. **Certificate:** Server sends its X.509 certificate chain.
4. **ServerKeyExchange:** (If using DHE/ECDHE) Server sends ephemeral key parameters, signed with its private key.
5. **ServerHelloDone:** Signals the server is finished.
6. **ClientKeyExchange:** Client sends its key exchange data (e.g., pre-master secret encrypted with server's public key, or ECDHE public value).
7. **ChangeCipherSpec:** Both sides signal switch to encrypted communication.
8. **Finished:** Both sides send a hash of the entire handshake, encrypted. Verifies integrity.

## TLS 1.3 Improvements

TLS 1.3 reduces the handshake to **1-RTT** (one round trip). The ClientHello includes key shares directly, and the server responds with its key share plus encrypted extensions. The ServerHello and all subsequent messages are encrypted, making passive fingerprinting harder.

**0-RTT resumption** allows previously connected clients to send data in the first flight, but is vulnerable to replay attacks. Servers must implement anti-replay mechanisms.

## JA3/JA3S Fingerprinting

JA3 hashes the ClientHello fields (TLS version, cipher suites, extensions, elliptic curves, EC point formats) into an MD5 hash. This fingerprints the TLS client implementation. JA3S does the same for the ServerHello.

**SOC usage:** Known malware families produce consistent JA3 hashes. Threat intel feeds include JA3 indicators. A JA3 mismatch (e.g., a curl User-Agent with a Chrome JA3) indicates spoofing.

## What to Examine Without Decryption

- **SNI field:** Reveals the destination hostname in cleartext (TLS 1.2 and 1.3 without ECH).
- **Certificate subject/issuer:** Identify self-signed certs, unusual CAs, or expired certificates.
- **Cipher suite selection:** Weak ciphers (RC4, DES, export-grade) indicate misconfiguration or downgrade attacks.
- **Certificate transparency:** Compare presented certs against CT logs.

## Wireshark Filters

```
tls.handshake.type == 1          # ClientHello
tls.handshake.type == 2          # ServerHello
tls.handshake.extensions.server_name  # SNI
```
""",
    },
    {
        "title": "Wireshark Display Filters for SOC Analysts",
        "tags": ["wireshark", "display-filters", "packet-analysis", "soc"],
        "content": r"""# Wireshark Display Filters for SOC Analysts

Display filters are applied after capture to isolate traffic of interest. They use a rich syntax distinct from BPF capture filters. Mastering display filters dramatically speeds up incident investigation.

## Syntax Fundamentals

Display filters use a protocol.field operator value format. Fields are accessed through a dot-separated hierarchy matching the protocol dissector tree.

**Comparison operators:** `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `matches` (regex), `in`.

**Logical operators:** `&&` (and), `||` (or), `!` (not). Parentheses group conditions.

## Essential SOC Filters

### Connection Analysis
```
tcp.flags.syn == 1 && tcp.flags.ack == 0    # New connections only
tcp.analysis.retransmission                   # Retransmissions (network issues)
tcp.analysis.zero_window                      # Zero-window (resource exhaustion)
tcp.analysis.reset                            # Connection resets
```

### DNS Investigation
```
dns.qry.name contains "suspicious.com"        # Queries for a domain
dns.qry.type == 28                             # AAAA record queries
dns.resp.len > 512                             # Large DNS responses (tunneling?)
dns.flags.rcode != 0                           # DNS errors (NXDOMAIN, SERVFAIL)
```

### HTTP/HTTPS
```
http.request.method == "POST"                  # POST requests (data submission)
http.response.code >= 400                      # HTTP errors
tls.handshake.type == 1                        # TLS ClientHello
tls.handshake.extensions.server_name contains "evil"  # SNI filtering
```

### Lateral Movement Detection
```
smb2 || dcerpc || kerberos                     # Windows protocol suite
smb2.cmd == 5                                  # SMB2 Create (file access)
kerberos.CNameString contains "$"              # Machine account Kerberos tickets
ntlmssp.auth.username                          # NTLM authentication usernames
```

### Data Exfiltration Indicators
```
tcp.len > 1000 && ip.dst != 10.0.0.0/8        # Large outbound payloads
icmp.data.len > 64                             # ICMP tunneling (oversized payloads)
dns.qry.name.len > 50                          # Long DNS queries (DNS tunneling)
```

## Advanced Techniques

**Follow stream:** Right-click a packet and select Follow → TCP/HTTP/TLS Stream to reconstruct the full conversation. The stream index is stored in `tcp.stream`.

**Filter by conversation:** `ip.addr == 10.1.1.5 && ip.addr == 192.168.1.100` isolates traffic between two hosts regardless of direction.

**Time-based filtering:** `frame.time >= "2026-03-15 14:00:00" && frame.time <= "2026-03-15 15:00:00"` narrows to a time window during an incident.

**Export objects:** File → Export Objects → HTTP/SMB/TFTP to extract transferred files for malware analysis.

## Performance Tips

Apply display filters only after capture completes on large files. Use capture filters (BPF) for live monitoring to reduce memory usage. Color rules (`View → Coloring Rules`) provide visual triage without filtering out packets.
""",
    },
    {
        "title": "tshark CLI Usage for Automated Analysis",
        "tags": ["tshark", "cli", "packet-analysis", "automation"],
        "content": r"""# tshark CLI Usage for Automated Analysis

tshark is the command-line counterpart to Wireshark. It uses the same dissectors and display filter syntax but enables scripted, automated, and large-scale packet analysis — essential for SOC automation and incident response pipelines.

## Basic Usage Patterns

**Live capture:**
```bash
tshark -i eth0 -w capture.pcap                    # Capture to file
tshark -i eth0 -f "port 53" -c 1000               # BPF filter, 1000 packets
tshark -i eth0 -Y "http.request" -T fields -e http.host  # Live field extraction
```

**Read from file:**
```bash
tshark -r capture.pcap                              # Display summary
tshark -r capture.pcap -Y "dns" -c 50              # First 50 DNS packets
tshark -r capture.pcap -qz io,stat,60              # I/O stats per 60s interval
```

## Field Extraction (-T fields)

The `-T fields` mode outputs specific protocol fields as delimited text — ideal for piping into other tools.

```bash
# Extract source IP, dest IP, DNS query name
tshark -r capture.pcap -Y "dns.qry.name" \
  -T fields -e ip.src -e ip.dst -e dns.qry.name -E separator=,

# HTTP requests with host and URI
tshark -r capture.pcap -Y "http.request" \
  -T fields -e ip.src -e http.host -e http.request.uri

# TLS SNI extraction
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e tls.handshake.extensions.server_name
```

## Statistics and Summaries

```bash
tshark -r capture.pcap -qz conv,tcp          # TCP conversations
tshark -r capture.pcap -qz endpoints,ip      # IP endpoints by bytes
tshark -r capture.pcap -qz http,tree         # HTTP request/response stats
tshark -r capture.pcap -qz dns,tree          # DNS query type distribution
tshark -r capture.pcap -qz io,stat,10        # I/O graph data (10s buckets)
tshark -r capture.pcap -qz expert            # Expert info (errors, warnings)
```

## SOC Automation Examples

**Find beaconing (regular intervals):**
```bash
tshark -r capture.pcap -Y "ip.dst == 203.0.113.50" \
  -T fields -e frame.time_epoch | \
  awk '{if(prev) print $1-prev; prev=$1}'
```

**Extract all unique destination IPs:**
```bash
tshark -r capture.pcap -T fields -e ip.dst | sort -u
```

**Count packets per source IP (top talkers):**
```bash
tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head -20
```

**Export HTTP objects:**
```bash
tshark -r capture.pcap --export-objects http,/tmp/extracted_files/
```

## JSON Output for SIEM Integration

```bash
tshark -r capture.pcap -Y "dns" -T json > dns_traffic.json
tshark -r capture.pcap -T ek > elastic_bulk.json   # Elasticsearch bulk format
```

The `-T ek` output mode generates newline-delimited JSON suitable for direct ingestion into Elasticsearch via the bulk API. This enables rapid enrichment of PCAP data into your SIEM.

## Performance Considerations

For large captures (>1GB), use two-pass analysis: first apply a BPF capture filter to reduce the dataset, then use display filters on the result. The `-2` flag enables two-pass analysis for filters that require future packet knowledge (e.g., `tcp.analysis.retransmission`).
""",
    },
    {
        "title": "BPF Capture Filter Syntax",
        "tags": ["bpf", "capture-filters", "packet-analysis", "tcpdump"],
        "content": r"""# BPF Capture Filter Syntax

Berkeley Packet Filter (BPF) expressions are used for capture-time filtering in tcpdump, Wireshark capture filters, and tshark's `-f` flag. BPF filters run in kernel space, making them extremely efficient — they determine which packets are copied to userspace.

## Syntax Structure

BPF filters use primitives combined with logical operators. Each primitive consists of one or more qualifiers followed by an ID (name or number).

**Qualifiers:**
- **Type:** `host`, `net`, `port`, `portrange`
- **Direction:** `src`, `dst`, `src or dst`, `src and dst`
- **Protocol:** `ether`, `ip`, `ip6`, `tcp`, `udp`, `icmp`, `arp`

**Logical operators:** `and` (`&&`), `or` (`||`), `not` (`!`). Parentheses for grouping (escape in shell: `\(` `\)`).

## Common Filter Examples

### Host and Network Filters
```
host 192.168.1.100                  # Traffic to/from this IP
src host 10.0.0.5                   # Only traffic from this source
dst net 172.16.0.0/12               # Destination in RFC 1918 range
not host 10.0.0.1                   # Exclude gateway traffic
```

### Port Filters
```
port 53                              # DNS traffic (TCP and UDP)
tcp port 443                         # HTTPS only
dst port 22                          # SSH connections
portrange 8000-8999                  # High-port web services
not port 53 and not port 80          # Exclude DNS and HTTP
```

### Protocol Filters
```
tcp                                  # All TCP traffic
udp                                  # All UDP traffic
icmp                                 # ICMP only
arp                                  # ARP only
ip proto 47                          # GRE protocol
```

### Combined Filters for SOC Use
```
# Capture only external DNS (not to internal resolver)
port 53 and not dst host 10.0.0.2

# HTTP POST to external servers
tcp dst port 80 and dst net not 10.0.0.0/8

# SMB traffic (lateral movement)
tcp port 445 or tcp port 139

# Potential C2 beaconing on unusual ports
tcp and not port 80 and not port 443 and not port 22 and dst net not 10.0.0.0/8
```

## Advanced: Byte Offset Filters

BPF can inspect arbitrary bytes in a packet. This is powerful for matching specific protocol fields.

```
# TCP SYN packets only (flags byte at offset 13, SYN=0x02)
tcp[13] & 2 != 0

# TCP SYN without ACK
tcp[13] == 2

# HTTP GET requests (match "GET " at TCP payload start)
tcp[20:4] = 0x47455420

# ICMP echo request (type 8)
icmp[0] == 8

# DNS queries only (QR bit = 0 in flags)
udp port 53 and udp[10] & 0x80 == 0

# VLAN tagged traffic
vlan
```

## BPF vs Display Filters

| Feature | BPF (Capture) | Display Filter |
|---------|--------------|----------------|
| When applied | During capture | After capture |
| Performance | Kernel-space, very fast | User-space, slower |
| Syntax | `host 10.0.0.1` | `ip.addr == 10.0.0.1` |
| Granularity | Limited protocol awareness | Full dissector access |
| Use case | Reduce capture volume | Detailed analysis |

Use BPF filters when capturing on busy networks to prevent packet drops. Apply display filters afterward for deeper protocol analysis. For long-running captures, always use BPF to keep file sizes manageable.
""",
    },
    {
        "title": "HTTP/2 Protocol Overview for Security Analysis",
        "tags": ["http2", "protocol", "packet-analysis", "web-security"],
        "content": r"""# HTTP/2 Protocol Overview for Security Analysis

HTTP/2 (RFC 7540) replaced HTTP/1.1's text-based protocol with a binary framing layer. Understanding HTTP/2 internals matters for SOC analysts because traditional HTTP inspection tools and signatures may miss threats in HTTP/2 traffic.

## Key Differences from HTTP/1.1

**Binary framing:** All communication is split into frames with a defined binary format. The frame header (9 bytes) contains length, type, flags, and stream identifier. This makes HTTP/2 more efficient but harder to read in raw captures.

**Multiplexing:** Multiple request-response pairs share a single TCP connection via streams. Each stream has a unique ID (odd for client-initiated, even for server-initiated). This eliminates head-of-line blocking at the HTTP layer.

**Header compression (HPACK):** HTTP/2 compresses headers using a static table (61 common headers) and a dynamic table built during the connection. This reduces overhead significantly but means headers cannot be read without maintaining HPACK state.

**Server push:** The server can proactively send resources the client has not requested. Push promises (PUSH_PROMISE frames) declare what will be pushed.

## Frame Types

| Type | ID | Description |
|------|----|-------------|
| DATA | 0x0 | Request/response body |
| HEADERS | 0x1 | HTTP headers (compressed) |
| PRIORITY | 0x2 | Stream priority |
| RST_STREAM | 0x3 | Terminate a stream |
| SETTINGS | 0x4 | Connection parameters |
| PUSH_PROMISE | 0x5 | Server push notification |
| PING | 0x6 | Keepalive and RTT measurement |
| GOAWAY | 0x7 | Graceful connection shutdown |
| WINDOW_UPDATE | 0x8 | Flow control |
| CONTINUATION | 0x9 | Additional header block fragments |

## Security Implications

**Inspection challenges:** HTTP/2 is almost always over TLS (h2). The binary format and header compression mean traditional regex-based IDS signatures for HTTP/1.1 headers do not work. Security tools must perform full HTTP/2 decoding.

**Smuggling attacks:** Discrepancies between how front-end proxies and back-end servers handle HTTP/2-to-HTTP/1.1 translation create request smuggling opportunities. H2C (HTTP/2 cleartext) upgrades can bypass WAF rules expecting HTTP/1.1.

**Denial of service:** Stream multiplexing introduces new DoS vectors — Rapid Reset attacks (CVE-2023-44487) exploit stream cancellation to overwhelm servers without completing requests.

**Server push abuse:** Malicious or compromised servers can push unexpected content. Browsers limit push handling, but intermediaries may not.

## Analyzing HTTP/2 in Wireshark

Wireshark fully dissects HTTP/2 when it can decrypt TLS (using SSLKEYLOGFILE). Without decryption, you see only the TLS layer. With decryption enabled:

```
http2                                     # All HTTP/2 frames
http2.type == 0                           # DATA frames
http2.type == 1                           # HEADERS frames
http2.headers.path contains "/api"        # Request path filtering
http2.streamid == 5                       # Specific stream
```

Set the `SSLKEYLOGFILE` environment variable before launching the browser to capture pre-master secrets for decryption.
""",
    },
    {
        "title": "ICMP Types, Codes & Security Implications",
        "tags": ["icmp", "network", "packet-analysis", "reconnaissance"],
        "content": r"""# ICMP Types, Codes & Security Implications

ICMP (Internet Control Message Protocol) is a network-layer protocol used for diagnostics and error reporting. While essential for network operations, ICMP is frequently abused for reconnaissance, covert channels, and denial-of-service attacks.

## Key ICMP Types and Codes

### Diagnostic Messages
| Type | Code | Name | Use |
|------|------|------|-----|
| 0 | 0 | Echo Reply | Ping response |
| 8 | 0 | Echo Request | Ping request |
| 13 | 0 | Timestamp Request | Clock synchronization |
| 14 | 0 | Timestamp Reply | Clock response |

### Error Messages
| Type | Code | Name | Meaning |
|------|------|------|---------|
| 3 | 0 | Destination Unreachable — Network | No route to destination network |
| 3 | 1 | Destination Unreachable — Host | Host is down or unreachable |
| 3 | 3 | Destination Unreachable — Port | No service listening (UDP) |
| 3 | 13 | Destination Unreachable — Admin Prohibited | Firewall blocked the traffic |
| 11 | 0 | Time Exceeded — TTL | TTL reached zero (traceroute) |
| 5 | 0-3 | Redirect | Router suggests a better path |

## Reconnaissance via ICMP

**Ping sweeps (Type 8):** Attackers send echo requests across a subnet to discover live hosts. Tools like nmap (`-sn`) and fping perform this efficiently.

**Traceroute (Type 11):** By incrementing TTL values, attackers map network topology. Each hop returns a Time Exceeded message revealing router IPs, helping identify firewall positions and network architecture.

**Port scanning inference (Type 3, Code 3):** When a UDP port is closed, the target sends ICMP Port Unreachable. This is the basis of UDP scanning — no ICMP reply suggests the port is open or filtered.

**OS fingerprinting:** Different operating systems set distinct values in ICMP responses — TTL (Linux: 64, Windows: 128), payload patterns, and whether they respond to unusual ICMP types.

## ICMP as a Covert Channel

ICMP tunneling embeds data in the payload of echo request/reply packets. Normal pings carry a small, predictable payload (often just incrementing bytes). Tunneling tools like `icmpsh`, `ptunnel`, and `hans` encode arbitrary data in this payload.

**Detection indicators:**
- ICMP payload larger than 64 bytes
- Non-standard payload content (not the typical incrementing pattern)
- High frequency of ICMP echo traffic to a single destination
- ICMP sessions lasting longer than expected

## SOC Monitoring Recommendations

**Allow selectively:** Permit ICMP Types 0, 3, 8, and 11 for operational needs. Block Types 5 (redirect), 13/14 (timestamp), and 17/18 (address mask) at perimeter firewalls.

**Alert on anomalies:** Monitor for ICMP payloads exceeding 100 bytes, sustained ICMP sessions, and high-rate ping sweeps (more than 10 destinations per second from a single source).

**Wireshark filters:**
```
icmp.type == 8 && data.len > 64       # Oversized ping (tunneling)
icmp.type == 3 && icmp.code == 13     # Admin prohibited (firewall)
icmp.type == 5                         # Redirect (potential MITM)
```

**Rate limiting:** Implement ICMP rate limiting on firewalls and hosts (Linux: `net.ipv4.icmp_ratelimit`) to mitigate ICMP-based DoS.
""",
    },
]

DNS_DEEP = [
    {
        "title": "DNS Resolution — Recursive vs Iterative Queries",
        "tags": ["dns", "resolution", "recursive", "iterative"],
        "content": r"""# DNS Resolution — Recursive vs Iterative Queries

DNS translates human-readable domain names to IP addresses through a hierarchical query process. Understanding the difference between recursive and iterative resolution is fundamental for SOC analysts investigating DNS-based attacks and misconfigurations.

## Recursive Resolution

In a recursive query, the client asks its configured resolver (typically the ISP or enterprise DNS server) to obtain the complete answer. The resolver takes full responsibility for chasing down the answer through the DNS hierarchy.

**Process for resolving `www.example.com`:**

1. Client sends query to recursive resolver (e.g., 10.0.0.53).
2. Resolver checks its cache. On cache miss, it queries a root server.
3. Root server responds with a referral to `.com` TLD nameservers.
4. Resolver queries a `.com` TLD nameserver.
5. TLD responds with a referral to `example.com` authoritative nameservers.
6. Resolver queries the authoritative nameserver for `example.com`.
7. Authoritative server returns the A record for `www.example.com`.
8. Resolver caches the result (per TTL) and returns it to the client.

The client makes one query; the resolver may make several. This is why recursive resolvers are sometimes called "full-service resolvers."

## Iterative Resolution

In an iterative query, the queried server returns the best answer it has — either the final answer or a referral to another server. The querying host must then follow the referral chain itself.

Root servers and TLD servers operate iteratively. They never perform recursive lookups on behalf of the querier — they simply point toward the next server in the chain.

## Security Implications

**Open resolvers:** A recursive resolver accessible from the internet is an open resolver. Attackers exploit these for DNS amplification DDoS attacks — a small query produces a large response, and spoofing the source IP directs the amplified traffic at the victim. Ensure enterprise resolvers only accept queries from internal networks.

**Cache poisoning:** Recursive resolvers cache results, making them targets for cache poisoning. The Kaminsky attack exploits the race condition between legitimate and forged responses. DNSSEC and source port randomization mitigate this.

**DNS hijacking:** Compromised recursive resolvers can return forged answers for any domain, redirecting users to phishing sites or malware distribution points.

**Query logging:** Recursive resolvers see every query from clients — a valuable data source for SOC monitoring. Log DNS queries to detect C2 callbacks, DGA domains, and data exfiltration via DNS tunneling.

## Enterprise DNS Architecture

Best practice is a layered approach: internal recursive resolvers (accessible only from corporate networks) forward to forwarders or resolve directly. Authoritative servers for corporate domains are separate from recursive resolvers. DNS query logs from recursive resolvers feed into the SIEM for threat detection.

**Split-horizon DNS** serves different answers for the same domain depending on the source (internal vs external), ensuring internal hostnames are not leaked externally.
""",
    },
    {
        "title": "DNS Record Types Explained",
        "tags": ["dns", "records", "A", "AAAA", "MX", "CNAME", "TXT"],
        "content": r"""# DNS Record Types Explained

DNS uses various record types to store different kinds of information. SOC analysts must recognize these records to investigate phishing infrastructure, email spoofing, data exfiltration, and domain abuse.

## Core Record Types

### A Record (Address)
Maps a hostname to an IPv4 address. The most common record type.
```
example.com.    300    IN    A    93.184.216.34
```

### AAAA Record (IPv6 Address)
Maps a hostname to an IPv6 address.
```
example.com.    300    IN    AAAA    2606:2800:220:1:248:1893:25c8:1946
```

### CNAME Record (Canonical Name)
An alias that points to another hostname. Cannot coexist with other record types for the same name (with the exception of DNSSEC records). Often used for CDN integration and subdomains.
```
www.example.com.    3600    IN    CNAME    cdn.provider.net.
```

**Security note:** CNAME chains can be abused for subdomain takeover — if the target (`cdn.provider.net`) is deprovisioned, an attacker may claim it and serve malicious content under `www.example.com`.

### MX Record (Mail Exchanger)
Specifies mail servers for a domain with priority values (lower = higher priority).
```
example.com.    3600    IN    MX    10 mail1.example.com.
example.com.    3600    IN    MX    20 mail2.example.com.
```

**SOC relevance:** Phishing infrastructure often has MX records pointing to bulletproof hosting. Check MX records during phishing investigations.

### TXT Record
Stores arbitrary text. Critical for email authentication:

- **SPF:** `v=spf1 include:_spf.google.com ~all` — defines authorized mail senders.
- **DKIM:** Public key for verifying email signatures.
- **DMARC:** `v=DMARC1; p=reject; rua=mailto:dmarc@example.com` — policy for handling SPF/DKIM failures.

**Exfiltration vector:** TXT records can store up to 255 bytes per string (multiple strings per record). Attackers may encode stolen data in TXT records of domains they control.

### NS Record (Nameserver)
Delegates authority for a zone to specific nameservers.
```
example.com.    86400    IN    NS    ns1.example.com.
```

**Security note:** Unauthorized NS record changes enable full domain hijacking.

### SOA Record (Start of Authority)
Contains zone metadata: primary nameserver, responsible party email, serial number, refresh/retry/expire timers, and minimum TTL. One SOA per zone.

### PTR Record (Pointer)
Reverse DNS — maps IP addresses to hostnames. Stored in the `in-addr.arpa` (IPv4) or `ip6.arpa` (IPv6) zones. Used for email server validation and log enrichment.

### SRV Record (Service)
Locates services: `_service._protocol.name TTL IN SRV priority weight port target`. Active Directory relies heavily on SRV records for domain controller discovery (`_ldap._tcp.dc._msdcs.domain.com`).

## Investigation Workflow

When investigating a suspicious domain, query A, MX, NS, TXT, and SOA records. Cross-reference IP addresses with threat intelligence. Check TXT for SPF/DMARC gaps that enable spoofing. Use historical DNS data (passive DNS) to trace infrastructure changes over time.
""",
    },
    {
        "title": "DNSSEC Chain of Trust",
        "tags": ["dnssec", "dns", "security", "chain-of-trust", "authentication"],
        "content": r"""# DNSSEC Chain of Trust

DNSSEC (Domain Name System Security Extensions) adds cryptographic authentication to DNS responses, preventing cache poisoning and response forgery. It does not encrypt DNS traffic — it ensures the integrity and authenticity of DNS data.

## How DNSSEC Works

DNSSEC uses public key cryptography to sign DNS records. Each zone has a signing key pair, and the parent zone vouches for child zones through a chain that starts at the DNS root.

### Key Types

**Zone Signing Key (ZSK):** Signs individual DNS record sets (RRsets) within a zone. Rotated frequently (e.g., monthly) since it is used often.

**Key Signing Key (KSK):** Signs the DNSKEY RRset containing the ZSK. Rotated less frequently (e.g., annually). The KSK's hash is stored as a DS record in the parent zone, creating the chain of trust.

### New Record Types

| Record | Purpose |
|--------|---------|
| **RRSIG** | Contains the cryptographic signature for an RRset |
| **DNSKEY** | Holds the zone's public keys (ZSK and KSK) |
| **DS** | Delegation Signer — hash of child zone's KSK, stored in parent |
| **NSEC/NSEC3** | Authenticated denial of existence (proves a name does not exist) |

## The Chain of Trust

1. **Root zone:** The root KSK is the trust anchor, hardcoded in validating resolvers. IANA manages root key ceremonies.
2. **TLD zone:** The root zone contains DS records for each TLD (`.com`, `.org`, etc.). The DS record is a hash of the TLD's KSK.
3. **Domain zone:** The TLD zone contains DS records for each DNSSEC-signed domain. This DS record hashes the domain's KSK.
4. **Validation:** A resolver walks the chain from root → TLD → domain, verifying each signature. If any link breaks, validation fails.

## Validation Process (Simplified)

When a DNSSEC-validating resolver receives a response for `www.example.com`:

1. Retrieve the DNSKEY and RRSIG for `example.com`.
2. Verify the RRSIG over the A record using the ZSK from the DNSKEY set.
3. Verify the DNSKEY set's RRSIG using the KSK.
4. Retrieve the DS record for `example.com` from the `.com` zone.
5. Verify the DS record matches the hash of the KSK.
6. Repeat up the chain to the root trust anchor.

## Security Benefits and Limitations

**Protects against:** Cache poisoning, response forgery, man-in-the-middle modification of DNS answers.

**Does not protect against:** DNS traffic eavesdropping (use DoH/DoT for privacy), DDoS attacks, compromised authoritative servers returning validly-signed but malicious data, or phishing domains that are themselves DNSSEC-signed.

**NSEC zone walking:** NSEC records inadvertently reveal all names in a zone (enumeration). NSEC3 mitigates this by using hashed names, though offline dictionary attacks remain possible.

## SOC Considerations

Monitor for DNSSEC validation failures (`SERVFAIL` with the AD bit unset) which may indicate an active attack or misconfiguration. Tools like `dig +dnssec` and `delv` help diagnose DNSSEC issues. Ensure enterprise resolvers have DNSSEC validation enabled.
""",
    },
    {
        "title": "DNS over HTTPS (DoH) and DNS over TLS (DoT)",
        "tags": ["doh", "dot", "dns", "encryption", "privacy"],
        "content": r"""# DNS over HTTPS (DoH) and DNS over TLS (DoT)

Traditional DNS queries are sent in cleartext over UDP port 53, allowing any network observer to see which domains a user visits. DoH and DoT encrypt DNS traffic, improving privacy but creating significant challenges for enterprise security monitoring.

## DNS over TLS (DoT) — RFC 7858

DoT wraps standard DNS queries inside a TLS connection on **TCP port 853**. The resolver authenticates using a TLS certificate (SPKI pin or hostname verification).

**Advantages:** Simple to implement, uses a dedicated port, easily identifiable by network monitoring. Firewalls can allow or block DoT by port number.

**Disadvantages:** The dedicated port makes it trivial to block. An attacker or restrictive network can simply drop TCP/853.

## DNS over HTTPS (DoH) — RFC 8484

DoH encapsulates DNS queries within HTTPS on **TCP port 443**. Queries are sent as HTTP POST (with `application/dns-message` content type) or HTTP GET (with base64url-encoded query parameter) to a well-known URI path (typically `/dns-query`).

**Advantages:** Blends with normal HTTPS traffic, making it difficult to block without breaking web browsing. Leverages existing HTTPS infrastructure.

**Disadvantages:** Extremely difficult to distinguish from regular HTTPS traffic. Enterprise security tools lose DNS visibility unless they are the DoH resolver.

## Impact on Enterprise Security

### Visibility Loss
Traditional enterprise DNS monitoring captures all queries at the recursive resolver. When endpoints use DoH to external resolvers (e.g., Cloudflare 1.1.1.1 or Google 8.8.8.8), the enterprise loses visibility into DNS queries — a critical data source for detecting malware C2, DGA domains, and data exfiltration.

### Malware Abuse
Malware authors increasingly use DoH to hide C2 DNS lookups from enterprise monitoring. Since DoH traffic looks like normal HTTPS, it bypasses DNS-layer security controls. Notable examples include the Godlua backdoor, which used DoH for domain resolution.

### Mitigation Strategies

**Block external DoH/DoT:** Maintain a blocklist of known public DoH resolver IPs at the firewall. Block TCP/853 outbound. This forces endpoints to use internal DNS.

**Enterprise DoH resolver:** Deploy an internal DoH/DoT resolver that provides encrypted DNS while maintaining full query logging. Configure endpoints (via group policy or MDM) to use only the internal resolver.

**TLS inspection:** If TLS inspection is deployed, DoH traffic can be decrypted and inspected. Look for requests to `/dns-query` paths.

**Canary domains:** Some organizations use canary domains (e.g., `use-application-dns.net`) that, when blocked, signal to browsers like Firefox to disable DoH and fall back to system DNS.

## Detection in Packet Captures

DoT is identifiable by traffic on TCP/853. DoH is harder — look for:
- HTTPS connections to known DoH resolver IPs (maintain an updated list)
- POST requests to `/dns-query` (if TLS is decrypted)
- JA3 hashes associated with known DoH client implementations
- Unusual volume of HTTPS connections to a single IP without corresponding web content

## SOC Recommendation

Treat DoH/DoT adoption as a DNS security architecture decision. If not controlled, it becomes a blind spot. Enterprise policy should mandate internal DNS resolution and block unauthorized encrypted DNS egress.
""",
    },
    {
        "title": "DNS Zone Transfer Risks",
        "tags": ["dns", "zone-transfer", "AXFR", "security", "misconfiguration"],
        "content": r"""# DNS Zone Transfer Risks

A DNS zone transfer (AXFR) replicates the complete contents of a DNS zone from a primary to a secondary nameserver. When misconfigured to allow transfers to any requester, it exposes the entire zone file — a goldmine for attackers performing reconnaissance.

## How Zone Transfers Work

Zone transfers use TCP port 53. The requesting server sends an AXFR query, and the primary server responds with every record in the zone, one by one, bookended by the SOA record.

**IXFR (Incremental Zone Transfer):** Transfers only changes since a given serial number. More efficient but still reveals zone data.

**Legitimate use:** Secondary DNS servers need zone transfers to stay synchronized with the primary. This is essential for DNS redundancy.

## What Attackers Gain

A successful zone transfer reveals:

- **All subdomains:** Including internal-facing services, development environments, and staging servers that may not be publicly linked.
- **IP addresses:** Complete mapping of hostnames to IPs, enabling targeted scanning.
- **Mail servers:** MX records reveal email infrastructure.
- **Service records:** SRV records expose internal services (LDAP, SIP, Kerberos).
- **TXT records:** May contain SPF, DKIM, verification tokens, or other metadata.
- **Network architecture:** Naming conventions reveal organizational structure (e.g., `vpn-nyc`, `db-prod-01`, `jenkins.internal`).

## Testing for Misconfigured Transfers

```bash
# Using dig
dig @ns1.target.com target.com AXFR

# Using nslookup
nslookup
> server ns1.target.com
> set type=any
> ls -d target.com

# Using host
host -t axfr target.com ns1.target.com

# Nmap script
nmap --script dns-zone-transfer -p 53 ns1.target.com
```

A successful transfer returns the complete zone. A properly secured server returns "Transfer refused" or simply times out.

## Securing Zone Transfers

**ACL restriction:** Configure the primary DNS server to allow AXFR only from specific secondary server IPs.

```
# BIND example
zone "example.com" {
    type master;
    allow-transfer { 10.0.0.2; 10.0.0.3; };
};
```

**TSIG authentication:** Transaction Signatures (RFC 2845) use shared secrets to authenticate zone transfer requests. More secure than IP-based ACLs alone, as IPs can be spoofed.

```
# BIND TSIG example
key "transfer-key" {
    algorithm hmac-sha256;
    secret "base64-encoded-secret";
};
zone "example.com" {
    allow-transfer { key "transfer-key"; };
};
```

**Network controls:** Restrict TCP/53 at the firewall to only authorized secondary DNS servers. Monitor for unexpected AXFR queries in DNS logs.

## SOC Detection

Alert on any AXFR query (DNS query type 252) in network logs — especially from non-nameserver IPs. In Wireshark:
```
dns.qry.type == 252    # AXFR query
dns.qry.type == 251    # IXFR query
```

Zone transfer attempts are a strong indicator of active reconnaissance. Correlate the source IP with other scanning activity and investigate promptly.
""",
    },
    {
        "title": "DNS Caching, TTL & Negative Caching",
        "tags": ["dns", "caching", "ttl", "performance", "troubleshooting"],
        "content": r"""# DNS Caching, TTL & Negative Caching

DNS caching is fundamental to the DNS system's scalability. Every resolver, forwarder, and even client OS maintains a cache. Understanding TTL behavior and caching mechanics is essential for incident response (how quickly can you block a malicious domain?) and troubleshooting (why are users still reaching the old IP?).

## How TTL Works

Every DNS record includes a Time-To-Live (TTL) value in seconds. When a resolver caches a record, it stores the TTL and decrements it over time. When TTL reaches zero, the cached entry expires, and the resolver must query the authoritative server again.

**Common TTL values:**
- **300 (5 minutes):** Dynamic services, CDNs, failover configurations
- **3600 (1 hour):** Standard for most records
- **86400 (24 hours):** Stable infrastructure, MX records, NS records
- **604800 (1 week):** Very stable records (rarely changed)

## Caching Layers

1. **Application cache:** Browsers cache DNS independently (Chrome: `chrome://net-internals/#dns`). Default TTL respect varies by browser.
2. **OS stub resolver cache:** Windows DNS Client service, Linux `systemd-resolved`, macOS `mDNSResponder`. Query with `ipconfig /displaydns` (Windows) or `resolvectl statistics` (Linux).
3. **Enterprise recursive resolver:** The primary cache. Serves all clients in the organization.
4. **Forwarder cache:** If the enterprise resolver forwards to an upstream (e.g., ISP), that forwarder also caches.

## Negative Caching (RFC 2308)

When a domain does not exist (NXDOMAIN) or a specific record type is absent (NODATA), the resolver caches this negative result. The TTL for negative caching comes from the SOA record's minimum TTL field.

**SOC impact:** If you query a DGA domain and get NXDOMAIN, that negative result is cached. If the attacker later registers the domain during the cache window, your resolver will continue returning NXDOMAIN until the negative cache expires. This can be both a protection (brief window of immunity) and a problem (delayed detection if monitoring relies on positive responses).

## Cache Poisoning Concerns

An attacker who can inject a forged response before the legitimate answer arrives can poison the resolver's cache. The forged record will be served for the duration of its TTL.

**Defenses:** DNSSEC validation, source port randomization (RFC 5452), 0x20 encoding (mixed-case query names for additional entropy), and limiting cache scope to prevent bailiwick violations.

## Incident Response Implications

**Blocking a malicious domain:** Even after adding a domain to your DNS sinkhole or blocklist, clients will use their cached results until TTL expires. For urgent containment:

- Flush the enterprise resolver's cache for that domain.
- Push a GPO/MDM command to flush client DNS caches.
- Consider that browser caches may need a restart.

**Minimum propagation time:** When rotating IPs for a compromised server, factor in the current record's TTL. If the TTL is 86400, some clients may take up to 24 hours to see the new IP.

## Useful Commands

```bash
# Check TTL of a live record
dig example.com +noall +answer    # Shows remaining TTL

# Flush Windows DNS cache
ipconfig /flushdns

# Flush Linux systemd-resolved cache
resolvectl flush-caches

# View macOS DNS cache (requires log stream)
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```
""",
    },
    {
        "title": "Passive DNS Intelligence for Threat Hunting",
        "tags": ["passive-dns", "threat-hunting", "dns", "intelligence", "osint"],
        "content": r"""# Passive DNS Intelligence for Threat Hunting

Passive DNS (pDNS) is a technique that collects DNS query-response pairs from network sensors without sending any queries. This historical DNS data is invaluable for threat intelligence, incident response, and attribution — it reveals the infrastructure relationships that attackers try to hide.

## What Passive DNS Captures

pDNS sensors sit at recursive resolvers or on network taps and record:
- **Query name:** The domain being resolved
- **Record type:** A, AAAA, CNAME, MX, NS, etc.
- **Response data:** The IP address or value returned
- **First seen / Last seen:** Timestamps bounding when a resolution was active
- **Count:** How many times the resolution was observed

This data is stored in databases indexed by both domain and IP, enabling bidirectional lookups.

## Intelligence Use Cases

### Pivot from IP to Domains
Given a known malicious IP, query pDNS to find all domains that have ever resolved to it. This reveals:
- Other C2 domains sharing the same infrastructure
- Historical campaigns by the same threat actor
- Domain parking or fast-flux behavior

### Pivot from Domain to IPs
Given a suspicious domain, find all IPs it has resolved to over time. This reveals:
- Infrastructure migrations (moving between hosting providers)
- Shared hosting that connects seemingly unrelated domains
- CDN usage vs dedicated infrastructure

### Domain Generation Algorithm (DGA) Detection
pDNS databases enable bulk analysis of domain resolution patterns. DGA domains typically show:
- High volumes of NXDOMAIN responses
- Short-lived resolutions (seen for hours, not days)
- Algorithmic naming patterns (high entropy)

### Fast-Flux Detection
Legitimate domains resolve to a stable set of IPs. Fast-flux domains cycle through many IPs rapidly (TTLs of 60-300 seconds) to evade takedowns. pDNS data showing hundreds of A records over a short period is a strong indicator.

## Major Passive DNS Sources

| Source | Access | Coverage |
|--------|--------|----------|
| **Farsight DNSDB** | Commercial API | Largest global pDNS database |
| **VirusTotal** | Free (limited) / Commercial | Aggregates multiple sources |
| **SecurityTrails** | Free (limited) / Commercial | Historical DNS + WHOIS |
| **RiskIQ / PassiveTotal** | Commercial | DNS, WHOIS, certificates |
| **CIRCL pDNS** | Free (CIRCL members) | European-focused collection |
| **Internal sensors** | Self-hosted | Full visibility on your network |

## Building Internal Passive DNS

Deploy pDNS collection on your enterprise recursive resolvers. Tools:
- **Zeek (Bro):** `dns.log` captures all queries and responses seen on the network.
- **dnstap:** A structured logging format supported by BIND, Unbound, and Knot. Efficient binary encoding.
- **PacketBeat:** Elastic's packet shipper includes DNS protocol parsing, sending data directly to Elasticsearch.

## Threat Hunting Workflow

1. Start with an IOC (IP or domain) from a threat report.
2. Query pDNS for historical resolutions.
3. Identify co-hosted domains or infrastructure overlap.
4. Cross-reference discovered domains with threat intel feeds.
5. Check if any discovered domains appear in your DNS query logs.
6. If matches are found, investigate the endpoints that queried those domains.

This iterative expansion — IOC → pDNS → related infrastructure → internal logs — is one of the most effective threat hunting techniques for network-based investigations.
""",
    },
    {
        "title": "DNS Monitoring and Alerting for SOC Teams",
        "tags": ["dns", "monitoring", "soc", "detection", "alerting"],
        "content": r"""# DNS Monitoring and Alerting for SOC Teams

DNS is one of the most valuable data sources in a SOC. Nearly every network action — legitimate or malicious — involves a DNS query. Effective DNS monitoring provides early detection of C2 communications, data exfiltration, lateral movement, and policy violations.

## Data Collection Architecture

### Sources
- **Recursive resolver logs:** Capture all client queries. Enable query logging on BIND (`querylog yes`), Unbound (`log-queries: yes`), or Windows DNS Server (debug logging).
- **Network taps / Zeek:** Parse DNS from packet captures. Zeek's `dns.log` provides structured output with query, response, RTT, and flags.
- **Firewall logs:** Log DNS traffic (UDP/TCP 53, TCP 853 for DoT) including allowed and denied connections.
- **Endpoint telemetry:** Sysmon Event ID 22 (DNS query) on Windows captures per-process DNS resolution.

### Normalization
Regardless of source, normalize DNS logs to consistent fields: timestamp, source IP, query name, query type, response code, response data, and TTL. Map to ECS (Elastic Common Schema) `dns.*` fields for consistency across tools.

## Detection Rules

### High-Entropy Domain Queries (DGA Detection)
Calculate Shannon entropy of queried domain names. Legitimate domains average 2.5-3.5 entropy; DGA domains typically exceed 3.8. Alert on sustained queries with high entropy from a single host.

```
Threshold: entropy > 3.8 AND query_count > 20 in 10 minutes from same source
```

### DNS Tunneling
Data exfiltration via DNS encodes data in subdomain labels. Indicators:
- Query names exceeding 50 characters
- High volume of unique subdomain queries under the same parent domain
- TXT record queries to unusual domains
- Unusual query type distribution (high ratio of TXT, NULL, or CNAME queries)

```
Alert: unique_subdomains > 100 under same registered domain in 1 hour
```

### Newly Registered Domains (NRD)
Domains registered within the past 30 days are disproportionately used for phishing, malware distribution, and C2. Enrich DNS logs with domain age from WHOIS or commercial feeds.

### Rare Domain Queries
Track domain query frequency across the organization. A domain queried by only one endpoint in a month is statistically anomalous and warrants investigation — especially if combined with other indicators.

### Direct-to-IP DNS Bypass
Monitor for DNS queries to public resolvers (8.8.8.8, 1.1.1.1, 208.67.222.222) that bypass enterprise DNS. Also detect DoH by blocking or alerting on connections to known DoH resolver IPs.

### NXDOMAIN Spikes
A sudden increase in NXDOMAIN responses from a single host may indicate DGA malware attempting to find its active C2 domain, or a misconfigured application.

## Response Playbook

1. **Triage:** Identify the source host, user, and process (if endpoint telemetry available).
2. **Enrich:** Query the suspicious domain against threat intel (VirusTotal, AbuseIPDB, passive DNS).
3. **Scope:** Search DNS logs for all hosts querying the same domain or IP.
4. **Contain:** Add the domain to the DNS sinkhole or blocklist. Isolate affected hosts if C2 is confirmed.
5. **Investigate:** Examine endpoint artifacts — process trees, file hashes, persistence mechanisms.

## Key Metrics for DNS Dashboards

- Queries per second (baseline and current)
- Top queried domains (filter out CDN/cloud noise)
- NXDOMAIN rate and top NXDOMAIN domains
- Unique domains per source host
- Query type distribution (A, AAAA, TXT, MX, ANY)
- External DNS usage (queries bypassing enterprise resolver)
""",
    },
]

NETWORK_INFRA = [
    {
        "title": "VLANs & 802.1Q Trunking",
        "tags": ["vlan", "802.1Q", "trunking", "network-segmentation", "switching"],
        "content": r"""# VLANs & 802.1Q Trunking

Virtual LANs (VLANs) partition a physical switch into multiple logical broadcast domains. Combined with 802.1Q trunking, VLANs are the foundation of network segmentation in enterprise environments — a critical security control.

## VLAN Fundamentals

Each VLAN is a separate Layer 2 broadcast domain. Devices in VLAN 10 cannot communicate with devices in VLAN 20 at Layer 2, even if they share the same physical switch. Inter-VLAN communication requires a Layer 3 device (router or L3 switch).

**Port types:**
- **Access port:** Belongs to a single VLAN. Frames entering are tagged with that VLAN; frames leaving have the tag stripped. End devices (PCs, servers, printers) connect to access ports.
- **Trunk port:** Carries traffic for multiple VLANs simultaneously using 802.1Q tags. Connects switches to switches, switches to routers, and switches to hypervisors.

## 802.1Q Tagging

The 802.1Q standard inserts a 4-byte tag into the Ethernet frame between the source MAC and EtherType fields:
- **TPID (2 bytes):** Tag Protocol Identifier, always 0x8100 for 802.1Q.
- **TCI (2 bytes):** Contains PCP (3-bit priority), DEI (1-bit drop eligibility), and **VLAN ID** (12 bits, supporting VLANs 0-4095).

**Native VLAN:** Traffic on the native VLAN is sent untagged across a trunk. Default is VLAN 1. Mismatched native VLANs between trunk endpoints cause traffic leakage — a security risk.

## Security Considerations

### VLAN Hopping Attacks

**Switch spoofing:** An attacker configures their NIC to negotiate a trunk with the switch (using DTP — Dynamic Trunking Protocol). Once trunking, they can send tagged frames to any VLAN.

**Mitigation:** Disable DTP on all access ports (`switchport mode access`, `switchport nonegotiate`). Explicitly configure trunk ports.

**Double tagging:** The attacker sends a frame with two 802.1Q tags. The first switch strips the outer tag (native VLAN) and forwards the frame. The next switch reads the inner tag and delivers it to the target VLAN.

**Mitigation:** Set the native VLAN to an unused VLAN (e.g., VLAN 999). Tag native VLAN traffic explicitly (`vlan dot1q tag native`).

### Best Practices
- Change the native VLAN from the default (VLAN 1).
- Disable unused ports and assign them to a "parking lot" VLAN.
- Use private VLANs (PVLAN) for isolating hosts within the same VLAN (e.g., DMZ servers).
- Enable DHCP snooping and Dynamic ARP Inspection (DAI) per VLAN.
- Limit allowed VLANs on trunk ports to only those needed (`switchport trunk allowed vlan`).

## Inter-VLAN Routing

**Router-on-a-stick:** A single router interface with sub-interfaces, each tagged for a different VLAN. Simple but creates a bandwidth bottleneck.

**L3 switch (SVI):** Switch Virtual Interfaces provide wire-speed inter-VLAN routing. Each SVI is a virtual interface in a VLAN with an IP address serving as the default gateway.

**Firewall as gateway:** Route inter-VLAN traffic through a firewall for inspection. Essential for high-security segments (e.g., PCI zones, OT networks).
""",
    },
    {
        "title": "Spanning Tree Protocol — STP & RSTP",
        "tags": ["stp", "rstp", "spanning-tree", "switching", "layer2"],
        "content": r"""# Spanning Tree Protocol — STP & RSTP

Spanning Tree Protocol (IEEE 802.1D) prevents Layer 2 loops in networks with redundant switch links. Without STP, broadcast frames circulate endlessly, causing broadcast storms, MAC table instability, and network outages within seconds.

## Why Loops Are Dangerous

Layer 2 has no TTL mechanism (unlike IP's TTL). A broadcast frame entering a loop is forwarded indefinitely by every switch, duplicating at each fork. Within seconds, the broadcast storm consumes all bandwidth and CPU on every switch, effectively taking the network offline.

## STP Operation

### Bridge Protocol Data Units (BPDUs)
Switches exchange BPDUs every 2 seconds (hello timer) to build a loop-free topology.

### Election Process
1. **Root bridge election:** The switch with the lowest Bridge ID (priority + MAC address) becomes root. All ports on the root bridge are designated (forwarding).
2. **Root port selection:** Each non-root switch selects one root port — the port with the lowest cost path to the root bridge.
3. **Designated port selection:** On each network segment, one designated port is elected (lowest cost to root). All other ports on that segment become blocked (non-designated).

### Port States (STP 802.1D)
| State | Duration | Behavior |
|-------|----------|----------|
| Blocking | — | Receives BPDUs only, does not forward |
| Listening | 15s (forward delay) | Participates in topology decisions |
| Learning | 15s (forward delay) | Learns MAC addresses, no forwarding |
| Forwarding | — | Full operation |
| Disabled | — | Administratively shut down |

**Convergence time:** 30-50 seconds for STP (802.1D). This delay is significant — users experience a 30+ second outage after any topology change.

## Rapid Spanning Tree (RSTP — 802.1w)

RSTP dramatically improves convergence to 1-3 seconds through:
- **Proposal/agreement mechanism:** Switches negotiate port roles directly instead of waiting for timer expiration.
- **Edge ports:** Ports connected to end devices transition immediately to forwarding (equivalent to PortFast).
- **Alternate and backup ports:** Pre-calculated failover paths that activate instantly when the root port fails.

## Security Attacks and Mitigations

### Root Bridge Manipulation
An attacker connects a switch (or host running STP software) with a lower bridge priority, becoming the root bridge. All traffic reroutes through the attacker, enabling interception.

**Mitigation:** Enable **Root Guard** on ports facing non-core switches. If a superior BPDU is received, the port enters root-inconsistent state (blocking).

### BPDU Flooding
Sending a high volume of BPDUs with changing topology information forces constant STP recalculations, causing instability.

**Mitigation:** Enable **BPDU Guard** on access/edge ports. If a BPDU is received on a port where none is expected, the port is shut down (err-disabled).

### Best Practices
- Explicitly set root bridge priority (`spanning-tree vlan X root primary`) — do not rely on the default election.
- Enable **PortFast** on all access ports (immediate forwarding, no STP delay for end devices).
- Enable **BPDU Guard** on all PortFast-enabled ports.
- Use RSTP (802.1w) or MST (802.1s) instead of legacy STP.
- Monitor for unexpected topology change notifications (TCN) in switch logs.
""",
    },
    {
        "title": "BGP Fundamentals for Security Professionals",
        "tags": ["bgp", "routing", "internet", "hijacking", "security"],
        "content": r"""# BGP Fundamentals for Security Professionals

Border Gateway Protocol (BGP) is the routing protocol that holds the internet together. It enables autonomous systems (ASes) to exchange reachability information. BGP's trust model — built on cooperation between operators — makes it vulnerable to hijacking and route leaks with potentially global impact.

## Core Concepts

**Autonomous System (AS):** A network or group of networks under a single administrative domain, identified by an AS Number (ASN). Examples: AS13335 (Cloudflare), AS15169 (Google), AS8075 (Microsoft).

**BGP peering:** Two BGP routers (peers) establish a TCP connection on port 179. They exchange full routing tables initially, then incremental updates. Peering types:
- **eBGP (external):** Between different ASes. Typically at internet exchange points (IXPs) or private interconnects.
- **iBGP (internal):** Within the same AS. Distributes external routes to internal routers.

**BGP path attributes:** Each route advertisement includes attributes that influence path selection:
- **AS_PATH:** List of ASes the route has traversed. Shorter is preferred. Also used for loop detection.
- **NEXT_HOP:** The IP address to forward traffic toward.
- **LOCAL_PREF:** Internal preference (higher is preferred). Used within an AS.
- **MED:** Multi-Exit Discriminator — suggests to a neighbor which entry point to prefer.

## BGP Path Selection (Simplified)

BGP selects the best path using a decision process (in order): highest LOCAL_PREF → shortest AS_PATH → lowest origin type → lowest MED → eBGP over iBGP → lowest IGP metric to NEXT_HOP → lowest router ID.

## BGP Hijacking

A BGP hijack occurs when an AS announces routes for IP prefixes it does not legitimately own. Because BGP trusts route announcements by default, other ASes may accept and propagate the hijack.

**Types:**
- **Prefix hijack:** Announcing an identical prefix (e.g., 93.184.216.0/24). Traffic may split between the legitimate and hijacking AS.
- **Sub-prefix hijack:** Announcing a more-specific prefix (e.g., 93.184.216.0/25). More-specific routes are always preferred, so this is highly effective.
- **AS_PATH manipulation:** Prepending the victim's ASN to the path to appear as a legitimate transit provider.

**Impact:** Traffic redirection (enabling interception or MITM), denial of service (blackholing traffic), cryptocurrency theft (hijacking mining pool prefixes), and certificate issuance (obtaining TLS certs during the hijack window).

**Notable incidents:**
- 2018: Amazon Route 53 BGP hijack to steal cryptocurrency
- 2022: Russian Rostelecom routing incidents affecting multiple countries
- 2024: Orange Spain BGP hijack via stolen RIPE credentials

## Defenses

**RPKI (Resource Public Key Infrastructure):** Cryptographically signs ROAs (Route Origin Authorizations) binding prefixes to authorized ASNs. Validators reject announcements with invalid origins. Adoption is growing but not universal.

**BGP communities:** Signal routing policy preferences to peers. Can help contain the spread of illegitimate routes.

**Prefix filters:** Configure maximum prefix length acceptance (/24 for IPv4, /48 for IPv6). Reject routes with suspiciously long AS_PATHs.

**Monitoring:** Use BGP monitoring tools (RIPE RIS, BGPStream, Cloudflare Radar) to detect unexpected route changes for your prefixes.
""",
    },
    {
        "title": "Network Segmentation Strategies",
        "tags": ["segmentation", "network-security", "architecture", "defense-in-depth"],
        "content": r"""# Network Segmentation Strategies

Network segmentation divides a network into smaller, isolated zones to limit lateral movement, contain breaches, and enforce access policies. It is one of the most effective security controls — a well-segmented network turns a single breach into an isolated incident rather than a total compromise.

## Segmentation Models

### Flat Network (Anti-Pattern)
All devices share one broadcast domain with unrestricted communication. A single compromised host can reach every other host. Unfortunately, this is still common in smaller organizations.

### Zone-Based Segmentation
Traditional model using VLANs and firewalls to create security zones:
- **Internet zone:** Public-facing, untrusted.
- **DMZ:** Hosts externally accessible services (web servers, email gateways, reverse proxies). Dual-homed between internet and internal firewalls.
- **Internal/Corporate zone:** End-user workstations, printers, internal apps.
- **Server zone:** Internal servers, databases, application backends.
- **Management zone:** Infrastructure management interfaces (switch consoles, IPMI/iLO, vCenter).
- **Restricted zone:** PCI cardholder data, healthcare (PHI), sensitive R&D.

### Micro-Segmentation
Granular segmentation at the workload level, typically using software-defined networking (SDN) or host-based firewalls. Each server or container has its own security policy. Lateral movement between any two workloads requires explicit authorization.

**Implementation:** VMware NSX, Cisco ACI, Illumio, cloud security groups (AWS SG, Azure NSG), or host-based firewalls managed by policy (Windows Firewall via GPO, iptables/nftables via Ansible).

## Implementation Approaches

### VLAN + Firewall (Traditional)
Assign each zone to a VLAN. Route inter-VLAN traffic through a firewall or L3 switch ACL. Simple and well-understood, but ACL management becomes complex at scale.

### Software-Defined Segmentation
Use SDN controllers to push microsegmentation policies to hypervisor-level virtual switches. Policies follow the workload regardless of physical location. More flexible but requires SDN infrastructure investment.

### Cloud-Native Segmentation
In AWS/Azure/GCP, use VPCs (Virtual Private Clouds), subnets, security groups, and network ACLs. Each application tier gets its own subnet with security groups limiting traffic.

## Critical Segmentation Boundaries

1. **User-to-server:** Users should reach only specific application ports. Block direct access to database ports, management interfaces, and backend services.
2. **Server-to-server:** Application servers should reach only the databases they need. Prevent lateral movement between unrelated application stacks.
3. **Management plane:** Out-of-band management (IPMI, SSH, RDP to infrastructure) should be on a dedicated network, accessible only from jump boxes.
4. **OT/IoT isolation:** Operational technology and IoT devices on isolated VLANs with strict one-way data flows where possible.

## Monitoring and Validation

- **Flow logs:** Capture and analyze network flows (NetFlow/sFlow/IPFIX) to validate that segmentation policies are enforced.
- **Breach simulation:** Tools like Safebreach or AttackIQ test whether an attacker can move between segments.
- **Regular audits:** Review firewall rules quarterly. Remove overly permissive rules. Document business justification for each rule.

Effective segmentation requires ongoing maintenance. Networks evolve, new applications are deployed, and exceptions accumulate. Without continuous validation, segmentation degrades over time.
""",
    },
    {
        "title": "Zero Trust Architecture Principles",
        "tags": ["zero-trust", "architecture", "security", "identity", "network"],
        "content": r"""# Zero Trust Architecture Principles

Zero Trust is a security model that eliminates implicit trust based on network location. The core principle: "never trust, always verify." Every access request — regardless of whether it originates inside or outside the network perimeter — must be authenticated, authorized, and continuously validated.

## The Problem with Perimeter Security

Traditional security assumes everything inside the firewall is trusted. This model fails because:
- **VPN extends the perimeter:** Remote users with VPN access get broad network access, making a compromised endpoint equally dangerous as if the attacker were onsite.
- **Lateral movement:** Once past the perimeter, attackers move freely. The 2020 SolarWinds attack demonstrated how a single supply chain compromise gave attackers access across thousands of networks.
- **Cloud dissolution:** With SaaS, IaaS, and remote work, the "inside" no longer has clear boundaries.

## Core Principles (NIST SP 800-207)

### 1. All Resources Are Accessed Securely
Every resource (application, service, data) requires authenticated and authorized access, regardless of network location. An internal database should demand the same authentication as a public-facing API.

### 2. Access Is Granted Per-Session
Each access request is evaluated independently. Prior authentication does not grant ongoing access. Sessions have limited duration, and re-authentication may be required based on risk signals.

### 3. Access Policy Is Dynamic
Authorization decisions incorporate multiple signals:
- **Identity:** Who is requesting access? (Strong authentication, MFA)
- **Device health:** Is the device compliant? (Patched, encrypted, MDM-enrolled)
- **Context:** What time, from where, what behavior patterns? (Geolocation, impossible travel)
- **Data sensitivity:** What is being accessed? (Classification level)

### 4. Continuous Monitoring and Validation
Trust is not a one-time decision. Monitor sessions continuously. Anomalous behavior (unusual data volume, off-hours access, privilege escalation) triggers re-evaluation or termination.

## Implementation Components

### Identity Provider (IdP)
Centralized authentication with SSO and MFA. All access starts with identity verification. Examples: Entra ID (Azure AD), Okta, Ping Identity.

### Policy Engine / Policy Decision Point (PDP)
Evaluates access requests against policies incorporating identity, device, context, and data classification. Returns allow/deny decisions.

### Policy Enforcement Point (PEP)
Enforces PDP decisions at the access point. Could be a reverse proxy, API gateway, network gateway, or application middleware.

### Device Trust
Assess device posture before granting access: OS patch level, EDR agent running, disk encryption enabled, certificate-based device identity. Untrusted devices get reduced access or are directed to remediation.

### Micro-Segmentation
Complements Zero Trust by limiting network-level access even after authentication. Reduces blast radius of a compromised identity.

## SOC Implications

Zero Trust generates rich telemetry. Every access decision is logged with full context — identity, device, location, resource, and decision. This data feeds into SIEM for:
- Detecting compromised credentials (impossible travel, credential stuffing patterns)
- Identifying lateral movement attempts (denied access requests across resources)
- Compliance reporting (who accessed what, when, from where)

## Adoption Strategy

Zero Trust is a journey, not a product. Start with:
1. **Inventory:** Map users, devices, applications, and data flows.
2. **Strong identity:** Implement MFA everywhere. Eliminate password-only authentication.
3. **Least privilege:** Reduce access rights to the minimum required.
4. **Segment critical assets:** Apply micro-segmentation to high-value targets first.
5. **Iterate:** Expand Zero Trust policies progressively, measuring security posture improvements.
""",
    },
    {
        "title": "Load Balancers — Layer 4 vs Layer 7",
        "tags": ["load-balancer", "L4", "L7", "infrastructure", "high-availability"],
        "content": r"""# Load Balancers — Layer 4 vs Layer 7

Load balancers distribute traffic across multiple backend servers to ensure availability, scalability, and performance. Understanding the difference between Layer 4 (transport) and Layer 7 (application) load balancing is essential for security architecture, incident investigation, and understanding traffic flows.

## Layer 4 Load Balancing

L4 load balancers operate at the TCP/UDP transport layer. They route traffic based on IP address and port number without inspecting the application payload.

**How it works:** The load balancer receives a TCP SYN, selects a backend server using its algorithm, and forwards the connection. It may use NAT (rewriting destination IP) or DSR (Direct Server Return, where the backend responds directly to the client).

**Algorithms:**
- **Round robin:** Distribute sequentially across backends.
- **Least connections:** Send to the server with fewest active connections.
- **Source IP hash:** Same client IP always goes to the same backend (session affinity).
- **Weighted:** Assign proportional traffic based on server capacity.

**Advantages:** Very fast (no payload inspection), protocol-agnostic (works for any TCP/UDP service), lower resource consumption, supports any application protocol.

**Limitations:** Cannot make routing decisions based on HTTP headers, URLs, cookies, or content. Cannot perform SSL termination at this layer (though some L4 LBs support it as an add-on). Cannot insert headers (like X-Forwarded-For).

**Use cases:** Database load balancing, TCP-based services (SMTP, LDAP), high-throughput scenarios where every microsecond matters, and UDP services (DNS, gaming).

## Layer 7 Load Balancing

L7 load balancers operate at the application layer, inspecting HTTP/HTTPS content to make intelligent routing decisions.

**How it works:** The load balancer terminates the client's TCP (and often TLS) connection, inspects the HTTP request, applies routing rules, and opens a new connection to the selected backend.

**Capabilities:**
- **URL-based routing:** `/api/*` goes to API servers, `/static/*` goes to CDN origin.
- **Host-based routing:** `api.example.com` → API pool, `www.example.com` → web pool.
- **Header inspection:** Route based on cookies, authorization headers, content type.
- **SSL termination:** Decrypt TLS at the load balancer, forward plaintext to backends (offloading TLS from servers).
- **Header injection:** Add `X-Forwarded-For`, `X-Real-IP` for backend logging.
- **WAF integration:** Inspect requests for attacks (SQLi, XSS) before forwarding.
- **Rate limiting:** Per-URL or per-client rate controls.

**Limitations:** Higher latency (payload inspection), higher resource consumption, limited to HTTP/HTTPS (typically), and TLS termination means the load balancer sees plaintext traffic.

## Security Considerations

**SSL/TLS termination:** L7 load balancers decrypt traffic, creating a point where data is in cleartext. Ensure the load balancer is hardened and the backend connection is re-encrypted if traversing an untrusted network.

**Source IP visibility:** With L4 NAT, the backend sees the load balancer's IP as the source. L7 load balancers add `X-Forwarded-For` headers, but backends must be configured to trust these headers only from the load balancer.

**Health checks:** Both L4 and L7 perform health checks. L4 checks TCP connectivity; L7 can verify HTTP response codes and content. Ensure health check endpoints do not expose sensitive information.

**DDoS considerations:** L4 load balancers handle volumetric attacks more efficiently. L7 load balancers are better at detecting application-layer attacks (slowloris, HTTP floods) but consume more resources per connection.

## Common Implementations

| Product | Type | Notes |
|---------|------|-------|
| HAProxy | L4/L7 | High-performance, open source |
| NGINX | L7 (L4 stream) | HTTP-focused, widely deployed |
| AWS ALB | L7 | Native AWS, WAF integration |
| AWS NLB | L4 | Ultra-low latency, static IPs |
| F5 BIG-IP | L4/L7 | Enterprise, full-featured |
| Envoy | L4/L7 | Service mesh, cloud-native |
""",
    },
    {
        "title": "NAT Types & Traversal Techniques",
        "tags": ["nat", "networking", "firewall", "traversal", "infrastructure"],
        "content": r"""# NAT Types & Traversal Techniques

Network Address Translation (NAT) maps private IP addresses to public addresses, enabling multiple devices to share a single public IP. NAT is ubiquitous in both home and enterprise networks, but it complicates peer-to-peer communication, incident investigation, and certain attack techniques.

## NAT Types

### Static NAT (1:1)
Maps a single private IP to a single public IP permanently. Used for servers that need consistent external addressing. Every port on the private IP maps to the same port on the public IP.

### Dynamic NAT (Many:Many)
Maps private IPs to a pool of public IPs on a first-come basis. Less common today; useful when you have multiple public IPs but more internal hosts than public addresses.

### PAT / NAT Overload (Many:1)
Port Address Translation — the most common type. Many private IPs share one public IP, distinguished by source port numbers. The NAT device maintains a translation table mapping (private_IP:private_port) ↔ (public_IP:translated_port).

**Example:** Internal host 10.0.0.5:54321 → NAT → 203.0.113.1:40001. The NAT table tracks this mapping so return traffic is correctly delivered.

### Carrier-Grade NAT (CGNAT — RFC 6598)
ISPs apply an additional NAT layer, placing customers behind shared public IPs. Uses the 100.64.0.0/10 address range. Complicates attribution — multiple subscribers share the same public IP simultaneously. Investigators need both the IP and port at a specific timestamp to identify a subscriber.

## NAT Traversal Challenges

NAT breaks end-to-end connectivity. Inbound connections to NAT'd hosts fail because the NAT device has no existing mapping for unsolicited inbound traffic.

### STUN (Session Traversal Utilities for NAT)
A client sends a request to a public STUN server, which replies with the client's observed public IP and port. The client uses this information to communicate its external address to peers. Works for "cone NAT" types but fails for symmetric NAT.

### TURN (Traversal Using Relays around NAT)
When direct communication is impossible, traffic relays through a TURN server. Both peers connect outbound to the relay. Guaranteed to work but adds latency and server cost.

### ICE (Interactive Connectivity Establishment)
The framework used by WebRTC and VoIP. ICE gathers connection candidates (local, STUN-derived, TURN-derived), tests all pairs simultaneously, and selects the best working path. Prioritizes direct connections, falling back to relay only when necessary.

### UDP Hole Punching
Both peers send UDP packets to each other's external address (learned via a signaling server). The outbound packets create NAT mappings; the peer's inbound packets match these mappings. Works with most NAT types except symmetric NAT.

## NAT Behavioral Types (RFC 4787)

| Type | Mapping Behavior | Impact |
|------|-----------------|--------|
| **Endpoint-Independent (Full Cone)** | Same mapping for all destinations | Easiest to traverse |
| **Address-Dependent (Restricted Cone)** | Mapping valid only for previously contacted IPs | Moderate difficulty |
| **Address+Port-Dependent (Port-Restricted)** | Mapping valid only for specific IP:port | Harder |
| **Symmetric** | Different mapping for each destination | Hardest; STUN fails, needs TURN |

## Security & Investigation Implications

**Log correlation:** NAT complicates log analysis. An external IP in an alert may represent thousands of internal hosts. Correlate NAT translation logs (timestamp + source IP + source port) with firewall and endpoint logs.

**NAT as security:** NAT is NOT a firewall, though it provides incidental protection by dropping unsolicited inbound traffic. It does not inspect payloads, enforce policies, or log malicious activity. Always deploy a proper stateful firewall alongside NAT.

**VPN and tunneling:** NAT can break IPsec ESP (protocol 50) since PAT only handles TCP/UDP. NAT-Traversal (NAT-T, RFC 3947) encapsulates ESP in UDP/4500 to solve this. IKEv2 handles NAT-T natively.

**IPv6 eliminates NAT:** With sufficient IPv6 addresses, NAT is unnecessary. Every device gets a globally routable address. Security relies on firewalls rather than address scarcity. This shift simplifies end-to-end connectivity but requires robust firewall policies.
""",
    },
    {
        "title": "IPv6 Addressing & Security Considerations",
        "tags": ["ipv6", "addressing", "security", "networking", "transition"],
        "content": r"""# IPv6 Addressing & Security Considerations

IPv6 (Internet Protocol version 6) uses 128-bit addresses, providing approximately 3.4 x 10^38 unique addresses — solving IPv4 exhaustion. As IPv6 adoption grows, SOC analysts must understand its addressing, security implications, and the risks introduced during dual-stack transition.

## Address Format

IPv6 addresses are written as eight groups of four hexadecimal digits separated by colons:
```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

**Shortening rules:**
- Leading zeros in each group can be omitted: `2001:db8:85a3:0:0:8a2e:370:7334`
- One consecutive sequence of all-zero groups can be replaced with `::`: `2001:db8:85a3::8a2e:370:7334`

## Address Types

| Type | Prefix | Purpose |
|------|--------|---------|
| **Global Unicast (GUA)** | 2000::/3 | Public, routable addresses (equivalent to IPv4 public) |
| **Link-Local** | fe80::/10 | Auto-configured on every interface, not routable (used for NDP, routing protocols) |
| **Unique Local (ULA)** | fc00::/7 (fd00::/8 in practice) | Private addresses (equivalent to RFC 1918) |
| **Multicast** | ff00::/8 | One-to-many (replaces broadcast) |
| **Loopback** | ::1/128 | Equivalent to 127.0.0.1 |
| **Unspecified** | ::/128 | Equivalent to 0.0.0.0 |

## Address Assignment Methods

**SLAAC (Stateless Address Autoconfiguration):** Hosts generate their own address using the network prefix (from Router Advertisement) and an Interface ID. The Interface ID can be derived from the MAC address (EUI-64) or randomly generated (RFC 7217 stable privacy addresses, or temporary addresses per RFC 8981).

**DHCPv6 (Stateful):** A DHCPv6 server assigns addresses, similar to DHCPv4. Provides centralized control and logging of assignments. Can provide DNS, NTP, and other configuration.

**EUI-64 privacy concern:** When the Interface ID is derived from the MAC address, the device is trackable across networks. Modern operating systems use temporary, randomized Interface IDs by default to address this.

## Security Implications

### Expanded Attack Surface
Every host may have multiple IPv6 addresses (link-local, GUA, temporary, ULA). Security tools and firewalls must handle all of them. A host with a blocking rule on its GUA may still be reachable on a secondary address.

### IPv6 in IPv4-Only Networks
Many operating systems enable IPv6 by default. Even on an "IPv4-only" network, hosts communicate via link-local IPv6. Attackers exploit this with:
- **Rogue Router Advertisements:** An attacker sends RAs, causing hosts to configure IPv6 addresses with the attacker as the default gateway. All IPv6 traffic (and possibly IPv4 via DNS64/NAT64) routes through the attacker.
- **DHCPv6 spoofing:** Similar to rogue DHCP in IPv4 but often unmonitored.

**Mitigation:** Enable RA Guard on switch ports. Deploy DHCPv6 snooping. Monitor for unexpected IPv6 traffic on IPv4-only segments.

### Dual-Stack Risks
During the IPv4-to-IPv6 transition, networks run both protocols. Security controls must be applied to both stacks. A firewall that only inspects IPv4 traffic is blind to IPv6 threats.

### Tunneling Risks
Transition mechanisms (6to4, Teredo, ISATAP) encapsulate IPv6 in IPv4. These tunnels may bypass IPv4 firewalls that do not inspect the encapsulated payload. Teredo (UDP/3544) is particularly concerning as it provides IPv6 connectivity through NAT without administrator involvement.

**Mitigation:** Block 6to4 (protocol 41), Teredo (UDP/3544), and ISATAP at the firewall unless explicitly needed. Disable Teredo on Windows endpoints via GPO.

### NDP (Neighbor Discovery Protocol)
NDP replaces ARP in IPv6. It uses ICMPv6 messages (Types 133-137) for router discovery, neighbor resolution, and address autoconfiguration. NDP spoofing is the IPv6 equivalent of ARP spoofing.

**Mitigation:** Implement ND inspection (similar to DHCP snooping + DAI in IPv4). Use SEND (SEcure Neighbor Discovery) where supported, though adoption is limited.

## SOC Monitoring

Log IPv6 traffic alongside IPv4. Ensure SIEM rules and dashboards account for IPv6 addresses. Monitor for unexpected Teredo/6to4 tunnel traffic. Alert on rogue Router Advertisements. Include IPv6 addresses in threat intelligence lookups and IOC matching.
""",
    },
]

COLLECTIONS = [
    ("Packet Analysis & Protocol Dissection", "Deep technical guides to packet capture analysis, protocol mechanics, and traffic inspection techniques for SOC analysts.", PACKET_ANALYSIS),
    ("DNS Architecture & Security", "Comprehensive coverage of DNS resolution, record types, DNSSEC, encrypted DNS, and DNS-based threat detection.", DNS_DEEP),
    ("Network Infrastructure & Design", "Enterprise networking concepts including VLANs, routing protocols, segmentation strategies, and modern architecture patterns.", NETWORK_INFRA),
]
