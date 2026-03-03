"""Restore knowledge base collection structure and move orphaned documents."""
import requests

BASE = "http://127.0.0.1:8000"
SESSION = requests.Session()

def login():
    r = SESSION.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin2025"})
    r.raise_for_status()
    print("[+] Logged in as admin")

def create_collection(name, desc, parent_id=None):
    body = {"name": name, "description": desc}
    if parent_id:
        body["parent_id"] = parent_id
    r = SESSION.post(f"{BASE}/api/collections", json=body)
    if r.status_code == 400:
        # Collection may already exist
        return None
    r.raise_for_status()
    cid = r.json()["id"]
    print(f"  Created: {name} (id={cid})")
    return cid

def get_collections():
    r = SESSION.get(f"{BASE}/api/collections", params={"flat": "true"})
    data = r.json()
    if isinstance(data, list):
        return data
    return data.get("collections", [])

def get_documents(search_term=None):
    params = {"search": search_term} if search_term else {}
    r = SESSION.get(f"{BASE}/api/documents", params=params)
    data = r.json()
    if isinstance(data, list):
        return data
    return data.get("documents", [])

def move_doc_to_collection(doc_id, col_id):
    """Move document to collection by adding it."""
    r = SESSION.post(f"{BASE}/api/collections/{col_id}/documents/{doc_id}")
    if r.status_code == 200:
        return True
    return False

def main():
    print("="*70)
    print("Restoring Knowledge Base Collection Structure")
    print("="*70)

    login()

    # Find Analyst Knowledge Base parent
    cols = get_collections()
    analyst_kb = next((c for c in cols if c["name"] == "Analyst Knowledge Base"), None)
    if not analyst_kb:
        print("Error: 'Analyst Knowledge Base' parent not found!")
        return
    parent_id = analyst_kb["id"]
    print(f"\n[*] Found parent 'Analyst Knowledge Base' (id={parent_id})")

    # Define collection structure
    collections = [
        ("Windows & Active Directory", "Windows internals, event logs, AD attacks, PowerShell, registry, services"),
        ("Linux & Bash", "Linux filesystem, processes, logs, common attack surfaces, hardening"),
        ("Networking", "TCP/IP, DNS, HTTP, TLS, Wireshark filters, packet analysis, protocols"),
        ("SIEM & Log Analysis", "KQL queries, Splunk SPL, log source guides, correlation rules, parsing"),
        ("Malware Analysis", "Static/dynamic analysis, sandboxing, reverse engineering basics, tools"),
        ("Incident Response & Forensics", "Memory forensics, disk imaging, timeline analysis, evidence handling"),
        ("Threat Intelligence", "MITRE ATT&CK deep-dives, threat actor profiles, IOC management, OSINT"),
        ("Cloud Security", "AWS/Azure/GCP logging, IAM attacks, cloud IR, container security"),
        ("Penetration Testing", "Recon, exploitation, privesc, lateral movement, web app attacks, tools"),
        ("Detection Engineering", "Sigma rules, YARA rules, detection logic, tuning, coverage mapping"),
        ("Cryptography & Authentication", "TLS, PKI, Kerberos, OAuth, hashing, common crypto attacks"),
        ("Compliance & Frameworks", "NIST CSF, ISO 27001, PCI-DSS, GDPR, CIS benchmarks overview"),
    ]

    # Create collections
    print(f"\n[*] Creating {len(collections)} sub-collections under parent...")
    collection_map = {}
    for col_name, col_desc in collections:
        # Check if exists
        existing = next((c for c in cols if c["name"] == col_name), None)
        if existing:
            print(f"  Exists: {col_name} (id={existing['id']})")
            collection_map[col_name] = existing["id"]
        else:
            cid = create_collection(col_name, col_desc, parent_id)
            if cid:
                collection_map[col_name] = cid
                cols = get_collections()  # Refresh

    # Get orphaned documents
    print(f"\n[*] Finding orphaned knowledge base documents...")
    all_docs = get_documents()
    orphaned = [d for d in all_docs if d.get("collection_id") is None and d.get("name") not in ["Test", "Sample"]]
    print(f"  Found {len(orphaned)} orphaned documents")

    # Map docs to collections based on keywords in their names
    print(f"\n[*] Moving documents to collections...")
    doc_move_count = 0

    keyword_map = {
        "Windows & Active Directory": ["windows", "active directory", "kerberos", "dcsync", "credential dumping", "lsass", "wmi", "dcom", "group policy"],
        "Linux & Bash": ["linux", "bash", "ssh", "privilege escalation", "systemd", "selinux", "container escape"],
        "Networking": ["tcp", "dns", "http", "tls", "wireshark", "arp", "dhcp", "icmp", "bgp", "smtp", "port", "proxy"],
        "SIEM & Log Analysis": ["kql", "splunk", "elasticsearch", "log source", "sysmon", "correlation", "firewall log", "email gateway"],
        "Malware Analysis": ["malware", "static analysis", "dynamic analysis", "sandbox", "office", "pdf", "javascript", "powershell malware", "reverse engineering", "packing", "ransomware", "rat", "fileless", "yara"],
        "Incident Response & Forensics": ["incident response", "forensics", "memory", "disk imaging", "timeline", "email header", "browser forensics", "usb", "evidence", "cloud forensics", "mobile forensics", "ransomware response", "bec", "insider threat", "incident report"],
        "Threat Intelligence": ["mitre attack", "diamond model", "kill chain", "threat actor", "apt", "osint", "ioc", "dark web"],
        "Cloud Security": ["aws", "azure", "gcp", "cloudtrail", "kubernetes", "docker", "container", "serverless"],
        "Penetration Testing": ["penetration testing", "reconnaissance", "nmap", "burp", "sql injection", "xss", "ssrf", "directory traversal", "privilege escalation", "password attack", "metasploit", "post-exploitation", "api security"],
        "Detection Engineering": ["sigma", "yara", "snort", "suricata", "detection coverage", "alert tuning", "detection-as-code", "threat hunting", "detection lab", "detection rule"],
        "Cryptography & Authentication": ["tls", "ssl", "pki", "certificate", "oauth", "openid", "hashing", "crypto attack", "password storage", "jwt"],
        "Compliance & Frameworks": ["nist", "iso 27001", "pci-dss", "gdpr", "cis controls", "soc 2", "hipaa", "incident reporting"],
    }

    for doc in orphaned:
        doc_name = doc.get("name", "").lower()
        # Find matching collection
        for col_name, keywords in keyword_map.items():
            if any(kw in doc_name for kw in keywords):
                col_id = collection_map.get(col_name)
                if col_id and move_doc_to_collection(doc["id"], col_id):
                    doc_move_count += 1
                    print(f"    Moved: {doc['name'][:50]:50} >> {col_name}")
                break

    print(f"\n[*] Moved {doc_move_count} documents to collections")

    # Special case: add to Threat Intelligence and Detection Engineering
    print(f"\n[*] Adding existing articles to their designated collections...")
    existing_docs = [d for d in all_docs if d.get("collection_id") is not None]
    print(f"  Total existing collection members: {len(existing_docs)}")

    print("\n" + "="*70)
    print("Knowledge Base Restoration Complete!")
    print("="*70)
    print(f"\nFinal structure:")
    print(f"  Analyst Knowledge Base (id={parent_id}) [parent]")
    for col_name in [c[0] for c in collections]:
        col_id = collection_map.get(col_name)
        print(f"    - {col_name} (id={col_id}) [child]")

if __name__ == "__main__":
    main()
