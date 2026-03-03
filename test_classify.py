"""Test rule classification directly."""
import sqlite3
import json

DB = r"C:\Users\Tomo\ion\.ion\ion.db"

# Test the classification function standalone
_RULE_CATEGORY_KEYWORDS = {
    "Credential Access": ["brute force", "credential", "kerberoast", "kerberos", "lsass", "mimikatz", "password", "ntlm"],
    "Execution": ["powershell", "script", "command", "wmi", "macro", "malware", "trojan"],
    "Lateral Movement": ["lateral", "psexec", "rdp", "remote", "smb", "wmi"],
    "Exfiltration": ["exfiltration", "upload", "data loss", "transfer"],
    "Persistence": ["persistence", "scheduled task", "registry", "service", "startup"],
    "Privilege Escalation": ["privilege", "escalation", "uac", "bypass", "admin"],
    "Command and Control": ["c2", "beacon", "dns tunnel", "dga", "cobalt", "ssl"],
    "Defense Evasion": ["evasion", "log clear", "firewall", "disable", "tamper"],
    "Network Security": ["port scan", "scan", "firewall rule"],
    "Initial Access": ["phishing", "email", "login", "geo"],
    "Impact": ["ransomware", "encrypt", "wiper", "destroy"],
}

def _classify(rules):
    if not rules:
        return "General"
    combined = " ".join(rules).lower()
    for category, keywords in _RULE_CATEGORY_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return category
    return "General"

# Test cases
tests = [
    ["Kerberoasting Detected"],
    ["Credential Dumping - LSASS Access"],
    ["Lateral Movement via PsExec"],
    ["Ransomware Behavior"],
    None,
    [],
]
for t in tests:
    print(f"  {t!r:50s} -> {_classify(t)}")

# Check what's actually in the DB
print("\n=== KFPs in DB ===")
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT id, title, match_rules FROM known_false_positives")
for row in cur.fetchall():
    rules = json.loads(row[2]) if row[2] else None
    cat = _classify(rules)
    print(f"  KFP {row[0]}: '{row[1]}' | rules={rules} -> {cat}")
conn.close()
