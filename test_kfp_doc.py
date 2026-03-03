"""Test consolidated KFP registry documents by rule category."""
import requests
import json
import time

BASE = "http://127.0.0.1:8000"
s = requests.Session()

# Login
time.sleep(5)
resp = s.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin2025"})
print(f"Login: {resp.status_code}")

# 1. Create KFP in "Credential Access" category
print("\n=== 1. Create KFP — Credential Access ===")
resp = s.post(f"{BASE}/api/known-false-positives", json={
    "title": "FP: Kerberos Service Account Renewal",
    "description": "Service accounts auto-renew Kerberos tickets every 4 hours, triggering Kerberoasting alerts.",
    "match_rules": ["Kerberoasting Detected"],
    "match_users": ["svc_backup"],
    "match_hosts": ["SRV-DC01"],
})
r1 = resp.json()
print(f"KFP {r1['id']} created, doc_id={r1.get('document_id')}")

# 2. Create another KFP in same category
print("\n=== 2. Create second KFP — Credential Access ===")
resp = s.post(f"{BASE}/api/known-false-positives", json={
    "title": "FP: LSASS Access by AV Scanner",
    "description": "Antivirus scanner legitimately accesses LSASS for memory scanning.",
    "match_rules": ["Credential Dumping - LSASS Access"],
    "match_hosts": ["WKS-HR01", "WKS-ANALYST01"],
})
r2 = resp.json()
print(f"KFP {r2['id']} created, doc_id={r2.get('document_id')}")
# Same doc should be returned (amended)
assert r1.get("document_id") == r2.get("document_id"), \
    f"Expected same doc ID, got {r1.get('document_id')} vs {r2.get('document_id')}"
print("  Same document amended — PASS")

# 3. Create KFP in different category: Lateral Movement
print("\n=== 3. Create KFP — Lateral Movement ===")
resp = s.post(f"{BASE}/api/known-false-positives", json={
    "title": "FP: PsExec Admin Maintenance",
    "description": "IT admin uses PsExec for remote maintenance on weekends.",
    "match_rules": ["Lateral Movement via PsExec"],
    "match_users": ["admin"],
    "match_hosts": ["SRV-FILE01"],
})
r3 = resp.json()
print(f"KFP {r3['id']} created, doc_id={r3.get('document_id')}")
assert r3.get("document_id") != r1.get("document_id"), \
    "Expected different doc for different category"
print("  Different document for different category — PASS")

# 4. Verify the documents
print("\n=== 4. Verify documents ===")
for doc_id, label in [(r1["document_id"], "Credential Access"), (r3["document_id"], "Lateral Movement")]:
    resp = s.get(f"{BASE}/api/documents/{doc_id}")
    doc = resp.json()
    print(f"\n  [{doc_id}] {doc['name']}")
    print(f"  Version: {doc['current_version']}")
    content = doc["rendered_content"]
    # Show first 500 chars
    print(f"  Content preview:\n{'='*60}")
    print(content[:500])
    print(f"{'='*60}")

# 5. Check that Credential Access doc is at version 2 (two entries)
resp = s.get(f"{BASE}/api/documents/{r1['document_id']}")
doc = resp.json()
print(f"\n=== 5. Verify versioning ===")
print(f"  Credential Access doc version: {doc['current_version']} (expected 2)")
assert doc["current_version"] == 2, f"Expected version 2, got {doc['current_version']}"
print("  PASS")

# 6. Check collections
print("\n=== 6. Verify collections ===")
resp = s.get(f"{BASE}/api/collections")
collections = resp.json().get("collections", resp.json()) if isinstance(resp.json(), dict) else resp.json()
if isinstance(collections, list):
    kfp_colls = [c for c in collections if "Known False Positive" in c.get("name", "")]
else:
    kfp_colls = [c for c in collections.get("collections", []) if "Known False Positive" in c.get("name", "")]
for c in kfp_colls:
    print(f"  {c['name']} (id={c['id']})")
print(f"  {len(kfp_colls)} KFP collections found")

print("\n=== ALL TESTS PASSED ===")
