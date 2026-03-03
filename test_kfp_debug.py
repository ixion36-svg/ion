"""Debug: check what documents exist after creating a KFP."""
import requests
import json
import time
import sqlite3

BASE = "http://127.0.0.1:8000"
DB = r"C:\Users\Tomo\ion\.ion\ion.db"
s = requests.Session()

# Login
resp = s.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin2025"})
print(f"Login: {resp.status_code}")

# Create first KFP
print("\n=== Create KFP 1 ===")
resp = s.post(f"{BASE}/api/known-false-positives", json={
    "title": "FP: Kerberos Renewal",
    "description": "Test",
    "match_rules": ["Kerberoasting Detected"],
})
r1 = resp.json()
print(f"KFP {r1['id']}, doc_id={r1.get('document_id')}")

# Directly check SQLite
print("\n=== Documents in DB ===")
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT id, name, collection_id, status FROM documents")
for row in cur.fetchall():
    print(f"  id={row[0]}, name='{row[1]}', coll_id={row[2]}, status={row[3]}")

print("\n=== Collections in DB ===")
cur.execute("SELECT id, name FROM collections")
for row in cur.fetchall():
    print(f"  id={row[0]}, name='{row[1]}'")
conn.close()

# Create second KFP in same category
print("\n=== Create KFP 2 ===")
resp = s.post(f"{BASE}/api/known-false-positives", json={
    "title": "FP: LSASS by AV",
    "description": "Test 2",
    "match_rules": ["Credential Dumping - LSASS Access"],
})
r2 = resp.json()
print(f"KFP {r2['id']}, doc_id={r2.get('document_id')}")

# Check DB again
print("\n=== Documents in DB after 2nd KFP ===")
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT id, name, collection_id, status, current_version FROM documents")
for row in cur.fetchall():
    print(f"  id={row[0]}, name='{row[1]}', coll_id={row[2]}, status={row[3]}, ver={row[4]}")
conn.close()
