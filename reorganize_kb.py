"""Reorganize knowledge base documents under a dedicated parent collection."""
import requests

BASE = "http://127.0.0.1:8000"
SESSION = requests.Session()

def login():
    r = SESSION.post(
        f"{BASE}/api/auth/login",
        json={"username": "admin", "password": "admin2025"},
    )
    r.raise_for_status()
    print("[+] Logged in as admin")

def get_collections(flat=True):
    """Get collections. If flat=True, returns flattened list including nested."""
    params = {"flat": "true"} if flat else {}
    r = SESSION.get(f"{BASE}/api/collections", params=params)
    r.raise_for_status()
    data = r.json()
    # Handle both flat list and tree structure responses
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "collections" in data:
        return data["collections"]
    else:
        return data

def create_collection(name, desc, parent_id=None):
    body = {"name": name, "description": desc}
    if parent_id:
        body["parent_id"] = parent_id
    r = SESSION.post(f"{BASE}/api/collections", json=body)
    r.raise_for_status()
    cid = r.json()["id"]
    print(f"  Created collection: {name} (id={cid})")
    return cid

def update_collection(col_id, parent_id):
    body = {"parent_id": parent_id}
    r = SESSION.put(f"{BASE}/api/collections/{col_id}", json=body)
    if r.status_code == 200:
        print(f"  Updated collection {col_id}: parent_id={parent_id}")
    else:
        print(f"  Warning: Could not update collection {col_id}: {r.status_code}")

def delete_collection(col_id):
    r = SESSION.delete(f"{BASE}/api/collections/{col_id}")
    if r.status_code == 200:
        print(f"  Deleted collection {col_id}")
    else:
        print(f"  Warning: Could not delete collection {col_id}: {r.status_code}")

def main():
    print("="*60)
    print("Reorganizing Knowledge Base")
    print("="*60)

    login()

    # Get current collections
    collections = get_collections()
    cols_by_id = {c["id"]: c for c in collections}
    cols_by_name = {c["name"]: c for c in collections}

    print("\nCurrent collection structure:")
    for col in collections:
        parent_info = f" (parent_id={col.get('parent_id')})" if col.get("parent_id") else " (root)"
        print(f"  {col['name']:40} id={col['id']:3}{parent_info}")

    # Find old parent
    old_parent_id = cols_by_name.get("Knowledge Base", {}).get("id")
    if not old_parent_id:
        print("\nError: 'Knowledge Base' parent collection not found")
        return

    print(f"\n[*] Found old parent 'Knowledge Base' (id={old_parent_id})")

    # Create new parent
    print("\n[*] Creating 'Analyst Knowledge Base' parent collection...")
    new_parent_id = create_collection(
        "Analyst Knowledge Base",
        "SOC Analyst Reference Library — comprehensive knowledge base covering "
        "Windows, Linux, networking, SIEM, malware analysis, incident response, "
        "threat intelligence, cloud security, penetration testing, detection "
        "engineering, cryptography, and compliance frameworks."
    )

    # Find all sub-collections (children of old parent)
    subcols = [c for c in collections if c.get("parent_id") == old_parent_id]
    print(f"\n[*] Found {len(subcols)} sub-collections to move:")
    for col in subcols:
        print(f"    - {col['name']} (id={col['id']})")

    # Move sub-collections to new parent
    print(f"\n[*] Moving sub-collections under new parent (id={new_parent_id})...")
    for col in subcols:
        update_collection(col["id"], new_parent_id)

    # Delete old parent (now empty)
    print(f"\n[*] Deleting old empty parent 'Knowledge Base' (id={old_parent_id})...")
    delete_collection(old_parent_id)

    print("\n" + "="*60)
    print("Reorganization complete!")
    print("="*60)
    print(f"\nNew structure:")
    print(f"  Analyst Knowledge Base (id={new_parent_id}) [parent]")
    for col in subcols:
        print(f"    - {col['name']} (id={col['id']}) [child]")

if __name__ == "__main__":
    main()
