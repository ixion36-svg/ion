"""Seed ION with test observables pulled from OpenCTI, then enrich them.

Usage: python seed_observables.py
Requires: ION server running at http://127.0.0.1:8000
"""

import requests
import time

BASE = "http://127.0.0.1:8000"
SESSION = requests.Session()


def login():
    r = SESSION.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin2025"})
    r.raise_for_status()
    print("Logged in as admin")


def create_observables_batch(observables):
    """Create observables via CSV import API (JSON body)."""
    # Build CSV string: type,value
    lines = ["type,value"]
    for obs_type, value in observables:
        # Escape commas/quotes in values
        escaped = value.replace('"', '""')
        if "," in escaped or '"' in escaped:
            escaped = f'"{escaped}"'
        lines.append(f"{obs_type},{escaped}")
    csv_data = "\n".join(lines)

    r = SESSION.post(
        f"{BASE}/api/observables/import/csv",
        json={"csv_data": csv_data, "auto_enrich": False},
    )
    r.raise_for_status()
    result = r.json()
    print(f"  CSV import: created={result.get('created', 0)}, existing={result.get('existing', 0)}, errors={result.get('errors', 0)}")
    return result


def find_observable(value):
    """Find an observable by value."""
    r = SESSION.get(f"{BASE}/api/observables", params={"query": value, "limit": 1})
    r.raise_for_status()
    data = r.json()
    if data.get("observables"):
        return data["observables"][0]
    return None


def enrich_observable(obs_id, value):
    """Trigger enrichment for an observable."""
    try:
        r = SESSION.post(f"{BASE}/api/observables/{obs_id}/enrich", params={"source": "opencti"}, timeout=30)
        r.raise_for_status()
        data = r.json()
        enrichment = data.get("enrichment", {})
        obs = data.get("observable", {})
        is_mal = enrichment.get("is_malicious")
        score = enrichment.get("score")
        threat_level = obs.get("threat_level")
        ta = len(enrichment.get("threat_actors") or [])
        ind = len(enrichment.get("indicators") or [])
        labels = len(enrichment.get("labels") or [])
        status = "MALICIOUS" if is_mal else "clean"
        print(f"  [{status:9s}] {obs.get('type','?'):10s} {value[:50]:50s} score={score} threat={threat_level} ind={ind} ta={ta} labels={labels}")
        return True
    except Exception as e:
        print(f"  [FAILED   ] {value[:50]:50s} {e}")
        return False


def main():
    login()

    # Known-malicious observables from OpenCTI feeds + benign for contrast
    observables = [
        # IPs (GreyNoise malicious scanners)
        ("ipv4", "106.117.106.208"),
        ("ipv4", "59.97.252.28"),
        ("ipv4", "59.183.103.52"),
        ("ipv4", "123.5.112.107"),
        ("ipv4", "46.22.235.96"),
        ("ipv4", "102.129.229.228"),
        ("ipv4", "202.107.97.192"),
        # Domains (phishing/malware C2)
        ("domain", "tows.instawaregoodtagsfree.com"),
        ("domain", "j0rq.instawaregoodtagsfree.com"),
        ("domain", "wwtb.instawaregoodtagsfree.com"),
        ("domain", "su3i.instawaregoodtagsfree.com"),
        ("domain", "f0b5.gigaversecentiliumai.cloud"),
        # URLs (phishing)
        ("url", "https://8k0n.instawaregoodtagsfree.com/?aaaa702984be883cb0"),
        ("url", "https://j0rq.instawaregoodtagsfree.com/"),
        ("url", "https://tows.instawaregoodtagsfree.com/?821e1aceef9"),
        # File hashes - MD5 (malware samples from AbuseCH feed)
        ("md5", "bad0235077624f052320e4c402839047"),
        ("md5", "609f45ac1b88e05e762a60db820b019d"),
        ("md5", "4ae862685e53196eb4d405120827a72c"),
        ("md5", "595fcb113805a57ae9cb7ecde542a655"),
        ("md5", "6d2e24eef41d515aff1c323bfc62b243"),
        # Benign / clean
        ("ipv4", "8.8.8.8"),
        ("ipv4", "1.1.1.1"),
        ("domain", "google.com"),
        ("domain", "microsoft.com"),
    ]

    print(f"\n=== Creating {len(observables)} observables via CSV import ===")
    create_observables_batch(observables)

    print(f"\n=== Enriching observables against OpenCTI ===")
    success = 0
    failed = 0
    for obs_type, value in observables:
        obs = find_observable(value)
        if not obs:
            print(f"  [NOT FOUND] {obs_type:10s} {value[:50]}")
            failed += 1
            continue
        if enrich_observable(obs["id"], value):
            success += 1
        else:
            failed += 1
        time.sleep(0.2)

    print(f"\n=== Results ===")
    print(f"  Enriched OK: {success}")
    print(f"  Failed:      {failed}")

    # Show summary stats
    print(f"\n=== Observable Stats ===")
    r = SESSION.get(f"{BASE}/api/observables/stats")
    if r.ok:
        stats = r.json()
        for key, val in stats.items():
            print(f"  {key}: {val}")


if __name__ == "__main__":
    main()
