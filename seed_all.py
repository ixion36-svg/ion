"""Master seeder — runs all ION seed scripts in order.

Used by:
  - Docker seeder container (entrypoint)
  - start_ion.ps1 (Windows local dev, first-run)

Checks for a .seeded marker so it only runs once per data volume.
Pass --force to re-seed regardless.

Environment variables:
  ION_SEED_URL          Base URL of ION server (default: http://127.0.0.1:8000)
  ION_ADMIN_PASSWORD    Admin password (default: admin2025)
  ION_DATA_DIR          Data directory for .seeded marker (default: /data)
"""

import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

SEED_URL = os.environ.get("ION_SEED_URL", "http://127.0.0.1:8000")
DATA_DIR = os.environ.get("ION_DATA_DIR", "/data")
MARKER = Path(DATA_DIR) / ".ion" / ".seeded"

# Ordered list of seed scripts (HTTP API only)
SEEDS = [
    ("Core Templates", "seed_ion_data.py"),
    ("Knowledge Base (core)", "seed_knowledge_base.py"),
    ("Knowledge Base (blue team)", "seed_knowledge_base_blueteam.py"),
    ("Knowledge Base (foundations)", "seed_knowledge_base_foundations.py"),
    ("Knowledge Base (security fundamentals)", "seed_knowledge_base_security_fundamentals.py"),
    ("Playbooks", "seed_playbooks.py"),
    ("SOC Templates", "seed_soc_templates.py"),
]

HEALTH_URL = f"{SEED_URL}/api/health"
HEALTH_TIMEOUT = 120  # seconds
HEALTH_INTERVAL = 5   # seconds between retries


def wait_for_health():
    """Wait until ION health endpoint responds 200."""
    print(f"Waiting for ION at {HEALTH_URL} ...")
    deadline = time.time() + HEALTH_TIMEOUT
    while time.time() < deadline:
        try:
            req = urllib.request.Request(HEALTH_URL)
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    print("  ION is healthy.")
                    return True
        except (urllib.error.URLError, OSError):
            pass
        remaining = int(deadline - time.time())
        print(f"  Not ready, retrying... ({remaining}s remaining)")
        time.sleep(HEALTH_INTERVAL)

    print(f"ERROR: ION did not become healthy within {HEALTH_TIMEOUT}s")
    return False


def run_seed(label, script_name):
    """Run a seed script as a subprocess. Returns True on success."""
    script_dir = Path(__file__).resolve().parent
    script_path = script_dir / script_name

    if not script_path.exists():
        print(f"  WARNING: {script_name} not found at {script_path}, skipping")
        return False

    print(f"\n{'='*60}")
    print(f"  Seeding: {label}")
    print(f"  Script:  {script_name}")
    print(f"{'='*60}")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(script_dir),
        env={**os.environ},
        timeout=300,
    )

    if result.returncode != 0:
        print(f"  FAILED (exit code {result.returncode})")
        return False

    print(f"  OK")
    return True


def main():
    force = "--force" in sys.argv

    # Check marker
    if MARKER.exists() and not force:
        print(f"Already seeded (marker: {MARKER})")
        print("Pass --force to re-seed.")
        return 0

    # Wait for ION
    if not wait_for_health():
        return 1

    # Run seeds
    results = {}
    for label, script in SEEDS:
        try:
            ok = run_seed(label, script)
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT: {script} exceeded 300s")
            ok = False
        except Exception as e:
            print(f"  ERROR: {e}")
            ok = False
        results[label] = ok

    # Summary
    print(f"\n{'='*60}")
    print("  SEED SUMMARY")
    print(f"{'='*60}")
    passed = 0
    failed = 0
    for label, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  [{status:6s}] {label}")
        if ok:
            passed += 1
        else:
            failed += 1
    print(f"\n  Total: {passed} passed, {failed} failed")

    # Write marker if at least some seeds succeeded
    if passed > 0:
        try:
            MARKER.parent.mkdir(parents=True, exist_ok=True)
            MARKER.write_text(
                f"Seeded at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
                f"Passed: {passed}, Failed: {failed}\n"
            )
            print(f"\n  Marker written: {MARKER}")
        except OSError as e:
            print(f"  WARNING: Could not write marker: {e}")

    if failed > 0:
        print("\nSome seeds failed — check logs above.")
        return 1

    print("\nAll seeds completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
