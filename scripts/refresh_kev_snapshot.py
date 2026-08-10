#!/usr/bin/env python3
"""Refresh the bundled CISA KEV snapshot. Run at RELEASE time, never at runtime.

ION ships into air-gapped and siloed environments, so the KEV catalog travels
inside the image. This is the one place that reaches out to cisa.gov, and it is
a developer tool run on a connected machine while cutting a release — the
application itself never fetches.

    python scripts/refresh_kev_snapshot.py            # fetch + write if newer
    python scripts/refresh_kev_snapshot.py --check    # report only, exit 1 if stale
    python scripts/refresh_kev_snapshot.py --from FILE  # use an already-downloaded copy

The written file is minified: the published feed is ~40% whitespace and nothing
reads it by hand.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.request

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BUNDLE = pathlib.Path(__file__).resolve().parent.parent / "src" / "ion" / "data" / "kev_catalog.json"
TIMEOUT = 60


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fetch() -> dict:
    print(f"fetching {FEED_URL}")
    with urllib.request.urlopen(FEED_URL, timeout=TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _validate(doc: dict) -> tuple[str, int]:
    """Refuse to write anything that is not recognisably a KEV catalog.

    A truncated download or an error page rendered as JSON would otherwise
    replace a good snapshot with a broken one, and the failure would not show
    up until a deployment somewhere reported an empty catalog.
    """
    version = str(doc.get("catalogVersion") or "").strip()
    vulns = doc.get("vulnerabilities")
    if not version:
        sys.exit("REFUSING: payload has no catalogVersion")
    if not isinstance(vulns, list) or len(vulns) < 500:
        sys.exit(f"REFUSING: expected a list of 500+ entries, got {type(vulns).__name__} "
                 f"len={len(vulns) if isinstance(vulns, list) else 'n/a'}")
    if not any(str(v.get("cveID", "")).startswith("CVE-") for v in vulns[:20]):
        sys.exit("REFUSING: entries do not look like KEV records")
    return version, len(vulns)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="report whether the bundle is behind; do not write")
    ap.add_argument("--from", dest="from_file",
                    help="read the catalog from a local file instead of fetching")
    args = ap.parse_args()

    current_version = None
    if BUNDLE.exists():
        try:
            current_version = str(_load(BUNDLE).get("catalogVersion") or "")
        except json.JSONDecodeError:
            print("warning: existing bundle is not valid JSON; it will be replaced")

    doc = _load(pathlib.Path(args.from_file)) if args.from_file else _fetch()
    version, count = _validate(doc)

    print(f"bundled: {current_version or '(none)'}   upstream: {version}   entries: {count}")

    if current_version and version <= current_version:
        print("bundle is already current — nothing to do")
        return 0

    if args.check:
        print("STALE: run without --check to update the bundle")
        return 1

    BUNDLE.parent.mkdir(parents=True, exist_ok=True)
    BUNDLE.write_text(json.dumps(doc, separators=(",", ":"), ensure_ascii=False),
                      encoding="utf-8")
    print(f"wrote {BUNDLE} ({BUNDLE.stat().st_size / 1024:.0f} KB) at version {version}")
    print("commit the updated snapshot as part of the release.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
