#!/usr/bin/env python3
"""ION post-push image checker.

Reads the canonical version from pyproject.toml, then asks the registry what
the published image for that tag actually contains. Reports drift.

Why: step 8's warning used to be "three releases shipped as tags with no
image". v0.99.8 found the sneakier neighbour — a tag with the WRONG image,
twice over, each time looking fine from the outside:

  - the first push sent a stale local image whose baked-in version label read
    0.99.5, four days older than the release;
  - the second was a genuine build, but from a checkout that had never been
    fast-forwarded, so it stamped 0.99.5 again.

`docker push` reported success both times, because it had something to send.
Nothing in the release ritual looked at what landed. This script does, by
reading `org.opencontainers.image.version` out of the published image's config
blob — the Dockerfile's own stamp, which cannot be right unless the build came
from a correctly bumped tree.

It is deliberately NOT a `docker` wrapper: it talks to the registry over HTTPS
with stdlib only, so it needs no daemon, no local image and no login for a
repository that allows anonymous pulls.

Run it AFTER `docker push`, as the last step of the release.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PYPROJECT = REPO / "pyproject.toml"

# Distribution is the org's PRIVATE repo only, since 2026-08-20. The public
# `ixion36/ion` was retired the same day — do not add it back here.
IMAGE = "fubsxploitapps/ion"

AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
REGISTRY = "https://registry-1.docker.io/v2/{image}"
ACCEPT = ",".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
TIMEOUT = 30


def canonical_version() -> str:
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)["project"]["version"]


class Inconclusive(Exception):
    """The registry could not answer. NOT the same as drift — see main()."""


def _get(url: str, token: str, accept: str | None = None) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    if accept:
        req.add_header("Accept", accept)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            # 429 is Docker Hub's pull-rate limit and 5xx is its problem, not
            # the release's. Reporting either as drift would send someone
            # hunting a stale checkout that is not there.
            if e.code == 429 or e.code >= 500:
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise Inconclusive(
                    f"HTTP {e.code} from the registry"
                    + (" (pull-rate limited; retry shortly, or docker login)" if e.code == 429 else "")
                ) from e
            raise
    raise Inconclusive("exhausted retries")


def _token(image: str) -> str:
    try:
        with urllib.request.urlopen(AUTH.format(image=image), timeout=TIMEOUT) as resp:
            return json.load(resp)["token"]
    except urllib.error.HTTPError as e:
        if e.code == 429 or e.code >= 500:
            raise Inconclusive(f"HTTP {e.code} fetching a pull token") from e
        raise


def inspect(image: str, tag: str) -> dict:
    """The published image's build time, version label and config digest."""
    token = _token(image)
    base = REGISTRY.format(image=image)
    manifest = _get(f"{base}/manifests/{tag}", token, ACCEPT)

    if "manifests" in manifest:  # multi-arch index: follow linux/amd64
        children = manifest["manifests"]
        chosen = next(
            (
                m
                for m in children
                if m.get("platform", {}).get("os") == "linux"
                and m.get("platform", {}).get("architecture") == "amd64"
            ),
            children[0],
        )
        manifest = _get(f"{base}/manifests/{chosen['digest']}", token, ACCEPT)

    config = _get(f"{base}/blobs/{manifest['config']['digest']}", token)
    labels = (config.get("config") or {}).get("Labels") or {}
    return {
        "created": (config.get("created") or "")[:19],
        "version": labels.get("org.opencontainers.image.version"),
        "config_digest": manifest["config"]["digest"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=IMAGE, help=f"default: {IMAGE}")
    parser.add_argument(
        "--tag",
        help="image tag to check; defaults to the canonical version",
    )
    parser.add_argument(
        "--also-latest",
        action="store_true",
        help="also require `latest` to carry the canonical version",
    )
    args = parser.parse_args()

    target = canonical_version()
    tag = args.tag or target
    print(f"Canonical version (pyproject.toml): {target}")
    print(f"Published image:                    {args.image}:{tag}")
    print()

    failures = []
    unknown = []
    to_check = [tag] + (["latest"] if args.also_latest else [])

    for name in to_check:
        try:
            info = inspect(args.image, name)
        except Inconclusive as e:
            print(f"  ?  {name:<8} NOT VERIFIED — {e}")
            unknown.append(name)
            continue
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                print(f"  ?  {name:<8} NOT VERIFIED — HTTP {e.code}; needs a docker login")
                unknown.append(name)
            else:
                print(f"  X  {name:<8} HTTP {e.code} — no such tag; was the push run?")
                failures.append(name)
            continue
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  ?  {name:<8} NOT VERIFIED — {type(e).__name__}: {e}")
            unknown.append(name)
            continue
        except (KeyError, StopIteration) as e:
            print(f"  X  {name:<8} unreadable manifest: {type(e).__name__}: {e}")
            failures.append(name)
            continue

        label = info["version"] or "<no version label>"
        short = info["config_digest"][7:19]
        if label == target:
            print(f"  OK {name:<8} version={label:<8} built={info['created']}  {short}")
        else:
            print(f"  X  {name:<8} version={label:<8} built={info['created']}  {short}")
            print(f"     ^ expected {target}. The pushed image was not built from this tree.")
            failures.append(name)

    print()
    if unknown and not failures:
        print(f"INCONCLUSIVE: could not verify {', '.join(unknown)}.")
        print("This is NOT drift — the registry did not answer. Re-run before")
        print("concluding anything about the release.")
        return 2

    if failures:
        print(f"FAIL: {len(failures)} tag(s) do not carry {target}.")
        print()
        print("Almost always a stale checkout or a stale local image. Check, in order:")
        print("  git log --oneline -1                        # the release commit?")
        print("  grep opencontainers.image.version Dockerfile  # the canonical version?")
        print("  docker build --no-cache -t <image>:X.Y.Z .  # then push, then re-run this")
        print()
        print("`git fetch origin main` + `git checkout main` does NOT move local main;")
        print("use `git reset --hard origin/main` (or `git merge --ff-only origin/main`).")
        return 1

    print(f"PASS: the published image carries {target}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
