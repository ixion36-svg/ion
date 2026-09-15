#!/usr/bin/env python3
"""Vendor-side: mint an Ed25519-signed ION module licence.

This is NOT part of the running application. It is run by the vendor, offline,
with the private key that matches the public key baked into
``ion.licensing.vendor_key``. The resulting token is handed to a customer and
pointed at by ION_DE_LICENSE (inline value or a file path).

Usage:
  python tools/mint_de_licence.py \\
      --key /path/to/de_vendor_private_ed25519.pem \\
      --customer acme \\
      --modules detection_engineering \\
      --expires-days 365 \\
      --out acme.licence

Omit --expires-days for a non-expiring licence.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid

import jwt


def main() -> int:
    ap = argparse.ArgumentParser(description="Mint an ION module licence (Ed25519 JWT).")
    ap.add_argument("--key", required=True, help="Path to the Ed25519 private key PEM.")
    ap.add_argument("--customer", required=True, help="Customer id (recorded in the licence).")
    ap.add_argument(
        "--modules", default="detection_engineering",
        help="Comma-separated module ids to entitle (default: detection_engineering).",
    )
    ap.add_argument("--expires-days", type=int, default=None, help="Optional validity in days.")
    ap.add_argument("--out", default=None, help="Write the token here (default: stdout).")
    args = ap.parse_args()

    with open(args.key, "r", encoding="utf-8") as fh:
        private_pem = fh.read()

    now = int(time.time())
    claims = {
        "customer_id": args.customer,
        "modules": [m.strip() for m in args.modules.split(",") if m.strip()],
        "licence_id": str(uuid.uuid4()),
        "iat": now,
    }
    if args.expires_days is not None:
        claims["exp"] = now + args.expires_days * 86400

    token = jwt.encode(claims, private_pem, algorithm="EdDSA")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
        print(f"Wrote licence for '{args.customer}' ({', '.join(claims['modules'])}) -> {args.out}")
    else:
        print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
