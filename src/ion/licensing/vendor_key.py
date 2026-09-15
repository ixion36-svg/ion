"""Baked-in vendor public key for licence verification.

Only the PUBLIC key lives here. The matching Ed25519 private key is held by the
vendor and used by ``tools/mint_de_licence.py`` to sign licences; it is never
committed. Rotating the vendor key means replacing this constant and re-minting
outstanding licences.
"""

# Ed25519 SubjectPublicKeyInfo, PEM. Verifies EdDSA-signed licence JWTs.
VENDOR_PUBLIC_KEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEASeWRf/8CEViHuXRjXGyC3NKhjNGRS6w5Z+vQYnv10NQ=
-----END PUBLIC KEY-----
"""
