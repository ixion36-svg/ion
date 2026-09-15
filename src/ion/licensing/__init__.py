"""ION optional-module licensing.

Offline, air-gap-friendly entitlement: a licence is an Ed25519-signed JWT
(minted with the vendor private key, held only by the vendor) verified against
the public key baked into this package. No network, no phone-home.

The licence names which optional modules a deployment is entitled to. Gating is
computed in :mod:`ion.licensing.gating`; enforcement is a separate, default-off
switch so the machinery can ship dormant and be turned on later.
"""
