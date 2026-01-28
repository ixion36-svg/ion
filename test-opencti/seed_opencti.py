#!/usr/bin/env python3
"""Seed OpenCTI test instance with threat intelligence data.

Creates indicators, observables, threat actors, malware, and relationships
via individual GraphQL mutations. Uses raw httpx -- no pycti dependency.

Usage:
    python seed_opencti.py [--url URL] [--token TOKEN]
"""

import argparse
import sys
import time

try:
    import httpx
except ImportError:
    print("httpx is required: pip install httpx")
    sys.exit(1)

OPENCTI_URL = "http://localhost:8888"
OPENCTI_TOKEN = "5b3d8e6f-2a1c-4b9d-8e7f-3c6a9d4b2e1f"


class OpenCTISeeder:
    """Seeds an OpenCTI instance via individual GraphQL mutations."""

    def __init__(self, url: str, token: str):
        self.graphql_url = f"{url.rstrip('/')}/graphql"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.client = httpx.Client(timeout=60.0)
        # Logical key -> OpenCTI internal ID
        self.ids: dict[str, str] = {}
        self.created = 0
        self.errors = 0
        self.skipped = 0

    def _gql(self, query: str, variables: dict | None = None):
        """Execute a GraphQL request. Returns (data, error_msg)."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        resp = self.client.post(self.graphql_url, json=payload, headers=self.headers)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        body = resp.json()
        if "errors" in body:
            return None, body["errors"][0].get("message", str(body["errors"]))
        return body.get("data"), None

    # ------------------------------------------------------------------
    # Entity creators
    # ------------------------------------------------------------------

    def _create_threat_actor(self, key: str, **kwargs):
        mutation = """mutation($input: ThreatActorGroupAddInput!) {
            threatActorGroupAdd(input: $input) { id name }
        }"""
        data, err = self._gql(mutation, {"input": kwargs})
        if err:
            print(f"    ERROR threat actor '{kwargs.get('name')}': {err}")
            self.errors += 1
            return
        r = data["threatActorGroupAdd"]
        self.ids[key] = r["id"]
        print(f"    + Threat Actor: {r['name']}")
        self.created += 1

    def _create_malware(self, key: str, **kwargs):
        mutation = """mutation($input: MalwareAddInput!) {
            malwareAdd(input: $input) { id name }
        }"""
        data, err = self._gql(mutation, {"input": kwargs})
        if err:
            print(f"    ERROR malware '{kwargs.get('name')}': {err}")
            self.errors += 1
            return
        r = data["malwareAdd"]
        self.ids[key] = r["id"]
        print(f"    + Malware: {r['name']}")
        self.created += 1

    def _create_indicator(self, key: str, **kwargs):
        """Create indicator. createObservables=True auto-creates the
        observable and the based-on relationship."""
        mutation = """mutation($input: IndicatorAddInput!) {
            indicatorAdd(input: $input) { id name }
        }"""
        data, err = self._gql(mutation, {"input": kwargs})
        if err:
            print(f"    ERROR indicator '{kwargs.get('name')}': {err}")
            self.errors += 1
            return
        r = data["indicatorAdd"]
        self.ids[key] = r["id"]
        print(f"    + Indicator: {r['name']}")
        self.created += 1

    def _create_relationship(self, from_key: str, rel_type: str, to_key: str,
                             description: str = ""):
        from_id = self.ids.get(from_key)
        to_id = self.ids.get(to_key)
        if not from_id or not to_id:
            self.skipped += 1
            return
        mutation = """mutation($input: StixCoreRelationshipAddInput!) {
            stixCoreRelationshipAdd(input: $input) { id }
        }"""
        inp = {
            "fromId": from_id,
            "toId": to_id,
            "relationship_type": rel_type,
        }
        if description:
            inp["description"] = description
        data, err = self._gql(mutation, {"input": inp})
        if err:
            print(f"    ERROR rel {from_key} --{rel_type}--> {to_key}: {err}")
            self.errors += 1
            return
        self.created += 1

    # ------------------------------------------------------------------
    # Seed all data
    # ------------------------------------------------------------------

    def seed(self) -> bool:
        """Create all test threat intelligence objects."""

        # ==============================================================
        # 1. Threat Actors (3)
        # ==============================================================
        print("\n[1/5] Creating threat actors ...")
        self._create_threat_actor(
            "ta_apt1",
            name="APT-TEST-1",
            description=(
                "Financially motivated APT group targeting enterprise networks. "
                "Uses custom backdoors, credential theft tools, and "
                "living-off-the-land techniques."
            ),
            threat_actor_types=["crime-syndicate"],
            aliases=["TestBear", "FakeAPT"],
            first_seen="2023-06-01T00:00:00.000Z",
            roles=["agent"],
            sophistication="advanced",
            resource_level="organization",
            primary_motivation="financial-gain",
        )
        self._create_threat_actor(
            "ta_shadow",
            name="ShadowNet Collective",
            description=(
                "State-sponsored espionage group known for Tor-based exfiltration, "
                "DGA malware, and supply-chain attacks against critical infrastructure."
            ),
            threat_actor_types=["nation-state"],
            aliases=["ShadowNet", "DarkRelay"],
            first_seen="2022-03-15T00:00:00.000Z",
            roles=["agent", "infrastructure-operator"],
            sophistication="expert",
            resource_level="government",
            primary_motivation="organizational-gain",
        )
        self._create_threat_actor(
            "ta_ransomcrew",
            name="RansomCrew",
            description=(
                "Ransomware-as-a-service affiliate group. Deploys custom droppers "
                "via phishing, uses credential dumping tools for lateral movement "
                "before encryption."
            ),
            threat_actor_types=["criminal"],
            aliases=["RC-Ops", "CryptLock"],
            first_seen="2023-11-01T00:00:00.000Z",
            roles=["agent"],
            sophistication="intermediate",
            resource_level="organization",
            primary_motivation="financial-gain",
        )

        # ==============================================================
        # 2. Malware (2)
        # ==============================================================
        print("\n[2/5] Creating malware ...")
        self._create_malware(
            "mal_backdoor",
            name="SvcHostUpdate Backdoor",
            description=(
                "Custom backdoor that masquerades as svchost_update.exe. "
                "Provides persistent remote access with encrypted C2 channel."
            ),
            malware_types=["backdoor", "remote-access-trojan"],
            is_family=False,
        )
        self._create_malware(
            "mal_dropper",
            name="InvoiceQ4 Dropper",
            description=(
                "Dropper distributed via phishing emails as invoice_q4.exe. "
                "Downloads and executes the SvcHostUpdate backdoor."
            ),
            malware_types=["dropper"],
            is_family=False,
        )

        # ==============================================================
        # 3. IP Indicators (10) — all source IPs from seed_alerts.py
        #    createObservables=True auto-creates IPv4-Addr observables
        # ==============================================================
        print("\n[3/5] Creating IP indicators ...")
        ip_intel = [
            ("ip_0", "185.220.101.34", "Tor Exit Node - 185.220.101.34",
             "Known Tor exit node used for anonymous exfiltration. Linked to ShadowNet Collective operations.",
             85, "ta_shadow"),
            ("ip_1", "45.155.205.99", "Brute-Force Source - 45.155.205.99",
             "IP observed conducting large-scale SSH and RDP brute-force attacks against enterprise targets.",
             90, "ta_apt1"),
            ("ip_2", "103.75.201.2", "C2 Infrastructure - 103.75.201.2",
             "Command-and-control server hosting APT-TEST-1 implant management panel.",
             95, "ta_apt1"),
            ("ip_3", "198.51.100.23", "Scanning IP - 198.51.100.23",
             "IP performing automated vulnerability scanning and reconnaissance against public-facing web applications.",
             60, "ta_apt1"),
            ("ip_4", "91.240.118.50", "Malware Distribution - 91.240.118.50",
             "Hosting server distributing RansomCrew dropper payloads via HTTP. Active since late 2023.",
             88, "ta_ransomcrew"),
            ("ip_5", "203.0.113.42", "Data Exfil Endpoint - 203.0.113.42",
             "Staging server for exfiltrated data. Receives encrypted archives from compromised hosts via HTTPS.",
             80, "ta_shadow"),
            ("ip_6", "77.247.181.163", "Tor Exit / Proxy - 77.247.181.163",
             "Dual-use Tor exit node and anonymising proxy. Frequently seen in ShadowNet lateral movement traffic.",
             75, "ta_shadow"),
            ("ip_7", "176.10.99.200", "Credential Stuffing Source - 176.10.99.200",
             "IP linked to credential-stuffing campaigns targeting corporate VPN and webmail portals.",
             70, "ta_apt1"),
            ("ip_8", "37.120.198.100", "Primary C2 IP - 37.120.198.100",
             "Primary command-and-control address used by APT-TEST-1 backdoor implants for check-in and task retrieval.",
             95, "ta_apt1"),
            ("ip_9", "94.102.49.190", "Exploit Kit Server - 94.102.49.190",
             "Hosts browser exploit kit used in watering-hole attacks. Delivers initial-access payloads for RansomCrew affiliates.",
             85, "ta_ransomcrew"),
        ]

        for key, value, name, desc, score, actor_key in ip_intel:
            self._create_indicator(
                key,
                name=name,
                description=desc,
                pattern=f"[ipv4-addr:value = '{value}']",
                pattern_type="stix",
                valid_from="2024-01-01T00:00:00.000Z",
                x_opencti_main_observable_type="IPv4-Addr",
                x_opencti_score=score,
                createObservables=True,
            )

        # ==============================================================
        # 3b. Domain Indicators (5) — DGA + phishing from seed_alerts.py
        # ==============================================================
        print("\n[3/5] Creating domain indicators ...")
        domain_intel = [
            ("dom_0", "xkqpt7b2nf.evil.com", "DGA Domain - xkqpt7b2nf.evil.com",
             "Domain-generation-algorithm output linked to ShadowNet DGA malware family. Used for resilient C2 fallback.",
             80, "ta_shadow"),
            ("dom_1", "a8dh3kfm2p.xyz", "DGA Domain - a8dh3kfm2p.xyz",
             "DGA-generated domain registered in bulk. Part of ShadowNet infrastructure rotation.",
             75, "ta_shadow"),
            ("dom_2", "qw9r4t5y6u.top", "DGA Domain - qw9r4t5y6u.top",
             "DGA domain used as backup C2 channel. Rotates every 48 hours.",
             80, "ta_shadow"),
            ("dom_3", "zx3c2v1b0n.info", "DGA Domain - zx3c2v1b0n.info",
             "DGA domain hosting encoded configuration payloads for ShadowNet implants.",
             70, "ta_shadow"),
            ("dom_4", "evil-login.example.com", "Phishing Domain - evil-login.example.com",
             "Credential-harvesting domain impersonating corporate login portal. Used in APT-TEST-1 spearphishing campaigns.",
             90, "ta_apt1"),
        ]

        for key, value, name, desc, score, actor_key in domain_intel:
            self._create_indicator(
                key,
                name=name,
                description=desc,
                pattern=f"[domain-name:value = '{value}']",
                pattern_type="stix",
                valid_from="2024-01-01T00:00:00.000Z",
                x_opencti_main_observable_type="Domain-Name",
                x_opencti_score=score,
                createObservables=True,
            )

        # ==============================================================
        # 3c. File Hash Indicators (3)
        # ==============================================================
        print("\n[3/5] Creating file hash indicators ...")
        hash_intel = [
            ("hash_0",
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "Malware Hash - SvcHostUpdate Backdoor",
             "SHA-256 of the SvcHostUpdate backdoor binary. Deployed by APT-TEST-1 for persistent access.",
             95, "ta_apt1", "mal_backdoor"),
            ("hash_1",
             "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
             "Malware Hash - SvcHostUpdate Variant B",
             "SHA-256 of an updated variant of the SvcHostUpdate backdoor with anti-analysis improvements.",
             90, "ta_apt1", "mal_backdoor"),
            ("hash_2",
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
             "Malware Hash - InvoiceQ4 Dropper",
             "SHA-256 of phishing dropper disguised as a quarterly invoice. Downloads and executes backdoor payload.",
             92, "ta_ransomcrew", "mal_dropper"),
        ]

        for key, sha256, name, desc, score, actor_key, malware_key in hash_intel:
            self._create_indicator(
                key,
                name=name,
                description=desc,
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                valid_from="2024-01-01T00:00:00.000Z",
                x_opencti_main_observable_type="StixFile",
                x_opencti_score=score,
                createObservables=True,
            )

        # ==============================================================
        # 3d. URL Indicator (1)
        # ==============================================================
        print("\n[3/5] Creating URL indicator ...")
        self._create_indicator(
            "url_0",
            name="C2 Callback URL",
            description=(
                "Command-and-control callback URL used by APT-TEST-1 "
                "backdoor for check-in and task retrieval."
            ),
            pattern="[url:value = 'https://evil-login.example.com/api/callback']",
            pattern_type="stix",
            valid_from="2024-01-01T00:00:00.000Z",
            x_opencti_main_observable_type="Url",
            x_opencti_score=90,
            createObservables=True,
        )

        # ==============================================================
        # 4. Relationships
        # ==============================================================
        print("\n[4/5] Creating relationships ...")

        # Indicator → threat actor (indicates)
        for key, _, _, _, _, actor_key in ip_intel:
            self._create_relationship(key, "indicates", actor_key)
        for key, _, _, _, _, actor_key in domain_intel:
            self._create_relationship(key, "indicates", actor_key)
        for key, _, _, _, _, actor_key, _ in hash_intel:
            self._create_relationship(key, "indicates", actor_key)
        self._create_relationship("url_0", "indicates", "ta_apt1")

        # Indicator → malware (indicates)
        for key, _, _, _, _, _, malware_key in hash_intel:
            self._create_relationship(key, "indicates", malware_key)

        # Threat actor → malware (uses)
        self._create_relationship("ta_apt1", "uses", "mal_backdoor",
                                  "APT-TEST-1 deploys SvcHostUpdate backdoor")
        self._create_relationship("ta_ransomcrew", "uses", "mal_dropper",
                                  "RansomCrew distributes InvoiceQ4 dropper")

        # ==============================================================
        # 5. Summary
        # ==============================================================
        print(f"\n[5/5] Done.")
        print(f"  Created: {self.created}")
        print(f"  Errors:  {self.errors}")
        print(f"  Skipped: {self.skipped}")

        return self.errors == 0


def wait_for_opencti(url: str, token: str, retries: int = 30, delay: int = 5) -> bool:
    """Wait for OpenCTI to become ready."""
    graphql_url = f"{url.rstrip('/')}/graphql"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    query = {"query": "{ me { name } }"}

    for i in range(retries):
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(graphql_url, json=query, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if "data" in data and data["data"].get("me"):
                    print(f"OpenCTI is ready. Logged in as: {data['data']['me']['name']}")
                    return True
        except (httpx.ConnectError, httpx.ReadError, httpx.TimeoutException):
            pass
        print(f"  Waiting for OpenCTI... ({i + 1}/{retries})")
        time.sleep(delay)

    print("ERROR: OpenCTI did not become ready.")
    return False


def main():
    parser = argparse.ArgumentParser(description="Seed OpenCTI with test threat intel data")
    parser.add_argument("--url", default=OPENCTI_URL, help=f"OpenCTI URL (default: {OPENCTI_URL})")
    parser.add_argument("--token", default=OPENCTI_TOKEN, help="API token")
    parser.add_argument("--no-wait", action="store_true", help="Skip waiting for OpenCTI readiness")
    args = parser.parse_args()

    if not args.no_wait:
        if not wait_for_opencti(args.url, args.token):
            sys.exit(1)

    seeder = OpenCTISeeder(args.url, args.token)
    if seeder.seed():
        print("\nSeed data created successfully.")
    else:
        print("\nSeed completed with errors (see above).")
        sys.exit(1)


if __name__ == "__main__":
    main()
