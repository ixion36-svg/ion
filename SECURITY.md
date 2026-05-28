<!-- ion-doc:type=SECURITY -->
<!-- ion-doc:title=ION Security Policy -->
<!-- ion-doc:subtitle=Vulnerability reporting and supported versions -->
<!-- ion-doc:version=0.30.0 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Security researchers, customer security teams, anyone reporting a vulnerability -->
<!-- ion-doc:date=2026-05-13 -->

# Security Policy

ION (Intelligent Operating Network) is a Security Operations Portal shipped primarily to air-gapped and siloed environments. Vulnerability disclosure has to land in private channels — disclosing in a public issue tracker risks burning an unpatched deployment.

If you have found a security issue in ION, thank you. This document is how to report it.

## Reporting a vulnerability

Two channels are accepted; pick whichever you can use:

### Preferred — GitHub Security Advisory

Open a **private** advisory via the repository's **Security** tab → **Report a vulnerability**. GitHub routes the advisory directly to the maintainers and gives us a private space to triage, agree a fix, and coordinate the disclosure window.

If the GitHub Security Advisory form is unavailable, open a **GitHub issue** with the title `[SECURITY] <brief description>` — do not include reproducer details in the public issue body. The maintainer will open a private advisory and link it.

### What to include

- ION version (`/health/deep` exposes the running version, or read `pyproject.toml`)
- Deployment shape (Docker compose / bare-metal / air-gapped / internet-reachable)
- A minimal proof-of-concept or reproducer
- Your preferred attribution (named credit, handle, or anonymous)

### Please do NOT

- Open a public GitHub issue describing the vulnerability before we've coordinated a fix.
- Post to social media, mailing lists, or chat channels.
- Probe production deployments belonging to customers without their explicit consent — ION is operated by SOCs and probing them looks indistinguishable from an attack.

## Supported versions

ION uses semantic-ish versioning (`MAJOR.MINOR.PATCH`). The **latest minor on `main`** receives security patches. Older minors are not back-ported; operators are expected to roll forward.

| Version | Status |
|---|---|
| `0.30.x` (current) | Security patches |
| `0.29.x` and earlier | No back-ports — please upgrade |

Air-gapped operators who cannot upgrade promptly should contact the maintainer for guidance — depending on the severity, an out-of-band PATCH on an older minor may be issued by exception.

## Disclosure timeline

Once a report is acknowledged, the working timeline is:

| Step | Target |
|---|---|
| Acknowledgement of receipt | within **72 hours** |
| Triage + severity assignment | within **7 days** |
| Initial fix or mitigation guidance | per severity SLA — Critical 72 h, High 14 d, Medium next MINOR, Low opportunistic |
| Coordinated public disclosure | by mutual agreement, typically 30–90 days after a fix is available |

Severity tiers and SLAs are defined in `docs/DEVELOPMENT_LIFECYCLE.md` §3.5.4.

If you have not had a response within the acknowledgement window, please assume the report has been lost and re-send, or escalate via the alternative channel.

## What happens after a fix lands

- The fix lands in a PATCH (e.g. `v0.30.1`) and the release notes call out the vulnerability class and CVE (if assigned).
- `SECURITY_ASSESSMENT.md` is updated with a new severity-table column for the patched release and a "Net-New Surfaces / Closed Findings" entry.
- Reporters receive named credit unless they request otherwise.

## Scope

In scope:

- ION itself (this repository, this image)
- The deployment patterns documented in `docs/DEPLOYMENT.md` and the shipped `docker-compose*.yml` files
- Integration glue code for the upstream integrations declared in `docs/STACK.md`

Out of scope:

- Vulnerabilities in upstream dependencies — report those to their respective projects (Elastic, Kibana, Keycloak, Ollama, Arkime, OpenCTI, TIDE, etc.). ION's stance is documented in `docs/VULN_MGMT.md`.
- Customer-specific deployment misconfiguration (e.g. defaults overridden in a way that weakens the security posture). Those are operator issues; we will still triage to confirm they aren't symptoms of a default-config bug.

## Acknowledgements

A list of researchers who have contributed responsibly disclosed reports will be maintained here as reports land.

(Empty at v0.30.0 — first to file gets the first credit.)
