<!-- ion-doc:type=VULNERABILITY MANAGEMENT -->
<!-- ion-doc:title=ION Vulnerability Management Process -->
<!-- ion-doc:subtitle=CVE intake, triage, fix-cadence SLAs, disclosure policy — standalone process doc -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Customer security, ITHC supplier, customer DA, SRO -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Purpose

This document is the standalone vulnerability management process for ION. It covers:

- **Intake**: how vulnerabilities reach the maintainer
- **Triage**: how they are scored, prioritised, and ION-specifically assessed
- **Resolution**: SLAs for fix shipping
- **Disclosure**: responsible-disclosure policy and customer notification

The same content appears compressed in `_mod_through_life_plan.md`; this doc is the **detailed** reference reviewers ask for as a standalone artefact.

## 1.1 Companions

- `_mod_through_life_plan.md` §3 — patching cadence summary
- `_mod_ion_incident_response.md` — what happens if a vuln becomes an active incident
- `_mod_threat_model.md` — proactive threat model
- `SECURITY_ASSESSMENT.md` — per-release severity trend
- `_mod_exception_register.md` — exception register (including pip-audit deferrals)
- `docs/CRYPTOGRAPHY.md` — crypto-relevant vulnerability surface

# 2. Vulnerability intake channels

Vulnerabilities reach ION through these channels:

| Channel | Cadence | Owner |
|---|---|---|
| **Continuous SCA** (pip-audit + OSV) | Every CI run + nightly | ION maintainer (automated) |
| **SAST** (bandit + ruff) | Every CI run | ION maintainer (automated) |
| **CISA KEV catalogue** | Monitored continuously; bundled snapshot refreshed each release | ION maintainer |
| **NVD / Vendor advisories** | Watched for ION's dependency stack | ION maintainer |
| **Responsible disclosure** (security@ipair address — see §6) | As reports arrive | ION maintainer |
| **Customer ITHC findings** | Per engagement | Customer + ION maintainer |
| **Customer-detected anomaly** (operational discovery) | As discovered | Customer + ION maintainer |

# 3. Triage

## 3.1 Severity scoring

ION uses **CVSS v3.1** as the baseline severity scale, then applies **ION-specific reachability** to derive the operational severity.

| CVSS v3.1 score | Provisional rating |
|---|---|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |

## 3.2 ION-specific reachability assessment

A vulnerability's *provisional* rating is downgraded or upgraded based on **whether it's actually reachable** in ION's deployed configuration:

| Reachability finding | Adjustment |
|---|---|
| The vulnerable code path is reachable from an unauthenticated endpoint | **+1 tier** (Medium → High, etc.) |
| The vulnerable code path is reachable only from an authenticated session | (no change) |
| The vulnerable code path is reachable only from an admin session | **-1 tier** |
| The vulnerable code path is NOT reachable in any current ION code path | **-2 tiers** (often Low → Tracked-only) |
| The vulnerability requires a network position ION's threat model has already excluded | **-1 tier** |
| The vulnerability is in a library version ION does not actually ship | **N/A — not exploitable** |

The reachability finding is documented in `SECURITY_ASSESSMENT.md`'s per-finding entry.

## 3.3 Worked example — python-jose CVE-2024-23342

The python-jose CVE-2024-23342 is rated Medium in NVD. Reachability analysis:

- ION uses python-jose ONLY for OIDC JWT verification
- The CVE concerns ECDSA signature verification
- ION's OIDC configuration whitelists **RS256 only** (`auth/oidc.py` refuses HS256 AND ES256)
- Therefore the vulnerable ECDSA path is NOT reachable in ION

**Adjusted rating: Low (not exploitable in shipped ION configuration).**

**Action:** documented `--ignore-vuln CVE-2024-23342` in pip-audit workflow; queued for PyJWT migration to remove the deprecated python-jose entirely.

**Tracking:** `_mod_exception_register.md` candidate EX-003 (not formally filed; documented in pip-audit workflow comment).

# 4. Fix-cadence SLAs

The customer's expectation of ION patch cadence is documented in `_mod_through_life_plan.md` §3 and re-stated here:

| Severity (adjusted) | SLA for patched image shipped | SLA for customer-side deploy | Disclosure |
|---|---|---|---|
| **Critical** | **24 hours** from intake confirmation | Customer's choice; recommended within 48h of patched image | Coordinated; advisory published with patch |
| **High** | **5 working days** | Within 10 working days | Coordinated; advisory published with patch |
| **Medium** | Next minor release (typically within 4 weeks) | Per customer change cadence | In CHANGELOG + SECURITY_ASSESSMENT |
| **Low** | Backlog; bundled with adjacent work | Per customer change cadence | In CHANGELOG |
| **Tracked-only** (not exploitable) | Tracked in `_mod_exception_register.md`; no specific SLA | n/a | Tracked, not disclosed publicly |

## 4.1 What "patched image shipped" means

A Critical fix at 24h means:

| Time | Action |
|---|---|
| T+0 | Vulnerability confirmed exploitable |
| T+0–T+8 | Maintainer develops + tests fix |
| T+8–T+16 | Patched image built; SBOM regenerated; 8-file release ritual completed |
| T+16–T+24 | Patched image pushed to Docker Hub with bumped version; release-acceptance walk §3.4.8 performed |
| T+24 | Customer-side advisory + image hash made available |

The 24h clock includes the maintainer's time-zone realities — actual elapsed wall-clock may be slightly longer if intake occurs during off-hours.

## 4.2 What "Critical" actually triggers

Past examples (hypothetical, for illustration):

- Auth bypass on `/api/security/login` → Critical (24h)
- Remote code execution via prompt injection bypassing schema → Critical (24h) — but ION's structured-output design bounds this; we have not seen one
- SQL injection on a user-input parameter → Critical (24h) — ION uses parameterised ORM only
- XSS in an analyst-facing template → High (5 days)
- DoS via crafted webhook payload → Medium (next minor)

# 5. Vulnerability lifecycle

Each vulnerability tracked passes through these states:

```
INTAKE → TRIAGE → SCHEDULED → IN-FIX → RELEASED → DEPLOYED → CLOSED
                       ↓
                    EXCEPTION
                       ↓
                    DEFERRED
```

| State | Definition |
|---|---|
| INTAKE | Vulnerability identified; not yet rated |
| TRIAGE | CVSS + reachability adjustment in progress |
| SCHEDULED | Rated; assigned to a release per SLA |
| IN-FIX | Maintainer is actively fixing |
| RELEASED | Patched image published |
| DEPLOYED | Customer has deployed the patched image |
| CLOSED | Verified fixed in production |
| EXCEPTION | Cannot be fixed within SLA; risk-managed via `_mod_exception_register.md` |
| DEFERRED | Tracked-only (not exploitable in shipped configuration) |

# 6. Responsible disclosure

## 6.1 How to report

Security issues should be reported via:

- GitHub security advisory on `ixion36-svg/ion` (preferred — gives a private disclosure channel)
- Email to the security contact in repo's `SECURITY.md`

**Do NOT open a public GitHub issue for an unpatched vulnerability.**

## 6.2 What the reporter receives

| Timeline | Maintainer commitment |
|---|---|
| T+24h | Acknowledgement of receipt |
| T+72h | Initial triage outcome (Critical / High / Medium / Low / not-a-vulnerability) |
| Per SLA | Fix shipped |
| Post-release | Public credit if reporter wishes (CHANGELOG + SECURITY_ASSESSMENT acknowledgement) |

## 6.3 Coordinated disclosure

For Critical and High severities, ION practises **coordinated disclosure**:

- Patch is prepared in private
- Maintainer agrees a disclosure window with the reporter (typically 90 days)
- Patched image released; advisory published on the disclosure date
- Customers receive notification via release channel BEFORE public advisory

# 7. Customer notification

When a patched image is released for a Critical or High severity:

| Channel | Audience | Cadence |
|---|---|---|
| `SECURITY_ASSESSMENT.md` delta section | All customers + reviewers | At release |
| `CHANGELOG.md` entry | All customers + reviewers | At release |
| Per-customer notification (per Tier 2 support model) | Active customer engagements | At release |
| GitHub release notes | Public | At release |

Notification content:

- CVE ID (if assigned)
- Severity (CVSS + ION-adjusted)
- Affected versions
- Patched version
- Mitigation if patch cannot be applied immediately
- Reachability commentary (so customer can decide urgency)

# 8. SBOM cross-reference

For each vulnerability, the maintainer cross-references the SBOM (`/app/sbom.spdx.json` in the image) to confirm the affected component is actually shipped.

Customers can run the same check themselves:

```bash
# Extract SBOM from image
docker run --rm ixion36/ion:0.29.1 cat /app/sbom.spdx.json > sbom-0.29.1.json

# Search for a specific package version
jq '.packages[] | select(.name == "python-jose")' sbom-0.29.1.json
```

This lets the customer verify the maintainer's claim about "we don't ship that version" independently.

# 9. CI-side scanning + gating

ION's CI runs the following on every commit, blocking merge on any new High or Critical:

| Scanner | What it catches | CI behaviour |
|---|---|---|
| `pip-audit` (with OSV) | Python dependency CVEs | Block merge on any new Critical/High; documented exceptions OK |
| `bandit` | Python static security (e.g. assert in security context, hardcoded passwords) | Block merge on any High; Medium informational |
| `ruff` (incl. security-relevant rules) | Style + a subset of security rules (e.g. S-prefix bandit rules) | Block merge on any error |
| `syft` SBOM | Inventory generation only | Always runs; no merge gating; ships in image |

The CI workflow lives at `.github/workflows/test.yml`.

# 10. Sample exception entries

A Critical vulnerability that **cannot** be patched within SLA must be filed as an exception. The template lives in `_mod_exception_register.md` §2. Example shape:

```
### EX-### Short title
Filed: YYYY-MM-DD
MOD requirement: ION shall ship patched image within 24h of Critical confirmed
ION version at filing: vX.Y.Z

Gap statement:
The patched fix requires a breaking API change in <library>. The 24h SLA
cannot be met because of the regression-test surface required.

Residual risk:
Likelihood: Low (not Internet-exposed by deployed configuration)
Impact: Major (data integrity)
Risk rating: Amber

Mitigation:
- WAF rule deployed at customer reverse proxy to block the exploit pattern
- Affected endpoint disabled via feature flag
- Customer monitoring for the exploit pattern in audit log

Hard expiry: <date 14 days hence>
```

# 11. Periodic review

The vulnerability management process is reviewed:

| Review | Cadence | Owner |
|---|---|---|
| SLA performance — did all fixes meet their SLA? | Per release | Maintainer |
| Severity distribution trend | Per release in `SECURITY_ASSESSMENT.md` | Maintainer |
| Exception register review | Per release; close exceptions where possible | Maintainer + customer SRO |
| Customer feedback on patch cadence | Quarterly | Maintainer + customer SDM |
| Annual process audit | Annually | Customer security + ION maintainer |

# 12. Sign-off

- ION maintainer (process owner)
- Customer Security Lead (process acceptance)
- Customer SRO (Acceptance gate)

# 13. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial vulnerability management process authored at v0.29.1 |
