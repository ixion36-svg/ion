"""EXAMPLE KB module — drop-in template for a Bob-RAG-optimised KB article.

This mirrors the real format used by every module in ``src/ion/data/kb_*.py``:
each KB collection is a ``(collection_name, collection_description, article_source)``
tuple, and ``article_source`` is a callable returning a list of
``(title, tags_list, markdown_content)`` tuples (see
``src/ion/services/kb_seed_service.py`` for the loader).

WHY THIS SHAPE HELPS BOB (vs a generic reference doc):
  * Title is high-signal — it is embedded as ``Title: <name>`` and dominates the
    vector. Make it a specific, alert-like phrase ("Kerberoasting ...", not
    "Kerberos overview").
  * One technique per article — keeps the embedding tight so it surfaces for the
    right alerts (retrieval is cosine >= 0.65, top-3) and fits the 3800-token
    prompt budget without being truncated/dropped.
  * MITRE technique tags (T####/T####.###) are the matching key for
    AlertPromptTemplate AND enrich the embedding. Always tag.
  * The **Triage Decision Guidance** section is the part most reference KB lacks
    and the part Bob needs most: explicit TP signals, benign explanations, and
    escalation criteria so the LLM can reach a defensible verdict.

TO ACTUALLY SEED THIS:
  1. Move this file to ``src/ion/data/kb_examples.py`` (or merge the article into
     an existing kb_*.py module's article list).
  2. In ``src/ion/services/kb_seed_service.py`` add:
         from ion.data.kb_examples import COLLECTIONS as KB_EXAMPLES
     and append ``("Examples", KB_EXAMPLES)`` to ``all_modules``.
  3. Rebuild the image and let the KB-embedding background loop vectorise it,
     OR (fresh DB) it seeds on first startup. Per CLAUDE.md, prefer the
     research-dossier -> seed module -> docker rebuild pattern; do NOT JSON-import.
"""


def kerberoasting_articles():
    """Return example detection+triage articles. One technique per article."""
    articles = []

    articles.append((
        # --- Title: specific, alert-like, high embedding signal ---
        "Kerberoasting: Service-Ticket Requests with RC4 Encryption (T1558.003)",
        # --- Tags: MITRE technique IDs + topical. Drive matching + embedding ---
        ["T1558.003", "kerberoasting", "kerberos", "credential-access",
         "active-directory", "detection", "triage"],
        # --- Markdown body: reference structure + decision guidance ---
        r"""# Kerberoasting: Service-Ticket Requests with RC4 Encryption (T1558.003)

## Overview

Kerberoasting abuses the Kerberos protocol: any authenticated domain user can
request a service ticket (TGS) for any account with a Service Principal Name
(SPN). The ticket is encrypted with the service account's NTLM hash, so an
attacker requests tickets for high-value SPNs, exports them, and cracks them
offline to recover the service account password — with no traffic to the target
service and no elevated privileges required up front.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access |

## Detection Signal

| Data Source | Event | Key Fields |
|---|---|---|
| Windows Security (DC) | 4769 — Kerberos service ticket requested | TicketEncryptionType, ServiceName, TargetUserName, IpAddress |

The hallmark is **4769 with `TicketEncryptionType = 0x17` (RC4-HMAC)** — modern
AD defaults to AES (0x12), so RC4 requests for SPN accounts are anomalous —
especially many distinct SPNs requested by one user in a short window.

## Detection Query (Elastic / KQL)

```kql
event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"
and not winlog.event_data.ServiceName: "krbtgt"
```
Aggregate by `winlog.event_data.TargetUserName` (requesting user); alert when one
principal requests RC4 tickets for many distinct SPNs in < 5 minutes.

## Triage Decision Guidance  <!-- the section Bob needs to reach a verdict -->

**Likely TRUE POSITIVE when:**
- One user requests RC4 service tickets for many distinct SPNs rapidly (scripted).
- The requesting account is a normal user but the SPNs are high-value (SQL, svc_*).
- Source host is a workstation, not a server that legitimately brokers tickets.
- Correlates with prior recon (BloodHound/LDAP enumeration) from the same host.

**Likely BENIGN / FALSE POSITIVE when:**
- A single RC4 request from a legacy app or appliance that only speaks RC4.
- The SPN belongs to a service the user legitimately consumes (e.g. their own app).
- A known vulnerability scanner / AD hygiene tool on its allow-list runs it.

**Escalate (raise severity) when:**
- The cracked-account risk is high (Domain Admin SPN, unconstrained delegation).
- Followed by an interactive logon (4624 type 2/10) as the SPN account.

## Recommended Response

1. Identify the requesting principal and source host; confirm intent with the owner.
2. Rotate the targeted service account password (long, random) and move it to a
   gMSA where possible; force AES.
3. Hunt for offline cracking / subsequent logons as the service account.
""",
    ))

    return articles


# COLLECTIONS registry entry — (collection_name, collection_description, source)
COLLECTIONS = [
    (
        "Examples — Detection & Triage",
        "Example Bob-RAG-optimised articles: one technique each, with explicit "
        "triage decision guidance for AI-assisted closure.",
        kerberoasting_articles,
    ),
]
