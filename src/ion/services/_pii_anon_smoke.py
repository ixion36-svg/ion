"""Manual smoke test for ``PIIAnonService``.

Not a unit test — run with ``python -m ion.services._pii_anon_smoke`` to
eyeball the tokenisation / detokenisation of a sample SIEM event.
"""

from __future__ import annotations

import json

from ion.services.pii_anon_service import PIIAnonService

SAMPLE_EVENT = {
    "event": {
        "action": "process_started",
        "category": ["process"],
    },
    "host": {
        "name": "WORKSTATION-07",
        "hostname": "WORKSTATION-07",
        "ip": ["10.0.12.45", "8.8.8.8"],  # 8.8.8.8 is public → should NOT tokenise
    },
    "user": {
        "name": "alice.jones",
        "email": "alice.jones@example.com",
    },
    "source": {"ip": "192.168.1.50"},
    "destination": {"ip": "203.0.113.10"},  # public → must stay
    "process": {
        "name": "powershell.exe",  # preserved by whitelist
        "command_line": "powershell.exe -enc ...",  # preserved by whitelist
    },
    "message": (
        "User alice.jones on WORKSTATION-07 (10.0.12.45) launched powershell "
        "contacting 203.0.113.10"
    ),
    "rule": {"id": "ABC-123", "name": "suspicious_powershell"},
}


def main() -> None:
    svc = PIIAnonService(enabled=True)
    if not svc.is_enabled():
        print("Service not enabled or no rules loaded. Aborting.")
        return

    print("── ORIGINAL EVENT ────────────────────────────────────────────")
    print(json.dumps(SAMPLE_EVENT, indent=2, sort_keys=True))

    redacted, mapping = svc.tokenize_event(SAMPLE_EVENT)
    print("\n── TOKENISED EVENT ───────────────────────────────────────────")
    print(json.dumps(redacted, indent=2, sort_keys=True))

    print("\n── TOKEN MAP (forward) ───────────────────────────────────────")
    for original, token in mapping.forward.items():
        print(f"  {original!r:50s} -> {token}")

    fake_llm_output = (
        "IP-0001 was the source of the event attributed to USER-0001. "
        "Investigate HOST-0001 for further compromise. Public peer "
        "203.0.113.10 should also be reviewed."
    )
    print("\n── FAKE LLM OUTPUT (with tokens) ─────────────────────────────")
    print(fake_llm_output)
    print("\n── DETOKENISED OUTPUT ────────────────────────────────────────")
    print(svc.detokenize_text(fake_llm_output, mapping))


if __name__ == "__main__":
    main()
