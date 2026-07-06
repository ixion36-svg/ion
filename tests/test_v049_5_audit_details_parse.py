"""v0.49.5 — /api/audit-logs must not 500 on legacy plain-string details.

`audit_logs.details` is usually a JSON object, but historical producers stored
bare strings (e.g. "203.0.113.0/24", "es_alert_id=synthetic-1", "deleted entry
2"). The endpoint called `json.loads(details)` unconditionally inside a list
comprehension, so a single non-JSON row raised JSONDecodeError and 500'd the
WHOLE audit-log page ("Error loading audit logs"). `_parse_audit_details` now
falls back to the raw string.
"""

from ion.web.api import _parse_audit_details


def test_none_and_empty():
    assert _parse_audit_details(None) is None
    assert _parse_audit_details("") is None


def test_valid_json_object_is_parsed():
    assert _parse_audit_details('{"ip_address": "127.0.0.1"}') == {"ip_address": "127.0.0.1"}
    assert _parse_audit_details('{"expired_sessions_cleaned": 1}') == {"expired_sessions_cleaned": 1}


def test_legacy_plain_strings_fall_back_to_raw():
    # These are the exact shapes that were 500ing the endpoint.
    for raw in ("203.0.113.0/24", "10.0.0.0/8", "es_alert_id=synthetic-1", "deleted entry 2"):
        assert _parse_audit_details(raw) == raw


def test_json_scalar_still_parses():
    # A bare JSON number/string is valid JSON and round-trips as its value.
    assert _parse_audit_details("42") == 42
    assert _parse_audit_details('"quoted"') == "quoted"


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
