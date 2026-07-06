"""v0.49.4 — network-correlation report must render SQLEnum columns as their
lowercase *value*, not ``ClassName.MEMBER``.

Regression: ``Observable.type`` / ``threat_level`` and ``AlertCase.status`` are
``SQLEnum(native_enum=False)`` columns, so on read they come back as enum
members. The report used raw ``str()``, which yields ``"ObservableType.IPV4"`` /
``"ThreatLevel.HIGH"``. That broke the ``_NET_TYPES`` membership test, so
``net_obs`` matched nothing — every network case was silently dropped (or, for
netmon cases, listed with zero observables and an empty IOC/actor rollup).

These tests would have failed before the fix and pass after.
"""

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.observable import (
    Observable,
    ObservableLink,
    ObservableLinkType,
    ObservableType,
    ThreatLevel,
)
from ion.services.network_correlation_report_service import (
    _enum_val,
    generate_network_correlation_report,
)


def test_enum_val_renders_value_not_member_name():
    # The core helper: enum member -> its value; plain string / None tolerated.
    assert _enum_val(ThreatLevel.HIGH) == "high"
    assert _enum_val(ObservableType.IPV4) == "ipv4"
    assert _enum_val(AlertCaseStatus.OPEN) == "open"
    assert _enum_val("already-a-string") == "already-a-string"
    assert _enum_val(None, "unknown") == "unknown"
    assert _enum_val("", "unknown") == "unknown"


def _seed_network_case(session):
    case = AlertCase(
        case_number="CASE-0001", title="beacon to 45.77.1.1", description="d",
        status=AlertCaseStatus.OPEN, severity="high", created_by_id=1,
    )
    obs = Observable(
        type=ObservableType.IPV4, value="45.77.1.1", normalized_value="45.77.1.1",
        threat_level=ThreatLevel.HIGH,
    )
    session.add_all([case, obs])
    session.flush()
    session.add(ObservableLink(
        observable_id=obs.id, link_type=ObservableLinkType.CASE,
        entity_id=case.id, context="test",
    ))
    session.commit()
    return case, obs


def test_network_case_is_not_silently_dropped(session):
    # Pre-fix: net_obs was empty (type stringified to "observabletype.ipv4",
    # never in _NET_TYPES), so this non-netmon network case was skipped and
    # network_cases == 0.
    _seed_network_case(session)
    report = generate_network_correlation_report(session, days=7)
    assert report["summary"]["network_cases"] == 1
    assert report["summary"]["iocs"] == 1


def test_observable_and_status_render_as_values(session):
    _seed_network_case(session)
    report = generate_network_correlation_report(session, days=7)
    case = report["cases"][0]
    assert case["status"] == "open"           # not "AlertCaseStatus.OPEN"
    assert case["severity"] == "high"         # plain-string column, unchanged
    entry = case["observables"][0]
    assert entry["type"] == "ipv4"            # not "ObservableType.IPV4"
    assert entry["threat_level"] == "high"    # not "ThreatLevel.HIGH"
    # cross-case IOC rollup carries the value form too
    assert report["iocs"][0]["type"] == "ipv4"


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
