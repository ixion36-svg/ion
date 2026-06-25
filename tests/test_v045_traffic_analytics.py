"""v0.45.0 — Arkime Traffic Analytics improvements.

Covers the pure/cheap units of the geo fix, the IP/subnet exclusion filter,
the realtime-monitor severity mapping, and a smoke of the network-correlation
report against an empty DB (validates the query path compiles vs the schema).
"""

from ion.services.arkime_service import ArkimeService


# ── #2 geo extractor: tolerant of every Arkime field shape ───────────────


def test_geo_code_reads_flat_srcgeo():
    assert ArkimeService._geo_code({"srcGEO": "us"}, "src") == "US"
    assert ArkimeService._geo_code({"dstGEO": "DE"}, "dst") == "DE"


def test_geo_code_reads_flat_country_dotted():
    # The shape the user's Arkime actually returns.
    assert ArkimeService._geo_code({"country.src": "gb"}, "src") == "GB"
    assert ArkimeService._geo_code({"country.dst": "cn"}, "dst") == "CN"


def test_geo_code_reads_nested_country_object():
    assert ArkimeService._geo_code({"country": {"src": "fr", "dst": "jp"}}, "src") == "FR"
    assert ArkimeService._geo_code({"country": {"src": "fr", "dst": "jp"}}, "dst") == "JP"


def test_geo_code_handles_list_values_and_missing():
    assert ArkimeService._geo_code({"srcGEO": ["ru", "us"]}, "src") == "RU"
    assert ArkimeService._geo_code({}, "src") == ""
    assert ArkimeService._geo_code({"srcGEO": ""}, "src") == ""


# ── #1 exclusion expression builder ──────────────────────────────────────


def test_exclusion_expression_valid_only():
    expr = ArkimeService.build_exclusion_expression(["10.0.0.0/8", "1.2.3.4", "not-an-ip", ""])
    assert expr == "(ip != 10.0.0.0/8 && ip != 1.2.3.4)"


def test_exclusion_expression_empty():
    assert ArkimeService.build_exclusion_expression([]) == ""
    assert ArkimeService.build_exclusion_expression(["garbage"]) == ""


# ── #5 realtime monitor severity mapping ─────────────────────────────────


def test_rtmon_severity_mapping():
    from ion.services.arkime_realtime_monitor_service import _severity_for
    assert _severity_for("critical") == "critical"
    assert _severity_for("high") == "high"
    assert _severity_for("low") == "medium"
    assert _severity_for("") == "medium"


# ── #3 trend delta helper ────────────────────────────────────────────────


def test_trend_pct_delta():
    from ion.web.arkime_traffic_analytics_api import _pct
    assert _pct(150, 100) == 50.0
    assert _pct(50, 100) == -50.0
    assert _pct(10, 0) is None  # no prior baseline


# ── #4 correlation report: empty-DB smoke (query path compiles) ──────────


def test_correlation_report_empty_db(session):
    from ion.services.network_correlation_report_service import (
        generate_network_correlation_html,
        generate_network_correlation_report,
    )
    report = generate_network_correlation_report(session, days=7)
    assert report["summary"]["network_cases"] == 0
    assert report["cases"] == []
    assert report["threat_actors"] == []
    # HTML renders without error and is self-contained.
    html = generate_network_correlation_html(report)
    assert "Network Threat Correlation Report" in html
    assert "<!DOCTYPE html>" in html
