"""Tests for mitre_navigator_service — technique tagging and Navigator layers.

This module was at 0% when the coverage ratchet first measured the tree.
`tag_alert` is the canonical way the autonomous investigation loop attaches
MITRE techniques to an alert when the detection engine has not done the
mapping upstream, so a miss here is an alert that quietly loses its ATT&CK
context — not an error anyone sees.

The field list it scans is curated on purpose. Tests pin both halves of that:
the shapes it must find a technique in, and the fact that it does not go
hunting through arbitrary other keys.
"""

from __future__ import annotations

import pytest

from ion.services import mitre_navigator_service as svc


class TestTagAlert:
    @pytest.mark.parametrize("alert", [None, {}, [], "not a dict", 0])
    def test_junk_input_returns_no_techniques(self, alert):
        assert svc.tag_alert(alert) == []

    def test_a_plain_technique_id_is_found(self):
        assert svc.tag_alert({"rule.name": "T1059 execution"}) == ["T1059"]

    def test_a_sub_technique_keeps_its_suffix(self):
        """T1059.001 must not be truncated to its parent."""
        assert svc.tag_alert({"rule.name": "see T1059.001"}) == ["T1059.001"]

    def test_lowercase_ids_are_normalised(self):
        assert svc.tag_alert({"rule.name": "t1059"}) == ["T1059"]

    def test_results_are_deduped_and_sorted(self):
        alert = {"rule.name": "T1078 and T1059", "rule.description": "T1059 again"}
        assert svc.tag_alert(alert) == ["T1059", "T1078"]

    def test_a_nested_rule_object_is_walked(self):
        """Events arrive both flattened and nested; both must work."""
        assert svc.tag_alert({"rule": {"name": "T1021 remote services"}}) == ["T1021"]

    def test_a_flattened_dotted_key_is_read_directly(self):
        assert svc.tag_alert({"kibana.alert.rule.name": "T1486"}) == ["T1486"]

    def test_a_list_of_tags_is_searched(self):
        assert svc.tag_alert({"tags": ["persistence", "T1547.001"]}) == ["T1547.001"]

    def test_deeply_nested_structures_are_searched(self):
        alert = {"signal": {"rule": {"threat": [{"technique": {"id": "T1566"}}]}}}
        assert svc.tag_alert(alert) == ["T1566"]

    def test_fields_outside_the_curated_set_are_ignored(self):
        """Scanning everything would tag alerts off stray prose."""
        assert svc.tag_alert({"some_other_field": "T1059"}) == []

    def test_an_alert_with_no_technique_tags_cleanly(self):
        assert svc.tag_alert({"rule.name": "Suspicious logon"}) == []

    @pytest.mark.parametrize("text", ["T123", "T12345", "TT1059", "1059"])
    def test_near_misses_are_not_treated_as_techniques(self, text):
        assert svc.tag_alert({"rule.name": text}) == []

    def test_several_curated_fields_contribute_together(self):
        alert = {
            "rule.name": "T1059",
            "threat.technique.id": "T1078",
            "message": "also T1021.002",
        }
        assert svc.tag_alert(alert) == ["T1021.002", "T1059", "T1078"]

    def test_a_null_field_is_skipped(self):
        assert svc.tag_alert({"rule.name": None, "message": "T1059"}) == ["T1059"]


class TestCoverageColour:
    @pytest.mark.parametrize("count,colour", [
        (0, "#f85149"),   # red, no coverage
        (1, "#d29922"),   # amber, partial
        (3, "#d29922"),
        (4, "#3fb950"),   # green, good
        (99, "#3fb950"),
    ])
    def test_the_bands_at_their_boundaries(self, count, colour):
        assert svc._coverage_color(count) == colour

    def test_the_legend_lists_exactly_the_three_band_colours(self):
        layer = svc.generate_navigator_layer(_Tide({"techniques": {}}))
        legend = {item["color"] for item in layer["legendItems"]}
        assert legend == {"#f85149", "#d29922", "#3fb950"}


class _Tide:
    def __init__(self, coverage=None, raises=False):
        self._coverage, self._raises = coverage, raises

    def get_global_mitre_coverage(self):
        if self._raises:
            raise RuntimeError("TIDE unreachable")
        return self._coverage


class TestNavigatorLayer:
    def test_a_tide_failure_still_produces_a_valid_empty_layer(self):
        """The UI loads the layer regardless; it must not be handed a crash."""
        layer = svc.generate_navigator_layer(_Tide(raises=True))

        assert layer["techniques"] == []
        assert layer["domain"] == "enterprise-attack"
        assert "0/0 techniques covered" in layer["description"]

    def test_no_coverage_data_is_treated_the_same(self):
        assert svc.generate_navigator_layer(_Tide(None))["techniques"] == []

    def test_each_technique_becomes_a_navigator_entry(self):
        tide = _Tide({
            "techniques": {
                "T1059": {"rule_count": 5, "avg_quality": 32.5, "enabled_rules": 4},
            },
            "total_techniques": 10,
            "covered_techniques": 1,
        })

        entry = svc.generate_navigator_layer(tide)["techniques"][0]

        assert entry["techniqueID"] == "T1059"
        assert entry["score"] == 5
        assert entry["color"] == "#3fb950"
        assert entry["enabled"] is True
        assert "5 rules, avg quality: 32.5" in entry["comment"]

    def test_metadata_carries_rules_enabled_and_quality(self):
        tide = _Tide({"techniques": {
            "T1059": {"rule_count": 5, "avg_quality": 32.5, "enabled_rules": 4},
        }})

        meta = svc.generate_navigator_layer(tide)["techniques"][0]["metadata"]

        assert {m["name"] for m in meta} == {"Rules", "Enabled", "Quality"}
        assert {m["name"]: m["value"] for m in meta}["Enabled"] == "4"

    def test_missing_per_technique_fields_default_to_zero(self):
        """A sparse TIDE row must not break the layer."""
        layer = svc.generate_navigator_layer(_Tide({"techniques": {"T1059": {}}}))

        entry = layer["techniques"][0]
        assert entry["score"] == 0
        assert entry["color"] == "#f85149"

    def test_the_description_reports_the_coverage_ratio(self):
        tide = _Tide({"techniques": {}, "total_techniques": 200,
                      "covered_techniques": 47})
        assert "47/200 techniques covered" in \
            svc.generate_navigator_layer(tide)["description"]

    def test_the_layer_name_is_configurable(self):
        layer = svc.generate_navigator_layer(_Tide({"techniques": {}}),
                                             layer_name="Q3 review")
        assert layer["name"] == "Q3 review"

    def test_the_schema_version_block_is_present(self):
        """Navigator refuses a layer whose version block it does not recognise."""
        versions = svc.generate_navigator_layer(_Tide({"techniques": {}}))["versions"]
        assert versions == {"attack": "14", "navigator": "4.9.1", "layer": "4.5"}

    def test_every_technique_in_the_map_is_represented(self):
        tide = _Tide({"techniques": {
            "T1059": {"rule_count": 1}, "T1078": {"rule_count": 0},
            "T1021": {"rule_count": 9},
        }})

        layer = svc.generate_navigator_layer(tide)

        assert {t["techniqueID"] for t in layer["techniques"]} == {
            "T1059", "T1078", "T1021",
        }


class TestWalkerEdges:
    def test_a_null_inside_a_list_is_stepped_over(self):
        """Real events carry nulls in tag arrays; one must not stop the scan."""
        assert svc.tag_alert({"tags": [None, "T1059", None]}) == ["T1059"]

    def test_a_null_inside_a_nested_object_is_stepped_over(self):
        alert = {"rule": {"name": None, "description": "T1078"}}
        assert svc.tag_alert(alert) == ["T1078"]

    def test_non_string_scalars_are_ignored(self):
        assert svc.tag_alert({"tags": [1, 2.5, True, "T1059"]}) == ["T1059"]

    def test_dotted_lookup_on_a_non_dict_is_none(self):
        """Guards the walker when a field holds a scalar where an object was expected."""
        assert svc._lookup_dotted("a string", "rule.name") is None
        assert svc._lookup_dotted(None, "rule.name") is None
        assert svc._lookup_dotted(["a", "list"], "rule.name") is None

    def test_a_partial_dotted_path_stops_cleanly(self):
        assert svc._lookup_dotted({"rule": {"other": 1}}, "rule.name") is None
