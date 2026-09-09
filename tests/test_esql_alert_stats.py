"""ES|QL support in ElasticsearchService — the /_query response parser.

The live get_alert_stats ES|QL path was verified against Elasticsearch 9.4.4
(total + by_severity + by_status match the DSL shape); here we lock the pure
column/value → dict parser that path depends on.
"""

from ion.services.elasticsearch_service import ElasticsearchService


def test_esql_rows_zips_columns_and_values():
    result = {
        "columns": [
            {"name": "count", "type": "long"},
            {"name": "kibana.alert.severity", "type": "keyword"},
        ],
        "values": [[3, "high"], [1, "low"], [2, None]],
    }
    assert ElasticsearchService._esql_rows(result) == [
        {"count": 3, "kibana.alert.severity": "high"},
        {"count": 1, "kibana.alert.severity": "low"},
        {"count": 2, "kibana.alert.severity": None},  # null grouping key preserved
    ]


def test_esql_rows_empty():
    assert ElasticsearchService._esql_rows({}) == []
    assert ElasticsearchService._esql_rows({"columns": [{"name": "c"}], "values": []}) == []
