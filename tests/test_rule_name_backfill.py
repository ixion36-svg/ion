"""Triage rows saved without a rule name get it from Elasticsearch.

The defect this guards: Detection Health buckets an alert as ``(unmapped)``
although Elasticsearch knows which rule fired it, because the path that
created the triage row had only the alert id.
"""

import asyncio
from types import SimpleNamespace

from ion.models.alert_triage import AlertTriage
from ion.services.detection_health_service import get_detection_health
from ion.services.rule_name_backfill_service import fill_missing_rule_names


class FakeElasticsearch:
    def __init__(self, names):
        self.names = names
        self.asked = []

    async def get_alerts_by_ids(self, alert_ids, index=None):
        self.asked.append(list(alert_ids))
        return [
            SimpleNamespace(id=i, rule_name=self.names[i])
            for i in alert_ids
            if i in self.names
        ]


def _names(session):
    return {t.es_alert_id: t.rule_name for t in session.query(AlertTriage).all()}


def test_rows_without_a_name_take_the_one_elasticsearch_holds(session):
    session.add_all([
        AlertTriage(es_alert_id="a1"),
        AlertTriage(es_alert_id="a2", rule_name=""),
        AlertTriage(es_alert_id="a3", rule_name="Kept As Saved"),
    ])
    session.commit()
    es = FakeElasticsearch({"a1": "Brute Force", "a2": "Lateral Movement", "a3": "Renamed"})

    filled = asyncio.run(fill_missing_rule_names(session, es))

    assert filled == 2
    assert _names(session) == {
        "a1": "Brute Force",
        "a2": "Lateral Movement",
        "a3": "Kept As Saved",
    }


def test_every_batch_is_reached_when_the_newest_rows_cannot_be_named(session):
    session.add_all([AlertTriage(es_alert_id=f"old-{i}") for i in range(3)])
    session.add_all([AlertTriage(es_alert_id=f"gone-{i}") for i in range(4)])
    session.commit()
    es = FakeElasticsearch({f"old-{i}": "Old Rule" for i in range(3)})

    filled = asyncio.run(fill_missing_rule_names(session, es, batch=2))

    assert filled == 3
    names = _names(session)
    assert [names[f"old-{i}"] for i in range(3)] == ["Old Rule"] * 3
    assert [names[f"gone-{i}"] for i in range(4)] == [None] * 4


def test_arkime_markers_are_never_sent_to_elasticsearch(session):
    session.add_all([
        AlertTriage(es_alert_id="retention:33", source_system="arkime-retention"),
        AlertTriage(es_alert_id="a1", source_system="kibana"),
    ])
    session.commit()
    es = FakeElasticsearch({"a1": "Brute Force"})

    asyncio.run(fill_missing_rule_names(session, es))

    assert es.asked == [["a1"]]


def test_a_named_alert_leaves_the_unmapped_bucket(session):
    from ion.models.ai_feedback import AIFeedback

    session.add(AlertTriage(es_alert_id="a1"))
    session.add(AIFeedback(alert_id="a1", human_verdict="false_positive"))
    session.commit()
    before = {r["rule_name"] for r in get_detection_health(session, days=365)["rules"]}

    asyncio.run(fill_missing_rule_names(session, FakeElasticsearch({"a1": "Brute Force"})))

    after = {r["rule_name"] for r in get_detection_health(session, days=365)["rules"]}
    assert before == {"(unmapped)"}
    assert after == {"Brute Force"}
