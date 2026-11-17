"""Triage rows take their rule's name, id and uuid from Elasticsearch.

The defects this guards: Detection Health buckets an alert as ``(unmapped)``
although Elasticsearch knows which rule fired it, and rule outcomes leave ION
without the rule id TIDE joins on, because the path that created the triage row
had only the alert id.
"""

import asyncio
from types import SimpleNamespace

import pytest

from ion.models.alert_triage import AlertTriage
from ion.services.detection_health_service import get_detection_health
from ion.services.elasticsearch_service import ElasticsearchError
from ion.services.rule_identity_backfill_service import fill_rule_identity


class FakeElasticsearch:
    """Holds alerts by id. ``down`` makes every search fail, as an outage does."""

    def __init__(self, alerts, down=False):
        self.alerts = alerts
        self.down = down
        self.asked = []

    async def find_alerts_by_ids(self, alert_ids, index=None):
        self.asked.append(list(alert_ids))
        if self.down:
            raise ElasticsearchError("connection refused")
        return [SimpleNamespace(id=i, **self.alerts[i]) for i in alert_ids if i in self.alerts]


def _alert(name=None, rule_id=None, uuid=None):
    return {"rule_name": name, "rule_id": rule_id, "rule_uuid": uuid}


def _rows(session):
    session.expire_all()
    return {t.es_alert_id: t for t in session.query(AlertTriage).all()}


def test_rows_take_name_id_and_uuid_and_keep_what_they_had(session):
    session.add_all([
        AlertTriage(es_alert_id="a1"),
        AlertTriage(es_alert_id="a2", rule_name="Kept As Saved"),
    ])
    session.commit()
    es = FakeElasticsearch({
        "a1": _alert("Brute Force", "r-bf", "u-1"),
        "a2": _alert("Renamed", "r-lm", "u-2"),
    })

    filled = asyncio.run(fill_rule_identity(session, es))

    rows = _rows(session)
    assert filled == 2
    assert (rows["a1"].rule_name, rows["a1"].rule_id, rows["a1"].rule_uuid) == ("Brute Force", "r-bf", "u-1")
    assert (rows["a2"].rule_name, rows["a2"].rule_id) == ("Kept As Saved", "r-lm")


def test_a_second_run_changes_nothing_and_asks_nothing(session):
    session.add_all([AlertTriage(es_alert_id="a1"), AlertTriage(es_alert_id="gone")])
    session.commit()
    es = FakeElasticsearch({"a1": _alert("Brute Force", "r-bf")})
    asyncio.run(fill_rule_identity(session, es))
    first = {k: (r.rule_name, r.rule_id, r.rule_identity_checked_at) for k, r in _rows(session).items()}

    again = FakeElasticsearch({"a1": _alert("Other", "r-other"), "gone": _alert("Late", "r-late")})
    assert asyncio.run(fill_rule_identity(session, again)) == 0

    assert again.asked == []
    assert {k: (r.rule_name, r.rule_id, r.rule_identity_checked_at) for k, r in _rows(session).items()} == first


def test_a_missing_alert_leaves_null_and_is_not_asked_again(session):
    session.add(AlertTriage(es_alert_id="gone", rule_name="Old Rule"))
    session.commit()

    asyncio.run(fill_rule_identity(session, FakeElasticsearch({})))

    row = _rows(session)["gone"]
    assert row.rule_id is None and row.rule_uuid is None
    assert row.rule_identity_checked_at is not None


def test_an_outage_marks_nothing_and_the_next_run_resumes(session):
    session.add_all([AlertTriage(es_alert_id=f"a{i}") for i in range(5)])
    session.commit()
    alerts = {f"a{i}": _alert(f"Rule {i}", f"r-{i}") for i in range(5)}

    with pytest.raises(ElasticsearchError):
        asyncio.run(fill_rule_identity(session, FakeElasticsearch(alerts, down=True), batch=2))
    assert all(r.rule_identity_checked_at is None for r in _rows(session).values())

    assert asyncio.run(fill_rule_identity(session, FakeElasticsearch(alerts), batch=2)) == 5
    assert {k: r.rule_id for k, r in _rows(session).items()} == {f"a{i}": f"r-{i}" for i in range(5)}


def test_an_interrupted_run_keeps_the_batches_it_committed(session):
    session.add_all([AlertTriage(es_alert_id=f"a{i}") for i in range(4)])
    session.commit()
    alerts = {f"a{i}": _alert(f"Rule {i}", f"r-{i}") for i in range(4)}

    class FailsSecondBatch(FakeElasticsearch):
        async def find_alerts_by_ids(self, alert_ids, index=None):
            if self.asked:
                self.down = True
            return await super().find_alerts_by_ids(alert_ids, index)

    with pytest.raises(ElasticsearchError):
        asyncio.run(fill_rule_identity(session, FailsSecondBatch(alerts), batch=2))
    assert sum(r.rule_id is not None for r in _rows(session).values()) == 2

    resumed = FakeElasticsearch(alerts)
    asyncio.run(fill_rule_identity(session, resumed, batch=2))
    assert sum(len(ids) for ids in resumed.asked) == 2
    assert all(r.rule_id for r in _rows(session).values())


def test_arkime_markers_are_never_sent_to_elasticsearch(session):
    session.add_all([
        AlertTriage(es_alert_id="retention:33", source_system="arkime-retention"),
        AlertTriage(es_alert_id="a1", source_system="kibana"),
    ])
    session.commit()
    es = FakeElasticsearch({"a1": _alert("Brute Force", "r-bf")})

    asyncio.run(fill_rule_identity(session, es))

    assert es.asked == [["a1"]]


def test_a_named_alert_leaves_the_unmapped_bucket(session):
    session.add(AlertTriage(es_alert_id="a1"))
    session.commit()
    before = {r["rule_name"] for r in get_detection_health(session, days=365)["rules"]}

    asyncio.run(fill_rule_identity(session, FakeElasticsearch({"a1": _alert("Brute Force", "r-bf")})))

    after = {r["rule_name"] for r in get_detection_health(session, days=365)["rules"]}
    assert before == {"(unmapped)"}
    assert after == {"Brute Force"}


def test_a_value_longer_than_the_column_is_cut_to_fit(session):
    session.add(AlertTriage(es_alert_id="a1"))
    session.commit()

    asyncio.run(fill_rule_identity(session, FakeElasticsearch({"a1": _alert("R" * 900, "i" * 400)})))

    row = _rows(session)["a1"]
    assert row.rule_name == "R" * 500 and row.rule_id == "i" * 255


def test_the_alert_parser_reads_kibana_signal_and_wazuh_ids():
    from ion.services.elasticsearch_service import ElasticsearchService

    parse = ElasticsearchService._parse_alert.__get__(ElasticsearchService.__new__(ElasticsearchService))
    kibana = parse("k", {"kibana.alert.rule.rule_id": "rid-1", "kibana.alert.rule.uuid": "uuid-1",
                         "kibana.alert.rule.name": "K"})
    signal = parse("s", {"signal": {"rule": {"rule_id": "rid-2", "id": "uuid-2", "name": "S"}}})
    wazuh = parse("w", {"rule": {"id": 5710, "description": "sshd", "name": "W"}})

    assert (kibana.rule_id, kibana.rule_uuid) == ("rid-1", "uuid-1")
    assert (signal.rule_id, signal.rule_uuid) == ("rid-2", "uuid-2")
    assert (wazuh.rule_id, wazuh.rule_uuid) == ("5710", None)
