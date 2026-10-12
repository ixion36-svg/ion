"""TIDE's 4,000-character statement limit, and the silent zero behind it.

TIDE refuses any statement over 4,000 characters (upstream README, alongside
the SELECT/WITH-only rule and the keyword blocklist). `_query` turns that
refusal into None, and every caller reads None as "no rows", so an over-long
query arrives looking exactly like an absence of data.

`get_playbooks_with_kill_chains` built `t.technique_id IN (...)` from every
technique in a playbook, unbounded. Measured against the real query body of
439 characters, that leaves room for about 296 subtechnique ids. Past that the
coverage map came back empty and the page drew every technique as having no
rules: a query too long to send, rendered as a total absence of detection.

The positive control matters here more than usual. A chunking test passes
trivially if the limit is never approached, so `test_the_old_single_statement_
form_really_did_overflow` builds the statement the old code built and asserts
it exceeds the cap. If that test ever fails, the others are measuring nothing.
"""
from __future__ import annotations

from typing import Any, Optional

import pytest

from ion.services.tide_service import (
    _MAX_SQL_CHARS,
    _quoted_id_batches,
    TideService,
)


def _subtechnique_ids(n: int) -> list[str]:
    """Ids shaped like the real ones: 'T1059.001' is 9 chars, 11 once quoted."""
    return [f"T{1000 + i // 20}.{i % 20 + 1:03d}" for i in range(n)]


# The query body get_playbooks_with_kill_chains wraps the id list in.
_PREFIX = (
    "SELECT t.technique_id, "
    "count(DISTINCT dr.rule_id) as rule_count, "
    "count(DISTINCT dr.rule_id) FILTER (WHERE dr.enabled = 1) as enabled_rules "
    "FROM detection_rules dr, "
    "LATERAL unnest(dr.mitre_ids) AS t(technique_id) "
    "WHERE dr.space = 'default' AND t.technique_id IN ("
)
_SUFFIX = ") GROUP BY t.technique_id"
_BUDGET = _MAX_SQL_CHARS - len(_PREFIX) - len(_SUFFIX)


# ---------------------------------------------------------------------------
# The positive control. Without this, every test below could be vacuous.
# ---------------------------------------------------------------------------


def _old_single_statement(n: int) -> str:
    """What the code built before the fix: one statement, however long."""
    return _PREFIX + ",".join(f"'{t}'" for t in _subtechnique_ids(n)) + _SUFFIX


def test_the_old_single_statement_form_really_did_overflow():
    """The bug reproduced, and the threshold measured rather than assumed.

    The first version of this test asserted 300 ids overflowed and failed at
    3,886 characters, which was the control doing its job: the figure came
    from the original indented query body of 439 characters, and the rewritten
    prefix is shorter, so the ceiling sits a little higher. The threshold is
    computed here so it cannot drift again.
    """
    fits = max(n for n in range(1, 1000)
               if len(_old_single_statement(n)) <= _MAX_SQL_CHARS)

    # A real ATT&CK-shaped baseline runs to hundreds of techniques, so this
    # ceiling is reachable, not theoretical.
    assert 200 < fits < 600, f"unexpected threshold of {fits} ids"
    assert len(_old_single_statement(fits + 1)) > _MAX_SQL_CHARS, (
        f"{fits + 1} ids did not overflow, so these tests exercise nothing"
    )


def test_a_small_list_still_fits_in_one_statement():
    """The fix must not chunk work that never needed chunking."""
    batches = list(_quoted_id_batches(_subtechnique_ids(50), _BUDGET))
    assert len(batches) == 1
    assert len(_PREFIX + batches[0] + _SUFFIX) <= _MAX_SQL_CHARS


# ---------------------------------------------------------------------------
# The chunking itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("count", [297, 300, 650, 2000])
def test_every_batch_fits_inside_the_limit(count):
    """No batch, at any catalogue size, produces a statement TIDE refuses."""
    ids = _subtechnique_ids(count)
    batches = list(_quoted_id_batches(ids, _BUDGET))
    assert batches, "an id list must produce at least one batch"
    for frag in batches:
        sql = _PREFIX + frag + _SUFFIX
        assert len(sql) <= _MAX_SQL_CHARS, (
            f"{count} ids gave a {len(sql)}-char statement, over the cap"
        )


@pytest.mark.parametrize("count", [1, 50, 297, 650])
def test_chunking_loses_no_ids_and_duplicates_none(count):
    """A split that drops an id understates coverage, which is the whole bug."""
    ids = _subtechnique_ids(count)
    seen: list[str] = []
    for frag in _quoted_id_batches(ids, _BUDGET):
        seen.extend(part.strip("'") for part in frag.split(","))
    assert seen == ids, "ids must come back in order, once each"


def test_an_empty_list_yields_no_statements():
    assert list(_quoted_id_batches([], _BUDGET)) == []


def test_ids_are_escaped():
    """The old inline f-string did not escape, so a quote broke the statement."""
    (frag,) = list(_quoted_id_batches(["T1059", "it's"], _BUDGET))
    assert frag == "'T1059','it''s'"


# ---------------------------------------------------------------------------
# The guard in _query, which makes the failure loud instead of empty
# ---------------------------------------------------------------------------


class _RecordingTide(TideService):
    """Hand-written rather than Mock, matching test_de_tide_api's reasoning:
    a Mock answers every shape alike, and shape is what is under test."""

    def __init__(self, responses: Optional[dict] = None):
        self.enabled = True
        self.space = "default"
        self.url = "https://tide.invalid"
        self.api_key = "k"
        self.client_id = None
        self._resolved_client_id = None
        # No TLS settings here on purpose: _query is overridden below, so this
        # fake never opens a connection and a verify flag would only mislead.
        self.sent: list[str] = []
        self._responses = responses or {}

    def _query(self, sql: str, retries: int = 1) -> Optional[dict]:
        self.sent.append(sql)
        for needle, resp in self._responses.items():
            if needle in sql:
                return resp
        return {"rows": []}


def test_query_refuses_an_over_length_statement_without_sending_it(caplog):
    """The real _query, not the fake: an over-long statement never leaves."""
    svc = TideService.__new__(TideService)
    svc.enabled = True
    sql = "SELECT 1 WHERE x IN (" + ",".join(["'y'"] * 2000) + ")"
    assert len(sql) > _MAX_SQL_CHARS

    with caplog.at_level("ERROR"):
        assert svc._query(sql) is None
    assert any("over the" in r.message or "over the" in r.getMessage()
               for r in caplog.records), "the refusal must be logged, not silent"


# ---------------------------------------------------------------------------
# Failure is not emptiness
# ---------------------------------------------------------------------------


def _playbook_fixture(coverage_response: Any) -> _RecordingTide:
    return _RecordingTide({
        "FROM playbooks": {"rows": [{"id": "pb1", "name": "Ransomware",
                                     "description": "d"}]},
        "FROM playbook_steps": {"rows": [{
            "step_id": "s1", "step_number": 1, "title": "Execution",
            "description": "d", "technique_id": "T1059",
            "required_rule": None, "tactic": "execution",
        }]},
        "FROM step_techniques": {"rows": [{"technique_id": "T1059"}]},
        "FROM step_detections": {"rows": []},
        "FROM system_baselines": {"rows": []},
        "GROUP BY t.technique_id": coverage_response,
    })


def test_a_failed_coverage_batch_is_reported_as_unmeasured():
    """None from the coverage query must not read as "no rules cover this".

    Pre-fix there was no such key and an empty map was indistinguishable from
    a measured zero, which is the ION rule this whole module exists for.
    """
    svc = _playbook_fixture(None)
    (pb,) = svc.get_playbooks_with_kill_chains()
    assert pb["technique_coverage"] == {}
    assert pb["technique_coverage_measured"] is False


def test_a_successful_batch_is_reported_as_measured():
    svc = _playbook_fixture({"rows": [
        {"technique_id": "T1059", "rule_count": 4, "enabled_rules": 2},
    ]})
    (pb,) = svc.get_playbooks_with_kill_chains()
    assert pb["technique_coverage_measured"] is True
    assert pb["technique_coverage"]["T1059"]["enabled_rules"] == 2


def test_a_genuine_zero_is_still_measured():
    """A technique nothing covers must stay distinguishable from a failure."""
    svc = _playbook_fixture({"rows": []})
    (pb,) = svc.get_playbooks_with_kill_chains()
    assert pb["technique_coverage"] == {}
    assert pb["technique_coverage_measured"] is True


def test_a_playbook_with_no_techniques_is_measured_not_failed():
    svc = _RecordingTide({
        "FROM playbooks": {"rows": [{"id": "pb1", "name": "Empty",
                                     "description": "d"}]},
        "FROM playbook_steps": {"rows": []},
    })
    (pb,) = svc.get_playbooks_with_kill_chains()
    assert pb["technique_coverage"] == {}
    assert pb["technique_coverage_measured"] is True
