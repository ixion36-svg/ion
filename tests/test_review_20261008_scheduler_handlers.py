"""Scheduler job catalogue (review 2026-10-08, §21).

The scheduler had cron parsing, CRUD, enable/disable, run-now, execution
records and leader coordination — and exactly one registered handler,
``noop``, which echoes its parameters back. So the feature was complete
except for having anything to run: creating a job meant typing an
internal handler key and raw JSON, and the only key that existed did
nothing.

This pins the catalogue the review asked for — executive report
generation, briefing snapshots, stale-observable review and safe
maintenance — plus the metadata a form needs so an ordinary SOC job does
not require knowing internal handler names or hand-writing JSON, and a
next-run preview so a cron expression can be checked before it is saved.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.observable import Observable, ObservableEnrichment
from ion.models.scheduler import JobExecution, ScheduledJob
from ion.services import scheduler_service as svc


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(
        f"sqlite:///{tmp_path / 'review_scheduler.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()


# ── The catalogue exists ──────────────────────────────────────────────────


#: Every handler the review asked ION to ship.
EXPECTED = {
    "executive_report",
    "briefing_snapshot",
    "stale_observable_review",
    "measure_applied_proposals",
    "purge_execution_history",
}


class TestCatalogue:
    def test_more_than_noop_is_registered(self):
        assert svc.list_handlers() != ["noop"]

    @pytest.mark.parametrize("key", sorted(EXPECTED))
    def test_each_expected_handler_is_registered(self, key):
        assert svc.get_handler(key) is not None, f"{key} is not registered"

    def test_noop_is_still_available_for_smoke_testing(self):
        assert svc.get_handler("noop") is not None

    def test_every_handler_is_async(self):
        import inspect
        for key in svc.list_handlers():
            assert inspect.iscoroutinefunction(svc.get_handler(key)), key


# ── The metadata a form needs ─────────────────────────────────────────────


class TestHandlerMetadata:
    def test_every_handler_is_described(self):
        described = {h["key"] for h in svc.describe_handlers()}
        assert set(svc.list_handlers()) <= described

    @pytest.mark.parametrize("key", sorted(EXPECTED))
    def test_a_description_carries_a_human_label_and_summary(self, key):
        meta = {h["key"]: h for h in svc.describe_handlers()}[key]
        assert meta["label"] and meta["label"] != key
        assert meta["description"]
        # "Ordinary SOC jobs should not require internal handler names."
        assert "_" not in meta["label"]

    def test_parameters_are_typed_not_raw_json(self):
        meta = {h["key"]: h for h in svc.describe_handlers()}["executive_report"]
        params = {p["name"]: p for p in meta["parameters"]}
        assert params["days"]["type"] == "integer"
        assert params["days"]["default"] == 7
        assert params["days"]["minimum"] >= 1

    def test_a_boolean_parameter_is_declared_as_one(self):
        meta = {h["key"]: h for h in svc.describe_handlers()}["briefing_snapshot"]
        params = {p["name"]: p for p in meta["parameters"]}
        assert params["ai"]["type"] == "boolean"

    def test_a_parameterless_handler_declares_an_empty_list(self):
        meta = {h["key"]: h for h in svc.describe_handlers()}["noop"]
        assert isinstance(meta["parameters"], list)

    def test_every_parameter_has_a_label_and_a_default(self):
        for meta in svc.describe_handlers():
            for p in meta["parameters"]:
                assert p.get("label"), (meta["key"], p)
                assert "default" in p, (meta["key"], p)


# ── Next-run preview ──────────────────────────────────────────────────────


class TestNextRunPreview:
    def test_a_valid_cron_previews_several_runs(self):
        preview = svc.preview_schedule("0 3 * * *", count=3)
        assert preview["valid"] is True
        assert len(preview["next_runs"]) == 3
        assert preview["description"]

    def test_the_previewed_runs_are_in_order_and_in_the_future(self):
        preview = svc.preview_schedule("*/15 * * * *", count=4)
        runs = [datetime.fromisoformat(r) for r in preview["next_runs"]]
        assert runs == sorted(runs)
        assert runs[0] > datetime.now(timezone.utc) - timedelta(minutes=16)

    def test_an_invalid_cron_is_reported_not_raised(self):
        preview = svc.preview_schedule("not a cron")
        assert preview["valid"] is False
        assert preview["next_runs"] == []
        assert preview["error"]

    def test_the_timezone_is_stated(self):
        assert svc.preview_schedule("0 3 * * *")["timezone"] == "UTC"


# ── Behaviour: stale observable review ────────────────────────────────────


def _observable(db, value, *, watched=True, enriched_days_ago=None):
    obs = Observable(
        type="ipv4",
        value=value,
        normalized_value=value,
        first_seen=datetime.utcnow() - timedelta(days=90),
        last_seen=datetime.utcnow(),
        is_watched=watched,
    )
    db.add(obs)
    db.flush()
    if enriched_days_ago is not None:
        db.add(ObservableEnrichment(
            observable_id=obs.id,
            source="opencti",
            enriched_at=datetime.utcnow() - timedelta(days=enriched_days_ago),
        ))
    db.flush()
    return obs


class TestStaleObservableReview:
    def test_it_finds_an_observable_enriched_long_ago(self, db):
        _observable(db, "10.0.0.1", enriched_days_ago=60)
        db.commit()

        out = asyncio.run(svc.get_handler("stale_observable_review")({"days": 30}, db))
        values = [o["value"] for o in out["stale"]]
        assert "10.0.0.1" in values

    def test_it_leaves_a_freshly_enriched_observable_alone(self, db):
        _observable(db, "10.0.0.2", enriched_days_ago=1)
        db.commit()

        out = asyncio.run(svc.get_handler("stale_observable_review")({"days": 30}, db))
        assert [o["value"] for o in out["stale"]] == []

    def test_never_enriched_is_distinct_from_stale(self, db):
        """"Never checked" and "checked a while ago" are different states."""
        _observable(db, "10.0.0.3", enriched_days_ago=None)
        db.commit()

        out = asyncio.run(svc.get_handler("stale_observable_review")({"days": 30}, db))
        entry = next(o for o in out["stale"] if o["value"] == "10.0.0.3")
        assert entry["last_enriched_at"] is None
        assert entry["state"] == "never_enriched"

    def test_unwatched_observables_are_not_reviewed(self, db):
        _observable(db, "10.0.0.4", watched=False, enriched_days_ago=99)
        db.commit()

        out = asyncio.run(svc.get_handler("stale_observable_review")({"days": 30}, db))
        assert [o["value"] for o in out["stale"]] == []

    def test_the_result_states_its_window_and_count(self, db):
        _observable(db, "10.0.0.5", enriched_days_ago=60)
        db.commit()
        out = asyncio.run(svc.get_handler("stale_observable_review")({"days": 30}, db))
        assert out["stale_after_days"] == 30
        assert out["stale_count"] == len(out["stale"])

    def test_the_limit_is_honoured(self, db):
        for n in range(6):
            _observable(db, f"10.1.0.{n}", enriched_days_ago=60)
        db.commit()
        out = asyncio.run(svc.get_handler("stale_observable_review")(
            {"days": 30, "limit": 2}, db
        ))
        assert len(out["stale"]) == 2
        assert out["truncated"] is True


# ── Behaviour: safe maintenance ───────────────────────────────────────────


class TestPurgeExecutionHistory:
    def _job_with_executions(self, db, ages_in_days):
        job = ScheduledJob(
            name="noop job", handler_key="noop", cron_expr="0 3 * * *",
            enabled=True,
            next_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add(job)
        db.flush()
        for age in ages_in_days:
            db.add(JobExecution(
                job_id=job.id,
                started_at=datetime.now(timezone.utc) - timedelta(days=age),
                status="success",
            ))
        db.commit()
        return job

    def test_it_removes_records_older_than_the_window(self, db):
        self._job_with_executions(db, [100, 95, 2])
        out = asyncio.run(svc.get_handler("purge_execution_history")({"days": 30}, db))
        assert out["deleted"] == 2
        assert db.query(JobExecution).count() == 1

    def test_it_keeps_recent_records(self, db):
        self._job_with_executions(db, [1, 2, 3])
        out = asyncio.run(svc.get_handler("purge_execution_history")({"days": 30}, db))
        assert out["deleted"] == 0
        assert db.query(JobExecution).count() == 3

    def test_the_retention_floor_refuses_to_wipe_everything(self, db):
        """A safe maintenance job must not be a foot-gun."""
        self._job_with_executions(db, [1, 2, 3])
        out = asyncio.run(svc.get_handler("purge_execution_history")({"days": 0}, db))
        assert out["days"] >= svc.MIN_EXECUTION_RETENTION_DAYS
        assert db.query(JobExecution).count() == 3

    def test_it_reports_the_window_it_used(self, db):
        self._job_with_executions(db, [100])
        out = asyncio.run(svc.get_handler("purge_execution_history")({"days": 45}, db))
        assert out["days"] == 45
        assert out["cutoff"]


# ── Behaviour: the report and briefing handlers run ───────────────────────


class TestReportHandlers:
    def test_the_executive_report_handler_returns_a_summary(self, db):
        out = asyncio.run(svc.get_handler("executive_report")({"days": 7}, db))
        assert out["period_days"] == 7
        assert "cases" in out
        assert out["generated_at"]

    def test_a_bad_days_value_falls_back_to_the_default(self, db):
        out = asyncio.run(svc.get_handler("executive_report")({"days": "twelve"}, db))
        assert out["period_days"] == 7

    def test_the_executive_report_output_is_json_serialisable(self, db):
        import json
        out = asyncio.run(svc.get_handler("executive_report")({"days": 7}, db))
        json.dumps(out, default=str)
