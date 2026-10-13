"""The analytics API requires a named permission, not merely a session.

Reads take alert:read, the same permission the page and its fragments
already require. PATCH and POST /run take system:settings. Nothing in the
seeded catalogue means "may run an expensive read", and alert:read is the
page's read gate, so the run endpoint is deliberately as strict as the
schedule change.

A refusal is 403 before the handler looks the job up. A 404 would tell
the caller whether that job type exists.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.analytics import AnalyticsJob
from ion.models.base import Base
from ion.storage.database import reset_engine
from ion.web.api import get_db_session
from ion.web.server import app

JOB = "repeat_offenders"
MISSING = "no-such-job"

READS = (
    "/api/analytics/jobs",
    f"/api/analytics/jobs/{JOB}",
    f"/api/analytics/snapshots/{JOB}",
    "/api/analytics/dashboard",
    "/api/analytics/system-overview",
)


class _Account:
    def __init__(self, perms: set[str]):
        self.id = 1
        self.username = "analyst"
        self._perms = perms

    def has_permission(self, name: str) -> bool:
        return name in self._perms


def test_reads_take_alert_read_and_writes_take_system_settings(temp_db, monkeypatch):
    """No permission is refused, alert:read can read and cannot write, and
    system:settings can write. The missing job type is 403 until the caller
    holds the write permission, and only then 404."""
    import ion.models.cyab  # noqa: F401  — system-overview queries these tables
    Base.metadata.create_all(temp_db)
    # get_session_factory keeps the first engine it sees and ignores a later
    # one. TestClient startup binds that cache to the process database, so
    # patching get_engine does not point this request at temp_db. The
    # dependency override does. audit_refusal opens its own session on the
    # process engine; a 403 must not write that audit log.
    monkeypatch.setattr(
        "ion.auth.dependencies.audit_refusal", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        "ion.core.config.get_elasticsearch_config", lambda: {"url": ""}
    )

    class _Tide:
        enabled = False

    monkeypatch.setattr(
        "ion.services.tide_service.get_tide_service", lambda: _Tide()
    )

    class _Engine:
        def run_job_now(self, session, job_type):
            return {"ran": job_type}

    monkeypatch.setattr(
        "ion.web.analytics_api.get_analytics_engine", lambda: _Engine()
    )

    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=temp_db)

    def bind_temp_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    db = SessionLocal()
    db.add(AnalyticsJob(
        job_type=JOB,
        display_name="Repeat offenders",
        enabled=True,
        schedule_minutes=30,
        run_count=0,
    ))
    db.commit()
    db.close()

    held: dict[str, set[str]] = {"perms": set()}

    def current():
        return _Account(held["perms"])

    app.dependency_overrides[get_current_user] = current
    app.dependency_overrides[get_db_session] = bind_temp_db
    try:
        client = TestClient(app)
        none = set()
        reader = {"alert:read"}
        writer = {"system:settings"}

        def call(method: str, path: str, perms: set[str], **kw):
            held["perms"] = set(perms)
            return client.request(method, path, **kw)

        for path in READS:
            refused = call("GET", path, none)
            assert refused.status_code == 403, (path, refused.status_code, refused.text)
            assert refused.status_code != 404
            assert JOB not in refused.text
            assert "alert:read" not in refused.text

            # The write permission is not a read. A settings holder who
            # cannot open the page cannot read the API either.
            writer_read = call("GET", path, writer)
            assert writer_read.status_code == 403, (path, writer_read.status_code)

            allowed = call("GET", path, reader)
            assert allowed.status_code == 200, (path, allowed.status_code, allowed.text)

        jobs = call("GET", "/api/analytics/jobs", reader).json()
        assert jobs["jobs"][0]["job_type"] == JOB
        assert jobs["jobs"][0]["enabled"] is True

        # alert:read can see the job and still cannot disable it.
        blocked = call(
            "PATCH", f"/api/analytics/jobs/{JOB}", reader,
            json={"enabled": False},
        )
        assert blocked.status_code == 403, blocked.text
        assert JOB not in blocked.text
        still = call("GET", f"/api/analytics/jobs/{JOB}", reader).json()
        assert still["enabled"] is True

        updated = call(
            "PATCH", f"/api/analytics/jobs/{JOB}", writer,
            json={"enabled": False},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["enabled"] is False
        seen = call("GET", f"/api/analytics/jobs/{JOB}", reader).json()
        assert seen["enabled"] is False

        # A job type that does not exist. 404 only after the write gate.
        for perms in (none, reader):
            missing = call(
                "PATCH", f"/api/analytics/jobs/{MISSING}", perms,
                json={"enabled": False},
            )
            assert missing.status_code == 403, (perms, missing.status_code, missing.text)
            assert MISSING not in missing.text
        absent = call(
            "PATCH", f"/api/analytics/jobs/{MISSING}", writer,
            json={"enabled": False},
        )
        assert absent.status_code == 404, absent.text
        assert MISSING in absent.text

        # POST /run is the compute lever. alert:read cannot pull it;
        # system:settings can. The engine is the stub above, so a 200 is
        # the gate opening and not a search against Elasticsearch.
        run_blocked = call("POST", f"/api/analytics/jobs/{JOB}/run", reader)
        assert run_blocked.status_code == 403, run_blocked.text
        assert JOB not in run_blocked.text
        run_missing = call("POST", f"/api/analytics/jobs/{MISSING}/run", none)
        assert run_missing.status_code == 403, run_missing.text
        assert MISSING not in run_missing.text
        ran = call("POST", f"/api/analytics/jobs/{JOB}/run", writer)
        assert ran.status_code == 200, ran.text
        assert ran.json()["result"]["ran"] == JOB
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db_session, None)
        reset_engine()
