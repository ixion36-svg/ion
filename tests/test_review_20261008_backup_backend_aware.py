"""Backend-aware database backup/restore (review 2026-10-08, §22).

The shipped Compose stack runs PostgreSQL, but the admin backup and
restore handlers unconditionally copied ``config.db_path`` — a local
SQLite file. On a PostgreSQL deployment that is one of two bad outcomes:

* no local ``.db`` file exists, so Backup returns 404 "Database file not
  found" and the operator has no idea whether backups are possible; or
* a stale ``.db`` file left over from an earlier SQLite run *does* exist,
  so Backup reports success and a plausible size while protecting
  nothing. Restore then overwrites that unused file and reports success
  while PostgreSQL carries on serving the real, unrestored data.

The second is the dangerous one: a control that reports success without
doing anything is worse than one that errors.

These tests pin the corrected contract. The handlers must identify the
active backend and refuse rather than mislead, every response must name
the backend and say what the artefact actually covers, and an operator
must be able to see what a backup would and would not include.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web import admin_api


# ── Backend detection ─────────────────────────────────────────────────────


class TestBackendDetection:
    def test_sqlite_when_no_database_url(self, monkeypatch):
        monkeypatch.delenv("ION_DATABASE_URL", raising=False)
        assert admin_api._active_db_backend() == "sqlite"

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql://ion:pw@db:5432/ion",
            "postgresql+psycopg2://ion:pw@db:5432/ion",
            "postgres://ion:pw@localhost:5433/ion",
        ],
    )
    def test_postgres_when_database_url_is_postgres(self, monkeypatch, url):
        monkeypatch.setenv("ION_DATABASE_URL", url)
        assert admin_api._active_db_backend() == "postgresql"

    def test_unknown_external_backend_is_not_called_sqlite(self, monkeypatch):
        monkeypatch.setenv("ION_DATABASE_URL", "mysql://ion:pw@db:3306/ion")
        assert admin_api._active_db_backend() not in ("sqlite",)


# ── A PostgreSQL deployment must not be told a file copy worked ───────────


class TestPostgresRefusesFileCopy:
    @pytest.fixture(autouse=True)
    def _pg(self, monkeypatch):
        monkeypatch.setenv("ION_DATABASE_URL", "postgresql://ion:pw@db:5432/ion")

    def test_backup_plan_reports_postgres_and_is_not_supported(self):
        plan = admin_api._recovery_capability()
        assert plan["backend"] == "postgresql"
        assert plan["file_copy_supported"] is False
        # The operator has to be told what to use instead.
        assert "pg_dump" in " ".join(plan["guidance"]).lower()

    def test_backup_refuses_rather_than_copying_a_stale_file(self, tmp_path, monkeypatch):
        """The misleading-success case: a leftover .db file is present."""
        stale = tmp_path / ".ion" / "ion.db"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"SQLite format 3\x00" + b"stale" * 100)

        monkeypatch.setattr(
            admin_api, "_configured_db_path", lambda: stale, raising=False
        )
        with pytest.raises(admin_api.HTTPException) as exc:
            admin_api._assert_file_copy_backend()

        assert exc.value.status_code == 400
        detail = str(exc.value.detail).lower()
        assert "postgresql" in detail
        # It must not imply the stale file is a valid backup target.
        assert "pg_dump" in detail

    def test_manifest_names_what_is_not_covered(self):
        manifest = admin_api._recovery_capability()
        not_covered = " ".join(manifest["not_covered"]).lower()
        # The review asked for an exact manifest: database, evidence and
        # uploads, configuration.
        assert "evidence" in not_covered or "upload" in not_covered
        assert "config" in not_covered


# ── SQLite deployments keep working ───────────────────────────────────────


class TestSqliteStillSupported:
    @pytest.fixture(autouse=True)
    def _sqlite(self, monkeypatch):
        monkeypatch.delenv("ION_DATABASE_URL", raising=False)

    def test_file_copy_is_supported(self):
        plan = admin_api._recovery_capability()
        assert plan["backend"] == "sqlite"
        assert plan["file_copy_supported"] is True

    def test_assert_does_not_raise(self):
        admin_api._assert_file_copy_backend()  # must not raise

    def test_capability_still_lists_what_is_outside_the_db(self):
        plan = admin_api._recovery_capability()
        # Even on SQLite, a .db copy is not the whole system.
        assert plan["not_covered"], "a db copy is not a full-system backup"


# ── Secrets must not leak through the capability report ───────────────────


class TestNoCredentialLeak:
    def test_connection_password_is_never_echoed(self, monkeypatch):
        monkeypatch.setenv(
            "ION_DATABASE_URL", "postgresql://ion:sup3r-s3cret@db:5432/ion"
        )
        rendered = str(admin_api._recovery_capability())
        assert "sup3r-s3cret" not in rendered

    def test_host_and_database_may_be_shown_without_credentials(self, monkeypatch):
        monkeypatch.setenv(
            "ION_DATABASE_URL", "postgresql://ion:sup3r-s3cret@db:5432/ion"
        )
        target = admin_api._recovery_capability().get("target", "")
        assert "sup3r-s3cret" not in target
        assert "ion:" not in target
