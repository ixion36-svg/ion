"""`ion seed-tide` and `ion backfill-rule-identity`."""

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ion.cli.main import app
from ion.storage.database import get_engine, get_session_factory, init_db, reset_engine


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def project(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ION_DATABASE_URL", raising=False)
    db_path = tmp_path / ".ion" / "ion.db"
    init_db(db_path)
    from ion.core.config import Config, set_config
    config = Config(db_path=db_path)
    config.to_file(tmp_path / ".ion" / "config.json")
    set_config(config)
    yield db_path
    reset_engine()


def _token(output: str) -> str:
    match = re.search(r"Bearer token \(save this now\):\s*\n\s*(\S+)", output)
    assert match, output
    return match.group(1)


def _user_for(db_path, token):
    from ion.auth.service import AuthService
    session = get_session_factory(get_engine(db_path))()
    try:
        user = AuthService(session).validate_session(token)
        if user is None:
            return None
        return user.username, user.is_service_account, sorted(
            p.name for role in user.roles for p in role.permissions)
    finally:
        session.close()


def test_seed_tide_mints_a_token_for_a_service_account_that_can_only_read_rule_outcomes(runner, project):
    result = runner.invoke(app, ["seed-tide"])
    assert result.exit_code == 0, result.output
    assert _user_for(project, _token(result.output)) == ("tide", True, ["rule_outcomes:read"])


def test_seed_tide_again_revokes_the_previous_token(runner, project):
    first = _token(runner.invoke(app, ["seed-tide"]).output)
    second = _token(runner.invoke(app, ["seed-tide"]).output)
    assert second != first
    assert _user_for(project, first) is None
    assert _user_for(project, second) is not None


def test_seed_tide_refuses_a_ttl_under_a_day(runner, project):
    result = runner.invoke(app, ["seed-tide", "--ttl-days", "0"])
    assert result.exit_code == 1
    assert "--ttl-days must be at least 1" in result.output


def test_seed_tide_on_an_uninitialised_install_says_so(runner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ION_DATABASE_URL", raising=False)
    from ion.core.config import Config, set_config
    set_config(Config(db_path=tmp_path / ".ion" / "ion.db"))
    result = runner.invoke(app, ["seed-tide"])
    assert "ION not initialized" in result.output
    assert not (tmp_path / ".ion" / "ion.db").exists()


class _ES:
    def __init__(self, configured=True):
        self.is_configured = configured


def _patch_backfill(monkeypatch, *, configured=True, result=None, error=None):
    import ion.services.elasticsearch_service as es_mod
    import ion.services.rule_identity_backfill_service as backfill
    calls = []
    monkeypatch.setattr(es_mod, "ElasticsearchService", lambda: _ES(configured))

    async def fake_fill(session, es, batch):
        calls.append(batch)
        if error:
            raise error
        return result

    monkeypatch.setattr(backfill, "fill_rule_identity", fake_fill)
    return calls


def test_backfill_reports_how_many_rows_gained_a_rule_id_and_passes_the_batch(runner, project, monkeypatch):
    calls = _patch_backfill(monkeypatch, result=7)
    result = runner.invoke(app, ["backfill-rule-identity", "--batch", "50"])
    assert result.exit_code == 0, result.output
    assert "7 triage row(s) gained a rule id" in result.output
    assert calls == [50]


def test_backfill_without_elasticsearch_fails_and_reads_nothing(runner, project, monkeypatch):
    calls = _patch_backfill(monkeypatch, configured=False, result=1)
    result = runner.invoke(app, ["backfill-rule-identity"])
    assert result.exit_code == 1
    assert "Elasticsearch is not configured" in result.output
    assert calls == []


def test_backfill_that_stops_on_a_failed_search_exits_non_zero(runner, project, monkeypatch):
    _patch_backfill(monkeypatch, error=RuntimeError("search timed out"))
    result = runner.invoke(app, ["backfill-rule-identity"])
    assert result.exit_code == 1
    assert "Backfill stopped: search timed out" in result.output


def _human(db_path, username):
    """A person's account holding a service account's name."""
    from ion.auth.service import AuthService
    session = get_session_factory(get_engine(db_path))()
    try:
        AuthService(session).user_repo.create(
            username=username, email=f"{username}@example.com", password_hash="x")
        session.commit()
    finally:
        session.close()


@pytest.mark.parametrize("command", ["seed-tide", "seed-metis"])
def test_seeding_over_a_person_named_like_the_service_account_refuses(runner, project, command):
    name = command.split("-", 1)[1]
    _human(project, name)
    result = runner.invoke(app, [command])
    assert result.exit_code == 1, result.output
    assert f"a non-service account named '{name}' already exists" in result.output
    assert "Bearer token" not in result.output
