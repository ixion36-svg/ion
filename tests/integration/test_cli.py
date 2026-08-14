"""Integration tests for CLI commands."""

import pytest
from pathlib import Path
from typer.testing import CliRunner

from ion.cli.main import app
from ion.storage.database import init_db, reset_engine


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_project(tmp_path: Path):
    """Create a temporary project directory with initialized ION."""
    import os
    original_cwd = os.getcwd()
    os.chdir(tmp_path)

    # Initialize ION
    db_path = tmp_path / ".ion" / "ion.db"
    init_db(db_path)

    # Create config
    from ion.core.config import Config, set_config
    config = Config(db_path=db_path)
    config.to_file(tmp_path / ".ion" / "config.json")
    set_config(config)

    yield tmp_path

    os.chdir(original_cwd)
    reset_engine()


class TestInitCommand:
    """Tests for init command."""

    def test_init_creates_database(self, runner, tmp_path):
        """Test that init creates the database."""
        import os
        original_cwd = os.getcwd()
        os.chdir(tmp_path)

        try:
            reset_engine()
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0
            assert "Initialized ION" in result.output
            assert (tmp_path / ".ion" / "ion.db").exists()
        finally:
            os.chdir(original_cwd)
            reset_engine()


class TestTemplateCommands:
    """Tests for template commands."""

    def test_create_template(self, runner, temp_project):
        """Test creating a template."""
        result = runner.invoke(app, [
            "template", "create",
            "--name", "Test Template",
            "--content", "Hello {{ name }}",
        ])
        assert result.exit_code == 0
        assert "Created template" in result.output

    def test_list_templates(self, runner, temp_project):
        """Test listing templates."""
        # Create a template first
        runner.invoke(app, [
            "template", "create",
            "--name", "List Test",
            "--content", "content",
        ])

        result = runner.invoke(app, ["template", "list"])
        assert result.exit_code == 0
        assert "List Test" in result.output

    def test_show_template(self, runner, temp_project):
        """Test showing template details."""
        runner.invoke(app, [
            "template", "create",
            "--name", "Show Test",
            "--content", "Hello",
        ])

        result = runner.invoke(app, ["template", "show", "1"])
        assert result.exit_code == 0
        assert "Show Test" in result.output

    def test_delete_template(self, runner, temp_project):
        """Test deleting a template."""
        runner.invoke(app, [
            "template", "create",
            "--name", "Delete Test",
            "--content", "",
        ])

        result = runner.invoke(app, ["template", "delete", "1", "--force"])
        assert result.exit_code == 0
        assert "Deleted" in result.output


class TestRenderCommands:
    """Tests for render commands."""

    def test_preview(self, runner, temp_project):
        """Test preview command."""
        runner.invoke(app, [
            "template", "create",
            "--name", "Preview Test",
            "--content", "Hello {{ name }}!",
        ])

        result = runner.invoke(app, [
            "render", "preview", "1",
            "--data", '{"name": "World"}',
        ])
        assert result.exit_code == 0
        assert "Hello World!" in result.output

    def test_render_to_file(self, runner, temp_project):
        """Test rendering to a file."""
        runner.invoke(app, [
            "template", "create",
            "--name", "Render File Test",
            "--content", "Output: {{ value }}",
        ])

        output_file = temp_project / "output.txt"
        result = runner.invoke(app, [
            "render", "run", "1",
            "--data", '{"value": "test"}',
            "--output", str(output_file),
        ])
        assert result.exit_code == 0
        assert output_file.exists()
        assert "test" in output_file.read_text()


class TestSeedAegisCommand:
    """Tests for the seed-aegis CLI command."""

    def test_seed_aegis_creates_account_and_prints_token(self, runner, temp_project):
        """Seeding prints the token once plus the four scoped permissions."""
        result = runner.invoke(app, ["seed-aegis"])
        assert result.exit_code == 0
        assert "aegis" in result.output
        assert "alert:read" in result.output
        assert "de:read" in result.output
        assert "de:propose" in result.output
        assert "case:read" in result.output
        # least-privilege: verify/approve must never be listed as granted
        assert "de:verify" not in result.output
        assert "de:approve" not in result.output

    def test_seed_aegis_second_run_does_not_crash(self, runner, temp_project):
        """Re-running seed-aegis is idempotent — tops up, never errors."""
        first = runner.invoke(app, ["seed-aegis"])
        assert first.exit_code == 0

        second = runner.invoke(app, ["seed-aegis"])
        assert second.exit_code == 0
        assert "aegis" in second.output

    def test_seed_aegis_second_run_states_previous_token_revoked(self, runner, temp_project):
        """Re-minting is a rotation, not an addition — the CLI must say so,
        since that's the account's recovery path for a leaked token."""
        runner.invoke(app, ["seed-aegis"])
        second = runner.invoke(app, ["seed-aegis"])

        assert second.exit_code == 0
        assert "revoke" in second.output.lower()

    def test_seed_aegis_rejects_non_positive_ttl(self, runner, temp_project):
        result = runner.invoke(app, ["seed-aegis", "--ttl-days", "0"])
        assert result.exit_code != 0


class TestVersionCommands:
    """Tests for version commands."""

    def test_list_versions(self, runner, temp_project):
        """Test listing versions."""
        runner.invoke(app, [
            "template", "create",
            "--name", "Version Test",
            "--content", "v1",
        ])

        result = runner.invoke(app, ["version", "list", "1"])
        assert result.exit_code == 0
        assert "1" in result.output

    def test_create_checkpoint(self, runner, temp_project):
        """Test creating a checkpoint."""
        runner.invoke(app, [
            "template", "create",
            "--name", "Checkpoint Test",
            "--content", "content",
        ])

        result = runner.invoke(app, [
            "version", "checkpoint", "1",
            "--name", "v1.0",
        ])
        assert result.exit_code == 0
        assert "checkpoint" in result.output.lower()
