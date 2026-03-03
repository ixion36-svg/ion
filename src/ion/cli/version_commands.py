"""Version control CLI commands."""

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

from ion.core.config import get_config
from ion.core.exceptions import TemplateNotFoundError, VersionNotFoundError, ValidationError
from ion.storage.database import get_session, get_engine
from ion.services.version_service import VersionService
from ion.services.template_service import TemplateService

version_app = typer.Typer(help="Version control commands")
console = Console()


def get_services():
    """Get service instances."""
    config = get_config()
    engine = get_engine(config.db_path)
    session = next(get_session(engine))
    return VersionService(session), TemplateService(session), session


@version_app.command("list")
def list_versions(
    template_id: int = typer.Argument(..., help="Template ID"),
    checkpoints: bool = typer.Option(
        False, "--checkpoints", "-c", help="Show only checkpoints"
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-n", help="Limit number of versions shown"
    ),
) -> None:
    """List versions for a template."""
    version_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)
        versions = version_service.list_versions(
            template_id, checkpoints_only=checkpoints, limit=limit
        )

        if not versions:
            console.print(f"[yellow]No versions found for template '{template.name}'.[/yellow]")
            return

        table = Table(title=f"Versions of '{template.name}'")
        table.add_column("Version", style="cyan", justify="right")
        table.add_column("Checkpoint", style="green")
        table.add_column("Message")
        table.add_column("Created")

        for v in versions:
            checkpoint = v.checkpoint_name if v.is_checkpoint else ""
            message = v.message[:40] + "..." if v.message and len(v.message) > 40 else (v.message or "")
            table.add_row(
                str(v.version_number),
                checkpoint,
                message,
                v.created_at.strftime("%Y-%m-%d %H:%M"),
            )

        console.print(table)
        console.print(f"\nCurrent version: {template.current_version}")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)


@version_app.command("show")
def show_version(
    template_id: int = typer.Argument(..., help="Template ID"),
    version_number: int = typer.Argument(..., help="Version number"),
    diff: bool = typer.Option(False, "--diff", "-d", help="Show diff from previous version"),
) -> None:
    """Show a specific version."""
    version_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)
        version = version_service.get_version(template_id, version_number)

        console.print(Panel(
            f"[bold]{template.name}[/bold] - Version {version.version_number}",
            subtitle=f"Created: {version.created_at.strftime('%Y-%m-%d %H:%M')}"
        ))

        if version.is_checkpoint:
            console.print(f"  [green]Checkpoint: {version.checkpoint_name}[/green]")

        if version.message:
            console.print(f"  Message: {version.message}")

        if version.author:
            console.print(f"  Author: {version.author}")

        if diff and version.diff:
            console.print("\n[bold]Diff:[/bold]")
            syntax = Syntax(version.diff, "diff", theme="monokai")
            console.print(syntax)
        else:
            console.print("\n[bold]Content:[/bold]")
            syntax = Syntax(version.content, "jinja2", theme="monokai", line_numbers=True)
            console.print(syntax)

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except VersionNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@version_app.command("checkpoint")
def create_checkpoint(
    template_id: int = typer.Argument(..., help="Template ID"),
    name: str = typer.Option(..., "--name", "-n", help="Checkpoint name"),
    message: Optional[str] = typer.Option(
        None, "--message", "-m", help="Checkpoint message"
    ),
) -> None:
    """Create a named checkpoint for the current version."""
    version_service, template_service, session = get_services()

    try:
        template = template_service.get_template(template_id)
        version = version_service.create_checkpoint(template_id, name, message)
        session.commit()

        console.print(
            f"[green]OK[/green] Created checkpoint '{name}' for "
            f"'{template.name}' at version {version.version_number}"
        )

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@version_app.command("diff")
def diff_versions(
    template_id: int = typer.Argument(..., help="Template ID"),
    from_version: int = typer.Argument(..., help="From version number"),
    to_version: int = typer.Argument(..., help="To version number"),
    color: bool = typer.Option(True, "--color/--no-color", help="Colorize output"),
) -> None:
    """Show diff between two versions."""
    version_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)
        diff = version_service.diff_versions(template_id, from_version, to_version)

        console.print(
            f"[bold]Diff for '{template.name}'[/bold]: "
            f"v{from_version} → v{to_version}\n"
        )

        if color:
            syntax = Syntax(diff, "diff", theme="monokai")
            console.print(syntax)
        else:
            console.print(diff)

        # Show stats
        from ion.diff.differ import VersionDiffer
        differ = VersionDiffer()
        stats = differ.get_stats(diff)
        console.print(
            f"\n[green]+{stats['additions']}[/green] "
            f"[red]-{stats['deletions']}[/red] "
            f"({stats['total_changes']} changes)"
        )

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except VersionNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@version_app.command("rollback")
def rollback(
    template_id: int = typer.Argument(..., help="Template ID"),
    to_version: int = typer.Argument(..., help="Version to rollback to"),
    message: Optional[str] = typer.Option(
        None, "--message", "-m", help="Rollback message"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Rollback template to a previous version."""
    version_service, template_service, session = get_services()

    try:
        template = template_service.get_template(template_id)
        target_version = version_service.get_version(template_id, to_version)

        if not force:
            console.print(
                f"Rollback '{template.name}' from v{template.current_version} "
                f"to v{to_version}?"
            )
            confirm = typer.confirm("Proceed?")
            if not confirm:
                console.print("Cancelled.")
                return

        template = version_service.rollback(template_id, to_version, message)
        session.commit()

        console.print(
            f"[green]OK[/green] Rolled back '{template.name}' to version {to_version}"
        )
        console.print(f"  New version: {template.current_version}")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except VersionNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@version_app.command("prune")
def prune_versions(
    template_id: int = typer.Argument(..., help="Template ID"),
    keep: int = typer.Option(50, "--keep", "-k", help="Number of versions to keep"),
    keep_checkpoints: bool = typer.Option(
        True, "--keep-checkpoints/--no-keep-checkpoints",
        help="Preserve checkpoint versions"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete old versions, keeping recent ones and checkpoints."""
    version_service, template_service, session = get_services()

    try:
        template = template_service.get_template(template_id)
        count = version_service.count_versions(template_id)

        if count <= keep:
            console.print(
                f"[yellow]Template '{template.name}' has only {count} versions. "
                f"Nothing to prune.[/yellow]"
            )
            return

        to_delete = count - keep

        if not force:
            console.print(
                f"Prune {to_delete} versions from '{template.name}'?"
            )
            if keep_checkpoints:
                console.print("  (Checkpoints will be preserved)")
            confirm = typer.confirm("Proceed?")
            if not confirm:
                console.print("Cancelled.")
                return

        deleted = version_service.prune_versions(template_id, keep, keep_checkpoints)
        session.commit()

        console.print(f"[green]OK[/green] Deleted {deleted} versions")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
