"""Template management CLI commands."""

import json
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

from ixion.core.config import get_config
from ixion.core.exceptions import TemplateNotFoundError, ValidationError
from ixion.storage.database import get_session, get_engine
from ixion.services.template_service import TemplateService

template_app = typer.Typer(help="Template management commands")
console = Console()


def get_service():
    """Get a template service instance."""
    config = get_config()
    engine = get_engine(config.db_path)
    session = next(get_session(engine))
    return TemplateService(session), session


@template_app.command("create")
def create(
    name: str = typer.Option(..., "--name", "-n", help="Template name"),
    content: str = typer.Option("", "--content", "-c", help="Template content"),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="Read content from file"
    ),
    format: str = typer.Option("markdown", "--format", help="Template format"),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="Template description"
    ),
    tags: Optional[List[str]] = typer.Option(
        None, "--tag", "-t", help="Tags for the template"
    ),
) -> None:
    """Create a new template."""
    service, session = get_service()

    # Read content from file if specified
    if file:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        content = file.read_text(encoding="utf-8")

    try:
        template = service.create_template(
            name=name,
            content=content,
            format=format,
            description=description,
            tags=tags,
        )
        session.commit()

        console.print(f"[green]OK[/green] Created template '{template.name}' (ID: {template.id})")

        if template.tags:
            console.print(f"  Tags: {', '.join(t.name for t in template.tags)}")

    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@template_app.command("list")
def list_templates(
    format: Optional[str] = typer.Option(None, "--format", help="Filter by format"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag"),
    folder: Optional[str] = typer.Option(None, "--folder", help="Filter by folder"),
) -> None:
    """List all templates."""
    service, _ = get_service()

    tags = [tag] if tag else None
    templates = service.list_templates(format=format, folder_path=folder, tags=tags)

    if not templates:
        console.print("[yellow]No templates found.[/yellow]")
        return

    table = Table(title="Templates")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Name", style="green")
    table.add_column("Format", style="blue")
    table.add_column("Version", justify="right")
    table.add_column("Tags")
    table.add_column("Updated")

    for t in templates:
        tags_str = ", ".join(tag.name for tag in t.tags) if t.tags else ""
        table.add_row(
            str(t.id),
            t.name,
            t.format,
            str(t.current_version),
            tags_str,
            t.updated_at.strftime("%Y-%m-%d %H:%M") if t.updated_at else "",
        )

    console.print(table)


@template_app.command("show")
def show(
    template_id: int = typer.Argument(..., help="Template ID"),
    content: bool = typer.Option(False, "--content", "-c", help="Show full content"),
) -> None:
    """Show template details."""
    service, _ = get_service()

    try:
        template = service.get_template(template_id)

        console.print(Panel(f"[bold]{template.name}[/bold]", subtitle=f"ID: {template.id}"))
        console.print(f"  Format: {template.format}")
        console.print(f"  Version: {template.current_version}")

        if template.description:
            console.print(f"  Description: {template.description}")

        if template.tags:
            console.print(f"  Tags: {', '.join(t.name for t in template.tags)}")

        if template.variables:
            console.print("\n  [bold]Variables:[/bold]")
            for var in template.variables:
                req = "required" if var.required else "optional"
                console.print(f"    - {var.name} ({var.var_type}, {req})")

        if content:
            console.print("\n[bold]Content:[/bold]")
            syntax = Syntax(template.content, "jinja2", theme="monokai", line_numbers=True)
            console.print(syntax)

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)


@template_app.command("edit")
def edit(
    template_id: int = typer.Argument(..., help="Template ID"),
    content: Optional[str] = typer.Option(None, "--content", "-c", help="New content"),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="Read content from file"
    ),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="New name"),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="New description"
    ),
    message: Optional[str] = typer.Option(
        None, "--message", "-m", help="Version message"
    ),
) -> None:
    """Edit an existing template."""
    service, session = get_service()

    # Read content from file if specified
    if file:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        content = file.read_text(encoding="utf-8")

    try:
        template = service.update_template(
            template_id=template_id,
            name=name,
            content=content,
            description=description,
            version_message=message,
        )
        session.commit()

        console.print(f"[green]OK[/green] Updated template '{template.name}'")
        console.print(f"  Current version: {template.current_version}")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@template_app.command("delete")
def delete(
    template_id: int = typer.Argument(..., help="Template ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a template."""
    service, session = get_service()

    try:
        template = service.get_template(template_id)

        if not force:
            confirm = typer.confirm(
                f"Delete template '{template.name}' and all its versions?"
            )
            if not confirm:
                console.print("Cancelled.")
                return

        service.delete_template(template_id)
        session.commit()

        console.print(f"[green]OK[/green] Deleted template '{template.name}'")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)


@template_app.command("search")
def search(
    query: str = typer.Argument(..., help="Search query"),
) -> None:
    """Search templates by name, description, or content."""
    service, _ = get_service()

    templates = service.search_templates(query)

    if not templates:
        console.print(f"[yellow]No templates matching '{query}'.[/yellow]")
        return

    table = Table(title=f"Search results for '{query}'")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Name", style="green")
    table.add_column("Format", style="blue")
    table.add_column("Description")

    for t in templates:
        desc = (t.description[:50] + "...") if t.description and len(t.description) > 50 else (t.description or "")
        table.add_row(str(t.id), t.name, t.format, desc)

    console.print(table)


@template_app.command("import")
def import_template(
    file: Path = typer.Argument(..., help="File to import"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Template name"),
    format: Optional[str] = typer.Option(None, "--format", help="Template format"),
) -> None:
    """Import a template from a file."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    # Determine format from extension if not specified
    if format is None:
        ext_map = {".md": "markdown", ".html": "html", ".txt": "text", ".docx": "docx"}
        format = ext_map.get(file.suffix.lower(), "text")

    # Use filename as name if not specified
    if name is None:
        name = file.stem

    # Read content using plugin
    from ixion.plugins import PluginRegistry

    registry = PluginRegistry()
    plugin = registry.get_plugin_for_file(file)

    if plugin:
        content = plugin.read(file)
    else:
        content = file.read_text(encoding="utf-8")

    service, session = get_service()

    try:
        template = service.create_template(
            name=name,
            content=content,
            format=format,
        )
        session.commit()

        console.print(f"[green]OK[/green] Imported '{file.name}' as template '{template.name}' (ID: {template.id})")

    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@template_app.command("export")
def export_template(
    template_id: int = typer.Argument(..., help="Template ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
) -> None:
    """Export a template to a file."""
    service, _ = get_service()

    try:
        template = service.get_template(template_id)

        # Write using plugin
        from ixion.plugins import PluginRegistry

        registry = PluginRegistry()
        plugin = registry.get_plugin_for_file(output)

        if plugin:
            plugin.write(template.content, output)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(template.content, encoding="utf-8")

        console.print(f"[green]OK[/green] Exported template '{template.name}' to {output}")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)


@template_app.command("tag")
def manage_tags(
    template_id: int = typer.Argument(..., help="Template ID"),
    add: Optional[List[str]] = typer.Option(None, "--add", "-a", help="Tags to add"),
    remove: Optional[List[str]] = typer.Option(
        None, "--remove", "-r", help="Tags to remove"
    ),
) -> None:
    """Manage tags for a template."""
    service, session = get_service()

    try:
        template = service.get_template(template_id)

        if add:
            for tag_name in add:
                service.add_tag(template_id, tag_name)
                console.print(f"[green]OK[/green] Added tag '{tag_name}'")

        if remove:
            for tag_name in remove:
                service.remove_tag(template_id, tag_name)
                console.print(f"[green]OK[/green] Removed tag '{tag_name}'")

        session.commit()

        # Show current tags
        template = service.get_template(template_id)
        if template.tags:
            console.print(f"\nCurrent tags: {', '.join(t.name for t in template.tags)}")
        else:
            console.print("\nNo tags assigned.")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
