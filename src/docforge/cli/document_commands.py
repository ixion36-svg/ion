"""Document management CLI commands."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

from docforge.core.config import get_config
from docforge.core.exceptions import RenderError
from docforge.storage.database import get_session, get_engine
from docforge.services.render_service import RenderService

document_app = typer.Typer(help="Document management commands")
console = Console()


def get_service():
    """Get service instance."""
    config = get_config()
    engine = get_engine(config.db_path)
    session = next(get_session(engine))
    return RenderService(session), session


@document_app.command("list")
def list_documents(
    template_id: Optional[int] = typer.Option(
        None, "--template", "-t", help="Filter by source template ID"
    ),
    format: Optional[str] = typer.Option(
        None, "--format", "-f", help="Filter by output format"
    ),
) -> None:
    """List all rendered documents."""
    service, _ = get_service()

    documents = service.list_documents(template_id=template_id, output_format=format)

    if not documents:
        console.print("[yellow]No documents found.[/yellow]")
        return

    table = Table(title="Documents")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Name", style="green")
    table.add_column("Format", style="blue")
    table.add_column("Template ID", justify="right")
    table.add_column("Version", justify="right")
    table.add_column("Created")

    for doc in documents:
        table.add_row(
            str(doc.id),
            doc.name,
            doc.output_format,
            str(doc.source_template_id) if doc.source_template_id else "-",
            str(doc.source_template_version) if doc.source_template_version else "-",
            doc.created_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


@document_app.command("show")
def show_document(
    document_id: int = typer.Argument(..., help="Document ID"),
    content: bool = typer.Option(False, "--content", "-c", help="Show full content"),
    data: bool = typer.Option(False, "--data", "-d", help="Show input data"),
) -> None:
    """Show document details."""
    service, _ = get_service()

    document = service.get_document(document_id)

    if not document:
        console.print(f"[red]Document {document_id} not found.[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"[bold]{document.name}[/bold]", subtitle=f"ID: {document.id}"))
    console.print(f"  Format: {document.output_format}")

    if document.source_template_id:
        console.print(
            f"  Source: Template {document.source_template_id} "
            f"(v{document.source_template_version})"
        )

    if document.output_path:
        console.print(f"  Output path: {document.output_path}")

    console.print(f"  Created: {document.created_at.strftime('%Y-%m-%d %H:%M')}")
    console.print(f"  Updated: {document.updated_at.strftime('%Y-%m-%d %H:%M')}")

    if data and document.input_data:
        console.print("\n[bold]Input Data:[/bold]")
        try:
            parsed_data = json.loads(document.input_data)
            data_json = json.dumps(parsed_data, indent=2)
            syntax = Syntax(data_json, "json", theme="monokai")
            console.print(syntax)
        except json.JSONDecodeError:
            console.print(document.input_data)

    if content:
        console.print("\n[bold]Content:[/bold]")
        syntax_map = {
            "markdown": "markdown",
            "html": "html",
            "text": "text",
        }
        syntax_lang = syntax_map.get(document.output_format, "text")
        syntax = Syntax(document.rendered_content, syntax_lang, theme="monokai")
        console.print(syntax)


@document_app.command("regenerate")
def regenerate(
    document_id: int = typer.Argument(..., help="Document ID"),
    data: Optional[str] = typer.Option(
        None, "--data", "-d", help="New JSON data string"
    ),
    data_file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="New JSON data file"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="New output file path"
    ),
) -> None:
    """Regenerate a document with updated data or template."""
    service, session = get_service()

    document = service.get_document(document_id)

    if not document:
        console.print(f"[red]Document {document_id} not found.[/red]")
        raise typer.Exit(1)

    # Parse inline data
    data_dict = None
    if data:
        try:
            data_dict = json.loads(data)
        except json.JSONDecodeError as e:
            console.print(f"[red]Invalid JSON data: {e}[/red]")
            raise typer.Exit(1)
    elif data_file:
        if not data_file.exists():
            console.print(f"[red]File not found: {data_file}[/red]")
            raise typer.Exit(1)
        from docforge.engine.data_loader import DataLoader
        loader = DataLoader()
        data_dict = loader.load(data_file)

    try:
        updated = service.regenerate_document(
            document_id,
            data=data_dict,
            output_path=output,
        )
        session.commit()

        console.print(f"[green]OK[/green] Regenerated document '{updated.name}'")

        if updated.output_path:
            console.print(f"  Output: {updated.output_path}")

    except RenderError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@document_app.command("delete")
def delete_document(
    document_id: int = typer.Argument(..., help="Document ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a document record."""
    service, session = get_service()

    document = service.get_document(document_id)

    if not document:
        console.print(f"[red]Document {document_id} not found.[/red]")
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"Delete document '{document.name}'?")
        if not confirm:
            console.print("Cancelled.")
            return

    service.delete_document(document_id)
    session.commit()

    console.print(f"[green]OK[/green] Deleted document '{document.name}'")


@document_app.command("export")
def export_document(
    document_id: int = typer.Argument(..., help="Document ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
) -> None:
    """Export document content to a file."""
    service, _ = get_service()

    document = service.get_document(document_id)

    if not document:
        console.print(f"[red]Document {document_id} not found.[/red]")
        raise typer.Exit(1)

    # Write using plugin
    from docforge.plugins import PluginRegistry

    registry = PluginRegistry()
    plugin = registry.get_plugin_for_file(output)

    if plugin:
        plugin.write(document.rendered_content, output)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document.rendered_content, encoding="utf-8")

    console.print(f"[green]OK[/green] Exported document to {output}")
