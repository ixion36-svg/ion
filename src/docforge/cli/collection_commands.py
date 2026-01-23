"""Collection CLI commands."""

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from docforge.core.config import get_config
from docforge.core.exceptions import ValidationError
from docforge.storage.database import get_session, get_engine
from docforge.services.template_service import TemplateService, CollectionNotFoundError

collection_app = typer.Typer(help="Collection management commands")
console = Console()


def get_service():
    """Get service instance."""
    config = get_config()
    engine = get_engine(config.db_path)
    session = next(get_session(engine))
    return TemplateService(session), session


@collection_app.command("list")
def list_collections() -> None:
    """List all collections."""
    service, _ = get_service()

    collections = service.list_collections()

    if not collections:
        console.print("[yellow]No collections found.[/yellow]")
        console.print("Create one with: docforge collection create <name>")
        return

    table = Table(title="Collections")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Templates", justify="right")
    table.add_column("Icon")

    for c in collections:
        table.add_row(
            str(c.id),
            c.name,
            c.description or "-",
            str(len(c.templates)),
            c.icon or "-",
        )

    console.print(table)


@collection_app.command("create")
def create_collection(
    name: str = typer.Argument(..., help="Collection name"),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="Collection description"
    ),
    icon: Optional[str] = typer.Option(
        None, "--icon", "-i", help="Collection icon (emoji or name)"
    ),
) -> None:
    """Create a new collection."""
    service, session = get_service()

    try:
        collection = service.create_collection(
            name=name,
            description=description,
            icon=icon,
        )
        session.commit()

        console.print(f"[green]OK[/green] Created collection '{collection.name}' (ID: {collection.id})")

    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@collection_app.command("show")
def show_collection(
    collection_id: int = typer.Argument(..., help="Collection ID"),
) -> None:
    """Show collection details with its templates."""
    service, _ = get_service()

    try:
        collection = service.get_collection(collection_id)

        console.print(Panel(f"[bold]{collection.name}[/bold]", subtitle=f"ID: {collection.id}"))

        if collection.description:
            console.print(f"Description: {collection.description}")
        if collection.icon:
            console.print(f"Icon: {collection.icon}")

        console.print(f"\n[bold]Templates ({len(collection.templates)}):[/bold]")

        if collection.templates:
            table = Table()
            table.add_column("ID", style="cyan", justify="right")
            table.add_column("Name", style="bold")
            table.add_column("Format")
            table.add_column("Description")

            for t in collection.templates:
                table.add_row(
                    str(t.id),
                    t.name,
                    t.format,
                    t.description or "-",
                )
            console.print(table)
        else:
            console.print("  [dim]No templates in this collection[/dim]")

    except CollectionNotFoundError:
        console.print(f"[red]Collection {collection_id} not found.[/red]")
        raise typer.Exit(1)


@collection_app.command("update")
def update_collection(
    collection_id: int = typer.Argument(..., help="Collection ID"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="New name"),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="New description"
    ),
    icon: Optional[str] = typer.Option(None, "--icon", "-i", help="New icon"),
) -> None:
    """Update a collection."""
    service, session = get_service()

    try:
        collection = service.update_collection(
            collection_id=collection_id,
            name=name,
            description=description,
            icon=icon,
        )
        session.commit()

        console.print(f"[green]OK[/green] Updated collection '{collection.name}'")

    except CollectionNotFoundError:
        console.print(f"[red]Collection {collection_id} not found.[/red]")
        raise typer.Exit(1)
    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@collection_app.command("delete")
def delete_collection(
    collection_id: int = typer.Argument(..., help="Collection ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a collection (templates are unlinked, not deleted)."""
    service, session = get_service()

    try:
        collection = service.get_collection(collection_id)

        if not force:
            console.print(f"About to delete collection '{collection.name}'")
            console.print(f"  Templates will be unlinked, not deleted ({len(collection.templates)} templates)")
            confirm = typer.confirm("Continue?")
            if not confirm:
                console.print("[yellow]Cancelled.[/yellow]")
                raise typer.Exit(0)

        service.delete_collection(collection_id)
        session.commit()

        console.print(f"[green]OK[/green] Deleted collection '{collection.name}'")

    except CollectionNotFoundError:
        console.print(f"[red]Collection {collection_id} not found.[/red]")
        raise typer.Exit(1)


@collection_app.command("add")
def add_template(
    collection_id: int = typer.Argument(..., help="Collection ID"),
    template_id: int = typer.Argument(..., help="Template ID to add"),
) -> None:
    """Add a template to a collection."""
    service, session = get_service()

    try:
        collection = service.get_collection(collection_id)
        template = service.get_template(template_id)

        service.add_template_to_collection(template_id, collection_id)
        session.commit()

        console.print(f"[green]OK[/green] Added '{template.name}' to collection '{collection.name}'")

    except CollectionNotFoundError:
        console.print(f"[red]Collection {collection_id} not found.[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@collection_app.command("remove")
def remove_template(
    template_id: int = typer.Argument(..., help="Template ID to remove from its collection"),
) -> None:
    """Remove a template from its collection."""
    service, session = get_service()

    try:
        template = service.get_template(template_id)

        if not template.collection_id:
            console.print(f"[yellow]Template '{template.name}' is not in a collection.[/yellow]")
            raise typer.Exit(0)

        collection_name = template.collection.name if template.collection else "unknown"
        service.remove_template_from_collection(template_id)
        session.commit()

        console.print(f"[green]OK[/green] Removed '{template.name}' from collection '{collection_name}'")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
