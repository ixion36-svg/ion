"""Render CLI commands."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel

from docforge.core.config import get_config
from docforge.core.exceptions import TemplateNotFoundError, RenderError, ValidationError
from docforge.storage.database import get_session, get_engine
from docforge.services.render_service import RenderService
from docforge.services.template_service import TemplateService

render_app = typer.Typer(help="Template rendering commands")
console = Console()


def get_services():
    """Get service instances."""
    config = get_config()
    engine = get_engine(config.db_path)
    session = next(get_session(engine))
    return RenderService(session), TemplateService(session), session


@render_app.command("preview")
def preview(
    template_id: int = typer.Argument(..., help="Template ID"),
    data: Optional[str] = typer.Option(
        None, "--data", "-d", help="JSON data string"
    ),
    data_file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="JSON or CSV data file"
    ),
) -> None:
    """Preview rendered template without saving."""
    render_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)

        # Parse inline data
        data_dict = None
        if data:
            try:
                data_dict = json.loads(data)
            except json.JSONDecodeError as e:
                console.print(f"[red]Invalid JSON data: {e}[/red]")
                raise typer.Exit(1)

        rendered = render_service.preview(
            template_id,
            data=data_dict,
            data_file=data_file,
        )

        console.print(Panel(
            f"[bold]Preview: {template.name}[/bold]",
            subtitle=f"Format: {template.format}"
        ))
        console.print()

        # Display with syntax highlighting based on format
        syntax_map = {
            "markdown": "markdown",
            "html": "html",
            "text": "text",
        }
        syntax_lang = syntax_map.get(template.format, "text")
        syntax = Syntax(rendered, syntax_lang, theme="monokai")
        console.print(syntax)

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except RenderError as e:
        console.print(f"[red]Render error: {e}[/red]")
        raise typer.Exit(1)
    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@render_app.command("run")
def run(
    template_id: int = typer.Argument(..., help="Template ID"),
    data: Optional[str] = typer.Option(
        None, "--data", "-d", help="JSON data string"
    ),
    data_file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="JSON or CSV data file"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    format: Optional[str] = typer.Option(
        None, "--format", help="Output format (markdown, html, text, docx)"
    ),
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Document name for saved record"
    ),
    no_save: bool = typer.Option(
        False, "--no-save", help="Don't save document record"
    ),
) -> None:
    """Render a template and optionally save to file."""
    render_service, template_service, session = get_services()

    try:
        template = template_service.get_template(template_id)

        # Parse inline data
        data_dict = None
        if data:
            try:
                data_dict = json.loads(data)
            except json.JSONDecodeError as e:
                console.print(f"[red]Invalid JSON data: {e}[/red]")
                raise typer.Exit(1)

        rendered, document = render_service.render(
            template_id,
            data=data_dict,
            data_file=data_file,
            output_format=format,
            output_path=output,
            document_name=name,
            save_document=not no_save,
        )

        if not no_save:
            session.commit()

        # Show result
        if output:
            console.print(f"[green]OK[/green] Rendered to {output}")
        else:
            console.print(rendered)

        if document:
            console.print(f"\n[dim]Document ID: {document.id}[/dim]")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except RenderError as e:
        console.print(f"[red]Render error: {e}[/red]")
        raise typer.Exit(1)
    except ValidationError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@render_app.command("variables")
def show_variables(
    template_id: int = typer.Argument(..., help="Template ID"),
) -> None:
    """Show variables used in a template."""
    render_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)

        # Extract variables from content
        from docforge.engine.renderer import TemplateRenderer
        renderer = TemplateRenderer()
        variables = renderer.extract_variables(template.content)

        console.print(Panel(f"[bold]Variables in '{template.name}'[/bold]"))

        if not variables:
            console.print("[yellow]No variables found in template.[/yellow]")
            return

        # Show defined variables
        defined_vars = {v.name: v for v in template.variables}

        for var_name in sorted(variables):
            if var_name in defined_vars:
                var = defined_vars[var_name]
                req = "[red]*[/red]" if var.required else ""
                default = f" = {var.default_value}" if var.default_value else ""
                console.print(f"  {var_name}{req} ({var.var_type}){default}")
            else:
                console.print(f"  {var_name} [dim](not defined)[/dim]")

        console.print(f"\n[dim]Total: {len(variables)} variables[/dim]")

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)


@render_app.command("validate")
def validate(
    template_id: int = typer.Argument(..., help="Template ID"),
) -> None:
    """Validate template syntax."""
    render_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)

        from docforge.engine.renderer import TemplateRenderer
        renderer = TemplateRenderer()
        valid, error = renderer.validate(template.content)

        if valid:
            console.print(f"[green]OK[/green] Template '{template.name}' is valid")
        else:
            console.print(f"[red]FAIL[/red] Template '{template.name}' has errors:")
            console.print(f"  {error}")
            raise typer.Exit(1)

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
