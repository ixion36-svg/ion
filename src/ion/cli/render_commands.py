"""Render CLI commands."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel

from ion.core.config import get_config
from ion.core.exceptions import TemplateNotFoundError, RenderError, ValidationError
from ion.storage.database import get_session, get_engine
from ion.services.render_service import RenderService
from ion.services.template_service import TemplateService

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
        from ion.engine.renderer import TemplateRenderer
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

        from ion.engine.renderer import TemplateRenderer
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


@render_app.command("validate-data")
def validate_data(
    template_id: int = typer.Argument(..., help="Template ID"),
    data: Optional[str] = typer.Option(
        None, "--data", "-d", help="JSON data string"
    ),
    data_file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="JSON data file"
    ),
) -> None:
    """Validate input data against a template's variable schema."""
    render_service, template_service, _ = get_services()

    try:
        template = template_service.get_template(template_id)

        # Parse data
        data_dict = {}
        if data:
            try:
                data_dict = json.loads(data)
            except json.JSONDecodeError as e:
                console.print(f"[red]Invalid JSON data: {e}[/red]")
                raise typer.Exit(1)
        elif data_file:
            with open(data_file, "r", encoding="utf-8") as f:
                data_dict = json.load(f)

        result = render_service.validate_data(template_id, data_dict)

        console.print(Panel(f"[bold]Validation: {template.name}[/bold]"))

        if result.is_valid:
            console.print("[green]OK[/green] Data is valid")
        else:
            console.print("[red]FAIL[/red] Validation errors:")
            for error in result.errors:
                console.print(f"  - {error.field}: {error.message}")

        if result.warnings:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in result.warnings:
                console.print(f"  - {warning}")

        if not result.is_valid:
            raise typer.Exit(1)

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)


@render_app.command("batch")
def batch_render(
    template_id: int = typer.Argument(..., help="Template ID"),
    data_file: Path = typer.Argument(..., help="CSV or JSON file with data array"),
    format: Optional[str] = typer.Option(
        None, "--format", help="Output format (markdown, html, text, docx)"
    ),
    name_field: Optional[str] = typer.Option(
        None, "--name-field", help="Field in data to use as document name"
    ),
    prefix: Optional[str] = typer.Option(
        None, "--prefix", help="Prefix for auto-generated document names"
    ),
    no_save: bool = typer.Option(
        False, "--no-save", help="Don't save document records"
    ),
    no_validate: bool = typer.Option(
        False, "--no-validate", help="Skip data validation"
    ),
    stop_on_error: bool = typer.Option(
        False, "--stop-on-error", help="Stop on first error"
    ),
) -> None:
    """Render multiple documents from a CSV or JSON file.

    For CSV files: Each row becomes a document, headers become variable names.
    For JSON files: Expects an array of objects, each object becomes a document.

    Example:
        ion render batch 1 data.csv --name-field "title"
        ion render batch 1 records.json --prefix "report"
    """
    render_service, template_service, session = get_services()

    try:
        template = template_service.get_template(template_id)

        console.print(f"[bold]Batch rendering: {template.name}[/bold]")
        console.print(f"  Data file: {data_file}")

        summary = render_service.batch_render_from_file(
            template_id=template_id,
            data_file=data_file,
            output_format=format,
            document_name_field=name_field,
            document_name_prefix=prefix,
            save_documents=not no_save,
            validate=not no_validate,
            stop_on_error=stop_on_error,
        )

        if not no_save:
            session.commit()

        # Show results
        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"  Total: {summary.total}")
        console.print(f"  [green]Successful: {summary.successful}[/green]")
        if summary.failed > 0:
            console.print(f"  [red]Failed: {summary.failed}[/red]")

        # Show details for failed items
        failed_results = [r for r in summary.results if not r.success]
        if failed_results:
            console.print(f"\n[red]Failed items:[/red]")
            for r in failed_results[:10]:  # Show first 10 failures
                console.print(f"  [{r.index}] {r.error}")
            if len(failed_results) > 10:
                console.print(f"  ... and {len(failed_results) - 10} more failures")

        # Show created documents
        if not no_save:
            created_docs = [r for r in summary.results if r.document_id]
            if created_docs:
                console.print(f"\n[green]Created documents:[/green]")
                for r in created_docs[:10]:
                    console.print(f"  [{r.document_id}] {r.document_name}")
                if len(created_docs) > 10:
                    console.print(f"  ... and {len(created_docs) - 10} more documents")

        if summary.failed > 0:
            raise typer.Exit(1)

    except TemplateNotFoundError:
        console.print(f"[red]Template {template_id} not found.[/red]")
        raise typer.Exit(1)
    except RenderError as e:
        console.print(f"[red]Render error: {e}[/red]")
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print(f"[red]Data file not found: {data_file}[/red]")
        raise typer.Exit(1)
