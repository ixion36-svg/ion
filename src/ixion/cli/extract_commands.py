"""Template extraction CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

from ixion.core.config import get_config
from ixion.core.exceptions import ValidationError
from ixion.storage.database import get_session, get_engine
from ixion.services.template_service import TemplateService
from ixion.extraction.template_generator import TemplateGenerator

extract_app = typer.Typer(help="Template extraction commands")
console = Console()


def get_service():
    """Get service instance."""
    config = get_config()
    engine = get_engine(config.db_path)
    session = next(get_session(engine))
    return TemplateService(session), session


@extract_app.command("analyze")
def analyze(
    file: Path = typer.Argument(..., help="File to analyze"),
    confidence: float = typer.Option(
        0.5, "--confidence", "-c", help="Minimum confidence threshold (0-1)"
    ),
    show_content: bool = typer.Option(
        False, "--content", help="Show file content with highlighted patterns"
    ),
    no_nlp: bool = typer.Option(
        False, "--no-nlp", help="Disable NLP-based detection (use regex only)"
    ),
) -> None:
    """Analyze a document for patterns that could become template variables.

    By default, uses both regex patterns and NLP-based entity recognition.
    Use --no-nlp to disable NLP and use regex patterns only.
    """
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    use_nlp = not no_nlp
    generator = TemplateGenerator(use_nlp=use_nlp)

    # Show NLP status
    if use_nlp:
        if generator.nlp_available:
            console.print("[green]NLP detection enabled[/green]")
        else:
            console.print("[yellow]NLP not available (install spaCy). Using regex only.[/yellow]")
    else:
        console.print("[dim]NLP detection disabled (--no-nlp)[/dim]")

    try:
        matches, variables, content, stats = generator.analyze_file(file, confidence)

        console.print(Panel(f"[bold]Analysis of {file.name}[/bold]"))

        if not matches:
            console.print(
                f"[yellow]No patterns detected with confidence >= {confidence}[/yellow]"
            )
            return

        # Show detected patterns
        console.print(f"\n[bold]Detected Patterns ({len(matches)}):[/bold]")
        table = Table()
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Confidence", justify="right")
        table.add_column("Suggested Variable")

        for match in matches:
            value = match.value[:40] + "..." if len(match.value) > 40 else match.value
            table.add_row(
                match.pattern_type,
                value,
                f"{match.confidence:.0%}",
                match.suggested_name,
            )

        console.print(table)

        # Show inferred variables
        if variables:
            console.print(f"\n[bold]Inferred Variables ({len(variables)}):[/bold]")
            var_table = Table()
            var_table.add_column("Name", style="green")
            var_table.add_column("Type", style="blue")
            var_table.add_column("Occurrences", justify="right")
            var_table.add_column("Confidence", justify="right")
            var_table.add_column("Sample Values")

            for var in variables:
                samples = ", ".join(var.sample_values[:2])
                if len(var.sample_values) > 2:
                    samples += "..."
                var_table.add_row(
                    var.name,
                    var.var_type,
                    str(var.occurrences),
                    f"{var.confidence:.0%}",
                    samples,
                )

            console.print(var_table)

        if show_content:
            console.print("\n[bold]Content:[/bold]")
            # Highlight matches in content (simplified)
            console.print(content[:2000])
            if len(content) > 2000:
                console.print(f"\n[dim]... ({len(content)} total characters)[/dim]")

    except Exception as e:
        console.print(f"[red]Error analyzing file: {e}[/red]")
        raise typer.Exit(1)


@extract_app.command("generate")
def generate(
    file: Path = typer.Argument(..., help="File to generate template from"),
    confidence: float = typer.Option(
        0.7, "--confidence", "-c", help="Minimum confidence threshold (0-1)"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for generated template"
    ),
    save: bool = typer.Option(
        False, "--save", "-s", help="Save as a new template in database"
    ),
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Template name (for --save)"
    ),
    format: Optional[str] = typer.Option(
        None, "--format", help="Template format"
    ),
    no_nlp: bool = typer.Option(
        False, "--no-nlp", help="Disable NLP-based detection (use regex only)"
    ),
) -> None:
    """Generate a template from a document.

    By default, uses both regex patterns and NLP-based entity recognition.
    Use --no-nlp to disable NLP and use regex patterns only.
    """
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    use_nlp = not no_nlp
    generator = TemplateGenerator(use_nlp=use_nlp)

    # Show NLP status
    if use_nlp:
        if generator.nlp_available:
            console.print("[green]NLP detection enabled[/green]")
        else:
            console.print("[yellow]NLP not available (install spaCy). Using regex only.[/yellow]")
    else:
        console.print("[dim]NLP detection disabled (--no-nlp)[/dim]")

    try:
        result = generator.generate_from_file(file, confidence)

        console.print(Panel(f"[bold]Generated Template from {file.name}[/bold]"))
        console.print(f"  Replacements made: {result.replacements_made}")
        console.print(f"  Variables detected: {len(result.variables)}")

        if result.variables:
            console.print("\n[bold]Variables:[/bold]")
            for var in result.variables:
                console.print(f"  - {var.name} ({var.var_type})")

        # Show generated template
        console.print("\n[bold]Generated Template:[/bold]")
        syntax = Syntax(result.content, "jinja2", theme="monokai", line_numbers=True)
        console.print(syntax)

        # Write to output file
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(result.content, encoding="utf-8")
            console.print(f"\n[green]OK[/green] Saved to {output}")

        # Save to database
        if save:
            template_name = name or file.stem + "_template"

            # Determine format
            if format is None:
                ext_map = {".md": "markdown", ".html": "html", ".txt": "text", ".docx": "docx"}
                format = ext_map.get(file.suffix.lower(), "text")

            service, session = get_service()

            try:
                template = service.create_template(
                    name=template_name,
                    content=result.content,
                    format=format,
                )

                # Set variables
                var_dicts = [
                    {
                        "name": v.name,
                        "var_type": v.var_type,
                        "required": v.confidence >= 0.8,
                    }
                    for v in result.variables
                ]
                service.set_variables(template.id, var_dicts)

                session.commit()

                console.print(
                    f"\n[green]OK[/green] Saved as template '{template_name}' "
                    f"(ID: {template.id})"
                )

            except ValidationError as e:
                console.print(f"[red]Error saving template: {e}[/red]")
                raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error generating template: {e}[/red]")
        raise typer.Exit(1)


@extract_app.command("schema")
def generate_schema(
    file: Path = typer.Argument(..., help="File to analyze"),
    confidence: float = typer.Option(
        0.7, "--confidence", "-c", help="Minimum confidence threshold"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for JSON schema"
    ),
    no_nlp: bool = typer.Option(
        False, "--no-nlp", help="Disable NLP-based detection (use regex only)"
    ),
) -> None:
    """Generate a JSON schema for inferred variables.

    By default, uses both regex patterns and NLP-based entity recognition.
    Use --no-nlp to disable NLP and use regex patterns only.
    """
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    use_nlp = not no_nlp
    generator = TemplateGenerator(use_nlp=use_nlp)

    # Show NLP status
    if use_nlp:
        if generator.nlp_available:
            console.print("[green]NLP detection enabled[/green]")
        else:
            console.print("[yellow]NLP not available (install spaCy). Using regex only.[/yellow]")
    else:
        console.print("[dim]NLP detection disabled (--no-nlp)[/dim]")

    try:
        matches, variables, _, stats = generator.analyze_file(file, confidence)

        from ixion.extraction.variable_inferrer import VariableInferrer
        inferrer = VariableInferrer()
        schema = inferrer.to_schema(variables)

        import json
        schema_json = json.dumps(schema, indent=2)

        console.print(Panel("[bold]Generated JSON Schema[/bold]"))
        syntax = Syntax(schema_json, "json", theme="monokai")
        console.print(syntax)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(schema_json, encoding="utf-8")
            console.print(f"\n[green]OK[/green] Saved to {output}")

    except Exception as e:
        console.print(f"[red]Error generating schema: {e}[/red]")
        raise typer.Exit(1)
