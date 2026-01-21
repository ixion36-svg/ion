# DocForge

Documentation Template Management System with version control, template rendering, and intelligent extraction.

## Features

- **Template Management**: Create, edit, and organize document templates
- **Version Control**: Auto-save with snapshots, named checkpoints, diff, and rollback
- **Template Rendering**: Jinja2-based rendering with JSON/CSV data support
- **Multi-format Support**: Markdown, HTML, Plain Text, DOCX
- **Template Extraction**: Pattern detection to generate templates from existing documents
- **Tagging System**: Organize templates with tags
- **Web UI**: Browser-based interface for easy management

## Installation

```bash
cd C:\Projects\docforge
pip install -e .
```

For development:
```bash
pip install -e ".[dev]"
```

## Quick Start

### Initialize DocForge

```bash
docforge init
```

### Start Web UI (Recommended)

```bash
docforge web
```

Then open http://127.0.0.1:8000 in your browser.

Options:
- `--host` / `-h`: Host to bind to (default: 127.0.0.1)
- `--port` / `-p`: Port to bind to (default: 8000)
- `--reload`: Enable auto-reload for development

### Create a Template

```bash
docforge template create --name "Welcome Email" --content "Hello {{ name }},

Welcome to {{ company }}!"
```

### Render a Template

```bash
# Preview
docforge render preview 1 --data '{"name": "John", "company": "Acme"}'

# Render to file
docforge render run 1 --data '{"name": "John", "company": "Acme"}' --output welcome.md
```

### Version Control

```bash
# List versions
docforge version list 1

# Create checkpoint
docforge version checkpoint 1 --name "v1.0" --message "First release"

# View diff
docforge version diff 1 1 2

# Rollback
docforge version rollback 1 1
```

### Extract Templates

```bash
# Analyze a document for patterns
docforge extract analyze document.docx

# Generate a template from a document
docforge extract generate document.docx --save --name "Invoice Template"
```

## CLI Commands

### Template Commands
- `docforge template create` - Create a new template
- `docforge template list` - List all templates
- `docforge template show <id>` - Show template details
- `docforge template edit <id>` - Edit a template
- `docforge template delete <id>` - Delete a template
- `docforge template search <query>` - Search templates
- `docforge template import <file>` - Import from file
- `docforge template export <id>` - Export to file
- `docforge template tag <id>` - Manage tags

### Version Commands
- `docforge version list <id>` - List versions
- `docforge version show <id> <version>` - Show version details
- `docforge version checkpoint <id>` - Create checkpoint
- `docforge version diff <id> <from> <to>` - Show diff
- `docforge version rollback <id> <to>` - Rollback to version
- `docforge version prune <id>` - Delete old versions

### Render Commands
- `docforge render preview <id>` - Preview rendered template
- `docforge render run <id>` - Render and save
- `docforge render variables <id>` - Show template variables
- `docforge render validate <id>` - Validate template syntax

### Extract Commands
- `docforge extract analyze <file>` - Analyze document patterns
- `docforge extract generate <file>` - Generate template
- `docforge extract schema <file>` - Generate JSON schema

### Document Commands
- `docforge document list` - List rendered documents
- `docforge document show <id>` - Show document details
- `docforge document regenerate <id>` - Regenerate document
- `docforge document delete <id>` - Delete document
- `docforge document export <id>` - Export document

## Template Syntax

Templates use Jinja2 syntax:

```jinja2
# Welcome, {{ name }}!

Hello {{ name | title }},

{% if department %}
You work in the {{ department }} department.
{% endif %}

Your tasks:
{% for task in tasks %}
- {{ task }}
{% endfor %}
```

## Data Files

Provide data as JSON:
```json
{
  "name": "John Doe",
  "department": "Engineering",
  "tasks": ["Review code", "Write tests"]
}
```

Or CSV:
```csv
name,email,department
John,john@example.com,Engineering
Jane,jane@example.com,Marketing
```

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=docforge --cov-report=term-missing
```

## License

MIT
