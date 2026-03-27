"""PDF export service using WeasyPrint.

Converts documents (markdown, HTML, text) to professionally styled PDFs
with ION branding, page numbers, and metadata headers.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# CSS for print-quality PDF output
PDF_CSS = """
@page {
    size: A4;
    margin: 28mm 20mm 22mm 20mm;

    @top-left {
        content: "ION — Intelligent Operating Network";
        font-family: 'Liberation Sans', Arial, Helvetica, sans-serif;
        font-size: 7.5pt;
        color: #888;
    }
    @top-right {
        content: string(doc-title);
        font-family: 'Liberation Sans', Arial, Helvetica, sans-serif;
        font-size: 7.5pt;
        color: #888;
    }
    @bottom-left {
        content: "OFFICIAL";
        font-family: 'Liberation Sans', Arial, Helvetica, sans-serif;
        font-size: 7pt;
        color: #aaa;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Liberation Sans', Arial, Helvetica, sans-serif;
        font-size: 7.5pt;
        color: #888;
    }
}

@page :first {
    margin-top: 20mm;
    @top-left  { content: none; }
    @top-right { content: none; }
}

* { box-sizing: border-box; }

body {
    font-family: 'Liberation Sans', Arial, Helvetica, sans-serif;
    font-size: 11pt;
    line-height: 1.55;
    color: #1a1a1a;
    background: #fff;
    margin: 0;
    padding: 0;
}

/* Title element for running header */
.pdf-title {
    string-set: doc-title content();
    display: none;
}

/* Cover / header block on first page */
.pdf-header {
    border-bottom: 3px solid #0d47a1;
    padding-bottom: 16px;
    margin-bottom: 24px;
}
.pdf-header h1 {
    font-size: 22pt;
    font-weight: 700;
    color: #0d1117;
    margin: 0 0 6px 0;
    line-height: 1.2;
}
.pdf-header .pdf-subtitle {
    font-size: 10pt;
    color: #555;
    margin: 0;
}

/* Metadata table */
.pdf-meta {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 24px;
    font-size: 9.5pt;
}
.pdf-meta td {
    padding: 5px 10px;
    border: 1px solid #ddd;
    vertical-align: top;
}
.pdf-meta td:first-child {
    font-weight: 600;
    color: #333;
    width: 140px;
    background: #f7f8fa;
}

/* Headings */
h1 { font-size: 18pt; color: #0d1117; margin: 28px 0 10px; border-bottom: 2px solid #e1e4e8; padding-bottom: 6px; }
h2 { font-size: 15pt; color: #1a2332; margin: 24px 0 8px; border-bottom: 1px solid #eee; padding-bottom: 4px; }
h3 { font-size: 13pt; color: #24292e; margin: 20px 0 6px; }
h4 { font-size: 11.5pt; color: #333; margin: 16px 0 4px; }
h5, h6 { font-size: 11pt; color: #444; margin: 12px 0 4px; }

p { margin: 0 0 10px; }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 14px 0;
    font-size: 10pt;
    page-break-inside: auto;
}
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
th {
    background: #0d1117;
    color: #fff;
    font-weight: 600;
    padding: 8px 10px;
    text-align: left;
    border: 1px solid #0d1117;
}
td {
    padding: 6px 10px;
    border: 1px solid #ddd;
    vertical-align: top;
}
tr:nth-child(even) td { background: #f7f8fa; }

/* Code */
code {
    font-family: 'Liberation Mono', 'Courier New', monospace;
    font-size: 9pt;
    background: #f0f2f5;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid #e1e4e8;
}
pre {
    background: #f5f7fa;
    border: 1px solid #d0d7de;
    border-radius: 4px;
    padding: 12px;
    font-family: 'Liberation Mono', 'Courier New', monospace;
    font-size: 9pt;
    line-height: 1.45;
    overflow-wrap: break-word;
    white-space: pre-wrap;
    page-break-inside: avoid;
    margin: 12px 0;
}
pre code {
    background: none;
    border: none;
    padding: 0;
}

/* Lists */
ul, ol { margin: 6px 0 10px 20px; padding: 0; }
li { margin-bottom: 3px; }

/* Blockquotes */
blockquote {
    border-left: 4px solid #0d47a1;
    margin: 12px 0;
    padding: 8px 16px;
    background: #f0f4ff;
    color: #333;
    font-style: italic;
}
blockquote p { margin: 0; }

/* Links */
a { color: #0d47a1; text-decoration: none; }

/* Horizontal rules */
hr {
    border: none;
    border-top: 1px solid #d0d7de;
    margin: 20px 0;
}

/* Images */
img { max-width: 100%; height: auto; }
"""


def _content_to_html(content: str, output_format: str) -> str:
    """Convert document content to HTML based on its format."""
    if output_format == "html":
        return content

    if output_format == "markdown":
        import markdown
        return markdown.markdown(
            content,
            extensions=["tables", "fenced_code", "codehilite", "toc", "nl2br"],
        )

    if output_format == "csv":
        import csv
        import html
        import io
        rows = list(csv.reader(io.StringIO(content)))
        if not rows:
            return "<p>Empty CSV</p>"
        table = '<table>\n<thead><tr>'
        for cell in rows[0]:
            table += f'<th>{html.escape(cell)}</th>'
        table += '</tr></thead>\n<tbody>'
        for row in rows[1:]:
            table += '<tr>'
            for cell in row:
                table += f'<td>{html.escape(cell)}</td>'
            table += '</tr>\n'
        table += '</tbody></table>'
        return table

    # text / anything else — wrap in pre
    import html as html_mod
    return f"<pre>{html_mod.escape(content)}</pre>"


def _build_pdf_html(
    body_html: str,
    title: str,
    metadata: dict | None = None,
) -> str:
    """Build the full HTML document for WeasyPrint rendering."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    meta_rows = ""
    if metadata:
        for key, val in metadata.items():
            if val:
                meta_rows += f"<tr><td>{key}</td><td>{val}</td></tr>\n"

    meta_table = ""
    if meta_rows:
        meta_table = f'<table class="pdf-meta">{meta_rows}</table>'

    import html as html_mod
    safe_title = html_mod.escape(title)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>{PDF_CSS}</style>
</head>
<body>
<span class="pdf-title">{safe_title}</span>

<div class="pdf-header">
    <h1 style="border:none; margin:0; padding:0;">{safe_title}</h1>
    <p class="pdf-subtitle">Generated {now} &mdash; ION &bull; Intelligent Operating Network</p>
</div>

{meta_table}

{body_html}

</body>
</html>"""


def generate_pdf(
    html_content: str,
    title: str = "Document",
    metadata: dict | None = None,
) -> bytes:
    """Generate a PDF from HTML content.

    Args:
        html_content: The body HTML to render.
        title: Document title (used in header and running header).
        metadata: Optional dict of key-value pairs for the metadata table.

    Returns:
        PDF file contents as bytes.

    Raises:
        RuntimeError: If WeasyPrint is not available.
    """
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "PDF generation requires WeasyPrint and its system dependencies "
            "(Pango, Cairo, GDK-Pixbuf). Install them or use the Docker image."
        ) from exc

    full_html = _build_pdf_html(html_content, title, metadata)
    return HTML(string=full_html).write_pdf()


def document_to_pdf(document) -> bytes:
    """Generate a PDF from a Document model instance.

    Converts the document's content to HTML, then renders to PDF
    with metadata from the document record.
    """
    body_html = _content_to_html(
        document.rendered_content or "",
        document.output_format or "text",
    )

    metadata = {
        "Document": document.name,
        "Version": str(document.current_version) if document.current_version else "1",
        "Format": (document.output_format or "text").title(),
    }
    if document.source_template:
        metadata["Template"] = document.source_template.name
    if document.created_at:
        metadata["Created"] = document.created_at.strftime("%Y-%m-%d %H:%M")

    return generate_pdf(body_html, title=document.name, metadata=metadata)
