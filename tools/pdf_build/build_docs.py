"""Build ION-branded PDFs from markdown source.

Usage:
    python tools/pdf_build/build_docs.py
    python tools/pdf_build/build_docs.py --only docs/HLD.md

Pipeline per source markdown file:
    1. read .md
    2. parse front-matter-style header (ION_DOC_*) for cover-page metadata
    3. markdown -> HTML (python-markdown with tables + fenced code + toc)
    4. wrap in cover + TOC + body inside ion_pdf_template.html
    5. write rendered HTML to tools/pdf_build/_build/
    6. shell out to Chrome headless to print HTML -> PDF
    7. PDF lands next to the source .md (so docs/HLD.md -> docs/HLD.pdf;
       _mod_*.md -> _mod_*.pdf at the repo root)

Source markdown files declare metadata using HTML comments at the top
of the file. Example:

    <!-- ion-doc:type=HLD -->
    <!-- ion-doc:title=ION High-Level Design -->
    <!-- ion-doc:subtitle=Architecture, components, and deployment -->
    <!-- ion-doc:version=0.29.1 -->
    <!-- ion-doc:classification=PUBLIC -->
    <!-- ion-doc:date=2026-05-12 -->

Defaults fill in if a tag is missing.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import markdown as md

ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_DIR = Path(__file__).resolve().parent
BUILD_DIR = TEMPLATE_DIR / "_build"

CHROME_PATHS = [
    Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
    Path("C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"),
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
]

# Default doc set the builder picks up if no --only flag.
# Covers every public document that the MOD compliance pack cross-references,
# plus the design + use-case + traceability set.
DEFAULT_SOURCES = [
    # Core design docs (customer-agnostic)
    "docs/HLD.md",
    "docs/LLD.md",
    "docs/USER_REQUIREMENTS.md",
    "docs/TRACEABILITY.md",
    "docs/USE_CASES.md",
    "docs/GAPS_FILLED.md",
    "docs/ION_STACK_BRIEF.md",
    "docs/API.md",
    # Process + reference docs
    "docs/DEVELOPMENT_LIFECYCLE.md",
    "docs/ARCHITECTURE.md",
    "docs/DEPLOYMENT.md",
    "docs/RUNBOOK.md",
    "docs/AI_OUTPUT_CONTRACT.md",
    "docs/SOC_TEMPLATES.md",
    "docs/CyAB_SAL.md",
    "docs/CRYPTOGRAPHY.md",
    "docs/BACKUP_RESTORE.md",
    "docs/VULN_MGMT.md",
    "docs/CONFIG_MGMT.md",
    "docs/CAPACITY.md",
    # Root-level project docs
    "SECURITY_ASSESSMENT.md",
    "CHANGELOG.md",
    "README.md",
    "STACK.md",
    "SETUP.md",
]


def find_chrome() -> Path:
    for p in CHROME_PATHS:
        if p.exists():
            return p
    raise FileNotFoundError(
        "Chrome / Edge not found. Install Google Chrome or run on Windows 11 with Edge."
    )


META_RE = re.compile(r"<!--\s*ion-doc:([a-z_]+)\s*=\s*(.+?)\s*-->", re.IGNORECASE)


def parse_metadata(md_text: str) -> tuple[dict[str, str], str]:
    meta: dict[str, str] = {}
    consumed = 0
    for line in md_text.splitlines(keepends=True):
        match = META_RE.search(line)
        if match:
            meta[match.group(1).lower()] = match.group(2).strip()
            consumed += len(line)
        elif line.strip() == "":
            # blank line within header is allowed
            consumed += len(line)
        else:
            break
    return meta, md_text[consumed:]


def render_toc(html: str) -> str:
    headings = re.findall(
        r'<h([23])[^>]*id="([^"]+)"[^>]*>(.+?)</h\1>',
        html,
        re.DOTALL,
    )
    if not headings:
        return ""
    lines = ['<div class="ion-toc">', "<h2>Contents</h2>", "<ul>"]
    for level, anchor, title in headings:
        clean = re.sub(r"<[^>]+>", "", title).strip()
        lines.append(f'<li class="lvl-{level}"><a href="#{anchor}">{clean}</a></li>')
    lines.extend(["</ul>", "</div>"])
    return "\n".join(lines)


def cover_html(meta: dict[str, str]) -> str:
    title = meta.get("title", "ION Document")
    subtitle = meta.get("subtitle", "")
    doctype = meta.get("type", "DOCUMENT")
    version = meta.get("version", "0.29.1")
    classification = meta.get("classification", "PUBLIC")
    doc_date = meta.get("date", date.today().isoformat())
    owner = meta.get("owner", "ION Maintainer")
    audience = meta.get("audience", "Engineering / Security / Operations")
    return f"""
<section class="ion-cover">
  <header class="ion-cover-header">
    <div>
      <div class="ion-cover-logo">ION</div>
      <div class="ion-cover-logo-sub">Intelligent Operating Network</div>
    </div>
    <div class="ion-cover-classification">{classification}</div>
  </header>
  <div class="ion-cover-body">
    <div class="ion-cover-doctype">{doctype}</div>
    <h1 class="ion-cover-title">{title}</h1>
    <div class="ion-cover-subtitle">{subtitle}</div>
    <div class="ion-cover-meta">
      <div>
        <div class="ion-cover-meta-label">Document Type</div>
        <div class="ion-cover-meta-value">{doctype}</div>
      </div>
      <div>
        <div class="ion-cover-meta-label">ION Version</div>
        <div class="ion-cover-meta-value">v{version}</div>
      </div>
      <div>
        <div class="ion-cover-meta-label">Date</div>
        <div class="ion-cover-meta-value">{doc_date}</div>
      </div>
      <div>
        <div class="ion-cover-meta-label">Classification</div>
        <div class="ion-cover-meta-value">{classification}</div>
      </div>
      <div>
        <div class="ion-cover-meta-label">Owner</div>
        <div class="ion-cover-meta-value">{owner}</div>
      </div>
      <div>
        <div class="ion-cover-meta-label">Audience</div>
        <div class="ion-cover-meta-value">{audience}</div>
      </div>
    </div>
  </div>
  <footer class="ion-cover-footer">
    <span class="ion-cover-footer-brand">ION &mdash; SOC Analyst Workbench</span>
    <span>ixion36 &middot; MIT licensed</span>
  </footer>
</section>
"""


def render_html(md_text: str, css_text: str, meta: dict[str, str]) -> str:
    converter = md.Markdown(
        extensions=["extra", "fenced_code", "tables", "toc", "sane_lists"],
        extension_configs={"toc": {"permalink": False}},
    )
    body_html = converter.convert(md_text)
    toc_html = render_toc(body_html)
    cover = cover_html(meta)
    title = meta.get("title", "ION Document")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{css_text}</style>
</head>
<body>
{cover}
{toc_html}
<div class="ion-body">
{body_html}
</div>
</body>
</html>
"""


def html_to_pdf(html_path: Path, pdf_path: Path) -> None:
    chrome = find_chrome()
    # Use file:// URI; Chrome needs absolute path.
    file_uri = html_path.resolve().as_uri()
    footer_template = (
        '<div style="font-size:8px;color:#64748b;width:100%;'
        'padding:0 18mm;display:flex;justify-content:space-between;'
        'font-family:Segoe UI,Arial,sans-serif;letter-spacing:1px;">'
        '<span>ION &middot; <span class="title"></span></span>'
        '<span>Page <span class="pageNumber"></span> of '
        '<span class="totalPages"></span></span>'
        "</div>"
    )
    header_template = (
        '<div style="font-size:7px;color:#94a3b8;width:100%;'
        'padding:0 18mm;text-align:right;'
        'font-family:Segoe UI,Arial,sans-serif;letter-spacing:2px;'
        'text-transform:uppercase;">'
        "ION &mdash; <span class=\"title\"></span>"
        "</div>"
    )
    cmd = [
        str(chrome),
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",  # we use --print-to-pdf without margins
        f"--print-to-pdf={pdf_path}",
        "--virtual-time-budget=12000",
        "--run-all-compositor-stages-before-draw",
        file_uri,
    ]
    # Suppress most Chrome chatter; we just need the file.
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        sys.stderr.write(f"Chrome failed for {html_path.name}:\n{result.stderr}\n")
        raise RuntimeError(f"Chrome PDF render failed: returncode={result.returncode}")
    # 'header_template' / 'footer_template' set via flags doesn't work in
    # newer headless; we leave headers/footers off (cover page + clean body
    # is more professional than browser-default headers anyway).
    _ = (header_template, footer_template)


def build_one(md_src: Path, css_text: str) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    md_text = md_src.read_text(encoding="utf-8")
    meta, body = parse_metadata(md_text)
    meta.setdefault("title", md_src.stem.replace("_", " ").title())
    meta.setdefault("version", "0.29.1")
    html = render_html(body, css_text, meta)
    html_out = BUILD_DIR / f"{md_src.stem}.html"
    html_out.write_text(html, encoding="utf-8")
    pdf_out = md_src.with_suffix(".pdf")
    print(f"[build] {md_src.relative_to(ROOT)} -> {pdf_out.relative_to(ROOT)}")
    html_to_pdf(html_out, pdf_out)
    return pdf_out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build ION-branded PDFs from markdown.")
    parser.add_argument(
        "--only", nargs="*", default=None,
        help="Limit to specific md paths (relative to repo root).",
    )
    parser.add_argument(
        "--add-mod-set", action="store_true",
        help="Also build the _mod_*.md MOD compliance pack.",
    )
    args = parser.parse_args(argv)

    css_text = (TEMPLATE_DIR / "ion_pdf.css").read_text(encoding="utf-8")

    if args.only:
        sources = [ROOT / p for p in args.only]
    else:
        sources = [ROOT / p for p in DEFAULT_SOURCES]

    if args.add_mod_set:
        sources.extend(sorted(ROOT.glob("_mod_*.md")))

    # dedupe + filter to existing
    seen: set[Path] = set()
    todo: list[Path] = []
    for s in sources:
        if s in seen or not s.exists():
            continue
        seen.add(s)
        todo.append(s)

    if not todo:
        print("no source files found; nothing to build")
        return 1

    failed: list[str] = []
    for src in todo:
        try:
            build_one(src, css_text)
        except Exception as exc:  # pragma: no cover
            failed.append(f"{src}: {exc}")

    if failed:
        print("\nFAILURES:")
        for f in failed:
            print(f"  - {f}")
        return 2

    print(f"\nbuilt {len(todo)} PDF(s) successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
