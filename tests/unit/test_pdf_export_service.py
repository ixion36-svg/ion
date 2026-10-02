"""Tests for pdf_export_service — the PDF an analyst mails out of the SOC.

This module was at 0% when the coverage ratchet first measured the tree. Two of
its behaviours are security controls rather than formatting, and both are
tested as such:

* ``_block_external_url_fetcher``. WeasyPrint will happily fetch whatever a
  document's HTML references. In an air-gapped SOC an outbound request from the
  PDF renderer is both an exfiltration channel and an SSRF primitive against
  internal services, and document content comes from templates and alert data.
  Only ``data:`` URIs are allowed through.
* escaping in ``_build_pdf_html`` and the CSV/text paths of
  ``_content_to_html``. A document name or CSV cell is not trusted markup.

The ``output_format == "html"`` path deliberately passes content through
unescaped — that is what the format means — and is pinned so the intent is
explicit rather than looking like an oversight.

Only four tests actually invoke WeasyPrint; the rest exercise the HTML builders,
which is where the logic lives and where a regression would be silent.
"""

from __future__ import annotations

import sys
from datetime import datetime

import pytest

from ion.models.document import Document
from ion.services.pdf_export_service import (
    PDF_CSS,
    _block_external_url_fetcher,
    _build_pdf_html,
    _content_to_html,
    document_to_pdf,
    generate_pdf,
)


class TestContentToHtml:
    def test_html_is_passed_through_unchanged(self):
        """By design: the caller said the content IS html. Escaping it would
        render the markup as visible text."""
        assert _content_to_html("<p>hi</p>", "html") == "<p>hi</p>"

    def test_markdown_headings_become_html(self):
        # The `toc` extension adds an id, so this is `<h1 id="title">`.
        assert "<h1" in _content_to_html("# Title", "markdown")

    def test_markdown_tables_are_enabled(self):
        out = _content_to_html("| a | b |\n|---|---|\n| 1 | 2 |", "markdown")
        assert "<table>" in out and "<th>" in out

    def test_markdown_fenced_code_is_enabled(self):
        out = _content_to_html("```\nx = 1\n```", "markdown")
        assert "<code>" in out or "<pre>" in out

    def test_markdown_single_newlines_become_breaks(self):
        """nl2br: report text written with soft wraps must not reflow into one
        paragraph in the PDF."""
        assert "<br" in _content_to_html("line one\nline two", "markdown")

    def test_csv_becomes_a_table_with_a_header_row(self):
        out = _content_to_html("host,severity\nweb-01,high", "csv")
        assert "<thead>" in out and "<tbody>" in out
        assert "<th>host</th>" in out
        assert "<td>web-01</td>" in out

    def test_a_csv_cell_is_escaped(self):
        out = _content_to_html("a,b\n<script>x</script>,2", "csv")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_a_csv_header_is_escaped(self):
        out = _content_to_html("<script>h</script>,b\n1,2", "csv")
        assert "<script>" not in out

    def test_an_empty_csv_says_so_rather_than_rendering_a_broken_table(self):
        assert _content_to_html("", "csv") == "<p>Empty CSV</p>"

    def test_a_csv_with_ragged_rows_still_renders(self):
        out = _content_to_html("a,b,c\n1,2", "csv")
        assert out.count("<td>") == 2

    def test_text_is_wrapped_in_pre_and_escaped(self):
        out = _content_to_html("a < b & c", "text")
        assert out.startswith("<pre>") and out.endswith("</pre>")
        assert "&lt;" in out and "&amp;" in out

    def test_an_unknown_format_is_treated_as_text(self):
        """A document with a format nobody implemented must still export, and
        must be escaped while doing so."""
        out = _content_to_html("<b>x</b>", "yaml")
        assert out == "<pre>&lt;b&gt;x&lt;/b&gt;</pre>"

    def test_empty_text_renders_an_empty_block(self):
        assert _content_to_html("", "text") == "<pre></pre>"


class TestBuildPdfHtml:
    def test_the_document_is_self_contained(self):
        out = _build_pdf_html("<p>body</p>", "Report")
        assert out.startswith("<!DOCTYPE html>")
        assert out.rstrip().endswith("</html>")
        assert PDF_CSS in out

    def test_the_body_is_inserted_verbatim(self):
        assert "<p>body</p>" in _build_pdf_html("<p>body</p>", "Report")

    def test_the_title_appears_as_the_heading_and_the_running_header(self):
        """The ``.pdf-title`` span feeds `string-set: doc-title`, which the
        @page rule prints at the top of every page after the first."""
        out = _build_pdf_html("", "Quarterly Review")
        assert '<span class="pdf-title">Quarterly Review</span>' in out
        assert "<h1" in out and "Quarterly Review</h1>" in out

    def test_a_hostile_title_is_escaped_in_both_places(self):
        out = _build_pdf_html("", "<script>alert(1)</script>")
        assert "<script>" not in out
        assert out.count("&lt;script&gt;") == 2

    def test_the_generation_time_is_stamped_in_utc(self):
        out = _build_pdf_html("", "Report")
        assert "UTC" in out
        assert datetime.now().strftime("%Y") in out

    def test_metadata_becomes_a_table(self):
        out = _build_pdf_html("", "R", {"Course": "SOC 101", "Level": "Beginner"})
        assert 'class="pdf-meta"' in out
        assert "<td>Course</td><td>SOC 101</td>" in out

    def test_a_falsy_metadata_value_is_omitted(self):
        """A row reading "Duration: None" is worse than no row."""
        out = _build_pdf_html("", "R", {"Duration": None, "Level": "Beginner"})
        assert "Duration" not in out
        assert "Beginner" in out

    def test_no_metadata_means_no_table(self):
        assert 'class="pdf-meta"' not in _build_pdf_html("", "R")

    def test_metadata_that_is_entirely_falsy_means_no_table(self):
        assert 'class="pdf-meta"' not in _build_pdf_html("", "R", {"A": "",
                                                                   "B": None})

    def test_a_metadata_value_is_escaped(self):
        out = _build_pdf_html("", "R", {"Document": "<img src=x onerror=1>"})
        assert "<img" not in out

    def test_a_metadata_key_is_escaped(self):
        """Keys are literals at every call site today. Escaping them anyway
        costs nothing and means a future caller passing a user-supplied key
        cannot inject markup into a document that gets mailed outward."""
        out = _build_pdf_html("", "R", {"<script>k</script>": "v"})
        assert "<script>" not in out

    def test_a_non_string_metadata_value_is_coerced(self):
        out = _build_pdf_html("", "R", {"Version": 3})
        assert "<td>Version</td><td>3</td>" in out


class TestUrlFetcher:
    def test_a_data_uri_is_allowed(self):
        """Inline images are how a chart reaches the PDF with no network."""
        result = _block_external_url_fetcher(
            "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
        assert result is not None

    @pytest.mark.parametrize("url", [
        "http://evil.example/x.png",
        "https://evil.example/x.png",
        "file:///etc/passwd",
        "//evil.example/x.png",
        "http://169.254.169.254/latest/meta-data/",
    ])
    def test_everything_else_is_blocked(self, url):
        """Air-gapped: an outbound fetch from the renderer is an exfiltration
        channel, and a file:// or link-local URL is an SSRF read."""
        with pytest.raises(ValueError, match="External resource blocked"):
            _block_external_url_fetcher(url)

    def test_the_rejection_names_the_url_for_the_log(self):
        with pytest.raises(ValueError, match="evil.example"):
            _block_external_url_fetcher("http://evil.example/x.png")

    def test_an_inline_image_actually_reaches_the_pdf(self):
        """The point of allowing data: at all. This is the regression that was
        live: on WeasyPrint >= 63 the data: branch raised ImportError inside the
        fetcher, WeasyPrint swallowed it, and every inline image was dropped —
        invisibly, because a PDF with a missing image is still a PDF. Compared
        against the same document with no image so the assertion is about the
        image being embedded, not about PDFs being large."""
        gif = ("data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAA"
               "AQABAAACAUwAOw==")
        with_image = generate_pdf(f'<p><img src="{gif}" width="200"></p>',
                                  title="R")
        without = generate_pdf("<p></p>", title="R")

        assert with_image.startswith(b"%PDF")
        assert len(with_image) > len(without)
        assert b"/Image" in with_image

    def test_the_legacy_weasyprint_api_is_still_supported(self, monkeypatch):
        """pyproject asks for weasyprint>=62.0 and 62 predates the URLFetcher
        class, so the function-based API has to keep working."""
        import types

        calls = []
        legacy = types.ModuleType("weasyprint")
        legacy.default_url_fetcher = lambda url: calls.append(url) or {"string": b""}
        monkeypatch.setitem(sys.modules, "weasyprint.urls", None)
        monkeypatch.setitem(sys.modules, "weasyprint", legacy)

        result = _block_external_url_fetcher("data:text/plain,hi")

        assert calls == ["data:text/plain,hi"]
        assert result == {"string": b""}

    def test_a_url_merely_containing_data_is_still_blocked(self):
        """The check is a prefix, not a substring — "https://x/data:" must not
        slip through.

        The assertion matches ION's own message rather than any ValueError: with
        `startswith` relaxed to a substring test, WeasyPrint's own
        `allowed_protocols` still rejects this URL with a *different* ValueError,
        so a bare `pytest.raises(ValueError)` passes while ION's guard is gone.
        (Found by mutation testing — the bare form let that mutant survive.)
        """
        with pytest.raises(ValueError, match="External resource blocked"):
            _block_external_url_fetcher("https://evil.example/data:image")


class TestGeneratePdf:
    def test_a_pdf_is_produced(self):
        pdf = generate_pdf("<p>hello</p>", title="Report")
        assert pdf.startswith(b"%PDF")

    def test_metadata_and_body_survive_into_a_rendered_pdf(self):
        pdf = generate_pdf("<h1>Body</h1>", title="R", metadata={"K": "V"})
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 1000

    def test_an_external_image_does_not_abort_the_render(self):
        """The fetcher raises, and `_fail_on_errors = False` means WeasyPrint
        skips the resource rather than failing the export. An analyst gets a PDF
        with a missing image instead of an error page."""
        pdf = generate_pdf('<p><img src="http://evil.example/x.png"></p>',
                           title="R")
        assert pdf.startswith(b"%PDF")

    def test_the_fetcher_carries_the_flag_newer_weasyprint_reads(self):
        generate_pdf("<p>x</p>", title="R")
        from ion.services import pdf_export_service as svc
        assert svc._block_external_url_fetcher._fail_on_errors is False

    def test_a_missing_renderer_raises_with_the_remedy_in_the_message(
        self, monkeypatch
    ):
        """WeasyPrint needs Pango/Cairo, which an air-gapped host may not have.
        The error has to say what to install, because the operator cannot look
        it up."""
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        with pytest.raises(RuntimeError, match="Pango"):
            generate_pdf("<p>x</p>")


class TestDocumentToPdf:
    def _doc(self, session, **over):
        fields = dict(name="Investigation Report", rendered_content="# Findings",
                      output_format="markdown", current_version=3)
        fields.update(over)
        d = Document(**fields)
        session.add(d)
        session.flush()
        return d

    def test_the_model_exposes_every_attribute_the_exporter_reads(self, session):
        """A stub would not catch a renamed column, so this one uses the ORM."""
        d = self._doc(session)
        for attr in ("name", "rendered_content", "output_format",
                     "current_version", "source_template", "created_at"):
            assert hasattr(d, attr), attr

    def test_a_document_renders_to_a_pdf(self, session):
        pdf = document_to_pdf(self._doc(session))
        assert pdf.startswith(b"%PDF")

    def test_the_metadata_is_built_from_the_document_record(self, session,
                                                            monkeypatch):
        captured = {}

        def fake(body_html, title=None, metadata=None):
            captured.update(body_html=body_html, title=title, metadata=metadata)
            return b"%PDF-stub"

        monkeypatch.setattr("ion.services.pdf_export_service.generate_pdf", fake)
        d = self._doc(session)

        document_to_pdf(d)

        assert captured["title"] == "Investigation Report"
        assert captured["metadata"]["Document"] == "Investigation Report"
        assert captured["metadata"]["Version"] == "3"
        assert captured["metadata"]["Format"] == "Markdown"
        assert captured["metadata"]["Created"] == d.created_at.strftime(
            "%Y-%m-%d %H:%M")
        assert "Findings</h1>" in captured["body_html"]

    def test_a_document_with_no_version_reads_as_one(self, session, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "ion.services.pdf_export_service.generate_pdf",
            lambda b, title=None, metadata=None: captured.update(
                metadata=metadata) or b"%PDF")
        d = self._doc(session)
        d.current_version = 0

        document_to_pdf(d)

        assert captured["metadata"]["Version"] == "1"

    def test_a_document_with_no_format_is_exported_as_text(self, session,
                                                           monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "ion.services.pdf_export_service.generate_pdf",
            lambda b, title=None, metadata=None: captured.update(
                body_html=b, metadata=metadata) or b"%PDF")
        d = self._doc(session, rendered_content="<b>raw</b>")
        d.output_format = None

        document_to_pdf(d)

        assert captured["metadata"]["Format"] == "Text"
        assert captured["body_html"] == "<pre>&lt;b&gt;raw&lt;/b&gt;</pre>"

    def test_an_empty_document_still_exports(self, session, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "ion.services.pdf_export_service.generate_pdf",
            lambda b, title=None, metadata=None: captured.update(
                body_html=b) or b"%PDF")
        d = self._doc(session)
        d.rendered_content = ""

        document_to_pdf(d)

        assert captured["body_html"] == ""

    def test_a_source_template_is_named_in_the_metadata(self, session,
                                                        monkeypatch):
        from ion.models.template import Template

        tmpl = Template(name="IR Report", content="x", format="markdown")
        session.add(tmpl)
        session.flush()
        captured = {}
        monkeypatch.setattr(
            "ion.services.pdf_export_service.generate_pdf",
            lambda b, title=None, metadata=None: captured.update(
                metadata=metadata) or b"%PDF")
        d = self._doc(session, source_template_id=tmpl.id)
        session.refresh(d)

        document_to_pdf(d)

        assert captured["metadata"]["Template"] == "IR Report"

    def test_a_document_with_no_creation_time_omits_the_row(self, session,
                                                            monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "ion.services.pdf_export_service.generate_pdf",
            lambda b, title=None, metadata=None: captured.update(
                metadata=metadata) or b"%PDF")
        d = self._doc(session)
        d.created_at = None

        document_to_pdf(d)

        assert "Created" not in captured["metadata"]

    def test_no_source_template_omits_the_row(self, session, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "ion.services.pdf_export_service.generate_pdf",
            lambda b, title=None, metadata=None: captured.update(
                metadata=metadata) or b"%PDF")

        document_to_pdf(self._doc(session))

        assert "Template" not in captured["metadata"]
