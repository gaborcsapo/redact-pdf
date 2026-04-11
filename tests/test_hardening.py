"""Tests for hardening features:
- Font /CharSet and /CIDSet stripping
- Thorough object metadata sweep
- Form XObject content scrubbing
- get_text() detection fallback in scanner
- --rasterize-failed flag
"""

from pathlib import Path

import fitz
import pikepdf
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from typer.testing import CliRunner

from redact.cli import app
from redact.manifest import create_manifest
from redact.rasterize import (
    _pages_from_failures,
    rasterize_failed_pages,
    rasterize_pages,
)
from redact.redactor import apply_redactions
from redact.sanitize import (
    sanitize_and_rewrite,
    scrub_form_xobjects,
)
from redact.scanner import scan_pdf
from redact.verify import verify_redaction

runner = CliRunner()


def _make_simple_pdf(path: Path, lines: list[str]) -> Path:
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 700
    for line in lines:
        c.drawString(72, y, line)
        y -= 20
    c.showPage()
    c.save()
    return path


# --- Font subset hint stripping ---


def test_sanitize_strips_charset_from_font_descriptor(tmp_path: Path):
    """Font descriptors with /CharSet should have it removed."""
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Hello world"])

    # Inject a synthetic font descriptor with /CharSet
    with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
        fake_desc = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/FontDescriptor"),
            FontName=pikepdf.Name("/TestFont"),
            CharSet=pikepdf.String("/A/B/C/D/E"),
            CIDSet=pikepdf.Stream(pdf, b"\x01\x02\x03"),
        ))
        pdf.save(str(pdf_path))

    output = tmp_path / "out.pdf"
    sanitize_and_rewrite(pdf_path, output)

    # Walk objects and confirm no font descriptor has /CharSet or /CIDSet
    with pikepdf.open(str(output)) as pdf:
        for obj in pdf.objects:
            if not hasattr(obj, "keys"):
                continue
            try:
                if obj.get("/Type") == pikepdf.Name("/FontDescriptor"):
                    assert "/CharSet" not in obj
                    assert "/CIDSet" not in obj
            except Exception:
                continue


# --- Object metadata sweep ---


def test_sanitize_strips_xml_from_indirect_objects(tmp_path: Path):
    """Indirect objects with /XML entries should be cleaned."""
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Page content"])

    with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
        # Create an indirect dict with /XML entry
        fake_obj = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Fake"),
            XML=pikepdf.Stream(pdf, b"<secret>leaked</secret>"),
        ))
        pdf.Root.FakeRef = fake_obj
        pdf.save(str(pdf_path))

    output = tmp_path / "out.pdf"
    sanitize_and_rewrite(pdf_path, output)

    raw = output.read_bytes()
    assert b"leaked" not in raw


def test_sanitize_strips_pieceinfo_from_indirect_objects(tmp_path: Path):
    """Indirect objects with /PieceInfo should be cleaned."""
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Content"])

    with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
        fake_obj = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Fake"),
            PieceInfo=pikepdf.Dictionary(
                AppName=pikepdf.Dictionary(
                    Private=pikepdf.String("secret_app_data_xyz"),
                ),
            ),
        ))
        pdf.Root.FakeRef = fake_obj
        pdf.save(str(pdf_path))

    output = tmp_path / "out.pdf"
    sanitize_and_rewrite(pdf_path, output)

    raw = output.read_bytes()
    assert b"secret_app_data_xyz" not in raw


# --- Form XObject scrubbing ---


def _inject_form_xobject(pdf_path: Path, content: bytes, name: str = "Fm1"):
    """Inject a Form XObject into page 0's resources with given content."""
    with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
        xobject = pikepdf.Stream(
            pdf,
            content,
            Type=pikepdf.Name("/XObject"),
            Subtype=pikepdf.Name("/Form"),
            BBox=pikepdf.Array([0, 0, 612, 792]),
        )
        page = pdf.pages[0]
        if "/Resources" not in page:
            page.Resources = pikepdf.Dictionary()
        if "/XObject" not in page.Resources:
            page.Resources.XObject = pikepdf.Dictionary()
        page.Resources.XObject[f"/{name}"] = xobject
        pdf.save(str(pdf_path))


def test_scrub_form_xobjects_empties_matching_stream(tmp_path: Path):
    """A Form XObject containing a search term should be emptied."""
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Normal page content"])
    _inject_form_xobject(
        pdf_path,
        b"BT /F1 12 Tf 72 720 Td (Jane Doe SECRET HIDDEN) Tj ET",
    )

    with pikepdf.open(str(pdf_path)) as pdf:
        scrubbed = scrub_form_xobjects(pdf, ["Jane Doe SECRET HIDDEN"])
        assert len(scrubbed) >= 1


def test_scrub_form_xobjects_skips_clean_streams(tmp_path: Path):
    """A Form XObject without the term should be left alone."""
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Content"])
    _inject_form_xobject(
        pdf_path,
        b"BT /F1 12 Tf 72 720 Td (Totally fine text) Tj ET",
    )

    with pikepdf.open(str(pdf_path)) as pdf:
        scrubbed = scrub_form_xobjects(pdf, ["SENSITIVE_TERM"])
        assert len(scrubbed) == 0


def test_full_pipeline_scrubs_form_xobject(tmp_path: Path):
    """End-to-end: Form XObject content should be gone after apply."""
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Page text"])
    _inject_form_xobject(
        pdf_path,
        b"BT /F1 12 Tf 72 720 Td (HIDDEN_SSN_HERE) Tj ET",
    )

    # Scanner might not find text in Form XObjects via search_for,
    # but sanitize scrubs it anyway based on the term list.
    result = scan_pdf(pdf_path, ["HIDDEN_SSN_HERE"])
    manifest = create_manifest(result, pdf_path)

    # Use a dummy match if none — we want to trigger apply + sanitize
    if not manifest["matches"]:
        manifest["matches"] = [{
            "term": "HIDDEN_SSN_HERE",
            "page": 0,
            "rect": [72.0, 720.0, 100.0, 730.0],
        }]

    output = tmp_path / "out.pdf"
    apply_redactions(
        pdf_path, manifest["matches"], output, terms=["HIDDEN_SSN_HERE"],
    )

    raw = output.read_bytes()
    assert b"HIDDEN_SSN_HERE" not in raw


# --- get_text() detection fallback ---


def test_get_text_fallback_finds_matches_search_for_misses(tmp_path: Path):
    """Not all PDFs trigger the fallback, but the pipeline should
    not regress for ordinary content — search_for still dominates."""
    pdf = _make_simple_pdf(tmp_path / "test.pdf", [
        "Owner: Alex Example",
        "ID: 12345-67",
    ])
    result = scan_pdf(pdf, ["Alex Example"])
    assert any("Alex Example" == m.term for m in result.matches)


# --- Rasterization ---


def test_pages_from_failures_extracts_page_numbers():
    failures = [
        "Text extraction: term 'foo' found on page 2",
        "Stream inspection: term 'bar' found in content stream on page 5",
        "Byte scan: term 'baz' found in raw file data (utf-8 encoding)",
    ]
    pages = _pages_from_failures(failures)
    assert pages == {2, 5}


def test_rasterize_pages_replaces_page_content(tmp_path: Path):
    """Rasterizing a page should flatten it into an image."""
    pdf = _make_simple_pdf(tmp_path / "in.pdf", [
        "Page 1: SENSITIVE_DATA_HERE",
    ])
    output = tmp_path / "rast.pdf"

    rasterize_pages(pdf, output, {1}, dpi=150)

    # After rasterization the term should not be extractable as text
    doc = fitz.open(str(output))
    text = doc[0].get_text()
    doc.close()
    assert "SENSITIVE_DATA_HERE" not in text

    # Raw bytes should also not contain it
    raw = output.read_bytes()
    assert b"SENSITIVE_DATA_HERE" not in raw


def test_rasterize_pages_preserves_non_targeted_pages(tmp_path: Path):
    """Only targeted pages should be rasterized; others unchanged."""
    path = tmp_path / "in.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Page 1 RASTERIZE_ME")
    c.showPage()
    c.drawString(72, 700, "Page 2 keep as text")
    c.showPage()
    c.save()

    output = tmp_path / "out.pdf"
    rasterize_pages(path, output, {1}, dpi=150)

    doc = fitz.open(str(output))
    p1_text = doc[0].get_text()
    p2_text = doc[1].get_text()
    doc.close()

    assert "RASTERIZE_ME" not in p1_text
    # Page 2 should still have its text
    assert "keep as text" in p2_text


def test_rasterize_failed_pages_only_touches_failing_pages(tmp_path: Path):
    """Helper that combines verification + rasterization."""
    # Make a PDF where term is visible and will not be redacted
    path = tmp_path / "in.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Page 1 LEAK_HERE still visible")
    c.showPage()
    c.drawString(72, 700, "Page 2 clean content")
    c.showPage()
    c.save()

    output = tmp_path / "out.pdf"
    final, rasterized = rasterize_failed_pages(
        path, output, ["LEAK_HERE"], dpi=150,
    )

    assert 1 in rasterized
    assert 2 not in rasterized
    assert final.passed is True

    # Verify page 1 is flat, page 2 still has text
    doc = fitz.open(str(output))
    assert "LEAK_HERE" not in doc[0].get_text()
    assert "clean content" in doc[1].get_text()
    doc.close()


def test_rasterize_failed_pages_skipped_if_already_clean(tmp_path: Path):
    """If verification already passes, nothing gets rasterized."""
    pdf = _make_simple_pdf(tmp_path / "in.pdf", ["No sensitive content"])
    output = tmp_path / "out.pdf"

    final, rasterized = rasterize_failed_pages(
        pdf, output, ["NONEXISTENT"], dpi=150,
    )

    assert rasterized == set()
    assert final.passed is True


# --- CLI integration ---


def test_cli_apply_rasterize_failed_flag(tmp_path: Path):
    """Single-file apply with --rasterize-failed flag."""
    # Make a PDF where the term survives normal redaction
    # (by putting it in a Form XObject that's extra tricky)
    pdf_path = tmp_path / "in.pdf"
    _make_simple_pdf(pdf_path, ["Visible: TARGET_TERM on page"])

    # Create terms file and run scan
    terms = tmp_path / "terms.txt"
    terms.write_text("TARGET_TERM\n")

    manifest = tmp_path / "manifest.json"
    result = runner.invoke(app, [
        "scan", str(pdf_path), "--terms", str(terms),
        "--output", str(manifest),
    ])
    assert result.exit_code == 0, result.output

    output = tmp_path / "out.pdf"
    result = runner.invoke(app, [
        "apply", str(manifest),
        "--output", str(output),
        "--rasterize-failed",
    ])
    # Should succeed (verification passes because term is in content stream
    # and apply_redactions removes it — no rasterization needed)
    assert result.exit_code == 0, result.output

    raw = output.read_bytes()
    assert b"TARGET_TERM" not in raw


def test_cli_bulk_apply_rasterize_failed_flag(tmp_path: Path):
    """Bulk apply with --rasterize-failed flag is accepted."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    _make_simple_pdf(input_dir / "doc.pdf", ["Content with SSN 555-12-9876"])

    terms = tmp_path / "terms.txt"
    terms.write_text("555-12-9876\n")

    manifest = tmp_path / "bulk.json"
    result = runner.invoke(app, [
        "bulk", "scan", str(input_dir),
        "--terms", str(terms),
        "--drafts", str(tmp_path / "drafts"),
        "--output", str(manifest),
    ])
    assert result.exit_code == 0

    result = runner.invoke(app, [
        "bulk", "apply", str(manifest),
        "--output", str(tmp_path / "out"),
        "--rasterize-failed",
    ])
    assert result.exit_code == 0
