"""Tests for form field flattening and annotation stripping."""

from pathlib import Path

import fitz
import pikepdf
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from redact.manifest import create_manifest
from redact.redactor import apply_redactions
from redact.scanner import scan_pdf
from redact.verify import verify_redaction


def _make_form_pdf(path: Path) -> Path:
    """Create a PDF with AcroForm text fields containing sensitive data."""
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Name:")
    c.drawString(72, 670, "SSN:")
    c.drawString(72, 640, "Non-sensitive content on this page.")

    form = c.acroForm
    form.textfield(
        name="name_field",
        tooltip="Name",
        x=150, y=695, width=200, height=16,
        value="Jane Doe SECRET",
    )
    form.textfield(
        name="ssn_field",
        tooltip="SSN",
        x=150, y=665, width=200, height=16,
        value="555-12-9876",
    )
    c.showPage()
    c.save()
    return path


# --- Form field scanning and redaction ---


def test_form_pdf_is_recognized(tmp_path: Path):
    """Sanity check that our fixture produces a form PDF."""
    pdf = _make_form_pdf(tmp_path / "form.pdf")
    doc = fitz.open(str(pdf))
    assert doc.is_form_pdf
    doc.close()


def test_scanner_finds_form_field_text(tmp_path: Path):
    """Scanner should find text inside form field values."""
    pdf = _make_form_pdf(tmp_path / "form.pdf")
    result = scan_pdf(pdf, ["Jane Doe SECRET", "555-12-9876"])
    assert len(result.matches) >= 2
    found_terms = {m.term for m in result.matches}
    assert "Jane Doe SECRET" in found_terms
    assert "555-12-9876" in found_terms


def test_redaction_removes_form_field_text(tmp_path: Path):
    """After redaction, form field text should be gone from all places."""
    pdf = _make_form_pdf(tmp_path / "form.pdf")
    result = scan_pdf(pdf, ["Jane Doe SECRET", "555-12-9876"])
    manifest = create_manifest(result, pdf)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    # Check 1: text extraction
    doc = fitz.open(str(output))
    for page in doc:
        text = page.get_text()
        assert "Jane Doe SECRET" not in text
        assert "555-12-9876" not in text
    doc.close()

    # Check 2: raw bytes
    raw = output.read_bytes()
    assert b"Jane Doe SECRET" not in raw
    assert b"555-12-9876" not in raw


def test_redaction_flattens_forms(tmp_path: Path):
    """Output PDF should no longer be interactive (no widgets)."""
    pdf = _make_form_pdf(tmp_path / "form.pdf")
    result = scan_pdf(pdf, ["Jane Doe SECRET"])
    manifest = create_manifest(result, pdf)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    doc = fitz.open(str(output))
    assert not doc.is_form_pdf
    for page in doc:
        widgets = list(page.widgets() or [])
        assert len(widgets) == 0
    doc.close()


def test_redaction_preserves_form_non_sensitive_page_content(tmp_path: Path):
    """Non-targeted text (outside form fields) should remain."""
    pdf = _make_form_pdf(tmp_path / "form.pdf")
    result = scan_pdf(pdf, ["Jane Doe SECRET"])
    manifest = create_manifest(result, pdf)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text()
    doc.close()

    assert "Non-sensitive content" in text


def test_form_pdf_full_verification_passes(tmp_path: Path):
    """End-to-end: form PDF redaction + verification."""
    pdf = _make_form_pdf(tmp_path / "form.pdf")
    terms = ["Jane Doe SECRET", "555-12-9876"]
    result = scan_pdf(pdf, terms)
    manifest = create_manifest(result, pdf)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    vr = verify_redaction(output, terms)
    assert vr.passed is True, f"failures: {vr.failures}"


# --- Annotation stripping ---


def test_sanitize_removes_page_annotations(tmp_path: Path):
    """After sanitize, pages should have no /Annots entries."""
    # Make a simple PDF first
    pdf_path = tmp_path / "with_annots.pdf"
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    c.drawString(72, 700, "Document with annotations")
    c.showPage()
    c.save()

    # Use PyMuPDF to add an annotation
    doc = fitz.open(str(pdf_path))
    page = doc[0]
    page.add_text_annot(fitz.Point(100, 100), "This is a secret note")
    doc.save(str(pdf_path), incremental=True, encryption=fitz.PDF_ENCRYPT_KEEP)
    doc.close()

    # Confirm annotation exists
    with pikepdf.open(str(pdf_path)) as pdf:
        assert "/Annots" in pdf.pages[0]

    # Now run the redaction pipeline (even with empty matches, sanitize runs)
    result = scan_pdf(pdf_path, ["secret note"])
    manifest = create_manifest(result, pdf_path)

    output = tmp_path / "cleaned.pdf"
    if manifest["matches"]:
        apply_redactions(pdf_path, manifest["matches"], output)
    else:
        # Even without matches, we can still test sanitize directly
        from redact.sanitize import sanitize_and_rewrite
        sanitize_and_rewrite(pdf_path, output)

    # Verify no /Annots remains
    with pikepdf.open(str(output)) as pdf:
        assert "/Annots" not in pdf.pages[0]


def test_sanitize_removes_outlines(tmp_path: Path):
    """Bookmarks / outline tree should be stripped."""
    pdf_path = tmp_path / "with_outline.pdf"
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    c.drawString(72, 700, "Page 1")
    c.bookmarkPage("pg1")
    c.addOutlineEntry("Secret Chapter Title", "pg1", level=0)
    c.showPage()
    c.save()

    # Confirm outlines exist
    with pikepdf.open(str(pdf_path)) as pdf:
        assert "/Outlines" in pdf.Root

    from redact.sanitize import sanitize_and_rewrite
    output = tmp_path / "cleaned.pdf"
    sanitize_and_rewrite(pdf_path, output)

    with pikepdf.open(str(output)) as pdf:
        assert "/Outlines" not in pdf.Root


def test_sanitize_removes_viewer_preferences(tmp_path: Path):
    """ViewerPreferences should be stripped."""
    pdf_path = tmp_path / "with_prefs.pdf"
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    c.drawString(72, 700, "test")
    c.showPage()
    c.save()

    # Add viewer preferences
    with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
        pdf.Root.ViewerPreferences = pikepdf.Dictionary(
            HideMenubar=True, HideToolbar=True
        )
        pdf.save(str(pdf_path))

    with pikepdf.open(str(pdf_path)) as pdf:
        assert "/ViewerPreferences" in pdf.Root

    from redact.sanitize import sanitize_and_rewrite
    output = tmp_path / "cleaned.pdf"
    sanitize_and_rewrite(pdf_path, output)

    with pikepdf.open(str(output)) as pdf:
        assert "/ViewerPreferences" not in pdf.Root


def test_sanitize_removes_names_tree(tmp_path: Path):
    """Full /Names tree (not just JS/EmbeddedFiles) should be stripped."""
    pdf_path = tmp_path / "with_names.pdf"
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    c.drawString(72, 700, "test")
    c.showPage()
    c.save()

    with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
        pdf.Root.Names = pikepdf.Dictionary(
            Dests=pikepdf.Dictionary(Names=pikepdf.Array())
        )
        pdf.save(str(pdf_path))

    with pikepdf.open(str(pdf_path)) as pdf:
        assert "/Names" in pdf.Root

    from redact.sanitize import sanitize_and_rewrite
    output = tmp_path / "cleaned.pdf"
    sanitize_and_rewrite(pdf_path, output)

    with pikepdf.open(str(output)) as pdf:
        assert "/Names" not in pdf.Root
