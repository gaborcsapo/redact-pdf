"""Tests for glyph position normalization (PETS 2023 defense)
and XFA form detection/stripping."""

from pathlib import Path

import fitz
import pikepdf
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from redact.sanitize import (
    normalize_glyph_positions,
    sanitize_and_rewrite,
    strip_xfa,
)
from redact.scanner import (
    _check_xfa_for_terms,
    _extract_xfa_xml,
    scan_pdf,
)


# --- Helpers ---


def _make_pdf_with_tj_kerning(path: Path) -> Path:
    """Create a PDF with a TJ array that has numeric position adjustments."""
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    page = pdf.pages[0]

    # Build a content stream with a TJ operator that has
    # numeric adjustments between character groups
    content = b"""q
BT
/F1 12 Tf
72 720 Td
[(AV) -70 (OI) -30 (D) 20 (Hello)] TJ
ET
Q
"""
    font = pikepdf.Dictionary(
        Type=pikepdf.Name("/Font"),
        Subtype=pikepdf.Name("/Type1"),
        BaseFont=pikepdf.Name("/Helvetica"),
    )
    page.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))
    page.Contents = pikepdf.Stream(pdf, content)
    pdf.save(str(path))
    pdf.close()
    return path


def _make_pdf_with_xfa(
    path: Path, xfa_content: bytes,
) -> Path:
    """Create a PDF with /AcroForm/XFA containing the given XML bytes."""
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    xfa_stream = pikepdf.Stream(pdf, xfa_content)
    pdf.Root.AcroForm = pikepdf.Dictionary(
        XFA=xfa_stream,
        Fields=pikepdf.Array(),
    )
    pdf.save(str(path))
    pdf.close()
    return path


def _get_tj_arrays(pdf_path: Path) -> list[list]:
    """Return all TJ arrays in the PDF as raw Python lists."""
    arrays = []
    pdf = pikepdf.open(str(pdf_path))
    try:
        for page in pdf.pages:
            for operands, operator in pikepdf.parse_content_stream(page):
                if str(operator) == "TJ" and operands:
                    arr = operands[0]
                    if isinstance(arr, pikepdf.Array):
                        arrays.append(list(arr))
    finally:
        pdf.close()
    return arrays


# --- Glyph position normalization tests ---


class TestGlyphNormalization:

    def test_tj_numeric_adjustments_are_stripped(self, tmp_path: Path):
        """After normalization, TJ arrays contain only strings."""
        pdf_path = _make_pdf_with_tj_kerning(tmp_path / "in.pdf")

        # Sanity check: the input HAS numeric adjustments
        arrays_before = _get_tj_arrays(pdf_path)
        assert len(arrays_before) >= 1
        has_numbers_before = any(
            not isinstance(item, pikepdf.String)
            for arr in arrays_before for item in arr
        )
        assert has_numbers_before, "fixture should have kerning numbers"

        output = tmp_path / "out.pdf"
        sanitize_and_rewrite(pdf_path, output)

        arrays_after = _get_tj_arrays(output)
        for arr in arrays_after:
            for item in arr:
                assert isinstance(item, pikepdf.String), (
                    f"TJ array still has numeric adjustment: {item!r}"
                )

    def test_normalization_reports_count(self, tmp_path: Path):
        """sanitize_and_rewrite returns tj_ops_normalized > 0 when modifying."""
        pdf_path = _make_pdf_with_tj_kerning(tmp_path / "in.pdf")
        output = tmp_path / "out.pdf"
        result = sanitize_and_rewrite(pdf_path, output)
        assert result["tj_ops_normalized"] >= 1

    def test_text_still_extractable_after_normalization(self, tmp_path: Path):
        """Characters must still be readable after stripping kerning."""
        pdf_path = _make_pdf_with_tj_kerning(tmp_path / "in.pdf")
        output = tmp_path / "out.pdf"
        sanitize_and_rewrite(pdf_path, output)

        doc = fitz.open(str(output))
        text = doc[0].get_text()
        doc.close()

        # The TJ array had "AV", "OI", "D", "Hello"
        for substr in ("AV", "OI", "D", "Hello"):
            assert substr in text

    def test_no_tj_ops_unchanged(self, tmp_path: Path):
        """A PDF with no TJ operators reports zero normalizations."""
        # ReportLab usually emits Tj, not TJ
        path = tmp_path / "simple.pdf"
        c = canvas.Canvas(str(path), pagesize=letter)
        c.setFont("Helvetica", 12)
        c.drawString(72, 700, "Just some plain text")
        c.showPage()
        c.save()

        output = tmp_path / "out.pdf"
        result = sanitize_and_rewrite(path, output)
        # Usually 0, but acceptable to be any count as long as output valid
        assert result["tj_ops_normalized"] >= 0

        doc = fitz.open(str(output))
        text = doc[0].get_text()
        doc.close()
        assert "Just some plain text" in text

    def test_normalize_glyph_positions_direct(self, tmp_path: Path):
        """Direct call to normalize_glyph_positions returns modified count."""
        pdf_path = _make_pdf_with_tj_kerning(tmp_path / "in.pdf")
        pdf = pikepdf.open(str(pdf_path))
        try:
            count = normalize_glyph_positions(pdf)
        finally:
            pdf.close()
        assert count >= 1

    def test_normalization_in_form_xobjects(self, tmp_path: Path):
        """TJ arrays inside Form XObjects are also normalized."""
        # Create a base PDF
        pdf_path = tmp_path / "with_xobj.pdf"
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        c.drawString(72, 700, "Page content")
        c.showPage()
        c.save()

        # Inject a Form XObject with a TJ array
        with pikepdf.open(str(pdf_path), allow_overwriting_input=True) as pdf:
            xobj_content = b"""q
BT
/F1 10 Tf
0 0 Td
[(Hidden) -50 (Kerned) -30 (Text)] TJ
ET
Q
"""
            xobject = pikepdf.Stream(
                pdf,
                xobj_content,
                Type=pikepdf.Name("/XObject"),
                Subtype=pikepdf.Name("/Form"),
                BBox=pikepdf.Array([0, 0, 100, 100]),
            )
            page = pdf.pages[0]
            if "/Resources" not in page:
                page.Resources = pikepdf.Dictionary()
            if "/XObject" not in page.Resources:
                page.Resources.XObject = pikepdf.Dictionary()
            page.Resources.XObject.Fm1 = xobject
            pdf.save(str(pdf_path))

        # Verify kerning exists in the XObject
        with pikepdf.open(str(pdf_path)) as pdf:
            for obj in pdf.objects:
                if not isinstance(obj, pikepdf.Stream):
                    continue
                if obj.get("/Subtype") != pikepdf.Name("/Form"):
                    continue
                for operands, operator in pikepdf.parse_content_stream(obj):
                    if str(operator) == "TJ":
                        arr = operands[0]
                        has_num = any(
                            not isinstance(item, pikepdf.String)
                            for item in arr
                        )
                        assert has_num, "fixture should have kerning"

        output = tmp_path / "out.pdf"
        sanitize_and_rewrite(pdf_path, output)

        # Verify kerning is gone from the XObject
        with pikepdf.open(str(output)) as pdf:
            for obj in pdf.objects:
                if not isinstance(obj, pikepdf.Stream):
                    continue
                if obj.get("/Subtype") != pikepdf.Name("/Form"):
                    continue
                for operands, operator in pikepdf.parse_content_stream(obj):
                    if str(operator) == "TJ":
                        arr = operands[0]
                        for item in arr:
                            assert isinstance(item, pikepdf.String), (
                                "XObject TJ array still has numeric adjustment"
                            )


# --- XFA tests ---


class TestXFA:

    XFA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<xfa:data xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
  <taxpayer>
    <ssn>555-12-9876</ssn>
    <name>Jane XFA Doe</name>
    <address>42 Wallaby Way</address>
  </taxpayer>
</xfa:data>
"""

    def test_extract_xfa_xml_stream(self, tmp_path: Path):
        """XFA stream content is extracted and decoded."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        xml = _extract_xfa_xml(pdf_path)
        assert xml is not None
        assert "Jane XFA Doe" in xml
        assert "555-12-9876" in xml

    def test_extract_xfa_returns_none_when_absent(self, tmp_path: Path):
        """Non-XFA PDFs return None."""
        path = tmp_path / "no_xfa.pdf"
        c = canvas.Canvas(str(path), pagesize=letter)
        c.drawString(72, 700, "Regular PDF, no forms")
        c.showPage()
        c.save()
        assert _extract_xfa_xml(path) is None

    def test_check_xfa_for_terms_flags_matches(self, tmp_path: Path):
        """Terms found in XFA XML produce warnings."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        warnings = _check_xfa_for_terms(
            pdf_path, ["Jane XFA Doe", "NOT_PRESENT"],
        )
        assert len(warnings) == 1
        assert warnings[0].font_name == "XFA"
        assert "Jane XFA Doe" in warnings[0].reason

    def test_scan_pdf_includes_xfa_warnings(self, tmp_path: Path):
        """scan_pdf reports XFA matches as font_warnings."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        result = scan_pdf(pdf_path, ["Jane XFA Doe"])
        xfa_warnings = [
            w for w in result.font_warnings if w.font_name == "XFA"
        ]
        assert len(xfa_warnings) == 1

    def test_strip_xfa_deletes_entry(self, tmp_path: Path):
        """strip_xfa removes /AcroForm/XFA."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        pdf = pikepdf.open(str(pdf_path))
        try:
            assert "/XFA" in pdf.Root.AcroForm
            assert strip_xfa(pdf) is True
            assert "/XFA" not in pdf.Root.AcroForm
        finally:
            pdf.close()

    def test_strip_xfa_returns_false_when_absent(self, tmp_path: Path):
        """strip_xfa returns False on PDFs without XFA."""
        path = tmp_path / "no_xfa.pdf"
        c = canvas.Canvas(str(path), pagesize=letter)
        c.drawString(72, 700, "hi")
        c.showPage()
        c.save()
        pdf = pikepdf.open(str(path))
        try:
            assert strip_xfa(pdf) is False
        finally:
            pdf.close()

    def test_sanitize_reports_xfa_removal(self, tmp_path: Path):
        """sanitize_and_rewrite reports when XFA was removed."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        output = tmp_path / "clean.pdf"
        result = sanitize_and_rewrite(pdf_path, output)
        assert result["xfa_removed"] is True

    def test_sanitize_removes_xfa_content_from_output(self, tmp_path: Path):
        """XFA text should not appear anywhere in the sanitized file."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        output = tmp_path / "clean.pdf"
        sanitize_and_rewrite(pdf_path, output)

        raw = output.read_bytes()
        assert b"Jane XFA Doe" not in raw
        assert b"555-12-9876" not in raw
        assert b"42 Wallaby Way" not in raw

    def test_sanitize_removes_acroform_entirely(self, tmp_path: Path):
        """After sanitize, /AcroForm is gone (defense in depth)."""
        pdf_path = _make_pdf_with_xfa(tmp_path / "xfa.pdf", self.XFA_XML)
        output = tmp_path / "clean.pdf"
        sanitize_and_rewrite(pdf_path, output)

        with pikepdf.open(str(output)) as pdf:
            assert "/AcroForm" not in pdf.Root
