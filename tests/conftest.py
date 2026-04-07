"""Shared test fixtures — generates test PDFs programmatically with ReportLab."""

from pathlib import Path

import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


@pytest.fixture
def pdf_with_ssn(tmp_path: Path) -> Path:
    """Single-page PDF containing SSN-like text."""
    path = tmp_path / "ssn_test.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Taxpayer Name: John Smith")
    c.drawString(72, 680, "SSN: 123-45-6789")
    c.drawString(72, 660, "Spouse SSN: 987-65-4321")
    c.drawString(72, 640, "Address: 742 Evergreen Terrace, Springfield")
    c.drawString(72, 620, "Filing Status: Married Filing Jointly")
    c.setAuthor("Test Author")
    c.setTitle("Tax Return 2025")
    c.setSubject("Confidential tax document")
    c.showPage()
    c.save()
    return path


@pytest.fixture
def pdf_multipage(tmp_path: Path) -> Path:
    """Multi-page PDF with sensitive data on different pages."""
    path = tmp_path / "multipage_test.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)

    # Page 1
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Page 1: Taxpayer SSN: 111-22-3333")
    c.drawString(72, 680, "Name: Alice Johnson")
    c.showPage()

    # Page 2
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Page 2: Bank Account: 9876543210")
    c.drawString(72, 680, "Routing: 021000021")
    c.showPage()

    # Page 3 — no sensitive data
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Page 3: General instructions and notes.")
    c.drawString(72, 680, "No sensitive information on this page.")
    c.showPage()

    # Page 4
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Page 4: Employer EIN: 12-3456789")
    c.drawString(72, 680, "Wages: $85,000.00")
    c.showPage()

    c.save()
    return path


@pytest.fixture
def pdf_no_matches(tmp_path: Path) -> Path:
    """PDF with no sensitive data — should produce zero matches."""
    path = tmp_path / "clean_test.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "This is a clean document.")
    c.drawString(72, 680, "It contains no sensitive information.")
    c.drawString(72, 660, "Nothing to redact here.")
    c.showPage()
    c.save()
    return path


@pytest.fixture
def pdf_repeated_term(tmp_path: Path) -> Path:
    """PDF where the same term appears multiple times on the same page."""
    path = tmp_path / "repeated_test.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "Reference: ABC-SECRET-123")
    c.drawString(72, 680, "See also: ABC-SECRET-123 on prior form")
    c.drawString(72, 660, "Confirmed: ABC-SECRET-123 is correct")
    c.showPage()
    c.save()
    return path


@pytest.fixture
def terms_file(tmp_path: Path) -> Path:
    """Terms file for testing."""
    path = tmp_path / "terms.txt"
    path.write_text(
        "# Search terms for tax document redaction\n"
        "123-45-6789\n"
        "987-65-4321\n"
        "John Smith\n"
        "742 Evergreen Terrace\n"
        "\n"
        "# Blank lines and comments are ignored\n"
    )
    return path
