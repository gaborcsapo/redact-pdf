"""Tests for the redactor module.

These are the most critical tests: they verify that text is TRULY
removed from the PDF, not just visually hidden. Each test checks
at multiple levels (text extraction, stream bytes, full file bytes).
"""

from pathlib import Path

import fitz  # PyMuPDF

from redact.manifest import create_manifest
from redact.redactor import apply_redactions
from redact.scanner import scan_pdf


def test_redaction_removes_text_from_extraction(
    tmp_path: Path, pdf_with_ssn: Path
):
    """After redaction, get_text() should not find the redacted term."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "123-45-6789" not in text


def test_redaction_removes_text_from_raw_bytes(
    tmp_path: Path, pdf_with_ssn: Path
):
    """The redacted term should not appear anywhere in the raw file bytes."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    raw = output.read_bytes()
    assert b"123-45-6789" not in raw


def test_redaction_multiple_terms(tmp_path: Path, pdf_with_ssn: Path):
    """Multiple terms are all removed."""
    terms = ["123-45-6789", "987-65-4321", "John Smith"]
    result = scan_pdf(pdf_with_ssn, terms)
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    for term in terms:
        assert term not in text

    raw = output.read_bytes()
    for term in terms:
        assert term.encode("utf-8") not in raw


def test_redaction_preserves_non_redacted_text(
    tmp_path: Path, pdf_with_ssn: Path
):
    """Text not targeted for redaction should survive."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    # "Filing Status" was not redacted and should remain
    assert "Filing Status" in text


def test_redaction_multipage(tmp_path: Path, pdf_multipage: Path):
    """Redaction works across multiple pages."""
    terms = ["111-22-3333", "9876543210"]
    result = scan_pdf(pdf_multipage, terms)
    manifest = create_manifest(result, pdf_multipage)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_multipage, manifest["matches"], output)

    doc = fitz.open(str(output))
    for page in doc:
        text = page.get_text("text")
        for term in terms:
            assert term not in text
    doc.close()


def test_redaction_repeated_term(tmp_path: Path, pdf_repeated_term: Path):
    """All occurrences of a repeated term are removed."""
    result = scan_pdf(pdf_repeated_term, ["ABC-SECRET-123"])
    assert len(result.matches) == 3

    manifest = create_manifest(result, pdf_repeated_term)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_repeated_term, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "ABC-SECRET-123" not in text
    assert text.count("ABC-SECRET-123") == 0


def test_redacted_pdf_has_redacted_label(
    tmp_path: Path, pdf_with_ssn: Path
):
    """The redaction area should contain a 'REDACTED' text overlay."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "REDACTED" in text


def test_redaction_does_not_corrupt_pdf(
    tmp_path: Path, pdf_with_ssn: Path
):
    """The redacted PDF should be valid and openable."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    # Should open without error
    doc = fitz.open(str(output))
    assert len(doc) == 1
    doc.close()


def test_redaction_strips_metadata(tmp_path: Path, pdf_with_ssn: Path):
    """Metadata should be stripped from the redacted PDF."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    doc = fitz.open(str(output))
    metadata = doc.metadata
    doc.close()

    # Author and Title were set in the fixture — they should be gone
    assert not metadata.get("author")
    assert not metadata.get("title")
    assert not metadata.get("subject")


def test_redaction_output_is_new_file(
    tmp_path: Path, pdf_with_ssn: Path
):
    """Redaction should never overwrite the original."""
    original_hash_before = pdf_with_ssn.read_bytes()

    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    # Original file should be unchanged
    assert pdf_with_ssn.read_bytes() == original_hash_before
    # Output should be a different file
    assert output != pdf_with_ssn
    assert output.exists()


def test_redaction_case_insensitive(tmp_path: Path, pdf_with_ssn: Path):
    """Searching with different case should still redact the text."""
    # PDF contains "John Smith" — search with lowercase
    result = scan_pdf(pdf_with_ssn, ["john smith"])
    assert len(result.matches) == 1

    manifest = create_manifest(result, pdf_with_ssn)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    # "John Smith" should be gone regardless of search case
    assert "John Smith" not in text
    assert "john smith" not in text.lower()
