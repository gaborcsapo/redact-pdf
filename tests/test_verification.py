"""Tests for the verification module."""

from pathlib import Path

from redact.manifest import create_manifest
from redact.redactor import apply_redactions
from redact.scanner import scan_pdf
from redact.verify import verify_redaction


def test_verify_passes_after_redaction(tmp_path: Path, pdf_with_ssn: Path):
    """Verification should pass on a properly redacted PDF."""
    terms = ["123-45-6789", "987-65-4321"]
    result = scan_pdf(pdf_with_ssn, terms)
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    vr = verify_redaction(output, terms)
    assert vr.passed is True
    assert vr.text_extraction_clean is True
    assert vr.stream_inspection_clean is True
    assert vr.byte_scan_clean is True
    assert len(vr.failures) == 0


def test_verify_fails_on_unredacted_pdf(pdf_with_ssn: Path):
    """Verification should fail on a PDF that hasn't been redacted."""
    vr = verify_redaction(pdf_with_ssn, ["123-45-6789"])
    assert vr.passed is False
    assert len(vr.failures) > 0


def test_verify_failures_include_term(pdf_with_ssn: Path):
    """Failure messages should include the term that was found
    (the term is user input, not extracted content, so it's safe
    to echo back for debugging)."""
    term = "123-45-6789"
    vr = verify_redaction(pdf_with_ssn, [term])
    assert len(vr.failures) > 0
    # At least one failure should mention the term
    assert any(term in f for f in vr.failures)


def test_verify_failures_distinguish_multiple_terms(pdf_with_ssn: Path):
    """When multiple terms fail, each failure names its own term."""
    terms = ["123-45-6789", "John Smith"]
    vr = verify_redaction(pdf_with_ssn, terms)
    assert len(vr.failures) > 0
    # Find failures for each term
    ssn_failures = [f for f in vr.failures if "123-45-6789" in f]
    name_failures = [f for f in vr.failures if "John Smith" in f]
    assert len(ssn_failures) > 0
    assert len(name_failures) > 0


def test_verify_failures_deduplicate_per_page(pdf_with_ssn: Path):
    """The same term on the same page should only produce one
    text extraction failure (not one per check pass)."""
    vr = verify_redaction(pdf_with_ssn, ["123-45-6789"])
    text_failures = [f for f in vr.failures if "Text extraction" in f]
    # Exactly one text-extraction failure per unique (term, page)
    assert len(text_failures) == 1


def test_verify_clean_pdf_with_unrelated_terms(pdf_no_matches: Path):
    """Verification against terms not in the PDF should pass."""
    vr = verify_redaction(pdf_no_matches, ["NONEXISTENT_TERM"])
    assert vr.passed is True


def test_verify_multipage(tmp_path: Path, pdf_multipage: Path):
    """Verification works across all pages."""
    terms = ["111-22-3333", "9876543210"]
    result = scan_pdf(pdf_multipage, terms)
    manifest = create_manifest(result, pdf_multipage)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_multipage, manifest["matches"], output)

    vr = verify_redaction(output, terms)
    assert vr.passed is True


def test_verify_catches_case_variants(pdf_with_ssn: Path):
    """Verification should detect text regardless of case in the term."""
    # PDF contains "John Smith" — verify with different cases
    vr_lower = verify_redaction(pdf_with_ssn, ["john smith"])
    vr_upper = verify_redaction(pdf_with_ssn, ["JOHN SMITH"])

    assert vr_lower.passed is False
    assert vr_upper.passed is False


def test_verify_passes_case_insensitive_after_redaction(
    tmp_path: Path, pdf_with_ssn: Path
):
    """After redacting with one case, verification with any case should pass."""
    # Scan with lowercase, redact, then verify with uppercase
    result = scan_pdf(pdf_with_ssn, ["john smith"])
    manifest = create_manifest(result, pdf_with_ssn)

    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf_with_ssn, manifest["matches"], output)

    vr = verify_redaction(output, ["JOHN SMITH"])
    assert vr.passed is True
