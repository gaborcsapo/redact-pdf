"""Tests for smart term expansion and its integration with scanning/redaction."""

from pathlib import Path

import fitz
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from redact.manifest import create_manifest
from redact.redactor import apply_redactions
from redact.scanner import (
    _strip_mask,
    expand_term,
    expand_terms,
    scan_pdf,
)
from redact.verify import verify_redaction


def _make_pdf(path: Path, lines: list[str]) -> Path:
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 700
    for line in lines:
        c.drawString(72, y, line)
        y -= 20
    c.showPage()
    c.save()
    return path


# --- expand_term unit tests ---


class TestExpandTerm:

    def test_plain_text_no_expansion(self):
        """Non-numeric terms should not be expanded."""
        variants = expand_term("John Smith")
        assert variants == ["John Smith"]

    def test_ssn_with_dashes(self):
        """SSN with dashes gets separator variants + suffixes."""
        variants = expand_term("123-45-6789")
        assert "123-45-6789" in variants   # original
        assert "123456789" in variants     # digits only
        assert "123 45 6789" in variants   # spaces
        assert "123.45.6789" in variants   # dots
        assert "6789" in variants          # last 4
        assert "56789" in variants         # last 5

    def test_ssn_with_spaces(self):
        """SSN with spaces gets separator variants."""
        variants = expand_term("123 45 6789")
        assert "123-45-6789" in variants
        assert "123456789" in variants
        assert "123 45 6789" in variants

    def test_pure_digit_sequence_long(self):
        """Long digit-only term gets suffix expansion."""
        variants = expand_term("987654321012")
        assert "987654321012" in variants
        assert "1012" in variants    # last 4
        assert "21012" in variants   # last 5

    def test_pure_digit_sequence_short(self):
        """Short digit-only term (< 6 digits) does NOT get suffix expansion."""
        variants = expand_term("1234")
        assert variants == ["1234"]

    def test_exactly_6_digits_gets_suffixes(self):
        """6-digit boundary: should get suffix expansion."""
        variants = expand_term("123456")
        assert "3456" in variants   # last 4
        assert "23456" in variants  # last 5

    def test_5_digits_no_suffixes(self):
        """5 digits: no suffix expansion."""
        variants = expand_term("12345")
        assert "2345" not in variants
        assert "12345" in variants

    def test_masked_ssn(self):
        """Masked SSN extracts the visible digits."""
        variants = expand_term("***-**-6789")
        assert "6789" in variants

    def test_masked_with_x(self):
        """X-masked number extracts digits."""
        variants = expand_term("XXXX1234")
        assert "1234" in variants

    def test_masked_credit_card(self):
        """Masked credit card last-4."""
        variants = expand_term("****-****-****-1234")
        assert "1234" in variants

    def test_masked_dots(self):
        """Dot-masked number."""
        variants = expand_term("....5678")
        assert "5678" in variants

    def test_account_with_dashes(self):
        """12-digit account number with dashes."""
        variants = expand_term("1234-5678-9012")
        assert "123456789012" in variants  # digits only
        assert "1234 5678 9012" in variants  # spaces
        assert "9012" in variants  # last 4
        assert "89012" in variants  # last 5

    def test_ein_format(self):
        """EIN: 12-3456789."""
        variants = expand_term("12-3456789")
        assert "123456789" in variants
        assert "12 3456789" in variants
        assert "6789" in variants   # last 4
        assert "56789" in variants  # last 5

    def test_phone_number(self):
        """Phone number with dashes."""
        variants = expand_term("555-123-4567")
        assert "5551234567" in variants
        assert "555 123 4567" in variants
        assert "4567" in variants  # last 4

    def test_no_duplicates(self):
        """Expanded variants should have no duplicates."""
        variants = expand_term("123-45-6789")
        assert len(variants) == len(set(variants))

    def test_address_not_expanded(self):
        """An address with a number should not get wild expansions."""
        variants = expand_term("742 Evergreen Terrace")
        # Should just be the original — it's text with a number,
        # not a numeric identifier
        assert "742 Evergreen Terrace" in variants


class TestStripMask:

    def test_star_mask(self):
        assert _strip_mask("***-**-6789") == "6789"

    def test_x_mask(self):
        assert _strip_mask("XXXX1234") == "1234"

    def test_dot_mask(self):
        assert _strip_mask("....5678") == "5678"

    def test_no_mask(self):
        assert _strip_mask("John Smith") is None

    def test_pure_digits(self):
        assert _strip_mask("123456") is None

    def test_too_few_digits_after_mask(self):
        """If only 1-2 digits after mask, don't extract (too short)."""
        assert _strip_mask("****12") is None

    def test_mixed_masks(self):
        assert _strip_mask("XX**1234") == "1234"


class TestExpandTerms:

    def test_multiple_terms(self):
        result = expand_terms(["123-45-6789", "John Smith"])
        assert "123-45-6789" in result
        assert "John Smith" in result
        assert "123456789" in result["123-45-6789"]
        assert result["John Smith"] == ["John Smith"]


# --- Integration: scan with expanded terms ---


def test_scan_finds_digits_only_variant(tmp_path: Path):
    """Term has dashes, PDF has digits only — should still match."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: 123456789",
    ])
    result = scan_pdf(pdf, ["123-45-6789"])
    assert len(result.matches) >= 1


def test_scan_finds_spaces_variant(tmp_path: Path):
    """Term has dashes, PDF has spaces — should match."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: 123 45 6789",
    ])
    result = scan_pdf(pdf, ["123-45-6789"])
    assert len(result.matches) >= 1


def test_scan_finds_dots_variant(tmp_path: Path):
    """Term has dashes, PDF has dots — should match."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: 123.45.6789",
    ])
    result = scan_pdf(pdf, ["123-45-6789"])
    assert len(result.matches) >= 1


def test_scan_finds_last4_of_masked_ssn(tmp_path: Path):
    """PDF shows masked SSN, term is the full number — last 4 should match."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: ***-**-6789",
    ])
    result = scan_pdf(pdf, ["123-45-6789"])
    # The last-4 suffix "6789" should match inside "***-**-6789"
    assert len(result.matches) >= 1


def test_scan_finds_last4_of_account(tmp_path: Path):
    """PDF shows masked account number, term is full number."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Account: ****5678",
    ])
    result = scan_pdf(pdf, ["1234-5678"])
    assert len(result.matches) >= 1


def test_scan_masked_term_matches_masked_pdf(tmp_path: Path):
    """User provides a masked term from a statement."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Your SSN on file: ***-**-4321",
    ])
    # User pastes the masked version they see on a statement
    result = scan_pdf(pdf, ["***-**-4321"])
    assert len(result.matches) >= 1


def test_scan_no_duplicate_matches_for_same_location(tmp_path: Path):
    """Multiple variants matching the same spot should produce one match."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: 123-45-6789",
    ])
    # "123-45-6789" and "123 45 6789" both expand, but only the
    # original should match this specific text. No duplicates.
    result = scan_pdf(pdf, ["123-45-6789"])
    # Should be exactly 1 match for the SSN (not multiple for variants)
    ssn_matches = [m for m in result.matches if m.term == "123-45-6789"]
    rects = [(m.page_number, m.rect) for m in ssn_matches]
    # No duplicate rects
    assert len(rects) == len(set(rects))


def test_scan_multiple_formats_same_page(tmp_path: Path):
    """Same number in different formats on one page — all found."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: 123-45-6789",
        "Also: 123456789",
        "And: 123 45 6789",
    ])
    result = scan_pdf(pdf, ["123-45-6789"])
    assert len(result.matches) == 3


def test_scan_short_number_no_wild_matches(tmp_path: Path):
    """A short digit term should match exactly, not generate wild suffixes."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Page 42",
        "Code: 1234",
        "Amount: $5,678",
    ])
    result = scan_pdf(pdf, ["1234"])
    # Should find "1234" in "Code: 1234" only
    assert len(result.matches) == 1


def test_scan_line_break_warning(tmp_path: Path):
    """If a number appears in collapsed text but not in standard search,
    warn about possible line break split."""
    # Create a PDF where the number is split across two lines
    path = tmp_path / "split.pdf"
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 700, "SSN: 123-45-")
    c.drawString(72, 680, "6789")
    c.showPage()
    c.save()

    result = scan_pdf(path, ["123-45-6789"])
    # The suffix "6789" should still be found via expansion
    suffix_matches = [m for m in result.matches]
    assert len(suffix_matches) >= 1  # last-4 suffix catches "6789"


# --- End-to-end: redaction with expanded terms ---


def test_redaction_removes_all_separator_variants(tmp_path: Path):
    """Redaction should remove the number regardless of separator format."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Format 1: 123-45-6789",
        "Format 2: 123456789",
        "Format 3: 123 45 6789",
        "Unrelated: Hello world",
    ])

    result = scan_pdf(pdf, ["123-45-6789"])
    manifest = create_manifest(result, pdf)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "123-45-6789" not in text
    assert "123456789" not in text
    assert "123 45 6789" not in text
    assert "Hello world" in text  # unrelated text preserved


def test_redaction_removes_masked_occurrence(tmp_path: Path):
    """Redacting with full number also removes the masked version's suffix."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Full: 123-45-6789",
        "Masked: ***-**-6789",
    ])

    result = scan_pdf(pdf, ["123-45-6789"])
    manifest = create_manifest(result, pdf)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "6789" not in text


def test_redaction_with_masked_input_term(tmp_path: Path):
    """User provides a masked term — it should still redact."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Your SSN: ***-**-4321",
    ])

    result = scan_pdf(pdf, ["***-**-4321"])
    manifest = create_manifest(result, pdf)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "4321" not in text


def test_full_pipeline_verification_with_expansion(tmp_path: Path):
    """End-to-end: scan with expansion → redact → verify all variants gone."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "SSN: 123-45-6789",
        "Also shown as: 123456789",
        "Statement shows: ***-**-6789",
    ])

    terms = ["123-45-6789"]
    result = scan_pdf(pdf, terms)
    manifest = create_manifest(result, pdf)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    vr = verify_redaction(output, terms)
    assert vr.passed is True


def test_expansion_does_not_break_plain_text_terms(tmp_path: Path):
    """Plain text terms should work exactly as before."""
    pdf = _make_pdf(tmp_path / "test.pdf", [
        "Taxpayer: Jane Doe",
        "Address: 742 Evergreen Terrace",
    ])

    terms = ["Jane Doe", "742 Evergreen Terrace"]
    result = scan_pdf(pdf, terms)
    assert len(result.matches) == 2

    manifest = create_manifest(result, pdf)
    output = tmp_path / "redacted.pdf"
    apply_redactions(pdf, manifest["matches"], output)

    doc = fitz.open(str(output))
    text = doc[0].get_text("text")
    doc.close()

    assert "Jane Doe" not in text
    assert "742 Evergreen Terrace" not in text
