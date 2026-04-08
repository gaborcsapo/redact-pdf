"""Tests for the scanner module."""

from pathlib import Path

from redact.scanner import load_terms, scan_pdf


def test_load_terms(terms_file: Path):
    terms = load_terms(terms_file)
    assert "123-45-6789" in terms
    assert "987-65-4321" in terms
    assert "John Smith" in terms
    assert "742 Evergreen Terrace" in terms
    # Comments and blank lines should be excluded
    assert len(terms) == 4


def test_load_terms_ignores_comments(tmp_path: Path):
    f = tmp_path / "t.txt"
    f.write_text("# comment\n\nterm1\n  \nterm2\n# another comment\n")
    terms = load_terms(f)
    assert terms == ["term1", "term2"]


def test_scan_finds_ssn(pdf_with_ssn: Path):
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    assert len(result.matches) >= 1
    assert result.matches[0].term == "123-45-6789"
    assert result.matches[0].page_number == 0


def test_scan_finds_multiple_terms(pdf_with_ssn: Path):
    terms = ["123-45-6789", "987-65-4321", "John Smith"]
    result = scan_pdf(pdf_with_ssn, terms)
    assert len(result.matches) >= 3
    found_terms = {m.term for m in result.matches}
    assert found_terms == set(terms)


def test_scan_returns_rects(pdf_with_ssn: Path):
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    rect = result.matches[0].rect
    # rect should be (x0, y0, x1, y1) with sensible coordinates
    assert len(rect) == 4
    assert rect[0] < rect[2]  # x0 < x1
    assert rect[1] < rect[3]  # y0 < y1


def test_scan_no_matches(pdf_no_matches: Path):
    result = scan_pdf(pdf_no_matches, ["SECRET_TERM"])
    assert len(result.matches) == 0
    assert result.pages_scanned == 1


def test_scan_multipage(pdf_multipage: Path):
    result = scan_pdf(pdf_multipage, ["111-22-3333", "9876543210"])
    assert len(result.matches) >= 2
    pages = {m.page_number for m in result.matches}
    assert 0 in pages  # page 1 (0-indexed)
    assert 1 in pages  # page 2 (0-indexed)


def test_scan_repeated_term(pdf_repeated_term: Path):
    result = scan_pdf(pdf_repeated_term, ["ABC-SECRET-123"])
    assert len(result.matches) == 3
    # All on page 0
    assert all(m.page_number == 0 for m in result.matches)


def test_scan_pages_scanned_count(pdf_multipage: Path):
    result = scan_pdf(pdf_multipage, ["anything"])
    assert result.pages_scanned == 4


def test_scan_terms_searched_tracked(pdf_with_ssn: Path):
    terms = ["term1", "term2"]
    result = scan_pdf(pdf_with_ssn, terms)
    assert result.terms_searched == terms


def test_scan_case_insensitive(pdf_with_ssn: Path):
    """Search terms should match regardless of case."""
    # PDF contains "John Smith" — searching with different cases should match
    result_lower = scan_pdf(pdf_with_ssn, ["john smith"])
    result_upper = scan_pdf(pdf_with_ssn, ["JOHN SMITH"])
    result_mixed = scan_pdf(pdf_with_ssn, ["jOhN sMiTh"])

    assert len(result_lower.matches) == 1
    assert len(result_upper.matches) == 1
    assert len(result_mixed.matches) == 1
