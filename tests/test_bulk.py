"""Tests for bulk folder-based redaction."""

from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from typer.testing import CliRunner

from redact.bulk import bulk_apply, bulk_scan, discover_pdfs, read_bulk_manifest
from redact.cli import app
from redact.scanner import load_terms

runner = CliRunner()


def _make_pdf(path: Path, lines: list[str]) -> Path:
    """Helper: create a single-page PDF with the given text lines."""
    c = canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 700
    for line in lines:
        c.drawString(72, y, line)
        y -= 20
    c.showPage()
    c.save()
    return path


def _make_input_folder(tmp_path: Path) -> tuple[Path, Path]:
    """Create an input/ folder with several test PDFs and a terms file."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()

    _make_pdf(input_dir / "tax_return.pdf", [
        "Taxpayer: Jane Doe",
        "SSN: 555-12-9876",
        "Address: 42 Wallaby Way, Sydney",
    ])
    _make_pdf(input_dir / "w2_form.pdf", [
        "Employee: Jane Doe",
        "EIN: 12-3456789",
        "Wages: $92,500",
    ])
    _make_pdf(input_dir / "cover_letter.pdf", [
        "Dear IRS,",
        "Please find enclosed documents.",
        "Sincerely, A Taxpayer",
    ])

    terms_file = tmp_path / "terms.txt"
    terms_file.write_text("Jane Doe\n555-12-9876\n42 Wallaby Way\n")

    return input_dir, terms_file


# --- discover_pdfs ---


def test_discover_pdfs_finds_only_pdfs(tmp_path: Path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.pdf").write_bytes(b"%PDF-1.4")
    (folder / "b.PDF").write_bytes(b"%PDF-1.4")  # uppercase
    (folder / "notes.txt").write_text("not a pdf")
    (folder / "image.png").write_bytes(b"PNG")

    pdfs = discover_pdfs(folder)
    names = {p.name for p in pdfs}
    assert names == {"a.pdf", "b.PDF"}


def test_discover_pdfs_skips_hidden_files(tmp_path: Path):
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / ".hidden.pdf").write_bytes(b"%PDF-1.4")
    (folder / "visible.pdf").write_bytes(b"%PDF-1.4")

    pdfs = discover_pdfs(folder)
    assert len(pdfs) == 1
    assert pdfs[0].name == "visible.pdf"


def test_discover_pdfs_empty_folder(tmp_path: Path):
    folder = tmp_path / "empty"
    folder.mkdir()
    assert discover_pdfs(folder) == []


def test_discover_pdfs_returns_sorted(tmp_path: Path):
    folder = tmp_path / "docs"
    folder.mkdir()
    _make_pdf(folder / "c.pdf", ["C"])
    _make_pdf(folder / "a.pdf", ["A"])
    _make_pdf(folder / "b.pdf", ["B"])

    pdfs = discover_pdfs(folder)
    assert [p.name for p in pdfs] == ["a.pdf", "b.pdf", "c.pdf"]


# --- bulk_scan ---


def test_bulk_scan_creates_drafts_and_manifest(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"

    manifest, summary = bulk_scan(input_dir, terms, drafts_dir, manifest_path)

    assert drafts_dir.exists()
    assert manifest_path.exists()
    assert manifest["type"] == "bulk"
    assert summary.files_scanned == 3
    # tax_return.pdf and w2_form.pdf have matches; cover_letter.pdf does not
    assert summary.files_with_matches == 2
    assert summary.files_without_matches == 1
    assert summary.total_matches > 0


def test_bulk_scan_generates_preview_per_file(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"

    bulk_scan(input_dir, terms, drafts_dir, manifest_path)

    # Previews should exist for files with matches
    previews = list(drafts_dir.glob("*_preview.pdf"))
    assert len(previews) == 2
    preview_names = {p.name for p in previews}
    assert "tax_return_preview.pdf" in preview_names
    assert "w2_form_preview.pdf" in preview_names


def test_bulk_scan_no_previews_for_clean_files(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"

    bulk_scan(input_dir, terms, drafts_dir, manifest_path)

    # No preview for the cover letter (no matches)
    assert not (drafts_dir / "cover_letter_preview.pdf").exists()


def test_bulk_scan_empty_folder(tmp_path: Path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    manifest_path = tmp_path / "manifest.json"

    manifest, summary = bulk_scan(
        empty_dir, ["term"], tmp_path / "drafts", manifest_path
    )

    assert summary.files_scanned == 0
    assert summary.total_matches == 0


def test_bulk_scan_no_matches_anywhere(tmp_path: Path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    _make_pdf(input_dir / "clean.pdf", ["Nothing sensitive here."])

    manifest_path = tmp_path / "manifest.json"
    manifest, summary = bulk_scan(
        input_dir, ["SECRET_TERM"], tmp_path / "drafts", manifest_path
    )

    assert summary.files_scanned == 1
    assert summary.files_with_matches == 0
    assert summary.total_matches == 0
    assert len(manifest.get("files", [])) == 0


def test_bulk_scan_skips_corrupt_pdfs(tmp_path: Path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    # Good PDF
    _make_pdf(input_dir / "good.pdf", ["SSN: 123-45-6789"])
    # Corrupt PDF
    (input_dir / "corrupt.pdf").write_bytes(b"this is not a pdf")

    manifest_path = tmp_path / "manifest.json"
    manifest, summary = bulk_scan(
        input_dir, ["123-45-6789"], tmp_path / "drafts", manifest_path
    )

    assert summary.files_skipped == ["corrupt.pdf"]
    assert summary.files_with_matches == 1


# --- bulk_apply ---


def test_bulk_apply_creates_redacted_files(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "output"

    manifest, _ = bulk_scan(input_dir, terms, drafts_dir, manifest_path)
    results = bulk_apply(manifest, output_dir)

    assert output_dir.exists()
    done = [r for r in results if r["status"] == "done"]
    assert len(done) == 2

    # Check output files exist
    output_files = {p.name for p in output_dir.glob("*.pdf")}
    assert "tax_return_redacted.pdf" in output_files
    assert "w2_form_redacted.pdf" in output_files


def test_bulk_apply_removes_text_from_bytes(tmp_path: Path):
    """The most critical test: sensitive text must be gone from raw bytes."""
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "output"

    manifest, _ = bulk_scan(input_dir, terms, drafts_dir, manifest_path)
    bulk_apply(manifest, output_dir)

    for pdf_file in output_dir.glob("*.pdf"):
        raw = pdf_file.read_bytes()
        assert b"Jane Doe" not in raw
        assert b"555-12-9876" not in raw
        assert b"42 Wallaby Way" not in raw


def test_bulk_apply_verification_passes(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "output"

    manifest, _ = bulk_scan(input_dir, terms, drafts_dir, manifest_path)
    results = bulk_apply(manifest, output_dir)

    for r in results:
        if r["status"] == "done":
            assert r["verification"] == "passed"


def test_bulk_apply_detects_changed_source(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "output"

    manifest, _ = bulk_scan(input_dir, terms, drafts_dir, manifest_path)

    # Tamper with one source file
    tax_pdf = input_dir / "tax_return.pdf"
    tax_pdf.write_bytes(tax_pdf.read_bytes() + b"% tampered")

    results = bulk_apply(manifest, output_dir)

    statuses = {r["source"]: r["status"] for r in results}
    assert statuses["tax_return.pdf"] == "skipped"
    assert "changed" in [r for r in results if r["source"] == "tax_return.pdf"][0].get("reason", "")
    # The other file should still succeed
    assert statuses["w2_form.pdf"] == "done"


def test_bulk_apply_does_not_modify_originals(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    terms = load_terms(terms_file)

    # Record original bytes
    originals = {}
    for pdf in input_dir.glob("*.pdf"):
        originals[pdf.name] = pdf.read_bytes()

    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "output"

    manifest, _ = bulk_scan(input_dir, terms, drafts_dir, manifest_path)
    bulk_apply(manifest, output_dir)

    # Originals should be unchanged
    for pdf in input_dir.glob("*.pdf"):
        assert pdf.read_bytes() == originals[pdf.name]


# --- CLI integration ---


def test_bulk_scan_cli(tmp_path: Path):
    input_dir, terms_file = _make_input_folder(tmp_path)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"

    result = runner.invoke(app, [
        "bulk", "scan",
        str(input_dir),
        "--terms", str(terms_file),
        "--drafts", str(drafts_dir),
        "--output", str(manifest_path),
    ])

    assert result.exit_code == 0, result.output
    assert manifest_path.exists()
    assert drafts_dir.exists()
    assert "file(s) with matches" in result.output


def test_bulk_full_workflow_cli(tmp_path: Path):
    """End-to-end: bulk scan → bulk apply via CLI."""
    input_dir, terms_file = _make_input_folder(tmp_path)
    drafts_dir = tmp_path / "drafts"
    manifest_path = tmp_path / "manifest.json"
    output_dir = tmp_path / "output"

    # Phase 1: Bulk scan
    scan_result = runner.invoke(app, [
        "bulk", "scan",
        str(input_dir),
        "--terms", str(terms_file),
        "--drafts", str(drafts_dir),
        "--output", str(manifest_path),
    ])
    assert scan_result.exit_code == 0, scan_result.output

    # Phase 2: Bulk apply
    apply_result = runner.invoke(app, [
        "bulk", "apply",
        str(manifest_path),
        "--output", str(output_dir),
    ])
    assert apply_result.exit_code == 0, apply_result.output
    assert "completed" in apply_result.output

    # Verify output files exist and are clean
    output_pdfs = list(output_dir.glob("*.pdf"))
    assert len(output_pdfs) == 2
    for pdf in output_pdfs:
        raw = pdf.read_bytes()
        assert b"Jane Doe" not in raw
        assert b"555-12-9876" not in raw


def test_bulk_scan_cli_empty_folder(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    terms = tmp_path / "terms.txt"
    terms.write_text("something\n")

    result = runner.invoke(app, [
        "bulk", "scan",
        str(empty),
        "--terms", str(terms),
    ])

    assert result.exit_code == 1
    assert "No PDF files" in result.output


def test_bulk_scan_cli_no_matches(tmp_path: Path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    _make_pdf(input_dir / "clean.pdf", ["Nothing here."])
    terms = tmp_path / "terms.txt"
    terms.write_text("NONEXISTENT\n")

    result = runner.invoke(app, [
        "bulk", "scan",
        str(input_dir),
        "--terms", str(terms),
    ])

    assert result.exit_code == 1
    assert "No matches found" in result.output


def test_bulk_cli_does_not_print_sensitive_values(tmp_path: Path):
    """Bulk CLI output must never contain extracted document content."""
    input_dir, terms_file = _make_input_folder(tmp_path)

    result = runner.invoke(app, [
        "bulk", "scan",
        str(input_dir),
        "--terms", str(terms_file),
        "--drafts", str(tmp_path / "drafts"),
        "--output", str(tmp_path / "manifest.json"),
    ])

    # Should not contain text that's in the PDFs but not in the terms
    assert "Dear IRS" not in result.output
    assert "Sincerely" not in result.output
    assert "$92,500" not in result.output
    assert "12-3456789" not in result.output


def test_bulk_apply_wrong_manifest_type(tmp_path: Path):
    """Passing a single-file manifest to bulk apply should error clearly."""
    # Create a minimal single-file manifest
    manifest = tmp_path / "single.json"
    manifest.write_text('{"version": "1.0", "source_pdf": "/x.pdf", '
                        '"source_pdf_sha256": "abc", "matches": []}')

    result = runner.invoke(app, [
        "bulk", "apply",
        str(manifest),
    ])

    assert result.exit_code == 1
