"""Integration tests for the CLI."""

from pathlib import Path

from typer.testing import CliRunner

from redact.cli import app

runner = CliRunner()


def test_scan_produces_manifest_and_preview(
    tmp_path: Path, pdf_with_ssn: Path, terms_file: Path
):
    manifest_path = tmp_path / "manifest.json"
    preview_path = tmp_path / "preview.pdf"

    result = runner.invoke(app, [
        "scan",
        str(pdf_with_ssn),
        "--terms", str(terms_file),
        "--output", str(manifest_path),
        "--preview", str(preview_path),
    ])

    assert result.exit_code == 0, result.output
    assert manifest_path.exists()
    assert preview_path.exists()


def test_scan_no_matches_exits_with_code_1(
    tmp_path: Path, pdf_no_matches: Path
):
    terms = tmp_path / "terms.txt"
    terms.write_text("NONEXISTENT_TERM\n")

    result = runner.invoke(app, [
        "scan",
        str(pdf_no_matches),
        "--terms", str(terms),
        "--output", str(tmp_path / "manifest.json"),
    ])

    assert result.exit_code == 1
    assert "No matches found" in result.output


def test_scan_empty_terms_file_exits_with_code_1(
    tmp_path: Path, pdf_with_ssn: Path
):
    terms = tmp_path / "empty.txt"
    terms.write_text("# only comments\n\n")

    result = runner.invoke(app, [
        "scan",
        str(pdf_with_ssn),
        "--terms", str(terms),
    ])

    assert result.exit_code == 1
    assert "No search terms" in result.output


def test_full_scan_then_apply_workflow(
    tmp_path: Path, pdf_with_ssn: Path, terms_file: Path
):
    """End-to-end: scan → produce manifest → apply → verify."""
    manifest_path = tmp_path / "manifest.json"

    # Phase 1: Scan
    scan_result = runner.invoke(app, [
        "scan",
        str(pdf_with_ssn),
        "--terms", str(terms_file),
        "--output", str(manifest_path),
        "--preview", str(tmp_path / "preview.pdf"),
    ])
    assert scan_result.exit_code == 0, scan_result.output

    # Phase 2: Apply
    output_path = tmp_path / "redacted.pdf"
    apply_result = runner.invoke(app, [
        "apply",
        str(manifest_path),
        "--output", str(output_path),
    ])
    assert apply_result.exit_code == 0, apply_result.output
    assert "Verification passed" in apply_result.output
    assert output_path.exists()

    # Final check: sensitive data should not be in the output file bytes
    raw = output_path.read_bytes()
    assert b"123-45-6789" not in raw
    assert b"987-65-4321" not in raw
    assert b"John Smith" not in raw


def test_apply_detects_tampered_source(
    tmp_path: Path, pdf_with_ssn: Path, terms_file: Path
):
    """Apply should refuse if the source PDF changed since scanning."""
    manifest_path = tmp_path / "manifest.json"

    runner.invoke(app, [
        "scan",
        str(pdf_with_ssn),
        "--terms", str(terms_file),
        "--output", str(manifest_path),
    ])

    # Tamper with the source PDF
    pdf_with_ssn.write_bytes(pdf_with_ssn.read_bytes() + b"\n% tampered")

    result = runner.invoke(app, [
        "apply",
        str(manifest_path),
    ])

    assert result.exit_code == 1
    assert "changed since scanning" in result.output


def test_cli_does_not_print_sensitive_values(
    tmp_path: Path, pdf_with_ssn: Path, terms_file: Path
):
    """The CLI output should never contain actual sensitive data values."""
    manifest_path = tmp_path / "manifest.json"

    result = runner.invoke(app, [
        "scan",
        str(pdf_with_ssn),
        "--terms", str(terms_file),
        "--output", str(manifest_path),
    ])

    # The term names appear in the stats table (they're the user's input).
    # But extracted text from the PDF that is NOT a search term should
    # never appear in the output.
    assert "Taxpayer Name" not in result.output
    assert "Filing Status" not in result.output
    assert "Married Filing Jointly" not in result.output
    # "Evergreen Terrace" IS in the terms file, so it correctly appears
    # in the stats table — that's the user's own input, not extracted data.
