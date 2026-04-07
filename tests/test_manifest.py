"""Tests for the manifest module."""

from pathlib import Path

from redact.manifest import (
    compute_file_hash,
    create_manifest,
    read_manifest,
    verify_source_integrity,
    write_manifest,
)
from redact.scanner import scan_pdf


def test_compute_file_hash(pdf_with_ssn: Path):
    h = compute_file_hash(pdf_with_ssn)
    assert len(h) == 64  # SHA-256 hex digest
    # Same file should produce same hash
    assert compute_file_hash(pdf_with_ssn) == h


def test_create_manifest(pdf_with_ssn: Path):
    result = scan_pdf(pdf_with_ssn, ["123-45-6789", "John Smith"])
    manifest = create_manifest(result, pdf_with_ssn)

    assert manifest["version"] == "1.0"
    assert "created_at" in manifest
    assert manifest["source_pdf_sha256"] == compute_file_hash(pdf_with_ssn)
    assert len(manifest["matches"]) == 2
    assert manifest["statistics"]["total_matches"] == 2


def test_manifest_round_trip(tmp_path: Path, pdf_with_ssn: Path):
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest, manifest_path)

    loaded = read_manifest(manifest_path)
    assert loaded["version"] == "1.0"
    assert len(loaded["matches"]) == 1
    assert loaded["matches"][0]["term"] == "123-45-6789"


def test_manifest_statistics(pdf_multipage: Path):
    result = scan_pdf(pdf_multipage, ["111-22-3333", "9876543210"])
    manifest = create_manifest(result, pdf_multipage)

    stats = manifest["statistics"]
    assert stats["total_matches"] == 2
    assert stats["pages_scanned"] == 4
    assert len(stats["pages_affected"]) == 2


def test_verify_source_integrity(pdf_with_ssn: Path):
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    assert verify_source_integrity(manifest) is True


def test_verify_source_integrity_detects_change(
    tmp_path: Path, pdf_with_ssn: Path
):
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    # Tamper with the hash
    manifest["source_pdf_sha256"] = "0" * 64
    assert verify_source_integrity(manifest) is False


def test_read_manifest_validates_keys(tmp_path: Path):
    bad_manifest = tmp_path / "bad.json"
    bad_manifest.write_text('{"version": "1.0"}')

    try:
        read_manifest(bad_manifest)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "missing keys" in str(e)


def test_manifest_does_not_store_matched_text(pdf_with_ssn: Path):
    """The manifest should not contain the actual sensitive text values."""
    result = scan_pdf(pdf_with_ssn, ["123-45-6789"])
    manifest = create_manifest(result, pdf_with_ssn)

    # The matches store the term name (which is the search input),
    # page number, and rect — but NOT the extracted text content
    for m in manifest["matches"]:
        assert set(m.keys()) == {"term", "page", "rect"}
