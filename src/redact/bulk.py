"""Bulk PDF redaction — process a folder of documents at once.

Folder layout:
    input/       Drop PDFs here
    drafts/      Previews with highlights land here (one per input PDF)
    output/      Final redacted PDFs land here

The bulk manifest tracks all files in a single JSON so the user
can review all drafts at once, then apply everything in one shot.
"""

from __future__ import annotations

import dataclasses
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path

from redact.manifest import compute_file_hash, create_manifest, write_manifest
from redact.preview import generate_preview
from redact.redactor import apply_redactions
from redact.scanner import Match, ScanResult, load_terms, scan_pdf
from redact.verify import verify_redaction


@dataclasses.dataclass
class BulkFileResult:
    """Scan result for a single file in a bulk run."""

    source_pdf: Path
    scan_result: ScanResult
    preview_pdf: Path | None = None


@dataclasses.dataclass
class BulkScanSummary:
    """Overall summary of a bulk scan."""

    files_scanned: int
    files_with_matches: int
    files_without_matches: int
    files_skipped: list[str]  # filenames only, not full paths
    total_matches: int


def discover_pdfs(input_dir: Path) -> list[Path]:
    """Find all PDF files in a directory (non-recursive).

    Only files with a .pdf extension (case-insensitive) are included.
    Hidden files (starting with .) are skipped.
    """
    pdfs = []
    for f in sorted(input_dir.iterdir()):
        if f.is_file() and f.suffix.lower() == ".pdf" and not f.name.startswith("."):
            pdfs.append(f)
    return pdfs


def bulk_scan(
    input_dir: Path,
    terms: list[str],
    drafts_dir: Path,
    manifest_path: Path,
) -> tuple[dict, BulkScanSummary]:
    """Scan all PDFs in input_dir and generate previews in drafts_dir.

    Returns the bulk manifest dict and a summary.
    """
    drafts_dir.mkdir(parents=True, exist_ok=True)

    pdfs = discover_pdfs(input_dir)
    if not pdfs:
        return {}, BulkScanSummary(
            files_scanned=0,
            files_with_matches=0,
            files_without_matches=0,
            files_skipped=[],
            total_matches=0,
        )

    file_manifests: list[dict] = []
    skipped: list[str] = []
    total_matches = 0
    files_with = 0
    files_without = 0

    for pdf_path in pdfs:
        try:
            scan_result = scan_pdf(pdf_path, terms)
        except Exception:
            skipped.append(pdf_path.name)
            continue

        if scan_result.matches:
            files_with += 1
            total_matches += len(scan_result.matches)

            # Generate preview in drafts folder
            preview_path = drafts_dir / f"{pdf_path.stem}_preview.pdf"
            matches = [
                Match(m.term, m.page_number, m.rect)
                for m in scan_result.matches
            ]
            generate_preview(pdf_path, matches, preview_path)

            manifest = create_manifest(scan_result, pdf_path, preview_path)
            file_manifests.append(manifest)
        else:
            files_without += 1

    bulk_manifest = {
        "version": "1.0",
        "type": "bulk",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_dir": str(input_dir.resolve()),
        "drafts_dir": str(drafts_dir.resolve()),
        "terms": terms,
        "files": file_manifests,
        "summary": {
            "files_scanned": len(pdfs) - len(skipped),
            "files_with_matches": files_with,
            "files_without_matches": files_without,
            "files_skipped": skipped,
            "total_matches": total_matches,
        },
    }

    write_manifest(bulk_manifest, manifest_path)

    summary = BulkScanSummary(
        files_scanned=len(pdfs) - len(skipped),
        files_with_matches=files_with,
        files_without_matches=files_without,
        files_skipped=skipped,
        total_matches=total_matches,
    )

    return bulk_manifest, summary


def read_bulk_manifest(manifest_path: Path) -> dict:
    """Read and validate a bulk manifest."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    if data.get("type") != "bulk":
        raise ValueError(
            "Not a bulk manifest. Use `redact apply` for single-file manifests."
        )

    if "files" not in data:
        raise ValueError("Invalid bulk manifest: missing 'files' key.")

    return data


def bulk_apply(
    manifest: dict,
    output_dir: Path,
) -> list[dict]:
    """Apply redactions for all files in a bulk manifest.

    Returns a list of result dicts, one per file, with status and
    verification results.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []

    for file_manifest in manifest["files"]:
        source_pdf = Path(file_manifest["source_pdf"])
        output_path = output_dir / f"{source_pdf.stem}_redacted.pdf"

        result_entry = {
            "source": source_pdf.name,
            "output": str(output_path),
            "status": "pending",
            "matches": len(file_manifest["matches"]),
        }

        # Verify source hasn't changed
        try:
            current_hash = compute_file_hash(source_pdf)
        except Exception as e:
            result_entry["status"] = "error"
            result_entry["phase"] = "hash"
            result_entry["error_type"] = type(e).__name__
            result_entry["error_message"] = str(e)
            result_entry["traceback"] = traceback.format_exc()
            results.append(result_entry)
            continue

        if current_hash != file_manifest["source_pdf_sha256"]:
            result_entry["status"] = "skipped"
            result_entry["reason"] = "source PDF changed since scanning"
            results.append(result_entry)
            continue

        if not file_manifest["matches"]:
            result_entry["status"] = "skipped"
            result_entry["reason"] = "no matches"
            results.append(result_entry)
            continue

        # Phase 1: apply redactions
        try:
            apply_redactions(source_pdf, file_manifest["matches"], output_path)
        except Exception as e:
            result_entry["status"] = "error"
            result_entry["phase"] = "redact"
            result_entry["error_type"] = type(e).__name__
            result_entry["error_message"] = str(e)
            result_entry["traceback"] = traceback.format_exc()
            results.append(result_entry)
            continue

        # Phase 2: verify
        try:
            terms = file_manifest.get("terms", manifest.get("terms", []))
            if terms:
                vr = verify_redaction(output_path, terms)
                result_entry["verification"] = "passed" if vr.passed else "FAILED"
                if not vr.passed:
                    result_entry["verification_failures"] = vr.failures
            else:
                result_entry["verification"] = "skipped (no terms)"

            result_entry["status"] = "done"

        except Exception as e:
            result_entry["status"] = "error"
            result_entry["phase"] = "verify"
            result_entry["error_type"] = type(e).__name__
            result_entry["error_message"] = str(e)
            result_entry["traceback"] = traceback.format_exc()

        results.append(result_entry)

    return results
