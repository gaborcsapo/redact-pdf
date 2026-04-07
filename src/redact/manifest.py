"""JSON manifest for the two-phase redaction workflow.

The manifest stores scan results between the scan and apply phases,
allowing human review before redaction is applied.

Privacy: matched text values are never stored in the manifest.
Only term names, page numbers, and rectangle coordinates are kept.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from redact.scanner import Match, ScanResult


def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _build_statistics(matches: list[Match], pages_scanned: int) -> dict:
    """Build statistics summary from matches."""
    per_term: dict[str, int] = {}
    pages_affected: set[int] = set()

    for m in matches:
        per_term[m.term] = per_term.get(m.term, 0) + 1
        pages_affected.add(m.page_number)

    return {
        "total_matches": len(matches),
        "pages_scanned": pages_scanned,
        "pages_affected": sorted(pages_affected),
        "matches_per_term": per_term,
    }


def create_manifest(
    scan_result: ScanResult,
    source_pdf: Path,
    preview_pdf: Path | None = None,
) -> dict:
    """Create a manifest dict from scan results.

    The manifest intentionally does NOT store:
    - Actual matched text content (even partially masked)
    - The original filename if it contains PII
    - Search patterns (reveals what the user considers sensitive)

    It stores only what's needed to apply redactions:
    term labels, page numbers, and bounding rectangles.
    """
    manifest = {
        "version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_pdf": str(source_pdf.resolve()),
        "source_pdf_sha256": compute_file_hash(source_pdf),
        "terms": scan_result.terms_searched,
        "matches": [
            {
                "term": m.term,
                "page": m.page_number,
                "rect": list(m.rect),
            }
            for m in scan_result.matches
        ],
        "font_warnings": [
            {
                "page": w.page_number,
                "font": w.font_name,
                "reason": w.reason,
            }
            for w in scan_result.font_warnings
        ],
        "statistics": _build_statistics(
            scan_result.matches, scan_result.pages_scanned
        ),
    }

    if preview_pdf:
        manifest["preview_pdf"] = str(preview_pdf.resolve())

    return manifest


def write_manifest(manifest: dict, output_path: Path) -> None:
    """Write manifest to a JSON file."""
    output_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def read_manifest(manifest_path: Path) -> dict:
    """Read and validate a manifest from disk."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    required_keys = {"version", "source_pdf", "source_pdf_sha256", "matches"}
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"Invalid manifest: missing keys {missing}")

    return data


def verify_source_integrity(manifest: dict) -> bool:
    """Verify the source PDF has not changed since scanning."""
    source = Path(manifest["source_pdf"])
    if not source.exists():
        raise FileNotFoundError(
            f"Source PDF not found: {source}"
        )
    current_hash = compute_file_hash(source)
    return current_hash == manifest["source_pdf_sha256"]
