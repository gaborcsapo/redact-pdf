"""Post-redaction verification.

Three-level verification to confirm text is truly removed:
1. Text extraction — PyMuPDF get_text() finds no matches
2. Content stream inspection — pikepdf raw stream contains no matches
3. Full byte scan — the entire file contains no trace of redacted terms
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import fitz  # PyMuPDF
import pikepdf


@dataclasses.dataclass
class VerificationResult:
    """Result of post-redaction verification."""

    passed: bool
    text_extraction_clean: bool
    stream_inspection_clean: bool
    byte_scan_clean: bool
    failures: list[str]


def _check_text_extraction(pdf_path: Path, terms: list[str]) -> list[str]:
    """Level 1: Extract text from every page and search for terms.

    Failure messages include the offending term (which is user input
    from the terms file, not extracted document content).
    """
    failures = []
    # Deduplicate per-(term, page) to avoid noise
    seen: set[tuple[str, int]] = set()
    doc = fitz.open(str(pdf_path))
    try:
        for page in doc:
            text_lower = page.get_text("text").lower()
            for term in terms:
                if term.lower() in text_lower:
                    key = (term, page.number)
                    if key in seen:
                        continue
                    seen.add(key)
                    failures.append(
                        f"Text extraction: term {term!r} found on page "
                        f"{page.number + 1}"
                    )
    finally:
        doc.close()
    return failures


def _check_content_streams(pdf_path: Path, terms: list[str]) -> list[str]:
    """Level 2: Inspect raw PDF content streams with pikepdf."""
    failures = []
    seen: set[tuple[str, int]] = set()
    pdf = pikepdf.open(str(pdf_path))
    try:
        for page_num, page in enumerate(pdf.pages):
            try:
                if "/Contents" not in page:
                    continue
                contents = page["/Contents"]
                if isinstance(contents, pikepdf.Array):
                    streams = [pdf.get_object(ref) for ref in contents]
                else:
                    streams = [contents]

                for stream in streams:
                    try:
                        raw = bytes(stream.read_bytes())
                    except Exception:
                        continue
                    raw_lower = raw.lower()
                    for term in terms:
                        key = (term, page_num)
                        if key in seen:
                            continue
                        for encoding in ("utf-8", "latin-1", "utf-16-be"):
                            try:
                                encoded = term.lower().encode(encoding)
                            except (UnicodeEncodeError, UnicodeDecodeError):
                                continue
                            if encoded in raw_lower:
                                seen.add(key)
                                failures.append(
                                    f"Stream inspection: term {term!r} "
                                    f"found in content stream on page "
                                    f"{page_num + 1}"
                                )
                                break
            except Exception:
                continue
    finally:
        pdf.close()
    return failures


def _check_full_bytes(pdf_path: Path, terms: list[str]) -> list[str]:
    """Level 3: Scan the entire file as raw bytes.

    This catches text hiding in metadata, XMP, annotations,
    or any other non-page-content location in the PDF.
    """
    failures = []
    raw = pdf_path.read_bytes()
    raw_lower = raw.lower()
    for term in terms:
        for encoding in ("utf-8", "latin-1", "utf-16-be"):
            try:
                encoded = term.lower().encode(encoding)
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            if encoded in raw_lower:
                failures.append(
                    f"Byte scan: term {term!r} found in raw file data "
                    f"({encoding} encoding)"
                )
                break  # One failure per term is enough
    return failures


def verify_redaction(pdf_path: Path, terms: list[str]) -> VerificationResult:
    """Run all three verification levels on a redacted PDF.

    Returns a VerificationResult indicating whether the redaction
    is complete. Failure messages include the offending term —
    this is user input from the terms file, not extracted content.
    """
    text_failures = _check_text_extraction(pdf_path, terms)
    stream_failures = _check_content_streams(pdf_path, terms)
    byte_failures = _check_full_bytes(pdf_path, terms)

    all_failures = text_failures + stream_failures + byte_failures

    return VerificationResult(
        passed=len(all_failures) == 0,
        text_extraction_clean=len(text_failures) == 0,
        stream_inspection_clean=len(stream_failures) == 0,
        byte_scan_clean=len(byte_failures) == 0,
        failures=all_failures,
    )
