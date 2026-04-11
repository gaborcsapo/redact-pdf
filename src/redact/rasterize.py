"""Rasterize pages that failed verification.

Nuclear option: for pages where verification still finds traces
of redacted terms after the normal redaction pipeline, replace
the entire page content with a rasterized image. This destroys
all text layers, font data, hidden elements, and content streams
for that page — the output page becomes a flat image.

Trade-offs:
  - Selectability, copy/paste, and text search are lost
  - File size increases (images are larger than text)
  - Font antialiasing can look slightly different
  - But: no possibility of text leakage through any vector
    mechanism, because the page is now bytes of pixels
"""

from __future__ import annotations

import re
from pathlib import Path

import fitz  # PyMuPDF

from redact.verify import VerificationResult, verify_redaction


# DPI for rasterization — 300 is print-quality
DEFAULT_DPI = 300


def _pages_from_failures(failures: list[str]) -> set[int]:
    """Extract 1-indexed page numbers mentioned in failure messages.

    Failure messages look like:
        "Text extraction: term '...' found on page 3"
        "Stream inspection: term '...' found in content stream on page 5"
    """
    pages: set[int] = set()
    for f in failures:
        m = re.search(r"page\s+(\d+)", f, re.IGNORECASE)
        if m:
            pages.add(int(m.group(1)))
    return pages


def rasterize_pages(
    pdf_path: Path,
    output_path: Path,
    page_numbers_1indexed: set[int],
    dpi: int = DEFAULT_DPI,
) -> None:
    """Replace the specified pages with rasterized images.

    Builds a new PDF: targeted pages are flattened to images,
    other pages are copied as-is from the source.

    Args:
        pdf_path: Input PDF path (will be read).
        output_path: Where to save the modified PDF.
        page_numbers_1indexed: 1-based page numbers to rasterize.
        dpi: Resolution. Higher = better visual fidelity, larger file.
    """
    if not page_numbers_1indexed:
        if pdf_path != output_path:
            output_path.write_bytes(pdf_path.read_bytes())
        return

    src = fitz.open(str(pdf_path))
    new_doc = fitz.open()
    try:
        zoom = dpi / 72.0
        matrix = fitz.Matrix(zoom, zoom)

        for page_num in range(len(src)):
            page = src[page_num]
            if (page_num + 1) in page_numbers_1indexed:
                # Render this page to an image, put it on a fresh page
                pix = page.get_pixmap(matrix=matrix, alpha=False)
                img_bytes = pix.tobytes("png")
                new_page = new_doc.new_page(
                    width=page.rect.width,
                    height=page.rect.height,
                )
                new_page.insert_image(new_page.rect, stream=img_bytes)
            else:
                # Copy original page unchanged
                new_doc.insert_pdf(
                    src, from_page=page_num, to_page=page_num,
                )

        new_doc.save(str(output_path), garbage=4, deflate=True)
    finally:
        new_doc.close()
        src.close()


def rasterize_failed_pages(
    pdf_path: Path,
    output_path: Path,
    terms: list[str],
    dpi: int = DEFAULT_DPI,
) -> tuple[VerificationResult, set[int]]:
    """Run verification, rasterize any failing pages, and re-verify.

    Returns a tuple of (final verification result, set of 1-indexed
    page numbers that were rasterized).
    """
    initial = verify_redaction(pdf_path, terms)
    if initial.passed:
        # Nothing to do — copy if needed and return
        if pdf_path != output_path:
            output_path.write_bytes(pdf_path.read_bytes())
        return initial, set()

    failing_pages = _pages_from_failures(initial.failures)
    if not failing_pages:
        # Failures don't mention specific pages — can't rasterize targeted.
        # Don't rasterize the whole document; that's too destructive.
        if pdf_path != output_path:
            output_path.write_bytes(pdf_path.read_bytes())
        return initial, set()

    rasterize_pages(pdf_path, output_path, failing_pages, dpi=dpi)

    # Re-verify the rasterized output
    final = verify_redaction(output_path, terms)
    return final, failing_pages
