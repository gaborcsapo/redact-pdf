"""PDF text scanning and match collection.

Searches PDF pages for specified terms and returns match locations
with bounding rectangles for redaction.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import fitz  # PyMuPDF


@dataclasses.dataclass(frozen=True)
class Match:
    """A single text match found in the PDF."""

    term: str
    page_number: int  # 0-indexed
    rect: tuple[float, float, float, float]  # (x0, y0, x1, y1)


@dataclasses.dataclass
class FontWarning:
    """Warning about a font that may prevent reliable text extraction."""

    page_number: int
    font_name: str
    reason: str


@dataclasses.dataclass
class ScanResult:
    """Complete result of scanning a PDF."""

    matches: list[Match]
    font_warnings: list[FontWarning]
    pages_scanned: int
    terms_searched: list[str]


def load_terms(terms_path: Path) -> list[str]:
    """Load search terms from a file, one per line.

    Blank lines and lines starting with # are ignored.
    """
    terms: list[str] = []
    text = terms_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            terms.append(stripped)
    return terms


def _check_fonts(page: fitz.Page) -> list[FontWarning]:
    """Check for fonts that may prevent reliable text extraction."""
    warnings: list[FontWarning] = []
    fonts = page.get_fonts(full=True)
    for font_info in fonts:
        # font_info: (xref, ext, type, basefont, name, encoding, ...)
        font_type = font_info[2] if len(font_info) > 2 else ""
        font_name = font_info[3] if len(font_info) > 3 else "unknown"
        encoding = font_info[5] if len(font_info) > 5 else ""

        if "Type3" in str(font_type):
            warnings.append(FontWarning(
                page_number=page.number,
                font_name=font_name,
                reason="Type 3 font — text extraction unreliable, "
                       "characters may be missed by search",
            ))

        if encoding and "Identity" in str(encoding):
            # Identity encoding without a ToUnicode CMap can cause
            # search failures. We flag it as a warning.
            warnings.append(FontWarning(
                page_number=page.number,
                font_name=font_name,
                reason="Identity encoding detected — may lack Unicode "
                       "mapping, search could miss text",
            ))

    return warnings


def _check_text_vs_images(page: fitz.Page) -> FontWarning | None:
    """Warn if a page has images but little/no extractable text.

    This suggests the page is scanned/image-based.
    """
    text = page.get_text("text").strip()
    images = page.get_images(full=True)

    if images and len(text) < 20:
        return FontWarning(
            page_number=page.number,
            font_name="N/A",
            reason="Page has images but little/no extractable text — "
                   "may be scanned. OCR required for reliable redaction.",
        )
    return None


def scan_pdf(pdf_path: Path, terms: list[str]) -> ScanResult:
    """Scan a PDF for all occurrences of the given terms.

    Uses PyMuPDF's search_for() which returns bounding rectangles
    for each match. Also performs font analysis to warn about
    edge cases where text extraction may be unreliable.
    """
    # Reduce line-height overlap issues in bounding boxes
    fitz.TOOLS.set_small_glyph_heights(True)

    doc = fitz.open(str(pdf_path))
    try:
        all_matches: list[Match] = []
        all_warnings: list[FontWarning] = []

        for page in doc:
            # Font analysis
            all_warnings.extend(_check_fonts(page))

            # Scanned page detection
            img_warning = _check_text_vs_images(page)
            if img_warning:
                all_warnings.append(img_warning)

            # Search for each term
            for term in terms:
                rects = page.search_for(term)
                for rect in rects:
                    all_matches.append(Match(
                        term=term,
                        page_number=page.number,
                        rect=(rect.x0, rect.y0, rect.x1, rect.y1),
                    ))

        return ScanResult(
            matches=all_matches,
            font_warnings=all_warnings,
            pages_scanned=len(doc),
            terms_searched=terms,
        )
    finally:
        doc.close()
