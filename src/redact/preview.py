"""Generate a preview PDF with highlighted match locations.

The preview uses highlight annotations (not redaction annotations)
so the original data remains untouched for human review.
"""

from __future__ import annotations

from pathlib import Path

import fitz  # PyMuPDF

from redact.scanner import Match

# Orange-yellow highlight for visibility
HIGHLIGHT_COLOR = (1.0, 0.8, 0.0)


def generate_preview(
    source_pdf: Path,
    matches: list[Match],
    output_path: Path,
) -> Path:
    """Create a copy of the PDF with highlights on all match locations.

    This does NOT modify the original file. The preview is a separate
    file that the user can open to review what will be redacted.
    """
    doc = fitz.open(str(source_pdf))
    try:
        for match in matches:
            page = doc[match.page_number]
            rect = fitz.Rect(match.rect)
            annot = page.add_highlight_annot(rect)
            annot.set_colors(stroke=HIGHLIGHT_COLOR)
            annot.set_opacity(0.5)
            annot.update()

        doc.save(str(output_path))
    finally:
        doc.close()

    return output_path
