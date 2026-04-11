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

    Form fields are flattened in the preview so highlights land on
    the correct positions — matches from the scanner reference the
    flattened coordinates.
    """
    doc = fitz.open(str(source_pdf))
    try:
        # Flatten form fields to match the scanner's view of the document
        if doc.is_form_pdf:
            bake_fn = getattr(doc, "bake", None)
            if bake_fn is not None:
                try:
                    bake_fn(annots=False, widgets=True)
                except Exception:
                    pass

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
