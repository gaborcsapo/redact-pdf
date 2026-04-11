"""Apply redactions to a PDF.

Uses PyMuPDF's two-phase redaction API:
1. add_redact_annot() — marks areas for redaction
2. apply_redactions() — permanently destroys text in content streams

Followed by pikepdf sanitization for metadata stripping and clean rewrite.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import fitz  # PyMuPDF

from redact.sanitize import sanitize_and_rewrite

# Black fill with "[REDACTED]" overlay text
REDACT_FILL_COLOR = (0, 0, 0)
REDACT_TEXT = "REDACTED"
REDACT_TEXT_COLOR = (1, 1, 1)  # White text on black
REDACT_FONTSIZE = 8


def _flatten_forms(doc: fitz.Document) -> None:
    """Flatten form field widgets into page content streams.

    After this, any interactive AcroForm fields become static text
    in the page content, which apply_redactions() can remove.

    Tries doc.bake() first (PyMuPDF 1.23+). Falls back to manually
    deleting widgets if bake is unavailable.
    """
    if not doc.is_form_pdf:
        return

    # Preferred: use bake() which handles font embedding and layout
    bake_fn = getattr(doc, "bake", None)
    if bake_fn is not None:
        try:
            bake_fn(annots=False, widgets=True)
            return
        except Exception:
            pass

    # Fallback: manually delete widget annotations on each page.
    # This removes interactivity but may leave the text visible
    # if the widget had an appearance stream. Better than nothing.
    for page in doc:
        try:
            widgets = list(page.widgets() or [])
        except Exception:
            continue
        for widget in widgets:
            try:
                page.delete_widget(widget)
            except Exception:
                continue


def apply_redactions(
    source_pdf: Path,
    matches: list[dict],
    output_path: Path,
    terms: list[str] | None = None,
) -> Path:
    """Apply redactions to a PDF and save to output_path.

    Args:
        source_pdf: Path to the original (unmodified) PDF.
        matches: List of match dicts with "page" and "rect" keys.
        output_path: Where to save the redacted PDF.
        terms: Optional list of user search terms. If provided,
            Form XObject content streams containing these terms
            are emptied during the sanitize phase.

    Each match is applied as a black rectangle with "REDACTED" text.
    After PyMuPDF redaction, the file is passed through pikepdf
    for metadata sanitization and a clean structural rewrite.
    """
    # If terms weren't explicitly passed, derive them from the matches
    if terms is None:
        terms = sorted({m["term"] for m in matches if "term" in m})

    # Reduce bounding-box overlap issues
    fitz.TOOLS.set_small_glyph_heights(True)

    doc = fitz.open(str(source_pdf))
    try:
        # Phase 0: Flatten form field widgets into page content streams.
        # Widget field values live in separate appearance streams that
        # apply_redactions() doesn't touch. Baking converts them into
        # regular content stream text, which the redaction step can
        # then remove normally. This also eliminates interactivity:
        # no more clickable/editable fields in the output.
        _flatten_forms(doc)

        # Group matches by page for efficiency
        pages_to_redact: dict[int, list[tuple[float, float, float, float]]] = {}
        for m in matches:
            page_num = m["page"]
            rect = tuple(m["rect"])
            pages_to_redact.setdefault(page_num, []).append(rect)

        # Phase 1: Add redaction annotations
        for page_num, rects in pages_to_redact.items():
            page = doc[page_num]
            for rect_coords in rects:
                rect = fitz.Rect(rect_coords)
                # Pad slightly to catch boundary characters
                rect = rect + (-1, -1, 1, 1)
                page.add_redact_annot(
                    rect,
                    text=REDACT_TEXT,
                    fontsize=REDACT_FONTSIZE,
                    fill=REDACT_FILL_COLOR,
                    text_color=REDACT_TEXT_COLOR,
                )

        # Phase 2: Apply — permanently destroys text in content streams
        for page_num in pages_to_redact:
            page = doc[page_num]
            page.apply_redactions(
                images=fitz.PDF_REDACT_IMAGE_REMOVE,
                graphics=fitz.PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED,
            )

        # Save intermediate result to a temp file for pikepdf processing
        with tempfile.NamedTemporaryFile(
            suffix=".pdf", delete=False
        ) as tmp:
            intermediate_path = Path(tmp.name)

        doc.save(str(intermediate_path), garbage=4, deflate=True)
    finally:
        doc.close()

    # Phase 3: Sanitize metadata and rewrite cleanly with pikepdf.
    # Also scrub Form XObjects for any user terms that leaked through.
    try:
        sanitize_and_rewrite(
            intermediate_path, output_path, scrub_terms=terms,
        )
    finally:
        # Clean up intermediate file
        intermediate_path.unlink(missing_ok=True)

    return output_path
