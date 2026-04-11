"""Post-redaction PDF sanitization.

Strips all metadata, annotations, JavaScript, embedded files,
and other data that could leak sensitive information.
Uses pikepdf/QPDF for a clean full rewrite of the PDF structure.
"""

from __future__ import annotations

import os
from pathlib import Path

import pikepdf


def sanitize_metadata(pdf: pikepdf.Pdf) -> None:
    """Strip all metadata from every location in the PDF.

    Covers the 15+ metadata locations identified in the security audit:
    Info dictionary, XMP, PieceInfo, structure tree, output intents,
    ICC profiles, UUID identifiers, embedded files, JavaScript,
    form fields, annotations, page labels, OCG layers, thumbnails,
    and per-object XMP metadata.
    """
    # 1. Info dictionary (Author, Title, Subject, Creator, Producer, etc.)
    with pdf.open_metadata() as meta:
        # Iterate all XMP keys and delete them
        for key in list(meta.keys()):
            del meta[key]
    # Also clear the docinfo dict directly
    if pikepdf.Name.Info in pdf.trailer:
        try:
            pdf.trailer[pikepdf.Name.Info] = pdf.make_indirect(pikepdf.Dictionary())
        except Exception:
            pass

    # 2. XMP metadata stream on document root
    if "/Metadata" in pdf.Root:
        del pdf.Root["/Metadata"]

    # 3. PieceInfo (application-specific private data)
    if "/PieceInfo" in pdf.Root:
        del pdf.Root["/PieceInfo"]

    # 4. Structure tree and marked content (tagged PDF accessibility data)
    if "/MarkInfo" in pdf.Root:
        del pdf.Root["/MarkInfo"]
    if "/StructTreeRoot" in pdf.Root:
        del pdf.Root["/StructTreeRoot"]

    # 5. Output intents (ICC profile names, registry info)
    if "/OutputIntents" in pdf.Root:
        del pdf.Root["/OutputIntents"]

    # 6. Document ID — replace with random bytes
    if "/ID" in pdf.trailer:
        pdf.trailer["/ID"] = pikepdf.Array([
            pikepdf.String(os.urandom(16)),
            pikepdf.String(os.urandom(16)),
        ])

    # 7. Embedded files / attachments
    if hasattr(pdf, "attachments"):
        for key in list(pdf.attachments.keys()):
            del pdf.attachments[key]

    # 8. JavaScript and document actions
    if "/OpenAction" in pdf.Root:
        del pdf.Root["/OpenAction"]
    if "/AA" in pdf.Root:
        del pdf.Root["/AA"]
    # Note: /Names tree (JavaScript, EmbeddedFiles, Dests) is deleted
    # entirely in section 11d below.

    # 9. AcroForm (form fields with pre-filled data)
    if "/AcroForm" in pdf.Root:
        del pdf.Root["/AcroForm"]

    # 10. Optional content groups / layers
    if "/OCProperties" in pdf.Root:
        del pdf.Root["/OCProperties"]

    # 11. Page labels (custom page numbering)
    if "/PageLabels" in pdf.Root:
        del pdf.Root["/PageLabels"]

    # 11b. Bookmarks / outline tree — outline items have titles
    # that could contain names, account numbers, or other text.
    if "/Outlines" in pdf.Root:
        del pdf.Root["/Outlines"]
    if "/PageMode" in pdf.Root:
        # /PageMode = UseOutlines pointed at the now-deleted tree
        del pdf.Root["/PageMode"]

    # 11c. Named destinations (/Dests) and viewer preferences
    if "/Dests" in pdf.Root:
        del pdf.Root["/Dests"]
    if "/ViewerPreferences" in pdf.Root:
        del pdf.Root["/ViewerPreferences"]

    # 11d. Remaining /Names tree entries (destinations, URIs, etc.)
    # We already handled /JavaScript and /EmbeddedFiles; clear the rest.
    if "/Names" in pdf.Root:
        del pdf.Root["/Names"]

    # 12. Page-level cleanup
    for page in pdf.pages:
        # Thumbnails (may show redacted content in reduced form)
        if "/Thumb" in page:
            del page["/Thumb"]
        # Per-page metadata
        if "/Metadata" in page:
            del page["/Metadata"]
        # Per-page PieceInfo
        if "/PieceInfo" in page:
            del page["/PieceInfo"]
        # Per-page actions
        if "/AA" in page:
            del page["/AA"]
        # All annotations on this page — including widgets, comments,
        # stamps, sticky notes, free-text annotations, links. Their
        # appearance streams (/AP) can contain text the main content
        # stream redaction misses. Redacted text that should have
        # been destroyed can linger in these appearance streams.
        if "/Annots" in page:
            del page["/Annots"]
        # Tabs entry references structure tree which we're removing
        if "/Tabs" in page:
            del page["/Tabs"]
        # Per-page article threads (/B for Beads)
        if "/B" in page:
            del page["/B"]

    # 13. XMP metadata on all indirect objects (images, fonts, etc.)
    for obj_id in range(1, len(pdf.objects)):
        try:
            obj = pdf.objects.get(obj_id)
            if obj is None:
                continue
            if isinstance(obj, pikepdf.Dictionary) and "/Metadata" in obj:
                del obj["/Metadata"]
            if isinstance(obj, pikepdf.Stream) and "/Metadata" in obj:
                del obj["/Metadata"]
        except Exception:
            continue


def sanitize_and_rewrite(input_path: Path, output_path: Path) -> None:
    """Open a PDF, strip all metadata, and rewrite cleanly.

    Uses QPDF's linearization to force a complete structural rewrite,
    ensuring no orphaned objects or incremental update artifacts survive.
    """
    pdf = pikepdf.open(str(input_path))
    try:
        sanitize_metadata(pdf)

        # Remove unreferenced resources (orphaned objects)
        try:
            pdf.remove_unreferenced_resources()
        except Exception:
            pass

        # Save with linearization for a clean, complete rewrite.
        # This eliminates incremental save artifacts where old
        # (pre-redaction) data could be recovered.
        pdf.save(
            str(output_path),
            linearize=True,
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
        )
    finally:
        pdf.close()
