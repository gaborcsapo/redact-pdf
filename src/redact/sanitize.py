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

    # 13. Sweep metadata entries from ALL indirect objects.
    # Images, fonts, and XObjects can carry their own XMP, XML,
    # and PieceInfo dictionaries that the per-page loop misses.
    _sweep_object_metadata(pdf)

    # 14. Strip font subset leakage: /CharSet and /CIDSet list
    # exactly which characters a subsetted font contains.
    # Deleting these removes the easy explicit leak.
    _strip_font_subset_hints(pdf)


def _is_dict_like(obj) -> bool:
    """Check if an object supports dict-like key access."""
    try:
        # Dictionary and Stream both support this
        return hasattr(obj, "keys") and callable(obj.keys)
    except Exception:
        return False


def _sweep_object_metadata(pdf: pikepdf.Pdf) -> None:
    """Delete metadata-like entries from every indirect object."""
    metadata_keys = ("/Metadata", "/PieceInfo", "/XML", "/LastModified")
    for obj in pdf.objects:
        try:
            if not _is_dict_like(obj):
                continue
            for key in metadata_keys:
                try:
                    if key in obj:
                        del obj[key]
                except Exception:
                    continue
        except Exception:
            continue


def _strip_font_subset_hints(pdf: pikepdf.Pdf) -> None:
    """Delete /CharSet and /CIDSet from all font descriptors.

    These entries explicitly list which characters are in a font
    subset. For a subsetted font that rendered "Smith", the
    CharSet literally contains the letters S,M,I,T,H — a direct
    leak of the redacted text's character set.

    Rendering continues to work without these (they're optional
    spec additions).
    """
    font_desc = pikepdf.Name("/FontDescriptor")
    for obj in pdf.objects:
        try:
            if not _is_dict_like(obj):
                continue
            try:
                obj_type = obj.get("/Type")
            except Exception:
                continue
            if obj_type != font_desc:
                continue
            for key in ("/CharSet", "/CIDSet"):
                try:
                    if key in obj:
                        del obj[key]
                except Exception:
                    continue
        except Exception:
            continue


def scrub_form_xobjects(pdf: pikepdf.Pdf, terms: list[str]) -> list[int]:
    """Empty Form XObject content streams that contain any search term.

    Form XObjects are reusable content streams referenced by pages via
    /Fm1 Do operators. apply_redactions() may not reach into these
    streams, so sensitive text can survive redaction when it lives
    inside a Form XObject (common for tax form templates).

    For each Form XObject, we decode its content stream and check for
    the presence of any user term. If found, we replace the entire
    content stream with an empty stream. This destroys the XObject's
    visual but guarantees the sensitive text is gone.

    Returns a list of object IDs (approximate indices) that were
    scrubbed. Callers use this list for logging only.
    """
    if not terms:
        return []

    # Pre-encode terms in multiple encodings for byte matching
    encoded_terms: list[bytes] = []
    for t in terms:
        for encoding in ("utf-8", "latin-1", "utf-16-be"):
            try:
                encoded_terms.append(t.lower().encode(encoding))
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue

    if not encoded_terms:
        return []

    xobj_name = pikepdf.Name("/XObject")
    form_name = pikepdf.Name("/Form")

    scrubbed: list[int] = []
    for idx, obj in enumerate(pdf.objects):
        try:
            # Must be a stream with dict-like keys
            if not isinstance(obj, pikepdf.Stream):
                continue
            # Check it's a Form XObject
            try:
                if obj.get("/Subtype") != form_name:
                    continue
                # /Type is optional but if present must be /XObject
                obj_type = obj.get("/Type")
                if obj_type is not None and obj_type != xobj_name:
                    continue
            except Exception:
                continue

            try:
                content = bytes(obj.read_bytes())
            except Exception:
                continue

            content_lower = content.lower()
            if not any(et in content_lower for et in encoded_terms):
                continue

            # Empty the content stream
            try:
                obj.write(b"")
                scrubbed.append(idx)
            except Exception:
                continue
        except Exception:
            continue

    return scrubbed


def sanitize_and_rewrite(
    input_path: Path,
    output_path: Path,
    scrub_terms: list[str] | None = None,
) -> list[int]:
    """Open a PDF, strip all metadata, and rewrite cleanly.

    Uses QPDF's linearization to force a complete structural rewrite,
    ensuring no orphaned objects or incremental update artifacts survive.

    If scrub_terms is provided, also empties Form XObject content
    streams that contain any of those terms. Returns the list of
    scrubbed object IDs (empty if none or if scrub_terms is None).
    """
    pdf = pikepdf.open(str(input_path))
    try:
        sanitize_metadata(pdf)

        scrubbed_xobjects: list[int] = []
        if scrub_terms:
            scrubbed_xobjects = scrub_form_xobjects(pdf, scrub_terms)

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
        return scrubbed_xobjects
    finally:
        pdf.close()
