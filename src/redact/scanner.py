"""PDF text scanning and match collection.

Searches PDF pages for specified terms and returns match locations
with bounding rectangles for redaction.

Smart term expansion automatically generates separator variants,
suffix searches, and mask-stripped forms so the user only needs
to write each sensitive number once.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import fitz  # PyMuPDF

# Characters treated as separators between digit groups
_SEPARATORS = re.compile(r"[-\s.]+")

# Characters treated as masking in partially-redacted numbers
_MASK_CHARS = re.compile(r"^[*Xx.·•]+")

# A term that contains at least one digit mixed with separators
_HAS_DIGIT_WITH_SEP = re.compile(r"\d.*[-\s.]+.*\d|\d{2,}")


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


def _extract_digits(s: str) -> str:
    """Extract only digit characters from a string."""
    return "".join(c for c in s if c.isdigit())


def _extract_digit_groups(s: str) -> list[str]:
    """Extract groups of consecutive digits from a string."""
    return re.findall(r"\d+", s)


def _strip_mask(s: str) -> str | None:
    """If a term has leading mask characters before digits, extract the digits.

    Examples:
        "***-**-6789"    → "6789"
        "XXXX1234"       → "1234"
        "****-****-1234" → "1234"
        "....5678"       → "5678"
        "John Smith"     → None (no mask pattern)
    """
    # Remove dashes and spaces (but NOT dots — dots can be mask chars)
    cleaned = re.sub(r"[-\s]+", "", s)
    # Check if it starts with mask characters followed by digits
    mask_match = _MASK_CHARS.match(cleaned)
    if not mask_match:
        return None
    remainder = cleaned[mask_match.end():]
    if remainder and remainder.isdigit() and len(remainder) >= 3:
        return remainder
    return None


def expand_term(term: str) -> list[str]:
    """Expand a single term into all search variants.

    Rules:
    1. Separator variants — for terms with digits + separators,
       generate forms with dashes, spaces, dots, and no separators.
    2. Suffix search — for digit sequences >= 6 digits, also
       search for the last 4 and last 5 digits.
    3. Mask stripping — if term has mask characters (*, X, x)
       before digits, extract the digit portion.

    Non-numeric terms (names, addresses) pass through unchanged.
    """
    variants: list[str] = [term]

    # Rule 3: Mask stripping — extract digits from masked terms
    stripped = _strip_mask(term)
    if stripped:
        # For a masked term like "***-**-6789", the meaningful part
        # is just the digits. Expand those digits instead.
        variants.append(stripped)
        # Also apply separator variants to the extracted digits
        # if they're long enough to have groups
        digits = stripped
    else:
        digits = _extract_digits(term)

    groups = _extract_digit_groups(term)
    has_separators = bool(groups) and len(groups) > 1

    # Rule 1: Separator variants
    if has_separators and digits:
        # Generate variants preserving the original grouping pattern
        variants.append(digits)                           # no separators
        variants.append("-".join(groups))                 # dashes
        variants.append(" ".join(groups))                 # spaces
        variants.append(".".join(groups))                 # dots
    elif digits and len(digits) >= 2 and not has_separators:
        # Pure digit sequence or term with digits but no sep groups
        # Still add it as-is (already in variants)
        pass

    # Rule 2: Suffix search for partial masking
    if len(digits) >= 6:
        last4 = digits[-4:]
        last5 = digits[-5:]
        variants.append(last4)
        variants.append(last5)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for v in variants:
        v_stripped = v.strip()
        if v_stripped and v_stripped not in seen:
            seen.add(v_stripped)
            unique.append(v_stripped)

    return unique


def expand_terms(terms: list[str]) -> dict[str, list[str]]:
    """Expand all terms and return a mapping of original → variants."""
    return {term: expand_term(term) for term in terms}


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
            warnings.append(FontWarning(
                page_number=page.number,
                font_name=font_name,
                reason="Identity encoding detected — may lack Unicode "
                       "mapping, search could miss text",
            ))

    return warnings


def _check_text_vs_images(page: fitz.Page) -> FontWarning | None:
    """Warn if a page has images but little/no extractable text."""
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


def _check_line_breaks(
    page: fitz.Page,
    term: str,
    digits: str,
    already_found: bool,
) -> FontWarning | None:
    """Check if a digit sequence appears in collapsed page text
    but was not found by the standard search (suggesting a line break).
    """
    if not digits or len(digits) < 6 or already_found:
        return None

    # Extract text, collapse whitespace
    raw_text = page.get_text("text")
    collapsed = re.sub(r"\s+", "", raw_text)

    if digits in collapsed:
        return FontWarning(
            page_number=page.number,
            font_name="N/A",
            reason=f"A search term appears on this page but may be split "
                   f"across lines. Manual review recommended.",
        )
    return None


def _deduplicate_rects(rects: list[fitz.Rect]) -> list[fitz.Rect]:
    """Remove rects that are contained within or nearly overlap a larger rect.

    When a suffix variant (e.g., "6789") matches inside the same text
    that the full variant (e.g., "123-45-6789") also matched, we get
    two rects — one large, one small. We keep only the larger one.

    Two rects on the same horizontal line are considered overlapping
    if one's x-range is within the other's (with a small tolerance).
    """
    if not rects:
        return []

    # Sort by width descending so we check large rects first
    sorted_rects = sorted(rects, key=lambda r: r.width, reverse=True)
    kept: list[fitz.Rect] = []
    tolerance = 2.0  # points

    for rect in sorted_rects:
        is_contained = False
        for existing in kept:
            # Check if rect is on the same line and within the x-range
            same_line = (
                abs(rect.y0 - existing.y0) < tolerance
                and abs(rect.y1 - existing.y1) < tolerance
            )
            x_contained = (
                rect.x0 >= existing.x0 - tolerance
                and rect.x1 <= existing.x1 + tolerance
            )
            if same_line and x_contained:
                is_contained = True
                break
        if not is_contained:
            kept.append(rect)

    return kept


def _find_via_text_dict(
    page_dict: dict,
    variants: list[str],
) -> list[fitz.Rect]:
    """Fallback: use page.get_text('dict') to find term variants.

    When search_for() misses text (due to font encoding quirks,
    hidden text layers with render mode 3, or unusual CMaps),
    get_text('dict') may still extract it because it uses a
    different text extraction pipeline inside PyMuPDF.

    Walks the page's text structure (blocks → lines → spans) and
    checks each line's concatenated text for any variant. Returns
    bounding rectangles of matching lines.
    """
    rects: list[fitz.Rect] = []
    lowered_variants = [v.lower() for v in variants if v]
    if not lowered_variants:
        return rects

    for block in page_dict.get("blocks", []):
        if block.get("type") != 0:  # 0 = text block
            continue
        for line in block.get("lines", []):
            spans = line.get("spans", [])
            if not spans:
                continue
            # Concatenate span texts to reconstruct the line
            line_text = "".join(s.get("text", "") for s in spans).lower()
            for variant in lowered_variants:
                if variant in line_text:
                    # Use the line bounding box as the match rect.
                    # This may over-redact a bit (the whole line
                    # rather than just the matching substring), but
                    # that's safe and biases toward recall.
                    bbox = line.get("bbox")
                    if bbox and len(bbox) == 4:
                        rects.append(fitz.Rect(*bbox))
                    break  # one rect per line is enough
    return rects


def _flatten_forms_for_scan(doc: fitz.Document) -> None:
    """Flatten form widgets into content streams so search_for finds them.

    Form field values are stored in separate widget appearance streams
    that search_for() doesn't enter. Baking converts them into regular
    content stream text at the widget's rectangle, so our normal
    text search can find them.

    This is done in-memory on the open doc object — the source file
    is not modified (we never save this doc).
    """
    if not doc.is_form_pdf:
        return
    bake_fn = getattr(doc, "bake", None)
    if bake_fn is not None:
        try:
            bake_fn(annots=False, widgets=True)
        except Exception:
            pass


def scan_pdf(pdf_path: Path, terms: list[str]) -> ScanResult:
    """Scan a PDF for all occurrences of the given terms.

    Each term is automatically expanded into separator variants,
    suffix forms, and mask-stripped forms before searching.
    Uses PyMuPDF's search_for() which returns bounding rectangles.

    Form field widgets are flattened in-memory before scanning so
    their text becomes searchable. The source file is never modified.
    """
    fitz.TOOLS.set_small_glyph_heights(True)

    expansion_map = expand_terms(terms)

    doc = fitz.open(str(pdf_path))
    try:
        _flatten_forms_for_scan(doc)

        all_matches: list[Match] = []
        all_warnings: list[FontWarning] = []

        for page in doc:
            all_warnings.extend(_check_fonts(page))

            img_warning = _check_text_vs_images(page)
            if img_warning:
                all_warnings.append(img_warning)

            # Extract structured text once per page for the fallback pass
            try:
                page_dict = page.get_text("dict")
            except Exception:
                page_dict = None

            for original_term, variants in expansion_map.items():
                found_any = False
                # Collect all rects found by all variants for this term
                # on this page, then deduplicate by overlap.
                page_rects: list[fitz.Rect] = []
                for variant in variants:
                    rects = page.search_for(variant)
                    page_rects.extend(rects)

                # Deduplicate: drop rects that are contained within
                # a larger rect (suffix match inside a full match).
                # Keep the largest non-overlapping set.
                deduped = _deduplicate_rects(page_rects)

                # Fallback pass: if search_for found nothing for this
                # term on this page, check page.get_text("dict") to
                # catch text that search_for missed due to font
                # encoding quirks or hidden text layers.
                if not deduped and page_dict is not None:
                    fallback_rects = _find_via_text_dict(
                        page_dict, variants,
                    )
                    deduped = _deduplicate_rects(fallback_rects)

                for rect in deduped:
                    all_matches.append(Match(
                        term=original_term,
                        page_number=page.number,
                        rect=(rect.x0, rect.y0, rect.x1, rect.y1),
                    ))
                    found_any = True

                # Line break detection
                digits = _extract_digits(original_term)
                lb_warning = _check_line_breaks(
                    page, original_term, digits, found_any,
                )
                if lb_warning:
                    all_warnings.append(lb_warning)

        return ScanResult(
            matches=all_matches,
            font_warnings=all_warnings,
            pages_scanned=len(doc),
            terms_searched=terms,
        )
    finally:
        doc.close()
