# redact-pdf

A CLI tool that actually redacts PDFs. Not "draw a black box and hope for the best" redaction — **real** redaction that rips the text out of the file's content streams, scrubs metadata, and verifies the job is done.

Built because every year I'd prepare tax documents and think "surely there's a simple command-line tool for this." There wasn't.

## How it works

Two phases. You scan first, review what will be removed, then apply.

```bash
# Step 1: Tell it what to find
redact scan taxes.pdf --terms terms.txt

# Step 2: Open the preview PDF, make sure it looks right
# Step 3: Pull the trigger
redact apply manifest.json --output taxes_redacted.pdf
```

That's it. Your SSNs, addresses, and account numbers are gone — not hidden under a rectangle, but deleted from the underlying PDF data.

### The scan phase

```
$ redact scan taxes.pdf --terms terms.txt

Scanning taxes.pdf for 3 term(s)...

         Scan Results — taxes.pdf
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┓
┃ Term            ┃ Matches ┃ Pages ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━┩
│ Jane Doe        │       1 │ 1     │
│ 555-12-9876     │       1 │ 1     │
│ 1234 Oak Street │       1 │ 1     │
└─────────────────┴─────────┴───────┘

Total: 3 matches across 1 pages (0 pages unaffected)

Preview: taxes_preview.pdf
Manifest: manifest.json
```

It produces two files:
- **Preview PDF** — your original with yellow highlights over every match. Open it. Check that the right things are highlighted and nothing is missed.
- **Manifest** — a JSON file that records where the redactions go. No sensitive content is stored in it.

### The apply phase

```
$ redact apply manifest.json --output taxes_redacted.pdf

Source: taxes.pdf
Source integrity verified (SHA-256 match).
Applying 3 redactions...
Running verification...
Verification passed: 0 terms found in redacted output.
  Text extraction: clean
  Stream inspection: clean
  Byte scan: clean

Saved to: taxes_redacted.pdf
```

Three-level verification runs automatically:
1. Text extraction — can the text be read from the page?
2. Stream inspection — is the text hiding in the raw PDF content streams?
3. Byte scan — does the text appear *anywhere* in the file, in any encoding?

If any check fails, you'll know.

## The terms file

One term per line. Comments and blank lines are fine.

```
# terms.txt
# SSNs
123-45-6789
987-65-4321

# Names and addresses
Jane Doe
1234 Oak Street, Anytown
```

## Install

Requires Python 3.10+.

```bash
# With uv (recommended)
uv tool install redact-pdf

# With pip
pip install redact-pdf

# From source
git clone https://github.com/gaborcsapo/redact-pdf.git
cd redact-pdf
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

## What makes this different from drawing black boxes

Most "redaction" tools — including some commercial ones — just paint over the text. The data is still in the file. Select-all, copy, paste into a text editor, and there's your SSN. This has [caused real problems](https://en.wikipedia.org/wiki/Manafort_trial#Redaction_failure) for people who should have known better.

`redact-pdf` takes a different approach:

| Step | What happens |
|---|---|
| **Text removal** | PyMuPDF's `apply_redactions()` rewrites the content stream, destroying the text operators for redacted characters |
| **Image removal** | Images overlapping redaction areas are removed |
| **Metadata scrub** | pikepdf strips 15+ metadata locations: XMP, docinfo, structure tree, thumbnails, embedded files, JavaScript, form fields, annotations, and more |
| **Clean rewrite** | The entire PDF is rewritten from scratch via QPDF linearization — no incremental save artifacts, no orphaned objects, no recoverable history |
| **Verification** | The output is scanned at three levels to confirm zero traces remain |

A black `REDACTED` label is placed where the text used to be, so readers know something was there.

## Security model

**Everything is local.** No network calls, no telemetry, no cloud anything. The libraries used (PyMuPDF, pikepdf, Typer, Rich) have been audited — none of them make network connections or send data anywhere.

Additional safeguards:
- **Core dumps disabled** at startup (a crash won't dump your data to disk)
- **Spotlight indexing blocked** via `.metadata_never_index` in the working directory
- **Extended attributes stripped** from output files on macOS
- **Sensitive text never printed** to the terminal — only match counts and page numbers
- **Terms read from a file**, not CLI arguments (so they don't end up in shell history)
- **Source integrity check** — the apply phase verifies the PDF hasn't changed since scanning

### Known limitations

Be aware of these edge cases:

- **Scanned/image-only PDFs**: If the PDF is a scan with no text layer, there's nothing to search. The tool warns you when it detects this.
- **Text rendered as vector paths**: Some PDFs convert text to outlines (curves). This text is invisible to any text-based search. The tool cannot find it.
- **Type 3 fonts / exotic encodings**: Some fonts don't map to Unicode properly. The tool warns when it detects these, but matches may be missed.
- **Font subsetting**: After redaction, the embedded font subset may still contain glyphs for redacted characters. For high-security use cases, consider re-processing with full font replacement.

For maximum security on critical documents, consider also rasterizing the output (print to PDF at 300 DPI).

## Development

```bash
git clone https://github.com/gaborcsapo/redact-pdf.git
cd redact-pdf
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest
```

Tests generate PDFs on the fly with ReportLab — no binary test fixtures in the repo. Every redaction test verifies text removal at the byte level, not just visually.

## License

MIT. Do whatever you want with it.

Note: PyMuPDF (a dependency) is AGPL-3.0 licensed. If you're using this tool for personal/internal use, that's fine — AGPL only kicks in if you distribute modified software or serve it over a network. See [Artifex licensing](https://artifex.com/licensing) for details.
