"""CLI entry point for the redact tool.

Two subcommands:
  redact scan  — find matches, generate preview + manifest
  redact apply — apply redactions from a manifest

Security safeguards applied at startup:
  - Core dumps disabled
  - Spotlight indexing blocked in working directory
  - Sensitive data never printed to terminal
"""

from __future__ import annotations

import os
import resource
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from redact.manifest import (
    compute_file_hash,
    create_manifest,
    read_manifest,
    verify_source_integrity,
    write_manifest,
)
from redact.preview import generate_preview
from redact.redactor import apply_redactions
from redact.scanner import Match, load_terms, scan_pdf
from redact.verify import verify_redaction

app = typer.Typer(
    name="redact",
    help="Secure two-phase PDF redaction tool.",
    no_args_is_help=True,
)
console = Console(stderr=True)


def _apply_security_safeguards() -> None:
    """Apply OS-level security measures before processing any data."""
    # Disable core dumps — a crash would dump all sensitive data in memory
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass

    # Prevent Python from writing .pyc bytecode cache files
    sys.dont_write_bytecode = True


def _block_spotlight(directory: Path) -> None:
    """Drop a .metadata_never_index file to prevent Spotlight indexing."""
    marker = directory / ".metadata_never_index"
    if not marker.exists():
        try:
            marker.touch()
        except OSError:
            pass


def _strip_xattrs(file_path: Path) -> None:
    """Remove all extended attributes from a file (macOS)."""
    try:
        import subprocess

        subprocess.run(
            ["xattr", "-c", str(file_path)],
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass


def _print_scan_results(
    scan_result,
    source_pdf: Path,
) -> None:
    """Print a Rich table summarizing scan results."""
    stats = {}
    pages_per_term: dict[str, set[int]] = {}
    for m in scan_result.matches:
        stats[m.term] = stats.get(m.term, 0) + 1
        pages_per_term.setdefault(m.term, set()).add(m.page_number + 1)

    table = Table(title=f"Scan Results — {source_pdf.name}")
    table.add_column("Term", style="bold")
    table.add_column("Matches", justify="right")
    table.add_column("Pages")

    for term in scan_result.terms_searched:
        count = stats.get(term, 0)
        pages = pages_per_term.get(term, set())
        page_str = ", ".join(str(p) for p in sorted(pages)) if pages else "—"
        style = "green" if count > 0 else "dim"
        table.add_row(term, str(count), page_str, style=style)

    console.print(table)

    total = len(scan_result.matches)
    all_pages = {m.page_number + 1 for m in scan_result.matches}
    console.print(
        f"\nTotal: [bold]{total}[/bold] matches across "
        f"[bold]{len(all_pages)}[/bold] pages "
        f"({scan_result.pages_scanned - len(all_pages)} pages unaffected)"
    )

    # Print font warnings
    if scan_result.font_warnings:
        console.print("\n[yellow bold]Warnings:[/yellow bold]")
        for w in scan_result.font_warnings:
            console.print(
                f"  Page {w.page_number + 1}: {w.reason}"
            )


@app.command()
def scan(
    pdf: Annotated[
        Path,
        typer.Argument(
            help="Path to the PDF file to scan.",
            exists=True,
            readable=True,
        ),
    ],
    terms_file: Annotated[
        Path,
        typer.Option(
            "--terms", "-t",
            help="File containing search terms, one per line.",
            exists=True,
            readable=True,
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output", "-o",
            help="Path for the manifest JSON file.",
        ),
    ] = Path("manifest.json"),
    preview: Annotated[
        Optional[Path],
        typer.Option(
            "--preview", "-p",
            help="Path for the preview PDF with highlights.",
        ),
    ] = None,
) -> None:
    """Scan a PDF for terms and generate a redaction manifest.

    Produces a manifest JSON file listing all matches and a preview
    PDF with highlighted matches for human review.
    """
    _apply_security_safeguards()
    _block_spotlight(output.parent.resolve())

    terms = load_terms(terms_file)
    if not terms:
        console.print("[red]Error:[/red] No search terms found in terms file.")
        raise typer.Exit(code=1)

    console.print(
        f"Scanning [bold]{pdf.name}[/bold] for "
        f"{len(terms)} term(s)...\n"
    )

    scan_result = scan_pdf(pdf, terms)

    if not scan_result.matches:
        console.print("[yellow bold]No matches found.[/yellow bold]\n")
        console.print(f"  Pages scanned: {scan_result.pages_scanned}")
        console.print(f"  Terms searched: {len(terms)}")

        if scan_result.font_warnings:
            console.print("\n[yellow]Possible reasons:[/yellow]")
            for w in scan_result.font_warnings:
                console.print(f"  Page {w.page_number + 1}: {w.reason}")
        else:
            console.print(
                "\n  Tip: Verify the terms file contains text that "
                "appears in this PDF."
            )
        raise typer.Exit(code=1)

    _print_scan_results(scan_result, pdf)

    # Generate preview PDF
    if preview is None:
        preview = pdf.with_stem(pdf.stem + "_preview")

    matches = [
        Match(m.term, m.page_number, m.rect)
        for m in scan_result.matches
    ]
    generate_preview(pdf, matches, preview)
    console.print(f"\nPreview: [blue]{preview}[/blue]")

    # Write manifest
    manifest = create_manifest(scan_result, pdf, preview)
    write_manifest(manifest, output)
    console.print(f"Manifest: [blue]{output}[/blue]")

    console.print(
        "\n[green]Review the preview PDF, then run "
        "[bold]redact apply[/bold] to apply redactions.[/green]"
    )


@app.command(name="apply")
def apply_cmd(
    manifest_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the manifest JSON from the scan phase.",
            exists=True,
            readable=True,
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Path for the redacted PDF output.",
        ),
    ] = None,
) -> None:
    """Apply redactions from a manifest file.

    Reads the manifest produced by `redact scan`, applies true
    redactions that remove text from content streams, sanitizes
    all metadata, and verifies the result.
    """
    _apply_security_safeguards()

    manifest = read_manifest(manifest_path)
    source_pdf = Path(manifest["source_pdf"])

    console.print(f"Source: [bold]{source_pdf.name}[/bold]")

    # Verify source integrity
    if not verify_source_integrity(manifest):
        console.print(
            "[red bold]Error:[/red bold] Source PDF has changed since "
            "scanning. The SHA-256 hash does not match.\n"
            "Please re-run [bold]redact scan[/bold]."
        )
        raise typer.Exit(code=1)

    console.print("[green]Source integrity verified (SHA-256 match).[/green]")

    matches = manifest["matches"]
    if not matches:
        console.print("[yellow]No redactions to apply (0 matches).[/yellow]")
        raise typer.Exit(code=0)

    if output is None:
        output = source_pdf.with_stem(source_pdf.stem + "_redacted")

    _block_spotlight(output.parent.resolve())

    console.print(
        f"Applying [bold]{len(matches)}[/bold] redactions..."
    )

    apply_redactions(source_pdf, matches, output)
    _strip_xattrs(output)

    # Verification pass
    terms = manifest.get("terms", [])
    if terms:
        console.print("Running verification...")
        result = verify_redaction(output, terms)

        if result.passed:
            console.print(
                "[green bold]Verification passed:[/green bold] "
                "0 terms found in redacted output."
            )
            console.print(
                f"  Text extraction: {'clean' if result.text_extraction_clean else 'FAILED'}"
            )
            console.print(
                f"  Stream inspection: {'clean' if result.stream_inspection_clean else 'FAILED'}"
            )
            console.print(
                f"  Byte scan: {'clean' if result.byte_scan_clean else 'FAILED'}"
            )
        else:
            console.print(
                "[red bold]Verification FAILED:[/red bold] "
                "traces of redacted terms remain."
            )
            for f in result.failures:
                console.print(f"  [red]• {f}[/red]")
            console.print(
                "\n[yellow]The output file may not be fully redacted. "
                "Review manually before distributing.[/yellow]"
            )

    console.print(f"\nSaved to: [blue bold]{output}[/blue bold]")


if __name__ == "__main__":
    app()
