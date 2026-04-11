"""CLI entry point for the redact tool.

Subcommands:
  redact scan       — scan a single PDF, generate preview + manifest
  redact apply      — apply redactions from a manifest
  redact bulk scan  — scan a folder of PDFs
  redact bulk apply — apply redactions for an entire folder

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

from redact.bulk import bulk_apply, bulk_scan, discover_pdfs, read_bulk_manifest
from redact.manifest import (
    compute_file_hash,
    create_manifest,
    read_manifest,
    verify_source_integrity,
    write_manifest,
)
from redact.preview import generate_preview
from redact.rasterize import rasterize_failed_pages
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
    rasterize_failed: Annotated[
        bool,
        typer.Option(
            "--rasterize-failed",
            help="If verification fails, rasterize the failing pages "
                 "to flat images (nuclear option — kills selectability).",
        ),
    ] = False,
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

    terms = manifest.get("terms", [])
    apply_redactions(source_pdf, matches, output, terms=terms)
    _strip_xattrs(output)

    # Verification pass
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

            if rasterize_failed:
                console.print(
                    "\n[yellow]Rasterizing failing pages...[/yellow]"
                )
                final_result, rasterized = rasterize_failed_pages(
                    output, output, terms,
                )
                if rasterized:
                    console.print(
                        f"Rasterized {len(rasterized)} page(s): "
                        f"{sorted(rasterized)}"
                    )
                if final_result.passed:
                    console.print(
                        "[green bold]Verification passed after "
                        "rasterization.[/green bold]"
                    )
                else:
                    console.print(
                        "[red bold]Verification still failing after "
                        "rasterization:[/red bold]"
                    )
                    for f in final_result.failures:
                        console.print(f"  [red]• {f}[/red]")
            else:
                console.print(
                    "\n[yellow]Review manually before distributing, or "
                    "retry with [bold]--rasterize-failed[/bold] to "
                    "flatten the failing pages.[/yellow]"
                )

    console.print(f"\nSaved to: [blue bold]{output}[/blue bold]")


bulk_app = typer.Typer(
    name="bulk",
    help="Process a folder of PDFs at once.",
    no_args_is_help=True,
)
app.add_typer(bulk_app, name="bulk")


@bulk_app.command(name="scan")
def bulk_scan_cmd(
    input_dir: Annotated[
        Path,
        typer.Argument(
            help="Folder containing PDF files to scan.",
            exists=True,
            file_okay=False,
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
    drafts_dir: Annotated[
        Path,
        typer.Option(
            "--drafts", "-d",
            help="Folder for preview PDFs with highlights.",
        ),
    ] = Path("drafts"),
    manifest_out: Annotated[
        Path,
        typer.Option(
            "--output", "-o",
            help="Path for the bulk manifest JSON file.",
        ),
    ] = Path("bulk_manifest.json"),
) -> None:
    """Scan all PDFs in a folder and generate previews for review.

    Creates a drafts/ folder with highlighted preview PDFs and a
    bulk manifest that tracks all files and matches.
    """
    _apply_security_safeguards()
    _block_spotlight(drafts_dir.resolve())

    terms = load_terms(terms_file)
    if not terms:
        console.print("[red]Error:[/red] No search terms found in terms file.")
        raise typer.Exit(code=1)

    pdfs = discover_pdfs(input_dir)
    if not pdfs:
        console.print(
            f"[yellow]No PDF files found in [bold]{input_dir}[/bold].[/yellow]"
        )
        raise typer.Exit(code=1)

    console.print(
        f"Scanning [bold]{len(pdfs)}[/bold] PDF(s) in "
        f"[blue]{input_dir}[/blue] for {len(terms)} term(s)...\n"
    )

    manifest, summary = bulk_scan(input_dir, terms, drafts_dir, manifest_out)

    # Results table
    table = Table(title="Bulk Scan Results")
    table.add_column("File", style="bold")
    table.add_column("Matches", justify="right")
    table.add_column("Pages affected", justify="right")

    for fm in manifest.get("files", []):
        stats = fm.get("statistics", {})
        name = Path(fm["source_pdf"]).name
        matches = stats.get("total_matches", 0)
        pages = len(stats.get("pages_affected", []))
        table.add_row(name, str(matches), str(pages))

    console.print(table)

    console.print(
        f"\n[bold]{summary.files_with_matches}[/bold] file(s) with matches, "
        f"[bold]{summary.files_without_matches}[/bold] clean, "
        f"[bold]{summary.total_matches}[/bold] total redactions"
    )

    if summary.files_skipped:
        console.print(
            f"\n[yellow]Skipped {len(summary.files_skipped)} file(s) "
            f"(could not read): {', '.join(summary.files_skipped)}[/yellow]"
        )

    if summary.files_with_matches == 0:
        console.print(
            "\n[yellow]No matches found in any file.[/yellow]"
        )
        raise typer.Exit(code=1)

    console.print(f"\nDrafts:   [blue]{drafts_dir}[/blue]")
    console.print(f"Manifest: [blue]{manifest_out}[/blue]")
    console.print(
        "\n[green]Review the previews in the drafts folder, then run "
        "[bold]redact bulk apply[/bold] to apply redactions.[/green]"
    )


@bulk_app.command(name="apply")
def bulk_apply_cmd(
    manifest_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the bulk manifest JSON from the scan phase.",
            exists=True,
            readable=True,
        ),
    ],
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output", "-o",
            help="Folder for redacted PDF output.",
        ),
    ] = Path("output"),
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v",
            help="Show full tracebacks for errors.",
        ),
    ] = False,
    error_log: Annotated[
        Optional[Path],
        typer.Option(
            "--error-log",
            help="Write detailed errors (with tracebacks) to this file.",
        ),
    ] = None,
    rasterize_failed: Annotated[
        bool,
        typer.Option(
            "--rasterize-failed",
            help="For pages that fail verification, replace them with "
                 "rasterized images (nuclear option — kills "
                 "selectability on those pages).",
        ),
    ] = False,
) -> None:
    """Apply redactions for all files in a bulk manifest.

    Reads the bulk manifest from `redact bulk scan`, applies true
    redactions to every file, and saves results to the output folder.
    """
    _apply_security_safeguards()
    _block_spotlight(output_dir.resolve())

    manifest = read_bulk_manifest(manifest_path)
    file_count = len(manifest["files"])

    if file_count == 0:
        console.print("[yellow]No files to process in this manifest.[/yellow]")
        raise typer.Exit(code=0)

    console.print(
        f"Applying redactions for [bold]{file_count}[/bold] file(s)...\n"
    )

    results = bulk_apply(
        manifest, output_dir, rasterize_failed=rasterize_failed,
    )

    # Strip xattrs from all output files
    for r in results:
        if r["status"] == "done":
            _strip_xattrs(Path(r["output"]))

    # Results table
    table = Table(title="Bulk Apply Results")
    table.add_column("File", style="bold")
    table.add_column("Redactions", justify="right")
    table.add_column("Status")
    table.add_column("Verification")

    for r in results:
        status_style = {
            "done": "green",
            "skipped": "yellow",
            "error": "red",
        }.get(r["status"], "white")

        verification = r.get("verification", "—")
        ver_style = "green" if verification == "passed" else "red" if "FAIL" in str(verification) else "dim"

        table.add_row(
            r["source"],
            str(r["matches"]),
            f"[{status_style}]{r['status']}[/{status_style}]",
            f"[{ver_style}]{verification}[/{ver_style}]",
        )

    console.print(table)

    done = sum(1 for r in results if r["status"] == "done")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    errors = sum(1 for r in results if r["status"] == "error")
    failed_ver = sum(1 for r in results if r.get("verification") == "FAILED")

    console.print(
        f"\n[bold]{done}[/bold] completed, "
        f"[bold]{skipped}[/bold] skipped, "
        f"[bold]{errors}[/bold] errors"
    )

    # Show rasterization summary if it ran
    rasterized_files = [r for r in results if r.get("rasterized_pages")]
    if rasterized_files:
        total_pages = sum(
            len(r["rasterized_pages"]) for r in rasterized_files
        )
        console.print(
            f"\n[yellow]Rasterized {total_pages} page(s) across "
            f"{len(rasterized_files)} file(s) (flattened to images).[/yellow]"
        )
        for r in rasterized_files:
            console.print(
                f"  {r['source']}: pages {r['rasterized_pages']}"
            )

    if failed_ver > 0:
        console.print(
            f"\n[red bold]{failed_ver} file(s) failed verification. "
            f"Review manually before distributing.[/red bold]"
        )

    # Print detailed verification failures
    if failed_ver > 0:
        console.print("\n[red bold]Verification failure details:[/red bold]")
        for r in results:
            if r.get("verification") != "FAILED":
                continue
            failures = r.get("verification_failures", [])
            console.print(f"  [red]{r['source']}[/red]")
            if failures:
                for f in failures:
                    console.print(f"    [red]•[/red] {f}")
            else:
                console.print(
                    "    [dim](no failure details captured)[/dim]"
                )
        console.print(
            "\n[dim]Verification failures usually mean the redacted text "
            "appears in metadata, annotations, font subsets, or text that "
            "was split across lines. See the README for details.[/dim]"
        )

    # Print detailed error info for each failed file
    if errors > 0:
        console.print("\n[red bold]Error details:[/red bold]")
        for r in results:
            if r["status"] != "error":
                continue
            phase = r.get("phase", "unknown")
            err_type = r.get("error_type", "UnknownError")
            err_msg = r.get("error_message", "")
            console.print(
                f"  [red]{r['source']}[/red] "
                f"[dim](phase: {phase})[/dim]"
            )
            console.print(f"    [red]{err_type}:[/red] {err_msg}")
            if verbose and r.get("traceback"):
                # Indent the traceback for readability
                tb_lines = r["traceback"].rstrip().splitlines()
                for line in tb_lines:
                    console.print(f"    [dim]{line}[/dim]")

        if not verbose:
            console.print(
                "\n[dim]Tip: re-run with [bold]--verbose[/bold] for full "
                "tracebacks, or [bold]--error-log errors.log[/bold] to save "
                "them to a file.[/dim]"
            )

    # Write error log file if requested
    if error_log and (errors > 0 or failed_ver > 0):
        _write_error_log(results, error_log)
        console.print(f"\nError log written to: [blue]{error_log}[/blue]")

    console.print(f"\nOutput: [blue bold]{output_dir}[/blue bold]")


def _write_error_log(results: list[dict], log_path: Path) -> None:
    """Write a detailed error log with tracebacks and verification failures."""
    lines: list[str] = []
    lines.append("Redact bulk apply — error log")
    lines.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    lines.append("=" * 70)
    lines.append("")

    # Section 1: Errors (exceptions during processing)
    error_count = 0
    for r in results:
        if r["status"] != "error":
            continue
        error_count += 1
        if error_count == 1:
            lines.append("ERRORS")
            lines.append("-" * 70)
        lines.append(f"[{error_count}] {r['source']}")
        lines.append(f"    Phase:       {r.get('phase', 'unknown')}")
        lines.append(f"    Error type:  {r.get('error_type', 'UnknownError')}")
        lines.append(f"    Error msg:   {r.get('error_message', '')}")
        if r.get("traceback"):
            lines.append("    Traceback:")
            for tb_line in r["traceback"].rstrip().splitlines():
                lines.append(f"      {tb_line}")
        lines.append("")

    # Section 2: Verification failures
    ver_count = 0
    for r in results:
        if r.get("verification") != "FAILED":
            continue
        ver_count += 1
        if ver_count == 1:
            lines.append("VERIFICATION FAILURES")
            lines.append("-" * 70)
            lines.append(
                "These files were redacted but post-redaction verification"
            )
            lines.append(
                "found traces of the search terms still present. Review each"
            )
            lines.append("file manually before distributing.")
            lines.append("")
        lines.append(f"[{ver_count}] {r['source']}")
        failures = r.get("verification_failures", [])
        if failures:
            lines.append("    Failures:")
            for f in failures:
                lines.append(f"      - {f}")
        else:
            lines.append("    (no failure details captured)")
        lines.append("")

    log_path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    app()
