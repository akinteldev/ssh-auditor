"""CLI entry point for the SSH Hardening Auditor.

Usage::

    ssh-auditor scan <config_path>
    ssh-auditor scan <config_path> --format json [--output FILE]
    ssh-auditor scan <config_path> --format html --output FILE
    ssh-auditor rules list
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ssh_auditor.evaluator import Evaluator
from ssh_auditor.reporter.html_report import write_html_report
from ssh_auditor.reporter.json_report import write_json_report

app = typer.Typer(
    name="ssh-auditor",
    help="SSH server configuration hardening auditor.",
    add_completion=False,
)

console = Console()


def _exit_with_code(code: int) -> NoReturn:
    """Exit with the given code."""
    sys.exit(code)


# -- scan command -----------------------------------------------------------

@app.command()
def scan(
    config_path: str = typer.Argument(
        ...,
        help="Path to the sshd_config file to audit.",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        case_sensitive=False,
        help="Output format: text (Rich table), json, or html.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: stdout for json, config_path.report.html for html).",
    ),
) -> None:
    """Scan an sshd_config file and report findings."""
    path = Path(config_path)
    if not path.is_file():
        console.print(f"[red]Error: file not found: {path}[/red]")
        _exit_with_code(1)

    evaluator = Evaluator()
    findings = evaluator.get_findings(config_path)

    if format == "json":
        out = output or "-"
        json_str = write_json_report(findings, config_path, output=out if out != "-" else None)
        if out == "-":
            console.print(json_str)
        _exit_with_code(0 if not findings else 1)

    elif format == "html":
        out = output or f"{config_path}.report.html"
        write_html_report(findings, config_path, out)
        console.print(f"[green]HTML report written to {out}[/green]")
        _exit_with_code(0 if not findings else 1)

    else:
        # Text mode — Rich table.
        _print_text_report(evaluator, findings)
        _exit_with_code(0 if not findings else 1)


# -- rules command ----------------------------------------------------------

@app.command(name="rules")
def _rules_list() -> None:
    """List all available audit rules."""
    from ssh_auditor.evaluator import _discover_rules

    rule_classes = _discover_rules()
    if not list:
        return

    table = Table(title="Available Audit Rules")
    table.add_column("Rule ID", style="cyan", width=12)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Description")

    for rule in sorted(rule_classes, key=lambda r: (r.rule_id)):
        table.add_row(
            rule.rule_id,
            f"[{rule.severity.value}]{rule.severity.value.upper()}[/]",
            rule.description,
        )

    console.print(table)


# -- helpers ----------------------------------------------------------------

_SEVERITY_STYLES = {
    "critical": "red",
    "high": "orange_red1",
    "medium": "yellow",
    "low": "blue",
}


def _print_text_report(evaluator: Evaluator, findings: list) -> None:
    """Print a Rich-formatted text report to the console."""
    summary = evaluator.get_summary()

    # Header panel.
    header_text = (
        f"[bold]Config:[/bold] {summary['config_file']}\n"
        f"[bold]Scan date:[/bold] {summary['scan_date']}\n"
        f"[bold]Total findings:[/bold] {summary['total_findings']}"
    )
    console.print(Panel(header_text, title="[bold]SSH Audit Summary[/bold]", border_style="blue"))

    if not findings:
        console.print("\n[green]✓ No issues found. Configuration is compliant.[/green]\n")
        return

    # Severity breakdown.
    counts = evaluator.count_by_severity()
    parts = [f"[{_SEVERITY_STYLES[s]}]{s.upper()}:[/]" f" {counts[s]}" for s in ("critical", "high", "medium", "low")]
    console.print("  ".join(parts))

    # Detailed table.
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Rule ID", style="cyan", width=12)
    table.add_column("Directive", width=20)
    table.add_column("Description")

    for f in findings:
        style = _SEVERITY_STYLES.get(f.severity.value, "")
        table.add_row(
            f"[{style}]{f.severity.value.upper()}[/]",
            f.rule_id,
            f.directive,
            f.description,
        )

    console.print("\n")
    console.print(table)


def main() -> None:
    """Entry point invoked by the ``ssh-auditor`` console script."""
    app()


if __name__ == "__main__":
    main()
