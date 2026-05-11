"""HTML report generator for SSH audit findings."""

from __future__ import annotations

import html as html_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ssh_auditor.rules.base import Finding

# Severity → CSS colour mapping.
_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",  # red-600
    "high": "#ea580c",      # orange-600
    "medium": "#eab308",    # yellow-500
    "low": "#2563eb",       # blue-600
}


def _severity_color(severity: str) -> str:
    """Return the CSS colour for a severity string."""
    return _SEVERITY_COLORS.get(severity, "#6b7280")


def _escape(text: str) -> str:
    """HTML-escape a string."""
    return html_module.escape(text, quote=True)


def _build_summary_html(summary: dict[str, int]) -> str:
    """Build the summary statistics section."""
    rows = ""
    for sev in ("critical", "high", "medium", "low"):
        count = summary.get(sev, 0)
        color = _severity_color(sev)
        rows += (
            f'<div class="summary-card" style="border-left-color: {color}">'
            f"<strong>{_escape(sev.upper())}</strong>: {count}"
            "</div>\n"
        )
    return rows


def _build_findings_table(findings: list[Finding]) -> str:
    """Build the detailed findings table rows."""
    rows = ""
    for f in findings:
        color = _severity_color(f.severity.value)
        rows += (
            f"<tr>"
            f'<td><span class="severity-badge" style="background-color: {color}">'
            f"{_escape(f.severity.value.upper())}</span></td>"
            f"<td>{_escape(f.rule_id)}</td>"
            f"<td><code>{_escape(f.directive)}</code></td>"
            f"<td>{_escape(f.description)}</td>"
            f"<td>{_escape(f.remediation)}</td>"
            f"</tr>\n"
        )
    return rows


def generate_html_report(
    findings: list[Finding],
    config_path: str,
) -> str:
    """Generate a full HTML report string from findings.

    Args:
        findings: List of ``Finding`` objects.
        config_path: Path to the scanned configuration file.

    Returns:
        A complete HTML document as a string.
    """
    severity_counts: dict[str, int] = {}
    for sev in ("critical", "high", "medium", "low"):
        severity_counts[sev] = sum(1 for f in findings if f.severity.value == sev)

    summary_html = _build_summary_html(severity_counts)
    table_rows = _build_findings_table(findings)

    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SSH Audit Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #f8fafc; color: #1e293b; padding: 2rem; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .subtitle {{ color: #64748b; margin-bottom: 1.5rem; font-size: 0.875rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .summary-card {{ background: #fff; border-left: 4px solid #6b7280;
                   padding: 1rem 1.5rem; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
                   min-width: 140px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           box-shadow: 0 1px 3px rgba(0,0,0,.1); border-radius: 6px; overflow: hidden; }}
  th {{ background: #1e293b; color: #fff; text-align: left; padding: 0.75rem 1rem; }}
  td {{ padding: 0.625rem 1rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .severity-badge {{ display: inline-block; padding: 0.125rem 0.625rem; border-radius: 999px;
                     color: #fff; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  code {{ background: #f1f5f9; padding: 0.125rem 0.375rem; border-radius: 4px; font-size: 0.875em; }}
</style>
</head>
<body>
<h1>SSH Audit Report</h1>
<p class="subtitle">Config: {_escape(config_path)} &middot; Scanned: {_escape(scan_date)}</p>

<div class="summary">
{summary_html}
<p class="summary-card"><strong>TOTAL</strong>: {len(findings)}</p>
</div>

<table>
<thead><tr>
<th>Severity</th><th>Rule ID</th><th>Directive</th><th>Description</th><th>Remediation</th>
</tr></thead>
<tbody>
{table_rows}
</tbody>
</table>
</body>
</html>"""

    return html


def write_html_report(
    findings: list[Finding],
    config_path: str,
    output: str | Path,
) -> None:
    """Generate an HTML report and write it to *output*.

    Args:
        findings: List of ``Finding`` objects.
        config_path: Path to the scanned configuration file.
        output: File path to write the HTML report.
    """
    html = generate_html_report(findings, config_path)
    Path(output).write_text(html, encoding="utf-8")
